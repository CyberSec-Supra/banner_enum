#!/usr/bin/env python3

import argparse
import socket
import subprocess
import requests
import re
import time
import shutil
import concurrent.futures
import json
import xml.etree.ElementTree as ET
import os
import importlib.util
import sys

USE_WEASYPRINT = False
USE_XHTML2PDF = False

try:
    from weasyprint import HTML
    USE_WEASYPRINT = True
except ImportError:
    pass

try:
    from xhtml2pdf import pisa
    USE_XHTML2PDF = True
except ImportError:
    pass

def pipx_module_exists(module_name):
    home = os.path.expanduser("~")
    pipx_base = os.path.join(home, ".local", "pipx", "venvs", module_name, "lib")
    for root, dirs, files in os.walk(pipx_base):
        if "site-packages" in root:
            sys.path.insert(0, root)
            try:
                importlib.import_module(module_name)
                return root
            except ImportError:
                continue
    return None

if not USE_WEASYPRINT:
    path = pipx_module_exists("weasyprint")
    if path:
        try:
            from weasyprint import HTML
            USE_WEASYPRINT = True
        except ImportError:
            pass

if not USE_XHTML2PDF:
    path = pipx_module_exists("xhtml2pdf")
    if path:
        try:
            from xhtml2pdf import pisa
            USE_XHTML2PDF = True
        except ImportError:
            pass

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CPE_API_BASE = "https://services.nvd.nist.gov/rest/json/cpes/2.0"

SERVICE_PATTERNS = {
    "ssh": [r"SSH-\d\.\d"],
    "ftp": [r"FTP", r"220 .*ftp", r"FileZilla"],
    "http": [r"HTTP/1\.[01]", r"Server:.*"],
    "telnet": [r"^\xFF\xFB", r"telnet"],
    "smb": [r"SMB", r"NT_STATUS"],
    "smtp": [r"SMTP"],
    "rdp": [r"RDP"],
    "mysql": [r"mysql"]
}

def read_targets(input_file):
    targets = []
    with open(input_file, 'r') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            matches = re.findall(r"(\d+\.\d+\.\d+\.\d+):(\d+)", line)
            for match in matches:
                ip, port = match
                try:
                    targets.append((ip.strip(), int(port.strip())))
                except ValueError:
                    print(f"[!] Skipping malformed entry: {line}")
    return targets

def detect_service(banner):
    for service, patterns in SERVICE_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, banner, re.IGNORECASE):
                return service
    return "unknown"

def get_cpe_candidates(banner):
    try:
        resp = requests.get(CPE_API_BASE, params={"keyword": banner, "resultsPerPage": 1}, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            if "products" in data:
                for product in data["products"]:
                    cpe = product.get("cpe", {}).get("cpeName")
                    if cpe:
                        return cpe
    except Exception:
        pass
    return ""

def scan_target(target, apikey):
    ip, port = target
    try:
        with socket.create_connection((ip, port), timeout=3) as sock:
            sock.sendall(b'\r\n')
            banner = sock.recv(1024).decode(errors='ignore').strip()
    except Exception:
        banner = ''

    service = detect_service(banner) if banner else ("ssh" if port == 22 else "http" if port in [80, 8080] else "unknown")
    cpe = get_cpe_candidates(banner) if banner else ""

    result = {
        "ip": ip,
        "port": port,
        "service": service,
        "product": "",
        "version": "",
        "banner": banner,
        "cpe": cpe,
        "nvd_cves": []
    }

    if banner:
        q = cpe if cpe else f"{service} {banner}".strip()
        try:
            resp = requests.get(NVD_API_BASE, params={"keywordSearch": q, "resultsPerPage": 5}, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                for item in data.get("vulnerabilities", []):
                    cve = item.get("cve")
                    if cve:
                        score = cve.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseScore", "")
                        result["nvd_cves"].append(f"{cve['id']} (CVSS {score})")
        except Exception:
            pass

    return result

def export_results(results, args):
    if args.json:
        with open(args.json, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"[*] JSON exported to {args.json}")

    if args.xml:
        root = ET.Element("results")
        for r in results:
            host = ET.SubElement(root, "host")
            for key, value in r.items():
                child = ET.SubElement(host, key)
                if isinstance(value, list):
                    child.text = ", ".join(value)
                else:
                    child.text = str(value)
        tree = ET.ElementTree(root)
        tree.write(args.xml)
        print(f"[*] XML exported to {args.xml}")

    if args.output:
        with open(args.output, 'w') as f:
            f.write("<html><head><title>Scan Report</title></head><body>")
            f.write("<h1>Service Enumeration Report</h1>")
            for r in results:
                f.write("<div style='margin-bottom:15px;'><b>{ip}:{port}</b><br>Service: {service}<br>Banner: {banner}<br>CVEs: {cves}</div>".format(
                    ip=r["ip"], port=r["port"], service=r["service"], banner=r["banner"], cves="<br>".join(r["nvd_cves"])))
            f.write("<hr><p><b>Severity Legend:</b> CVSS 0.0–3.9 = Low, 4.0–6.9 = Medium, 7.0–8.9 = High, 9.0–10 = Critical</p>")
            f.write("</body></html>")
        print(f"[*] HTML report written to {args.output}")

    if args.pdf:
        if USE_WEASYPRINT:
            try:
                HTML(args.output).write_pdf(args.pdf)
                print(f"[*] PDF exported to {args.pdf} using WeasyPrint")
            except Exception as e:
                print(f"[!] PDF export failed (WeasyPrint): {e}")
        elif USE_XHTML2PDF:
            try:
                with open(args.output, 'r') as f:
                    html = f.read()
                with open(args.pdf, 'wb') as out:
                    pisa.CreatePDF(html, dest=out)
                print(f"[*] PDF exported to {args.pdf} using XHTML2PDF")
            except Exception as e:
                print(f"[!] PDF export failed (XHTML2PDF): {e}")
        else:
            print("[!] PDF export failed: No PDF engine (weasyprint or xhtml2pdf) is available.")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--input", required=True, help="Input file with IP:port list")
    parser.add_argument("-k", "--key", required=False, help="Vulners or API key (optional)")
    parser.add_argument("-o", "--output", help="HTML output filename")
    parser.add_argument("--json", help="Export results to JSON file")
    parser.add_argument("--xml", help="Export results to XML file")
    parser.add_argument("--pdf", help="Export results to PDF file")
    args = parser.parse_args()

    targets = read_targets(args.input)
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(scan_target, t, args.key) for t in targets]
        results = [f.result() for f in concurrent.futures.as_completed(futures)]

    export_results(results, args)

print(f"[DEBUG] WeasyPrint available: {USE_WEASYPRINT}, XHTML2PDF available: {USE_XHTML2PDF}")

if __name__ == "__main__":
    main()
