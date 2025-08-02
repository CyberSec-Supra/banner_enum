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
from collections import Counter
from datetime import datetime

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
    "ssh": [r"SSH-\\d\\.\\d"],
    "ftp": [r"FTP", r"220 .*ftp", r"FileZilla"],
    "http": [r"HTTP/1\\.[01]", r"Server:.*"],
    "telnet": [r"^\\xFF\\xFB", r"telnet"],
    "smb": [r"SMB", r"NT_STATUS"],
    "smtp": [r"SMTP"],
    "rdp": [r"RDP"],
    "mysql": [r"mysql"]
}

PORT_SERVICE_GUESS = {
    22: "ssh",
    80: "http",
    8080: "http",
    443: "https",
    21: "ftp",
    23: "telnet"
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

def guess_service_by_port(port):
    return PORT_SERVICE_GUESS.get(port, "unknown")

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

def grab_banner(ip, port):
    try:
        with socket.create_connection((ip, port), timeout=3) as sock:
            sock.sendall(b'\r\n')
            return sock.recv(1024).decode(errors='ignore').strip()
    except Exception:
        return ""

def scan_target(target, apikey):
    ip, port = target
    banner = grab_banner(ip, port)
    service = detect_service(banner) if banner else guess_service_by_port(port)
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

    if apikey:
        pass

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

def export_html(results, filename):
    with open(filename, 'w') as f:
        f.write("<html><head><style>body{font-family:Arial;}table{border-collapse:collapse;width:100%;}th,td{border:1px solid #ddd;padding:8px;}th{background:#f2f2f2;} .critical{color:red;font-weight:bold}</style></head><body>")
        f.write(f"<h2>Vulnerability Scan Report - {datetime.now()}</h2>")
        f.write("<table><tr><th>IP</th><th>Port</th><th>Service</th><th>Banner</th><th>CPE</th><th>CVEs</th></tr>")
        for r in results:
            cves_html = "<br>".join([
                f"<span class='{'critical' if 'CVSS 9' in cve or 'CVSS 10' in cve else ''}'>{cve}</span>" for cve in r['nvd_cves']
            ])
            f.write(f"<tr><td>{r['ip']}</td><td>{r['port']}</td><td>{r['service']}</td><td>{r['banner']}</td><td>{r['cpe']}</td><td>{cves_html}</td></tr>")
        f.write("</table><br><br><h4>Severity Legend:</h4><ul><li>Low: CVSS 0.0–3.9</li><li>Medium: 4.0–6.9</li><li>High: 7.0–8.9</li><li><span class='critical'>Critical: 9.0–10</span></li></ul></body></html>")

def export_results(results, json_file, xml_file, html_file, pdf_file):
    if json_file:
        with open(json_file, 'w') as jf:
            json.dump(results, jf, indent=2)
        print(f"[*] JSON exported to {json_file}")

    if xml_file:
        root = ET.Element("Results")
        for r in results:
            item = ET.SubElement(root, "Result")
            for k, v in r.items():
                if isinstance(v, list):
                    lv = ET.SubElement(item, k)
                    for e in v:
                        ET.SubElement(lv, "entry").text = e
                else:
                    ET.SubElement(item, k).text = str(v)
        tree = ET.ElementTree(root)
        tree.write(xml_file)
        print(f"[*] XML exported to {xml_file}")

    if html_file:
        export_html(results, html_file)
        print(f"[*] HTML report written to {html_file}")

    if pdf_file:
        try:
            if USE_WEASYPRINT:
                HTML(html_file).write_pdf(pdf_file)
                print(f"[*] PDF exported to {pdf_file} using WeasyPrint")
            elif USE_XHTML2PDF:
                with open(html_file, "r") as source, open(pdf_file, "wb") as target:
                    pisa.CreatePDF(source.read(), dest=target)
                print(f"[*] PDF exported to {pdf_file} using xhtml2pdf")
            else:
                print("[!] PDF export failed: No PDF engine (weasyprint or xhtml2pdf) is available.")
        except Exception as e:
            print(f"[!] PDF export error: {e}")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--input", required=True, help="Input file with IP:Port list")
    parser.add_argument("-k", "--apikey", help="Vulners API key (optional)")
    parser.add_argument("-o", "--html", help="Output HTML report")
    parser.add_argument("--json", help="Export JSON file")
    parser.add_argument("--xml", help="Export XML file")
    parser.add_argument("--pdf", help="Export PDF file")
    args = parser.parse_args()

    targets = read_targets(args.input)
    print(f"[*] Loaded {len(targets)} targets")

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        futures = [executor.submit(scan_target, target, args.apikey) for target in targets]
        for future in concurrent.futures.as_completed(futures):
            results.append(future.result())

    export_results(results, args.json, args.xml, args.html, args.pdf)

print(f"[DEBUG] WeasyPrint available: {USE_WEASYPRINT}, XHTML2PDF available: {USE_XHTML2PDF}")

if __name__ == "__main__":
    main()
