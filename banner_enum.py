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

try:
    from weasyprint import HTML
    USE_WEASYPRINT = True
except ImportError:
    USE_WEASYPRINT = False
    try:
        from xhtml2pdf import pisa
        USE_XHTML2PDF = True
    except ImportError:
        USE_XHTML2PDF = False

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Placeholder: read_targets and scan_target must be defined

def render_html(results, output_file):
    html = [
        "<html><head><title>Vulnerability Report</title><style>",
        "body { font-family: Arial; }",
        "table { border-collapse: collapse; width: 100%; }",
        "th, td { border: 1px solid #ddd; padding: 8px; }",
        "th { background-color: #f2f2f2; }",
        ".high { background-color: #f8d7da; }",
        ".medium { background-color: #fff3cd; }",
        ".low { background-color: #d4edda; }",
        "</style></head><body>",
        "<h1>Service Vulnerability Report</h1>",
        "<h2>Severity Legend:</h2>",
        "<ul>",
        "<li><span style='background-color:#f8d7da;'>High (CVSS ≥ 7)</span></li>",
        "<li><span style='background-color:#fff3cd;'>Medium (CVSS 4–6.9)</span></li>",
        "<li><span style='background-color:#d4edda;'>Low (CVSS < 4)</span></li>",
        "</ul>",
        "<table><tr><th>IP</th><th>Port</th><th>Service</th><th>Product</th><th>Version</th><th>Banner</th><th>NVD CVEs</th></tr>"
    ]

    for entry in results:
        max_score = 0
        for cve in entry.get("nvd_cves", []):
            match = re.search(r"CVSS ([0-9.]+)", cve)
            if match:
                score = float(match.group(1))
                if score > max_score:
                    max_score = score

        if max_score >= 7:
            row_class = "high"
        elif 4 <= max_score < 7:
            row_class = "medium"
        elif 0 < max_score < 4:
            row_class = "low"
        else:
            row_class = ""

        html.append(f"<tr class='{row_class}'><td>{entry['ip']}</td><td>{entry['port']}</td><td>{entry['service']}</td><td>{entry.get('product','')}</td><td>{entry.get('version','')}</td><td>{entry['banner']}</td><td><ul>")
        for cve in entry.get("nvd_cves", []):
            html.append(f"<li>{cve}</li>")
        html.append("</ul></td></tr>")

    html.append("</table></body></html>")
    with open(output_file, "w") as f:
        f.write("\n".join(html))

def export_json(results, json_file):
    with open(json_file, "w") as f:
        json.dump(results, f, indent=2)

def export_xml(results, xml_file):
    root = ET.Element("results")
    for entry in results:
        item = ET.SubElement(root, "host")
        for key, val in entry.items():
            if isinstance(val, list):
                child = ET.SubElement(item, key)
                for subval in val:
                    ET.SubElement(child, "entry").text = str(subval)
            else:
                ET.SubElement(item, key).text = str(val)
    tree = ET.ElementTree(root)
    tree.write(xml_file)

def export_nuclei(results, nuclei_file):
    with open(nuclei_file, "w") as f:
        for entry in results:
            if entry.get("service"):
                f.write(f"{entry['ip']}:{entry['port']} [{entry['service']}]")
                f.write("\n")

def export_pdf(html_path, pdf_path):
    with open(html_path, "r") as f:
        html_content = f.read()

    if USE_WEASYPRINT:
        HTML(string=html_content).write_pdf(pdf_path)
    elif USE_XHTML2PDF:
        with open(pdf_path, "wb") as f_out:
            pisa.CreatePDF(html_content, dest=f_out)
    else:
        print("[!] PDF export failed: No PDF engine (weasyprint or xhtml2pdf) is available.")

def main():
    parser = argparse.ArgumentParser(description="Threaded Service and Vulnerability Enumeration")
    parser.add_argument("-i", "--input", help="Input file with IP:PORT lines", required=True)
    parser.add_argument("-k", "--apikey", help="Vulners API key", required=False)
    parser.add_argument("-o", "--output", help="Output HTML report filename", default="report.html")
    parser.add_argument("--json", help="Optional JSON export file")
    parser.add_argument("--xml", help="Optional XML export file")
    parser.add_argument("--nuclei", help="Optional Nuclei-compatible export file")
    parser.add_argument("--pdf", help="Optional PDF output file")
    args = parser.parse_args()

    targets = read_targets(args.input)
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(scan_target, target, args.apikey): target for target in targets}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            results.append(result)

    render_html(results, args.output)
    print(f"[*] HTML report written to {args.output}")

    if args.json:
        export_json(results, args.json)
        print(f"[*] JSON exported to {args.json}")

    if args.xml:
        export_xml(results, args.xml)
        print(f"[*] XML exported to {args.xml}")

    if args.nuclei:
        export_nuclei(results, args.nuclei)
        print(f"[*] Nuclei template exported to {args.nuclei}")

    if args.pdf:
        export_pdf(args.output, args.pdf)
        if os.path.exists(args.pdf):
            print(f"[*] PDF exported to {args.pdf}")

if __name__ == "__main__":
    main()
