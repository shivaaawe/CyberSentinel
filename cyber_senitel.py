#!/usr/bin/env python3

import os
import requests
import json
import argparse
import pdfkit

# Colorful output
def print_banner():
    print("\033[1;34m" + "="*40)
    print("   CyberSentinel: Cyber Threat Analysis")
    print("="*40 + "\033[0m")

# VirusTotal API Request
def fetch_virustotal_data(url):
    vt_api_key = os.getenv('VT_API_KEY')
    if not vt_api_key:
        return "VirusTotal API key not set"
    
    vt_url = f"https://www.virustotal.com/vtapi/v2/url/report?apikey={vt_api_key}&resource={url}"
    try:
        response = requests.get(vt_url)
        if response.status_code == 200:
            return response.json()
        else:
            return f"Error fetching VirusTotal data: {response.status_code}"
    except Exception as e:
        return f"Error: {e}"

# Calculate threat score
def calculate_threat_score(vt_data):
    score = 0
    
    # VirusTotal score based on number of positives
    if vt_data and isinstance(vt_data, dict):
        positives = vt_data.get('positives', 0)
        score += positives
    
    return score

# Generate HTML Report
def generate_report(data, score, file_name="report/threat_report.html"):
    os.makedirs("report", exist_ok=True)
    with open(file_name, "w") as f:
        f.write("<html><body>")
        f.write("<h1>Threat Intelligence Report</h1>")
        f.write(f"<p>Threat Score: {score}</p>")
        f.write("<h2>VirusTotal Data</h2>")
        f.write(f"<pre>{json.dumps(data, indent=2)}</pre>")
        f.write("</body></html>")
    print(f"Report saved as {file_name}")

# Main Logic
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Cyber Threat Intelligence CLI")
    parser.add_argument("--url", help="Analyze a suspicious URL")
    args = parser.parse_args()

    if args.url:
        print(f"Fetching data for URL: {args.url}")
        vt_data = fetch_virustotal_data(args.url)
        threat_score = calculate_threat_score(vt_data)
        print(f"Threat score calculated: {threat_score}")

        # Generate the report
        generate_report(vt_data, threat_score)
