# Cyber Threat Intelligence (CTI) Toolkit

The **CTI Toolkit** is a command-line tool that gathers real-time threat intelligence data from the public API (VirusTotal) and generates a threat report for cybersecurity professionals. It calculates a threat score based on gathered data, assisting in incident response and threat mitigation.

## Features
- Fetches data from **VirusTotal** for URLs.
- Calculates a **Threat Score** based on gathered intelligence.
- Generates **HTML reports** with detailed information.
- Optionally, converts the HTML report into a **PDF** format.

## Installation

1. Clone the repository:

    ```bash
    git clone https://github.com/yourusername/CTI-Toolkit.git
    cd CTI-Toolkit
    ```

2. Set up environment variables for API keys:

    ```bash
    export VT_API_KEY="your_virustotal_api_key"
    ```

3. Install dependencies:

    ```bash
    pip install -r requirements.txt
    ```

4. Make the script executable:

    ```bash
    chmod +x cti_toolkit.py
    chmod +x start.sh
    ```

## Usage

To analyze a URL using VirusTotal:

```bash
./cti_toolkit.py --url https://example.com
