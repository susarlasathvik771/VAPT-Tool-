# VAPT-Tool-
# VAPT Dashboard — Nmap + OWASP ZAP Integration

**VAPT Dashboard** is a Python-based graphical tool that combines **network scanning** (Nmap) and **web application vulnerability assessment** (OWASP ZAP) into a single interactive platform. The tool provides comprehensive security insights, real-time feedback, and professional reporting capabilities.

> ⚠️ **Warning:** Use this tool **only on targets you own or have explicit written permission to test**.

---

## Features

- Input URL or domain in any format (e.g., `example.com`, `https://example.com`).
- Automated **DNS resolution**, HTTP header analysis, SSL/TLS certificate validation.
- Optional **Nmap scan** for open ports and service detection.
- Optional **OWASP ZAP integration** for passive and active web application scanning.
- Interactive **dashboard** with progress bar, log window, and findings table.
- **Double-click on findings** to view full details in a dialog.
- Export results in **JSON** or **CSV** formats.
- Copy individual findings to clipboard or export as separate JSON files.
- Severity classification of findings: High, Medium, Low.

---

## Requirements

- Python 3.9 or later
- Required Python libraries:
  ```bash
  pip install pyqt5 requests nmap python-owasp-zap-v2.4 cryptography vulners pandas python-dateutil


**Warnings & Cautions**

Authorization Required

Only perform scans on targets you own or have explicit written permission to test. Unauthorized scanning is illegal and may be considered a cybercrime.

Intrusive Scans

Enabling Nmap scans or OWASP ZAP Active scans can generate high traffic and may disrupt services on the target. Use with caution and permission.

System Resource Usage

Scanning large networks or complex web applications may consume significant CPU, memory, and network bandwidth, potentially slowing down your system.

Incomplete or False Results

Some services may be hidden behind firewalls or security appliances, resulting in missed vulnerabilities.

False positives may occur during automated scanning.

SSL/TLS Warnings

The tool may ignore certificate validation for HTTPS targets to perform analysis.

Do not use this tool to bypass security or trust mechanisms in production systems.

Heavy Traffic Warning

Scanning multiple hosts, ports, or enabling active web scans can lead to network congestion, delays, or application slowdowns.

External Dependencies

Full functionality relies on external tools: Nmap CLI and OWASP ZAP.

Missing dependencies will disable associated features.

Legal and Ethical Responsibility

Users are fully responsible for the results of scans.

Always follow ethical guidelines and legal regulations when performing vulnerability assessments.
