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
