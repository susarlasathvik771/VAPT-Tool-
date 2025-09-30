#!/usr/bin/env python3
"""
vapt_zap_nmap_with_details.py

VAPT Dashboard (Nmap + OWASP ZAP integration) with detail dialog:
- Double-click a finding row to open a scrollable dialog showing all details
- Buttons: Copy to clipboard, Export single finding as JSON, Close

WARNING: Use only on targets you own or have explicit written permission to test.
"""

import sys
import re
import socket
import ssl
import json
import datetime
import traceback
from urllib.parse import urlparse

import requests
from requests.exceptions import RequestException

# PyQt5 UI
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton,
    QTextEdit, QTableWidget, QTableWidgetItem, QHeaderView, QProgressBar,
    QMessageBox, QCheckBox, QFileDialog, QSplitter, QComboBox, QDialog
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal

# Optional libs
try:
    import nmap
    NMAPPER_AVAILABLE = True
except Exception:
    NMAPPER_AVAILABLE = False

try:
    from zapv2 import ZAPv2
    ZAP_AVAILABLE = True
except Exception:
    ZAP_AVAILABLE = False

try:
    import vulners
    VULNERS_AVAILABLE = True
except Exception:
    VULNERS_AVAILABLE = False

try:
    from cryptography import x509
    CRYPTO_AVAILABLE = True
except Exception:
    CRYPTO_AVAILABLE = False

# ----------------------------
# Config & constants
# ----------------------------
USER_AGENT = "VAPT-Pro/1.0 (+use-with-permission)"
COMMON_SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "Set-Cookie"
]

DEFAULT_ZAP_API_HOST = "http://127.0.0.1"
DEFAULT_ZAP_API_PORT = 8090
DEFAULT_ZAP_API_KEY = None  # set if you configured ZAP API key

# ----------------------------
# Utilities
# ----------------------------
def normalize_url(raw: str) -> str:
    raw = (raw or "").strip()
    if not raw:
        raise ValueError("Empty input")
    if not re.match(r"^https?://", raw):
        raw = "https://" + raw
    parsed = urlparse(raw)
    if not parsed.netloc:
        raise ValueError("Invalid URL")
    clean = parsed._replace(fragment="", query="").geturl()
    return clean

def resolve_dns(hostname: str):
    try:
        infos = socket.getaddrinfo(hostname, None)
        return sorted({ai[4][0] for ai in infos})
    except Exception:
        return []

def fetch_http(url: str, timeout=8):
    headers = {"User-Agent": USER_AGENT}
    try:
        r = requests.head(url, headers=headers, allow_redirects=True, timeout=timeout, verify=False)
        if r.status_code in (405, 403) or not r.headers:
            r = requests.get(url, headers=headers, allow_redirects=True, timeout=timeout, verify=False)
    except RequestException:
        parsed = urlparse(url)
        if parsed.scheme == "https":
            alt = "http://" + parsed.netloc + parsed.path
            try:
                r = requests.get(alt, headers=headers, allow_redirects=True, timeout=timeout, verify=False)
            except RequestException:
                return None
        else:
            return None
    text = getattr(r, "text", "") or ""
    title = ""
    m = re.search(r"<title>(.*?)</title>", text, re.IGNORECASE | re.DOTALL)
    if m:
        title = m.group(1).strip()
    return {"status": r.status_code, "headers": dict(r.headers), "title": title}

def get_ssl_cert(hostname: str, port=443, timeout=6):
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                der = ssock.getpeercert(True)
                if CRYPTO_AVAILABLE:
                    cert = x509.load_der_x509_certificate(der)
                    return {
                        "subject": cert.subject.rfc4514_string(),
                        "issuer": cert.issuer.rfc4514_string(),
                        "not_before": cert.not_valid_before.isoformat(),
                        "not_after": cert.not_valid_after.isoformat()
                    }
                else:
                    return ssock.getpeercert()
    except Exception:
        return None

def run_nmap(host_or_ip: str, top_ports=100, scan_type="-sV"):
    if not NMAPPER_AVAILABLE:
        return {"error": "python-nmap not installed"}
    try:
        nm = nmap.PortScanner()
        args = f"{scan_type} --top-ports {top_ports} -Pn"
        nm.scan(hosts=host_or_ip, arguments=args)
        hosts = nm.all_hosts()
        if not hosts:
            return {"hosts": [], "ports": []}
        h = hosts[0]
        ports = []
        for proto in nm[h].all_protocols():
            for p in sorted(nm[h][proto].keys()):
                rec = nm[h][proto][p]
                ports.append({
                    "port": p,
                    "protocol": proto,
                    "state": rec.get("state"),
                    "service": rec.get("name"),
                    "product": rec.get("product"),
                    "version": rec.get("version")
                })
        return {"hosts": hosts, "ports": ports}
    except Exception as e:
        return {"error": str(e)}

def vulners_lookup(banner: str):
    if not VULNERS_AVAILABLE:
        return {"error": "vulners not installed"}
    try:
        v = vulners.Vulners()
        res = v.search(banner)
        matches = []
        data = res.get("data", {})
        if isinstance(data, dict):
            for k, vlist in data.items():
                if isinstance(vlist, list):
                    matches += vlist
        return {"matches": matches[:10]}
    except Exception as e:
        return {"error": str(e)}

def make_finding(ftype, severity, description, evidence=None):
    return {
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "type": ftype,
        "severity": severity,
        "description": description,
        "evidence": evidence or ""
    }

# ----------------------------
# Worker Thread
# ----------------------------
class ScanWorker(QThread):
    progress = pyqtSignal(int)
    info = pyqtSignal(str)
    finding = pyqtSignal(dict)
    finished_signal = pyqtSignal(dict)
    log = pyqtSignal(str)

    def __init__(self, target_url: str, do_nmap=False, nmap_top=100, zap_opts=None):
        super().__init__()
        self.target_url = target_url
        self.do_nmap = do_nmap
        self.nmap_top = nmap_top
        self.zap_opts = zap_opts or {"enabled": False, "address": DEFAULT_ZAP_API_HOST, "port": DEFAULT_ZAP_API_PORT, "apikey": DEFAULT_ZAP_API_KEY, "active": False}
        self.results = {"target": target_url, "started": datetime.datetime.now().isoformat(), "findings": []}

    def safe_log(self, s):
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        self.log.emit(f"[{ts}] {s}")

    def emit_f(self, f):
        self.results.setdefault("findings", []).append(f)
        self.finding.emit(f)

    def run(self):
        try:
            self.progress.emit(2)
            self.safe_log(f"Scan started for {self.target_url}")
            parsed = urlparse(self.target_url)
            hostname = parsed.netloc.split(":")[0]

            # DNS resolution
            self.progress.emit(8)
            ips = resolve_dns(hostname)
            self.results["ips"] = ips
            self.info.emit(f"Target: {self.target_url}\nResolved IPs: {', '.join(ips) if ips else 'None'}")
            self.safe_log(f"Resolved IPs: {ips}")

            # HTTP headers & title
            self.progress.emit(18)
            http = fetch_http(self.target_url)
            if http:
                self.results["http"] = http
                self.safe_log(f"HTTP status {http.get('status')}")
                headers = http.get("headers", {})
                # header checks
                for h in COMMON_SECURITY_HEADERS:
                    if h not in headers:
                        f = make_finding("header-missing", "Medium", f"{h} header missing", evidence=h)
                        self.emit_f(f)
                sc = headers.get("Set-Cookie", "")
                if sc:
                    if "Secure" not in sc:
                        self.emit_f(make_finding("cookie-flag", "Low", "Cookie missing Secure flag", evidence=sc))
                    if "HttpOnly" not in sc and "httponly" not in sc.lower():
                        self.emit_f(make_finding("cookie-flag", "Low", "Cookie missing HttpOnly flag", evidence=sc))
            else:
                self.emit_f(make_finding("http-failure", "High", "Failed to fetch HTTP info"))

            # SSL
            self.progress.emit(30)
            if parsed.scheme == "https":
                cert = get_ssl_cert(hostname)
                if cert:
                    self.results["ssl"] = cert
                    not_after = None
                    if isinstance(cert, dict):
                        not_after = cert.get("not_after") or cert.get("notValidTo") or cert.get("notAfter")
                    if not_after:
                        try:
                            from dateutil import parser as dateparser
                            expir = dateparser.parse(not_after)
                            days_left = (expir - datetime.datetime.utcnow()).days
                            if days_left < 0:
                                self.emit_f(make_finding("ssl-expired", "High", f"Certificate expired ({not_after})", evidence=cert))
                            elif days_left < 30:
                                self.emit_f(make_finding("ssl-expiring", "Medium", f"Certificate expires in {days_left} days", evidence=cert))
                        except Exception:
                            pass
                else:
                    self.emit_f(make_finding("ssl-info", "Low", "Could not fetch SSL certificate"))

            # robots & sitemap
            self.progress.emit(40)
            try:
                robots_resp = requests.get(f"{parsed.scheme}://{parsed.netloc}/robots.txt", headers={"User-Agent": USER_AGENT}, timeout=6, verify=False)
                if robots_resp.status_code == 200:
                    text = robots_resp.text
                    self.results["robots"] = text
                    self.emit_f(make_finding("robots", "Low", "robots.txt present", evidence=(text[:500] + "...") if len(text)>500 else text))
            except Exception:
                pass
            try:
                sitemap_resp = requests.get(f"{parsed.scheme}://{parsed.netloc}/sitemap.xml", headers={"User-Agent": USER_AGENT}, timeout=6, verify=False)
                if sitemap_resp.status_code == 200:
                    text = sitemap_resp.text
                    self.results["sitemap"] = text
                    self.emit_f(make_finding("sitemap", "Low", "sitemap.xml present", evidence=(text[:500] + "...") if len(text)>500 else text))
            except Exception:
                pass

            # Nmap (optional)
            if self.do_nmap:
                self.progress.emit(48)
                self.safe_log("Starting nmap scan (may be intrusive).")
                nres = run_nmap(hostname, top_ports=self.nmap_top)
                self.results["nmap"] = nres
                if "error" in nres:
                    self.emit_f(make_finding("nmap-error", "Low", f"Nmap error: {nres['error']}"))
                else:
                    ports = nres.get("ports", [])
                    for p in ports:
                        desc = f"Port {p['port']}/{p['protocol']} {p['state']} - {p.get('service','')} {p.get('product','')} {p.get('version','')}".strip()
                        sev = "Low"
                        if p['state'] == 'open' and p['port'] in (21,22,23,80,443,445,3306,1433,3389):
                            sev = "Medium"
                        self.emit_f(make_finding("open-port", sev, desc, evidence=p))
                        banner = " ".join(filter(None, [p.get("service",""), p.get("product",""), p.get("version","")]))
                        if banner and VULNERS_AVAILABLE:
                            vres = vulners_lookup(banner)
                            if vres and "matches" in vres and vres["matches"]:
                                for match in vres["matches"][:3]:
                                    title = match.get("title") or match.get("id") or str(match)
                                    self.emit_f(make_finding("cve-match", "High", f"CVE match for service banner: {title}", evidence=match))

            # OWASP ZAP integration (passive, optional active)
            if self.zap_opts.get("enabled") and ZAP_AVAILABLE:
                self.progress.emit(70)
                zap_addr = self.zap_opts.get("address", DEFAULT_ZAP_API_HOST)
                zap_port = int(self.zap_opts.get("port", DEFAULT_ZAP_API_PORT))
                zap_apikey = self.zap_opts.get("apikey", DEFAULT_ZAP_API_KEY)
                try:
                    zap = ZAPv2(apikey=zap_apikey, proxies={"http": f"{zap_addr}:{zap_port}", "https": f"{zap_addr}:{zap_port}"})
                    self.safe_log("Connected to ZAP API.")
                    zap.urlopen(self.target_url)
                    import time
                    time.sleep(2)
                    alerts = zap.core.alerts(baseurl=self.target_url)
                    for a in alerts:
                        desc = a.get("alert", "")
                        risk = a.get("risk", "")
                        url_hit = a.get("url", "")
                        evidence = a.get("evidence", "") or a.get("other", "")
                        self.emit_f(make_finding("zap-alert", risk or "Medium", f"{desc} on {url_hit}", evidence=evidence))
                    if self.zap_opts.get("active"):
                        self.safe_log("Starting ZAP active scan (intrusive).")
                        scan_id = zap.ascan.scan(self.target_url)
                        while int(zap.ascan.status(scan_id)) < 100:
                            time.sleep(2)
                        alerts2 = zap.core.alerts(baseurl=self.target_url)
                        for a in alerts2:
                            self.emit_f(make_finding("zap-active", a.get("risk"), a.get("alert"), evidence=a.get("evidence")))
                except Exception as e:
                    self.safe_log("ZAP error: " + str(e))
                    self.emit_f(make_finding("zap-error", "Low", "ZAP API error or connection problem", evidence=str(e)))
            elif self.zap_opts.get("enabled"):
                self.emit_f(make_finding("zap-unavailable", "Low", "python-owasp-zap-v2.4 not installed or ZAP not running"))

            # Heuristics
            self.progress.emit(92)
            if parsed.scheme == "https":
                hdrs = (self.results.get("http") or {}).get("headers", {}) or {}
                if "Strict-Transport-Security" not in hdrs:
                    self.emit_f(make_finding("hsts-missing", "Medium", "Strict-Transport-Security header missing"))

            # Finish
            self.progress.emit(100)
            self.results["finished"] = datetime.datetime.now().isoformat()
            self.safe_log("Scan completed.")
            self.finished_signal.emit(self.results)
        except Exception as e:
            tb = traceback.format_exc()
            self.safe_log(f"Worker exception: {e}\n{tb}")
            self.results["error"] = str(e)
            self.results["traceback"] = tb
            self.finished_signal.emit(self.results)

# ----------------------------
# Detail Dialog (new)
# ----------------------------
class FindingDetailDialog(QDialog):
    def __init__(self, parent=None, finding: dict = None):
        super().__init__(parent)
        self.setWindowTitle("Finding Details")
        self.resize(700, 520)
        self.finding = finding or {}
        self.init_ui()

    def init_ui(self):
        v = QVBoxLayout()
        header = QLabel(f"<b>{self.finding.get('type','')} — {self.finding.get('severity','')}</b>")
        v.addWidget(header)

        self.txt = QTextEdit()
        self.txt.setReadOnly(False)  # allow selecting & copying; we'll copy programmatically too
        # create formatted full detail text
        pretty = json.dumps(self.finding, indent=2, ensure_ascii=False)
        self.txt.setPlainText(pretty)
        v.addWidget(self.txt)

        btn_row = QHBoxLayout()
        self.btn_copy = QPushButton("Copy to clipboard")
        self.btn_copy.clicked.connect(self.copy_to_clipboard)
        self.btn_export = QPushButton("Export finding as JSON")
        self.btn_export.clicked.connect(self.export_finding_json)
        self.btn_close = QPushButton("Close")
        self.btn_close.clicked.connect(self.accept)
        btn_row.addWidget(self.btn_copy)
        btn_row.addWidget(self.btn_export)
        btn_row.addStretch()
        btn_row.addWidget(self.btn_close)

        v.addLayout(btn_row)
        self.setLayout(v)

    def copy_to_clipboard(self):
        clipboard = QApplication.clipboard()
        clipboard.setText(self.txt.toPlainText())
        QMessageBox.information(self, "Copied", "Finding details copied to clipboard.")

    def export_finding_json(self):
        default_name = f"finding_{self.finding.get('type','unknown')}_{self.finding.get('timestamp','')}.json".replace(":", "-")
        fname, _ = QFileDialog.getSaveFileName(self, "Export Finding JSON", default_name, "JSON files (*.json)")
        if not fname:
            return
        try:
            with open(fname, "w", encoding="utf-8") as fh:
                json.dump(self.finding, fh, indent=2, ensure_ascii=False)
            QMessageBox.information(self, "Saved", f"Finding exported to {fname}")
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to save finding: {e}")

# ----------------------------
# GUI Application
# ----------------------------
class VAPTApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("VAPT Dashboard (Project 2)")
        self.resize(1200, 760)
        self.worker = None
        self.current_results = {}
        self.init_ui()

    def init_ui(self):
        main = QVBoxLayout()
        top = QHBoxLayout()

        self.input_field = QLineEdit()
        self.input_field.setPlaceholderText("Enter URL or domain (example.com, https://example.com)")
        self.btn_scan = QPushButton("Scan")
        self.btn_scan.clicked.connect(self.on_scan)
        self.chk_nmap = QCheckBox("Enable Nmap (intrusive)")
        if not NMAPPER_AVAILABLE:
            self.chk_nmap.setEnabled(False)
            self.chk_nmap.setToolTip("Install python-nmap and nmap CLI for Nmap scanning")
        self.combo_nmap_ports = QComboBox()
        self.combo_nmap_ports.addItems(["Top 100", "Top 200", "Top 1000"])
        self.chk_zap = QCheckBox("Enable OWASP ZAP")
        if not ZAP_AVAILABLE:
            self.chk_zap.setToolTip("Install python-owasp-zap-v2.4 to integrate with ZAP")
        self.chk_zap_active = QCheckBox("Allow ZAP Active Scan (intrusive)")
        self.chk_zap_active.setToolTip("Active scans are intrusive — require explicit permission")
        self.btn_export_json = QPushButton("Export JSON")
        self.btn_export_json.clicked.connect(self.export_json)
        self.btn_export_csv = QPushButton("Export CSV")
        self.btn_export_csv.clicked.connect(self.export_csv)

        top.addWidget(self.input_field)
        top.addWidget(self.btn_scan)
        top.addWidget(self.chk_nmap)
        top.addWidget(self.combo_nmap_ports)
        top.addWidget(self.chk_zap)
        top.addWidget(self.chk_zap_active)
        top.addWidget(self.btn_export_json)
        top.addWidget(self.btn_export_csv)

        splitter = QSplitter(Qt.Horizontal)

        left_w = QWidget()
        left_layout = QVBoxLayout()
        left_w.setLayout(left_layout)
        left_layout.addWidget(QLabel("<b>Target Info</b>"))
        self.txt_info = QTextEdit()
        self.txt_info.setReadOnly(True)
        left_layout.addWidget(self.txt_info)

        right_w = QWidget()
        right_layout = QVBoxLayout()
        right_w.setLayout(right_layout)
        right_layout.addWidget(QLabel("<b>Findings</b>"))
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["Timestamp", "Type", "Severity", "Description", "Evidence"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        # connect double-click to open detail dialog
        self.table.cellDoubleClicked.connect(self.show_finding_details)
        right_layout.addWidget(self.table)

        splitter.addWidget(left_w)
        splitter.addWidget(right_w)
        splitter.setSizes([420, 760])

        self.progress = QProgressBar()
        self.txt_log = QTextEdit()
        self.txt_log.setReadOnly(True)

        main.addLayout(top)
        main.addWidget(splitter)
        main.addWidget(self.progress)
        main.addWidget(QLabel("<b>Log</b>"))
        main.addWidget(self.txt_log)

        self.setLayout(main)

    def log(self, s):
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        self.txt_log.append(f"[{ts}] {s}")

    def add_finding(self, f: dict):
        r = self.table.rowCount()
        self.table.insertRow(r)
        self.table.setItem(r, 0, QTableWidgetItem(f.get("timestamp", "")))
        self.table.setItem(r, 1, QTableWidgetItem(f.get("type", "")))
        self.table.setItem(r, 2, QTableWidgetItem(f.get("severity", "")))
        self.table.setItem(r, 3, QTableWidgetItem(f.get("description", "")))
        ev = f.get("evidence", "")
        ev_text = ev if isinstance(ev, str) else json.dumps(ev)
        if len(ev_text) > 500:
            ev_text = ev_text[:500] + "..."
        self.table.setItem(r, 4, QTableWidgetItem(ev_text))

    def clear_findings(self):
        self.table.setRowCount(0)

    def on_scan(self):
        raw = self.input_field.text().strip()
        if not raw:
            QMessageBox.warning(self, "Input required", "Please enter a URL or domain.")
            return
        try:
            url = normalize_url(raw)
        except Exception:
            QMessageBox.warning(self, "Invalid URL", "Please enter a valid URL or domain, e.g., example.com")
            return

        resp = QMessageBox.question(self, "Authorization required",
                                    "You MUST have explicit written permission to test the target. Do you have permission?",
                                    QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if resp != QMessageBox.Yes:
            QMessageBox.information(self, "Permission required", "Get explicit permission and try again.")
            return

        if self.chk_zap.isChecked() and self.chk_zap_active.isChecked():
            resp2 = QMessageBox.question(self, "Active scan confirmation",
                                         "Active ZAP scans are intrusive. Confirm you have permission to run active tests.",
                                         QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            if resp2 != QMessageBox.Yes:
                QMessageBox.information(self, "Cancelled", "Active scan cancelled.")
                self.chk_zap_active.setChecked(False)

        top_map = {0:100, 1:200, 2:1000}
        top_ports = top_map.get(self.combo_nmap_ports.currentIndex(), 100)
        do_nmap = self.chk_nmap.isChecked()
        zap_opts = {"enabled": self.chk_zap.isChecked(), "address": DEFAULT_ZAP_API_HOST, "port": DEFAULT_ZAP_API_PORT, "apikey": DEFAULT_ZAP_API_KEY, "active": self.chk_zap_active.isChecked()}

        self.btn_scan.setEnabled(False)
        self.clear_findings()
        self.txt_info.clear()
        self.txt_log.clear()
        self.progress.setValue(1)
        self.log(f"Starting scan for {url}")

        self.worker = ScanWorker(url, do_nmap=do_nmap, nmap_top=top_ports, zap_opts=zap_opts)
        self.worker.progress.connect(self.progress.setValue)
        self.worker.info.connect(lambda s: self.txt_info.append(s))
        self.worker.finding.connect(self.handle_finding)
        self.worker.log.connect(self.log)
        self.worker.finished_signal.connect(self.scan_finished)
        self.worker.start()

    def handle_finding(self, f: dict):
        self.add_finding(f)

    def scan_finished(self, results):
        self.current_results = results
        self.btn_scan.setEnabled(True)
        self.progress.setValue(100)
        self.log("Scan finished.")
        counts = {}
        for f in results.get("findings", []):
            sv = f.get("severity", "Unknown")
            counts[sv] = counts.get(sv, 0) + 1
        summary = " | ".join([f"{k}:{v}" for k, v in counts.items()]) or "No findings"
        self.txt_info.append("\nScan summary: " + summary)

    def export_json(self):
        if not getattr(self, "current_results", None):
            QMessageBox.information(self, "No data", "No scan results to export.")
            return
        fname, _ = QFileDialog.getSaveFileName(self, "Save JSON", "vapt_results.json", "JSON files (*.json)")
        if not fname:
            return
        try:
            with open(fname, "w", encoding="utf-8") as fh:
                json.dump(self.current_results, fh, indent=2)
            QMessageBox.information(self, "Saved", f"Saved to {fname}")
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to save: {e}")

    def export_csv(self):
        try:
            import pandas as pd
        except Exception:
            QMessageBox.warning(self, "Missing dependency", "pandas required for CSV export. Install: pip install pandas")
            return
        if not getattr(self, "current_results", None):
            QMessageBox.information(self, "No data", "No scan results to export.")
            return
        fname, _ = QFileDialog.getSaveFileName(self, "Save CSV", "vapt_results.csv", "CSV files (*.csv)")
        if not fname:
            return
        try:
            rows = []
            for f in self.current_results.get("findings", []):
                rows.append({
                    "timestamp": f.get("timestamp"),
                    "type": f.get("type"),
                    "severity": f.get("severity"),
                    "description": f.get("description"),
                    "evidence": f.get("evidence")
                })
            df = pd.DataFrame(rows)
            df.to_csv(fname, index=False)
            QMessageBox.information(self, "Saved", f"CSV exported to {fname}")
        except Exception as e:
            QMessageBox.warning(self, "Error", f"CSV export failed: {e}")

    # ----------------------------
    # New: detail view on double-click
    # ----------------------------
    def show_finding_details(self, row, column):
        # fetch the full data from current_results by matching timestamp + type + description (best-effort)
        if not getattr(self, "current_results", None):
            QMessageBox.information(self, "No details", "No scan results available.")
            return

        # extract visible fields
        ts_item = self.table.item(row, 0)
        type_item = self.table.item(row, 1)
        desc_item = self.table.item(row, 3)
        ev_item = self.table.item(row, 4)
        ts = ts_item.text() if ts_item else ""
        ftype = type_item.text() if type_item else ""
        desc = desc_item.text() if desc_item else ""
        ev = ev_item.text() if ev_item else ""

        # attempt to find the original finding dict
        found = None
        for f in self.current_results.get("findings", []):
            # match by timestamp first (best), else match type+description substring
            if f.get("timestamp") == ts:
                found = f
                break
        if not found:
            # fallback: try type+desc substring matching
            for f in self.current_results.get("findings", []):
                if f.get("type") == ftype and desc in (f.get("description") or ""):
                    found = f
                    break
        # if still not found, construct a dict from visible columns
        if not found:
            found = {
                "timestamp": ts,
                "type": ftype,
                "severity": self.table.item(row, 2).text() if self.table.item(row, 2) else "",
                "description": desc,
                "evidence": ev
            }

        dlg = FindingDetailDialog(self, finding=found)
        dlg.exec_()

# ----------------------------
# Main
# ----------------------------
def main():
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    app = QApplication(sys.argv)
    win = VAPTApp()
    win.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
