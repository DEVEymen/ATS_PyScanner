# ============================================================
# ATS PyScanner 6.0
# Static Security Analyzer
#
# Supports: .py / .pyw / .exe
# IMPORTANT: Files are NEVER executed.
# ============================================================

import ast
import hashlib
import json
import os
import re
import struct
import threading
import subprocess
import shutil
import secrets
import zipfile
import time
import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, ttk


def hide_windows_console():
    """Hide the console window when ATS is launched by python.exe.

    The scanner remains a normal GUI application. On Windows this also
    prevents a black CMD window from appearing when the .py file is
    double-clicked. It does not execute or interact with scanned files.
    """
    if os.name != "nt":
        return
    try:
        import ctypes
        hwnd = ctypes.windll.kernel32.GetConsoleWindow()
        if hwnd:
            ctypes.windll.user32.ShowWindow(hwnd, 0)  # SW_HIDE
    except Exception:
        pass


# ============================================================
# THEME - ATS / Kaspersky-inspired security-suite layout
# (Original styling; no Kaspersky assets or branding.)
# ============================================================

BG = "#f3f6f8"
WHITE = "#ffffff"
TEXT = "#1f2d36"
MUTED = "#73818b"
BORDER = "#dce4e8"
SIDEBAR = "#1d2933"
SIDEBAR_HOVER = "#273742"

GREEN = "#19a463"
GREEN_LIGHT = "#e9f8f1"
BLUE = "#1478c9"
BLUE_LIGHT = "#eaf4fc"
YELLOW = "#d59600"
YELLOW_LIGHT = "#fff7df"
RED = "#d83b4b"
RED_LIGHT = "#fdecef"

FONT = "Segoe UI"
APP_TITLE = "ATS PyScanner"
VERSION = "6.0"


# ============================================================
# RISK ENGINE
# ============================================================

SEVERITY_POINTS = {
    "INFO": 0,
    "DÜŞÜK": 1,
    "ORTA": 3,
    "YÜKSEK": 7,
    "KRİTİK": 12,
}


def calculate_risk(findings):
    """Calculate a heuristic risk level.

    INFO findings deliberately contribute zero points.
    This prevents harmless imports/APIs from turning a file into
    a suspicious result by themselves.
    """
    score = sum(SEVERITY_POINTS.get(f.get("severity"), 0) for f in findings)

    if any(f.get("severity") == "KRİTİK" for f in findings):
        return score, "YÜKSEK RİSK"

    high_count = sum(f.get("severity") == "YÜKSEK" for f in findings)
    medium_count = sum(f.get("severity") == "ORTA" for f in findings)

    if high_count >= 2 or (high_count >= 1 and score >= 10):
        return score, "YÜKSEK RİSK"

    if score >= 4 or medium_count >= 2:
        return score, "ŞÜPHELİ"

    return score, "TEMİZ"


def make_finding(severity, title, description, line=None, code=None):
    return {
        "severity": severity,
        "title": title,
        "description": description,
        "line": line,
        "code": code,
    }


def safe_hash(path):
    sha = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            while True:
                chunk = f.read(1024 * 1024)
                if not chunk:
                    break
                sha.update(chunk)
        return sha.hexdigest()
    except (OSError, PermissionError) as exc:
        return f"Hesaplanamadı: {exc}"


# ============================================================
# PYTHON STATIC ANALYSIS
# ============================================================

class PythonScanner(ast.NodeVisitor):
    def __init__(self, source):
        self.source = source
        self.lines = source.splitlines()
        self.findings = []

    def add(self, severity, title, description, node=None):
        line = getattr(node, "lineno", None) if node else None
        code = None
        if line and 1 <= line <= len(self.lines):
            code = self.lines[line - 1].strip()

        self.findings.append(
            make_finding(severity, title, description, line, code)
        )

    def visit_Import(self, node):
        informational = {
            "requests": (
                "Ağ kütüphanesi",
                "Program HTTP/HTTPS bağlantıları kurabilir."
            ),
            "socket": (
                "Ağ kütüphanesi",
                "Program düşük seviyeli ağ bağlantıları kurabilir."
            ),
            "urllib": (
                "URL kütüphanesi",
                "Program URL üzerinden veri alışverişi yapabilir."
            ),
            "subprocess": (
                "Process kütüphanesi",
                "Program başka işlemler başlatabilir."
            ),
            "ctypes": (
                "Native API kütüphanesi",
                "Program işletim sistemi API'lerine erişebilir."
            ),
            "winreg": (
                "Registry kütüphanesi",
                "Program Windows Registry ile çalışabilir."
            ),
        }

        for alias in node.names:
            module = alias.name.split(".")[0]
            if module in informational:
                title, desc = informational[module]
                self.add("INFO", title, desc, node)

        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        module = (node.module or "").split(".")[0]
        if module in {"requests", "socket", "urllib", "subprocess", "ctypes", "winreg"}:
            self.add(
                "INFO",
                "Sistem/ağ kütüphanesi",
                f"{module} modülü kullanılıyor. Bu tek başına zararlı değildir.",
                node,
            )
        self.generic_visit(node)

    def visit_Call(self, node):
        name = self.get_call_name(node)

        if name == "eval":
            self.add(
                "ORTA",
                "Dinamik kod değerlendirme",
                "eval() çalışma zamanında oluşturulan ifadeleri değerlendirebilir.",
                node,
            )

        elif name == "exec":
            self.add(
                "YÜKSEK",
                "Dinamik Python kodu",
                "exec() çalışma zamanında Python kodu çalıştırabilir.",
                node,
            )

        elif name == "os.system":
            self.add(
                "ORTA",
                "Sistem komutu",
                "İşletim sistemi komutu çalıştırılabilir.",
                node,
            )

        elif name.startswith("subprocess."):
            self.add(
                "INFO",
                "Process başlatma",
                "Program başka bir işlem başlatabilir; bu tek başına tehdit değildir.",
                node,
            )

        elif name in {"os.remove", "os.unlink"}:
            self.add(
                "INFO",
                "Dosya silme işlemi",
                "Program dosya silebilir.",
                node,
            )

        elif name == "shutil.rmtree":
            self.add(
                "ORTA",
                "Toplu klasör silme",
                "Program bir klasör ağacını silebilir.",
                node,
            )

        last = name.split(".")[-1] if name else ""
        if last in {"b64decode", "urlsafe_b64decode"}:
            self.add(
                "INFO",
                "Base64 çözme",
                "Kodlanmış veri çözülebilir. Base64 kullanımı tek başına zararlı değildir.",
                node,
            )

        if last in {"CDLL", "WinDLL", "OleDLL", "PyDLL"}:
            self.add(
                "ORTA",
                "Native DLL yükleme",
                "Program harici native DLL yükleyebilir.",
                node,
            )

        self.generic_visit(node)

    def visit_Constant(self, node):
        if isinstance(node.value, str):
            value = node.value
            lower = value.lower()

            patterns = {
                "powershell -enc": (
                    "YÜKSEK",
                    "Encoded PowerShell",
                    "Kodlanmış PowerShell komutu izi bulundu."
                ),
                "-encodedcommand": (
                    "YÜKSEK",
                    "Encoded PowerShell",
                    "PowerShell'in kodlanmış komut parametresi bulundu."
                ),
                "invoke-expression": (
                    "YÜKSEK",
                    "PowerShell dinamik komut",
                    "PowerShell üzerinden dinamik komut çalıştırma göstergesi bulundu."
                ),
                "downloadstring": (
                    "YÜKSEK",
                    "Uzak içerik indirme",
                    "Uzak kaynaktan içerik alıp çalıştırmaya yönelik bir gösterge bulundu."
                ),
                "frombase64string": (
                    "YÜKSEK",
                    "PowerShell Base64 çözme",
                    "PowerShell Base64 çözme göstergesi bulundu."
                ),
                "wscript.shell": (
                    "ORTA",
                    "Windows Script Shell",
                    "Windows Script Shell kullanımı için bir gösterge bulundu."
                ),
                "certutil -decode": (
                    "YÜKSEK",
                    "CertUtil veri çözme",
                    "CertUtil ile kodlanmış/veri halindeki içeriği çözmeye yönelik bir gösterge bulundu."
                ),
            }

            for pattern, info in patterns.items():
                if pattern in lower:
                    sev, title, desc = info
                    self.add(sev, title, desc, node)

            # Long strings are only informational.
            if len(value) > 3000:
                self.add(
                    "INFO",
                    "Uzun string",
                    "Dosyada olağandışı uzunlukta bir metin bulundu. Bu tek başına kötü amaçlılık göstergesi değildir.",
                    node,
                )

        self.generic_visit(node)

    @staticmethod
    def get_call_name(node):
        current = node.func

        if isinstance(current, ast.Name):
            return current.id

        if isinstance(current, ast.Attribute):
            parts = []
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value

            if isinstance(current, ast.Name):
                parts.append(current.id)
                return ".".join(reversed(parts))

        return None


def scan_python(path):
    try:
        source = path.read_text(encoding="utf-8", errors="replace")
    except (OSError, PermissionError) as exc:
        return {"error": f"Dosya okunamadı: {exc}", "path": str(path)}

    scanner = PythonScanner(source)

    try:
        tree = ast.parse(source, filename=str(path))
        scanner.visit(tree)
    except SyntaxError as exc:
        # A syntax error is a code-quality issue, not proof of malware.
        scanner.findings.append(
            make_finding(
                "INFO",
                "Python syntax hatası",
                "Dosya standart Python sözdizimine göre parse edilemedi.",
                exc.lineno,
                None,
            )
        )
    except Exception as exc:
        scanner.findings.append(
            make_finding(
                "INFO",
                "AST analiz uyarısı",
                f"Python AST analizi tamamlanamadı: {exc}",
            )
        )

    lines = source.splitlines()

    regex_rules = [
        (
            r"powershell(?:\.exe)?\s+-(?:enc|encodedcommand)\b",
            "YÜKSEK",
            "Encoded PowerShell",
            "Kodlanmış PowerShell komutu çalıştırılabilir."
        ),
        (
            r"invoke-expression",
            "YÜKSEK",
            "PowerShell dinamik komut",
            "PowerShell üzerinden dinamik komut çalıştırılabilir."
        ),
        (
            r"downloadstring\s*\(",
            "YÜKSEK",
            "Uzak içerik çalıştırma göstergesi",
            "Uzak kaynaktan içerik alma/işleme göstergesi bulundu."
        ),
    ]

    for number, line in enumerate(lines, 1):
        for pattern, severity, title, description in regex_rules:
            if re.search(pattern, line, re.IGNORECASE):
                scanner.findings.append(
                    make_finding(
                        severity, title, description, number, line.strip()
                    )
                )

    # Deduplicate by actual location where possible.
    unique = {}
    for finding in scanner.findings:
        key = (
            finding["severity"],
            finding["title"],
            finding.get("line"),
            finding.get("code"),
        )
        unique[key] = finding

    findings = list(unique.values())
    findings.sort(key=lambda x: (x.get("line") or 0, x["severity"], x["title"]))

    score, risk = calculate_risk(findings)

    return {
        "path": str(path),
        "type": path.suffix.lower(),
        "findings": findings,
        "score": score,
        "risk": risk,
        "hash": safe_hash(path),
        "size": path.stat().st_size if path.exists() else 0,
    }


# ============================================================
# PE / EXE ANALYZER
# ============================================================

class PEAnalyzer:
    def __init__(self, path):
        self.path = Path(path)
        self.data = b""
        self.findings = []
        self.architecture = "Bilinmiyor"
        self.subsystem = "Bilinmiyor"
        self.strings = []
        self.is_pe = False

    def add(self, severity, title, description):
        self.findings.append(
            make_finding(severity, title, description)
        )

    def read(self):
        with self.path.open("rb") as f:
            # A practical upper bound prevents a huge file from consuming
            # excessive RAM just for string extraction.
            self.data = f.read(128 * 1024 * 1024)

    def headers(self):
        data = self.data

        if len(data) < 64:
            self.add(
                "ORTA",
                "Eksik DOS header",
                "Dosya PE yapısı için yeterli büyüklükte değil."
            )
            return

        if data[:2] != b"MZ":
            self.add(
                "ORTA",
                "MZ header bulunamadı",
                "Dosya .exe uzantısına sahip ancak standart PE başlangıcı bulunamadı."
            )
            return

        pe_offset = struct.unpack_from("<I", data, 0x3C)[0]

        if pe_offset < 64 or pe_offset + 24 > len(data):
            self.add(
                "ORTA",
                "PE header okunamadı",
                "PE header konumu geçersiz veya dosya eksik."
            )
            return

        if data[pe_offset:pe_offset + 4] != b"PE\x00\x00":
            self.add(
                "ORTA",
                "Geçersiz PE signature",
                "PE signature bulunamadı."
            )
            return

        self.is_pe = True

        machine = struct.unpack_from("<H", data, pe_offset + 4)[0]
        self.architecture = {
            0x014C: "x86 / 32-bit",
            0x8664: "x64 / 64-bit",
            0xAA64: "ARM64",
            0x01C4: "ARM",
        }.get(machine, f"Bilinmeyen (0x{machine:04X})")

        optional_offset = pe_offset + 24
        if optional_offset + 70 <= len(data):
            magic = struct.unpack_from("<H", data, optional_offset)[0]
            if magic not in (0x10B, 0x20B):
                self.add(
                    "ORTA",
                    "Geçersiz Optional Header",
                    "PE Optional Header magic değeri beklenen formatlardan biri değil."
                )
                return

            subsystem = struct.unpack_from(
                "<H", data, optional_offset + 68
            )[0]

            self.subsystem = {
                2: "Windows GUI",
                3: "Windows Console",
            }.get(subsystem, f"Diğer ({subsystem})")

    def extract_strings(self):
        # ASCII
        for raw in re.findall(rb"[\x20-\x7e]{5,}", self.data):
            try:
                self.strings.append(raw.decode("ascii", errors="ignore"))
            except Exception:
                pass

        # UTF-16LE
        for raw in re.findall(rb"(?:[\x20-\x7e]\x00){5,}", self.data):
            try:
                self.strings.append(
                    raw.decode("utf-16le", errors="ignore")
                )
            except Exception:
                pass

        # Keep memory bounded and remove duplicates.
        self.strings = list(dict.fromkeys(self.strings))[:100000]

    def inspect_strings(self):
        rules = {
            "powershell -enc": (
                "YÜKSEK",
                "Encoded PowerShell",
                "Dosyada kodlanmış PowerShell komutu izi bulundu."
            ),
            "-encodedcommand": (
                "YÜKSEK",
                "Encoded PowerShell",
                "PowerShell'in kodlanmış komut parametresi için bir gösterge bulundu."
            ),
            "downloadstring": (
                "YÜKSEK",
                "Uzak içerik indirme",
                "Uzak bir kaynaktan içerik alma/işleme göstergesi bulundu."
            ),
            "invoke-expression": (
                "YÜKSEK",
                "Dinamik PowerShell",
                "PowerShell dinamik komut çalıştırma göstergesi bulundu."
            ),
            "wscript.shell": (
                "ORTA",
                "Windows Script Shell",
                "Windows Script Shell kullanımı için bir gösterge bulundu."
            ),
            "regsetvalue": (
                "ORTA",
                "Registry yazma",
                "Windows Registry değerlerini değiştirme göstergesi bulundu."
            ),
            "createprocess": (
                "INFO",
                "Process API",
                "Başka bir işlem başlatabilen bir API adı bulundu."
            ),
            "deletefile": (
                "INFO",
                "Dosya silme API",
                "Dosya silebilen bir API adı bulundu."
            ),
            "virtualalloc": (
                "INFO",
                "Bellek API",
                "Çalışma zamanında bellek ayırabilen bir API adı bulundu."
            ),
        }

        found = set()
        for text in self.strings:
            lower = text.lower()
            for key, info in rules.items():
                if key in lower and key not in found:
                    found.add(key)
                    sev, title, desc = info
                    self.add(sev, title, desc)

    def analyze(self):
        try:
            self.read()
            self.headers()
            if self.is_pe:
                self.extract_strings()
                self.inspect_strings()
        except (OSError, PermissionError) as exc:
            return {
                "error": f"EXE okunamadı: {exc}",
                "path": str(self.path),
            }
        except Exception as exc:
            return {
                "error": f"PE analizi sırasında hata: {exc}",
                "path": str(self.path),
            }

        score, risk = calculate_risk(self.findings)

        return {
            "path": str(self.path),
            "type": ".exe",
            "findings": self.findings,
            "score": score,
            "risk": risk,
            "hash": safe_hash(self.path),
            "architecture": self.architecture,
            "subsystem": self.subsystem,
            "string_count": len(self.strings),
            "size": self.path.stat().st_size if self.path.exists() else 0,
        }


# ============================================================
# GENERAL SCANNER
# ============================================================

SUPPORTED = {".py", ".pyw", ".exe", ".zip"}


def get_authenticode_status(path):
    """Check a selected Windows executable's Authenticode signature.
    This invokes PowerShell itself, never the selected target file.
    """
    if os.name != "nt" or Path(path).suffix.lower() != ".exe":
        return {"status": "UYGULANAMAZ", "signer": "-", "message": "Yalnızca Windows .exe dosyalarında kullanılabilir."}
    ps = (
        "$s=Get-AuthenticodeSignature -LiteralPath "
        + "'" + str(Path(path)).replace("'", "''") + "'; "
        + "$o=[ordered]@{Status=[string]$s.Status;Signer=if($s.SignerCertificate){$s.SignerCertificate.Subject}else{'-'};Message=[string]$s.StatusMessage}; "
        + "$o|ConvertTo-Json -Compress"
    )
    try:
        cp = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ps],
                            capture_output=True, text=True, timeout=12, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        if cp.returncode != 0:
            return {"status":"BİLİNMİYOR", "signer":"-", "message":cp.stderr.strip() or "İmza kontrolü başarısız."}
        data = json.loads(cp.stdout.strip() or "{}")
        return {"status": data.get("Status", "BİLİNMİYOR"), "signer": data.get("Signer", "-"), "message": data.get("Message", "")}
    except Exception as exc:
        return {"status":"BİLİNMİYOR", "signer":"-", "message":str(exc)}


def quarantine_file(path):
    """Move a user-selected file into ATS quarantine without executing it."""
    src = Path(path)
    if not src.exists() or not src.is_file():
        return False, "Dosya bulunamadı."
    qdir = Path(r"D:\Anti-virüs\Karantina")
    try:
        # The user-selected quarantine location is intentionally fixed.
        # Do not silently fall back to another drive/location.
        if not qdir.drive or not Path(qdir.drive + "\\").exists():
            return False, "D: sürücüsü bulunamadı; karantina konumu D:\\Anti-virüs\\Karantina olarak ayarlı."
        qdir.mkdir(parents=True, exist_ok=True)
        token = secrets.token_hex(12)
        dest = qdir / f"{token}_{src.name}"
        shutil.move(str(src), str(dest))
        meta = dest.with_suffix(dest.suffix + ".json")
        meta.write_text(json.dumps({"original_path": str(src), "quarantined_at": datetime.now().isoformat()}, ensure_ascii=False, indent=2), encoding="utf-8")
        return True, str(dest)
    except Exception as exc:
        return False, str(exc)


def scan_zip(path):
    """Inspect ZIP members statically; never execute or extract them."""
    findings=[]
    try:
        with zipfile.ZipFile(path, "r") as z:
            names=z.namelist()
            supported=[n for n in names if Path(n).suffix.lower() in {".py",".pyw",".exe"}]
            for n in supported[:200]:
                ext=Path(n).suffix.lower()
                if ext in {".py",".pyw"}:
                    findings.append(make_finding("INFO", "Arşivde Python dosyası", f"ZIP içinde analiz edilebilir Python üyesi bulundu: {n}"))
                elif ext==".exe":
                    findings.append(make_finding("INFO", "Arşivde EXE dosyası", f"ZIP içinde Windows çalıştırılabilir dosya bulundu: {n}"))
            if len(names)>200:
                findings.append(make_finding("INFO", "Arşiv sınırı", "İlk 200 desteklenen üye değerlendirildi."))
            score,risk=calculate_risk(findings)
            return {"path":str(path),"type":".zip","hash":safe_hash(path),"score":score,"risk":risk,"findings":findings,"member_count":len(names),"supported_members":len(supported)}
    except zipfile.BadZipFile:
        return {"error":"Geçersiz veya bozuk ZIP arşivi.","path":str(path)}
    except Exception as exc:
        return {"error":f"ZIP analizi başarısız: {exc}","path":str(path)}


def scan_file(path):
    path = Path(path)

    if not path.exists():
        return {"error": "Dosya bulunamadı.", "path": str(path)}

    if not path.is_file():
        return {"error": "Seçilen öğe bir dosya değil.", "path": str(path)}

    suffix = path.suffix.lower()

    if suffix in {".py", ".pyw"}:
        return scan_python(path)

    if suffix == ".exe":
        result = PEAnalyzer(path).analyze()
        result["signature"] = get_authenticode_status(path)
        if result.get("signature", {}).get("status") == "NotSigned":
            result.setdefault("findings", []).append(make_finding("INFO", "Dijital imza yok", "EXE dosyasında geçerli Authenticode imzası bulunamadı; bu tek başına zararlı olduğu anlamına gelmez."))
        return result

    if suffix == ".zip":
        return scan_zip(path)

    return {
        "error": f"Desteklenmeyen dosya türü: {suffix or 'uzantısız'}",
        "path": str(path),
    }


# ============================================================
# GUI HELPERS
# ============================================================

class ScrollableFrame(tk.Frame):
    """Simple Tkinter scrollable content area."""

    def __init__(self, parent, bg=BG):
        super().__init__(parent, bg=bg)

        self.canvas = tk.Canvas(
            self,
            bg=bg,
            highlightthickness=0,
            bd=0,
        )
        self.scrollbar = ttk.Scrollbar(
            self,
            orient="vertical",
            command=self.canvas.yview,
        )
        self.inner = tk.Frame(self.canvas, bg=bg)

        self.window_id = self.canvas.create_window(
            (0, 0),
            window=self.inner,
            anchor="nw",
        )

        self.canvas.configure(yscrollcommand=self.scrollbar.set)

        self.canvas.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")

        self.inner.bind("<Configure>", self._update_scroll)
        self.canvas.bind("<Configure>", self._resize_inner)

        self.canvas.bind_all("<MouseWheel>", self._wheel)

    def _update_scroll(self, _event=None):
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))

    def _resize_inner(self, event):
        self.canvas.itemconfigure(self.window_id, width=event.width)

    def _wheel(self, event):
        try:
            self.canvas.yview_scroll(int(-event.delta / 120), "units")
        except Exception:
            pass


# ============================================================
# APPLICATION
# ============================================================

class ATSApp:
    def __init__(self, root):
        self.root = root
        self.root.title(f"{APP_TITLE} {VERSION}")
        self.root.geometry("1240x780")
        self.root.minsize(1000, 650)
        self.root.configure(bg=BG)

        self.scanning = False
        self.cancel_requested = False
        self.scan_files = []
        self.scan_results = []
        self.last_scan_results = []
        self.history = []

        self.history_file = Path.home() / ".ats_pyscanner_history.json"

        self._load_history()
        self._build_style()
        self._build_shell()
        self.show_dashboard()

        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    # --------------------------------------------------------
    # STYLE
    # --------------------------------------------------------

    def _build_style(self):
        style = ttk.Style()
        style.theme_use("clam")

        style.configure(
            "ATS.Horizontal.TProgressbar",
            troughcolor="#dfe6ea",
            background=GREEN,
            bordercolor="#dfe6ea",
            lightcolor=GREEN,
            darkcolor=GREEN,
        )

        style.configure(
            "ATS.Vertical.TScrollbar",
            troughcolor=BG,
            background="#c5d0d6",
            bordercolor=BG,
            arrowcolor=MUTED,
        )

    # --------------------------------------------------------
    # SHELL
    # --------------------------------------------------------

    def _build_shell(self):
        header = tk.Frame(self.root, bg=WHITE, height=68)
        header.pack(fill="x")
        header.pack_propagate(False)

        logo = tk.Frame(header, bg=WHITE)
        logo.pack(side="left", padx=24)

        tk.Label(
            logo,
            text="ATS",
            font=(FONT, 23, "bold"),
            fg=GREEN,
            bg=WHITE,
        ).pack(side="left")

        tk.Label(
            logo,
            text="  PyScanner",
            font=(FONT, 16, "bold"),
            fg=TEXT,
            bg=WHITE,
        ).pack(side="left")

        self.header_status = tk.Label(
            header,
            text="● HAZIR",
            font=(FONT, 9, "bold"),
            fg=GREEN,
            bg=GREEN_LIGHT,
            padx=13,
            pady=6,
        )
        self.header_status.pack(side="right", padx=24)

        body = tk.Frame(self.root, bg=BG)
        body.pack(fill="both", expand=True)

        self.sidebar = tk.Frame(body, bg=SIDEBAR, width=225)
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)

        tk.Label(
            self.sidebar,
            text="GÜVENLİK MERKEZİ",
            font=(FONT, 8, "bold"),
            fg="#8797a2",
            bg=SIDEBAR,
        ).pack(anchor="w", padx=23, pady=(24, 10))

        self.menu_buttons = []

        self._add_menu("01   Genel Bakış", self.show_dashboard)
        self._add_menu("02   Dosya Tara", self.choose_file)
        self._add_menu("03   Klasör Tara", self.choose_folder)
        self._add_menu("04   Tarama Geçmişi", self.show_history)

        tk.Label(
            self.sidebar,
            text="ANALİZ ARAÇLARI",
            font=(FONT, 8, "bold"),
            fg="#8797a2",
            bg=SIDEBAR,
        ).pack(anchor="w", padx=23, pady=(25, 10))

        self._add_menu("05   Python Analizi", self.choose_python)
        self._add_menu("06   EXE Analizi", self.choose_exe)
        self._add_menu("07   Ayarlar", self.show_settings)

        tk.Label(
            self.sidebar,
            text=f"ATS PyScanner {VERSION}\nStatik analiz motoru",
            font=(FONT, 8),
            fg="#667681",
            bg=SIDEBAR,
            justify="left",
        ).pack(side="bottom", anchor="w", padx=23, pady=20)

        self.content = tk.Frame(body, bg=BG)
        self.content.pack(side="left", fill="both", expand=True)

    def _add_menu(self, text, command):
        button = tk.Button(
            self.sidebar,
            text=text,
            command=command,
            anchor="w",
            bg=SIDEBAR,
            fg="#d8e1e6",
            activebackground=SIDEBAR_HOVER,
            activeforeground=WHITE,
            relief="flat",
            bd=0,
            font=(FONT, 10),
            padx=23,
            pady=12,
            cursor="hand2",
        )
        button.pack(fill="x")
        self.menu_buttons.append(button)

    # --------------------------------------------------------
    # COMMON UI
    # --------------------------------------------------------

    def clear_content(self):
        for widget in self.content.winfo_children():
            widget.destroy()

    def page_title(self, title, subtitle=None):
        tk.Label(
            self.content,
            text=title,
            font=(FONT, 24, "bold"),
            fg=TEXT,
            bg=BG,
        ).pack(anchor="w", padx=36, pady=(30, 3))

        if subtitle:
            tk.Label(
                self.content,
                text=subtitle,
                font=(FONT, 10),
                fg=MUTED,
                bg=BG,
            ).pack(anchor="w", padx=36)

    def make_button(self, parent, text, command, kind="green", **kwargs):
        colors = {
            "green": (GREEN, "#12804d", WHITE),
            "blue": (BLUE, "#0f5f9d", WHITE),
            "white": (WHITE, "#eef2f4", TEXT),
            "red": (RED, "#b92d3b", WHITE),
        }
        bg, active, fg = colors.get(kind, colors["green"])

        return tk.Button(
            parent,
            text=text,
            command=command,
            bg=bg,
            activebackground=active,
            fg=fg,
            activeforeground=fg,
            relief="flat",
            bd=0,
            font=(FONT, 9, "bold"),
            padx=22,
            pady=10,
            cursor="hand2",
            **kwargs,
        )

    def _set_header(self, text, state="ready"):
        states = {
            "ready": (GREEN, GREEN_LIGHT),
            "scan": (YELLOW, YELLOW_LIGHT),
            "danger": (RED, RED_LIGHT),
            "info": (BLUE, BLUE_LIGHT),
        }
        fg, bg = states.get(state, states["ready"])
        self.header_status.config(text=text, fg=fg, bg=bg)

    # --------------------------------------------------------
    # DASHBOARD
    # --------------------------------------------------------

    def show_dashboard(self):
        if self.scanning:
            return

        self.clear_content()
        self._set_header("● HAZIR", "ready")

        self.page_title(
            "Genel Bakış",
            "Dosyaları çalıştırmadan statik güvenlik analizi yapın."
        )

        # Main protection card
        card = tk.Frame(
            self.content,
            bg=WHITE,
            highlightbackground=BORDER,
            highlightthickness=1,
        )
        card.pack(fill="x", padx=36, pady=24)

        shield = tk.Frame(card, bg=GREEN_LIGHT, width=110, height=110)
        shield.pack(side="left", padx=25, pady=25)
        shield.pack_propagate(False)

        tk.Label(
            shield,
            text="✓",
            font=(FONT, 42, "bold"),
            fg=GREEN,
            bg=GREEN_LIGHT,
        ).place(relx=.5, rely=.5, anchor="center")

        info = tk.Frame(card, bg=WHITE)
        info.pack(side="left", fill="both", expand=True, pady=25)

        tk.Label(
            info,
            text="Koruma merkezi hazır",
            font=(FONT, 18, "bold"),
            fg=TEXT,
            bg=WHITE,
        ).pack(anchor="w")

        tk.Label(
            info,
            text="ATS PyScanner Python ve Windows PE dosyalarını statik olarak analiz eder.",
            font=(FONT, 9),
            fg=MUTED,
            bg=WHITE,
        ).pack(anchor="w", pady=(5, 12))

        badges = tk.Frame(info, bg=WHITE)
        badges.pack(anchor="w")

        self._badge(badges, "PYTHON AST", BLUE_LIGHT, BLUE)
        self._badge(badges, "PE ANALİZ", BLUE_LIGHT, BLUE)
        self._badge(badges, "DOSYA ÇALIŞTIRILMAZ", GREEN_LIGHT, GREEN)

        self.make_button(
            card,
            "TARAMA BAŞLAT",
            self.choose_file,
            "green",
        ).pack(side="right", padx=25)

        # Statistics
        stats = tk.Frame(self.content, bg=BG)
        stats.pack(fill="x", padx=31)

        self._stat_card(stats, "SON TARAMA", self._last_scan_text())
        self._stat_card(stats, "BULGU", str(self._last_finding_count()))
        self._stat_card(stats, "TARANAN", str(self._last_file_count()))

        # Scan cards
        tk.Label(
            self.content,
            text="Hızlı tarama",
            font=(FONT, 14, "bold"),
            fg=TEXT,
            bg=BG,
        ).pack(anchor="w", padx=36, pady=(28, 10))

        row = tk.Frame(self.content, bg=BG)
        row.pack(fill="x", padx=31)

        self._action_card(
            row,
            "01",
            "Tek Dosya",
            "PY / PYW / EXE",
            self.choose_file,
        )
        self._action_card(
            row,
            "02",
            "Klasör",
            "Desteklenen dosyaları tara",
            self.choose_folder,
        )
        self._action_card(
            row,
            "03",
            "EXE Analizi",
            "Windows PE statik analiz",
            self.choose_exe,
        )

        note = tk.Frame(
            self.content,
            bg=BLUE_LIGHT,
            highlightbackground="#d7e8f5",
            highlightthickness=1,
        )
        note.pack(fill="x", padx=36, pady=22)

        tk.Label(
            note,
            text="ⓘ",
            font=(FONT, 16, "bold"),
            fg=BLUE,
            bg=BLUE_LIGHT,
        ).pack(side="left", padx=(15, 8), pady=13)

        tk.Label(
            note,
            text="Bu motor sezgiseldir. 'Şüpheli' sonucu tek başına dosyanın zararlı olduğunu kanıtlamaz.",
            font=(FONT, 9),
            fg=TEXT,
            bg=BLUE_LIGHT,
        ).pack(side="left", pady=13)

    def _badge(self, parent, text, bg, fg):
        tk.Label(
            parent,
            text=text,
            font=(FONT, 7, "bold"),
            fg=fg,
            bg=bg,
            padx=8,
            pady=4,
        ).pack(side="left", padx=(0, 6))

    def _stat_card(self, parent, title, value):
        frame = tk.Frame(
            parent,
            bg=WHITE,
            highlightbackground=BORDER,
            highlightthickness=1,
        )
        frame.pack(side="left", fill="both", expand=True, padx=5)

        tk.Label(
            frame,
            text=title,
            font=(FONT, 8, "bold"),
            fg=MUTED,
            bg=WHITE,
        ).pack(anchor="w", padx=16, pady=(13, 3))

        tk.Label(
            frame,
            text=value,
            font=(FONT, 16, "bold"),
            fg=TEXT,
            bg=WHITE,
        ).pack(anchor="w", padx=16, pady=(0, 13))

    def _action_card(self, parent, icon, title, subtitle, command):
        frame = tk.Frame(
            parent,
            bg=WHITE,
            highlightbackground=BORDER,
            highlightthickness=1,
            cursor="hand2",
        )
        frame.pack(side="left", fill="both", expand=True, padx=5)

        tk.Label(
            frame,
            text=icon,
            font=(FONT, 23, "bold"),
            fg=GREEN,
            bg=WHITE,
        ).pack(anchor="w", padx=16, pady=(14, 2))

        tk.Label(
            frame,
            text=title,
            font=(FONT, 11, "bold"),
            fg=TEXT,
            bg=WHITE,
        ).pack(anchor="w", padx=16)

        tk.Label(
            frame,
            text=subtitle,
            font=(FONT, 8),
            fg=MUTED,
            bg=WHITE,
        ).pack(anchor="w", padx=16, pady=(2, 14))

        for widget in frame.winfo_children():
            widget.bind("<Button-1>", lambda _e, c=command: c())

        frame.bind("<Button-1>", lambda _e: command())

    # --------------------------------------------------------
    # FILE PICKERS
    # --------------------------------------------------------

    def choose_file(self):
        if self.scanning:
            return

        path = filedialog.askopenfilename(
            title="Dosya seç",
            filetypes=[
                ("ATS desteklenen dosyalar", "*.py *.pyw *.exe *.zip"),
                ("Python", "*.py *.pyw"),
                ("Windows Executable", "*.exe"),
                ("Tüm dosyalar", "*.*"),
            ],
        )

        if path:
            self.start_scan([Path(path)])

    def choose_python(self):
        if self.scanning:
            return

        path = filedialog.askopenfilename(
            title="Python dosyası seç",
            filetypes=[("Python", "*.py *.pyw")],
        )

        if path:
            self.start_scan([Path(path)])

    def choose_exe(self):
        if self.scanning:
            return

        path = filedialog.askopenfilename(
            title="EXE dosyası seç",
            filetypes=[("Windows Executable", "*.exe")],
        )

        if path:
            self.start_scan([Path(path)])

    def choose_folder(self):
        if self.scanning:
            return

        folder = filedialog.askdirectory(title="Klasör seç")
        if not folder:
            return

        files = []
        try:
            for path in Path(folder).rglob("*"):
                try:
                    if path.is_file() and path.suffix.lower() in SUPPORTED:
                        files.append(path)
                except OSError:
                    continue
        except OSError as exc:
            messagebox.showerror("Klasör hatası", str(exc))
            return

        # Prevent accidentally scanning an enormous tree.
        files.sort(key=lambda p: str(p).lower())

        if not files:
            messagebox.showinfo(
                APP_TITLE,
                "Bu klasörde desteklenen .py, .pyw, .exe veya .zip dosyası bulunamadı."
            )
            return

        self.start_scan(files)

    # --------------------------------------------------------
    # SCAN
    # --------------------------------------------------------

    def start_scan(self, files):
        if self.scanning or not files:
            return

        # Remove duplicates while preserving order.
        unique = []
        seen = set()
        for p in files:
            try:
                key = str(Path(p).resolve()).lower()
            except Exception:
                key = str(p).lower()

            if key not in seen:
                seen.add(key)
                unique.append(Path(p))

        self.scan_files = unique
        self.scan_results = []
        self.cancel_requested = False
        self.scanning = True

        self.clear_content()
        self._set_header("● TARANIYOR", "scan")
        self._build_scan_screen(len(self.scan_files))

        threading.Thread(
            target=self._scan_worker,
            daemon=True,
        ).start()

    def _build_scan_screen(self, total):
        tk.Label(
            self.content,
            text="Güvenlik taraması",
            font=(FONT, 25, "bold"),
            fg=TEXT,
            bg=BG,
        ).pack(pady=(45, 4))

        tk.Label(
            self.content,
            text="Dosyalar çalıştırılmadan analiz ediliyor",
            font=(FONT, 10),
            fg=MUTED,
            bg=BG,
        ).pack()

        self.scan_icon = tk.Label(
            self.content,
            text="◈",
            font=(FONT, 72, "bold"),
            fg=GREEN,
            bg=BG,
        )
        self.scan_icon.pack(pady=30)

        self.scan_title = tk.Label(
            self.content,
            text="Analiz motoru hazırlanıyor...",
            font=(FONT, 16, "bold"),
            fg=TEXT,
            bg=BG,
        )
        self.scan_title.pack()

        self.scan_file_label = tk.Label(
            self.content,
            text="",
            font=(FONT, 9),
            fg=MUTED,
            bg=BG,
        )
        self.scan_file_label.pack(pady=7)

        self.scan_progress = ttk.Progressbar(
            self.content,
            style="ATS.Horizontal.TProgressbar",
            maximum=max(total, 1),
            value=0,
        )
        self.scan_progress.pack(fill="x", padx=130, pady=20)

        self.scan_counter = tk.Label(
            self.content,
            text=f"0 / {total}",
            font=(FONT, 10, "bold"),
            fg=BLUE,
            bg=BG,
        )
        self.scan_counter.pack()

        self.scan_status = tk.Label(
            self.content,
            text="Dosya statik analiz için hazırlanıyor...",
            font=(FONT, 9),
            fg=MUTED,
            bg=BG,
        )
        self.scan_status.pack(pady=14)

        self.make_button(
            self.content,
            "TARAMAYI İPTAL ET",
            self.request_cancel,
            "white",
        ).pack(pady=10)

        self._animate_scan()

    def _animate_scan(self):
        if not self.scanning or not hasattr(self, "scan_icon"):
            return

        icons = ["◈", "◇", "◆", "◇"]
        idx = int(time.time() * 5) % len(icons)

        try:
            self.scan_icon.config(text=icons[idx])
        except tk.TclError:
            return

        self.root.after(180, self._animate_scan)

    def request_cancel(self):
        if not self.scanning:
            return
        self.cancel_requested = True
        self.scan_status.config(text="İptal isteniyor... mevcut dosya tamamlanıyor.")

    def _scan_worker(self):
        total = len(self.scan_files)

        for index, path in enumerate(self.scan_files, 1):
            if self.cancel_requested:
                break

            self.root.after(
                0,
                lambda p=path, i=index: self._update_scan_progress(
                    p, i, total
                ),
            )

            result = scan_file(path)
            self.scan_results.append(result)

        self.root.after(0, self.show_scan_result)

    def _update_scan_progress(self, path, index, total):
        if not self.scanning:
            return

        self.scan_file_label.config(text=str(path))
        self.scan_counter.config(text=f"{index} / {total}")
        self.scan_progress["value"] = index

        self.scan_title.config(text="Dosya statik olarak analiz ediliyor...")
        self.scan_status.config(text="AST / PE / string göstergeleri kontrol ediliyor...")

    # --------------------------------------------------------
    # RESULTS
    # --------------------------------------------------------

    def show_scan_result(self):
        self.scanning = False

        results = list(self.scan_results)
        valid_results = [r for r in results if "error" not in r]
        errors = [r for r in results if "error" in r]

        total_findings = sum(len(r.get("findings", [])) for r in valid_results)
        high_risk = sum(
            1 for r in valid_results if r.get("risk") == "YÜKSEK RİSK"
        )
        suspicious = sum(
            1 for r in valid_results if r.get("risk") == "ŞÜPHELİ"
        )

        self.last_scan_results = results
        self._save_history(results)

        if high_risk:
            self._set_header("● ŞÜPHELİ BULGU", "danger")
            title = "Daha ayrıntılı inceleme gerekli"
            color = RED
            icon = "!"
            subtitle = "Bazı dosyalarda yüksek riskli davranış göstergeleri bulundu."
        elif suspicious:
            self._set_header("● ŞÜPHELİ BULGU", "scan")
            title = "Şüpheli göstergeler bulundu"
            color = YELLOW
            icon = "!"
            subtitle = "Bazı davranışlar daha ayrıntılı incelenmelidir."
        else:
            self._set_header("● TARAMA TAMAMLANDI", "ready")
            title = "Tarama tamamlandı"
            color = GREEN
            icon = "✓"
            subtitle = "Yüksek riskli bilinen davranış göstergesi bulunmadı."

        self.clear_content()

        tk.Label(
            self.content,
            text=icon,
            font=(FONT, 48, "bold"),
            fg=color,
            bg=BG,
        ).pack(pady=(42, 2))

        tk.Label(
            self.content,
            text=title,
            font=(FONT, 23, "bold"),
            fg=TEXT,
            bg=BG,
        ).pack()

        tk.Label(
            self.content,
            text=subtitle,
            font=(FONT, 10),
            fg=MUTED,
            bg=BG,
        ).pack(pady=5)

        stats = tk.Frame(self.content, bg=BG)
        stats.pack(fill="x", padx=75, pady=28)

        self._result_stat(stats, "TARANAN", str(len(valid_results)))
        self._result_stat(stats, "BULGU", str(total_findings))
        self._result_stat(stats, "YÜKSEK RİSK", str(high_risk))
        self._result_stat(stats, "OKUNAMADI", str(len(errors)))

        action = tk.Frame(self.content, bg=BG)
        action.pack(pady=5)

        self.make_button(
            action,
            "AYRINTILI RAPOR",
            self.show_report,
            "blue",
        ).pack(side="left", padx=5)

        self.make_button(
            action,
            "ANA MENÜ",
            self.show_dashboard,
            "white",
        ).pack(side="left", padx=5)

        if errors:
            note = f"{len(errors)} dosya okunamadı veya analiz edilemedi. Ayrıntılar raporda."
        else:
            note = "Not: Sezgisel analiz sonucu kesin malware tespiti anlamına gelmez."

        tk.Label(
            self.content,
            text=note,
            font=(FONT, 9),
            fg=MUTED,
            bg=BG,
        ).pack(pady=18)

    def _result_stat(self, parent, title, value):
        frame = tk.Frame(
            parent,
            bg=WHITE,
            highlightbackground=BORDER,
            highlightthickness=1,
        )
        frame.pack(side="left", fill="both", expand=True, padx=4)

        tk.Label(
            frame,
            text=title,
            font=(FONT, 8, "bold"),
            fg=MUTED,
            bg=WHITE,
        ).pack(pady=(13, 3))

        tk.Label(
            frame,
            text=value,
            font=(FONT, 19, "bold"),
            fg=TEXT,
            bg=WHITE,
        ).pack(pady=(0, 13))

    # --------------------------------------------------------
    # REPORT
    # --------------------------------------------------------

    def show_report(self):
        self.clear_content()
        self.page_title(
            "Tarama Raporu",
            "Her dosyanın statik analiz sonucu ve bulguları."
        )

        wrapper = tk.Frame(self.content, bg=BG)
        wrapper.pack(fill="both", expand=True, padx=30, pady=(5, 20))

        scroll = ScrollableFrame(wrapper, BG)
        scroll.pack(fill="both", expand=True)

        if not self.last_scan_results:
            tk.Label(
                scroll.inner,
                text="Henüz rapor oluşturulmadı.",
                font=(FONT, 11),
                fg=MUTED,
                bg=BG,
            ).pack(pady=50)
            return

        for index, result in enumerate(self.last_scan_results, 1):
            self._report_card(scroll.inner, index, result)

        bottom = tk.Frame(self.content, bg=BG)
        bottom.pack(pady=(0, 12))

        self.make_button(
            bottom,
            "← ANA MENÜ",
            self.show_dashboard,
            "white",
        ).pack(side="left", padx=4)

        self.make_button(
            bottom,
            "YENİ TARAMA",
            self.choose_file,
            "green",
        ).pack(side="left", padx=4)

    def _report_card(self, parent, index, result):
        card = tk.Frame(
            parent,
            bg=WHITE,
            highlightbackground=BORDER,
            highlightthickness=1,
        )
        card.pack(fill="x", padx=5, pady=7)

        if "error" in result:
            risk_text = "ANALİZ EDİLEMEDİ"
            risk_color = RED
        else:
            risk_text = result.get("risk", "BİLİNMİYOR")
            risk_color = {
                "TEMİZ": GREEN,
                "ŞÜPHELİ": YELLOW,
                "YÜKSEK RİSK": RED,
            }.get(risk_text, BLUE)

        head = tk.Frame(card, bg=WHITE)
        head.pack(fill="x", padx=17, pady=13)

        tk.Label(
            head,
            text=f"{index}. {Path(result.get('path', '?')).name}",
            font=(FONT, 11, "bold"),
            fg=TEXT,
            bg=WHITE,
        ).pack(side="left")

        tk.Label(
            head,
            text=risk_text,
            font=(FONT, 8, "bold"),
            fg=risk_color,
            bg=WHITE,
            padx=9,
            pady=4,
        ).pack(side="right")

        tk.Label(
            card,
            text=result.get("path", "?"),
            font=("Consolas", 8),
            fg=MUTED,
            bg=WHITE,
            anchor="w",
        ).pack(fill="x", padx=17)

        if "error" in result:
            tk.Label(
                card,
                text=result["error"],
                font=(FONT, 9),
                fg=RED,
                bg=WHITE,
                anchor="w",
                justify="left",
                wraplength=850,
            ).pack(fill="x", padx=17, pady=12)
            return

        meta = (
            f"SHA-256: {result.get('hash', '-')}\n"
            f"Risk skoru: {result.get('score', 0)}    "
            f"Bulgu: {len(result.get('findings', []))}"
        )

        if result.get("type") == ".exe":
            meta += (
                f"\nMimari: {result.get('architecture', '-')}"
                f"    Subsystem: {result.get('subsystem', '-')}"
                f"    String: {result.get('string_count', 0)}"
            )
            sig = result.get("signature", {})
            if sig:
                meta += f"\nDijital imza: {sig.get('status', '-')}    İmzacı: {sig.get('signer', '-')}"
        elif result.get("type") == ".zip":
            meta += f"\nZIP üye sayısı: {result.get('member_count', 0)}    Desteklenen üye: {result.get('supported_members', 0)}"

        tk.Label(
            card,
            text=meta,
            font=("Consolas", 8),
            fg=MUTED,
            bg=WHITE,
            justify="left",
            anchor="w",
        ).pack(fill="x", padx=17, pady=(9, 5))

        findings = result.get("findings", [])
        if not findings:
            tk.Label(
                card,
                text="✓ Bilinen yüksek riskli davranış göstergesi bulunmadı.",
                font=(FONT, 9, "bold"),
                fg=GREEN,
                bg=WHITE,
                anchor="w",
            ).pack(fill="x", padx=17, pady=(6, 14))
            return

        tk.Label(
            card,
            text="BULGULAR",
            font=(FONT, 8, "bold"),
            fg=MUTED,
            bg=WHITE,
            anchor="w",
        ).pack(fill="x", padx=17, pady=(8, 4))

        for finding in findings:
            sev = finding.get("severity", "INFO")
            sev_color = {
                "INFO": BLUE,
                "DÜŞÜK": BLUE,
                "ORTA": YELLOW,
                "YÜKSEK": RED,
                "KRİTİK": RED,
            }.get(sev, MUTED)

            line = f"[{sev}] {finding.get('title', '')}"
            if finding.get("line"):
                line += f"  • Satır {finding['line']}"

            tk.Label(
                card,
                text=line,
                font=(FONT, 9, "bold"),
                fg=sev_color,
                bg=WHITE,
                anchor="w",
            ).pack(fill="x", padx=17, pady=(2, 0))

            tk.Label(
                card,
                text=finding.get("description", ""),
                font=(FONT, 8),
                fg=TEXT,
                bg=WHITE,
                anchor="w",
                justify="left",
                wraplength=850,
            ).pack(fill="x", padx=17, pady=(1, 3))

            if finding.get("code"):
                tk.Label(
                    card,
                    text=f"  {finding['code']}",
                    font=("Consolas", 8),
                    fg=MUTED,
                    bg="#f6f8f9",
                    anchor="w",
                    justify="left",
                    wraplength=850,
                ).pack(fill="x", padx=25, pady=(1, 4))

        if risk_text in {"ŞÜPHELİ", "YÜKSEK RİSK"}:
            action = tk.Frame(card, bg=WHITE)
            action.pack(fill="x", padx=17, pady=(8, 3))
            self.make_button(action, "KARANTİNAYA AL", lambda p=result.get("path"): self.quarantine_selected(p), "red").pack(side="left")
            tk.Label(action, text="Yalnızca seçtiğin dosya karantinaya taşınır; çalıştırılmaz.", font=(FONT,8), fg=MUTED, bg=WHITE).pack(side="left", padx=10)

        tk.Frame(card, bg=WHITE, height=9).pack()

    def quarantine_selected(self, path):
        if not path:
            return
        ok, info = quarantine_file(path)
        if ok:
            messagebox.showinfo("ATS Karantina", "Seçtiğin dosya karantinaya alındı.\n\n" + info)
        else:
            messagebox.showerror("Karantina hatası", info)

    # --------------------------------------------------------
    # HISTORY
    # --------------------------------------------------------

    def _load_history(self):
        try:
            if self.history_file.exists():
                data = json.loads(
                    self.history_file.read_text(
                        encoding="utf-8",
                        errors="replace",
                    )
                )
                self.history = data if isinstance(data, list) else []
        except Exception:
            self.history = []

    def _save_history(self, results):
        record = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "files": len(results),
            "findings": sum(len(r.get("findings", [])) for r in results if "error" not in r),
            "high_risk": sum(
                1 for r in results
                if r.get("risk") == "YÜKSEK RİSK"
            ),
            "errors": sum(1 for r in results if "error" in r),
        }

        self.history.insert(0, record)
        self.history = self.history[:50]

        try:
            self.history_file.write_text(
                json.dumps(self.history, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
        except Exception:
            # History is non-critical; scanning should not fail if it
            # cannot be written.
            pass

    def show_history(self):
        if self.scanning:
            return

        self.clear_content()
        self.page_title(
            "Tarama Geçmişi",
            "Son 50 tarama oturumu."
        )

        if not self.history:
            tk.Label(
                self.content,
                text="Henüz kayıtlı tarama bulunmuyor.",
                font=(FONT, 11),
                fg=MUTED,
                bg=BG,
            ).pack(pady=70)
            return

        wrapper = tk.Frame(self.content, bg=BG)
        wrapper.pack(fill="both", expand=True, padx=35, pady=10)

        scroll = ScrollableFrame(wrapper, BG)
        scroll.pack(fill="both", expand=True)

        for item in self.history:
            card = tk.Frame(
                scroll.inner,
                bg=WHITE,
                highlightbackground=BORDER,
                highlightthickness=1,
            )
            card.pack(fill="x", pady=5)

            tk.Label(
                card,
                text=item.get("timestamp", "-"),
                font=(FONT, 10, "bold"),
                fg=TEXT,
                bg=WHITE,
            ).pack(side="left", padx=15, pady=14)

            summary = (
                f"{item.get('files', 0)} dosya   •   "
                f"{item.get('findings', 0)} bulgu   •   "
                f"{item.get('high_risk', 0)} yüksek risk   •   "
                f"{item.get('errors', 0)} hata"
            )

            tk.Label(
                card,
                text=summary,
                font=(FONT, 9),
                fg=MUTED,
                bg=WHITE,
            ).pack(side="right", padx=15)

    # --------------------------------------------------------
    # SETTINGS
    # --------------------------------------------------------

    def show_settings(self):
        if self.scanning:
            return

        self.clear_content()
        self.page_title(
            "Ayarlar",
            "ATS PyScanner analiz motoru hakkında."
        )

        card = tk.Frame(
            self.content,
            bg=WHITE,
            highlightbackground=BORDER,
            highlightthickness=1,
        )
        card.pack(fill="x", padx=35, pady=10)

        tk.Label(
            card,
            text="Statik analiz",
            font=(FONT, 12, "bold"),
            fg=TEXT,
            bg=WHITE,
        ).pack(anchor="w", padx=20, pady=(20, 6))

        description = (
            "ATS PyScanner dosyaları çalıştırmaz. "
            "Python dosyaları AST ve metin göstergeleriyle; "
            "EXE dosyaları ise PE header ve string göstergeleriyle incelenir."
        )

        tk.Label(
            card,
            text=description,
            font=(FONT, 9),
            fg=MUTED,
            bg=WHITE,
            wraplength=850,
            justify="left",
        ).pack(anchor="w", padx=20, pady=(0, 18))

        tk.Label(
            card,
            text="Önemli",
            font=(FONT, 10, "bold"),
            fg=YELLOW,
            bg=WHITE,
        ).pack(anchor="w", padx=20, pady=(0, 3))

        tk.Label(
            card,
            text="Şüpheli bulgu, tek başına dosyanın malware olduğunu kanıtlamaz. Bu sürüm davranış sezgileri kullanan statik bir analiz aracıdır.",
            font=(FONT, 9),
            fg=TEXT,
            bg=WHITE,
            wraplength=850,
            justify="left",
        ).pack(anchor="w", padx=20, pady=(0, 20))

        tk.Label(
            card,
            text=f"Versiyon: {VERSION}",
            font=(FONT, 8),
            fg=MUTED,
            bg=WHITE,
        ).pack(anchor="w", padx=20, pady=(0, 20))

    # --------------------------------------------------------
    # DASHBOARD DATA
    # --------------------------------------------------------

    def _last_scan_text(self):
        if not self.history:
            return "Henüz yok"
        return self.history[0].get("timestamp", "Henüz yok")

    def _last_finding_count(self):
        if not self.history:
            return 0
        return self.history[0].get("findings", 0)

    def _last_file_count(self):
        if not self.history:
            return 0
        return self.history[0].get("files", 0)

    # --------------------------------------------------------
    # CLOSE
    # --------------------------------------------------------

    def _on_close(self):
        if self.scanning:
            if not messagebox.askyesno(
                APP_TITLE,
                "Tarama devam ediyor. Programı kapatmak istediğine emin misin?"
            ):
                return
            self.cancel_requested = True

        self.root.destroy()


# ============================================================
# MAIN
# ============================================================

def main():
    hide_windows_console()
    root = tk.Tk()
    ATSApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
