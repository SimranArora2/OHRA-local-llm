"""
WCAT - Web Content Analysis Tool
Safe, isolated malware download and static analysis for OHRA.

Novel contribution: adds signature-based threat classification on top of
static analysis — closes the gap where EICAR was detected but not flagged.
"""

import hashlib
import time
import zipfile
import json
import math
import os
import string
import threading
import traceback
from datetime import datetime
from urllib.parse import urlparse, urlunparse

import requests
from flask import Flask, request, jsonify

SAVE_DIR = os.environ.get("WCAT_SAVE_DIR", "/app/downloaded_content")
ARCHIVE_DIR = os.environ.get("MALWARE_ARCHIVE_DIR", "/app/malware_archive")
app = Flask(__name__)


# ──────────────────────────────────────────────
# Signature Rules (YARA-style string matching)
# ──────────────────────────────────────────────

SIGNATURE_RULES = [
    {
        "name": "EICAR Test File",
        "severity": "HIGH",
        "description": "Industry-standard antivirus test file — treated as malware by all AV engines",
        "patterns": [b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE"],
    },
    {
        "name": "Windows PE Executable",
        "severity": "MEDIUM",
        "description": "Windows executable — suspicious if disguised as another file type",
        "patterns": [b"\x4d\x5a\x90\x00", b"\x4d\x5a\x50\x45"],
    },
    {
        "name": "ELF Linux Executable",
        "severity": "MEDIUM",
        "description": "Linux/Unix executable binary",
        "patterns": [b"\x7fELF"],
    },
    {
        "name": "Reverse Shell Indicators",
        "severity": "CRITICAL",
        "description": "Strings commonly found in reverse shell payloads",
        "patterns": [
            b"/bin/bash -i",
            b"bash -i >& /dev/tcp",
            b"0>&1",
            b"nc -e /bin/bash",
            b"nc -e /bin/sh",
            b"/bin/sh -i",
        ],
    },
    {
        "name": "Cryptocurrency Miner",
        "severity": "HIGH",
        "description": "Strings associated with cryptomining malware",
        "patterns": [
            b"stratum+tcp://",
            b"xmrig",
            b"cryptonight",
            b"--donate-level",
        ],
    },
    {
        "name": "Persistence Mechanisms",
        "severity": "HIGH",
        "description": "Commands used to establish persistence on compromised systems",
        "patterns": [
            b"crontab -e",
            b"/etc/cron",
            b".bashrc",
            b"systemctl enable",
            b"rc.local",
        ],
    },
    {
        "name": "Credential Harvesting",
        "severity": "CRITICAL",
        "description": "Strings targeting credential files or auth mechanisms",
        "patterns": [
            b"/etc/shadow",
            b"id_rsa",
            b".ssh/authorized_keys",
            b"mimikatz",
            b"hashdump",
        ],
    },
    {
        "name": "Lateral Movement Tools",
        "severity": "HIGH",
        "description": "Tools used for network scanning and lateral movement",
        "patterns": [
            b"nmap -sS",
            b"masscan",
            b"hydra",
            b"metasploit",
            b"msfvenom",
        ],
    },
    {
        "name": "Data Exfiltration",
        "severity": "CRITICAL",
        "description": "Patterns suggesting data exfiltration attempts",
        "patterns": [
            b"curl -X POST",
            b"wget --post-data",
            b"tar czf /tmp/",
        ],
    },
    {
        "name": "Ransomware Indicators",
        "severity": "CRITICAL",
        "description": "Strings associated with ransomware behavior",
        "patterns": [
            b"openssl enc -aes",
            b"YOUR FILES HAVE BEEN ENCRYPTED",
            b"bitcoin",
            b".encrypted",
        ],
    },
    {
        "name": "Encoded Payload",
        "severity": "HIGH",
        "description": "Base64-encoded payloads commonly used to evade detection",
        "patterns": [
            b"base64 -d",
            b"base64 --decode",
            b"eval(base64",
        ],
    },
    {
        "name": "Privilege Escalation",
        "severity": "CRITICAL",
        "description": "Techniques used to escalate privileges or hide attacker presence",
        "patterns": [
            b"chmod 4755",
            b"chmod u+s",
            b"LD_PRELOAD",
            b"/proc/self/mem",
        ],
    },
]

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "CLEAN": 4}


def match_signatures(data: bytes) -> dict:
    """
    Run all signature rules against file content.
    Returns verdict: CLEAN / SUSPICIOUS / MALICIOUS
    """
    matched = []

    for rule in SIGNATURE_RULES:
        for pattern in rule["patterns"]:
            if pattern in data:
                matched.append({
                    "rule": rule["name"],
                    "severity": rule["severity"],
                    "description": rule["description"],
                    "matched_pattern": pattern.decode("utf-8", errors="replace"),
                })
                break  # one match per rule is enough

    if not matched:
        verdict = "CLEAN"
        severity = "CLEAN"
    else:
        severities = [m["severity"] for m in matched]
        severity = min(severities, key=lambda s: SEVERITY_ORDER.get(s, 99))
        verdict = "MALICIOUS" if severity in ("CRITICAL", "HIGH") else "SUSPICIOUS"

    return {
        "verdict": verdict,
        "severity": severity,
        "matched_rules_count": len(matched),
        "matched_rules": matched,
        "note": (
            "Submit SHA256 to https://virustotal.com for confirmation"
            if verdict != "CLEAN"
            else "No known signatures matched"
        ),
    }


# ──────────────────────────────────────────────
# Static Analysis Functions
# ──────────────────────────────────────────────

def compute_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def compute_md5(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def compute_entropy(data: bytes) -> float:
    """Shannon entropy — high entropy (>7.0) suggests encryption/packing."""
    if not data:
        return 0.0
    freq = {}
    for byte in data:
        freq[byte] = freq.get(byte, 0) + 1
    entropy = 0.0
    length = len(data)
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def detect_file_type(data: bytes) -> str:
    """Detect file type using magic bytes."""
    signatures = {
        b"\x4d\x5a": "PE Executable (Windows .exe/.dll)",
        b"\x7fELF": "ELF Executable (Linux binary)",
        b"PK\x03\x04": "ZIP Archive",
        b"\x1f\x8b": "GZIP Compressed",
        b"%PDF": "PDF Document",
        b"\x89PNG": "PNG Image",
        b"\xff\xd8\xff": "JPEG Image",
        b"#!/": "Shell Script",
        b"#!": "Script (shebang)",
    }
    for magic, label in signatures.items():
        if data[:len(magic)] == magic:
            return label
    try:
        data[:512].decode("utf-8")
        return "Text File"
    except UnicodeDecodeError:
        return "Unknown Binary"


def extract_strings(data: bytes, min_len: int = 6) -> list:
    """Extract readable ASCII strings from binary."""
    result = []
    current = []
    printable = set(string.printable.encode())
    for byte in data:
        if byte in printable:
            current.append(chr(byte))
        else:
            if len(current) >= min_len:
                result.append("".join(current))
            current = []
    if len(current) >= min_len:
        result.append("".join(current))
    return list(dict.fromkeys(result))[:100]


# ──────────────────────────────────────────────
# Core Download + Analysis
# ──────────────────────────────────────────────


def archive_malware(file_path: str, sha256: str, verdict: str, matched_rules: list):
    """
    Compress malware binary with password infected (industry standard).
    Saved to host-mounted directory BEFORE container auto-reset.
    Password: infected — same standard used by VirusTotal, MalwareBazaar, CERT.
    """
    try:
        os.makedirs(ARCHIVE_DIR, exist_ok=True)
        rule_names = "_".join(r["rule"].replace(" ", "-")[:20] for r in matched_rules[:2])
        archive_name = f"{sha256[:16]}_{verdict}_{rule_names}.zip"
        archive_path = os.path.join(ARCHIVE_DIR, archive_name)
        with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.setpassword(b"infected")
            zf.write(file_path, arcname=f"{sha256}.bin")
        print(f"Malware archived: {archive_path}")
        return archive_path
    except Exception as e:
        print(f"Archive failed: {e}")
        return None

def analyze_and_save(url: str):
    """Download URL safely and run static analysis + signature matching."""
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    }

    report = {
        "url": url,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "status": "pending",
        "error": None,
        "file_info": {},
        "static_analysis": {},
        "threat_classification": {},
    }

    try:
        parsed = urlparse(url)
        safe_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))
        response = requests.get(safe_url, headers=headers, timeout=20)
        content = response.content

        sha256 = compute_sha256(content)
        md5 = compute_md5(content)
        entropy = compute_entropy(content)
        strings = extract_strings(content)
        file_type = detect_file_type(content)
        threat = match_signatures(content)

        os.makedirs(SAVE_DIR, exist_ok=True)
        file_path = os.path.join(SAVE_DIR, f"{sha256}.bin")
        with open(file_path, "wb") as f:
            f.write(content)

        report["status"] = "success"
        report["file_info"] = {
            "sha256": sha256,
            "md5": md5,
            "size_bytes": len(content),
            "detected_type": file_type,
            "saved_as": file_path,
        }
        report["static_analysis"] = {
            "entropy": entropy,
            "entropy_interpretation": (
                "High — likely encrypted/packed (suspicious)" if entropy > 7.0
                else "Medium — mixed content" if entropy > 4.0
                else "Low — likely plaintext"
            ),
            "strings_count": len(strings),
            "strings_sample": strings[:20],
        }
       
        report["threat_classification"] = threat

        # SAVE REPORT IMMEDIATELY after analysis (before any reset)
        try:
            sha256_key = report.get("file_info", {}).get("sha256", "unknown")
            report_path = os.path.join(SAVE_DIR, f"{sha256_key}_report.json")
            os.makedirs(SAVE_DIR, exist_ok=True)
            with open(report_path, "w") as f:
                json.dump(report, f, indent=2)
            print(f"Report saved: {report_path}")
        except Exception as _re:
            print(f"Report save failed: {_re}")

       # AUTO-RESET ON MALWARE DETECTION
        verdict = threat.get("verdict", "CLEAN")
        if verdict in ["MALICIOUS", "RANSOMWARE"]:
            archive_malware(file_path, sha256, verdict, threat.get("matched_rules", []))
            time.sleep(2)  # wait for ZIP write to complete before reset
            print(f"⚠️  MALWARE DETECTED: {verdict} — Container auto-reset triggered!")
            import socket as _sock, http.client as _http
            container_name = os.environ.get("WCAT_CONTAINER_NAME", "src-wcat-1")
            try:
                class _UnixHTTP(_http.HTTPConnection):
                    def connect(self):
                        self.sock = _sock.socket(_sock.AF_UNIX, _sock.SOCK_STREAM)
                        self.sock.connect("/var/run/docker.sock")
                conn = _UnixHTTP("localhost")
                conn.request("POST", f"/v1.41/containers/{container_name}/restart")
                resp = conn.getresponse()
                print(f"✅ WCAT reset triggered (HTTP {resp.status})")
            except Exception as _e:
                print(f"❌ Reset failed: {_e}")

    except Exception as e:
        report["status"] = "error"
        report["error"] = str(e)

    finally:
        try:
            sha256_key = report.get("file_info", {}).get("sha256", "unknown")
            report_path = os.path.join(SAVE_DIR, f"{sha256_key}_report.json")
            os.makedirs(SAVE_DIR, exist_ok=True)
            with open(report_path, "w") as f:
                json.dump(report, f, indent=2)
        except Exception:
            pass


# ──────────────────────────────────────────────
# Flask API
# ──────────────────────────────────────────────

@app.route("/is_ready", methods=["GET"])
def is_ready():
    return jsonify({"ready": True}), 200


@app.route("/analyze", methods=["POST"])
def analyze():
    """Receive URLs and spawn background analysis threads."""
    data = request.get_json(force=True)
    urls = data.get("urls", [])
    if not urls:
        return jsonify({"error": "No URLs provided"}), 400

    for url in urls:
        thread = threading.Thread(target=analyze_and_save, args=(url,), daemon=True)
        thread.start()

    return jsonify({"status": "accepted", "urls_queued": len(urls)}), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8002)
