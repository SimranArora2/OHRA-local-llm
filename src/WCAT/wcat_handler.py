"""
WCAT - Web Content Analysis Tool
Safe, isolated malware download and static analysis for OHRA.
"""

import hashlib
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
app = Flask(__name__)


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


def analyze_and_save(url: str):
    """Download URL safely and run static analysis."""
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
            "strings_count": len(strings),
            "strings_sample": strings[:20],
        }

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
