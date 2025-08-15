#!/usr/bin/env python3
"""
Email Forensics Tool (Beginner-Friendly)
---------------------------------------
Parses .eml (and optionally .msg) emails to extract:
- SPF/DKIM/DMARC pass/fail from Authentication-Results headers
- Sender IP and Receiver IP from Received headers
- From, To, Subject, Date
- Attachments with hashes; flags suspicious extensions (e.g., .exe)
- Outputs a combined CSV + JSON report
- Optionally saves attachments to disk

Usage:
  python3 email_forensics_tool.py INPUT_PATH [--outdir OUTDIR] [--save-attachments]

Examples:
  python3 email_forensics_tool.py samples/emails --outdir report --save-attachments
  python3 email_forensics_tool.py one_email.eml

Notes:
- .eml support is native (standard library).
- .msg support requires the optional package `extract_msg`. If not installed, .msg files are skipped with a warning.
"""

import argparse
import csv
import hashlib
import json
import os
import re
import sys
from datetime import datetime
from email import policy
from email.parser import BytesParser
from email.utils import parsedate_to_datetime

# Optional dependency for .msg (Outlook) files
try:
    import extract_msg  # type: ignore
    HAS_EXTRACT_MSG = True
except Exception:
    HAS_EXTRACT_MSG = False

SUSPICIOUS_EXTS = {
    ".exe", ".dll", ".bat", ".cmd", ".vbs", ".js", ".jse", ".vbe",
    ".scr", ".ps1", ".psm1", ".lnk", ".hta", ".iso", ".img", ".jar",
    ".chm", ".msi", ".com"
}

IPV4_REGEX = re.compile(r'(?:\d{1,3}\.){3}\d{1,3}')
# Basic IPv6 capture (not exhaustive, but helpful)
IPV6_REGEX = re.compile(r'([0-9a-fA-F:]+:+)+[0-9a-fA-F]+')

AUTH_RESULTS_KEYS = ("authentication-results", "x-authentication-results")

def sha256_filelike(fp):
    h = hashlib.sha256()
    for chunk in iter(lambda: fp.read(8192), b""):
        h.update(chunk)
    return h.hexdigest()

def extract_auth_results(headers):
    """Return dict with dmarc/spf/dkim = pass/fail/none based on Authentication-Results headers."""
    result = {"dmarc": "none", "spf": "none", "dkim": "none", "raw": []}
    for key in headers.keys():
        if key.lower() in AUTH_RESULTS_KEYS:
            vals = headers.get_all(key) or []
            for v in vals:
                text = " ".join(v.split())
                result["raw"].append(text)
                # Look for tokens like "dmarc=pass" or "spf=fail" etc.
                for mech in ("dmarc", "spf", "dkim"):
                    m = re.search(rf'\b{mech}\s*=\s*(pass|fail|neutral|softfail|permerror|temperror)', text, re.IGNORECASE)
                    if m:
                        result[mech] = m.group(1).lower()
    return result

def extract_ips_from_received(headers):
    """Parse Received headers to estimate sender and receiver IPs.
    Heuristic:
      - First (bottom-most) Received header: likely sender/client IP
      - Last  (top-most)   Received header: likely receiving gateway IP
    """
    received_all = headers.get_all("Received") or []
    if not received_all:
        # Try also "X-Received"
        received_all = headers.get_all("X-Received") or []

    # Normalize whitespace
    received_all = [" ".join(r.split()) for r in received_all]

    sender_ip = None
    receiver_ip = None

    if received_all:
        # Bottom-most (original) appears last when read top-down -> reverse list
        bottom = received_all[-1]
        top = received_all[0]

        # Try to find IPv4 first, fallback to IPv6
        m4 = IPV4_REGEX.search(bottom)
        m6 = IPV6_REGEX.search(bottom) if not m4 else None
        sender_ip = m4.group(0) if m4 else (m6.group(0) if m6 else None)

        m4 = IPV4_REGEX.search(top)
        m6 = IPV6_REGEX.search(top) if not m4 else None
        receiver_ip = m4.group(0) if m4 else (m6.group(0) if m6 else None)

    return sender_ip, receiver_ip, received_all

def parse_date(header_value):
    try:
        dt = parsedate_to_datetime(header_value)
        if dt and dt.tzinfo is None:
            return dt.isoformat() + "Z"
        return dt.isoformat() if dt else ""
    except Exception:
        return ""

def safe_filename(name):
    name = re.sub(r'[\\/:*?"<>|]+', "_", name)
    name = name.strip()
    return name or "unnamed"

def handle_eml(path, outdir, save_attachments):
    with open(path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)

    headers = msg

    auth = extract_auth_results(headers)
    sender_ip, receiver_ip, received_raw = extract_ips_from_received(headers)

    report = {
        "source_file": path,
        "format": "eml",
        "subject": headers.get("Subject", ""),
        "from": headers.get("From", ""),
        "to": headers.get("To", ""),
        "date": parse_date(headers.get("Date", "")),
        "message_id": headers.get("Message-ID", ""),
        "auth_results": auth,
        "sender_ip_estimate": sender_ip,
        "receiver_ip_estimate": receiver_ip,
        "received_chain": received_raw,
        "attachments": []
    }

    # Iterate parts to extract attachments
    if msg.is_multipart():
        for part in msg.walk():
            content_disposition = part.get_content_disposition()
            filename = part.get_filename()
            if content_disposition == "attachment" or filename:
                fname = safe_filename(filename or "attachment.bin")
                payload = part.get_payload(decode=True) or b""

                # Save attachment if requested
                saved_path = ""
                sha256 = ""
                if save_attachments:
                    att_dir = os.path.join(outdir, "attachments", safe_filename(os.path.basename(path)))
                    os.makedirs(att_dir, exist_ok=True)
                    saved_path = os.path.join(att_dir, fname)
                    with open(saved_path, "wb") as wf:
                        wf.write(payload)
                    with open(saved_path, "rb") as rf:
                        sha256 = hashlib.sha256(rf.read()).hexdigest()
                else:
                    # Hash in-memory to avoid writing
                    import io
                    sha256 = sha256_filelike(io.BytesIO(payload))

                ext = os.path.splitext(fname)[1].lower()
                suspicious = ext in SUSPICIOUS_EXTS

                report["attachments"].append({
                    "filename": fname,
                    "size_bytes": len(payload),
                    "sha256": sha256,
                    "saved_path": saved_path,
                    "mime_type": part.get_content_type(),
                    "suspicious_ext": suspicious
                })
    return report

def handle_msg(path, outdir, save_attachments):
    if not HAS_EXTRACT_MSG:
        return {
            "source_file": path,
            "format": "msg",
            "error": "extract_msg not installed; skipping .msg parsing."
        }

    msg = extract_msg.Message(path)
    msg_sender = getattr(msg, "sender", "") or getattr(msg, "from_", "")
    msg_to = getattr(msg, "to", "")
    msg_subj = getattr(msg, "subject", "")
    msg_date = ""
    try:
        if msg.date:
            msg_date = msg.date.isoformat()
    except Exception:
        pass

    # Headers text (Outlook MSG doesn't preserve raw headers cleanly)
    headers_text = msg.header or ""
    # Try to emulate auth results parsing
    auth = {"dmarc": "none", "spf": "none", "dkim": "none", "raw": []}
    if headers_text:
        flat = " ".join(headers_text.split())
        auth["raw"].append(flat)
        for mech in ("dmarc", "spf", "dkim"):
            m = re.search(rf'\b{mech}\s*=\s*(pass|fail|neutral|softfail|permerror|temperror)', flat, re.IGNORECASE)
            if m:
                auth[mech] = m.group(1).lower()

    # Try to find IPs in headers if present
    sender_ip = None
    receiver_ip = None
    if headers_text:
        # crude: first and last IPs in the text
        ips = IPV4_REGEX.findall(headers_text) or IPV6_REGEX.findall(headers_text)
        if ips:
            sender_ip = ips[-1]
            receiver_ip = ips[0]

    report = {
        "source_file": path,
        "format": "msg",
        "subject": msg_subj,
        "from": msg_sender,
        "to": msg_to,
        "date": msg_date,
        "message_id": "",  # extract_msg doesn't always expose this
        "auth_results": auth,
        "sender_ip_estimate": sender_ip,
        "receiver_ip_estimate": receiver_ip,
        "received_chain": [],
        "attachments": []
    }

    # Save attachments
    att_dir = os.path.join(outdir, "attachments", safe_filename(os.path.basename(path)))
    if save_attachments:
        os.makedirs(att_dir, exist_ok=True)

    for att in msg.attachments:
        fname = safe_filename(att.longFilename or att.shortFilename or "attachment.bin")
        data = att.data or b""

        saved_path = ""
        if save_attachments:
            saved_path = os.path.join(att_dir, fname)
            with open(saved_path, "wb") as wf:
                wf.write(data)

        sha256 = hashlib.sha256(data).hexdigest()
        ext = os.path.splitext(fname)[1].lower()
        suspicious = ext in SUSPICIOUS_EXTS
        report["attachments"].append({
            "filename": fname,
            "size_bytes": len(data),
            "sha256": sha256,
            "saved_path": saved_path,
            "mime_type": "",  # extract_msg doesn't expose MIME
            "suspicious_ext": suspicious
        })

    return report

def collect_input_files(input_path):
    files = []
    if os.path.isdir(input_path):
        for root, _, filenames in os.walk(input_path):
            for n in filenames:
                if n.lower().endswith((".eml", ".msg")):
                    files.append(os.path.join(root, n))
    else:
        if input_path.lower().endswith((".eml", ".msg")):
            files.append(input_path)
    return files

def write_reports(reports, outdir):
    os.makedirs(outdir, exist_ok=True)
    # JSON
    json_path = os.path.join(outdir, "report.json")
    with open(json_path, "w", encoding="utf-8") as jf:
        json.dump(reports, jf, indent=2, ensure_ascii=False)

    # CSV
    csv_fields = [
        "source_file","format","subject","from","to","date","message_id",
        "auth_dmarc","auth_spf","auth_dkim",
        "sender_ip_estimate","receiver_ip_estimate",
        "attachments_count","suspicious_attachments_count"
    ]
    csv_path = os.path.join(outdir, "report.csv")
    with open(csv_path, "w", newline="", encoding="utf-8") as cf:
        writer = csv.DictWriter(cf, fieldnames=csv_fields)
        writer.writeheader()
        for r in reports:
            auth = r.get("auth_results", {})
            atts = r.get("attachments", [])
            row = {
                "source_file": r.get("source_file",""),
                "format": r.get("format",""),
                "subject": r.get("subject",""),
                "from": r.get("from",""),
                "to": r.get("to",""),
                "date": r.get("date",""),
                "message_id": r.get("message_id",""),
                "auth_dmarc": auth.get("dmarc","none"),
                "auth_spf": auth.get("spf","none"),
                "auth_dkim": auth.get("dkim","none"),
                "sender_ip_estimate": r.get("sender_ip_estimate",""),
                "receiver_ip_estimate": r.get("receiver_ip_estimate",""),
                "attachments_count": len(atts),
                "suspicious_attachments_count": sum(1 for a in atts if a.get("suspicious_ext"))
            }
            writer.writerow(row)

    return json_path, csv_path

def main():
    ap = argparse.ArgumentParser(description="Email Forensics Tool: parse .eml/.msg for auth results, IPs, and attachments.")
    ap.add_argument("input_path", help="Path to .eml/.msg file or a directory containing them")
    ap.add_argument("--outdir", default="email_report", help="Directory to write reports and attachments")
    ap.add_argument("--save-attachments", action="store_true", help="Save attachments to disk")
    args = ap.parse_args()

    files = collect_input_files(args.input_path)
    if not files:
        print("No .eml/.msg files found at:", args.input_path)
        if os.path.isdir(args.input_path):
            print("Tip: ensure files end in .eml or .msg")
        sys.exit(1)

    reports = []
    for path in files:
        try:
            if path.lower().endswith(".eml"):
                r = handle_eml(path, args.outdir, args.save_attachments)
            else:
                r = handle_msg(path, args.outdir, args.save_attachments)
            reports.append(r)
        except Exception as e:
            reports.append({
                "source_file": path,
                "error": f"Failed to parse: {e}"
            })

    json_path, csv_path = write_reports(reports, args.outdir)

    print(f"[+] Processed {len(reports)} file(s).")
    print(f"[+] JSON report: {json_path}")
    print(f"[+] CSV report : {csv_path}")
    if args.save_attachments:
        print(f"[+] Attachments saved under: {os.path.join(args.outdir, 'attachments')}")

if __name__ == "__main__":
    main()
