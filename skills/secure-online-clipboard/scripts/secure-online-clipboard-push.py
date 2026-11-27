#!/usr/bin/env python3
"""secure-online-clipboard-push — upload to Secure online clipboard and print the link(s).

    python3 secure-online-clipboard-push.py "content" [options]
    python3 secure-online-clipboard-push.py --file report.pdf [options]

Encryption happens here, in this process. The server only ever sees ciphertext.

Requires: Python 3.8+ and the `cryptography` package (pip install cryptography).
The PBKDF2 step uses the standard library; only AES-GCM needs the package.
"""

import argparse
import base64
import hashlib
import json
import os
import sys
import urllib.request
import urllib.error

BASE = os.environ.get("KHEPRI_BASE", "https://paste.vantolab.com")
ITERATIONS = 1_000_000          # server accepts 100000..1000000
MAX_REQUEST = 1024 * 1024       # must match core.js MAX_BODY
MAX_FILE = 512 * 1024           # a file is base64'd twice: x1.778
FILE_MARKER = "KHEPRI-FILE 1"


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64u_to_bytes(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def post(url: str, obj: dict, headers: dict) -> tuple:
    """Return (status, body_text)."""
    req = urllib.request.Request(
        url,
        data=json.dumps(obj).encode("utf-8"),
        headers={"Content-Type": "application/json", **headers},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, r.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="secure-online-clipboard-push",
        description="Upload an encrypted paste and print the link(s).",
    )
    p.add_argument("text", nargs="?", help="the content to upload")
    p.add_argument("--file", dest="file", help="attach a file instead of text (limit 512 KB)")
    p.add_argument("--short", action="store_true", help="also ask for a short code")
    p.add_argument("--len", dest="len", type=int, default=5, help="short code length, 3-8 (default 5)")
    p.add_argument("--ttl", type=int, default=21600, help="lifetime in seconds, 60-604800 (default 21600)")
    p.add_argument("--burn", action="store_true", help="burn after one read")
    p.add_argument("--reads", type=int, default=None, help="read limit 0-20; 0 means unlimited")
    p.add_argument("--pin-ip", dest="pin_ip", action="store_true", help="bind to the first reader's address")
    p.add_argument("--password", default="", help="add a password — send it over a separate channel")
    p.add_argument("--base", default=BASE, help="deployment to talk to")
    p.add_argument("--quiet", action="store_true", help="print only the link, no JSON")
    return p


def main() -> int:
    args = build_parser().parse_args()
    if not 3 <= args.len <= 8:
        print("error: --len must be an integer from 3 to 8", file=sys.stderr)
        return 1
    if not 60 <= args.ttl <= 604800:
        print("error: --ttl must be seconds from 60 to 604800", file=sys.stderr)
        return 1
    read_limit = (1 if args.burn else 0) if args.reads is None else args.reads
    if not 0 <= read_limit <= 20:
        print("error: --reads must be an integer from 0 to 20", file=sys.stderr)
        return 1

    # ---- the payload ------------------------------------------------------
    if args.file:
        with open(args.file, "rb") as fh:
            raw = fh.read()
        if len(raw) > MAX_FILE:
            print(f"error: file is {len(raw)} bytes; the limit is {MAX_FILE} ({MAX_FILE // 1024} KB)",
                  file=sys.stderr)
            return 1
        meta = b64u(json.dumps(
            {"name": os.path.basename(args.file), "type": "", "size": len(raw)}
        ).encode("utf-8"))
        plaintext = f"{FILE_MARKER}\n{meta}\n{b64u(raw)}"
    elif args.text:
        plaintext = args.text
    else:
        print("error: nothing to send: pass text or --file <path>", file=sys.stderr)
        return 1

    # ---- encrypt locally --------------------------------------------------
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:
        print("error: needs the cryptography package — pip install cryptography", file=sys.stderr)
        return 1

    paste_id = os.urandom(8).hex()
    key_bytes = os.urandom(32)
    salt = os.urandom(8)
    iv = os.urandom(12)

    # keyBytes || password, then PBKDF2. Same order as the browser.
    material = key_bytes + args.password.encode("utf-8")
    key = hashlib.pbkdf2_hmac("sha256", material, salt, ITERATIONS, dklen=32)

    ct_and_tag = AESGCM(key).encrypt(iv, plaintext.encode("utf-8"), paste_id.encode("ascii"))

    # The reader proves itself with this before the server releases the body.
    proof = os.urandom(32)
    claim_iv = os.urandom(12)
    claim = AESGCM(key).encrypt(claim_iv, proof, ("claim:" + paste_id).encode("ascii"))
    claim_hash = hashlib.sha256(proof).digest()

    payload = {
        "id": paste_id, "ct": b64u(ct_and_tag), "iv": b64u(iv), "salt": b64u(salt),
        "claim": b64u(claim), "claimIv": b64u(claim_iv), "claimHash": b64u(claim_hash),
        "iterations": ITERATIONS, "ttl": args.ttl, "reads": read_limit,
        "burn": args.burn, "pinIp": args.pin_ip,
    }
    blob = json.dumps(payload).encode("utf-8")
    if len(blob) > MAX_REQUEST:
        print(f"error: request would be {len(blob)} bytes; the limit is {MAX_REQUEST} (1 MiB)",
              file=sys.stderr)
        return 1

    # ---- send ---------------------------------------------------------------
    base = args.base.rstrip("/")
    headers = {}
    if os.environ.get("KHEPRI_IP"):
        headers["X-Forwarded-For"] = os.environ["KHEPRI_IP"]

    req = urllib.request.Request(
        base + "/api/paste", data=blob,
        headers={"Content-Type": "application/json", **headers}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            status, body = r.status, r.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        status, body = e.code, e.read().decode("utf-8", "replace")
    if status == 413:
        print("error: too large once encrypted (1 MiB)", file=sys.stderr)
        return 1
    if status != 200:
        print(f"error: create failed {status}: {body}", file=sys.stderr)
        return 1

    long_url = f"{base}/?{paste_id}#{b64u(key_bytes)}"
    out = {"long": long_url}

    if args.short:
        s_status, s_body = post(base + "/s/shorten", {"url": long_url, "len": args.len}, headers)
        if s_status == 200:
            out["short"] = s_body.strip()
        else:
            out["shortError"] = f"shorten failed {s_status}: {s_body}"

    if args.quiet:
        print(out.get("short") or out["long"])
    else:
        print(json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
