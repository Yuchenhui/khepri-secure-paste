#!/usr/bin/env python3
"""secure-online-clipboard-fetch — read a paste back from Secure online clipboard.

    python3 secure-online-clipboard-fetch.py "<long link>" [--out file.bin] [--password pw]
    python3 secure-online-clipboard-fetch.py r7lld3                 # a short code works too

The link alone is enough: the read proof is recoverable from the claim with the
key, which is exactly what the browser does.

Requires: Python 3.8+ and the `cryptography` package (pip install cryptography).
The PBKDF2 step uses the standard library; only AES-GCM needs the package.
"""

import argparse
import base64
import hashlib
import json
import os
import sys
import urllib.error
import urllib.request
from urllib.parse import urlparse

BASE = os.environ.get("KHEPRI_BASE", "https://paste.vantolab.com")
SHORT_PREFIX = os.environ.get("KHEPRI_SHORT_PREFIX", "/s/")
FILE_MARKER = "KHEPRI-FILE 1"


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64u_to_bytes(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A short code answers with a 302 to the paste. That Location header is
    what carries the key, so the redirect must not be followed."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def get(url: str, headers: dict, method: str = "GET", obj: dict = None):
    data = json.dumps(obj).encode("utf-8") if obj is not None else None
    req = urllib.request.Request(
        url, data=data,
        headers={"Content-Type": "application/json", **headers}, method=method)
    try:
        with _OPENER.open(req, timeout=30) as r:
            return r.status, dict(r.headers), r.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode("utf-8", "replace")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="secure-online-clipboard-fetch",
        description="Read an encrypted paste back. A long link or a bare short code.",
    )
    p.add_argument("target", help="a long link (?id#key) or a bare short code")
    p.add_argument("--out", help="write the file here; without it a file paste prints metadata")
    p.add_argument("--password", default="", help="the password the paste was created with")
    p.add_argument("--base", default=BASE, help="deployment to talk to")
    return p


def key_of(fragment: str) -> str:
    """A short link adds its code after the key in the fragment, so that the
    reader can see which code brought them here. The key is base64url and has no
    dot in it, so the two parts are told apart by the first dot."""
    raw = fragment.lstrip("#")
    return raw.split(".", 1)[0]


def resolve(target: str, base: str):
    """Accept a long link or a bare short code; return (base, id, key_bytes)."""
    if target.startswith(("http://", "https://")):
        u = urlparse(target)
        return u.scheme + "://" + u.netloc, u.query, b64u_to_bytes(key_of(u.fragment))
    status, headers, _ = get(base.rstrip("/") + SHORT_PREFIX + target, {}, method="GET")
    loc = headers.get("Location") or headers.get("location")
    if not loc:
        raise SystemExit(f"error: no such short code ({status})")
    u = urlparse(loc)
    return u.scheme + "://" + u.netloc, u.query, b64u_to_bytes(key_of(u.fragment))


def main() -> int:
    args = build_parser().parse_args()
    base, paste_id, key_bytes = resolve(args.target, args.base)

    headers = {}
    if os.environ.get("KHEPRI_IP"):
        headers["X-Forwarded-For"] = os.environ["KHEPRI_IP"]

    # 1. opening call: salt, iterations, claim. No ciphertext yet.
    status, _, body = get(f"{base}/api/paste/{paste_id}", headers)
    meta = json.loads(body)
    if meta.get("error"):
        raise SystemExit("error: " + meta["error"])

    # 2. derive the key exactly the way the creator did.
    material = key_bytes + args.password.encode("utf-8")
    key = hashlib.pbkdf2_hmac("sha256", material, b64u_to_bytes(meta["salt"]),
                              meta["iterations"], dklen=32)

    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:
        raise SystemExit("error: needs the cryptography package — pip install cryptography")

    # 3. recover the proof from the claim, which is that proof encrypted under
    #    the same key. This is what the browser does on every read.
    claim_raw = b64u_to_bytes(meta["claim"])
    proof = AESGCM(key).decrypt(
        b64u_to_bytes(meta["claimIv"]), claim_raw, ("claim:" + paste_id).encode("ascii"))

    # 4. trade the proof for the ciphertext.
    status, _, body = get(f"{base}/api/paste/{paste_id}", headers, method="POST",
                          obj={"proof": b64u(proof)})
    data = json.loads(body)
    if data.get("error"):
        raise SystemExit("error: " + data["error"])

    # 5. decrypt. The paste id is additional data, as on the write side.
    raw = b64u_to_bytes(data["ct"])
    plaintext = AESGCM(key).decrypt(
        b64u_to_bytes(data["iv"]), raw, paste_id.encode("ascii")).decode("utf-8")

    # 6. a file paste is marker + metadata + base64 payload; text is anything else.
    if plaintext.startswith(FILE_MARKER + "\n"):
        head = FILE_MARKER + "\n"
        meta_end = plaintext.index("\n", len(head))
        m = json.loads(b64u_to_bytes(plaintext[len(head):meta_end]).decode("utf-8"))
        payload = plaintext[meta_end + 1:]
        blob = b64u_to_bytes("".join(payload.split()))
        if args.out:
            with open(args.out, "wb") as fh:
                fh.write(blob)
            print(json.dumps({"kind": "file", "name": m.get("name"),
                              "type": m.get("type", ""), "size": len(blob),
                              "saved": args.out}, indent=2))
        else:
            print(json.dumps({"kind": "file", "name": m.get("name"),
                              "type": m.get("type", ""), "size": len(blob),
                              "note": "pass --out <path> to save it"}, indent=2))
        return 0

    print(plaintext)
    return 0


if __name__ == "__main__":
    sys.exit(main())
