#!/usr/bin/env python3
"""
RADIUS PoC Client
Simulates a NAS sending Access-Request and Accounting-Request packets.

Usage:
    python3 radius_client.py
    python3 radius_client.py --user alice --password password123
"""

import argparse
import socket
import struct
import hashlib
import os
import random
import sys

# ── Configuration ──────────────────────────────────────────────────────────────
RADIUS_HOST    = "127.0.0.1"
AUTH_PORT      = 1812
ACCT_PORT      = 1813
SHARED_SECRET  = b"testing123"
NAS_IDENTIFIER = "poc-nas"
TIMEOUT        = 5  # seconds

# ── RADIUS packet codes ────────────────────────────────────────────────────────
ACCESS_REQUEST    = 1
ACCESS_ACCEPT     = 2
ACCESS_REJECT     = 3
ACCT_REQUEST      = 4
ACCT_RESPONSE     = 5
ACCESS_CHALLENGE  = 11

CODE_NAMES = {
    ACCESS_ACCEPT:   "Access-Accept   ✓",
    ACCESS_REJECT:   "Access-Reject   ✗",
    ACCESS_CHALLENGE:"Access-Challenge ?",
}

# ── RADIUS attribute type numbers ─────────────────────────────────────────────
ATTR = {
    "User-Name":               1,
    "User-Password":           2,
    "NAS-IP-Address":          4,
    "NAS-Port":                5,
    "Service-Type":            6,
    "Framed-IP-Address":       8,
    "Reply-Message":           18,
    "NAS-Identifier":          32,
    "Acct-Status-Type":        40,
    "Acct-Session-Id":         44,
    "Tunnel-Type":             64,
    "Tunnel-Medium-Type":      65,
    "Tunnel-Private-Group-Id": 81,
}
ATTR_NAMES = {v: k for k, v in ATTR.items()}   # reverse map for display


# ── Utility helpers ────────────────────────────────────────────────────────────

def encode_attr(attr_type: int, value: bytes) -> bytes:
    """Encode a single TLV attribute."""
    return bytes([attr_type, 2 + len(value)]) + value


def encrypt_password(password: str, secret: bytes, authenticator: bytes) -> bytes:
    """
    RFC 2865 §5.2 — User-Password obfuscation.
    c[i] = p[i] XOR MD5(secret + last_cipher_block)
    """
    p = password.encode("utf-8")
    # Pad to nearest 16-byte boundary
    pad = (16 - len(p) % 16) % 16
    p += b"\x00" * pad

    result, last = b"", authenticator
    for i in range(0, len(p), 16):
        digest = hashlib.md5(secret + last).digest()
        block  = bytes(a ^ b for a, b in zip(p[i:i+16], digest))
        result += block
        last    = block
    return result


def parse_attributes(data: bytes, start: int, end: int) -> list:
    """Parse AVP list from raw bytes; return [(type, value_bytes), ...]."""
    attrs, pos = [], start
    while pos < end:
        t   = data[pos]
        ln  = data[pos + 1]
        val = data[pos + 2: pos + ln]
        attrs.append((t, val))
        pos += ln
    return attrs


def print_attrs(attrs: list):
    for t, val in attrs:
        name = ATTR_NAMES.get(t, f"Attr-{t}")
        # Decode known string/IP types nicely
        if t in (ATTR["Reply-Message"], ATTR["NAS-Identifier"],
                 ATTR["Tunnel-Private-Group-Id"]):
            display = val.decode("utf-8", errors="replace")
        elif t in (ATTR["NAS-IP-Address"], ATTR["Framed-IP-Address"]):
            display = socket.inet_ntoa(val)
        elif t in (ATTR["Service-Type"], ATTR["Acct-Status-Type"],
                   ATTR["NAS-Port"], ATTR["Tunnel-Type"],
                   ATTR["Tunnel-Medium-Type"]):
            display = str(int.from_bytes(val, "big"))
        else:
            display = val.hex()
        print(f"      {name:<30} = {display}")


# ── Core send/receive ──────────────────────────────────────────────────────────

def send_udp(packet: bytes, host: str, port: int) -> bytes:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(TIMEOUT)
    try:
        sock.sendto(packet, (host, port))
        data, _ = sock.recvfrom(4096)
        return data
    finally:
        sock.close()


# ── Access-Request ─────────────────────────────────────────────────────────────

def authenticate(username: str, password: str) -> str:
    """
    Build and send an Access-Request; print the server response.
    Returns 'ACCEPT', 'REJECT', or 'CHALLENGE'.
    """
    print(f"\n{'='*60}")
    print(f"  Access-Request  →  user='{username}'")
    print(f"{'='*60}")

    identifier    = random.getrandbits(8)
    authenticator = os.urandom(16)

    # Build attributes
    attrs  = encode_attr(ATTR["User-Name"],      username.encode())
    attrs += encode_attr(ATTR["User-Password"],  encrypt_password(password, SHARED_SECRET, authenticator))
    attrs += encode_attr(ATTR["NAS-IP-Address"], socket.inet_aton("127.0.0.1"))
    attrs += encode_attr(ATTR["NAS-Port"],       (0).to_bytes(4, "big"))
    attrs += encode_attr(ATTR["NAS-Identifier"], NAS_IDENTIFIER.encode())

    length = 20 + len(attrs)
    header = struct.pack(">BBH16s", ACCESS_REQUEST, identifier, length, authenticator)
    packet = header + attrs

    print(f"  Sending {len(packet)} bytes to {RADIUS_HOST}:{AUTH_PORT}")
    print(f"  Attributes sent:")
    print(f"      {'User-Name':<30} = {username}")
    print(f"      {'User-Password':<30} = (encrypted, {len(password)} chars)")
    print(f"      {'NAS-IP-Address':<30} = 127.0.0.1")
    print(f"      {'NAS-Identifier':<30} = {NAS_IDENTIFIER}")

    try:
        reply = send_udp(packet, RADIUS_HOST, AUTH_PORT)
    except socket.timeout:
        print("\n  [!] Timeout — is FreeRADIUS running?  (docker compose up -d)")
        return "TIMEOUT"

    r_code, r_id, r_len = struct.unpack(">BBH", reply[:4])
    result = CODE_NAMES.get(r_code, f"Unknown ({r_code})")

    print(f"\n  Response: code={r_code}  →  {result}")

    r_attrs = parse_attributes(reply, 20, r_len)
    if r_attrs:
        print(f"  Reply attributes:")
        print_attrs(r_attrs)

    return result.split()[0]   # 'Access-Accept', 'Access-Reject', etc.


# ── Accounting-Request ─────────────────────────────────────────────────────────

ACCT_STATUS = {1: "Start", 2: "Stop", 3: "Interim-Update"}

def send_accounting(username: str, session_id: str, status: int = 1):
    print(f"\n{'='*60}")
    print(f"  Accounting-Request ({ACCT_STATUS.get(status, status)})  →  user='{username}'")
    print(f"{'='*60}")

    identifier    = random.getrandbits(8)
    authenticator = os.urandom(16)

    attrs  = encode_attr(ATTR["User-Name"],       username.encode())
    attrs += encode_attr(ATTR["NAS-Identifier"],  NAS_IDENTIFIER.encode())
    attrs += encode_attr(ATTR["Acct-Status-Type"],status.to_bytes(4, "big"))
    attrs += encode_attr(ATTR["Acct-Session-Id"], session_id.encode())
    attrs += encode_attr(ATTR["NAS-IP-Address"],  socket.inet_aton("127.0.0.1"))

    length = 20 + len(attrs)
    header = struct.pack(">BBH16s", ACCT_REQUEST, identifier, length, authenticator)
    packet = header + attrs

    print(f"  Sending {len(packet)} bytes to {RADIUS_HOST}:{ACCT_PORT}")

    try:
        reply = send_udp(packet, RADIUS_HOST, ACCT_PORT)
        r_code = reply[0]
        print(f"  Response: code={r_code} → {'Accounting-Response ✓' if r_code == ACCT_RESPONSE else 'Unknown'}")
    except socket.timeout:
        print("  [!] Timeout — accounting port not responding.")


# ── Main ───────────────────────────────────────────────────────────────────────

def run_full_demo():
    print("\n" + "="*60)
    print("  RADIUS PoC — Full Demo")
    print(f"  Server: {RADIUS_HOST}:{AUTH_PORT}  |  Secret: {SHARED_SECRET.decode()}")
    print("="*60)

    tests = [
        ("alice", "password123", "valid credentials"),
        ("bob",   "bobsecret",   "valid credentials (VLAN policy)"),
        ("admin", "admin@radius","valid credentials (admin)"),
        ("alice", "wrongpass",   "wrong password"),
        ("ghost", "noexist",     "unknown user"),
    ]

    results = []
    for user, pwd, desc in tests:
        print(f"\n  >> Test: {desc}")
        result = authenticate(user, pwd)
        results.append((user, desc, result))

    # Accounting demo for a successful session
    print("\n\n  >> Accounting demo for alice's session")
    send_accounting("alice", session_id="sess-abc123", status=1)  # Start
    send_accounting("alice", session_id="sess-abc123", status=2)  # Stop

    # Summary
    print(f"\n\n{'='*60}")
    print("  SUMMARY")
    print(f"{'='*60}")
    for user, desc, result in results:
        icon = "✓" if "Accept" in result else "✗"
        print(f"  {icon}  {user:<10}  {desc:<35}  {result}")
    print()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="RADIUS PoC Client")
    parser.add_argument("--user",     help="Single user to authenticate")
    parser.add_argument("--password", help="Password for single-user mode")
    parser.add_argument("--host",     default=RADIUS_HOST, help="RADIUS server host")
    args = parser.parse_args()

    if args.host != RADIUS_HOST:
        RADIUS_HOST = args.host

    if args.user:
        if not args.password:
            print("Error: --password required with --user")
            sys.exit(1)
        authenticate(args.user, args.password)
    else:
        run_full_demo()
