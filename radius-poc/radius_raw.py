#!/usr/bin/env python3
"""
RADIUS Raw Packet Inspector
Sends a hand-crafted Access-Request and pretty-prints the wire bytes.
No external dependencies — pure stdlib.
"""

import socket
import struct
import hashlib
import os

SECRET        = b"testing123"
RADIUS_HOST   = "127.0.0.1"
AUTH_PORT     = 1812


def encrypt_password(password: str, secret: bytes, authenticator: bytes) -> bytes:
    p   = password.encode()
    pad = (16 - len(p) % 16) % 16
    p  += b"\x00" * pad
    result, last = b"", authenticator
    for i in range(0, len(p), 16):
        digest = hashlib.md5(secret + last).digest()
        block  = bytes(a ^ b for a, b in zip(p[i:i+16], digest))
        result += block
        last    = block
    return result


def hexdump(data: bytes, indent: int = 4):
    """Print a classic hexdump."""
    for i in range(0, len(data), 16):
        chunk  = data[i:i+16]
        hex_   = " ".join(f"{b:02x}" for b in chunk)
        ascii_ = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        print(f"{' '*indent}{i:04x}  {hex_:<48}  |{ascii_}|")


def annotate_packet(data: bytes):
    """Print field-by-field annotation of a RADIUS packet."""
    code   = data[0]
    id_    = data[1]
    length = struct.unpack(">H", data[2:4])[0]
    auth   = data[4:20]

    code_name = {1:"Access-Request", 2:"Access-Accept",
                 3:"Access-Reject",  4:"Acct-Request",
                 11:"Access-Challenge"}.get(code, f"Unknown({code})")

    print(f"  ┌─ Code         : {code:3d}  ({code_name})")
    print(f"  ├─ Identifier   : {id_:3d}")
    print(f"  ├─ Length       : {length}")
    print(f"  ├─ Authenticator: {auth.hex()}")
    print(f"  └─ Attributes:")

    attr_type_names = {
        1:"User-Name", 2:"User-Password", 4:"NAS-IP-Address",
        5:"NAS-Port",  18:"Reply-Message", 32:"NAS-Identifier",
        40:"Acct-Status-Type", 81:"Tunnel-Private-Group-Id",
    }

    pos = 20
    while pos < length:
        t   = data[pos]
        ln  = data[pos + 1]
        val = data[pos + 2: pos + ln]
        name = attr_type_names.get(t, f"Type-{t}")

        if t == 4:   # IP
            display = socket.inet_ntoa(val)
        elif t == 2: # encrypted password
            display = f"(encrypted) {val.hex()}"
        elif t in (5, 40):
            display = str(int.from_bytes(val, "big"))
        else:
            display = val.decode("utf-8", errors="replace")

        print(f"       [{t:3d}] {name:<25} len={ln:2d}  val={display}")
        pos += ln


def main():
    username = "alice"
    password = "password123"

    authenticator = os.urandom(16)
    identifier    = 42

    enc_pass = encrypt_password(password, SECRET, authenticator)

    def attr(t, v): return bytes([t, 2 + len(v)]) + v

    attrs  = attr(1,  username.encode())            # User-Name
    attrs += attr(2,  enc_pass)                      # User-Password (encrypted)
    attrs += attr(4,  socket.inet_aton("127.0.0.1")) # NAS-IP-Address
    attrs += attr(5,  (0).to_bytes(4, "big"))        # NAS-Port
    attrs += attr(32, b"poc-nas")                    # NAS-Identifier

    length = 20 + len(attrs)
    header = struct.pack(">BBH16s", 1, identifier, length, authenticator)
    packet = header + attrs

    print("=" * 60)
    print("  OUTGOING Access-Request — wire bytes")
    print("=" * 60)
    hexdump(packet)
    print()
    annotate_packet(packet)

    print("\n  Sending to FreeRADIUS...")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)
    try:
        sock.sendto(packet, (RADIUS_HOST, AUTH_PORT))
        reply, addr = sock.recvfrom(4096)

        print(f"\n{'='*60}")
        print(f"  INCOMING response from {addr} — wire bytes")
        print(f"{'='*60}")
        hexdump(reply)
        print()
        annotate_packet(reply)

    except socket.timeout:
        print("  [!] Timeout — is FreeRADIUS running?  (docker compose up -d)")
    finally:
        sock.close()


if __name__ == "__main__":
    main()
