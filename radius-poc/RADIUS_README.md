# RADIUS - Remote Authentication Dial-In User Service

## What is RADIUS?

RADIUS is a **client-server networking protocol** (RFC 2865) that provides centralized **Authentication, Authorization, and Accounting (AAA)** for network access. It's used in:

- Wi-Fi enterprise authentication (WPA2-Enterprise / 802.1X)
- VPN access control
- ISP dial-up / PPP connections
- Network Device (router/switch) admin login
- VoIP systems

---

## Core Concepts

### AAA Model

| Component | Role |
|-----------|------|
| **Authentication** | Who are you? (verify identity via credentials) |
| **Authorization** | What can you do? (assign permissions/VLAN/bandwidth) |
| **Accounting** | What did you do? (log session start/stop/duration) |

### Actors

```
[Supplicant]  <---> [NAS / RADIUS Client]  <---> [RADIUS Server]  <---> [User DB]
(end user)        (Access Point, VPN GW,         (FreeRADIUS,             (LDAP,
                   Switch, Router)                Cisco ISE, etc.)         AD, SQL)
```

- **Supplicant**: The end user/device requesting access
- **NAS (Network Access Server)**: The device that enforces access (AP, VPN GW, switch) — acts as RADIUS *client*
- **RADIUS Server**: Validates credentials and returns policy decisions
- **User DB**: Backend identity store (LDAP, Active Directory, flat file, SQL)

---

## Protocol Details

- **Transport**: UDP (not TCP)
- **Port 1812**: Authentication & Authorization
- **Port 1813**: Accounting
- **Port 1645/1646**: Legacy (older implementations)
- **Shared Secret**: Pre-shared key between NAS and RADIUS server (used for packet integrity + password encryption)

### Packet Types

| Code | Name | Direction | Description |
|------|------|-----------|-------------|
| 1 | Access-Request | NAS → Server | User wants access |
| 2 | Access-Accept | Server → NAS | Grant access |
| 3 | Access-Reject | Server → NAS | Deny access |
| 4 | Accounting-Request | NAS → Server | Session accounting |
| 5 | Accounting-Response | Server → NAS | Ack accounting |
| 11 | Access-Challenge | Server → NAS | MFA / more info needed |

### Packet Structure

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Code      |  Identifier   |            Length             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                         Authenticator (16 bytes)             |
|                                                               |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Attributes ...
+-+-+-+-+-+-+-+-+-+-+-+-+-
```

### Password Encryption (PAP over RADIUS)

The password is **NOT sent in plaintext**. It's XOR'd with `MD5(shared_secret + authenticator)`:

```
encrypted_pass = password XOR MD5(secret + Request-Authenticator)
```

> Note: This is still considered weak — PEAP/EAP-TLS are preferred for modern deployments.

### Common Attributes (AVPs - Attribute Value Pairs)

| Type | Attribute | Example |
|------|-----------|---------|
| 1 | User-Name | `alice` |
| 2 | User-Password | (encrypted) |
| 4 | NAS-IP-Address | `192.168.1.1` |
| 5 | NAS-Port | `1` |
| 6 | Service-Type | `Framed-User` |
| 8 | Framed-IP-Address | `10.0.0.5` |
| 25 | Class | (policy group) |
| 64 | Tunnel-Type | VLAN |
| 81 | Tunnel-Private-Group-Id | VLAN ID |

---

## Authentication Flow (PAP)

```
Supplicant          NAS                    RADIUS Server
    |                |                          |
    |-- credentials->|                          |
    |                |--- Access-Request ------->|
    |                |    (User-Name,            |
    |                |     User-Password)        |
    |                |                          |-- check DB
    |                |<-- Access-Accept ---------|
    |                |    (or Reject/Challenge)  |
    |<-- network ----|                          |
        access
```

---

## PoC: Building a RADIUS Lab

The PoC uses **FreeRADIUS** (server) + two pure-Python clients — **no pip, no
third-party packages**, stdlib only.

### Architecture

```
[Python Client (NAS simulator)]  <--UDP 1812-->  [FreeRADIUS Server]
                                                        |
                                                  [users flat file]
```

### Option A: Docker-based (Recommended)

```bash
# docker-compose.yml handles everything — just run:
docker compose up -d
```

### Option B: Native Install (Debian/Ubuntu)

```bash
sudo apt-get install freeradius
# No pip install needed — clients use Python stdlib only
```

---

## FreeRADIUS Configuration

### 1. Add a NAS client — `/etc/freeradius/3.0/clients.conf`

```
client localhost_nas {
    ipaddr          = 127.0.0.1
    secret          = testing123
    shortname       = poc-nas
}
```

### 2. Add test users — `/etc/freeradius/3.0/users`

```
alice   Cleartext-Password := "password123"
        Reply-Message = "Hello, Alice!"

bob     Cleartext-Password := "bobsecret"
        Reply-Message = "Hello, Bob!"
        Tunnel-Type = VLAN,
        Tunnel-Medium-Type = IEEE-802,
        Tunnel-Private-Group-Id = "100"
```

### 3. Run FreeRADIUS in debug mode

```bash
sudo freeradius -X
# or inside Docker:
docker exec -it freeradius freeradius -X
```

---

## Python RADIUS Client (NAS Simulator)

Two scripts are provided — both use **Python stdlib only** (no pip required).

| Script | Purpose |
|--------|---------|
| `radius_client.py` | Full demo — 5 auth tests + accounting start/stop, human-readable output |
| `radius_raw.py` | Wire-level — hexdump + field-by-field annotation of every byte |

### `radius_client.py`

```python
#!/usr/bin/env python3
"""
RADIUS PoC Client — simulates a NAS sending Access-Request packets.
Pure stdlib — no pip install required.

Usage:
    python3 radius_client.py                          # full demo
    python3 radius_client.py --user alice --password password123
"""

import argparse, socket, struct, hashlib, os, sys

RADIUS_HOST    = "127.0.0.1"
AUTH_PORT      = 1812
ACCT_PORT      = 1813
SHARED_SECRET  = b"testing123"
NAS_IDENTIFIER = "poc-nas"

# Packet codes
ACCESS_REQUEST = 1;  ACCESS_ACCEPT = 2
ACCESS_REJECT  = 3;  ACCT_REQUEST  = 4;  ACCT_RESPONSE = 5

# AVP type numbers
ATTR = {
    "User-Name": 1, "User-Password": 2, "NAS-IP-Address": 4,
    "NAS-Port": 5,  "Reply-Message": 18, "NAS-Identifier": 32,
    "Acct-Status-Type": 40, "Acct-Session-Id": 44,
    "Framed-IP-Address": 8, "Tunnel-Private-Group-Id": 81,
}


def encode_attr(t, v):
    return bytes([t, 2 + len(v)]) + v


def encrypt_password(password, secret, authenticator):
    """RFC 2865 §5.2 — XOR with MD5(secret + last_block)."""
    p = password.encode()
    p += b"\x00" * ((16 - len(p) % 16) % 16)
    result, last = b"", authenticator
    for i in range(0, len(p), 16):
        digest = hashlib.md5(secret + last).digest()
        block  = bytes(a ^ b for a, b in zip(p[i:i+16], digest))
        result += block; last = block
    return result


def authenticate(username, password):
    authenticator = os.urandom(16)
    attrs  = encode_attr(ATTR["User-Name"],      username.encode())
    attrs += encode_attr(ATTR["User-Password"],  encrypt_password(password, SHARED_SECRET, authenticator))
    attrs += encode_attr(ATTR["NAS-IP-Address"], socket.inet_aton("127.0.0.1"))
    attrs += encode_attr(ATTR["NAS-Port"],       (0).to_bytes(4, "big"))
    attrs += encode_attr(ATTR["NAS-Identifier"], NAS_IDENTIFIER.encode())

    pkt = struct.pack(">BBH16s", ACCESS_REQUEST, os.getrandbits(8),
                      20 + len(attrs), authenticator) + attrs

    print(f"\n[>] Access-Request  user='{username}'  ({len(pkt)} bytes)")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5)
        sock.sendto(pkt, (RADIUS_HOST, AUTH_PORT))
        reply, _ = sock.recvfrom(4096)
    except socket.timeout:
        print("    [!] Timeout — is FreeRADIUS running?"); return "TIMEOUT"
    finally:
        sock.close()

    code = reply[0]
    name = {ACCESS_ACCEPT: "Access-Accept ✓", ACCESS_REJECT: "Access-Reject ✗"}.get(code, f"code={code}")
    print(f"[<] {name}")

    # Print reply attributes
    pos, length = 20, struct.unpack(">H", reply[2:4])[0]
    while pos < length:
        t, ln, val = reply[pos], reply[pos+1], reply[pos+2:pos+reply[pos+1]]
        if t == ATTR["Reply-Message"]:
            print(f"    Reply-Message          = {val.decode()}")
        elif t == ATTR["Framed-IP-Address"]:
            print(f"    Framed-IP-Address      = {socket.inet_ntoa(val)}")
        elif t == ATTR["Tunnel-Private-Group-Id"]:
            print(f"    Tunnel-Private-Group-Id= {val.decode()}")
        pos += ln
    return name


def send_accounting(username, session_id, status):
    attrs  = encode_attr(ATTR["User-Name"],        username.encode())
    attrs += encode_attr(ATTR["NAS-Identifier"],   NAS_IDENTIFIER.encode())
    attrs += encode_attr(ATTR["Acct-Status-Type"], status.to_bytes(4, "big"))
    attrs += encode_attr(ATTR["Acct-Session-Id"],  session_id.encode())
    attrs += encode_attr(ATTR["NAS-IP-Address"],   socket.inet_aton("127.0.0.1"))

    pkt = struct.pack(">BBH16s", 4, os.getrandbits(8),
                      20 + len(attrs), os.urandom(16)) + attrs
    label = {1:"Start", 2:"Stop", 3:"Interim-Update"}.get(status, str(status))
    print(f"\n[>] Accounting-Request ({label})  user='{username}'")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5)
        sock.sendto(pkt, (RADIUS_HOST, ACCT_PORT))
        reply, _ = sock.recvfrom(4096)
        print(f"[<] Accounting-Response ✓  code={reply[0]}")
    except socket.timeout:
        print("    [!] Timeout")
    finally:
        sock.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--user"); parser.add_argument("--password")
    args = parser.parse_args()

    if args.user:
        authenticate(args.user, args.password or "")
    else:
        for user, pwd, desc in [
            ("alice", "password123",  "valid credentials"),
            ("bob",   "bobsecret",    "valid credentials (VLAN policy)"),
            ("admin", "admin@radius", "valid credentials (admin)"),
            ("alice", "wrongpass",    "wrong password"),
            ("ghost", "noexist",      "unknown user"),
        ]:
            print(f"\n  >> {desc}")
            authenticate(user, pwd)

        send_accounting("alice", "sess-abc123", status=1)  # Start
        send_accounting("alice", "sess-abc123", status=2)  # Stop
```

---

## Wire-Level Inspector

`radius_raw.py` sends one Access-Request for `alice` and prints a **hex dump +
field-by-field annotation** of both the outgoing and incoming packets — useful
for understanding the exact wire format.

### `radius_raw.py`

```python
#!/usr/bin/env python3
"""
RADIUS Raw Packet Inspector — hand-crafted UDP packet with hexdump output.
Pure stdlib. Educational — shows every byte on the wire.
"""

import socket, struct, hashlib, os

SECRET      = b"testing123"
RADIUS_HOST = "127.0.0.1"
AUTH_PORT   = 1812


def encrypt_password(password, secret, authenticator):
    p = password.encode()
    p += b"\x00" * ((16 - len(p) % 16) % 16)
    result, last = b"", authenticator
    for i in range(0, len(p), 16):
        digest = hashlib.md5(secret + last).digest()
        block  = bytes(a ^ b for a, b in zip(p[i:i+16], digest))
        result += block; last = block
    return result


def hexdump(data, indent=4):
    for i in range(0, len(data), 16):
        chunk  = data[i:i+16]
        hex_   = " ".join(f"{b:02x}" for b in chunk)
        ascii_ = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        print(f"{' '*indent}{i:04x}  {hex_:<48}  |{ascii_}|")


def annotate(data):
    code, id_, length = data[0], data[1], struct.unpack(">H", data[2:4])[0]
    names = {1:"Access-Request", 2:"Access-Accept",
             3:"Access-Reject",  11:"Access-Challenge"}
    attr_names = {1:"User-Name", 2:"User-Password", 4:"NAS-IP-Address",
                  5:"NAS-Port",  18:"Reply-Message", 32:"NAS-Identifier"}

    print(f"  ┌─ Code         : {code:3d}  ({names.get(code, '?')})")
    print(f"  ├─ Identifier   : {id_}")
    print(f"  ├─ Length       : {length}")
    print(f"  ├─ Authenticator: {data[4:20].hex()}")
    print(f"  └─ Attributes:")

    pos = 20
    while pos < length:
        t, ln, val = data[pos], data[pos+1], data[pos+2:pos+data[pos+1]]
        name = attr_names.get(t, f"Type-{t}")
        if t == 4:    display = socket.inet_ntoa(val)
        elif t == 2:  display = f"(encrypted) {val.hex()}"
        elif t == 5:  display = str(int.from_bytes(val, "big"))
        else:         display = val.decode("utf-8", errors="replace")
        print(f"       [{t:3d}] {name:<25} len={ln:2d}  val={display}")
        pos += ln


if __name__ == "__main__":
    authenticator = os.urandom(16)
    def attr(t, v): return bytes([t, 2+len(v)]) + v

    attrs  = attr(1,  b"alice")
    attrs += attr(2,  encrypt_password("password123", SECRET, authenticator))
    attrs += attr(4,  socket.inet_aton("127.0.0.1"))
    attrs += attr(5,  (0).to_bytes(4, "big"))
    attrs += attr(32, b"poc-nas")

    pkt = struct.pack(">BBH16s", 1, 42, 20+len(attrs), authenticator) + attrs

    print("="*60)
    print("  OUTGOING Access-Request — wire bytes")
    print("="*60)
    hexdump(pkt); print(); annotate(pkt)

    print("\n  Sending to FreeRADIUS...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)
    try:
        sock.sendto(pkt, (RADIUS_HOST, AUTH_PORT))
        reply, addr = sock.recvfrom(4096)
        print(f"\n{'='*60}")
        print(f"  INCOMING response from {addr} — wire bytes")
        print(f"{'='*60}")
        hexdump(reply); print(); annotate(reply)
    except socket.timeout:
        print("  [!] Timeout — is FreeRADIUS running?  (docker compose up -d)")
    finally:
        sock.close()
```

---

## Security Notes

| Concern | Detail |
|---------|--------|
| **PAP** | Password obfuscated with MD5 — vulnerable to offline cracking if traffic is captured |
| **CHAP** | Challenge-response; server needs plaintext password stored |
| **PEAP/EAP-TLS** | Preferred for Wi-Fi; wraps EAP in TLS tunnel |
| **Shared Secret** | Must be long, random, and rotated; weak secrets are crackable |
| **UDP** | No built-in reliability or ordering; susceptible to spoofing without IPsec |
| **RadSec** | RADIUS over TLS/TCP (RFC 6614) — modern secure transport |

---

## Quick Reference

```
# Test with radtest (ships with FreeRADIUS utils)
radtest alice password123 127.0.0.1 0 testing123

# Capture RADIUS traffic
sudo tcpdump -i lo -n udp port 1812 -w radius.pcap

# Open in Wireshark (knows RADIUS dissector)
wireshark radius.pcap
```

---

## Further Reading

- RFC 2865 — RADIUS (Authentication)
- RFC 2866 — RADIUS Accounting
- RFC 3579 — RADIUS EAP Support
- RFC 6614 — RadSec (RADIUS over TLS)
- [FreeRADIUS Documentation](https://wiki.freeradius.org)
- [pyrad library](https://github.com/wichert/pyrad)
