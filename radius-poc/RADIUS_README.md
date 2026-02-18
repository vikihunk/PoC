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

The PoC uses **FreeRADIUS** (server) + a **Python RADIUS client** via the `pyrad` library.

### Architecture

```
[Python Client (NAS simulator)]  <--UDP 1812-->  [FreeRADIUS Server]
                                                        |
                                                  [users flat file]
```

### Option A: Docker-based (Recommended)

```bash
# Pull a ready-made FreeRADIUS image
docker run -d --name freeradius \
  -p 1812:1812/udp \
  -p 1813:1813/udp \
  freeradius/freeradius-server:latest

# Install the Python RADIUS client library
pip install pyrad
```

### Option B: Native Install (Debian/Ubuntu)

```bash
sudo apt-get install freeradius
pip install pyrad
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

### `radius_client.py`

```python
#!/usr/bin/env python3
"""
RADIUS PoC Client — simulates a NAS sending Access-Request packets.
Requires: pip install pyrad
"""

import pyrad.packet
from pyrad.client import Client
from pyrad.dictionary import Dictionary
import pyrad.dictionary
import os

# ── Configuration ──────────────────────────────────────────────
RADIUS_HOST   = "127.0.0.1"
RADIUS_PORT   = 1812
SHARED_SECRET = b"testing123"          # must match clients.conf
NAS_IDENTIFIER = "poc-nas"

# pyrad needs a RADIUS dictionary file; use the bundled one or provide a path
DICT_PATH = "/usr/share/freeradius/dictionary"  # adjust if needed


def authenticate(username: str, password: str) -> str:
    """
    Send an Access-Request and return 'ACCEPT', 'REJECT', or 'CHALLENGE'.
    """
    try:
        dictionary = Dictionary(DICT_PATH)
    except FileNotFoundError:
        # Minimal inline dictionary for the PoC
        dictionary = Dictionary()

    srv = Client(
        server=RADIUS_HOST,
        authport=RADIUS_PORT,
        secret=SHARED_SECRET,
        dict=dictionary,
    )
    srv.timeout = 5
    srv.retries = 1

    # Build Access-Request
    req = srv.CreateAuthPacket(
        code=pyrad.packet.AccessRequest,
        User_Name=username,
        NAS_Identifier=NAS_IDENTIFIER,
    )
    req["User-Password"] = req.PwCrypt(password)   # encrypt per RFC 2865

    print(f"\n[>] Sending Access-Request for user='{username}'")
    print(f"    Server : {RADIUS_HOST}:{RADIUS_PORT}")
    print(f"    Secret : {SHARED_SECRET.decode()}")

    reply = srv.SendPacket(req)

    code_map = {
        pyrad.packet.AccessAccept:    "ACCEPT",
        pyrad.packet.AccessReject:    "REJECT",
        pyrad.packet.AccessChallenge: "CHALLENGE",
    }
    result = code_map.get(reply.code, f"UNKNOWN ({reply.code})")

    print(f"[<] Response code : {reply.code} → {result}")

    if "Reply-Message" in reply:
        print(f"    Reply-Message : {reply['Reply-Message'][0]}")

    if result == "ACCEPT":
        # Print any authorization attributes returned
        for attr in ("Framed-IP-Address", "Tunnel-Private-Group-Id", "Class"):
            if attr in reply:
                print(f"    {attr} : {reply[attr][0]}")

    return result


def send_accounting(username: str, session_id: str, status_type: int = 1):
    """
    Send an Accounting-Request (Start=1, Stop=2, Interim=3).
    """
    try:
        dictionary = Dictionary(DICT_PATH)
    except FileNotFoundError:
        dictionary = Dictionary()

    srv = Client(
        server=RADIUS_HOST,
        acctport=1813,
        secret=SHARED_SECRET,
        dict=dictionary,
    )

    req = srv.CreateAcctPacket(User_Name=username)
    req["Acct-Status-Type"]  = status_type
    req["Acct-Session-Id"]   = session_id
    req["NAS-Identifier"]    = NAS_IDENTIFIER

    status_name = {1: "Start", 2: "Stop", 3: "Interim-Update"}.get(status_type, str(status_type))
    print(f"\n[>] Sending Accounting-Request ({status_name}) for user='{username}'")

    reply = srv.SendPacket(req)
    print(f"[<] Accounting-Response code : {reply.code}")


if __name__ == "__main__":
    print("=" * 50)
    print("  RADIUS PoC — Authentication Demo")
    print("=" * 50)

    # Test 1: valid credentials
    authenticate("alice", "password123")

    # Test 2: wrong password
    authenticate("alice", "wrongpassword")

    # Test 3: unknown user
    authenticate("mallory", "hacker")

    # Test 4: accounting (optional — comment out if server not running acct)
    # send_accounting("alice", session_id="sess-001", status_type=1)  # Start
    # send_accounting("alice", session_id="sess-001", status_type=2)  # Stop
```

---

## Raw Packet PoC (no library)

To understand the wire format at a byte level:

### `radius_raw.py`

```python
#!/usr/bin/env python3
"""
Low-level RADIUS Access-Request — hand-crafted UDP packet.
Educational only; does NOT handle the full RFC correctly.
"""

import socket
import os
import struct
import hashlib


def encrypt_password(password: str, secret: bytes, authenticator: bytes) -> bytes:
    """RFC 2865 §5.2 password obfuscation."""
    password_bytes = password.encode("utf-8")
    # Pad to 16-byte boundary
    pad_len = (16 - len(password_bytes) % 16) % 16
    password_bytes += b"\x00" * pad_len

    result = b""
    last = authenticator
    for i in range(0, len(password_bytes), 16):
        digest = hashlib.md5(secret + last).digest()
        chunk = bytes(a ^ b for a, b in zip(password_bytes[i:i+16], digest))
        result += chunk
        last = chunk
    return result


def build_access_request(username: str, password: str, secret: bytes) -> bytes:
    identifier    = 1
    authenticator = os.urandom(16)

    # Attribute: User-Name (type=1)
    uname_bytes = username.encode()
    attr_username = bytes([1, 2 + len(uname_bytes)]) + uname_bytes

    # Attribute: User-Password (type=2)
    enc_pass = encrypt_password(password, secret, authenticator)
    attr_password = bytes([2, 2 + len(enc_pass)]) + enc_pass

    # Attribute: NAS-IP-Address (type=4) — 127.0.0.1
    attr_nas_ip = bytes([4, 6]) + socket.inet_aton("127.0.0.1")

    # Attribute: NAS-Port (type=5)
    attr_nas_port = bytes([5, 6]) + struct.pack(">I", 0)

    attributes = attr_username + attr_password + attr_nas_ip + attr_nas_port

    # Header: Code=1, ID, Length (2 bytes), Authenticator (16 bytes)
    length = 20 + len(attributes)
    header = struct.pack(">BBH16s", 1, identifier, length, authenticator)

    return header + attributes


def parse_response(data: bytes):
    code, identifier, length = struct.unpack(">BBH", data[:4])
    authenticator = data[4:20]
    code_map = {2: "Access-Accept", 3: "Access-Reject", 11: "Access-Challenge"}
    print(f"Response code: {code} ({code_map.get(code, 'Unknown')})")

    # Parse attributes
    pos = 20
    while pos < length:
        attr_type   = data[pos]
        attr_length = data[pos + 1]
        attr_value  = data[pos + 2: pos + attr_length]
        if attr_type == 18:  # Reply-Message
            print(f"  Reply-Message: {attr_value.decode(errors='replace')}")
        pos += attr_length


if __name__ == "__main__":
    SECRET = b"testing123"
    packet = build_access_request("alice", "password123", SECRET)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)
    sock.sendto(packet, ("127.0.0.1", 1812))
    print("Sent Access-Request, waiting for reply...")

    try:
        data, addr = sock.recvfrom(4096)
        parse_response(data)
    except socket.timeout:
        print("No response (timeout). Is FreeRADIUS running?")
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
