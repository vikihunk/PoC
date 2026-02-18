# RADIUS PoC — Setup & Run Guide

A hands-on lab that runs a real **FreeRADIUS** server in Docker and exercises it
with two pure-Python clients (no external dependencies beyond Docker).

---

## Directory Structure

```
radius-poc/
├── docker-compose.yml                  # FreeRADIUS service definition
├── freeradius-config/
│   ├── clients.conf                    # NAS clients allowed to talk to the server
│   └── users                           # Test user credentials + reply attributes
├── radius_client.py                    # High-level client — full demo + accounting
├── radius_raw.py                       # Wire-level client — hexdump + field annotation
├── run_poc.sh                          # One-shot runner script
└── POC_README.md                       # This file
```

---

## Prerequisites

| Requirement | Check |
|-------------|-------|
| Docker | `docker --version` |
| Python 3.x | `python3 --version` |
| User in `docker` group | `groups \| grep docker` |

> **No pip / no third-party Python packages required.**
> Both client scripts use Python stdlib only.

---

## Step 1 — Fix Docker Permissions

By default your user may not have access to the Docker socket.
Run once, then start a new shell (or use `newgrp`):

```bash
sudo usermod -aG docker $USER
newgrp docker          # activate in current shell without logging out
```

Verify:

```bash
docker info | head -3
```

---

## Step 2 — Start FreeRADIUS

```bash
cd ~/workspace/radius-poc
docker compose up -d
```

The container mounts two local config files:

| Local file | Container path | Purpose |
|------------|---------------|---------|
| `freeradius-config/clients.conf` | `/etc/freeradius/3.0/clients.conf` | Registers `poc-nas` as an allowed NAS client |
| `freeradius-config/users` | `/etc/freeradius/3.0/mods-config/files/authorize` | Defines test users + reply attributes |

FreeRADIUS starts in **debug mode** (`freeradius -X`) — every packet processed is
logged in full detail.

### Watch the server log (optional — open a second terminal)

```bash
docker compose logs -f
```

### Confirm it's ready

```bash
docker compose logs | grep "Ready to process requests"
```

---

## Step 3 — Run the Full Demo Client

```bash
python3 radius_client.py
```

This runs **5 authentication tests** followed by **2 accounting packets**:

| Test | User | Password | Expected |
|------|------|----------|----------|
| 1 | `alice` | `password123` | Access-Accept + Framed-IP |
| 2 | `bob` | `bobsecret` | Access-Accept + VLAN 100 |
| 3 | `admin` | `admin@radius` | Access-Accept + Admin service |
| 4 | `alice` | `wrongpass` | Access-Reject |
| 5 | `ghost` | `noexist` | Access-Reject |
| 6 | Accounting Start | `alice` | Accounting-Response |
| 7 | Accounting Stop | `alice` | Accounting-Response |

### Example output

```
============================================================
  RADIUS PoC — Full Demo
  Server: 127.0.0.1:1812  |  Secret: testing123
============================================================

  >> Test: valid credentials

============================================================
  Access-Request  →  user='alice'
============================================================
  Sending 68 bytes to 127.0.0.1:1812
  Attributes sent:
      User-Name                      = alice
      User-Password                  = (encrypted, 11 chars)
      NAS-IP-Address                 = 127.0.0.1
      NAS-Identifier                 = poc-nas

  Response: code=2  →  Access-Accept   ✓
  Reply attributes:
      Reply-Message                  = Welcome, Alice!
      Framed-IP-Address              = 10.0.0.10

...

============================================================
  SUMMARY
============================================================
  ✓  alice      valid credentials                    Access-Accept
  ✓  bob        valid credentials (VLAN policy)      Access-Accept
  ✓  admin      valid credentials (admin)            Access-Accept
  ✗  alice      wrong password                       Access-Reject
  ✗  ghost      unknown user                         Access-Reject
```

### Single-user mode

```bash
python3 radius_client.py --user alice --password password123
python3 radius_client.py --user bob   --password bobsecret
```

---

## Step 4 — Run the Wire-Level Inspector

```bash
python3 radius_raw.py
```

Sends one Access-Request for `alice` and prints:

1. The **outgoing packet** as a hex dump + field-by-field annotation
2. The **incoming response** in the same format

### Example output

```
============================================================
  OUTGOING Access-Request — wire bytes
============================================================
    0000  01 2a 00 44 8f 3b a1 c2 ...  |.*...;..|
    0010  ...

  ┌─ Code         :   1  (Access-Request)
  ├─ Identifier   :  42
  ├─ Length       :  68
  ├─ Authenticator: 8f3ba1c2...
  └─ Attributes:
       [  1] User-Name              len= 7  val=alice
       [  2] User-Password          len=18  val=(encrypted) 3f8a...
       [  4] NAS-IP-Address         len= 6  val=127.0.0.1
       [  5] NAS-Port               len= 6  val=0
       [ 32] NAS-Identifier         len= 9  val=poc-nas

  Sending to FreeRADIUS...

============================================================
  INCOMING response from ('127.0.0.1', 1812) — wire bytes
============================================================
    ...
  ┌─ Code         :   2  (Access-Accept)
  ├─ Identifier   :  42
  ├─ Length       :  38
  ├─ Authenticator: ...
  └─ Attributes:
       [ 18] Reply-Message          len=18  val=Welcome, Alice!
       [  8] Framed-IP-Address      len= 6  val=10.0.0.10
```

---

## Step 5 — One-Shot Runner (all of the above)

```bash
./run_poc.sh
```

This script:
1. Starts the Docker container
2. Waits until FreeRADIUS is ready
3. Prints the last 20 lines of the server log
4. Runs `radius_client.py` (full demo)
5. Runs `radius_raw.py` (wire hexdump)
6. Prints matching server-side log lines
7. Prints helpful follow-up commands

---

## Test Users Reference

Defined in `freeradius-config/users`:

| Username | Password | Reply Attributes |
|----------|----------|-----------------|
| `alice` | `password123` | `Reply-Message`, `Framed-IP-Address = 10.0.0.10` |
| `bob` | `bobsecret` | `Reply-Message`, `Tunnel-Type = VLAN`, `Tunnel-Private-Group-Id = 100` |
| `admin` | `admin@radius` | `Reply-Message`, `Service-Type = Administrative-User` |

---

## Shared Secret

Both `clients.conf` and the Python clients use:

```
testing123
```

This is the pre-shared key between the NAS (Python client) and the RADIUS server.
It is used to encrypt the `User-Password` attribute and sign response packets.

---

## Protocol Quick Reference

```
RADIUS ports
  UDP 1812  — Authentication & Authorization
  UDP 1813  — Accounting

Packet codes used in this PoC
  1   Access-Request    (client → server, carries credentials)
  2   Access-Accept     (server → client, grants access)
  3   Access-Reject     (server → client, denies access)
  4   Accounting-Request
  5   Accounting-Response

Password encryption (RFC 2865 §5.2)
  encrypted = password XOR MD5(shared_secret + Request-Authenticator)
```

---

## Useful Commands

```bash
# Live server log
docker compose logs -f

# Test with radtest (if freeradius-utils installed)
radtest alice password123 127.0.0.1 0 testing123

# Capture traffic with tcpdump
sudo tcpdump -i lo -n udp port 1812 -w radius.pcap

# Open capture in Wireshark (understands RADIUS natively)
wireshark radius.pcap

# Stop and remove the container
docker compose down
```

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `permission denied` on `docker` | User not in docker group | `sudo usermod -aG docker $USER && newgrp docker` |
| `Timeout — is FreeRADIUS running?` | Container not started | `docker compose up -d` |
| `Access-Reject` for valid user | Config not mounted | Check `docker compose logs` for config errors |
| Port 1812 already in use | Another RADIUS service running | `sudo lsof -u UDP -i :1812` to find and stop it |

---

## Further Reading

- [RFC 2865 — RADIUS Authentication](https://datatracker.ietf.org/doc/html/rfc2865)
- [RFC 2866 — RADIUS Accounting](https://datatracker.ietf.org/doc/html/rfc2866)
- [RFC 6614 — RadSec (RADIUS over TLS)](https://datatracker.ietf.org/doc/html/rfc6614)
- [FreeRADIUS Wiki](https://wiki.freeradius.org)
- See `RADIUS_README.md` in the parent directory for full protocol theory.
