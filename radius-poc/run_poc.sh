#!/usr/bin/env bash
# RADIUS PoC — one-shot runner
# Run this after: sudo usermod -aG docker $USER && newgrp docker

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'

log()  { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[✗]${NC} $*"; }

# ── 1. Start FreeRADIUS ───────────────────────────────────────────────────────
log "Starting FreeRADIUS container..."
docker compose up -d

log "Waiting for FreeRADIUS to be ready..."
for i in $(seq 1 15); do
    if docker compose logs 2>/dev/null | grep -q "Ready to process requests"; then
        log "FreeRADIUS is up!"
        break
    fi
    sleep 1
    echo -n "."
done
echo

# ── 2. Show live logs in background ──────────────────────────────────────────
log "FreeRADIUS debug log (last 20 lines):"
docker compose logs --tail=20
echo

# ── 3. Run the PoC client ─────────────────────────────────────────────────────
log "Running radius_client.py (full demo)..."
python3 radius_client.py

echo
log "Running radius_raw.py (wire-level hexdump)..."
python3 radius_raw.py

# ── 4. Show server logs for the requests ─────────────────────────────────────
echo
log "FreeRADIUS log for the above requests:"
docker compose logs --tail=50 | grep -E "(Auth|Login|ACCEPT|REJECT|alice|bob|admin|ghost)" || true

echo
log "Done! Container is still running. Useful commands:"
echo "    docker compose logs -f          # live server log"
echo "    docker compose down             # stop and remove container"
echo "    python3 radius_client.py --user alice --password password123"
echo "    python3 radius_raw.py           # wire-level hexdump"
