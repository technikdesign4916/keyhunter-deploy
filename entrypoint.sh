#!/bin/sh
# Render/Koyeb entrypoint: health HTTP on $PORT + keyhunter-rs in foreground.
set -e

mkdir -p /app/data

# Operator proxies from env (base64, one URL per line) -> owned_proxies.txt
if [ -n "$OWNED_PROXIES_B64" ]; then
  printf '%s' "$OWNED_PROXIES_B64" | base64 -d > /app/data/owned_proxies.txt 2>/dev/null || true
  echo "[entry] owned proxies: $(grep -c . /app/data/owned_proxies.txt 2>/dev/null || echo 0)"
fi

PORT="${PORT:-8080}"
echo "[entry] health server on :$PORT"
python3 -m http.server "$PORT" --bind 0.0.0.0 >/dev/null 2>&1 &

echo "[entry] seeding settings + PAT pool in background"
python3 /app/seed.py &

# Findings ship to central ingest always (ephemeral disk loses them on sleep/redeploy).
echo "[entry] shipping findings to ${KH_INGEST_URL:-default}"
python3 /app/ship.py &

echo "[entry] starting keyhunter-rs (NO_POLL=${NO_POLL:-1}, auto=${AUTO:-1})"
exec keyhunter-rs
