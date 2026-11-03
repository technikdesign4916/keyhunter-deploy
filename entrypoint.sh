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

# Seed settings + GitHub PAT pool AFTER the binary created/migrated the DB.
# PATs land in the `pats` table so code search starts with the whole pool
# instead of crawling on anonymous limits.
(
  i=0
  while [ $i -lt 40 ]; do
    sleep 5
    i=$((i+1))
    python3 - "$DB_PATH" "${GH_PATS_B64:-}" "${AUTO_CARDS:-1}" <<'PY' && break
import base64, os, sqlite3, sys
db = sys.argv[1] or "/app/data/scanner.db"
pats_b64 = sys.argv[2] if len(sys.argv) > 2 else ""
auto_cards = sys.argv[3] if len(sys.argv) > 3 else "1"
if not os.path.exists(db):
    raise SystemExit(1)
con = sqlite3.connect(db, timeout=10)
try:
    con.execute("select 1 from pats limit 1")
except sqlite3.OperationalError:
    raise SystemExit(1)
for k, v in (("auto_cards", auto_cards), ("auto", "1"), ("auto_batch", os.environ.get("AUTO_BATCH", "4"))):
    con.execute("INSERT OR REPLACE INTO settings(key,value) VALUES(?,?)", (k, v))
n = 0
if pats_b64:
    tokens = base64.b64decode(pats_b64).decode("utf-8", "ignore").split()
    for t in tokens:
        t = t.strip()
        if not t.startswith(("ghp_", "github_pat_")):
            continue
        con.execute(
            "INSERT OR IGNORE INTO pats(token,provider,status,search_lane,added_at) VALUES(?,?,?,?,strftime('%s','now'))",
            (t, "github", "alive", "pat"),
        )
        n += 1
con.commit()
print("[seed] settings ok, pats offered:", n, "alive:", con.execute("select count(*) from pats where status='alive'").fetchone()[0])
PY
  done
) &

echo "[entry] starting keyhunter-rs (NO_POLL=${NO_POLL:-1}, auto=${AUTO:-1})"
exec keyhunter-rs