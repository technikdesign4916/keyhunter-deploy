#!/usr/bin/env bash
# Local, unattended backup of the parser. Runs from the user systemd timer
# every 30 minutes. Backups are private and never sent to a shared chat.
set -euo pipefail

ROOT=/home/hermes/keyhunter-rs
cd "$ROOT"

umask 077
mkdir -p data/backups logs
stamp="$(date +%Y%m%d_%H%M%S)"
out="$ROOT/data/backups/auto-$stamp.zip"

./target/release/keyhunter-rs --backup "$out" >> logs/auto_backup.log 2>&1
chmod 600 "$out"

# Keep 24 snapshots (12 hours at a 30-minute cadence).
mapfile -t old < <(
  find "$ROOT/data/backups" -maxdepth 1 -type f -name 'auto-*.zip' \
    -printf '%T@ %p\n' | sort -nr | tail -n +25 | cut -d' ' -f2-
)
for f in "${old[@]:-}"; do
  [ -n "$f" ] && rm -f -- "$f"
done

printf '%s backup=%s size=%s\n' "$(date -Is)" "$out" "$(stat -c %s "$out")" >> logs/auto_backup.log