#!/usr/bin/env python3
"""Seed settings + GitHub PAT pool into the scanner DB once the schema exists.

Render free has an ephemeral disk: every deploy starts from an empty database,
so the operator PAT pool and card settings must be re-applied on boot.
Reads: DB_PATH, GH_PATS_B64 (base64 of whitespace-separated tokens), AUTO_CARDS.
"""
import base64
import os
import sqlite3
import sys
import time


def main() -> int:
    db = os.environ.get("DB_PATH", "/app/data/scanner.db")
    pats_b64 = os.environ.get("GH_PATS_B64", "")
    auto_cards = os.environ.get("AUTO_CARDS", "1")
    auto_batch = os.environ.get("AUTO_BATCH", "4")

    deadline = time.time() + 180
    while time.time() < deadline:
        time.sleep(5)
        try:
            con = sqlite3.connect(db, timeout=10)
            con.execute("select 1 from pats limit 1")
        except Exception:
            continue
        try:
            for k, v in (("auto_cards", auto_cards), ("auto", "1"), ("auto_batch", auto_batch)):
                con.execute("INSERT OR REPLACE INTO settings(key,value) VALUES(?,?)", (k, v))
            offered = 0
            if pats_b64:
                raw = base64.b64decode(pats_b64).decode("utf-8", "ignore")
                for t in raw.split():
                    t = t.strip()
                    if not t.startswith(("ghp_", "github_pat_")):
                        continue
                    con.execute(
                        "INSERT OR IGNORE INTO pats(token,provider,status,search_lane,added_at) "
                        "VALUES(?,?,?,?,strftime('%s','now'))",
                        (t, "github", "alive", "pat"),
                    )
                    offered += 1
            con.commit()
            alive = con.execute("select count(*) from pats where status='alive'").fetchone()[0]
            print("[seed] auto_cards=%s offered=%d alive=%d" % (auto_cards, offered, alive), flush=True)
            return 0
        except Exception as exc:
            print("[seed] retry:", repr(exc)[:120], flush=True)
            time.sleep(5)
    print("[seed] gave up: schema never appeared", flush=True)
    return 1


if __name__ == "__main__":
    sys.exit(main())