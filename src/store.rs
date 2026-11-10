use anyhow::Result;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::Path;
use std::sync::Mutex;

pub fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS pats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token TEXT NOT NULL UNIQUE,
    provider TEXT NOT NULL DEFAULT 'github',
    login TEXT NOT NULL DEFAULT '',
    scopes TEXT NOT NULL DEFAULT '',
    kind TEXT NOT NULL DEFAULT 'classic',
    status TEXT NOT NULL DEFAULT 'alive',
    search_lane TEXT NOT NULL DEFAULT 'pair',
    remaining_core INTEGER NOT NULL DEFAULT 5000,
    remaining_search INTEGER NOT NULL DEFAULT 10,
    reset_core INTEGER NOT NULL DEFAULT 0,
    reset_search INTEGER NOT NULL DEFAULT 0,
    added_at INTEGER NOT NULL DEFAULT 0,
    last_check INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS repos (
    full_name TEXT PRIMARY KEY,
    default_branch TEXT NOT NULL DEFAULT 'main',
    stars INTEGER NOT NULL DEFAULT 0,
    fork INTEGER NOT NULL DEFAULT 0,
    archived INTEGER NOT NULL DEFAULT 0,
    fetched_at INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    endpoint TEXT NOT NULL,
    key TEXT NOT NULL,
    key_kind TEXT NOT NULL DEFAULT '',
    repo TEXT NOT NULL DEFAULT '',
    path TEXT NOT NULL DEFAULT '',
    commit_sha TEXT NOT NULL DEFAULT '',
    source TEXT NOT NULL DEFAULT 'code',
    status TEXT NOT NULL DEFAULT 'NEW',
    pair INTEGER NOT NULL DEFAULT 0,
    total_models INTEGER NOT NULL DEFAULT 0,
    tested INTEGER NOT NULL DEFAULT 0,
    chat_ok INTEGER NOT NULL DEFAULT 0,
    models_json TEXT NOT NULL DEFAULT '[]',
    probes_json TEXT NOT NULL DEFAULT '[]',
    latency_ms INTEGER NOT NULL DEFAULT 0,
    first_seen INTEGER NOT NULL DEFAULT 0,
    last_checked INTEGER NOT NULL DEFAULT 0,
    card_sent INTEGER NOT NULL DEFAULT 0,
    balance TEXT NOT NULL DEFAULT '',
    rpm TEXT NOT NULL DEFAULT '',
    rank TEXT NOT NULL DEFAULT '',
    rank_score INTEGER NOT NULL DEFAULT 0,
    rank_verdict TEXT NOT NULL DEFAULT '',
    rank_note TEXT NOT NULL DEFAULT '',
    ranked_at INTEGER NOT NULL DEFAULT 0,
    UNIQUE(endpoint, key)
);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_findings_repo ON findings(repo);
CREATE INDEX IF NOT EXISTS idx_findings_checked ON findings(last_checked);

CREATE TABLE IF NOT EXISTS queries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    q TEXT NOT NULL UNIQUE,
    enabled INTEGER NOT NULL DEFAULT 1,
    last_run INTEGER NOT NULL DEFAULT 0,
    hits INTEGER NOT NULL DEFAULT 0,
    priority INTEGER NOT NULL DEFAULT 0,
    runs INTEGER NOT NULL DEFAULT 0,
    official INTEGER NOT NULL DEFAULT 0,
    pair_lane INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_queries_lane
    ON queries(enabled, official, priority DESC, runs);

CREATE TABLE IF NOT EXISTS jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL DEFAULT '',
    query TEXT NOT NULL DEFAULT '',
    state TEXT NOT NULL DEFAULT 'queued',
    found INTEGER NOT NULL DEFAULT 0,
    valid INTEGER NOT NULL DEFAULT 0,
    error TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL DEFAULT 0,
    finished_at INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_jobs_state ON jobs(state, created_at);
CREATE INDEX IF NOT EXISTS idx_jobs_finished ON jobs(finished_at);

CREATE TABLE IF NOT EXISTS hosts (
    host TEXT PRIMARY KEY,
    count INTEGER NOT NULL DEFAULT 0,
    valid INTEGER NOT NULL DEFAULT 0,
    last_seen INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS scanned (
    repo TEXT NOT NULL,
    path TEXT NOT NULL,
    sha TEXT NOT NULL,
    scanned_at INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (repo, path, sha)
);
CREATE INDEX IF NOT EXISTS idx_scanned_at ON scanned(scanned_at);

CREATE TABLE IF NOT EXISTS deep_scans (
    repo TEXT PRIMARY KEY,
    ts INTEGER NOT NULL DEFAULT 0
);

-- Source Atlas: search tasks learned from endpoints, and a crawl frontier
-- of pages discovered inside results. Both survive restarts.
CREATE TABLE IF NOT EXISTS source_tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source TEXT NOT NULL,
    query TEXT NOT NULL,
    priority INTEGER NOT NULL DEFAULT 0,
    runs INTEGER NOT NULL DEFAULT 0,
    hits INTEGER NOT NULL DEFAULT 0,
    last_run INTEGER NOT NULL DEFAULT 0,
    enabled INTEGER NOT NULL DEFAULT 1,
    UNIQUE(source, query)
);
CREATE INDEX IF NOT EXISTS idx_source_tasks_pick
    ON source_tasks(enabled, priority DESC, runs ASC, last_run ASC);

CREATE TABLE IF NOT EXISTS gh_accounts (
    email TEXT PRIMARY KEY,
    password TEXT NOT NULL DEFAULT '',
    totp TEXT NOT NULL DEFAULT '',
    recovery TEXT NOT NULL DEFAULT '',
    login TEXT NOT NULL DEFAULT '',
    raw TEXT NOT NULL DEFAULT '',
    added_at INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS source_frontier (
    url TEXT PRIMARY KEY,
    source TEXT NOT NULL DEFAULT '',
    depth INTEGER NOT NULL DEFAULT 0,
    priority INTEGER NOT NULL DEFAULT 0,
    state TEXT NOT NULL DEFAULT 'queued',
    hits INTEGER NOT NULL DEFAULT 0,
    last_seen INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_source_frontier_pick
    ON source_frontier(state, priority DESC, depth ASC, last_seen ASC);
"#;

const DEFAULT_QUERIES: &[&str] = &[
    // High-signal official env assignments. Provider host/prefix dorks are
    // seeded by official.rs; this is the compact pair-lane baseline.
    "\"OPENAI_API_KEY\" in:file",
    "\"OPENAI_API_KEY\" filename:.env",
    "\"DEEPSEEK_API_KEY\" in:file",
    "\"ANTHROPIC_API_KEY\" in:file",
    "\"OPENROUTER_API_KEY\" in:file",
    "\"MOONSHOT_API_KEY\" in:file",
    "\"DASHSCOPE_API_KEY\" in:file",
    "\"XAI_API_KEY\" in:file",
    "\"sk-proj-\" in:file",
    "\"sk-or-v1-\" in:file",
    "\"sk-ant-\" in:file",
    "\"sk-ws-\" in:file",
    "\"xai-\" in:file",
    "\"api.openai.com\" \"sk-\" in:file",
    "\"api.deepseek.com\" \"sk-\" in:file",
    "\"api.anthropic.com\" \"sk-ant-\" in:file",
    "\"openrouter.ai\" \"sk-or-v1-\" in:file",
    "\"dashscope.aliyuncs.com\" \"sk-\" in:file",
    "\"dashscope-intl.aliyuncs.com\" \"sk-\" in:file",
    "\"maas.aliyuncs.com\" \"sk-\" in:file",
    // PAT discovery.
    "\"ghp_\" in:file",
    "\"github_pat_\" in:file",
    "\"GITHUB_TOKEN\" \"ghp_\" in:file",
    "\"GH_TOKEN\" \"github_pat_\" in:file",
    "\"GITHUB_TOKEN\" filename:.env",
    "\"GH_TOKEN\" filename:.env",
    "\"GITHUB_TOKEN=ghp_\" in:file",
    "\"GH_TOKEN=ghp_\" in:file",
    "\"GH_PAT\" in:file",
    // PAT .env pack: exact assignment shapes beat the broad GITHUB_TOKEN dork.
    "\"github_pat_\" extension:env",
    "\"github_pat_\" path:.github/workflows",
    "\"ghp_\" path:.github/workflows",
    "\"GITHUB_TOKEN\" path:.github/workflows",
    "\"GH_TOKEN\" path:.github/workflows",
    "\"GITHUB_PAT\" path:.github/workflows",
    "\"GH_PAT\" path:.github/workflows",
    "\"github_pat_\" filename:.env",
    "\"ghp_\" filename:.env",
    "\"GITHUB_TOKEN\" filename:.env",
    "\"GH_TOKEN\" filename:.env",
    "\"GITHUB_PAT\" filename:.env",
    "\"GH_PAT\" filename:.env",
    "\"GITHUB_TOKEN\" \"ghp_\" extension:env",
    "\"GITHUB_TOKEN\" \"github_pat_\" extension:env",
    "\"GH_TOKEN\" \"ghp_\" extension:env",
    "\"GH_TOKEN\" \"github_pat_\" extension:env",
    "\"github_pat_\" \"api.github.com\" extension:env",
    "\"ghp_\" \"api.github.com\" extension:env",
    "\"GITHUB_TOKEN=github_pat_\" extension:env",
    "\"GH_TOKEN=github_pat_\" extension:env",
    "\"ghp_\" extension:env",
    "\"GITHUB_TOKEN=ghp_\" extension:env",
    "\"GH_TOKEN=ghp_\" extension:env",
    "\"GITHUB_PAT\" extension:env",
    "\"github_pat_\" filename:.env",
    "\"ghp_\" filename:.env",
    // Exact endpoint+key shapes for relay/API configs.
    "\"sk-\" \"api_key\" in:file",
    "\"sk-\" \"base_url\" in:file",
    "\"sk-\" \"baseURL\" in:file",
    "\"sk-\" \"Authorization\" in:file",
    "\"sk-proj-\" extension:env",
    "\"OPENAI_API_KEY\" extension:env",
    "\"DASHSCOPE_API_KEY\" extension:env",
    "\"ANTHROPIC_API_KEY\" extension:env",
    "\"OPENROUTER_API_KEY\" extension:env",
    // Batch pack: exact endpoint + credential assignments. These are
    // deliberately narrow: one official host, one key shape, one file class.
    "\"sk-or-v1-\" extension:env",
    "\"sk-proj-\" extension:env",
    "\"sk-ant-\" extension:env",
    "\"sk-ws-\" extension:env",
    "\"OPENAI_API_KEY\" filename:docker-compose.yml",
    "\"OPENAI_API_KEY\" filename:docker-compose.yaml",
    "\"OPENAI_API_KEY\" path:.github/workflows",
    "\"DEEPSEEK_API_KEY\" extension:env",
    "\"ANTHROPIC_API_KEY\" extension:env",
    "\"MOONSHOT_API_KEY\" extension:env",
    "\"DASHSCOPE_API_KEY\" extension:env",
    "\"XAI_API_KEY\" extension:env",
    "\"OPENROUTER_API_KEY\" filename:docker-compose.yml",
    "\"api.openai.com\" \"Authorization: Bearer sk-\" in:file",
    "\"api.deepseek.com\" \"Authorization: Bearer sk-\" in:file",
    "\"api.anthropic.com\" \"x-api-key\" in:file",
    "\"openrouter.ai\" \"Bearer sk-or-v1-\" in:file",
    "\"dashscope.aliyuncs.com\" \"Bearer sk-\" in:file",
    "\"sk-or-v1-\" filename:.env",
    "\"sk-proj-\" filename:.env",
    "\"sk-ant-\" filename:.env",
    "\"sk-ws-\" filename:.env",
    "\"OPENAI_API_KEY\" \"sk-proj-\" in:file",
    "\"ANTHROPIC_API_KEY\" \"sk-ant-\" in:file",
    "\"OPENROUTER_API_KEY\" \"sk-or-v1-\" in:file",
    // Extended provider pack (LLM, media, infra): seeded once, high priority.
    "\"GEMINI_API_KEY\" in:file",
    "\"GOOGLE_API_KEY\" in:file",
    "\"GOOGLE_GENAI_API_KEY\" in:file",
    "\"GROQ_API_KEY\" in:file",
    "\"TOGETHER_API_KEY\" in:file",
    "\"FIREWORKS_API_KEY\" in:file",
    "\"DEEPINFRA_API_KEY\" in:file",
    "\"CEREBRAS_API_KEY\" in:file",
    "\"MISTRAL_API_KEY\" in:file",
    "\"COHERE_API_KEY\" in:file",
    "\"VOYAGE_API_KEY\" in:file",
    "\"JINA_API_KEY\" in:file",
    "\"REPLICATE_API_TOKEN\" in:file",
    "\"HUGGINGFACE_API_KEY\" in:file",
    "\"HF_TOKEN\" in:file",
    "\"PERPLEXITY_API_KEY\" in:file",
    "\"SILICONFLOW_API_KEY\" in:file",
    "\"ZHIPUAI_API_KEY\" in:file",
    "\"ZHIPU_API_KEY\" in:file",
    "\"BIGMODEL_API_KEY\" in:file",
    "\"MOONSHOT_API_KEY\" in:file",
    "\"MINIMAX_API_KEY\" in:file",
    "\"BAICHUAN_API_KEY\" in:file",
    "\"STEPFUN_API_KEY\" in:file",
    "\"QIANFAN_AK\" in:file",
    "\"HUNYUAN_API_KEY\" in:file",
    "\"SPARK_API_KEY\" in:file",
    "\"NOVITA_API_KEY\" in:file",
    "\"SAMBANOVA_API_KEY\" in:file",
    "\"HYPERBOLIC_API_KEY\" in:file",
    "\"LEPTON_API_KEY\" in:file",
    "\"TOGETHER_AI_API_KEY\" in:file",
    "\"OPENAI_API_KEY\" in:file",
    "\"ANTHROPIC_API_KEY\" in:file",
    "\"XAI_API_KEY\" in:file",
    "\"DEEPSEEK_API_KEY\" in:file",
    "\"OPENROUTER_API_KEY\" in:file",
    "\"DASHSCOPE_API_KEY\" in:file",
    "\"MODELSCOPE_API_KEY\" in:file",
    "\"AZURE_OPENAI_API_KEY\" in:file",
    "\"AWS_BEDROCK_API_KEY\" in:file",
    "\"VERTEX_AI_KEY\" in:file",
    "\"GROK_API_KEY\" in:file",
    "\"ELEVENLABS_API_KEY\" in:file",
    "\"DEEPGRAM_API_KEY\" in:file",
    "\"ASSEMBLYAI_API_KEY\" in:file",
    "\"STABILITY_API_KEY\" in:file",
    "\"FAL_KEY\" in:file",
    "\"RUNWAY_API_KEY\" in:file",
    "\"LUMA_API_KEY\" in:file",
    "\"IDEOGRAM_API_KEY\" in:file",
    "\"RECRAFT_API_KEY\" in:file",
    "\"OPENAI_API_KEY\" extension:env",
    "\"ANTHROPIC_API_KEY\" extension:env",
    "\"GEMINI_API_KEY\" extension:env",
    "\"GROQ_API_KEY\" extension:env",
    "\"TOGETHER_API_KEY\" extension:env",
    "\"FIREWORKS_API_KEY\" extension:env",
    "\"MISTRAL_API_KEY\" extension:env",
    "\"COHERE_API_KEY\" extension:env",
    "\"REPLICATE_API_TOKEN\" extension:env",
    "\"HUGGINGFACE_API_KEY\" extension:env",
    "\"PERPLEXITY_API_KEY\" extension:env",
    "\"SILICONFLOW_API_KEY\" extension:env",
    "\"ZHIPUAI_API_KEY\" extension:env",
    "\"MOONSHOT_API_KEY\" extension:env",
    "\"MINIMAX_API_KEY\" extension:env",
    "\"ELEVENLABS_API_KEY\" extension:env",
    "\"DEEPGRAM_API_KEY\" extension:env",
    "\"STABILITY_API_KEY\" extension:env",
    "\"FAL_KEY\" extension:env",
    "\"RUNWAY_API_KEY\" extension:env",
    "\"gsk_\" in:file",
    "\"fw_\" \"FIREWORKS\" in:file",
    "\"csk-\" in:file",
    "\"pplx-\" in:file",
    "\"r8_\" in:file",
    "\"hf_\" in:file",
    "\"nvapi-\" in:file",
    "\"jina_\" in:file",
    "\"AIza\" \"generativelanguage\" in:file",
    "\"sk-admin-\" in:file",
    "\"lsv2_\" in:file",
    "\"tvly-\" in:file",
    "\"fc-\" \"firecrawl\" in:file",
    "\"apify_api_\" in:file",
    "\"re_\" \"resend\" in:file",
    "\"SG.\" \"sendgrid\" in:file",
    "\"api.groq.com\" \"key\" in:file",
    "\"api.together.xyz\" \"key\" in:file",
    "\"api.fireworks.ai\" \"key\" in:file",
    "\"api.deepinfra.com\" \"key\" in:file",
    "\"api.cerebras.ai\" \"key\" in:file",
    "\"api.mistral.ai\" \"key\" in:file",
    "\"api.cohere.com\" \"key\" in:file",
    "\"api.voyageai.com\" \"key\" in:file",
    "\"api.jina.ai\" \"key\" in:file",
    "\"api.replicate.com\" \"key\" in:file",
    "\"api-inference.huggingface.co\" \"key\" in:file",
    "\"api.perplexity.ai\" \"key\" in:file",
    "\"api.siliconflow.cn\" \"key\" in:file",
    "\"open.bigmodel.cn\" \"key\" in:file",
    "\"api.moonshot.cn\" \"key\" in:file",
    "\"api.minimax.chat\" \"key\" in:file",
    "\"api.baichuan-ai.com\" \"key\" in:file",
    "\"api.stepfun.com\" \"key\" in:file",
    "\"qianfan.baidubce.com\" \"key\" in:file",
    "\"api.novita.ai\" \"key\" in:file",
    "\"api.sambanova.ai\" \"key\" in:file",
    "\"generativelanguage.googleapis.com\" \"key\" in:file",
    "\"api.elevenlabs.io\" \"key\" in:file",
    "\"api.deepgram.com\" \"key\" in:file",
    "\"api.assemblyai.com\" \"key\" in:file",
    "\"api.stability.ai\" \"key\" in:file",
    "\"fal.run\" \"key\" in:file",
    "\"api.runwayml.com\" \"key\" in:file",
    "\"api.tavily.com\" \"key\" in:file",
    "\"api.exa.ai\" \"key\" in:file",
    "\"api.firecrawl.dev\" \"key\" in:file",
    "\"api.apify.com\" \"key\" in:file",
    "\"STRIPE_SECRET_KEY\" in:file",
    "\"TWILIO_AUTH_TOKEN\" in:file",
    "\"SENDGRID_API_KEY\" in:file",
    "\"MAILGUN_API_KEY\" in:file",
    "\"POSTMARK_API_KEY\" in:file",
    "\"CLOUDFLARE_API_TOKEN\" in:file",
    "\"DIGITALOCEAN_TOKEN\" in:file",
    "\"LINODE_TOKEN\" in:file",
    "\"HETZNER_TOKEN\" in:file",
    "\"VERCEL_TOKEN\" in:file",
    "\"NETLIFY_AUTH_TOKEN\" in:file",
    "\"FLY_API_TOKEN\" in:file",
    "\"RAILWAY_TOKEN\" in:file",
    "\"RENDER_API_KEY\" in:file",
    "\"SUPABASE_SERVICE_ROLE_KEY\" in:file",
    "\"PINECONE_API_KEY\" in:file",
    "\"QDRANT_API_KEY\" in:file",
    "\"WEAVIATE_API_KEY\" in:file",
    "\"TURSO_AUTH_TOKEN\" in:file",
    "\"NEON_API_KEY\" in:file",
    "\"PLANETSCALE_SERVICE_TOKEN\" in:file",
    "\"AWS_SECRET_ACCESS_KEY\" in:file",
    "\"GCP_SERVICE_ACCOUNT\" in:file",
    "\"AZURE_CLIENT_SECRET\" in:file",
    "\"glpat-\" in:file",
    "\"glpat-\" extension:env",
    "\"BITBUCKET_TOKEN\" in:file",
    "\"pypi-AgEI\" in:file",
    "\"npm_\" \"_authToken\" in:file",
    "\"dop_v1_\" in:file",
    "\"vultr-\" in:file",
    "\"xoxb-\" in:file",
    "\"secret_\" \"notion\" in:file",
];

/// Ranking for the pair lane. The static pack is intentionally huge, but a
/// random unrun long-tail query is a poor use of a 10/min token. Give the
/// short, high-yield dorks a head start; Atlas pivots and explicit user
/// priorities still win through MAX(priority).
pub fn query_priority(q: &str) -> i64 {
    let ql = q.to_ascii_lowercase();
    if ql == "\"sk-\" in:file" {
        255
    } else if ql.contains("extension:env") {
        320
    } else if ql.contains("filename:.env")
        || ql.contains("extension:env")
        || ql.contains(".env.local")
        || ql.contains(".env.production")
    {
        310
    } else if crate::searchplan::is_provider_dork(q) {
        285
    } else if [
        "openai_api_key",
        "anthropic_api_key",
        "deepseek_api_key",
        "openrouter_api_key",
        "moonshot_api_key",
        "dashscope_api_key",
        "xai_api_key",
    ]
    .iter()
    .any(|x| ql.contains(x))
    {
        295
    } else if ql.contains("api_key")
        && (ql.contains("sk-") || ql.contains("base_url") || ql.contains("apikey"))
    {
        275
    } else if [
        "sk-proj-",
        "sk-or-v1-",
        "sk-ant-",
        "sk-ws-",
        "xai-",
        "sk-live-",
    ]
    .iter()
    .any(|x| ql.contains(x))
    {
        260
    } else if [
        "api.openai.com",
        "api.deepseek.com",
        "openrouter.ai",
        "api.moonshot",
        "api.anthropic.com",
        "api.x.ai",
        "dashscope",
        "maas.aliyuncs.com",
    ]
    .iter()
    .any(|x| ql.contains(x))
    {
        245
    } else if ql.contains("ghp_")
        || ql.contains("github_pat_")
        || ql.contains("github_token")
        || ql.contains("gh_token")
    {
        300
    } else if ql.contains("\"sk-\"") {
        230
    } else if ql.contains("filename:") {
        170
    } else if ql.contains("language:") {
        140
    } else if ql.contains("中转")
        || ql.contains("百炼")
        || ql.contains("密钥")
        || ql.contains("接口")
        || ql.contains("令牌")
    {
        120
    } else {
        90
    }
}

/// True for GitHub credential dorks. The dedicated PAT burst uses the same
/// predicate as the SQL queue, so a hand-edited query cannot drift.
pub fn is_pat_query(q: &str) -> bool {
    let q = q.to_ascii_lowercase();
    q.contains("ghp_")
        || q.contains("github_pat_")
        || q.contains("gho_")
        || q.contains("ghu_")
        || q.contains("ghs_")
        || q.contains("ghr_")
        || q.contains("github_token")
        || q.contains("gh_token")
        || q.contains("github_pat")
        || q.contains("gh_pat")
        || q.contains("x-access-token")
}

/// Prefix partitions for the two main PAT shapes. GitHub code search caps
/// every query at 1,000 retrievable results; a bare `"ghp_"` has millions of
/// hits, so rotating prefixes exposes buckets that the first page would never
/// reach. The search engine treats these literals case-insensitively, so a
/// lowercase alphabet plus digits is enough.
fn pat_prefix_queries() -> Vec<String> {
    let mut out = Vec::new();
    for c in (b'a'..=b'z').chain(b'0'..=b'9') {
        let c = c as char;
        out.push(format!("\"ghp_{c}\" in:file"));
        out.push(format!("\"github_pat_11{c}\" in:file"));
        // `.env` slice of the same prefix bucket: higher precision and a
        // different 1,000-result window than the generic `in:file` query.
        out.push(format!("\"ghp_{c}\" extension:env"));
        out.push(format!("\"github_pat_11{c}\" extension:env"));
    }
    for q in [
        // Assignment/context shapes that survive JSON/YAML/shell quoting.
        "\"GITHUB_TOKEN: ghp_\" in:file",
        "\"GH_TOKEN: ghp_\" in:file",
        "\"GITHUB_PAT: ghp_\" in:file",
        "\"GH_PAT: ghp_\" in:file",
        "\"x-access-token:ghp_\" in:file",
        "\"x-access-token:github_pat_\" in:file",
        "\"https://ghp_\" in:file",
        "\"Authorization: Bearer ghp_\" in:file",
        "\"ghp_\" filename:.npmrc",
        "\"ghp_\" filename:.pypirc",
        "\"ghp_\" filename:.netrc",
        "\"ghp_\" filename:.git-credentials",
        "\"ghp_\" filename:Dockerfile",
        "\"ghp_\" filename:docker-compose.yml",
        "\"ghp_\" filename:Jenkinsfile",
        "\"ghp_\" filename:.gitlab-ci.yml",
        "\"ghp_\" filename:terraform.tfvars",
        "\"ghp_\" filename:values.yaml",
    ] {
        out.push(q.to_string());
    }
    out
}

fn default_queries() -> Vec<String> {
    let mut out: Vec<String> = DEFAULT_QUERIES.iter().map(|q| q.to_string()).collect();
    out.extend(crate::searchplan::auto_queries());
    out.extend(pat_prefix_queries());
    let mut seen = HashSet::new();
    out.retain(|q| seen.insert(q.clone()));
    out
}

const DEFAULT_SETTINGS: &[(&str, &str)] = &[
    ("probe_limit", "40"),
    ("probe_concurrency", "12"),
    ("concurrency", "64"),
    ("probe_gate", "32"),
    ("commit_depth", "100"),
    ("branch_depth", "2"),
    ("balance_cost_probe", "0"),
    ("rank_recheck_hours", "24"),
    ("atlas_interval", "45"),
    ("last_atlas", "0"),
    ("scan_pages", "6"),
    ("search_fresh_days", "0"),
    ("official_scan_pages", "1"),
    ("max_files", "1200"),
    ("max_files_per_repo", "24"),
    ("max_probes", "500"),
    // Dedicated PAT-lane burst: many small page jobs, high file/probe
    // ceilings. Kept separate from AI scan limits.
    ("pat_scan_pages", "2"),
    ("pat_max_files", "2000"),
    ("pat_files_per_repo", "64"),
    ("pat_max_probes", "3000"),
    ("pat_probe_concurrency", "24"),
    ("pat_burst", "6"),
    ("pat_history", "1"),
    ("pat_history_files", "3"),
    ("pat_history_depth", "25"),
    ("mine_files", "80"),
    ("deep_repos", "10"),
    ("page_concurrency", "4"),
    ("file_concurrency", "64"),
    ("deep_hours", "12"),
    ("cache_days", "3"),
    ("min_stars", "0"),
    ("include_forks", "1"),
    ("include_archived", "0"),
    ("recheck_hours", "12"),
    // Manual runs are explicit: wider dork set, longer known-pair skip and a
    // short deep-scan cache prevent the same repos/files being re-read every
    // time the operator presses scan.
    ("manual_dorks", "20"),
    ("manual_deep_hours", "6"),
    ("manual_skip_hours", "24"),
    ("manual_skip_forever", "1"),
    ("manual_force_rescan", "0"),
    ("manual_dork_cursor", "0"),
    ("manual_source_cursor", "0"),
    ("notify_invalid", "0"),
    ("notify_limit", "1"),
    ("auto", "1"),
    ("auto_interval", "25"),
    ("auto_batch", "6"),
    ("search_concurrency", "6"),
    ("auto_discover", "1"),
    ("discover_interval", "300"),
    ("discover_repos", "8"),
    ("last_discover", "0"),
    ("repo_query_idx", "0"),
    ("sources", "1"),
    ("source_interval", "15"),
    ("source_docs", "1200"),
    ("source_timeout", "60"),
    ("source_batch", "24"),
    ("source_crawl_depth", "4"),
    ("source_frontier_every", "8"),
    ("source_atlas_interval", "90"),
    ("last_source_atlas", "0"),
    ("source_batch_slot", "0"),
    ("pat_lanes_manual", "0"),
    ("official_pats", "3"),
    ("pat_pats", "2"),
    ("source_task_idx", "0"),
    ("last_source", "0"),
    ("workers", "8"),
    ("last_auto", "0"),
    ("watch", "0"),
    ("watch_interval", "900"),
    ("last_watch", "0"),
    ("probe_challenge", "alibaba"),
    ("probe_random", "1"),
    ("auto_proxy", "1"),
    ("proxy_refresh", "300"),
    ("proxy_scope", "sources"),
    ("checker_models", "16"),
    ("checker_threads", "32"),
    ("checker_timeout", "8"),
    ("checker_probe_concurrency", "32"),
    ("probe_timeout", "30"),
];

const TUNING_V2: &[(&str, &str)] = &[
    ("probe_concurrency", "6"),
    ("concurrency", "16"),
    ("probe_gate", "24"),
    ("commit_depth", "50"),
    ("scan_pages", "6"),
    ("max_files", "600"),
    ("max_probes", "150"),
    ("mine_files", "30"),
    ("deep_repos", "4"),
    ("deep_hours", "12"),
    ("auto_interval", "240"),
    ("auto_batch", "4"),
    ("discover_interval", "600"),
    ("discover_repos", "3"),
    ("workers", "6"),
    ("source_interval", "480"),
    ("source_docs", "60"),
];

const TUNING_V3: &[(&str, &str)] = &[("scan_pages", "6")];

const TUNING_V4: &[(&str, &str)] = &[
    ("source_interval", "120"),
    ("source_docs", "120"),
    ("source_batch", "4"),
];

const TUNING_V5: &[(&str, &str)] = &[
    ("auto_interval", "30"),
    ("source_interval", "60"),
    ("last_auto", "0"),
    ("last_source", "0"),
];

const TUNING_V6: &[(&str, &str)] = &[("checker_threads", "8"), ("checker_models", "60")];

/// Aggressive search profile: maximum throughput over quota economy.
const TUNING_V8: &[(&str, &str)] = &[
    ("workers", "12"),
    ("auto_batch", "8"),
    ("auto_interval", "20"),
    ("page_concurrency", "8"),
    ("file_concurrency", "64"),
    ("scan_pages", "10"),
    ("max_files", "1200"),
    ("concurrency", "64"),
    ("probe_gate", "96"),
    ("probe_concurrency", "12"),
    ("probe_limit", "40"),
    ("max_probes", "500"),
    ("mine_files", "80"),
    ("deep_repos", "10"),
    ("commit_depth", "100"),
    ("discover_repos", "8"),
    ("discover_interval", "300"),
    ("source_batch", "6"),
    ("source_interval", "30"),
    ("source_docs", "300"),
    ("last_auto", "0"),
    ("last_source", "0"),
];

/// Re-anchor the source rotation so the newly prepended official-provider
/// tasks run immediately instead of waiting for a full old-index cycle.
const TUNING_V9: &[(&str, &str)] = &[("source_task_idx", "0"), ("last_source", "0")];

/// Ultra source profile: more source jobs, more documents, lower latency.
const TUNING_V10: &[(&str, &str)] = &[
    ("workers", "24"),
    ("source_batch", "16"),
    ("source_concurrency", "2"),
    ("source_interval", "15"),
    ("source_docs", "600"),
    ("source_timeout", "45"),
    ("last_source", "0"),
];

/// Three dedicated official-API PATs; all other PATs serve PAIR/custom queries.
const TUNING_V11: &[(&str, &str)] = &[("official_pats", "3")];

/// Sixteen concurrent source jobs: two thirds of the 24-worker pool.
const TUNING_V12: &[(&str, &str)] = &[("source_batch", "16")];

/// Restart the source rotation at the new web head.
const TUNING_V13: &[(&str, &str)] = &[("source_task_idx", "0"), ("last_source", "0")];

/// Search-bucket safety: 6 jobs x 6 pages, lower page fan-out, slower tick.
const TUNING_V14: &[(&str, &str)] = &[
    ("auto_batch", "6"),
    ("scan_pages", "6"),
    ("page_concurrency", "4"),
    ("auto_interval", "25"),
];

/// Source Atlas: crawl frontier + endpoint-driven source tasks.
const TUNING_V15: &[(&str, &str)] = &[
    ("source_crawl_depth", "4"),
    ("source_frontier_every", "2"),
    ("source_atlas_interval", "90"),
];

/// Officials are checked against the first two result pages first; this
/// leaves search quota for more distinct official dorks.
const TUNING_V16: &[(&str, &str)] = &[("official_scan_pages", "1")];

/// GitHub code search recency window (days; 0 disables pushed: filter).
const TUNING_V17: &[(&str, &str)] = &[("search_fresh_days", "90")];

/// GitHub search v2: spend the first page of every dork, keep the freshness
/// window useful, rank files locally, and parallelize page fetches a little
/// more aggressively. Search quota is still the hard ceiling.
const TUNING_V18: &[(&str, &str)] = &[
    ("auto_interval", "25"),
    ("official_scan_pages", "1"),
    ("scan_pages", "6"),
    ("page_concurrency", "6"),
    ("file_concurrency", "96"),
    ("max_files_per_repo", "32"),
    ("cache_days", "7"),
    ("search_fresh_days", "0"),
];

/// GitHub code search's `pushed:` qualifier is not reliable (it collapses
/// broad queries to near-zero). Keep freshness for repository discovery and
/// never append it to code-search queries.
const TUNING_V19: &[(&str, &str)] = &[("search_fresh_days", "0")];

/// PAT burst profile. Four dedicated PAT searches per scheduler tick, each
/// up to three result pages and 2,000 files; probe up to 3,000 candidates.
const TUNING_V20: &[(&str, &str)] = &[
    ("pat_scan_pages", "3"),
    ("pat_max_files", "2000"),
    ("pat_files_per_repo", "64"),
    ("pat_max_probes", "3000"),
    ("pat_burst", "4"),
];

/// PAT history pass: for a few candidate files per burst, inspect recent
/// commits to recover tokens deleted from the current branch.
const TUNING_V21: &[(&str, &str)] = &[
    ("pat_history", "1"),
    ("pat_history_files", "3"),
    ("pat_history_depth", "25"),
];

/// Six PAT dorks per tick, two pages each: same 12 search requests as the
/// previous 4x3 profile, but twice the query diversity.
const TUNING_V22: &[(&str, &str)] = &[("pat_burst", "6"), ("pat_scan_pages", "2")];

/// Checker speed profile: 32 pairs in flight, 16 models per key, 8s per
/// request. The background scanner keeps its own probe settings.
const TUNING_V23: &[(&str, &str)] = &[
    ("checker_threads", "32"),
    ("checker_models", "16"),
    ("checker_timeout", "8"),
    ("checker_probe_concurrency", "32"),
];

/// Checker reliability profile: four chat probes per key and a 12s timeout.
/// A larger per-key burst makes OpenRouter answer 429 and look dead.
const TUNING_V24: &[(&str, &str)] = &[
    ("checker_threads", "32"),
    ("checker_models", "16"),
    ("checker_timeout", "12"),
    ("checker_probe_concurrency", "4"),
];

/// Batch GitHub profile: more independent search jobs per tick, a slightly
/// shorter cadence, and a larger file/probe budget. Search is still bounded
/// by the live PAT search buckets; this only lets the scheduler use them.
const TUNING_V25: &[(&str, &str)] = &[
    ("auto_batch", "10"),
    ("auto_interval", "20"),
    ("pat_burst", "6"),
    ("page_concurrency", "4"),
    ("discover_repos", "20"),
    ("discover_interval", "180"),
    ("official_max_files", "400"),
    ("official_files_per_repo", "16"),
    ("max_files", "1800"),
    ("max_files_per_repo", "40"),
    ("max_probes", "1500"),
    // GitHub and API probes should go direct; public source crawling keeps
    // the rotating proxy pool. A dead rotating proxy must not throttle search.
    ("proxy_scope", "sources"),
];

/// Keep GitHub search and API probes direct. Rotating source proxies are
/// excellent for crawling, but a dead/rate-limited exit makes GitHub search
/// look like a 403 and burns a whole cooldown window.
const TUNING_V26: &[(&str, &str)] = &[("proxy_scope", "sources")];

/// Rate-friendly batch profile for existing databases. GitHub's code-search
/// secondary limit punishes a 12-job simultaneous burst even when token
/// buckets look healthy. Ten jobs, six PAT dorks and four page fetches keep
/// the pipeline busy without burning cooldown windows.
const TUNING_V27: &[(&str, &str)] = &[
    ("auto_batch", "10"),
    ("pat_burst", "6"),
    ("page_concurrency", "4"),
];

/// Full model visibility in the API checker. `0` means all models returned by
/// the endpoint; a capped list hides working models on large catalogs.
const TUNING_V28: &[(&str, &str)] = &[("checker_models", "0")];

/// Stress-test defaults. The engine enforces the target, not a fixed request
/// count, so this is the operator-visible token floor.
const TUNING_V29: &[(&str, &str)] = &[("stress_target_tokens", "5500000"), ("stress_models", "5")];

/// Search recovery profile: distinct queries, first page only, fewer jobs.
/// The previous 10-job/6-page burst produced duplicate dorks and GitHub
/// secondary cooldowns while the official lane kept re-running one broad
/// `in:file` query. First-page-only plus a 30s cadence lets every lane breathe.
const TUNING_V30: &[(&str, &str)] = &[
    ("auto_batch", "8"),
    ("pat_burst", "2"),
    ("auto_interval", "30"),
    ("scan_pages", "1"),
    ("pat_scan_pages", "1"),
    ("official_scan_pages", "1"),
    ("page_concurrency", "3"),
];

/// Pair-lane recovery: two PAT dorks are enough (PAT VALID is rare) and the
/// freed slot goes to relay/custom pair queries. PAT dorks are also excluded
/// from `next_pair_query`, so pair jobs no longer spend their two pages on
/// `GITHUB_TOKEN`/`ghp_` instead of AI endpoints.
const TUNING_V31: &[(&str, &str)] = &[
    ("auto_batch", "8"),
    ("pat_burst", "2"),
    ("auto_interval", "30"),
];

/// PAT recovery: spend three slots on exact `.env` PAT dorks, two result pages,
/// and a wider history pass. Broad `GITHUB_TOKEN` files are mostly examples;
/// exact `github_pat_` / `ghp_` assignments are the useful candidates.
const TUNING_V32: &[(&str, &str)] = &[
    ("pat_burst", "3"),
    ("pat_scan_pages", "2"),
    ("pat_history_files", "10"),
    ("pat_history_depth", "50"),
];

/// PAT coverage: three search pages per dork, not just two. The PAT lane has
/// its own three slots and search quota; page 3 is where workflow dumps and
/// older `.env` commits often live.
const TUNING_V33: &[(&str, &str)] = &[("pat_scan_pages", "3")];

/// PAT final profile: four PAT slots, 3 pages, and a deeper history pass.
/// Public classic tokens are often revoked; the extra slots are for accounts
/// with private-repo access and for different dorks, not for re-running one.
const TUNING_V34: &[(&str, &str)] = &[
    ("pat_burst", "4"),
    ("pat_scan_pages", "3"),
    ("pat_history_files", "25"),
    ("pat_history_depth", "100"),
];

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct ProbeLine {
    pub model: String,
    pub code: u16,
    pub latency_ms: u64,
    pub note: String,
    #[serde(default)]
    pub rpm: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct Finding {
    pub id: i64,
    pub endpoint: String,
    pub key: String,
    pub key_kind: String,
    pub repo: String,
    pub path: String,
    pub commit_sha: String,
    pub source: String,
    pub status: String,
    pub pair: bool,
    pub total_models: i64,
    pub tested: i64,
    pub chat_ok: bool,
    pub models: Vec<String>,
    pub probes: Vec<ProbeLine>,
    pub latency_ms: i64,
    pub first_seen: i64,
    pub last_checked: i64,
    pub card_sent: bool,
    pub balance: String,
    pub rpm: String,
    pub rank: String,
    pub rank_score: i64,
    pub rank_verdict: String,
    pub rank_note: String,
    pub ranked_at: i64,
}

#[derive(Clone, Debug)]
pub struct PatRow {
    pub id: i64,
    pub token: String,
    pub provider: String,
    pub login: String,
    pub scopes: String,
    pub kind: String,
    pub status: String,
    pub search_lane: String,
    pub remaining_core: i64,
    pub remaining_search: i64,
    pub reset_core: i64,
    pub reset_search: i64,
    pub added_at: i64,
    pub last_check: i64,
}

#[derive(Clone, Debug)]
pub struct QueryRow {
    pub id: i64,
    pub q: String,
    pub enabled: bool,
    pub last_run: i64,
    pub hits: i64,
}

#[derive(Clone, Debug)]
pub struct HostRow {
    pub host: String,
    pub count: i64,
    pub valid: i64,
    pub last_seen: i64,
}

#[derive(Clone, Debug)]
pub struct SourceTaskRow {
    pub id: i64,
    pub source: String,
    pub query: String,
    pub priority: i64,
    pub runs: i64,
    pub hits: i64,
}

#[derive(Clone, Debug)]
pub struct FrontierRow {
    pub url: String,
    pub source: String,
    pub depth: i64,
    pub priority: i64,
}

#[derive(Clone, Debug, Default)]
pub struct Stats {
    pub pats_total: i64,
    pub pats_alive: i64,
    pub findings: i64,
    pub valid: i64,
    /// Valid GitHub PAT credentials usable by the bot.
    pub pat_valid: i64,
    pub fake: i64,
    pub jobs: i64,
    pub findings_today: i64,
    pub hosts: i64,
}

#[derive(Clone, Debug, Default)]
pub struct NewFinding {
    pub endpoint: String,
    pub key: String,
    pub key_kind: String,
    pub repo: String,
    pub path: String,
    pub commit_sha: String,
    pub source: String,
    pub status: String,
    pub pair: bool,
    pub total_models: i64,
    pub tested: i64,
    pub chat_ok: bool,
    pub models: Vec<String>,
    pub probes: Vec<ProbeLine>,
    pub latency_ms: i64,
    pub balance: String,
    pub rpm: String,
    pub rank: String,
    pub rank_score: i64,
    pub rank_verdict: String,
    pub rank_note: String,
    pub ranked_at: i64,
}

#[derive(Clone, Debug)]
pub struct UpsertResult {
    pub id: i64,
    pub is_new: bool,
    pub became_valid: bool,
    pub card_sent: bool,
}

#[derive(Clone, Debug)]
pub struct RepoRow {
    pub full_name: String,
    pub default_branch: String,
    pub stars: i64,
    pub fork: bool,
    pub archived: bool,
    pub fetched_at: i64,
}

const FINDING_COLS: &str = "id,endpoint,key,key_kind,repo,path,commit_sha,source,status,pair,total_models,tested,chat_ok,models_json,probes_json,latency_ms,first_seen,last_checked,card_sent,balance,rpm,rank,rank_score,rank_verdict,rank_note,ranked_at";

pub struct Store {
    conn: Mutex<Connection>,
}

impl Store {
    pub fn open(path: &str) -> Result<Self> {
        if path != ":memory:" {
            if let Some(parent) = Path::new(path).parent() {
                if !parent.as_os_str().is_empty() {
                    std::fs::create_dir_all(parent)?;
                }
            }
        }
        let conn = Connection::open(path)?;
        #[cfg(unix)]
        if path != ":memory:" {
            use std::os::unix::fs::PermissionsExt;
            if let Some(parent) = Path::new(path).parent() {
                if !parent.as_os_str().is_empty() {
                    let _ =
                        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
                }
            }
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        }
        conn.busy_timeout(std::time::Duration::from_secs(15))?;
        if path != ":memory:" {
            let _: String = conn.query_row("PRAGMA journal_mode=WAL", [], |r| r.get(0))?;
            // Keep the hot index pages resident and avoid fsync on every
            // checkpoint. WAL + NORMAL is safe against application crashes
            // and is the fastest mode short of `synchronous=OFF`.
            conn.execute_batch(
                "PRAGMA synchronous=NORMAL;
                 PRAGMA cache_size=-65536;
                 PRAGMA mmap_size=268435456;
                 PRAGMA temp_store=MEMORY;
                 PRAGMA wal_autocheckpoint=1000;",
            )?;
        }
        conn.execute_batch(SCHEMA)?;
        // A previous process may have died between claim and finish. Requeue
        // those pages instead of leaving them stuck in "running" forever.
        let _ = conn.execute(
            "UPDATE source_frontier SET state='queued' WHERE state='running'",
            [],
        );
        // Drop old search-engine redirect wrappers from earlier builds.
        let _ = conn.execute(
            "DELETE FROM source_frontier
             WHERE url LIKE '%://www.bing.com/%'
                OR url LIKE '%://bing.com/%'
                OR url LIKE '%://www.google.com/%'
                OR url LIKE '%://google.com/%'
                OR url LIKE '%://duckduckgo.com/%'
                OR url LIKE '%://search.brave.com/%'
                OR url LIKE '%://yandex.%'",
            [],
        );
        // Lightweight migration for databases created before balance support.
        let has_balance = {
            let mut stmt = conn.prepare("PRAGMA table_info(findings)")?;
            let cols = stmt.query_map([], |r| r.get::<_, String>(1))?;
            let mut found = false;
            for c in cols.flatten() {
                if c == "balance" {
                    found = true;
                    break;
                }
            }
            found
        };
        if !has_balance {
            conn.execute(
                "ALTER TABLE findings ADD COLUMN balance TEXT NOT NULL DEFAULT ''",
                [],
            )?;
        }
        let has_rpm = {
            let mut stmt = conn.prepare("PRAGMA table_info(findings)")?;
            let cols = stmt.query_map([], |r| r.get::<_, String>(1))?;
            let mut found = false;
            for c in cols.flatten() {
                if c == "rpm" {
                    found = true;
                    break;
                }
            }
            found
        };
        if !has_rpm {
            conn.execute(
                "ALTER TABLE findings ADD COLUMN rpm TEXT NOT NULL DEFAULT ''",
                [],
            )?;
        }
        for (column, sql) in [
            (
                "rank",
                "ALTER TABLE findings ADD COLUMN rank TEXT NOT NULL DEFAULT ''",
            ),
            (
                "rank_score",
                "ALTER TABLE findings ADD COLUMN rank_score INTEGER NOT NULL DEFAULT 0",
            ),
            (
                "rank_verdict",
                "ALTER TABLE findings ADD COLUMN rank_verdict TEXT NOT NULL DEFAULT ''",
            ),
            (
                "rank_note",
                "ALTER TABLE findings ADD COLUMN rank_note TEXT NOT NULL DEFAULT ''",
            ),
            (
                "ranked_at",
                "ALTER TABLE findings ADD COLUMN ranked_at INTEGER NOT NULL DEFAULT 0",
            ),
        ] {
            let present = {
                let mut stmt = conn.prepare("PRAGMA table_info(findings)")?;
                let cols = stmt.query_map([], |r| r.get::<_, String>(1))?;
                let mut found = false;
                for c in cols.flatten() {
                    if c == column {
                        found = true;
                        break;
                    }
                }
                found
            };
            if !present {
                conn.execute(sql, [])?;
            }
        }
        let has_provider = {
            let mut stmt = conn.prepare("PRAGMA table_info(pats)")?;
            let cols = stmt.query_map([], |r| r.get::<_, String>(1))?;
            let mut found = false;
            for c in cols.flatten() {
                if c == "provider" {
                    found = true;
                    break;
                }
            }
            found
        };
        if !has_provider {
            conn.execute(
                "ALTER TABLE pats ADD COLUMN provider TEXT NOT NULL DEFAULT 'github'",
                [],
            )?;
        }
        let has_lane = {
            let mut stmt = conn.prepare("PRAGMA table_info(pats)")?;
            let cols = stmt.query_map([], |r| r.get::<_, String>(1))?;
            let mut found = false;
            for c in cols.flatten() {
                if c == "search_lane" {
                    found = true;
                    break;
                }
            }
            found
        };
        if !has_lane {
            conn.execute(
                "ALTER TABLE pats ADD COLUMN search_lane TEXT NOT NULL DEFAULT 'pair'",
                [],
            )?;
        }
        for (column, sql) in [
            (
                "priority",
                "ALTER TABLE queries ADD COLUMN priority INTEGER NOT NULL DEFAULT 0",
            ),
            (
                "runs",
                "ALTER TABLE queries ADD COLUMN runs INTEGER NOT NULL DEFAULT 0",
            ),
            (
                "official",
                "ALTER TABLE queries ADD COLUMN official INTEGER NOT NULL DEFAULT 0",
            ),
            (
                "pair_lane",
                "ALTER TABLE queries ADD COLUMN pair_lane INTEGER NOT NULL DEFAULT 0",
            ),
        ] {
            let present = {
                let mut stmt = conn.prepare("PRAGMA table_info(queries)")?;
                let cols = stmt.query_map([], |r| r.get::<_, String>(1))?;
                let mut found = false;
                for c in cols.flatten() {
                    if c == column {
                        found = true;
                        break;
                    }
                }
                found
            };
            if !present {
                conn.execute(sql, [])?;
            }
        }
        for (column, sql) in [
            (
                "failures",
                "ALTER TABLE source_tasks ADD COLUMN failures INTEGER NOT NULL DEFAULT 0",
            ),
            (
                "last_error",
                "ALTER TABLE source_tasks ADD COLUMN last_error TEXT NOT NULL DEFAULT ''",
            ),
            (
                "cooldown_until",
                "ALTER TABLE source_tasks ADD COLUMN cooldown_until INTEGER NOT NULL DEFAULT 0",
            ),
        ] {
            let names: Vec<String> = {
                let mut stmt = conn.prepare("PRAGMA table_info(source_tasks)")?;
                let cols = stmt.query_map([], |r| r.get::<_, String>(1))?;
                cols.flatten().collect()
            };
            let present = names.iter().any(|c| c == column);
            if !present {
                conn.execute(sql, [])?;
            }
        }
        let _ = conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_queries_pair_lane
             ON queries(enabled, pair_lane, priority DESC, runs)",
            [],
        );
        let store = Self {
            conn: Mutex::new(conn),
        };
        store.seed()?;
        store.refresh_query_lanes()?;
        store.refresh_host_valid_counts();
        let official = store.setting_i64("official_pats", 3).clamp(0, 60) as usize;
        store.ensure_pat_lanes(official);
        Ok(store)
    }

    fn seed(&self) -> Result<()> {
        {
            let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
            for (k, v) in DEFAULT_SETTINGS {
                conn.execute(
                    "INSERT INTO settings(key,value) VALUES(?1,?2) ON CONFLICT(key) DO NOTHING",
                    params![k, v],
                )?;
            }
            let query_seed = default_queries();
            let priority_marker: Option<String> = conn
                .query_row(
                    "SELECT value FROM settings WHERE key='query_priority_v1'",
                    [],
                    |r| r.get(0),
                )
                .optional()?;
            if priority_marker.is_none() {
                for q in &query_seed {
                    conn.execute(
                        "UPDATE queries SET priority=MAX(priority, ?2) WHERE q=?1",
                        params![q, query_priority(q)],
                    )?;
                }
                conn.execute(
                    "INSERT INTO settings(key,value) VALUES('query_priority_v1','1')
                     ON CONFLICT(key) DO UPDATE SET value='1'",
                    [],
                )?;
            }
            let priority_v2: Option<String> = conn
                .query_row(
                    "SELECT value FROM settings WHERE key='query_priority_v2'",
                    [],
                    |r| r.get(0),
                )
                .optional()?;
            if priority_v2.is_none() {
                // The bare "sk-" dork is broad but low precision; the .env
                // and env-assignment dorks should run before it.
                conn.execute(
                    "UPDATE queries SET priority=?2 WHERE q=?1 AND priority>?2",
                    params!["\"sk-\" in:file", 255i64],
                )?;
                conn.execute(
                    "INSERT INTO settings(key,value) VALUES('query_priority_v2','1')
                     ON CONFLICT(key) DO UPDATE SET value='1'",
                    [],
                )?;
            }
            for q in query_seed {
                conn.execute(
                    "INSERT OR IGNORE INTO queries(q,enabled,last_run,priority) VALUES(?1,1,0,?2)",
                    params![q, query_priority(&q)],
                )?;
            }
            // Existing DBs already have provider queries seeded at the old
            // generic priority. Promote them once so the autonomous scheduler
            // actually spends search budget on the new provider pack.
            for q in crate::searchplan::auto_queries() {
                let p = query_priority(&q);
                if p > 90 {
                    conn.execute(
                        "UPDATE queries SET priority=MAX(priority, ?2) WHERE q=?1",
                        params![q, p],
                    )?;
                }
            }
            // Official-lane seed: provider+prefix/env dorks. These are
            // classified again below so a hand-added query cannot drift.
            for (q, priority) in crate::official::seed_queries() {
                let pair_lane = i64::from(crate::official::is_dashscope_query(&q));
                conn.execute(
                                "INSERT OR IGNORE INTO queries(q,enabled,last_run,priority,runs,official,pair_lane)
                                 VALUES(?1,1,0,?2,0,1,?3)",
                                params![q, priority, pair_lane],
                            )?;
                let _ = conn.execute(
                    "UPDATE queries SET priority=MAX(priority, ?2), official=1,
                                                    pair_lane=MAX(pair_lane, ?3) WHERE q=?1",
                    params![q, priority, pair_lane],
                )?;
            }
            // Legacy free-text probe message is no longer used: probes now
            // always send the strict challenge prompt.
            let _ = conn.execute("DELETE FROM settings WHERE key='probe_message'", []);
            // Drop placeholder rows seeded by older builds.
            let _ = conn.execute("DELETE FROM queries WHERE q LIKE '%redacted%'", []);
            // Groq was removed from the product; stop legacy rows from
            // consuming search quota or source workers.
            let _ = conn.execute(
                "UPDATE queries SET enabled=0, official=0
                 WHERE lower(q) LIKE '%groq%' OR lower(q) LIKE '%gsk_%'",
                [],
            );
            let _ = conn.execute(
                "UPDATE source_tasks SET enabled=0
                 WHERE lower(query) LIKE '%groq%' OR lower(query) LIKE '%gsk_%'",
                [],
            );
            let _ = conn.execute("DELETE FROM hosts WHERE lower(host) LIKE '%groq%'", []);
            // Moonshot China is force-invalid by policy. Stop its old official
            // queries and source tasks from burning search/source slots.
            let _ = conn.execute(
                "UPDATE queries SET enabled=0, official=0
                 WHERE lower(q) LIKE '%api.moonshot.cn%'",
                [],
            );
            let _ = conn.execute(
                "UPDATE source_tasks SET enabled=0
                 WHERE lower(query) LIKE '%api.moonshot.cn%'",
                [],
            );
            // Classic DashScope keys only. Workspace `sk-ws-…` dorks are the
            // low-quality path the operator explicitly excluded from the
            // quality parser; keep old findings but stop scanning for them.
            let _ = conn.execute(
                "UPDATE queries SET enabled=0 WHERE lower(q) LIKE '%sk-ws-%'",
                [],
            );
            let _ = conn.execute(
                "UPDATE source_tasks SET enabled=0 WHERE lower(query) LIKE '%sk-ws-%'",
                [],
            );
            let _ = conn.execute(
                "UPDATE findings SET key_kind='dashscope_ws'
                 WHERE lower(key) LIKE 'sk-ws-%' AND key_kind!='dashscope_ws'",
                [],
            );
            let _ = conn.execute(
                "DELETE FROM source_frontier WHERE lower(url) LIKE '%api.groq.com%'",
                [],
            );
            // Keep the historical row but make it unusable for counters,
            // exports and future cards.
            let _ = conn.execute(
                "UPDATE findings SET status='INVALID', pair=0, card_sent=1
                 WHERE lower(endpoint) LIKE '%api.groq.com%' OR lower(key) LIKE 'gsk%'",
                [],
            );
            let cutoff = now() - 30 * 86_400;
            let _ = conn.execute("DELETE FROM scanned WHERE scanned_at < ?1", params![cutoff]);
            let tuned: Option<String> = conn
                .query_row(
                    "SELECT value FROM settings WHERE key='tuning_v2'",
                    [],
                    |r| r.get(0),
                )
                .optional()?;
            if tuned.is_none() {
                for (k, v) in TUNING_V2 {
                    conn.execute("UPDATE settings SET value=?2 WHERE key=?1", params![k, v])?;
                }
                conn.execute(
                    "INSERT INTO settings(key,value) VALUES('tuning_v2','1')
                     ON CONFLICT(key) DO UPDATE SET value='1'",
                    [],
                )?;
            }
            let tuned3: Option<String> = conn
                .query_row(
                    "SELECT value FROM settings WHERE key='tuning_v3'",
                    [],
                    |r| r.get(0),
                )
                .optional()?;
            if tuned3.is_none() {
                for (k, v) in TUNING_V3 {
                    conn.execute("UPDATE settings SET value=?2 WHERE key=?1", params![k, v])?;
                }
                conn.execute(
                    "INSERT INTO settings(key,value) VALUES('tuning_v3','1')
                     ON CONFLICT(key) DO UPDATE SET value='1'",
                    [],
                )?;
            }
            let tuned4: Option<String> = conn
                .query_row(
                    "SELECT value FROM settings WHERE key='tuning_v4'",
                    [],
                    |r| r.get(0),
                )
                .optional()?;
            if tuned4.is_none() {
                for (k, v) in TUNING_V4 {
                    conn.execute("UPDATE settings SET value=?2 WHERE key=?1", params![k, v])?;
                    conn.execute(
                        "INSERT INTO settings(key,value) VALUES(?1,?2)
                         ON CONFLICT(key) DO NOTHING",
                        params![k, v],
                    )?;
                }
                conn.execute(
                    "INSERT INTO settings(key,value) VALUES('tuning_v4','1')
                     ON CONFLICT(key) DO UPDATE SET value='1'",
                    [],
                )?;
            }
            let tuned5: Option<String> = conn
                .query_row(
                    "SELECT value FROM settings WHERE key='tuning_v5'",
                    [],
                    |r| r.get(0),
                )
                .optional()?;
            if tuned5.is_none() {
                for (k, v) in TUNING_V5 {
                    conn.execute("UPDATE settings SET value=?2 WHERE key=?1", params![k, v])?;
                    conn.execute(
                        "INSERT INTO settings(key,value) VALUES(?1,?2)
                         ON CONFLICT(key) DO NOTHING",
                        params![k, v],
                    )?;
                }
                conn.execute(
                    "INSERT INTO settings(key,value) VALUES('tuning_v5','1')
                     ON CONFLICT(key) DO UPDATE SET value='1'",
                    [],
                )?;
            }
            let tuned6: Option<String> = conn
                .query_row(
                    "SELECT value FROM settings WHERE key='tuning_v6'",
                    [],
                    |r| r.get(0),
                )
                .optional()?;
            if tuned6.is_none() {
                for (k, v) in TUNING_V6 {
                    conn.execute("UPDATE settings SET value=?2 WHERE key=?1", params![k, v])?;
                    conn.execute(
                        "INSERT INTO settings(key,value) VALUES(?1,?2)
                         ON CONFLICT(key) DO NOTHING",
                        params![k, v],
                    )?;
                }
                conn.execute(
                    "INSERT INTO settings(key,value) VALUES('tuning_v6','1')
                     ON CONFLICT(key) DO UPDATE SET value='1'",
                    [],
                )?;
            }
            let tuned8: Option<String> = conn
                .query_row(
                    "SELECT value FROM settings WHERE key='tuning_v8'",
                    [],
                    |r| r.get(0),
                )
                .optional()?;
            if tuned8.is_none() {
                for (k, v) in TUNING_V8 {
                    conn.execute("UPDATE settings SET value=?2 WHERE key=?1", params![k, v])?;
                    conn.execute(
                        "INSERT INTO settings(key,value) VALUES(?1,?2)
                         ON CONFLICT(key) DO NOTHING",
                        params![k, v],
                    )?;
                }
                conn.execute(
                    "INSERT INTO settings(key,value) VALUES('tuning_v8','1')
                     ON CONFLICT(key) DO UPDATE SET value='1'",
                    [],
                )?;
            }
            let tuned9: Option<String> = conn
                .query_row(
                    "SELECT value FROM settings WHERE key='tuning_v9'",
                    [],
                    |r| r.get(0),
                )
                .optional()?;
            if tuned9.is_none() {
                for (k, v) in TUNING_V9 {
                    conn.execute("UPDATE settings SET value=?2 WHERE key=?1", params![k, v])?;
                    conn.execute(
                        "INSERT INTO settings(key,value) VALUES(?1,?2)
                         ON CONFLICT(key) DO NOTHING",
                        params![k, v],
                    )?;
                }
                conn.execute(
                    "INSERT INTO settings(key,value) VALUES('tuning_v9','1')
                     ON CONFLICT(key) DO UPDATE SET value='1'",
                    [],
                )?;
            }
            let tuned10: Option<String> = conn
                .query_row(
                    "SELECT value FROM settings WHERE key='tuning_v10'",
                    [],
                    |r| r.get(0),
                )
                .optional()?;
            if tuned10.is_none() {
                for (k, v) in TUNING_V10 {
                    conn.execute("UPDATE settings SET value=?2 WHERE key=?1", params![k, v])?;
                    conn.execute(
                        "INSERT INTO settings(key,value) VALUES(?1,?2)
                         ON CONFLICT(key) DO NOTHING",
                        params![k, v],
                    )?;
                }
                conn.execute(
                    "INSERT INTO settings(key,value) VALUES('tuning_v10','1')
                     ON CONFLICT(key) DO UPDATE SET value='1'",
                    [],
                )?;
            }
            let tuned11: Option<String> = conn
                .query_row(
                    "SELECT value FROM settings WHERE key='tuning_v11'",
                    [],
                    |r| r.get(0),
                )
                .optional()?;
            if tuned11.is_none() {
                for (k, v) in TUNING_V11 {
                    conn.execute("UPDATE settings SET value=?2 WHERE key=?1", params![k, v])?;
                    conn.execute(
                        "INSERT INTO settings(key,value) VALUES(?1,?2)
                         ON CONFLICT(key) DO NOTHING",
                        params![k, v],
                    )?;
                }
                conn.execute(
                    "INSERT INTO settings(key,value) VALUES('tuning_v11','1')
                     ON CONFLICT(key) DO UPDATE SET value='1'",
                    [],
                )?;
            }
            let tuned12: Option<String> = conn
                .query_row(
                    "SELECT value FROM settings WHERE key='tuning_v12'",
                    [],
                    |r| r.get(0),
                )
                .optional()?;
            if tuned12.is_none() {
                for (k, v) in TUNING_V12 {
                    conn.execute("UPDATE settings SET value=?2 WHERE key=?1", params![k, v])?;
                    conn.execute(
                        "INSERT INTO settings(key,value) VALUES(?1,?2)
                         ON CONFLICT(key) DO NOTHING",
                        params![k, v],
                    )?;
                }
                conn.execute(
                    "INSERT INTO settings(key,value) VALUES('tuning_v12','1')
                     ON CONFLICT(key) DO UPDATE SET value='1'",
                    [],
                )?;
            }
            let tuned13: Option<String> = conn
                .query_row(
                    "SELECT value FROM settings WHERE key='tuning_v13'",
                    [],
                    |r| r.get(0),
                )
                .optional()?;
            if tuned13.is_none() {
                for (k, v) in TUNING_V13 {
                    conn.execute("UPDATE settings SET value=?2 WHERE key=?1", params![k, v])?;
                    conn.execute(
                        "INSERT INTO settings(key,value) VALUES(?1,?2)
                         ON CONFLICT(key) DO NOTHING",
                        params![k, v],
                    )?;
                }
                conn.execute(
                    "INSERT INTO settings(key,value) VALUES('tuning_v13','1')
                     ON CONFLICT(key) DO UPDATE SET value='1'",
                    [],
                )?;
            }
            let tuned14: Option<String> = conn
                .query_row(
                    "SELECT value FROM settings WHERE key='tuning_v14'",
                    [],
                    |r| r.get(0),
                )
                .optional()?;
            if tuned14.is_none() {
                for (k, v) in TUNING_V14 {
                    conn.execute("UPDATE settings SET value=?2 WHERE key=?1", params![k, v])?;
                    conn.execute(
                        "INSERT INTO settings(key,value) VALUES(?1,?2)
                         ON CONFLICT(key) DO NOTHING",
                        params![k, v],
                    )?;
                }
                conn.execute(
                    "INSERT INTO settings(key,value) VALUES('tuning_v14','1')
                     ON CONFLICT(key) DO UPDATE SET value='1'",
                    [],
                )?;
            }
            let tuned15: Option<String> = conn
                .query_row(
                    "SELECT value FROM settings WHERE key='tuning_v15'",
                    [],
                    |r| r.get(0),
                )
                .optional()?;
            if tuned15.is_none() {
                for (k, v) in TUNING_V15 {
                    conn.execute("UPDATE settings SET value=?2 WHERE key=?1", params![k, v])?;
                    conn.execute(
                        "INSERT INTO settings(key,value) VALUES(?1,?2)
                         ON CONFLICT(key) DO NOTHING",
                        params![k, v],
                    )?;
                }
                conn.execute(
                    "INSERT INTO settings(key,value) VALUES('tuning_v15','1')
                     ON CONFLICT(key) DO UPDATE SET value='1'",
                    [],
                )?;
            }
            let tuned16: Option<String> = conn
                .query_row(
                    "SELECT value FROM settings WHERE key='tuning_v16'",
                    [],
                    |r| r.get(0),
                )
                .optional()?;
            if tuned16.is_none() {
                for (k, v) in TUNING_V16 {
                    conn.execute("UPDATE settings SET value=?2 WHERE key=?1", params![k, v])?;
                    conn.execute(
                        "INSERT INTO settings(key,value) VALUES(?1,?2)
                         ON CONFLICT(key) DO NOTHING",
                        params![k, v],
                    )?;
                }
                conn.execute(
                    "INSERT INTO settings(key,value) VALUES('tuning_v16','1')
                     ON CONFLICT(key) DO UPDATE SET value='1'",
                    [],
                )?;
            }
            let tuned17: Option<String> = conn
                .query_row(
                    "SELECT value FROM settings WHERE key='tuning_v17'",
                    [],
                    |r| r.get(0),
                )
                .optional()?;
            if tuned17.is_none() {
                for (k, v) in TUNING_V17 {
                    conn.execute("UPDATE settings SET value=?2 WHERE key=?1", params![k, v])?;
                    conn.execute(
                        "INSERT INTO settings(key,value) VALUES(?1,?2)
                         ON CONFLICT(key) DO NOTHING",
                        params![k, v],
                    )?;
                }
                conn.execute(
                    "INSERT INTO settings(key,value) VALUES('tuning_v17','1')
                     ON CONFLICT(key) DO UPDATE SET value='1'",
                    [],
                )?;
            }
            let tuned18: Option<String> = conn
                .query_row(
                    "SELECT value FROM settings WHERE key='tuning_v18'",
                    [],
                    |r| r.get(0),
                )
                .optional()?;
            if tuned18.is_none() {
                for (k, v) in TUNING_V18 {
                    conn.execute("UPDATE settings SET value=?2 WHERE key=?1", params![k, v])?;
                    conn.execute(
                        "INSERT INTO settings(key,value) VALUES(?1,?2)
                         ON CONFLICT(key) DO NOTHING",
                        params![k, v],
                    )?;
                }
                conn.execute(
                    "INSERT INTO settings(key,value) VALUES('tuning_v18','1')
                     ON CONFLICT(key) DO UPDATE SET value='1'",
                    [],
                )?;
            }
            let tuned19: Option<String> = conn
                .query_row(
                    "SELECT value FROM settings WHERE key='tuning_v19'",
                    [],
                    |r| r.get(0),
                )
                .optional()?;
            if tuned19.is_none() {
                for (k, v) in TUNING_V19 {
                    conn.execute("UPDATE settings SET value=?2 WHERE key=?1", params![k, v])?;
                    conn.execute(
                        "INSERT INTO settings(key,value) VALUES(?1,?2)
                         ON CONFLICT(key) DO NOTHING",
                        params![k, v],
                    )?;
                }
                conn.execute(
                    "INSERT INTO settings(key,value) VALUES('tuning_v19','1')
                     ON CONFLICT(key) DO UPDATE SET value='1'",
                    [],
                )?;
            }
            let tuned20: Option<String> = conn
                .query_row(
                    "SELECT value FROM settings WHERE key='tuning_v20'",
                    [],
                    |r| r.get(0),
                )
                .optional()?;
            if tuned20.is_none() {
                for (k, v) in TUNING_V20 {
                    conn.execute("UPDATE settings SET value=?2 WHERE key=?1", params![k, v])?;
                    conn.execute(
                        "INSERT INTO settings(key,value) VALUES(?1,?2)
                         ON CONFLICT(key) DO NOTHING",
                        params![k, v],
                    )?;
                }
                conn.execute(
                    "INSERT INTO settings(key,value) VALUES('tuning_v20','1')
                     ON CONFLICT(key) DO UPDATE SET value='1'",
                    [],
                )?;
            }
            let tuned21: Option<String> = conn
                .query_row(
                    "SELECT value FROM settings WHERE key='tuning_v21'",
                    [],
                    |r| r.get(0),
                )
                .optional()?;
            if tuned21.is_none() {
                for (k, v) in TUNING_V21 {
                    conn.execute("UPDATE settings SET value=?2 WHERE key=?1", params![k, v])?;
                    conn.execute(
                        "INSERT INTO settings(key,value) VALUES(?1,?2)
                         ON CONFLICT(key) DO NOTHING",
                        params![k, v],
                    )?;
                }
                conn.execute(
                    "INSERT INTO settings(key,value) VALUES('tuning_v21','1')
                     ON CONFLICT(key) DO UPDATE SET value='1'",
                    [],
                )?;
            }
            let tuned22: Option<String> = conn
                .query_row(
                    "SELECT value FROM settings WHERE key='tuning_v22'",
                    [],
                    |r| r.get(0),
                )
                .optional()?;
            if tuned22.is_none() {
                for (k, v) in TUNING_V22 {
                    conn.execute("UPDATE settings SET value=?2 WHERE key=?1", params![k, v])?;
                    conn.execute(
                        "INSERT INTO settings(key,value) VALUES(?1,?2)
                         ON CONFLICT(key) DO NOTHING",
                        params![k, v],
                    )?;
                }
                conn.execute(
                    "INSERT INTO settings(key,value) VALUES('tuning_v22','1')
                     ON CONFLICT(key) DO UPDATE SET value='1'",
                    [],
                )?;
            }
            let tuned23: Option<String> = conn
                .query_row(
                    "SELECT value FROM settings WHERE key='tuning_v23'",
                    [],
                    |r| r.get(0),
                )
                .optional()?;
            if tuned23.is_none() {
                for (k, v) in TUNING_V23 {
                    conn.execute("UPDATE settings SET value=?2 WHERE key=?1", params![k, v])?;
                    conn.execute(
                        "INSERT INTO settings(key,value) VALUES(?1,?2)
                         ON CONFLICT(key) DO NOTHING",
                        params![k, v],
                    )?;
                }
                conn.execute(
                    "INSERT INTO settings(key,value) VALUES('tuning_v23','1')
                     ON CONFLICT(key) DO UPDATE SET value='1'",
                    [],
                )?;
            }
            let tuned24: Option<String> = conn
                .query_row(
                    "SELECT value FROM settings WHERE key='tuning_v24'",
                    [],
                    |r| r.get(0),
                )
                .optional()?;
            if tuned24.is_none() {
                for (k, v) in TUNING_V24 {
                    conn.execute("UPDATE settings SET value=?2 WHERE key=?1", params![k, v])?;
                    conn.execute(
                        "INSERT INTO settings(key,value) VALUES(?1,?2)
                         ON CONFLICT(key) DO NOTHING",
                        params![k, v],
                    )?;
                }
                conn.execute(
                    "INSERT INTO settings(key,value) VALUES('tuning_v24','1')
                     ON CONFLICT(key) DO UPDATE SET value='1'",
                    [],
                )?;
            }
            let tuned25: Option<String> = conn
                .query_row(
                    "SELECT value FROM settings WHERE key='tuning_v25'",
                    [],
                    |r| r.get(0),
                )
                .optional()?;
            if tuned25.is_none() {
                for (k, v) in TUNING_V25 {
                    conn.execute("UPDATE settings SET value=?2 WHERE key=?1", params![k, v])?;
                    conn.execute(
                        "INSERT INTO settings(key,value) VALUES(?1,?2)
                         ON CONFLICT(key) DO NOTHING",
                        params![k, v],
                    )?;
                }
                conn.execute(
                    "INSERT INTO settings(key,value) VALUES('tuning_v25','1')
                     ON CONFLICT(key) DO UPDATE SET value='1'",
                    [],
                )?;
            }
            let tuned26: Option<String> = conn
                .query_row(
                    "SELECT value FROM settings WHERE key='tuning_v26'",
                    [],
                    |r| r.get(0),
                )
                .optional()?;
            if tuned26.is_none() {
                for (k, v) in TUNING_V26 {
                    conn.execute("UPDATE settings SET value=?2 WHERE key=?1", params![k, v])?;
                    conn.execute(
                        "INSERT INTO settings(key,value) VALUES(?1,?2)
                         ON CONFLICT(key) DO NOTHING",
                        params![k, v],
                    )?;
                }
                conn.execute(
                    "INSERT INTO settings(key,value) VALUES('tuning_v26','1')
                     ON CONFLICT(key) DO UPDATE SET value='1'",
                    [],
                )?;
            }
            let tuned27: Option<String> = conn
                .query_row(
                    "SELECT value FROM settings WHERE key='tuning_v27'",
                    [],
                    |r| r.get(0),
                )
                .optional()?;
            if tuned27.is_none() {
                for (k, v) in TUNING_V27 {
                    conn.execute("UPDATE settings SET value=?2 WHERE key=?1", params![k, v])?;
                    conn.execute(
                        "INSERT INTO settings(key,value) VALUES(?1,?2)
                         ON CONFLICT(key) DO NOTHING",
                        params![k, v],
                    )?;
                }
                conn.execute(
                    "INSERT INTO settings(key,value) VALUES('tuning_v27','1')
                     ON CONFLICT(key) DO UPDATE SET value='1'",
                    [],
                )?;
            }
            let tuned28: Option<String> = conn
                .query_row(
                    "SELECT value FROM settings WHERE key='tuning_v28'",
                    [],
                    |r| r.get(0),
                )
                .optional()?;
            if tuned28.is_none() {
                for (k, v) in TUNING_V28 {
                    conn.execute("UPDATE settings SET value=?2 WHERE key=?1", params![k, v])?;
                    conn.execute(
                        "INSERT INTO settings(key,value) VALUES(?1,?2)
                         ON CONFLICT(key) DO NOTHING",
                        params![k, v],
                    )?;
                }
                conn.execute(
                    "INSERT INTO settings(key,value) VALUES('tuning_v28','1')
                     ON CONFLICT(key) DO UPDATE SET value='1'",
                    [],
                )?;
            }
            let tuned29: Option<String> = conn
                .query_row(
                    "SELECT value FROM settings WHERE key='tuning_v29'",
                    [],
                    |r| r.get(0),
                )
                .optional()?;
            if tuned29.is_none() {
                for (k, v) in TUNING_V29 {
                    conn.execute("UPDATE settings SET value=?2 WHERE key=?1", params![k, v])?;
                    conn.execute(
                        "INSERT INTO settings(key,value) VALUES(?1,?2)
                         ON CONFLICT(key) DO NOTHING",
                        params![k, v],
                    )?;
                }
                conn.execute(
                    "INSERT INTO settings(key,value) VALUES('tuning_v29','1')
                     ON CONFLICT(key) DO UPDATE SET value='1'",
                    [],
                )?;
            }
            let tuned30: Option<String> = conn
                .query_row(
                    "SELECT value FROM settings WHERE key='tuning_v30'",
                    [],
                    |r| r.get(0),
                )
                .optional()?;
            if tuned30.is_none() {
                for (kter, v) in TUNING_V30 {
                    conn.execute(
                        "UPDATE settings SET value=?2 WHERE key=?1",
                        params![kter, v],
                    )?;
                    conn.execute(
                        "INSERT INTO settings(key,value) VALUES(?1,?2)
                         ON CONFLICT(key) DO NOTHING",
                        params![kter, v],
                    )?;
                }
                conn.execute(
                    "INSERT INTO settings(key,value) VALUES('tuning_v30','1')
                     ON CONFLICT(key) DO UPDATE SET value='1'",
                    [],
                )?;
            }
            let tuned31: Option<String> = conn
                .query_row(
                    "SELECT value FROM settings WHERE key='tuning_v31'",
                    [],
                    |r| r.get(0),
                )
                .optional()?;
            if tuned31.is_none() {
                for (key, value) in TUNING_V31 {
                    conn.execute(
                        "UPDATE settings SET value=?2 WHERE key=?1",
                        params![key, value],
                    )?;
                    conn.execute(
                        "INSERT INTO settings(key,value) VALUES(?1,?2)
                         ON CONFLICT(key) DO NOTHING",
                        params![key, value],
                    )?;
                }
                conn.execute(
                    "INSERT INTO settings(key,value) VALUES('tuning_v31','1')
                     ON CONFLICT(key) DO UPDATE SET value='1'",
                    [],
                )?;
            }
            let tuned32: Option<String> = conn
                .query_row(
                    "SELECT value FROM settings WHERE key='tuning_v32'",
                    [],
                    |r| r.get(0),
                )
                .optional()?;
            if tuned32.is_none() {
                for (key, value) in TUNING_V32 {
                    conn.execute(
                        "UPDATE settings SET value=?2 WHERE key=?1",
                        params![key, value],
                    )?;
                    conn.execute(
                        "INSERT INTO settings(key,value) VALUES(?1,?2)
                         ON CONFLICT(key) DO NOTHING",
                        params![key, value],
                    )?;
                }
                conn.execute(
                    "INSERT INTO settings(key,value) VALUES('tuning_v32','1')
                     ON CONFLICT(key) DO UPDATE SET value='1'",
                    [],
                )?;
            }
            let tuned33: Option<String> = conn
                .query_row(
                    "SELECT value FROM settings WHERE key='tuning_v33'",
                    [],
                    |r| r.get(0),
                )
                .optional()?;
            if tuned33.is_none() {
                for (key, value) in TUNING_V33 {
                    conn.execute(
                        "UPDATE settings SET value=?2 WHERE key=?1",
                        params![key, value],
                    )?;
                    conn.execute(
                        "INSERT INTO settings(key,value) VALUES(?1,?2)
                         ON CONFLICT(key) DO NOTHING",
                        params![key, value],
                    )?;
                }
                conn.execute(
                    "INSERT INTO settings(key,value) VALUES('tuning_v33','1')
                     ON CONFLICT(key) DO UPDATE SET value='1'",
                    [],
                )?;
            }
            let tuned34: Option<String> = conn
                .query_row(
                    "SELECT value FROM settings WHERE key='tuning_v34'",
                    [],
                    |r| r.get(0),
                )
                .optional()?;
            if tuned34.is_none() {
                for (key, value) in TUNING_V34 {
                    conn.execute(
                        "UPDATE settings SET value=?2 WHERE key=?1",
                        params![key, value],
                    )?;
                    conn.execute(
                        "INSERT INTO settings(key,value) VALUES(?1,?2)
                         ON CONFLICT(key) DO NOTHING",
                        params![key, value],
                    )?;
                }
                conn.execute(
                    "INSERT INTO settings(key,value) VALUES('tuning_v34','1')
                     ON CONFLICT(key) DO UPDATE SET value='1'",
                    [],
                )?;
            }
            // `path:.env` matches a directory named `.env`, not the dotfile
            // GitHub users actually commit. `extension:env` matches `.env`
            // files and produces real credentials. Migrate old rows once.
            let qpath: Option<String> = conn
                .query_row(
                    "SELECT value FROM settings WHERE key='query_ext_env_v1'",
                    [],
                    |r| r.get(0),
                )
                .optional()?;
            if qpath.is_none() {
                let rows: Vec<(i64, String)> = {
                    let mut stmt =
                        conn.prepare("SELECT id,q FROM queries WHERE q LIKE '%path:.env%'")?;
                    let mapped = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
                    mapped.flatten().collect()
                };
                for (id, q) in rows {
                    let nq = q.replace("path:.env", "extension:env");
                    if nq == q {
                        continue;
                    }
                    if conn
                        .execute(
                            "UPDATE queries SET q=?2, official=1 WHERE id=?1",
                            params![id, nq],
                        )
                        .is_err()
                    {
                        let _ =
                            conn.execute("UPDATE queries SET enabled=0 WHERE id=?1", params![id]);
                    }
                }
                conn.execute(
                    "INSERT INTO settings(key,value) VALUES('query_ext_env_v1','1')
                     ON CONFLICT(key) DO UPDATE SET value='1'",
                    [],
                )?;
            }
        }
        Ok(())
    }

    pub fn ensure_setting(&self, key: &str, value: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        conn.execute(
            "INSERT INTO settings(key,value) VALUES(?1,?2) ON CONFLICT(key) DO NOTHING",
            params![key, value],
        )?;
        Ok(())
    }

    pub fn setting(&self, key: &str, default: &str) -> String {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        conn.query_row(
            "SELECT value FROM settings WHERE key=?1",
            params![key],
            |r| r.get::<_, String>(0),
        )
        .optional()
        .ok()
        .flatten()
        .unwrap_or_else(|| default.to_string())
    }

    pub fn setting_i64(&self, key: &str, default: i64) -> i64 {
        self.setting(key, &default.to_string())
            .parse()
            .unwrap_or(default)
    }

    pub fn set_setting(&self, key: &str, value: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        conn.execute(
            "INSERT INTO settings(key,value) VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    // ---------- PATs ----------

    pub fn add_pat(
        &self,
        token: &str,
        login: &str,
        scopes: &str,
        kind: &str,
        status: &str,
    ) -> Result<i64> {
        self.add_pat_provider("github", token, login, scopes, kind, status)
    }

    pub fn add_pat_provider(
        &self,
        provider: &str,
        token: &str,
        login: &str,
        scopes: &str,
        kind: &str,
        status: &str,
    ) -> Result<i64> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let ts = now();
        conn.execute(
            "INSERT INTO pats(token,provider,login,scopes,kind,status,added_at,last_check)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?7)
             ON CONFLICT(token) DO UPDATE SET provider=excluded.provider, login=excluded.login,
                 scopes=excluded.scopes, kind=excluded.kind, status=excluded.status,
                 last_check=excluded.last_check",
            params![token, provider, login, scopes, kind, status, ts],
        )?;
        let id = conn.query_row("SELECT id FROM pats WHERE token=?1", params![token], |r| {
            r.get(0)
        })?;
        Ok(id)
    }

    /// Сохраняет combo-строку `email:pass:totp:recovery:user:token` как аккаунт.
    pub fn add_gh_account(&self, raw: &str) -> Result<bool> {
        let line = raw.trim();
        let mut parts: Vec<&str> = line.split(':').collect();
        if parts.len() < 5 {
            return Ok(false);
        }
        let has_token = parts.last().map(|t| {
            t.starts_with("ghp_") || t.starts_with("gho_") || t.starts_with("ghs_")
                || t.starts_with("github_pat_")
        }).unwrap_or(false);
        if has_token {
            parts.pop();
        }
        if parts.len() < 5 {
            return Ok(false);
        }
        let email = parts[0].trim().to_string();
        if !email.contains('@') {
            return Ok(false);
        }
        let login = parts[parts.len() - 1].trim().to_string();
        let recovery = parts[parts.len() - 2].trim().to_string();
        let totp = parts[parts.len() - 3].trim().to_string();
        let password = parts[1..parts.len() - 3].join(":");
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        conn.execute(
            "INSERT INTO gh_accounts(email,password,totp,recovery,login,raw,added_at)
             VALUES(?1,?2,?3,?4,?5,?6,?7)
             ON CONFLICT(email) DO UPDATE SET password=excluded.password, totp=excluded.totp,
                 recovery=excluded.recovery, login=excluded.login, raw=excluded.raw,
                 added_at=excluded.added_at",
            params![email, password, totp, recovery, login, line, now()],
        )?;
        Ok(true)
    }

    pub fn list_pats(&self) -> Vec<PatRow> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = match conn.prepare(
            "SELECT id,token,provider,login,scopes,kind,status,search_lane,remaining_core,remaining_search,
                    reset_core,reset_search,added_at,last_check
             FROM pats ORDER BY (status='alive') DESC, id ASC",
        ) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        let rows = match stmt.query_map([], |r| {
            Ok(PatRow {
                id: r.get(0)?,
                token: r.get(1)?,
                provider: r.get(2)?,
                login: r.get(3)?,
                scopes: r.get(4)?,
                kind: r.get(5)?,
                status: r.get(6)?,
                search_lane: r.get(7)?,
                remaining_core: r.get(8)?,
                remaining_search: r.get(9)?,
                reset_core: r.get(10)?,
                reset_search: r.get(11)?,
                added_at: r.get(12)?,
                last_check: r.get(13)?,
            })
        }) {
            Ok(rows) => rows,
            Err(_) => return Vec::new(),
        };
        rows.filter_map(|r| r.ok()).collect()
    }

    pub fn list_pats_provider(&self, provider: &str) -> Vec<PatRow> {
        self.list_pats()
            .into_iter()
            .filter(|p| p.provider.eq_ignore_ascii_case(provider))
            .collect()
    }

    pub fn pats_alive(&self) -> i64 {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        conn.query_row("SELECT COUNT(*) FROM pats WHERE status='alive'", [], |r| {
            r.get(0)
        })
        .unwrap_or(0)
    }

    pub fn update_pat_quota(&self, id: i64, search: bool, remaining: i64, reset: i64) {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let sql = if search {
            "UPDATE pats SET remaining_search=?2, reset_search=?3 WHERE id=?1"
        } else {
            "UPDATE pats SET remaining_core=?2, reset_core=?3 WHERE id=?1"
        };
        let _ = conn.execute(sql, params![id, remaining, reset]);
    }

    pub fn mark_pat(&self, id: i64, status: &str) {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let _ = conn.execute(
            "UPDATE pats SET status=?2, last_check=?3 WHERE id=?1",
            params![id, status, now()],
        );
    }

    pub fn delete_pat(&self, id: i64) {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let _ = conn.execute("DELETE FROM pats WHERE id=?1", params![id]);
    }

    pub fn prune_dead_pats(&self) -> usize {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        conn.execute("DELETE FROM pats WHERE status!='alive'", [])
            .unwrap_or(0)
    }

    // ---------- repos ----------

    pub fn get_repo(&self, full: &str) -> Option<RepoRow> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        conn.query_row(
            "SELECT full_name,default_branch,stars,fork,archived,fetched_at FROM repos WHERE full_name=?1",
            params![full],
            |r| {
                Ok(RepoRow {
                    full_name: r.get(0)?,
                    default_branch: r.get(1)?,
                    stars: r.get(2)?,
                    fork: r.get::<_, i64>(3)? != 0,
                    archived: r.get::<_, i64>(4)? != 0,
                    fetched_at: r.get(5)?,
                })
            },
        )
        .optional()
        .ok()
        .flatten()
    }

    pub fn upsert_repo(&self, full: &str, branch: &str, stars: i64, fork: bool, archived: bool) {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let _ = conn.execute(
            "INSERT INTO repos(full_name,default_branch,stars,fork,archived,fetched_at)
             VALUES(?1,?2,?3,?4,?5,?6)
             ON CONFLICT(full_name) DO UPDATE SET default_branch=excluded.default_branch,
                stars=excluded.stars, fork=excluded.fork, archived=excluded.archived, fetched_at=excluded.fetched_at",
            params![full, branch, stars, fork as i64, archived as i64, now()],
        );
    }

    // ---------- queries ----------

    pub fn query_count(&self) -> usize {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        conn.query_row("SELECT COUNT(*) FROM queries", [], |r| r.get::<_, i64>(0))
            .unwrap_or(0) as usize
    }

    /// Pending work, not total historical rows. The query cap must not
    /// permanently disable Atlas once the table has accumulated old dorks.
    pub fn pending_query_count(&self) -> usize {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        conn.query_row(
            "SELECT COUNT(*) FROM queries WHERE enabled=1 AND runs=0",
            [],
            |r| r.get::<_, i64>(0),
        )
        .unwrap_or(0) as usize
    }

    pub fn list_queries(&self) -> Vec<QueryRow> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt =
            match conn.prepare("SELECT id,q,enabled,last_run,hits FROM queries ORDER BY id ASC") {
                Ok(s) => s,
                Err(_) => return Vec::new(),
            };
        let rows = match stmt.query_map([], |r| {
            Ok(QueryRow {
                id: r.get(0)?,
                q: r.get(1)?,
                enabled: r.get::<_, i64>(2)? != 0,
                last_run: r.get(3)?,
                hits: r.get(4)?,
            })
        }) {
            Ok(rows) => rows,
            Err(_) => return Vec::new(),
        };
        rows.filter_map(|r| r.ok()).collect()
    }

    pub fn add_query(&self, q: &str) -> Result<bool> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let official = i64::from(crate::official::is_official_query(q));
        let pair_lane = i64::from(crate::official::is_dashscope_query(q));
        let n = conn.execute(
            "INSERT OR IGNORE INTO queries(q,enabled,last_run,priority,official,pair_lane)
             VALUES(?1,1,0,?2,?3,?4)",
            params![q, query_priority(q), official, pair_lane],
        )?;
        if n == 0 && pair_lane != 0 {
            let _ = conn.execute("UPDATE queries SET pair_lane=1 WHERE q=?1", params![q]);
        }
        Ok(n > 0)
    }

    pub fn add_query_priority(&self, q: &str, priority: i64) -> Result<bool> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let official = i64::from(crate::official::is_official_query(q));
        let pair_lane = i64::from(crate::official::is_dashscope_query(q));
        let n = conn.execute(
            "INSERT OR IGNORE INTO queries(q,enabled,last_run,hits,priority,runs,official,pair_lane)
             VALUES(?1,1,0,0,?2,0,?3,?4)",
            params![q, priority, official, pair_lane],
        )?;
        if n == 0 {
            let _ = conn.execute(
                "UPDATE queries SET priority=MAX(priority, ?2), official=MAX(official, ?3),
                                    pair_lane=MAX(pair_lane, ?4) WHERE q=?1",
                params![q, priority, official, pair_lane],
            );
        }
        Ok(n > 0)
    }

    /// Reclassify every query after migrations or manual inserts. The query
    /// count is large, but this is a single indexed scan at startup.
    pub fn refresh_query_lanes(&self) -> Result<()> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = conn.prepare("SELECT id,q FROM queries")?;
        let rows: Vec<(i64, String)> = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .map(|rows| rows.filter_map(|r| r.ok()).collect())
            .unwrap_or_default();
        drop(stmt);
        for (id, q) in rows {
            let score = crate::official::query_score(&q);
            let official = i64::from(score.is_some());
            let pair_lane = i64::from(crate::official::is_dashscope_query(&q));
            let _ = conn.execute(
                "UPDATE queries SET official=?2, priority=MAX(priority, ?3), pair_lane=?4
                 WHERE id=?1",
                params![id, official, score.unwrap_or(0), pair_lane],
            );
        }
        Ok(())
    }

    pub fn delete_query(&self, id: i64) {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let _ = conn.execute("DELETE FROM queries WHERE id=?1", params![id]);
    }

    pub fn toggle_query(&self, id: i64) -> bool {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let _ = conn.execute(
            "UPDATE queries SET enabled=1-enabled WHERE id=?1",
            params![id],
        );
        conn.query_row(
            "SELECT enabled FROM queries WHERE id=?1",
            params![id],
            |r| r.get::<_, i64>(0),
        )
        .map(|v| v != 0)
        .unwrap_or(false)
    }

    pub fn next_query(&self) -> Option<QueryRow> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        conn.query_row(
            "SELECT id,q,enabled,last_run,hits FROM queries WHERE enabled=1 \
             ORDER BY CASE WHEN last_run=0 THEN 0 ELSE 1 END ASC, \
             priority DESC, \
             CASE WHEN q LIKE '%openai%' OR q LIKE '%deepseek%' OR q LIKE '%openrouter%' OR q LIKE '%moonshot%' \
                        OR q LIKE '%anthropic%' OR q LIKE '%claude%' \
                        OR q LIKE '%xai%' THEN 0 ELSE 1 END ASC, \
             CASE WHEN runs=0 THEN 0 ELSE 1 END ASC, \
             (CAST(hits AS REAL)+1.0)/(CAST(runs AS REAL)+2.0) DESC, \
             last_run ASC, length(q) ASC, RANDOM() LIMIT 1",
            [],
            |r| {
                Ok(QueryRow {
                    id: r.get(0)?,
                    q: r.get(1)?,
                    enabled: r.get::<_, i64>(2)? != 0,
                    last_run: r.get(3)?,
                    hits: r.get(4)?,
                })
            },
        )
        .optional()
        .ok()
        .flatten()
    }

    /// Highest-priority queue for GitHub PAT credentials. `used` prevents the
    /// same dork from occupying several slots in one batch.
    pub fn next_pat_query(&self) -> Option<QueryRow> {
        self.next_pat_query_avoid(&HashSet::new())
    }

    pub fn next_pat_query_avoid(&self, used: &HashSet<String>) -> Option<QueryRow> {
        self.pick_query_unused(
            "SELECT id,q,enabled,last_run,hits FROM queries
             WHERE enabled=1 AND (
                lower(q) LIKE '%ghp_%' OR lower(q) LIKE '%github_pat_%'
                OR lower(q) LIKE '%gho_%' OR lower(q) LIKE '%ghu_%'
                OR lower(q) LIKE '%ghs_%' OR lower(q) LIKE '%ghr_%'
                OR lower(q) LIKE '%github_token%' OR lower(q) LIKE '%gh_token%'
                OR lower(q) LIKE '%github_pat%' OR lower(q) LIKE '%gh_pat%'
             )
             ORDER BY CASE WHEN runs=0 THEN 0 ELSE 1 END ASC,
                      last_run ASC,
                      priority DESC,
                      (CAST(hits AS REAL)+1.0)/(CAST(runs AS REAL)+2.0) DESC,
                      length(q) ASC, RANDOM()
             LIMIT 300",
            used,
        )
    }

    /// Reserve at least one slot per auto batch for first-party providers.
    /// `used` keeps the reserved slots on distinct provider dorks.
    pub fn next_official_query(&self) -> Option<QueryRow> {
        self.next_official_query_avoid(&HashSet::new())
    }

    pub fn next_official_query_avoid(&self, used: &HashSet<String>) -> Option<QueryRow> {
        self.pick_query_unused(
            "SELECT id,q,enabled,last_run,hits FROM queries
             WHERE enabled=1 AND official=1
             ORDER BY CASE WHEN runs=0 THEN 0 ELSE 1 END ASC,
                      last_run ASC,
                      priority DESC,
                      (CAST(hits AS REAL)+1.0)/(CAST(runs AS REAL)+2.0) DESC,
                      length(q) ASC, RANDOM()
             LIMIT 300",
            used,
        )
    }

    /// Non-official queue for relay/custom queries.
    pub fn next_pair_query(&self) -> Option<QueryRow> {
        self.next_pair_query_avoid(&HashSet::new())
    }

    pub fn next_pair_query_avoid(&self, used: &HashSet<String>) -> Option<QueryRow> {
        self.pick_query_unused(
            "SELECT id,q,enabled,last_run,hits FROM queries
             WHERE enabled=1 AND official=0 AND pair_lane=0
               AND NOT (
                    lower(q) LIKE '%ghp_%' OR lower(q) LIKE '%github_pat_%'
                    OR lower(q) LIKE '%gho_%' OR lower(q) LIKE '%ghu_%'
                    OR lower(q) LIKE '%ghs_%' OR lower(q) LIKE '%ghr_%'
                    OR lower(q) LIKE '%github_token%' OR lower(q) LIKE '%gh_token%'
                    OR lower(q) LIKE '%github_pat%' OR lower(q) LIKE '%gh_pat%'
               )
             ORDER BY CASE WHEN runs=0 THEN 0 ELSE 1 END ASC,
                      last_run ASC,
                      priority DESC,
                      (CAST(hits AS REAL)+1.0)/(CAST(runs AS REAL)+2.0) DESC,
                      length(q) ASC, RANDOM()
             LIMIT 300",
            used,
        )
    }

    /// Reserved queue for dual-lane dorks (DashScope). The pair scheduler takes
    /// exactly one of these per batch before ordinary pair queries, so the same
    /// provider is searched in both lanes without starving relay dorks.
    pub fn next_dual_query_avoid(&self, used: &HashSet<String>) -> Option<QueryRow> {
        self.pick_query_unused(
            "SELECT id,q,enabled,last_run,hits FROM queries
             WHERE enabled=1 AND pair_lane=1
               AND NOT (
                    lower(q) LIKE '%ghp_%' OR lower(q) LIKE '%github_pat_%'
                    OR lower(q) LIKE '%gho_%' OR lower(q) LIKE '%ghu_%'
                    OR lower(q) LIKE '%ghs_%' OR lower(q) LIKE '%ghr_%'
                    OR lower(q) LIKE '%github_token%' OR lower(q) LIKE '%gh_token%'
                    OR lower(q) LIKE '%github_pat%' OR lower(q) LIKE '%gh_pat%'
               )
             ORDER BY CASE WHEN lower(q) LIKE '%sk-%' THEN 0 ELSE 1 END ASC,
                      CASE WHEN official=1 THEN 0 ELSE 1 END ASC,
                      CASE WHEN runs=0 THEN 0 ELSE 1 END ASC,
                      last_run ASC,
                      priority DESC,
                      (CAST(hits AS REAL)+1.0)/(CAST(runs AS REAL)+2.0) DESC,
                      length(q) ASC, RANDOM()
             LIMIT 300",
            used,
        )
    }

    /// True when the pair lane has at least one dual-lane dork (currently
    /// DashScope). The batch scheduler reserves one pair slot for it so the
    /// official reserve cannot starve DashScope on the pair side.
    pub fn has_pair_lane_queries(&self) -> bool {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        conn.query_row(
            "SELECT 1 FROM queries
             WHERE enabled=1 AND pair_lane=1
               AND NOT (
                    lower(q) LIKE '%ghp_%' OR lower(q) LIKE '%github_pat_%'
                    OR lower(q) LIKE '%gho_%' OR lower(q) LIKE '%ghu_%'
                    OR lower(q) LIKE '%ghs_%' OR lower(q) LIKE '%ghr_%'
                    OR lower(q) LIKE '%github_token%' OR lower(q) LIKE '%gh_token%'
                    OR lower(q) LIKE '%github_pat%' OR lower(q) LIKE '%gh_pat%'
               )
             LIMIT 1",
            [],
            |_| Ok(()),
        )
        .optional()
        .ok()
        .flatten()
        .is_some()
    }

    fn pick_query_unused(&self, sql: &str, used: &HashSet<String>) -> Option<QueryRow> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = conn.prepare(sql).ok()?;
        let rows = stmt
            .query_map([], |r| {
                Ok(QueryRow {
                    id: r.get(0)?,
                    q: r.get(1)?,
                    enabled: r.get::<_, i64>(2)? != 0,
                    last_run: r.get(3)?,
                    hits: r.get(4)?,
                })
            })
            .ok()?;
        for row in rows.flatten() {
            if !used.contains(&row.q) {
                return Some(row);
            }
        }
        None
    }

    /// Deterministically assign the first live PATs to the official lane.
    /// A manual `/lane` layout is never rewritten by a reload.
    /// Create a compact, consistent SQLite snapshot containing the scanner's
    /// meaningful state (keys, PATs, queries, settings, jobs, repos) without
    /// the multi-hundred-megabyte `scanned` URL cache. The snapshot is safe to
    /// hand to an operator as a backup and stays small enough for Telegram.
    pub fn snapshot_compact(&self, source: &str, dest: &str) -> Result<()> {
        let source =
            std::fs::canonicalize(source).unwrap_or_else(|_| std::path::PathBuf::from(source));
        let source = source.to_string_lossy().to_string();
        if let Some(parent) = Path::new(dest).parent() {
            std::fs::create_dir_all(parent)?;
        }
        let _ = std::fs::remove_file(dest);
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let out = Connection::open(dest)?;
        out.execute_batch(
            "PRAGMA journal_mode=OFF; PRAGMA synchronous=OFF; PRAGMA foreign_keys=OFF;",
        )?;
        out.execute("ATTACH DATABASE ?1 AS src", params![source])?;
        // The URL scan cache is intentionally omitted: it is reproducible,
        // huge, and has nothing to do with the key database.
        let tables = [
            "pats",
            "findings",
            "queries",
            "jobs",
            "settings",
            "repos",
            "hosts",
            "deep_scans",
            "source_tasks",
            "source_frontier",
        ];
        out.execute_batch("BEGIN")?;
        for table in tables {
            let schema: Option<String> = conn
                .query_row(
                    "SELECT sql FROM sqlite_master WHERE type='table' AND name=?1",
                    params![table],
                    |r| r.get(0),
                )
                .optional()?;
            let Some(schema) = schema else { continue };
            out.execute_batch(&schema)?;
        }
        for table in tables {
            let exists: bool = out
                .query_row(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1",
                    params![table],
                    |_| Ok(true),
                )
                .optional()?
                .unwrap_or(false);
            if exists {
                out.execute(
                    &format!("INSERT INTO \"{table}\" SELECT * FROM src.\"{table}\""),
                    [],
                )?;
            }
        }
        out.execute_batch("COMMIT")?;
        // Recreate secondary indexes after the bulk copy.
        for table in tables {
            let mut stmt = conn.prepare(
                "SELECT sql FROM sqlite_master WHERE type='index' AND tbl_name=?1 AND sql IS NOT NULL",
            )?;
            let idx: Vec<String> = stmt
                .query_map(params![table], |r| r.get(0))?
                .flatten()
                .collect();
            for sql in idx {
                let _ = out.execute_batch(&sql);
            }
        }
        out.execute_batch("DETACH DATABASE src; VACUUM;")?;
        drop(out);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(dest, std::fs::Permissions::from_mode(0o600));
        }
        Ok(())
    }

    pub fn ensure_pat_lanes(&self, official: usize) {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let manual: i64 = conn
            .query_row(
                "SELECT value FROM settings WHERE key='pat_lanes_manual'",
                [],
                |r| r.get::<_, String>(0),
            )
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        if manual == 1 {
            return;
        }
        let _ = conn.execute(
            "UPDATE pats SET search_lane='pair' WHERE provider='github'",
            [],
        );
        let ids: Vec<i64> = {
            let mut stmt = match conn
                .prepare("SELECT id FROM pats WHERE status='alive' AND provider='github' ORDER BY COALESCE(added_at,0) DESC, id DESC LIMIT ?1")
            {
                Ok(st) => st,
                Err(_) => return,
            };
            let out: Vec<i64> = match stmt.query_map(params![official as i64], |r| r.get(0)) {
                Ok(rows) => rows.flatten().collect(),
                Err(_) => return,
            };
            out
        };
        for id in ids {
            let _ = conn.execute(
                "UPDATE pats SET search_lane='official' WHERE id=?1",
                params![id],
            );
        }
    }

    /// Assign up to `want` live pair-lane PATs to the dedicated PAT lane.
    pub fn ensure_pat_lane_count(&self, lane: &str, want: usize) {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let manual: i64 = conn
            .query_row(
                "SELECT value FROM settings WHERE key='pat_lanes_manual'",
                [],
                |r| r.get::<_, String>(0),
            )
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        if manual == 1 {
            return;
        }
        let _ = conn.execute(
            "UPDATE pats SET search_lane='pair' WHERE search_lane=?1 AND provider='github'",
            params![lane],
        );
        let ids: Vec<i64> = {
            let mut stmt = match conn.prepare(
                "SELECT id FROM pats WHERE status='alive' AND search_lane='pair' AND provider='github'
                 ORDER BY COALESCE(added_at,0) DESC, id DESC LIMIT ?1",
            ) {
                Ok(st) => st,
                Err(_) => return,
            };
            let out: Vec<i64> = match stmt.query_map(params![want as i64], |r| r.get(0)) {
                Ok(rows) => rows.flatten().collect(),
                Err(_) => return,
            };
            out
        };
        for id in ids {
            let _ = conn.execute(
                "UPDATE pats SET search_lane=?2 WHERE id=?1 AND provider='github'",
                params![id, lane],
            );
        }
    }

    pub fn set_pat_lane(&self, id: i64, lane: &str) -> bool {
        let normalized = match lane.trim().to_ascii_lowercase().as_str() {
            "official" | "off" | "официальный" | "офиц" => "official",
            "pair" | "pairlane" | "общий" => "pair",
            "pat" | "lane2" | "patlane" => "pat",
            _ => return false,
        };
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let changed = conn
            .execute(
                "UPDATE pats SET search_lane=?2 WHERE id=?1 AND provider='github'",
                params![id, normalized],
            )
            .unwrap_or(0);
        if changed > 0 {
            let _ = conn.execute(
                "INSERT INTO settings(key,value) VALUES('pat_lanes_manual','1')
                 ON CONFLICT(key) DO UPDATE SET value='1'",
                [],
            );
        }
        changed > 0
    }

    pub fn reset_pat_lanes_auto(&self, official: usize) {
        {
            let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
            let _ = conn.execute(
                "INSERT INTO settings(key,value) VALUES('pat_lanes_manual','0')
                 ON CONFLICT(key) DO UPDATE SET value='0'",
                [],
            );
        }
        self.ensure_pat_lanes(official);
        self.ensure_pat_lane_count("pat", 2);
    }

    /// Non-official queue for relay/custom queries.
    pub fn mark_query_run(&self, id: i64, hits: i64) {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let _ = conn.execute(
            "UPDATE queries SET last_run=?2, runs=runs+1, hits=hits+?3 WHERE id=?1",
            params![id, now(), hits],
        );
    }

    pub fn add_query_hits(&self, q: &str, hits: i64) {
        if hits <= 0 {
            return;
        }
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let _ = conn.execute(
            "UPDATE queries SET hits=hits+?2 WHERE q=?1",
            params![q, hits],
        );
    }

    // ---------- hosts / cache / deep ----------

    pub fn record_host(&self, host: &str) {
        if host.is_empty() {
            return;
        }
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let _ = conn.execute(
            "INSERT INTO hosts(host,count,valid,last_seen) VALUES(?1,1,0,?2)
             ON CONFLICT(host) DO UPDATE SET count=count+1, last_seen=excluded.last_seen",
            params![host, now()],
        );
    }

    pub fn record_host_valid(&self, host: &str) {
        if host.is_empty() {
            return;
        }
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let _ = conn.execute(
            "INSERT INTO hosts(host,count,valid,last_seen) VALUES(?1,0,1,?2)
             ON CONFLICT(host) DO UPDATE SET valid=valid+1, last_seen=excluded.last_seen",
            params![host, now()],
        );
    }

    /// Recompute host VALID counts from findings.
    pub fn refresh_host_valid_counts(&self) {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let mut counts: std::collections::HashMap<String, i64> = std::collections::HashMap::new();
        let mut stmt =
            match conn.prepare("SELECT endpoint,key_kind FROM findings WHERE status='VALID'") {
                Ok(s) => s,
                Err(_) => return,
            };
        if let Ok(rows) =
            stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
        {
            for row in rows.flatten() {
                let (endpoint, _kind) = row;
                let host = crate::extract::host_of(&endpoint);
                if !host.is_empty() {
                    *counts.entry(host).or_default() += 1;
                }
            }
        }
        drop(stmt);
        let _ = conn.execute("UPDATE hosts SET valid=0", []);
        for (host, count) in counts {
            let _ = conn.execute(
                "INSERT INTO hosts(host,count,valid,last_seen) VALUES(?1,0,?2,?3)
                 ON CONFLICT(host) DO UPDATE SET valid=?2",
                params![host, count, now()],
            );
        }
    }

    /// Repositories with the most findings, used by the Atlas pivot layer.
    /// Seed the source scheduler once. Duplicate (source, query) rows are
    /// ignored, so this can be called on every start without duplicating work.
    pub fn seed_source_tasks(&self, rows: &[(String, String, i64)]) {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        for (source, query, priority) in rows {
            let _ = conn.execute(
                "INSERT INTO source_tasks(source,query,priority)
                 VALUES(?1,?2,?3)
                 ON CONFLICT(source,query) DO UPDATE SET
                   priority=MAX(source_tasks.priority, excluded.priority)",
                params![source, query, priority],
            );
        }
    }

    pub fn add_source_task(&self, source: &str, query: &str, priority: i64) {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let _ = conn.execute(
            "INSERT INTO source_tasks(source,query,priority)
             VALUES(?1,?2,?3)
             ON CONFLICT(source,query) DO UPDATE SET
               priority=MAX(source_tasks.priority, excluded.priority)",
            params![source, query, priority],
        );
    }

    /// The GitHub-PAT source pack is useful but must not outrank the
    /// official-provider source tasks. Older rows were seeded at 410; cap
    /// them after every synthesis, not only at process start.
    pub fn cap_pat_source_priority(&self, cap: i64) {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let _ = conn.execute(
            "UPDATE source_tasks SET priority=MIN(priority,?1)
             WHERE lower(query) LIKE '%ghp_%' OR lower(query) LIKE '%github_pat_%'
                OR lower(query) LIKE '%github_token%' OR lower(query) LIKE '%gh_token%'",
            params![cap],
        );
    }

    pub fn source_task_count(&self) -> i64 {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        conn.query_row(
            "SELECT COUNT(*) FROM source_tasks WHERE enabled=1",
            [],
            |r| r.get(0),
        )
        .unwrap_or(0)
    }

    pub fn source_frontier_count(&self) -> i64 {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        conn.query_row(
            "SELECT COUNT(*) FROM source_frontier WHERE state='queued'",
            [],
            |r| r.get(0),
        )
        .unwrap_or(0)
    }

    /// Pick the highest-yield source task not already used in this batch.
    /// `last_run` is moved forward at claim time, so a task cannot be picked
    /// twice before its result is recorded.
    pub fn next_source_task(&self, avoid: Option<&str>) -> Option<SourceTaskRow> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let sql = if avoid.is_some() {
            "SELECT id,source,query,priority,runs,hits FROM source_tasks
             WHERE enabled=1 AND source<>?1 AND cooldown_until<=?2
             ORDER BY CASE WHEN runs=0 THEN 0 ELSE 1 END,
                      last_run ASC,
                      (priority - (CASE WHEN failures>20 THEN 20 ELSE failures END)*5) DESC,
                      (CAST(hits AS REAL)+1.0)/(CAST(runs AS REAL)+2.0) DESC,
                      RANDOM() LIMIT 1"
        } else {
            "SELECT id,source,query,priority,runs,hits FROM source_tasks
             WHERE enabled=1 AND cooldown_until<=?1
             ORDER BY CASE WHEN runs=0 THEN 0 ELSE 1 END,
                      last_run ASC,
                      (priority - (CASE WHEN failures>20 THEN 20 ELSE failures END)*5) DESC,
                      (CAST(hits AS REAL)+1.0)/(CAST(runs AS REAL)+2.0) DESC,
                      RANDOM() LIMIT 1"
        };
        let row = if let Some(a) = avoid {
            conn.query_row(sql, params![a, now()], |r| {
                Ok(SourceTaskRow {
                    id: r.get(0)?,
                    source: r.get(1)?,
                    query: r.get(2)?,
                    priority: r.get(3)?,
                    runs: r.get(4)?,
                    hits: r.get(5)?,
                })
            })
            .optional()
            .ok()
            .flatten()
        } else {
            conn.query_row(sql, params![now()], |r| {
                Ok(SourceTaskRow {
                    id: r.get(0)?,
                    source: r.get(1)?,
                    query: r.get(2)?,
                    priority: r.get(3)?,
                    runs: r.get(4)?,
                    hits: r.get(5)?,
                })
            })
            .optional()
            .ok()
            .flatten()
        }?;
        let _ = conn.execute(
            "UPDATE source_tasks SET last_run=?2 WHERE id=?1",
            params![row.id, now()],
        );
        Some(row)
    }

    /// Pick a task whose source is not already used in this batch. A single-
    /// source exclusion is not enough: with 16 slots the scheduler would
    /// otherwise bounce between two hot sources and queue one of them twice.
    pub fn next_source_task_avoid(
        &self,
        avoid: &std::collections::HashSet<String>,
    ) -> Option<SourceTaskRow> {
        if avoid.is_empty() {
            return self.next_source_task(None);
        }
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = conn
            .prepare(
                "SELECT id,source,query,priority,runs,hits FROM source_tasks
                 WHERE enabled=1 AND cooldown_until<=?1
                 ORDER BY CASE WHEN runs=0 THEN 0 ELSE 1 END,
                          last_run ASC,
                          (priority - (CASE WHEN failures>20 THEN 20 ELSE failures END)*5) DESC,
                          (CAST(hits AS REAL)+1.0)/(CAST(runs AS REAL)+2.0) DESC,
                          RANDOM() LIMIT 4000",
            )
            .ok()?;
        let mut chosen: Option<SourceTaskRow> = None;
        if let Ok(rows) = stmt.query_map(params![now()], |r| {
            Ok(SourceTaskRow {
                id: r.get(0)?,
                source: r.get(1)?,
                query: r.get(2)?,
                priority: r.get(3)?,
                runs: r.get(4)?,
                hits: r.get(5)?,
            })
        }) {
            for row in rows.flatten() {
                if !avoid.contains(&row.source) {
                    chosen = Some(row);
                    break;
                }
            }
        }
        drop(stmt);
        if let Some(ref row) = chosen {
            let _ = conn.execute(
                "UPDATE source_tasks SET last_run=?2 WHERE id=?1",
                params![row.id, now()],
            );
        }
        chosen
    }

    pub fn record_source_result(&self, source: &str, query: &str, hits: i64) {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let _ = conn.execute(
            "UPDATE source_tasks
             SET runs=runs+1, hits=hits+?3,
                 failures=CASE WHEN failures>0 THEN failures-1 ELSE 0 END,
                 last_error='', cooldown_until=0
             WHERE source=?1 AND query=?2",
            params![source, query, hits],
        );
    }

    /// A transport/challenge failure is scheduler state, not just a log line.
    /// Repeated failures lower the task's effective priority until a later
    /// successful run decays the penalty.
    pub fn record_source_failure(&self, source: &str, query: &str, error: &str) {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let err = error.chars().take(180).collect::<String>();
        let cooldown = now()
            + (conn
                .query_row(
                    "SELECT failures FROM source_tasks WHERE source=?1 AND query=?2",
                    params![source, query],
                    |r| r.get::<_, i64>(0),
                )
                .unwrap_or(0)
                .clamp(1, 12))
                * 300;
        let _ = conn.execute(
            "UPDATE source_tasks
             SET runs=runs+1, failures=failures+1, last_error=?3, cooldown_until=?4
             WHERE source=?1 AND query=?2",
            params![source, query, err, cooldown],
        );
    }

    pub fn push_frontier(&self, url: &str, source: &str, depth: i64, priority: i64) {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let _ = conn.execute(
            "INSERT INTO source_frontier(url,source,depth,priority,state,last_seen)
             VALUES(?1,?2,?3,?4,'queued',?5)
             ON CONFLICT(url) DO UPDATE SET
               priority=MAX(source_frontier.priority, excluded.priority),
               last_seen=excluded.last_seen,
               state=CASE WHEN source_frontier.state='done'
                          THEN 'done' ELSE 'queued' END",
            params![url, source, depth, priority, now()],
        );
    }

    /// Claim frontier URLs. The state transition happens before returning,
    /// so a second scheduler tick cannot queue the same page.
    pub fn pop_frontier(&self, limit: i64) -> Vec<FrontierRow> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let mut out = Vec::new();
        let mut stmt = match conn.prepare(
            "SELECT url,source,depth,priority FROM source_frontier
             WHERE state='queued' AND last_seen <= ?2
             ORDER BY priority DESC, depth ASC, last_seen ASC LIMIT ?1",
        ) {
            Ok(s) => s,
            Err(_) => return out,
        };
        if let Ok(rows) = stmt.query_map(params![limit.max(1), now()], |r| {
            Ok(FrontierRow {
                url: r.get(0)?,
                source: r.get(1)?,
                depth: r.get(2)?,
                priority: r.get(3)?,
            })
        }) {
            for row in rows.flatten() {
                let _ = conn.execute(
                    "UPDATE source_frontier SET state='running', last_seen=?2 WHERE url=?1",
                    params![row.url, now()],
                );
                out.push(row);
            }
        }
        out
    }

    pub fn release_frontier(&self, url: &str) {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        // 5-minute backoff for transient failures. `pop_frontier` ignores
        // queued rows whose last_seen lies in the future.
        let _ = conn.execute(
            "UPDATE source_frontier SET state='queued', last_seen=?2 WHERE url=?1",
            params![url, now() + 300],
        );
    }

    pub fn finish_frontier(&self, url: &str, hits: i64) {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let _ = conn.execute(
            "UPDATE source_frontier SET state='done', hits=hits+?2, last_seen=?3 WHERE url=?1",
            params![url, hits, now()],
        );
    }

    pub fn top_repos(&self, limit: usize) -> Vec<(String, i64)> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = match conn.prepare(
            "SELECT repo, COUNT(*) AS c FROM findings
             WHERE repo <> '' AND status IN ('VALID','PAIR','PARTIAL')
             GROUP BY repo ORDER BY c DESC, MAX(last_checked) DESC LIMIT ?1",
        ) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        let mut out = Vec::new();
        if let Ok(rows) = stmt.query_map(params![limit as i64], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
        }) {
            for row in rows.flatten() {
                if is_github_repo(&row.0) {
                    out.push(row);
                }
            }
        }
        out
    }

    pub fn top_hosts(&self, limit: i64) -> Vec<HostRow> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = match conn.prepare(
            "SELECT host,count,valid,last_seen FROM hosts
             ORDER BY valid DESC, count DESC, last_seen DESC LIMIT ?1",
        ) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        let rows = match stmt.query_map(params![limit], |r| {
            Ok(HostRow {
                host: r.get(0)?,
                count: r.get(1)?,
                valid: r.get(2)?,
                last_seen: r.get(3)?,
            })
        }) {
            Ok(rows) => rows,
            Err(_) => return Vec::new(),
        };
        rows.filter_map(|r| r.ok()).collect()
    }

    pub fn hosts_count(&self) -> i64 {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        conn.query_row("SELECT COUNT(*) FROM hosts", [], |r| r.get(0))
            .unwrap_or(0)
    }

    pub fn was_scanned(&self, repo: &str, path: &str, sha: &str, since: i64) -> bool {
        if sha.is_empty() {
            return false;
        }
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = match conn.prepare_cached(
            "SELECT 1 FROM scanned WHERE repo=?1 AND path=?2 AND sha=?3 AND scanned_at>=?4",
        ) {
            Ok(s) => s,
            Err(_) => return false,
        };
        stmt.query_row(params![repo, path, sha, since], |_| Ok(()))
            .optional()
            .ok()
            .flatten()
            .is_some()
    }

    pub fn mark_scanned(&self, repo: &str, path: &str, sha: &str) {
        if sha.is_empty() {
            return;
        }
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let _ = conn.execute(
            "INSERT INTO scanned(repo,path,sha,scanned_at) VALUES(?1,?2,?3,?4)
             ON CONFLICT(repo,path,sha) DO UPDATE SET scanned_at=excluded.scanned_at",
            params![repo, path, sha, now()],
        );
    }

    pub fn needs_deep(&self, repo: &str, hours: i64) -> bool {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let ts: Option<i64> = match conn.prepare_cached("SELECT ts FROM deep_scans WHERE repo=?1") {
            Ok(mut stmt) => stmt
                .query_row(params![repo], |r| r.get(0))
                .optional()
                .ok()
                .flatten(),
            Err(_) => None,
        };
        match ts {
            Some(t) => now() - t >= hours.max(1) * 3600,
            None => true,
        }
    }

    pub fn mark_deep(&self, repo: &str) {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let _ = conn.execute(
            "INSERT INTO deep_scans(repo,ts) VALUES(?1,?2)
             ON CONFLICT(repo) DO UPDATE SET ts=excluded.ts",
            params![repo, now()],
        );
    }

    // ---------- jobs ----------

    pub fn job_start(&self, kind: &str, query: &str) -> Result<i64> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        conn.execute(
            "INSERT INTO jobs(kind,query,state,created_at) VALUES(?1,?2,'running',?3)",
            params![kind, query, now()],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn running_job_count(&self, kind: &str) -> i64 {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        conn.query_row(
            "SELECT COUNT(*) FROM jobs WHERE kind=?1 AND state='running'",
            params![kind],
            |r| r.get(0),
        )
        .unwrap_or(0)
    }

    pub fn reset_running_jobs(&self) -> i64 {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        conn.execute(
            "UPDATE jobs SET state='error', error='interrupted by restart', finished_at=?1
             WHERE state='running'",
            params![now()],
        )
        .unwrap_or(0) as i64
    }

    pub fn job_finish(&self, id: i64, state: &str, found: i64, valid: i64, error: &str) {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let _ = conn.execute(
            "UPDATE jobs SET state=?2, found=?3, valid=?4, error=?5, finished_at=?6 WHERE id=?1",
            params![id, state, found, valid, error, now()],
        );
    }

    // ---------- findings ----------

    pub fn upsert_finding(&self, nf: &NewFinding) -> Result<UpsertResult> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let ts = now();
        let models_json = serde_json::to_string(&nf.models)?;
        let probes_json = serde_json::to_string(&nf.probes)?;
        let existing: Option<(i64, String, i64)> = conn
            .query_row(
                "SELECT id,status,card_sent FROM findings WHERE endpoint=?1 AND key=?2",
                params![nf.endpoint, nf.key],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;

        if let Some((id, old_status, card_sent)) = existing {
            let became_valid = old_status != "VALID" && nf.status == "VALID";
            // A finding that was previously only LIMIT/INVALID may already
            // have a card; a later VALID transition must be deliverable.
            let next_card_sent = if became_valid { 0 } else { card_sent };
            conn.execute(
                "UPDATE findings SET key_kind=?2,
                    repo=COALESCE(NULLIF(?3,''), repo),
                    path=COALESCE(NULLIF(?4,''), path),
                    commit_sha=COALESCE(NULLIF(?5,''), commit_sha),
                    source=CASE WHEN ?6='' OR ?6='manual' THEN source ELSE ?6 END,
                    status=?7, pair=?8, total_models=?9, tested=?10, chat_ok=?11,
                    models_json=?12, probes_json=?13, latency_ms=?14, last_checked=?15,
                    balance=COALESCE(NULLIF(?16,''), balance),
                    rpm=COALESCE(NULLIF(?17,''), rpm),
                    rank=COALESCE(NULLIF(?18,''), rank),
                    rank_score=CASE WHEN ?19 >= 0 THEN ?19 ELSE rank_score END,
                    rank_verdict=COALESCE(NULLIF(?20,''), rank_verdict),
                    rank_note=COALESCE(NULLIF(?21,''), rank_note),
                    ranked_at=CASE WHEN ?22 > 0 THEN ?22 ELSE ranked_at END,
                    card_sent=?23
                 WHERE id=?1",
                params![
                    id,
                    nf.key_kind,
                    nf.repo,
                    nf.path,
                    nf.commit_sha,
                    nf.source,
                    nf.status,
                    nf.pair as i64,
                    nf.total_models,
                    nf.tested,
                    nf.chat_ok as i64,
                    models_json,
                    probes_json,
                    nf.latency_ms,
                    ts,
                    nf.balance,
                    nf.rpm,
                    nf.rank,
                    nf.rank_score,
                    nf.rank_verdict,
                    nf.rank_note,
                    nf.ranked_at,
                    next_card_sent
                ],
            )?;
            Ok(UpsertResult {
                id,
                is_new: false,
                became_valid,
                card_sent: next_card_sent != 0,
            })
        } else {
            conn.execute(
                "INSERT INTO findings(endpoint,key,key_kind,repo,path,commit_sha,source,status,pair,
                    total_models,tested,chat_ok,models_json,probes_json,latency_ms,first_seen,last_checked,card_sent,balance,rpm,rank,rank_score,rank_verdict,rank_note,ranked_at)
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?16,0,?17,?18,?19,?20,?21,?22,?23)",
                params![
                    nf.endpoint,
                    nf.key,
                    nf.key_kind,
                    nf.repo,
                    nf.path,
                    nf.commit_sha,
                    nf.source,
                    nf.status,
                    nf.pair as i64,
                    nf.total_models,
                    nf.tested,
                    nf.chat_ok as i64,
                    models_json,
                    probes_json,
                    nf.latency_ms,
                    ts,
                    nf.balance,
                    nf.rpm,
                    nf.rank,
                    nf.rank_score,
                    nf.rank_verdict,
                    nf.rank_note,
                    nf.ranked_at
                ],
            )?;
            Ok(UpsertResult {
                id: conn.last_insert_rowid(),
                is_new: true,
                became_valid: nf.status == "VALID",
                card_sent: false,
            })
        }
    }

    /// A key we already probed recently: skip re-probing it on Telegram-card
    /// channels. A key card stays pinned in the channel for days, so without
    /// this every cycle burns a full probe on the same handful of keys.
    pub fn key_fresh(&self, key: &str, hours: i64) -> bool {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let since = now() - hours.max(0) * 3600;
        conn.query_row(
            "SELECT 1 FROM findings WHERE key=?1 AND last_checked>?2
             AND status IN ('VALID','PARTIAL','LIMIT') LIMIT 1",
            params![key, since],
            |_| Ok(true),
        )
        .optional()
        .ok()
        .flatten()
        .unwrap_or(false)
    }

    pub fn mark_card_sent(&self, id: i64) {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let _ = conn.execute("UPDATE findings SET card_sent=1 WHERE id=?1", params![id]);
    }

    /// Whether an AI rank should be requested for this pair. Invalid/never
    /// ranked pairs are always eligible; valid ranks are cached for
    /// `rank_recheck_hours`.
    pub fn needs_rank(&self, endpoint: &str, key: &str, recheck_hours: i64) -> bool {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let row: Option<(String, i64)> = conn
            .query_row(
                "SELECT rank,ranked_at FROM findings WHERE endpoint=?1 AND key=?2",
                params![endpoint, key],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .ok()
            .flatten();
        match row {
            None => true,
            Some((rank, ranked_at)) if rank.trim().is_empty() || ranked_at <= 0 => true,
            Some((_, ranked_at)) => {
                recheck_hours <= 0 || now().saturating_sub(ranked_at) >= recheck_hours * 3600
            }
        }
    }

    /// Atomically claim a finding for a single Telegram card. Only one worker
    /// can win, so two concurrent jobs cannot send the same key twice.
    pub fn claim_card(&self, id: i64) -> bool {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        conn.execute(
            "UPDATE findings SET card_sent=1 WHERE id=?1 AND card_sent=0",
            params![id],
        )
        .map(|n| n > 0)
        .unwrap_or(false)
    }

    /// Release the claim if Telegram rejected the send, so a later cycle can
    /// retry the card. A successful send never releases it.
    pub fn release_card(&self, id: i64) {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let _ = conn.execute("UPDATE findings SET card_sent=0 WHERE id=?1", params![id]);
    }

    pub fn recent_finding(&self, endpoint: &str, key: &str, since: i64) -> Option<Finding> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let sql = format!(
            "SELECT {} FROM findings WHERE endpoint=?1 AND key=?2 AND last_checked>=?3",
            FINDING_COLS
        );
        let mut stmt = match conn.prepare_cached(&sql) {
            Ok(s) => s,
            Err(_) => return None,
        };
        stmt.query_row(params![endpoint, key, since], row_to_finding)
            .optional()
            .ok()
            .flatten()
    }

    /// One round-trip check for a batch of endpoint/key pairs. `probe_pairs`
    /// used to issue one SELECT per candidate; on a manual run that is
    /// thousands of lock acquisitions before the first network probe.
    pub fn recent_finding_pairs(
        &self,
        pairs: &[(String, String)],
        since: i64,
    ) -> HashSet<(String, String)> {
        let mut out = HashSet::new();
        if pairs.is_empty() {
            return out;
        }
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        for chunk in pairs.chunks(250) {
            let mut sql =
                String::from("SELECT endpoint,key FROM findings WHERE last_checked>=?1 AND (");
            for i in 0..chunk.len() {
                if i > 0 {
                    sql.push_str(" OR ");
                }
                sql.push_str("(endpoint=? AND key=?)");
            }
            sql.push(')');
            let Ok(mut stmt) = conn.prepare_cached(&sql) else {
                continue;
            };
            let mut vals: Vec<&dyn rusqlite::ToSql> = Vec::with_capacity(1 + chunk.len() * 2);
            vals.push(&since);
            for (endpoint, key) in chunk {
                vals.push(endpoint);
                vals.push(key);
            }
            let Ok(rows) = stmt.query_map(rusqlite::params_from_iter(vals), |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
            }) else {
                continue;
            };
            for row in rows.flatten() {
                out.insert(row);
            }
        }
        out
    }

    /// Pairs that are already known to be valid (or were rate-limited last
    /// time). Manual scans skip these permanently, but still re-probe keys
    /// that ended as INVALID/UNREACHABLE so a changed account is not hidden.
    pub fn recent_good_finding_pairs(
        &self,
        pairs: &[(String, String)],
        since: i64,
    ) -> HashSet<(String, String)> {
        let mut out = HashSet::new();
        if pairs.is_empty() {
            return out;
        }
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        for chunk in pairs.chunks(250) {
            let mut sql = String::from(
                "SELECT endpoint,key FROM findings WHERE last_checked>=?1 AND status IN ('VALID','PARTIAL','LIMIT') AND (",
            );
            for i in 0..chunk.len() {
                if i > 0 {
                    sql.push_str(" OR ");
                }
                sql.push_str("(endpoint=? AND key=?)");
            }
            sql.push(')');
            let Ok(mut stmt) = conn.prepare_cached(&sql) else {
                continue;
            };
            let mut vals: Vec<&dyn rusqlite::ToSql> = Vec::with_capacity(1 + chunk.len() * 2);
            vals.push(&since);
            for (endpoint, key) in chunk {
                vals.push(endpoint);
                vals.push(key);
            }
            let Ok(rows) = stmt.query_map(rusqlite::params_from_iter(vals), |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
            }) else {
                continue;
            };
            for row in rows.flatten() {
                out.insert(row);
            }
        }
        out
    }

    pub fn finding_by_id(&self, id: i64) -> Option<Finding> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let sql = format!("SELECT {} FROM findings WHERE id=?1", FINDING_COLS);
        conn.query_row(&sql, params![id], row_to_finding)
            .optional()
            .ok()
            .flatten()
    }

    pub fn list_findings(&self, limit: i64) -> Vec<Finding> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let sql = format!(
            "SELECT {} FROM findings ORDER BY id DESC LIMIT ?1",
            FINDING_COLS
        );
        let mut stmt = match conn.prepare(&sql) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        let rows = match stmt.query_map(params![limit], row_to_finding) {
            Ok(r) => r,
            Err(_) => return Vec::new(),
        };
        rows.filter_map(|r| r.ok()).collect()
    }

    pub fn valid_pairs(&self) -> Vec<(String, String)> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = match conn.prepare(
            "SELECT key,endpoint FROM findings
             WHERE status='VALID' AND key_kind<>'github_pat'
             ORDER BY first_seen ASC, id ASC",
        ) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        let rows =
            match stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))) {
                Ok(r) => r,
                Err(_) => return Vec::new(),
            };
        rows.filter_map(|r| r.ok()).collect()
    }

    /// Every VALID finding that has never had a card delivered. This is the
    /// recovery backlog for crashes and Telegram failures.
    pub fn unsent_valid_findings(&self) -> Vec<Finding> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let sql = format!(
            "SELECT {} FROM findings
             WHERE status='VALID' AND card_sent=0
             ORDER BY first_seen ASC, id ASC",
            FINDING_COLS
        );
        let mut stmt = match conn.prepare(&sql) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        let rows = match stmt.query_map([], row_to_finding) {
            Ok(r) => r,
            Err(_) => return Vec::new(),
        };
        rows.filter_map(|r| r.ok()).collect()
    }

    /// Full VALID findings, including model/probe metadata, for filtered exports.
    pub fn valid_findings(&self) -> Vec<Finding> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let sql = format!(
            "SELECT {} FROM findings
             WHERE status='VALID' AND key_kind<>'github_pat'
             ORDER BY first_seen ASC, id ASC",
            FINDING_COLS
        );
        let mut stmt = match conn.prepare(&sql) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        let rows = match stmt.query_map([], row_to_finding) {
            Ok(r) => r,
            Err(_) => return Vec::new(),
        };
        rows.filter_map(|r| r.ok()).collect()
    }

    pub fn stats(&self) -> Stats {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let pats_total = conn
            .query_row("SELECT COUNT(*) FROM pats", [], |r| r.get(0))
            .unwrap_or(0);
        let pats_alive = conn
            .query_row("SELECT COUNT(*) FROM pats WHERE status='alive'", [], |r| {
                r.get(0)
            })
            .unwrap_or(0);
        let findings = conn
            .query_row("SELECT COUNT(*) FROM findings", [], |r| r.get(0))
            .unwrap_or(0);
        let valid = conn
            .query_row(
                "SELECT COUNT(*) FROM findings
                 WHERE status='VALID' AND key_kind<>'github_pat'",
                [],
                |r| r.get(0),
            )
            .unwrap_or(0);
        let pat_valid = conn
            .query_row(
                "SELECT COUNT(*) FROM findings
                 WHERE status='VALID' AND key_kind='github_pat'",
                [],
                |r| r.get(0),
            )
            .unwrap_or(0);
        let fake = conn
            .query_row(
                "SELECT COUNT(*) FROM findings WHERE status='FAKE'",
                [],
                |r| r.get(0),
            )
            .unwrap_or(0);
        let jobs = conn
            .query_row("SELECT COUNT(*) FROM jobs", [], |r| r.get(0))
            .unwrap_or(0);
        let day_ago = now() - 86_400;
        let findings_today = conn
            .query_row(
                "SELECT COUNT(*) FROM findings WHERE first_seen>=?1",
                params![day_ago],
                |r| r.get(0),
            )
            .unwrap_or(0);
        let hosts = conn
            .query_row("SELECT COUNT(*) FROM hosts", [], |r| r.get(0))
            .unwrap_or(0);
        Stats {
            pats_total,
            pats_alive,
            findings,
            valid,
            pat_valid,
            fake,
            jobs,
            findings_today,
            hosts,
        }
    }
}

fn is_github_repo(repo: &str) -> bool {
    let Some((owner, name)) = repo.split_once('/') else {
        return false;
    };
    !owner.is_empty()
        && !name.is_empty()
        && !name.contains('/')
        && !repo.contains(':')
        && owner.len() < 100
        && name.len() < 150
        && repo
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '/'))
}

fn row_to_finding(r: &rusqlite::Row<'_>) -> rusqlite::Result<Finding> {
    let models_json: String = r.get(13)?;
    let probes_json: String = r.get(14)?;
    Ok(Finding {
        id: r.get(0)?,
        endpoint: r.get(1)?,
        key: r.get(2)?,
        key_kind: r.get(3)?,
        repo: r.get(4)?,
        path: r.get(5)?,
        commit_sha: r.get(6)?,
        source: r.get(7)?,
        status: r.get(8)?,
        pair: r.get::<_, i64>(9)? != 0,
        total_models: r.get(10)?,
        tested: r.get(11)?,
        chat_ok: r.get::<_, i64>(12)? != 0,
        models: serde_json::from_str(&models_json).unwrap_or_default(),
        probes: serde_json::from_str(&probes_json).unwrap_or_default(),
        latency_ms: r.get(15)?,
        first_seen: r.get(16)?,
        last_checked: r.get(17)?,
        card_sent: r.get::<_, i64>(18)? != 0,
        balance: r.get(19)?,
        rpm: r.get(20)?,
        rank: r.get(21)?,
        rank_score: r.get(22)?,
        rank_verdict: r.get(23)?,
        rank_note: r.get(24)?,
        ranked_at: r.get(25)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_roundtrip() {
        let s = Store::open(":memory:").unwrap();
        assert!(!s.setting("probe_limit", "0").is_empty());
        s.set_setting("probe_limit", "42").unwrap();
        assert_eq!(s.setting_i64("probe_limit", 0), 42);

        let id = s
            .add_pat("ghp_test123", "octocat", "public_repo", "classic", "alive")
            .unwrap();
        assert!(id > 0);
        assert_eq!(s.pats_alive(), 1);
        s.mark_pat(id, "dead");
        assert_eq!(s.pats_alive(), 0);

        let nf = NewFinding {
            endpoint: "https://api.example.com/v1".into(),
            key: "sk-test12345678901234567890".into(),
            status: "VALID".into(),
            models: vec!["m1".into(), "m2".into()],
            probes: vec![ProbeLine {
                model: "m1".into(),
                code: 200,
                latency_ms: 900,
                note: String::new(),
                rpm: String::new(),
            }],
            total_models: 2,
            tested: 1,
            chat_ok: true,
            balance: "$5.00".into(),
            ..Default::default()
        };
        let up = s.upsert_finding(&nf).unwrap();
        assert!(up.is_new && up.became_valid);
        s.mark_card_sent(up.id);
        let f = s.finding_by_id(up.id).unwrap();
        assert_eq!(f.models.len(), 2);
        assert!(f.card_sent);
        assert_eq!(f.balance, "$5.00");

        let up2 = s.upsert_finding(&nf).unwrap();
        assert!(!up2.is_new);
        assert!(up2.card_sent);
        assert!(!up2.became_valid);

        let mut empty_balance = nf.clone();
        empty_balance.balance.clear();
        s.upsert_finding(&empty_balance).unwrap();
        assert_eq!(s.finding_by_id(up.id).unwrap().balance, "$5.00");
    }

    #[test]
    fn card_claim_is_atomic() {
        let s = Store::open(":memory:").unwrap();
        let nf = NewFinding {
            endpoint: "https://api.example.com/v1".into(),
            key: "sk-claim".into(),
            status: "VALID".into(),
            ..Default::default()
        };
        let up = s.upsert_finding(&nf).unwrap();
        assert!(!up.card_sent);
        assert!(s.claim_card(up.id));
        assert!(!s.claim_card(up.id));
        assert!(s.upsert_finding(&nf).unwrap().card_sent);
        s.release_card(up.id);
        assert!(s.claim_card(up.id));
    }

    #[test]
    fn pat_prefix_pack_partitions_the_search_cap() {
        let qs = default_queries();
        for q in [
            "\"ghp_a\" in:file",
            "\"ghp_z\" in:file",
            "\"github_pat_11a\" in:file",
            "\"ghp_a\" extension:env",
            "\"github_pat_11z\" extension:env",
        ] {
            assert!(qs.iter().any(|x| x == q), "missing {q}");
        }
        assert!(qs.len() <= 1000);
        assert!(is_pat_query("\"ghp_a\" in:file"));
        assert!(is_pat_query("\"github_pat_11z\" in:file"));
    }

    #[test]
    fn source_task_failures_are_recorded_and_decay_on_success() {
        let s = Store::open(":memory:").unwrap();
        s.seed_source_tasks(&[("probe-source".to_string(), "q".to_string(), 300)]);
        s.record_source_failure("probe-source", "q", "HTTP 403 challenge");
        s.record_source_failure("probe-source", "q", "timeout");
        {
            let conn = s.conn.lock().unwrap_or_else(|e| e.into_inner());
            let row: (i64, String) = conn
                .query_row(
                    "SELECT failures,last_error FROM source_tasks
                     WHERE source='probe-source' AND query='q'",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .unwrap();
            assert_eq!(row.0, 2);
            assert!(row.1.contains("timeout"));
            let cooldown: i64 = conn
                .query_row(
                    "SELECT cooldown_until FROM source_tasks
                     WHERE source='probe-source' AND query='q'",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert!(cooldown > now());
        }
        s.record_source_result("probe-source", "q", 5);
        {
            let conn = s.conn.lock().unwrap_or_else(|e| e.into_inner());
            let (failures, hits): (i64, i64) = conn
                .query_row(
                    "SELECT failures,hits FROM source_tasks
                     WHERE source='probe-source' AND query='q'",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .unwrap();
            assert_eq!(failures, 1);
            assert_eq!(hits, 5);
        }
    }

    #[test]
    fn queries_seed_and_rotate() {
        let s = Store::open(":memory:").unwrap();
        let qs = s.list_queries();
        assert!(
            (100..=1000).contains(&qs.len()),
            "query pool must stay compact, got {}",
            qs.len()
        );
        let q = s.next_query().unwrap();
        let ql = q.q.to_ascii_lowercase();
        assert!(
            ql.contains("openai")
                || ql.contains("deepseek")
                || ql.contains("openrouter")
                || ql.contains("moonshot")
                || ql.contains("anthropic")
                || ql.contains("xai")
                || ql.contains("claude")
                || ql.contains("dashscope")
                || ql.contains("bailian")
                || ql.contains("qwen_api_key"),
            "official query first, got {}",
            q.q
        );
        s.mark_query_run(q.id, 3);
        let q2 = s.next_query().unwrap();
        assert_ne!(q.id, q2.id);
    }

    #[test]
    fn official_and_pair_lanes_are_split() {
        let s = Store::open(":memory:").unwrap();
        for i in 0..5 {
            s.add_pat(&format!("ghp_test_{i}"), "", "", "classic", "alive")
                .unwrap();
        }
        s.ensure_pat_lanes(3);
        let rows = s.list_pats();
        assert_eq!(
            rows.iter().filter(|p| p.search_lane == "official").count(),
            3
        );
        assert_eq!(rows.iter().filter(|p| p.search_lane == "pair").count(), 2);
        let official = s.next_official_query().unwrap();
        let lower = official.q.to_lowercase();
        assert!(
            [
                "api.openai.com",
                "openai_api_key",
                "api.deepseek.com",
                "deepseek_api_key",
                "openrouter.ai",
                "openrouter_api_key",
                "api.moonshot.cn",
                "moonshot_api_key",
                "api.anthropic.com",
                "anthropic_api_key",
                "api.x.ai",
                "xai_api_key",
                "xai_key",
                "dashscope",
                "bailian",
                "qwen_api_key",
            ]
            .iter()
            .any(|x| lower.contains(x)),
            "not official: {}",
            official.q
        );
        let pair = s.next_pair_query().unwrap();
        assert!(
            !is_pat_query(&pair.q),
            "PAT dork leaked into pair lane: {}",
            pair.q
        );
        assert!(
            !crate::official::is_dashscope_query(&pair.q),
            "ordinary pair lane should not take the dual-lane reserve: {}",
            pair.q
        );
        let lower = pair.q.to_lowercase();
        assert!(
            ![
                "api.openai.com",
                "openai_api_key",
                "api.deepseek.com",
                "deepseek_api_key",
                "openrouter.ai",
                "openrouter_api_key",
                "api.moonshot.cn",
                "moonshot_api_key",
                "api.anthropic.com",
                "anthropic_api_key",
                "api.x.ai",
                "xai_api_key",
            ]
            .iter()
            .any(|x| lower.contains(x)),
            "pair got official: {}",
            pair.q
        );
    }

    #[test]
    fn dashscope_is_seeded_in_both_lanes() {
        let s = Store::open(":memory:").unwrap();
        let q = "\"DASHSCOPE_API_KEY\" extension:env";
        let (official, pair_lane): (i64, i64) = s
            .conn
            .lock()
            .unwrap()
            .query_row(
                "SELECT official,pair_lane FROM queries WHERE q=?1",
                params![q],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(official, 1, "DashScope must stay in the official lane");
        assert_eq!(pair_lane, 1, "DashScope must also be eligible for pair");
        assert!(s.has_pair_lane_queries());
        let dual = s.next_dual_query_avoid(&HashSet::new()).unwrap();
        assert!(
            crate::official::is_dashscope_query(&dual.q),
            "dual queue did not pick DashScope: {}",
            dual.q
        );
        let regular = s.next_pair_query().unwrap();
        assert!(
            !crate::official::is_dashscope_query(&regular.q),
            "ordinary pair queue should not burn its slot on dual-lane: {}",
            regular.q
        );
    }

    #[test]
    fn valid_pairs_are_oldest_first() {
        let s = Store::open(":memory:").unwrap();
        for (i, ep) in ["https://api.one.test/v1", "https://api.two.test/v1"]
            .iter()
            .enumerate()
        {
            let nf = NewFinding {
                endpoint: ep.to_string(),
                key: format!("sk-test-{i}"),
                status: "VALID".into(),
                ..Default::default()
            };
            s.upsert_finding(&nf).unwrap();
        }
        let rows = s.valid_pairs();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].0, "sk-test-0");
        assert_eq!(rows[1].1, "https://api.two.test/v1");
    }

    #[test]
    fn hosts_cache_and_deep_scans() {
        let s = Store::open(":memory:").unwrap();
        s.record_host("api.foo.dev");
        s.record_host("api.foo.dev");
        s.record_host_valid("api.foo.dev");
        assert_eq!(s.hosts_count(), 1);
        let top = s.top_hosts(5);
        assert_eq!(top[0].host, "api.foo.dev");
        assert_eq!(top[0].count, 2);
        assert_eq!(top[0].valid, 1);

        assert!(s.needs_deep("acme/demo", 24));
        s.mark_deep("acme/demo");
        assert!(!s.needs_deep("acme/demo", 24));

        assert!(!s.was_scanned("acme/demo", ".env", "sha1", now() - 100));
        s.mark_scanned("acme/demo", ".env", "sha1");
        assert!(s.was_scanned("acme/demo", ".env", "sha1", now() - 100));
        assert!(!s.was_scanned("acme/demo", ".env", "", now() - 100));
    }
}

#[cfg(test)]
mod atlas_store_tests {
    use super::*;

    #[test]
    fn generated_query_priorities_favor_precise_dorks() {
        assert!(query_priority("\"sk-\" in:file") > query_priority("\"sk-\" language:python"));
        assert!(
            query_priority("\"OPENAI_API_KEY\" extension:env")
                > query_priority("\"sk-\" language:go")
        );
        assert!(query_priority("\"ghp_\" extension:env") >= 300);
    }

    #[test]
    fn top_repos_returns_repo_pivots() {
        let s = Store::open(":memory:").unwrap();
        for i in 0..3 {
            let nf = NewFinding {
                endpoint: "https://api.test/v1".into(),
                key: format!("sk-atlas-{i}"),
                repo: "acme/demo".into(),
                status: "PAIR".into(),
                ..Default::default()
            };
            s.upsert_finding(&nf).unwrap();
        }
        let repos = s.top_repos(10);
        assert_eq!(repos.first().map(|x| x.0.as_str()), Some("acme/demo"));
    }
}

#[cfg(test)]
mod source_and_lane_tests {
    use super::*;

    #[test]
    fn manual_lane_survives_reload_and_auto_resets() {
        let s = Store::open(":memory:").unwrap();
        let mut ids = Vec::new();
        for i in 0..5 {
            ids.push(
                s.add_pat(
                    &format!("ghp_lane_{i}"),
                    "u",
                    "public_repo",
                    "classic",
                    "alive",
                )
                .unwrap(),
            );
        }
        s.ensure_pat_lanes(3);
        let pats = s.list_pats();
        assert_eq!(
            pats.iter().filter(|p| p.search_lane == "official").count(),
            3
        );
        let target = pats
            .iter()
            .find(|p| p.search_lane == "official")
            .unwrap()
            .id;
        assert!(s.set_pat_lane(target, "pair"));
        s.ensure_pat_lanes(3);
        let pats = s.list_pats();
        assert_eq!(
            pats.iter().find(|p| p.id == target).unwrap().search_lane,
            "pair"
        );
        s.reset_pat_lanes_auto(3);
        let pats = s.list_pats();
        assert_eq!(
            pats.iter().filter(|p| p.search_lane == "official").count(),
            3
        );
        let _ = ids;
    }

    fn finding_for(status: &str) -> NewFinding {
        NewFinding {
            endpoint: "https://relay.example/v1".into(),
            key: "sk-test".into(),
            key_kind: "openai".into(),
            repo: "acme/demo".into(),
            path: ".env".into(),
            commit_sha: "abc".into(),
            source: "code".into(),
            status: status.into(),
            pair: true,
            total_models: 1,
            tested: 1,
            chat_ok: status == "VALID",
            models: vec![],
            probes: vec![],
            latency_ms: 1,
            balance: "?".into(),
            rpm: "?".into(),
            rank: String::new(),
            rank_score: -1,
            rank_verdict: String::new(),
            rank_note: String::new(),
            ranked_at: 0,
        }
    }

    #[test]
    fn valid_transition_resets_card_and_keeps_provenance() {
        let s = Store::open(":memory:").unwrap();
        let first = s.upsert_finding(&finding_for("LIMIT")).unwrap();
        assert!(!first.card_sent);
        assert!(s.claim_card(first.id));

        let transition = s.upsert_finding(&finding_for("VALID")).unwrap();
        assert!(transition.became_valid);
        assert!(
            !transition.card_sent,
            "VALID transition must be deliverable"
        );
        assert!(s.claim_card(transition.id));

        let repeat = s.upsert_finding(&finding_for("VALID")).unwrap();
        assert!(!repeat.became_valid);
        assert!(repeat.card_sent);

        let mut manual = finding_for("VALID");
        manual.repo.clear();
        manual.path.clear();
        manual.commit_sha.clear();
        manual.source = "manual".into();
        s.upsert_finding(&manual).unwrap();
        let f = s.finding_by_id(transition.id).unwrap();
        assert_eq!(f.repo, "acme/demo");
        assert_eq!(f.path, ".env");
        assert_eq!(f.source, "code");
    }

    #[test]
    fn recent_pairs_batch_matches_single_lookup() {
        let s = Store::open(":memory:").unwrap();
        s.upsert_finding(&finding_for("VALID")).unwrap();
        let now = now();
        let pairs = vec![
            (
                "https://relay.example/v1".to_string(),
                "sk-test".to_string(),
            ),
            (
                "https://relay.example/v1".to_string(),
                "sk-other".to_string(),
            ),
        ];
        let recent = s.recent_finding_pairs(&pairs, now - 60);
        assert!(recent.contains(&pairs[0]));
        assert!(!recent.contains(&pairs[1]));
        assert!(s
            .recent_finding("https://relay.example/v1", "sk-test", now - 60)
            .is_some());
    }

    #[test]
    fn failed_frontier_waits_before_retry() {
        let s = Store::open(":memory:").unwrap();
        s.push_frontier("https://example.com/retry", "bing", 1, 10);
        let first = s.pop_frontier(1);
        assert_eq!(first.len(), 1);
        s.release_frontier("https://example.com/retry");
        assert!(s.pop_frontier(1).is_empty(), "backoff must suppress retry");
    }

    #[test]
    fn source_tasks_and_frontier_are_durable() {
        let s = Store::open(":memory:").unwrap();
        s.seed_source_tasks(&[
            ("bing".into(), "\"api.example.com\"".into(), 250),
            ("gitee".into(), "DEEPSEEK_API_KEY".into(), 0),
        ]);
        assert_eq!(s.source_task_count(), 2);
        let first = s.next_source_task(None).unwrap();
        assert_eq!(first.source, "bing");
        s.record_source_result(&first.source, &first.query, 7);
        let again = s.next_source_task(Some("bing")).unwrap();
        assert_eq!(again.source, "gitee");

        s.push_frontier("https://paste.example/a", "bing", 1, 180);
        s.push_frontier("https://paste.example/b", "bing", 1, 190);
        assert_eq!(s.source_frontier_count(), 2);
        let popped = s.pop_frontier(1);
        assert_eq!(popped.len(), 1);
        assert_eq!(popped[0].url, "https://paste.example/b");
        s.finish_frontier(&popped[0].url, 0);
        assert_eq!(s.source_frontier_count(), 1);
        let second = s.pop_frontier(1);
        assert_eq!(second[0].url, "https://paste.example/a");
    }
}
