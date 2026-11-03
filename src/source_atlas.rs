//! Source Atlas: a durable, self-expanding search graph for non-GitHub
//! sources.
//!
//! Two kinds of work are produced here:
//!   1. endpoint-driven search tasks (`bing`/`bing2`/`torch`) learned from
//!      hosts that already produced findings;
//!   2. a crawl frontier filled by `scan::run_source` from links found in
//!      fetched pages.
//!
//! The task table is persistent, so a new host pivot survives restarts and
//! competes with static seed tasks by priority and yield.

use crate::app::App;
use crate::store::now;
use std::sync::Arc;
use tracing::debug;

const PAT_SOURCE_QUERIES: &[&str] = &[
    "\"ghp_\"",
    "\"github_pat_\"",
    "\"GITHUB_TOKEN\" \"ghp_\"",
    "\"GH_TOKEN\" \"github_pat_\"",
    "\"github_pat_\" path:.env",
    "\"ghp_\" path:.env",
    "\"GH_PAT\"",
    "\"GITHUB_TOKEN=ghp_\"",
    "\"GITHUB_TOKEN=github_pat_\"",
    "\"GH_TOKEN=ghp_\"",
    "\"GH_TOKEN=github_pat_\"",
    "\"GITHUB_PAT=ghp_\"",
    "\"GH_PAT=ghp_\"",
    "\"x-access-token\"",
    "\"gho_\"",
    "\"ghs_\"",
    "\"ghr_\"",
    "\"ghp_\" extension:env",
    "\"github_pat_\" extension:env",
    "\"GITHUB_TOKEN\" path:.github/workflows",
    "\"GH_TOKEN\" path:.github/workflows",
];

pub fn synthesize(app: &Arc<App>) {
    // GitHub PAT credentials get their own source pack, but not the highest
    // tier: the dedicated two-token search lane is the priority mechanism.
    // They are seeded before the Atlas interval gate so a restart does not
    // wait 90s for them.
    for (i, q) in PAT_SOURCE_QUERIES.iter().enumerate() {
        for (j, source) in [
            "bing",
            "ddg",
            "gitee",
            "gitlab",
            "hf",
            "debian",
            "marginalia",
            "gists",
            "urlscan",
            "bluesky",
            "npm",
            "pastegg",
        ]
        .iter()
        .enumerate()
        {
            app.store
                .add_source_task(source, q, 300 - (i as i64) - (j as i64));
        }
    }
    app.store.cap_pat_source_priority(299);
    let interval = app.store.setting_i64("source_atlas_interval", 90).max(30);
    let last = app.store.setting_i64("last_source_atlas", 0);
    if now() - last < interval {
        return;
    }
    app.store
        .set_setting("last_source_atlas", &now().to_string())
        .ok();

    let mut added = 0usize;
    // Provider-specific source dorks. These are deliberately above generic
    // host pivots: if an official key is sitting on a paste/forum page, the
    // source lane should see it before another random relay query.
    for (i, q) in crate::official::source_queries().into_iter().enumerate() {
        let source = if i % 2 == 0 { "bing" } else { "bing2" };
        app.store.add_source_task(source, &q, 330);
        added += 1;
        // Code hosts give more exact endpoint+key context than generic web
        // results. Reserve a few high-priority jobs per provider.
        let code_query = !q.to_ascii_lowercase().contains("site:");
        for (j, code_source) in ["gitee", "gitlab", "hf", "debian", "gitlab_snippet", "ddg"]
            .iter()
            .enumerate()
        {
            if !code_query {
                break;
            }
            app.store
                .add_source_task(code_source, &q, 320 - j as i64 * 5);
            added += 1;
        }
    }
    for (i, h) in app.store.top_hosts(60).into_iter().enumerate() {
        let host = h.host.trim().to_ascii_lowercase();
        if host.is_empty()
            || host == "localhost"
            || host.starts_with("127.")
            || host.starts_with("10.")
            || host.starts_with("192.168.")
            || host.starts_with("172.")
            || host.contains(' ')
            || host.contains("groq")
            // TTS endpoints are validated by the modality prober, not by new
            // automatic search dorks. Do not seed the auto scanner with them.
            || host.contains("fish.audio")
            || host.contains("elevenlabs.io")
        {
            continue;
        }
        let source = if i % 2 == 0 { "bing" } else { "bing2" };
        let score = 250 + (h.valid.min(20) * 2);
        // Host-first queries catch public docs, README files and forum posts
        // that never contain the literal string "sk-".
        let queries = [
            format!("\"{host}\" \"api key\""),
            format!("\"{host}\" \"sk-\""),
            format!("\"{host}\" site:pastebin.com"),
        ];
        for q in queries {
            app.store.add_source_task(source, &q, score);
            added += 1;
        }
        // Torch gets a lower-priority host pivot: onion indexes are noisy but
        // occasionally carry leaked relay configs that clearnet search misses.
        if h.valid > 0 {
            app.store.add_source_task("torch", &host, 210);
            added += 1;
        }
    }
    if added > 0 {
        debug!("source atlas: {} endpoint pivots examined", added);
    }
}
