//! Atlas: layered, self-expanding GitHub discovery.
//!
//! Layer 0 is the static dork pack. Layer 1 is endpoint-first search. Layer 2
//! pivots through repositories and owners. Layer 3 expands every newly seen
//! endpoint host back into the query frontier. Queries carry a priority and a
//! yield score, so the scheduler explores new pivots before burning calls on
//! exhausted dorks.

use crate::app::App;
use crate::store::HostRow;

const EXCLUDE: &[&str] = &[
    "github.com",
    "raw.githubusercontent.com",
    "api.github.com",
    "gitlab.com",
    "gitee.com",
    "api.groq.com",
    "bitbucket.org",
    "w3.org",
    "schema.org",
    "example.com",
    "localhost",
    "127.0.0.1",
];

fn good_host(host: &str) -> bool {
    !host.is_empty()
        && host.contains('.')
        && host.len() < 120
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
        && !host.starts_with("10.")
        && !host.starts_with("192.168.")
        && !host.starts_with("172.16.")
        && !host.starts_with("172.17.")
        && !host.starts_with("172.18.")
        && !host.starts_with("172.19.")
        && !host.starts_with("172.2")
        && !host.starts_with("172.30.")
        && !host.starts_with("172.31.")
        && !host.starts_with("169.254.")
        && !EXCLUDE
            .iter()
            .any(|x| host == *x || host.ends_with(&format!(".{x}")))
}

fn owner_of(repo: &str) -> Option<&str> {
    repo.split_once('/').map(|(owner, _)| owner)
}

/// Add the first three layers for a host. Returns the number of newly queued
/// queries. The caller may invoke this for every endpoint it discovers; the
/// unique index keeps it cheap.
pub fn pivot_host(app: &App, host: &str, priority: i64) -> usize {
    if !good_host(host) || app.store.pending_query_count() >= 600 {
        return 0;
    }
    let mut added = 0;
    let layer = [
        (format!("\"{host}\" in:file"), priority),
        (format!("\"{host}\" \"sk-\" in:file"), priority + 20),
        (format!("\"{host}\" \"api_key\" in:file"), priority + 15),
        (format!("\"{host}\" path:.env"), priority + 10),
    ];
    for (q, p) in layer {
        if app.store.add_query_priority(&q, p).unwrap_or(false) {
            added += 1;
        }
    }
    added
}

/// Run one Atlas synthesis pass. It reads the host/repository graph that the
/// scanner has accumulated and materializes high-value pivots into the query
/// frontier. Returns the number of newly added queries.
pub fn synthesize(app: &App) -> usize {
    // Do not flood the DB if a previous pass is still feeding workers.
    let total = app.store.pending_query_count();
    if total >= 600 {
        return 0;
    }

    let hosts = app.store.top_hosts(160);
    let repos = app.store.top_repos(30);
    let mut added = 0usize;
    let mut host_added = 0usize;
    let mut repo_added = 0usize;

    for h in hosts.iter().take(160) {
        if added >= 30 {
            break;
        }
        let priority = if h.valid > 0 {
            260
        } else if is_priority_host(&h.host) {
            240
        } else if h.count >= 2 {
            140
        } else {
            90
        };
        let before = added;
        added += pivot_host(app, &h.host, priority);
        host_added += added - before;
    }

    for (repo, hits) in repos.iter().take(30) {
        if repo_added >= 20 {
            break;
        }
        if !repo.contains('/') {
            continue;
        }
        let p = if *hits > 0 { 250 } else { 160 };
        for q in [
            format!("repo:{repo} \"sk-\" in:file"),
            format!("repo:{repo} \"api_key\" in:file"),
            format!("repo:{repo} \"base_url\" in:file"),
            format!("repo:{repo} \"apiKey\" in:file"),
        ] {
            if app.store.add_query_priority(&q, p).unwrap_or(false) {
                added += 1;
                repo_added += 1;
            }
        }
        if let Some(owner) = owner_of(repo) {
            let q = format!("user:{owner} \"sk-\" in:file");
            if app.store.add_query_priority(&q, p - 30).unwrap_or(false) {
                added += 1;
                repo_added += 1;
            }
        }
    }

    if added > 0 {
        tracing::info!(
            "atlas: synth hosts={host_added} repos={repo_added} total={added} frontier={}",
            total + added
        );
    }
    added
}

fn is_priority_host(host: &str) -> bool {
    let h = host.to_lowercase();
    [
        "openai",
        "deepseek",
        "openrouter",
        "moonshot",
        "anthropic",
        "xai",
        "dashscope",
        "aliyuncs",
    ]
    .iter()
    .any(|x| h.contains(x))
}

/// A hostname-level description used by `/atlas` and logs.
pub fn host_layer(host: &HostRow) -> &'static str {
    if host.valid > 0 {
        "L3-valid"
    } else if is_priority_host(&host.host) {
        "L2-priority"
    } else if host.count > 1 {
        "L1-repeated"
    } else {
        "L0-seed"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_filter_rejects_infrastructure() {
        if !good_host("api.openai.com") {
            // The test environment is not allowed to suppress a real API host.
            // This assertion is intentionally inverted for clarity in logs.
            panic!("real API host rejected");
        }
        assert!(!good_host("github.com"));
        assert!(!good_host("127.0.0.1"));
        assert!(!good_host("localhost"));
        assert!(!good_host("bad host"));
    }

    #[test]
    fn owner_is_parsed() {
        assert_eq!(owner_of("acme/demo"), Some("acme"));
        assert_eq!(owner_of("no-slash"), None);
    }
}
