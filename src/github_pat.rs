//! GitHub PAT credentials: the bot can consume these directly, so they get
//! their own probe and their own VALID counter. The search endpoint is the
//! auth boundary: it is a separate 10/min bucket, while `/user` shares the
//! core bucket and can return 403 for a perfectly valid token when the core
//! allowance is exhausted.

use crate::probe::{PStatus, ProbeOutcome};
use reqwest::Client;
use std::time::Instant;

const API: &str = "https://api.github.com";

pub async fn probe(client: &Client, endpoint: &str, key: &str) -> ProbeOutcome {
    let started = Instant::now();
    let search_url = format!("{API}/search/code?q=test&per_page=1");
    let req = || {
        client
            .get(&search_url)
            .timeout(std::time::Duration::from_secs(12))
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .bearer_auth(key)
            .send()
    };
    // One quiet retry on transport failure. GitHub intermittently resets a
    // TLS connection under a large probe burst; a reset is not evidence that
    // the token is invalid.
    let resp = match req().await {
        Ok(r) => r,
        Err(first) => {
            tracing::debug!("github pat search: {first}");
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            match req().await {
                Ok(r) => r,
                Err(e) => {
                    tracing::debug!("github pat search retry: {e}");
                    return outcome(endpoint, PStatus::Unreachable, 0, started, String::new());
                }
            }
        }
    };
    let code = resp.status().as_u16();
    let remaining = resp
        .headers()
        .get("x-ratelimit-remaining")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<i64>().ok());
    let body = resp.text().await.unwrap_or_default();
    let rate_limited = code == 403
        && (remaining == Some(0)
            || body.to_lowercase().contains("rate limit")
            || body.to_lowercase().contains("secondary rate")
            || body.to_lowercase().contains("abuse"));
    let valid_search_body = serde_json::from_str::<serde_json::Value>(&body)
        .ok()
        .map(|v| v.get("total_count").is_some() && v.get("items").is_some())
        .unwrap_or(false);
    let status = if code == 200 && valid_search_body {
        PStatus::Valid
    } else if code == 200 {
        // Captive portal / WAF / proxy page with HTTP 200 is not a GitHub
        // search response.
        PStatus::Partial
    } else if code == 401 {
        PStatus::Invalid
    } else if code == 429 || rate_limited {
        PStatus::Limited
    } else if code == 403 {
        PStatus::Invalid
    } else if (500..=599).contains(&code) {
        PStatus::Unreachable
    } else {
        PStatus::Partial
    };
    let rights = if status == PStatus::Valid {
        "search:code ✅".to_string()
    } else {
        String::new()
    };
    outcome(endpoint, status, code, started, rights)
}

fn outcome(
    endpoint: &str,
    status: PStatus,
    http_status: u16,
    started: Instant,
    scopes: String,
) -> ProbeOutcome {
    ProbeOutcome {
        endpoint: if endpoint.is_empty() {
            API.to_string()
        } else {
            endpoint.to_string()
        },
        base: API.to_string(),
        status,
        models: Vec::new(),
        probes: Vec::new(),
        tested: 0,
        chat_ok: false,
        latency_ms: started.elapsed().as_millis() as u64,
        http_status,
        // The card labels this field itself; store the raw scope list.
        balance: scopes,
        rpm: String::new(),
    }
}
