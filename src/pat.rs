//! Multi-provider personal access tokens.
//!
//! GitHub tokens stay in the dedicated GitHub search pool. Gitee, GitLab,
//! Gitea and Codeberg tokens are validated separately and can be attached to
//! the matching source adapters (where the public API accepts a PAT).

use crate::github::{truncate, PatCheck};
use reqwest::header::HeaderMap;
use reqwest::{Client, StatusCode};
use serde_json::Value;
use std::time::Duration;

pub const PROVIDERS: &[&str] = &["github", "gitee", "gitlab", "gitea", "codeberg"];

pub fn is_provider(s: &str) -> bool {
    PROVIDERS.iter().any(|p| s.eq_ignore_ascii_case(p))
}

pub fn provider_for_token(token: &str) -> Option<&'static str> {
    let t = token.trim();
    if t.starts_with("ghp_")
        || t.starts_with("github_pat_")
        || t.starts_with("gho_")
        || t.starts_with("ghu_")
        || t.starts_with("ghs_")
        || t.starts_with("ghr_")
    {
        Some("github")
    } else if t.starts_with("glpat-") {
        Some("gitlab")
    } else if t.starts_with("gitee_") {
        Some("gitee")
    } else if t.starts_with("gitea_") {
        Some("gitea")
    } else if t.starts_with("codeberg_") {
        Some("codeberg")
    } else {
        None
    }
}

pub fn kind(provider: &str, token: &str) -> String {
    if provider.eq_ignore_ascii_case("github") {
        crate::github::pat_kind(token).to_string()
    } else {
        format!("{provider}-pat")
    }
}

pub fn label(provider: &str) -> &'static str {
    match provider.to_ascii_lowercase().as_str() {
        "gitee" => "GITEE",
        "gitlab" => "GITLAB",
        "gitea" => "GITEA",
        "codeberg" => "CODEBERG",
        _ => "GITHUB",
    }
}

#[derive(Default)]
pub struct ParsedPats {
    pub entries: Vec<(String, String)>,
    pub skipped: Vec<String>,
}

/// Accepts `provider:token`, a bare `provider` word that sets the default for
/// following tokens, and auto-detects GitHub/GitLab prefixes. Opaque Gitee /
/// Gitea / Codeberg tokens must be tagged, because they have no distinctive
/// prefix and must not be mistaken for a GitHub PAT.
pub fn parse_input(raw: &str) -> ParsedPats {
    let mut out = ParsedPats::default();
    let mut default_provider: Option<String> = None;
    for part in raw.split(|c: char| c.is_whitespace() || c == ',' || c == ';') {
        let t = part
            .trim()
            .trim_matches(|c| c == '"' || c == '\'' || c == '`');
        if t.is_empty() {
            continue;
        }
        if is_provider(t) {
            default_provider = Some(t.to_ascii_lowercase());
            continue;
        }
        let (provider, token) = if let Some((head, tail)) = t.split_once(':') {
            if is_provider(head) && !tail.trim().is_empty() {
                (head.to_ascii_lowercase(), tail.trim().to_string())
            } else {
                (default_provider.clone().unwrap_or_default(), t.to_string())
            }
        } else {
            (
                provider_for_token(t)
                    .map(str::to_string)
                    .or_else(|| default_provider.clone())
                    .unwrap_or_default(),
                t.to_string(),
            )
        };
        if token.len() < 20 || token.contains(char::is_whitespace) {
            out.skipped.push(t.to_string());
            continue;
        }
        let provider = if provider.is_empty() {
            provider_for_token(&token)
                .map(str::to_string)
                .unwrap_or_default()
        } else {
            provider
        };
        if provider.is_empty() {
            out.skipped.push(t.to_string());
            continue;
        }
        if !out
            .entries
            .iter()
            .any(|(p, x)| p == &provider && x == &token)
        {
            out.entries.push((provider, token));
        }
    }
    out
}

fn header_i64(headers: &HeaderMap, names: &[&str]) -> Option<i64> {
    names.iter().find_map(|name| {
        headers
            .get(*name)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<i64>().ok())
    })
}

fn header_str(headers: &HeaderMap, names: &[&str]) -> String {
    names
        .iter()
        .find_map(|name| headers.get(*name).and_then(|v| v.to_str().ok()))
        .unwrap_or("")
        .to_string()
}

pub async fn validate(client: &Client, provider: &str, token: &str) -> PatCheck {
    let provider = provider.to_ascii_lowercase();
    let (display_url, req) = match provider.as_str() {
        "gitee" => (
            "https://gitee.com/api/v5/user".to_string(),
            client
                .get("https://gitee.com/api/v5/user")
                .header("Authorization", format!("token {token}")),
        ),
        "gitlab" => (
            "https://gitlab.com/api/v4/user".to_string(),
            client
                .get("https://gitlab.com/api/v4/user")
                .header("PRIVATE-TOKEN", token),
        ),
        "gitea" => (
            "https://gitea.com/api/v1/user".to_string(),
            client
                .get("https://gitea.com/api/v1/user")
                .header("Authorization", format!("token {token}")),
        ),
        "codeberg" => (
            "https://codeberg.org/api/v1/user".to_string(),
            client
                .get("https://codeberg.org/api/v1/user")
                .header("Authorization", format!("token {token}")),
        ),
        _ => {
            return PatCheck {
                error: "unsupported PAT provider".into(),
                ..Default::default()
            };
        }
    };
    let resp = match req
        .timeout(Duration::from_secs(12))
        .header("Accept", "application/json")
        .header("User-Agent", crate::github::UA)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            return PatCheck {
                error: e.to_string(),
                ..Default::default()
            };
        }
    };
    let code = resp.status();
    let headers = resp.headers().clone();
    let body = resp.text().await.unwrap_or_default();
    let lowered = body.to_ascii_lowercase();
    let rate_limited = code == StatusCode::TOO_MANY_REQUESTS
        || lowered.contains("rate limit")
        || lowered.contains("too many requests");
    let remaining = header_i64(
        &headers,
        &[
            "x-ratelimit-remaining",
            "ratelimit-remaining",
            "x-rate-limit-remaining",
        ],
    )
    .unwrap_or(1);
    let scopes = header_str(&headers, &["x-oauth-scopes", "x-gitlab-scopes"]);
    if code != StatusCode::OK {
        return PatCheck {
            ok: rate_limited
                && (code == StatusCode::TOO_MANY_REQUESTS || code == StatusCode::FORBIDDEN),
            search: 0,
            error: format!("HTTP {} · {}", code.as_u16(), truncate(&display_url, 90)),
            ..Default::default()
        };
    }
    let v: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
    let login = v["login"]
        .as_str()
        .or_else(|| v["username"].as_str())
        .or_else(|| v["name"].as_str())
        .unwrap_or("?")
        .to_string();
    PatCheck {
        ok: true,
        login,
        scopes: if scopes.is_empty() {
            "PAT".into()
        } else {
            scopes
        },
        core: 0,
        search: remaining.max(1),
        error: String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_provider_prefixed_tokens() {
        let p =
            parse_input("gitee abcdefghijklmnopqrstuvwxyz123456 gitlab:glpat-12345678901234567890");
        assert_eq!(p.entries.len(), 2);
        assert_eq!(p.entries[0].0, "gitee");
        assert_eq!(p.entries[1].0, "gitlab");
        assert!(p.skipped.is_empty());
    }

    #[test]
    fn rejects_untagged_opaque_token() {
        let p = parse_input("abcdefghijklmnopqrstuvwxyz123456");
        assert!(p.entries.is_empty());
        assert_eq!(p.skipped.len(), 1);
    }

    #[test]
    fn detects_known_prefixes() {
        assert_eq!(
            provider_for_token("ghp_123456789012345678901234567890123456"),
            Some("github")
        );
        assert_eq!(
            provider_for_token("glpat-12345678901234567890"),
            Some("gitlab")
        );
    }
}
