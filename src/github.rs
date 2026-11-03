use crate::store::{now, PatRow, Store};
use anyhow::{anyhow, bail, Result};
use base64::Engine;
use reqwest::header::HeaderMap;
use reqwest::{Client, StatusCode};
use serde_json::Value;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SearchLane {
    Official,
    Pair,
    /// Dedicated GitHub-PAT credential search (two pool tokens).
    Pat,
}

pub fn query_is_official(q: &str) -> bool {
    crate::official::is_official_query(q)
}
impl SearchLane {
    pub fn as_str(self) -> &'static str {
        match self {
            SearchLane::Official => "official",
            SearchLane::Pair => "pair",
            SearchLane::Pat => "pat",
        }
    }
}

pub const UA: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 keyhunter-rs/1.0";

#[derive(Clone, Debug)]
pub struct PatEntry {
    pub id: i64,
    pub token: String,
    pub login: String,
    pub status: String,
    pub search_lane: String,
    pub remaining_core: i64,
    pub remaining_search: i64,
    pub reset_core: i64,
    pub reset_search: i64,
}

impl From<PatRow> for PatEntry {
    fn from(p: PatRow) -> Self {
        Self {
            id: p.id,
            token: p.token,
            login: p.login,
            status: p.status,
            search_lane: p.search_lane,
            remaining_core: p.remaining_core,
            remaining_search: p.remaining_search,
            reset_core: p.reset_core,
            reset_search: p.reset_search,
        }
    }
}

pub struct PatPool {
    store: Arc<Store>,
    entries: RwLock<Vec<PatEntry>>,
    rr: AtomicUsize,
}

impl PatPool {
    pub fn new(store: Arc<Store>) -> Self {
        Self {
            store,
            entries: RwLock::new(Vec::new()),
            rr: AtomicUsize::new(0),
        }
    }

    pub fn reload(&self) -> Result<()> {
        let official = self.store.setting_i64("official_pats", 3).clamp(0, 60) as usize;
        self.store.ensure_pat_lanes(official);
        self.store.ensure_pat_lane_count(
            "pat",
            self.store.setting_i64("pat_pats", 2).clamp(0, 60) as usize,
        );
        let rows = self.store.list_pats_provider("github");
        let entries: Vec<PatEntry> = rows.into_iter().map(PatEntry::from).collect();
        *self.entries.write().unwrap_or_else(|e| e.into_inner()) = entries;
        Ok(())
    }

    pub fn alive(&self) -> usize {
        self.entries
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter(|p| p.status == "alive")
            .count()
    }

    pub fn count_lane(&self, lane: SearchLane) -> usize {
        self.entries
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter(|p| p.status == "alive" && p.search_lane == lane.as_str())
            .count()
    }

    pub fn snapshot(&self) -> Vec<PatEntry> {
        self.entries
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    pub fn pick(&self, search: bool, lane: Option<SearchLane>) -> Option<PatEntry> {
        // Reserve the request budget in memory before returning the token.
        // Parallel page fetches otherwise all see remaining=10 and overshoot
        // the GitHub 10/min search bucket before the first response arrives.
        let mut entries = self.entries.write().unwrap_or_else(|e| e.into_inner());
        let ts = now();
        let rr = self.rr.fetch_add(1, Ordering::Relaxed);
        let mut viable: Vec<usize> = Vec::new();
        for (i, p) in entries.iter().enumerate() {
            if p.status != "alive" {
                continue;
            }
            if let Some(lane) = lane {
                if p.search_lane != lane.as_str() {
                    continue;
                }
            }
            if search {
                if p.remaining_search > 0 || p.reset_search <= ts {
                    viable.push(i);
                }
            } else if p.remaining_core > 0 || p.reset_core <= ts {
                viable.push(i);
            }
        }
        // The lane split is about *which dorks a token runs by default*, not a
        // hard wall on search capacity. GitHub's search bucket is per token;
        // leaving 100+ pair tokens idle while three official tokens burn their
        // 10/min bucket is the main throughput bottleneck. Fall back to any
        // live search-capable token when the requested lane is exhausted.
        if viable.is_empty() && search && lane.is_some() {
            for (i, p) in entries.iter().enumerate() {
                if p.status == "alive" && (p.remaining_search > 0 || p.reset_search <= ts) {
                    viable.push(i);
                }
            }
        }
        if viable.is_empty() {
            return None;
        }
        let i = viable[rr % viable.len()];
        let p = &mut entries[i];
        if search {
            if p.remaining_search <= 0 && p.reset_search <= ts {
                p.remaining_search = 10;
            }
            if p.remaining_search <= 0 {
                return None;
            }
            p.remaining_search -= 1;
        } else {
            if p.remaining_core <= 0 && p.reset_core <= ts {
                p.remaining_core = 5000;
            }
            if p.remaining_core <= 0 {
                return None;
            }
            p.remaining_core -= 1;
        }
        Some(p.clone())
    }

    pub fn search_remaining(&self) -> i64 {
        self.search_remaining_lane(None)
    }

    pub fn search_remaining_lane(&self, lane: Option<SearchLane>) -> i64 {
        let ts = now();
        self.entries
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter(|p| p.status == "alive")
            .filter(|p| lane.map(|l| p.search_lane == l.as_str()).unwrap_or(true))
            .map(|p| {
                if p.remaining_search <= 0 && p.reset_search <= ts {
                    10
                } else {
                    p.remaining_search.max(0)
                }
            })
            .sum()
    }

    pub fn core_remaining(&self) -> i64 {
        let ts = now();
        self.entries
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter(|p| p.status == "alive")
            .map(|p| {
                if p.remaining_core <= 0 && p.reset_core <= ts {
                    5000
                } else {
                    p.remaining_core.max(0)
                }
            })
            .sum()
    }

    pub fn wait_secs(&self) -> i64 {
        let entries = self.entries.read().unwrap_or_else(|e| e.into_inner());
        let ts = now();
        let mut best: Option<i64> = None;
        for p in entries.iter().filter(|p| p.status == "alive") {
            let reset = if p.remaining_search <= 0 {
                p.reset_search
            } else if p.remaining_core <= 0 {
                p.reset_core
            } else {
                continue;
            };
            let wait = (reset - ts).max(2);
            best = Some(best.map_or(wait, |b: i64| b.min(wait)));
        }
        best.unwrap_or(30).clamp(2, 600)
    }

    pub fn report(&self, id: i64, search: bool, remaining: i64, reset: i64) {
        {
            let mut entries = self.entries.write().unwrap_or_else(|e| e.into_inner());
            if let Some(p) = entries.iter_mut().find(|p| p.id == id) {
                if search {
                    p.remaining_search = remaining;
                    p.reset_search = reset;
                } else {
                    p.remaining_core = remaining;
                    p.reset_core = reset;
                }
            }
        }
        self.store.update_pat_quota(id, search, remaining, reset);
    }

    pub fn mark_dead(&self, id: i64) {
        {
            let mut entries = self.entries.write().unwrap_or_else(|e| e.into_inner());
            if let Some(p) = entries.iter_mut().find(|p| p.id == id) {
                p.status = "dead".into();
            }
        }
        self.store.mark_pat(id, "dead");
        // Rebalance immediately: the official lane must keep three live PATs.
        let _ = self.reload();
    }
}

#[derive(Clone, Debug)]
pub struct RepoInfo {
    pub full_name: String,
    pub default_branch: String,
    pub stars: i64,
    pub fork: bool,
    pub archived: bool,
}

#[derive(Clone, Debug, Default)]
pub struct PatCheck {
    pub ok: bool,
    pub login: String,
    pub scopes: String,
    pub core: i64,
    pub search: i64,
    pub error: String,
}

pub struct Gh {
    base: String,
    raw_base: String,
    http: RwLock<Client>,
    pool: Arc<PatPool>,
    store: Arc<Store>,
}

impl Gh {
    pub fn new(store: Arc<Store>, pool: Arc<PatPool>, proxy: Option<String>) -> Result<Self> {
        Self::with_base(
            store,
            pool,
            proxy,
            "https://api.github.com".into(),
            "https://raw.githubusercontent.com".into(),
        )
    }

    pub fn with_base(
        store: Arc<Store>,
        pool: Arc<PatPool>,
        proxy: Option<String>,
        base: String,
        raw_base: String,
    ) -> Result<Self> {
        Ok(Self {
            base,
            raw_base,
            http: RwLock::new(build_client(proxy.as_deref(), 30)?),
            pool,
            store,
        })
    }

    pub fn pool(&self) -> &Arc<PatPool> {
        &self.pool
    }

    pub fn set_proxy(&self, proxy: Option<String>) -> Result<()> {
        let client = build_client(proxy.as_deref(), 30)?;
        *self.http.write().unwrap_or_else(|e| e.into_inner()) = client;
        Ok(())
    }

    pub async fn validate(&self, token: &str) -> PatCheck {
        let client = self.http.read().unwrap_or_else(|e| e.into_inner()).clone();
        // `/user` is the core bucket and can return 403 for a perfectly valid
        // token after the 5,000/hour core allowance is exhausted. The code
        // search endpoint is the auth boundary that actually matters to the
        // scanner, and it has its own bucket.
        let search_resp = client
            .get(format!("{}/search/code?q=test&per_page=1", self.base))
            .header("Authorization", format!("Bearer {token}"))
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .send()
            .await;
        let search_resp = match search_resp {
            Ok(r) => r,
            Err(e) => {
                return PatCheck {
                    error: e.to_string(),
                    ..Default::default()
                }
            }
        };
        let status = search_resp.status();
        let remaining_search = search_resp
            .headers()
            .get("x-ratelimit-remaining")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<i64>().ok())
            .unwrap_or(0);
        let search_text = search_resp.text().await.unwrap_or_default();
        if status != StatusCode::OK {
            let lowered = search_text.to_lowercase();
            let rate_limited = status == StatusCode::TOO_MANY_REQUESTS
                || (status == StatusCode::FORBIDDEN
                    && (remaining_search == 0
                        || lowered.contains("rate limit")
                        || lowered.contains("secondary rate")));
            let error = if status == StatusCode::UNAUTHORIZED {
                format!("HTTP 401 {}", truncate(&search_text, 120))
            } else if status == StatusCode::FORBIDDEN {
                format!("HTTP 403 {}", truncate(&search_text, 120))
            } else {
                format!("HTTP {} {}", status.as_u16(), truncate(&search_text, 120))
            };
            return PatCheck {
                ok: rate_limited,
                search: remaining_search,
                error,
                ..Default::default()
            };
        }

        let mut check = PatCheck {
            ok: true,
            login: "?".into(),
            scopes: String::new(),
            core: 0,
            search: remaining_search.max(1),
            error: String::new(),
        };
        // Login/scopes are useful for the pool UI, but never let a core-limit
        // 403 turn a valid search-capable token into a dead one.
        if let Ok(resp) = client
            .get(format!("{}/user", self.base))
            .header("Authorization", format!("Bearer {token}"))
            .header("Accept", "application/vnd.github+json")
            .send()
            .await
        {
            if resp.status() == StatusCode::OK {
                check.scopes = resp
                    .headers()
                    .get("x-oauth-scopes")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_string();
                if let Ok(text) = resp.text().await {
                    if let Ok(v) = serde_json::from_str::<Value>(&text) {
                        check.login = v["login"].as_str().unwrap_or("?").to_string();
                    }
                }
            }
        }
        check
    }

    async fn get_json(
        &self,
        url: &str,
        accept: &str,
        search: bool,
        lane: Option<SearchLane>,
    ) -> Result<Value> {
        let mut attempt = 0usize;
        let mut last_err = String::new();
        loop {
            attempt += 1;
            if attempt > 14 {
                if last_err.is_empty() {
                    last_err = "no GitHub capacity left".into();
                }
                bail!("GitHub request failed after retries: {}", last_err);
            }
            let Some(pat) = self.pool.pick(search, lane) else {
                if self.pool.alive() == 0 {
                    bail!("PAT pool is empty or all tokens are dead");
                }
                if search {
                    // Do not pin a worker for ten minutes when every search
                    // bucket is empty. Fail the job fast; the next scheduler
                    // tick will retry as soon as a token resets.
                    bail!("search quota exhausted; retry on next tick");
                }
                // Waiting here from every worker creates a log storm and
                // keeps deep-scan jobs occupied doing nothing. Let the job
                // fail fast; auto/deep scheduling will retry later.
                bail!("core quota exhausted; retry on next tick");
            };
            let client = self.http.read().unwrap_or_else(|e| e.into_inner()).clone();
            let resp = client
                .get(url)
                .header("Authorization", format!("Bearer {}", pat.token))
                .header("Accept", accept)
                .header("X-GitHub-Api-Version", "2022-11-28")
                .send()
                .await;
            let resp = match resp {
                Ok(r) => r,
                Err(e) => {
                    last_err = e.to_string();
                    if attempt >= 4 {
                        return Err(anyhow!("GitHub network error: {}", last_err));
                    }
                    tokio::time::sleep(Duration::from_secs(attempt as u64 + 1)).await;
                    continue;
                }
            };
            let status = resp.status();
            let remaining = header_i64(resp.headers(), "x-ratelimit-remaining");
            let reset = header_i64(resp.headers(), "x-ratelimit-reset");
            if let (Some(rem), Some(res)) = (remaining, reset) {
                self.pool.report(pat.id, search, rem, res);
            }
            if status == StatusCode::UNAUTHORIZED {
                tracing::warn!("PAT {} is dead (401)", pat.id);
                self.pool.mark_dead(pat.id);
                last_err = "401 from GitHub".into();
                continue;
            }
            let retry_after = header_i64(resp.headers(), "retry-after").unwrap_or(0);
            let text = resp.text().await.unwrap_or_default();
            let mut forced_wait = 0i64;
            if search
                && (status == StatusCode::FORBIDDEN || status == StatusCode::TOO_MANY_REQUESTS)
                && (text.to_lowercase().contains("secondary rate limit")
                    || retry_after > 0
                    || remaining == Some(0))
            {
                // Search has its own 10/min bucket. GitHub's secondary limit
                // often returns 403 with a stale x-ratelimit-reset; force a
                // real cooldown instead of hammering the endpoint.
                forced_wait = retry_after
                    .max(if remaining == Some(0) {
                        reset.map(|r| r - now()).unwrap_or(60)
                    } else {
                        60
                    })
                    .clamp(30, 300);
                self.pool.report(pat.id, true, 0, now() + forced_wait);
            }
            if search && forced_wait > 0 {
                bail!(
                    "GitHub search rate limited; cooldown {}s (do not burn retries)",
                    forced_wait
                );
            }
            if status.is_success() {
                return Ok(serde_json::from_str(&text)?);
            }
            if status == StatusCode::FORBIDDEN
                && (text.contains("Resource not accessible")
                    || text.contains("not accessible by personal access token"))
            {
                if search {
                    tracing::warn!(
                        "PAT {} cannot use code search (scope), cooling down search lane: {}",
                        pat.id,
                        truncate(&text, 160)
                    );
                    // Do not destroy the token for core operations (repo,
                    // tree, blob) just because it lacks code-search scope.
                    // Park only its search bucket for an hour.
                    self.pool.report(pat.id, true, 0, now() + 3600);
                    last_err = "PAT lacks code search scope".into();
                    continue;
                }
                bail!("GitHub 403: {}", truncate(&text, 200));
            }
            if status == StatusCode::FORBIDDEN
                && remaining.unwrap_or(0) > 0
                && !text.to_lowercase().contains("secondary rate limit")
            {
                bail!("GitHub 403 (scope?): {}", truncate(&text, 240));
            }
            if !search
                && remaining == Some(0)
                && (status == StatusCode::FORBIDDEN || status == StatusCode::TOO_MANY_REQUESTS)
            {
                // The core bucket is empty. A blob/tree fallback must not
                // sleep a worker for three minutes in a turbo scan.
                bail!("core quota exhausted; skipping core call");
            }
            if status == StatusCode::FORBIDDEN
                || status == StatusCode::TOO_MANY_REQUESTS
                || status.is_server_error()
            {
                let max_attempts = if search { 12 } else { 4 };
                if attempt < max_attempts {
                    let wait = if forced_wait > 0 {
                        forced_wait
                    } else if remaining == Some(0) {
                        reset.map(|r| (r - now()).max(2)).unwrap_or(30)
                    } else if retry_after > 0 {
                        retry_after
                    } else if status == StatusCode::TOO_MANY_REQUESTS {
                        40 + attempt as i64 * 15
                    } else {
                        3 * attempt as i64
                    };
                    let sleep_for = wait.clamp(2, if search { 180 } else { 10 });
                    tracing::warn!(
                        "GitHub {} on {}, retry in {}s (attempt {})",
                        status.as_u16(),
                        url,
                        sleep_for,
                        attempt
                    );
                    tokio::time::sleep(Duration::from_secs(sleep_for as u64)).await;
                    continue;
                }
            }
            last_err = format!("HTTP {} {}", status.as_u16(), truncate(&text, 240));
            bail!("{}", last_err);
        }
    }

    pub async fn repo(&self, full: &str) -> Result<RepoInfo> {
        if let Some(cached) = self.store.get_repo(full) {
            if now() - cached.fetched_at < 3 * 86_400 {
                return Ok(RepoInfo {
                    full_name: cached.full_name,
                    default_branch: cached.default_branch,
                    stars: cached.stars,
                    fork: cached.fork,
                    archived: cached.archived,
                });
            }
        }
        let url = format!("{}/repos/{}", self.base, encode_repo(full));
        let v = self
            .get_json(&url, "application/vnd.github+json", false, None)
            .await?;
        let branch = v["default_branch"].as_str().unwrap_or("main").to_string();
        let stars = v["stargazers_count"].as_i64().unwrap_or(0);
        let fork = v["fork"].as_bool().unwrap_or(false);
        let archived = v["archived"].as_bool().unwrap_or(false);
        self.store.upsert_repo(full, &branch, stars, fork, archived);
        Ok(RepoInfo {
            full_name: full.to_string(),
            default_branch: branch,
            stars,
            fork,
            archived,
        })
    }

    pub async fn search_code(&self, q: &str, page: u32, lane: SearchLane) -> Result<Value> {
        // Do not append `pushed:>` to code search. GitHub's code-search
        // endpoint accepts the qualifier syntactically but returns an almost
        // empty result set (empirically 1 hit for "sk-" instead of ~49M).
        // `sort=indexed` gives stable ordering; repository discovery still
        // uses the supported pushed filter.
        let query = q.to_string();
        let url = format!(
            "{}/search/code?q={}&sort=indexed&order=desc&per_page=100&page={}",
            self.base,
            urlencoding::encode(&query),
            page
        );
        // GitHub's search bucket is per token. The official/pair/pat lane is a
        // *dork priority* classification, not a search-capacity wall: if we
        // pin official jobs to three tokens, page 5 of ten parallel jobs burns
        // their 10/min bucket and every extra page fails. Use the whole live
        // pool for official-provider searches; pair/PAT jobs keep their lane
        // preference but can also fall back inside PatPool.
        let pick_lane = if matches!(lane, SearchLane::Official) {
            None
        } else {
            Some(lane)
        };
        self.get_json(
            &url,
            "application/vnd.github.text-match+json",
            true,
            pick_lane,
        )
        .await
    }

    pub async fn search_repos(&self, q: &str, per_page: u32) -> Result<Value> {
        let url = format!(
            "{}/search/repositories?q={}&sort=updated&order=desc&per_page={}",
            self.base,
            urlencoding::encode(q),
            per_page.clamp(1, 100)
        );
        self.get_json(
            &url,
            "application/vnd.github+json",
            true,
            Some(SearchLane::Pair),
        )
        .await
    }

    /// Public branches. Used by the Atlas deep layer to inspect code that is
    /// not on the default branch (feature/config branches often carry keys).
    pub async fn branches(&self, full: &str) -> Result<Vec<(String, String)>> {
        let url = format!(
            "{}/repos/{}/branches?per_page=100",
            self.base,
            encode_repo(full)
        );
        let v = self
            .get_json(&url, "application/vnd.github+json", false, None)
            .await?;
        let mut out = Vec::new();
        if let Some(items) = v.as_array() {
            for b in items {
                let Some(name) = b["name"].as_str() else {
                    continue;
                };
                let sha = b["commit"]["sha"].as_str().unwrap_or("").to_string();
                out.push((name.to_string(), sha));
            }
        }
        Ok(out)
    }

    pub async fn tree(&self, full: &str, branch: &str) -> Result<Vec<TreeEntry>> {
        let url = format!(
            "{}/repos/{}/git/trees/{}?recursive=1",
            self.base,
            encode_repo(full),
            urlencoding::encode(branch)
        );
        let v = self
            .get_json(&url, "application/vnd.github+json", false, None)
            .await?;
        let mut out = Vec::new();
        if let Some(arr) = v["tree"].as_array() {
            for it in arr {
                if it["type"].as_str() != Some("blob") {
                    continue;
                }
                let Some(path) = it["path"].as_str() else {
                    continue;
                };
                out.push(TreeEntry {
                    path: path.to_string(),
                    size: it["size"].as_i64().unwrap_or(0),
                    sha: it["sha"].as_str().unwrap_or("").to_string(),
                });
            }
        }
        Ok(out)
    }

    pub async fn list_commits(
        &self,
        full: &str,
        path: Option<&str>,
        limit: usize,
    ) -> Result<Vec<CommitRef>> {
        // GitHub caps a commits page at 100. Manual deep scans ask for up to
        // 300 commits, so page through the endpoint instead of silently
        // returning only the first page.
        let want = limit.clamp(1, 1000);
        let mut out = Vec::new();
        for page in 1..=want.div_ceil(100) {
            let mut url = format!(
                "{}/repos/{}/commits?per_page=100&page={}",
                self.base,
                encode_repo(full),
                page
            );
            if let Some(p) = path {
                url.push_str("&path=");
                url.push_str(&urlencoding::encode(p));
            }
            let v = self
                .get_json(&url, "application/vnd.github+json", false, None)
                .await?;
            let arr = v.as_array().cloned().unwrap_or_default();
            if arr.is_empty() {
                break;
            }
            for c in &arr {
                let Some(sha) = c["sha"].as_str() else {
                    continue;
                };
                out.push(CommitRef {
                    sha: sha.to_string(),
                    message: c["commit"]["message"].as_str().unwrap_or("").to_string(),
                    date: c["commit"]["author"]["date"]
                        .as_str()
                        .unwrap_or("")
                        .to_string(),
                });
                if out.len() >= want {
                    break;
                }
            }
            if out.len() >= want || arr.len() < 100 {
                break;
            }
        }
        out.truncate(want);
        Ok(out)
    }

    pub async fn commit_files(&self, full: &str, sha: &str) -> Result<Vec<FilePatch>> {
        let url = format!(
            "{}/repos/{}/commits/{}",
            self.base,
            encode_repo(full),
            urlencoding::encode(sha)
        );
        let v = self
            .get_json(&url, "application/vnd.github+json", false, None)
            .await?;
        let mut out = Vec::new();
        if let Some(arr) = v["files"].as_array() {
            for f in arr {
                let Some(name) = f["filename"].as_str() else {
                    continue;
                };
                out.push(FilePatch {
                    filename: name.to_string(),
                    status: f["status"].as_str().unwrap_or("").to_string(),
                    patch: f["patch"].as_str().unwrap_or("").to_string(),
                });
            }
        }
        Ok(out)
    }

    pub async fn raw(&self, repo: &str, branch: &str, path: &str) -> Result<Option<String>> {
        let url = format!(
            "{}/{}/{}/{}",
            self.raw_base,
            encode_repo(repo),
            encode_path(branch),
            encode_path(path)
        );
        let client = self.http.read().unwrap_or_else(|e| e.into_inner()).clone();
        let resp = client
            .get(&url)
            .header("Accept", "text/plain, */*")
            .timeout(Duration::from_secs(20))
            .send()
            .await?;
        if !resp.status().is_success() {
            return Ok(None);
        }
        if resp.content_length().unwrap_or(0) > 1_500_000 {
            return Ok(None);
        }
        let text = resp.text().await?;
        if text.len() > 1_500_000 {
            return Ok(None);
        }
        Ok(Some(text))
    }

    pub async fn blob(&self, repo: &str, sha: &str) -> Result<Option<String>> {
        if sha.is_empty() {
            return Ok(None);
        }
        let url = format!(
            "{}/repos/{}/git/blobs/{}",
            self.base,
            encode_repo(repo),
            urlencoding::encode(sha)
        );
        let v = self
            .get_json(&url, "application/vnd.github+json", false, None)
            .await?;
        if v["encoding"].as_str() != Some("base64") {
            return Ok(None);
        }
        let Some(content) = v["content"].as_str() else {
            return Ok(None);
        };
        let cleaned: String = content.chars().filter(|c| !c.is_whitespace()).collect();
        if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(cleaned) {
            if bytes.len() <= 1_500_000 {
                return Ok(Some(String::from_utf8_lossy(&bytes).to_string()));
            }
        }
        Ok(None)
    }
}

#[derive(Clone, Debug)]
pub struct TreeEntry {
    pub path: String,
    pub size: i64,
    pub sha: String,
}

#[derive(Clone, Debug)]
pub struct CommitRef {
    pub sha: String,
    pub message: String,
    pub date: String,
}

#[derive(Clone, Debug)]
pub struct FilePatch {
    pub filename: String,
    pub status: String,
    pub patch: String,
}

pub fn build_client(proxy: Option<&str>, timeout_secs: u64) -> Result<Client> {
    let mut b = Client::builder()
        .user_agent(UA)
        .timeout(Duration::from_secs(timeout_secs))
        .connect_timeout(Duration::from_secs(10))
        .pool_max_idle_per_host(16);
    if let Some(p) = proxy {
        if !p.trim().is_empty() {
            b = b.proxy(reqwest::Proxy::all(p)?);
        }
    }
    Ok(b.build()?)
}

fn encode_repo(full: &str) -> String {
    full.split('/')
        .map(|part| urlencoding::encode(part).into_owned())
        .collect::<Vec<_>>()
        .join("/")
}

pub fn pat_kind(token: &str) -> &'static str {
    if token.starts_with("github_pat_") {
        "fine-grained"
    } else if token.starts_with("ghp_") {
        "classic"
    } else if token.starts_with("gho_") {
        "oauth"
    } else if token.starts_with("ghu_") || token.starts_with("ghs_") {
        "app"
    } else {
        "other"
    }
}

fn header_i64(headers: &HeaderMap, name: &str) -> Option<i64> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<i64>().ok())
}

fn encode_path(p: &str) -> String {
    p.split('/')
        .map(|s| urlencoding::encode(s).to_string())
        .collect::<Vec<_>>()
        .join("/")
}

pub fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        let cut: String = s.chars().take(n).collect();
        format!("{}…", cut)
    }
}

#[cfg(test)]
mod lane_tests {
    use super::*;

    #[test]
    fn official_and_pair_picks_do_not_cross() {
        let store = Arc::new(Store::open(":memory:").unwrap());
        for i in 0..5 {
            store
                .add_pat(&format!("ghp_lane_{i}"), "", "", "classic", "alive")
                .unwrap();
        }
        store.ensure_pat_lanes(3);
        store.set_setting("pat_pats", "0").unwrap();
        let pool = PatPool::new(store);
        pool.reload().unwrap();
        let official = pool.pick(true, Some(SearchLane::Official)).unwrap();
        let pair = pool.pick(true, Some(SearchLane::Pair)).unwrap();
        assert_eq!(official.search_lane, "official");
        assert_eq!(pair.search_lane, "pair");
    }

    #[test]
    fn pick_reserves_search_budget_atomically() {
        let store = Arc::new(Store::open(":memory:").unwrap());
        let id = store
            .add_pat("ghp_reserve", "u", "public_repo", "classic", "alive")
            .unwrap();
        store.update_pat_quota(id, true, 1, now() + 3600);
        let pool = PatPool::new(store);
        pool.reload().unwrap();
        assert!(pool.pick(true, None).is_some());
        assert!(pool.pick(true, None).is_none());
    }

    #[test]
    fn pat_lane_uses_two_tokens_without_stealing_official_lane() {
        let store = Arc::new(Store::open(":memory:").unwrap());
        for i in 0..6 {
            store
                .add_pat(&format!("ghp_pat_lane_{i}"), "", "", "classic", "alive")
                .unwrap();
        }
        store.ensure_pat_lanes(3);
        store.ensure_pat_lane_count("pat", 2);
        let rows = store.list_pats();
        assert_eq!(
            rows.iter().filter(|p| p.search_lane == "official").count(),
            3
        );
        assert_eq!(rows.iter().filter(|p| p.search_lane == "pat").count(), 2);
        let pool = PatPool::new(store);
        pool.reload().unwrap();
        assert_eq!(pool.count_lane(SearchLane::Pat), 2);
    }
}
