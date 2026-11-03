use crate::app::App;
use anyhow::{bail, Result};
use futures::StreamExt;
use rand::seq::SliceRandom;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;
use tracing::{info, warn};

const UA: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36";

/// Public lists. They are fetched directly; only the validated proxies are
/// used for scanner traffic.
const LISTS: &[(&str, &str)] = &[
    ("http", "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt"),
    ("socks5", "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt"),
    ("http", "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt"),
    ("socks5", "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt"),
    ("http", "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/http/data.txt"),
    ("socks5", "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/socks5/data.txt"),
    ("socks5", "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt"),
    ("http", "https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt"),
    ("http", "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt"),
    ("http", "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt"),
    ("socks5", "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks5.txt"),
    ("http", "https://raw.githubusercontent.com/themiralay/Proxy-List-World/master/data.txt"),
    ("http", "https://raw.githubusercontent.com/zloi-user/hideip.me/main/https.txt"),
    ("http", "https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/https.txt"),
    ("http", "https://raw.githubusercontent.com/mmpx12/proxy-list/master/https.txt"),
    ("http", "https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&protocol=http&proxy_format=ipport&format=text"),
    ("http", "https://proxyspace.pro/http.txt"),
    ("socks5", "https://proxyspace.pro/socks5.txt"),
    ("http", "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all"),
    ("socks5", "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&timeout=10000&country=all&ssl=all&anonymity=all"),
    ("http", "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/all/data.txt"),
    ("http", "https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/http.txt"),
    ("socks5", "https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/socks5.txt"),
    ("http", "https://raw.githubusercontent.com/zloi-user/hideip.me/main/http.txt"),
    ("socks5", "https://raw.githubusercontent.com/zloi-user/hideip.me/main/socks5.txt"),
    ("http", "https://raw.githubusercontent.com/mmpx12/proxy-list/master/http.txt"),
    ("socks5", "https://raw.githubusercontent.com/mmpx12/proxy-list/master/socks5.txt"),
    ("http", "https://raw.githubusercontent.com/rdavydov/proxy-list/main/proxies/http.txt"),
    ("socks5", "https://raw.githubusercontent.com/rdavydov/proxy-list/main/proxies/socks5.txt"),
    ("socks5", "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5_RAW.txt"),
    ("http", "https://raw.githubusercontent.com/casals-ar/proxy-list/main/http"),
    ("socks5", "https://raw.githubusercontent.com/casals-ar/proxy-list/main/socks5"),
    ("http", "https://raw.githubusercontent.com/fyvri/fresh-proxy-list/archive/storage/classic/http.txt"),
    ("http", "https://raw.githubusercontent.com/fyvri/fresh-proxy-list/archive/storage/classic/https.txt"),
    ("socks5", "https://raw.githubusercontent.com/fyvri/fresh-proxy-list/archive/storage/classic/socks5.txt"),
    ("http", "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/all.txt"),
];

const MAX_CANDIDATES: usize = 4000;
const CHECK_CONCURRENCY: usize = 384;
const CHECK_TIMEOUT: u64 = 3;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProxyEntry {
    pub url: String,
    pub kind: String,
    pub latency_ms: u64,
}

pub struct ProxyPool {
    http: reqwest::Client,
    entries: RwLock<Vec<ProxyEntry>>,
    active: RwLock<Option<String>>,
    last_refresh: AtomicI64,
    refreshing: AtomicBool,
}

pub fn list_count() -> usize {
    LISTS.len()
}

impl ProxyPool {
    pub fn new() -> Result<Self> {
        let http = reqwest::Client::builder()
            .user_agent(UA)
            .timeout(Duration::from_secs(20))
            .gzip(false)
            .brotli(false)
            .build()?;
        let (entries, last_refresh) = load_cache();
        let active = entries.first().map(|p| p.url.clone());
        Ok(Self {
            http,
            entries: RwLock::new(entries),
            active: RwLock::new(active),
            last_refresh: AtomicI64::new(last_refresh),
            refreshing: AtomicBool::new(false),
        })
    }

    pub fn count(&self) -> usize {
        self.entries.read().unwrap_or_else(|e| e.into_inner()).len()
    }

    pub fn active(&self) -> Option<String> {
        self.active
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    pub fn last_refresh(&self) -> i64 {
        self.last_refresh.load(Ordering::Relaxed)
    }

    pub fn best(&self) -> Option<String> {
        self.entries
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .first()
            .map(|p| p.url.clone())
    }

    pub fn urls(&self, n: usize) -> Vec<String> {
        let mut seen = std::collections::HashSet::new();
        self.entries
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter_map(|p| {
                if seen.insert(p.url.clone()) {
                    Some(p.url.clone())
                } else {
                    None
                }
            })
            .take(n.max(1))
            .collect()
    }

    pub fn clear(&self) {
        self.entries
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        *self.active.write().unwrap_or_else(|e| e.into_inner()) = None;
    }

    pub fn refresh_if_due(&self, interval: i64) -> bool {
        if self.refreshing.load(Ordering::Relaxed) {
            return false;
        }
        let last = self.last_refresh.load(Ordering::Relaxed);
        crate::store::now() - last >= interval
    }

    pub async fn refresh(&self) -> Result<usize> {
        if self.refreshing.swap(true, Ordering::SeqCst) {
            bail!("proxy refresh already running");
        }
        let mut candidates = match self.fetch_lists().await {
            Ok(c) => c,
            Err(e) => {
                self.refreshing.store(false, Ordering::Relaxed);
                return Err(e);
            }
        };
        info!(
            "proxy pool: {} candidates from {} lists",
            candidates.len(),
            LISTS.len()
        );

        candidates.extend(owned_proxies());
        let sem = Arc::new(Semaphore::new(CHECK_CONCURRENCY));
        let futs = candidates.into_iter().map(|(url, kind)| {
            let sem = sem.clone();
            async move {
                let _permit = sem.acquire_owned().await.ok()?;
                check_one(&url, &kind).await
            }
        });
        let mut working: Vec<ProxyEntry> = futures::stream::iter(futs)
            .buffer_unordered(CHECK_CONCURRENCY)
            .filter_map(|x| async move { x })
            .collect()
            .await;
        working.sort_by_key(|p| p.latency_ms);
        working.dedup_by(|a, b| a.url == b.url);
        let owned_urls: Vec<String> = owned_proxies().into_iter().map(|(u, _)| u).collect();
        working.sort_by_key(|p| if owned_urls.iter().any(|u| u == &p.url) { 0 } else { 1 });

        if working.is_empty() {
            warn!("proxy refresh found no working exits; keeping previous pool");
            self.refreshing.store(false, Ordering::Relaxed);
            return Ok(0);
        }
        let best = working.first().cloned();
        let count = working.len();
        save_cache(&working);
        *self.entries.write().unwrap_or_else(|e| e.into_inner()) = working;
        *self.active.write().unwrap_or_else(|e| e.into_inner()) =
            best.as_ref().map(|p| p.url.clone());
        self.last_refresh
            .store(crate::store::now(), Ordering::Relaxed);
        self.refreshing.store(false, Ordering::Relaxed);
        info!(
            "proxy pool: {} working{}",
            count,
            best.map(|p| format!(", best {} ({}ms)", p.url, p.latency_ms))
                .unwrap_or_default()
        );
        Ok(count)
    }

    async fn fetch_lists(&self) -> Result<Vec<(String, String)>> {
        let lists: Vec<(String, String)> = LISTS
            .iter()
            .map(|(kind, url)| (kind.to_string(), url.to_string()))
            .collect();
        let futs = lists.into_iter().map(|(kind, url)| {
            let http = self.http.clone();
            async move {
                let r = http.get(&url).send().await?;
                let status = r.status();
                let text = r.text().await.unwrap_or_default();
                if !status.is_success() {
                    bail!("HTTP {} {}", status.as_u16(), url);
                }
                Ok::<_, anyhow::Error>(parse_list(&text, &kind))
            }
        });
        let results: Vec<Result<Vec<(String, String)>>> = futures::stream::iter(futs)
            .buffer_unordered(32)
            .collect()
            .await;
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        for r in results {
            match r {
                Ok(mut items) => {
                    items.shuffle(&mut rand::thread_rng());
                    items.truncate(150);
                    for (url, kind) in items {
                        if seen.insert(url.clone()) {
                            out.push((url, kind));
                        }
                    }
                }
                Err(e) => warn!("proxy list: {e}"),
            }
        }
        out.shuffle(&mut rand::thread_rng());
        out.truncate(MAX_CANDIDATES);
        if out.is_empty() {
            bail!("no proxy candidates");
        }
        Ok(out)
    }
}

/// Operator-pinned exits that survive every pool refresh (one URL per line,
/// '#' comments allowed). Override the path with PROXY_OWNED.
fn owned_proxies() -> Vec<(String, String)> {
    let path =
        std::env::var("PROXY_OWNED").unwrap_or_else(|_| "data/owned_proxies.txt".into());
    match std::fs::read_to_string(&path) {
        Ok(text) => text
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(|l| {
                let kind = if l.starts_with("socks5") { "socks5" } else { "http" };
                (l.to_string(), kind.to_string())
            })
            .collect(),
        Err(_) => Vec::new(),
    }
}

fn cache_path() -> PathBuf {
    PathBuf::from(std::env::var("PROXY_CACHE").unwrap_or_else(|_| "data/proxies.json".into()))
}

fn load_cache() -> (Vec<ProxyEntry>, i64) {
    let path = cache_path();
    let Ok(text) = std::fs::read_to_string(&path) else {
        return (Vec::new(), 0);
    };
    let Ok(entries) = serde_json::from_str::<Vec<ProxyEntry>>(&text) else {
        return (Vec::new(), 0);
    };
    // Cache is a head start, not a permanent allow-list. Preserve the real
    // file mtime so a stale cache does not masquerade as freshly checked.
    let last = std::fs::metadata(&path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    (entries, last)
}

fn save_cache(entries: &[ProxyEntry]) {
    let path = cache_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(text) = serde_json::to_string(entries) {
        let tmp = path.with_extension("json.tmp");
        if std::fs::write(&tmp, text).is_ok() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
            }
            let _ = std::fs::rename(tmp, path);
        }
    }
}

fn parse_list(text: &str, kind: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for line in text.lines() {
        if let Some(v) = parse_line(line, kind) {
            out.push(v);
        }
    }
    out
}

fn parse_line(line: &str, kind: &str) -> Option<(String, String)> {
    let s = line.trim();
    if s.is_empty() || s.starts_with('#') || s.len() > 120 {
        return None;
    }
    let core = s.split_whitespace().next().unwrap_or(s);
    for (prefix, out_scheme) in [
        ("http://", "http"),
        ("https://", "http"),
        ("socks5://", "socks5"),
        ("socks4://", "socks5"),
    ] {
        if let Some(rest) = core.strip_prefix(prefix) {
            let hp = hostport_of(rest);
            if valid_hostport(&hp) {
                return Some((format!("{out_scheme}://{hp}"), out_scheme.into()));
            }
            return None;
        }
    }
    // hideip.me uses ip:port:Country; keep only the host:port part.
    let hp = hostport_of(core);
    if !valid_hostport(&hp) {
        return None;
    }
    let scheme = if kind == "socks5" { "socks5" } else { "http" };
    Some((format!("{scheme}://{hp}"), kind.to_string()))
}

fn hostport_of(s: &str) -> String {
    if !s.starts_with('[') && s.matches(':').count() > 1 {
        s.splitn(3, ':').take(2).collect::<Vec<_>>().join(":")
    } else {
        s.to_string()
    }
}

fn valid_hostport(s: &str) -> bool {
    static RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    let Some((host, port)) = s.rsplit_once(':') else {
        return false;
    };
    if host.is_empty() || port.is_empty() || port.len() > 5 {
        return false;
    }
    let Ok(p) = port.parse::<u16>() else {
        return false;
    };
    if p < 1 {
        return false;
    }
    let re = RE.get_or_init(|| Regex::new(r"^[A-Za-z0-9.\-\[\]:]+$").unwrap());
    re.is_match(host)
}

async fn check_one(url: &str, kind: &str) -> Option<ProxyEntry> {
    let proxy = reqwest::Proxy::all(url).ok()?;
    let client = reqwest::Client::builder()
        .proxy(proxy)
        .user_agent(UA)
        .timeout(Duration::from_secs(CHECK_TIMEOUT))
        .gzip(false)
        .brotli(false)
        .build()
        .ok()?;
    let started = Instant::now();
    let r = client
        .get("https://api.ipify.org?format=json")
        .send()
        .await
        .ok()?;
    if !r.status().is_success() {
        return None;
    }
    let body = r.text().await.ok()?;
    if !body.contains("\"ip\"") {
        return None;
    }
    Some(ProxyEntry {
        url: url.to_string(),
        kind: kind.to_string(),
        latency_ms: started.elapsed().as_millis() as u64,
    })
}

pub async fn run(app: Arc<App>, pool: Arc<ProxyPool>) {
    info!("proxy manager started");
    let mut applied: Option<(Option<String>, String)> = None;
    loop {
        let manual = app.store.setting("proxy", "");
        let auto = app.store.setting_i64("auto_proxy", 1) == 1;
        if auto && manual.trim().is_empty() {
            let interval = app.store.setting_i64("proxy_refresh", 300).max(60);
            if pool.refresh_if_due(interval) {
                if let Err(e) = pool.refresh().await {
                    warn!("proxy refresh: {e}");
                }
            }
            let best = pool.best();
            let scope = app.store.setting("proxy_scope", "sources");
            if scope == "sources" {
                let urls = pool.urls(12);
                let key = urls.join(",");
                let current = (Some(key.clone()), scope.clone());
                if applied.as_ref() != Some(&current) {
                    if let Err(e) = app.set_source_proxies(urls) {
                        warn!("apply source proxies: {e}");
                    } else {
                        info!(
                            "source proxies applied: {} rotating exit IPs",
                            key.matches(',').count() + 1
                        );
                        applied = Some(current);
                    }
                }
            } else {
                let current = (best.clone(), scope.clone());
                if applied.as_ref() != Some(&current) {
                    if let Err(e) = app.set_scoped_proxy(best.clone(), &scope) {
                        warn!("apply proxy: {e}");
                    } else {
                        info!(
                            "proxy applied: {} ({})",
                            best.as_deref().unwrap_or("direct"),
                            scope
                        );
                        applied = Some(current);
                    }
                }
            }
        } else if applied.is_some() {
            // Manual proxy (or auto off) owns the clients now. If there is
            // no manual proxy, drop the auto one and return to direct.
            if manual.trim().is_empty() {
                let _ = app.set_scoped_proxy(None, "probe");
                let _ = app.set_source_proxies(Vec::new());
            }
            applied = None;
        }
        tokio::time::sleep(Duration::from_secs(20)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_proxy_lines() {
        assert_eq!(
            parse_line("1.2.3.4:8080", "http").unwrap().0,
            "http://1.2.3.4:8080"
        );
        assert_eq!(
            parse_line("socks5://5.6.7.8:1080", "socks5").unwrap().0,
            "socks5://5.6.7.8:1080"
        );
        assert!(parse_line("not a proxy", "http").is_none());
    }

    #[test]
    fn list_parser_keeps_both_protocols() {
        let v = parse_list("1.2.3.4:80\n5.6.7.8:1080\n", "socks5");
        assert_eq!(v.len(), 2);
        assert!(v[0].0.starts_with("socks5://"));
    }
}
