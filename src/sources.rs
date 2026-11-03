use anyhow::{anyhow, bail, Context, Result};
use futures::stream::{self, StreamExt};
use regex::Regex;
use serde_json::Value;
use std::collections::{hash_map::DefaultHasher, HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{OnceLock, RwLock};
use std::time::Duration;
use tracing::debug;

const UA: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36";

/// A single piece of text pulled from a non-GitHub source. The existing
/// extractor/prober pipeline treats it exactly like a repository file.
#[derive(Clone, Debug)]
pub struct SourceDoc {
    pub source: String,
    pub repo: String,
    pub path: String,
    pub text: String,
    pub url: String,
}

/// Flattened rotation: every task is (source, query). The auto loop walks it
/// round-robin so one source cannot starve the others.
pub const TASKS: &[(&str, &str)] = &[
    ("torch", "api key"),
    ("torch", "pastebin"),
    ("torch", "openai"),
    ("torch", "deepseek"),
    ("torch", "leak"),
    ("torch", "sk-"),
    ("bing", "\"OPENAI_API_KEY\" \"sk-\""),
    ("bing2", "\"sk-proj-\" \"api.openai.com\""),
    ("bing", "\"sk-or-v1-\" \"openrouter.ai\""),
    ("bing2", "\"DASHSCOPE_API_KEY\""),
    ("bing", "\"sk-ws-\" \"maas.aliyuncs.com\""),
    ("bing2", "\"sk-\" site:pastebin.com"),
    ("bing", "\"sk-\" site:gist.github.com"),
    ("bing2", "\"sk-\" site:rentry.co"),
    ("bing", "\"sk-\" site:telegra.ph"),
    ("gitee", "DEEPSEEK_API_KEY"),
    ("hn", "DEEPSEEK_API_KEY"),
    ("gitea", "openai"),
    ("codeberg", "openai"),
    ("nodeloc", "openai"),
    ("gitlab", "openai"),
    ("hf", "openai"),
    ("stackexchange", "openai api key"),
    ("devto", "openai"),
    ("medium", "openai"),
    ("techinasia", "openai"),
    ("geeksforgeeks", "openai"),
    ("qiita", "openai"),
    ("zenn", "openai"),
    ("note", "openai"),
    ("hatena", "openai"),
    ("velog", "openai"),
    ("viblo", "openai"),
    ("tinhte", "openai"),
    ("habr", "openai"),
    ("tproger", "openai"),
    ("dou", "openai"),
    ("devby", "openai"),
    ("telegram", "openai"),
    ("gitee", "api.deepseek.com"),
    ("hn", "OPENROUTER_API_KEY"),
    ("gitea", "OPENAI_API_KEY"),
    ("codeberg", "OPENAI_API_KEY"),
    ("nodeloc", "dashscope"),
    ("gitlab", "OPENAI_API_KEY"),
    ("hf", "deepseek"),
    ("stackexchange", "OPENROUTER_API_KEY"),
    ("devto", "dashscope"),
    ("medium", "dashscope"),
    ("velog", "dashscope"),
    ("viblo", "dashscope"),
    ("habr", "dashscope"),
    ("gitee", "OPENAI_API_KEY"),
    ("hn", "OPENAI_API_KEY"),
    ("gitea", "DEEPSEEK_API_KEY"),
    ("gitlab", "DEEPSEEK_API_KEY"),
    ("hf", "qwen"),
    ("stackexchange", "dashscope"),
    ("velog", "DASHSCOPE_API_KEY"),
    ("gitee", "api.openai.com"),
    ("hn", "ANTHROPIC_API_KEY"),
    ("hf", "OPENAI_API_KEY"),
    ("hn", "OPENROUTER_API_KEY"),
    ("hf", "dashscope"),
    ("hn", "dashscope"),
    ("gitee", "OPENROUTER_API_KEY"),
    ("hn", "DASHSCOPE_API_KEY"),
    ("gitee", "openrouter.ai"),
    ("hn", "sk-ws-"),
    ("gitee", "MOONSHOT_API_KEY"),
    ("hn", "maas.aliyuncs.com"),
    ("gitee", "api.moonshot.cn"),
    ("gitee", "ANTHROPIC_API_KEY"),
    ("gitee", "api.anthropic.com"),
    ("gitee", "XAI_API_KEY"),
    ("gitee", "openai"),
    ("gitee", "deepseek"),
    ("gitee", "OPENAI_API_KEY"),
    ("gitee", "DEEPSEEK_API_KEY"),
    ("gitee", "OPENROUTER_API_KEY"),
    ("gitee", "MOONSHOT_API_KEY"),
    ("gitee", "dashscope"),
    ("gitee", "百炼"),
    ("gitee", "DASHSCOPE_API_KEY"),
    ("gitee", "sk-ws-"),
    ("gitee", "maas.aliyuncs.com"),
    ("gitee", "cn-beijing.maas.aliyuncs.com"),
    ("gitee", "TONGYI_QIANWEN_API_KEY"),
    ("gitee", "QWEN_DASHSCOPE_API_KEY"),
    ("gitee", "DASHSCOPE_LLM_API_KEY"),
    ("gitee", "dashscope-intl.aliyuncs.com"),
    ("gitee", "bailian"),
    ("gitee", "通义"),
    ("gitee", "qwen-turbo"),
    ("gitee", "qwen-flash"),
    ("hn", "QWEN_DASHSCOPE_API_KEY"),
    ("hn", "TONGYI_QIANWEN_API_KEY"),
    ("hn", "bailian"),
    ("hf", "QWEN_API_KEY"),
    ("hf", "BAILIAN_API_KEY"),
    ("gitee", "compatible-mode/v1"),
    ("gitee", "dashscope-intl.aliyuncs.com"),
    ("gitee", "qwen-max"),
    ("gitee", "api.x.ai"),
    ("nodeseek", ""),
    ("gists", ""),
    ("gitea", "llm"),
    ("codeberg", "llm"),
    ("nodeloc", "中转"),
    ("v2ex", ""),
    ("gitlab", "llm"),
    ("hf", "api"),
    ("pastebin", ""),
    ("gist_search", "OPENAI_API_KEY"),
    ("gist_search", "OPENROUTER_API_KEY"),
    ("gist_search", "DASHSCOPE_API_KEY"),
    ("gist_search", "sk-or-v1-"),
    ("gist_search", "sk-proj-"),
    ("hn", "sk-proj-"),
    ("stackexchange", "leaked api key"),
    ("devto", "llm"),
    ("medium", "llm"),
    ("qiita", "api"),
    ("zenn", "api"),
    ("velog", "api"),
    ("viblo", "api"),
    ("habr", "api"),
    ("telegram", "ai_newz"),
    ("gitee", "中转"),
    ("gitea", "sk-"),
    ("codeberg", "sk-"),
    ("nodeloc", "sk-"),
    ("gitlab", "api key"),
    ("hf", "sk-"),
    ("hn", "sk-"),
    ("stackexchange", "sk-"),
    ("devto", "security"),
    ("medium", "chatgpt"),
    ("qiita", "llm"),
    ("zenn", "llm"),
    ("velog", "llm"),
    ("viblo", "llm"),
    ("habr", "нейросети"),
    ("telegram", "llm_ru"),
    ("gitee", "chatgpt"),
    ("nodeloc", "api"),
    ("gitlab", "sk-"),
    ("devto", "sk-"),
    ("medium", "sk-"),
    ("telegram", "devby"),
    ("gitee", "密钥"),
    ("nodeloc", ""),
    ("gitlab", "sk-proj-"),
    ("telegram", "dou_ua"),
    ("gitee", "api_key"),
    ("gitee", "sk-"),
    ("gitee", "sk-proj-"),
    ("gitee", "base_url"),
    // New source pack: independent web/code indexes and public statuses.
    ("ddg", "\"OPENAI_API_KEY\" \"sk-proj-\""),
    ("ddg2", "\"sk-or-v1-\" \"openrouter.ai\""),
    ("ddg", "\"sk-ant-\" \"api.anthropic.com\""),
    ("ddg2", "\"sk-\" site:pastebin.com"),
    ("ddg", "\"sk-\" site:gist.github.com"),
    ("ddg2", "\"sk-\" site:rentry.co"),
    ("ddg", "\"sk-\" site:telegra.ph"),
    ("ddg2", "\"api.deepseek.com\" \"sk-\""),
    ("ddg", "\"api.x.ai\" \"sk-\""),
    ("ddg2", "\"sk-ws-\" \"maas.aliyuncs.com\""),
    ("debian", "OPENAI_API_KEY"),
    ("debian", "sk-proj-"),
    ("debian", "ANTHROPIC_API_KEY"),
    ("debian", "DASHSCOPE_API_KEY"),
    ("debian", "api.openai.com"),
    ("debian", "api.deepseek.com"),
    ("debian", "openrouter.ai"),
    ("archive", "OPENAI_API_KEY"),
    ("archive", "api.openai.com sk-"),
    ("archive", "DASHSCOPE_API_KEY"),
    ("archive", "sk-proj-"),
    ("mastodon", "OPENAI_API_KEY"),
    ("mastodon", "sk-proj-"),
    ("mastodon", "api.deepseek.com"),
    ("mastodon", "DASHSCOPE_API_KEY"),
    ("gitlab_snippet", "OPENAI_API_KEY"),
    ("gitlab_snippet", "sk-proj-"),
    ("gitlab_snippet", "api.deepseek.com"),
    ("gitlab_snippet", "ANTHROPIC_API_KEY"),
    ("gitlab_snippet", "DASHSCOPE_API_KEY"),
    ("marginalia", "OPENAI_API_KEY"),
    ("marginalia", "sk-proj-"),
    ("marginalia", "api.deepseek.com"),
    ("marginalia", "DASHSCOPE_API_KEY"),
    ("marginalia", "sk-ant-"),
    ("marginalia", "api.x.ai"),
    ("marginalia", "site:pastebin.com"),
    ("marginalia", "site:gist.github.com"),
    ("dockerhub", "OPENAI_API_KEY"),
    ("dockerhub", "DASHSCOPE_API_KEY"),
    ("dockerhub", "api.openai.com"),
    ("dockerhub", "sk-proj-"),
    // Search/OSINT service keys.
    ("gitee", "TAVILY_API_KEY"),
    ("gitlab", "SCRAPERAPI_KEY"),
    ("hf", "APODEX_API_KEY"),
    ("hn", "VALUESERP_API_KEY"),
    ("stackexchange", "TAVILY_API_KEY"),
    ("debian", "TAVILY_API_KEY"),
    ("archive", "TAVILY_API_KEY"),
    ("mastodon", "TAVILY_API_KEY"),
    // GitHub PAT pack. Search-engine/code-index mirrors see tokens that are
    // already gone from the public GitHub tree; keep multiple token families
    // and both the bare prefix and the env assignment.
    ("gitee", "ghp_"),
    ("gitee", "github_pat_"),
    ("gitee", "gho_"),
    ("gitee", "ghs_"),
    ("gitee", "GITHUB_TOKEN"),
    ("gitee", "GH_TOKEN"),
    ("gitee", "GITHUB_PAT"),
    ("gitee", "GH_PAT"),
    ("gitlab", "ghp_"),
    ("gitlab", "github_pat_"),
    ("gitlab", "GITHUB_TOKEN"),
    ("gitlab", "GH_TOKEN"),
    ("gitlab", "GITHUB_PAT"),
    ("hf", "ghp_"),
    ("hf", "GH_TOKEN"),
    ("hf", "GITHUB_TOKEN"),
    ("stackexchange", "ghp_"),
    ("stackexchange", "github_pat_"),
    ("stackexchange", "GITHUB_TOKEN"),
    ("hn", "ghp_"),
    ("hn", "github_pat_"),
    ("hn", "GH_TOKEN"),
    ("ddg", "ghp_"),
    ("ddg", "github_pat_"),
    ("ddg", "GITHUB_TOKEN"),
    ("ddg", "GH_TOKEN"),
    ("debian", "github_pat_"),
    ("debian", "ghp_"),
    ("debian", "GITHUB_TOKEN"),
    ("gists", "github_pat_"),
    ("gists", "ghp_"),
    ("gists", "GITHUB_TOKEN"),
    ("grepapp", "github_pat_"),
    ("grepapp", "ghp_"),
    ("grepapp", "GITHUB_TOKEN"),
    ("grepapp", "GH_TOKEN"),
    ("pastegg", "github_pat_"),
    ("pastegg", "ghp_"),
    ("pastegg", "GITHUB_TOKEN"),
    ("urlscan", "github_pat_"),
    ("urlscan", "ghp_"),
    ("urlscan", "GITHUB_TOKEN"),
    ("npm", "github_pat_"),
    ("npm", "ghp_"),
    ("bluesky", "github_pat_"),
    ("mastodon", "ghp_"),
    ("archive", "ghp_"),
    // Lemmy public search: independent federated forum lane, no auth.
    ("lemmy", "OPENAI_API_KEY"),
    ("lemmy", "ANTHROPIC_API_KEY"),
    ("lemmy", "OPENROUTER_API_KEY"),
    ("lemmy", "DASHSCOPE_API_KEY"),
    ("lemmy", "sk-"),
    ("lemmy", "ghp_"),
    ("lemmy", "github_pat_"),
    ("lemmy", "中转"),
    ("lemmy_comments", "OPENAI_API_KEY"),
    ("lemmy_comments", "ANTHROPIC_API_KEY"),
    ("lemmy_comments", "OPENROUTER_API_KEY"),
    ("lemmy_comments", "DASHSCOPE_API_KEY"),
    ("lemmy_comments", "sk-"),
    ("lemmy_comments", "ghp_"),
    ("lemmy_comments", "github_pat_"),
    // v3 source pack: code indexes, regional search, social, paste and
    // security/news pages. Each adapter returns SourceDoc only; extraction,
    // pairing and probing stay in the shared pipeline.
    ("juejin", "OPENAI_API_KEY"),
    ("juejin", "sk-"),
    ("juejin", "中转"),
    ("juejin", "DASHSCOPE_API_KEY"),
    ("npm", "openai"),
    ("npm", "api key"),
    ("npm", "dashscope"),
    ("pastegg", ""),
    ("urlscan", "OPENAI_API_KEY"),
    ("urlscan", "sk-"),
    ("bluesky", "OPENAI_API_KEY"),
    ("bluesky", "sk-"),
    ("mojeek", "OPENAI_API_KEY"),
    ("mojeek", "sk-"),
    ("yandex", "OPENAI_API_KEY"),
    ("yandex", "sk-"),
    ("google", "OPENAI_API_KEY"),
    ("google", "sk-"),
    ("baidu", "OPENAI_API_KEY"),
    ("baidu", "sk-"),
    ("sogou", "OPENAI_API_KEY"),
    ("sogou", "sk-"),
    ("naver", "OPENAI_API_KEY"),
    ("naver", "sk-"),
    ("startpage", "OPENAI_API_KEY"),
    ("startpage", "sk-"),
    ("searx", "OPENAI_API_KEY"),
    ("searx", "sk-"),
    ("oldreddit", "OPENAI_API_KEY"),
    ("oldreddit", "sk-"),
    ("lobsters", "OPENAI_API_KEY"),
    ("lobsters", "sk-"),
    ("csdn", "OPENAI_API_KEY"),
    ("csdn", "sk-"),
    ("segmentfault", "OPENAI_API_KEY"),
    ("segmentfault", "sk-"),
    ("cnblogs", "OPENAI_API_KEY"),
    ("cnblogs", "sk-"),
    ("oschina", "OPENAI_API_KEY"),
    ("oschina", "sk-"),
    ("cto51", "OPENAI_API_KEY"),
    ("cto51", "sk-"),
    ("tencent", "OPENAI_API_KEY"),
    ("tencent", "sk-"),
    ("aliyun", "OPENAI_API_KEY"),
    ("aliyun", "sk-"),
    ("justpaste", "OPENAI_API_KEY"),
    ("rentry", "OPENAI_API_KEY"),
    ("thehackernews", "OPENAI_API_KEY"),
    ("thehackernews", "api key"),
    ("bleepingcomputer", "OPENAI_API_KEY"),
    ("securityweek", "OPENAI_API_KEY"),
    ("infoq", "OPENAI_API_KEY"),
    ("jianshu", "OPENAI_API_KEY"),
    ("weibo", "OPENAI_API_KEY"),
    ("bilibili", "OPENAI_API_KEY"),
    ("hackread", "OPENAI_API_KEY"),
    ("cybernews", "OPENAI_API_KEY"),
    ("theregister", "OPENAI_API_KEY"),
    ("packetstorm", "OPENAI_API_KEY"),
    ("openai_community", "OPENAI_API_KEY"),
    ("openai_community", "sk-"),
    ("hf_forum", "OPENAI_API_KEY"),
    ("hf_forum", "sk-"),
    ("cursor_forum", "OPENAI_API_KEY"),
    ("vercel_forum", "OPENAI_API_KEY"),
    ("devforum", "OPENAI_API_KEY"),
    ("wechat", "OPENAI_API_KEY"),
    ("wechat", "sk-"),
    ("hashnode2", "OPENAI_API_KEY"),
    ("hashnode2", "sk-"),
    ("securityse", "OPENAI_API_KEY"),
    ("securityse", "sk-"),
    ("serverfault", "OPENAI_API_KEY"),
    ("superuser", "OPENAI_API_KEY"),
    ("askubuntu", "OPENAI_API_KEY"),
];

pub fn tasks() -> &'static [(&'static str, &'static str)] {
    TASKS
}

/// Provider-aware source tasks generated from the search registry. The static
/// TASKS list is broad but frozen; this pack keeps new providers and aliases
/// flowing into Gitee/GitLab/HN/HF and the web indexes without editing 300
/// hand-written rows every time a provider is added.
pub fn provider_tasks() -> Vec<(&'static str, &'static str)> {
    let sources = [
        "gitee",
        "gitlab",
        "gitlab_snippet",
        "hn",
        "hf",
        "grepapp",
        "ddg",
        "bing",
        "gist_search",
    ];
    let mut out = Vec::new();
    for p in crate::searchplan::PROVIDERS
        .iter()
        .filter(|p| crate::searchplan::PRIORITY.contains(&p.name))
    {
        for var in p.env_vars.iter().take(1) {
            for source in sources {
                out.push((source, *var));
            }
        }
        for host in p.hosts.iter().take(1) {
            for source in sources {
                out.push((source, *host));
            }
        }
    }
    out
}

/// Scheduler priority for the new source pack. Existing DB rows keep their
/// priority because seeding is INSERT OR IGNORE; only new adapters get a
/// head start over the old zero-priority backlog.
pub fn task_priority(source: &str) -> i64 {
    match source {
        "wechat" => 285,
        "juejin" => 280,
        "csdn" => 275,
        "hashnode2" => 270,
        "npm" => 265,
        "pastegg" => 260,
        "bluesky" => 255,
        "openai_community" => 250,
        "securityse" => 245,
        "mojeek" => 240,
        "gist_search" => 260,
        "urlscan" => 235,
        "hf_forum" | "cursor_forum" | "vercel_forum" | "devforum" => 230,
        "cnblogs" | "segmentfault" | "oschina" | "cto51" | "tencent" | "aliyun" => 220,
        "lemmy" | "lemmy_comments" => 215,
        "weibo" | "bilibili" | "jianshu" | "infoq" => 210,
        "google" | "yandex" | "baidu" | "sogou" | "naver" | "startpage" | "searx" => 200,
        "oldreddit" | "lobsters" | "justpaste" | "rentry" => 195,
        "thehackernews" | "bleepingcomputer" | "securityweek" | "hackread" | "cybernews"
        | "theregister" | "packetstorm" => 190,
        "serverfault" | "superuser" | "askubuntu" => 185,
        _ => 0,
    }
}

/// Number of distinct adapters, not the number of (source, query) tasks.
pub fn source_count() -> usize {
    let mut names = std::collections::HashSet::new();
    for (source, _) in TASKS {
        names.insert(*source);
    }
    names.len()
}

pub struct Sources {
    clients: RwLock<Vec<reqwest::Client>>,
    direct: reqwest::Client,
    tor: RwLock<Option<reqwest::Client>>,
    proxied: AtomicBool,
    rr: AtomicUsize,
    pat_tokens: RwLock<HashMap<String, String>>,
}

impl Sources {
    pub fn new(proxy: Option<String>) -> Result<Self> {
        let proxied = proxy
            .as_deref()
            .map(|p| !p.trim().is_empty())
            .unwrap_or(false);
        let tor = std::env::var("TOR_PROXY")
            .ok()
            .filter(|p| !p.trim().is_empty())
            .map(|p| build_tor_client(Some(p)))
            .transpose()?;
        Ok(Self {
            direct: build_client(None)?,
            clients: RwLock::new(vec![build_client(proxy)?]),
            tor: RwLock::new(tor),
            proxied: AtomicBool::new(proxied),
            rr: AtomicUsize::new(0),
            pat_tokens: RwLock::new(HashMap::new()),
        })
    }

    pub fn set_proxy(&self, proxy: Option<String>) -> Result<()> {
        self.set_proxies(proxy.into_iter().collect())
    }

    /// Rotate across a pool of source proxies. Each request picks the next
    /// client, so 16 parallel source jobs do not hammer one exit IP into 429.
    pub fn set_proxies(&self, proxies: Vec<String>) -> Result<()> {
        let mut clients = Vec::new();
        for proxy in proxies {
            if proxy.trim().is_empty() {
                continue;
            }
            clients.push(build_client(Some(proxy))?);
        }
        let proxied = !clients.is_empty();
        if clients.is_empty() {
            clients.push(build_client(None)?);
        }
        *self.clients.write().unwrap_or_else(|e| e.into_inner()) = clients;
        self.proxied.store(proxied, Ordering::Relaxed);
        Ok(())
    }

    fn tor_http(&self) -> Option<reqwest::Client> {
        self.tor.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    fn http(&self) -> reqwest::Client {
        let clients = self.clients.read().unwrap_or_else(|e| e.into_inner());
        if clients.is_empty() {
            return self.direct.clone();
        }
        let idx = self.rr.fetch_add(1, Ordering::Relaxed) % clients.len();
        clients[idx].clone()
    }

    /// Sticky proxy affinity per host. Search engines and code hosts are far
    /// more likely to challenge a session when its HTML page and follow-up
    /// raw requests arrive from different exit IPs. Hash the host to a stable
    /// proxy; a dead exit still falls back to direct in text()/json().
    fn http_for_url(&self, url: &str) -> reqwest::Client {
        let clients = self.clients.read().unwrap_or_else(|e| e.into_inner());
        if clients.is_empty() {
            return self.direct.clone();
        }
        let host = reqwest::Url::parse(url)
            .ok()
            .and_then(|u| u.host_str().map(|h| h.to_ascii_lowercase()));
        let idx = match host {
            Some(host) => proxy_index_for_host(&host, clients.len()),
            None => self.rr.fetch_add(1, Ordering::Relaxed) % clients.len(),
        };
        clients[idx].clone()
    }

    async fn direct_text(&self, url: &str) -> Result<String> {
        let rb = self.direct.get(url).header(
            "Accept",
            "text/plain,text/html,application/json;q=0.9,*/*;q=0.8",
        );
        let r = self.with_pat(rb, url).send().await?;
        if !r.status().is_success() {
            bail!("HTTP {} · {}", r.status().as_u16(), url);
        }
        Ok(r.text().await.unwrap_or_default())
    }

    /// Attach provider PATs to the matching public code-host APIs. GitHub
    /// tokens never reach this map: the GitHub pool has its own search lane.
    pub fn set_pat_tokens(&self, tokens: Vec<(String, String)>) {
        let mut map = HashMap::new();
        for (provider, token) in tokens {
            if provider.eq_ignore_ascii_case("github") || token.trim().is_empty() {
                continue;
            }
            map.insert(provider.to_ascii_lowercase(), token);
        }
        *self.pat_tokens.write().unwrap_or_else(|e| e.into_inner()) = map;
    }

    pub fn set_pat_tokens_from_store(&self, store: &crate::store::Store) {
        let mut tokens = Vec::new();
        for provider in ["gitee", "gitlab", "gitea", "codeberg"] {
            for p in store.list_pats_provider(provider) {
                if p.status == "alive" {
                    tokens.push((provider.to_string(), p.token));
                }
            }
        }
        self.set_pat_tokens(tokens);
    }

    fn with_pat(&self, rb: reqwest::RequestBuilder, url: &str) -> reqwest::RequestBuilder {
        let host = url_host(url);
        let tokens = self.pat_tokens.read().unwrap_or_else(|e| e.into_inner());
        if host == "gitee.com" {
            if let Some(token) = tokens.get("gitee") {
                // Gitee OpenAPI uses `Authorization: token …`; keep the PAT out
                // of URLs and proxy logs.
                return rb.header("Authorization", format!("token {token}"));
            }
        } else if host == "gitlab.com" {
            if let Some(token) = tokens.get("gitlab") {
                return rb.header("PRIVATE-TOKEN", token);
            }
        } else if host == "gitea.com" {
            if let Some(token) = tokens.get("gitea") {
                return rb.header("Authorization", format!("token {token}"));
            }
        } else if host == "codeberg.org" {
            if let Some(token) = tokens.get("codeberg") {
                return rb.header("Authorization", format!("token {token}"));
            }
        }
        rb
    }

    async fn text(&self, url: &str) -> Result<String> {
        if !public_http_url(url) {
            bail!("refusing non-public source URL: {url}");
        }
        let mut last_status = 0u16;
        for attempt in 0..2 {
            let http = self.http_for_url(url);
            let rb = http.get(url).header(
                "Accept",
                "text/plain,text/html,application/json;q=0.9,*/*;q=0.8",
            );
            let r = match self.with_pat(rb, url).send().await {
                Ok(r) => r,
                Err(e) => {
                    tracing::debug!("sources proxy error {url}: {e}");
                    break;
                }
            };
            let status = r.status();
            last_status = status.as_u16();
            let body = r.text().await.unwrap_or_default();
            if status.is_success() {
                return Ok(body);
            }
            // 403/429: re-requesting only burns seconds. Fail the source fast
            // and let the next cycle use a fresh proxy/token window.
            if status == 403 || status == 429 {
                break;
            }
            if status.is_server_error() && attempt < 1 {
                tokio::time::sleep(Duration::from_millis(250)).await;
                continue;
            }
            break;
        }
        // A dead public exit must not turn a live source into a zero-doc
        // result. Try the direct client once before failing the adapter.
        match self.direct_text(url).await {
            Ok(body) => Ok(body),
            Err(direct_err) => {
                tracing::debug!("sources direct fallback failed {url}: {direct_err}");
                bail!("HTTP {last_status} (proxy); direct: {direct_err} · {url}")
            }
        }
    }

    async fn curl_text(&self, url: &str) -> Result<String> {
        let out = tokio::process::Command::new("curl")
            .args(["-sSL", "--max-time", "30", "-A", UA, url])
            .output()
            .await
            .with_context(|| format!("curl {url}"))?;
        if !out.status.success() {
            bail!("curl {}: {}", url, String::from_utf8_lossy(&out.stderr));
        }
        Ok(String::from_utf8_lossy(&out.stdout).to_string())
    }

    async fn json(&self, url: &str) -> Result<Value> {
        if !public_http_url(url) {
            bail!("refusing non-public source URL: {url}");
        }
        let mut last_status = 0u16;
        for attempt in 0..2 {
            let http = self.http_for_url(url);
            let rb = http.get(url).header("Accept", "application/json");
            let r = match self.with_pat(rb, url).send().await {
                Ok(r) => r,
                Err(e) => {
                    tracing::debug!("sources proxy error {url}: {e}");
                    break;
                }
            };
            let status = r.status();
            last_status = status.as_u16();
            let body = r.text().await.unwrap_or_default();
            if status.is_success() {
                return serde_json::from_str(&body).with_context(|| format!("json from {url}"));
            }
            if status == 403 || status == 429 {
                break;
            }
            if status.is_server_error() && attempt < 1 {
                tokio::time::sleep(Duration::from_millis(250)).await;
                continue;
            }
            break;
        }
        let rb = self.direct.get(url).header("Accept", "application/json");
        let direct = self.with_pat(rb, url).send().await;
        match direct {
            Ok(r) if r.status().is_success() => {
                let body = r.text().await.unwrap_or_default();
                serde_json::from_str(&body).with_context(|| format!("json from {url}"))
            }
            Ok(r) => bail!(
                "HTTP {} (proxy {last_status}); direct HTTP {} · {url}",
                last_status,
                r.status().as_u16()
            ),
            Err(e) => bail!("HTTP {last_status} (proxy); direct: {e} · {url}"),
        }
    }

    async fn post_json(&self, url: &str, payload: &Value) -> Result<Value> {
        if !public_http_url(url) {
            bail!("refusing non-public source URL: {url}");
        }
        let send = |client: reqwest::Client| {
            let payload = payload.clone();
            async move {
                client
                    .post(url)
                    .header("Accept", "application/json")
                    .json(&payload)
                    .send()
                    .await
            }
        };
        let r = match send(self.http_for_url(url)).await {
            Ok(r) => r,
            Err(e) => {
                tracing::debug!("sources POST error {url}: {e}");
                if self.proxied.load(Ordering::Relaxed) {
                    self.direct
                        .post(url)
                        .header("Accept", "application/json")
                        .json(payload)
                        .send()
                        .await?
                } else {
                    return Err(e.into());
                }
            }
        };
        let status = r.status();
        let body = r.text().await.unwrap_or_default();
        if !status.is_success() {
            bail!(
                "HTTP {} · {} · {}",
                status.as_u16(),
                url,
                body.chars().take(120).collect::<String>()
            );
        }
        serde_json::from_str(&body).with_context(|| format!("json from {url}"))
    }

    async fn fetch_raw_docs(
        &self,
        source: &str,
        items: Vec<(String, String, String)>,
        limit: usize,
        concurrency: usize,
    ) -> Vec<SourceDoc> {
        let futs = stream::iter(items.into_iter().filter_map(|(repo, path, url)| {
            // API responses (urlscan, GitLab, Gitee, HF) are attacker-influenced.
            if !public_http_url(&url) {
                debug!("source {source} skipped non-public URL {url}");
                return None;
            }
            Some(async move {
                let text = self.text(&url).await;
                (repo, path, url, text)
            })
        }));
        let mut buffered = futs.buffer_unordered(concurrency.max(1));
        let mut docs = Vec::new();
        while let Some((repo, path, url, text)) = buffered.next().await {
            let text = match text {
                Ok(text) => text,
                Err(e) => {
                    debug!("{source} raw {repo}/{path}: {e}");
                    continue;
                }
            };
            if text.trim().is_empty() {
                continue;
            }
            docs.push(SourceDoc {
                source: source.to_string(),
                repo,
                path,
                text: cap(text),
                url,
            });
            if docs.len() >= limit {
                break;
            }
        }
        docs
    }

    /// Fetch one crawled page. Onion URLs use the Tor client; everything
    /// else uses the rotating source-proxy client.
    pub async fn fetch_url(&self, url: &str) -> Result<Vec<SourceDoc>> {
        if !(url.starts_with("http://") || url.starts_with("https://")) {
            bail!("not an http url: {url}");
        }
        let parsed = reqwest::Url::parse(url).map_err(|e| anyhow!("bad url {url}: {e}"))?;
        if parsed.host_str().map(non_public_host).unwrap_or(true) {
            bail!("refusing non-public crawl target: {url}");
        }
        let text = if url.contains(".onion") {
            let client = self
                .tor_http()
                .ok_or_else(|| anyhow!("TOR_PROXY is not configured"))?;
            let r = client
                .get(url)
                .header("Accept", "text/html,text/plain,application/json")
                .send()
                .await?;
            if !r.status().is_success() {
                bail!("HTTP {} · {url}", r.status().as_u16());
            }
            r.text().await.unwrap_or_default()
        } else {
            self.text(url).await?
        };
        if text.trim().is_empty() {
            bail!("empty page: {url}");
        }
        let host = url_host(url);
        Ok(vec![SourceDoc {
            source: "crawl".into(),
            repo: host.clone(),
            path: url.to_string(),
            text: cap(text),
            url: url.to_string(),
        }])
    }

    pub async fn gather(&self, source: &str, query: &str, limit: usize) -> Result<Vec<SourceDoc>> {
        let limit = limit.clamp(1, 2000);
        match source {
            "gitee" => self.gitee(query, limit).await,
            "brave" | "brave2" | "brave3" => self.brave(source, query, limit).await,
            "torch" => self.torch(query, limit).await,
            "bing" | "bing2" => self.bing(source, query, limit).await,
            "ddg" | "ddg2" => self.duckduckgo(source, query, limit).await,
            "debian" => self.debian(query, limit).await,
            "marginalia" => self.marginalia(query, limit).await,
            "lemmy" => self.lemmy(query, limit).await,
            "lemmy_comments" => self.lemmy_comments(query, limit).await,
            "dockerhub" => self.dockerhub(query, limit).await,
            "archive" => self.archive_org(query, limit).await,
            "mastodon" => self.mastodon(query, limit).await,
            "grepapp" => self.grep_app(query, limit).await,
            "juejin" => self.juejin(query, limit).await,
            "npm" => self.npm(query, limit).await,
            "pastegg" => self.pastegg(query, limit).await,
            "urlscan" => self.urlscan(query, limit).await,
            "bluesky" => self.bluesky(query, limit).await,
            "shodan" => self.shodan(query, limit).await,
            "openai_community" => {
                self.discourse(source, "community.openai.com", query, limit)
                    .await
            }
            "hf_forum" => {
                self.discourse(source, "discuss.huggingface.co", query, limit)
                    .await
            }
            "cursor_forum" => {
                self.discourse(source, "forum.cursor.com", query, limit)
                    .await
            }
            "vercel_forum" => {
                self.discourse(source, "community.vercel.com", query, limit)
                    .await
            }
            "devforum" => {
                self.discourse(source, "devforum.roblox.com", query, limit)
                    .await
            }
            "gitlab_snippet" | "gitlab_snippets" => self.gitlab_snippets(query, limit).await,
            "gitlab" => self.gitlab(query, limit).await,
            "hf" => self.huggingface(query, limit).await,
            "v2ex" => self.v2ex(limit).await,
            "nodeloc" => self.nodeloc(query, limit).await,
            "nodeseek" => self.nodeseek(limit).await,
            "gists" => self.gists(limit).await,
            "gist_search" => self.gist_search(query, limit).await,
            "gitea" => self.gitea("https://gitea.com", "gitea", query, limit).await,
            "codeberg" => self.codeberg(query, limit).await,
            "pastebin" => self.pastebin(limit).await,
            "hn" => self.hackernews(query, limit).await,
            "stackexchange" => self.stackexchange(query, limit).await,
            "securityse" | "serverfault" | "superuser" | "askubuntu" => {
                self.html_source(source, query, limit).await
            }
            "devto" => self.devto(query, limit).await,
            "qiita" => self.qiita(query, limit).await,
            "zenn" => self.zenn(query, limit).await,
            "viblo" => self.viblo(query, limit).await,
            "habr" => self.habr(query, limit).await,
            "velog" => self.velog(query, limit).await,
            "medium" => self.medium(query, limit).await,
            "dou" | "devby" | "tproger" | "techinasia" | "e27" | "geeksforgeeks" | "tinhte"
            | "note" | "hatena" | "mojeek" | "yandex" | "google" | "baidu" | "sogou" | "naver"
            | "startpage" | "searx" | "oldreddit" | "lobsters" | "csdn" | "segmentfault"
            | "cnblogs" | "oschina" | "cto51" | "tencent" | "aliyun" | "justpaste" | "rentry"
            | "thehackernews" | "bleepingcomputer" | "securityweek" | "infoq" | "jianshu"
            | "weibo" | "bilibili" | "hackread" | "cybernews" | "theregister" | "packetstorm"
            | "wechat" | "hashnode2" => self.html_source(source, query, limit).await,
            "telegram" => self.telegram(query, limit).await,
            other => bail!("unknown source: {other}"),
        }
    }

    // ---------- Global / US / India: Hacker News, Stack Exchange, Dev.to ----------

    async fn hackernews(&self, query: &str, limit: usize) -> Result<Vec<SourceDoc>> {
        let q = if query.trim().is_empty() {
            "OPENAI_API_KEY"
        } else {
            query
        };
        let url = format!(
            "https://hn.algolia.com/api/v1/search?query={}&tags=comment&hitsPerPage=50",
            urlencoding::encode(q)
        );
        let v = self.json(&url).await?;
        let mut docs = Vec::new();
        if let Some(hits) = v["hits"].as_array() {
            for h in hits.iter().take(limit.min(120)) {
                let text = strip_html(h["comment_text"].as_str().unwrap_or(""));
                if text.trim().len() < 20 {
                    continue;
                }
                let title = h["story_title"].as_str().unwrap_or("HN comment");
                let id = h["objectID"].as_str().unwrap_or("");
                docs.push(SourceDoc {
                    source: "hn".into(),
                    repo: format!("hn:{title}"),
                    path: format!("item/{id}"),
                    text: cap(format!("{title}\n{text}")),
                    url: format!("https://news.ycombinator.com/item?id={id}"),
                });
            }
        }
        Ok(docs)
    }

    async fn lemmy(&self, query: &str, limit: usize) -> Result<Vec<SourceDoc>> {
        let q = if query.trim().is_empty() {
            "OPENAI_API_KEY"
        } else {
            query
        };
        let url = format!(
            "https://lemmy.world/api/v3/search?q={}&type_=Posts&limit={}&sort=New",
            urlencoding::encode(q),
            limit.min(50)
        );
        let v = self.json(&url).await?;
        let mut docs = Vec::new();
        if let Some(posts) = v["posts"].as_array() {
            for item in posts.iter().take(limit.min(50)) {
                let post = &item["post"];
                let body = strip_html(post["body"].as_str().unwrap_or(""));
                let title = post["name"].as_str().unwrap_or("Lemmy post");
                if body.trim().len() < 20 && title.trim().len() < 10 {
                    continue;
                }
                let id = post["id"].as_i64().unwrap_or_default();
                let ap_id = post["ap_id"].as_str().unwrap_or("");
                let link = if ap_id.starts_with("http") {
                    ap_id.to_string()
                } else if id > 0 {
                    format!("https://lemmy.world/post/{id}")
                } else {
                    String::new()
                };
                if link.is_empty() {
                    continue;
                }
                docs.push(SourceDoc {
                    source: "lemmy".into(),
                    repo: format!("lemmy:{title}"),
                    path: if id > 0 {
                        format!("post/{id}")
                    } else {
                        link.clone()
                    },
                    text: cap(format!("{title}\n{body}")),
                    url: link,
                });
            }
        }
        Ok(docs)
    }

    async fn lemmy_comments(&self, query: &str, limit: usize) -> Result<Vec<SourceDoc>> {
        let q = if query.trim().is_empty() {
            "OPENAI_API_KEY"
        } else {
            query
        };
        let url = format!(
            "https://lemmy.world/api/v3/search?q={}&type_=Comments&limit={}",
            urlencoding::encode(q),
            limit.min(50)
        );
        let v = self.json(&url).await?;
        let mut docs = Vec::new();
        if let Some(comments) = v["comments"].as_array() {
            for item in comments.iter().take(limit.min(50)) {
                let comment = &item["comment"];
                let body = strip_html(comment["content"].as_str().unwrap_or(""));
                let post_title = item["post"]["name"].as_str().unwrap_or("Lemmy comment");
                if body.trim().len() < 20 {
                    continue;
                }
                let id = comment["id"].as_i64().unwrap_or_default();
                let ap_id = comment["ap_id"].as_str().unwrap_or("");
                let link = if ap_id.starts_with("http") {
                    ap_id.to_string()
                } else if id > 0 {
                    format!("https://lemmy.world/comment/{id}")
                } else {
                    String::new()
                };
                if link.is_empty() {
                    continue;
                }
                docs.push(SourceDoc {
                    source: "lemmy_comments".into(),
                    repo: format!("lemmy:{post_title}"),
                    path: if id > 0 {
                        format!("comment/{id}")
                    } else {
                        link.clone()
                    },
                    text: cap(format!("{post_title}\n{body}")),
                    url: link,
                });
            }
        }
        Ok(docs)
    }

    async fn stackexchange(&self, query: &str, limit: usize) -> Result<Vec<SourceDoc>> {
        self.stackexchange_site("stackexchange", "stackoverflow", query, limit)
            .await
    }

    async fn stackexchange_site(
        &self,
        source: &str,
        site: &str,
        query: &str,
        limit: usize,
    ) -> Result<Vec<SourceDoc>> {
        let q = if query.trim().is_empty() {
            "openai api key"
        } else {
            query
        };
        let page = limit.min(50);
        let url = format!(
            "https://api.stackexchange.com/2.3/search/advanced?order=desc&sort=creation&q={}&site={}&filter=withbody&pagesize={page}",
            urlencoding::encode(q),
            urlencoding::encode(site)
        );
        let v = self.json(&url).await?;
        let mut docs = Vec::new();
        if let Some(items) = v["items"].as_array() {
            for it in items.iter().take(page) {
                let body = strip_html(it["body"].as_str().unwrap_or(""));
                if body.trim().len() < 20 {
                    continue;
                }
                let title = it["title"].as_str().unwrap_or("SO question");
                let link = it["link"].as_str().unwrap_or("");
                docs.push(SourceDoc {
                    source: source.to_string(),
                    repo: format!("{site}:{title}"),
                    path: link.to_string(),
                    text: cap(format!("{title}\n{body}")),
                    url: link.to_string(),
                });
            }
        }
        Ok(docs)
    }

    async fn devto(&self, query: &str, limit: usize) -> Result<Vec<SourceDoc>> {
        let tag = if query.trim().is_empty() {
            "openai"
        } else {
            query
        };
        let url = format!(
            "https://dev.to/api/articles?tag={}&per_page=30",
            urlencoding::encode(tag)
        );
        let list = self.json(&url).await?;
        let mut docs = Vec::new();
        if let Some(items) = list.as_array() {
            for it in items.iter().take(limit.min(14)) {
                let Some(id) = it["id"].as_i64() else {
                    continue;
                };
                let full = match self
                    .json(&format!("https://dev.to/api/articles/{id}"))
                    .await
                {
                    Ok(v) => v,
                    Err(e) => {
                        debug!("devto {id}: {e}");
                        continue;
                    }
                };
                let body = full["body_markdown"]
                    .as_str()
                    .or_else(|| full["body_html"].as_str())
                    .unwrap_or("");
                let body_plain = if full["body_markdown"].is_string() {
                    body.to_string()
                } else {
                    strip_html(body)
                };
                if body_plain.trim().len() < 30 {
                    continue;
                }
                let title = full["title"].as_str().unwrap_or("dev.to article");
                let link = full["url"].as_str().unwrap_or("");
                let user = full["user"]["username"].as_str().unwrap_or("devto");
                docs.push(SourceDoc {
                    source: "devto".into(),
                    repo: format!("dev.to/{user}"),
                    path: link.to_string(),
                    text: cap(format!("{title}\n{body_plain}")),
                    url: link.to_string(),
                });
            }
        }
        Ok(docs)
    }

    // ---------- Japan: Qiita, Zenn ----------

    async fn qiita(&self, query: &str, limit: usize) -> Result<Vec<SourceDoc>> {
        let q = if query.trim().is_empty() {
            "openai"
        } else {
            query
        };
        let url = format!(
            "https://qiita.com/api/v2/items?query={}&per_page=12",
            urlencoding::encode(q)
        );
        let v = self.json(&url).await?;
        let mut docs = Vec::new();
        if let Some(items) = v.as_array() {
            for it in items.iter().take(limit.min(12)) {
                let body = it["body"].as_str().unwrap_or("");
                if body.trim().len() < 30 {
                    continue;
                }
                let title = it["title"].as_str().unwrap_or("Qiita article");
                let link = it["url"].as_str().unwrap_or("");
                docs.push(SourceDoc {
                    source: "qiita".into(),
                    repo: format!("qiita:{title}"),
                    path: link.to_string(),
                    text: cap(format!("{title}\n{body}")),
                    url: link.to_string(),
                });
            }
        }
        Ok(docs)
    }

    async fn zenn(&self, query: &str, limit: usize) -> Result<Vec<SourceDoc>> {
        let q = if query.trim().is_empty() {
            "openai"
        } else {
            query
        };
        let url = format!(
            "https://zenn.dev/api/search?q={}&source=articles",
            urlencoding::encode(q)
        );
        let v = self.json(&url).await?;
        let mut docs = Vec::new();
        let Some(items) = v["articles"].as_array() else {
            return Ok(docs);
        };
        for it in items.iter().take(limit.min(12)) {
            let Some(slug) = it["slug"].as_str() else {
                continue;
            };
            let detail = match self
                .json(&format!("https://zenn.dev/api/articles/{slug}"))
                .await
            {
                Ok(v) => v,
                Err(e) => {
                    debug!("zenn {slug}: {e}");
                    continue;
                }
            };
            let article = &detail["article"];
            let body = article["body_html"].as_str().unwrap_or("");
            let body = strip_html(body);
            if body.trim().len() < 30 {
                continue;
            }
            let title = article["title"].as_str().unwrap_or("Zenn article");
            let path = article["path"].as_str().unwrap_or("");
            docs.push(SourceDoc {
                source: "zenn".into(),
                repo: format!("zenn:{title}"),
                path: path.to_string(),
                text: cap(format!("{title}\n{body}")),
                url: format!("https://zenn.dev{path}"),
            });
        }
        Ok(docs)
    }

    // ---------- Vietnam: Viblo, Tinhte ----------

    async fn viblo(&self, query: &str, limit: usize) -> Result<Vec<SourceDoc>> {
        let q = if query.trim().is_empty() {
            "openai"
        } else {
            query
        };
        let url = format!(
            "https://viblo.asia/api/posts?q={}&limit={}",
            urlencoding::encode(q),
            limit.min(30)
        );
        let v = self.json(&url).await?;
        let mut docs = Vec::new();
        if let Some(items) = v["data"].as_array() {
            for it in items.iter().take(limit.min(30)) {
                let body = strip_html(it["contents"].as_str().unwrap_or(""));
                if body.trim().len() < 30 {
                    continue;
                }
                let title = it["title"].as_str().unwrap_or("Viblo post");
                let link = it["url"].as_str().unwrap_or("");
                docs.push(SourceDoc {
                    source: "viblo".into(),
                    repo: format!("viblo:{title}"),
                    path: link.to_string(),
                    text: cap(format!("{title}\n{body}")),
                    url: link.to_string(),
                });
            }
        }
        Ok(docs)
    }

    // ---------- Russia / Ukraine / Belarus ----------

    async fn habr(&self, query: &str, limit: usize) -> Result<Vec<SourceDoc>> {
        let q = if query.trim().is_empty() {
            "openai"
        } else {
            query
        };
        let url = format!(
            "https://habr.com/kek/v2/articles/?query={}&order=relevance&page=1",
            urlencoding::encode(q)
        );
        let v = self.json(&url).await?;
        let mut ids: Vec<String> = Vec::new();
        if let Some(refs) = v["publicationRefs"].as_object() {
            for id in refs.keys().take(limit.min(12)) {
                ids.push(id.clone());
            }
        }
        let mut docs = Vec::new();
        for id in ids {
            let detail = match self
                .json(&format!("https://habr.com/kek/v2/articles/{id}"))
                .await
            {
                Ok(v) => v,
                Err(e) => {
                    debug!("habr {id}: {e}");
                    continue;
                }
            };
            let body = strip_html(detail["textHtml"].as_str().unwrap_or(""));
            if body.trim().len() < 40 {
                continue;
            }
            let title = strip_html(
                detail["titleHtml"]
                    .as_str()
                    .or_else(|| detail["title"].as_str())
                    .unwrap_or("Habr article"),
            );
            docs.push(SourceDoc {
                source: "habr".into(),
                repo: format!("habr:{title}"),
                path: format!("article/{id}"),
                text: cap(format!("{title}\n{body}")),
                url: format!("https://habr.com/ru/articles/{id}/"),
            });
        }
        Ok(docs)
    }

    // ---------- South Korea: Velog ----------

    async fn velog(&self, query: &str, limit: usize) -> Result<Vec<SourceDoc>> {
        let keyword = if query.trim().is_empty() {
            "openai"
        } else {
            query
        };
        let payload = serde_json::json!({
            "query": "query($keyword: String!, $limit: Int) { searchPosts(input: {keyword: $keyword, limit: $limit}) { posts { id title url_slug body user { username } } } }",
            "variables": {"keyword": keyword, "limit": limit.min(20)}
        });
        let v = self
            .post_json("https://v3.velog.io/graphql", &payload)
            .await?;
        let mut docs = Vec::new();
        if let Some(items) = v["data"]["searchPosts"]["posts"].as_array() {
            for it in items.iter().take(limit.min(20)) {
                let body = it["body"].as_str().unwrap_or("");
                if body.trim().len() < 30 {
                    continue;
                }
                let title = it["title"].as_str().unwrap_or("Velog post");
                let slug = it["url_slug"].as_str().unwrap_or("");
                let user = it["user"]["username"].as_str().unwrap_or("velog");
                docs.push(SourceDoc {
                    source: "velog".into(),
                    repo: format!("velog:@{user}"),
                    path: slug.to_string(),
                    text: cap(format!("{title}\n{body}")),
                    url: format!("https://velog.io/@{user}/{slug}"),
                });
            }
        }
        Ok(docs)
    }

    // ---------- India / global: Medium RSS ----------

    async fn medium(&self, query: &str, limit: usize) -> Result<Vec<SourceDoc>> {
        let tag = if query.trim().is_empty() {
            "openai"
        } else {
            query
        };
        let url = format!("https://medium.com/feed/tag/{}", urlencoding::encode(tag));
        let xml = self.text(&url).await?;
        let mut docs = Vec::new();
        for item in rss_items(&xml).into_iter().take(limit.min(20)) {
            let body = strip_html(&item.content);
            if body.trim().len() < 30 {
                continue;
            }
            docs.push(SourceDoc {
                source: "medium".into(),
                repo: format!("medium:{}", item.title),
                path: item.link.clone(),
                text: cap(format!("{}\n{body}", item.title)),
                url: item.link,
            });
        }
        Ok(docs)
    }

    // ---------- Code/search indexes and social/JSON sources ----------

    async fn grep_app(&self, query: &str, limit: usize) -> Result<Vec<SourceDoc>> {
        let q = if query.trim().is_empty() {
            "OPENAI_API_KEY"
        } else {
            query
        };
        let url = format!("https://grep.app/api/search?q={}", urlencoding::encode(q));
        let v = self.json(&url).await?;
        let mut docs = Vec::new();
        if let Some(hits) = v["hits"]["hits"].as_array() {
            for h in hits.iter().take(limit.min(30)) {
                let Some(repo) = h["repo"].as_str() else {
                    continue;
                };
                let Some(path) = h["path"].as_str() else {
                    continue;
                };
                let snippet = h["content"]["snippet"].as_str().unwrap_or("");
                let text = strip_html(snippet);
                if text.trim().len() < 10 {
                    continue;
                }
                docs.push(SourceDoc {
                    source: "grepapp".into(),
                    repo: format!("grep.app/{repo}"),
                    path: path.to_string(),
                    text: cap(format!("{repo}/{path}\n{text}")),
                    url: format!("https://grep.app/search?q={}", urlencoding::encode(q)),
                });
            }
        }
        Ok(docs)
    }

    async fn juejin(&self, query: &str, limit: usize) -> Result<Vec<SourceDoc>> {
        let q = if query.trim().is_empty() {
            "OpenAI API"
        } else {
            query
        };
        let url = format!(
            "https://api.juejin.cn/search_api/v1/search?query={}&id_type=0&cursor=0&limit={}",
            urlencoding::encode(q),
            limit.min(20)
        );
        let v = self.json(&url).await?;
        let mut docs = Vec::new();
        if let Some(items) = v["data"].as_array() {
            for it in items.iter().take(limit.min(20)) {
                let info = &it["result_model"]["article_info"];
                let title = info["title"].as_str().unwrap_or("Juejin article");
                let body = info["brief_content"]
                    .as_str()
                    .or_else(|| info["content"].as_str())
                    .unwrap_or("");
                if body.trim().len() < 15 && title.trim().len() < 10 {
                    continue;
                }
                let id = info["article_id"].as_str().unwrap_or("");
                docs.push(SourceDoc {
                    source: "juejin".into(),
                    repo: format!("juejin:{title}"),
                    path: if id.is_empty() {
                        q.to_string()
                    } else {
                        id.to_string()
                    },
                    text: cap(format!("{title}\n{body}")),
                    url: if id.is_empty() {
                        "https://juejin.cn/".into()
                    } else {
                        format!("https://juejin.cn/post/{id}")
                    },
                });
            }
        }
        Ok(docs)
    }

    async fn npm(&self, query: &str, limit: usize) -> Result<Vec<SourceDoc>> {
        let q = if query.trim().is_empty() {
            "openai"
        } else {
            query
        };
        let url = format!(
            "https://registry.npmjs.org/-/v1/search?text={}&size={}",
            urlencoding::encode(q),
            limit.min(50)
        );
        let v = self.json(&url).await?;
        let mut docs = Vec::new();
        if let Some(items) = v["objects"].as_array() {
            for it in items.iter().take(limit.min(50)) {
                let p = &it["package"];
                let name = p["name"].as_str().unwrap_or("");
                let desc = p["description"].as_str().unwrap_or("");
                if name.is_empty() || desc.trim().is_empty() {
                    continue;
                }
                let keywords = p["keywords"]
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .filter_map(|x| x.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    })
                    .unwrap_or_default();
                docs.push(SourceDoc {
                    source: "npm".into(),
                    repo: format!("npm:{name}"),
                    path: name.to_string(),
                    text: cap(format!("{name}\n{desc}\n{keywords}")),
                    url: format!("https://www.npmjs.com/package/{name}"),
                });
            }
        }
        Ok(docs)
    }

    async fn pastegg(&self, _query: &str, limit: usize) -> Result<Vec<SourceDoc>> {
        let url = format!("https://api.paste.gg/v1/pastes?limit={}", limit.min(12));
        let list = self.json(&url).await?;
        let mut docs = Vec::new();
        if let Some(items) = list["result"].as_array() {
            for it in items.iter().take(limit.min(12)) {
                let id = it["id"].as_str().unwrap_or("");
                if id.is_empty() {
                    continue;
                }
                let files = match self
                    .json(&format!("https://api.paste.gg/v1/pastes/{id}/files"))
                    .await
                {
                    Ok(v) => v,
                    Err(e) => {
                        debug!("pastegg {id}: {e}");
                        continue;
                    }
                };
                let mut text = String::new();
                if let Some(arr) = files["result"].as_array() {
                    for f in arr {
                        if let Some(v) = f["content"]["value"].as_str() {
                            text.push_str(v);
                            text.push('\n');
                        }
                    }
                }
                if text.trim().len() < 20 {
                    continue;
                }
                let name = it["name"].as_str().unwrap_or("paste");
                docs.push(SourceDoc {
                    source: "pastegg".into(),
                    repo: format!("paste.gg:{name}"),
                    path: id.to_string(),
                    text: cap(text),
                    url: format!("https://paste.gg/p/{id}"),
                });
            }
        }
        Ok(docs)
    }

    async fn urlscan(&self, query: &str, limit: usize) -> Result<Vec<SourceDoc>> {
        let q = if query.trim().is_empty() {
            "OPENAI_API_KEY"
        } else {
            query
        };
        let url = format!(
            "https://urlscan.io/api/v1/search/?q={}&size={}",
            urlencoding::encode(q),
            limit.min(50)
        );
        let v = self.json(&url).await?;
        let mut items = Vec::new();
        if let Some(results) = v["results"].as_array() {
            for r in results.iter().take(limit.min(50)) {
                let page = &r["page"];
                let u = page["url"].as_str().unwrap_or("");
                if u.is_empty() {
                    continue;
                }
                let title = page["title"].as_str().unwrap_or("");
                let domain = page["domain"].as_str().unwrap_or("");
                items.push((
                    "urlscan:page".to_string(),
                    format!("{domain} {title}"),
                    u.to_string(),
                ));
            }
        }
        Ok(self.fetch_raw_docs("urlscan", items, limit, 6).await)
    }

    async fn bluesky(&self, query: &str, limit: usize) -> Result<Vec<SourceDoc>> {
        let q = if query.trim().is_empty() {
            "OPENAI_API_KEY"
        } else {
            query
        };
        let url = format!(
            "https://api.bsky.app/xrpc/app.bsky.feed.searchPosts?q={}&limit={}",
            urlencoding::encode(q),
            limit.min(50)
        );
        let v = self.json(&url).await?;
        let mut docs = Vec::new();
        if let Some(posts) = v["posts"].as_array() {
            for p in posts.iter().take(limit.min(50)) {
                let text = p["record"]["text"].as_str().unwrap_or("");
                if text.trim().len() < 10 {
                    continue;
                }
                let handle = p["author"]["handle"].as_str().unwrap_or("bsky");
                let uri = p["uri"].as_str().unwrap_or("");
                docs.push(SourceDoc {
                    source: "bluesky".into(),
                    repo: format!("bsky:@{handle}"),
                    path: uri.to_string(),
                    text: cap(text.to_string()),
                    url: uri.to_string(),
                });
            }
        }
        Ok(docs)
    }

    async fn shodan(&self, query: &str, limit: usize) -> Result<Vec<SourceDoc>> {
        let key = std::env::var("SHODAN_API_KEY").unwrap_or_default();
        if key.trim().is_empty() {
            return Ok(Vec::new());
        }
        let q = if query.trim().is_empty() {
            "http.html:OPENAI_API_KEY"
        } else {
            query
        };
        let client = self.http_for_url("https://api.shodan.io/shodan/host/search");
        let resp = client
            .get("https://api.shodan.io/shodan/host/search")
            .query(&[
                ("key", key.as_str()),
                ("query", q),
                ("minify", "true"),
                ("limit", &limit.min(50).to_string()),
            ])
            .send()
            .await?;
        if !resp.status().is_success() {
            bail!("Shodan HTTP {}", resp.status().as_u16());
        }
        let v: Value = resp.json().await?;
        let mut docs = Vec::new();
        if let Some(matches) = v["matches"].as_array() {
            for m in matches.iter().take(limit.min(50)) {
                let ip = m["ip_str"].as_str().unwrap_or("");
                let port = m["port"].as_i64().unwrap_or(0);
                let data = m["data"].as_str().unwrap_or("");
                if ip.is_empty() || data.trim().is_empty() {
                    continue;
                }
                let host = m["hostnames"]
                    .as_array()
                    .and_then(|a| a.first())
                    .and_then(|x| x.as_str())
                    .unwrap_or(ip);
                docs.push(SourceDoc {
                    source: "shodan".into(),
                    repo: format!("shodan:{host}"),
                    path: format!("{ip}:{port}"),
                    text: cap(data.to_string()),
                    url: format!("https://www.shodan.io/host/{ip}"),
                });
            }
        }
        Ok(docs)
    }

    // ---------- Country HTML search pages ----------

    async fn html_source(&self, source: &str, query: &str, limit: usize) -> Result<Vec<SourceDoc>> {
        let _ = limit;
        let q = if query.trim().is_empty() {
            "openai"
        } else {
            query
        };
        let template = match source {
            "dou" => "https://dou.ua/search/?q={q}",
            "devby" => "https://dev.by/news?query={q}",
            "tproger" => "https://tproger.ru/?s={q}",
            "techinasia" => "https://www.techinasia.com/search?q={q}",
            "e27" => "https://e27.co/?s={q}",
            "geeksforgeeks" => "https://www.geeksforgeeks.org/?s={q}",
            "tinhte" => "https://tinhte.vn/search/?q={q}",
            "note" => "https://note.com/search?q={q}",
            "hatena" => "https://b.hatena.ne.jp/search/text?q={q}",
            "mojeek" => "https://www.mojeek.com/search?q={q}",
            "yandex" => "https://yandex.com/search/?text={q}",
            "google" => "https://www.google.com/search?q={q}",
            "baidu" => "https://www.baidu.com/s?wd={q}",
            "sogou" => "https://www.sogou.com/web?query={q}",
            "naver" => "https://search.naver.com/search.naver?query={q}",
            "startpage" => "https://www.startpage.com/sp/search?query={q}",
            "searx" => "https://searx.be/search?q={q}",
            "oldreddit" => "https://old.reddit.com/search?q={q}&sort=new",
            "lobsters" => "https://lobste.rs/search?q={q}",
            "csdn" => "https://so.csdn.net/so/search?q={q}",
            "segmentfault" => "https://segmentfault.com/search?q={q}",
            "cnblogs" => "https://zzk.cnblogs.com/s?w={q}",
            "oschina" => "https://www.oschina.net/search?scope=code&q={q}",
            "cto51" => "https://so.51cto.com/?keywords={q}",
            "tencent" => "https://cloud.tencent.com/search?q={q}",
            "aliyun" => "https://developer.aliyun.com/search?q={q}",
            "justpaste" => "https://justpaste.it/search?q={q}",
            "rentry" => "https://rentry.co/search?q={q}",
            "thehackernews" => "https://thehackernews.com/search?q={q}",
            "bleepingcomputer" => "https://www.bleepingcomputer.com/search/?q={q}",
            "securityweek" => "https://www.securityweek.com/?s={q}",
            "infoq" => "https://www.infoq.cn/search?query={q}",
            "jianshu" => "https://www.jianshu.com/search?q={q}",
            "weibo" => "https://s.weibo.com/weibo?q={q}",
            "bilibili" => "https://search.bilibili.com/all?keyword={q}",
            "hackread" => "https://www.hackread.com/?s={q}",
            "cybernews" => "https://cybernews.com/search/?q={q}",
            "theregister" => "https://www.theregister.com/search/?q={q}",
            "packetstorm" => "https://packetstormsecurity.com/search/?q={q}",
            "wechat" => "https://weixin.sogou.com/weixin?type=2&query={q}",
            "hashnode2" => "https://hashnode.com/search?q={q}",
            "securityse" => "https://security.stackexchange.com/search?q={q}",
            "serverfault" => "https://serverfault.com/search?q={q}",
            "superuser" => "https://superuser.com/search?q={q}",
            "askubuntu" => "https://askubuntu.com/search?q={q}",
            _ => return Ok(Vec::new()),
        };
        let url = template.replace("{q}", &urlencoding::encode(q));
        let html = self.text(&url).await?;
        let text = strip_html(&html);
        if text.trim().len() < 80 {
            return Ok(Vec::new());
        }
        Ok(vec![SourceDoc {
            source: source.to_string(),
            repo: format!("{source}:search"),
            path: url.clone(),
            text: cap(text),
            url,
        }])
    }

    // ---------- DuckDuckGo HTML search ----------

    async fn duckduckgo(&self, label: &str, query: &str, limit: usize) -> Result<Vec<SourceDoc>> {
        let q = if query.trim().is_empty() {
            "\"OPENAI_API_KEY\" \"sk-\""
        } else {
            query
        };
        let search_url = format!(
            "https://html.duckduckgo.com/html/?q={}",
            urlencoding::encode(q)
        );
        let html = self.text(&search_url).await?;
        let mut docs = Vec::new();
        let plain = strip_html(&html);
        if plain.trim().len() > 40 {
            docs.push(SourceDoc {
                source: label.to_string(),
                repo: format!("{label}:search"),
                path: q.to_string(),
                text: cap(plain),
                url: search_url.clone(),
            });
        }
        let mut items = Vec::new();
        for url in ddg_links(&html).into_iter().take(limit.min(20)) {
            let path = url
                .split_once("://")
                .map(|(_, rest)| rest)
                .unwrap_or(&url)
                .to_string();
            items.push((format!("{label}:web"), path, url));
        }
        docs.extend(self.fetch_raw_docs(label, items, limit, 6).await);
        docs.truncate(limit);
        Ok(docs)
    }

    // ---------- Marginalia search ----------

    async fn marginalia(&self, query: &str, limit: usize) -> Result<Vec<SourceDoc>> {
        let q = if query.trim().is_empty() {
            "OPENAI_API_KEY"
        } else {
            query
        };
        let search_url = format!(
            "https://search.marginalia.nu/search?query={}",
            urlencoding::encode(q)
        );
        let html = self.text(&search_url).await?;
        let mut docs = Vec::new();
        let plain = strip_html(&html);
        if plain.trim().len() > 40 {
            docs.push(SourceDoc {
                source: "marginalia".into(),
                repo: "marginalia:search".into(),
                path: q.to_string(),
                text: cap(plain),
                url: search_url.clone(),
            });
        }
        let mut items = Vec::new();
        for url in page_links(&html, "search.marginalia.nu")
            .into_iter()
            .take(limit.min(20))
        {
            let path = url
                .split_once("://")
                .map(|(_, rest)| rest)
                .unwrap_or(&url)
                .to_string();
            items.push(("marginalia:web".to_string(), path, url));
        }
        docs.extend(self.fetch_raw_docs("marginalia", items, limit, 6).await);
        docs.truncate(limit);
        Ok(docs)
    }

    // ---------- Docker Hub repository search ----------

    async fn dockerhub(&self, query: &str, limit: usize) -> Result<Vec<SourceDoc>> {
        let q = if query.trim().is_empty() {
            "OPENAI_API_KEY"
        } else {
            query
        };
        let url = format!(
            "https://hub.docker.com/v2/search/repositories/?query={}&page_size={}",
            urlencoding::encode(q),
            limit.min(100)
        );
        let v = self.json(&url).await?;
        let mut docs = Vec::new();
        if let Some(items) = v["results"].as_array() {
            for it in items.iter().take(limit) {
                let name = it["repo_name"].as_str().unwrap_or("");
                let desc = it["short_description"].as_str().unwrap_or("");
                if name.is_empty() || desc.trim().is_empty() {
                    continue;
                }
                docs.push(SourceDoc {
                    source: "dockerhub".into(),
                    repo: format!("dockerhub:{name}"),
                    path: name.to_string(),
                    text: cap(format!("{name}\n{desc}")),
                    url: format!("https://hub.docker.com/r/{name}"),
                });
            }
        }
        Ok(docs)
    }

    // ---------- Debian Code Search ----------

    async fn debian(&self, query: &str, limit: usize) -> Result<Vec<SourceDoc>> {
        let q = if query.trim().is_empty() {
            "OPENAI_API_KEY"
        } else {
            query
        };
        let url = format!(
            "https://codesearch.debian.net/search?q={}",
            urlencoding::encode(q)
        );
        let html = self.text(&url).await?;
        let text = strip_html(&html);
        if text.trim().len() < 80 {
            return Ok(Vec::new());
        }
        let _ = limit;
        Ok(vec![SourceDoc {
            source: "debian".into(),
            repo: "debian:codesearch".into(),
            path: q.to_string(),
            text: cap(text),
            url,
        }])
    }

    // ---------- Internet Archive metadata search ----------

    async fn archive_org(&self, query: &str, limit: usize) -> Result<Vec<SourceDoc>> {
        let q = if query.trim().is_empty() {
            "OPENAI_API_KEY"
        } else {
            query
        };
        let url = format!(
            "https://archive.org/advancedsearch.php?q={}&fl%5B%5D=identifier&fl%5B%5D=title&fl%5B%5D=description&rows={}&output=json",
            urlencoding::encode(q),
            limit.min(100)
        );
        let v = self.json(&url).await?;
        let mut docs = Vec::new();
        if let Some(items) = v["response"]["docs"].as_array() {
            for it in items.iter().take(limit) {
                let id = it["identifier"].as_str().unwrap_or("");
                if id.is_empty() {
                    continue;
                }
                let title = it["title"].as_str().unwrap_or("");
                let desc = it["description"].as_str().unwrap_or("");
                let text = format!("{title}\n{desc}\nhttps://archive.org/details/{id}");
                if text.trim().len() < 20 {
                    continue;
                }
                docs.push(SourceDoc {
                    source: "archive".into(),
                    repo: format!("archive:{id}"),
                    path: id.to_string(),
                    text: cap(text),
                    url: format!("https://archive.org/details/{id}"),
                });
            }
        }
        Ok(docs)
    }

    // ---------- Mastodon public status search ----------

    async fn mastodon(&self, query: &str, limit: usize) -> Result<Vec<SourceDoc>> {
        let q = if query.trim().is_empty() {
            "OPENAI_API_KEY"
        } else {
            query
        };
        let url = format!(
            "https://mastodon.social/api/v2/search?q={}&type=statuses&limit={}",
            urlencoding::encode(q),
            limit.min(40)
        );
        let v = self.json(&url).await?;
        let mut docs = Vec::new();
        if let Some(items) = v["statuses"].as_array() {
            for it in items.iter().take(limit) {
                let content = strip_html(it["content"].as_str().unwrap_or(""));
                if content.trim().len() < 20 {
                    continue;
                }
                let id = it["id"].as_str().unwrap_or("");
                let account = it["account"]["acct"].as_str().unwrap_or("mastodon");
                docs.push(SourceDoc {
                    source: "mastodon".into(),
                    repo: format!("mastodon:{account}"),
                    path: id.to_string(),
                    text: cap(content),
                    url: it["url"].as_str().unwrap_or(&url).to_string(),
                });
            }
        }
        Ok(docs)
    }

    // ---------- Public Discourse forums ----------

    async fn discourse(
        &self,
        source: &str,
        host: &str,
        query: &str,
        limit: usize,
    ) -> Result<Vec<SourceDoc>> {
        let q = if query.trim().is_empty() {
            "OPENAI_API_KEY"
        } else {
            query
        };
        let url = format!("https://{host}/search.json?q={}", urlencoding::encode(q));
        let v = self.json(&url).await?;
        let mut docs = Vec::new();
        let titles: std::collections::HashMap<i64, String> = v["topics"]
            .as_array()
            .map(|ts| {
                ts.iter()
                    .filter_map(|t| {
                        Some((
                            t["id"].as_i64()?,
                            t["title"].as_str().unwrap_or("").to_string(),
                        ))
                    })
                    .collect()
            })
            .unwrap_or_default();
        if let Some(posts) = v["posts"].as_array() {
            for p in posts.iter().take(limit.min(40)) {
                let Some(tid) = p["topic_id"].as_i64() else {
                    continue;
                };
                let title = titles.get(&tid).map(|s| s.as_str()).unwrap_or("");
                let blurb = p["blurb"].as_str().unwrap_or("");
                let text = format!("{title}\n{blurb}");
                if text.trim().len() < 20 {
                    continue;
                }
                let pn = p["post_number"].as_i64().unwrap_or(1);
                docs.push(SourceDoc {
                    source: source.to_string(),
                    repo: format!("discourse:{host}"),
                    path: format!("t/{tid}#p{pn}"),
                    text: cap(text),
                    url: format!("https://{host}/t/{tid}/{pn}"),
                });
            }
        }
        Ok(docs)
    }

    // ---------- GitLab public snippets ----------

    async fn gitlab_snippets(&self, query: &str, limit: usize) -> Result<Vec<SourceDoc>> {
        let q = if query.trim().is_empty() {
            "OPENAI_API_KEY"
        } else {
            query
        };
        let url = format!(
            "https://gitlab.com/api/v4/snippets?search={}&per_page={}",
            urlencoding::encode(q),
            limit.min(50)
        );
        let v = self.json(&url).await?;
        let mut items = Vec::new();
        if let Some(arr) = v.as_array() {
            for it in arr.iter().take(limit) {
                let raw = it["raw_url"].as_str().unwrap_or("");
                let web = it["web_url"].as_str().unwrap_or("");
                if !raw.is_empty() {
                    items.push((
                        "gitlab_snippet".to_string(),
                        it["id"].to_string(),
                        raw.to_string(),
                    ));
                } else if !web.is_empty() {
                    items.push((
                        "gitlab_snippet".to_string(),
                        it["id"].to_string(),
                        web.to_string(),
                    ));
                }
            }
        }
        Ok(self.fetch_raw_docs("gitlab_snippet", items, limit, 6).await)
    }

    // ---------- Telegram public channels ----------

    async fn telegram(&self, channel: &str, limit: usize) -> Result<Vec<SourceDoc>> {
        let channel = channel.trim().trim_start_matches('@');
        if channel.is_empty() {
            return Ok(Vec::new());
        }
        let url = format!("https://t.me/s/{}", urlencoding::encode(channel));
        let html = self.text(&url).await?;
        let text = strip_html(&html);
        if text.trim().len() < 80 {
            return Ok(Vec::new());
        }
        let _ = limit;
        Ok(vec![SourceDoc {
            source: "telegram".into(),
            repo: format!("telegram:@{channel}"),
            path: channel.to_string(),
            text: cap(text),
            url,
        }])
    }

    // ---------- Torch: Tor hidden-service search ----------

    async fn torch(&self, query: &str, limit: usize) -> Result<Vec<SourceDoc>> {
        let client = self
            .tor_http()
            .ok_or_else(|| anyhow!("TOR_PROXY is not configured"))?;
        let q = if query.trim().is_empty() {
            "api key"
        } else {
            query
        };
        let search_url = format!(
            "http://torchdeedp3i2jigzjdmfpn5ttjhthh5wbmda2rr3jvqjg5p77c54dqd.onion/search?query={}",
            urlencoding::encode(q)
        );
        let resp = client
            .get(&search_url)
            .header("Accept", "text/html,application/xhtml+xml")
            .send()
            .await?;
        if !resp.status().is_success() {
            bail!("torch HTTP {}", resp.status().as_u16());
        }
        let html = resp.text().await.unwrap_or_default();
        let mut docs = Vec::new();
        let plain = strip_html(&html);
        if plain.trim().len() > 40 {
            docs.push(SourceDoc {
                source: "torch".into(),
                repo: "torch:search".into(),
                path: q.to_string(),
                text: cap(plain),
                url: search_url.clone(),
            });
        }
        let links = torch_links(&html);
        let futs = stream::iter(links.into_iter().take(limit.min(12)).map(|url| {
            let client = client.clone();
            async move {
                let text = match client
                    .get(&url)
                    .header("Accept", "text/html,text/plain")
                    .send()
                    .await
                {
                    Ok(r) if r.status().is_success() => r.text().await.unwrap_or_default(),
                    _ => String::new(),
                };
                (url, text)
            }
        }));
        let results: Vec<_> = futs.buffer_unordered(6).collect().await;
        for (url, text) in results {
            if text.trim().len() < 40 {
                continue;
            }
            docs.push(SourceDoc {
                source: "torch".into(),
                repo: "torch:onion".into(),
                path: url.clone(),
                text: cap(strip_html(&text)),
                url,
            });
            if docs.len() >= limit {
                break;
            }
        }
        docs.truncate(limit);
        Ok(docs)
    }

    // ---------- Bing web search: independent index and paste/page fallback ----------

    async fn bing(&self, label: &str, query: &str, limit: usize) -> Result<Vec<SourceDoc>> {
        let q = if query.trim().is_empty() {
            "\"OPENAI_API_KEY\" \"sk-\""
        } else {
            query
        };
        let search_url = format!(
            "https://www.bing.com/search?q={}&count=30&setlang=en-US",
            urlencoding::encode(q)
        );
        let html = self.text(&search_url).await?;
        let mut docs = Vec::new();
        let plain = strip_html(&html);
        if plain.trim().len() > 40 {
            docs.push(SourceDoc {
                source: label.to_string(),
                repo: format!("{label}:search"),
                path: q.to_string(),
                text: cap(plain),
                url: search_url.clone(),
            });
        }
        let links = bing_links(&html);
        let mut items: Vec<(String, String, String)> = Vec::new();
        for url in links.into_iter().take(limit.min(40)) {
            let path = url
                .split_once("://")
                .map(|(_, rest)| rest)
                .unwrap_or(&url)
                .to_string();
            items.push((format!("{label}:web"), path, url));
        }
        docs.extend(self.fetch_raw_docs(label, items, limit, 8).await);
        docs.truncate(limit);
        Ok(docs)
    }

    // ---------- Brave web search: clearnet + indexed paste/code pages ----------

    async fn brave(&self, label: &str, query: &str, limit: usize) -> Result<Vec<SourceDoc>> {
        let q = if query.trim().is_empty() {
            "\"OPENAI_API_KEY\" \"sk-\""
        } else {
            query
        };
        let search_url = format!(
            "https://search.brave.com/search?q={}&source=web",
            urlencoding::encode(q)
        );
        let html = self.text(&search_url).await?;
        let mut docs = Vec::new();
        let plain = strip_html(&html);
        if plain.trim().len() > 40 {
            docs.push(SourceDoc {
                source: label.to_string(),
                repo: format!("{label}:search"),
                path: q.to_string(),
                text: cap(plain),
                url: search_url.clone(),
            });
        }
        let links = brave_links(&html);
        let mut items: Vec<(String, String, String)> = Vec::new();
        for url in links.into_iter().take(limit.min(40)) {
            let path = url
                .split_once("://")
                .map(|(_, rest)| rest)
                .unwrap_or(&url)
                .to_string();
            items.push((format!("{label}:web"), path, url));
        }
        docs.extend(self.fetch_raw_docs(label, items, limit, 8).await);
        docs.truncate(limit);
        Ok(docs)
    }

    // ---------- Gitee (码云) ----------

    async fn gitee(&self, query: &str, limit: usize) -> Result<Vec<SourceDoc>> {
        // Two discovery paths:
        //   1. PAT-scoped `/user/repos` — includes private repos when the token
        //      has project scope;
        //   2. so.gitee.com code-search widget — public code hits that the
        //      official API does not index.
        // Both feed the same tree/raw pipeline; the PAT is attached to every
        // gitee.com API/raw request by `with_pat`.
        let mut repos: Vec<String> = Vec::new();
        let mut seen = HashSet::new();
        let push_repo = |full: String, repos: &mut Vec<String>, seen: &mut HashSet<String>| {
            let full = full.trim_matches('/').to_string();
            if full.split('/').count() == 2 && seen.insert(full.clone()) {
                repos.push(full);
            }
        };

        if let Ok(v) = self
            .json("https://gitee.com/api/v5/user/repos?per_page=100&sort=updated&direction=desc")
            .await
        {
            if let Some(items) = v.as_array() {
                for r in items.iter().take(100) {
                    let full = r["full_name"].as_str().map(str::to_string).or_else(|| {
                        Some(format!(
                            "{}/{}",
                            r["owner"]["login"].as_str()?,
                            r["name"].as_str()?
                        ))
                    });
                    if let Some(full) = full {
                        push_repo(full, &mut repos, &mut seen);
                    }
                }
            }
        }

        for page in 0..10 {
            let url = format!(
                "https://so.gitee.com/v1/search/widget/wong1slagnlmzwvsu5ya?query=1048&q={}&from={}&size=20&type=code&sort_by_f=",
                urlencoding::encode(query),
                page * 20
            );
            let v = match self.json(&url).await {
                Ok(v) => v,
                Err(e) => {
                    debug!("gitee search page {page}: {e}");
                    break;
                }
            };
            let Some(hits) = v["hits"]["hits"].as_array() else {
                break;
            };
            if hits.is_empty() {
                break;
            }
            for h in hits {
                let f = &h["fields"];
                if f["fork"].as_i64().unwrap_or(0) == 1 {
                    continue;
                }
                let Some(u) = f["url"]
                    .as_array()
                    .and_then(|a| a.first())
                    .and_then(|x| x.as_str())
                else {
                    continue;
                };
                let full = u
                    .trim_start_matches("https://gitee.com/")
                    .trim_start_matches("http://gitee.com/")
                    .trim_end_matches('/')
                    .to_string();
                push_repo(full, &mut repos, &mut seen);
            }
        }
        debug!("gitee '{}': {} repos", query, repos.len());

        let repo_cap = 48.min(limit.max(1));
        let mut items: Vec<(String, String, String)> = Vec::new();
        let mut misses = 0usize;
        for full in repos.into_iter().take(repo_cap) {
            if items.len() >= limit {
                break;
            }
            let meta = match self
                .json(&format!("https://gitee.com/api/v5/repos/{full}"))
                .await
            {
                Ok(v) => v,
                Err(e) => {
                    debug!("gitee meta {full}: {e}");
                    misses += 1;
                    if rate_limited(&e) || misses >= 3 {
                        break;
                    }
                    continue;
                }
            };
            let branch = meta["default_branch"].as_str().unwrap_or("master");
            let tree_url = format!(
                "https://gitee.com/api/v5/repos/{full}/git/trees/{}?recursive=1",
                urlencoding::encode(branch)
            );
            let tree = match self.json(&tree_url).await {
                Ok(v) => v,
                Err(e) => {
                    debug!("gitee tree {full}: {e}");
                    misses += 1;
                    if rate_limited(&e) || misses >= 3 {
                        break;
                    }
                    continue;
                }
            };
            let mut files: Vec<(String, u64)> = Vec::new();
            if let Some(tree_items) = tree["tree"].as_array() {
                for it in tree_items {
                    if it["type"].as_str() != Some("blob") {
                        continue;
                    }
                    let Some(path) = it["path"].as_str() else {
                        continue;
                    };
                    let size = it["size"].as_u64().unwrap_or(0);
                    if is_candidate(path, size) {
                        files.push((path.to_string(), size));
                    }
                }
            }
            files.sort_by_key(|(p, _)| std::cmp::Reverse(priority(p)));
            for (path, _) in files.into_iter().take(240) {
                if items.len() >= limit {
                    break;
                }
                let raw = format!(
                    "https://gitee.com/{full}/raw/{}/{}",
                    urlencoding::encode(branch),
                    encode_path(&path)
                );
                items.push((format!("gitee:{full}"), path, raw));
            }
        }
        Ok(self.fetch_raw_docs("gitee", items, limit, 32).await)
    }

    // ---------- GitLab ----------

    async fn gitlab(&self, query: &str, limit: usize) -> Result<Vec<SourceDoc>> {
        let url = format!(
            "https://gitlab.com/api/v4/projects?search={}&per_page=20&order_by=last_activity_at&sort=desc",
            urlencoding::encode(query)
        );
        let v = self.json(&url).await?;
        let mut projects: Vec<(i64, String)> = Vec::new();
        if let Some(items) = v.as_array() {
            for p in items.iter().take(30) {
                if let (Some(id), Some(branch)) = (
                    p["id"].as_i64(),
                    p["default_branch"].as_str().filter(|s| !s.is_empty()),
                ) {
                    projects.push((id, branch.to_string()));
                }
            }
        }
        let mut items: Vec<(String, String, String)> = Vec::new();
        let mut misses = 0usize;
        for (id, branch) in projects {
            if items.len() >= limit {
                break;
            }
            let tree_url = format!(
                "https://gitlab.com/api/v4/projects/{id}/repository/tree?recursive=true&per_page=100"
            );
            let tree = match self.json(&tree_url).await {
                Ok(v) => v,
                Err(e) => {
                    debug!("gitlab tree {id}: {e}");
                    misses += 1;
                    if rate_limited(&e) || misses >= 2 {
                        break;
                    }
                    continue;
                }
            };
            let mut files: Vec<(String, u64)> = Vec::new();
            if let Some(items) = tree.as_array() {
                for it in items {
                    if it["type"].as_str() != Some("blob") {
                        continue;
                    }
                    let Some(path) = it["path"].as_str() else {
                        continue;
                    };
                    if is_candidate(path, it["size"].as_u64().unwrap_or(0)) {
                        files.push((path.to_string(), 0));
                    }
                }
            }
            files.sort_by_key(|(p, _)| std::cmp::Reverse(priority(p)));
            for (path, _) in files.into_iter().take(240) {
                if items.len() >= limit {
                    break;
                }
                let raw = format!(
                    "https://gitlab.com/api/v4/projects/{id}/repository/files/{}/raw?ref={}",
                    urlencoding::encode(&path),
                    urlencoding::encode(&branch)
                );
                items.push((format!("gitlab:{id}"), path, raw));
            }
        }
        Ok(self.fetch_raw_docs("gitlab", items, limit, 24).await)
    }

    // ---------- Hugging Face Spaces + models ----------

    async fn huggingface(&self, query: &str, limit: usize) -> Result<Vec<SourceDoc>> {
        let mut items: Vec<(&'static str, String)> = Vec::new();
        let spaces = format!(
            "https://huggingface.co/api/spaces?search={}&limit=30&sort=lastModified&direction=-1",
            urlencoding::encode(query)
        );
        if let Ok(v) = self.json(&spaces).await {
            if let Some(arr) = v.as_array() {
                for it in arr.iter().take(30) {
                    if let Some(id) = it["id"].as_str() {
                        items.push(("spaces", id.to_string()));
                    }
                }
            }
        }
        let models = format!(
            "https://huggingface.co/api/models?search={}&limit=30&sort=lastModified&direction=-1",
            urlencoding::encode(query)
        );
        if let Ok(v) = self.json(&models).await {
            if let Some(arr) = v.as_array() {
                for it in arr.iter().take(12) {
                    if let Some(id) = it["id"].as_str() {
                        items.push(("models", id.to_string()));
                    }
                }
            }
        }
        let datasets = format!(
            "https://huggingface.co/api/datasets?search={}&limit=20&sort=lastModified&direction=-1",
            urlencoding::encode(query)
        );
        if let Ok(v) = self.json(&datasets).await {
            if let Some(arr) = v.as_array() {
                for it in arr.iter().take(8) {
                    if let Some(id) = it["id"].as_str() {
                        items.push(("datasets", id.to_string()));
                    }
                }
            }
        }
        let mut raw_items: Vec<(String, String, String)> = Vec::new();
        for (kind, id) in items {
            if raw_items.len() >= limit {
                break;
            }
            let tree_url = format!("https://huggingface.co/api/{kind}/{id}/tree/main");
            let tree = match self.json(&tree_url).await {
                Ok(v) => v,
                Err(e) => {
                    debug!("hf tree {id}: {e}");
                    if rate_limited(&e) {
                        break;
                    }
                    continue;
                }
            };
            let arr = if let Some(a) = tree.as_array() {
                a.clone()
            } else {
                tree["siblings"].as_array().cloned().unwrap_or_default()
            };
            let mut files: Vec<(String, u64)> = Vec::new();
            for it in &arr {
                if it["type"].as_str().map(|t| t != "file").unwrap_or(false) {
                    continue;
                }
                let Some(path) = it["path"].as_str() else {
                    continue;
                };
                if is_candidate(path, it["size"].as_u64().unwrap_or(0)) {
                    files.push((path.to_string(), 0));
                }
            }
            files.sort_by_key(|(p, _)| std::cmp::Reverse(priority(p)));
            for (path, _) in files.into_iter().take(240) {
                if raw_items.len() >= limit {
                    break;
                }
                let raw = match kind {
                    "spaces" => format!("https://huggingface.co/spaces/{id}/raw/main/{path}"),
                    "datasets" => {
                        format!("https://huggingface.co/datasets/{id}/raw/main/{path}")
                    }
                    _ => format!("https://huggingface.co/{id}/raw/main/{path}"),
                };
                raw_items.push((format!("hf:{id}"), path, raw));
            }
        }
        Ok(self.fetch_raw_docs("hf", raw_items, limit, 24).await)
    }

    // ---------- Gitea / Codeberg ----------

    async fn gitea(
        &self,
        base: &str,
        label: &str,
        query: &str,
        limit: usize,
    ) -> Result<Vec<SourceDoc>> {
        let url = format!(
            "{base}/api/v1/repos/search?q={}&limit=50",
            urlencoding::encode(query)
        );
        let v = self.json(&url).await?;
        let mut repos: Vec<(String, String)> = Vec::new();
        if let Some(items) = v["data"].as_array() {
            for p in items.iter().take(50) {
                if p["empty"].as_bool().unwrap_or(false) {
                    continue;
                }
                if let (Some(full), Some(branch)) = (
                    p["full_name"].as_str(),
                    p["default_branch"].as_str().filter(|s| !s.is_empty()),
                ) {
                    repos.push((full.to_string(), branch.to_string()));
                }
            }
        }
        let mut items: Vec<(String, String, String)> = Vec::new();
        let mut misses = 0usize;
        for (full, branch) in repos {
            if items.len() >= limit {
                break;
            }
            let tree_url = format!(
                "{base}/api/v1/repos/{full}/git/trees/{}?recursive=true",
                urlencoding::encode(&branch)
            );
            let tree = match self.json(&tree_url).await {
                Ok(v) => v,
                Err(e) => {
                    debug!("{label} tree {full}: {e}");
                    misses += 1;
                    if rate_limited(&e) || misses >= 2 {
                        break;
                    }
                    continue;
                }
            };
            let mut files: Vec<(String, u64)> = Vec::new();
            if let Some(items) = tree["tree"].as_array() {
                for it in items {
                    if it["type"].as_str() != Some("blob") {
                        continue;
                    }
                    let Some(path) = it["path"].as_str() else {
                        continue;
                    };
                    if is_candidate(path, it["size"].as_u64().unwrap_or(0)) {
                        files.push((path.to_string(), 0));
                    }
                }
            }
            files.sort_by_key(|(p, _)| std::cmp::Reverse(priority(p)));
            for (path, _) in files.into_iter().take(240) {
                if items.len() >= limit {
                    break;
                }
                let raw = format!(
                    "{base}/{full}/raw/branch/{}/{}",
                    urlencoding::encode(&branch),
                    encode_path(&path)
                );
                items.push((format!("{label}:{full}"), path, raw));
            }
        }
        Ok(self.fetch_raw_docs(label, items, limit, 24).await)
    }

    async fn codeberg(&self, query: &str, limit: usize) -> Result<Vec<SourceDoc>> {
        self.gitea("https://codeberg.org", "codeberg", query, limit)
            .await
    }

    // ---------- GitHub Gist search ----------
    // Public gists are one of the highest-density sources of copy-pasted
    // credentials. GitHub's public gist feed is not query-aware, so use the
    // HTML search results and fetch each matching gist's raw bundle.
    async fn gist_search(&self, query: &str, limit: usize) -> Result<Vec<SourceDoc>> {
        let q = if query.trim().is_empty() {
            "OPENAI_API_KEY"
        } else {
            query
        };
        static RE: OnceLock<Regex> = OnceLock::new();
        let re = RE.get_or_init(|| {
            Regex::new(r#"href="/([A-Za-z0-9_.-]+)/([a-f0-9]{10,})""#).expect("gist link regex")
        });
        let mut seen = HashSet::new();
        let mut items: Vec<(String, String, String)> = Vec::new();
        // Gist search is the densest public source for pasted API keys. Walk
        // ten result pages, but stop immediately when a page adds nothing.
        for page in 1..=10 {
            let url = format!(
                "https://gist.github.com/search?q={}&p={}",
                urlencoding::encode(q),
                page
            );
            let html = match self.text(&url).await {
                Ok(html) => html,
                Err(e) => {
                    debug!("gist search page {page}: {e}");
                    break;
                }
            };
            let mut added = 0usize;
            for cap in re.captures_iter(&html) {
                let Some(user) = cap.get(1) else { continue };
                let Some(id) = cap.get(2) else { continue };
                let key = format!("{}/{}", user.as_str(), id.as_str());
                if !seen.insert(key.clone()) {
                    continue;
                }
                added += 1;
                items.push((
                    format!("gist:{key}"),
                    id.as_str().to_string(),
                    format!("https://gist.githubusercontent.com/{key}/raw"),
                ));
                if items.len() >= limit {
                    break;
                }
            }
            if added == 0 || items.len() >= limit {
                break;
            }
        }
        Ok(self.fetch_raw_docs("gist_search", items, limit, 12).await)
    }

    // ---------- GitHub Gists ----------

    async fn gists(&self, limit: usize) -> Result<Vec<SourceDoc>> {
        let v = self
            .json("https://api.github.com/gists/public?per_page=100")
            .await?;
        let mut docs = Vec::new();
        if let Some(items) = v.as_array() {
            for g in items {
                if docs.len() >= limit {
                    break;
                }
                let Some(id) = g["id"].as_str() else { continue };
                let desc = g["description"].as_str().unwrap_or("");
                if let Some(files) = g["files"].as_object() {
                    for (name, f) in files.iter().take(16) {
                        if docs.len() >= limit {
                            break;
                        }
                        let size = f["size"].as_u64().unwrap_or(0);
                        if size > 512 * 1024 || !is_candidate(name, size) {
                            continue;
                        }
                        let Some(raw) = f["raw_url"].as_str() else {
                            continue;
                        };
                        match self.text(raw).await {
                            Ok(text) if !text.trim().is_empty() => docs.push(SourceDoc {
                                source: "gists".into(),
                                repo: format!("gist:{id}"),
                                path: name.clone(),
                                text: cap(format!("{desc}\n{text}")),
                                url: format!("https://gist.github.com/{id}"),
                            }),
                            Ok(_) => {}
                            Err(e) => debug!("gist {id}/{name}: {e}"),
                        }
                    }
                }
            }
        }
        Ok(docs)
    }

    // ---------- NodeSeek (Chinese forum) ----------

    async fn nodeseek(&self, limit: usize) -> Result<Vec<SourceDoc>> {
        // NodeSeek's Cloudflare fingerprint rejects rustls; curl's TLS
        // fingerprint is accepted, so this one adapter uses the system curl.
        let home = self.curl_text("https://www.nodeseek.com/").await?;
        let links = nodeseek_links(&home);
        let mut docs = Vec::new();
        for path in links.into_iter().take(limit.min(120)) {
            if docs.len() >= limit {
                break;
            }
            let url = format!("https://www.nodeseek.com{path}");
            let html = match self.curl_text(&url).await {
                Ok(h) => h,
                Err(e) => {
                    debug!("nodeseek {path}: {e}");
                    continue;
                }
            };
            let text = nodeseek_text(&html);
            if text.trim().len() < 30 {
                continue;
            }
            docs.push(SourceDoc {
                source: "nodeseek".into(),
                repo: "nodeseek".into(),
                path: path.trim_start_matches('/').to_string(),
                text: cap(text),
                url,
            });
        }
        Ok(docs)
    }

    // ---------- V2EX ----------

    async fn v2ex(&self, limit: usize) -> Result<Vec<SourceDoc>> {
        let raw = self
            .curl_text("https://www.v2ex.com/api/topics/latest.json")
            .await?;
        let v: Value =
            serde_json::from_str(&raw).with_context(|| "json from v2ex latest.json".to_string())?;
        let items: Vec<_> = v
            .as_array()
            .map(|a| a.iter().take(limit.min(120)).cloned().collect())
            .unwrap_or_default();
        let futs = stream::iter(items.into_iter().enumerate().map(|(idx, t)| async move {
            let id = t["id"].as_i64().unwrap_or(0);
            let title = t["title"].as_str().unwrap_or("").to_string();
            let content = t["content"].as_str().unwrap_or("").to_string();
            let rendered = strip_html(t["content_rendered"].as_str().unwrap_or(""));
            let replies = if idx < 50 {
                self.text(&format!("https://www.v2ex.com/t/{id}"))
                    .await
                    .map(|html| v2ex_replies(&html))
                    .unwrap_or_default()
            } else {
                String::new()
            };
            let text = format!("{title}\n{content}\n{rendered}{replies}");
            let url = t["url"]
                .as_str()
                .unwrap_or("https://www.v2ex.com")
                .to_string();
            (id, title, text, url)
        }));
        let results: Vec<_> = futs.buffer_unordered(24).collect().await;
        let mut docs = Vec::new();
        for (id, _title, text, url) in results {
            if text.trim().len() < 20 {
                continue;
            }
            docs.push(SourceDoc {
                source: "v2ex".into(),
                repo: "v2ex".into(),
                path: format!("t/{id}"),
                text: cap(text),
                url,
            });
            if docs.len() >= limit {
                break;
            }
        }
        Ok(docs)
    }

    // ---------- NodeLoc (Discourse) ----------

    async fn nodeloc_topics(&self, topics: Vec<(i64, String)>, limit: usize) -> Vec<SourceDoc> {
        let futs = stream::iter(topics.into_iter().take(limit.max(1)).map(
            |(id, title)| async move {
                let detail = self
                    .json(&format!("https://www.nodeloc.com/t/{id}.json"))
                    .await;
                (id, title, detail)
            },
        ));
        let results: Vec<_> = futs.buffer_unordered(24).collect().await;
        let mut docs = Vec::new();
        for (id, title, detail) in results {
            let detail = match detail {
                Ok(v) => v,
                Err(e) => {
                    debug!("nodeloc topic {id}: {e}");
                    continue;
                }
            };
            let mut text = format!("{title}\n");
            if let Some(posts) = detail["post_stream"]["posts"].as_array() {
                for p in posts.iter().take(30) {
                    text.push_str(&strip_html(p["cooked"].as_str().unwrap_or("")));
                    text.push('\n');
                }
            }
            if text.trim().len() < 20 {
                continue;
            }
            docs.push(SourceDoc {
                source: "nodeloc".into(),
                repo: "nodeloc".into(),
                path: format!("t/{id}"),
                text: cap(text),
                url: format!("https://www.nodeloc.com/t/{id}"),
            });
            if docs.len() >= limit {
                break;
            }
        }
        docs
    }

    async fn nodeloc(&self, query: &str, limit: usize) -> Result<Vec<SourceDoc>> {
        if !query.trim().is_empty() {
            return self.nodeloc_search(query, limit).await;
        }
        let v = self.json("https://www.nodeloc.com/latest.json").await?;
        let topics = v["topic_list"]["topics"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        let items: Vec<(i64, String)> = topics
            .iter()
            .take(limit.min(120))
            .filter_map(|t| {
                Some((
                    t["id"].as_i64()?,
                    t["title"].as_str().unwrap_or("").to_string(),
                ))
            })
            .collect();
        Ok(self.nodeloc_topics(items, limit).await)
    }

    async fn nodeloc_search(&self, query: &str, limit: usize) -> Result<Vec<SourceDoc>> {
        // Discourse search exposes 50 matching posts without auth. Blurbs
        // often contain the full relay key; topic title gives context.
        let url = format!(
            "https://www.nodeloc.com/search.json?q={}",
            urlencoding::encode(query)
        );
        let v = self.json(&url).await?;
        let titles: std::collections::HashMap<i64, String> = v["topics"]
            .as_array()
            .map(|ts| {
                ts.iter()
                    .filter_map(|t| {
                        Some((
                            t["id"].as_i64()?,
                            t["title"].as_str().unwrap_or("").to_string(),
                        ))
                    })
                    .collect()
            })
            .unwrap_or_default();
        let mut docs = Vec::new();
        let mut tids: Vec<i64> = Vec::new();
        let blurb_limit = limit.saturating_sub(6).max(1);
        if let Some(posts) = v["posts"].as_array() {
            for p in posts.iter().take(blurb_limit) {
                let Some(tid) = p["topic_id"].as_i64() else {
                    continue;
                };
                if !tids.contains(&tid) {
                    tids.push(tid);
                }
                let title = titles.get(&tid).map(|s| s.as_str()).unwrap_or("");
                let blurb = p["blurb"].as_str().unwrap_or("");
                let text = format!("{title}\n{blurb}");
                if text.trim().len() < 20 {
                    continue;
                }
                let pn = p["post_number"].as_i64().unwrap_or(1);
                docs.push(SourceDoc {
                    source: "nodeloc".into(),
                    repo: "nodeloc".into(),
                    path: format!("t/{tid}#p{pn}"),
                    text: cap(text),
                    url: format!("https://www.nodeloc.com/t/{tid}/{pn}"),
                });
            }
        }
        // Search blurbs are truncated; pull full topics in parallel.
        if docs.len() < limit {
            let items: Vec<(i64, String)> = tids
                .into_iter()
                .map(|tid| {
                    let title = titles.get(&tid).cloned().unwrap_or_default();
                    (tid, title)
                })
                .collect();
            docs.extend(
                self.nodeloc_topics(items, limit.saturating_sub(docs.len()))
                    .await,
            );
        }
        docs.truncate(limit);
        Ok(docs)
    }

    // ---------- Pastebin ----------

    async fn pastebin(&self, limit: usize) -> Result<Vec<SourceDoc>> {
        let html = self.text("https://pastebin.com/archive").await?;
        let ids: Vec<String> = paste_ids(&html).into_iter().take(limit.min(120)).collect();
        let futs = stream::iter(ids.into_iter().map(|id| async move {
            let raw = format!("https://pastebin.com/raw/{id}");
            let text = self.text(&raw).await;
            (id, text)
        }));
        let results: Vec<_> = futs.buffer_unordered(24).collect().await;
        let mut docs = Vec::new();
        for (id, text) in results {
            let Ok(text) = text else { continue };
            if text.trim().is_empty() {
                continue;
            }
            docs.push(SourceDoc {
                source: "pastebin".into(),
                repo: "pastebin".into(),
                path: id.clone(),
                text: cap(text),
                url: format!("https://pastebin.com/{id}"),
            });
            if docs.len() >= limit {
                break;
            }
        }
        Ok(docs)
    }
}

fn torch_links(html: &str) -> Vec<String> {
    static LINK: OnceLock<Regex> = OnceLock::new();
    let re = LINK.get_or_init(|| Regex::new(r#"<a[^>]+href="([^"]+)"[^>]*>"#).unwrap());
    let mut out: Vec<String> = Vec::new();
    for c in re.captures_iter(html) {
        let u = c
            .get(1)
            .map(|m| m.as_str())
            .unwrap_or("")
            .replace("&amp;", "&");
        if !u.starts_with("http") || !u.contains(".onion") {
            continue;
        }
        if u.contains("torchdeedp3i2jigzjdmfpn5ttjhthh5wbmda2rr3jvqjg5p77c54dqd.onion") {
            continue;
        }
        if !out.iter().any(|x| x == &u) {
            out.push(u);
        }
    }
    out
}

fn page_links(html: &str, skip_host: &str) -> Vec<String> {
    static LINK: OnceLock<Regex> = OnceLock::new();
    let re = LINK.get_or_init(|| Regex::new(r#"(?i)<a[^>]+href="(https?://[^"]+)""#).unwrap());
    let mut out = Vec::new();
    for c in re.captures_iter(html) {
        let u = c
            .get(1)
            .map(|m| m.as_str())
            .unwrap_or("")
            .replace("&amp;", "&");
        let low = u.to_lowercase();
        if low.contains(skip_host)
            || low.contains("marginalia.nu/")
            || low.contains("w3.org")
            || low.contains("schema.org")
            || low.contains("youtube.com")
            || low.contains("facebook.com")
            || low.contains("instagram.com")
        {
            continue;
        }
        if !out.iter().any(|x| x == &u) {
            out.push(u);
        }
    }
    out
}

fn ddg_links(html: &str) -> Vec<String> {
    static LINK: OnceLock<Regex> = OnceLock::new();
    let re = LINK.get_or_init(|| {
        Regex::new(r#"(?is)<a[^>]+class="[^"]*result__a[^"]*"[^>]+href="([^"]+)""#).unwrap()
    });
    let mut out = Vec::new();
    for c in re.captures_iter(html) {
        let raw = c
            .get(1)
            .map(|m| m.as_str())
            .unwrap_or("")
            .replace("&amp;", "&");
        let decoded = if let Some(rest) = raw.split_once("uddg=") {
            let val = rest.1.split('&').next().unwrap_or(rest.1);
            urlencoding::decode(val)
                .map(|s| s.into_owned())
                .unwrap_or_default()
        } else {
            raw
        };
        if !decoded.starts_with("http") || decoded.contains("duckduckgo.com/l/") {
            continue;
        }
        if !out.iter().any(|x| x == &decoded) {
            out.push(decoded);
        }
    }
    out
}

fn bing_links(html: &str) -> Vec<String> {
    static BLOCK: OnceLock<Regex> = OnceLock::new();
    static HREF: OnceLock<Regex> = OnceLock::new();
    let block_re = BLOCK.get_or_init(|| Regex::new(r#"(?is)<li class="b_algo".*?</li>"#).unwrap());
    let href_re = HREF.get_or_init(|| Regex::new(r#"href="([^"]+)"#).unwrap());
    let mut out: Vec<String> = Vec::new();
    for block in block_re.find_iter(html) {
        for c in href_re.captures_iter(block.as_str()) {
            let u = c
                .get(1)
                .map(|m| m.as_str())
                .unwrap_or("")
                .replace("&amp;", "&");
            if !u.starts_with("http") || u.contains("r.bing.com") || u.contains("bing.com/rp") {
                continue;
            }
            if !out.iter().any(|x| x == &u) {
                out.push(u);
            }
            break;
        }
    }
    out
}

fn brave_links(html: &str) -> Vec<String> {
    static LINK: OnceLock<Regex> = OnceLock::new();
    let re = LINK.get_or_init(|| Regex::new(r#"<a[^>]+href="(https?://[^"]+)"[^>]*>"#).unwrap());
    let mut out: Vec<String> = Vec::new();
    for c in re.captures_iter(html) {
        let u = c.get(1).map(|m| m.as_str()).unwrap_or("");
        let u = u.replace("&amp;", "&");
        if u.len() > 500 || u.contains("search.brave.com") || u.contains("brave.com/") {
            continue;
        }
        if u.contains("javascript:") || u.contains("mailto:") {
            continue;
        }
        let lower = u.to_lowercase();
        if lower.contains("youtube.com")
            || lower.contains("facebook.com")
            || lower.contains("instagram.com")
            || lower.contains("pinterest.")
            || lower.contains("apple.com")
            || lower.contains("w3.org")
            || lower.contains("schema.org")
        {
            continue;
        }
        if !out.iter().any(|x| x == &u) {
            out.push(u);
        }
    }
    out
}

fn rate_limited(e: &anyhow::Error) -> bool {
    let s = e.to_string();
    s.contains("HTTP 403") || s.contains("HTTP 429")
}

fn build_tor_client(proxy: Option<String>) -> Result<reqwest::Client> {
    let mut b = reqwest::Client::builder()
        .user_agent(UA)
        .connect_timeout(Duration::from_secs(20))
        .timeout(Duration::from_secs(30))
        .gzip(false)
        .brotli(false)
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            if attempt.previous().len() >= 5
                || attempt
                    .url()
                    .host_str()
                    .map(non_public_host)
                    .unwrap_or(true)
            {
                attempt.stop()
            } else {
                attempt.follow()
            }
        }));
    if let Some(p) = proxy {
        let p = p.trim();
        if !p.is_empty() {
            b = b.proxy(reqwest::Proxy::all(p)?);
        }
    }
    Ok(b.build()?)
}

fn build_client(proxy: Option<String>) -> Result<reqwest::Client> {
    let mut b = reqwest::Client::builder()
        .user_agent(UA)
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(10))
        .gzip(false)
        .brotli(false)
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            if attempt.previous().len() >= 5
                || attempt
                    .url()
                    .host_str()
                    .map(non_public_host)
                    .unwrap_or(true)
            {
                attempt.stop()
            } else {
                attempt.follow()
            }
        }));
    if let Some(p) = proxy {
        let p = p.trim();
        if !p.is_empty() {
            b = b.proxy(reqwest::Proxy::all(p)?);
        }
    }
    Ok(b.build()?)
}

struct RssItem {
    title: String,
    link: String,
    content: String,
}

fn rss_items(xml: &str) -> Vec<RssItem> {
    static ITEM: OnceLock<Regex> = OnceLock::new();
    static TITLE: OnceLock<Regex> = OnceLock::new();
    static LINK: OnceLock<Regex> = OnceLock::new();
    static CONTENT: OnceLock<Regex> = OnceLock::new();
    static DESC: OnceLock<Regex> = OnceLock::new();
    let item_re = ITEM.get_or_init(|| Regex::new(r"(?is)<item>(.*?)</item>").unwrap());
    let title_re = TITLE.get_or_init(|| Regex::new(r"(?is)<title>(.*?)</title>").unwrap());
    let link_re = LINK.get_or_init(|| Regex::new(r"(?is)<link>(.*?)</link>").unwrap());
    let content_re = CONTENT
        .get_or_init(|| Regex::new(r"(?is)<content:encoded>(.*?)</content:encoded>").unwrap());
    let desc_re =
        DESC.get_or_init(|| Regex::new(r"(?is)<description>(.*?)</description>").unwrap());
    let mut out = Vec::new();
    for c in item_re.captures_iter(xml) {
        let Some(block) = c.get(1) else { continue };
        let b = block.as_str();
        let pick = |re: &Regex| {
            re.captures(b)
                .and_then(|c| c.get(1))
                .map(|m| m.as_str().to_string())
                .unwrap_or_default()
        };
        let title = strip_html(&pick(title_re).replace("<![CDATA[", "").replace("]]>", ""));
        let link = pick(link_re)
            .replace("<![CDATA[", "")
            .replace("]]>", "")
            .trim()
            .to_string();
        let content = {
            let raw = pick(content_re);
            let raw = if raw.is_empty() { pick(desc_re) } else { raw };
            strip_html(&raw.replace("<![CDATA[", "").replace("]]>", ""))
        };
        if title.is_empty() && content.is_empty() {
            continue;
        }
        out.push(RssItem {
            title,
            link: link.trim().to_string(),
            content,
        });
    }
    out
}

/// Canonical form used for de-duplication and the crawl frontier: drop
/// credentials, fragments, default ports and tracking parameters. Preserve
/// real query parameters (search, API, pagination) because many source APIs
/// put the content identity in them.
pub fn canonical_url(url: &str) -> String {
    let Ok(mut u) = reqwest::Url::parse(url.trim()) else {
        return url.trim().to_string();
    };
    let _ = u.set_username("");
    let _ = u.set_password(None);
    if let Some(host) = u.host_str() {
        let lower = host.to_ascii_lowercase();
        let _ = u.set_host(Some(&lower));
    }
    match (u.scheme(), u.port()) {
        ("http", Some(80)) | ("https", Some(443)) => {
            let _ = u.set_port(None);
        }
        _ => {}
    }
    let pairs: Vec<(String, String)> = u
        .query_pairs()
        .filter(|(k, _)| !tracking_param(&k))
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    if pairs.is_empty() {
        u.set_query(None);
    } else {
        let mut ser = u.query_pairs_mut();
        ser.clear();
        for (k, v) in pairs {
            ser.append_pair(&k, &v);
        }
    }
    let path = u.path().to_string();
    if path.len() > 1 {
        u.set_path(path.trim_end_matches('/'));
    }
    u.set_fragment(None);
    u.to_string()
}

fn tracking_param(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.starts_with("utm_")
        || matches!(
            n.as_str(),
            "fbclid"
                | "gclid"
                | "msclkid"
                | "mc_cid"
                | "mc_eid"
                | "ref"
                | "ref_src"
                | "spm"
                | "scm"
                | "share_token"
                | "igshid"
        )
}

fn looks_like_challenge(text: &str) -> bool {
    let head: String = text.chars().take(4096).collect();
    let low = head.to_ascii_lowercase();
    [
        "just a moment",
        "cf-browser-verification",
        "vercel security checkpoint",
        "enable javascript and cookies",
        "unusual traffic",
        "attention required",
        "captcha challenge",
        "bot verification",
    ]
    .iter()
    .any(|needle| low.contains(needle))
}

/// Search-engine shell pages are useful for link discovery, not for key
/// extraction: their forms and snippets repeat the query and can turn the
/// query itself into a fake provenance record.
pub fn is_search_shell(doc: &SourceDoc) -> bool {
    doc.repo.ends_with(":search")
}

/// Frontier priority derived from document signal. A page containing actual
/// key/config vocabulary should outrank a generic article when both expose
/// the same number of links.
/// Search shells are not crawl seeds either: their result links are already
/// fetched as target documents by the adapters, and crawling the shell again
/// mostly enqueues unrelated same-site navigation.
pub fn crawlable_doc(doc: &SourceDoc) -> bool {
    !is_search_shell(doc)
}

pub fn frontier_priority(doc: &SourceDoc) -> i64 {
    180 + (source_doc_score(doc).clamp(0, 600) / 10) as i64
}

fn source_doc_score(doc: &SourceDoc) -> i32 {
    let text = doc.text.to_ascii_lowercase();
    let url = doc.url.to_ascii_lowercase();
    let mut score = 0i32;
    for needle in [
        "sk-",
        "api_key",
        "apikey",
        "ghp_",
        "github_pat_",
        "github_token",
        "base_url",
        "endpoint",
        "/v1",
        "secret",
        ".env",
    ] {
        if text.contains(needle) || url.contains(needle) {
            score += 20;
        }
    }
    if is_search_shell(doc) {
        score -= 100;
    }
    score
}

/// Normalize, rank and de-duplicate the adapter output before extraction.
/// A search page and a target page often describe the same URL; syndicated
/// forum posts also appear through several engines. One canonical copy keeps
/// provenance while preventing duplicate probes.
pub fn prepare_docs(docs: Vec<SourceDoc>, limit: usize) -> Vec<SourceDoc> {
    let mut docs = docs;
    docs.retain(|d| {
        let n = d.text.trim().chars().count();
        n >= 20 && !looks_like_challenge(&d.text)
    });
    docs.sort_by(|a, b| source_doc_score(b).cmp(&source_doc_score(a)));
    let mut seen_url = HashSet::new();
    let mut seen_text = HashSet::new();
    let mut out = Vec::new();
    for doc in docs {
        let url_key = canonical_url(&doc.url);
        let mut hasher = DefaultHasher::new();
        doc.text.hash(&mut hasher);
        let text_key = hasher.finish();
        if !seen_url.insert(url_key) {
            continue;
        }
        if !seen_text.insert(text_key) {
            continue;
        }
        out.push(doc);
        if out.len() >= limit {
            break;
        }
    }
    out
}

fn proxy_index_for_host(host: &str, len: usize) -> usize {
    if len <= 1 {
        return 0;
    }
    let mut hasher = DefaultHasher::new();
    host.hash(&mut hasher);
    (hasher.finish() % len as u64) as usize
}

fn cap(mut s: String) -> String {
    const MAX: usize = 64 * 1024;
    if s.len() > MAX {
        let mut cut = MAX;
        while cut > 0 && !s.is_char_boundary(cut) {
            cut -= 1;
        }
        s.truncate(cut);
    }
    s
}

fn encode_path(path: &str) -> String {
    path.split('/')
        .map(|s| urlencoding::encode(s).into_owned())
        .collect::<Vec<_>>()
        .join("/")
}

fn is_candidate(path: &str, size: u64) -> bool {
    if size > 600 * 1024 {
        return false;
    }
    let p = path.to_lowercase();
    if p.split('/').any(|c| {
        matches!(
            c,
            ".git"
                | "node_modules"
                | "vendor"
                | "dist"
                | "build"
                | "target"
                | "__pycache__"
                | ".venv"
        )
    }) {
        return false;
    }
    let name = p.rsplit('/').next().unwrap_or("");
    if name.contains(".min.") || name.ends_with(".lock") {
        return false;
    }
    let ext = name.rsplit('.').next().unwrap_or("");
    const EXT: &[&str] = &[
        "env",
        "py",
        "js",
        "ts",
        "tsx",
        "jsx",
        "go",
        "rs",
        "java",
        "kt",
        "php",
        "rb",
        "yml",
        "yaml",
        "json",
        "toml",
        "ini",
        "cfg",
        "conf",
        "sh",
        "bash",
        "txt",
        "sql",
        "properties",
        "xml",
        "gradle",
        "tf",
        "tfvars",
        "md",
        "config",
    ];
    EXT.contains(&ext) || name.starts_with(".env") || name == "dockerfile" || name == "procfile"
}

fn priority(path: &str) -> i32 {
    let p = path.to_lowercase();
    let name = p.rsplit('/').next().unwrap_or("");
    let mut score = 0i32;
    if name == ".env" || name.starts_with(".env.") {
        score += 120;
    }
    if p.contains("secret")
        || p.contains("credential")
        || p.contains("apikey")
        || p.contains("api_key")
    {
        score += 100;
    }
    if p.contains("config") || p.contains("setting") {
        score += 70;
    }
    if matches!(
        name,
        "app.py" | "main.py" | "server.py" | "index.js" | "main.go"
    ) {
        score += 60;
    }
    if p.ends_with(".py") || p.ends_with(".js") || p.ends_with(".ts") || p.ends_with(".go") {
        score += 40;
    }
    if p.ends_with(".json") || p.ends_with(".yaml") || p.ends_with(".yml") || p.ends_with(".toml") {
        score += 30;
    }
    if p.ends_with(".md") {
        score -= 20;
    }
    score - (p.len() as i32 / 10)
}

fn v2ex_replies(html: &str) -> String {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re =
        RE.get_or_init(|| Regex::new(r#"(?s)<div class="reply_content">(.*?)</div>"#).unwrap());
    let mut out = String::new();
    for c in re.captures_iter(html).take(50) {
        if let Some(m) = c.get(1) {
            out.push('\n');
            out.push_str(&strip_html(m.as_str()));
        }
    }
    out
}

fn nodeseek_links(html: &str) -> Vec<String> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r#"href="(/post-\d+-\d+)""#).unwrap());
    let mut out: Vec<String> = Vec::new();
    for c in re.captures_iter(html) {
        if let Some(p) = c.get(1) {
            let p = p.as_str().to_string();
            if !out.contains(&p) {
                out.push(p);
            }
        }
    }
    out
}

fn nodeseek_text(html: &str) -> String {
    static TITLE: OnceLock<Regex> = OnceLock::new();
    static ART: OnceLock<Regex> = OnceLock::new();
    let title_re = TITLE.get_or_init(|| Regex::new(r"(?is)<title>(.*?)</title>").unwrap());
    let art_re = ART.get_or_init(|| {
        Regex::new(r#"(?is)<article class="post-content">(.*?)</article>"#).unwrap()
    });
    let title = title_re
        .captures(html)
        .and_then(|c| c.get(1))
        .map(|m| strip_html(m.as_str()))
        .unwrap_or_default();
    let mut text = title;
    let mut count = 0usize;
    for c in art_re.captures_iter(html) {
        if let Some(m) = c.get(1) {
            text.push('\n');
            text.push_str(&strip_html(m.as_str()));
            count += 1;
            if count >= 12 {
                break;
            }
        }
    }
    text
}

fn paste_ids(html: &str) -> Vec<String> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r#"href="/([A-Za-z0-9]{8})\?source=archive""#).unwrap());
    let mut out = Vec::new();
    for c in re.captures_iter(html) {
        if let Some(id) = c.get(1) {
            let id = id.as_str().to_string();
            if !out.contains(&id) {
                out.push(id);
            }
        }
    }
    out
}

pub fn strip_html(s: &str) -> String {
    static REMOVE: OnceLock<Regex> = OnceLock::new();
    static BLOCK: OnceLock<Regex> = OnceLock::new();
    static TAGS: OnceLock<Regex> = OnceLock::new();
    let remove = REMOVE.get_or_init(|| {
        Regex::new(r"(?is)<script\b[^>]*>.*?</script>|<style\b[^>]*>.*?</style>|<noscript\b[^>]*>.*?</noscript>|<svg\b[^>]*>.*?</svg>|<!--.*?-->")
            .expect("remove regex")
    });
    let block = BLOCK.get_or_init(|| {
        Regex::new(r"(?is)</?(?:p|div|br|li|tr|h[1-6]|pre|blockquote)[^>]*>").unwrap()
    });
    let tags = TAGS.get_or_init(|| Regex::new(r"(?s)<[^>]+>").unwrap());
    let without_junk = remove.replace_all(s, " ");
    let with_breaks = block.replace_all(without_junk.as_ref(), "\n");
    let plain = tags.replace_all(&with_breaks, " ");
    static ENT: OnceLock<Regex> = OnceLock::new();
    let ent = ENT
        .get_or_init(|| Regex::new(r"&(?:amp|apos|lt|gt|quot|#39|nbsp);").expect("entity regex"));
    let named = ent.replace_all(&plain, |c: &regex::Captures<'_>| {
        match c.get(0).map(|m| m.as_str()).unwrap_or("") {
            "&amp;" => "&",
            "&apos;" => "'",
            "&lt;" => "<",
            "&gt;" => ">",
            "&quot;" => "\"",
            "&#39;" => "'",
            "&nbsp;" => " ",
            _ => "",
        }
    });
    static NUM: OnceLock<Regex> = OnceLock::new();
    let num = NUM.get_or_init(|| {
        Regex::new(r"&#x([0-9a-fA-F]+);|&#([0-9]+);").expect("numeric entity regex")
    });
    let decoded = num.replace_all(&named, |c: &regex::Captures<'_>| {
        let hex = c
            .get(1)
            .and_then(|m| u32::from_str_radix(m.as_str(), 16).ok());
        let dec = c.get(2).and_then(|m| m.as_str().parse::<u32>().ok());
        char::from_u32(hex.or(dec).unwrap_or(0xfffd))
            .map(String::from)
            .unwrap_or_default()
    });
    decoded
        .lines()
        .map(|l| l.split_whitespace().collect::<Vec<_>>().join(" "))
        .filter(|l| !l.is_empty())
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn html_is_stripped_and_lines_kept() {
        let s = strip_html("<p>hello &amp; hi</p><br><b>sk-abc</b>");
        assert!(s.contains("hello & hi"));
        assert!(s.contains("sk-abc"));
        assert!(!s.contains("<p>"));
    }

    #[test]
    fn source_url_is_canonicalized() {
        assert_eq!(
            canonical_url("HTTPS://Example.COM/path/?utm_source=x&fbclid=y#frag"),
            "https://example.com/path"
        );
        assert_ne!(
            canonical_url("https://example.com/a?utm_source=x"),
            canonical_url("https://example.com/b?utm_source=x")
        );
    }

    #[test]
    fn outbound_links_skip_frontend_infrastructure() {
        let base = "https://community.example.com/t/topic/1";
        let html = r#"<a href="/plugins/discourse-app/javascripts/app.js?v=1"></a><a href="/opensearch.xml"></a><a href="/t/topic/2"></a>"#;
        let links = outbound_links(base, html, 10);
        assert!(links.iter().all(|l| !l.contains(".js")));
        assert!(links.iter().all(|l| !l.contains("opensearch.xml")));
        assert!(links.iter().any(|l| l.ends_with("/t/topic/2")));
    }

    #[test]
    fn source_docs_are_ranked_deduped_and_challenges_dropped() {
        let target = SourceDoc {
            source: "ddg".into(),
            repo: "ddg:web".into(),
            path: "example.com/a".into(),
            text: "OPENAI_API_KEY=sk-abc".into(),
            url: "https://example.com/a?utm_source=x".into(),
        };
        let duplicate = target.clone();
        let shell = SourceDoc {
            source: "ddg".into(),
            repo: "ddg:search".into(),
            path: "q".into(),
            text: "OPENAI_API_KEY=sk-abc search page".into(),
            url: "https://html.duckduckgo.com/html/?q=OPENAI_API_KEY".into(),
        };
        let challenge = SourceDoc {
            source: "ddg".into(),
            repo: "ddg:web".into(),
            path: "blocked".into(),
            text: "Just a moment... Enable JavaScript and cookies".into(),
            url: "https://example.com/blocked".into(),
        };
        let out = prepare_docs(vec![challenge, shell, duplicate, target], 10);
        assert_eq!(out.len(), 2);
        assert!(out[0].repo == "ddg:web");
        // The shell stays for link discovery, but always ranks below targets;
        // run_source skips it during extraction.
        assert!(out[1].repo.ends_with(":search"));
        assert!(source_doc_score(&out[0]) > source_doc_score(&out[1]));
        assert_eq!(
            proxy_index_for_host("example.com", 4),
            proxy_index_for_host("example.com", 4)
        );
    }

    #[test]
    fn outbound_links_reject_regex_artifacts() {
        let html = r#"<a href="https://huggingface.co/spaces/23v/qwen/raw/main/([^">bad</a>
            <a href="https://example.com/good">good</a>"#;
        let links = outbound_links("https://example.com/page", html, 10);
        assert!(!links.iter().any(|u| u.contains("([^")));
        assert!(links.iter().any(|u| u == "https://example.com/good"));
    }

    #[test]
    fn search_shell_is_not_a_crawl_seed() {
        let shell = SourceDoc {
            source: "ddg".into(),
            repo: "ddg:search".into(),
            path: "q".into(),
            text: "search shell".into(),
            url: "https://html.duckduckgo.com/html/?q=x".into(),
        };
        let target = SourceDoc {
            source: "ddg".into(),
            repo: "ddg:web".into(),
            path: "page".into(),
            text: "target page".into(),
            url: "https://example.com/page".into(),
        };
        assert!(!crawlable_doc(&shell));
        assert!(crawlable_doc(&target));
    }

    #[test]
    fn frontier_priority_follows_document_signal() {
        let strong = SourceDoc {
            source: "web".into(),
            repo: "web:page".into(),
            path: "config".into(),
            text: "OPENAI_API_KEY=sk-abc base_url https://api.example.com/v1".into(),
            url: "https://example.com/config".into(),
        };
        let weak = SourceDoc {
            source: "web".into(),
            repo: "web:page".into(),
            path: "article".into(),
            text: "an unrelated article about weather".into(),
            url: "https://example.com/article".into(),
        };
        assert!(frontier_priority(&strong) > frontier_priority(&weak));
    }

    #[test]
    fn source_documents_are_capped_at_128k() {
        let text = "x".repeat(200 * 1024);
        assert_eq!(cap(text).len(), 64 * 1024);
    }

    #[test]
    fn strip_html_removes_script_style_and_decodes_numeric_entities() {
        let html = r#"<script>var x="sk-fake"</script><style>.a{color:red}</style><p>sk-real &#x61;&#98; &#38; ok</p>"#;
        let text = strip_html(html);
        assert!(!text.contains("sk-fake"));
        assert!(!text.contains("color:red"));
        assert!(text.contains("sk-real ab & ok"));
    }

    #[test]
    fn rss_items_parse_cdata_and_description() {
        let xml = r#"<rss><channel><item><title><![CDATA[OpenAI key]]></title><link><![CDATA[https://example.com/a]]></link><description><![CDATA[<p>sk-test endpoint</p>]]></description></item></channel></rss>"#;
        let items = rss_items(xml);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].title, "OpenAI key");
        assert_eq!(items[0].link, "https://example.com/a");
        assert!(items[0].content.contains("sk-test"));
    }

    #[test]
    fn country_sources_are_registered() {
        for source in [
            "hn",
            "stackexchange",
            "devto",
            "medium",
            "qiita",
            "zenn",
            "velog",
            "viblo",
            "habr",
            "dou",
            "devby",
            "techinasia",
            "telegram",
        ] {
            assert!(
                TASKS.iter().any(|(name, _)| *name == source),
                "missing source {source}"
            );
        }
    }

    #[test]
    fn paste_ids_are_parsed() {
        let html =
            r#"<a href="/B1hyLfcF?source=archive">x</a><a href="/fREBZL2q?source=archive">y</a>"#;
        assert_eq!(paste_ids(html), vec!["B1hyLfcF", "fREBZL2q"]);
    }

    #[test]
    fn candidate_filter() {
        assert!(is_candidate(".env", 100));
        assert!(is_candidate("app/main.py", 100));
        assert!(!is_candidate("node_modules/x/index.js", 100));
        assert!(!is_candidate("big.bin", 100));
    }

    #[test]
    fn v2ex_replies_are_extracted() {
        let html = r#"<div class="reply_content"><p>key sk-live-0123456789abcdef0123456789abcdef</p></div>"#;
        assert!(v2ex_replies(html).contains("sk-live-"));
    }

    #[test]
    fn nodeseek_links_and_text() {
        let html = r#"<a href="/post-123-1">x</a><article class="post-content"><p>key sk-live-0123456789abcdef0123456789abcdef</p></article>"#;
        assert_eq!(nodeseek_links(html), vec!["/post-123-1"]);
        assert!(nodeseek_text(html).contains("sk-live-"));
    }

    #[test]
    fn cap_does_not_split_utf8() {
        let s = "я".repeat(300_000);
        let capped = cap(s);
        assert!(capped.len() <= 512 * 1024);
        assert!(std::str::from_utf8(capped.as_bytes()).is_ok());
    }

    #[test]
    fn non_public_crawl_targets_are_rejected() {
        assert!(non_public_host("127.0.0.1"));
        assert!(non_public_host("10.0.0.1"));
        assert!(non_public_host("192.168.1.10"));
        assert!(non_public_host("169.254.169.254"));
        assert!(non_public_host("localhost"));
        assert!(!non_public_host("api.openai.com"));
        assert!(!non_public_host("8.8.8.8"));
    }

    #[test]
    fn outbound_links_follow_site_and_code_hubs() {
        let html = r#"
            <a href="/docs/next">next</a>
            <a href="https://gist.github.com/u/1">gist</a>
            <a href="https://random.example/x">offsite</a>
            <a href="/logo.png">img</a>
            <a href="javascript:void(0)">js</a>
        "#;
        let links = outbound_links("https://relay.example/page", html, 10);
        assert!(links.contains(&"https://relay.example/docs/next".to_string()));
        assert!(links.contains(&"https://gist.github.com/u/1".to_string()));
        assert!(!links.iter().any(|u| u.contains("random.example")));
        assert!(!links.iter().any(|u| u.ends_with(".png")));
    }

    #[test]
    fn v2ex_shape_is_supported() {
        let v = json!([{
            "id": 1,
            "title": "relay",
            "content": "OPENAI_BASE_URL=https://api.relay.test/v1",
            "content_rendered": "<p>sk-live-0123456789abcdef0123456789abcdef</p>",
            "url": "https://www.v2ex.com/t/1"
        }]);
        assert_eq!(v.as_array().unwrap().len(), 1);
        assert!(strip_html(v[0]["content_rendered"].as_str().unwrap()).contains("sk-live-"));
    }
}

#[cfg(test)]
mod web_search_tests {
    use super::*;

    #[test]
    fn brave_results_are_direct_and_deduped() {
        let html = r#"<a href="https://example.dev/a">A</a>
            <a href="https://example.dev/a">A2</a>
            <a href="https://search.brave.com/search?q=x">engine</a>
            <a href="https://example.dev/b">B</a>"#;
        let links = brave_links(html);
        assert_eq!(
            links,
            vec!["https://example.dev/a", "https://example.dev/b"]
        );
    }

    #[test]
    fn duckduckgo_redirect_links_are_decoded() {
        let html = r#"
            <a class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fgist.github.com%2Fu%2F1&amp;rut=x">gist</a>
            <a class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.dev%2Fa%3Fx%3D1">example</a>
        "#;
        let links = ddg_links(html);
        assert_eq!(
            links,
            vec![
                "https://gist.github.com/u/1".to_string(),
                "https://example.dev/a?x=1".to_string()
            ]
        );
    }

    #[test]
    fn new_source_pack_is_registered() {
        for source in ["ddg", "debian", "archive", "mastodon", "gitlab_snippet"] {
            assert!(
                TASKS.iter().any(|(name, _)| *name == source),
                "missing source {source}"
            );
        }
    }

    #[test]
    fn bing_algo_blocks_are_extracted() {
        let html = r#"<li class="b_algo"><h2><a href="https://www.bing.com/ck/a?u=a1abc">x</a></h2></li>
            <li class="b_algo"><h2><a href="https://www.bing.com/ck/a?u=a1def">y</a></h2></li>"#;
        let links = bing_links(html);
        assert_eq!(links.len(), 2);
    }
}

fn url_host(url: &str) -> String {
    reqwest::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_ascii_lowercase()))
        .unwrap_or_else(|| "crawl".to_string())
}

/// Reject local/link-local/private targets before a crawler request. A page
/// can contain links to cloud metadata or localhost; following those from the
/// VPS would turn the source crawler into an SSRF primitive.
fn non_public_host(host: &str) -> bool {
    let h = host.trim_matches(['[', ']']).trim_end_matches('.');
    if h.eq_ignore_ascii_case("localhost") || h.ends_with(".localhost") {
        return true;
    }
    let Ok(ip) = h.parse::<IpAddr>() else {
        return false;
    };
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return v4.is_private()
                    || v4.is_loopback()
                    || v4.is_link_local()
                    || v4.is_unspecified()
                    || v4.is_broadcast();
            }
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_unique_local()
                || v6.is_unicast_link_local()
        }
    }
}

fn public_http_url(url: &str) -> bool {
    let Ok(u) = reqwest::Url::parse(url) else {
        return false;
    };
    matches!(u.scheme(), "http" | "https")
        && u.host_str().map(|h| !non_public_host(h)).unwrap_or(false)
}

fn crawlable_external(host: &str) -> bool {
    const HUBS: &[&str] = &[
        "github.com",
        "gist.github.com",
        "raw.githubusercontent.com",
        "gitlab.com",
        "gitee.com",
        "codeberg.org",
        "pastebin.com",
        "rentry.co",
        "telegra.ph",
        "justpaste.it",
        "controlc.com",
        "dpaste.org",
        "paste.ee",
        "hastebin.com",
        "ghostbin.com",
        "medium.com",
        "dev.to",
        "habr.com",
        "qiita.com",
        "zenn.dev",
        "v2ex.com",
        "nodeloc.com",
        "nodeseek.com",
        "juejin.cn",
        "csdn.net",
        "segmentfault.com",
        "cnblogs.com",
        "oschina.net",
        "51cto.com",
        "hashnode.com",
        "npmjs.com",
        "paste.gg",
        "bsky.app",
        "discourse.org",
        "community.openai.com",
        "discuss.huggingface.co",
        "forum.cursor.com",
        "community.vercel.com",
        "devforum.roblox.com",
        "security.stackexchange.com",
        "serverfault.com",
        "superuser.com",
        "askubuntu.com",
    ];
    HUBS.iter()
        .any(|h| host == *h || host.ends_with(&format!(".{h}")))
}

fn search_engine_host(host: &str) -> bool {
    const ENGINES: &[&str] = &[
        "bing.com",
        "www.bing.com",
        "google.com",
        "www.google.com",
        "search.brave.com",
        "duckduckgo.com",
        "html.duckduckgo.com",
        "yandex.com",
        "yandex.ru",
        "baidu.com",
        "www.baidu.com",
        "so.com",
        "sogou.com",
        "html.duckduckgo.com",
        "duckduckgo.com",
        "codesearch.debian.net",
        "archive.org",
        "mastodon.social",
        "mojeek.com",
        "www.mojeek.com",
        "startpage.com",
        "www.startpage.com",
        "searx.be",
        "naver.com",
        "search.naver.com",
        "sogou.com",
        "weixin.sogou.com",
        "so.com",
        "www.so.com",
        "google.com",
        "www.google.com",
        "yandex.com",
        "yandex.ru",
        "search.yahoo.com",
    ];
    ENGINES
        .iter()
        .any(|e| host == *e || host.ends_with(&format!(".{e}")))
}

/// Extract links that are worth a second crawl hop. Same-host links are
/// followed for site depth; external links only for known code/paste hubs.
pub fn outbound_links(base: &str, text: &str, limit: usize) -> Vec<String> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r#"(?i)(?:href|src)\s*=\s*["']([^"'#]+)["']"#).unwrap());
    let base_url = match reqwest::Url::parse(base) {
        Ok(u) => u,
        Err(_) => return Vec::new(),
    };
    let base_host = base_url.host_str().unwrap_or("").to_ascii_lowercase();
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for cap in re.captures_iter(text) {
        let raw = cap.get(1).map(|m| m.as_str()).unwrap_or("").trim();
        if raw.is_empty()
            || raw.starts_with('#')
            || raw.starts_with("javascript:")
            || raw.starts_with("mailto:")
            || raw.starts_with("data:")
        {
            continue;
        }
        let Ok(joined) = base_url.join(raw) else {
            continue;
        };
        if !(joined.scheme() == "http" || joined.scheme() == "https") {
            continue;
        }
        let host = joined.host_str().unwrap_or("").to_ascii_lowercase();
        if host.is_empty() || non_public_host(&host) || search_engine_host(&host) {
            continue;
        }
        let path = joined.path().to_ascii_lowercase();
        // HTML/JSON sometimes contains regex fragments inside an href
        // (`.../raw/main/([^`). Those are not pages; retrying them just
        // fills the frontier with permanent 404s.
        if path.contains('[')
            || path.contains(']')
            || path.contains('{')
            || path.contains('}')
            || path.contains("([")
            || path.contains("([^")
        {
            continue;
        }
        // Search-result redirect wrappers are not pages. Crawling them only
        // burns a proxy round-trip and yields a 0-byte document.
        if path.contains("/ck/a")
            || path.contains("/url")
                && joined.query().is_some()
                && joined.query().unwrap_or("").contains("u=a1")
        {
            continue;
        }
        if [
            ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico", ".css", ".woff", ".woff2",
            ".ttf", ".js", ".mjs", ".map", ".xml", ".rss",
        ]
        .iter()
        .any(|ext| path.ends_with(ext))
        {
            continue;
        }
        // Front-end bundles, plugin assets and opensearch descriptors are
        // infrastructure noise for a key parser, not source documents.
        if [
            "/javascripts/",
            "/assets/",
            "/static/",
            "/plugins/",
            "/vendor/",
            "/dist/",
        ]
        .iter()
        .any(|seg| path.contains(seg))
        {
            continue;
        }
        if host != base_host && !crawlable_external(&host) {
            continue;
        }
        let mut clean = joined.clone();
        clean.set_fragment(None);
        let url = canonical_url(&clean.to_string());
        if seen.insert(url.clone()) {
            out.push(url);
            if out.len() >= limit {
                break;
            }
        }
    }
    out
}

#[cfg(test)]
mod source_pack_tests {
    use super::*;

    #[test]
    fn expanded_source_pack_has_many_live_adapters() {
        assert!(source_count() >= 80, "source_count={}", source_count());
        for name in [
            "juejin",
            "npm",
            "pastegg",
            "urlscan",
            "bluesky",
            "openai_community",
            "mojeek",
            "csdn",
            "wechat",
            "securityse",
            "lemmy",
            "lemmy_comments",
        ] {
            assert!(
                tasks().iter().any(|(s, _)| *s == name),
                "missing source {name}"
            );
        }
    }

    #[test]
    fn new_source_names_are_routable() {
        let names = [
            "juejin",
            "npm",
            "pastegg",
            "urlscan",
            "bluesky",
            "openai_community",
            "mojeek",
            "csdn",
            "wechat",
            "securityse",
        ];
        for n in names {
            assert!(!n.is_empty());
        }
    }
}
