use crate::app::{App, Job, JobKind};
use crate::extract::{self, KeyKind};
use crate::format;
use crate::probe::{PStatus, ProbeOutcome};
use crate::store::{now, NewFinding};
use anyhow::Result;
use futures::stream::{self, StreamExt};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

#[derive(Clone, Debug)]
struct FileRef {
    repo: String,
    path: String,
    sha: String,
}

#[derive(Clone, Debug)]
struct FoundPair {
    endpoint: String,
    key: String,
    kind: KeyKind,
    repo: String,
    path: String,
    commit: String,
    source: String,
    pair: bool,
}

fn is_official_pair(p: &FoundPair) -> bool {
    extract::is_priority_official_endpoint(&p.endpoint)
        || extract::host_of(&p.endpoint).contains("dashscope")
        || extract::is_dashscope_workspace_endpoint(&p.endpoint)
        || p.key.starts_with("sk-ws-")
}

#[derive(Clone, Debug, Default)]
struct FileResult {
    repo: String,
    pairs: Vec<FoundPair>,
    endpoints: Vec<String>,
}

#[derive(Clone, Debug, Default)]
struct Summary {
    files: usize,
    pairs: usize,
    skipped: usize,
    snippets: usize,
    probed: usize,
    valid: usize,
    cards: usize,
}

pub fn spawn_workers(app: Arc<App>, rx: mpsc::Receiver<Job>, n: usize) {
    struct ActiveGuard(Arc<App>);
    impl Drop for ActiveGuard {
        fn drop(&mut self) {
            self.0.active_jobs.fetch_sub(1, Ordering::Relaxed);
        }
    }
    let rx = Arc::new(tokio::sync::Mutex::new(rx));
    for _ in 0..n.max(1) {
        let app = app.clone();
        let rx = rx.clone();
        tokio::spawn(async move {
            loop {
                let job = {
                    let mut guard = rx.lock().await;
                    guard.recv().await
                };
                let Some(job) = job else { break };
                app.active_jobs.fetch_add(1, Ordering::Relaxed);
                let _guard = ActiveGuard(app.clone());
                if let Err(e) = run_job(app.clone(), &job).await {
                    warn!("job {} failed: {e}", job.id);
                }
            }
        });
    }
}

async fn update_manual_batch(app: &Arc<App>, job: &Job) {
    if !job.manual {
        return;
    }
    let batch = {
        let batches = app.manual_batches.lock().unwrap_or_else(|e| e.into_inner());
        batches.get(&job.chat_id).cloned()
    };
    let Some(batch) = batch else {
        return;
    };
    let Some((done, total)) = batch.mark_done(job.id) else {
        return;
    };
    if !batch.should_edit(done) {
        return;
    }
    let mid = batch.message_id.load(std::sync::atomic::Ordering::Relaxed);
    if mid > 0 {
        let _ = app
            .tg
            .edit(job.chat_id, mid, &batch.progress_text(done), None)
            .await;
    }
    if done >= total {
        let mut batches = app.manual_batches.lock().unwrap_or_else(|e| e.into_inner());
        batches.remove(&job.chat_id);
    }
}

async fn run_job(app: Arc<App>, job: &Job) -> Result<()> {
    let started = Instant::now();
    let label = match job.kind {
        JobKind::Search => "поиск",
        JobKind::Repo => "репозиторий",
        JobKind::Discover => "repo-hunt",
        JobKind::Manual => "проверка",
        JobKind::Source => "источники",
    };
    let mid = if job.quiet {
        0
    } else {
        app.tg
            .send(
                job.chat_id,
                &format!(
                    "🔍 <b>Скан #{}</b> · {}\n<code>{}</code>\n\n⏳ Старт…",
                    job.id,
                    label,
                    format::esc(&job.query)
                ),
                None,
            )
            .await
            .unwrap_or(0)
    };

    let result = match job.kind {
        JobKind::Search => run_search(&app, job, mid).await,
        JobKind::Repo => run_repo(&app, job, mid).await,
        JobKind::Discover => run_discover(&app, job).await,
        JobKind::Manual => Ok(Summary::default()),
        JobKind::Source => run_source(&app, job).await,
    };

    match result {
        Ok(sum) => {
            app.store
                .job_finish(job.id, "done", sum.pairs as i64, sum.valid as i64, "");
            update_manual_batch(&app, job).await;
            if job.kind == JobKind::Search {
                app.store.add_query_hits(&job.query, sum.pairs as i64);
            }
            if job.quiet {
                info!(
                    "auto job #{} done: {} files, {} snippet pairs, {} pairs, {} valid, {} cards",
                    job.id, sum.files, sum.snippets, sum.pairs, sum.valid, sum.cards
                );
                return Ok(());
            }
            let elapsed = started.elapsed().as_secs();
            let text = format!(
                "🏁 <b>Скан #{}</b> · готово за {}с\n\
                 <code>{}</code>\n\n\
                 📄 Файлов: <b>{}</b>\n\
                 ✂️ Сниппет-пар: <b>{}</b>\n\
                 🔑 Новых пар endpoint+key: <b>{}</b>\n\
                 ⏭ Известных пропущено: <b>{}</b>\n\
                 🧪 Проверено сейчас: <b>{}</b>\n\
                 ✅ Валидных: <b>{}</b>\n\
                 💬 Карточек: <b>{}</b>",
                job.id,
                elapsed,
                format::esc(&job.query),
                sum.files,
                sum.snippets,
                sum.pairs,
                sum.skipped,
                sum.probed,
                sum.valid,
                sum.cards
            );
            if mid > 0 {
                if let Err(e) = app.tg.edit(job.chat_id, mid, &text, None).await {
                    let msg = e.to_string();
                    if msg.contains("rate limited") {
                        warn!("final edit skipped for job #{}: {msg}", job.id);
                    } else {
                        warn!(
                            "final edit failed for job #{}: {e}; sending a new message",
                            job.id
                        );
                        let _ = app.tg.send(job.chat_id, &text, None).await;
                    }
                }
            } else {
                let _ = app.tg.send(job.chat_id, &text, None).await;
            }
        }
        Err(e) => {
            app.store.job_finish(job.id, "error", 0, 0, &e.to_string());
            update_manual_batch(&app, job).await;
            if job.quiet {
                warn!("auto job #{} error: {e}", job.id);
                return Ok(());
            }
            let text = format!(
                "❌ <b>Скан #{}</b> · ошибка\n<code>{}</code>\n\n{}",
                job.id,
                format::esc(&job.query),
                format::esc(&e.to_string())
            );
            if mid > 0 {
                if let Err(e) = app.tg.edit(job.chat_id, mid, &text, None).await {
                    warn!(
                        "error edit failed for job #{}: {e}; sending a new message",
                        job.id
                    );
                    let _ = app.tg.send(job.chat_id, &text, None).await;
                }
            } else {
                let _ = app.tg.send(job.chat_id, &text, None).await;
            }
        }
    }
    Ok(())
}

async fn run_source(app: &Arc<App>, job: &Job) -> Result<Summary> {
    // Source jobs are the heaviest text buffers in the scanner. Gate them
    // independently of worker count so a manual fan-out cannot consume the
    // entire worker pool and RSS budget.
    let _source_permit = app
        .source_gate
        .acquire()
        .await
        .map_err(|e| anyhow::anyhow!("source gate closed: {e}"))?;
    let raw = job.query.as_str();
    let (source, query) = raw.split_once('|').unwrap_or((raw, ""));
    let limit = app.store.setting_i64("source_docs", 1200).clamp(5, 2000) as usize;
    let timeout_secs = app.store.setting_i64("source_timeout", 45).clamp(5, 180) as u64;
    let mut crawl_depth = 0i64;
    let mut crawl_url: Option<String> = None;
    let mut source = source.to_string();
    let mut query = query.to_string();
    if let Some(rest) = raw.strip_prefix("url:") {
        // url:<depth>:<url> — depth stays outside the URL so the HTTP parser
        // never has to guess where the scheme ends.
        let (d, u) = rest.split_once(':').unwrap_or(("0", rest));
        crawl_depth = d.parse::<i64>().unwrap_or(0).clamp(0, 4);
        if u.starts_with("http://") || u.starts_with("https://") {
            crawl_url = Some(u.to_string());
            source = "crawl".to_string();
            query = u.to_string();
        }
    }
    let mut fetch_failed = false;
    let mut fetch_error: Option<String> = None;
    let fetched = match tokio::time::timeout(Duration::from_secs(timeout_secs), async {
        match crawl_url.as_deref() {
            Some(url) => app.sources.fetch_url(url).await,
            None => app.sources.gather(&source, &query, limit).await,
        }
    })
    .await
    {
        Ok(Ok(docs)) => docs,
        Ok(Err(e)) => {
            warn!("source {source}|{query} failed fast: {e}");
            fetch_failed = true;
            fetch_error = Some(e.to_string());
            Vec::new()
        }
        Err(_) => {
            warn!("source {source}|{query} timed out after {timeout_secs}s");
            fetch_failed = true;
            fetch_error = Some("timeout".to_string());
            Vec::new()
        }
    };
    // Canonicalize, drop challenge/empty pages, rank signal-heavy docs, and
    // remove duplicates before any extractor or probe work.
    let docs = crate::sources::prepare_docs(fetched, limit);
    // Crawl the page graph one hop at a time. Same-host links deepen a site;
    // external links are only followed for code/paste hubs (see sources.rs).
    let max_depth = app.store.setting_i64("source_crawl_depth", 4).clamp(0, 8);
    if crawl_depth < max_depth {
        let mut pushed = 0usize;
        let mut per_host: HashMap<String, usize> = HashMap::new();
        for doc in &docs {
            if !crate::sources::crawlable_doc(doc) {
                continue;
            }
            for link in crate::sources::outbound_links(&doc.url, &doc.text, 8) {
                // One large forum/site must not monopolize the crawl budget.
                // Keep the frontier diverse even when a hub page exposes
                // hundreds of same-host navigation links.
                let host = extract::host_of(&link);
                let n = per_host.entry(host).or_default();
                if *n >= 16 {
                    continue;
                }
                *n += 1;
                app.store.push_frontier(
                    &link,
                    &source,
                    crawl_depth + 1,
                    crate::sources::frontier_priority(doc),
                );
                pushed += 1;
                if pushed >= 80 {
                    break;
                }
            }
            if pushed >= 80 {
                break;
            }
        }
        if pushed > 0 {
            debug!(
                "source crawl: queued {pushed} links at depth {}",
                crawl_depth + 1
            );
        }
    }
    let official_source = crate::official::is_official_query(&query);
    let mut pairs: Vec<FoundPair> = Vec::new();
    for doc in &docs {
        // Search shells are link-discovery documents only. Extracting their
        // form values/snippets would re-record the query as provenance.
        if crate::sources::is_search_shell(doc) {
            continue;
        }
        let ex = extract::extract(&doc.text);
        let endpoints = ex.strong_endpoints();
        for ep in &endpoints {
            let host = extract::host_of(ep);
            app.store.record_host(&host);
            crate::atlas::pivot_host(app, &host, 220);
        }
        for p in ex.pairs {
            pairs.push(FoundPair {
                endpoint: p.endpoint,
                key: p.key,
                kind: p.kind,
                repo: doc.repo.clone(),
                path: doc.path.clone(),
                commit: String::new(),
                source: doc.source.clone(),
                pair: true,
            });
        }
        let mut paired: HashSet<String> = pairs
            .iter()
            .filter(|p| p.repo == doc.repo && p.path == doc.path)
            .map(|p| p.key.clone())
            .collect();
        for k in &ex.keys {
            if paired.contains(&k.key) {
                continue;
            }
            // On forums/pastes an endpoint and a prefixed key in the same
            // block are a pair even when the host does not look "API-ish".
            let near = ex
                .endpoints
                .iter()
                .filter(|e| e.line.abs_diff(k.line) <= 8)
                .min_by_key(|e| e.line.abs_diff(k.line));
            if let Some(ep) = near {
                pairs.push(FoundPair {
                    endpoint: ep.url.clone(),
                    key: k.key.clone(),
                    kind: k.kind,
                    repo: doc.repo.clone(),
                    path: doc.path.clone(),
                    commit: String::new(),
                    source: doc.source.clone(),
                    pair: true,
                });
                paired.insert(k.key.clone());
                continue;
            }
            if let Some(ep) = k.kind.default_endpoint() {
                pairs.push(FoundPair {
                    endpoint: ep.to_string(),
                    key: k.key.clone(),
                    kind: k.kind,
                    repo: doc.repo.clone(),
                    path: doc.path.clone(),
                    commit: String::new(),
                    source: doc.source.clone(),
                    pair: false,
                });
                paired.insert(k.key.clone());
            }
        }
        // Chinese relays frequently hand out bare 32/40/64-hex tokens in
        // forum posts. If such a token sits next to an endpoint, treat it as
        // a key even without a prefix.
        let mut opaque = 0usize;
        for (line, key) in extract::opaque_tokens(&doc.text) {
            if paired.contains(&key) {
                continue;
            }
            let nearest = ex
                .endpoints
                .iter()
                .filter(|e| e.line.abs_diff(line) <= 8)
                .min_by_key(|e| e.line.abs_diff(line));
            if let Some(ep) = nearest {
                pairs.push(FoundPair {
                    endpoint: ep.url.clone(),
                    key: key.clone(),
                    kind: KeyKind::Generic,
                    repo: doc.repo.clone(),
                    path: doc.path.clone(),
                    commit: String::new(),
                    source: doc.source.clone(),
                    pair: true,
                });
                paired.insert(key);
                opaque += 1;
                if opaque >= 20 {
                    break;
                }
            }
        }
    }
    pairs = dedupe(pairs);
    if official_source {
        pairs.retain(is_official_pair);
    }
    let mut sum = Summary {
        files: docs.len(),
        pairs: pairs.len(),
        ..Default::default()
    };
    info!(
        "source {}|{}: {} docs, {} pairs",
        source,
        query,
        docs.len(),
        pairs.len()
    );
    let hits = pairs.len() as i64;
    if crawl_url.is_none() {
        if fetch_failed {
            app.store
                .record_source_failure(&source, &query, "source fetch failed");
        } else {
            app.store.record_source_result(&source, &query, hits);
        }
    }
    if let Some(url) = &crawl_url {
        if fetch_failed {
            let permanent = fetch_error.as_deref().is_some_and(|e| {
                e.contains("HTTP 404")
                    || e.contains("HTTP 410")
                    || e.contains("HTTP 401")
                    || e.contains("HTTP 400")
            });
            if permanent {
                // A dead/forbidden page must not be retried every crawl tick.
                app.store.finish_frontier(url, 0);
            } else {
                // Transient proxy/DNS/timeout: requeue with a short cooldown
                // instead of hammering the same URL in the next scheduler tick.
                app.store.release_frontier(url);
            }
        } else {
            app.store.finish_frontier(url, hits);
        }
    }
    probe_pairs(app, job, pairs, 0, &mut sum).await?;
    Ok(sum)
}

async fn run_discover(app: &Arc<App>, job: &Job) -> Result<Summary> {
    let fresh_days = app.store.setting_i64("search_fresh_days", 0).clamp(0, 3650);
    let queries = repo_queries(if fresh_days > 0 { fresh_days } else { 120 });
    if queries.is_empty() {
        return Ok(Summary::default());
    }
    let idx = app.store.setting_i64("repo_query_idx", 0).max(0) as usize % queries.len();
    let q = queries[idx].clone();
    let v = app.gh.search_repos(&q, 100).await?;
    let mut repos: Vec<(String, i64)> = Vec::new();
    if let Some(items) = v["items"].as_array() {
        for it in items {
            if it["fork"].as_bool().unwrap_or(false) || it["archived"].as_bool().unwrap_or(false) {
                continue;
            }
            if let Some(full) = it["full_name"].as_str() {
                repos.push((
                    full.to_string(),
                    it["stargazers_count"].as_i64().unwrap_or(0),
                ));
            }
        }
    }
    let found = repos.len();
    repos.sort_by(|a, b| b.1.cmp(&a.1));
    let cap = app.store.setting_i64("deep_concurrency", 4).clamp(1, 12) as usize;
    let active = app.store.running_job_count("repo").max(0) as usize;
    let limit = (app.store.setting_i64("discover_repos", 2).clamp(0, 20) as usize)
        .min(cap.saturating_sub(active));
    if limit == 0 {
        return Ok(Summary::default());
    }
    let hours = if !job.manual {
        app.store.setting_i64("deep_hours", 12).max(1)
    } else {
        app.store.setting_i64("manual_deep_hours", 6).max(1)
    };
    let mut queued = 0usize;
    let pat_repo = crate::store::is_pat_query(&q);
    for (repo, _) in repos
        .into_iter()
        .filter(|(r, _)| app.store.needs_deep(r, hours))
        .take(limit)
    {
        let id = app.store.job_start(JobKind::Repo.as_str(), &repo)?;
        let deep = Job {
            id,
            chat_id: job.chat_id,
            kind: JobKind::Repo,
            query: repo.clone(),
            quiet: true,
            manual: job.manual,
            lane: if pat_repo {
                crate::github::SearchLane::Pat
            } else {
                job.lane
            },
        };
        if app.scan_tx.send(deep).await.is_ok() {
            app.store.mark_deep(&repo);
            queued += 1;
        }
    }
    app.store
        .set_setting("repo_query_idx", &((idx + 1) % queries.len()).to_string())
        .ok();
    info!("discover: '{}' -> {} repos, queued {}", q, found, queued);
    Ok(Summary::default())
}

fn repo_queries(days: i64) -> Vec<String> {
    let cutoff = (chrono::Utc::now() - chrono::Duration::days(days.clamp(1, 3650)))
        .format("%Y-%m-%d")
        .to_string();
    let mut out = vec![
        format!("topic:openai pushed:>{}", cutoff),
        format!("topic:llm pushed:>{}", cutoff),
        format!("topic:ai-agents pushed:>{}", cutoff),
        format!("topic:chatgpt pushed:>{}", cutoff),
        format!("topic:gpt pushed:>{}", cutoff),
        format!("topic:llm-api pushed:>{}", cutoff),
        format!("topic:rag pushed:>{}", cutoff),
        format!("topic:new-api pushed:>{}", cutoff),
        format!("topic:one-api pushed:>{}", cutoff),
        format!("topic:litellm pushed:>{}", cutoff),
        format!("topic:openai-proxy pushed:>{}", cutoff),
        format!("topic:api-relay pushed:>{}", cutoff),
        format!("topic:chatgpt-api pushed:>{}", cutoff),
        format!("topic:deepseek pushed:>{}", cutoff),
        format!("topic:dashscope pushed:>{}", cutoff),
        format!("topic:qwen pushed:>{}", cutoff),
        format!("topic:ai-api pushed:>{}", cutoff),
        format!("\"openai\" pushed:>{}", cutoff),
        format!("\"api key\" pushed:>{}", cutoff),
        format!("\"OPENAI_API_KEY\" pushed:>{}", cutoff),
        format!("\"openai api\" pushed:>{}", cutoff),
        // PAT-focused repo pivots: deep-scan repos whose docs/config mention
        // GitHub credentials even when the current default branch no longer
        // contains the token in the first search page.
        format!("\"ghp_\" pushed:>{}", cutoff),
        format!("\"github_pat_\" pushed:>{}", cutoff),
        format!("\"GITHUB_TOKEN\" pushed:>{}", cutoff),
        format!("topic:github-actions pushed:>{}", cutoff),
        format!("topic:secrets pushed:>{}", cutoff),
        format!("language:python \"openai\" pushed:>{}", cutoff),
        format!("language:typescript \"openai\" pushed:>{}", cutoff),
        format!("language:javascript \"openai\" pushed:>{}", cutoff),
    ];
    out.extend(crate::searchplan::repo_queries(&cutoff));
    let mut seen = std::collections::HashSet::new();
    out.retain(|q| seen.insert(q.clone()));
    out
}

/// Extract credentials directly from GitHub's `text_matches` fragments.
/// Code search already returns the matched lines; fetching every raw file just
/// to rediscover the same token is wasted I/O. Snippets are a first-class
/// candidate source, while full-file extraction remains the fallback.
fn snippet_pairs(v: &serde_json::Value, job: &Job) -> Vec<FoundPair> {
    let pat_job = crate::store::is_pat_query(&job.query);
    let official_job = job.lane == crate::github::SearchLane::Official;
    let mut out = Vec::new();
    let mut seen: HashSet<(String, String)> = HashSet::new();
    let Some(items) = v["items"].as_array() else {
        return out;
    };
    for it in items {
        let (Some(repo), Some(path)) =
            (it["repository"]["full_name"].as_str(), it["path"].as_str())
        else {
            continue;
        };
        if !is_candidate(path, 0) || (pat_job && !is_pat_candidate(path)) {
            continue;
        }
        for tm in it["text_matches"].as_array().into_iter().flatten() {
            let Some(fragment) = tm["fragment"].as_str() else {
                continue;
            };
            // Official-provider snippets from docs/README are usually
            // examples, but DashScope keys in docs are a real source of live
            // classic keys. Keep the exact `sk-` + 32 hex extractor as the
            // quality gate and let the prober decide; only reject non-official
            // paths when the fragment has no DashScope context.
            let dashscope_ctx = fragment.contains("DASHSCOPE")
                || fragment.contains("BAILIAN")
                || fragment.contains("QWEN_API_KEY")
                || fragment.to_ascii_lowercase().contains("dashscope");
            if official_job && !is_official_candidate(path) && !dashscope_ctx {
                continue;
            }
            let ex = extract::extract(fragment);
            let mut push = |endpoint: String, key: String, kind: KeyKind, pair: bool| {
                if !seen.insert((endpoint.clone(), key.clone())) {
                    return;
                }
                out.push(FoundPair {
                    endpoint,
                    key,
                    kind,
                    repo: repo.to_string(),
                    path: path.to_string(),
                    commit: String::new(),
                    source: "snippet".into(),
                    pair,
                });
            };
            for p in ex.pairs {
                push(p.endpoint, p.key, p.kind, true);
            }
            for k in ex.keys {
                if let Some(ep) = k.kind.default_endpoint() {
                    push(ep.to_string(), k.key, k.kind, false);
                }
            }
        }
    }
    out
}

async fn run_search(app: &Arc<App>, job: &Job, mid: i64) -> Result<Summary> {
    // Keep a wide manual plan from turning into 80 simultaneous GitHub
    // searches. Jobs wait here, preserving their order and depth.
    let _search_permit = app
        .search_gate
        .acquire()
        .await
        .map_err(|e| anyhow::anyhow!("search gate closed: {e}"))?;
    let pat_job = crate::store::is_pat_query(&job.query);
    // Manual jobs are explicit and get the deepest pass: all available pages,
    // the full file budget, and no cached-file skips. Auto jobs keep the
    // quota-aware profile.
    let manual = job.manual;
    // Official queries usually surface their best candidates on page 1;
    // PAT jobs get their own page/file budget so one tick can cover four
    // different credential dorks without starving the AI lane.
    let pages = if manual {
        app.store.setting_i64("manual_scan_pages", 10).clamp(1, 10)
    } else if job.lane == crate::github::SearchLane::Official {
        app.store.setting_i64("official_scan_pages", 2).clamp(1, 10)
    } else if pat_job {
        app.store.setting_i64("pat_scan_pages", 3).clamp(1, 10)
    } else {
        app.store.setting_i64("scan_pages", 6).clamp(1, 10)
    } as u32;
    let official_job = job.lane == crate::github::SearchLane::Official;
    let max_files = if manual {
        app.store
            .setting_i64("manual_max_files", 5000)
            .clamp(1, 10_000) as usize
    } else if pat_job {
        app.store.setting_i64("pat_max_files", 2000).clamp(1, 2000) as usize
    } else if official_job {
        app.store
            .setting_i64("official_max_files", 400)
            .clamp(1, 2000) as usize
    } else {
        app.store.setting_i64("max_files", 1200).clamp(1, 2000) as usize
    };
    let mut files: Vec<FileRef> = Vec::new();

    // Page 1 tells us whether the query has more than 100 hits. Only then
    // fetch the remaining pages, in parallel. Most queries are small, so
    // this avoids burning nine search requests per miss.
    let first = match app.gh.search_code(&job.query, 1, job.lane).await {
        Ok(v) => v,
        Err(e) if e.to_string().contains("unable to parse query") => {
            // A malformed operator must not become a retryable job error.
            // GitHub will reject it identically on every retry.
            warn!("search query rejected by GitHub, skipping: {:?}", job.query);
            return Ok(Summary::default());
        }
        Err(e) => return Err(e),
    };
    let total_count = first["total_count"].as_i64().unwrap_or(0);
    let mut page_results: Vec<_> = vec![(1u32, Ok(first))];
    if total_count > 100 && pages > 1 {
        let gh = app.gh.clone();
        let query = job.query.clone();
        let lane = job.lane;
        let futs = (2..=pages).map(move |page| {
            let gh = gh.clone();
            let query = query.clone();
            async move { (page, gh.search_code(&query, page, lane).await) }
        });
        let page_conc = app.store.setting_i64("page_concurrency", 4).clamp(1, 10) as usize;
        let mut rest: Vec<_> = stream::iter(futs)
            .buffer_unordered(page_conc)
            .collect()
            .await;
        rest.sort_by_key(|(page, _)| *page);
        page_results.extend(rest);
    }

    for (page, result) in &page_results {
        let v = match result {
            Ok(v) => v,
            Err(e) => {
                if *page == 1 {
                    return Err(anyhow::anyhow!("{e}"));
                }
                warn!("search page {} failed: {e}", page);
                continue;
            }
        };
        let items = v["items"].as_array().cloned().unwrap_or_default();
        for it in &items {
            let repo = it["repository"]["full_name"].as_str();
            let path = it["path"].as_str();
            if let (Some(repo), Some(path)) = (repo, path) {
                if !is_candidate(path, 0) {
                    continue;
                }
                if pat_job && !is_pat_candidate(path) {
                    continue;
                }
                if official_job && !is_official_candidate(path) {
                    continue;
                }
                files.push(FileRef {
                    repo: repo.to_string(),
                    path: path.to_string(),
                    sha: it["sha"].as_str().unwrap_or("").to_string(),
                });
            }
        }
    }
    info!(
        "search #{id} q={q:?} lane={lane:?} total={total_count} pages={pages} raw_items={raw_items} accepted_files={files_len_before}",
        id = job.id,
        q = job.query,
        lane = job.lane,
        total_count = total_count,
        pages = pages,
        raw_items = page_results.iter().filter_map(|(_, r)| r.as_ref().ok()).map(|v| v["items"].as_array().map(|a| a.len()).unwrap_or(0)).sum::<usize>(),
        files_len_before = files.len(),
    );
    let mut snippet_candidates: Vec<FoundPair> = Vec::new();
    for (_, result) in &page_results {
        if let Ok(v) = result {
            snippet_candidates.extend(snippet_pairs(v, job));
        }
    }
    snippet_candidates = dedupe(snippet_candidates);
    let mut seen = HashSet::new();
    files.retain(|f| seen.insert((f.repo.clone(), f.path.clone())));
    status(
        app,
        job.chat_id,
        mid,
        &format!(
            "🔍 <b>Скан #{}</b> · поиск\n<code>{}</code>\n\n🌐 GitHub: {} совпадений\n📄 В очереди: {}",
            job.id,
            format::esc(&job.query),
            total_count,
            files.len()
        ),
    )
    .await;

    // Rank search hits before the file cap: a 1,200-file budget must spend
    // its first slots on .env/secret/config files, not READMEs or tests.
    files.sort_by(|a, b| {
        search_path_score(&job.query, &b.path)
            .cmp(&search_path_score(&job.query, &a.path))
            .then(a.path.len().cmp(&b.path.len()))
    });
    let per_repo = if manual {
        app.store
            .setting_i64("manual_files_per_repo", 128)
            .clamp(1, 500) as usize
    } else if pat_job {
        app.store
            .setting_i64("pat_files_per_repo", 64)
            .clamp(1, 200) as usize
    } else if official_job {
        app.store
            .setting_i64("official_files_per_repo", 16)
            .clamp(1, 200) as usize
    } else {
        app.store
            .setting_i64("max_files_per_repo", 24)
            .clamp(1, 200) as usize
    };
    let mut repo_counts: HashMap<String, usize> = HashMap::new();
    files.retain(|f| {
        let n = repo_counts.entry(f.repo.clone()).or_default();
        if *n >= per_repo {
            return false;
        }
        *n += 1;
        true
    });
    files.truncate(max_files);
    let mut sum = Summary {
        files: files.len(),
        snippets: snippet_candidates.len(),
        ..Default::default()
    };
    let results = if files.is_empty() {
        Vec::new()
    } else {
        process_files(app, job, files, mid, false).await?
    };
    let mut pairs = snippet_candidates;
    pairs.extend(results.iter().flat_map(|r| r.pairs.clone()));
    pairs = dedupe(pairs);
    if official_job {
        pairs.retain(is_official_pair);
    }
    sum.pairs = pairs.len();
    probe_pairs(app, job, pairs, mid, &mut sum).await?;
    enqueue_deep(app, job, &results).await;
    Ok(sum)
}

async fn run_repo(app: &Arc<App>, job: &Job, mid: i64) -> Result<Summary> {
    let repo_name = job.query.trim().trim_end_matches(".git").to_string();
    let repo = app.gh.repo(&repo_name).await?;
    if repo.archived && app.store.setting_i64("include_archived", 0) == 0 && job.quiet {
        anyhow::bail!("репозиторий архивный");
    }
    let max_files = if !job.manual {
        app.store.setting_i64("max_files", 1200).clamp(1, 2000) as usize
    } else {
        app.store
            .setting_i64("manual_max_files", 5000)
            .clamp(1, 10_000) as usize
    };
    let tree = app.gh.tree(&repo.full_name, &repo.default_branch).await?;
    let mut files: Vec<FileRef> = tree
        .into_iter()
        .filter(|e| is_candidate(&e.path, e.size))
        .map(|e| FileRef {
            repo: repo.full_name.clone(),
            path: e.path,
            sha: e.sha,
        })
        .collect();
    // Atlas deep pass: non-default branches are indexed separately by GitHub
    // code search only on the default branch. Scan a small number explicitly.
    let branch_depth = if !job.manual {
        app.store.setting_i64("branch_depth", 2).clamp(0, 5) as usize
    } else {
        app.store.setting_i64("manual_branches", 20).clamp(1, 100) as usize
    };
    if branch_depth > 0 && app.pool.core_remaining() > 10 {
        if let Ok(branches) = app.gh.branches(&repo.full_name).await {
            for (branch, _sha) in branches
                .into_iter()
                .filter(|(name, _)| *name != repo.default_branch)
                .take(branch_depth)
            {
                if let Ok(extra) = app.gh.tree(&repo.full_name, &branch).await {
                    for e in extra.into_iter().filter(|e| is_candidate(&e.path, e.size)) {
                        files.push(FileRef {
                            repo: repo.full_name.clone(),
                            path: e.path,
                            sha: e.sha,
                        });
                    }
                }
            }
        }
    }
    let mut seen_files = HashSet::new();
    files.retain(|f| seen_files.insert((f.path.clone(), f.sha.clone())));
    if files.len() > max_files {
        files.sort_by(|a, b| {
            priority(&b.path)
                .cmp(&priority(&a.path))
                .then(a.path.len().cmp(&b.path.len()))
        });
        files.truncate(max_files);
    }
    let mut sum = Summary {
        files: files.len(),
        ..Default::default()
    };
    let results = process_files(app, job, files, mid, true).await?;
    let mut pairs: Vec<FoundPair> = results.iter().flat_map(|r| r.pairs.clone()).collect();
    let endpoints: Vec<String> = results
        .iter()
        .flat_map(|r| r.endpoints.clone())
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();
    if !endpoints.is_empty() {
        status(
            app,
            job.chat_id,
            mid,
            &format!(
                "🕳 <b>Скан #{}</b> · коммиты\n<code>{}</code>\n\n🔗 Endpoint'ов: {}\n📄 Файлов: {}\n⏳ Спускаюсь в историю…",
                job.id,
                format::esc(&job.query),
                endpoints.len(),
                sum.files
            ),
        )
        .await;
        let mined = mine_repo_commits(app, &repo.full_name, &endpoints).await;
        pairs.extend(mined);
    }
    pairs = dedupe(pairs);
    if job.lane == crate::github::SearchLane::Official {
        pairs.retain(is_official_pair);
    }
    sum.pairs = pairs.len();
    probe_pairs(app, job, pairs, mid, &mut sum).await?;
    Ok(sum)
}

async fn process_files(
    app: &Arc<App>,
    job: &Job,
    files: Vec<FileRef>,
    mid: i64,
    deep: bool,
) -> Result<Vec<FileResult>> {
    let cap = if !job.manual {
        app.store.setting_i64("mine_files", 80).clamp(0, 400) as usize
    } else {
        app.store
            .setting_i64("manual_mine_files", 1000)
            .clamp(0, 10_000) as usize
    };
    let force = job.manual && app.store.setting_i64("manual_force_rescan", 0).clamp(0, 1) == 1;
    let budget = Arc::new(AtomicUsize::new(0));
    let pat_mode = (crate::store::is_pat_query(&job.query)
        || job.lane == crate::github::SearchLane::Pat)
        && app.store.setting_i64("pat_history", 1) == 1;
    let pat_cap = app.store.setting_i64("pat_history_files", 3).clamp(0, 24) as usize;
    let pat_budget = Arc::new(AtomicUsize::new(0));
    let total = files.len();
    let mut done = 0usize;
    let mut results = Vec::new();

    for chunk in files.chunks(128) {
        let futs = chunk.iter().cloned().map(|f| {
            let app = app.clone();
            let budget = budget.clone();
            let pat_budget = pat_budget.clone();
            async move {
                process_file(
                    app, f, budget, pat_budget, pat_cap, pat_mode, cap, deep, force,
                )
                .await
            }
        });
        let file_conc = app.store.setting_i64("file_concurrency", 64).clamp(1, 128) as usize;
        let chunk_res: Vec<FileResult> = stream::iter(futs)
            .buffer_unordered(file_conc)
            .collect()
            .await;
        results.extend(chunk_res);
        done += chunk.len();
        let found: usize = results.iter().map(|r| r.pairs.len()).sum();
        status(
            app,
            job.chat_id,
            mid,
            &format!(
                "🔍 <b>Скан #{}</b> · {}\n<code>{}</code>\n\n📄 Файлы: {}/{}\n🔑 Пар: {}",
                job.id,
                match job.kind {
                    JobKind::Repo => "репозиторий",
                    _ => "поиск",
                },
                format::esc(&job.query),
                done,
                total,
                found
            ),
        )
        .await;
    }
    Ok(results)
}

async fn process_file(
    app: Arc<App>,
    f: FileRef,
    budget: Arc<AtomicUsize>,
    pat_budget: Arc<AtomicUsize>,
    pat_cap: usize,
    pat_mode: bool,
    cap: usize,
    deep: bool,
    force: bool,
) -> FileResult {
    let mut out = FileResult {
        repo: f.repo.clone(),
        ..Default::default()
    };
    let cache_days = app.store.setting_i64("cache_days", 3).max(0);
    if !force
        && app
            .store
            .was_scanned(&f.repo, &f.path, &f.sha, now() - cache_days * 86_400)
    {
        return out;
    }

    let repo = if deep {
        if app.pool.core_remaining() < 5 {
            return out;
        }
        match app.gh.repo(&f.repo).await {
            Ok(r) => {
                if r.archived && app.store.setting_i64("include_archived", 0) == 0 {
                    return out;
                }
                if r.fork && app.store.setting_i64("include_forks", 1) == 0 {
                    return out;
                }
                if r.stars < app.store.setting_i64("min_stars", 0) {
                    return out;
                }
                Some(r)
            }
            Err(e) => {
                warn!("repo {}: {e}", f.repo);
                return out;
            }
        }
    } else {
        None
    };

    let mut text: Option<String> = None;
    if let Some(r) = &repo {
        text = app
            .gh
            .raw(&f.repo, &r.default_branch, &f.path)
            .await
            .ok()
            .flatten();
    }
    if text.is_none() {
        text = app.gh.raw(&f.repo, "HEAD", &f.path).await.ok().flatten();
    }
    if text.is_none() && repo.is_none() {
        if app.pool.core_remaining() < 5 {
            return out;
        }
        if let Ok(r) = app.gh.repo(&f.repo).await {
            text = app
                .gh
                .raw(&f.repo, &r.default_branch, &f.path)
                .await
                .ok()
                .flatten();
        }
    }
    if text.is_none() {
        if app.pool.core_remaining() < 5 {
            return out;
        }
        text = app.gh.blob(&f.repo, &f.sha).await.ok().flatten();
    }
    let Some(text) = text else {
        return out;
    };

    let ex = extract::extract(&text);
    out.endpoints = ex.strong_endpoints();
    let direct_pairs = ex.pairs.len();
    for p in ex.pairs {
        out.pairs.push(FoundPair {
            endpoint: p.endpoint,
            key: p.key,
            kind: p.kind,
            repo: f.repo.clone(),
            path: f.path.clone(),
            commit: String::new(),
            source: "code".into(),
            pair: true,
        });
    }
    let mut paired_keys: HashSet<String> = out.pairs.iter().map(|p| p.key.clone()).collect();
    for k in &ex.keys {
        if paired_keys.contains(&k.key) {
            continue;
        }
        if let Some(ep) = k.kind.default_endpoint() {
            out.pairs.push(FoundPair {
                endpoint: ep.to_string(),
                key: k.key.clone(),
                kind: k.kind,
                repo: f.repo.clone(),
                path: f.path.clone(),
                commit: String::new(),
                source: "code".into(),
                pair: false,
            });
            paired_keys.insert(k.key.clone());
        }
    }
    for ep in &out.endpoints {
        let host = extract::host_of(ep);
        app.store.record_host(&host);
        crate::atlas::pivot_host(app.as_ref(), &host, 200);
    }
    for p in &out.pairs {
        let host = extract::host_of(&p.endpoint);
        app.store.record_host(&host);
        crate::atlas::pivot_host(app.as_ref(), &host, 240);
    }
    if direct_pairs == 0 && !out.endpoints.is_empty() {
        if budget.fetch_add(1, Ordering::Relaxed) < cap {
            let mined = mine_path(&app, &f.repo, &f.path, &out.endpoints).await;
            if !mined.is_empty() {
                info!(
                    "commit-mined {} pairs from {}/{}",
                    mined.len(),
                    f.repo,
                    f.path
                );
                out.pairs.extend(mined);
            }
        }
    }
    // A current .env may contain only a placeholder while an older commit
    // still carries the real token. Spend a tiny, bounded fraction of the
    // PAT burst on file history; normal AI searches keep the old behaviour.
    let history_text = text.to_ascii_lowercase();
    let pat_history_hint = [
        "ghp_",
        "github_pat_",
        "gho_",
        "ghu_",
        "ghs_",
        "ghr_",
        "github_token",
        "gh_token",
        "github_pat",
        "gh_pat",
        "x-access-token",
    ]
    .iter()
    .any(|m| history_text.contains(m));
    if pat_mode && pat_history_hint && pat_budget.fetch_add(1, Ordering::Relaxed) < pat_cap {
        let mined = mine_pat_history(&app, &f.repo, &f.path).await;
        if !mined.is_empty() {
            info!(
                "PAT history: {} keys from {}/{}",
                mined.len(),
                f.repo,
                f.path
            );
            out.pairs.extend(mined);
        }
    }
    app.store.mark_scanned(&f.repo, &f.path, &f.sha);
    out
}

async fn mine_pat_history(app: &App, repo: &str, path: &str) -> Vec<FoundPair> {
    if app.pool.core_remaining() < 10 {
        return Vec::new();
    }
    let depth = app.store.setting_i64("pat_history_depth", 25).clamp(1, 100) as usize;
    let commits = match app.gh.list_commits(repo, Some(path), depth).await {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    let shas: Vec<String> = commits.into_iter().take(depth).map(|c| c.sha).collect();
    let gh = app.gh.clone();
    let details: Vec<(String, Vec<crate::github::FilePatch>)> = stream::iter(shas)
        .map(|sha| {
            let gh = gh.clone();
            let repo = repo.to_string();
            async move {
                let files = gh.commit_files(&repo, &sha).await.unwrap_or_default();
                (sha, files)
            }
        })
        .buffer_unordered(8)
        .collect()
        .await;
    let mut out = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    for (sha, files) in details {
        for fp in files {
            if fp.filename != path {
                continue;
            }
            let ex = extract::extract(&fp.patch);
            for k in ex.keys {
                if k.kind != KeyKind::GithubPat || !seen.insert(k.key.clone()) {
                    continue;
                }
                let Some(endpoint) = k.kind.default_endpoint() else {
                    continue;
                };
                out.push(FoundPair {
                    endpoint: endpoint.to_string(),
                    key: k.key,
                    kind: k.kind,
                    repo: repo.to_string(),
                    path: path.to_string(),
                    commit: sha.clone(),
                    source: "pat_commit".into(),
                    pair: false,
                });
            }
        }
    }
    out
}

async fn mine_path(app: &App, repo: &str, path: &str, endpoints: &[String]) -> Vec<FoundPair> {
    if app.pool.core_remaining() < 10 {
        return Vec::new();
    }
    let depth = app.store.setting_i64("commit_depth", 100).clamp(1, 300) as usize;
    let commits = match app.gh.list_commits(repo, Some(path), depth).await {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    let shas: Vec<String> = commits.iter().take(depth).map(|c| c.sha.clone()).collect();
    let gh = app.gh.clone();
    let details: Vec<(String, Vec<crate::github::FilePatch>)> = stream::iter(shas)
        .map(|sha| {
            let gh = gh.clone();
            let repo = repo.to_string();
            async move {
                let files = gh.commit_files(&repo, &sha).await.unwrap_or_default();
                (sha, files)
            }
        })
        .buffer_unordered(16)
        .collect()
        .await;
    let mut out = Vec::new();
    for (sha, files) in details {
        for fp in files {
            if fp.filename != path {
                continue;
            }
            let ex = extract::extract(&fp.patch);
            if !ex.pairs.is_empty() {
                for p in &ex.pairs {
                    out.push(FoundPair {
                        endpoint: p.endpoint.clone(),
                        key: p.key.clone(),
                        kind: p.kind,
                        repo: repo.to_string(),
                        path: path.to_string(),
                        commit: sha.clone(),
                        source: "commit".into(),
                        pair: true,
                    });
                }
                continue;
            }
            for k in &ex.keys {
                if let Some(ep) = endpoint_for_key(&ex, k.line, k.kind, endpoints) {
                    if !extract::endpoint_fits(k.kind, &ep) {
                        continue;
                    }
                    out.push(FoundPair {
                        endpoint: ep,
                        key: k.key.clone(),
                        kind: k.kind,
                        repo: repo.to_string(),
                        path: path.to_string(),
                        commit: sha.clone(),
                        source: "commit".into(),
                        pair: true,
                    });
                }
            }
        }
    }
    out
}

async fn mine_repo_commits(app: &App, repo: &str, endpoints: &[String]) -> Vec<FoundPair> {
    if app.pool.core_remaining() < 10 {
        return Vec::new();
    }
    let depth = app.store.setting_i64("commit_depth", 100).clamp(1, 300) as usize;
    let commits = match app.gh.list_commits(repo, None, depth).await {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    let shas: Vec<String> = commits.iter().take(depth).map(|c| c.sha.clone()).collect();
    let gh = app.gh.clone();
    let details: Vec<(String, Vec<crate::github::FilePatch>)> = stream::iter(shas)
        .map(|sha| {
            let gh = gh.clone();
            let repo = repo.to_string();
            async move {
                let files = gh.commit_files(&repo, &sha).await.unwrap_or_default();
                (sha, files)
            }
        })
        .buffer_unordered(16)
        .collect()
        .await;
    let mut out = Vec::new();
    for (sha, files) in details {
        for fp in files {
            let ex = extract::extract(&fp.patch);
            if !ex.pairs.is_empty() {
                for p in &ex.pairs {
                    out.push(FoundPair {
                        endpoint: p.endpoint.clone(),
                        key: p.key.clone(),
                        kind: p.kind,
                        repo: repo.to_string(),
                        path: fp.filename.clone(),
                        commit: sha.clone(),
                        source: "commit".into(),
                        pair: true,
                    });
                }
                continue;
            }
            for k in &ex.keys {
                if let Some(ep) = endpoint_for_key(&ex, k.line, k.kind, endpoints)
                    .filter(|ep| extract::endpoint_fits(k.kind, ep))
                {
                    out.push(FoundPair {
                        endpoint: ep,
                        key: k.key.clone(),
                        kind: k.kind,
                        repo: repo.to_string(),
                        path: fp.filename.clone(),
                        commit: sha.clone(),
                        source: "commit".into(),
                        pair: true,
                    });
                }
            }
        }
    }
    out
}

async fn enqueue_deep(app: &Arc<App>, job: &Job, results: &[FileResult]) {
    let limit = if !job.manual {
        app.store.setting_i64("deep_repos", 10).clamp(0, 20)
    } else {
        app.store.setting_i64("manual_deep_repos", 50).clamp(0, 100)
    };
    if limit == 0 {
        return;
    }
    // Deep scans are core-bucket heavy. Do not enqueue more repositories
    // than the remaining core quota can reasonably cover; otherwise every
    // queued repo fails with "core quota exhausted" and floods the logs.
    let core = app.pool.core_remaining();
    if core < 50 {
        return;
    }
    let cap = app.store.setting_i64("deep_concurrency", 4).clamp(1, 12);
    let active = app.store.running_job_count("repo");
    let limit = limit.min((core / 50).max(0)).min((cap - active).max(0));
    if limit == 0 {
        return;
    }
    let hours = if !job.manual {
        app.store.setting_i64("deep_hours", 12).max(1)
    } else {
        app.store.setting_i64("manual_deep_hours", 6).max(1)
    };
    let mut scores: HashMap<String, i64> = HashMap::new();
    for r in results {
        let dashscope = r.endpoints.iter().any(|e| {
            extract::host_of(e).contains("dashscope") || extract::is_dashscope_workspace_endpoint(e)
        });
        let official = r
            .endpoints
            .iter()
            .any(|e| extract::is_priority_official_endpoint(e));
        let ws_key = r.pairs.iter().any(|p| p.key.starts_with("sk-ws-"));
        let score = r.pairs.len() as i64 * 3
            + r.endpoints.len() as i64
            + if official {
                8
            } else if dashscope || ws_key {
                6
            } else {
                0
            };
        if score > 0 && !r.repo.is_empty() {
            *scores.entry(r.repo.clone()).or_default() += score;
        }
    }
    let mut ranked: Vec<(String, i64)> = scores.into_iter().collect();
    ranked.sort_by_key(|a| std::cmp::Reverse(a.1));
    for (repo, _) in ranked
        .into_iter()
        .filter(|(r, _)| app.store.needs_deep(r, hours))
        .take(limit as usize)
    {
        let Ok(id) = app.store.job_start("repo", &repo) else {
            continue;
        };
        let deep = Job {
            id,
            chat_id: job.chat_id,
            kind: JobKind::Repo,
            query: repo.clone(),
            quiet: true,
            manual: job.manual,
            lane: crate::github::SearchLane::Pair,
        };
        if app.scan_tx.send(deep).await.is_ok() {
            app.store.mark_deep(&repo);
            info!("queued deep repo scan #{} for {}", id, repo);
        }
    }
}

async fn probe_pairs(
    app: &Arc<App>,
    job: &Job,
    mut pairs: Vec<FoundPair>,
    mid: i64,
    sum: &mut Summary,
) -> Result<()> {
    // Quality DashScope pass: classic `sk-…` keys only, and only from
    // credential/config paths. Workspace `sk-ws-…` pairs are ignored entirely.
    pairs.retain(|p| match p.kind {
        KeyKind::DashScopeWorkspace => false,
        // The extractor already requires classic `sk-` + 32 hex and a
        // DashScope context. Do not throw a live key away only because it is
        // documented in README/docs; the probe is still the final authority.
        _ => true,
    });
    pairs.sort_by_key(|p| {
        let official = extract::is_priority_official_endpoint(&p.endpoint)
            || matches!(
                p.kind,
                KeyKind::OpenAi | KeyKind::Anthropic | KeyKind::OpenRouter | KeyKind::Xai
            );
        let dashscope = extract::host_of(&p.endpoint).contains("dashscope")
            || extract::is_dashscope_workspace_endpoint(&p.endpoint)
            || p.key.starts_with("sk-ws-");
        // Official first-party providers edge out DashScope by one rank;
        // the gap is deliberately small, not an official-only filter.
        let priority = if official {
            0
        } else if dashscope {
            1
        } else {
            2
        };
        (priority, if p.pair { 0 } else { 1 })
    });
    let recheck_hours = if !job.manual {
        app.store.setting_i64("recheck_hours", 12).max(0)
    } else {
        app.store.setting_i64("manual_skip_hours", 24).max(0)
    };
    // Manual scans should not reprobe pairs that already exist in the DB.
    // `manual_skip_forever=1` makes the seen-set permanent; the hour setting
    // remains the fallback for auto scans and for operators who disable it.
    let since = if job.manual && app.store.setting_i64("manual_skip_forever", 1) == 1 {
        0
    } else {
        now() - recheck_hours * 3600
    };
    let pat_job =
        crate::store::is_pat_query(&job.query) || job.lane == crate::github::SearchLane::Pat;
    let max_probes = if pat_job {
        app.store.setting_i64("pat_max_probes", 3000).clamp(1, 5000) as usize
    } else {
        app.store.setting_i64("max_probes", 500).clamp(1, 2000) as usize
    };
    let candidates: Vec<(String, String)> = pairs
        .iter()
        .map(|p| (p.endpoint.clone(), p.key.clone()))
        .collect();
    let recently_checked = if job.manual && app.store.setting_i64("manual_skip_forever", 1) == 1 {
        // The operator explicitly asked not to see known pairs again: remove
        // them before counting, probing or showing them in the result card.
        app.store.recent_finding_pairs(&candidates, 0)
    } else {
        app.store.recent_finding_pairs(&candidates, since)
    };
    let before_filter = pairs.len();
    pairs.retain(|p| !recently_checked.contains(&(p.endpoint.clone(), p.key.clone())));
    sum.skipped += before_filter.saturating_sub(pairs.len());
    sum.pairs += pairs.len();
    if pairs.is_empty() {
        return Ok(());
    }
    let mut todo = Vec::new();
    for p in pairs {
        todo.push(p);
        if todo.len() >= max_probes {
            break;
        }
    }
    if todo.is_empty() {
        return Ok(());
    }
    status(
        app,
        job.chat_id,
        mid,
        &format!(
            "🧪 <b>Скан #{}</b> · проба\n<code>{}</code>\n\n🔑 Ключей: {}\n⏳ GET /models → hi…",
            job.id,
            format::esc(&job.query),
            todo.len()
        ),
    )
    .await;

    let mut opts = app.probe_opts();
    opts.all_types = job.manual;
    opts.video_generate = job.manual;
    let conc = if pat_job {
        app.store
            .setting_i64("pat_probe_concurrency", 24)
            .clamp(1, 64) as usize
    } else {
        app.store.setting_i64("concurrency", 64).clamp(1, 128) as usize
    };
    let total = todo.len();
    let futs = todo.into_iter().map(|p| {
        let app = app.clone();
        let opts = opts.clone();
        let gate = app.probe_gate.clone();
        async move {
            let _permit = gate.acquire_owned().await.ok();
            let out = if p.kind == KeyKind::GithubPat {
                crate::github_pat::probe(&app.prober.http_client(), &p.endpoint, &p.key).await
            } else {
                app.prober.probe(&p.endpoint, &p.key, &opts).await
            };
            (p, out)
        }
    });
    let results: Vec<(FoundPair, ProbeOutcome)> =
        stream::iter(futs).buffer_unordered(conc).collect().await;

    let mut done = 0usize;
    let mut last_status = Instant::now();
    for (p, out) in results {
        let rank = if matches!(out.status, PStatus::Valid | PStatus::Limited)
            && p.kind != KeyKind::GithubPat
            && !crate::probe::is_special_catalog(&out.models)
            && app.store.needs_rank(
                &p.endpoint,
                &p.key,
                app.store.setting_i64("rank_recheck_hours", 24),
            ) {
            crate::rank::evaluate(&app.cfg, &p.endpoint, &p.key, &out).await
        } else {
            None
        };
        let nf = NewFinding {
            endpoint: p.endpoint.clone(),
            key: p.key.clone(),
            key_kind: p.kind.label().to_string(),
            repo: p.repo.clone(),
            path: p.path.clone(),
            commit_sha: p.commit.clone(),
            source: p.source.clone(),
            status: out.status.as_str().to_string(),
            pair: p.pair,
            total_models: out.models.len() as i64,
            tested: out.tested as i64,
            chat_ok: out.chat_ok,
            models: out.models.clone(),
            probes: out.probes.clone(),
            latency_ms: out.latency_ms as i64,
            balance: out.balance.clone(),
            rpm: out.rpm.clone(),
            rank: rank.as_ref().map(|r| r.rank.clone()).unwrap_or_default(),
            rank_score: rank.as_ref().map(|r| r.score).unwrap_or(-1),
            rank_verdict: rank.as_ref().map(|r| r.verdict.clone()).unwrap_or_default(),
            rank_note: rank.as_ref().map(|r| r.note.clone()).unwrap_or_default(),
            ranked_at: rank.as_ref().map(|_| now()).unwrap_or(0),
        };
        let up = match app.store.upsert_finding(&nf) {
            Ok(u) => u,
            Err(e) => {
                warn!("store finding: {e}");
                continue;
            }
        };
        sum.probed += 1;
        done += 1;
        if out.status == PStatus::Valid {
            sum.valid += 1;
            if up.became_valid {
                app.store.record_host_valid(&extract::host_of(&p.endpoint));
            }
        }
        let notify = (out.status == PStatus::Valid)
            || (out.status == PStatus::Limited && app.store.setting_i64("notify_limit", 1) == 1)
            || (out.status == PStatus::Invalid && app.store.setting_i64("notify_invalid", 0) == 1);
        // Auto/source scans should not flood the DM with cards. Manual
        // scans keep the full card flow; operators can opt in for auto.
        let notify =
            notify && (job.manual || !job.quiet || app.store.setting_i64("auto_cards", 0) == 1);
        if notify && !up.card_sent && app.store.claim_card(up.id) {
            if let Some(f) = app.store.finding_by_id(up.id) {
                let card = format::card(&f);
                match app.tg.send(job.chat_id, &card, None).await {
                    Ok(_) => {
                        sum.cards += 1;
                    }
                    Err(e) => {
                        let msg = e.to_string();
                        if msg.contains("timeout") {
                            // Telegram may have accepted the card before the
                            // response timed out. Keep the claim to avoid a
                            // duplicate card; the operator can still see it.
                            warn!("send card uncertain (timeout): {msg}");
                        } else {
                            app.store.release_card(up.id);
                            warn!("send card: {e}");
                        }
                    }
                }
                tokio::time::sleep(Duration::from_millis(1200)).await;
            } else {
                app.store.release_card(up.id);
            }
        }
        // Editing the same Telegram message for every single key was the
        // loudest non-network cost of a manual probe. Do it at most every
        // 10 keys (or after two seconds), and always on the final key.
        if done == total || done % 10 == 0 || last_status.elapsed() >= Duration::from_secs(2) {
            status(
                app,
                job.chat_id,
                mid,
                &format!(
                    "🧪 <b>Скан #{}</b> · проба\n<code>{}</code>\n\n🔑 {}/{} · ✅ valid: {}",
                    job.id,
                    format::esc(&job.query),
                    done,
                    total,
                    sum.valid
                ),
            )
            .await;
            last_status = Instant::now();
        }
    }
    Ok(())
}

pub async fn manual_check(app: Arc<App>, chat: i64, endpoint: String, key: String) {
    let ep = extract::normalize(&endpoint).unwrap_or_else(|| endpoint.clone());
    let host = extract::host_of(&ep);
    app.store.record_host(&host);
    crate::atlas::pivot_host(&app, &host, 300);
    let mut opts = app.probe_opts();
    opts.all_types = true;
    opts.video_generate = true;
    let out = app.prober.probe(&ep, &key, &opts).await;
    if out.status == PStatus::Valid {
        app.store.record_host_valid(&extract::host_of(&ep));
    }
    let rank = if matches!(out.status, PStatus::Valid | PStatus::Limited)
        && app
            .store
            .needs_rank(&ep, &key, app.store.setting_i64("rank_recheck_hours", 24))
    {
        crate::rank::evaluate(&app.cfg, &ep, &key, &out).await
    } else {
        None
    };
    let nf = NewFinding {
        endpoint: ep,
        key: key.clone(),
        key_kind: "manual".into(),
        repo: String::new(),
        path: String::new(),
        commit_sha: String::new(),
        source: "manual".into(),
        status: out.status.as_str().to_string(),
        pair: false,
        total_models: out.models.len() as i64,
        tested: out.tested as i64,
        chat_ok: out.chat_ok,
        models: out.models.clone(),
        probes: out.probes.clone(),
        latency_ms: out.latency_ms as i64,
        balance: out.balance.clone(),
        rpm: out.rpm.clone(),
        rank: rank.as_ref().map(|r| r.rank.clone()).unwrap_or_default(),
        rank_score: rank.as_ref().map(|r| r.score).unwrap_or(-1),
        rank_verdict: rank.as_ref().map(|r| r.verdict.clone()).unwrap_or_default(),
        rank_note: rank.as_ref().map(|r| r.note.clone()).unwrap_or_default(),
        ranked_at: rank.as_ref().map(|_| now()).unwrap_or(0),
    };
    match app.store.upsert_finding(&nf) {
        Ok(up) => {
            if let Some(f) = app.store.finding_by_id(up.id) {
                let card = format::card(&f);
                match app.tg.send(chat, &card, None).await {
                    Ok(_) => app.store.mark_card_sent(up.id),
                    Err(e) => {
                        let msg = e.to_string();
                        if msg.contains("timeout") {
                            // Treat an uncertain manual send as claimed.
                            app.store.mark_card_sent(up.id);
                        }
                        warn!("manual card not sent: {msg}");
                    }
                }
            }
        }
        Err(e) => {
            let _ = app
                .tg
                .send(
                    chat,
                    &format!("❌ Не смог сохранить: {}", format::esc(&e.to_string())),
                    None,
                )
                .await;
        }
    }
}

async fn status(app: &Arc<App>, chat: i64, mid: i64, text: &str) {
    if mid > 0 {
        let _ = app.tg.edit(chat, mid, text, None).await;
    }
}

fn endpoint_for_key(
    ex: &extract::Extraction,
    line: usize,
    kind: KeyKind,
    fallback: &[String],
) -> Option<String> {
    if let Some(ep) = ex
        .endpoints
        .iter()
        .filter(|e| e.line.abs_diff(line) <= 8)
        .min_by_key(|e| e.line.abs_diff(line))
        .map(|e| e.url.clone())
        .filter(|ep| extract::endpoint_fits(kind, ep))
    {
        return Some(ep);
    }
    if fallback.len() == 1 && extract::endpoint_fits(kind, &fallback[0]) {
        return Some(fallback[0].clone());
    }
    kind.default_endpoint().map(|s| s.to_string())
}

fn dedupe(v: Vec<FoundPair>) -> Vec<FoundPair> {
    let mut seen = HashSet::new();
    v.into_iter()
        .filter(|p| seen.insert((p.endpoint.clone(), p.key.clone())))
        .collect()
}

fn priority(path: &str) -> i32 {
    let l = path.to_lowercase();
    let name = l.rsplit('/').next().unwrap_or(&l);
    if name.starts_with(".env") || name.contains(".env.") {
        130
    } else if l.contains("credentials") || l.contains("secrets") || l.contains("secret") {
        115
    } else if name.contains("config")
        || name.contains("settings")
        || name.ends_with(".ini")
        || name.ends_with(".toml")
        || name.ends_with(".yaml")
        || name.ends_with(".yml")
    {
        100
    } else if l.contains("key") || name.ends_with(".pem") {
        90
    } else if l.contains("/test") || l.contains("/tests") || l.contains("/example") {
        20
    } else if l.contains("/docs") || l.ends_with(".md") || l.ends_with(".mdx") {
        10
    } else {
        55
    }
}

/// Search-hit rank: path quality plus a small penalty for examples/tests.
/// This is ordering only; every candidate still goes through extraction.
fn search_path_score(query: &str, path: &str) -> i32 {
    let l = path.to_lowercase();
    let mut score = priority(path);
    if l.contains("example") || l.contains("sample") || l.contains("fixture") {
        score -= 25;
    }
    if l.contains("test") || l.contains("spec") {
        score -= 15;
    }
    let q = query.to_ascii_lowercase();
    if q.contains("filename:") && l.contains(".env") {
        score += 10;
    }
    if q.contains("path:.env") && l.contains(".env") {
        score += 10;
    }
    score
}

/// High-precision path filter for GitHub credential searches. Test fixtures,
/// docs and example files dominate broad `ghp_`/`GITHUB_TOKEN` hits and almost
/// never contain a live token; spend the PAT file budget on configs/scripts.
fn is_pat_candidate(path: &str) -> bool {
    let l = path.to_ascii_lowercase();
    if [
        "/test",
        "/tests",
        "/spec",
        "/specs",
        "/fixture",
        "/fixtures",
        "/example",
        "/examples",
        "/sample",
        "/samples",
        "/docs/",
        "/doc/",
        "/semgrep-rules/",
        "/detected-github-token",
        "/.github/issue_template",
        "/.github/pull_request_template",
    ]
    .iter()
    .any(|x| l.contains(x))
    {
        return false;
    }
    let name = l.rsplit('/').next().unwrap_or(&l);
    if [
        ".md",
        ".markdown",
        ".rst",
        ".adoc",
        ".html",
        ".htm",
        ".svg",
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".lock",
    ]
    .iter()
    .any(|x| name.ends_with(x))
    {
        return false;
    }
    if name.contains("package-lock")
        || name.contains("yarn.lock")
        || name.contains("pnpm-lock")
        || name.contains("composer.lock")
        || name.contains(".example")
        || name.contains(".sample")
        || name.contains(".template")
        || name.contains(".fake")
        || name.contains(".dummy")
        || name.contains(".dist")
    {
        return false;
    }
    let ext = name.rsplit('.').next().unwrap_or("");
    const EXT: &[&str] = &[
        "env",
        "yml",
        "yaml",
        "json",
        "toml",
        "ini",
        "cfg",
        "conf",
        "properties",
        "sh",
        "bash",
        "zsh",
        "fish",
        "ps1",
        "bat",
        "cmd",
        "py",
        "js",
        "mjs",
        "cjs",
        "ts",
        "tsx",
        "jsx",
        "go",
        "rb",
        "php",
        "java",
        "kt",
        "kts",
        "cs",
        "rs",
        "swift",
        "scala",
        "tf",
        "tfvars",
        "hcl",
        "xml",
        "gradle",
        "plist",
        "txt",
        "pem",
        "key",
    ];
    EXT.contains(&ext)
        || name.starts_with(".env")
        || name == "dockerfile"
        || name == "makefile"
        || name == "jenkinsfile"
        || name == "procfile"
        || name == ".npmrc"
        || name == ".pypirc"
        || name == ".netrc"
        || name == ".git-credentials"
        || name == "config"
        || name == "credentials"
}

fn is_official_candidate(path: &str) -> bool {
    let l = path.to_ascii_lowercase();
    if [
        "/test",
        "/tests",
        "/spec",
        "/specs",
        "/fixture",
        "/fixtures",
        "/example",
        "/examples",
        "/sample",
        "/samples",
        "/docs/",
        "/doc/",
        "/demo",
        "/demos",
    ]
    .iter()
    .any(|x| l.contains(x))
    {
        return false;
    }
    let name = l.rsplit('/').next().unwrap_or(&l);
    // `.env.example`, `.env.prod.example`, `.env-template`, `example.env`,
    // `.env_test`, `.env.enc`: these dominate code-search result pages and
    // almost never contain a usable secret. Reject every obvious template
    // marker before spending a raw fetch.
    if [
        "example",
        "sample",
        "template",
        "fixture",
        ".enc",
        ".dist",
        ".test",
        ".spec",
        ".mock",
        ".fake",
        ".dummy",
        "readme",
        "changelog",
        "license",
        "contributing",
    ]
    .iter()
    .any(|x| name.contains(x))
    {
        return false;
    }
    if name.starts_with("readme")
        || name.starts_with("changelog")
        || name.starts_with("license")
        || name.starts_with("contributing")
        || name.ends_with(".md")
        || name.ends_with(".rst")
        || name.ends_with(".adoc")
        || name.ends_with(".html")
        || name.ends_with(".svg")
        || name.ends_with(".lock")
        || name.contains("lock.json")
        || name.contains("lock.yaml")
        || name.contains("lock.yml")
        || name.ends_with(".env.example")
        || name.ends_with(".env.sample")
        || name.ends_with(".env.template")
        || name.ends_with(".env.dist")
    {
        return false;
    }
    true
}

fn is_candidate(path: &str, size: i64) -> bool {
    if size > 512 * 1024 {
        return false;
    }
    let lower = path.to_lowercase();
    for bad in [
        "node_modules/",
        "/vendor/",
        "/dist/",
        "/build/",
        "/target/",
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
    ] {
        if lower.contains(bad) {
            return false;
        }
    }
    let name = lower.rsplit('/').next().unwrap_or(&lower);
    if name.contains(".min.") {
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
        "zsh",
        "txt",
        "sql",
        "properties",
        "xml",
        "gradle",
        "tf",
        "tfvars",
        "pem",
        "key",
        "md",
        "config",
    ];
    EXT.contains(&ext)
        || name.starts_with(".env")
        || name == "dockerfile"
        || name == "procfile"
        || name == ".npmrc"
        || name == ".pypirc"
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::github::Gh;
    use crate::github::PatPool;
    use crate::probe::Prober;
    use crate::store::Store;
    use crate::tg::Tg;
    use serde_json::json;
    use std::collections::HashMap;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::Mutex;
    use tokio::sync::mpsc;

    fn mock_github() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let key = format!("sk-live-{}", "0123456789abcdef".repeat(3));
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut s) = stream else { continue };
                let mut buf = vec![0u8; 65536];
                let n = s.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let path = req
                    .lines()
                    .next()
                    .and_then(|l| l.split_whitespace().nth(1))
                    .unwrap_or("/");
                let (ctype, body) = if path.starts_with("/api/repos/acme/demo/commits?") {
                    (
                        "application/json",
                        json!([{
                            "sha": "c1",
                            "commit": {"message": "remove key", "author": {"date": "2026-01-01T00:00:00Z"}}
                        }])
                        .to_string(),
                    )
                } else if path == "/api/repos/acme/demo/commits/c1" {
                    (
                        "application/json",
                        json!({
                            "files": [{
                                "filename": ".env",
                                "status": "modified",
                                "patch": format!("@@ -1,2 +1,1 @@\n-OPENAI_API_KEY={}\n+OPENAI_API_KEY=\n", key)
                            }]
                        })
                        .to_string(),
                    )
                } else if path == "/api/repos/acme/demo" {
                    (
                        "application/json",
                        json!({
                            "full_name": "acme/demo",
                            "default_branch": "main",
                            "stargazers_count": 42,
                            "fork": false,
                            "archived": false
                        })
                        .to_string(),
                    )
                } else if path == "/raw/acme/demo/main/.env" {
                    (
                        "text/plain",
                        "OPENAI_BASE_URL=https://api.mock-relay.test/v1\n".to_string(),
                    )
                } else {
                    (
                        "application/json",
                        json!({"message": "Not Found"}).to_string(),
                    )
                };
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    ctype,
                    body.len(),
                    body
                );
                let _ = s.write_all(resp.as_bytes());
            }
        });
        format!("http://{}", addr)
    }

    fn test_app(base: &str) -> Arc<App> {
        let store = Arc::new(Store::open(":memory:").unwrap());
        store.set_setting("commit_depth", "3").unwrap();
        store.set_setting("mine_files", "5").unwrap();
        let cfg = Config {
            tg_token: "1:test".into(),
            admin_id: 1,
            db_path: ":memory:".into(),
            tg_proxy: None,
            proxy: None,
            notify_start: false,
            rank_enabled: false,
            rank_base_url: String::new(),
            rank_model: String::new(),
            headless: false,
        };
        let pool = Arc::new(PatPool::new(store.clone()));
        store
            .add_pat(
                "ghp_testtoken1234567890",
                "tester",
                "public_repo",
                "classic",
                "alive",
            )
            .unwrap();
        pool.reload().unwrap();
        let gh = Arc::new(
            Gh::with_base(
                store.clone(),
                pool.clone(),
                None,
                format!("{}/api", base),
                format!("{}/raw", base),
            )
            .unwrap(),
        );
        let tg = Arc::new(Tg::new("1:test", None).unwrap());
        let prober = Arc::new(Prober::new(None).unwrap());
        let (tx, _rx) = mpsc::channel(4);
        Arc::new(App {
            cfg,
            store,
            tg,
            gh,
            pool,
            prober,
            sources: Arc::new(crate::sources::Sources::new(None).unwrap()),
            proxy_pool: Arc::new(crate::proxy::ProxyPool::new().unwrap()),
            scan_tx: tx,
            awaiting: Mutex::new(HashMap::new()),
            active_jobs: std::sync::atomic::AtomicUsize::new(0),
            probe_gate: Arc::new(tokio::sync::Semaphore::new(4)),
            search_gate: Arc::new(tokio::sync::Semaphore::new(4)),
            source_gate: Arc::new(tokio::sync::Semaphore::new(2)),
            manual_batches: Mutex::new(HashMap::new()),
        })
    }

    #[tokio::test]
    async fn endpoint_in_file_then_key_in_commits() {
        let base = mock_github();
        let app = test_app(&base);
        let job = Job {
            id: 1,
            chat_id: 0,
            kind: JobKind::Repo,
            query: "acme/demo".into(),
            quiet: true,
            manual: false,
            lane: crate::github::SearchLane::Pair,
        };
        let files = vec![FileRef {
            repo: "acme/demo".into(),
            path: ".env".into(),
            sha: String::new(),
        }];
        let out = process_files(&app, &job, files, 0, true).await.unwrap();
        let pairs: Vec<FoundPair> = out.into_iter().flat_map(|r| r.pairs).collect();
        assert_eq!(pairs.len(), 1, "pairs: {:?}", pairs);
        assert_eq!(pairs[0].endpoint, "https://api.mock-relay.test/v1");
        assert!(pairs[0].key.starts_with("sk-live-"));
        assert_eq!(pairs[0].commit, "c1");
        assert_eq!(pairs[0].source, "commit");
    }

    #[test]
    fn search_path_ranking_prefers_env_and_penalizes_examples() {
        assert!(
            search_path_score("\"sk-\" in:file", "service/.env")
                > search_path_score("\"sk-\" in:file", "src/main.py")
        );
        assert!(
            search_path_score("\"sk-\" in:file", "config/prod.yaml")
                > search_path_score("\"sk-\" in:file", "tests/fixture.py")
        );
    }

    #[test]
    fn official_filter_requires_first_party_endpoint() {
        let pair = |endpoint: &str, key: &str| FoundPair {
            endpoint: endpoint.into(),
            key: key.into(),
            kind: KeyKind::OpenAi,
            repo: "acme/demo".into(),
            path: ".env".into(),
            commit: String::new(),
            source: "code".into(),
            pair: true,
        };
        assert!(is_official_pair(&pair(
            "https://api.openai.com/v1",
            "sk-live"
        )));
        assert!(is_official_pair(&pair(
            "https://ws-1.cn-beijing.maas.aliyuncs.com/compatible-mode/v1",
            "sk-ws-1"
        )));
        assert!(!is_official_pair(&pair(
            "https://relay.example/v1",
            "sk-live"
        )));
    }

    #[test]
    fn official_candidate_filter_rejects_docs_and_examples() {
        assert!(is_official_candidate(".env"));
        assert!(is_official_candidate("deploy/prod/.env.production"));
        assert!(is_official_candidate("src/config.py"));
        assert!(is_official_candidate(".github/workflows/release.yml"));
        assert!(!is_official_candidate("tests/fixture.py"));
        assert!(!is_official_candidate("docs/setup.md"));
        assert!(!is_official_candidate("README.md"));
        assert!(!is_official_candidate(".env.example"));
        assert!(!is_official_candidate(".env.prod.example"));
        assert!(!is_official_candidate(".env-template"));
        assert!(is_official_candidate("server/.env"));
        assert!(is_official_candidate("config.env"));
    }

    #[test]
    fn snippet_extraction_finds_pairs_without_raw_fetch() {
        let v = serde_json::json!({
            "items": [{
                "repository": {"full_name": "acme/demo"},
                "path": ".env",
                "text_matches": [{
                    "fragment": "OPENAI_API_KEY=sk-proj-A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0\nOPENAI_BASE_URL=https://api.openai.com/v1"
                }]
            }]
        });
        let job = Job {
            id: 1,
            chat_id: 0,
            kind: JobKind::Search,
            query: "\"OPENAI_API_KEY\" in:file".into(),
            quiet: true,
            manual: false,
            lane: crate::github::SearchLane::Pair,
        };
        let pairs = snippet_pairs(&v, &job);
        assert_eq!(pairs.len(), 1, "pairs: {:?}", pairs);
        assert_eq!(pairs[0].source, "snippet");
        assert_eq!(pairs[0].path, ".env");
        assert!(pairs[0].key.starts_with("sk-proj-"));
    }

    #[test]
    fn snippet_placeholders_are_rejected() {
        let v = serde_json::json!({
            "items": [{
                "repository": {"full_name": "acme/demo"},
                "path": ".env",
                "text_matches": [{"fragment": "OPENAI_API_KEY=sk-proj-xxxxxxxxxxxxxxxxxxxx"}]
            }]
        });
        let job = Job {
            id: 1,
            chat_id: 0,
            kind: JobKind::Search,
            query: "\"OPENAI_API_KEY\" in:file".into(),
            quiet: true,
            manual: false,
            lane: crate::github::SearchLane::Pair,
        };
        assert!(snippet_pairs(&v, &job).is_empty());
    }

    #[test]
    fn candidate_filter() {
        assert!(is_candidate(".env", 100));
        assert!(is_candidate("src/config.py", 100));
        assert!(!is_candidate("node_modules/x/index.js", 100));
        assert!(!is_candidate("big.png", 100));
        assert!(!is_candidate("a.txt", 2_000_000));
    }

    #[test]
    fn pat_candidate_filter_rejects_docs_and_examples() {
        assert!(is_pat_candidate(".env"));
        assert!(is_pat_candidate("deploy/prod/.env.production"));
        assert!(is_pat_candidate(".github/workflows/release.yml"));
        assert!(is_pat_candidate("docker-compose.yml"));
        assert!(is_pat_candidate(".npmrc"));
        assert!(!is_pat_candidate("tests/fixture.env"));
        assert!(!is_pat_candidate("docs/example.env"));
        assert!(!is_pat_candidate(".env.example"));
        assert!(!is_pat_candidate("README.md"));
        assert!(!is_pat_candidate("package-lock.json"));
    }
}
