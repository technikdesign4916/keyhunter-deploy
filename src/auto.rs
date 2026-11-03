use crate::app::{App, Job, JobKind};
use crate::sources;
use crate::store::now;
use std::collections::HashSet;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use tracing::info;

pub async fn run(app: Arc<App>) {
    info!("auto-discovery loop started");
    loop {
        tokio::time::sleep(Duration::from_secs(5)).await;
        maybe_sources(&app).await;
        if app.store.setting_i64("auto", 1) != 1 {
            continue;
        }
        if app.pool.alive() == 0 {
            continue;
        }
        let workers = app.store.setting_i64("workers", 24).clamp(1, 48) as usize;
        if app.active_jobs.load(Ordering::Relaxed) >= workers {
            continue;
        }
        maybe_discover(&app).await;
        let interval = app.store.setting_i64("auto_interval", 25).max(3);
        let last = app.store.setting_i64("last_auto", 0);
        if now() - last < interval {
            continue;
        }
        let n = launch_batch(&app).await;
        if n > 0 {
            info!("auto: launched {} search jobs", n);
        }
    }
}

fn ensure_source_seed(app: &Arc<App>) {
    // Always INSERT OR IGNORE. New source packs must reach an existing DB
    // without waiting for the source_tasks table to be empty.
    let rows: Vec<(String, String, i64)> = sources::tasks()
        .iter()
        .map(|(s, q)| (s.to_string(), q.to_string(), sources::task_priority(s)))
        .collect();
    app.store.seed_source_tasks(&rows);
}

async fn queue_source(app: &Arc<App>, force: bool) -> Option<String> {
    queue_source_opts(app, force, false, None).await
}

/// `skip_interval` is used by the batch scheduler: it has already checked the
/// interval once and must queue several distinct source tasks in one tick.
async fn queue_source_opts(
    app: &Arc<App>,
    force: bool,
    skip_interval: bool,
    avoid: Option<&HashSet<String>>,
) -> Option<String> {
    if !force && app.store.setting_i64("sources", 1) != 1 {
        return None;
    }
    let workers = app.store.setting_i64("workers", 24).clamp(1, 48) as usize;
    if app.active_jobs.load(Ordering::Relaxed) >= workers {
        return None;
    }
    if !skip_interval {
        if !force {
            let interval = app.store.setting_i64("source_interval", 15).max(10);
            let last = app.store.setting_i64("last_source", 0);
            if now() - last < interval {
                return None;
            }
        } else {
            // Manual "now" is force, but still debounce it so a double tap
            // cannot flood the worker pool with source jobs.
            let last = app.store.setting_i64("last_source", 0);
            if now() - last < 60 {
                return None;
            }
        }
    }

    // Seed the durable task table once, then let the scheduler learn from
    // runs/hits. Existing static tasks are the low-priority baseline; the
    // Source Atlas adds endpoint-driven tasks on top.
    ensure_source_seed(app);

    let batch_slot = app.store.setting_i64("source_batch_slot", 0).max(0);
    let frontier_every = app
        .store
        .setting_i64("source_frontier_every", 4)
        .clamp(1, 64);
    let mut chosen: Option<(String, String)> = None;

    // Every Nth slot in a batch is a real page from the crawl frontier.
    if batch_slot % frontier_every == 0 {
        if let Some(front) = app.store.pop_frontier(1).into_iter().next() {
            let query = format!("url:{}:{}", front.depth, front.url);
            chosen = Some(("crawl".to_string(), query));
        }
    }

    if chosen.is_none() {
        let task = match avoid {
            Some(used) => app.store.next_source_task_avoid(used),
            None => app.store.next_source_task(None),
        };
        if let Some(t) = task {
            let query = if t.query.is_empty() {
                t.source.clone()
            } else {
                format!("{}|{}", t.source, t.query)
            };
            // The same exact task must not be queued twice in one batch,
            // even if a source name has many high-priority rows.
            if let Some(used) = avoid {
                if used.contains(&query) {
                    return None;
                }
            }
            chosen = Some((t.source, query));
        }
    }

    let (src, query) = chosen?;
    let id = app.store.job_start(JobKind::Source.as_str(), &query).ok()?;
    let job = Job {
        id,
        chat_id: app.report_chat(),
        kind: JobKind::Source,
        query: query.clone(),
        quiet: true,
        manual: false,
        lane: crate::github::SearchLane::Pair,
    };
    if app.scan_tx.send(job).await.is_err() {
        return None;
    }
    app.store
        .set_setting("last_source", &now().to_string())
        .ok();
    app.store
        .set_setting("source_batch_slot", &((batch_slot + 1).to_string()))
        .ok();
    info!("auto: queued source job #{} ({})", id, query);
    let _ = src;
    Some(query)
}

async fn maybe_sources(app: &Arc<App>) {
    if app.store.setting_i64("sources", 1) != 1 {
        return;
    }
    let interval = app.store.setting_i64("source_interval", 15).max(10);
    let last = app.store.setting_i64("last_source", 0);
    if now() - last < interval {
        return;
    }
    ensure_source_seed(app);
    crate::source_atlas::synthesize(app);
    let workers = app.store.setting_i64("workers", 24).clamp(1, 48) as usize;
    let batch = app.store.setting_i64("source_batch", 4).clamp(1, 32) as usize;
    // Reserve at least half the workers for GitHub search. Sources are
    // high-volume and would otherwise occupy every worker on a fast box.
    let batch = batch.min((workers * 2 / 3).max(1));
    let mut used: HashSet<String> = HashSet::new();
    for _ in 0..batch {
        if app.active_jobs.load(Ordering::Relaxed) >= workers {
            break;
        }
        let Some(query) = queue_source_opts(app, true, true, Some(&used)).await else {
            break;
        };
        used.insert(query.clone());
        if let Some((src, _)) = query.split_once('|') {
            used.insert(src.to_string());
        }
    }
}

pub async fn trigger_sources_now(app: &Arc<App>) -> Option<String> {
    queue_source(app, true).await
}

async fn maybe_discover(app: &Arc<App>) {
    if app.store.setting_i64("auto_discover", 1) != 1 {
        return;
    }
    if app.pool.core_remaining() < 10 {
        return;
    }
    let interval = app.store.setting_i64("discover_interval", 300).max(60);
    let last = app.store.setting_i64("last_discover", 0);
    if now() - last < interval {
        return;
    }
    let Ok(id) = app.store.job_start(JobKind::Discover.as_str(), "repo-hunt") else {
        return;
    };
    let job = Job {
        id,
        chat_id: app.report_chat(),
        kind: JobKind::Discover,
        query: "repo-hunt".into(),
        quiet: true,
        manual: false,
        lane: crate::github::SearchLane::Pair,
    };
    if app.scan_tx.send(job).await.is_ok() {
        app.store
            .set_setting("last_discover", &now().to_string())
            .ok();
        info!("auto: queued repo discovery #{}", id);
    }
}

pub async fn trigger_now(app: &Arc<App>) -> usize {
    launch_batch(app).await
}

async fn launch_batch(app: &Arc<App>) -> usize {
    generate_queries(app);
    let workers = app.store.setting_i64("workers", 24).clamp(1, 48) as usize;
    let active = app.active_jobs.load(Ordering::Relaxed);
    if active >= workers {
        return 0;
    }
    let batch = app.store.setting_i64("auto_batch", 6).clamp(1, 12) as usize;
    // The setting is only the fresh-pool default. After /lane the live pool
    // is authoritative, so a manual 5-official layout really uses 5 slots.
    let official_pats = app.pool.count_lane(crate::github::SearchLane::Official);
    let official_quota = app
        .pool
        .search_remaining_lane(Some(crate::github::SearchLane::Official));
    let pair_quota = app
        .pool
        .search_remaining_lane(Some(crate::github::SearchLane::Pair));
    let pat_pats = app.pool.count_lane(crate::github::SearchLane::Pat);
    let pat_quota = app
        .pool
        .search_remaining_lane(Some(crate::github::SearchLane::Pat));
    let total_search_quota = official_quota + pair_quota + pat_quota;
    if total_search_quota <= 0 {
        return 0;
    }
    let mut batch = batch.min(workers - active);
    // Search is a 10/min bucket per PAT. Do not launch a batch whose page
    // fan-out cannot fit into the remaining search tokens.
    // Page 1 is always one search request; extra pages are conditional on
    // total_count>100. Do not throttle the batch by the maximum page depth.
    let quota_cap = (total_search_quota / 2).max(1) as usize;
    batch = batch.min(quota_cap);
    if total_search_quota < 20 {
        batch = batch.min(1);
    }
    if batch == 0 {
        return 0;
    }
    let mut launched = 0usize;
    let mut official_launched = 0usize;
    let mut pat_launched = 0usize;
    let mut used_queries: HashSet<String> = HashSet::new();

    // Lane 0: GitHub PAT credentials. The burst uses the dedicated Pat lane
    // first and then the pair lane, leaving the official-provider reserve
    // untouched. Each job is a different dork; page fan-out is controlled by
    // pat_scan_pages in run_search, not by the AI scan_pages setting.
    let pat_burst = app.store.setting_i64("pat_burst", 4).clamp(1, 12) as usize;
    // DashScope is dual-lane: reserve one pair slot so the official reserve
    // and the PAT burst cannot consume the whole batch.
    let pair_reserve = usize::from(pair_quota > 0 && app.store.has_pair_lane_queries());
    let pat_budget = pat_burst.min(batch.saturating_sub(pair_reserve));
    let mut pat_lanes: Vec<crate::github::SearchLane> = Vec::new();
    if pat_quota > 0 && pat_pats > 0 {
        pat_lanes.push(crate::github::SearchLane::Pat);
    }
    if pair_quota > 0 {
        pat_lanes.push(crate::github::SearchLane::Pair);
    }
    if pat_lanes.is_empty() && official_quota > 0 && official_pats > 0 {
        pat_lanes.push(crate::github::SearchLane::Official);
    }
    while !pat_lanes.is_empty() && pat_launched < pat_budget {
        if launched >= batch {
            break;
        }
        let preferred = pat_lanes.get(pat_launched % pat_lanes.len()).copied();
        let lane = preferred
            .filter(|lane| app.pool.search_remaining_lane(Some(*lane)) > 0)
            .or_else(|| {
                pat_lanes
                    .iter()
                    .copied()
                    .find(|lane| app.pool.search_remaining_lane(Some(*lane)) > 0)
            });
        let Some(lane) = lane else { break };
        let Some(q) = app.store.next_pat_query_avoid(&used_queries) else {
            break;
        };
        let Ok(id) = app.store.job_start(JobKind::Search.as_str(), &q.q) else {
            break;
        };
        let job = Job {
            id,
            chat_id: app.report_chat(),
            kind: JobKind::Search,
            query: q.q.clone(),
            quiet: true,
            manual: false,
            lane,
        };
        if app.scan_tx.send(job).await.is_err() {
            break;
        }
        used_queries.insert(q.q.clone());
        app.store.mark_query_run(q.id, 0);
        launched += 1;
        pat_launched += 1;
        tokio::time::sleep(Duration::from_millis(320)).await;
        info!("auto: queued PAT burst #{id} lane={lane:?} ({pat_launched}/{pat_burst})");
    }

    // `official_pats` is only the default lane size. Search may fall back to
    // any live PAT when the official lane quota is exhausted, so do not cap
    // official-key jobs at three when 100+ tokens still have search budget.
    let _ = official_pats;
    let official_slots = if total_search_quota > 0 {
        batch.saturating_sub(launched + pair_reserve)
    } else {
        0
    };

    // Lane 1: dedicated official-provider PATs.
    for _ in 0..official_slots {
        let Some(q) = app.store.next_official_query_avoid(&used_queries) else {
            break;
        };
        let Ok(id) = app.store.job_start(JobKind::Search.as_str(), &q.q) else {
            break;
        };
        let job = Job {
            id,
            chat_id: app.report_chat(),
            kind: JobKind::Search,
            query: q.q.clone(),
            quiet: true,
            manual: false,
            lane: crate::github::SearchLane::Official,
        };
        if app.scan_tx.send(job).await.is_err() {
            break;
        }
        used_queries.insert(q.q.clone());
        app.store.mark_query_run(q.id, 0);
        launched += 1;
        official_launched += 1;
        tokio::time::sleep(Duration::from_millis(300)).await;
    }

    // Lane 1b: one reserved pair-lane copy of the DashScope pack.
    for _ in 0..pair_reserve {
        if launched >= batch || pair_quota <= 0 {
            break;
        }
        let Some(q) = app.store.next_dual_query_avoid(&used_queries) else {
            break;
        };
        let Ok(id) = app.store.job_start(JobKind::Search.as_str(), &q.q) else {
            break;
        };
        let job = Job {
            id,
            chat_id: app.report_chat(),
            kind: JobKind::Search,
            query: q.q.clone(),
            quiet: true,
            manual: false,
            lane: crate::github::SearchLane::Pair,
        };
        if app.scan_tx.send(job).await.is_err() {
            break;
        }
        used_queries.insert(q.q.clone());
        app.store.mark_query_run(q.id, 0);
        launched += 1;
        tokio::time::sleep(Duration::from_millis(300)).await;
        info!("auto: queued dual-lane #{id} ({})", q.q);
    }

    // Lane 2: every other PAT, PAIR/custom/relay/query-pack searches.
    let pair_slots = batch.saturating_sub(launched);
    for _ in 0..pair_slots {
        if pair_quota <= 0 {
            break;
        }
        let Some(q) = app.store.next_pair_query_avoid(&used_queries) else {
            break;
        };
        let Ok(id) = app.store.job_start(JobKind::Search.as_str(), &q.q) else {
            break;
        };
        let job = Job {
            id,
            chat_id: app.report_chat(),
            kind: JobKind::Search,
            query: q.q.clone(),
            quiet: true,
            manual: false,
            lane: crate::github::SearchLane::Pair,
        };
        if app.scan_tx.send(job).await.is_err() {
            break;
        }
        used_queries.insert(q.q.clone());
        app.store.mark_query_run(q.id, 0);
        launched += 1;
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    if launched > 0 {
        info!(
            "auto: lanes pat={} official={} pair={}",
            pat_launched,
            official_launched,
            launched.saturating_sub(official_launched + pat_launched)
        );
        app.store.set_setting("last_auto", &now().to_string()).ok();
    }
    launched
}

fn generate_queries(app: &App) {
    // Atlas owns query synthesis now: host pivot, repo pivot and owner pivot.
    let interval = app.store.setting_i64("atlas_interval", 45).max(10);
    let last = app.store.setting_i64("last_atlas", 0);
    if now() - last < interval {
        return;
    }
    let _ = crate::atlas::synthesize(app);
    app.store.set_setting("last_atlas", &now().to_string()).ok();
}
