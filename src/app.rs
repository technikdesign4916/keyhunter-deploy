use crate::config::Config;
use crate::github::{Gh, PatPool, SearchLane};
use crate::probe::{ProbeOpts, Prober};
use crate::proxy::ProxyPool;
use crate::sources::Sources;
use crate::store::Store;
use crate::tg::Tg;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicI64, AtomicUsize};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, Semaphore};

#[derive(Clone, Debug)]
pub struct Job {
    pub id: i64,
    pub chat_id: i64,
    pub kind: JobKind,
    pub query: String,
    pub quiet: bool,
    /// Explicit operator action (manual `/scan`, `/repo`, source fan-out).
    /// Quiet manual jobs suppress chat progress but still get the manual
    /// cache/skip/rotation profile.
    pub manual: bool,
    pub lane: SearchLane,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JobKind {
    Search,
    Repo,
    Discover,
    Manual,
    Source,
}

impl JobKind {
    pub fn as_str(self) -> &'static str {
        match self {
            JobKind::Search => "search",
            JobKind::Repo => "repo",
            JobKind::Discover => "discover",
            JobKind::Manual => "manual",
            JobKind::Source => "source",
        }
    }
}

#[derive(Clone, Debug)]
pub enum Pending {
    Pats,
    ApiCheck,
    Stress,
    ExportFilter,
    Setting(String),
    QueryAdd,
    Scan,
}

/// One aggregate progress message for a manual scan. All per-dork jobs report
/// into this object; the chat sees `Готово: N/M`, not 80 separate messages.
pub struct ManualBatch {
    pub chat_id: i64,
    pub query: String,
    pub total: usize,
    pub done: AtomicUsize,
    pub ids: Mutex<HashSet<i64>>,
    pub message_id: AtomicI64,
    pub last_edit: AtomicI64,
    pub started: Instant,
}

impl ManualBatch {
    pub fn new(chat_id: i64, query: String, ids: &[i64]) -> Self {
        Self {
            chat_id,
            query,
            total: ids.len(),
            done: AtomicUsize::new(0),
            ids: Mutex::new(ids.iter().copied().collect()),
            message_id: AtomicI64::new(0),
            last_edit: AtomicI64::new(0),
            started: Instant::now(),
        }
    }

    pub fn mark_done(&self, id: i64) -> Option<(usize, usize)> {
        {
            let ids = self.ids.lock().unwrap_or_else(|e| e.into_inner());
            if !ids.contains(&id) {
                return None;
            }
        }
        let done = self.done.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
        Some((done, self.total))
    }

    pub fn should_edit(&self, done: usize) -> bool {
        if done >= self.total || done % 5 == 0 {
            return true;
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let last = self.last_edit.load(std::sync::atomic::Ordering::Relaxed);
        if now - last >= 2 {
            self.last_edit
                .store(now, std::sync::atomic::Ordering::Relaxed);
            true
        } else {
            false
        }
    }

    pub fn progress_text(&self, done: usize) -> String {
        let elapsed = self.started.elapsed().as_secs();
        format!(
            "📊 <b>Ручной скан</b> · готово <b>{done}/{}</b>\n             <code>{}</code>\n\n             ⏱ {}с · осталось задач: <b>{}</b>",
            self.total,
            crate::format::esc(&self.query),
            elapsed,
            self.total.saturating_sub(done)
        )
    }
}

pub struct App {
    pub cfg: Config,
    pub store: Arc<Store>,
    pub tg: Arc<Tg>,
    pub gh: Arc<Gh>,
    pub pool: Arc<PatPool>,
    pub prober: Arc<Prober>,
    pub sources: Arc<Sources>,
    pub proxy_pool: Arc<ProxyPool>,
    pub scan_tx: mpsc::Sender<Job>,
    pub awaiting: Mutex<HashMap<i64, Pending>>,
    pub active_jobs: AtomicUsize,
    pub probe_gate: Arc<Semaphore>,
    /// Limits concurrent GitHub code-search jobs across manual and auto runs.
    /// Without this, 80 manual dorks all hit search at once and burn the
    /// token pool before any page can complete.
    pub search_gate: Arc<Semaphore>,
    /// Hard cap for concurrent source jobs. Source adapters can otherwise
    /// occupy every worker and buffer hundreds of megabytes of page text.
    pub source_gate: Arc<Semaphore>,
    pub manual_batches: Mutex<HashMap<i64, Arc<ManualBatch>>>,
}

impl App {
    pub fn is_admin(&self, user_id: i64) -> bool {
        user_id == self.cfg.admin_id
    }

    pub fn probe_opts(&self) -> ProbeOpts {
        let base = self
            .store
            .setting("probe_challenge", "alibaba")
            .trim()
            .to_string();
        let base = if base.is_empty() {
            "alibaba".to_string()
        } else {
            base
        };
        let challenge = if self.store.setting_i64("probe_random", 1) == 1 {
            crate::probe::random_challenge_with(&base)
        } else {
            base
        };
        ProbeOpts {
            probe_limit: self.store.setting_i64("probe_limit", 40).clamp(1, 120) as usize,
            concurrency: self.store.setting_i64("probe_concurrency", 12).clamp(1, 96) as usize,
            message: crate::probe::challenge_prompt(&challenge),
            challenge,
            cost_probe: self.store.setting_i64("balance_cost_probe", 0) == 1,
            all_types: false,
            timeout_secs: self.store.setting_i64("probe_timeout", 30).clamp(3, 60) as u64,
            video_generate: false,
        }
    }

    pub fn report_chat(&self) -> i64 {
        self.store
            .setting("report_chat", &self.cfg.admin_id.to_string())
            .parse()
            .unwrap_or(self.cfg.admin_id)
    }

    /// Push validated Gitee/GitLab/Gitea/Codeberg PATs into the source
    /// adapters. GitHub tokens stay in the dedicated GitHub pool.
    pub fn sync_source_pats(&self) {
        self.sources.set_pat_tokens_from_store(&self.store);
    }

    pub fn set_proxy(&self, proxy: Option<String>) -> anyhow::Result<()> {
        self.gh.set_proxy(proxy.clone())?;
        self.prober.set_proxy(proxy.clone())?;
        self.sources.set_proxy(proxy)?;
        Ok(())
    }

    pub fn set_source_proxies(&self, proxies: Vec<String>) -> anyhow::Result<()> {
        self.gh.set_proxy(None)?;
        self.prober.set_proxy(None)?;
        self.sources.set_proxies(proxies)
    }

    pub fn set_scoped_proxy(&self, proxy: Option<String>, scope: &str) -> anyhow::Result<()> {
        if scope == "all" {
            return self.set_proxy(proxy);
        }
        // "sources": only external sources use the public proxy; GitHub
        // stays direct and probes stay direct for reliable validation.
        self.gh.set_proxy(None)?;
        match scope {
            "probe" => {
                self.prober.set_proxy(proxy)?;
                self.sources.set_proxy(None)?;
            }
            _ => {
                self.prober.set_proxy(None)?;
                self.sources.set_proxy(proxy)?;
            }
        }
        Ok(())
    }

    pub fn set_pending(&self, user: i64, p: Pending) {
        self.awaiting
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(user, p);
    }

    pub fn take_pending(&self, user: i64) -> Option<Pending> {
        self.awaiting
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&user)
    }

    pub fn clear_pending(&self, user: i64) {
        self.awaiting
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&user);
    }
}
