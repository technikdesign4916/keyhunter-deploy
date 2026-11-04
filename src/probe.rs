use crate::extract::host_of;
use crate::github::{build_client, truncate};
use crate::store::ProbeLine;
use anyhow::Result;
use futures::stream::{self, FuturesUnordered, StreamExt};
use rand::seq::SliceRandom;
use rand::Rng;
use regex::Regex;
use reqwest::header::HeaderMap;
use reqwest::multipart::{Form, Part};
use reqwest::Client;
use serde_json::{json, Value};
use std::sync::{OnceLock, RwLock};
use std::time::{Duration, Instant};

const MAX_SANE_BALANCE: f64 = 1_000_000_000.0;
/// Last-resort generic catalog used when /models is unavailable. A relay
/// returning exactly this set and a 429 for every one is not a usable API:
/// it is the scanner's own fallback being echoed back.
const GENERIC_FALLBACK_MODELS: [&str; 5] = [
    "gpt-4o-mini",
    "gpt-4o",
    "gpt-3.5-turbo",
    "claude-3-haiku-20240307",
    "deepseek-chat",
];
const CHALLENGE_WORDS: &[&str] = &[
    "alibaba", "saffron", "kumquat", "tundra", "obsidian", "marigold", "cobalt", "pecan", "zephyr",
    "quartz", "juniper", "cinder", "vellum", "thistle", "pulsar", "wicker", "basalt", "nectar",
    "orchid", "garnet", "lumen", "mosaic", "onyx", "pepper", "rivet", "sable", "tamarind", "umber",
    "velvet", "willow", "yarrow", "zinc",
];

#[derive(Clone, Debug)]
pub struct ProbeOpts {
    pub probe_limit: usize,
    pub concurrency: usize,
    pub message: String,
    pub challenge: String,
    /// Opt-in: send one intentionally over-budget request only when every
    /// billing endpoint returned nothing. Some relays reveal the remaining
    /// balance in the pre-deduct error. Disabled by default.
    pub cost_probe: bool,
    /// Manual scans validate every supported modality (embeddings, images,
    /// audio, rerank, moderation, ASR), not only chat/TTS. Automatic scans
    /// keep the cheaper chat/TTS path.
    pub all_types: bool,
    /// Per-request timeout for /models and chat probes. The file checker uses
    /// a short value; background scans can afford a longer one.
    pub timeout_secs: u64,
    /// Manual/API-checker only: generate one minimal video for every Seedance
    /// model, then delete the task immediately. Never enabled for auto scans.
    pub video_generate: bool,
}

/// OCR/embedding/audio/rerank models can answer HTTP 200 without being a
/// general chat model. They must not make an API key look usable.
pub fn is_non_chat_model(model: &str) -> bool {
    let m = model.to_ascii_lowercase();
    [
        "ocr",
        "embed",
        "rerank",
        "tts",
        "speech",
        "audio",
        "voice",
        "whisper",
        "transcribe",
        "asr",
        "image",
        "wanx",
        "wan2",
        "flux",
        "stable-diffusion",
        "cosyvoice",
        "paraformer",
        "sambert",
        "sensevoice",
    ]
    .iter()
    .any(|needle| m.contains(needle))
}

fn is_generic_fallback_429(probes: &[ProbeLine], models: &[String]) -> bool {
    if probes.len() != GENERIC_FALLBACK_MODELS.len()
        || models.len() != GENERIC_FALLBACK_MODELS.len()
        || probes.iter().any(|p| p.code != 429)
    {
        return false;
    }
    let expected: std::collections::HashSet<String> = GENERIC_FALLBACK_MODELS
        .iter()
        .map(|m| m.to_ascii_lowercase())
        .collect();
    let probed: std::collections::HashSet<String> = probes
        .iter()
        .map(|p| p.model.to_ascii_lowercase())
        .collect();
    let catalog: std::collections::HashSet<String> =
        models.iter().map(|m| m.to_ascii_lowercase()).collect();
    probed == expected && catalog == expected
}

pub fn challenge_prompt(word: &str) -> String {
    format!(
        "Reply with exactly this token and nothing else: {word}\n\
         Rules: no punctuation, no quotes, no spaces, no explanations, no markdown, \
         no code block, no ASCII art. Only the token."
    )
}

pub fn random_challenge() -> String {
    random_challenge_with("")
}

pub fn random_challenge_with(base: &str) -> String {
    let mut rng = rand::thread_rng();
    let clean: String = base
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .collect();
    let stem = if clean.is_empty() {
        CHALLENGE_WORDS
            .choose(&mut rng)
            .copied()
            .unwrap_or("alibaba")
            .to_string()
    } else {
        clean
    };
    format!("{stem}-{:06x}", rng.gen_range(0..=0xff_ffff))
}

impl Default for ProbeOpts {
    fn default() -> Self {
        let challenge = random_challenge();
        Self {
            probe_limit: 26,
            concurrency: 3,
            message: challenge_prompt(&challenge),
            challenge,
            cost_probe: false,
            all_types: false,
            timeout_secs: 30,
            video_generate: false,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PStatus {
    Valid,
    Limited,
    Invalid,
    Unreachable,
    Partial,
    Fake,
}

impl PStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            PStatus::Valid => "VALID",
            PStatus::Limited => "LIMIT",
            PStatus::Invalid => "INVALID",
            PStatus::Unreachable => "UNREACHABLE",
            PStatus::Partial => "PARTIAL",
            PStatus::Fake => "FAKE",
        }
    }

    pub fn icon(self) -> &'static str {
        match self {
            PStatus::Valid => "✅",
            PStatus::Limited => "⏱️",
            PStatus::Invalid => "❌",
            PStatus::Unreachable => "🌐",
            PStatus::Partial => "⚠️",
            PStatus::Fake => "🎭",
        }
    }
}

#[derive(Clone, Debug)]
pub struct ProbeOutcome {
    pub endpoint: String,
    pub base: String,
    pub status: PStatus,
    pub models: Vec<String>,
    pub probes: Vec<ProbeLine>,
    pub tested: usize,
    pub chat_ok: bool,
    pub latency_ms: u64,
    pub http_status: u16,
    pub balance: String,
    /// Provider rate limit from x-ratelimit-* headers, e.g. "500/мин".
    pub rpm: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TtsProvider {
    Fish,
    Eleven,
}

fn tts_provider(endpoint: &str) -> Option<TtsProvider> {
    let host = host_of(endpoint);
    if host.contains("fish.audio") {
        Some(TtsProvider::Fish)
    } else if host.contains("elevenlabs.io") {
        Some(TtsProvider::Eleven)
    } else {
        None
    }
}

/// Seedance is served by Volcengine Ark (and compatible relays) through a
/// different, asynchronous video-generation API. Keep it separate from chat:
/// the key can be perfectly valid for Ark chat and still have no video
/// entitlement.
fn is_seedance_endpoint(endpoint: &str) -> bool {
    let host = host_of(endpoint);
    host.contains("seedance")
        || host.starts_with("ark.")
        || host.contains(".ark.")
        || (host.contains("volces.com") && endpoint.contains("/api/v3"))
}

fn seedance_base(endpoint: &str) -> String {
    let trimmed = endpoint.trim().trim_end_matches('/');
    let host = host_of(trimmed);
    if trimmed.ends_with("/api/v3") {
        trimmed.to_string()
    } else if host.contains("seedance")
        || host.starts_with("ark.")
        || host.contains(".ark.")
        || host.contains("volces.com")
        || host.contains("bytepluses.com")
    {
        format!("{}/api/v3", origin_of(trimmed))
    } else {
        trimmed.to_string()
    }
}

pub fn is_tts_catalog(models: &[String]) -> bool {
    models.iter().any(|m| m.starts_with("tts/"))
}

pub fn is_special_catalog(models: &[String]) -> bool {
    models
        .iter()
        .any(|m| m.starts_with("tts/") || m.starts_with("type/") || m.starts_with("video/"))
}

pub struct Prober {
    http: RwLock<Client>,
}

impl Prober {
    pub fn new(proxy: Option<String>) -> Result<Self> {
        Ok(Self {
            http: RwLock::new(build_client(proxy.as_deref(), 45)?),
        })
    }

    pub fn set_proxy(&self, proxy: Option<String>) -> Result<()> {
        *self.http.write().unwrap_or_else(|e| e.into_inner()) = build_client(proxy.as_deref(), 45)?;
        Ok(())
    }

    pub async fn test_model_hi(&self, endpoint: &str, key: &str, model: &str) -> bool {
        if is_disabled_api(endpoint) {
            return false;
        }
        let client = self.client();
        for base in candidates(endpoint) {
            let anthropic = is_anthropic(&base);
            match chat_request(&client, &base, key, model, "hi", anthropic, 30).await {
                Ok((200, _, text, _)) => {
                    if answer_text(&text)
                        .map(|answer| !answer.trim().is_empty())
                        .unwrap_or(false)
                    {
                        return true;
                    }
                }
                _ => {}
            }
        }
        false
    }

    pub async fn probe(&self, endpoint: &str, key: &str, opts: &ProbeOpts) -> ProbeOutcome {
        let started = Instant::now();
        // Official Mistral API keys are deliberately not accepted by this
        // scanner. Do not waste a request or let a valid response resurrect
        // them from history/imports.
        if is_disabled_api(endpoint) {
            return ProbeOutcome {
                endpoint: endpoint.trim_end_matches('/').to_string(),
                base: endpoint.trim_end_matches('/').to_string(),
                status: PStatus::Invalid,
                models: Vec::new(),
                probes: Vec::new(),
                tested: 0,
                chat_ok: false,
                latency_ms: started.elapsed().as_millis() as u64,
                http_status: 0,
                balance: String::new(),
                rpm: String::new(),
            };
        }
        if is_seedance_endpoint(endpoint) {
            return self.probe_seedance(endpoint, key, opts, started).await;
        }
        if let Some(provider) = tts_provider(endpoint) {
            return self.probe_tts(endpoint, key, opts, provider, started).await;
        }
        let bases = candidates(endpoint);
        let mut models: Vec<String> = Vec::new();
        let mut models_code: u16 = 0;
        let mut models_auth = false;
        let mut rpm = String::new();
        let mut balance_hint = String::new();
        let mut base_used = bases
            .first()
            .cloned()
            .unwrap_or_else(|| endpoint.trim_end_matches('/').to_string());

        // Discover the working base in parallel. A dead origin can otherwise
        // cost three sequential timeouts before chat probes even start.
        let mut base_probes = FuturesUnordered::new();
        for (idx, b) in bases.iter().cloned().enumerate() {
            let client = self.client();
            let key = key.to_string();
            let timeout_secs = opts.timeout_secs;
            let anthropic = is_anthropic(&b);
            base_probes.push(async move {
                let r = get_models(&client, &b, &key, anthropic, timeout_secs).await;
                (idx, b, r)
            });
        }
        let mut first_401: Option<String> = None;
        // The exact endpoint is candidate 0. A fallback base may answer 200
        // first (OpenRouter serves /models at the origin too), but its chat
        // route is not necessarily the same. Wait for the exact base and only
        // use a fallback after the exact one has failed.
        let mut fallback_ok: Option<(String, Vec<String>, String)> = None;
        while let Some((idx, b, result)) = base_probes.next().await {
            match result {
                Ok((code, list, header_rpm, body)) => {
                    if code != 200 && is_google(&b, key) && google_auth_error(code, &body) {
                        models_auth = true;
                        models_code = code;
                    }
                    if code == 200 {
                        if idx == 0 {
                            base_used = b;
                            models_code = 200;
                            rpm = header_rpm;
                            models = list;
                            break;
                        }
                        // A 200 with an empty catalog is not evidence that this
                        // candidate is the API base: a marketing/landing page at
                        // `{origin}/models` also answers 200. Accepting it moved
                        // the chat route to `{origin}/chat/completions`, which
                        // 404s on every model and hides a live key as PARTIAL.
                        if !list.is_empty() && fallback_ok.is_none() {
                            fallback_ok = Some((b, list, header_rpm));
                        }
                    } else if idx == 0 && code == 401 && first_401.is_none() {
                        first_401 = Some(b);
                    }
                    if balance_hint.is_empty() {
                        balance_hint = parse_balance_error(&body).unwrap_or_default();
                    }
                }
                Err(_) => {}
            }
            if idx == 0 {
                if let Some((fallback_base, fallback_models, fallback_rpm)) = fallback_ok.take() {
                    base_used = fallback_base;
                    models_code = 200;
                    models = fallback_models;
                    rpm = fallback_rpm;
                    break;
                }
            }
        }
        if models_code == 0 {
            if let Some((fallback_base, fallback_models, fallback_rpm)) = fallback_ok.take() {
                base_used = fallback_base;
                models_code = 200;
                models = fallback_models;
                rpm = fallback_rpm;
            } else if let Some(b) = first_401 {
                // A 401 /models base is still the right base for chat: many
                // relays authenticate chat even when /models is restricted.
                base_used = b;
                models_code = 401;
            }
        }

        let anthropic = is_anthropic(&base_used);
        if models.is_empty() {
            models = fallback_models(&base_used, key, anthropic);
        }
        let selected = select_models(&models, opts.probe_limit);
        let cost_model = selected.first().cloned();
        let client = self.client();
        let base = base_used.clone();
        let key_owned = key.to_string();
        let msg = opts.message.clone();
        let challenge = opts.challenge.clone();
        let conc = opts.concurrency.max(1);

        let probes_fut = stream::iter(selected.into_iter().map(|m| {
            let client = client.clone();
            let base = base.clone();
            let key = key_owned.clone();
            let msg = msg.clone();
            let challenge = challenge.clone();
            async move {
                probe_one(
                    &client,
                    &base,
                    &key,
                    &m,
                    &msg,
                    &challenge,
                    anthropic,
                    opts.timeout_secs,
                )
                .await
            }
        }))
        .buffer_unordered(conc)
        .collect::<Vec<(ProbeLine, String)>>();
        // Balance is independent of model probes — run it alongside them instead
        // of adding its latency after the slowest chat request.
        let balance_fut = async {
            // A relay can expose billing endpoints even when /models is 404 or
            // returns a bespoke schema. Only a hard 401 proves the key is dead.
            if models_code != 401 {
                balance_for(&client, endpoint, key, anthropic).await
            } else {
                String::new()
            }
        };
        let (probe_pairs, mut balance) = tokio::join!(probes_fut, balance_fut);
        let (mut probes, probe_hints): (Vec<ProbeLine>, Vec<String>) =
            probe_pairs.into_iter().unzip();
        if balance.is_empty() {
            balance = probe_hints
                .into_iter()
                .find(|s| !s.is_empty())
                .or_else(|| (!balance_hint.is_empty()).then_some(balance_hint))
                .unwrap_or_default();
        }
        if balance.is_empty() && opts.cost_probe {
            if let Some(model) = cost_model.as_deref() {
                balance = cost_probe_balance(&client, &base_used, key, model, anthropic)
                    .await
                    .unwrap_or_default();
            }
        }

        let type_probes = if opts.all_types {
            all_type_probes(&client, &base_used, key, &models, opts.timeout_secs).await
        } else {
            Vec::new()
        };
        let type_ok = type_probes
            .iter()
            .any(|p| p.code == 200 && p.note.starts_with("type "));
        for p in &type_probes {
            if !models.contains(&p.model) {
                models.push(p.model.clone());
            }
        }
        probes.extend(type_probes);

        let ok = probes
            .iter()
            .filter(|p| p.code == 200 && p.note.is_empty())
            .count();
        let ok_chat = probes
            .iter()
            .filter(|p| p.code == 200 && p.note.is_empty() && !is_non_chat_model(&p.model))
            .count();
        let http_ok = probes.iter().filter(|p| p.code == 200).count();
        let fake = probes
            .iter()
            .filter(|p| p.code == 200 && p.note.starts_with("фейк"))
            .count();
        let empty = probes
            .iter()
            .filter(|p| p.code == 200 && p.note == "пустой ответ")
            .count();
        let no_token: Vec<&str> = probes
            .iter()
            .filter(|p| p.code == 200 && p.note.starts_with("нет challenge · "))
            .map(|p| {
                p.note
                    .split_once(" · ")
                    .map(|(_, preview)| preview)
                    .unwrap_or("")
            })
            .filter(|preview| !preview.is_empty() && *preview != "пусто")
            .collect();
        // A static relay often answers every model with the same canned line.
        // Two distinct models returning the identical no-token preview is a
        // stronger fake signal than one model merely ignoring the challenge.
        let repeated_no_token = no_token.len() >= 2
            && no_token
                .iter()
                .collect::<std::collections::HashSet<_>>()
                .len()
                == 1;
        let rate = probes.iter().filter(|p| p.code == 429).count();
        let auth = probes
            .iter()
            .filter(|p| p.code == 401 || p.note == "ключ")
            .count();
        let net = probes.iter().filter(|p| p.code == 0).count();
        let tested = probes.len();

        let mut status = if models_auth {
            PStatus::Invalid
        } else if ok_chat > 0 || type_ok {
            PStatus::Valid
        } else if ok > 0 {
            // Only OCR/embedding/audio/rerank models answered: the key is not
            // a usable chat credential.
            PStatus::Invalid
        } else if (fake > 0 && (fake >= 2 || fake == http_ok))
            || (empty > 0 && empty == http_ok)
            || repeated_no_token
        {
            // One suspicious model among 404s is not enough to call a whole
            // endpoint fake. Require repeated fakes, every HTTP-200 probe
            // protocol-invalid/empty, or the same no-token answer from two
            // independent models (a static relay echo).
            PStatus::Fake
        } else if rate > 0 {
            if is_generic_fallback_429(&probes, &models) {
                // Every model is one of the five generic fallbacks and every
                // one is 429. This is a dead/blocked relay, not a usable key.
                PStatus::Invalid
            } else {
                PStatus::Limited
            }
        } else if tested > 0 && auth == tested {
            PStatus::Invalid
        } else if models_code == 401 {
            PStatus::Invalid
        } else if tested > 0 && net == tested {
            PStatus::Unreachable
        } else {
            PStatus::Partial
        };
        // User validity rule: a positive balance or `?` is VALID; a zero or
        // negative OpenRouter balance is not. OpenRouter sometimes still
        // answers a free model on an exhausted account, so a 200 alone must
        // not promote it to VALID.
        let openrouter = base_used.to_ascii_lowercase().contains("openrouter")
            || key.to_ascii_lowercase().starts_with("sk-or-v1-");
        if openrouter
            && matches!(status, PStatus::Valid | PStatus::Limited)
            && !balance.is_empty()
            && balance_is_nonpositive(&balance)
        {
            status = PStatus::Invalid;
        }

        let mut sorted = probes;
        sorted.sort_by_key(|p| match p.code {
            200 if p.note.is_empty() => (0, p.latency_ms),
            429 => (1, p.latency_ms),
            200 => (2, p.latency_ms),
            _ => (3, p.latency_ms),
        });
        if rpm.is_empty() {
            rpm = sorted
                .iter()
                .find(|p| !p.rpm.is_empty())
                .map(|p| p.rpm.clone())
                .unwrap_or_default();
        }

        ProbeOutcome {
            endpoint: endpoint.trim_end_matches('/').to_string(),
            base: base_used,
            status,
            models,
            probes: sorted,
            tested,
            chat_ok: ok_chat > 0,
            latency_ms: started.elapsed().as_millis() as u64,
            http_status: models_code,
            balance,
            rpm: if rpm.is_empty() { "?".to_string() } else { rpm },
        }
    }

    /// Validate a Seedance/Ark key without creating a paid video task. A
    /// successful task-list call proves authentication; the model catalog
    /// tells us which Seedance versions the key exposes. We deliberately do
    /// not POST a generation request here — that spends credits and can take
    /// minutes, which is unacceptable for a scanner.
    async fn probe_seedance(
        &self,
        endpoint: &str,
        key: &str,
        opts: &ProbeOpts,
        started: Instant,
    ) -> ProbeOutcome {
        let client = self.client();
        let base = seedance_base(endpoint);
        if base.is_empty() {
            return ProbeOutcome {
                endpoint: endpoint.trim_end_matches('/').to_string(),
                base: endpoint.trim_end_matches('/').to_string(),
                status: PStatus::Unreachable,
                models: Vec::new(),
                probes: Vec::new(),
                tested: 0,
                chat_ok: false,
                latency_ms: started.elapsed().as_millis() as u64,
                http_status: 0,
                balance: "?".to_string(),
                rpm: "?".to_string(),
            };
        }
        let timeout = Duration::from_secs(opts.timeout_secs.clamp(5, 90));
        let tasks_url = format!("{base}/contents/generations/tasks?limit=1");
        let models_url = format!("{base}/models");

        let tasks = client
            .get(&tasks_url)
            .bearer_auth(key)
            .timeout(timeout)
            .send()
            .await;
        let (tasks_code, tasks_json, rpm) = match tasks {
            Ok(resp) => {
                let code = resp.status().as_u16();
                let rpm = parse_rpm_headers(resp.headers());
                let text = resp.text().await.unwrap_or_default();
                let json = serde_json::from_str::<Value>(&text).ok();
                (code, json, rpm)
            }
            Err(_) => (0, None, String::new()),
        };
        let mut models: Vec<String> = Vec::new();
        if let Ok(resp) = client
            .get(&models_url)
            .bearer_auth(key)
            .timeout(timeout)
            .send()
            .await
        {
            if resp.status().is_success() {
                if let Ok(v) = resp.json::<Value>().await {
                    let arr = v
                        .as_array()
                        .or_else(|| v.get("data").and_then(|x| x.as_array()))
                        .or_else(|| v.get("models").and_then(|x| x.as_array()));
                    if let Some(arr) = arr {
                        for item in arr {
                            let id = item.as_str().map(str::to_string).or_else(|| {
                                item.get("id")
                                    .or_else(|| item.get("name"))
                                    .and_then(|x| x.as_str())
                                    .map(str::to_string)
                            });
                            let Some(id) = id else { continue };
                            if id.to_ascii_lowercase().contains("seedance") {
                                models.push(id);
                            }
                        }
                    }
                }
            }
        }
        models.sort();
        models.dedup();
        let output_models: Vec<String> = models
            .iter()
            .map(|m| format!("video/seedance/{m}"))
            .collect();
        let authenticated = tasks_code == 200 && tasks_json.is_some();
        let latency_started = Instant::now();
        let mut probes: Vec<ProbeLine> = Vec::new();
        let mut any_video_ok = false;
        let mut any_delete_failed = false;
        if authenticated && opts.video_generate {
            // Real generation probe. The request is deliberately tiny:
            // 480p, the shortest supported duration, no audio, a trivial
            // prompt. Every created task is deleted immediately after it
            // reaches a terminal state (or after the polling deadline).
            for model in &models {
                let (code, note, deleted, ok) = seedance_generate_video(
                    &client,
                    &base,
                    key,
                    model,
                    Duration::from_secs(opts.timeout_secs.clamp(180, 360)),
                )
                .await;
                any_video_ok |= ok && deleted;
                any_delete_failed |= ok && !deleted;
                probes.push(ProbeLine {
                    model: format!("video/seedance/{model}"),
                    code,
                    latency_ms: latency_started.elapsed().as_millis() as u64,
                    note,
                    rpm: rpm.clone(),
                });
            }
        } else {
            for m in &output_models {
                probes.push(ProbeLine {
                    model: m.clone(),
                    code: if authenticated { 200 } else { tasks_code },
                    latency_ms: latency_started.elapsed().as_millis() as u64,
                    note: if authenticated {
                        "seedance ok".to_string()
                    } else {
                        format!("seedance HTTP {tasks_code}")
                    },
                    rpm: rpm.clone(),
                });
            }
        }
        let status = if authenticated && opts.video_generate {
            if any_video_ok && !any_delete_failed {
                PStatus::Valid
            } else if any_video_ok {
                PStatus::Partial
            } else {
                PStatus::Invalid
            }
        } else if authenticated {
            // Authentication alone is not a Seedance entitlement. Only a
            // real generated+deleted video can promote the key to VALID;
            // background scans use Partial so a chat-only Ark key is not
            // mistaken for a working video key.
            PStatus::Partial
        } else {
            match tasks_code {
                401 | 402 | 403 => PStatus::Invalid,
                429 => PStatus::Limited,
                0 => PStatus::Unreachable,
                _ => PStatus::Partial,
            }
        };
        let latency =
            latency_started.elapsed().as_millis() as u64 + started.elapsed().as_millis() as u64;
        ProbeOutcome {
            endpoint: endpoint.trim_end_matches('/').to_string(),
            base,
            status,
            models: output_models,
            tested: probes.len(),
            chat_ok: false,
            latency_ms: latency,
            http_status: tasks_code,
            balance: "?".to_string(),
            rpm: if rpm.is_empty() { "?".to_string() } else { rpm },
            probes,
        }
    }

    async fn probe_tts(
        &self,
        endpoint: &str,
        key: &str,
        opts: &ProbeOpts,
        provider: TtsProvider,
        started: Instant,
    ) -> ProbeOutcome {
        let client = self.client();
        let origin = origin_of(endpoint);
        let origin = if origin.is_empty() {
            match provider {
                TtsProvider::Fish => "https://api.fish.audio".to_string(),
                TtsProvider::Eleven => "https://api.elevenlabs.io".to_string(),
            }
        } else {
            match provider {
                TtsProvider::Fish
                    if origin.eq_ignore_ascii_case("https://fish.audio")
                        || origin.eq_ignore_ascii_case("https://www.fish.audio") =>
                {
                    "https://api.fish.audio".to_string()
                }
                TtsProvider::Eleven
                    if origin.eq_ignore_ascii_case("https://elevenlabs.io")
                        || origin.eq_ignore_ascii_case("https://www.elevenlabs.io") =>
                {
                    "https://api.elevenlabs.io".to_string()
                }
                _ => origin,
            }
        };
        let timeout = Duration::from_secs(opts.timeout_secs.clamp(5, 90));
        let (provider_name, models) = match provider {
            TtsProvider::Fish => {
                let mut models = vec!["s2.1-pro-free".to_string()];
                if opts.all_types {
                    models.extend(
                        ["s2-pro", "s2.1-pro", "drama-3"]
                            .into_iter()
                            .map(str::to_string),
                    );
                }
                ("fish", models)
            }
            TtsProvider::Eleven => {
                let models = if opts.all_types {
                    tts_eleven_models(&client, &origin, key, timeout).await
                } else {
                    vec!["eleven_flash_v2_5".to_string()]
                };
                ("elevenlabs", models)
            }
        };
        let voice = if provider == TtsProvider::Eleven {
            tts_eleven_voice(&client, &origin, key, timeout).await
        } else {
            String::new()
        };
        let mut probes = Vec::new();
        let mut output_models = Vec::new();
        let mut any_ok = false;
        let mut last_code = 0u16;
        let mut last_body = String::new();
        for model in models {
            let url = match provider {
                TtsProvider::Fish => format!("{origin}/v1/tts"),
                TtsProvider::Eleven => format!(
                    "{origin}/v1/text-to-speech/{}?output_format=mp3_22050_32",
                    voice
                ),
            };
            let request = match provider {
                TtsProvider::Fish => client
                    .post(&url)
                    .bearer_auth(key)
                    .header("model", &model)
                    .header("Accept", "audio/mpeg")
                    .json(&json!({"text":"hi","format":"mp3"}))
                    .timeout(timeout),
                TtsProvider::Eleven => client
                    .post(&url)
                    .header("xi-api-key", key)
                    .header("Accept", "audio/mpeg")
                    .json(&json!({"text":"hi","model_id":model}))
                    .timeout(timeout),
            };
            let t0 = Instant::now();
            let (code, content_type, bytes, body) = match request.send().await {
                Ok(resp) => {
                    let code = resp.status().as_u16();
                    let content_type = resp
                        .headers()
                        .get(reqwest::header::CONTENT_TYPE)
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("")
                        .to_string();
                    let body = resp.bytes().await.map(|b| b.to_vec()).unwrap_or_default();
                    (code, content_type, body, String::new())
                }
                Err(e) => (0, String::new(), Vec::new(), e.to_string()),
            };
            let audio_ok = code == 200
                && bytes.len() > 32
                && (content_type.starts_with("audio/")
                    || content_type.contains("octet-stream")
                    || content_type.is_empty());
            any_ok |= audio_ok;
            last_code = code;
            last_body = body;
            let probe_model = format!("tts/{provider_name}/{model}");
            output_models.push(probe_model.clone());
            let note = if audio_ok {
                "tts ok".to_string()
            } else if !last_body.is_empty() {
                format!("tts HTTP {code}: {}", truncate(&last_body, 120))
            } else {
                format!("tts HTTP {code}")
            };
            probes.push(ProbeLine {
                model: probe_model,
                code,
                latency_ms: t0.elapsed().as_millis() as u64,
                note,
                rpm: String::new(),
            });
        }
        let status = if any_ok {
            PStatus::Valid
        } else {
            match last_code {
                401 | 403 | 400 => PStatus::Invalid,
                402 | 429 => PStatus::Limited,
                0 => PStatus::Unreachable,
                _ => PStatus::Partial,
            }
        };
        let balance = if provider == TtsProvider::Fish && last_code != 0 {
            tts_fish_balance(&client, &origin, key, timeout).await
        } else {
            "?".to_string()
        };
        let tested = probes.len();
        ProbeOutcome {
            endpoint: endpoint.trim_end_matches('/').to_string(),
            base: origin,
            status,
            models: output_models,
            probes,
            tested,
            chat_ok: false,
            latency_ms: started.elapsed().as_millis() as u64,
            http_status: last_code,
            balance,
            rpm: "?".to_string(),
        }
    }

    fn client(&self) -> Client {
        self.http.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub fn http_client(&self) -> Client {
        self.client()
    }
}

/// One tiny image accepted by Ark's image-to-video models. It is the
/// official documentation asset, so it is reachable from Ark's own network.
const SEEDANCE_IMAGE_URL: &str =
    "https://arkdocs.tos-cn-beijing.volces.com/images/video-generation/seedance2.5_reference1.png";

fn seedance_request_body(model: &str) -> Value {
    let i2v = model.to_ascii_lowercase().contains("i2v");
    let mut content = vec![json!({
        "type": "text",
        "text": "A red dot on a white background"
    })];
    if i2v {
        content.push(json!({
            "type": "image_url",
            "image_url": {"url": SEEDANCE_IMAGE_URL},
            "role": "first_frame"
        }));
    }
    let mut body = json!({
        "model": model,
        "content": content,
        "resolution": "480p",
        "duration": 5
    });
    if !i2v {
        body["ratio"] = json!("16:9");
    }
    body
}

/// Create, poll and always delete a Seedance task. Returns
/// (http_code, note, deleted, generated_ok). A failed DELETE makes the result
/// PARTIAL rather than VALID: a generated video must never be left behind.
async fn seedance_generate_video(
    client: &Client,
    base: &str,
    key: &str,
    model: &str,
    poll_window: Duration,
) -> (u16, String, bool, bool) {
    let client = client.clone();
    let body = seedance_request_body(model);
    let resp = client
        .post(format!("{base}/contents/generations/tasks"))
        .bearer_auth(key)
        .json(&body)
        .timeout(Duration::from_secs(30))
        .send()
        .await;
    let (code, text) = match resp {
        Ok(r) => (r.status().as_u16(), r.text().await.unwrap_or_default()),
        Err(e) => (0, e.without_url().to_string()),
    };
    if code != 200 {
        return (
            code,
            format!("seedance HTTP {code}: {}", truncate(&text, 160)),
            false,
            false,
        );
    }
    let task_id = serde_json::from_str::<Value>(&text)
        .ok()
        .and_then(|v| v.get("id").and_then(|x| x.as_str()).map(str::to_string));
    let Some(task_id) = task_id else {
        return (code, "seedance: no task id".to_string(), false, false);
    };
    let deadline = Instant::now() + poll_window;
    let mut status = String::new();
    let mut error_text = String::new();
    while Instant::now() < deadline {
        tokio::time::sleep(Duration::from_secs(2)).await;
        let q = client
            .get(format!("{base}/contents/generations/tasks/{task_id}"))
            .bearer_auth(key)
            .timeout(Duration::from_secs(20))
            .send()
            .await;
        let Ok(q) = q else { continue };
        if !q.status().is_success() {
            continue;
        }
        let Ok(v) = q.json::<Value>().await else {
            continue;
        };
        status = v
            .get("status")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        error_text = v
            .get("error")
            .and_then(|e| e.get("message"))
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        if matches!(
            status.as_str(),
            "succeeded" | "failed" | "cancelled" | "expired"
        ) {
            break;
        }
    }
    // If the task is still generating when the normal poll window ends,
    // wait for it to finish (DELETE cannot cancel a running task) before
    // removing it. This is the last line of defence against leaving a paid
    // video behind.
    if status == "queued" || status == "running" {
        let cleanup_deadline = Instant::now() + Duration::from_secs(300);
        while Instant::now() < cleanup_deadline {
            tokio::time::sleep(Duration::from_secs(5)).await;
            let q = client
                .get(format!("{base}/contents/generations/tasks/{task_id}"))
                .bearer_auth(key)
                .timeout(Duration::from_secs(20))
                .send()
                .await;
            let Ok(q) = q else { continue };
            if !q.status().is_success() {
                continue;
            }
            let Ok(v) = q.json::<Value>().await else {
                continue;
            };
            status = v
                .get("status")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            error_text = v
                .get("error")
                .and_then(|e| e.get("message"))
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            if matches!(
                status.as_str(),
                "succeeded" | "failed" | "cancelled" | "expired"
            ) {
                break;
            }
        }
    }
    // Delete whether it succeeded, failed, or timed out. DELETE is the
    // documented way to remove the task and its output.
    let mut delete_code = 0u16;
    for _ in 0..4 {
        let d = client
            .delete(format!("{base}/contents/generations/tasks/{task_id}"))
            .bearer_auth(key)
            .timeout(Duration::from_secs(20))
            .send()
            .await;
        if let Ok(d) = d {
            delete_code = d.status().as_u16();
            if delete_code == 204 || delete_code == 200 {
                break;
            }
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    let deleted = delete_code == 204 || delete_code == 200;
    let ok = status == "succeeded";
    let note = if ok && deleted {
        "video ok · deleted".to_string()
    } else if ok {
        format!("video ok · delete HTTP {delete_code}")
    } else if !error_text.is_empty() {
        format!("seedance {status}: {}", truncate(&error_text, 180))
    } else {
        format!("seedance {status} · delete HTTP {delete_code}")
    };
    let result_code = if ok { 200 } else { 422 };
    (result_code, note, deleted, ok)
}

/// Probe every non-chat model exposed by the endpoint's catalog. This runs
/// only for explicit manual checks: automatic
/// scans stay on the cheap chat/TTS path.
async fn all_type_probes(
    client: &Client,
    base: &str,
    key: &str,
    models: &[String],
    timeout_secs: u64,
) -> Vec<ProbeLine> {
    let mut out = Vec::new();
    let timeout = Duration::from_secs(timeout_secs.clamp(5, 60));
    for model in models {
        let lm = model.to_ascii_lowercase();
        let kind = if lm.contains("embed") {
            "embed"
        } else if lm.contains("image")
            || lm.contains("dall-e")
            || lm.contains("flux")
            || lm.contains("stable-diffusion")
            || lm.contains("wanx")
            || lm.contains("imagen")
        {
            "image"
        } else if lm.contains("whisper")
            || lm.contains("transcribe")
            || lm.contains("asr")
            || lm.contains("paraformer")
            || lm.contains("sensevoice")
        {
            "asr"
        } else if lm.contains("tts")
            || lm.contains("speech")
            || lm.contains("audio")
            || lm.contains("voice")
        {
            "tts"
        } else if lm.contains("rerank") {
            "rerank"
        } else if lm.contains("moderation") {
            "moderation"
        } else {
            continue;
        };
        let url = match kind {
            "embed" => api_url(base, "/embeddings"),
            "image" => api_url(base, "/images/generations"),
            "asr" => api_url(base, "/audio/transcriptions"),
            "tts" => api_url(base, "/audio/speech"),
            "rerank" => api_url(base, "/rerank"),
            _ => api_url(base, "/moderations"),
        };
        let started = Instant::now();
        let result = match kind {
            "asr" => {
                let wav = tiny_wav();
                let form = Form::new().text("model", model.clone()).part(
                    "file",
                    Part::bytes(wav)
                        .file_name("probe.wav")
                        .mime_str("audio/wav")
                        .unwrap_or_else(|_| Part::bytes(Vec::new())),
                );
                client
                    .post(&url)
                    .bearer_auth(key)
                    .multipart(form)
                    .timeout(timeout)
                    .send()
                    .await
            }
            _ => {
                let body = match kind {
                    "embed" => json!({"model": model, "input": "hi"}),
                    "image" => json!({"model": model, "prompt": "a dot", "n": 1}),
                    "tts" => json!({"model": model, "input": "hi", "voice": "alloy"}),
                    "rerank" => json!({"model": model, "query": "hi", "documents": ["hi"]}),
                    _ => json!({"model": model, "input": "hi"}),
                };
                client
                    .post(&url)
                    .bearer_auth(key)
                    .json(&body)
                    .timeout(timeout)
                    .send()
                    .await
            }
        };
        let (code, note) = match result {
            Ok(resp) => {
                let code = resp.status().as_u16();
                let ok = code == 200;
                let note = if ok {
                    format!("type {kind} ok")
                } else {
                    format!("type {kind} HTTP {code}")
                };
                (code, note)
            }
            Err(e) => (0, format!("type {kind} {}", e.without_url())),
        };
        out.push(ProbeLine {
            model: format!("type/{kind}/{model}"),
            code,
            latency_ms: started.elapsed().as_millis() as u64,
            note,
            rpm: String::new(),
        });
    }
    out
}

fn tiny_wav() -> Vec<u8> {
    // A minimal 8 kHz mono PCM WAV with a short silence. Transcription
    // endpoints need a real file, but they only have to prove auth and route.
    let samples: u32 = 800;
    let data_len = samples * 4;
    let mut out = Vec::with_capacity(44 + data_len as usize);
    out.extend_from_slice(b"RIFF");
    out.extend_from_slice(&(36 + data_len).to_le_bytes());
    out.extend_from_slice(b"WAVEfmt ");
    out.extend_from_slice(&16u32.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&8000u32.to_le_bytes());
    out.extend_from_slice(&32000u32.to_le_bytes());
    out.extend_from_slice(&4u16.to_le_bytes());
    out.extend_from_slice(&32u16.to_le_bytes());
    out.extend_from_slice(b"data");
    out.extend_from_slice(&data_len.to_le_bytes());
    out.resize(44 + data_len as usize, 0);
    out
}

async fn tts_eleven_models(
    client: &Client,
    origin: &str,
    key: &str,
    timeout: Duration,
) -> Vec<String> {
    let fallback = vec!["eleven_flash_v2_5".to_string()];
    let url = format!("{origin}/v1/models");
    let Ok(resp) = client
        .get(&url)
        .header("xi-api-key", key)
        .timeout(timeout)
        .send()
        .await
    else {
        return fallback;
    };
    if !resp.status().is_success() {
        return fallback;
    }
    let Ok(v) = resp.json::<Value>().await else {
        return fallback;
    };
    let arr = v
        .as_array()
        .or_else(|| v.get("data").and_then(|x| x.as_array()))
        .or_else(|| v.get("models").and_then(|x| x.as_array()));
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    if let Some(arr) = arr {
        for it in arr {
            let Some(id) = it
                .get("model_id")
                .and_then(|x| x.as_str())
                .or_else(|| it.get("id").and_then(|x| x.as_str()))
                .or_else(|| it.as_str())
            else {
                continue;
            };
            let tts = it
                .get("can_do_text_to_speech")
                .and_then(|x| x.as_bool())
                .unwrap_or(false)
                || {
                    let l = id.to_ascii_lowercase();
                    l.contains("tts")
                        || l.contains("flash")
                        || l.contains("turbo")
                        || l.contains("multilingual")
                        || l.contains("eleven_v")
                };
            if tts && seen.insert(id.to_string()) {
                out.push(id.to_string());
            }
        }
    }
    if out.is_empty() {
        fallback
    } else {
        out
    }
}

async fn tts_eleven_voice(client: &Client, origin: &str, key: &str, timeout: Duration) -> String {
    const FALLBACK: &str = "21m00Tcm4TlvDq8ikWAM";
    let url = format!("{origin}/v1/voices");
    let Ok(resp) = client
        .get(&url)
        .header("xi-api-key", key)
        .timeout(timeout)
        .send()
        .await
    else {
        return FALLBACK.to_string();
    };
    if !resp.status().is_success() {
        return FALLBACK.to_string();
    }
    let Ok(v) = resp.json::<Value>().await else {
        return FALLBACK.to_string();
    };
    v["voices"]
        .as_array()
        .and_then(|a| a.first())
        .and_then(|v| v["voice_id"].as_str())
        .unwrap_or(FALLBACK)
        .to_string()
}

async fn tts_fish_balance(client: &Client, origin: &str, key: &str, timeout: Duration) -> String {
    let url = format!("{origin}/wallet/self/api-credit");
    let Ok(resp) = client
        .get(&url)
        .bearer_auth(key)
        .timeout(timeout)
        .send()
        .await
    else {
        return "?".to_string();
    };
    if !resp.status().is_success() {
        return "?".to_string();
    }
    let Ok(v) = resp.json::<Value>().await else {
        return "?".to_string();
    };
    v["credit"]
        .as_str()
        .map(|s| s.to_string())
        .or_else(|| v["credit"].as_f64().map(|n| format!("{n:.6}")))
        .unwrap_or_else(|| "?".to_string())
}

async fn balance_for(client: &Client, endpoint: &str, key: &str, anthropic: bool) -> String {
    if anthropic || is_google(endpoint, key) {
        return String::new();
    }
    let origin = origin_of(endpoint);
    if origin.is_empty() {
        return String::new();
    }
    let host = host_of(endpoint);
    let mut known: Vec<String> = Vec::new();
    if host.contains("deepseek") {
        known.push(format!("{origin}/user/balance"));
    } else if host.contains("openrouter") {
        known.push(format!("{origin}/api/v1/credits"));
        known.push(format!("{origin}/api/v1/key"));
    } else if host.contains("siliconflow") {
        known.push(format!("{origin}/v1/user/info"));
    } else if host.contains("moonshot") {
        known.push(format!("{origin}/v1/users/me/balance"));
    }
    // Try provider-specific endpoints first so a generic relay fallback cannot
    // win the race with a less accurate quota field.
    if !known.is_empty() {
        if let Some(s) = first_balance(client, &known, key, &host).await {
            return s;
        }
    }
    // OpenAI-compatible relays: New API / One API / Sub2API and similar.
    let mut generic: Vec<String> = Vec::new();
    for path in [
        "/api/user/self",
        "/api/user/info",
        "/api/user/current",
        "/api/user/balance",
        "/api/user/quota",
        "/api/user/dashboard",
        "/dashboard/billing/subscription",
        "/dashboard/billing/credit_grants",
        "/v1/dashboard/billing/subscription",
        "/v1/dashboard/billing/credit_grants",
        "/v1/user/info",
        "/v1/users/me/balance",
        "/v1/me",
        "/v1/account",
        "/v1/credits",
        "/v1/key",
        "/api/v1/credits",
        "/api/v1/key",
        "/user/balance",
        "/user/info",
    ] {
        let u = format!("{origin}{path}");
        if !known.contains(&u) && !generic.contains(&u) {
            generic.push(u);
        }
    }
    let direct = first_balance(client, &generic, key, &host);
    let (direct, billing) = tokio::join!(direct, billing_balance(client, &origin, key));
    if let Some(s) = direct {
        return s;
    }
    if let Some(s) = billing {
        return s;
    }
    String::new()
}

async fn first_balance(client: &Client, urls: &[String], key: &str, host: &str) -> Option<String> {
    let mut set = FuturesUnordered::new();
    for url in urls.iter().take(16) {
        let client = client.clone();
        let key = key.to_string();
        let host = host.to_string();
        let url = url.clone();
        set.push(async move {
            let (code, body) = get_balance_text(&client, &url, &key).await?;
            if code == 200 {
                if let Ok(v) = serde_json::from_str::<Value>(&body) {
                    if let Some(v) = parse_balance(&v, &host) {
                        return Some(v);
                    }
                }
            }
            parse_balance_error(&body)
        });
    }
    while let Some(s) = set.next().await {
        if let Some(s) = s {
            return Some(s);
        }
    }
    None
}

async fn get_json(client: &Client, url: &str, key: &str) -> Option<Value> {
    let resp = client
        .get(url)
        .bearer_auth(key)
        .header("Accept", "application/json")
        .header(
            "User-Agent",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36",
        )
        .timeout(std::time::Duration::from_secs(4))
        .send()
        .await
        .ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let body = resp.text().await.ok()?;
    serde_json::from_str(&body).ok()
}

async fn get_balance_text(client: &Client, url: &str, key: &str) -> Option<(u16, String)> {
    let resp = client
        .get(url)
        .bearer_auth(key)
        .header("Accept", "application/json,text/plain")
        .header(
            "User-Agent",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36",
        )
        .timeout(std::time::Duration::from_secs(4))
        .send()
        .await
        .ok()?;
    let code = resp.status().as_u16();
    let body = resp.text().await.ok()?;
    Some((code, body))
}

fn sane_money(value: f64, currency: &str) -> Option<String> {
    if !value.is_finite() || value.abs() > MAX_SANE_BALANCE {
        return None;
    }
    Some(money(value, currency))
}

fn parse_balance_error(body: &str) -> Option<String> {
    let low = body.to_lowercase();
    let is_balance_error = low.contains("insufficient")
        || low.contains("balance")
        || low.contains("quota")
        || low.contains("credit")
        || body.contains("余额")
        || body.contains("额度");
    if !is_balance_error {
        return None;
    }
    static MONEY: OnceLock<Regex> = OnceLock::new();
    let re = MONEY.get_or_init(|| {
        Regex::new(r#"(?i)(?:balance|remaining|available|余额|额度)[^0-9$¥€＄]{0,48}?([$¥€＄]?\s*-?[0-9]+(?:\.[0-9]+)?)"#).unwrap()
    });
    let cap = re.captures(body)?;
    let raw = cap.get(1)?.as_str().trim();
    let symbol = if raw.contains('¥') {
        "CNY"
    } else if raw.contains('€') {
        "EUR"
    } else if raw.contains('£') {
        "GBP"
    } else {
        "USD"
    };
    let n = num(raw)?;
    sane_money(n, symbol)
}

async fn billing_balance(client: &Client, origin: &str, key: &str) -> Option<String> {
    let usage_url = format!(
        "{origin}/dashboard/billing/usage?start_date=2024-01-01&end_date={}",
        chrono::Utc::now().format("%Y-%m-%d")
    );
    let sub_url = format!("{origin}/dashboard/billing/subscription");
    let (sub, usage) = tokio::join!(
        get_json(client, &sub_url, key),
        get_json(client, &usage_url, key)
    );
    let sub = sub?;
    let usage = usage?;
    let hard = sub["hard_limit_usd"].as_f64()?;
    if hard <= 0.0 || hard >= 100_000.0 {
        return None;
    }
    let used_cents = usage["total_usage"].as_f64()?;
    let remaining = hard - used_cents / 100.0;
    if remaining >= 100_000.0 {
        return None;
    }
    // This is a spending limit, not a purchased balance — label it honestly.
    Some(format!("лимит {}", money(remaining, "USD")))
}

fn origin_of(url: &str) -> String {
    let Ok(u) = reqwest::Url::parse(url.trim()) else {
        return String::new();
    };
    let origin = u.origin().ascii_serialization();
    if origin == "null" {
        String::new()
    } else {
        origin
    }
}

pub(crate) fn balance_is_nonpositive(balance: &str) -> bool {
    let numeric: String = balance
        .chars()
        .filter(|c| c.is_ascii_digit() || *c == '.' || *c == '-')
        .collect();
    numeric.parse::<f64>().map(|v| v <= 0.0).unwrap_or(false)
}

fn parse_balance(v: &Value, host: &str) -> Option<String> {
    // DeepSeek
    if let Some(items) = v["balance_infos"].as_array() {
        for first in items {
            if let Some(total) = value_num(first.get("total_balance")) {
                let currency = first["currency"].as_str().unwrap_or("CNY");
                if let Some(m) = sane_money(total, currency) {
                    return Some(m);
                }
            }
        }
    }
    // OpenRouter: credits minus usage.
    let credits = v["data"]["total_credits"].as_f64();
    let usage = v["data"]["total_usage"].as_f64();
    if let (Some(c), Some(u)) = (credits, usage) {
        if let Some(m) = sane_money(c - u, "USD") {
            return Some(m);
        }
    }
    if let Some(limit) = v["data"]["limit"].as_f64() {
        if let Some(used) = v["data"]["usage"].as_f64() {
            if let Some(m) = sane_money(limit - used, "USD") {
                return Some(m);
            }
        }
    }
    // SiliconFlow / New API / generic.
    let data = &v["data"];
    for (key, currency) in [
        ("totalBalance", "CNY"),
        ("balance", ""),
        ("available_balance", ""),
        ("availableBalance", ""),
        ("total_balance", ""),
        ("remaining", ""),
        ("remain", ""),
        ("quota", "quota"),
        ("remaining_quota", "quota"),
        ("remain_quota", "quota"),
    ] {
        if let Some(n) = value_num(data.get(key).or_else(|| v.get(key))) {
            let cur = data["currency"]
                .as_str()
                .or_else(|| v["currency"].as_str())
                .or_else(|| data["currency_code"].as_str())
                .unwrap_or(currency);
            if cur == "quota" {
                let qpu = value_num(data.get("quota_per_unit"))
                    .or_else(|| value_num(v.get("quota_per_unit")))
                    .filter(|q| *q > 0.0)
                    .unwrap_or(500_000.0);
                if let Some(m) = sane_money(n / qpu, "USD") {
                    return Some(m);
                }
                continue;
            }
            if let Some(m) = sane_money(n, cur) {
                return Some(m);
            }
        }
    }
    // Some relays nest values under data.
    for (key, currency) in [
        ("quota", "quota"),
        ("remaining", ""),
        ("balance", ""),
        ("total_balance", ""),
    ] {
        if let Some(n) = value_num(data.get(key)) {
            if currency == "quota" {
                let qpu = value_num(data.get("quota_per_unit"))
                    .or_else(|| value_num(v.get("quota_per_unit")))
                    .filter(|q| *q > 0.0)
                    .unwrap_or(500_000.0);
                if let Some(m) = sane_money(n / qpu, "USD") {
                    return Some(m);
                }
                continue;
            }
            if let Some(m) = sane_money(n, currency) {
                return Some(m);
            }
        }
    }
    // Credit-grant style billing payloads.
    for root in [v, data, &v["result"], &v["account"], &v["user"]] {
        for (key, label) in [
            ("total_available", "USD"),
            ("total_available_usd", "USD"),
            ("available_credit", "USD"),
            ("remaining_credit", "USD"),
            ("credit", "USD"),
            ("credits", "USD"),
        ] {
            if let Some(n) = value_num(root.get(key)) {
                if let Some(m) = sane_money(n, label) {
                    return Some(m);
                }
            }
        }
    }
    // Last-resort recursive scan for a sane money field in a provider-
    // specific wrapper (`result`, `account`, `user`, `data.user`). The direct
    // loops above cover the common shapes; this catches relays that nest the
    // real balance beside a timestamp-shaped `balance` field.
    let data = &v["data"];
    for root in [
        v,
        data,
        &v["result"],
        &v["account"],
        &v["user"],
        &data["user"],
    ] {
        for key in [
            "balance",
            "remaining_balance",
            "remain_balance",
            "current_balance",
            "available",
            "available_balance",
            "availableBalance",
            "credit",
            "credits",
            "total_available",
        ] {
            if let Some(n) = value_num(root.get(key)) {
                let cur = root["currency"]
                    .as_str()
                    .or_else(|| root["currency_code"].as_str())
                    .unwrap_or("");
                if let Some(m) = sane_money(n, cur) {
                    return Some(m);
                }
            }
        }
    }
    // If a relay only exposes used_quota, do not pretend it is a balance.
    let _ = host;
    None
}

fn value_num(v: Option<&Value>) -> Option<f64> {
    let v = v?;
    if let Some(n) = v.as_f64() {
        return Some(n);
    }
    v.as_str().and_then(num)
}

fn num(s: &str) -> Option<f64> {
    let cleaned: String = s
        .chars()
        .filter(|c| c.is_ascii_digit() || *c == '.' || *c == '-')
        .collect();
    if cleaned.is_empty() {
        None
    } else {
        cleaned.parse::<f64>().ok()
    }
}

fn money(value: f64, currency: &str) -> String {
    let cur = currency.to_uppercase();
    let symbol = match cur.as_str() {
        "USD" => "$",
        "CNY" | "RMB" => "¥",
        "EUR" => "€",
        "GBP" => "£",
        _ => "",
    };
    if symbol.is_empty() {
        if cur.is_empty() {
            format!("{value:.2}")
        } else {
            format!("{value:.2} {cur}")
        }
    } else {
        format!("{symbol}{value:.2}")
    }
}

pub fn candidates(endpoint: &str) -> Vec<String> {
    let e = endpoint.trim().trim_end_matches('/');
    if e.is_empty() {
        return vec![];
    }
    let origin = match e.find("://") {
        Some(i) => {
            let rest = &e[i + 3..];
            let slash = rest.find('/').map(|x| i + 3 + x).unwrap_or(e.len());
            e[..slash].to_string()
        }
        None => e.to_string(),
    };
    let host = host_of(e);
    let dashscope_host =
        host.contains("dashscope") || crate::extract::is_dashscope_workspace_endpoint(e);
    let google_host = host == "generativelanguage.googleapis.com";
    // OpenRouter serves its OpenAI-compatible API under /api/v1. The generic
    // `{origin}/v1` guess returns 404 and the bare origin answers /models with
    // its HTML site (200), so a live sk-or key was probed on a 404 chat route
    // and stored as PARTIAL for every model.
    let openrouter_host = host == "openrouter.ai" || host == "www.openrouter.ai";
    let mut out = Vec::new();
    if google_host {
        if e.ends_with("/v1beta") {
            out.push(e.to_string());
            if origin != e {
                out.push(format!("{origin}/v1beta"));
            }
        } else {
            out.push(format!("{origin}/v1beta"));
            out.push(e.to_string());
        }
        out.push(origin.clone());
    } else if dashscope_host {
        // DashScope native endpoints live under /api/v1/services/..., while
        // OpenAI-compatible clients must talk to /compatible-mode/v1. Try the
        // compatible endpoint first regardless of which form was extracted.
        out.push(format!("{origin}/compatible-mode/v1"));
        out.push(format!("{origin}/api/v1"));
        out.push(origin.clone());
    } else if openrouter_host && !e.ends_with("/api/v1") {
        out.push(format!("{origin}/api/v1"));
        out.push(format!("{origin}/v1"));
        out.push(origin.clone());
    } else if let Some(base) = e
        .strip_suffix("/chat/completions")
        .or_else(|| e.strip_suffix("/messages"))
    {
        // A manual /check input may be a full chat URL, not a base URL.
        let base = base.trim_end_matches('/').to_string();
        out.push(base.clone());
        if origin != base {
            out.push(origin.clone());
        }
    } else if e.ends_with("/v1") || e.ends_with("/v1beta") {
        out.push(e.to_string());
        if origin != e {
            out.push(origin.clone());
        }
        out.push(format!("{}/v1", origin));
    } else {
        out.push(format!("{}/v1", e));
        out.push(e.to_string());
    }
    let mut seen = std::collections::HashSet::new();
    out.into_iter().filter(|s| seen.insert(s.clone())).collect()
}

fn is_anthropic(base: &str) -> bool {
    host_of(base).contains("anthropic.com")
}

fn is_google(base: &str, key: &str) -> bool {
    host_of(base) == "generativelanguage.googleapis.com" || key.starts_with("AIza")
}

pub fn is_official_mistral(endpoint: &str) -> bool {
    matches!(
        host_of(endpoint).as_str(),
        "api.mistral.ai" | "codestral.mistral.ai" | "mistral.ai"
    )
}

/// Official Moonshot China endpoint is deliberately blocked: it must never
/// be probed, even if a stored/imported key was previously VALID.
pub fn is_official_moonshot_cn(endpoint: &str) -> bool {
    host_of(endpoint) == "api.moonshot.cn"
}

pub fn is_disabled_api(endpoint: &str) -> bool {
    is_official_mistral(endpoint) || is_official_moonshot_cn(endpoint)
}

fn google_model(model: &str) -> &str {
    model.strip_prefix("models/").unwrap_or(model)
}

fn google_auth_error(code: u16, body: &str) -> bool {
    if code != 400 && code != 403 {
        return false;
    }
    let low = body.to_ascii_lowercase();
    low.contains("api key not valid")
        || low.contains("api_key_invalid")
        || low.contains("api key expired")
        || low.contains("api key is invalid")
        || low.contains("permission_denied")
}

fn fallback_models(base: &str, key: &str, anthropic: bool) -> Vec<String> {
    let host = host_of(base);
    let low_key = key.to_lowercase();
    let list: &[&str] = if is_google(base, key) {
        &[
            "gemini-2.5-flash",
            "gemini-2.5-pro",
            "gemini-2.0-flash",
            "gemini-1.5-flash",
            "gemini-1.5-pro",
        ]
    } else if anthropic || low_key.starts_with("sk-ant-") {
        &[
            "claude-3-5-haiku-latest",
            "claude-3-7-sonnet-latest",
            "claude-sonnet-4-20250514",
        ]
    } else if host.contains("x.ai") || low_key.starts_with("xai-") {
        &[
            "grok-4",
            "grok-3",
            "grok-3-mini",
            "grok-2-1212",
            "grok-beta",
        ]
    } else if host.contains("huggingface") || low_key.starts_with("hf_") {
        &[
            "meta-llama/Llama-3.3-70B-Instruct",
            "Qwen/Qwen2.5-72B-Instruct",
            "mistralai/Mistral-7B-Instruct-v0.3",
        ]
    } else if host.contains("openrouter") || low_key.starts_with("sk-or-") {
        &[
            "openai/gpt-4o-mini",
            "anthropic/claude-3.5-haiku",
            "google/gemini-2.0-flash-001",
            "deepseek/deepseek-chat",
        ]
    } else if host.contains("dashscope") || host.contains("aliyuncs.com") {
        &[
            "qwen3-max",
            "qwen-max-latest",
            "qwen-max",
            "qwen-plus-latest",
            "qwen-plus",
            "qwen-turbo",
            "qwen3-coder-plus",
            "qwen-vl-max",
            "qwen2.5-72b-instruct",
            "deepseek-v3",
        ]
    } else if host.contains("deepseek") {
        &["deepseek-chat", "deepseek-reasoner"]
    } else {
        &GENERIC_FALLBACK_MODELS
    };
    list.iter().map(|s| s.to_string()).collect()
}

fn api_url(base: &str, suffix: &str) -> String {
    format!("{}{}", base.trim_end_matches('/'), suffix)
}

async fn get_models(
    client: &Client,
    base: &str,
    key: &str,
    anthropic: bool,
    timeout_secs: u64,
) -> Result<(u16, Vec<String>, String, String)> {
    let url = api_url(base, "/models");
    let google = is_google(base, key);
    let mut req = client
        .get(&url)
        .timeout(std::time::Duration::from_secs(timeout_secs.clamp(3, 60)));
    if google {
        req = req.header("x-goog-api-key", key);
    } else if anthropic {
        req = req
            .header("x-api-key", key)
            .header("anthropic-version", "2023-06-01");
    } else {
        req = req.bearer_auth(key);
    }
    let resp = req.send().await?;
    let code = resp.status().as_u16();
    let rpm = parse_rpm_headers(resp.headers());
    let text = resp.text().await.unwrap_or_default();
    if code != 200 {
        return Ok((code, Vec::new(), rpm, text));
    }
    let v: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
    Ok((code, parse_models(&v), rpm, text))
}

/// Extract the provider's requests-per-minute cap from standard rate-limit
/// headers. Different providers use different names, so check the common ones.
pub fn parse_rpm_headers(headers: &HeaderMap) -> String {
    const NAMES: &[&str] = &[
        "x-ratelimit-limit-requests",
        "x-ratelimit-requests-limit",
        "x-ratelimit-limit",
        "x-rate-limit-limit",
        "ratelimit-limit",
        "x-ratelimit-limit-rpm",
    ];
    for name in NAMES {
        let Some(value) = headers.get(*name).and_then(|v| v.to_str().ok()) else {
            continue;
        };
        let digits: String = value
            .chars()
            .skip_while(|c| !c.is_ascii_digit())
            .take_while(|c| c.is_ascii_digit())
            .collect();
        if let Ok(n) = digits.parse::<i64>() {
            return format!("{n}/мин");
        }
    }
    String::new()
}

fn parse_models(v: &Value) -> Vec<String> {
    let arr = v
        .get("data")
        .and_then(|x| x.as_array())
        .or_else(|| v.get("models").and_then(|x| x.as_array()))
        .or_else(|| v.as_array());
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    if let Some(arr) = arr {
        for it in arr {
            let id = it
                .get("id")
                .and_then(|x| x.as_str())
                .or_else(|| it.get("name").and_then(|x| x.as_str()))
                .or_else(|| it.as_str());
            if let Some(id) = id {
                let id = id
                    .trim()
                    .strip_prefix("models/")
                    .unwrap_or(id.trim())
                    .to_string();
                if let Some(methods) = it
                    .get("supportedGenerationMethods")
                    .and_then(|x| x.as_array())
                {
                    if !methods
                        .iter()
                        .any(|m| m.as_str() == Some("generateContent"))
                    {
                        continue;
                    }
                }
                if !id.is_empty() && seen.insert(id.clone()) {
                    out.push(id);
                }
            }
        }
    }
    out
}

fn select_models(models: &[String], limit: usize) -> Vec<String> {
    let mut scored: Vec<(i32, usize, String)> = Vec::new();
    for (i, m) in models.iter().enumerate() {
        let lm = m.to_lowercase();
        if [
            "embed",
            "whisper",
            "tts",
            "moderation",
            "rerank",
            "dall-e",
            "stable-diffusion",
            "flux",
            "audio",
            "transcribe",
            "speech",
            "batch",
        ]
        .iter()
        .any(|x| lm.contains(x))
        {
            continue;
        }
        let mut score = 0;
        // DashScope ships placeholder rows first (`pre-mock_ptu_auth_v2_*`) and
        // wraps partner catalogs (`vanchin/`, `antdigital/`). They are not chat
        // models; probing them burned the whole model budget and stamped live
        // workspace keys as INVALID.
        if lm.contains("pre-mock")
            || lm.contains("mock_ptu")
            || lm.starts_with("pre-")
            || lm.starts_with("vanchin/")
            || lm.starts_with("antdigital/")
        {
            continue;
        }
        for (needle, pts) in [
            // Leaked workspace keys (`sk-ws-…`) usually serve a single cheap
            // model while the flagship ids answer Arrearage/403. Probe these
            // first so a live key is not reported dead on the expensive ids.
            ("qwen3.8-27b", 220),
            ("qwen3.8-max", 210),
            ("deepseek-v4.1-flash-1017", 205),
            ("glm-5.3", 200),
            ("qwen-plus", 195),
            ("qwen-max", 190),
            ("claude-opus", 100),
            ("claude-sonnet", 95),
            ("claude-haiku", 90),
            ("gpt-6", 100),
            ("gpt-5", 95),
            ("gpt-4", 80),
            ("gemini", 90),
            ("deepseek", 85),
            ("qwen", 80),
            ("grok", 80),
            ("llama", 60),
            ("mistral", 55),
        ] {
            if lm.contains(needle) {
                score += pts;
                break;
            }
        }
        score -= lm.len() as i32 / 8;
        scored.push((score, i, m.clone()));
    }
    scored.sort_by(|a, b| b.0.cmp(&a.0).then(a.2.len().cmp(&b.2.len())));
    let limit = if limit == 0 { usize::MAX } else { limit };
    scored.into_iter().take(limit).map(|(_, _, m)| m).collect()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AnswerClass {
    Exact,
    Near,
    Echo,
    Art,
    Refusal,
    Empty,
    BadJson,
    NoToken,
}

async fn chat_request(
    client: &Client,
    base: &str,
    key: &str,
    model: &str,
    message: &str,
    anthropic: bool,
    timeout_secs: u64,
) -> std::result::Result<(u16, u64, String, String), reqwest::Error> {
    let t0 = Instant::now();
    let google = is_google(base, key);
    let resp = if google {
        let model = google_model(model);
        client
            .post(api_url(base, &format!("/models/{model}:generateContent")))
            .header("x-goog-api-key", key)
            .json(&json!({
                "contents": [{"role": "user", "parts": [{"text": message}]}],
                "generationConfig": {"maxOutputTokens": 64, "temperature": 0.0}
            }))
            .timeout(std::time::Duration::from_secs(timeout_secs.clamp(3, 60)))
            .send()
            .await?
    } else if anthropic {
        client
            .post(api_url(base, "/messages"))
            .header("x-api-key", key)
            .header("anthropic-version", "2023-06-01")
            .json(&json!({
                "model": model,
                "max_tokens": 64,
                "messages": [{"role": "user", "content": message}]
            }))
            .timeout(std::time::Duration::from_secs(timeout_secs.clamp(3, 60)))
            .send()
            .await?
    } else {
        client
            .post(api_url(base, "/chat/completions"))
            .bearer_auth(key)
            .json(&json!({
                "model": model,
                "messages": [{"role": "user", "content": message}],
                "max_tokens": 64,
                "temperature": 0.0,
                "stream": false
            }))
            .timeout(std::time::Duration::from_secs(timeout_secs.clamp(3, 60)))
            .send()
            .await?
    };
    let code = resp.status().as_u16();
    let rpm = parse_rpm_headers(resp.headers());
    let text = resp.text().await.unwrap_or_default();
    Ok((code, t0.elapsed().as_millis() as u64, text, rpm))
}

fn classify_answer(body: &str, challenge: &str) -> (AnswerClass, Option<String>) {
    if serde_json::from_str::<Value>(body).is_err() {
        return (AnswerClass::BadJson, None);
    }
    let Some(answer) = answer_text(body) else {
        return (AnswerClass::Empty, None);
    };
    if answer.trim().is_empty() {
        return (AnswerClass::Empty, None);
    }
    if looks_like_echo(&answer) {
        return (AnswerClass::Echo, Some(answer));
    }
    if looks_like_ascii(&answer) {
        return (AnswerClass::Art, Some(answer));
    }
    if exact_token(&answer, challenge) {
        return (AnswerClass::Exact, Some(answer));
    }
    if looks_like_refusal(&answer) {
        return (AnswerClass::Refusal, Some(answer));
    }
    if contains_token(&answer, challenge) {
        return (AnswerClass::Near, Some(answer));
    }
    (AnswerClass::NoToken, Some(answer))
}

fn exact_token(answer: &str, challenge: &str) -> bool {
    let clean = normalized_token(answer);
    !clean.is_empty() && clean.eq_ignore_ascii_case(challenge)
}

fn normalized_token(answer: &str) -> String {
    let t = answer.trim().trim_matches('\u{feff}').trim();
    let t = t.trim_matches(|c: char| {
        matches!(
            c,
            '"' | '\''
                | '`'
                | '«'
                | '»'
                | '“'
                | '”'
                | '‘'
                | '’'
                | '<'
                | '>'
                | '*'
                | '_'
                | '.'
                | ','
                | '!'
                | '?'
                | ';'
                | ':'
        )
    });
    t.trim().to_string()
}

fn contains_token(answer: &str, challenge: &str) -> bool {
    let low = answer.to_lowercase();
    let token = challenge.to_lowercase();
    if token.is_empty() {
        return false;
    }
    low.match_indices(&token).any(|(i, _)| {
        let before = low[..i]
            .chars()
            .next_back()
            .map(is_word_char)
            .unwrap_or(false);
        let after = low[i + token.len()..]
            .chars()
            .next()
            .map(is_word_char)
            .unwrap_or(false);
        !before && !after
    })
}

fn is_word_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

fn looks_like_echo(answer: &str) -> bool {
    let low = answer.to_lowercase();
    [
        "reply with exactly",
        "no punctuation",
        "no explanations",
        "only the token",
        "rules:",
    ]
    .iter()
    .any(|m| low.contains(m))
}

fn looks_like_refusal(answer: &str) -> bool {
    let low = answer.to_lowercase();
    [
        "i cannot",
        "i can't",
        "i can’t",
        "cannot comply",
        "unable to",
        "as an ai",
        "не могу",
        "не буду",
        "sorry,",
    ]
    .iter()
    .any(|m| low.contains(m))
}

fn looks_like_ascii(answer: &str) -> bool {
    let chars = answer.chars().count();
    let lines = answer.lines().count();
    let art = answer
        .chars()
        .filter(|c| "─│┌┐└┘╔╗╚╝║═╬╠╣╦╩╪╫/\\|_=+<>".contains(*c))
        .count();
    if art >= 8 || (art >= 5 && (chars > 30 || lines >= 2)) {
        return true;
    }
    let alnum = answer.chars().filter(|c| c.is_alphanumeric()).count();
    chars > 120 && alnum * 100 / chars < 55
}

fn status_note(code: u16) -> String {
    match code {
        429 => "рейт-окно".to_string(),
        401 => "ключ".to_string(),
        403 => "доступ".to_string(),
        404 => "нет модели".to_string(),
        400 => "запрос".to_string(),
        c if c >= 500 => "сервер".to_string(),
        _ => String::new(),
    }
}

fn preview_or_empty(answer: &Option<String>) -> String {
    answer
        .as_deref()
        .map(preview)
        .unwrap_or_else(|| "пусто".into())
}

fn class_note(class: AnswerClass, answer: &Option<String>) -> String {
    match class {
        AnswerClass::Exact | AnswerClass::Near => String::new(),
        AnswerClass::Echo => "фейк: эхо промпта".into(),
        AnswerClass::Art => "фейк: ASCII-арт".into(),
        AnswerClass::Refusal => "отказ модели".into(),
        AnswerClass::Empty => "пустой ответ".into(),
        AnswerClass::BadJson => "фейк: не JSON".into(),
        AnswerClass::NoToken => format!("нет challenge · {}", preview_or_empty(answer)),
    }
}

async fn cost_probe_balance(
    client: &Client,
    base: &str,
    key: &str,
    model: &str,
    anthropic: bool,
) -> Option<String> {
    // Deliberately over-budget request. It is only sent when the operator
    // enables balance_cost_probe. Some New-API/Sub2API relays reject it with
    // "Need to pre-deduct …, balance $X is insufficient" before generation.
    let req = if anthropic {
        client
            .post(api_url(base, "/messages"))
            .header("x-api-key", key)
            .header("anthropic-version", "2023-06-01")
            .json(&json!({
                "model": model,
                "max_tokens": 1_000_000,
                "messages": [{"role": "user", "content": "hi"}]
            }))
    } else {
        client
            .post(api_url(base, "/chat/completions"))
            .bearer_auth(key)
            .json(&json!({
                "model": model,
                "messages": [{"role": "user", "content": "hi"}],
                "max_tokens": 1_000_000,
                "temperature": 0.0,
                "stream": false
            }))
    };
    let resp = req
        .timeout(std::time::Duration::from_secs(4))
        .send()
        .await
        .ok()?;
    let code = resp.status().as_u16();
    if code == 200 {
        // Do not consume a potentially expensive body.
        return None;
    }
    let body = resp.text().await.ok()?;
    parse_balance_error(&body)
}

async fn probe_one(
    client: &Client,
    base: &str,
    key: &str,
    model: &str,
    message: &str,
    challenge: &str,
    anthropic: bool,
    timeout_secs: u64,
) -> (ProbeLine, String) {
    let t0 = Instant::now();
    let first = match chat_request(client, base, key, model, message, anthropic, timeout_secs).await
    {
        Ok(v) => v,
        Err(_) => {
            return (
                ProbeLine {
                    model: model.to_string(),
                    code: 0,
                    latency_ms: t0.elapsed().as_millis() as u64,
                    note: "сеть/таймаут".into(),
                    rpm: String::new(),
                },
                String::new(),
            );
        }
    };
    let (code, _, text, mut chat_rpm) = first;
    let balance_hint = if code != 200 {
        parse_balance_error(&text).unwrap_or_default()
    } else {
        String::new()
    };
    let mut note = status_note(code);
    if is_google(base, key) && google_auth_error(code, &text) {
        note = "ключ".into();
    }

    if code == 200 {
        let (class, body) = classify_answer(&text, challenge);
        let mut answer = body;
        note = class_note(class, &answer);
        if class == AnswerClass::Near {
            // A model may wrap the token in a sentence or markdown. Ask once
            // more with a fresh token; a static/echo fake fails the second
            // round, while a real model confirms.
            let second = random_challenge();
            let second_prompt = challenge_prompt(&second);
            match chat_request(
                client,
                base,
                key,
                model,
                &second_prompt,
                anthropic,
                timeout_secs,
            )
            .await
            {
                Ok((code2, _, second_text, second_rpm)) if code2 == 200 => {
                    if chat_rpm.is_empty() {
                        chat_rpm = second_rpm;
                    }
                    let (class2, answer2) = classify_answer(&second_text, &second);
                    answer = answer2;
                    match class2 {
                        AnswerClass::Exact | AnswerClass::Near => note = String::new(),
                        AnswerClass::Refusal | AnswerClass::Empty => {
                            note = format!("challenge: {}", class_note(class2, &answer));
                        }
                        _ => {
                            note = format!(
                                "фейк: не подтвердил challenge · {}",
                                preview_or_empty(&answer)
                            );
                        }
                    }
                }
                Ok((code2, _, _, _)) => {
                    note = format!("challenge: вторая проба HTTP {code2}");
                }
                Err(_) => note = "challenge: сеть на второй пробе".into(),
            }
        }
    }

    (
        ProbeLine {
            model: model.to_string(),
            code,
            latency_ms: t0.elapsed().as_millis() as u64,
            note,
            rpm: chat_rpm,
        },
        balance_hint,
    )
}

fn preview(answer: &str) -> String {
    let one = answer.replace(['\n', '\r', '\t'], " ");
    let mut out: String = one.trim().chars().take(32).collect();
    if one.trim().chars().count() > 32 {
        out.push('…');
    }
    out
}

fn answer_matches(answer: &str, challenge: &str) -> bool {
    let answer = answer.trim().trim_matches('\u{feff}').trim();
    // The challenge is one word. Anything else — punctuation, quotes,
    // markdown, ASCII art, an explanation — is a failed challenge.
    !answer.is_empty() && answer.eq_ignore_ascii_case(challenge)
}

fn answer_text(body: &str) -> Option<String> {
    let v: Value = serde_json::from_str(body).ok()?;
    if let Some(error) = v.get("error") {
        if !error.is_null() {
            return None;
        }
    }
    let content = |x: &Value| -> Option<String> {
        if let Some(s) = x.as_str() {
            return Some(s.to_string());
        }
        if let Some(s) = x.get("text").and_then(|x| x.as_str()) {
            return Some(s.to_string());
        }
        let arr = x.as_array()?;
        let mut out = String::new();
        for part in arr {
            if let Some(s) = part.get("text").and_then(|x| x.as_str()) {
                out.push_str(s);
            } else if let Some(s) = part.as_str() {
                out.push_str(s);
            }
        }
        if out.is_empty() {
            None
        } else {
            Some(out)
        }
    };
    v.pointer("/candidates/0/content/parts")
        .and_then(content)
        .or_else(|| v.pointer("/choices/0/message/content").and_then(content))
        .or_else(|| v.pointer("/choices/0/text").and_then(content))
        .or_else(|| v.get("content").and_then(content))
        .or_else(|| v.get("completion").and_then(content))
        .or_else(|| v.get("output_text").and_then(content))
        .or_else(|| v.pointer("/output/0/content").and_then(content))
        .or_else(|| {
            v.pointer("/choices/0/message/reasoning_content")
                .and_then(content)
        })
        .or_else(|| v.pointer("/choices/0/message/reasoning").and_then(content))
        .or_else(|| v.get("reasoning_content").and_then(content))
        .or_else(|| v.get("reasoning").and_then(content))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    fn spawn_mock() -> (String, Arc<AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let hits = Arc::new(AtomicUsize::new(0));
        let h = hits.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut s) = stream else { continue };
                let mut buf = vec![0u8; 16384];
                let n = s.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                h.fetch_add(1, Ordering::SeqCst);
                let (status, body) = if req.starts_with("GET /v1/models") {
                    (
                        "200 OK",
                        r#"{"object":"list","data":[{"id":"gpt-test-1"},{"id":"claude-test-1"}]}"#,
                    )
                } else if req.starts_with("POST /v1/chat/completions") {
                    (
                        "200 OK",
                        r#"{"id":"x","object":"chat.completion","choices":[{"message":{"role":"assistant","content":"alibaba"}}]}"#,
                    )
                } else {
                    ("404 Not Found", r#"{"error":"nope"}"#)
                };
                let resp = format!(
                    "HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    status,
                    body.len(),
                    body
                );
                let _ = s.write_all(resp.as_bytes());
            }
        });
        (format!("http://{}", addr), hits)
    }

    fn spawn_seedance_mock() -> (String, Arc<AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let deletes = Arc::new(AtomicUsize::new(0));
        let d = deletes.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut s) = stream else { continue };
                let mut buf = vec![0u8; 16384];
                let n = s.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let (status, body) = if req.starts_with("POST /api/v3/contents/generations/tasks") {
                    ("200 OK", r#"{"id":"cgt-test"}"#.to_string())
                } else if req.starts_with("GET /api/v3/contents/generations/tasks/cgt-test") {
                    (
                        "200 OK",
                        r#"{"status":"succeeded","content":{"video_url":"https://example.test/v.mp4"}}"#
                            .to_string(),
                    )
                } else if req.starts_with("DELETE /api/v3/contents/generations/tasks/cgt-test") {
                    d.fetch_add(1, Ordering::SeqCst);
                    ("204 No Content", String::new())
                } else {
                    ("404 Not Found", r#"{"error":"nope"}"#.to_string())
                };
                let resp = format!(
                    "HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    status,
                    body.len(),
                    body
                );
                let _ = s.write_all(resp.as_bytes());
            }
        });
        (format!("http://{}", addr), deletes)
    }

    #[tokio::test]
    async fn seedance_generation_is_deleted_after_success() {
        let (url, deletes) = spawn_seedance_mock();
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap();
        let (code, note, deleted, ok) = seedance_generate_video(
            &client,
            &format!("{url}/api/v3"),
            "test-key",
            "doubao-seedance-1-0-pro-250528",
            Duration::from_secs(5),
        )
        .await;
        assert_eq!(code, 200);
        assert!(ok);
        assert!(deleted);
        assert!(note.contains("deleted"), "note: {note}");
        assert_eq!(deletes.load(Ordering::SeqCst), 1);
    }

    fn spawn_mock_models_401() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut s) = stream else { continue };
                let mut buf = vec![0u8; 16384];
                let n = s.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let (status, body) = if req.starts_with("GET /v1/models") {
                    ("401 Unauthorized", r#"{"error":{"message":"nope"}}"#)
                } else if req.starts_with("POST /v1/chat/completions") {
                    (
                        "200 OK",
                        r#"{"id":"x","choices":[{"message":{"role":"assistant","content":"alibaba"}}]}"#,
                    )
                } else {
                    ("404 Not Found", r#"{"error":"nope"}"#)
                };
                let resp = format!(
                    "HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    status,
                    body.len(),
                    body
                );
                let _ = s.write_all(resp.as_bytes());
            }
        });
        format!("http://{}", addr)
    }

    fn spawn_mock_fake() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut s) = stream else { continue };
                let mut buf = vec![0u8; 16384];
                let n = s.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let (status, body) = if req.starts_with("GET /v1/models") {
                    (
                        "200 OK",
                        r#"{"object":"list","data":[{"id":"gpt-test-1"},{"id":"claude-test-1"}]}"#,
                    )
                } else if req.starts_with("POST /v1/chat/completions") {
                    (
                        "200 OK",
                        r#"{"id":"x","choices":[{"message":{"role":"assistant","content":"╔══╗\\n║AI║\\n╚══╝ hi!"}}]}"#,
                    )
                } else {
                    ("404 Not Found", r#"{"error":"nope"}"#)
                };
                let resp = format!(
                    "HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    status,
                    body.len(),
                    body
                );
                let _ = s.write_all(resp.as_bytes());
            }
        });
        format!("http://{}", addr)
    }

    fn spawn_mock_near() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut s) = stream else { continue };
                let mut buf = vec![0u8; 16384];
                let n = s.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let (status, body) = if req.starts_with("GET /v1/models") {
                    (
                        "200 OK",
                        r#"{"object":"list","data":[{"id":"gpt-test-1"}]}"#.to_string(),
                    )
                } else if req.starts_with("POST /v1/chat/completions") {
                    let raw = req.split("\r\n\r\n").nth(1).unwrap_or("");
                    let prompt = serde_json::from_str::<Value>(raw)
                        .ok()
                        .and_then(|v| v["messages"][0]["content"].as_str().map(|s| s.to_string()))
                        .unwrap_or_default();
                    let token = prompt
                        .split("nothing else: ")
                        .nth(1)
                        .and_then(|s| s.split_whitespace().next())
                        .unwrap_or("missing");
                    let content = format!("Sure! The token is {token}.");
                    (
                        "200 OK",
                        serde_json::json!({
                            "id": "x",
                            "choices": [{"message": {"role": "assistant", "content": content}}]
                        })
                        .to_string(),
                    )
                } else {
                    ("404 Not Found", r#"{"error":"nope"}"#.to_string())
                };
                let body = body;
                let resp = format!(
                    "HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    status,
                    body.len(),
                    body
                );
                let _ = s.write_all(resp.as_bytes());
            }
        });
        format!("http://{}", addr)
    }

    #[test]
    fn balance_shapes_are_parsed() {
        let deepseek = serde_json::json!({
            "balance_infos": [{"currency": "CNY", "total_balance": "12.5"}]
        });
        assert_eq!(
            parse_balance(&deepseek, "api.deepseek.com").as_deref(),
            Some("¥12.50")
        );
        let deepseek_numeric = serde_json::json!({
            "balance_infos": [{"currency": "USD", "total_balance": 3.5}]
        });
        assert_eq!(
            parse_balance(&deepseek_numeric, "api.deepseek.com").as_deref(),
            Some("$3.50")
        );
        let openrouter = serde_json::json!({
            "data": {"total_credits": 10.0, "total_usage": 2.5}
        });
        assert_eq!(
            parse_balance(&openrouter, "openrouter.ai").as_deref(),
            Some("$7.50")
        );
        let siliconflow = serde_json::json!({
            "data": {"totalBalance": "8.88"}
        });
        assert_eq!(
            parse_balance(&siliconflow, "api.siliconflow.cn").as_deref(),
            Some("¥8.88")
        );
        let newapi = serde_json::json!({"data": {"quota": 500000}});
        assert_eq!(
            parse_balance(&newapi, "relay.example").as_deref(),
            Some("$1.00")
        );
        let used_only = serde_json::json!({"data": {"used_quota": 100}});
        assert_eq!(parse_balance(&used_only, "relay.example"), None);
        // A timestamp/id must never be printed as money. If a sane sibling
        // field exists, it wins; otherwise the balance stays unknown.
        let timestamp_only = serde_json::json!({
            "data": {"balance": 2026102622361475021131657248768.0}
        });
        assert_eq!(parse_balance(&timestamp_only, "relay.example"), None);
        let timestamp_and_real = serde_json::json!({
            "data": {
                "balance": 2026102622361475021131657248768.0,
                "remaining": 5.0
            }
        });
        assert_eq!(
            parse_balance(&timestamp_and_real, "relay.example").as_deref(),
            Some("5.00")
        );
        let nested = serde_json::json!({
            "data": {"balance": 2026102622361475021131657248768.0},
            "account": {"balance": 5.0, "currency": "USD"}
        });
        assert_eq!(
            parse_balance(&nested, "relay.example").as_deref(),
            Some("$5.00")
        );
    }

    #[test]
    fn insufficient_balance_error_is_parsed() {
        assert_eq!(
            parse_balance_error(
                r#"{"error":{"message":"Need to pre-deduct $1000, balance $5.839 is insufficient"}}"#
            )
            .as_deref(),
            Some("$5.84")
        );
        assert_eq!(
            parse_balance_error("余额不足，当前余额 ¥12.50").as_deref(),
            Some("¥12.50")
        );
        assert_eq!(parse_balance_error("all good"), None);
    }

    #[test]
    fn challenge_is_strict() {
        assert!(answer_matches("alibaba", "alibaba"));
        assert!(answer_matches("  Alibaba\n", "alibaba"));
        assert!(!answer_matches("alibaba.", "alibaba"));
        assert!(!answer_matches("\"alibaba\"", "alibaba"));
        assert!(!answer_matches("alibaba, sir", "alibaba"));
        assert!(!answer_matches("╔══╗\n║AI║\n╚══╝", "alibaba"));
        assert!(!answer_matches("", "alibaba"));
    }

    fn classify_content(content: &str, token: &str) -> AnswerClass {
        let body = json!({
            "choices": [{"message": {"role": "assistant", "content": content}}]
        })
        .to_string();
        classify_answer(&body, token).0
    }

    #[test]
    fn wrappers_are_not_fake() {
        let token = "alibaba-0a1b2c";
        assert_eq!(classify_content(token, token), AnswerClass::Exact);
        assert_eq!(
            classify_content(&format!("\"{token}\"."), token),
            AnswerClass::Exact
        );
        assert_eq!(
            classify_content(&format!("**{token}**"), token),
            AnswerClass::Exact
        );
        assert_eq!(
            classify_content(&format!("```\n{token}\n```"), token),
            AnswerClass::Exact
        );
        assert_eq!(
            classify_content(&format!("Sure! The token is {token}."), token),
            AnswerClass::Near
        );
    }

    #[test]
    fn no_token_is_not_automatically_fake() {
        let note = class_note(AnswerClass::NoToken, &Some("hello there".into()));
        assert!(!note.starts_with("фейк"), "{note}");
        assert!(note.contains("нет challenge"));
        let note = class_note(AnswerClass::BadJson, &None);
        assert!(note.starts_with("фейк"));
        let note = class_note(AnswerClass::Empty, &None);
        assert!(!note.starts_with("фейк"));
    }

    #[test]
    fn echo_art_and_refusal_are_separate() {
        let token = "alibaba-0a1b2c";
        let echo = challenge_prompt(token);
        assert_eq!(classify_content(&echo, token), AnswerClass::Echo);
        assert_eq!(
            classify_content("╔══╗\n║AI║\n╚══╝ hi!", token),
            AnswerClass::Art
        );
        assert_eq!(
            classify_content("I cannot comply with that.", token),
            AnswerClass::Refusal
        );
        assert_eq!(classify_content("hello world", token), AnswerClass::NoToken);
        assert_eq!(classify_answer("not json", token).0, AnswerClass::BadJson);
    }

    #[test]
    fn random_challenge_defeats_static_fake() {
        let challenge = random_challenge();
        assert!(challenge.contains('-'), "challenge must have a nonce");
        assert!(answer_matches(&challenge, &challenge));
        assert!(!answer_matches("alibaba", &challenge));
        assert!(!answer_matches("╔══╗\n║AI║\n╚══╝", &challenge));
        assert_ne!(random_challenge(), random_challenge());
    }

    #[test]
    fn openrouter_negative_balance_is_not_valid() {
        assert!(balance_is_nonpositive("$-0.04"));
        assert!(balance_is_nonpositive("-$1.00"));
        assert!(balance_is_nonpositive("$0.00"));
        assert!(!balance_is_nonpositive("$9.15"));
        assert!(!balance_is_nonpositive("?"));
    }

    #[test]
    fn ocr_and_embedding_models_are_not_chat() {
        assert!(is_non_chat_model("qwen3.5-ocr"));
        assert!(is_non_chat_model("qwen-vl-ocr"));
        assert!(is_non_chat_model("text-embedding-v4"));
        assert!(is_non_chat_model("qwen3-asr-flash"));
        assert!(!is_non_chat_model("qwen-plus"));
        assert!(!is_non_chat_model("qwen3.5-omni-plus"));
    }

    #[test]
    fn empty_content_is_empty_not_near() {
        let body = r#"{"choices":[{"message":{"content":""}}]}"#;
        let (class, answer) = classify_answer(body, "alibaba");
        assert_eq!(class, AnswerClass::Empty);
        assert!(answer.is_none());
    }

    #[test]
    fn challenge_prompt_names_the_token() {
        let token = "alibaba-0a1b2c";
        let prompt = challenge_prompt(token);
        assert!(prompt.contains(token));
        assert!(prompt.to_lowercase().contains("ascii art"));
        assert!(prompt.to_lowercase().contains("nothing else"));
    }

    #[test]
    fn fallback_models_by_provider() {
        assert!(
            fallback_models("https://api.x.ai/v1", "sk-abc", false).contains(&"grok-3".to_string())
        );
        assert!(
            fallback_models("https://api.deepseek.com/v1", "sk-abc", false)
                .contains(&"deepseek-chat".to_string())
        );
        assert!(fallback_models(
            "https://dashscope.aliyuncs.com/compatible-mode/v1",
            "sk-abc",
            false
        )
        .contains(&"qwen-max".to_string()));
    }

    #[test]
    fn dashscope_workspace_endpoint_uses_compatible_mode() {
        let c = candidates("https://ws-bvicalcqq28azivp.cn-beijing.maas.aliyuncs.com");
        assert_eq!(
            c.first().map(String::as_str),
            Some("https://ws-bvicalcqq28azivp.cn-beijing.maas.aliyuncs.com/compatible-mode/v1")
        );
        assert!(crate::extract::is_dashscope_workspace_endpoint(
            "https://ws-bvicalcqq28azivp.cn-beijing.maas.aliyuncs.com/compatible-mode/v1"
        ));
    }

    #[test]
    fn dashscope_native_endpoint_uses_compatible_mode() {
        let c = candidates("https://dashscope.aliyuncs.com/api/v1");
        assert_eq!(
            c.first().map(String::as_str),
            Some("https://dashscope.aliyuncs.com/compatible-mode/v1")
        );
        assert!(c.contains(&"https://dashscope.aliyuncs.com/api/v1".to_string()));
        let intl = candidates("https://dashscope-intl.aliyuncs.com");
        assert_eq!(
            intl.first().map(String::as_str),
            Some("https://dashscope-intl.aliyuncs.com/compatible-mode/v1")
        );
    }

    #[tokio::test]
    async fn keeps_v1_base_when_models_rejects() {
        let url = spawn_mock_models_401();
        let p = Prober::new(None).unwrap();
        let out = p
            .probe(
                &format!("{}/v1", url),
                "sk-test-abcdefghijklmnopqrstuvwxyz0123456789",
                &ProbeOpts {
                    probe_limit: 3,
                    concurrency: 2,
                    message: challenge_prompt("alibaba"),
                    challenge: "alibaba".into(),
                    cost_probe: false,
                    all_types: false,
                    timeout_secs: 30,
                    video_generate: false,
                },
            )
            .await;
        assert_eq!(out.status, PStatus::Valid, "probes: {:?}", out.probes);
        assert!(out.base.ends_with("/v1"));
        assert_eq!(out.probes[0].code, 200);
    }

    #[tokio::test]
    async fn probes_mock_endpoint() {
        let (url, hits) = spawn_mock();
        let p = Prober::new(None).unwrap();
        let out = p
            .probe(
                &format!("{}/v1", url),
                "sk-test-abcdefghijklmnopqrstuvwxyz0123456789",
                &ProbeOpts {
                    probe_limit: 2,
                    concurrency: 2,
                    message: challenge_prompt("alibaba"),
                    challenge: "alibaba".into(),
                    cost_probe: false,
                    all_types: false,
                    timeout_secs: 30,
                    video_generate: false,
                },
            )
            .await;
        assert_eq!(out.status, PStatus::Valid, "probes: {:?}", out.probes);
        assert_eq!(out.models.len(), 2);
        assert!(out.chat_ok);
        assert!(hits.load(Ordering::SeqCst) >= 3);
    }

    #[tokio::test]
    async fn fake_ascii_is_rejected() {
        let url = spawn_mock_fake();
        let p = Prober::new(None).unwrap();
        let out = p
            .probe(
                &format!("{}/v1", url),
                "sk-test",
                &ProbeOpts {
                    probe_limit: 2,
                    concurrency: 2,
                    message: challenge_prompt("alibaba"),
                    challenge: "alibaba".into(),
                    cost_probe: false,
                    all_types: false,
                    timeout_secs: 30,
                    video_generate: false,
                },
            )
            .await;
        assert_eq!(out.status, PStatus::Fake, "probes: {:?}", out.probes);
        assert!(!out.chat_ok);
        assert!(out.probes.iter().all(|p| p.note.starts_with("фейк")));
    }

    #[tokio::test]
    async fn near_answer_confirms_with_second_challenge() {
        let url = spawn_mock_near();
        let p = Prober::new(None).unwrap();
        let challenge = "alibaba-0a1b2c";
        let out = p
            .probe(
                &format!("{}/v1", url),
                "sk-test",
                &ProbeOpts {
                    probe_limit: 1,
                    concurrency: 1,
                    message: challenge_prompt(challenge),
                    challenge: challenge.into(),
                    cost_probe: false,
                    all_types: false,
                    timeout_secs: 30,
                    video_generate: false,
                },
            )
            .await;
        assert_eq!(out.status, PStatus::Valid, "probes: {:?}", out.probes);
        assert!(out.chat_ok);
        assert!(out.probes[0].note.is_empty());
    }

    #[test]
    fn seedance_detection_and_tiny_body() {
        assert!(is_seedance_endpoint(
            "https://ark.cn-beijing.volces.com/api/v3"
        ));
        assert!(is_seedance_endpoint(
            "https://ark.cn-beijing.volces.com/api/coding/v1"
        ));
        assert!(!is_seedance_endpoint("https://api.openai.com/v1"));
        let t2v = seedance_request_body("doubao-seedance-1-0-pro-250528");
        assert_eq!(t2v["resolution"], "480p");
        assert_eq!(t2v["duration"], 5);
        assert_eq!(t2v["ratio"], "16:9");
        let i2v = seedance_request_body("doubao-seedance-1-0-lite-i2v-250428");
        assert!(i2v.get("ratio").is_none());
        assert!(i2v["content"]
            .as_array()
            .is_some_and(|a| a.iter().any(|x| x["type"] == "image_url")));
    }

    #[test]
    fn tts_endpoint_detection() {
        assert_eq!(
            tts_provider("https://api.fish.audio/v1"),
            Some(TtsProvider::Fish)
        );
        assert_eq!(
            tts_provider("https://api.elevenlabs.io/v1"),
            Some(TtsProvider::Eleven)
        );
        assert!(tts_provider("https://api.openai.com/v1").is_none());
        assert!(is_tts_catalog(&["tts/fish/s2.1-pro-free".to_string()]));
        assert!(!is_tts_catalog(&["gpt-4o-mini".to_string()]));
    }

    #[test]
    fn candidates_v1_and_origin() {
        let c = candidates("https://api.example.com/v1");
        assert_eq!(c[0], "https://api.example.com/v1");
        assert!(c.contains(&"https://api.example.com".to_string()));
    }

    #[test]
    fn candidates_openrouter_prefers_api_v1() {
        // The bare origin must resolve to OpenRouter's real API root, never to
        // `{origin}/v1` (404) or the HTML site at `{origin}/models` (200).
        let c = candidates("https://openrouter.ai");
        assert_eq!(c[0], "https://openrouter.ai/api/v1");
        let c = candidates("https://www.openrouter.ai");
        assert_eq!(c[0], "https://www.openrouter.ai/api/v1");
        // An already-correct endpoint keeps candidate 0 authoritative.
        let c = candidates("https://openrouter.ai/api/v1");
        assert_eq!(c[0], "https://openrouter.ai/api/v1");
    }

    /// OpenRouter-like origin: `/models` is an HTML landing page answering 200
    /// with no catalog, `/v1/*` is a 404, and the real API lives at `/api/v1`.
    fn spawn_mock_landing_and_api_v1() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut s) = stream else { continue };
                let mut buf = vec![0u8; 16384];
                let n = s.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let (status, ctype, body) = if req.starts_with("GET /api/v1/models") {
                    (
                        "200 OK",
                        "application/json",
                        r#"{"object":"list","data":[{"id":"openai/gpt-4o-mini"},{"id":"anthropic/claude-3.5-haiku"}]}"#.to_string(),
                    )
                } else if req.starts_with("POST /api/v1/chat/completions") {
                    (
                        "200 OK",
                        "application/json",
                        r#"{"id":"x","choices":[{"message":{"role":"assistant","content":"alibaba"}}]}"#.to_string(),
                    )
                } else if req.starts_with("GET /models") {
                    // A landing page, not an API: 200 without a catalog.
                    ("200 OK", "text/html", "<html>welcome</html>".to_string())
                } else {
                    (
                        "404 Not Found",
                        "text/html",
                        "<html>nope</html>".to_string(),
                    )
                };
                let resp = format!(
                    "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    status,
                    ctype,
                    body.len(),
                    body
                );
                let _ = s.write_all(resp.as_bytes());
            }
        });
        format!("http://{}", addr)
    }

    #[tokio::test]
    async fn probes_api_v1_root_and_ignores_landing_page() {
        let url = spawn_mock_landing_and_api_v1();
        let p = Prober::new(None).unwrap();
        let opts = ProbeOpts {
            probe_limit: 2,
            concurrency: 2,
            message: challenge_prompt("alibaba"),
            challenge: "alibaba".into(),
            cost_probe: false,
            all_types: false,
            timeout_secs: 10,
            video_generate: false,
        };
        // The real API root probes cleanly.
        let good = p
            .probe(&format!("{url}/api/v1"), "sk-tes...6789", &opts)
            .await;
        assert_eq!(good.status, PStatus::Valid, "probes: {:?}", good.probes);
        assert!(good.base.ends_with("/api/v1"));
        // `/v1` is a 404 here; the origin's 200 HTML page must not become the
        // chat base, otherwise every model 404s and a live key looks PARTIAL.
        let bad = p.probe(&format!("{url}/v1"), "sk-tes...6789", &opts).await;
        assert_ne!(bad.status, PStatus::Valid, "probes: {:?}", bad.probes);
        assert!(
            bad.base.ends_with("/v1"),
            "chat base moved to the landing page: {}",
            bad.base
        );
    }

    #[test]
    fn models_are_prioritized() {
        let models = vec![
            "text-embedding-3-large".to_string(),
            "gpt-4o-mini".to_string(),
            "claude-opus-4-5".to_string(),
            "whisper-1".to_string(),
        ];
        let selected = select_models(&models, 2);
        assert_eq!(selected.len(), 2);
        assert_eq!(selected[0], "claude-opus-4-5");
        assert!(selected.contains(&"gpt-4o-mini".to_string()));
    }

    #[tokio::test]
    async fn official_moonshot_cn_is_always_invalid_without_network() {
        let p = Prober::new(None).unwrap();
        for endpoint in [
            "https://api.moonshot.cn/v1",
            "https://api.moonshot.cn/v1/",
            "https://api.moonshot.cn",
        ] {
            let out = p.probe(endpoint, "sk-test", &ProbeOpts::default()).await;
            assert_eq!(out.status, PStatus::Invalid, "{endpoint}: {out:?}");
            assert!(!out.chat_ok);
            assert_eq!(out.tested, 0);
            assert!(out.probes.is_empty());
        }
        assert!(!is_disabled_api("https://api.moonshot.ai/v1"));
    }

    #[tokio::test]
    async fn official_mistral_is_always_invalid_without_network() {
        let p = Prober::new(None).unwrap();
        for endpoint in [
            "https://api.mistral.ai/v1",
            "https://api.mistral.ai",
            "https://codestral.mistral.ai/v1",
        ] {
            let out = p.probe(endpoint, "sk-test", &ProbeOpts::default()).await;
            assert_eq!(out.status, PStatus::Invalid, "{endpoint}: {out:?}");
            assert!(!out.chat_ok);
            assert_eq!(out.tested, 0);
            assert!(out.probes.is_empty());
        }
    }

    #[test]
    fn exact_generic_fallback_all_429_is_invalid() {
        let models: Vec<String> = GENERIC_FALLBACK_MODELS
            .iter()
            .map(|m| m.to_string())
            .collect();
        let probes: Vec<ProbeLine> = models
            .iter()
            .map(|m| ProbeLine {
                model: m.clone(),
                code: 429,
                latency_ms: 1,
                note: "рейт-окно".into(),
                rpm: String::new(),
            })
            .collect();
        assert!(is_generic_fallback_429(&probes, &models));
        let mut subset = probes.clone();
        subset.pop();
        assert!(!is_generic_fallback_429(&subset, &models));
        let mut one_ok = probes.clone();
        one_ok[0].code = 200;
        assert!(!is_generic_fallback_429(&one_ok, &models));
        let mut extra_model = models.clone();
        extra_model.push("extra-model".into());
        assert!(!is_generic_fallback_429(&probes, &extra_model));
    }

    #[test]
    fn google_uses_v1beta_and_native_models() {
        let c = candidates("https://generativelanguage.googleapis.com/v1beta");
        assert_eq!(c[0], "https://generativelanguage.googleapis.com/v1beta");
        assert!(!c.iter().any(|x| x.ends_with("/v1")));
        assert!(is_google(
            "https://generativelanguage.googleapis.com/v1beta",
            "AIza-test"
        ));
        assert!(google_auth_error(
            403,
            r#"{"error":{"status":"PERMISSION_DENIED","message":"API key was reported as leaked"}}"#
        ));
        let v = serde_json::json!({
            "models": [
                {"name": "models/gemini-2.5-flash", "supportedGenerationMethods": ["generateContent"]},
                {"name": "models/text-embedding-004", "supportedGenerationMethods": ["embedContent"]}
            ]
        });
        assert_eq!(parse_models(&v), vec!["gemini-2.5-flash"]);
        assert_eq!(
            answer_text(r#"{"candidates":[{"content":{"parts":[{"text":"alibaba"}]}}]}"#)
                .as_deref(),
            Some("alibaba")
        );
    }

    #[tokio::test]
    async fn google_chat_uses_native_generate_content() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let seen = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
        let seen2 = seen.clone();
        std::thread::spawn(move || {
            if let Ok((mut s, _)) = listener.accept() {
                let mut buf = vec![0u8; 16384];
                let n = s.read(&mut buf).unwrap_or(0);
                *seen2.lock().unwrap_or_else(|e| e.into_inner()) =
                    String::from_utf8_lossy(&buf[..n]).to_string();
                let body = r#"{"candidates":[{"content":{"parts":[{"text":"alibaba"}]}}]}"#;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = s.write_all(resp.as_bytes());
            }
        });
        let client = build_client(None, 10).unwrap();
        let base = format!("http://{addr}/v1beta");
        let (code, _, body, _) = chat_request(
            &client,
            &base,
            "AIza-test",
            "gemini-2.5-flash",
            "hi",
            false,
            10,
        )
        .await
        .unwrap();
        assert_eq!(code, 200);
        let req = seen.lock().unwrap_or_else(|e| e.into_inner()).clone();
        assert!(req.starts_with("POST /v1beta/models/gemini-2.5-flash:generateContent"));
        assert!(req
            .to_ascii_lowercase()
            .contains("x-goog-api-key: aiza-test"));
        assert!(req.contains("\"contents\""));
        assert_eq!(answer_text(&body).as_deref(), Some("alibaba"));
    }

    #[test]
    fn rpm_headers_are_parsed() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-ratelimit-limit-requests",
            reqwest::header::HeaderValue::from_static("500"),
        );
        assert_eq!(parse_rpm_headers(&headers), "500/мин");

        let mut fallback = HeaderMap::new();
        fallback.insert(
            "ratelimit-limit",
            reqwest::header::HeaderValue::from_static("60;w=60"),
        );
        assert_eq!(parse_rpm_headers(&fallback), "60/мин");
        assert_eq!(parse_rpm_headers(&HeaderMap::new()), "");
    }
}
