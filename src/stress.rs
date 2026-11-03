use crate::app::App;
use crate::checker::Pair;
use crate::format::esc;
use crate::probe::candidates;
use anyhow::{anyhow, bail, Result};
use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::Client;
use serde_json::{json, Value};
use std::path::Path;
use std::time::{Duration, Instant};
use tracing::{info, warn};

const DEFAULT_TARGET: i64 = 5_500_000;
const MAX_MODELS: usize = 5;
const CONTEXT_CAP: usize = 64_000;
const MAX_REQUESTS: usize = 4000;

#[derive(Clone, Debug)]
struct ModelInfo {
    id: String,
    context: Option<usize>,
}

#[derive(Clone, Debug, Default)]
struct ModelStat {
    model: String,
    context: Option<usize>,
    requests: usize,
    successes: usize,
    failures: usize,
    tokens_in: u64,
    tokens_out: u64,
    tokens_total: u64,
    latencies: Vec<u64>,
    rpm_header: String,
    last_error: String,
}

#[derive(Clone, Debug)]
struct CallResult {
    status: u16,
    text: String,
    usage_in: u64,
    usage_out: u64,
    usage_total: u64,
    latency_ms: u64,
    rpm: String,
}

struct Engine {
    client: Client,
    base: String,
    key: String,
    anthropic: bool,
}

impl Engine {
    async fn new(pair: &Pair) -> Result<Self> {
        let client = crate::github::build_client(None, 120)?;
        let base = pair.base.trim().trim_end_matches('/').to_string();
        let anthropic = crate::extract::host_of(&base).contains("anthropic");
        Ok(Self {
            client,
            base,
            key: pair.key.clone(),
            anthropic,
        })
    }

    fn headers(&self) -> Result<HeaderMap> {
        let mut h = HeaderMap::new();
        let header_value = |name: &'static str, value: &str| {
            HeaderValue::from_str(value)
                .map(|v| (name, v))
                .map_err(|_| anyhow!("{name} contains characters invalid in an HTTP header"))
        };
        if self.anthropic {
            let (name, value) = header_value("x-api-key", &self.key)?;
            h.insert(name, value);
            let (name, value) = header_value("anthropic-version", "2023-06-01")?;
            h.insert(name, value);
        } else {
            let bearer = format!("Bearer {}", self.key);
            let (name, value) = header_value("authorization", &bearer)?;
            h.insert(name, value);
        }
        let (name, value) = header_value("content-type", "application/json")?;
        h.insert(name, value);
        let (name, value) = header_value("user-agent", crate::github::UA)?;
        h.insert(name, value);
        Ok(h)
    }

    async fn models(&self) -> Result<(String, Vec<ModelInfo>)> {
        let mut candidates = candidates(&self.base);
        if candidates.is_empty() {
            candidates.push(self.base.clone());
        }
        // Exact endpoint first; a public root /models is not proof that the
        // chat route is the same (OpenRouter serves both).
        for base in candidates {
            let url = format!("{}/models", base.trim_end_matches('/'));
            let resp = self
                .client
                .get(&url)
                .headers(self.headers()?)
                .timeout(Duration::from_secs(30))
                .send()
                .await;
            let Ok(resp) = resp else { continue };
            if resp.status().as_u16() != 200 {
                continue;
            }
            let v: Value = resp.json().await.unwrap_or(Value::Null);
            let models = parse_models(&v);
            if !models.is_empty() {
                return Ok((base, models));
            }
        }
        bail!("не удалось получить каталог /models")
    }

    async fn chat(
        &self,
        base: &str,
        model: &str,
        prompt: &str,
        max_tokens: u32,
    ) -> Result<CallResult> {
        let url = if self.anthropic {
            format!("{}/messages", base.trim_end_matches('/'))
        } else {
            format!("{}/chat/completions", base.trim_end_matches('/'))
        };
        let body = if self.anthropic {
            json!({
                "model": model,
                "max_tokens": max_tokens,
                "temperature": 0.2,
                "messages": [{"role": "user", "content": prompt}]
            })
        } else {
            json!({
                "model": model,
                "max_tokens": max_tokens,
                "temperature": 0.2,
                "messages": [{"role": "user", "content": prompt}]
            })
        };
        let started = Instant::now();
        let resp = self
            .client
            .post(&url)
            .headers(self.headers()?)
            .json(&body)
            .timeout(Duration::from_secs(120))
            .send()
            .await?;
        let status = resp.status().as_u16();
        let rpm = crate::probe::parse_rpm_headers(resp.headers());
        let text = resp.text().await.unwrap_or_default();
        let v: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
        let (usage_in, usage_out, usage_total) = parse_usage(&v);
        Ok(CallResult {
            status,
            text,
            usage_in,
            usage_out,
            usage_total,
            latency_ms: started.elapsed().as_millis() as u64,
            rpm,
        })
    }
}

fn parse_models(v: &Value) -> Vec<ModelInfo> {
    let arr = v
        .get("data")
        .and_then(|x| x.as_array())
        .or_else(|| v.get("models").and_then(|x| x.as_array()))
        .or_else(|| v.as_array());
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let Some(arr) = arr else { return out };
    for item in arr {
        let id = item
            .get("id")
            .and_then(|x| x.as_str())
            .or_else(|| item.get("name").and_then(|x| x.as_str()))
            .or_else(|| item.as_str());
        let Some(id) = id else { continue };
        let id = id.trim().to_string();
        if id.is_empty() || !seen.insert(id.clone()) {
            continue;
        }
        let lower = id.to_ascii_lowercase();
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
            "ocr",
            "rerank",
            "asr",
        ]
        .iter()
        .any(|x| lower.contains(x))
        {
            continue;
        }
        let context = item
            .get("context_length")
            .and_then(|x| x.as_u64())
            .or_else(|| item.get("context_window").and_then(|x| x.as_u64()))
            .or_else(|| item.get("max_context_length").and_then(|x| x.as_u64()))
            .or_else(|| item.get("max_model_len").and_then(|x| x.as_u64()))
            .or_else(|| {
                item.get("top_provider")
                    .and_then(|p| p.get("context_length"))
                    .and_then(|x| x.as_u64())
            })
            .map(|x| x as usize);
        out.push(ModelInfo { id, context });
    }
    out
}

fn parse_usage(v: &Value) -> (u64, u64, u64) {
    let usage = v.get("usage").unwrap_or(&Value::Null);
    let input = usage
        .get("prompt_tokens")
        .or_else(|| usage.get("input_tokens"))
        .and_then(|x| x.as_u64())
        .unwrap_or(0);
    let output = usage
        .get("completion_tokens")
        .or_else(|| usage.get("output_tokens"))
        .and_then(|x| x.as_u64())
        .unwrap_or(0);
    let total = usage
        .get("total_tokens")
        .and_then(|x| x.as_u64())
        .unwrap_or(input + output);
    (input, output, total)
}

fn model_score(id: &str) -> i32 {
    let l = id.to_ascii_lowercase();
    let mut score = 0;
    for (needle, pts) in [
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
    ] {
        if l.contains(needle) {
            score += pts;
            break;
        }
    }
    score - l.len() as i32 / 8
}

fn select_models(mut models: Vec<ModelInfo>, limit: usize) -> Vec<ModelInfo> {
    models.sort_by(|a, b| {
        model_score(&b.id)
            .cmp(&model_score(&a.id))
            .then(a.id.len().cmp(&b.id.len()))
    });
    models.truncate(limit);
    models
}

async fn find_working(
    engine: &Engine,
    base: &str,
    models: Vec<ModelInfo>,
    want: usize,
) -> Vec<ModelInfo> {
    let mut working = Vec::new();
    for model in select_models(models, 40) {
        if working.len() >= want {
            break;
        }
        let prompt = "Reply with exactly: ok";
        match engine.chat(base, &model.id, prompt, 2).await {
            Ok(out) if out.status == 200 => {
                // A 200 is not a completion: relays return 200 with an error
                // object, an empty body, or a quota notice. Require actual
                // answer text before promoting a model to the stress pool.
                if extract_answer(&out.text).trim().is_empty() {
                    warn!("stress: model {} returned 200 without content", model.id);
                    continue;
                }
                if let Some(total) = usage_or_estimate(&out, prompt, "ok") {
                    if total > 0 {
                        working.push(model);
                    }
                }
            }
            Ok(out) => {
                warn!("stress: model {} probe HTTP {}", model.id, out.status);
            }
            Err(e) => warn!("stress: model {} probe error: {e}", model.id),
        }
    }
    working
}

fn usage_or_estimate(out: &CallResult, prompt: &str, answer: &str) -> Option<u64> {
    if out.usage_total > 0 {
        return Some(out.usage_total);
    }
    let text = extract_answer(&out.text);
    let answer = if text.is_empty() {
        answer
    } else {
        text.as_str()
    };
    let total = (prompt.chars().count() + answer.chars().count()) as u64 / 4;
    (total > 0).then_some(total)
}

fn extract_answer(body: &str) -> String {
    let v: Value = serde_json::from_str(body).unwrap_or(Value::Null);
    if let Some(s) = v
        .get("choices")
        .and_then(|x| x.as_array())
        .and_then(|a| a.first())
        .and_then(|c| c.get("message"))
        .and_then(|m| m.get("content"))
        .and_then(|x| x.as_str())
    {
        return s.to_string();
    }
    if let Some(arr) = v.get("content").and_then(|x| x.as_array()) {
        return arr
            .iter()
            .filter_map(|x| x.get("text").and_then(|t| t.as_str()))
            .collect::<Vec<_>>()
            .join(" ");
    }
    String::new()
}

fn make_prompt(tokens: usize) -> String {
    let mut out = String::with_capacity(tokens.saturating_mul(4).min(2_000_000));
    out.push_str("This is a controlled API stress test. Read the context and answer briefly.\n");
    let block = "The quick brown fox jumps over the lazy dog. This repeated context is intentionally long for a token-throughput and context-window benchmark. ";
    while out.len() < tokens.saturating_mul(4) {
        out.push_str(block);
    }
    out.push_str("\nReturn one short sentence summarising the test.");
    out
}

fn pct(v: &[u64], p: usize) -> u64 {
    if v.is_empty() {
        return 0;
    }
    let mut s = v.to_vec();
    s.sort_unstable();
    s[(p.min(100) * (s.len() - 1)) / 100]
}

fn fmt_num(n: u64) -> String {
    let mut s = n.to_string();
    let mut out = String::new();
    while s.len() > 3 {
        let tail = s.split_off(s.len() - 3);
        if out.is_empty() {
            out = tail;
        } else {
            out = format!("{tail},{out}");
        }
    }
    if out.is_empty() {
        s
    } else {
        format!("{s},{out}")
    }
}

fn masked(key: &str) -> String {
    let chars: Vec<char> = key.chars().collect();
    if chars.len() <= 10 {
        return "***".into();
    }
    format!(
        "{}…{}",
        chars[..6].iter().collect::<String>(),
        chars[chars.len() - 4..].iter().collect::<String>()
    )
}

pub async fn run(app: std::sync::Arc<App>, pairs: Vec<Pair>, source: String) -> Result<()> {
    let Some(pair) = pairs.into_iter().next() else {
        bail!("нет пары ключ + base url");
    };
    if crate::probe::is_disabled_api(&pair.base) {
        bail!("этот официальный endpoint отключён и не проверяется");
    }
    let target = app
        .store
        .setting_i64("stress_target_tokens", DEFAULT_TARGET)
        .clamp(100_000, 20_000_000) as u64;
    let max_models = app
        .store
        .setting_i64("stress_models", MAX_MODELS as i64)
        .clamp(1, MAX_MODELS as i64) as usize;
    let chat = app.report_chat();
    let mid = app
        .tg
        .send(
            chat,
            &format!(
                "⚡ <b>Стресс-тест API</b>\n\n🌐 <code>{}</code>\n🎯 Цель: <b>{} токенов</b>\n🤖 Моделей: до {max_models}\n\nСначала найду рабочие модели, затем прогоню нагрузку.",
                esc(&pair.base),
                fmt_num(target)
            ),
            None,
        )
        .await
        .ok();

    let result = run_pair(&app, &pair, target, max_models, chat, mid.unwrap_or(0)).await;
    match result {
        Ok(report) => {
            let stamp = chrono::Utc::now().timestamp_millis();
            let dir = Path::new("exports");
            std::fs::create_dir_all(dir)?;
            let path = dir.join(format!("stress_{stamp}.txt"));
            std::fs::write(&path, &report)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
                let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
            }
            let caption = format!("⚡ <b>Стресс-тест готов</b> · {}", esc(&source));
            app.tg.send_document(chat, &path, &caption).await?;
            Ok(())
        }
        Err(e) => {
            let text = format!("❌ <b>Стресс-тест не удался</b>\n\n{}", esc(&e.to_string()));
            if let Some(mid) = mid {
                let _ = app.tg.edit(chat, mid, &text, None).await;
            } else {
                let _ = app.tg.send(chat, &text, None).await;
            }
            Err(e)
        }
    }
}

async fn run_pair(
    app: &std::sync::Arc<App>,
    pair: &Pair,
    target: u64,
    max_models: usize,
    chat: i64,
    mid: i64,
) -> Result<String> {
    let engine = Engine::new(pair).await?;
    let (base, models) = engine.models().await?;
    // Pick the first candidate that has a working model; keep the exact base
    // selected by the model lookup.
    let working = find_working(&engine, &base, models, max_models).await;
    if working.is_empty() {
        bail!("не удалось найти ни одной рабочей модели");
    }
    run_models(app, &engine, &base, working, target, chat, mid).await
}

async fn run_models(
    app: &std::sync::Arc<App>,
    engine: &Engine,
    base: &str,
    working: Vec<ModelInfo>,
    target: u64,
    chat: i64,
    mid: i64,
) -> Result<String> {
    let started = Instant::now();
    let mut stats: Vec<ModelStat> = working
        .iter()
        .map(|m| ModelStat {
            model: m.id.clone(),
            context: m.context,
            ..Default::default()
        })
        .collect();
    let per_model = (target / stats.len() as u64).max(1);
    let mut total: u64 = 0;
    let mut requests = 0usize;
    let mut last_progress = Instant::now();

    for idx in 0..stats.len() {
        let context = stats[idx].context.unwrap_or(8192).clamp(1024, CONTEXT_CAP);
        let mut input_target = ((context as f64 * 0.70) as usize).clamp(512, CONTEXT_CAP);
        let mut model_tokens = 0u64;
        let mut model_requests = 0usize;
        let mut consecutive_429 = 0usize;
        while total < target
            && model_tokens < per_model
            && requests < MAX_REQUESTS
            && model_requests < 800
        {
            let prompt = make_prompt(input_target);
            let result = engine.chat(base, &stats[idx].model, &prompt, 128).await;
            requests += 1;
            model_requests += 1;
            stats[idx].requests += 1;
            match result {
                Ok(out) if out.status == 200 => {
                    let answer_text = extract_answer(&out.text);
                    if answer_text.trim().is_empty() {
                        stats[idx].failures += 1;
                        stats[idx].last_error = "HTTP 200 без ответа".into();
                        continue;
                    }
                    // Count provider-reported usage only. A relay that omits
                    // usage must not be able to fabricate a 5.5M-token run.
                    let tokens = if out.usage_total > 0 {
                        out.usage_total
                    } else {
                        (answer_text.chars().count() as u64 / 4).max(1)
                    };
                    let in_tokens = if out.usage_in > 0 {
                        out.usage_in
                    } else {
                        prompt.chars().count() as u64 / 4
                    };
                    let out_tokens = if out.usage_out > 0 {
                        out.usage_out
                    } else {
                        extract_answer(&out.text).chars().count() as u64 / 4
                    };
                    stats[idx].successes += 1;
                    consecutive_429 = 0;
                    stats[idx].tokens_total += tokens;
                    stats[idx].tokens_in += in_tokens;
                    stats[idx].tokens_out += out_tokens;
                    stats[idx].latencies.push(out.latency_ms);
                    if stats[idx].rpm_header.is_empty() {
                        stats[idx].rpm_header = out.rpm;
                    }
                    model_tokens += tokens;
                    total += tokens;
                }
                Ok(out) => {
                    stats[idx].failures += 1;
                    stats[idx].last_error = format!("HTTP {}", out.status);
                    if out.status == 401 || out.status == 403 {
                        break;
                    }
                    if (out.status == 400 || out.status == 413) && input_target > 1024 {
                        input_target /= 2;
                    }
                    if out.status == 429 {
                        consecutive_429 += 1;
                        if consecutive_429 >= 3 {
                            stats[idx].last_error = "429: слишком много подряд".into();
                            break;
                        }
                        tokio::time::sleep(Duration::from_secs(2)).await;
                    } else {
                        consecutive_429 = 0;
                    }
                }
                Err(e) => {
                    stats[idx].failures += 1;
                    stats[idx].last_error = e.to_string();
                }
            }
            if last_progress.elapsed() >= Duration::from_secs(8) {
                last_progress = Instant::now();
                if mid > 0 {
                    let _ = app
                        .tg
                        .edit(
                            chat,
                            mid,
                            &format!(
                                "⚡ <b>Стресс-тест</b>\n\n🎯 Токены: <b>{} / {}</b>\n📡 Запросов: {}\n🤖 Модель: <code>{}</code>",
                                fmt_num(total),
                                fmt_num(target),
                                requests,
                                esc(&stats[idx].model)
                            ),
                            None,
                        )
                        .await;
                }
            }
        }
        if total >= target {
            break;
        }
    }

    let elapsed = started.elapsed().as_secs_f64().max(1.0);
    let mut out = String::new();
    out.push_str("⚡ STRESS TEST · API\n");
    out.push_str("════════════════════════════════════════════════\n");
    out.push_str(&format!("KEY: {}\n", masked(&engine.key)));
    out.push_str(&format!("BASE URL: {}\n", base));
    out.push_str(&format!(
        "DATE: {}\n",
        chrono::Local::now().format("%d.%m.%Y %H:%M")
    ));
    out.push_str(&format!("TARGET TOKENS: {}\n", fmt_num(target)));
    out.push_str(&format!("TOTAL TOKENS: {}\n", fmt_num(total)));
    out.push_str(&format!(
        "TARGET MET: {}\n",
        if total >= target { "YES" } else { "NO" }
    ));
    out.push_str(&format!("REQUESTS: {}\n", requests));
    out.push_str(&format!("ELAPSED: {:.1}s\n", elapsed));
    out.push_str(&format!(
        "OBSERVED RPM: {:.1}\n",
        requests as f64 / (elapsed / 60.0)
    ));
    out.push_str(&format!("MODELS TESTED: {}\n\n", stats.len()));

    for (i, s) in stats.iter().enumerate() {
        let avg = if s.latencies.is_empty() {
            0
        } else {
            s.latencies.iter().sum::<u64>() / s.latencies.len() as u64
        };
        let tps = if elapsed > 0.0 {
            s.tokens_out as f64 / elapsed
        } else {
            0.0
        };
        out.push_str(&format!("MODEL {}: {}\n", i + 1, s.model));
        out.push_str(&format!(
            "  context: {}\n",
            s.context
                .map(|x| x.to_string())
                .unwrap_or_else(|| "?".into())
        ));
        out.push_str(&format!(
            "  requests: {} (ok {}, fail {})\n",
            s.requests, s.successes, s.failures
        ));
        out.push_str(&format!(
            "  tokens: {} (in {}, out {})\n",
            fmt_num(s.tokens_total),
            fmt_num(s.tokens_in),
            fmt_num(s.tokens_out)
        ));
        out.push_str(&format!(
            "  latency avg/p50/p95 ms: {} / {} / {}\n",
            avg,
            pct(&s.latencies, 50),
            pct(&s.latencies, 95)
        ));
        out.push_str(&format!("  TPS (completion): {:.2}\n", tps));
        out.push_str(&format!(
            "  RPM header: {}\n",
            if s.rpm_header.is_empty() {
                "?"
            } else {
                &s.rpm_header
            }
        ));
        if !s.last_error.is_empty() {
            out.push_str(&format!("  last error: {}\n", s.last_error));
        }
        out.push('\n');
    }
    out.push_str("════════════════════════════════════════════════\n");
    info!(
        "stress test done: tokens={} target={} requests={}",
        total, target, requests
    );
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn model_context_is_parsed_from_common_shapes() {
        let v = json!({"data": [
            {"id": "openai/gpt-test", "context_length": 128000},
            {"id": "anthropic/claude-test", "top_provider": {"context_length": 200000}},
            {"id": "embed-test", "context_length": 8192}
        ]});
        let models = parse_models(&v);
        assert_eq!(models.len(), 2);
        assert_eq!(models[0].context, Some(128000));
        assert_eq!(models[1].context, Some(200000));
    }

    #[test]
    fn usage_handles_openai_and_anthropic() {
        assert_eq!(
            parse_usage(
                &json!({"usage": {"prompt_tokens": 10, "completion_tokens": 4, "total_tokens": 14}})
            ),
            (10, 4, 14)
        );
        assert_eq!(
            parse_usage(&json!({"usage": {"input_tokens": 7, "output_tokens": 3}})),
            (7, 3, 10)
        );
    }

    #[test]
    fn prompt_is_large_enough_for_token_target() {
        let p = make_prompt(2048);
        assert!(p.len() >= 2048 * 4);
        assert!(p.contains("Return one short sentence"));
    }

    #[test]
    fn key_is_masked() {
        assert_eq!(masked("sk-or-v1-1234567890abcdef"), "sk-or-…cdef");
        assert_eq!(masked("short"), "***");
    }
}
