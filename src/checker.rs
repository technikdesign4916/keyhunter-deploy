use crate::app::App;
use crate::format::esc;
use crate::probe::{challenge_prompt, random_challenge, PStatus, ProbeOpts, ProbeOutcome, Prober};
use anyhow::Result;
use futures::stream::{self, StreamExt};
use reqwest::Client;
use serde_json::Value;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct Pair {
    pub key: String,
    pub base: String,
}

fn auth_valid(out: &ProbeOutcome) -> bool {
    // `/models` is public on several OpenAI-compatible providers (notably
    // DashScope compatible-mode and OpenRouter). A 200 catalog therefore is
    // not proof that the key authenticates. Only a successful challenge chat
    // proves both auth and usable inference; a 200 with an empty/refused/
    // fake answer is not enough.
    if out.status == PStatus::Valid {
        return true;
    }
    // A chat 200 on an exhausted OpenRouter account is not a usable key.
    out.chat_ok && !crate::probe::balance_is_nonpositive(&out.balance)
}

fn model_works(p: &crate::store::ProbeLine) -> bool {
    // TTS probes use a synthetic `tts/<provider>/<model>` catalog entry and
    // a verified audio response. They are not chat models, but they are a
    // working model for this endpoint.
    if p.model.starts_with("tts/") || p.model.starts_with("type/") || p.model.starts_with("video/")
    {
        return p.code == 200 && (p.note.ends_with(" ok") || p.note.is_empty());
    }
    // A model that returned a non-empty, non-fake JSON answer is working even
    // if it ignored the exact challenge. Challenge correctness is a fraud
    // signal for the KEY, not a reason to hide a model from the checker.
    p.code == 200
        && !crate::probe::is_non_chat_model(&p.model)
        && p.note != "пустой ответ"
        && !p.note.contains("пустой ответ")
        && !p.note.starts_with("фейк")
        && !p.note.starts_with("не JSON")
        && !p.note.starts_with("challenge:")
        && !p.note.contains("эхо")
}

#[derive(Debug)]
pub struct CheckRow {
    pub key: String,
    pub base: String,
    pub balance: String,
    pub rpm: String,
    pub subscription: String,
    pub account_type: String,
    pub models: Vec<String>,
}

/// Best-effort plan/subscription lookup. Missing/inaccessible endpoints return
/// `?`; this is display metadata only and must never make a valid key invalid.
pub async fn subscription_for(client: &Client, base: &str, key: &str) -> String {
    let host = crate::extract::host_of(base);
    let root = if let Some(i) = base.find("://") {
        let after = &base[i + 3..];
        let slash = after.find('/').map(|x| i + 3 + x).unwrap_or(base.len());
        base[..slash].trim_end_matches('/').to_string()
    } else {
        base.trim_end_matches('/').to_string()
    };
    let attempts: Vec<(String, reqwest::RequestBuilder)> = if host.contains("elevenlabs") {
        vec![(
            format!("{root}/v1/user"),
            client
                .get(format!("{root}/v1/user"))
                .header("xi-api-key", key),
        )]
    } else if host.contains("fish.audio") {
        vec![
            (
                format!("{root}/wallet/self/package"),
                client
                    .get(format!("{root}/wallet/self/package"))
                    .bearer_auth(key),
            ),
            (
                format!("{root}/wallet/self/api-credit"),
                client
                    .get(format!("{root}/wallet/self/api-credit"))
                    .bearer_auth(key),
            ),
        ]
    } else if host.contains("openrouter") {
        vec![(
            format!("{root}/api/v1/key"),
            client.get(format!("{root}/api/v1/key")).bearer_auth(key),
        )]
    } else {
        let mut out = Vec::new();
        for (path, header) in [
            ("/v1/dashboard/billing/subscription", "bearer"),
            ("/v1/user", "bearer"),
            ("/v1/me", "bearer"),
            ("/user", "bearer"),
            ("/subscription", "bearer"),
        ] {
            let url = format!("{root}{path}");
            let rb = if header == "bearer" {
                client.get(&url).bearer_auth(key)
            } else {
                client.get(&url)
            };
            out.push((url, rb));
        }
        out
    };
    for (_, rb) in attempts {
        let Ok(resp) = rb.timeout(Duration::from_secs(8)).send().await else {
            continue;
        };
        if !resp.status().is_success() {
            continue;
        }
        let Ok(v) = resp.json::<Value>().await else {
            continue;
        };
        if let Some(s) = find_subscription(&v) {
            return s;
        }
    }
    "?".to_string()
}

fn find_subscription(v: &Value) -> Option<String> {
    if let Some(b) = v.get("is_free_tier").and_then(|x| x.as_bool()) {
        return Some(if b { "free".into() } else { "paid".into() });
    }
    for key in [
        "subscription",
        "plan",
        "tier",
        "package",
        "subscription_tier",
        "type",
        "name",
        "label",
    ] {
        let Some(x) = v.get(key) else { continue };
        if let Some(s) = x.as_str() {
            let s = s.trim();
            if !s.is_empty() {
                return Some(s.to_ascii_lowercase());
            }
        }
        if let Some(s) = find_subscription(x) {
            return Some(s);
        }
    }
    // OpenAI billing and some relays nest the plan under `data`.
    v.get("data").and_then(find_subscription)
}

/// Human-readable account tier for the checker. The raw provider value stays
/// in `Подписка`; this line only normalizes the common free/paid markers.
fn account_type_for(subscription: &str) -> String {
    let s = subscription.trim().to_ascii_lowercase();
    if s.is_empty() || s == "?" {
        return "?".to_string();
    }
    if s.contains("free") || s.contains("trial") || s.contains("basic") {
        return "Free".to_string();
    }
    if s.contains("paid")
        || s.contains("pro")
        || s.contains("scale")
        || s.contains("premium")
        || s.contains("enterprise")
        || s.contains("team")
        || s.contains("standard")
        || s.contains("pay-as-you-go")
    {
        return "Paid".to_string();
    }
    "?".to_string()
}

pub fn parse_pairs(text: &str) -> Vec<Pair> {
    let mut out: Vec<Pair> = Vec::new();
    let mut pending_key: Option<String> = None;
    let mut pending_base: Option<String> = None;

    for raw in text.lines() {
        let line = raw.trim().trim_start_matches('\u{feff}').trim().to_string();
        if line.is_empty()
            || line.starts_with('#')
            || line.starts_with("//")
            || line.starts_with(';')
        {
            continue;
        }
        let low = line.to_lowercase();
        if matches!(
            low.as_str(),
            "api key"
                | "apikey"
                | "api_key"
                | "base url"
                | "base_url"
                | "baseurl"
                | "ключ"
                | "базовый url"
                | "базовый url api"
        ) {
            continue;
        }
        if ["ghp_", "github_pat_", "gho_", "ghu_", "ghs_", "ghr_"]
            .iter()
            .any(|p| line.starts_with(p))
        {
            // GitHub PAT files use the same hook as the checker; never treat
            // them as API keys.
            continue;
        }
        if low.starts_with("http://") || low.starts_with("https://") {
            let base = line.trim_end_matches('/').to_string();
            if let Some(key) = pending_key.take() {
                push_pair(&mut out, key, base);
            } else {
                pending_base = Some(base);
            }
            continue;
        }
        if let Some(base) = pending_base.take() {
            push_pair(&mut out, line, base);
            continue;
        }
        if line.len() >= 6 && !line.contains(char::is_whitespace) {
            pending_key = Some(line);
        }
    }
    if let (Some(key), Some(base)) = (pending_key, pending_base) {
        push_pair(&mut out, key, base);
    }
    out
}

fn push_pair(out: &mut Vec<Pair>, key: String, base: String) {
    if key.is_empty() || base.is_empty() {
        return;
    }
    if out.iter().any(|p| p.key == key && p.base == base) {
        return;
    }
    out.push(Pair { key, base });
}

pub async fn check_pairs(
    prober: &Prober,
    pairs: &[Pair],
    model_limit: usize,
    workers: usize,
) -> Vec<(usize, CheckRow)> {
    let challenge = random_challenge();
    let opts = ProbeOpts {
        probe_limit: model_limit,
        // Per-key chat concurrency must stay low: OpenRouter and similar
        // providers rate-limit a burst of 16 model calls even when the key is
        // valid. Parallelism belongs across keys, not inside one key.
        concurrency: 4,
        message: challenge_prompt(&challenge),
        challenge,
        cost_probe: false,
        all_types: true,
        timeout_secs: 12,
        video_generate: true,
    };
    let futures = stream::iter(pairs.iter().cloned().enumerate().map(|(idx, pair)| {
        let opts = opts.clone();
        async move {
            let out = prober.probe(&pair.base, &pair.key, &opts).await;
            if !auth_valid(&out) {
                return None;
            }
            let mut models: Vec<String> = out
                .probes
                .iter()
                .filter(|p| model_works(p))
                .map(|p| p.model.clone())
                .collect();
            models.sort();
            models.dedup();
            let subscription = subscription_for(&prober.http_client(), &pair.base, &pair.key).await;
            Some((
                idx,
                CheckRow {
                    key: pair.key,
                    base: out.base.clone(),
                    account_type: account_type_for(&subscription),
                    subscription,
                    balance: if out.balance.trim().is_empty() {
                        "?".to_string()
                    } else {
                        out.balance
                    },
                    rpm: if out.rpm.trim().is_empty() {
                        "?".to_string()
                    } else {
                        out.rpm
                    },
                    models,
                },
            ))
        }
    }))
    .buffer_unordered(workers.max(1));
    let results: Vec<Option<(usize, CheckRow)>> = futures.collect().await;
    let mut rows: Vec<(usize, CheckRow)> = results.into_iter().flatten().collect();
    rows.sort_by_key(|(idx, _)| *idx);
    rows
}

pub fn render_rows(rows: &[(usize, CheckRow)], total: usize) -> String {
    render(rows, total)
}

/// Run the checker and send a txt file containing only valid API keys.
pub async fn run(app: Arc<App>, chat: i64, pairs: Vec<Pair>, source: String) -> Result<()> {
    let total = pairs.len();
    if total == 0 {
        let _ = app
            .tg
            .send(
                chat,
                "⚠️ Не вижу пар «ключ + base url». Формат: ключ, строка ниже base url, пустая строка между парами.",
                None,
            )
            .await;
        return Ok(());
    }

    let workers = app.store.setting_i64("checker_threads", 32).clamp(1, 64) as usize;
    let model_limit = app.store.setting_i64("checker_models", 0).clamp(0, 512) as usize;
    let checker_timeout = app.store.setting_i64("checker_timeout", 8).clamp(3, 30) as u64;
    let checker_probe_conc = app
        .store
        .setting_i64("checker_probe_concurrency", 32)
        .clamp(1, 64) as usize;
    let stamp = chrono::Utc::now().timestamp_millis();

    let mid = app
        .tg
        .send(
            chat,
            &format!(
                "🧪 <b>Чекер API</b>\n\nПар: <b>{total}</b> · потоков: <b>{workers}</b> · моделей на ключ: <b>{}</b>\nПроверяю /models, модели и баланс…",
                if model_limit == 0 { "все".to_string() } else { format!("до {model_limit}") }
            ),
            None,
        )
        .await
        .ok();
    let done = Arc::new(AtomicUsize::new(0));
    // API checks must not inherit the rotating source proxy: a dead proxy can
    // look like a dead key. Try direct first, then the configured proxy as a
    // fallback for providers that are only reachable through it.
    let direct = Arc::new(Prober::new(None)?);

    let app_for_task = app.clone();
    let futures = stream::iter(pairs.into_iter().enumerate().map(|(idx, pair)| {
        let app = app_for_task.clone();
        let direct = direct.clone();
        let done = done.clone();
        let chat = chat;
        let mid = mid;
        async move {
            let mut opts = app.probe_opts();
            opts.probe_limit = model_limit;
            opts.all_types = true;
            opts.video_generate = true;
            opts.concurrency = checker_probe_conc;
            opts.timeout_secs = checker_timeout;
            let mut out = direct.probe(&pair.base, &pair.key, &opts).await;
            if !auth_valid(&out) {
                let proxied = app.prober.probe(&pair.base, &pair.key, &opts).await;
                if auth_valid(&proxied) {
                    out = proxied;
                }
            }

            let n = done.fetch_add(1, Ordering::Relaxed) + 1;
            if n == total || n % 10 == 0 {
                if let Some(mid) = mid {
                    let _ = app
                        .tg
                        .edit(
                            chat,
                            mid,
                            &format!("🧪 <b>Чекер API</b> · проверено <b>{n}</b> / {total}"),
                            None,
                        )
                        .await;
                }
            }

            if !auth_valid(&out) {
                return None;
            }
            let mut models: Vec<String> = out
                .probes
                .iter()
                .filter(|p| model_works(p))
                .map(|p| p.model.clone())
                .collect();
            models.sort();
            models.dedup();
            let subscription = subscription_for(&direct.http_client(), &pair.base, &pair.key).await;
            Some((
                idx,
                CheckRow {
                    key: pair.key,
                    base: out.base.clone(),
                    account_type: account_type_for(&subscription),
                    subscription,
                    balance: if out.balance.trim().is_empty() {
                        "?".to_string()
                    } else {
                        out.balance
                    },
                    rpm: if out.rpm.trim().is_empty() {
                        "?".to_string()
                    } else {
                        out.rpm
                    },
                    models,
                },
            ))
        }
    }))
    .buffer_unordered(workers);
    let results: Vec<Option<(usize, CheckRow)>> = futures.collect().await;
    let mut rows: Vec<(usize, CheckRow)> = results.into_iter().flatten().collect();
    rows.sort_by_key(|(idx, _)| *idx);

    let dir = Path::new("exports");
    std::fs::create_dir_all(dir)?;
    let path = dir.join(format!("api_check_{stamp}.txt"));
    std::fs::write(&path, render(&rows, total))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }

    if let Some(mid) = mid {
        let _ = app
            .tg
            .edit(
                chat,
                mid,
                &format!(
                    "🧪 <b>Чекер API</b> · готово\n\n✅ valid: <b>{}</b> / {total}",
                    rows.len()
                ),
                None,
            )
            .await;
    }

    let caption = format!(
        "🧪 <b>API checker</b> · ✅ valid <b>{}</b> / {total}\n📄 {}",
        rows.len(),
        esc(&source)
    );
    app.tg.send_document(chat, &path, &caption).await?;
    Ok(())
}

fn render(rows: &[(usize, CheckRow)], total: usize) -> String {
    let rule = "────────────────────────────────────────────────";
    let mut out = String::new();
    out.push_str("════════════════════════════════════════════════\n");
    out.push_str("            ✅ API ЧЕКЕР · ВАЛИДНЫЕ КЛЮЧИ\n");
    out.push_str("════════════════════════════════════════════════\n");
    let msk = chrono::Utc::now()
        .with_timezone(&chrono::FixedOffset::east_opt(3 * 3600).expect("MSK offset"));
    out.push_str(&format!(
        "Валидных ключей: {} из {}\nДата проверки: {}\n\n",
        rows.len(),
        total,
        msk.format("%d.%m.%Y %H:%M МСК")
    ));

    if rows.is_empty() {
        out.push_str("❌ Валидных ключей нет.\n");
        return out;
    }

    for (idx, (_, row)) in rows.iter().enumerate() {
        out.push_str(rule);
        out.push('\n');
        out.push_str(&format!("{}. 🔑 КЛЮЧ\n", idx + 1));
        out.push_str(&row.key);
        out.push_str("\n\n");

        out.push_str("🌐 BASE URL\n");
        out.push_str(&row.base);
        out.push_str("\n\n");

        out.push_str("💰 БАЛАНС\n");
        out.push_str(if row.balance.trim().is_empty() {
            "?"
        } else {
            &row.balance
        });
        out.push_str("\n\n");

        out.push_str("⚡ RPM\n");
        out.push_str(if row.rpm.trim().is_empty() {
            "?"
        } else {
            &row.rpm
        });
        out.push_str("\n\n");

        out.push_str("Подписка: ");
        out.push_str(if row.subscription.trim().is_empty() {
            "?"
        } else {
            &row.subscription
        });
        out.push_str("\n\n");

        out.push_str("Тип: ");
        out.push_str(if row.account_type.trim().is_empty() {
            "?"
        } else {
            &row.account_type
        });
        out.push_str("\n\n");

        out.push_str(&format!("🤖 РАБОТАЮЩИЕ МОДЕЛИ ({})\n", row.models.len()));
        if row.models.is_empty() {
            out.push_str("—\n");
        } else {
            for model in &row.models {
                out.push_str("• ");
                out.push_str(model);
                out.push('\n');
            }
        }
        out.push('\n');
    }
    out.push_str(rule);
    out.push('\n');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pairs_are_parsed_with_blank_lines() {
        let text = "Api key\nBase url\n\nsk-one\nhttps://a.example/v1\n\nsk-two\nhttps://b.example/api/v1/\n";
        let pairs = parse_pairs(text);
        assert_eq!(pairs.len(), 2);
        assert_eq!(pairs[0].key, "sk-one");
        assert_eq!(pairs[0].base, "https://a.example/v1");
        assert_eq!(pairs[1].base, "https://b.example/api/v1");
    }

    #[test]
    fn reverse_order_and_duplicates_are_handled() {
        let text = "https://a.example/v1\nsk-one\nsk-one\nhttps://a.example/v1\n";
        let pairs = parse_pairs(text);
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].key, "sk-one");
    }

    #[test]
    fn pat_file_has_no_pairs() {
        assert!(parse_pairs("ghp_abc\nghp_def\n").is_empty());
    }

    #[test]
    fn uppercase_base_url_is_recognized() {
        let pairs = parse_pairs("sk-test\nHTTPS://API.EXAMPLE/V1\n");
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].key, "sk-test");
        assert_eq!(pairs[0].base, "HTTPS://API.EXAMPLE/V1");
    }

    #[test]
    fn account_types_are_normalized() {
        assert_eq!(account_type_for("free"), "Free");
        assert_eq!(account_type_for("scale_2024_08_10"), "Paid");
        assert_eq!(account_type_for("paid"), "Paid");
        assert_eq!(account_type_for("?"), "?");
    }

    #[test]
    fn subscription_values_are_parsed() {
        assert_eq!(
            find_subscription(&serde_json::json!({"subscription": {"tier": "free"}})),
            Some("free".into())
        );
        assert_eq!(
            find_subscription(&serde_json::json!({"is_free_tier": false})),
            Some("paid".into())
        );
        assert_eq!(find_subscription(&serde_json::json!({"ok": true})), None);
    }

    #[test]
    fn empty_input_has_no_pairs() {
        assert!(parse_pairs("").is_empty());
    }

    fn outcome(status: PStatus, code: u16, note: &str) -> ProbeOutcome {
        ProbeOutcome {
            endpoint: "https://relay.example/v1".into(),
            base: "https://relay.example/v1".into(),
            status,
            models: vec!["gpt-test".into()],
            probes: vec![crate::store::ProbeLine {
                model: "gpt-test".into(),
                code,
                latency_ms: 1,
                note: note.into(),
                rpm: String::new(),
            }],
            tested: 1,
            chat_ok: false,
            latency_ms: 2,
            http_status: 200,
            balance: "?".into(),
            rpm: "?".into(),
        }
    }

    #[test]
    fn ocr_only_model_is_not_a_valid_chat_key() {
        let p = crate::store::ProbeLine {
            model: "qwen3.5-ocr".into(),
            code: 200,
            latency_ms: 1,
            note: String::new(),
            rpm: String::new(),
        };
        assert!(!model_works(&p));
    }

    #[test]
    fn public_catalog_and_network_failure_are_not_valid() {
        assert!(!auth_valid(&outcome(
            PStatus::Unreachable,
            0,
            "сеть/таймаут"
        )));
        assert!(!auth_valid(&outcome(
            PStatus::Partial,
            200,
            "нет challenge · hi"
        )));
        assert!(!auth_valid(&outcome(PStatus::Fake, 200, "фейк: эхо")));
    }

    #[test]
    fn exhausted_openrouter_is_not_a_valid_checker_result() {
        let mut out = outcome(PStatus::Invalid, 200, "");
        out.chat_ok = true;
        out.balance = "$-0.04".into();
        assert!(!auth_valid(&out));
    }

    #[test]
    fn challenge_confirmation_is_valid() {
        let mut out = outcome(PStatus::Valid, 200, "");
        out.chat_ok = true;
        assert!(auth_valid(&out));
    }
}
