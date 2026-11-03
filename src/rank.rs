//! AI-assisted credential ranking.
//!
//! The scanner's probe remains authoritative for `VALID`/`LIMIT`. After that
//! deterministic pass, this module asks a configured OpenAI-compatible model
//! to review the evidence and assign a rank from S (best) to F (worst). The
//! model receives a masked key fingerprint, never the secret itself.

use crate::config::Config;
use crate::extract::host_of;
use crate::probe::{is_non_chat_model, PStatus, ProbeOutcome};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::Duration;
use tracing::warn;

#[derive(Clone, Debug, Default)]
pub struct RankResult {
    pub rank: String,
    pub score: i64,
    pub verdict: String,
    pub note: String,
    pub model: String,
}

#[derive(Debug, Serialize)]
struct ModelEvidence {
    model: String,
    weight: i64,
}

#[derive(Debug, Serialize)]
struct ProbeEvidence {
    model: String,
    code: u16,
    note: String,
}

#[derive(Debug, Serialize)]
struct Evidence<'a> {
    endpoint: &'a str,
    provider: &'a str,
    key_fingerprint: String,
    script_status: &'a str,
    balance: &'a str,
    rpm: &'a str,
    catalog_count: usize,
    tested: usize,
    chat_ok: bool,
    working_models: Vec<ModelEvidence>,
    probes: Vec<ProbeEvidence>,
    heuristic: Heuristic,
}

#[derive(Debug, Serialize)]
struct Heuristic {
    working_models: usize,
    model_quality: i64,
    balance_score: i64,
    score: i64,
    rank: String,
}

#[derive(Debug, Deserialize, Default)]
struct AiRank {
    #[serde(default)]
    verdict: String,
    #[serde(default)]
    rank: String,
    #[serde(default)]
    score: f64,
    #[serde(default)]
    working_models: Value,
    #[serde(default)]
    reasons: Value,
    #[serde(default)]
    confidence: f64,
}

fn working_count(v: &Value) -> i64 {
    if let Some(n) = v.as_i64() {
        return n.max(0);
    }
    if let Some(a) = v.as_array() {
        return a.len() as i64;
    }
    0
}

fn reason_list(v: &Value) -> Vec<String> {
    if let Some(a) = v.as_array() {
        return a
            .iter()
            .filter_map(|x| x.as_str().map(str::to_string))
            .collect();
    }
    v.as_str().map(|s| vec![s.to_string()]).unwrap_or_default()
}

pub fn enabled(cfg: &Config) -> bool {
    cfg.rank_enabled && api_key().is_some()
}

fn api_key() -> Option<String> {
    std::env::var("RANK_API_KEY")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

fn mask_key(key: &str) -> String {
    let chars: Vec<char> = key.chars().collect();
    if chars.len() <= 10 {
        return "••••".into();
    }
    let head: String = chars.iter().take(6).collect();
    let tail: String = chars.iter().skip(chars.len().saturating_sub(4)).collect();
    format!("{head}…{tail}")
}

fn model_weight(model: &str) -> i64 {
    let m = model.to_ascii_lowercase();
    let flagship = [
        "gpt-6",
        "gpt-5",
        "claude-opus",
        "claude-sonnet-5",
        "qwen3-max",
        "qwen-max",
        "deepseek-v4",
        "deepseek-v3.1",
        "deepseek-reasoner",
        "grok-4",
        "gemini-3",
        "gemini-2.5-pro",
    ];
    if flagship.iter().any(|x| m.contains(x)) {
        5
    } else if [
        "gpt-4o",
        "claude-3.5",
        "claude-3-7",
        "qwen-plus",
        "qwen3-coder",
        "qwen2.5-72b",
        "deepseek-chat",
        "deepseek-v3",
        "grok-3",
        "gemini-2.5-flash",
    ]
    .iter()
    .any(|x| m.contains(x))
    {
        3
    } else {
        1
    }
}

fn balance_score(balance: &str) -> i64 {
    let cleaned: String = balance
        .chars()
        .filter(|c| c.is_ascii_digit() || *c == '.' || *c == '-')
        .collect();
    match cleaned.parse::<f64>() {
        Ok(n) if n >= 100.0 => 30,
        Ok(n) if n >= 20.0 => 26,
        Ok(n) if n >= 5.0 => 20,
        Ok(n) if n > 0.0 => 14,
        Ok(_) => 0,
        Err(_) if balance.trim() == "?" || balance.trim().is_empty() => 6,
        Err(_) => 0,
    }
}

fn working_models(out: &ProbeOutcome) -> Vec<&str> {
    out.probes
        .iter()
        .filter(|p| p.code == 200 && p.note.is_empty() && !is_non_chat_model(&p.model))
        .map(|p| p.model.as_str())
        .collect()
}

fn heuristic(out: &ProbeOutcome) -> Heuristic {
    let working = working_models(out);
    let model_quality: i64 = working.iter().map(|m| model_weight(m)).sum();
    let bscore = balance_score(&out.balance);
    let mut score = (working.len() as i64 * 6 + model_quality * 2 + bscore).clamp(0, 100);
    if out.status == PStatus::Limited {
        score = score.min(42);
    }
    if working.is_empty() {
        score = score.min(24);
    }
    if !out.chat_ok {
        score = score.min(30);
    }
    let rank = match score {
        85..=100 => "S",
        72..=84 => "A",
        60..=71 => "B",
        45..=59 => "C",
        30..=44 => "D",
        15..=29 => "E",
        _ => "F",
    };
    Heuristic {
        working_models: working.len(),
        model_quality,
        balance_score: bscore,
        score,
        rank: rank.to_string(),
    }
}

fn normalize_rank(raw: &str) -> Option<String> {
    let c = raw.trim().chars().next()?.to_ascii_uppercase();
    matches!(c, 'S' | 'A' | 'B' | 'C' | 'D' | 'E' | 'F').then(|| c.to_string())
}

fn fallback(out: &ProbeOutcome, why: &str) -> RankResult {
    let h = heuristic(out);
    RankResult {
        rank: h.rank,
        score: h.score,
        verdict: if out.status == PStatus::Valid {
            "valid".into()
        } else {
            "uncertain".into()
        },
        note: format!("{why}; heuristic"),
        model: "heuristic".into(),
    }
}

fn parse_ai(text: &str) -> Option<AiRank> {
    let start = text.find('{')?;
    let end = text.rfind('}')?;
    if end <= start {
        return None;
    }
    serde_json::from_str(&text[start..=end]).ok()
}

pub async fn evaluate(
    cfg: &Config,
    endpoint: &str,
    key: &str,
    out: &ProbeOutcome,
) -> Option<RankResult> {
    if !enabled(cfg) {
        return None;
    }
    let key_fp = mask_key(key);
    let working = working_models(out);
    let h = heuristic(out);
    let evidence = Evidence {
        endpoint,
        provider: &host_of(endpoint),
        key_fingerprint: key_fp,
        script_status: out.status.as_str(),
        balance: &out.balance,
        rpm: &out.rpm,
        catalog_count: out.models.len(),
        tested: out.tested,
        chat_ok: out.chat_ok,
        working_models: working
            .iter()
            .take(32)
            .map(|m| ModelEvidence {
                model: (*m).to_string(),
                weight: model_weight(m),
            })
            .collect(),
        probes: out
            .probes
            .iter()
            .take(24)
            .map(|p| ProbeEvidence {
                model: p.model.clone(),
                code: p.code,
                note: p.note.clone(),
            })
            .collect(),
        heuristic: Heuristic {
            working_models: h.working_models,
            model_quality: h.model_quality,
            balance_score: h.balance_score,
            score: h.score,
            rank: h.rank.clone(),
        },
    };
    let evidence_json = serde_json::to_string(&evidence).ok()?;
    let system = "You are a strict API credential ranker. The scanner has already probed the key; \
script_status is authoritative and you cannot call the endpoint. Use only the supplied evidence. \
Judge: (1) validity evidence, (2) remaining balance, (3) number of working chat models, \
(4) how capable those models are (flagship vs small/utility), (5) reliability and rate limits. \
Return ONLY one JSON object with keys: verdict (valid|invalid|uncertain), rank (S|A|B|C|D|E|F), \
score (0..100), working_models (integer), reasons (array of short strings), confidence (0..1). \
S = excellent balance and several flagship working models; A = strong; B = good; C = usable; \
D = weak; E = barely usable/limit; F = invalid, dead, zero working models or no balance. \
Never invent models or claim you made network requests. Be conservative when evidence is thin.";
    let user = format!(
        "Rank this credential. Evidence JSON:\n{evidence_json}\n\n\
Rules: balance '?' is unknown, not proof of credit. LIMIT can never be S. \
A key with zero working chat models cannot be above E. Return JSON only."
    );

    let base = cfg.rank_base_url.trim_end_matches('/');
    let url = format!("{base}/chat/completions");
    let body = serde_json::json!({
        "model": cfg.rank_model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user}
        ],
        "temperature": 0,
        "max_tokens": 2000
    });
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            warn!("rank client build failed: {e}");
            return Some(fallback(out, "rank client unavailable"));
        }
    };
    let resp = match client
        .post(&url)
        .bearer_auth(api_key()?)
        .json(&body)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            warn!("rank request failed for {}: {e}", host_of(endpoint));
            return Some(fallback(out, "AI request failed"));
        }
    };
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        warn!(
            "rank API {} for {}: {}",
            status.as_u16(),
            host_of(endpoint),
            text.chars().take(180).collect::<String>()
        );
        return Some(fallback(out, "AI API error"));
    }
    let v: serde_json::Value = match serde_json::from_str(&text) {
        Ok(v) => v,
        Err(e) => {
            warn!("rank JSON parse failed: {e}");
            return Some(fallback(out, "AI response not JSON"));
        }
    };
    let message = &v["choices"][0]["message"];
    let content = message["content"].as_str().unwrap_or_default();
    let reasoning = message["reasoning_content"].as_str().unwrap_or_default();
    // Some OpenAI-compatible reasoning models put the answer only in
    // `reasoning_content`, or spend the whole content budget on reasoning.
    // Parse both channels; the JSON object is still the contract.
    let combined = format!("{content}\n{reasoning}");
    let Some(ai) = parse_ai(&combined) else {
        warn!(
            "rank model returned no JSON for {} (content={} reasoning={})",
            host_of(endpoint),
            content.len(),
            reasoning.len()
        );
        return Some(fallback(out, "AI returned no JSON"));
    };
    let Some(rank) = normalize_rank(&ai.rank) else {
        return Some(fallback(out, "AI returned invalid rank"));
    };
    let verdict = match ai.verdict.trim().to_ascii_lowercase().as_str() {
        "valid" => "valid",
        "invalid" => "invalid",
        "uncertain" | "" => "uncertain",
        _ => "uncertain",
    };
    let score = ai.score.clamp(0.0, 100.0) as i64;
    let mut reasons = reason_list(&ai.reasons);
    if reasons.is_empty() {
        reasons.push(format!(
            "{} working models; confidence {:.2}",
            working_count(&ai.working_models).max(working.len() as i64),
            ai.confidence
        ));
    }
    let note = reasons.join("; ");
    Some(RankResult {
        rank,
        score,
        verdict: verdict.into(),
        note: note.chars().take(500).collect(),
        model: cfg.rank_model.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rank_shape_and_weights() {
        assert_eq!(normalize_rank(" s ").as_deref(), Some("S"));
        assert_eq!(normalize_rank("X"), None);
        assert!(model_weight("qwen3-max") > model_weight("qwen-turbo"));
        assert!(balance_score("$25.00") > balance_score("?"));
    }

    #[test]
    fn parses_json_inside_fence() {
        let v = parse_ai("```json\n{\"rank\":\"A\",\"score\":77}\n```").unwrap();
        assert_eq!(v.rank, "A");
        assert_eq!(v.score, 77.0);
    }

    #[test]
    fn accepts_model_array_from_live_model() {
        let v = parse_ai(
            r#"{"verdict":"valid","rank":"A","score":77,"working_models":["qwen3-max","qwen-plus"],"reasons":["strong"]}"#,
        )
        .unwrap();
        assert_eq!(working_count(&v.working_models), 2);
        assert_eq!(reason_list(&v.reasons), vec!["strong"]);
    }
}
