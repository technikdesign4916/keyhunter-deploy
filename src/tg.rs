use crate::github::truncate;
use anyhow::{anyhow, bail, Result};
use reqwest::multipart::{Form, Part};
use reqwest::Client;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::Path;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct User {
    pub id: i64,
    #[serde(default)]
    pub is_bot: bool,
    #[serde(default)]
    pub first_name: String,
    #[serde(default)]
    pub username: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Chat {
    pub id: i64,
    #[serde(default, rename = "type")]
    pub chat_type: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Document {
    pub file_id: String,
    #[serde(default)]
    pub file_name: Option<String>,
    #[serde(default)]
    pub mime_type: Option<String>,
    #[serde(default)]
    pub file_size: Option<i64>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Message {
    pub message_id: i64,
    #[serde(default)]
    pub from: Option<User>,
    pub chat: Chat,
    #[serde(default)]
    pub text: Option<String>,
    #[serde(default)]
    pub document: Option<Document>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct CallbackQuery {
    pub id: String,
    pub from: User,
    #[serde(default)]
    pub message: Option<Message>,
    #[serde(default)]
    pub data: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Update {
    pub update_id: i64,
    #[serde(default)]
    pub message: Option<Message>,
    #[serde(default)]
    pub callback_query: Option<CallbackQuery>,
}

#[derive(Debug, Deserialize)]
struct ApiResp<T> {
    ok: bool,
    result: Option<T>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    parameters: Option<Value>,
}

pub struct Tg {
    http: Client,
    api: String,
    token: String,
    /// Serializes outbound messages. Telegram allows roughly one message per
    /// second per chat; flooding it makes the whole admin bot unresponsive
    /// for hours (429 retry_after), so never send in parallel.
    send_lock: tokio::sync::Mutex<()>,
    /// Absolute unix time until which Telegram has told us not to send.
    rate_until: AtomicI64,
}

impl Tg {
    pub fn new(token: &str, proxy: Option<&str>) -> Result<Self> {
        let mut b = Client::builder()
            .user_agent("keyhunter-rs/1.0")
            .timeout(Duration::from_secs(90))
            .connect_timeout(Duration::from_secs(10));
        if let Some(p) = proxy {
            if !p.trim().is_empty() {
                b = b.proxy(reqwest::Proxy::all(p)?);
            }
        }
        Ok(Self {
            http: b.build()?,
            api: format!("https://api.telegram.org/bot{}", token),
            token: token.to_string(),
            send_lock: tokio::sync::Mutex::new(()),
            rate_until: AtomicI64::new(0),
        })
    }

    fn epoch_secs() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    }

    fn wait_left(&self) -> i64 {
        (self.rate_until.load(Ordering::Relaxed) - Self::epoch_secs()).max(0)
    }

    fn ensure_send_allowed(&self, method: &str) -> Result<()> {
        let wait = self.wait_left();
        if wait > 0 {
            bail!("telegram {method}: rate limited for {wait}s");
        }
        Ok(())
    }

    async fn call<T: DeserializeOwned>(&self, method: &str, payload: Value) -> Result<T> {
        let url = format!("{}/{}", self.api, method);
        let mut last = String::new();
        for attempt in 0..5 {
            let resp = self.http.post(&url).json(&payload).send().await;
            let resp = match resp {
                Ok(r) => r,
                Err(e) => {
                    let timeout = e.is_timeout();
                    let clean = e.without_url();
                    last = clean.to_string();
                    if timeout {
                        // A read timeout may mean Telegram accepted the
                        // message and the response was lost. Retrying would
                        // duplicate it.
                        bail!("telegram {} timeout: {}", method, clean);
                    }
                    tokio::time::sleep(Duration::from_secs(2 + attempt)).await;
                    continue;
                }
            };
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            let parsed: ApiResp<T> = match serde_json::from_str(&text) {
                Ok(v) => v,
                Err(_) => {
                    last = format!("bad response: {}", truncate(&text, 200));
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    continue;
                }
            };
            if parsed.ok {
                if let Some(r) = parsed.result {
                    return Ok(r);
                }
                bail!("telegram {}: empty result", method);
            }
            let desc = parsed.description.unwrap_or_default();
            last = desc.clone();
            if status == 429 || desc.to_lowercase().contains("too many requests") {
                let wait = parsed
                    .parameters
                    .as_ref()
                    .and_then(|p| p["retry_after"].as_i64())
                    .unwrap_or(2);
                // A long 429 is a chat-wide cooldown. Sleeping here for
                // retry_after (often thousands of seconds) blocks the
                // update loop; fail fast so polling and commands continue.
                if wait > 10 {
                    self.rate_until
                        .store(Self::epoch_secs() + wait, Ordering::Relaxed);
                    bail!("telegram {method}: rate limited for {wait}s");
                }
                tokio::time::sleep(Duration::from_secs(wait.clamp(1, 10) as u64)).await;
                continue;
            }
            bail!("telegram {}: {}", method, desc);
        }
        bail!("telegram {} failed: {}", method, last)
    }

    pub async fn get_me(&self) -> Result<User> {
        self.call("getMe", json!({})).await
    }

    pub async fn get_updates(&self, offset: i64, timeout: u32) -> Result<Vec<Update>> {
        self.call(
            "getUpdates",
            json!({
                "offset": offset,
                "timeout": timeout,
                "allowed_updates": ["message", "callback_query"]
            }),
        )
        .await
    }

    pub async fn send(&self, chat_id: i64, text: &str, kb: Option<Value>) -> Result<i64> {
        let _send_guard = self.send_lock.lock().await;
        self.ensure_send_allowed("sendMessage")?;
        // Keep a small gap between messages to stay below Telegram's
        // per-chat flood limit.
        tokio::time::sleep(Duration::from_millis(1100)).await;
        let mut payload = json!({
            "chat_id": chat_id,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": true
        });
        if let Some(kb) = kb {
            payload["reply_markup"] = kb;
        }
        let msg: Message = self.call("sendMessage", payload).await?;
        Ok(msg.message_id)
    }

    pub async fn send_document(&self, chat_id: i64, path: &Path, caption: &str) -> Result<()> {
        let _send_guard = self.send_lock.lock().await;
        self.ensure_send_allowed("sendDocument")?;
        tokio::time::sleep(Duration::from_millis(1100)).await;
        // Telegram caps captions at 1024 characters. Keep a little headroom
        // for the trailing ellipsis and any UTF-16 expansion.
        let caption: String = caption.chars().take(1000).collect();
        let bytes = tokio::fs::read(path).await?;
        let filename = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("valid_keys.txt")
            .to_string();
        let url = format!("{}/sendDocument", self.api);
        let mut last = String::new();
        for attempt in 0..3 {
            let part = Part::bytes(bytes.clone())
                .file_name(filename.clone())
                .mime_str("text/plain")?;
            let form = Form::new()
                .text("chat_id", chat_id.to_string())
                .text("caption", caption.clone())
                .text("parse_mode", "HTML")
                .part("document", part);
            let resp = self.http.post(&url).multipart(form).send().await;
            let resp = match resp {
                Ok(r) => r,
                Err(e) => {
                    let timeout = e.is_timeout();
                    let clean = e.without_url();
                    last = clean.to_string();
                    if timeout {
                        bail!("telegram sendDocument timeout: {}", clean);
                    }
                    tokio::time::sleep(Duration::from_secs(2 + attempt)).await;
                    continue;
                }
            };
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            let parsed: ApiResp<Value> = match serde_json::from_str(&text) {
                Ok(v) => v,
                Err(_) => {
                    last = format!("bad response: {}", truncate(&text, 200));
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    continue;
                }
            };
            if parsed.ok {
                return Ok(());
            }
            let desc = parsed.description.unwrap_or_default();
            last = desc.clone();
            if status == 429 || desc.to_lowercase().contains("too many requests") {
                let wait = parsed
                    .parameters
                    .as_ref()
                    .and_then(|p| p["retry_after"].as_i64())
                    .unwrap_or(3);
                tokio::time::sleep(Duration::from_secs(wait.clamp(1, 60) as u64)).await;
                continue;
            }
            bail!("telegram sendDocument: {}", desc);
        }
        bail!("telegram sendDocument failed: {}", last)
    }

    pub async fn edit(
        &self,
        chat_id: i64,
        message_id: i64,
        text: &str,
        kb: Option<Value>,
    ) -> Result<()> {
        self.ensure_send_allowed("editMessageText")?;
        let mut payload = json!({
            "chat_id": chat_id,
            "message_id": message_id,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": true
        });
        if let Some(kb) = kb {
            payload["reply_markup"] = kb;
        }
        match self.call::<Value>("editMessageText", payload).await {
            Ok(_) => Ok(()),
            Err(e) => {
                if e.to_string().contains("message is not modified") {
                    Ok(())
                } else {
                    Err(e)
                }
            }
        }
    }

    pub async fn answer_cb(&self, id: &str, text: &str) -> Result<()> {
        let text = truncate(text, 200);
        let _: Value = self
            .call(
                "answerCallbackQuery",
                json!({"callback_query_id": id, "text": text}),
            )
            .await?;
        Ok(())
    }

    pub async fn download_text(&self, file_id: &str, max_bytes: usize) -> Result<String> {
        #[derive(Deserialize)]
        struct FileResp {
            file_path: String,
        }
        let f: FileResp = self.call("getFile", json!({"file_id": file_id})).await?;
        let url = format!(
            "https://api.telegram.org/file/bot{}/{}",
            self.token, f.file_path
        );
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| anyhow!("download transport: {}", e.without_url()))?;
        if !resp.status().is_success() {
            bail!("не смог скачать файл: HTTP {}", resp.status().as_u16());
        }
        if resp.content_length().unwrap_or(0) as usize > max_bytes {
            bail!("файл больше {} КБ", max_bytes / 1024);
        }
        let text = resp.text().await?;
        if text.len() > max_bytes {
            bail!("файл больше {} КБ", max_bytes / 1024);
        }
        Ok(text)
    }
}
