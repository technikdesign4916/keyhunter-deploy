use anyhow::{bail, Result};
use std::env;
use std::path::Path;

#[derive(Clone, Debug)]
pub struct Config {
    pub tg_token: String,
    pub admin_id: i64,
    pub db_path: String,
    pub tg_proxy: Option<String>,
    pub proxy: Option<String>,
    pub notify_start: bool,
    pub rank_enabled: bool,
    pub rank_base_url: String,
    pub rank_model: String,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let tg_token = env::var("TG_TOKEN")
            .map_err(|_| anyhow::anyhow!("TG_TOKEN is not set (put it in .env)"))?
            .trim()
            .to_string();
        if !tg_token.contains(':') {
            bail!("TG_TOKEN does not look like a Telegram bot token");
        }
        let admin_id: i64 = env::var("ADMIN_ID")
            .unwrap_or_default()
            .trim()
            .parse()
            .map_err(|_| anyhow::anyhow!("ADMIN_ID must be a numeric Telegram user id"))?;
        if admin_id <= 0 {
            bail!("ADMIN_ID must be positive");
        }
        let db_path = env::var("DB_PATH").unwrap_or_else(|_| "data/scanner.db".to_string());
        if let Some(parent) = Path::new(&db_path).parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let clean = |v: Option<String>| v.filter(|s| !s.trim().is_empty());
        let rank_api_key = clean(env::var("RANK_API_KEY").ok());
        let rank_enabled = env::var("RANK_ENABLED")
            .map(|v| v != "0")
            .unwrap_or(rank_api_key.is_some());
        Ok(Self {
            tg_token,
            admin_id,
            db_path,
            tg_proxy: clean(env::var("TG_PROXY").ok()),
            proxy: clean(env::var("PROXY").ok()),
            notify_start: env::var("NOTIFY_START").map(|v| v != "0").unwrap_or(true),
            rank_enabled,
            rank_base_url: env::var("RANK_BASE_URL")
                .unwrap_or_else(|_| "https://dashscope.aliyuncs.com/compatible-mode/v1".into()),
            rank_model: env::var("RANK_MODEL")
                .unwrap_or_else(|_| "deepseek-v4.1-flash-1017".into()),
        })
    }
}
