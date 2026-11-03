use crate::app::App;
use crate::store::Store;
use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

/// Build the full operator backup (source, deploy files, exports, `.env`, and a
/// compact SQLite snapshot of every key/state table) and send it to the admin
/// private chat. The archive never goes to a group/report chat by itself.
pub async fn send_full_backup(app: Arc<App>, chat: i64) -> Result<PathBuf> {
    let stamp = chrono::Local::now().format("%Y%m%d_%H%M%S").to_string();
    let root = PathBuf::from("data/backups");
    std::fs::create_dir_all(&root).with_context(|| "create data/backups")?;
    let stage = root.join(format!("keyhunter-backup-{stamp}"));
    let zip = root.join(format!("keyhunter-backup-{stamp}.zip"));
    let db = app.cfg.db_path.clone();
    let store = app.store.clone();
    let stage_build = stage.clone();
    let zip_build = zip.clone();

    tokio::task::spawn_blocking(move || build_archive(&store, &db, &stage_build, &zip_build))
        .await
        .context("backup worker panicked")??;

    let size = std::fs::metadata(&zip)?.len();
    let caption = format!(
        "📦 <b>Полный бэкап сканера</b>\n\n\
         Код, PAT/ключи, findings, queries, jobs, settings, экспорт и .env.\n\
         Размер: <b>{:.1} МБ</b>\n\n\
         ⚠️ Архив содержит секреты — только для админа.",
        size as f64 / 1_048_576.0
    );
    app.tg.send_document(chat, &zip, &caption).await?;

    let _ = std::fs::remove_dir_all(&stage);
    // Keep the last archive on disk for recovery, but cap the directory.
    prune_backups(&root, 3);
    Ok(zip)
}

/// Build an archive without sending it (CLI/diagnostic path).
pub fn create_archive(db_path: &str, stage: &Path, zip: &Path) -> Result<()> {
    let store = Arc::new(Store::open(db_path)?);
    build_archive(&store, db_path, stage, zip)
}

fn build_archive(store: &Arc<Store>, db: &str, stage: &Path, zip: &Path) -> Result<()> {
    let _ = std::fs::remove_dir_all(stage);
    let _ = std::fs::remove_file(zip);
    let root = stage.join("keyhunter-rs");
    std::fs::create_dir_all(root.join("data"))?;

    for file in [
        "Cargo.toml",
        "Cargo.lock",
        "README.md",
        ".env",
        ".env.example",
        ".gitignore",
    ] {
        let src = Path::new(file);
        if src.is_file() {
            std::fs::copy(src, root.join(file)).with_context(|| format!("copy {file}"))?;
        }
    }
    for dir in ["src", "deploy", "exports"] {
        if Path::new(dir).is_dir() {
            copy_tree(Path::new(dir), &root.join(dir))?;
        }
    }
    if Path::new("data/autoloop.md").is_file() {
        std::fs::copy("data/autoloop.md", root.join("data/autoloop.md"))?;
    }
    if Path::new("data/proxies.json").is_file() {
        std::fs::copy("data/proxies.json", root.join("data/proxies.json"))?;
    }
    if let Ok(entries) = std::fs::read_dir("data") {
        for entry in entries.flatten() {
            let path = entry.path();
            let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
            if path.is_file() && name.starts_with("valid_all_") && name.ends_with(".txt") {
                let _ = std::fs::copy(&path, root.join("data").join(name));
            }
        }
    }

    // Compact DB: all keys/PATs/findings/settings; omit the huge URL cache.
    let snapshot = root.join("data/scanner.db");
    store.snapshot_compact(db, snapshot.to_string_lossy().as_ref())?;

    let manifest = format!(
        "KEYHUNTER-RS BACKUP\n\
         generated: {}\n\
         source: {}\n\n\
         Included:\n\
         - source code (src/, Cargo.toml, Cargo.lock, README)\n\
         - deploy/ and exports/\n\
         - .env (secrets; admin-only archive)\n\
         - data/scanner.db snapshot: pats, findings, queries, jobs, settings,\n\
           repos, hosts, deep_scans, source_tasks, source_frontier\n\n\
         The huge `scanned` URL cache is intentionally excluded: it is\n\
         reproducible crawl state, not key data. Full findings and PATs are\n\
         preserved.\n",
        chrono::Local::now().to_rfc3339(),
        db
    );
    std::fs::write(root.join("BACKUP.txt"), manifest)?;

    let zip_abs = if zip.is_absolute() {
        zip.to_path_buf()
    } else {
        std::env::current_dir()?.join(zip)
    };
    if let Some(parent) = zip_abs.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let status = Command::new("zip")
        .current_dir(stage)
        .arg("-r")
        .arg("-q")
        .arg(&zip_abs)
        .arg(".")
        .status()
        .context("run zip")?;
    if !status.success() {
        bail!("zip failed with status {status}");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(zip, std::fs::Permissions::from_mode(0o600));
    }
    let _ = std::fs::remove_dir_all(stage);
    Ok(())
}

fn copy_tree(src: &Path, dst: &Path) -> Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        let name = entry.file_name();
        if ty.is_dir() {
            copy_tree(&entry.path(), &dst.join(&name))?;
        } else if ty.is_file() {
            std::fs::copy(entry.path(), dst.join(&name))?;
        }
    }
    Ok(())
}

fn prune_backups(root: &Path, keep: usize) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    let mut files: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("zip"))
        .collect();
    files.sort();
    if files.len() > keep {
        for p in &files[..files.len() - keep] {
            let _ = std::fs::remove_file(p);
        }
    }
}
