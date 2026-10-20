//! Durable new-invoice pause switch. Existing workers and retries remain independent.
use anyhow::{Context, Result};
use proto::index::Db;
use serde::{Deserialize, Serialize};
use std::{fs::{File, OpenOptions}, path::Path, time::{SystemTime, UNIX_EPOCH}};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Control {
    pub version: u32,
    pub paused: bool,
    pub revision: u64,
    pub reason: String,
    pub changed_at: u64,
}
impl Default for Control {
    fn default() -> Self {
        Self { version: 1, paused: false, revision: 0, reason: "Initial admission policy".into(), changed_at: 0 }
    }
}

pub fn lock(path: &Path) -> Result<File> {
    if let Some(parent) = path.parent() { std::fs::create_dir_all(parent)?; }
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        anyhow::ensure!(meta.is_file(), "invalid invoice control lock");
    }
    let file = OpenOptions::new().read(true).write(true).create(true).truncate(false).open(path)?;
    file.try_lock().context("invoice admission is busy; retry this operation")?;
    Ok(file)
}

pub fn read(db: &Db) -> Result<Control> {
    let records = db.kv_all::<Control>("invoice-control")?;
    anyhow::ensure!(records.len() <= 1 && records.keys().all(|k| k == "state"), "invalid invoice control records");
    if records.is_empty() {
        let has_audit: bool = db.conn.query_row("SELECT EXISTS(SELECT 1 FROM kv WHERE ns='invoice-control-audit')", [], |row| row.get(0))?;
        anyhow::ensure!(!has_audit, "invoice control state missing despite existing audit");
    }
    let state = records.get("state").cloned().unwrap_or_default();
    anyhow::ensure!(state.version == 1, "unsupported invoice control version");
    Ok(state)
}

pub fn set(db: &Db, paused: bool, reason: &str) -> Result<Control> {
    let reason = reason.trim();
    anyhow::ensure!(!reason.is_empty() && reason.len() <= 256 && !reason.chars().any(char::is_control), "provide a short nonempty operator reason");
    let old = read(db)?;
    let next = Control { version: 1, paused, revision: old.revision.checked_add(1).context("control revision overflow")?, reason: reason.into(), changed_at: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() };
    let raw = serde_json::to_string(&next)?;
    let transaction = db.conn.unchecked_transaction()?;
    transaction.execute("INSERT INTO kv(ns,k,json) VALUES('invoice-control-audit',?1,?2)", [&next.revision.to_string(), &raw])?;
    transaction.execute("INSERT OR REPLACE INTO kv(ns,k,json) VALUES('invoice-control','state',?1)", [&raw])?;
    transaction.commit()?;
    Ok(next)
}

pub fn command(args: &[String]) -> Result<()> {
    anyhow::ensure!((args.len() == 1 && args[0] == "invoices-status") || (args.len() == 2 && matches!(args[0].as_str(), "invoices-pause" | "invoices-resume")), "usage: invoices-status | invoices-pause <reason> | invoices-resume <reason>");
    let path = Path::new(proto::index::DB_FILE);
    anyhow::ensure!(std::fs::symlink_metadata(path)?.is_file(), "existing runtime database required");
    let _guard = lock(Path::new("mintd/admission.lock"))?;
    let db = Db::open(proto::index::DB_FILE)?;
    db.conn.busy_timeout(std::time::Duration::from_secs(5))?;
    let state = if args[0] == "invoices-status" { read(&db)? } else { set(&db, args[0] == "invoices-pause", &args[1])? };
    println!("{}", serde_json::to_string(&state)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn durable_pause_resume_and_audit_survive_reopen() {
        let dir=std::env::temp_dir().join(format!("overstory-control-{}",rand::random::<u64>()));std::fs::create_dir(&dir).unwrap();
        let path=dir.join("index.sqlite");
        {
            let db=Db::open(path.to_str().unwrap()).unwrap();
            assert!(!read(&db).unwrap().paused);
            assert!(set(&db,true, " ").is_err());
            assert!(set(&db,true, "bad\nreason").is_err());
            assert_eq!(set(&db,true,"incident investigation").unwrap().revision,1);
        }
        {
            let db=Db::open(path.to_str().unwrap()).unwrap();assert!(read(&db).unwrap().paused);
            assert_eq!(set(&db,false,"incident resolved").unwrap().revision,2);
            assert_eq!(db.kv_all::<Control>("invoice-control-audit").unwrap().len(),2);
            db.conn.execute("DELETE FROM kv WHERE ns='invoice-control'", []).unwrap();
            assert!(read(&db).is_err());
            db.kv_put("invoice-control","state",&serde_json::json!({"paused":false})).unwrap();
            assert!(read(&db).is_err());
        }
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn admission_lock_serializes_operator_and_new_order() {
        let dir=std::env::temp_dir().join(format!("overstory-control-lock-{}",rand::random::<u64>()));std::fs::create_dir(&dir).unwrap();
        let path=dir.join("lock");let guard=lock(&path).unwrap();assert!(lock(&path).is_err());drop(guard);drop(lock(&path).unwrap());std::fs::remove_dir_all(dir).unwrap();
    }
}
