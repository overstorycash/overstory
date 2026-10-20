//! Bounded index undo journal. It never changes, signs, or broadcasts order transactions.
//! Recovering an index installs a persistent spending barrier until order reconciliation.
use crate::{index::{Changes, Db, State}, Rpc};
use anyhow::{Context, Result, ensure};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeMap;

pub const UNDO_DEPTH: u32 = 100;
#[derive(Debug)]
pub struct ForkDetected(pub &'static str);
impl std::fmt::Display for ForkDetected {
    fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result {write!(f,"{}",self.0)}
}
impl std::error::Error for ForkDetected {}

const TABLES: [(&str,&str);4] = [("inscriptions","id"),("pending","outpoint"),("collections","id"),("mints","inscription")];
#[derive(Clone, Serialize, Deserialize)]
struct Undo {
    version:u32, height:u32, hash:String, previous_height:u32, previous_hash:Option<String>, previous_network:Option<String>,
    #[serde(default)]
    previous_replay_from:Option<u32>,
    rows:Vec<BTreeMap<String,Option<String>>>, carriers:BTreeMap<String,Vec<String>>, rejected_rowid:i64,
}
fn meta(db:&Connection,key:&str)->Result<Option<String>> {
    Ok(db.query_row("SELECT v FROM meta WHERE k=?1",[key],|r|r.get(0)).optional()?)
}
fn indexed(db:&Connection)->Result<(u32,Option<String>)> {
    Ok((meta(db,"height")?.map(|x|x.parse()).transpose()?.unwrap_or(0),meta(db,"tip_hash")?))
}
fn schema(db:&Connection)->Result<()> {
    db.execute_batch("CREATE TABLE IF NOT EXISTS index_undo(height INTEGER PRIMARY KEY, hash TEXT NOT NULL, json TEXT NOT NULL)")?;
    Ok(())
}
fn capture(db:&Connection, before:&State, after:&State,ch:&Changes)->Result<Undo> {
    ensure!(indexed(db)?==(before.height,before.tip_hash.clone()),"index changed before journal write");
    ensure!(meta(db,"network")?==before.network,"index network changed before journal write");
    ensure!(after.height>before.height,"undo journal requires a forward block");
    let hash=after.tip_hash.clone().context("block lacks hash")?;
    let pending=ch.pending_put.union(&ch.pending_del).cloned().collect();
    let keys=[&ch.inscriptions,&pending,&ch.collections,&ch.mints];
    let mut rows=vec![];
    for ((table,column),keys) in TABLES.iter().zip(keys) {
        let mut prior=BTreeMap::new();
        for key in keys {
            let old=db.query_row(&format!("SELECT json FROM {table} WHERE {column}=?1"),[key],|r|r.get(0)).optional()?;
            prior.insert(key.clone(),old);
        }
        rows.push(prior);
    }
    let mut carriers=BTreeMap::new();
    for key in ch.carriers_put.union(&ch.carriers_del) {
        let mut q=db.prepare("SELECT inscription FROM carriers WHERE outpoint=?1 ORDER BY inscription")?;
        let old=q.query_map([key],|r|r.get(0))?.collect::<rusqlite::Result<Vec<String>>>()?;
        carriers.insert(key.clone(),old);
    }
    let rejected_rowid=db.query_row("SELECT COALESCE(MAX(rowid),0) FROM rejected",[],|r|r.get(0))?;
    Ok(Undo {version:1,height:after.height,hash,previous_height:before.height,previous_hash:before.tip_hash.clone(),previous_network:before.network.clone(),previous_replay_from:before.replay_from,rows,carriers,rejected_rowid})
}
/// Journal and new block state share one FULL-sync SQLite transaction.
pub fn apply_block(db:&mut Db,before:&State,after:&State,ch:&Changes)->Result<()> {
    let tx=db.conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    schema(&tx)?;
    let undo=capture(&tx,before,after,ch)?;
    tx.execute("INSERT INTO index_undo(height,hash,json) VALUES(?1,?2,?3)",params![undo.height,undo.hash,serde_json::to_string(&undo)?])?;
    Db::apply_tx(&tx,after,ch)?;
    tx.execute("DELETE FROM index_undo WHERE height<=?1",[after.height.saturating_sub(UNDO_DEPTH)])?;
    tx.commit()?;
    Ok(())
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct Recovery {
    pub from_height:u32, pub from_hash:String, pub ancestor_height:u32, pub ancestor_hash:String,
    pub observed_tip:u32, pub observed_tip_hash:String, pub blocks_rolled_back:u32,
}
pub fn pending(db:&Db)->Result<Option<Recovery>> {
    meta(&db.conn,"reorg_pending")?.map(|s|serde_json::from_str(&s).map_err(Into::into)).transpose()
}
fn hash_at(rpc:&Rpc,height:u32)->Result<String> {
    Ok(rpc.call("getblockhash",json!([height]))?.as_str().context("missing block hash")?.to_owned())
}
fn undo_at(db:&Db,height:u32,hash:&str)->Result<Undo> {
    let exists:bool=db.conn.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='index_undo')",[],|r|r.get(0))?;
    ensure!(exists,"no undo history: preserve this index and rebuild separately");
    let (saved_hash,raw):(String,String)=db.conn.query_row("SELECT hash,json FROM index_undo WHERE height=?1",[height],|r|Ok((r.get(0)?,r.get(1)?))).optional()?.context("reorg exceeds retained undo history; separate rebuild required")?;
    let u:Undo=serde_json::from_str(&raw).context("corrupt undo record")?;
    ensure!(u.version==1 && u.height==height && saved_hash==hash && u.hash==hash && u.previous_height<height && u.rows.len()==TABLES.len(),"invalid undo identity");
    ensure!(u.previous_height==0 || u.previous_hash.is_some(),"undo lacks parent identity");
    Ok(u)
}
fn restore(tx:&rusqlite::Transaction<'_>,u:&Undo)->Result<()> {
    ensure!(indexed(tx)?==(u.height,Some(u.hash.clone())),"index changed during rollback");
    for ((table,column),rows) in TABLES.iter().zip(&u.rows) {
        for (key,old) in rows {
            tx.execute(&format!("DELETE FROM {table} WHERE {column}=?1"),[key])?;
            if let Some(old)=old {
                tx.execute(&format!("INSERT INTO {table}({column},json) VALUES(?1,?2)"),params![key,old])?;
            }
        }
    }
    for (key,ids) in &u.carriers {
        tx.execute("DELETE FROM carriers WHERE outpoint=?1",[key])?;
        for id in ids {tx.execute("INSERT INTO carriers(outpoint,inscription) VALUES(?1,?2)",params![key,id])?;}
    }
    tx.execute("DELETE FROM rejected WHERE rowid>?1",[u.rejected_rowid])?;
    for (key,value) in [("height",Some(u.previous_height.to_string())),("tip_hash",u.previous_hash.clone()),("network",u.previous_network.clone()),("replay_from",u.previous_replay_from.map(|h|h.to_string())),("replay_tip_height",u.previous_replay_from.map(|_|u.previous_height.to_string())),("replay_tip_hash",u.previous_replay_from.and(u.previous_hash.clone()))] {
        tx.execute("DELETE FROM meta WHERE k=?1",[key])?;
        if let Some(value)=value {tx.execute("INSERT INTO meta(k,v) VALUES(?1,?2)",params![key,value])?;}
    }
    tx.execute("DELETE FROM index_undo WHERE height=?1",[u.height])?;
    Ok(())
}
/// Called while the service worker is quarantined; never a standalone spending authorization.
/// A moving/unavailable node, missing journal, or deep fork leaves every database row untouched.
pub fn rollback_to_ancestor(rpc:&Rpc,db:&mut Db,st:&mut State)->Result<Option<Recovery>> {
    Db::check_schema(&db.conn)?;
    ensure!(st.network.as_deref()==Some(rpc.net().name()),"recovery network mismatch");
    ensure!(pending(db)?.is_none(),"previous reorg still requires order reconciliation");
    ensure!(indexed(&db.conn)?==(st.height,st.tip_hash.clone()),"memory and database index differ");
    let from_hash=st.tip_hash.clone().context("index has no recovery anchor")?;
    let tip=rpc.checked_target()? - 1;
    let tip_hash=hash_at(rpc,tip)?;
    let mut h=st.height;let mut hash=from_hash.clone();let mut undos=vec![];
    loop {
        if h<=tip && hash_at(rpc,h)?==hash {break;}
        ensure!(undos.len()<(UNDO_DEPTH as usize),"reorg exceeds maximum rollback depth");
        let u=undo_at(db,h,&hash)?;
        h=u.previous_height;hash=u.previous_hash.clone().unwrap_or_else(||rpc.chain.genesis_hash.clone());
        undos.push(u);
    }
    ensure!(rpc.checked_target()? - 1==tip && hash_at(rpc,tip)?==tip_hash,"chain changed during recovery planning");
    if undos.is_empty(){return Ok(None);}
    let recovery=Recovery {from_height:st.height,from_hash,ancestor_height:h,ancestor_hash:hash,observed_tip:tip,observed_tip_hash:tip_hash,blocks_rolled_back:undos.len() as u32};
    let tx=db.conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    for u in &undos {restore(&tx,u)?;}
    tx.execute("INSERT OR REPLACE INTO meta(k,v) VALUES('reorg_pending',?1)",[serde_json::to_string(&recovery)?])?;
    let restored=Db::load_from(&tx)?;
    tx.commit()?;
    *st=restored;
    Ok(Some(recovery))
}

/// Atomically publish all reconciled order states and release the spending barrier.
/// The caller must finish chain verification first; compare-and-swap rejects local races.
pub fn commit_reconciliation(db:&mut Db,recovery:&Recovery,height:u32,hash:&str,expected:&BTreeMap<String,serde_json::Value>,updates:&BTreeMap<String,serde_json::Value>,audit:&serde_json::Value)->Result<()> {
    ensure!(expected.keys().eq(updates.keys()),"reconciliation order keys differ");
    let tx=db.conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let barrier:Recovery=serde_json::from_str(&meta(&tx,"reorg_pending")?.context("recovery barrier disappeared")?)?;
    ensure!(barrier==*recovery && indexed(&tx)?==(height,Some(hash.into())),"recovery snapshot changed");
    let current:BTreeMap<String,serde_json::Value>={
        let mut q=tx.prepare("SELECT k,json FROM kv WHERE ns='orders'")?;
        let rows=q.query_map([],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?)))?.collect::<rusqlite::Result<Vec<_>>>()?;
        rows.into_iter().map(|(k,v)|Ok((k,serde_json::from_str(&v)?))).collect::<Result<_>>()?
    };
    ensure!(current==*expected,"orders changed during reorg reconciliation");
    for (id,order) in updates {tx.execute("UPDATE kv SET json=?1 WHERE ns='orders' AND k=?2",params![serde_json::to_string(order)?,id])?;}
    let key=format!("{}:{}",recovery.from_height,recovery.from_hash);
    tx.execute("INSERT OR REPLACE INTO kv(ns,k,json) VALUES('reorg_history',?1,?2)",params![key,serde_json::to_string(&json!({"recovery":recovery,"checked_at_height":height,"checked_at_hash":hash,"audit":audit}))?])?;
    tx.execute("DELETE FROM meta WHERE k='reorg_pending'",[])?;
    tx.commit()?;
    Ok(())
}


#[cfg(test)]
mod provenance_tests {
    use super::*;
    #[test]
    fn rollback_restores_scope_and_never_invents_legacy_provenance() {
        for first in [None, Some(1), Some(50)] {
            let mut db=Db::open(":memory:").unwrap();
            let before=State{height:50,tip_hash:Some("aa".repeat(32)),network:Some("regtest".into()),replay_from:first,..Default::default()};
            db.apply(&before,&Changes::default()).unwrap();
            db.kv_put("orders","keep",&json!({"id":"keep"})).unwrap();
            let after=State{height:51,tip_hash:Some("bb".repeat(32)),..before.clone()};
            apply_block(&mut db,&before,&after,&Changes::default()).unwrap();
            let undo=undo_at(&db,51,after.tip_hash.as_ref().unwrap()).unwrap();
            let tx=db.conn.transaction().unwrap();restore(&tx,&undo).unwrap();tx.commit().unwrap();
            let restored=db.load().unwrap();assert_eq!(restored.replay_from,first);assert_eq!(restored.height,50);
            assert_eq!(db.kv_all::<serde_json::Value>("orders").unwrap().len(),1);
        }
    }
    #[test]
    fn first_block_rollback_removes_scope_and_old_undo_is_unknown() {
        let mut db=Db::open(":memory:").unwrap();let before=State::default();
        let after=State{height:1,tip_hash:Some("aa".repeat(32)),network:Some("regtest".into()),replay_from:Some(1),..Default::default()};
        apply_block(&mut db,&before,&after,&Changes::default()).unwrap();
        let undo=undo_at(&db,1,after.tip_hash.as_ref().unwrap()).unwrap();
        let mut old=serde_json::to_value(&undo).unwrap();old.as_object_mut().unwrap().remove("previous_replay_from");
        assert!(serde_json::from_value::<Undo>(old).unwrap().previous_replay_from.is_none());
        let tx=db.conn.transaction().unwrap();restore(&tx,&undo).unwrap();tx.commit().unwrap();
        let restored=db.load().unwrap();assert_eq!(restored.height,0);assert_eq!(restored.replay_from,None);
    }
}

/// Dedicated read-only index runtimes only. Never reconcile a funded service here.
pub fn recover_key_free(rpc: &Rpc, db: &mut Db, st: &mut State, root: &std::path::Path) -> Result<Option<Recovery>> {
    for name in ["keys", "mintd.json", "mintd"] {
        match std::fs::symlink_metadata(root.join(name)) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {},
            _ => anyhow::bail!("key-free recovery refuses wallet/service runtime: {name}"),
        }
    }
    let foreign: u64 = db.conn.query_row("SELECT COUNT(*) FROM kv WHERE ns != 'reorg_history'", [], |r| r.get(0))?;
    ensure!(foreign == 0, "key-free recovery refuses service or wallet records");
    if st.tip_hash.is_none() { return Ok(None); }
    let recovery = match pending(db)? {
        Some(r) => Some(r),
        None => rollback_to_ancestor(rpc, db, st)?,
    };
    if let Some(r) = &recovery {
        // Resume a crash after rollback only at a currently canonical checkpoint.
        ensure!(st.height <= rpc.checked_target()? - 1, "node behind recovery checkpoint");
        let hash = st.tip_hash.as_deref().context("missing recovery checkpoint")?;
        ensure!(hash_at(rpc, st.height)? == hash, "recovery checkpoint is not canonical");
        commit_reconciliation(db, r, st.height, hash, &BTreeMap::new(), &BTreeMap::new(),
            &json!({"mode":"key-free-index", "orders":0, "broadcasts":0}))?;
    }
    Ok(recovery)
}
