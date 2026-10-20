//! Durable quarantine before exceptional service settlement. No payout authorization.
use crate::*;
use rusqlite::{OptionalExtension, TransactionBehavior};
use sha2::{Digest,Sha256};
use std::collections::BTreeSet;

const NS: &str = "service-settlements";
fn digest(v:&Value)->Result<String>{Ok(hex::encode(Sha256::digest(serde_json::to_vec(v)?)))}
fn protected(o:&Value)->Value {
    let mut v=o.clone();
    if let Some(map)=v.as_object_mut() {
        for k in ["status","error","retry_after","attempts","number","seed","settlement_hold"] {map.remove(k);}
        if let Some(refunds)=map.get_mut("refunds").and_then(Value::as_array_mut) {
            for r in refunds {if let Some(m)=r.as_object_mut(){m.remove("confirmation");}}
        }
    }
    v
}
fn summary(record:&Value)->Value {
    json!({"order_id":record["order_id"],"state":"held_for_settlement","authorizes_payment":false,
        "broadcast":false,"refund_address":record["refund_address"],"evidence_is_historical":true,
        "at_height":record["audit"]["at_height"],"at_hash":record["audit"]["at_hash"],
        "scope":"local order/coin-selection quarantine only; does not revoke existing signatures or external wallets"})
}
fn reserve(db:&rusqlite::Transaction<'_>,id:&str,raw:&str,report:&Value)->Result<Value> {
    let current:String=db.query_row("SELECT json FROM kv WHERE ns='orders' AND k=?1",[id],|r|r.get(0))?;
    anyhow::ensure!(current==raw,"order changed during settlement review");
    let mut order:Value=serde_json::from_str(raw)?;
    anyhow::ensure!(order["id"]==id && order["settlement_hold"]!=true,"invalid order or orphan settlement marker");
    let barrier:bool=db.query_row("SELECT EXISTS(SELECT 1 FROM meta WHERE k='reorg_pending')",[],|r|r.get(0))?;
    anyhow::ensure!(!barrier,"reorg reconciliation pending");
    for (key,expected) in [("height",report["at_height"].to_string()),("tip_hash",report["at_hash"].as_str().context("audit hash")?.to_owned())] {
        let v:String=db.query_row("SELECT v FROM meta WHERE k=?1",[key],|r|r.get(0))?;
        anyhow::ensure!(v==expected,"audit index changed before reservation");
    }
    let p:inscribe::SignedInscription=serde_json::from_value(order["mint_plan"].clone())?;
    let overlaps:bool=db.query_row("SELECT EXISTS(SELECT 1 FROM kv WHERE k=?1 AND ns IN ('cli-inscription-plans','expired-reclaims','self-mint-refunds'))",[&p.result.inscription_id],|r|r.get(0))?;
    anyhow::ensure!(!overlaps,"inscription already belongs to another recovery workflow");
    let mut points:BTreeSet<String>=order["receipts"].as_object().context("missing receipts")?.keys().cloned().collect();
    // Standard audited plan: continuation at commit:0, upfront service payment at :1.
    // The optional commit:2 is already returned excess and must not be reserved.
    anyhow::ensure!(p.transactions.len()==2 && p.commit_vout==0,"unsupported service plan");
    points.insert(format!("{}:0",p.transactions[0].txid));
    points.insert(format!("{}:1",p.transactions[0].txid));
    let locked=refund_claim::reserved_inputs(db)?;
    anyhow::ensure!(points.is_disjoint(&locked),"settlement funds already reserved");
    let record=json!({"version":1,"order_id":id,"state":"held","protected_sha256":digest(&protected(&order))?,
        "original_order":order,"refund_address":order["refund_address"],"reserved_outpoints":points,"audit":report});
    order["settlement_hold"]=json!(true);order["status"]=json!("recovery_required");
    order["error"]=json!("order held for exceptional settlement; no automatic mint or refund");
    order["retry_after"]=json!(0);order["attempts"]=json!(0);
    for point in &points {db.execute("INSERT INTO kv(ns,k,json) VALUES('service-settlement-inputs',?1,?2)",(point,serde_json::to_string(&json!({"order_id":id}))?))?;}
    db.execute("INSERT INTO kv(ns,k,json) VALUES(?1,?2,?3)",(NS,id,serde_json::to_string(&record)?))?;
    db.execute("UPDATE kv SET json=?1 WHERE ns='orders' AND k=?2",(serde_json::to_string(&order)?,id))?;
    db.execute("INSERT INTO kv(ns,k,json) VALUES('operator-actions',?1,?2)",(format!("settlement-hold:{id}"),serde_json::to_string(&summary(&record))?))?;
    Ok(record)
}
/// A frozen invoice also blocks newly arriving funds, which have no saved outpoint yet.
pub fn ensure_spend_address(db:&rusqlite::Connection,address:&str)->Result<()> {
    manual_cases::ensure_address(db,address)?;
    let mut q=db.prepare("SELECT json FROM kv WHERE ns='service-settlements'")?;
    for row in q.query_map([],|r|r.get::<_,String>(0))? {
        let v:Value=serde_json::from_str(&row?)?;
        anyhow::ensure!(v["version"]==1,"unsupported settlement record");
        let invoice=v["original_order"]["invoice_address"].as_str().context("settlement invoice missing")?;
        anyhow::ensure!(invoice!=address,"invoice quarantined for settlement, including late payments");
    }
    Ok(())
}
pub(crate) struct Held {
    pub record_raw:String, pub record:Value, pub order_raw:String, pub order:Value,
}
pub(crate) fn checked_hold(db:&rusqlite::Connection,id:&str)->Result<Held> {
    manual_cases::ensure_standard_allowed(db,id)?;
    let order_raw:String=db.query_row("SELECT json FROM kv WHERE ns='orders' AND k=?1",[id],|r|r.get(0))?;
    let record_raw:String=db.query_row("SELECT json FROM kv WHERE ns=?1 AND k=?2",(NS,id),|r|r.get(0))?;
    let record:Value=serde_json::from_str(&record_raw)?;let order:Value=serde_json::from_str(&order_raw)?;
    anyhow::ensure!(record["version"]==1 && record["state"]=="held" && record["order_id"]==id && order["id"]==id && order["settlement_hold"]==true && record["protected_sha256"]==digest(&protected(&order))?,"settlement snapshot differs; manual reconciliation required");
    for p in record["reserved_outpoints"].as_array().context("missing reservations")? {
        let owner:String=db.query_row("SELECT json FROM kv WHERE ns='service-settlement-inputs' AND k=?1",[p.as_str().context("invalid reservation")?],|r|r.get(0))?;
        anyhow::ensure!(serde_json::from_str::<Value>(&owner)?["order_id"]==id,"settlement reservation owner changed");
    }
    Ok(Held{record_raw,record,order_raw,order})
}
/// Caller is mintd's local command, holding the runtime worker lock for the whole call.
/// Also acquire the CLI wallet lock so no same-runtime coin selection crosses reservation.
pub fn hold(rpc:&Rpc,path:&str,id:&str)->Result<Value> {
    let parent=std::path::Path::new(path).parent().context("database directory missing")?;
    let _wallet=refund_claim::wallet_lock(&parent.join("wallet.lock"))?;
    let mut db=index::Db::open(path)?;
    manual_cases::ensure_standard_allowed(&db.conn,id)?;
    let raw:String=db.conn.query_row("SELECT json FROM kv WHERE ns='orders' AND k=?1",[id],|r|r.get(0))?;
    let old:Option<String>=db.conn.query_row("SELECT json FROM kv WHERE ns=?1 AND k=?2",(NS,id),|r|r.get(0)).optional()?;
    if old.is_some() {return Ok(summary(&checked_hold(&db.conn,id)?.record));}
    let report=settlement_audit::audit(rpc,path,id)?;
    let tx=db.conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let record=reserve(&tx,id,&raw,&report)?;tx.commit()?;Ok(summary(&record))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn invoice_quarantine_covers_late_funds_without_blocking_other_wallets(){
        let db=rusqlite::Connection::open_in_memory().unwrap();db.execute_batch("CREATE TABLE kv(ns TEXT,k TEXT,json TEXT);").unwrap();
        db.execute("INSERT INTO kv VALUES('service-settlements','a',?1)",[json!({"version":1,"original_order":{"invoice_address":"invoice"}}).to_string()]).unwrap();
        assert!(ensure_spend_address(&db,"invoice").is_err());assert!(ensure_spend_address(&db,"treasury").is_ok());
        db.execute("UPDATE kv SET json='{}'",[]).unwrap();assert!(ensure_spend_address(&db,"treasury").is_err());
    }
    #[test] fn protected_terms_ignore_only_reconciliation_metadata(){
        let o=json!({"status":"inscribing","refund_address":"a","mint_plan":{"raw":"original"},"refunds":[{"plan":{"raw":"refund"},"confirmation":null}]});
        let mut changed=o.clone();changed["status"]=json!("recovery_required");changed["settlement_hold"]=json!(true);changed["refunds"][0]["confirmation"]=json!({"height":2});
        assert_eq!(protected(&o),protected(&changed));
        changed["refund_address"]=json!("b");assert_ne!(protected(&o),protected(&changed));
        changed=o.clone();changed["refunds"][0]["plan"]["raw"]=json!("new");assert_ne!(protected(&o),protected(&changed));
    }
}
