//! Read-only raw-block payment discovery. Reports discrepancies; never imports,
//! signs, resumes an order, or authorizes a refund. No address-index completeness assumption.
use crate::*;
use rusqlite::{Connection, OpenFlags};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Deserialize)]
struct Invoice {
    id: String,
    invoice_address: String,
    #[serde(default)]
    payment_start_height: Option<u32>,
    #[serde(default)]
    receipts: BTreeMap<String,Utxo>,
    #[serde(default)]
    mint_plan: Option<inscribe::SignedInscription>,
    #[serde(default)]
    refunds: Vec<SavedRefund>,
}
#[derive(Deserialize)]
struct SavedRefund {plan: refund::RefundPlan}
fn point(u: &Utxo)->String {format!("{}:{}",u.txid,u.n)}
fn classify(found:&Utxo, saved:Option<&Utxo>, allocated:bool)->&'static str {
    match saved {
        Some(old) if old.value != found.value || old.script != found.script || point(old) != point(found) => "receipt_mismatch",
        Some(old) if old.height != found.height => "receipt_height_changed",
        Some(_) if allocated => "recorded_allocated",
        Some(_) => "recorded_unallocated",
        None if allocated => "allocation_without_receipt",
        None => "unrecorded_receipt",
    }
}
pub fn audit(rpc:&Rpc,path:&str,id:&str,start:u32,end:u32)->Result<Value> {
    anyhow::ensure!(start<=end && end-start<2000,"choose an inclusive range of 1..2000 blocks");
    let mut db=Connection::open_with_flags(path,OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let snapshot=db.transaction()?;
    let schema:String=snapshot.query_row("SELECT v FROM meta WHERE k='schema_version'",[],|r|r.get(0))?;
    anyhow::ensure!(schema == crate::index::SCHEMA_VERSION,"unsupported index schema");
    let network:String=snapshot.query_row("SELECT v FROM meta WHERE k='network'",[],|r|r.get(0))?;
    anyhow::ensure!(network==rpc.net().name(),"invoice index network mismatch");
    let raw:String=snapshot.query_row("SELECT json FROM kv WHERE ns='orders' AND k=?1",[id],|r|r.get(0))?;
    let order:Invoice=serde_json::from_str(&raw)?;
    anyhow::ensure!(order.id==id,"invoice identity mismatch");
    let mut locked=BTreeSet::new();
    for table in ["carriers","pending"] {
        let mut stmt=snapshot.prepare(&format!("SELECT outpoint FROM {table}"))?;
        for row in stmt.query_map([],|r|r.get::<_,String>(0))? {locked.insert(row?);}
    }
    snapshot.commit()?;
    let script=index::script_bytes(&parse_taddr_for(&order.invoice_address,rpc.net().network_type())?.script().into());
    let mut allocated=BTreeSet::new();
    let mut issues=Vec::<String>::new();
    let funding=order.mint_plan.iter().flat_map(|p|p.funding.iter())
        .chain(order.refunds.iter().flat_map(|r|r.plan.funding.iter()));
    for u in funding {
        let key=point(u);
        if !allocated.insert(key.clone()) {issues.push(format!("duplicate_allocation:{key}"));}
        if !order.receipts.get(&key).is_some_and(|old|old.value==u.value && old.script==u.script) {
            issues.push(format!("allocation_receipt_mismatch:{key}"));
        }
    }
    let tip=rpc.checked_target()? - 1;
    anyhow::ensure!(end<=tip,"history range beyond node tip");
    let hash_at=|h:u32|->Result<String> {Ok(rpc.call("getblockhash",json!([h]))?.as_str().context("missing block hash")?.to_owned())};
    let anchor=hash_at(end)?;
    let mut previous=if start==0 {None} else {Some(hash_at(start-1)?)};
    let mut found=BTreeMap::<String,Utxo>::new();
    let mut spent=BTreeMap::<String,String>::new();
    for height in start..=end {
        let expected=hash_at(height)?;
        let raw=rpc.call("getblock",json!([expected,0]))?;
        let block=index::parse_block(&hex::decode(raw.as_str().context("missing raw block")?)?,rpc.net().branch_for(height))?;
        anyhow::ensure!(block.hash==expected,"raw block identity differs");
        if let Some(parent)=&previous {anyhow::ensure!(block.previous_hash==*parent,"disconnected payment history");}
        previous=Some(block.hash);
        for (txid,tx) in block.txs {
            if let Some(bundle)=tx.transparent_bundle() {
                for input in &bundle.vin {
                    let mut bytes=*input.prevout().hash();bytes.reverse();
                    let key=format!("{}:{}",hex::encode(bytes),input.prevout().n());
                    // Retain only relevant spends; a deposit must precede its spend in chain order.
                    if found.contains_key(&key) {anyhow::ensure!(spent.insert(key,txid.clone()).is_none(),"duplicate payment spend");}
                }
                for (n,out) in bundle.vout.iter().enumerate() {
                    if index::script_bytes(out.script_pubkey())==script {
                        let u=Utxo {txid:txid.clone(),n:u32::try_from(n)?,script:hex::encode(&script),value:out.value().into_u64(),height};
                        anyhow::ensure!(found.insert(point(&u),u).is_none(),"duplicate receipt outpoint");
                        anyhow::ensure!(found.len()<=10000,"too many receipts; narrow history range");
                    }
                }
            }
        }
    }
    let mut outputs=Vec::new();let mut total=0u64;let mut unrecorded=0u64;
    for (key,u) in &found {
        total=total.checked_add(u.value).context("payment sum overflow")?;
        let state=classify(u,order.receipts.get(key),allocated.contains(key));
        if state=="unrecorded_receipt" {unrecorded=unrecorded.checked_add(u.value).context("unrecorded sum overflow")?;}
        if matches!(state,"receipt_mismatch"|"receipt_height_changed"|"allocation_without_receipt") {issues.push(format!("{state}:{key}"));}
        outputs.push(json!({"outpoint":key,"value_zat":u.value,"height":u.height,"journal_state":state,
            "spent_in_range":spent.get(key),"carrier_or_pending_in_saved_index":locked.contains(key),
            "refund_eligible":false}));
    }
    for (key,u) in &order.receipts {
        if *key!=point(u) {issues.push(format!("receipt_key_mismatch:{key}"));}
        if (start..=end).contains(&u.height) && !found.contains_key(key) {issues.push(format!("saved_receipt_absent_from_range:{key}"));}
    }
    anyhow::ensure!(hash_at(end)?==anchor,"payment history anchor changed; discard report");
    // A running worker may change reservations while scanning. Never combine two order versions.
    let current:String=db.query_row("SELECT json FROM kv WHERE ns='orders' AND k=?1",[id],|r|r.get(0))?;
    anyhow::ensure!(current==raw,"order changed during history audit; retry");
    Ok(json!({"read_only":true,"authorizes_refund":false,"authorizes_resume":false,
        "scope":"canonical raw-block deposits in the specified range; not refund eligibility or live spendability",
        "order_id":id,"network":network,"start_height":start,"end_height":end,"anchor_hash":anchor,
        "covers_creation_through_end":start==0 || order.payment_start_height.is_some_and(|h|start<=h),
        "observed_received_zat":total,"unrecorded_received_zat":unrecorded,"outputs":outputs,"issues":issues}))
}
#[cfg(test)]mod tests {
    use super::*;
    #[test]fn history_discovery_never_equates_unrecorded_with_allocated() {
        let found=Utxo {txid:"11".repeat(32),n:0,script:"76".into(),value:30000,height:12};
        assert_eq!(classify(&found,None,false),"unrecorded_receipt");
        assert_eq!(classify(&found,None,true),"allocation_without_receipt");
        assert_eq!(classify(&found,Some(&found),false),"recorded_unallocated");
        assert_eq!(classify(&found,Some(&found),true),"recorded_allocated");
        let mut old=found.clone();old.height=11;assert_eq!(classify(&found,Some(&old),false),"receipt_height_changed");
        old.value+=1;assert_eq!(classify(&found,Some(&old),false),"receipt_mismatch");
    }
}
