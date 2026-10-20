//! Independent, normal-fee refunds for later deposits to a quarantined invoice.
//! Original mint, customer advance and project recovery records are never repriced.
use crate::*;
use rusqlite::{Connection,OptionalExtension,TransactionBehavior,params};
use std::collections::{BTreeMap,BTreeSet};
const NS:&str="service-settlement-late";
#[derive(Clone,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
struct Batch {plan:refund::RefundPlan,confirmation:Option<refund::RefundConfirmation>}
#[derive(Clone,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    version:u32,network:String,genesis_hash:String,order_id:String,payout_txid:String,
    invoice_address:String,destination:String,checkpoint_height:u32,checkpoint_hash:String,
    observed:BTreeMap<String,Utxo>,batches:Vec<Batch>,
}
fn point(u:&Utxo)->String{format!("{}:{}",u.txid,u.n)}
fn add(a:u64,b:u64)->Result<u64>{let n=a.checked_add(b).context("late ledger overflow")?;zat(n)?;Ok(n)}
fn action(id:&str,p:&refund::RefundPlan)->Value {
    json!({"action":"normal_late_payment_refund","order_id":id,"txid":p.txid,"destination":p.destination,
        "inputs":p.funding.iter().map(point).collect::<Vec<_>>(),"input_zat":p.input_zat,"refund_zat":p.refund_zat,
        "fee_zat":p.fee_zat,"external_payments_reconciled":true,"broadcast":false})
}
fn row(db:&Connection,id:&str)->Result<Option<String>> {
    Ok(db.query_row("SELECT json FROM kv WHERE ns=?1 AND k=?2",(NS,id),|r|r.get(0)).optional()?)
}
fn reserved(db:&Connection,held:&service_settlement::Held,id:&str,u:&Utxo)->Result<()> {
    let key=point(u);let list=held.record["reserved_outpoints"].as_array().context("hold reservations")?;
    anyhow::ensure!(list.iter().filter(|v|v.as_str()==Some(&key)).count()==1,"late receipt missing/duplicated in case reservations");
    let raw:String=db.query_row("SELECT json FROM kv WHERE ns='service-settlement-inputs' AND k=?1",[&key],|r|r.get(0))?;
    anyhow::ensure!(serde_json::from_str::<Value>(&raw)?==json!({"order_id":id,"kind":"late_payment"}),"late receipt belongs to another case or purpose");
    let conflict:bool=db.query_row("SELECT EXISTS(SELECT 1 FROM kv WHERE k=?1 AND ns IN ('self-mint-refund-inputs','reclaim-inputs'))",[&key],|r|r.get(0))?;
    anyhow::ensure!(!conflict,"late receipt overlaps another workflow");Ok(())
}
struct Review {
    held:service_settlement::Held,paid:service_payout::Paid,raw:Option<String>,case:Case,
    found:BTreeMap<String,Utxo>,used:BTreeSet<String>,confirmations:Vec<Option<refund::RefundConfirmation>>,
    summary:Value,
}
fn review(rpc:&Rpc,path:&str,db:&Connection,id:&str)->Result<Review> {
    let held=service_settlement::checked_hold(db,id)?;
    let paid=service_payout::verified_paid(rpc,path,db,id)?;
    let start=u32::try_from(held.order["payment_start_height"].as_u64().context("missing original history start")?)?;
    let end=u32::try_from(paid.audit["at_height"].as_u64().context("audit height")?)?;
    let checkpoint=u32::try_from(paid.history["end_height"].as_u64().context("payout checkpoint")?)?;
    let invoice=held.order["invoice_address"].as_str().context("invoice address")?;
    let script=hex::encode(index::script_bytes(&parse_taddr_for(invoice,rpc.net().network_type())?.script().into()));
    let h=payment_history::audit(rpc,path,id,start,end)?;
    anyhow::ensure!(h["covers_creation_through_end"]==true && h["anchor_hash"]==paid.audit["at_hash"]
        && h["issues"].as_array().is_some_and(Vec::is_empty),"late history incomplete or inconsistent");
    let mut found=BTreeMap::new();let mut spends=BTreeMap::new();let mut recorded=0;
    for v in h["outputs"].as_array().context("history outputs")? {
        let amount=v["value_zat"].as_u64().context("receipt amount")?;
        match v["journal_state"].as_str() {
            Some("recorded_allocated"|"recorded_unallocated")=>{recorded=add(recorded,amount)?;continue;},
            Some("unrecorded_receipt")=>{},_=>bail!("unknown receipt allocation"),
        }
        let height=u32::try_from(v["height"].as_u64().context("receipt height")?)?;
        anyhow::ensure!(height>checkpoint,"unrecorded payment predates paid scope; manual reconciliation required");
        anyhow::ensure!(v["carrier_or_pending_in_saved_index"]==false,"late invoice contains assets; manual review required");
        let key=v["outpoint"].as_str().context("receipt outpoint")?;
        let (txid,n)=key.split_once(':').context("invalid outpoint")?;
        let u=Utxo{txid:txid.into(),n:n.parse()?,script:script.clone(),value:amount,height};u.outpoint()?;
        anyhow::ensure!(found.insert(key.into(),u).is_none(),"duplicate late receipt");
        if !v["spent_in_range"].is_null(){spends.insert(key.to_owned(),v["spent_in_range"].as_str().context("invalid spend")?.to_owned());}
    }
    anyhow::ensure!(json!(recorded)==paid.audit["observed_received_zat"],"original receipt total changed");
    let raw=row(db,id)?;
    let c:Case=if let Some(raw)=&raw {serde_json::from_str(raw)?}else{Case{version:1,network:rpc.net().name().into(),genesis_hash:rpc.chain.genesis_hash.clone(),order_id:id.into(),payout_txid:paid.plan.txid.clone(),invoice_address:invoice.into(),destination:paid.plan.destination.clone(),checkpoint_height:checkpoint,checkpoint_hash:paid.history["anchor_hash"].as_str().context("checkpoint hash")?.into(),observed:BTreeMap::new(),batches:vec![]}};
    anyhow::ensure!(c.version==1 && c.network==rpc.net().name() && c.genesis_hash==rpc.chain.genesis_hash && c.order_id==id
        && c.payout_txid==paid.plan.txid && c.invoice_address==invoice && c.destination==paid.plan.destination && c.destination!=invoice
        && c.checkpoint_height==checkpoint && json!(c.checkpoint_hash)==paid.history["anchor_hash"] && c.batches.len()<=1000,"late case identity/checkpoint changed");
    for (key,u) in &c.observed {
        anyhow::ensure!(*key==point(u) && serde_json::to_value(found.get(key).context("late receipt is no longer canonical")?)?==serde_json::to_value(u)?,"late receipt changed");
        reserved(db,&held,id,u)?;
    }
    let mut used=BTreeSet::new();let mut owners=BTreeMap::new();let mut confirmations=Vec::new();
    let mut returned=0;let mut fees=0;let mut pending=0;
    for b in &c.batches {
        let p=&b.plan;p.validate(rpc)?;
        let bytes=hex::decode(&p.raw_transaction)?;let tx=Transaction::read(&bytes[..],rpc.net().branch_for(p.target_height))?;
        anyhow::ensure!(tx.sapling_bundle().is_none() && tx.orchard_bundle().is_none() && tx.sprout_bundle().is_none(),"late refund must be transparent-only");
        anyhow::ensure!(p.destination==c.destination,"late refund destination changed");
        for u in &p.funding {
            let key=point(u);
            anyhow::ensure!(used.insert(key.clone()) && serde_json::to_value(c.observed.get(&key).context("unrecorded late refund source")?)?==serde_json::to_value(u)?,"late source reused or altered");
            owners.insert(key,p.txid.clone());
        }
        let saved:String=db.query_row("SELECT json FROM kv WHERE ns='operator-actions' AND k=?1",[format!("settlement-late-refund:{id}:{}",p.txid)],|r|r.get(0))?;
        anyhow::ensure!(serde_json::from_str::<Value>(&saved)?==action(id,p),"late refund action changed");
        let proof=audit::transaction(rpc,&p.txid,&p.raw_transaction)?;
        match proof["state"].as_str() {
            Some("confirmed")=>{
                anyhow::ensure!(p.funding.iter().all(|u|spends.get(&point(u))==Some(&p.txid)),"confirmed late refund absent from history");
                returned=add(returned,p.refund_zat)?;fees=add(fees,p.fee_zat)?;
                confirmations.push(Some(refund::RefundConfirmation{height:u32::try_from(proof["height"].as_u64().context("confirmation height")?)?,block_hash:proof["block_hash"].as_str().context("confirmation hash")?.into()}));
            },
            Some("missing"|"unconfirmed")=>{
                anyhow::ensure!(b.confirmation.is_none() && p.funding.iter().all(|u|!spends.contains_key(&point(u))),"late confirmation disappeared or history contradicts lookup");
                pending=add(pending,p.input_zat)?;confirmations.push(None);
            },_=>bail!("late refund lookup unavailable or noncanonical; preserve signed plan"),
        }
    }
    anyhow::ensure!(confirmations.iter().filter(|c|c.is_none()).count()<=1
        && confirmations.iter().enumerate().all(|(i,c)|c.is_some() || i+1==confirmations.len()),"multiple or out-of-order pending late refunds");
    for (key,txid) in &spends {anyhow::ensure!(owners.get(key)==Some(txid),"late receipt spent outside recorded refund; reconcile external payments");}
    let total=found.values().try_fold(0,|n,u|add(n,u.value))?;
    let available=found.iter().filter(|(k,_)|!used.contains(*k)).try_fold(0,|n,(_,u)|add(n,u.value))?;
    anyhow::ensure!(total==add(add(returned,fees)?,add(pending,available)?)?,"late funds do not conserve");
    let now=service_settlement::checked_hold(db,id)?;
    let current_payment:String=db.query_row("SELECT json FROM kv WHERE ns='service-settlement-payouts' AND k=?1",[id],|r|r.get(0))?;
    anyhow::ensure!(now.record_raw==held.record_raw && now.order_raw==held.order_raw && current_payment==paid.raw && row(db,id)?==raw,"late case changed during review");
    service_payout::verify_recorded_source(db,&now,&current_payment)?;
    for u in c.observed.values(){reserved(db,&now,id,u)?;}
    for b in &c.batches {
        let saved:String=db.query_row("SELECT json FROM kv WHERE ns='operator-actions' AND k=?1",[format!("settlement-late-refund:{id}:{}",b.plan.txid)],|r|r.get(0))?;
        anyhow::ensure!(serde_json::from_str::<Value>(&saved)?==action(id,&b.plan),"late action changed during review");
    }
    service_payout::anchor(db,rpc,&paid.audit)?;
    let summary=json!({"read_only":true,"authorizes_payment":false,"order_id":id,"order_remains_held":true,"destination":c.destination,
        "as_of_height":end,"as_of_hash":h["anchor_hash"],"observed_late_received_zat":total,"confirmed_late_returned_zat":returned,
        "confirmed_late_network_fee_zat":fees,"signed_pending_input_zat":pending,"unallocated_late_zat":available,
        "scope":"later invoice payments only; original mint/advance/recovery separate; small balances and future payment rights remain open",
        "batches":c.batches.iter().zip(&confirmations).map(|(b,confirmation)|json!({"txid":b.plan.txid,"refund_zat":b.plan.refund_zat,"fee_zat":b.plan.fee_zat,"confirmation":confirmation})).collect::<Vec<_>>()});
    Ok(Review{held,paid,raw,case:c,found,used,confirmations,summary})
}
pub fn audit(rpc:&Rpc,path:&str,id:&str)->Result<Value> {
    let db=Connection::open_with_flags(path,rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    Ok(review(rpc,path,&db,id)?.summary)
}
fn unchanged(tx:&rusqlite::Transaction<'_>,rpc:&Rpc,id:&str,r:&Review)->Result<()> {
    let held=service_settlement::checked_hold(tx,id)?;
    let paid:String=tx.query_row("SELECT json FROM kv WHERE ns='service-settlement-payouts' AND k=?1",[id],|r|r.get(0))?;
    anyhow::ensure!(held.record_raw==r.held.record_raw && held.order_raw==r.held.order_raw && paid==r.paid.raw && row(tx,id)?==r.raw,"late case changed; retain original signatures");
    service_payout::verify_recorded_source(tx,&held,&paid)?;
    for u in r.case.observed.values(){reserved(tx,&held,id,u)?;}
    for b in &r.case.batches {
        let raw:String=tx.query_row("SELECT json FROM kv WHERE ns='operator-actions' AND k=?1",[format!("settlement-late-refund:{id}:{}",b.plan.txid)],|r|r.get(0))?;
        anyhow::ensure!(serde_json::from_str::<Value>(&raw)?==action(id,&b.plan),"late refund action changed during network call");
    }
    service_payout::anchor(tx,rpc,&r.paid.audit)
}
/// mintd owns its worker lock; this adds the shared wallet lock. Preparation never broadcasts.
pub fn command(rpc:&Rpc,path:&str,id:&str,key:Option<&str>)->Result<Value> {
    let _lock=refund_claim::wallet_lock(&std::path::Path::new(path).parent().context("runtime directory")?.join("wallet.lock"))?;
    let mut db=index::Db::open(path)?;let r=review(rpc,path,&db.conn,id)?;
    let mut c=r.case.clone();let mut result=r.summary.clone();result["read_only"]=json!(false);
    if let Some(name)=key {
        anyhow::ensure!(r.confirmations.iter().all(Option::is_some),"existing late refund pending; resume original bytes first");
        anyhow::ensure!(c.batches.len()<1000,"too many late refund batches; manual review required");
        let fresh:Vec<_>=r.found.iter().filter(|(k,_)|!c.observed.contains_key(*k)).map(|(_,u)|u.clone()).collect();
        let funding:Vec<_>=r.found.iter().filter(|(k,_)|!r.used.contains(*k)).map(|(_,u)|u.clone()).collect();
        if funding.is_empty(){result["state"]=json!("no_unallocated_late_payments");return Ok(result);}
        anyhow::ensure!(funding.len()<=100,"late refund exceeds 100 inputs; retain liability for manual batching");
        let total=funding.iter().try_fold(0,|n,u|add(n,u.value))?;
        let locked=refund_claim::reserved_inputs(&db.conn)?;
        anyhow::ensure!(fresh.iter().all(|u|!locked.contains(&point(u))),"new late receipt already reserved");
        for (b,confirmation) in c.batches.iter_mut().zip(&r.confirmations){b.confirmation=confirmation.clone();}
        for u in &fresh {c.observed.insert(point(u),u.clone());}
        let plan=if refund::amounts(total,funding.len())?.is_some() {
            let k=Key::load(name)?;anyhow::ensure!(k.address_string(rpc.net())==c.invoice_address,"use the original invoice key");
            refund::RefundPlan::prepare(rpc,&k,funding,&c.destination)?
        }else{None};
        if fresh.is_empty() && plan.is_none(){result["state"]=json!("late_refund_pending_small");return Ok(result);}
        let tx=db.conn.transaction_with_behavior(TransactionBehavior::Immediate)?;unchanged(&tx,rpc,id,&r)?;
        let mut hold=r.held.record.clone();
        for u in &fresh {
            let point=point(u);anyhow::ensure!(!refund_claim::reserved_inputs(&tx)?.contains(&point),"late receipt allocated during signing");
            tx.execute("INSERT INTO kv VALUES('service-settlement-inputs',?1,?2)",params![point,json!({"order_id":id,"kind":"late_payment"}).to_string()])?;
            hold["reserved_outpoints"].as_array_mut().context("hold reservations")?.push(json!(point));
        }
        if let Some(p)=plan {
            result["prepared_txid"]=json!(p.txid);result["prepared_refund_zat"]=json!(p.refund_zat);result["state"]=json!("late_refund_prepared");
            tx.execute("INSERT INTO kv VALUES('operator-actions',?1,?2)",params![format!("settlement-late-refund:{id}:{}",p.txid),action(id,&p).to_string()])?;
            c.batches.push(Batch{plan:p,confirmation:None});
        }else{result["state"]=json!("late_refund_pending_small");}
        tx.execute("UPDATE kv SET json=?1 WHERE ns='service-settlements' AND k=?2",params![hold.to_string(),id])?;
        tx.execute("INSERT INTO kv VALUES(?1,?2,?3) ON CONFLICT(ns,k) DO UPDATE SET json=excluded.json",params![NS,id,serde_json::to_string(&c)?])?;
        service_payout::anchor(&tx,rpc,&r.paid.audit)?;tx.commit()?;
        result["summary_is_before_preparation"]=json!(true);return Ok(result);
    }
    anyhow::ensure!(r.raw.is_some(),"no recorded late-payment case; review and prepare first");
    for (b,confirmation) in c.batches.iter_mut().zip(&r.confirmations) {
        b.confirmation=if confirmation.is_some(){confirmation.clone()}else{
            service_payout::anchor(&db.conn,rpc,&r.paid.audit)?;b.plan.resume(rpc)?
        };
    }
    let tx=db.conn.transaction_with_behavior(TransactionBehavior::Immediate)?;unchanged(&tx,rpc,id,&r)?;
    // Recheck all locally saved authorizations after a network action as well.
    for b in &r.case.batches {
        let raw:String=tx.query_row("SELECT json FROM kv WHERE ns='operator-actions' AND k=?1",[format!("settlement-late-refund:{id}:{}",b.plan.txid)],|r|r.get(0))?;
        anyhow::ensure!(serde_json::from_str::<Value>(&raw)?==action(id,&b.plan),"late refund action changed during network call");
    }
    tx.execute("UPDATE kv SET json=?1 WHERE ns=?2 AND k=?3",params![serde_json::to_string(&c)?,NS,id])?;tx.commit()?;
    let mut result=review(rpc,path,&db.conn,id)?.summary;result["read_only"]=json!(false);result["state"]=json!("late_refunds_rechecked_order_still_held");Ok(result)
}
#[cfg(test)] mod tests {
 use super::*;
 #[test] fn late_reservation_requires_unique_case_purpose_and_no_competing_claim() {
  let db=Connection::open_in_memory().unwrap();db.execute_batch("CREATE TABLE kv(ns TEXT,k TEXT,json TEXT,PRIMARY KEY(ns,k));").unwrap();
  let u=Utxo{txid:"ab".repeat(32),n:0,script:String::new(),value:5000,height:100};let point=point(&u);
  let mut held=service_settlement::Held{record_raw:String::new(),record:json!({"reserved_outpoints":[point]}),order_raw:String::new(),order:json!({"id":"case"})};
  for (owner,kind) in [("other","late_payment"),("case","project_reserve"),("case","late_payment")] {
   db.execute("INSERT OR REPLACE INTO kv VALUES('service-settlement-inputs',?1,?2)",params![point,json!({"order_id":owner,"kind":kind}).to_string()]).unwrap();
   assert_eq!(reserved(&db,&held,"case",&u).is_ok(),owner=="case" && kind=="late_payment");
  }
  held.record["reserved_outpoints"]=json!([point,point]);assert!(reserved(&db,&held,"case",&u).is_err());
  held.record["reserved_outpoints"]=json!([point]);
  for ns in ["self-mint-refund-inputs","reclaim-inputs"] {
   db.execute("INSERT INTO kv VALUES(?1,?2,'{}')",params![ns,point]).unwrap();assert!(reserved(&db,&held,"case",&u).is_err());
   db.execute("DELETE FROM kv WHERE ns=?1",[ns]).unwrap();
  }
  assert!(reserved(&db,&held,"case",&u).is_ok());
 }
 #[test] fn late_liability_cannot_overflow_or_exceed_chain_money_range() {
  assert_eq!(add(22000,21000).unwrap(),43000);
  assert!(add(u64::MAX,1).is_err());assert!(add(2_100_000_000_000_000,1).is_err());
 }
}
/// Historical local receipts only; does not claim complete discovery or current chain confirmation.
pub fn public_cached(db:&Connection,id:&str,net:index::Net,genesis_hash:&str)->Result<Value> {
    let Some(raw)=row(db,id)? else {return Ok(json!({"available":true,"state":"not_reviewed","confirmation_is_historical":true}));};
    let c:Case=serde_json::from_str(&raw)?;let held=service_settlement::checked_hold(db,id)?;
    let old=service_payout::public_cached(db,id,net,genesis_hash)?;
    anyhow::ensure!(old["available"]==true && old["state"]=="refund_confirmation_recorded", "original refund requires review");
    anyhow::ensure!(c.version==1 && c.network==net.name() && c.genesis_hash==genesis_hash && c.order_id==id
        && json!(c.invoice_address)==held.order["invoice_address"] && json!(c.destination)==old["payout"]["destination"]
        && json!(c.payout_txid)==old["payout"]["txid"] && c.invoice_address!=c.destination && c.batches.len()<=1000,"late receipt identity changed");
    let paid:String=db.query_row("SELECT json FROM kv WHERE ns='service-settlement-payouts' AND k=?1",[id],|r|r.get(0))?;
    let paid:Value=serde_json::from_str(&paid)?;
    anyhow::ensure!(json!(c.checkpoint_height)==paid["history"]["end_height"] && json!(c.checkpoint_hash)==paid["history"]["anchor_hash"],"late checkpoint changed");
    let script=hex::encode(index::script_bytes(&parse_taddr_for(&c.invoice_address,net.network_type())?.script().into()));
    let mut total=0;let mut returned=0;let mut fees=0;let mut pending=0;let mut used=BTreeSet::new();let mut batches=Vec::new();
    for (key,u) in &c.observed {
        anyhow::ensure!(*key==point(u) && u.script==script && u.height>c.checkpoint_height,"late receipt changed");u.outpoint()?;reserved(db,&held,id,u)?;total=add(total,u.value)?;
    }
    for (i,b) in c.batches.iter().enumerate() {
        let p=&b.plan;p.validate_for_chain(net,genesis_hash)?;
        let bytes=hex::decode(&p.raw_transaction)?;let tx=Transaction::read(&bytes[..],net.branch_for(p.target_height))?;
        anyhow::ensure!(tx.sapling_bundle().is_none() && tx.orchard_bundle().is_none() && tx.sprout_bundle().is_none() && p.destination==c.destination,"late refund scope changed");
        for u in &p.funding {let key=point(u);anyhow::ensure!(used.insert(key.clone()) && serde_json::to_value(c.observed.get(&key).context("late source missing")?)?==serde_json::to_value(u)?,"late source changed/reused");}
        let saved:String=db.query_row("SELECT json FROM kv WHERE ns='operator-actions' AND k=?1",[format!("settlement-late-refund:{id}:{}",p.txid)],|r|r.get(0))?;
        anyhow::ensure!(serde_json::from_str::<Value>(&saved)?==action(id,p),"late action changed");
        if let Some(conf)=&b.confirmation {
            anyhow::ensure!(conf.height>c.checkpoint_height && conf.block_hash.len()==64 && conf.block_hash.bytes().all(|b|b.is_ascii_hexdigit()),"late confirmation invalid");
            returned=add(returned,p.refund_zat)?;fees=add(fees,p.fee_zat)?;
        }else{anyhow::ensure!(i+1==c.batches.len(),"pending late refund precedes another batch");pending=add(pending,p.input_zat)?;}
        batches.push(json!({"txid":p.txid,"amount_zat":p.refund_zat,"confirmation":b.confirmation}));
    }
    let unallocated=c.observed.iter().filter(|(k,_)|!used.contains(*k)).try_fold(0,|sum,(_,u)|add(sum,u.value))?;
    anyhow::ensure!(total==add(add(returned,fees)?,add(pending,unallocated)?)?,"late ledger differs");
    Ok(json!({"available":true,"state":"recorded","confirmation_is_historical":true,"recorded_received_zat":total,
        "recorded_returned_zat":returned,"recorded_network_fee_zat":fees,"pending_input_zat":pending,"unallocated_zat":unallocated,"batches":batches}))
}
