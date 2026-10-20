//! Return a paid, quarantined order's original commit outputs to the advancing reserve.
//! This is project reimbursement, never a second customer refund or an order unfreeze.
use crate::*;
use rusqlite::{OptionalExtension,TransactionBehavior};
const NS:&str="service-settlement-recoveries";
#[derive(Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
struct Recovery {
    version:u32,order_id:String,payout_txid:String,destination:String,
    plans:Vec<refund::RefundPlan>,confirmations:Vec<Option<refund::RefundConfirmation>>,
}
fn accounting(a:&Value,p:&refund::RefundPlan,r:&Recovery)->Result<Value>{
    let received=a["observed_received_zat"].as_u64().context("received")?;
    let old_fees=a["confirmed_network_fees_zat"].as_u64().context("original fees")?;
    let old_returns=a["confirmed_returned_zat"].as_u64().context("original returns")?;
    let mut input=0u64;let mut returned=0u64;let mut fees=0u64;
    for x in &r.plans {input=input.checked_add(x.input_zat).context("recovery input overflow")?;returned=returned.checked_add(x.refund_zat).context("recovery return overflow")?;fees=fees.checked_add(x.fee_zat).context("recovery fee overflow")?;}
    let still_held=received.checked_sub(old_fees).and_then(|n|n.checked_sub(old_returns)).and_then(|n|n.checked_sub(input)).context("original funds do not cover recovery")?;
    let sources=received.checked_add(p.input_zat).context("source overflow")?;
    let uses=[old_fees,old_returns,p.refund_zat,p.fee_zat,returned,fees,still_held].into_iter().try_fold(0u64,|n,v|n.checked_add(v).context("uses overflow"))?;
    anyhow::ensure!(sources==uses && input==returned+fees,"settlement conservation failed");
    Ok(json!({"sources_zat":sources,"uses_zat":uses,"original_received_zat":received,"original_network_fees_zat":old_fees,"original_returned_zat":old_returns,
        "project_advance_input_zat":p.input_zat,"customer_payout_zat":p.refund_zat,"payout_network_fee_zat":p.fee_zat,
        "recovery_input_zat":input,"recovery_to_project_zat":returned,"recovery_network_fees_zat":fees,"original_funds_still_held_zat":still_held,
        "project_net_outlay_zat":p.input_zat.checked_sub(returned).context("recovery exceeds advance")?,"scope":"recorded funds only; recovery fees borne by project; unrecorded late-payment rights remain open"}))
}
fn summary(r:&Recovery,a:&Value,p:&refund::RefundPlan,cached:bool)->Result<Value>{
    let all=r.confirmations.len()==2 && r.confirmations.iter().all(Option::is_some);
    Ok(json!({"order_id":r.order_id,"payout_txid":r.payout_txid,"destination":r.destination,
        "transactions":r.plans.iter().zip(&r.confirmations).map(|(p,c)|json!({"txid":p.txid,"recovered_zat":p.refund_zat,"fee_zat":p.fee_zat,"confirmation":c})).collect::<Vec<_>>(),
        "confirmation_is_cached":cached,"all_recoveries_confirmed":all,"accounting":accounting(a,p,r)?,
        "accounting_is_plan":!all || cached,"status":if all{"recorded_recoveries_confirmed_order_still_held"}else{"recovery_signed_pending"},"order_remains_held":true}))
}
fn original(held:&service_settlement::Held,rpc:&Rpc)->Result<inscribe::SignedInscription>{
    let p:inscribe::SignedInscription=serde_json::from_value(held.order["mint_plan"].clone())?;p.validate(rpc)?;
    anyhow::ensure!(p.transactions.len()==2 && p.commit_vout==0 && rpc.checked_target()?>p.expiry_height,"unsupported or unexpired original plan");Ok(p)
}
fn validate(r:&Recovery,rpc:&Rpc,id:&str,original:&inscribe::SignedInscription,paid:&service_payout::Paid)->Result<()> {
    anyhow::ensure!(r.version==1 && r.order_id==id && r.payout_txid==paid.plan.txid && r.destination==paid.reserve_address && r.plans.len()==2 && r.confirmations.len()==2,"recovery identity/count changed");
    let tx=reclaim::parse(&original.transactions[0],rpc.net(),original.target_height)?;
    let outputs=&tx.transparent_bundle().context("commit outputs")?.vout;
    for (n,p) in r.plans.iter().enumerate(){
        p.validate(rpc)?;let u=p.funding.first().context("recovery funding")?;let out=outputs.get(n).context("commit output missing")?;
        anyhow::ensure!(p.destination==r.destination && p.funding.len()==1 && p.target_height>original.expiry_height && u.txid==original.transactions[0].txid && u.n==n as u32 && u.value==out.value().into_u64() && u.script==hex::encode(index::script_bytes(out.script_pubkey())),"recovery must spend exact original commit output to reserve");
        if n==0 {
            let bytes=hex::decode(&p.raw_transaction)?;let t=Transaction::read(&mut bytes.as_slice(),rpc.net().branch_for(p.target_height))?;
            reclaim::validate_spend(&t,p.version,p.fee_zat)?;
        }
    }
    accounting(&paid.audit,&paid.plan,r)?;Ok(())
}
fn unchanged(tx:&rusqlite::Transaction<'_>,id:&str,held:&service_settlement::Held,paid:&service_payout::Paid)->Result<()> {
    let now=service_settlement::checked_hold(tx,id)?;
    let payout:String=tx.query_row("SELECT json FROM kv WHERE ns='service-settlement-payouts' AND k=?1",[id],|r|r.get(0))?;
    let pending:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM meta WHERE k='reorg_pending')",[],|r|r.get(0))?;
    anyhow::ensure!(!pending && now.record_raw==held.record_raw && now.order_raw==held.order_raw && payout==paid.raw,"case or payout changed; preserve original recovery plans");
    service_payout::verify_recorded_source(tx,&now,&payout)?;Ok(())
}
pub fn command(rpc:&Rpc,path:&str,id:&str,keys:Option<(&str,&str)>)->Result<Value>{
    let _wallet=refund_claim::wallet_lock(&std::path::Path::new(path).parent().context("runtime directory")?.join("wallet.lock"))?;
    let mut db=index::Db::open(path)?;let held=service_settlement::checked_hold(&db.conn,id)?;
    let paid=service_payout::verified_paid(rpc,path,&db.conn,id)?;let original=original(&held,rpc)?;
    let old:Option<String>=db.conn.query_row("SELECT json FROM kv WHERE ns=?1 AND k=?2",(NS,id),|r|r.get(0)).optional()?;
    if let Some(raw)=old {
        let mut r:Recovery=serde_json::from_str(&raw)?;validate(&r,rpc,id,&original,&paid)?;
        for p in &r.plans {let point=format!("{}:{}",p.funding[0].txid,p.funding[0].n);anyhow::ensure!(held.record["reserved_outpoints"].as_array().context("case reservations")?.contains(&json!(point)),"recovery source missing from case reservations");}
        if keys.is_some(){return summary(&r,&paid.audit,&paid.plan,true);}
        anyhow::ensure!(audit::transaction(rpc,&original.transactions[0].txid,&original.transactions[0].raw)?["state"]=="confirmed","original commit is not canonical");
        for i in 0..r.plans.len(){
            let p=&r.plans[i];
            match rpc.call("getrawtransaction",json!([p.txid,1])) {
                Ok(_)=>{},Err(e) if e.downcast_ref::<RpcCallError>().is_some_and(|e|e.code == -5)=>rpc.validate_utxo(&p.funding[0])?,Err(e)=>return Err(e),
            }
            service_payout::anchor(&db.conn,rpc,&paid.audit)?;
            r.confirmations[i]=p.resume(rpc)?;
        }
        let tx=db.conn.transaction_with_behavior(TransactionBehavior::Immediate)?;unchanged(&tx,id,&held,&paid)?;
        let current:String=tx.query_row("SELECT json FROM kv WHERE ns=?1 AND k=?2",(NS,id),|r|r.get(0))?;
        anyhow::ensure!(current==raw && rpc.call("getblockhash",json!([paid.audit["at_height"]]))?==paid.audit["at_hash"],"recovery state or anchor changed after network action");
        tx.execute("UPDATE kv SET json=?1 WHERE ns=?2 AND k=?3",(serde_json::to_string(&r)?,NS,id))?;tx.commit()?;
        return summary(&r,&paid.audit,&paid.plan,false);
    }
    let (invoice_key,service_key)=keys.context("no saved recovery; prepare after confirmed customer payout")?;
    let st=index::Db::load_from(&db.conn)?;let (n,u,mut reveal)=reclaim::select_source(rpc,&original,&st)?;anyhow::ensure!(n==0,"only original standard commit supported");
    let destination=parse_taddr_for(&paid.reserve_address,rpc.net().network_type())?;
    let (amount,fee,version)=reclaim::configure_outputs(&mut reveal,&destination)?;
    let signed=inscribe::build_reclaim(&reveal,&Key::load(invoice_key)?)?;
    reclaim::validate_spend(&signed,version,fee)?;
    let mut bytes=Vec::new();signed.write(&mut bytes)?;
    let first=refund::RefundPlan{version,network:rpc.net().name().into(),genesis_hash:rpc.chain.genesis_hash.clone(),target_height:rpc.checked_target()?,expiry_height:reveal.expiry,destination:paid.reserve_address.clone(),funding:vec![u.clone()],input_zat:u.value,refund_zat:amount,fee_zat:fee,txid:signed.txid().to_string(),raw_transaction:hex::encode(bytes)};
    let commit=reclaim::parse(&original.transactions[0],rpc.net(),original.target_height)?;
    let out=commit.transparent_bundle().context("commit bundle")?.vout.get(1).context("service output")?;
    let service=Utxo{txid:original.transactions[0].txid.clone(),n:1,value:out.value().into_u64(),script:hex::encode(index::script_bytes(out.script_pubkey())),height:u.height};
    let second=refund::RefundPlan::prepare(rpc,&Key::load(service_key)?,vec![service],&paid.reserve_address)?.context("service output too small; retain held balance")?;
    let r=Recovery{version:1,order_id:id.into(),payout_txid:paid.plan.txid.clone(),destination:paid.reserve_address.clone(),plans:vec![first,second],confirmations:vec![None,None]};validate(&r,rpc,id,&original,&paid)?;
    let tx=db.conn.transaction_with_behavior(TransactionBehavior::Immediate)?;unchanged(&tx,id,&held,&paid)?;service_payout::anchor(&tx,rpc,&paid.audit)?;
    for p in &r.plans {let point=format!("{}:{}",p.funding[0].txid,p.funding[0].n);anyhow::ensure!(held.record["reserved_outpoints"].as_array().context("case reservations")?.contains(&json!(point)),"source not reserved by settlement");}
    tx.execute("INSERT INTO kv(ns,k,json) VALUES(?1,?2,?3)",(NS,id,serde_json::to_string(&r)?))?;
    tx.execute("INSERT INTO kv(ns,k,json) VALUES('operator-actions',?1,?2)",(format!("settlement-recovery-plan:{id}"),json!({"action":"recover_original_funds_after_customer_payout","order_id":id,"payout_txid":paid.plan.txid,"destination":r.destination,"txids":r.plans.iter().map(|p|&p.txid).collect::<Vec<_>>(),"broadcast":false}).to_string()))?;
    tx.commit()?;summary(&r,&paid.audit,&paid.plan,true)
}

#[cfg(test)] mod tests {
    use super::*;
    fn plan(input:u64,output:u64,fee:u64)->refund::RefundPlan{refund::RefundPlan{version:1,network:"regtest".into(),genesis_hash:String::new(),target_height:1,expiry_height:40,destination:String::new(),funding:vec![],input_zat:input,refund_zat:output,fee_zat:fee,txid:String::new(),raw_transaction:String::new()}}
    #[test] fn project_reimbursement_conserves_customer_and_reserve_funds(){
        let a=json!({"observed_received_zat":100000,"confirmed_network_fees_zat":10000,"confirmed_returned_zat":0});
        let r=Recovery{version:1,order_id:"a".into(),payout_txid:String::new(),destination:String::new(),plans:vec![plan(25546,15546,10000),plan(64454,54454,10000)],confirmations:vec![None,None]};
        let fault=accounting(&a,&plan(110000,100000,10000),&r).unwrap();assert_eq!(fault["sources_zat"],210000);assert_eq!(fault["uses_zat"],210000);assert_eq!(fault["project_net_outlay_zat"],40000);assert_eq!(fault["original_funds_still_held_zat"],0);
        let normal=accounting(&a,&plan(90000,80000,10000),&r).unwrap();assert_eq!(normal["project_net_outlay_zat"],20000);
        assert!(accounting(&a,&plan(110000,100001,10000),&r).is_err());
        let mut missing=a.clone();missing["observed_received_zat"]=json!(99999);assert!(accounting(&missing,&plan(110000,100000,10000),&r).is_err());
    }
    #[test] fn prior_refunds_and_unrecovered_receipts_remain_in_the_ledger(){
        let a=json!({"observed_received_zat":140000,"confirmed_network_fees_zat":20000,"confirmed_returned_zat":20000});
        let r=Recovery{version:1,order_id:"a".into(),payout_txid:String::new(),destination:String::new(),plans:vec![plan(25546,15546,10000),plan(64454,54454,10000)],confirmations:vec![None,None]};
        let v=accounting(&a,&plan(130000,120000,10000),&r).unwrap();
        assert_eq!(v["sources_zat"],270000);assert_eq!(v["uses_zat"],270000);assert_eq!(v["original_funds_still_held_zat"],10000);assert_eq!(v["project_net_outlay_zat"],60000);
        assert_eq!(v["original_returned_zat"],20000);assert_eq!(v["customer_payout_zat"],120000);
    }
}
