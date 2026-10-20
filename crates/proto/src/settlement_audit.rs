//! Conditional liability evidence for expired, incomplete inclusive service mints.
//! No signing, key access, order mutation, fund selection or payment authorization.
use crate::*;
use rusqlite::{Connection, OpenFlags};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Deserialize)]
struct Order {
    id: String, kind: String, dest: String, invoice_address: String,
    refund_address: String, accounting_version: u32, amount_zat: u64, paid_zat: u64,
    receipts: BTreeMap<String,Utxo>, mint_plan: inscribe::SignedInscription,
    quote: Quote, refunds: Vec<SavedRefund>,
}
#[derive(Deserialize)]
struct Quote {
    version:u32, inclusive:bool, network:String, genesis_hash:String, collection:String,
    total_zat:u64, price_zat:u64, pay:String, fee_address:String,
}
#[derive(Deserialize)]
struct SavedRefund {plan:refund::RefundPlan}
fn add(a:u64,b:u64)->Result<u64>{let v=a.checked_add(b).context("amount overflow")?;zat(v)?;Ok(v)}
fn point(u:&Utxo)->String{format!("{}:{}",u.txid,u.n)}
fn scenarios(received:u64,fees:u64,returned:u64)->Result<Value>{
    zat(received)?;zat(fees)?;zat(returned)?;
    let normal=received.checked_sub(fees).and_then(|v|v.checked_sub(returned)).context("returns and fees exceed received funds")?;
    let fault=received.checked_sub(returned).context("returns exceed received funds")?;
    Ok(json!({"normal_failure_remaining_before_future_fees_zat":normal,
        "project_fault_remaining_before_future_fees_zat":fault,
        "additional_project_fault_compensation_zat":fees}))
}
fn parse(raw:&str,branch:zcash_protocol::consensus::BranchId)->Result<Transaction>{
    let bytes=hex::decode(raw)?;let mut cursor=std::io::Cursor::new(&bytes);
    let tx=Transaction::read(&mut cursor,branch)?;
    anyhow::ensure!(cursor.position() as usize==bytes.len() && tx.sapling_bundle().is_none() && tx.orchard_bundle().is_none() && tx.sprout_bundle().is_none(),"requires exact transparent-only transaction");
    Ok(tx)
}
fn script(address:&str,rpc:&Rpc)->Result<Script>{Ok(parse_taddr_for(address,rpc.net().network_type())?.script().into())}
fn allocate(receipts:&BTreeMap<String,Utxo>,used:&mut BTreeSet<String>,funding:&[Utxo])->Result<u64>{
    let mut sum=0;
    for u in funding {
        let key=point(u);let old=receipts.get(&key).context("allocation lacks receipt")?;
        anyhow::ensure!(old.value==u.value && old.script==u.script && used.insert(key),"duplicate or changed allocation");
        sum=add(sum,u.value)?;
    }
    Ok(sum)
}
pub fn audit(rpc:&Rpc,path:&str,id:&str)->Result<Value>{
    let mut conn=Connection::open_with_flags(path,OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let snapshot=conn.transaction()?;
    let schema:String=snapshot.query_row("SELECT v FROM meta WHERE k='schema_version'",[],|r|r.get(0))?;
    anyhow::ensure!(schema == crate::index::SCHEMA_VERSION,"unsupported schema");
    let raw:String=snapshot.query_row("SELECT json FROM kv WHERE ns='orders' AND k=?1",[id],|r|r.get(0))?;
    let o:Order=serde_json::from_str(&raw)?;let q=&o.quote;let p=&o.mint_plan;
    let overlapping:bool=snapshot.query_row("SELECT EXISTS(SELECT 1 FROM kv WHERE k=?1 AND ns IN ('self-mint-refunds','expired-reclaims'))",[&p.result.inscription_id],|r|r.get(0))?;
    anyhow::ensure!(!overlapping,"another claim/reclaim workflow requires reconciliation");
    let st=index::Db::load_from(&snapshot)?;
    let barrier:bool=snapshot.query_row("SELECT EXISTS(SELECT 1 FROM meta WHERE k='reorg_pending')",[],|r|r.get(0))?;
    anyhow::ensure!(!barrier,"reorg reconciliation pending");
    anyhow::ensure!(o.id==id && o.kind=="mint" && o.accounting_version==1 && q.version==1 && q.inclusive && q.total_zat==o.amount_zat,"requires immutable inclusive mint order");
    anyhow::ensure!(q.network==rpc.net().name() && q.genesis_hash==rpc.chain.genesis_hash && st.network.as_deref()==Some(q.network.as_str()),"order/index network mismatch");
    let tip=rpc.checked_target()? - 1;let hash=rpc.call("getblockhash",json!([tip]))?;
    anyhow::ensure!(st.height==tip && st.tip_hash.as_deref()==hash.as_str(),"index must match canonical tip");
    anyhow::ensure!(p.expiry_height<tip.saturating_add(1) && !st.inscriptions.contains_key(&p.result.inscription_id) && !st.mints.contains_key(&p.result.inscription_id),"requires expired incomplete mint, not delivered or completed inscription");
    let col=st.collections.get(&q.collection).context("collection missing")?;
    anyhow::ensure!(col.price==q.price_zat && col.pay==q.pay,"quote differs from collection");
    p.validate(rpc)?;
    anyhow::ensure!(p.destination==o.dest && p.transactions.len()==2 && p.commit_vout==0,"only standard single-reveal service plans supported");
    let refund_script=script(&o.refund_address,rpc)?;let service_script=script(&q.fee_address,rpc)?;
    let mut received=0;
    for (key,u) in &o.receipts {
        anyhow::ensure!(*key==point(u) && audit::receipt(rpc,u,&o.invoice_address)?["state"]=="confirmed","receipt not canonical or inconsistent");
        received=add(received,u.value)?;
    }
    anyhow::ensure!(received==o.paid_zat,"observed receipt total differs");
    let mut used=BTreeSet::new();let input=allocate(&o.receipts,&mut used,&p.funding)?;
    let excess=input.checked_sub(q.total_zat).context("underfunded inclusive order")?;
    let branch=rpc.net().branch_for(p.target_height);
    let commit=parse(&p.transactions[0].raw,branch)?;let cb=commit.transparent_bundle().context("no commit outputs")?;
    anyhow::ensure!(cb.vout.len()==if excess>0 {3}else{2} && cb.vout[1].script_pubkey()==&service_script,"unexpected inclusive commit layout");
    if excess>0 {anyhow::ensure!(cb.vout[2].value().into_u64()==excess && cb.vout[2].script_pubkey()==&refund_script,"overpayment destination/amount mismatch");}
    let output=cb.vout.iter().try_fold(0,|a,v|add(a,v.value().into_u64()))?;
    let commit_fee=input.checked_sub(output).context("commit creates money")?;
    let reveal=parse(&p.transactions[1].raw,branch)?;let rb=reveal.transparent_bundle().context("no reveal outputs")?;
    anyhow::ensure!(rb.vout.len()==2 && rb.vout[1].value().into_u64()==q.price_zat && rb.vout[1].script_pubkey()==&script(&q.pay,rpc)?,"mint payment differs from quote");
    let reveal_outputs=rb.vout.iter().try_fold(0,|a,v|add(a,v.value().into_u64()))?;
    anyhow::ensure!(cb.vout[0].value().into_u64()>=reveal_outputs,"reveal creates money");
    let mut evidence=vec![];
    for tx in &p.transactions {evidence.push(audit::transaction(rpc,&tx.txid,&tx.raw)?);}
    anyhow::ensure!(evidence[1]["state"]=="missing","final reveal still has chain/mempool evidence; reconcile before estimating");
    let confirmed=match evidence[0]["state"].as_str(){Some("confirmed")=>true,Some("missing")=>false,_=>bail!("commit confirmation uncertain")};
    let mut fees=if confirmed{commit_fee}else{0};let mut returned=if confirmed{excess}else{0};
    let service=if confirmed{cb.vout[1].value().into_u64()}else{0};
    for refund in &o.refunds {
        let r=&refund.plan;r.validate(rpc)?;
        anyhow::ensure!(r.destination==o.refund_address && allocate(&o.receipts,&mut used,&r.funding)?==r.input_zat,"refund terms mismatch");
        let proof=audit::transaction(rpc,&r.txid,&r.raw_transaction)?;
        anyhow::ensure!(proof["state"]=="confirmed","outstanding refund must be reconciled first");
        fees=add(fees,r.fee_zat)?;returned=add(returned,r.refund_zat)?;evidence.push(proof);
    }
    let amounts=scenarios(received,fees,returned)?;
    snapshot.commit()?;
    let current_index=index::Db::load_from(&conn)?;
    let pending:bool=conn.query_row("SELECT EXISTS(SELECT 1 FROM meta WHERE k='reorg_pending')",[],|r|r.get(0))?;
    anyhow::ensure!(!pending && current_index.height==st.height && current_index.tip_hash==st.tip_hash,"index changed during audit");
    let current:String=conn.query_row("SELECT json FROM kv WHERE ns='orders' AND k=?1",[id],|r|r.get(0))?;
    anyhow::ensure!(current==raw && rpc.checked_target()? - 1==tip && rpc.call("getblockhash",json!([tip]))?==hash,"order or chain changed during audit");
    Ok(json!({"read_only":true,"authorizes_payment":false,"order_id":id,"refund_address":o.refund_address,
        "at_height":tip,"at_hash":hash,"observed_received_zat":received,"confirmed_network_fees_zat":fees,
        "confirmed_returned_zat":returned,"unearned_service_paid_zat":service,"conditional_liability":amounts,"evidence":evidence,
        "limitations":["Recorded receipts only: reconcile full payment history separately", "Missing RPC result is not proof of absence or authority to replace a transaction", "No fault attribution: scenarios assume either ordinary failure or all evidenced fees caused by project fault", "Future recovery/refund fees, external wallet fees and unrecorded payments excluded", "No spendability check, order freeze, reserve funding or payout plan: do not pay from this report"]}))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn failed_service_refunds_service_and_compensates_only_evidenced_fees(){
        let v=scenarios(100000,10000,0).unwrap();
        assert_eq!(v["normal_failure_remaining_before_future_fees_zat"],90000);
        assert_eq!(v["project_fault_remaining_before_future_fees_zat"],100000);
        assert_eq!(v["additional_project_fault_compensation_zat"],10000);
    }
    #[test] fn overpayment_and_prior_returns_are_not_paid_twice(){
        let v=scenarios(195000,30000,65000).unwrap();
        assert_eq!(v["normal_failure_remaining_before_future_fees_zat"],100000);
        assert_eq!(v["project_fault_remaining_before_future_fees_zat"],130000);
        assert!(scenarios(10,11,0).is_err());assert!(scenarios(10,5,6).is_err());assert!(scenarios(u64::MAX,0,0).is_err());
    }
    #[test] fn duplicate_and_changed_receipts_are_rejected(){
        let u=Utxo{txid:"11".repeat(32),n:0,value:100000,script:"76".into(),height:1};
        let mut receipts=BTreeMap::new();receipts.insert(point(&u),u.clone());let mut used=BTreeSet::new();
        assert_eq!(allocate(&receipts,&mut used,std::slice::from_ref(&u)).unwrap(),100000);
        assert!(allocate(&receipts,&mut used,std::slice::from_ref(&u)).is_err());
        let mut changed=u;changed.value+=1;assert!(allocate(&receipts,&mut BTreeSet::new(),&[changed]).is_err());
    }
}
