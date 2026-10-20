//! Explicit project-reserve advances for quarantined failed service orders.
//! One immutable payout per case. Original funds and the order remain quarantined.
use crate::*;
use rusqlite::{OptionalExtension,TransactionBehavior};
const NS:&str="service-settlement-payouts";
const FEE:u64=10000;
#[derive(Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
struct Payment {
    version:u32, order_id:String, mode:String, reason:String, reserve_address:String,
    audit:Value, history:Value, plan:refund::RefundPlan,
    confirmation:Option<refund::RefundConfirmation>,
}
fn amounts(audit:&Value,mode:&str)->Result<(u64,u64)> {
    let v=&audit["conditional_liability"];
    let (input,refund)=match mode {
        "normal"=>{let n=v["normal_failure_remaining_before_future_fees_zat"].as_u64().context("missing normal liability")?;(n,n.checked_sub(FEE).context("small liability remains unpaid")?)},
        "project-fault"=>{let n=v["project_fault_remaining_before_future_fees_zat"].as_u64().context("missing fault liability")?;(n.checked_add(FEE).context("compensation overflow")?,n)},
        _=>bail!("choose normal or project-fault; mixed attribution requires separate review"),
    };
    zat(input)?;zat(refund)?;anyhow::ensure!(refund>=CARRIER_ZAT,"small liability remains unpaid");Ok((input,refund))
}
fn summary(p:&Payment,cached:bool)->Value {
    json!({"order_id":p.order_id,"mode":p.mode,"destination":p.plan.destination,"txid":p.plan.txid,
        "project_advance_input_zat":p.plan.input_zat,"refund_zat":p.plan.refund_zat,"payout_network_fee_zat":p.plan.fee_zat,
        "confirmed_paid_zat":if p.confirmation.is_some(){p.plan.refund_zat}else{0},"confirmation":p.confirmation,"confirmation_is_cached":cached,
        "status":if p.confirmation.is_some(){"payout_confirmed_order_still_held"}else{"signed_payout_pending"},
        "scope":"one project-funded payment for recorded liability; original funds and late-payment rights remain held for reconciliation"})
}
pub(crate) fn anchor(db:&rusqlite::Connection,rpc:&Rpc,a:&Value)->Result<()> {
    let st=index::Db::load_from(db)?;
    let pending:bool=db.query_row("SELECT EXISTS(SELECT 1 FROM meta WHERE k='reorg_pending')",[],|r|r.get(0))?;
    let h=u32::try_from(a["at_height"].as_u64().context("audit height")?)?;
    anyhow::ensure!(!pending && st.height==h && st.tip_hash.as_deref()==a["at_hash"].as_str()
        && rpc.checked_target()? - 1==h && rpc.call("getblockhash",json!([h]))?==a["at_hash"],"chain/index changed; payout remains held");Ok(())
}
fn history(rpc:&Rpc,path:&str,id:&str,o:&Value,a:&Value)->Result<Value>{
    let start=u32::try_from(o["payment_start_height"].as_u64().context("payment start height required; legacy case needs manual history review")?)?;
    let end=u32::try_from(a["at_height"].as_u64().context("audit height")?)?;
    let h=payment_history::audit(rpc,path,id,start,end)?;
    anyhow::ensure!(h["covers_creation_through_end"]==true && h["anchor_hash"]==a["at_hash"]
        && h["unrecorded_received_zat"]==0 && h["observed_received_zat"]==a["observed_received_zat"]
        && h["issues"].as_array().is_some_and(Vec::is_empty),"payment history incomplete or changed; no payout");
    anyhow::ensure!(h["outputs"].as_array().context("history outputs")?.iter().all(|v|
        matches!(v["journal_state"].as_str(),Some("recorded_allocated"|"recorded_unallocated")) && v["carrier_or_pending_in_saved_index"]==false),"invoice contains unreviewed assets or receipts");
    Ok(h)
}
fn history_checkpoint(rpc:&Rpc,id:&str,o:&Value,a:&Value,old:&Value)->Result<u32> {
    let end=u32::try_from(old["end_height"].as_u64().context("history checkpoint missing")?)?;
    let tip=u32::try_from(a["at_height"].as_u64().context("audit tip")?)?;
    let start=u32::try_from(old["start_height"].as_u64().context("history start missing")?)?;
    anyhow::ensure!(old["order_id"]==id && old["network"]==rpc.net().name() && start<=end
        && old["start_height"]==o["payment_start_height"] && old["covers_creation_through_end"]==true
        && old["observed_received_zat"]==a["observed_received_zat"] && old["unrecorded_received_zat"]==0
        && old["issues"].as_array().is_some_and(Vec::is_empty) && end<=tip
        && rpc.call("getblockhash",json!([end]))?==old["anchor_hash"],"history checkpoint changed; preserve payout for review");
    if end==tip {anyhow::ensure!(old["anchor_hash"]==a["at_hash"],"history anchor mismatch");}
    Ok(end)
}
fn advance_history(rpc:&Rpc,path:&str,id:&str,o:&Value,a:&Value,old:&Value)->Result<Value> {
    let end=history_checkpoint(rpc,id,o,a,old)?;
    let tip=u32::try_from(a["at_height"].as_u64().context("audit tip")?)?;
    if end==tip {return Ok(old.clone());}
    let delta=payment_history::audit(rpc,path,id,end.checked_add(1).context("history height overflow")?,tip)?;
    anyhow::ensure!(delta["anchor_hash"]==a["at_hash"] && delta["outputs"].as_array().is_some_and(Vec::is_empty)
        && delta["issues"].as_array().is_some_and(Vec::is_empty),"new invoice payment or changed history; payout remains held for review");
    let mut h=old.clone();h["end_height"]=json!(tip);h["anchor_hash"]=a["at_hash"].clone();Ok(h)
}
fn same_money(old:&Value,new:&Value)->Result<()> {
    for k in ["observed_received_zat","confirmed_network_fees_zat","confirmed_returned_zat","unearned_service_paid_zat","conditional_liability"] {
        anyhow::ensure!(old[k]==new[k],"liability changed since signing; preserve payout and reconcile");
    }Ok(())
}
pub(crate) fn reserve_is_independent(db:&rusqlite::Connection,address:&str,u:&Utxo)->Result<()> {
    let point=format!("{}:{}",u.txid,u.n);
    let mut q=db.prepare("SELECT ns,json FROM kv WHERE ns IN ('orders','cli-inscription-plans')")?;
    for row in q.query_map([],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?)))? {
        let (ns,raw)=row?;let v:Value=serde_json::from_str(&raw)?;
        let p=if ns=="orders" {
            anyhow::ensure!(v["invoice_address"].as_str().is_some(),"order invoice missing; reserve ownership cannot be verified");
            anyhow::ensure!(v["invoice_address"].as_str()!=Some(address) && ["fee_address","pay"].iter().all(|k|v["quote"][*k].as_str()!=Some(address)),"use a dedicated project reserve wallet, separate from managed invoice and project collection/service wallets");
            anyhow::ensure!(v["receipts"].as_object().is_none_or(|m|!m.contains_key(&point)),"reserve is an invoice receipt");
            &v["mint_plan"]
        } else {&v};
        for field in ["funding","transactions"] {
            if let Some(rows)=p[field].as_array(){for r in rows {
                anyhow::ensure!(r["txid"].as_str()!=Some(u.txid.as_str()) || (field=="funding" && r["n"].as_u64()!=Some(u.n as u64)),"reserve overlaps a known inscription transaction or funding");
            }}
        }
    }Ok(())
}
fn case_reserve_is_independent(address:&str,o:&Value)->Result<()> {
    anyhow::ensure!(o["refund_address"].as_str()!=Some(address) && o["dest"].as_str()!=Some(address),"reserve must differ from this case's refund and NFT destination");Ok(())
}
fn validate_payment(p:&Payment,rpc:&Rpc,id:&str,o:&Value)->Result<()> {
    validate_identity(p,rpc.net(),&rpc.chain.genesis_hash,id,o)
}
fn validate_identity(p:&Payment,net:index::Net,genesis_hash:&str,id:&str,o:&Value)->Result<()> {
    anyhow::ensure!(p.version==1 && p.order_id==id && p.plan.destination==o["refund_address"].as_str().context("refund address missing")?,"payout identity/destination changed");
    // Other orders' user-entered destinations do not establish ownership of this reserve.
    // This particular case must still use a distinct reserve, never its own recipient wallet.
    case_reserve_is_independent(&p.reserve_address,o)?;
    anyhow::ensure!((1..=512).contains(&p.reason.trim().len()),"attribution reason missing/too long");
    p.plan.validate_for_chain(net,genesis_hash)?;let (input,refund)=amounts(&p.audit,&p.mode)?;
    anyhow::ensure!(p.plan.funding.len()==1 && p.plan.input_zat==input && p.plan.refund_zat==refund && p.plan.fee_zat==FEE,"payout amounts changed");
    let script=index::script_bytes(&parse_taddr_for(&p.reserve_address,net.network_type())?.script().into());
    anyhow::ensure!(p.plan.funding[0].script==hex::encode(script),"reserve ownership changed");Ok(())
}
// A confirmed transaction alone cannot assign a payment to a particular case.
// Bind the exact source to this hold and its independently saved operator action.
fn source_binding(db:&rusqlite::Connection,held:&service_settlement::Held,p:&Payment)->Result<()> {
    anyhow::ensure!(p.order_id==held.order["id"] && p.plan.funding.len()==1,"payout case/source identity changed");
    let u=&p.plan.funding[0];let point=format!("{}:{}",u.txid,u.n);
    let points=held.record["reserved_outpoints"].as_array().context("case reservations")?;
    anyhow::ensure!(points.iter().filter(|v|**v==json!(point)).count()==1,"payout source missing/duplicated in case reservations");
    let raw:String=db.query_row("SELECT json FROM kv WHERE ns='service-settlement-inputs' AND k=?1",[&point],|r|r.get(0))?;
    anyhow::ensure!(serde_json::from_str::<Value>(&raw)?==json!({"order_id":p.order_id,"kind":"project_reserve"}),"payout source belongs to another case or purpose");
    let conflict:bool=db.query_row("SELECT EXISTS(SELECT 1 FROM kv WHERE k=?1 AND ns IN ('self-mint-refund-inputs','reclaim-inputs'))",[&point],|r|r.get(0))?;
    anyhow::ensure!(!conflict,"payout source overlaps another funding workflow");
    let raw:String=db.query_row("SELECT json FROM kv WHERE ns='operator-actions' AND k=?1",[format!("settlement-payout-plan:{}",p.order_id)],|r|r.get(0))?;
    let expected=json!({"action":"reserve_project_payout","order_id":p.order_id,"txid":p.plan.txid,"mode":p.mode,"reason":p.reason,"reserve_input_zat":p.plan.input_zat,"refund_zat":p.plan.refund_zat,"fee_zat":p.plan.fee_zat,"broadcast":false});
    anyhow::ensure!(serde_json::from_str::<Value>(&raw)?==expected,"payout operator action differs from signed payment");Ok(())
}
pub(crate) fn verify_recorded_source(db:&rusqlite::Connection,held:&service_settlement::Held,raw:&str)->Result<()> {
    source_binding(db,held,&serde_json::from_str::<Payment>(raw)?)
}
fn lock(path:&str)->Result<std::fs::File>{refund_claim::wallet_lock(&std::path::Path::new(path).parent().context("missing runtime directory")?.join("wallet.lock"))}
pub(crate) struct Paid {
    pub raw:String, pub plan:refund::RefundPlan, pub reserve_address:String, pub audit:Value, pub history:Value,
}
/// Customer-facing cached receipt only. No RPC, private keys, signatures or attribution notes.
pub fn public_cached(db:&rusqlite::Connection,id:&str,net:index::Net,genesis_hash:&str)->Result<Value>{
    let held=service_settlement::checked_hold(db,id)?;
    let row:Option<String>=db.query_row("SELECT json FROM kv WHERE ns=?1 AND k=?2",(NS,id),|r|r.get(0)).optional()?;
    let Some(raw)=row else {return Ok(json!({"available":true,"held":true,"state":"awaiting_review","payout":null,"confirmation_is_historical":true}));};
    let p:Payment=serde_json::from_str(&raw)?;validate_identity(&p,net,genesis_hash,id,&held.order)?;source_binding(db,&held,&p)?;
    if let Some(c)=&p.confirmation {anyhow::ensure!(c.height>0 && c.block_hash.len()==64 && c.block_hash.bytes().all(|b|b.is_ascii_hexdigit()),"invalid saved payout confirmation");}
    Ok(json!({"available":true,"held":true,"state":if p.confirmation.is_some(){"refund_confirmation_recorded"}else{"refund_prepared"},
        "payout":{"txid":p.plan.txid,"amount_zat":p.plan.refund_zat,"destination":p.plan.destination,"confirmation":p.confirmation},
        "confirmation_is_historical":true}))
}
/// Read-only prerequisite for returning original order funds to the advancing project.
/// Never calls RefundPlan::resume: a missing customer payment must not broadcast implicitly.
pub(crate) fn verified_paid(rpc:&Rpc,path:&str,db:&rusqlite::Connection,id:&str)->Result<Paid>{
    let held=service_settlement::checked_hold(db,id)?;
    let raw:String=db.query_row("SELECT json FROM kv WHERE ns=?1 AND k=?2",(NS,id),|r|r.get(0))?;
    let p:Payment=serde_json::from_str(&raw)?;validate_payment(&p,rpc,id,&held.order)?;
    source_binding(db,&held,&p)?;reserve_is_independent(db,&p.reserve_address,&p.plan.funding[0])?;
    let a=settlement_audit::audit(rpc,path,id)?;same_money(&p.audit,&a)?;
    // A later deposit cannot undo an already confirmed customer payment.
    // Only the paid scope is verified here; the invoice remains quarantined.
    history_checkpoint(rpc,id,&held.order,&a,&p.history)?;
    anyhow::ensure!(audit::transaction(rpc,&p.plan.txid,&p.plan.raw_transaction)?["state"]=="confirmed","customer payout is not currently confirmed; do not recover original funds");
    anyhow::ensure!(audit::receipt(rpc,&p.plan.funding[0],&p.reserve_address)?["state"]=="confirmed","project advance source is not canonical");
    anchor(db,rpc,&a)?;
    Ok(Paid{raw,plan:p.plan,reserve_address:p.reserve_address,audit:a,history:p.history})
}
/// Called only from the local mintd command while it owns the worker lock.
pub fn prepare(rpc:&Rpc,path:&str,id:&str,key_name:&str,point:&str,mode:&str,reason:&str)->Result<Value>{
    let _wallet=lock(path)?;let mut db=index::Db::open(path)?;
    let held=service_settlement::checked_hold(&db.conn,id)?;
    let old:Option<String>=db.conn.query_row("SELECT json FROM kv WHERE ns=?1 AND k=?2",(NS,id),|r|r.get(0)).optional()?;
    if let Some(raw)=old {
        let p:Payment=serde_json::from_str(&raw)?;validate_payment(&p,rpc,id,&held.order)?;source_binding(&db.conn,&held,&p)?;
        anyhow::ensure!(p.mode==mode && p.reason==reason && format!("{}:{}",p.plan.funding[0].txid,p.plan.funding[0].n)==point,"existing payout differs; never replace signed payment");
        return Ok(summary(&p,true));
    }
    anyhow::ensure!((1..=512).contains(&reason.trim().len()),"provide an attribution reason (1..512 bytes)");
    let a=settlement_audit::audit(rpc,path,id)?;let (input,refund)=amounts(&a,mode)?;
    let h=history(rpc,path,id,&held.order,&a)?;
    let key=Key::load(key_name)?;let address=key.address_string(rpc.net());
    let u=rpc.spendable(&address)?.into_iter().find(|u|format!("{}:{}",u.txid,u.n)==point).context("specified reserve outpoint is not spendable; no automatic replacement")?;
    anyhow::ensure!(u.value==input,"dedicated reserve input must equal {input} zat; no implicit change or extra funding");
    reserve_is_independent(&db.conn,&address,&u)?;
    anyhow::ensure!(audit::receipt(rpc,&u,&address)?["state"]=="confirmed","reserve parent is not canonical");
    let plan=refund::RefundPlan::prepare(rpc,&key,vec![u],held.order["refund_address"].as_str().context("refund address")?)?.context("small liability remains unpaid")?;
    anyhow::ensure!(plan.refund_zat==refund,"payout construction differs");
    let p=Payment{version:1,order_id:id.into(),mode:mode.into(),reason:reason.into(),reserve_address:address,audit:a.clone(),history:h,plan,confirmation:None};
    validate_payment(&p,rpc,id,&held.order)?;
    let tx=db.conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let current=service_settlement::checked_hold(&tx,id)?;
    anyhow::ensure!(current.record_raw==held.record_raw && current.order_raw==held.order_raw,"case changed during signing");
    anchor(&tx,rpc,&a)?;
    anyhow::ensure!(!refund_claim::reserved_inputs(&tx)?.contains(point),"reserve input already allocated");
    let mut record=held.record;record["reserved_outpoints"].as_array_mut().context("case reservations")?.push(json!(point));
    tx.execute("INSERT INTO kv(ns,k,json) VALUES('service-settlement-inputs',?1,?2)",(point,json!({"order_id":id,"kind":"project_reserve"}).to_string()))?;
    tx.execute("UPDATE kv SET json=?1 WHERE ns='service-settlements' AND k=?2",(record.to_string(),id))?;
    tx.execute("INSERT INTO kv(ns,k,json) VALUES(?1,?2,?3)",(NS,id,serde_json::to_string(&p)?))?;
    tx.execute("INSERT INTO kv(ns,k,json) VALUES('operator-actions',?1,?2)",(format!("settlement-payout-plan:{id}"),json!({"action":"reserve_project_payout","order_id":id,"txid":p.plan.txid,"mode":mode,"reason":reason,"reserve_input_zat":input,"refund_zat":refund,"fee_zat":FEE,"broadcast":false}).to_string()))?;
    tx.commit()?;Ok(summary(&p,true))
}
/// Original bytes only; no key access, new funding, address change or automatic second payout.
pub fn resume(rpc:&Rpc,path:&str,id:&str)->Result<Value>{
    let _wallet=lock(path)?;let mut db=index::Db::open(path)?;let held=service_settlement::checked_hold(&db.conn,id)?;
    let raw:String=db.conn.query_row("SELECT json FROM kv WHERE ns=?1 AND k=?2",(NS,id),|r|r.get(0))?;
    let mut p:Payment=serde_json::from_str(&raw)?;validate_payment(&p,rpc,id,&held.order)?;source_binding(&db.conn,&held,&p)?;
    let a=settlement_audit::audit(rpc,path,id)?;same_money(&p.audit,&a)?;
    let payment_state=audit::transaction(rpc,&p.plan.txid,&p.plan.raw_transaction)?;
    anyhow::ensure!(matches!(payment_state["state"].as_str(),Some("confirmed"|"unconfirmed"|"missing")),"payout confirmation unavailable or noncanonical; preserve original payment");
    if payment_state["state"]=="confirmed" {history_checkpoint(rpc,id,&held.order,&a,&p.history)?;}
    else {p.history=advance_history(rpc,path,id,&held.order,&a,&p.history)?;}
    let u=&p.plan.funding[0];let point=format!("{}:{}",u.txid,u.n);
    let owner:String=db.conn.query_row("SELECT json FROM kv WHERE ns='service-settlement-inputs' AND k=?1",[&point],|r|r.get(0))?;
    anyhow::ensure!(serde_json::from_str::<Value>(&owner)?["order_id"]==id,"payout input reservation changed");
    reserve_is_independent(&db.conn,&p.reserve_address,u)?;
    anyhow::ensure!(audit::receipt(rpc,u,&p.reserve_address)?["state"]=="confirmed","reserve source confirmation changed");
    if payment_state["state"]=="missing" {rpc.validate_utxo(u)?;}
    anchor(&db.conn,rpc,&a)?;
    p.confirmation=p.plan.resume(rpc)?;
    let tx=db.conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let current=service_settlement::checked_hold(&tx,id)?;
    let current_payment:String=tx.query_row("SELECT json FROM kv WHERE ns=?1 AND k=?2",(NS,id),|r|r.get(0))?;
    anyhow::ensure!(current.record_raw==held.record_raw && current.order_raw==held.order_raw && current_payment==raw,"case changed after network action; original payment remains reserved");
    let pending:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM meta WHERE k='reorg_pending')",[],|r|r.get(0))?;
    anyhow::ensure!(!pending,"reorg reconciliation started during network action; preserve original payment");
    anyhow::ensure!(rpc.call("getblockhash",json!([a["at_height"]]))?==a["at_hash"],"audit anchor forked during network action; preserve original plan");
    source_binding(&tx,&current,&p)?;
    // A new block may arrive during broadcast; confirmation comes only from RefundPlan's canonical check.
    tx.execute("UPDATE kv SET json=?1 WHERE ns=?2 AND k=?3",(serde_json::to_string(&p)?,NS,id))?;
    tx.commit()?;Ok(summary(&p,false))
}

#[cfg(test)] mod tests {
    use super::*;
    fn a()->Value{json!({"conditional_liability":{"normal_failure_remaining_before_future_fees_zat":90000,"project_fault_remaining_before_future_fees_zat":100000}})}
    #[test] fn normal_and_project_fault_do_not_double_charge_network_costs(){
        assert_eq!(amounts(&a(),"normal").unwrap(),(90000,80000));
        assert_eq!(amounts(&a(),"project-fault").unwrap(),(110000,100000));
        assert!(amounts(&a(),"other").is_err());
        let mut v=a();v["conditional_liability"]["normal_failure_remaining_before_future_fees_zat"]=json!(10545);assert!(amounts(&v,"normal").is_err());
        v["conditional_liability"]["project_fault_remaining_before_future_fees_zat"]=json!(u64::MAX);assert!(amounts(&v,"project-fault").is_err());
    }
    #[test] fn reserve_cannot_borrow_invoice_or_inscription_funds(){
        let db=rusqlite::Connection::open_in_memory().unwrap();db.execute_batch("CREATE TABLE kv(ns TEXT,k TEXT,json TEXT);").unwrap();
        let u=Utxo{txid:"11".repeat(32),n:0,value:110000,script:"76".into(),height:2};
        let insert=|v:Value|{db.execute("DELETE FROM kv",[]).unwrap();db.execute("INSERT INTO kv VALUES('orders','a',?1)",[v.to_string()]).unwrap();};
        insert(json!({"invoice_address":"invoice","quote":{"fee_address":"fee","pay":"pay"}}));
        for address in ["invoice","fee","pay"] {assert!(reserve_is_independent(&db,address,&u).is_err());}
        reserve_is_independent(&db,"reserve",&u).unwrap();
        insert(json!({"invoice_address":"invoice","receipts":{format!("{}:0",u.txid):u}}));assert!(reserve_is_independent(&db,"reserve",&u).is_err());
        insert(json!({"invoice_address":"invoice","mint_plan":{"funding":[u]}}));assert!(reserve_is_independent(&db,"reserve",&u).is_err());
        let mut other=u.clone();other.n=1;insert(json!({"invoice_address":"invoice","mint_plan":{"funding":[other]}}));reserve_is_independent(&db,"reserve",&u).unwrap();
        insert(json!({"invoice_address":"invoice","mint_plan":{"transactions":[{"txid":u.txid}]}}));assert!(reserve_is_independent(&db,"reserve",&u).is_err());
    }
    #[test] fn own_case_refund_and_destination_still_cannot_supply_the_reserve(){
        let o=json!({"refund_address":"refund","dest":"recipient"});
        case_reserve_is_independent("reserve",&o).unwrap();
        assert!(case_reserve_is_independent("refund",&o).is_err());
        assert!(case_reserve_is_independent("recipient",&o).is_err());
    }
    #[test] fn unrelated_user_entered_addresses_cannot_quarantine_project_reserve(){
        let db=rusqlite::Connection::open_in_memory().unwrap();db.execute_batch("CREATE TABLE kv(ns TEXT,k TEXT,json TEXT);").unwrap();
        let u=Utxo{txid:"11".repeat(32),n:0,value:110000,script:"76".into(),height:2};
        db.execute("INSERT INTO kv VALUES('orders','foreign',?1)",[json!({"invoice_address":"actual-invoice","dest":"reserve","refund_address":"reserve","quote":{"pay":"collection","fee_address":"service"}}).to_string()]).unwrap();
        reserve_is_independent(&db,"reserve",&u).unwrap();
        assert!(reserve_is_independent(&db,"actual-invoice",&u).is_err());
        assert!(reserve_is_independent(&db,"collection",&u).is_err());
    }
    #[test] fn altered_liability_cannot_reprice_a_saved_transaction(){
        let v=a();same_money(&v,&v).unwrap();let mut changed=v.clone();changed["conditional_liability"]["normal_failure_remaining_before_future_fees_zat"]=json!(90001);assert!(same_money(&v,&changed).is_err());
    }
}
