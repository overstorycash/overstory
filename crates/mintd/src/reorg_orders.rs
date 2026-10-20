//! Reconcile saved confirmations after an index rollback, before the worker may spend.
//! This pass is read-only on-chain: uncertain orders are quarantined, never re-signed.
use super::*;
use serde_json::Value;

fn hold(o:&mut Order,reason:&str) {
    o.status="recovery_required".into();o.error=Some(reason.into());o.retry_after=0;o.attempts=0;
}
fn checked_state(v:&Value)->Result<&str> {
    let state=v["state"].as_str().context("missing reconciliation state")?;
    anyhow::ensure!(!matches!(state,"lookup_unavailable"|"verification_unavailable"),"node evidence unavailable; reorg barrier retained");
    Ok(state)
}
/// Only derive statuses and confirmation metadata. Signed plans, receipts and amounts stay intact.
fn reconcile_order(o:&mut Order,evidence:&Value,receipts:&[Value],index:&Index)->Result<()> {
    let was_held=o.settlement_hold || matches!(o.status.as_str(),"recovery_required"|"error");
    let transactions=evidence["transactions"].as_array();
    let issues=evidence["issues"].as_array().context("missing order issues")?;
    if let Some(ts)=transactions {for t in ts {checked_state(t)?;}}
    let mut receipts_confirmed=true;
    for receipt in receipts {receipts_confirmed &= checked_state(receipt)?=="confirmed";}
    o.number=None;o.seed=None;
    for refund in &mut o.refunds {
        let record=transactions.and_then(|ts|ts.iter().find(|t|t["kind"]=="refund" && t["txid"]==refund.plan.txid));
        refund.confirmation=match record.filter(|r|r["state"]=="confirmed") {
            Some(r)=>Some(proto::refund::RefundConfirmation {height:u32::try_from(r["height"].as_u64().context("refund height missing")?)?,block_hash:r["block_hash"].as_str().context("refund hash missing")?.into()}),
            None=>None,
        };
    }
    let invalid=issues.iter().any(|v|matches!(v.as_str(),Some("invalid_order_record"|"order_id_mismatch"|"invalid_mint_plan"|"invalid_refund_plan"|"legacy_accounting_unavailable"|"completed_mint_missing_plan"|"refunded_order_missing_plan")));
    if invalid || !receipts_confirmed || receipts.len()!=o.receipts.len() {
        hold(o,"reorg changed or invalidated saved payment evidence; reconcile manually");return Ok(());
    }
    let totals=match ledger(o) {Ok(v)=>v,Err(_)=>{hold(o,"reorg accounting validation failed; reconcile manually");return Ok(());}};
    if was_held {hold(o,"previous hold remains after reorg; manual review required");return Ok(());}
    if let Some(plan)=&o.mint_plan {
        let confirmed=plan.transactions.iter().all(|saved|transactions.is_some_and(|ts|ts.iter().any(|t|t["kind"]=="mint" && t["txid"]==saved.txid && t["state"]=="confirmed")));
        if let Some(m)=index.mints.get(&plan.result.inscription_id).filter(|_|confirmed) {
            o.number=Some(m.number);o.seed=Some(m.seed.clone());o.status="done".into();o.error=None;
            if totals["unallocated_received_zat"]!=0 {hold(o,"mint confirmed after reorg but excess receipts need reconciliation");}
            if o.refunds.iter().any(|r|r.confirmation.is_none()) {hold(o,"mint remains valid but surplus refund confirmation changed; preserve refund plan for review");}
        } else {hold(o,"mint confirmation or membership changed after reorg; preserve original plan for review");}
    } else if !o.refunds.is_empty() {
        if o.refunds.iter().all(|r|r.confirmation.is_some()) && totals["unallocated_received_zat"]==0 {
            o.status="refunded".into();o.error=None;
        } else {hold(o,"refund confirmation or remaining balance changed after reorg; preserve original plan for review");}
    } else if o.paid_zat==0 && matches!(o.status.as_str(),"awaiting_payment"|"expired") {
        o.status=if now()<o.expires {"awaiting_payment"}else{"expired"}.into();o.error=None;
    } else {hold(o,"unsigned or legacy paid order requires review after reorg");}
    o.retry_after=0;o.attempts=0;
    Ok(())
}

pub(super) fn reconcile(shared:&Shared,rpc:&Rpc)->Result<()> {
    let (barrier,index,mut orders,expected)={
        let app=shared.lock().unwrap();
        let Some(barrier)=proto::reorg::pending(&app.db)? else{return Ok(());};
        (barrier,app.index.clone(),app.orders.clone(),app.db.kv_all::<Value>(NS_ORDERS)?)
    };
    let report=proto::audit::orders(rpc,proto::index::DB_FILE,None)?;
    anyhow::ensure!(report["index_state"]=="canonical" && report["at_height"]==index.height && report["at_hash"].as_str()==index.tip_hash.as_deref(),"reorg index is not current; barrier retained");
    let evidence=report["orders"].as_array().context("missing order audit")?;
    anyhow::ensure!(evidence.len()==orders.len(),"order set changed during recovery");
    for (id,o) in &mut orders {
        let row=evidence.iter().find(|r|r["order_id"]==*id).context("order missing from audit")?;
        let receipts=o.receipts.values().map(|u|proto::audit::receipt(rpc,u,&o.invoice_address)).collect::<Result<Vec<_>>>()?;
        reconcile_order(o,row,&receipts,&index)?;
    }
    // Discard every tentative update if even the final chain identity has changed.
    anyhow::ensure!(rpc.checked_target()? - 1==index.height && rpc.call("getblockhash",json!([index.height]))?.as_str()==index.tip_hash.as_deref(),"chain changed during reorg order reconciliation");
    let mut app=shared.lock().unwrap();
    anyhow::ensure!(app.index.height==index.height && app.index.tip_hash==index.tip_hash,"index changed during reorg order reconciliation");
    anyhow::ensure!(serde_json::to_value(proto::reorg::pending(&app.db)?)?==serde_json::to_value(Some(&barrier))?,"reorg barrier changed");
    let updates=orders.iter().map(|(k,v)|Ok((k.clone(),serde_json::to_value(v)?))).collect::<Result<BTreeMap<_,_>>>()?;
    proto::reorg::commit_reconciliation(&mut app.db,&barrier,index.height,index.tip_hash.as_deref().context("missing index hash")?,&expected,&updates,&report)?;
    app.orders=orders;app.export_dirty=true;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture(refund:bool)->Order {
        let u=Utxo {txid:"11".repeat(32),n:0,script:"76".into(),value:30000,height:1};
        let mut o:Order=serde_json::from_value(json!({"id":"fixture","dest":"dest","refund_address":"refund","invoice_address":"invoice","amount_zat":30000,"created":1,"expires":u64::MAX,"status":if refund {"refunded"}else{"done"},"paid_zat":30000,"inscription_id":"item","txids":["saved"],"number":7,"seed":"old","error":null,"mint_journal_version":1,"accounting_version":1})).unwrap();
        o.receipts.insert(point(&u),u.clone());
        if refund {
            o.refund_mode=true;
            o.refunds.push(RefundRecord {plan:proto::refund::RefundPlan {version:1,network:"regtest".into(),genesis_hash:"11".repeat(32),target_height:2,expiry_height:42,destination:"refund".into(),input_zat:30000,refund_zat:20000,fee_zat:10000,funding:vec![u],txid:"saved".into(),raw_transaction:"original-signed-refund".into()},confirmation:Some(proto::refund::RefundConfirmation {height:2,block_hash:"old".into()})});
        } else {
            o.mint_plan=Some(proto::inscribe::SignedInscription {version:1,network:"regtest".into(),genesis_hash:"11".repeat(32),target_height:2,expiry_height:42,destination:"dest".into(),commit_vout:0,funding:vec![u],transactions:vec![proto::inscribe::SignedTransaction {txid:"saved".into(),raw:"original-signed-mint".into()}],result:proto::inscribe::InscribeResult {commit_txid:"saved".into(),reveal_txids:vec!["saved".into()],inscription_id:"item".into(),total_cost:30000}});
        }
        o
    }
    fn evidence(kind:&str,state:&str)->Value {json!({"issues":[],"transactions":[{"kind":kind,"state":state,"txid":"saved","height":9,"block_hash":"new"}]})}
    #[test]
    fn canonical_mint_updates_number_and_seed_without_changing_plan() {
        let mut o=fixture(false);let saved=serde_json::to_value(&o.mint_plan).unwrap();let mut index=Index::default();
        index.mints.insert("item".into(),proto::index::Mint {inscription:"item".into(),collection:"collection".into(),number:3,minter:"dest".into(),height:9,seed:"new-seed".into()});
        reconcile_order(&mut o,&evidence("mint","confirmed"),&[json!({"state":"confirmed"})],&index).unwrap();
        assert_eq!(o.status,"done");assert_eq!(o.number,Some(3));assert_eq!(o.seed.as_deref(),Some("new-seed"));assert_eq!(serde_json::to_value(&o.mint_plan).unwrap(),saved);
        for state in ["missing","unconfirmed","noncanonical"] {
            let mut affected=fixture(false);
            reconcile_order(&mut affected,&evidence("mint",state),&[json!({"state":"confirmed"})],&index).unwrap();
            assert_eq!(affected.status,"recovery_required");assert!(affected.number.is_none());assert!(affected.seed.is_none());assert_eq!(serde_json::to_value(&affected.mint_plan).unwrap(),saved);
        }
        let mut rejected=fixture(false);reconcile_order(&mut rejected,&evidence("mint","confirmed"),&[json!({"state":"confirmed"})],&Index::default()).unwrap();assert_eq!(rejected.status,"recovery_required");
    }
    #[test]
    fn refund_reconfirmation_moves_metadata_but_missing_confirmation_preserves_reservation() {
        let mut o=fixture(true);let saved=serde_json::to_value(&o.refunds[0].plan).unwrap();
        reconcile_order(&mut o,&evidence("refund","confirmed"),&[json!({"state":"confirmed"})],&Index::default()).unwrap();
        assert_eq!(o.status,"refunded");assert_eq!(o.refunds[0].confirmation.as_ref().unwrap().height,9);
        assert_eq!(ledger(&o).unwrap()["refund_confirmed_zat"],20000);
        reconcile_order(&mut o,&evidence("refund","missing"),&[json!({"state":"confirmed"})],&Index::default()).unwrap();
        assert_eq!(o.status,"recovery_required");assert!(o.refunds[0].confirmation.is_none());assert_eq!(ledger(&o).unwrap()["refund_confirmed_zat"],0);assert_eq!(ledger(&o).unwrap()["refund_pending_input_zat"],30000);
        assert_eq!(serde_json::to_value(&o.refunds[0].plan).unwrap(),saved);
    }
    #[test]
    fn unavailable_evidence_aborts_and_old_holds_or_orphan_receipts_never_resume() {
        let mut o=fixture(true);let original=serde_json::to_value(&o).unwrap();
        assert!(reconcile_order(&mut o,&evidence("refund","lookup_unavailable"),&[json!({"state":"confirmed"})],&Index::default()).is_err());assert_eq!(serde_json::to_value(&o).unwrap(),original);
        assert!(reconcile_order(&mut o,&evidence("refund","confirmed"),&[json!({"state":"verification_unavailable"})],&Index::default()).is_err());assert_eq!(serde_json::to_value(&o).unwrap(),original);
        for state in ["missing","invalid_receipt"] {
            let mut changed=fixture(true);reconcile_order(&mut changed,&evidence("refund","confirmed"),&[json!({"state":state})],&Index::default()).unwrap();assert_eq!(changed.status,"recovery_required");
        }
        o.status="recovery_required".into();reconcile_order(&mut o,&evidence("refund","confirmed"),&[json!({"state":"confirmed"})],&Index::default()).unwrap();assert_eq!(o.status,"recovery_required");
    }
    #[test]
    fn delivered_mint_does_not_unpause_orphaned_surplus_refund() {
        let mut base=fixture(false);let mut refund=fixture(true).refunds.remove(0);
        refund.plan.funding[0].n=1;refund.plan.txid="surplus".into();
        base.receipts.insert(point(&refund.plan.funding[0]),refund.plan.funding[0].clone());base.paid_zat+=30000;base.refunds.push(refund);
        let original=serde_json::to_value(&base.refunds[0].plan).unwrap();
        let mut index=Index::default();index.mints.insert("item".into(),proto::index::Mint {inscription:"item".into(),collection:"collection".into(),number:1,minter:"dest".into(),height:9,seed:"new".into()});
        for state in ["confirmed","missing","unconfirmed","noncanonical"] {
            let mut o=base.clone();let mut e=evidence("mint","confirmed");
            e["transactions"].as_array_mut().unwrap().push(json!({"kind":"refund","state":state,"txid":"surplus","height":9,"block_hash":"new"}));
            reconcile_order(&mut o,&e,&[json!({"state":"confirmed"}),json!({"state":"confirmed"})],&index).unwrap();
            assert_eq!(o.status,if state=="confirmed" {"done"} else {"recovery_required"});
            assert_eq!(serde_json::to_value(&o.refunds[0].plan).unwrap(),original);
            assert_eq!(ledger(&o).unwrap()["refund_pending_input_zat"],if state=="confirmed" {0}else{30000});
        }
    }

}
