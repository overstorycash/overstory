//! Local exceptional-case inventory. Not a chain audit, eligibility decision or payment instruction.
use crate::*;
use rusqlite::{Connection,OpenFlags};
use sha2::{Digest,Sha256};
use std::collections::BTreeSet;
fn digest(bytes:&[u8])->String {hex::encode(Sha256::digest(bytes))}
fn command(name:&str,id:&str)->Value {json!({"program":"proto","arguments":[name,id],"read_only":true,"may_require_rpc":true})}
fn describe(id:&str,raw:&str,net:index::Net,height:Option<u32>,barrier:bool,names:&BTreeSet<String>)->Value {
    // Current and legacy mintd invoice IDs are 8 random bytes. Unknown database keys
    // are represented by a fingerprint, never rendered as commands or key material.
    let valid_id=id.len()==16 && id.bytes().all(|b|b.is_ascii_hexdigit());
    let safe_id=if valid_id {Some(id)}else{None};let parsed=serde_json::from_str::<Value>(raw).ok();
    let o=parsed.as_ref().filter(|v|v.is_object());let mut reasons=Vec::<&str>::new();
    if !valid_id {reasons.push("invalid_order_key");}
    if barrier {reasons.push("chain_reconciliation_pending");}
    let mut checks=vec![];
    let mut result=json!({"order_id":safe_id,"order_key_sha256":digest(id.as_bytes()),"snapshot_sha256":digest(raw.as_bytes()),
        "authorizes_payment":false,"authorizes_resume":false,"financial_balance":null,"balance_state":"not_reconciled_here",
        "saved_state_is_historical":true,"local_records":names});
    let Some(o)=o else {reasons.push("invalid_order_record");result["review_reasons"]=json!(reasons);result["attention_required"]=json!(true);result["next_read_only_checks"]=json!([]);return result;};
    if o["id"].as_str()!=Some(id){reasons.push("order_identity_mismatch");}
    let status=o["status"].as_str().unwrap_or("");
    let known=matches!(status,"awaiting_payment"|"paid"|"inscribing"|"done"|"expired"|"refunding"|"refunded"|"refund_pending_small"|"recovery_required"|"error");
    result["local_status"]=json!(if known {status}else{"unrecognized"});
    if !known {reasons.push("unknown_order_status");}
    if matches!(status,"recovery_required"|"error"){reasons.push("worker_requires_manual_review");}
    if status=="refund_pending_small" {reasons.push("small_balance_remains_owed");}
    let held=o["settlement_hold"]==true;result["settlement_hold"]=json!(held);
    if held || names.contains("service-settlements") {reasons.push("exceptional_settlement_remains_open");}
    if held!=names.contains("service-settlements") {reasons.push("hold_marker_record_mismatch");}
    let refund=o["refund_address"].as_str().filter(|a|parse_taddr_for(a,net.network_type()).is_ok());
    result["recorded_refund_address_valid_for_network"]=json!(refund.is_some());
    if refund.is_none(){reasons.push("missing_or_invalid_original_refund_address_do_not_substitute_nft_destination");}
    let quote=&o["quote"];let quoted=quote.is_object() && quote["version"]==1 && quote["network"]==net.name();
    result["basic_quote_fields_present"]=json!(quoted);
    if !quoted {reasons.push("missing_or_incompatible_frozen_quote");}
    if o["accounting_version"]!=1 || o["mint_journal_version"]!=1 {reasons.push("legacy_or_missing_payment_journal");}
    let mint=o.get("mint_plan").filter(|p|!p.is_null());
    result["saved_mint_present"]=json!(mint.is_some());
    if let Some(p)=mint {
        if serde_json::from_value::<inscribe::SignedInscription>(p.clone()).is_err(){reasons.push("malformed_saved_mint_preserve_original_bytes");}
        if p["transactions"].as_array().is_none_or(|v|v.len()!=2) || p["commit_vout"]!=0 || quote["inclusive"]!=true {
            reasons.push("nonstandard_service_plan_no_automatic_exceptional_settlement");
        }
    }
    let refunds=o["refunds"].as_array();result["saved_refund_count"]=json!(refunds.map(Vec::len));
    if refunds.is_none(){reasons.push("missing_or_malformed_refund_journal");}
    if let Some(refunds)=refunds {for r in refunds {
        if serde_json::from_value::<refund::RefundPlan>(r["plan"].clone()).is_err() {reasons.push("malformed_saved_refund_preserve_original_bytes");break;}
    }}
    let receipts=o["receipts"].as_object();result["recorded_receipt_count"]=json!(receipts.map(serde_json::Map::len));
    if receipts.is_none(){reasons.push("missing_or_malformed_receipt_journal");}
    if receipts.is_some_and(|v|v.len()>100){reasons.push("large_receipt_history_check_unallocated_inputs_before_batching");}
    if names.contains("service-settlement-late"){reasons.push("late_payment_case_requires_separate_reconciliation");}
    // These are diagnostic entry points only. Success of this inventory never makes
    // any plan executable, an amount payable, or a cached confirmation canonical.
    if valid_id && o["id"]==id {
        checks.push(command("audit-orders",id));
        if quoted && refund.is_some() && mint.is_some(){checks.push(command("audit-service-settlement",id));}
        if held && names.contains("service-settlement-payouts"){checks.push(command("audit-settlement-late",id));}
        match (o["payment_start_height"].as_u64().and_then(|h|u32::try_from(h).ok()),height) {
            (Some(start),Some(end)) if start<=end && end-start<2000=>checks.push(json!({"program":"proto","arguments":["audit-payment-history",id,start.to_string(),end.to_string()],"read_only":true,"may_require_rpc":true,"range_is_saved_index_only":true})),
            (Some(start),Some(end)) if start<=end=>reasons.push("history_exceeds_single_audit_range_manual_reconciliation_required"),
            _=>reasons.push("missing_or_invalid_history_range"),
        }
    }
    reasons.sort_unstable();reasons.dedup();
    result["attention_required"]=json!(!reasons.is_empty());result["review_reasons"]=json!(reasons);result["next_read_only_checks"]=json!(checks);result
}
pub fn report(path:&str,only:Option<&str>)->Result<Value> {
    let mut db=Connection::open_with_flags(path,OpenFlags::SQLITE_OPEN_READ_ONLY)?;let tx=db.transaction()?;
    let schema:String=tx.query_row("SELECT v FROM meta WHERE k='schema_version'",[],|r|r.get(0))?;
    anyhow::ensure!(schema == crate::index::SCHEMA_VERSION,"unsupported index schema");
    let network:String=tx.query_row("SELECT v FROM meta WHERE k='network'",[],|r|r.get(0))?;let net=index::Net::parse(&network)?;
    let height:Option<u32>=tx.query_row("SELECT v FROM meta WHERE k='height'",[],|r|r.get::<_,String>(0)).ok().and_then(|v|v.parse().ok());
    let barrier:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM meta WHERE k='reorg_pending')",[],|r|r.get(0))?;
    let mut query=tx.prepare("SELECT k,json FROM kv WHERE ns='orders' AND (?1 IS NULL OR k=?1) ORDER BY k LIMIT 10001")?;
    let rows=query.query_map([only],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?)))?.collect::<rusqlite::Result<Vec<_>>>()?;
    anyhow::ensure!(rows.len()<=10000,"inventory exceeds 10000 orders; choose one order ID");
    anyhow::ensure!(only.is_none() || !rows.is_empty(),"order not found");
    let mut cases=Vec::new();
    for (id,raw) in rows {
        let mut q=tx.prepare("SELECT ns FROM kv WHERE k=?1 AND ns IN ('service-settlements','service-settlement-payouts','service-settlement-recoveries','service-settlement-late')")?;
        let names=q.query_map([&id],|r|r.get::<_,String>(0))?.collect::<rusqlite::Result<BTreeSet<_>>>()?;
        cases.push(describe(&id,&raw,net,height,barrier,&names));
    }
    Ok(json!({"read_only":true,"rpc_requests":0,"keys_read":false,"authorizes_payment":false,"authorizes_resume":false,
        "network":network,"saved_index_height":height,"chain_reconciliation_pending":barrier,
        "scope":"local historical triage only; no current chain, spendability, complete discovery, refund ownership or external-payment proof",
        "operator_rules":["preserve database, original terms, signatures and reservations before intervention",
            "never repair eligibility by editing an order, changing its refund address or deleting a reservation",
            "reconcile canonical raw transactions and external/manual payments before any payout",
            "an unknown broadcast outcome requires original-transaction investigation, never a replacement payment",
            "mixed fault attribution, unsupported plans and uneconomic balances remain liabilities; use a separately reviewed procedure and budget",
            "a local hold does not revoke signatures or lock external wallets; this report does not pause a worker"],
        "orders":cases}))
}
#[cfg(test)] mod tests {
 use super::*;
 fn base()->Value{json!({"id":"0123456789abcdef","status":"awaiting_payment","quote":{"version":1,"network":"regtest","inclusive":true},"refund_address":Key::from_secret(&[1;32]).unwrap().address_string(index::Net::Regtest),"accounting_version":1,"mint_journal_version":1,"receipts":{},"refunds":[],"payment_start_height":10})}
 #[test] fn legacy_terms_never_infer_refund_from_nft_destination(){let mut o=base();o["dest"]=o["refund_address"].take();o["quote"]=Value::Null;let v=describe("0123456789abcdef",&o.to_string(),index::Net::Regtest,Some(20),false,&BTreeSet::new());assert_eq!(v["recorded_refund_address_valid_for_network"],false);assert!(v["attention_required"]==true);assert!(v["financial_balance"].is_null());assert!(!v.to_string().contains(o["dest"].as_str().unwrap()));}
 #[test] fn bad_fields_and_keys_are_not_echoed_as_commands_or_private_material(){let mut o=base();o["status"]=json!("secret-sentinel");o["error"]=json!("private-key-sentinel");o["mint_plan"]=json!({"raw":"signed-bytes-sentinel"});let v=describe("private-key-sentinel",&o.to_string(),index::Net::Regtest,Some(20),false,&BTreeSet::new());assert!(v["order_id"].is_null());assert_eq!(v["next_read_only_checks"],json!([]));for secret in ["secret-sentinel","private-key-sentinel","signed-bytes-sentinel"] {assert!(!v.to_string().contains(secret));}}
 #[test] fn small_balances_and_inconsistent_holds_stay_open(){let mut o=base();o["status"]=json!("refund_pending_small");o["settlement_hold"]=json!(true);let v=describe("0123456789abcdef",&o.to_string(),index::Net::Regtest,Some(2010),true,&BTreeSet::new());let reasons=v["review_reasons"].as_array().unwrap();for reason in ["small_balance_remains_owed","hold_marker_record_mismatch","chain_reconciliation_pending","history_exceeds_single_audit_range_manual_reconciliation_required"]{assert!(reasons.contains(&json!(reason)));}assert_eq!(v["authorizes_resume"],false);assert_eq!(v["authorizes_payment"],false);}
}
