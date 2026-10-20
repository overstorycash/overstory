//! Read-only evidence for manual recovery. Never signs, broadcasts, or changes orders.
use crate::inscribe::SignedInscription;
use crate::refund::{RefundConfirmation, RefundPlan};
use crate::*;
use rusqlite::{Connection, OpenFlags};
#[derive(Deserialize)]
struct SavedRefund {
    plan: RefundPlan,
    confirmation: Option<RefundConfirmation>,
}
#[derive(Deserialize)]
struct SavedOrder {
    id: String,
    status: String,
    dest: String,
    #[serde(default)]
    refund_address: Option<String>,
    #[serde(default)]
    mint_plan: Option<SignedInscription>,
    #[serde(default)]
    refunds: Vec<SavedRefund>,
    #[serde(default)]
    accounting_version: u32,
}
/// Only reads. Missing is not authorization to replace or rebroadcast a transaction.
pub(crate) fn transaction(rpc: &Rpc, id: &str, raw: &str) -> Result<Value> {
    let v = match rpc.call("getrawtransaction", json!([id, 1])) {
        Ok(v) => v,
        Err(e)
            if e.downcast_ref::<RpcCallError>()
                .is_some_and(|e| e.code == -5) =>
        {
            return Ok(json!({"txid":id,"state":"missing"}));
        }
        Err(_) => return Ok(json!({"txid":id,"state":"lookup_unavailable"})),
    };
    describe_transaction(rpc,id,raw,&v)
}
fn describe_transaction(rpc:&Rpc,id:&str,raw:&str,v:&Value)->Result<Value> {
    let bytes = v["hex"].as_str().context("missing transaction bytes")?;
    if hex::decode(bytes)? != hex::decode(raw)? {
        return Ok(json!({"txid":id,"state":"bytes_mismatch"}));
    }
    // Zebra may omit confirmations for a mempool transaction. Omission alone
    // is not evidence: require matching bytes above and explicit mempool membership.
    let conf = if v.get("confirmations").is_none() && v["blockhash"].is_null() {
        let pool=rpc.call("getrawmempool",json!([]))?;
        if !pool.as_array().context("invalid mempool response")?.iter().any(|x|x.as_str()==Some(id)) {
            return Ok(json!({"txid":id,"state":"lookup_unavailable"}));
        }
        0
    }else{v["confirmations"].as_i64().context("missing/invalid confirmations")?};
    if conf <= 0 {
        return Ok(json!({"txid":id,"state":if conf<0 {"noncanonical"} else {"unconfirmed"}}));
    }
    let hash = v["blockhash"]
        .as_str()
        .context("missing confirmation block")?;
    let block = rpc.call("getblock", json!([hash, 1]))?;
    let height = u32::try_from(block["height"].as_u64().context("missing block height")?)?;
    let member = block["tx"]
        .as_array()
        .context("missing block transaction list")?
        .iter()
        .any(|x| x.as_str() == Some(id));
    anyhow::ensure!(
        member,
        "transaction is absent from reported confirmation block"
    );
    let canonical = rpc.call("getblockhash", json!([height]))?.as_str() == Some(hash);
    Ok(
        json!({"txid":id,"state":if canonical {"confirmed"}else{"noncanonical"},"height":height,"block_hash":hash}),
    )
}
/// Verify a previously observed invoice output even after it has been spent.
/// Historical observation is never silently converted into canonical received funds.
pub fn receipt(rpc:&Rpc,u:&Utxo,invoice:&str)->Result<Value> {
    let v=match rpc.call("getrawtransaction",json!([u.txid,1])) {
        Ok(v)=>v,
        Err(e) if e.downcast_ref::<RpcCallError>().is_some_and(|x|x.code == -5)=>return Ok(json!({"txid":u.txid,"state":"missing"})),
        Err(_)=>return Ok(json!({"txid":u.txid,"state":"lookup_unavailable"})),
    };
    let raw=v["hex"].as_str().context("receipt has no raw transaction")?;
    let bytes=hex::decode(raw)?;let mut cursor=std::io::Cursor::new(&bytes);
    let tx=Transaction::read(&mut cursor,rpc.net().branch_for(u.height.max(1)))?;
    let expected=index::script_bytes(&parse_taddr_for(invoice,rpc.net().network_type())?.script().into());
    let actual=tx.transparent_bundle().and_then(|b|b.vout.get(u.n as usize));
    if cursor.position() as usize!=bytes.len() || tx.txid().to_string()!=u.txid || hex::decode(&u.script)?!=expected
        || !actual.is_some_and(|out|out.value().into_u64()==u.value && index::script_bytes(out.script_pubkey())==expected) {
        return Ok(json!({"txid":u.txid,"state":"invalid_receipt"}));
    }
    describe_transaction(rpc,&u.txid,raw,&v)
}
fn checked_transaction(rpc: &Rpc, id: &str, raw: &str) -> Value {
    transaction(rpc, id, raw)
        .unwrap_or_else(|_| json!({"txid":id,"state":"verification_unavailable"}))
}
fn inspect(rpc: &Rpc, key: &str, row: &str, tip: u32) -> Value {
    let Ok(o) = serde_json::from_str::<SavedOrder>(row) else {
        return json!({"order_id":key,"issues":["invalid_order_record"]});
    };
    let mut issues = vec![];
    let mut transactions = vec![];
    if o.id != key {
        issues.push("order_id_mismatch");
    }
    if o.accounting_version != 1 {
        issues.push("legacy_accounting_unavailable");
    }
    if let Some(p) = &o.mint_plan {
        if p.destination != o.dest || p.validate(rpc).is_err() {
            issues.push("invalid_mint_plan");
        } else {
            for t in &p.transactions {
                let mut v = checked_transaction(rpc, &t.txid, &t.raw);
                v["kind"] = json!("mint");
                v["expired_for_next_block"] = json!(tip.saturating_add(1) > p.expiry_height);
                transactions.push(v);
            }
        }
    }
    for r in &o.refunds {
        if r.plan.destination != o.refund_address.as_deref().unwrap_or(&o.dest) || r.plan.validate(rpc).is_err() {
            issues.push("invalid_refund_plan");
            continue;
        }
        let mut v = checked_transaction(rpc, &r.plan.txid, &r.plan.raw_transaction);
        v["kind"] = json!("refund");
        v["expired_for_next_block"] = json!(tip.saturating_add(1) > r.plan.expiry_height);
        if let Some(c) = &r.confirmation {
            if v["state"] != "confirmed"
                || v["height"] != json!(c.height)
                || v["block_hash"] != json!(c.block_hash)
            {
                issues.push("saved_refund_confirmation_changed");
            }
        }
        transactions.push(v);
    }
    if o.status == "done" && o.mint_plan.is_none() {
        issues.push("completed_mint_missing_plan");
    }
    if o.status == "refunded" && o.refunds.is_empty() {
        issues.push("refunded_order_missing_plan");
    }
    if transactions
        .iter()
        .any(|v| !matches!(v["state"].as_str(), Some("confirmed" | "unconfirmed")))
    {
        issues.push("saved_transaction_requires_review");
    }
    if o.status == "done"
        && transactions
            .iter()
            .filter(|v| v["kind"] == "mint")
            .any(|v| v["state"] != "confirmed")
    {
        issues.push("completed_mint_not_confirmed");
    }
    json!({"order_id":key,"saved_status":o.status,"issues":issues,"transactions":transactions})
}
/// A consistent DB read snapshot plus a stable node tip; this is not a financial audit.
pub fn orders(rpc: &Rpc, path: &str, only: Option<&str>) -> Result<Value> {
    let mut db = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let snapshot = db.transaction()?;
    let schema: String =
        snapshot.query_row("SELECT v FROM meta WHERE k='schema_version'", [], |r| {
            r.get(0)
        })?;
    anyhow::ensure!(schema == crate::index::SCHEMA_VERSION, "unsupported index schema");
    let meta = |key: &str| -> Result<String> {
        Ok(snapshot.query_row("SELECT v FROM meta WHERE k=?1", [key], |r| r.get(0))?)
    };
    let network = meta("network")?;
    anyhow::ensure!(network == rpc.net().name(), "index network mismatch");
    let indexed: u32 = meta("height")?.parse()?;
    let indexed_hash = meta("tip_hash")?;
    let rows: Vec<(String, String)> = {
        let mut q = snapshot.prepare(
            "SELECT k,json FROM kv WHERE ns='orders' AND (?1 IS NULL OR k=?1) ORDER BY k",
        )?;
        q.query_map([only], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<rusqlite::Result<_>>()?
    };
    snapshot.commit()?;
    anyhow::ensure!(only.is_none() || !rows.is_empty(), "order not found");
    let tip = rpc.checked_target()? - 1;
    let hash = rpc.call("getblockhash", json!([tip]))?;
    let index_state = if indexed > tip {
        "ahead_of_node"
    } else if rpc.call("getblockhash", json!([indexed]))?.as_str() != Some(indexed_hash.as_str()) {
        "noncanonical"
    } else if indexed < tip {
        "behind"
    } else {
        "canonical"
    };
    let result: Vec<_> = rows.iter().map(|(k, v)| inspect(rpc, k, v, tip)).collect();
    anyhow::ensure!(
        rpc.checked_target()? - 1 == tip && rpc.call("getblockhash", json!([tip]))? == hash,
        "chain changed during audit; discard report and retry"
    );
    Ok(
        json!({"read_only":true,"authorizes_resume":false,"scope":"saved transaction confirmations, not complete payment history or NFT membership","network":network,"at_height":tip,"at_hash":hash,"index_state":index_state,"index_height":indexed,"orders":result}),
    )
}
