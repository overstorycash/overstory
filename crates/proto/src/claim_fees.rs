//! Canonical fee evidence and explicitly prepared, immutable project compensation.
//! The audit endpoint is read-only; signing and broadcasting use separate commands.
use super::*;
use std::collections::BTreeSet;

fn add(a: u64, b: u64) -> Result<u64> {
    let n = a.checked_add(b).context("fee accounting overflow")?;
    zat(n)?;
    Ok(n)
}
fn fee(inputs: u64, mut outputs: impl Iterator<Item = u64>) -> Result<u64> {
    let total = outputs.try_fold(0, add)?;
    let n = inputs
        .checked_sub(total)
        .context("outputs exceed proven inputs")?;
    zat(n)?;
    Ok(n)
}
fn fetch(rpc: &Rpc, id: &str, height: u32) -> Result<(Transaction, Value)> {
    let raw = rpc.call("getrawtransaction", json!([id, 0]))?;
    let raw = raw.as_str().context("missing fee transaction")?;
    let bytes = hex::decode(raw)?;
    let mut cur = std::io::Cursor::new(&bytes);
    let tx = Transaction::read(&mut cur, rpc.net().branch_for(height))?;
    anyhow::ensure!(
        cur.position() as usize == bytes.len() && tx.txid().to_string() == id,
        "fee transaction identity mismatch"
    );
    let proof = audit::transaction(rpc, id, raw)?;
    anyhow::ensure!(
        proof["state"] == "confirmed",
        "fee transaction is not canonical"
    );
    Ok((tx, proof))
}
fn transparent(tx: &Transaction) -> Result<()> {
    anyhow::ensure!(
        tx.sapling_bundle().is_none()
            && tx.orchard_bundle().is_none()
            && tx.sprout_bundle().is_none(),
        "fee audit requires transparent-only mint transactions"
    );
    Ok(())
}
fn parent_id(
    input: &zcash_transparent::bundle::TxIn<zcash_transparent::bundle::Authorized>,
) -> String {
    let mut id = *input.prevout().hash();
    id.reverse();
    hex::encode(id)
}

fn basis(rpc: &Rpc, id: &str) -> Result<Value> {
    let mut db =
        Connection::open_with_flags(index::DB_FILE, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let snap = db.transaction()?;
    no_reorg(&snap)?;
    let st = index::Db::load_from(&snap)?;
    anchor(rpc, &st)?;
    let raw: String = snap.query_row(
        "SELECT json FROM kv WHERE ns='self-mint-refunds' AND k=?1",
        [id],
        |r| r.get(0),
    )?;
    let r: Record = serde_json::from_str(&raw)?;
    anyhow::ensure!(r.claim.inscription == id, "claim record identity mismatch");
    let e = verify(rpc, &st, &r.claim)?;
    unmanaged_claim(&snap, id)?;
    unrelated_inputs(&snap, &e.receipts)?;
    anyhow::ensure!(
        serde_json::to_value(&e.receipts)? == serde_json::to_value(&r.receipts)?,
        "saved receipts differ from canonical payment"
    );
    for u in &e.receipts {
        let owner: String = snap.query_row(
            "SELECT json FROM kv WHERE ns='self-mint-refund-inputs' AND k=?1",
            [format!("{}:{}", u.txid, u.n)],
            |r| r.get(0),
        )?;
        anyhow::ensure!(
            serde_json::from_str::<String>(&owner)? == id,
            "refund reservation differs"
        );
    }
    let ins = st.inscriptions.get(id).context("missing inscription")?;
    let genesis = id
        .strip_suffix("i0")
        .context("unsupported claim identity")?;
    let claimant: Script =
        TransparentAddress::PublicKeyHash(inscribe::hash160(&hex::decode(&r.claim.public_key)?))
            .script()
            .into();
    let mut next = completion_txid(ins)?;
    let mut transactions = Vec::new();
    let mut total = 0;
    let mut commit = None;
    for _ in 0..64 {
        let (tx, proof) = fetch(rpc, &next, ins.completion_height)?;
        transparent(&tx)?;
        let b = tx.transparent_bundle().context("missing reveal bundle")?;
        anyhow::ensure!(b.vin.len() == 1, "fee audit requires single-input reveals");
        let input = &b.vin[0];
        let parent = parent_id(input);
        let (previous, _) = fetch(rpc, &parent, ins.completion_height)?;
        let output = previous
            .transparent_bundle()
            .and_then(|b| b.vout.get(input.prevout().n() as usize))
            .context("missing fee input")?;
        let amount = fee(
            output.value().into_u64(),
            b.vout.iter().map(|o| o.value().into_u64()),
        )?;
        total = add(total, amount)?;
        transactions
            .push(json!({"kind":"reveal","txid":next,"fee_zat":amount,"confirmation":proof}));
        if next == genesis {
            commit = Some((previous, parent, input.prevout().n()));
            break;
        }
        next = parent;
    }
    let (tx, commit_id, n) = commit.context("fee chain exceeds reveal bound")?;
    transparent(&tx)?;
    let b = tx.transparent_bundle().context("commit bundle missing")?;
    // A single committed output and only original-signer change: no shared/batched
    // commit fee can silently be charged to more than one claim.
    anyhow::ensure!(
        n == 0
            && (1..=2).contains(&b.vout.len())
            && (b.vout.len() == 1 || *b.vout[1].script_pubkey() == claimant),
        "shared/nonstandard commit requires manual fee allocation"
    );
    anyhow::ensure!(
        (1..=100).contains(&b.vin.len()),
        "unsupported commit input count"
    );
    let mut inputs = 0;
    let mut seen = BTreeSet::new();
    let mut funding = Vec::new();
    for input in &b.vin {
        let parent = parent_id(input);
        let n = input.prevout().n();
        anyhow::ensure!(seen.insert((parent.clone(), n)), "duplicate commit funding");
        let (tx, proof) = fetch(rpc, &parent, ins.genesis_height)?;
        let output = tx
            .transparent_bundle()
            .and_then(|b| b.vout.get(n as usize))
            .context("commit funding missing")?;
        anyhow::ensure!(
            *output.script_pubkey() == claimant,
            "commit funding not owned by original reveal signer"
        );
        inputs = add(inputs, output.value().into_u64())?;
        funding.push(
            json!({"txid":parent,"n":n,"value_zat":output.value().into_u64(),"confirmation":proof}),
        );
    }
    let amount = fee(inputs, b.vout.iter().map(|o| o.value().into_u64()))?;
    total = add(total, amount)?;
    transactions.push(json!({"kind":"commit","txid":commit_id,"fee_zat":amount,"funding":funding}));
    let (returned, refund_fee, refund_proof) = if let Some(p) = &r.plan {
        p.validate(rpc)?;
        if r.advance.is_some() {
            check_advance(&snap, rpc, &st, &r)?;
        } else {
            anyhow::ensure!(
                p.destination == r.claim.destination
                    && p.input_zat == r.claim.received_zat
                    && serde_json::to_value(&p.funding)? == serde_json::to_value(&r.receipts)?,
                "signed refund differs from claim"
            );
        }
        let proof = audit::transaction(rpc, &p.txid, &p.raw_transaction)?;
        let bytes = hex::decode(&p.raw_transaction)?;
        let parsed = Transaction::read(&bytes[..], rpc.net().branch_for(p.target_height))?;
        transparent(&parsed)?;
        anyhow::ensure!(
            proof["state"] == "confirmed",
            "signed refund unresolved; cannot estimate additional compensation"
        );
        (p.refund_zat, p.fee_zat, proof)
    } else {
        anyhow::ensure!(
            r.advance.is_none() && r.confirmation.is_none(),
            "refund metadata without plan"
        );
        (0, 0, Value::Null)
    };
    let outstanding = r
        .claim
        .received_zat
        .checked_sub(returned)
        .context("refund exceeds original receipt")?;
    // Release read snapshot before re-reading current state: concurrent index or
    // claim writes cannot be concealed by SQLite snapshot isolation.
    snap.commit()?;
    no_reorg(&db)?;
    let now = index::Db::load_from(&db)?;
    let current: String = db.query_row(
        "SELECT json FROM kv WHERE ns='self-mint-refunds' AND k=?1",
        [id],
        |r| r.get(0),
    )?;
    anyhow::ensure!(
        current == raw && serde_json::to_value(&now)? == serde_json::to_value(&st)?,
        "claim audit snapshot changed"
    );
    anchor(rpc, &st)?;
    Ok(
        json!({"read_only":true,"authorizes_payment":false,"inscription":id,"destination":r.claim.destination,
        "claim_record_sha256":hex::encode(Sha256::digest(raw.as_bytes())),"as_of_height":st.height,"as_of_hash":st.tip_hash,"received_zat":r.claim.received_zat,
        "confirmed_original_mint_network_fee_zat":total,"confirmed_returned_zat":returned,
        "confirmed_refund_network_fee_zat":refund_fee,"unreturned_receipt_zat":outstanding,
        "if_all_original_mint_fees_are_project_fault":{"remaining_receipt_and_fee_liability_zat":add(outstanding,total)?,"original_network_fee_compensation_zat":total},
        "refund_confirmation":refund_proof,"transactions":transactions,
        "limitations":["Conditional evidence only; operator must establish fault attribution and reconcile external/manual compensation before payment.","Does not reserve compensation or include future payout fees, funding-wallet fees, transfers, or NFT carrier value.","Shared/nonstandard commits require manual allocation; canonical status is as of this snapshot and trusts node consensus."]}),
    )
}

const NS: &str = "self-mint-compensations";
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Compensation {
    version: u32,
    inscription: String,
    reason: String,
    claim_digest: String,
    original_refund_txid: String,
    original_fee_zat: u64,
    reserve_address: String,
    plan: refund::RefundPlan,
    confirmation: Option<refund::RefundConfirmation>,
}
fn liability(a: &Value) -> Result<u64> {
    a["if_all_original_mint_fees_are_project_fault"]["remaining_receipt_and_fee_liability_zat"]
        .as_u64()
        .context("missing fee liability")
}
fn load_record(db: &Connection, id: &str) -> Result<Record> {
    let raw: String = db.query_row(
        "SELECT json FROM kv WHERE ns='self-mint-refunds' AND k=?1",
        [id],
        |r| r.get(0),
    )?;
    Ok(serde_json::from_str(&raw)?)
}
fn check_payment(
    db: &Connection,
    rpc: &Rpc,
    st: &index::State,
    r: &Record,
    a: &Value,
    p: &Compensation,
) -> Result<()> {
    anyhow::ensure!(
        p.version == 1
            && p.inscription == r.claim.inscription
            && p.claim_digest == hex::encode(r.claim.digest()?)
            && (1..=512).contains(&p.reason.trim().len()),
        "compensation attribution changed"
    );
    let refund = r
        .plan
        .as_ref()
        .context("original refund must be confirmed first")?;
    anyhow::ensure!(
        p.original_refund_txid == refund.txid
            && a["refund_confirmation"]["txid"] == refund.txid
            && p.original_fee_zat
                == a["confirmed_original_mint_network_fee_zat"]
                    .as_u64()
                    .context("missing mint fees")?,
        "compensation evidence changed"
    );
    let n = liability(a)?;
    p.plan.validate(rpc)?;
    anyhow::ensure!(
        p.plan.destination == r.claim.destination
            && p.plan.refund_zat == n
            && p.plan.input_zat == add(n, 10000)?
            && p.plan.fee_zat == 10000
            && p.plan.funding.len() == 1,
        "compensation plan differs from proven liability"
    );
    let u = &p.plan.funding[0];
    check_reserve_source(db, rpc.net(), st, r, &p.reserve_address, u)?;
    let point = format!("{}:{}", u.txid, u.n);
    let owner: String = db.query_row(
        "SELECT json FROM kv WHERE ns='self-mint-refund-inputs' AND k=?1",
        [&point],
        |r| r.get(0),
    )?;
    anyhow::ensure!(
        serde_json::from_str::<String>(&owner)? == r.claim.inscription,
        "compensation reservation changed"
    );
    let conflict:bool=db.query_row("SELECT EXISTS(SELECT 1 FROM kv WHERE k=?1 AND ns IN ('reclaim-inputs','service-settlement-inputs'))",[&point],|r|r.get(0))?;
    anyhow::ensure!(!conflict, "compensation source overlaps another workflow");
    anyhow::ensure!(
        audit::receipt(rpc, u, &p.reserve_address)?["state"] == "confirmed",
        "compensation source is not canonical"
    );
    let raw: String = db.query_row(
        "SELECT json FROM kv WHERE ns='operator-actions' AND k=?1",
        [format!("self-mint-compensation:{}", p.inscription)],
        |r| r.get(0),
    )?;
    let action: Value = serde_json::from_str(&raw)?;
    anyhow::ensure!(
        action
            == json!({"inscription":p.inscription,"reason":p.reason,"source":point,"scope":"all-original-mint-fees-project-fault","external_payments_reconciled":true,"broadcast":false}),
        "compensation operator action changed"
    );
    Ok(())
}
fn response(p: &Compensation, cached: bool) -> Value {
    json!({"inscription":p.inscription,"destination":p.plan.destination,"txid":p.plan.txid,
        "compensation_zat":p.plan.refund_zat,"project_payout_fee_zat":p.plan.fee_zat,
        "confirmation":p.confirmation,"confirmation_is_cached":cached,
        "status":if p.confirmation.is_some(){"compensation_confirmed"}else{"signed_compensation_pending"},
        "scope":"Only the recorded self-mint claim and all-original-fees fault attribution; no global case closure."})
}
pub(super) fn report(rpc: &Rpc, id: &str) -> Result<Value> {
    let mut a = basis(rpc, id)?;
    let db =
        Connection::open_with_flags(index::DB_FILE, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let raw: Option<String> = db
        .query_row(
            "SELECT json FROM kv WHERE ns=?1 AND k=?2",
            params![NS, id],
            |r| r.get(0),
        )
        .optional()?;
    a["confirmed_separate_compensation_zat"] = json!(0);
    a["conditional_remaining_after_recorded_compensation_zat"] = json!(liability(&a)?);
    if let Some(raw) = raw {
        let p: Compensation = serde_json::from_str(&raw)?;
        let claim_raw: String = db.query_row(
            "SELECT json FROM kv WHERE ns='self-mint-refunds' AND k=?1",
            [id],
            |r| r.get(0),
        )?;
        anyhow::ensure!(
            json!(hex::encode(Sha256::digest(claim_raw.as_bytes()))) == a["claim_record_sha256"],
            "claim changed after fee audit"
        );
        let r = load_record(&db, id)?;
        let st = index::Db::load_from(&db)?;
        no_reorg(&db)?;
        anyhow::ensure!(
            json!(st.height) == a["as_of_height"] && json!(st.tip_hash) == a["as_of_hash"],
            "claim audit snapshot changed"
        );
        check_payment(&db, rpc, &st, &r, &a, &p)?;
        let proof = audit::transaction(rpc, &p.plan.txid, &p.plan.raw_transaction)?;
        a["separate_compensation_confirmation"] = proof.clone();
        if proof["state"] == "confirmed" {
            a["confirmed_separate_compensation_zat"] = json!(p.plan.refund_zat);
            a["conditional_remaining_after_recorded_compensation_zat"] = json!(0);
        }
        anchor(rpc, &st)?;
    }
    Ok(a)
}
pub(super) fn command(rpc: &Rpc, args: &[String]) -> Result<Value> {
    let preparing = args[0] == "refund-claim-compensation-plan";
    anyhow::ensure!(
        args.len() == if preparing { 6 } else { 2 },
        "usage: refund-claim-compensation-plan <inscription> <reserve-key> <txid:n> <reason> <external-payments-reconciled> | refund-claim-compensation-resume <inscription>"
    );
    if preparing {
        anyhow::ensure!(
            args[5] == "external-payments-reconciled",
            "reconcile external/manual payments before preparing compensation"
        );
    }
    let id = &args[1];
    let a = basis(rpc, id)?;
    anyhow::ensure!(
        a["refund_confirmation"]["state"] == "confirmed",
        "confirm original receipt refund before separate compensation"
    );
    let n = liability(&a)?;
    anyhow::ensure!(n >= CARRIER_ZAT, "small compensation remains unpaid");
    let mut db = index::Db::open(index::DB_FILE)?;
    let tx = db
        .conn
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    no_reorg(&tx)?;
    let st = index::Db::load_from(&tx)?;
    anyhow::ensure!(
        json!(st.height) == a["as_of_height"] && json!(st.tip_hash) == a["as_of_hash"],
        "compensation audit anchor changed"
    );
    let current: String = tx.query_row(
        "SELECT json FROM kv WHERE ns='self-mint-refunds' AND k=?1",
        [id],
        |r| r.get(0),
    )?;
    anyhow::ensure!(
        json!(hex::encode(Sha256::digest(current.as_bytes()))) == a["claim_record_sha256"],
        "claim changed after fee audit"
    );
    let r = load_record(&tx, id)?;
    anyhow::ensure!(
        r.claim.inscription == *id
            && json!(r.claim.destination) == a["destination"]
            && json!(r.claim.received_zat) == a["received_zat"]
            && r.plan
                .as_ref()
                .is_some_and(|p| json!(p.txid) == a["refund_confirmation"]["txid"]),
        "claim changed after fee audit"
    );
    verify(rpc, &st, &r.claim)?;
    unmanaged_claim(&tx, id)?;
    let old: Option<String> = tx
        .query_row(
            "SELECT json FROM kv WHERE ns=?1 AND k=?2",
            params![NS, id],
            |r| r.get(0),
        )
        .optional()?;
    let mut p = if let Some(raw) = old {
        let p: Compensation = serde_json::from_str(&raw)?;
        if preparing {
            anyhow::ensure!(
                p.reason == args[4]
                    && p.plan
                        .funding
                        .first()
                        .is_some_and(|u| format!("{}:{}", u.txid, u.n) == args[3]),
                "compensation already signed; never replace it"
            );
        }
        p
    } else {
        anyhow::ensure!(preparing, "prepare compensation before resume");
        anyhow::ensure!(
            (1..=512).contains(&args[4].trim().len()),
            "provide a fault attribution reason"
        );
        let key = Key::load(&args[2])?;
        let address = key.address_string(rpc.net());
        let found: Vec<_> = rpc
            .utxos(&address)?
            .into_iter()
            .filter(|u| format!("{}:{}", u.txid, u.n) == args[3])
            .collect();
        anyhow::ensure!(
            found.len() == 1,
            "exact compensation reserve unavailable; no replacement selection"
        );
        let u = found[0].clone();
        anyhow::ensure!(
            u.value == add(n, 10000)?,
            "compensation requires exact independent reserve amount"
        );
        anyhow::ensure!(
            !reserved_inputs(&tx)?.contains(&args[3]),
            "compensation reserve already allocated"
        );
        check_reserve_source(&tx, rpc.net(), &st, &r, &address, &u)?;
        rpc.validate_utxo(&u)?;
        let plan = refund::RefundPlan::prepare(rpc, &key, vec![u], &r.claim.destination)?
            .context("small compensation remains unpaid")?;
        let p = Compensation {
            version: 1,
            inscription: id.clone(),
            reason: args[4].clone(),
            claim_digest: hex::encode(r.claim.digest()?),
            original_refund_txid: r.plan.as_ref().unwrap().txid.clone(),
            original_fee_zat: a["confirmed_original_mint_network_fee_zat"]
                .as_u64()
                .unwrap(),
            reserve_address: address,
            plan,
            confirmation: None,
        };
        tx.execute(
            "INSERT INTO kv VALUES('self-mint-refund-inputs',?1,?2)",
            params![args[3], serde_json::to_string(id)?],
        )?;
        tx.execute("INSERT INTO kv VALUES('operator-actions',?1,?2)",params![format!("self-mint-compensation:{id}"),serde_json::to_string(&json!({"inscription":id,"reason":p.reason,"source":args[3],"scope":"all-original-mint-fees-project-fault","external_payments_reconciled":true,"broadcast":false}))?])?;
        p
    };
    check_payment(&tx, rpc, &st, &r, &a, &p)?;
    anchor(rpc, &st)?;
    if !preparing {
        p.confirmation = p.plan.resume(rpc)?;
    }
    anchor(rpc, &st)?;
    tx.execute("INSERT INTO kv(ns,k,json) VALUES(?1,?2,?3) ON CONFLICT(ns,k) DO UPDATE SET json=excluded.json",params![NS,id,serde_json::to_string(&p)?])?;
    tx.commit()?;
    Ok(response(&p, preparing))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fees_exclude_payments_change_and_carrier() {
        assert_eq!(fee(70546, [50000, 546, 10000].into_iter()).unwrap(), 10000);
    }
    #[test]
    fn inconsistent_or_overflowing_fee_evidence_fails() {
        assert!(fee(10, [11].into_iter()).is_err());
        assert!(fee(10, [u64::MAX, 1].into_iter()).is_err());
        assert!(add(u64::MAX, 1).is_err());
    }
}
