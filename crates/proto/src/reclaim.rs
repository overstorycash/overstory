//! Explicit recovery of expired CLI inscription continuations, never a replacement mint.
use crate::*;
use rusqlite::{OptionalExtension, TransactionBehavior, params};
use sha2::{Digest, Sha256};
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    original_sha256: String,
    parent_index: usize,
    plan: refund::RefundPlan,
    confirmation: Option<refund::RefundConfirmation>,
}
fn summary(r: &Record) -> Value {
    json!({"reclaimed_continuation":r.parent_index,"destination":r.plan.destination,"input_zat":r.plan.input_zat,"refund_zat":r.plan.refund_zat,"fee_zat":r.plan.fee_zat,"txid":r.plan.txid,"confirmation":r.confirmation,"status":if r.confirmation.is_some(){"confirmed"}else{"signed_pending"},"scope":"expired CLI continuation only; not a completed service-order refund or compensation"})
}
pub(crate) fn parse(saved: &inscribe::SignedTransaction, net: index::Net, height: u32) -> Result<Transaction> {
    let bytes = hex::decode(&saved.raw)?;
    let mut c = std::io::Cursor::new(&bytes);
    let t = Transaction::read(&mut c, net.branch_for(height))?;
    anyhow::ensure!(
        c.position() as usize == bytes.len() && t.txid().to_string() == saved.txid,
        "reclaim original identity differs"
    );
    Ok(t)
}
fn barrier(db: &rusqlite::Connection) -> Result<()> {
    let b: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM meta WHERE k='reorg_pending')",
        [],
        |r| r.get(0),
    )?;
    anyhow::ensure!(!b, "reorg reconciliation pending");
    Ok(())
}
fn canonical_source(rpc: &Rpc, saved: &inscribe::SignedTransaction) -> Result<u32> {
    let v = rpc.call("getrawtransaction", json!([saved.txid, 1]))?;
    anyhow::ensure!(
        v["hex"].as_str() == Some(saved.raw.as_str())
            && v["confirmations"].as_u64().is_some_and(|n| n > 0),
        "source not confirmed with original bytes"
    );
    let hash = v["blockhash"].as_str().context("source block missing")?;
    let b = rpc.call("getblock", json!([hash, 1]))?;
    let height = u32::try_from(b["height"].as_u64().context("source height")?)?;
    anyhow::ensure!(
        b["tx"]
            .as_array()
            .context("source block transactions")?
            .iter()
            .any(|id| id.as_str() == Some(saved.txid.as_str()))
            && rpc.call("getblockhash", json!([height]))?.as_str() == Some(hash),
        "source confirmation not canonical"
    );
    Ok(height)
}
pub(crate) fn select_source(
    rpc: &Rpc,
    original: &inscribe::SignedInscription,
    st: &index::State,
) -> Result<(usize, Utxo, inscribe::RevealPlan)> {
    let target = rpc.checked_target()?;
    anyhow::ensure!(
        target > original.expiry_height,
        "original reveal has not expired; do not create a competing spend"
    );
    anyhow::ensure!(
        !st.inscriptions
            .contains_key(&original.result.inscription_id),
        "inscription already completed; no reclaim"
    );
    let mut selected = None;
    for j in 0..original.transactions.len() - 1 {
        let saved = &original.transactions[j];
        let n = if j == 0 { original.commit_vout } else { 0 };
        if rpc
            .call("gettxout", json!([saved.txid, n, true]))?
            .is_null()
        {
            continue;
        }
        anyhow::ensure!(
            selected.is_none(),
            "multiple live continuations; manual reconciliation required"
        );
        let height = canonical_source(rpc, saved)?;
        let parent = parse(saved, rpc.net(), original.target_height)?;
        let out = parent
            .transparent_bundle()
            .context("source bundle")?
            .vout
            .get(n as usize)
            .context("source output")?;
        let u = Utxo {
            txid: saved.txid.clone(),
            n,
            script: hex::encode(index::script_bytes(out.script_pubkey())),
            value: out.value().into_u64(),
            height,
        };
        rpc.validate_utxo(&u)?;
        let point = format!("{}:{}", u.txid, u.n);
        anyhow::ensure!(
            !st.carriers.contains_key(&point),
            "source carries a completed inscription"
        );
        if let Some(p) = st.pending.get(&point) {
            anyhow::ensure!(
                format!("{}i0", p.genesis_txid) == original.result.inscription_id,
                "source carries another pending inscription"
            );
        }
        let next = parse(
            &original.transactions[j + 1],
            rpc.net(),
            original.target_height,
        )?;
        let vin = &next.transparent_bundle().context("next reveal bundle")?.vin;
        anyhow::ensure!(
            vin.len() == 1 && vin[0].prevout() == &u.outpoint()?,
            "next reveal does not spend selected source"
        );
        let script = index::script_bytes(vin[0].script_sig());
        let env = index::parse_envelope(&script).context("next reveal envelope")?;
        anyhow::ensure!(env.c.is_some(), "legacy reclaim unsupported");
        let pushes = index::parse_pushes(&script).context("reveal pushes")?;
        let redeem = pushes.last().context("reveal redeem")?.clone();
        selected = Some((
            j,
            u,
            inscribe::RevealPlan {
                branch: rpc.net().branch_for(target),
                commit_outpoint: vin[0].prevout().clone(),
                commit_value: out.value().into_u64(),
                commit_script: out.script_pubkey().clone(),
                redeem,
                content_type: env.content_type,
                total: env.total,
                pieces: env.pieces,
                outputs: vec![],
                expiry: target.checked_add(39).context("expiry overflow")?,
            },
        ));
    }
    selected.context("no confirmed unspent continuation; do not select replacement funds")
}
fn validate_record(rpc: &Rpc, original: &inscribe::SignedInscription, r: &Record) -> Result<()> {
    r.plan.validate(rpc)?;
    anyhow::ensure!(
        r.parent_index < original.transactions.len() - 1
            && r.plan.funding.len() == 1
            && r.plan.target_height > original.expiry_height,
        "invalid reclaim source/target"
    );
    let saved = &original.transactions[r.parent_index];
    let n = if r.parent_index == 0 {
        original.commit_vout
    } else {
        0
    };
    let parent = parse(saved, rpc.net(), original.target_height)?;
    let out = parent
        .transparent_bundle()
        .context("saved source bundle")?
        .vout
        .get(n as usize)
        .context("saved source output")?;
    let u = &r.plan.funding[0];
    anyhow::ensure!(
        u.txid == saved.txid
            && u.n == n
            && u.value == out.value().into_u64()
            && u.script == hex::encode(index::script_bytes(out.script_pubkey())),
        "saved reclaim does not spend original continuation"
    );
    Ok(())
}
/// Configure an explicit non-inscribing recovery. Authenticated inputs retain their
/// envelope and use a signed, zero-value marker output instead of a carrier.
pub(crate) fn configure_outputs(plan: &mut inscribe::RevealPlan, destination: &TransparentAddress) -> Result<(u64,u64,u32)> {
    let pk:[u8;33]=plan.redeem.get(1..34).context("reclaim public key")?.try_into()?;
    let authenticated = inscribe::authenticated_plan(plan,&pk);
    let fee = if authenticated {
        let refs:Vec<_> = plan.pieces.iter().map(|(i,p)|(*i,p.as_slice())).collect();
        inscribe::reveal_fee(inscribe::script_sig(&plan.content_type,plan.total,&refs,&[0;73],&plan.redeem).len(),2)
    } else { 10000 };
    let amount=plan.commit_value.checked_sub(fee).filter(|n|*n>=CARRIER_ZAT).context("continuation too small to reclaim; retain liability")?;
    plan.outputs=Vec::new();
    if authenticated { plan.outputs.push(TxOut::new(zat(0)?,script_from_raw(&inscribe::reclaim_marker())?)); }
    plan.outputs.push(TxOut::new(zat(amount)?,destination.script().into()));
    Ok((amount,fee,if authenticated {2}else{1}))
}
pub(crate) fn validate_spend(tx:&Transaction,version:u32,fee:u64)->Result<()> {
    let b=tx.transparent_bundle().context("reclaim bundle")?;
    anyhow::ensure!(b.vin.len()==1,"reclaim input count");
    let script=index::script_bytes(b.vin[0].script_sig());
    if version==2 {
        anyhow::ensure!(b.vout.len()==2 && b.vout[0].value().into_u64()==0 && index::script_bytes(b.vout[0].script_pubkey())==inscribe::reclaim_marker(),"authenticated reclaim marker missing");
        anyhow::ensure!(authenticated_fee(&script)?==fee,"authenticated reclaim fee mismatch");
    } else {
        anyhow::ensure!(version==1 && index::parse_envelope(&script).is_none() && inscribe::reveal_fee(script.len(),1)<=fee,"reclaim envelope/fee mismatch");
    }
    Ok(())
}
/// Validate the exact authenticated script shape and its conservative fee budget.
pub(crate) fn authenticated_fee(script:&[u8])->Result<u64> {
    let env=index::parse_envelope(script).context("authenticated reclaim envelope missing")?;
    let pushes=index::parse_pushes(script).context("reclaim pushes")?;
    let redeem=pushes.last().context("reclaim redeem")?;
    let pk:[u8;33]=redeem.get(1..34).context("reclaim public key")?.try_into()?;
    let c=env.c.context("reclaim commitment")?;
    let refs:Vec<_>=env.pieces.iter().map(|(i,p)|(*i,p.as_slice())).collect();
    anyhow::ensure!(inscribe::authenticated_redeem_script(&pk,&c,&env.content_type,env.total,&refs)==*redeem,"reclaim is not authenticated");
    Ok(inscribe::reveal_fee(inscribe::script_sig(&env.content_type,env.total,&refs,&[0;73],redeem).len(),2))
}
pub fn command(args: &[String]) -> Result<Value> {
    let prepare = args[0] == "inscribe-reclaim-plan";
    anyhow::ensure!(
        args.len() == if prepare { 4 } else { 2 },
        "usage: inscribe-reclaim-plan <CLI-inscription-id> <reveal-key> <refund-address> | inscribe-reclaim-resume <CLI-inscription-id>"
    );
    let rpc = Rpc::open()?;
    let mut db = index::Db::open(index::DB_FILE)?;
    let tx = db
        .conn
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    barrier(&tx)?;
    let st = index::Db::load_from(&tx)?;
    let target = rpc.checked_target()?;
    anyhow::ensure!(
        st.height == target - 1
            && st.network.as_deref() == Some(rpc.net().name())
            && st.tip_hash.as_deref() == rpc.call("getblockhash", json!([st.height]))?.as_str(),
        "reclaim requires synchronized canonical index"
    );
    let raw: String = tx.query_row(
        "SELECT json FROM kv WHERE ns='cli-inscription-plans' AND k=?1",
        [&args[1]],
        |r| r.get(0),
    )?;
    let original: inscribe::SignedInscription = serde_json::from_str(&raw)?;
    original.validate(&rpc)?;
    anyhow::ensure!(
        original.result.inscription_id == args[1],
        "original plan identity differs"
    );
    let digest = hex::encode(Sha256::digest(raw.as_bytes()));
    let old: Option<String> = tx
        .query_row(
            "SELECT json FROM kv WHERE ns='expired-reclaims' AND k=?1",
            [&args[1]],
            |r| r.get(0),
        )
        .optional()?;
    if let Some(raw) = old {
        let mut r: Record = serde_json::from_str(&raw)?;
        anyhow::ensure!(
            r.original_sha256 == digest
                && target > original.expiry_height
                && !st.inscriptions.contains_key(&args[1]),
            "original plan/expiry/completion changed; reconcile reclaim"
        );
        validate_record(&rpc, &original, &r)?;
        let point = format!("{}:{}", r.plan.funding[0].txid, r.plan.funding[0].n);
        let owner: String = tx.query_row(
            "SELECT json FROM kv WHERE ns='reclaim-inputs' AND k=?1",
            [point],
            |r| r.get(0),
        )?;
        anyhow::ensure!(
            serde_json::from_str::<String>(&owner)? == args[1],
            "reclaim reservation differs"
        );
        if prepare {
            anyhow::ensure!(
                args[3] == r.plan.destination,
                "cannot change saved reclaim destination"
            );
            let mut result = summary(&r);
            result["confirmation_is_cached"] = json!(true);
            return Ok(result);
        }
        canonical_source(&rpc, &original.transactions[r.parent_index])?;
        r.confirmation = r.plan.resume(&rpc)?;
        tx.execute(
            "UPDATE kv SET json=?2 WHERE ns='expired-reclaims' AND k=?1",
            params![args[1], serde_json::to_string(&r)?],
        )?;
        tx.commit()?;
        return Ok(summary(&r));
    }
    anyhow::ensure!(
        prepare,
        "no saved reclaim; prepare after reconciling the original plan"
    );
    let destination = parse_taddr_for(&args[3], rpc.net().network_type())?;
    let (parent_index, u, mut reveal) = select_source(&rpc, &original, &st)?;
    let point = format!("{}:{}", u.txid, u.n);
    anyhow::ensure!(
        !refund_claim::reserved_inputs(&tx)?.contains(&point),
        "source already reserved"
    );
    let (amount, fee, version) = configure_outputs(&mut reveal,&destination)?;
    let key = Key::load(&args[2])?;
    let signed = inscribe::build_reclaim(&reveal, &key)?;
    validate_spend(&signed,version,fee)?;
    let mut bytes = Vec::new();
    signed.write(&mut bytes)?;
    let plan = refund::RefundPlan {
        version,
        network: rpc.net().name().into(),
        genesis_hash: rpc.chain.genesis_hash.clone(),
        target_height: target,
        expiry_height: reveal.expiry,
        destination: args[3].clone(),
        funding: vec![u],
        input_zat: amount + fee,
        refund_zat: amount,
        fee_zat: fee,
        txid: signed.txid().to_string(),
        raw_transaction: hex::encode(bytes),
    };
    plan.validate(&rpc)?;
    anyhow::ensure!(
        rpc.checked_target()? == target
            && st.tip_hash.as_deref() == rpc.call("getblockhash", json!([st.height]))?.as_str(),
        "chain moved before saving reclaim"
    );
    let r = Record {
        original_sha256: digest,
        parent_index,
        plan,
        confirmation: None,
    };
    tx.execute(
        "INSERT INTO kv(ns,k,json) VALUES('reclaim-inputs',?1,?2)",
        params![point, serde_json::to_string(&args[1])?],
    )?;
    tx.execute(
        "INSERT INTO kv(ns,k,json) VALUES('expired-reclaims',?1,?2)",
        params![args[1], serde_json::to_string(&r)?],
    )?;
    tx.commit()?;
    Ok(summary(&r))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn authenticated_reclaim_preserves_envelope_but_cannot_be_a_mint() {
        let key=Key::from_secret(&[11;32]).unwrap();
        for n in 1..=4 {
            let pieces:Vec<_>=(0..n).rev().map(|i|(i,vec![42;240])).collect();
            let refs:Vec<_>=pieces.iter().map(|(i,p)|(*i,p.as_slice())).collect();
            let redeem=inscribe::authenticated_redeem_script(&key.pk.serialize(),&[9;32],b"text/plain",n,&refs);
            let source:Script=TransparentAddress::ScriptHash(inscribe::hash160(&redeem)).script().into();
            let mut reveal=inscribe::RevealPlan{branch:index::Net::Regtest.branch_for(200),commit_outpoint:OutPoint::new([8;32],0),commit_value:500000,commit_script:source.clone(),redeem,content_type:b"text/plain".to_vec(),total:n,pieces,outputs:vec![],expiry:239};
            let (amount,fee,version)=configure_outputs(&mut reveal,&key.address()).unwrap();
            assert_eq!(version,2);
            assert!(fee>10000);
            let tx=inscribe::build_reclaim(&reveal,&key).unwrap();
            validate_spend(&tx,version,fee).unwrap();
            assert!(validate_spend(&tx,1,fee).is_err());
            assert!(validate_spend(&tx,2,fee+5000).is_err());
            let b=tx.transparent_bundle().unwrap();
            let ss=index::script_bytes(b.vin[0].script_sig());
            assert!(index::parse_envelope(&ss).is_some());
            assert_eq!(b.vout[0].value().into_u64(),0);
            assert_eq!(b.vout[1].value().into_u64(),amount);
            let mut raw=Vec::new();tx.write(&mut raw).unwrap();
            let mut plan=refund::RefundPlan{version,network:"regtest".into(),genesis_hash:"test".into(),target_height:200,expiry_height:239,destination:key.address_string(index::Net::Regtest),funding:vec![Utxo{txid:hex::encode([8;32]),n:0,script:hex::encode(index::script_bytes(&source)),value:500000,height:100}],input_zat:500000,refund_zat:amount,fee_zat:fee,txid:tx.txid().to_string(),raw_transaction:hex::encode(raw)};
            plan.validate_for_chain(index::Net::Regtest,"test").unwrap();
            plan.version=1;assert!(plan.validate_for_chain(index::Net::Regtest,"test").is_err());plan.version=2;
            plan.funding[0].script="00".into();assert!(plan.validate_for_chain(index::Net::Regtest,"test").is_err());
            // A signed ordinary reveal cannot be mislabeled as a recovery plan.
            reveal.outputs[0]=TxOut::new(zat(CARRIER_ZAT).unwrap(),key.address().script().into());
            let not_recovery=inscribe::build_reveal(&reveal,&key).unwrap();
            assert!(validate_spend(&not_recovery,2,fee).is_err());
            // The signer refuses to produce an authenticated recovery with a carrier.
            reveal.outputs.remove(0);
            assert!(inscribe::build_reclaim(&reveal,&key).is_err());
        }
    }
    #[test]
    fn reclaim_unlocks_original_redeem_without_inscribing_content() {
        let key = Key::from_secret(&[11; 32]).unwrap();
        let wrong = Key::from_secret(&[12; 32]).unwrap();
        for n in 1..=4 {
            let redeem = inscribe::redeem_script(&key.pk.serialize(), &[9; 32], n);
            let script: Script = TransparentAddress::ScriptHash(inscribe::hash160(&redeem))
                .script()
                .into();
            let plan = inscribe::RevealPlan {
                branch: index::Net::Regtest.branch_for(200),
                commit_outpoint: OutPoint::new([8; 32], 0),
                commit_value: 50000,
                commit_script: script,
                redeem,
                content_type: b"text/plain".to_vec(),
                total: n,
                pieces: (0..n).map(|i| (i, vec![1; 240])).collect(),
                outputs: vec![TxOut::new(
                    zat(40000).unwrap(),
                    key.address().script().into(),
                )],
                expiry: 239,
            };
            assert!(inscribe::build_reclaim(&plan, &wrong).is_err());
            let tx = inscribe::build_reclaim(&plan, &key).unwrap();
            let b = tx.transparent_bundle().unwrap();
            let ss = index::script_bytes(b.vin[0].script_sig());
            assert!(index::parse_envelope(&ss).is_none());
            let pushes = index::parse_pushes(&ss).unwrap();
            assert_eq!(pushes.len(), 3 + 2 * n + 2);
            assert_eq!(&ss[..3 + 2 * n], &vec![0;3 + 2 * n]);
            assert_eq!(pushes.last().unwrap(), &plan.redeem);
            assert!(inscribe::reveal_fee(ss.len(), 1) <= 10000);
            assert_eq!(b.vout[0].value().into_u64(), 40000);
        }
    }
}
