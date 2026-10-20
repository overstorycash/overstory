//! Commit/reveal inscription envelope (ord-style scriptSig envelope with a content
//! commitment in the redeem script) and the `inscribe` command.
//!
//! Reveal input 0 scriptSig (push-only):
//!   PUSH "ord" | PUSHNUM totalPieces | PUSH contentType |
//!   (PUSHNUM index | PUSH piece)*  (indexes descending, 240-byte pieces) |
//!   PUSH signature | PUSH redeemScript
//! Redeem script:
//!   CHECKSIGVERIFY, content commitment, per-element SHA256/EQUALVERIFY, empty-stack check.
//! The legacy DROP-only redeem is retained for historical decoding and recovery.
//!   C = SHA256("UZRD1" || contentType || 0x00 || content)

use anyhow::{Context, Result, anyhow, bail};
use ripemd::Ripemd160;
use secp256k1::{Message};
use sha2::{Digest, Sha256};
use zcash_primitives::transaction::{
    Authorization, Authorized, Transaction, TransactionData, TxVersion,
    sighash::{SignableInput, signature_hash},
    txid::TxIdDigester,
};
use zcash_protocol::{
    consensus::{BlockHeight, BranchId},
    value::Zatoshis,
};
use zcash_transparent::{
    address::{Script, TransparentAddress},
    bundle::{self, Bundle, OutPoint, TxIn, TxOut},
    sighash::{SighashType, TransparentAuthorizingContext},
};

use crate::{
    CARRIER_ZAT, InputSpec, Key, OutputSpec, Rpc, build_pczt, finalize_tx, parse_taddr_for,
    script_from_raw, zat,
};
use pczt::roles::{io_finalizer::IoFinalizer, signer::Signer};

pub const PIECE: usize = 240;
pub const MAX_PIECES_PER_TX: usize = 4;
pub const COMMIT_TAG: &[u8] = b"UZRD1";
const OP_DROP: u8 = 0x75;
const OP_CHECKSIGVERIFY: u8 = 0xad;
const OP_1: u8 = 0x51;

pub fn push_bytes(out: &mut Vec<u8>, data: &[u8]) {
    if data.len() < 0x4c {
        out.push(data.len() as u8);
    } else if data.len() <= 0xff {
        out.push(0x4c);
        out.push(data.len() as u8);
    } else {
        out.push(0x4d);
        out.extend_from_slice(&(data.len() as u16).to_le_bytes());
    }
    out.extend_from_slice(data);
}

/// Minimal script-number push for 0..=255 as used by deployed envelope decoders.
pub fn push_num(out: &mut Vec<u8>, n: u8) {
    match n {
        0 => out.push(0x00),
        1..=16 => out.push(0x50 + n),
        _ => {
            out.push(1);
            out.push(n);
        }
    }
}

pub fn hash160(data: &[u8]) -> [u8; 20] {
    Ripemd160::digest(Sha256::digest(data)).into()
}

pub fn commitment(content_type: &[u8], content: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(COMMIT_TAG);
    h.update(content_type);
    h.update([0u8]);
    h.update(content);
    h.finalize().into()
}

pub fn redeem_script(pubkey: &[u8; 33], c: &[u8; 32], pieces: usize) -> Vec<u8> {
    let mut s = vec![];
    push_bytes(&mut s, pubkey);
    s.push(OP_CHECKSIGVERIFY);
    push_bytes(&mut s, c);
    s.push(OP_DROP); // C
    for _ in 0..(3 + 2 * pieces) {
        s.push(OP_DROP);
    }
    s.push(OP_1);
    s
}

/// The actual stack bytes produced by push_num, including the empty encoding of zero.
pub fn envelope_stack(content_type: &[u8], total: usize, pieces: &[(usize, &[u8])]) -> Vec<Vec<u8>> {
    let number = |n: usize| if n == 0 { vec![] } else { vec![n as u8] };
    let mut items = vec![b"ord".to_vec(), number(total), content_type.to_vec()];
    for (index, piece) in pieces { items.push(number(*index)); items.push(piece.to_vec()); }
    items
}

/// Authenticate every envelope stack value in the P2SH spending condition.
/// The final depth check forbids hidden prefix items even without policy CleanStack.
pub fn authenticated_redeem_script(pubkey: &[u8; 33], c: &[u8; 32], content_type: &[u8], total: usize, pieces: &[(usize, &[u8])]) -> Vec<u8> {
    let mut s = vec![];
    push_bytes(&mut s, pubkey);
    s.push(OP_CHECKSIGVERIFY);
    push_bytes(&mut s, c);
    s.push(OP_DROP);
    for item in envelope_stack(content_type, total, pieces).iter().rev() {
        s.push(0xa8); // OP_SHA256
        push_bytes(&mut s, &Sha256::digest(item));
        s.push(0x88); // OP_EQUALVERIFY
    }
    s.extend_from_slice(&[0x74, 0x00, 0x88, OP_1]); // DEPTH 0 EQUALVERIFY TRUE
    s
}

/// A signed output-zero marker prevents a recovery spend from creating an inscription.
pub fn reclaim_marker() -> Vec<u8> {
    let mut s = vec![0x6a]; // OP_RETURN
    push_bytes(&mut s, b"UZRD-RECLAIM");
    s
}

pub fn is_authenticated_plan(plan: &RevealPlan) -> bool {
    plan.redeem.get(1..34).and_then(|raw| <&[u8;33]>::try_from(raw).ok())
        .is_some_and(|pk| authenticated_plan(plan,pk))
}

pub fn authenticated_plan(plan: &RevealPlan, pubkey: &[u8; 33]) -> bool {
    let Some(raw) = plan.redeem.get(36..68) else { return false; };
    let Ok(c) = <&[u8; 32]>::try_from(raw) else { return false; };
    let refs: Vec<_> = plan.pieces.iter().map(|(i, p)| (*i, p.as_slice())).collect();
    authenticated_redeem_script(pubkey, c, &plan.content_type, plan.total, &refs) == plan.redeem
}

pub fn pieces_of(content: &[u8]) -> Vec<&[u8]> {
    content.chunks(PIECE).collect()
}

pub fn script_sig(
    content_type: &[u8],
    total: usize,
    pieces: &[(usize, &[u8])],
    sig_with_type: &[u8],
    redeem: &[u8],
) -> Vec<u8> {
    let mut s = vec![];
    push_bytes(&mut s, b"ord");
    push_num(&mut s, total as u8);
    push_bytes(&mut s, content_type);
    for (i, p) in pieces {
        push_num(&mut s, *i as u8);
        push_bytes(&mut s, p);
    }
    push_bytes(&mut s, sig_with_type);
    push_bytes(&mut s, redeem);
    s
}

/// ZIP 317 conventional fee for a reveal with one transparent input of the given
/// scriptSig size and `n_out` transparent outputs.
pub fn reveal_fee(script_sig_len: usize, n_out: usize) -> u64 {
    let txin_bytes = 32 + 4 + 3 + script_sig_len + 4; // prevout, index, compactsize, sig, sequence
    let in_actions = txin_bytes.div_ceil(150);
    let logical = in_actions.max(n_out).max(2);
    5_000 * logical as u64
}

// ---- authorization context used only to compute the reveal sighash

#[derive(Debug)]
struct RevealAuth {
    amounts: Vec<Zatoshis>,
    scripts: Vec<Script>,
}
impl bundle::Authorization for RevealAuth {
    type ScriptSig = ();
}
impl TransparentAuthorizingContext for RevealAuth {
    fn input_amounts(&self) -> Vec<Zatoshis> {
        self.amounts.clone()
    }
    fn input_scriptpubkeys(&self) -> Vec<Script> {
        self.scripts.clone()
    }
}
#[derive(Debug)]
struct RevealTxAuth;
impl Authorization for RevealTxAuth {
    type TransparentAuth = RevealAuth;
    type SaplingAuth = sapling::bundle::Authorized;
    type OrchardAuth = orchard::bundle::Authorized;
}

pub struct RevealPlan {
    pub branch: BranchId,
    pub commit_outpoint: OutPoint,
    pub commit_value: u64,
    pub commit_script: Script,
    pub redeem: Vec<u8>,
    pub content_type: Vec<u8>,
    pub total: usize,
    pub pieces: Vec<(usize, Vec<u8>)>,
    pub outputs: Vec<TxOut>,
    pub expiry: u32,
}

/// Builds and signs the reveal transaction by hand (the PCZT spend finalizer only knows
/// P2PKH and P2MS-in-P2SH).
pub fn build_reveal(plan: &RevealPlan, key: &Key) -> Result<Transaction> {
    build_reveal_inner(plan,key,false)
}
/// Return an expired continuation's funds without publishing another inscription.
/// Caller must prove expiry, canonical source and ownership before saving this spend.
pub(crate) fn build_reclaim(plan:&RevealPlan,key:&Key)->Result<Transaction> {
    anyhow::ensure!((1..=4).contains(&plan.pieces.len()),"invalid reclaim redeem size");
    let c:[u8;32]=plan.redeem.get(36..68).context("missing reclaim commitment")?.try_into()?;
    anyhow::ensure!(authenticated_plan(plan, &key.pk.serialize()) || redeem_script(&key.pk.serialize(),&c,plan.pieces.len())==plan.redeem,"reclaim key/redeem mismatch");
    if authenticated_plan(plan, &key.pk.serialize()) {
        anyhow::ensure!(plan.outputs.len()==2 && plan.outputs[0].value().into_u64()==0 && crate::index::script_bytes(plan.outputs[0].script_pubkey())==reclaim_marker(), "authenticated reclaim requires signed output-zero marker");
    }
    let expected:Script=TransparentAddress::ScriptHash(hash160(&plan.redeem)).script().into();
    anyhow::ensure!(expected==plan.commit_script,"reclaim source script mismatch");
    build_reveal_inner(plan,key,true)
}
fn build_reveal_inner(plan:&RevealPlan,key:&Key,reclaim:bool)->Result<Transaction> {
    let branch = plan.branch;
    let expiry = BlockHeight::from_u32(plan.expiry);
    let vin = vec![TxIn::<RevealAuth>::from_parts(
        plan.commit_outpoint.clone(),
        (),
        u32::MAX,
    )];
    let unsigned = TransactionData::<RevealTxAuth>::from_parts(
        TxVersion::suggested_for_branch(branch),
        branch,
        0,
        expiry,
        Some(Bundle {
            vin,
            vout: plan.outputs.clone(),
            authorization: RevealAuth {
                amounts: vec![zat(plan.commit_value)?],
                scripts: vec![plan.commit_script.clone()],
            },
        }),
        None,
        None,
        None,
    );
    let bundle = unsigned.transparent_bundle().context("bundle")?;
    let redeem_script = script_from_raw(&plan.redeem)?;
    let signable = zcash_transparent::sighash::SignableInput::from_parts(
        bundle,
        SighashType::ALL,
        0,
        &redeem_script,
        &plan.commit_script,
        zat(plan.commit_value)?,
    )
    .map_err(|e| anyhow!("signable input: {e:?}"))?;
    let digest = signature_hash(
        &unsigned,
        &SignableInput::Transparent(signable),
        &unsigned.digest(TxIdDigester),
    );
    let sig = secp256k1::ecdsa::sign(Message::from_digest(*digest.as_ref()), &key.sk);
    let mut sig_bytes = sig.serialize_der().to_vec();
    sig_bytes.push(SighashType::ALL.encode());
    let pieces: Vec<(usize, &[u8])> = plan
        .pieces
        .iter()
        .map(|(i, p)| (*i, p.as_slice()))
        .collect();
    let ss = if reclaim && !authenticated_plan(plan, &key.pk.serialize()) {
        // Empty placeholders satisfy the original redeem's DROP count. No "ord" tag.
        let mut script=vec![0;3+2*plan.pieces.len()];
        push_bytes(&mut script,&sig_bytes);push_bytes(&mut script,&plan.redeem);script
    } else {script_sig(&plan.content_type,plan.total,&pieces,&sig_bytes,&plan.redeem)};
    let signed = TransactionData::<Authorized>::from_parts(
        TxVersion::suggested_for_branch(branch),
        branch,
        0,
        expiry,
        Some(Bundle {
            vin: vec![TxIn::from_parts(
                plan.commit_outpoint.clone(),
                script_from_raw(&ss)?,
                u32::MAX,
            )],
            vout: plan.outputs.clone(),
            authorization: bundle::Authorized,
        }),
        None,
        None,
        None,
    );
    Ok(signed.freeze()?)
}

/// `inscribe <funder-key> <content-file> <content-type> <dest-addr> [<pay-addr> <pay-zat>]`
///
/// Content is split into 240-byte pieces, at most 4 per reveal. The genesis reveal carries
/// the highest indexes; each continuation spends output 0 of the previous reveal; the
/// completion reveal carries piece 0 and pays the destination on output 0.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct InscribeResult {
    pub inscription_id: String,
    pub commit_txid: String,
    pub reveal_txids: Vec<String>,
    pub total_cost: u64,
}

/// Cost of inscribing `content` (all reveal fees + postage + payment), excluding the
/// commit transaction's own fee.
pub fn inscription_cost(
    content: &[u8],
    content_type: &[u8],
    n_final_outputs: usize,
    extra_outputs_value: u64,
) -> u64 {
    let all = pieces_of(content);
    let total = all.len();
    let mut idx: Vec<usize> = (0..total).rev().collect();
    let groups: Vec<Vec<usize>> = idx
        .chunks_mut(MAX_PIECES_PER_TX)
        .map(|g| g.to_vec())
        .collect();
    let dummy_sig = vec![0u8; 73];
    let n = groups.len();
    let mut funding = 0u64;
    for k in (0..n).rev() {
        let pieces: Vec<(usize, &[u8])> = groups[k].iter().map(|&i| (i, all[i])).collect();
        let redeem = authenticated_redeem_script(&[2u8; 33], &[0u8; 32], content_type, total, &pieces);
        let ss_len = script_sig(content_type, total, &pieces, &dummy_sig, &redeem).len();
        let n_out = if k == n - 1 { n_final_outputs } else { 1 };
        let fee = reveal_fee(ss_len, n_out);
        let outs = if k == n - 1 {
            CARRIER_ZAT + extra_outputs_value
        } else {
            funding
        };
        funding = outs + fee;
    }
    funding
}

pub fn cmd_inscribe(
    funder: &str,
    file: &str,
    content_type: &str,
    dest: &str,
    pay: Option<(&str, u64)>,
) -> Result<()> {
    let rpc = Rpc::open()?;
    let key = Key::load(funder)?;
    let content = std::fs::read(file)?;
    let change_to = key.address();
    let r = inscribe(
        &rpc,
        &key,
        &content,
        content_type.as_bytes(),
        dest,
        pay,
        &change_to,
    )?;
    println!("inscription id {} -> {dest}", r.inscription_id);
    Ok(())
}

/// Inscribes `content`, funded from `key`'s spendable UTXOs; commit change goes to `change_to`.
pub fn inscribe(
    rpc: &Rpc,
    key: &Key,
    content: &[u8],
    content_type: &[u8],
    dest: &str,
    pay: Option<(&str, u64)>,
    change_to: &TransparentAddress,
) -> Result<InscribeResult> {
    inscribe_with(
        rpc,
        key,
        content,
        content_type,
        dest,
        pay,
        change_to,
        vec![],
    )
}

#[allow(clippy::too_many_arguments)]
pub fn prepare_inscription(
    rpc: &Rpc,
    key: &Key,
    content: &[u8],
    content_type: &[u8],
    dest: &str,
    pay: Option<(&str, u64)>,
    change_to: &TransparentAddress,
    commit_extra: Vec<OutputSpec>,
) -> Result<SignedInscription> {
    prepare_inscription_inner(rpc, key, content, content_type, dest, pay, change_to, commit_extra, None)
}

/// A fixed invoice total, including postage and all inscription network fees.
#[derive(Clone)]
pub struct InclusiveBudget {
    pub total_zat: u64,
    pub service_to: TransparentAddress,
}

fn inclusive_outputs(budget: &InclusiveBudget, reveal_funding: u64, have: u64, inputs: usize, change_to: &TransparentAddress) -> Result<Vec<OutputSpec>> {
    let hold=|message:&str|anyhow!(RecoveryRequired(message.into()));
    let excess=have.checked_sub(budget.total_zat).ok_or_else(||hold("invoice not fully funded"))?;
    if inputs==0 || inputs>100 { return Err(hold("invoice input count requires reconciliation")); }
    if excess>0 && excess<CARRIER_ZAT { return Err(hold("sub-dust overpayment requires reconciliation")); }
    let count=if excess>0 {3}else{2};
    let fee=5_000 * inputs.max(count).max(2) as u64;
    let service=budget.total_zat.checked_sub(reveal_funding).and_then(|v|v.checked_sub(fee))
        .ok_or_else(||hold("inclusive price cannot cover network costs"))?;
    if service<CARRIER_ZAT { return Err(hold("inclusive service remainder below minimum output")); }
    let mut outputs=vec![OutputSpec {to:budget.service_to.clone(),value:service}];
    if excess>0 { outputs.push(OutputSpec {to:change_to.clone(),value:excess}); }
    Ok(outputs)
}

#[allow(clippy::too_many_arguments)]
pub fn prepare_inclusive_inscription(
    rpc: &Rpc, key: &Key, content: &[u8], content_type: &[u8], dest: &str,
    pay: Option<(&str,u64)>, change_to: &TransparentAddress, budget: InclusiveBudget,
) -> Result<SignedInscription> {
    crate::zat(budget.total_zat)?;
    prepare_inscription_inner(rpc,key,content,content_type,dest,pay,change_to,vec![],Some(budget))
}

#[allow(clippy::too_many_arguments)]
fn prepare_inscription_inner(
    rpc: &Rpc, key: &Key, content: &[u8], content_type: &[u8], dest: &str,
    pay: Option<(&str,u64)>, change_to: &TransparentAddress, commit_extra: Vec<OutputSpec>,
    budget: Option<InclusiveBudget>,
) -> Result<SignedInscription> {
    let me = change_to.clone();
    let content = content.to_vec();
    let ct = content_type.to_vec();
    anyhow::ensure!(
        (3..=96).contains(&ct.len())
            && ct.contains(&b'/')
            && ct.iter().all(|b| (0x21..=0x7e).contains(b)),
        "invalid content type"
    );
    if content.is_empty() {
        bail!("empty content");
    }
    let all: Vec<&[u8]> = pieces_of(&content);
    let total = all.len();
    if total > 255 {
        bail!("{total} pieces > 255");
    }
    // Groups in transmission order: indexes descending, 4 per transaction.
    let mut order: Vec<(usize, Vec<u8>)> = all
        .iter()
        .enumerate()
        .map(|(i, p)| (i, p.to_vec()))
        .collect();
    order.reverse();
    let groups: Vec<Vec<(usize, Vec<u8>)>> = order
        .chunks(MAX_PIECES_PER_TX)
        .map(|g| g.to_vec())
        .collect();
    let c = commitment(&ct, &content);
    let redeems: Vec<Vec<u8>> = groups
        .iter()
        .map(|g| {
            let refs: Vec<_> = g.iter().map(|(i,p)| (*i,p.as_slice())).collect();
            authenticated_redeem_script(&key.pk.serialize(), &c, &ct, total, &refs)
        })
        .collect();
    anyhow::ensure!(redeems.iter().all(|r| r.len() <= 520), "redeem exceeds consensus element limit");
    let commit_addrs: Vec<TransparentAddress> = redeems
        .iter()
        .map(|r| TransparentAddress::ScriptHash(hash160(r)))
        .collect();

    // Final outputs, then fund each reveal backwards.
    let mut final_outputs = vec![TxOut::new(
        zat(CARRIER_ZAT)?,
        parse_taddr_for(dest, rpc.net().network_type())?
            .script()
            .into(),
    )];
    if let Some((addr, amt)) = pay {
        final_outputs.push(TxOut::new(
            zat(amt)?,
            parse_taddr_for(addr, rpc.net().network_type())?
                .script()
                .into(),
        ));
    }
    let dummy_sig = vec![0u8; 73];
    let n = groups.len();
    let mut funding = vec![0u64; n];
    let mut fees = vec![0u64; n];
    for k in (0..n).rev() {
        let pieces: Vec<(usize, &[u8])> =
            groups[k].iter().map(|(i, p)| (*i, p.as_slice())).collect();
        let ss_len = script_sig(&ct, total, &pieces, &dummy_sig, &redeems[k]).len();
        let n_out = if k == n - 1 { final_outputs.len() } else { 1 };
        fees[k] = reveal_fee(ss_len, n_out);
        let outs = if k == n - 1 {
            final_outputs
                .iter()
                .map(|o| o.value().into_u64())
                .sum::<u64>()
        } else {
            funding[k + 1]
        };
        funding[k] = outs + fees[k];
    }
    println!(
        "content {} bytes, {total} piece(s) in {n} reveal tx, fees {:?}, commit funding {} zat, commitment {}",
        content.len(),
        fees,
        funding[0],
        hex::encode(c)
    );

    // ---- commit: pay the first commit address from a mature UTXO
    let extra_total: u64 = commit_extra.iter().map(|o| o.value).sum();
    let tip = rpc.height()?;
    let mut utxos = rpc.spendable(&key.address_string(rpc.net()))?;
    utxos.sort_by_key(|u| u.height);
    // Take mature UTXOs until the commit is funded (an invoice address may hold several payments).
    let mut inputs = vec![];
    let mut selected_funding = vec![];
    let mut have = 0u64;
    for u in utxos {
        have = have.checked_add(u.value).context("funding overflow")?;
        inputs.push(InputSpec {
            pubkey: key.pk,
            outpoint: u.outpoint()?,
            coin: u.coin()?,
        });
        selected_funding.push(u);
        if have >= budget.as_ref().map(|b| b.total_zat).unwrap_or(funding[0] + 50_000 + extra_total) {
            break;
        }
    }
    let mut outs = vec![OutputSpec { to: commit_addrs[0].clone(), value: funding[0] }];
    if let Some(budget) = &budget {
        outs.extend(inclusive_outputs(budget, funding[0], have, inputs.len(), &me)?);
    } else {
        anyhow::ensure!(have >= funding[0] + 10_000 + extra_total, "insufficient mature funds");
        outs.extend(commit_extra);
    }
    let target = rpc.checked_window(tip + 40)?;
    let pczt = build_pczt(rpc.net(), target, tip + 40, &inputs, &outs, &me)?;
    let pczt = IoFinalizer::new(pczt)
        .finalize_io(rand::rng())
        .map_err(|e| anyhow!("io finalize: {e:?}"))?;
    let mut signer = Signer::new(pczt).map_err(|e| anyhow!("signer: {e:?}"))?;
    for i in 0..inputs.len() {
        signer
            .sign_transparent(i, &key.sk)
            .map_err(|e| anyhow!("sign {i}: {e:?}"))?;
    }
    let commit_tx = finalize_tx(signer.finish())?;
    if budget.is_some() {
        let actual = &commit_tx.transparent_bundle().context("no transparent commit")?.vout;
        anyhow::ensure!(actual.len() == outs.len() && actual.iter().zip(&outs).all(|(a,b)|
            a.value().into_u64()==b.value && *a.script_pubkey()==b.to.script().into()),
            "inclusive commit outputs differ from budget");
    }
    let commit_script: Script = commit_addrs[0].script().into();
    let commit_vout = commit_tx
        .transparent_bundle()
        .context("no transparent bundle")?
        .vout
        .iter()
        .position(|o| o.script_pubkey() == &commit_script)
        .context("commit output not found")? as u32;
    let mut raw = vec![];
    commit_tx.write(&mut raw)?;
    let commit_txid = commit_tx.txid().to_string();
    let mut transactions = vec![SignedTransaction { txid: commit_txid.clone(), raw: hex::encode(&raw) }];
    println!(
        "planned commit  txid={commit_txid} vout={commit_vout} bytes={}",
        raw.len()
    );

    // ---- reveal chain
    let mut prev_outpoint = OutPoint::new(*commit_tx.txid().as_ref(), commit_vout);
    let mut genesis = String::new();
    let mut reveal_txids = vec![];
    for k in 0..n {
        let outputs = if k == n - 1 {
            final_outputs.clone()
        } else {
            vec![TxOut::new(
                zat(funding[k + 1])?,
                commit_addrs[k + 1].script().into(),
            )]
        };
        let plan = RevealPlan {
            branch: rpc.net().branch_for(target),
            commit_outpoint: prev_outpoint.clone(),
            commit_value: funding[k],
            commit_script: commit_addrs[k].script().into(),
            redeem: redeems[k].clone(),
            content_type: ct.clone(),
            total,
            pieces: groups[k].clone(),
            outputs,
            expiry: tip + 40,
        };
        let tx = build_reveal(&plan, &key)?;
        let mut raw = vec![];
        tx.write(&mut raw)?;
        let txid = tx.txid().to_string();
        transactions.push(SignedTransaction { txid: txid.clone(), raw: hex::encode(&raw) });
        if k == 0 {
            genesis = txid.clone();
        }
        reveal_txids.push(txid.clone());
        println!(
            "planned reveal {}/{n}  txid={txid} bytes={} pieces={:?}",
            k + 1,
            raw.len(),
            groups[k].iter().map(|(i, _)| *i).collect::<Vec<_>>()
        );
        prev_outpoint = OutPoint::new(*tx.txid().as_ref(), 0);
    }
    Ok(SignedInscription {
        funding: selected_funding,
        version: 1, network: rpc.net().name().into(), genesis_hash: rpc.chain.genesis_hash.clone(),
        target_height: target, expiry_height: tip + 40, commit_vout, destination: dest.into(), transactions,
        result: InscribeResult {
        inscription_id: format!("{genesis}i0"),
        commit_txid,
        reveal_txids,
        total_cost: funding[0],
        },
    })
}

/// Immutable signed chain; persist this before sending any transaction.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedTransaction { pub txid: String, pub raw: String }
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedInscription {
    #[serde(default)]
    pub funding: Vec<crate::Utxo>,
    pub version: u32,
    pub network: String,
    pub genesis_hash: String,
    pub target_height: u32,
    pub expiry_height: u32,
    pub commit_vout: u32,
    pub destination: String,
    pub transactions: Vec<SignedTransaction>,
    pub result: InscribeResult,
}
#[derive(Debug)]
pub struct RecoveryRequired(pub String);
impl std::fmt::Display for RecoveryRequired {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { self.0.fmt(f) }
}
impl std::error::Error for RecoveryRequired {}
impl SignedInscription {
    pub fn validate(&self, rpc: &Rpc) -> Result<()> {
        anyhow::ensure!(self.version == 1 && self.network == rpc.net().name()
            && self.genesis_hash == rpc.chain.genesis_hash, "inscription plan chain mismatch");
        anyhow::ensure!((2..=65).contains(&self.transactions.len()), "invalid inscription chain length");
        let branch = crate::network::validate_window(rpc.net(), self.target_height, self.expiry_height)?;
        let mut previous = None;
        for (i, saved) in self.transactions.iter().enumerate() {
            let bytes = hex::decode(&saved.raw)?;
            let mut cursor = std::io::Cursor::new(&bytes);
            let tx = Transaction::read(&mut cursor, branch)?;
            anyhow::ensure!(cursor.position() as usize == bytes.len() && tx.txid().to_string() == saved.txid
                && u32::from(tx.expiry_height()) == self.expiry_height && tx.consensus_branch_id() == branch
                && tx.version() == TxVersion::suggested_for_branch(branch),
                "inscription transaction identity/epoch mismatch");
            let b = tx.transparent_bundle().context("missing transparent bundle")?;
            if i == 0 && !self.funding.is_empty() {
                anyhow::ensure!(b.vin.len()==self.funding.len(), "mint funding count mismatch");
                let mut seen=std::collections::BTreeSet::new();
                for (input,u) in b.vin.iter().zip(&self.funding) {
                    anyhow::ensure!(input.prevout()==&u.outpoint()? && seen.insert((u.txid.clone(),u.n)), "mint funding mismatch");
                }
            }
            if let Some(point) = previous {
                anyhow::ensure!(b.vin.len() == 1 && b.vin[0].prevout() == &point, "broken reveal chain");
            }
            let n = if i == 0 { self.commit_vout } else { 0 };
            anyhow::ensure!(b.vout.get(n as usize).is_some(), "missing continuation output");
            if i == self.transactions.len() - 1 {
                let dest = parse_taddr_for(&self.destination, rpc.net().network_type())?;
                anyhow::ensure!(b.vout[0].value().into_u64() == CARRIER_ZAT
                    && *b.vout[0].script_pubkey() == dest.script().into(), "plan destination mismatch");
            }
            previous = Some(OutPoint::new(*tx.txid().as_ref(), n));
        }
        anyhow::ensure!(self.result.commit_txid == self.transactions[0].txid
            && self.result.inscription_id == format!("{}i0", self.transactions[1].txid)
            && self.result.reveal_txids == self.transactions[1..].iter().map(|t| t.txid.clone()).collect::<Vec<_>>(),
            "inscription result mismatch");
        Ok(())
    }
    /// No key access, no construction, no new inputs. Unknown RPC outcomes stop this pass.
    pub fn resume(&self, rpc: &Rpc) -> Result<InscribeResult> {
        for saved in &self.transactions { crate::manual_cases::check_saved(rpc,&saved.raw)?; }
        self.validate(rpc)?;
        for saved in &self.transactions {
            match rpc.call("getrawtransaction", serde_json::json!([saved.txid, 0])) {
                Ok(raw) => {
                    anyhow::ensure!(raw.as_str() == Some(saved.raw.as_str()), "known transaction bytes differ from saved plan");
                    continue;
                }
                Err(e) if e.downcast_ref::<crate::RpcCallError>().is_some_and(|e| e.code == -5) => {}
                Err(e) => return Err(e),
            }
            if rpc.checked_target()? > self.expiry_height {
                return Err(RecoveryRequired(format!("saved inscription expired; inspect {} without rebuilding or automatic refund", saved.txid)).into());
            }
            rpc.send_raw(&saved.raw)?;
        }
        Ok(self.result.clone())
    }
}

/// Save the entire signed chain before the first broadcast, preserving it across lost replies.
pub fn save_cli_plan(db:&mut crate::index::Db,plan:&SignedInscription)->Result<()> {
    use rusqlite::OptionalExtension;
    let t=db.conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let id=&plan.result.inscription_id;let value=serde_json::to_string(plan)?;
    let old:Option<String>=t.query_row("SELECT json FROM kv WHERE ns='cli-inscription-plans' AND k=?1",[id],|r|r.get(0)).optional()?;
    if let Some(old)=old {anyhow::ensure!(serde_json::from_str::<serde_json::Value>(&old)?==serde_json::from_str::<serde_json::Value>(&value)?,"saved CLI plan differs; refusing overwrite");}
    else {t.execute("INSERT INTO kv(ns,k,json) VALUES('cli-inscription-plans',?1,?2)",rusqlite::params![id,value])?;}
    t.commit()?;Ok(())
}
pub fn resume_cli_plan(id:&str)->Result<()> {
    let db=crate::index::Db::open(crate::index::DB_FILE)?;
    let reclaim:bool=db.conn.query_row("SELECT EXISTS(SELECT 1 FROM kv WHERE ns='expired-reclaims' AND k=?1)",[id],|r|r.get(0))?;
    anyhow::ensure!(!reclaim,"inscription has a saved reclaim; original reveal resume disabled pending reconciliation");
    let raw:String=db.conn.query_row("SELECT json FROM kv WHERE ns='cli-inscription-plans' AND k=?1",[id],|r|r.get(0))?;
    let plan:SignedInscription=serde_json::from_str(&raw)?;
    let result=plan.resume(&Rpc::open()?)?;
    println!("inscription id {} -> {}",result.inscription_id,plan.destination);Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn inscribe_with(
    rpc: &Rpc, key: &Key, content: &[u8], content_type: &[u8], dest: &str,
    pay: Option<(&str, u64)>, change_to: &TransparentAddress, commit_extra: Vec<OutputSpec>,
) -> Result<InscribeResult> {
    let plan=prepare_inscription(rpc, key, content, content_type, dest, pay, change_to, commit_extra)?;
    plan.validate(rpc)?;
    save_cli_plan(&mut crate::index::Db::open(crate::index::DB_FILE)?,&plan)?;
    println!("saved CLI inscription plan {}",plan.result.inscription_id);
    plan.resume(rpc)
}

#[cfg(test)]
mod inclusive_tests {
    use super::*;
    #[test]
    fn inclusive_budget_refuses_dust_fragmentation_and_insufficient_costs() {
        let addr=Key::from_secret(&[8;32]).unwrap().address();
        let b=InclusiveBudget {total_zat:100000,service_to:addr.clone()};
        for (cost,have,n) in [(90000,100000,4),(50000,99999,1),(50000,100001,1),(50000,100000,101),(50000,100000,0)] {
            let e=inclusive_outputs(&b,cost,have,n,&addr).err().unwrap();
            assert!(e.downcast_ref::<RecoveryRequired>().is_some());
        }
    }
    #[test]
    fn inclusive_outputs_build_and_sign_without_hidden_change_or_extra_fees() {
        let key=Key::from_secret(&[8;32]).unwrap();
        let b=InclusiveBudget {total_zat:10000000,service_to:key.address()};
        for (n,excess) in [(1,0),(2,0),(4,0),(1,546),(4,1000),(100,0)] {
            let have=b.total_zat+excess;
            let inputs:Vec<_>=(0..n).map(|i|InputSpec {pubkey:key.pk,outpoint:OutPoint::new([9;32],i as u32),coin:TxOut::new(zat(have/n as u64+if i==0 {have%n as u64}else{0}).unwrap(),key.address().script().into())}).collect();
            let mut outs=vec![OutputSpec {to:key.address(),value:5015546}];
            outs.extend(inclusive_outputs(&b,5015546,have,n,&key.address()).unwrap());
            let pczt=build_pczt(crate::index::Net::Regtest,2,41,&inputs,&outs,&key.address()).unwrap();
            let pczt=IoFinalizer::new(pczt).finalize_io(rand::rng()).unwrap();
            let mut signer=Signer::new(pczt).unwrap();
            for i in 0..n { signer.sign_transparent(i,&key.sk).unwrap(); }
            let tx=finalize_tx(signer.finish()).unwrap();let actual=&tx.transparent_bundle().unwrap().vout;
            assert_eq!(actual.len(),outs.len());
            for (a,e) in actual.iter().zip(&outs) { assert_eq!(a.value().into_u64(),e.value); }
            let fee=have-actual.iter().map(|o|o.value().into_u64()).sum::<u64>();
            assert_eq!(fee,5000*n.max(outs.len()).max(2) as u64);
            assert_eq!(outs[0].value+outs[1].value+fee,b.total_zat);
        }
    }
}

#[cfg(test)]
#[path = "reveal_auth_tests.rs"]
mod reveal_auth_tests;
