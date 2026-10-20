//! Signed self-mint sold-out claims. Never infer entitlement from rejection text alone.
use crate::*;
#[path = "claim_fees.rs"]
mod claim_fees;
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use sha2::{Digest, Sha256};

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
pub struct Claim {
    pub version: u32,
    pub network: String,
    pub genesis_hash: String,
    pub collection: String,
    pub inscription: String,
    pub destination: String,
    pub received_zat: u64,
    pub public_key: String,
    pub signature: String,
}
impl Claim {
    fn digest(&self) -> Result<[u8; 32]> {
        // Fixed ordered tuple; signature excluded, every authorization field included.
        let payload = serde_json::to_vec(&(
            self.version,
            &self.network,
            &self.genesis_hash,
            &self.collection,
            &self.inscription,
            &self.destination,
            self.received_zat,
            &self.public_key,
        ))?;
        let mut h = Sha256::new();
        h.update(b"Overstory/self-mint-sold-out-refund/v1\0");
        h.update(payload);
        Ok(h.finalize().into())
    }
    fn verify_signature(&self) -> Result<()> {
        anyhow::ensure!(self.version == 1, "unsupported claim version");
        let pk = PublicKey::from_slice(&hex::decode(&self.public_key)?)?;
        anyhow::ensure!(
            hex::encode(pk.serialize()) == self.public_key,
            "noncanonical claim public key"
        );
        Signature::from_der(&hex::decode(&self.signature)?)?
            .verify(Message::from_digest(self.digest()?), &pk)?;
        Ok(())
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MintDeclaration {
    p: String,
    op: String,
    d: String,
}
struct Evidence {
    key: String,
    receipts: Vec<Utxo>,
}
fn block(rpc: &Rpc, height: u32, expected: &str) -> Result<index::Block> {
    anyhow::ensure!(
        rpc.call("getblockhash", json!([height]))?.as_str() == Some(expected),
        "claim block is not canonical"
    );
    let raw = rpc.call("getblock", json!([expected, 0]))?;
    let b = index::parse_block(
        &hex::decode(raw.as_str().context("missing raw block")?)?,
        rpc.net().branch_for(height),
    )?;
    anyhow::ensure!(b.hash == expected, "raw claim block differs");
    Ok(b)
}
fn anchor(rpc: &Rpc, st: &index::State) -> Result<()> {
    anyhow::ensure!(
        st.network.as_deref() == Some(rpc.net().name()) && rpc.checked_target()? - 1 == st.height,
        "claim requires synchronized index"
    );
    anyhow::ensure!(
        rpc.call("getblockhash", json!([st.height]))?.as_str() == st.tip_hash.as_deref(),
        "claim index anchor changed"
    );
    Ok(())
}
// Completion history is only a locator. Canonical raw blocks and the linked
// transaction bodies below prove identity; a current owner may already be a transfer.
fn completion_txid(ins: &index::Inscription) -> Result<String> {
    let prefix = format!("h{} completed in ", ins.completion_height);
    let entry = ins.history.first().context("missing completion history")?;
    let (txid, output) = entry.strip_prefix(&prefix).context("invalid completion history")?
        .split_once(" -> ").context("invalid completion output")?;
    anyhow::ensure!(txid.len() == 64 && hex::encode(hex::decode(txid)?) == txid
        && output == format!("{txid}:0"), "invalid completion transaction locator");
    Ok(txid.into())
}
struct RevealParts {
    total: usize,
    commitment: [u8; 32],
    pieces: Vec<Vec<u8>>,
}
impl RevealParts {
    fn add_backwards(&mut self, env: &index::Envelope) -> Result<()> {
        anyhow::ensure!(env.total == self.total && env.c == Some(self.commitment)
            && env.content_type == b"application/json", "reveal chain changes its declaration");
        // Transactions are traversed backwards. Each transaction sends descending
        // piece indexes, so reversing its pieces must extend exactly 0,1,2,...
        for (i, bytes) in env.pieces.iter().rev() {
            anyhow::ensure!(*i == self.pieces.len() && *i < self.total,
                "reveal chain contains missing, reordered or repeated pieces");
            self.pieces.push(bytes.clone());
        }
        Ok(())
    }
    fn finish(self, ins: &index::Inscription) -> Result<Vec<u8>> {
        anyhow::ensure!(self.pieces.len() == self.total, "incomplete reveal chain");
        let bytes: Vec<u8> = self.pieces.into_iter().flatten().collect();
        anyhow::ensure!(bytes.len() <= 4096 && bytes.len() == ins.content_len
            && hex::encode(&bytes) == ins.content_hex
            && hex::encode(Sha256::digest(&bytes)) == ins.content_sha256
            && self.commitment == inscribe::commitment(b"application/json", &bytes),
            "mint content commitment mismatch");
        Ok(bytes)
    }
}
fn reveal_chain(rpc: &Rpc, ins: &index::Inscription, genesis: &str)
    -> Result<(String, String, Vec<TxOut>, Vec<u8>)> {
    anyhow::ensure!(ins.genesis_height <= ins.completion_height, "invalid reveal heights");
    let completion = completion_txid(ins)?;
    let b = block(rpc, ins.completion_height, &ins.completion_block_hash)?;
    anyhow::ensure!((ins.genesis_height == ins.completion_height)
        == (ins.genesis_block_hash == ins.completion_block_hash), "reveal block heights and identities disagree");
    if ins.genesis_block_hash == ins.completion_block_hash {
        let first = b.txs.iter().position(|(id,_)| id == genesis).context("genesis absent from canonical block")?;
        let last = b.txs.iter().position(|(id,_)| id == &completion).context("completion absent from canonical block")?;
        anyhow::ensure!(first <= last, "completion precedes genesis");
    } else {
        anyhow::ensure!(block(rpc,ins.genesis_height,&ins.genesis_block_hash)?.txs.iter().any(|(id,_)|id==genesis),
            "genesis absent from canonical block");
    }
    let mut tx = b.txs.into_iter().find(|(id,_)| id == &completion)
        .context("mint absent from canonical completion block")?.1;
    let outputs = tx.transparent_bundle().context("mint has no transparent bundle")?.vout.clone();
    let mut parts: Option<RevealParts> = None;
    for _ in 0..64 {
        let current = tx.txid().to_string();
        let tb = tx.transparent_bundle().context("reveal bundle missing")?;
        let input = tb.vin.first().context("mint input missing")?;
        let ss = index::script_bytes(input.script_sig());
        let env = index::parse_envelope(&ss).context("invalid reveal envelope")?;
        let commitment = env.c.context("uncommitted reveal")?;
        let assembled = parts.get_or_insert_with(|| RevealParts{total:env.total,commitment,pieces:Vec::new()});
        assembled.add_backwards(&env)?;
        let pushes = index::parse_pushes(&ss).context("missing reveal pushes")?;
        let redeem = pushes.last().context("missing redeem")?;
        let key = hex::encode(redeem.get(1..34).context("missing reveal key")?);
        let mut parent_bytes = *input.prevout().hash(); parent_bytes.reverse();
        let parent_id = hex::encode(parent_bytes);
        let raw = rpc.call("getrawtransaction",json!([parent_id,0]))?;
        let bytes = hex::decode(raw.as_str().context("missing reveal parent bytes")?)?;
        let mut cur = std::io::Cursor::new(&bytes);
        let parent = Transaction::read(&mut cur,rpc.net().branch_for(ins.completion_height))?;
        anyhow::ensure!(cur.position() as usize == bytes.len() && parent.txid().to_string() == parent_id,
            "reveal parent identity mismatch");
        let prev = parent.transparent_bundle().context("reveal parent bundle")?.vout
            .get(input.prevout().n() as usize).context("reveal parent output")?;
        let expected: Script = TransparentAddress::ScriptHash(inscribe::hash160(redeem)).script().into();
        anyhow::ensure!(*prev.script_pubkey() == expected, "reveal key not committed by spent output");
        if current == genesis {
            return Ok((key,completion,outputs,parts.take().unwrap().finish(ins)?));
        }
        anyhow::ensure!(input.prevout().n() == 0 && assembled.pieces.len() < assembled.total,
            "reveal chain does not lead to original inscription");
        // A canonical completion spends this exact ancestor. Verify every parent
        // txid/script, rather than trusting an RPC's height or a mutable owner field.
        tx = parent;
    }
    bail!("reveal chain exceeds 64 transactions")
}
fn evidence(rpc: &Rpc, st: &index::State, collection: &str, id: &str) -> Result<Evidence> {
    anchor(rpc, st)?;
    let ins = st
        .inscriptions
        .get(id)
        .context("unknown mint inscription")?;
    let col = st
        .collections
        .get(collection)
        .context("unknown collection")?;
    anyhow::ensure!(
        ins.family == "v1" && ins.content_type == "application/json" && !st.mints.contains_key(id),
        "not a failed committed mint"
    );
    anyhow::ensure!(
        st.rejected
            .iter()
            .any(|s| s == &format!("{id} mint: supply exhausted")),
        "not a sold-out rejection"
    );
    anyhow::ensure!(
        col.max_per_addr == 0 && col.price > 0 && ins.completion_height >= col.start,
        "unsupported cap/free mint or premature mint"
    );
    let txid = id.strip_suffix("i0").context("invalid inscription id")?;
    anyhow::ensure!(
        txid.len() == 64 && hex::encode(hex::decode(txid)?) == txid,
        "invalid mint txid"
    );
    let (key, completion, outputs, bytes) = reveal_chain(rpc, ins, txid)?;
    let m: MintDeclaration = serde_json::from_slice(&bytes)?;
    anyhow::ensure!(m.p == index::PROTOCOL && m.op == "mint" && m.d == collection,
        "wrong mint declaration");
    let first = outputs.first().context("mint destination missing")?;
    anyhow::ensure!(
        index::address_of(
            &index::script_bytes(first.script_pubkey()),
            rpc.net().network_type()
        )
        .is_some(),
        "invalid original NFT destination"
    );
    let receipts = payment_receipts(
        outputs.as_slice(),
        &col.pay,
        col.price,
        rpc.net(),
        &completion,
        ins.completion_height,
    )?;
    for u in &receipts {
        let point = format!("{}:{}", u.txid, u.n);
        anyhow::ensure!(
            !st.carriers.contains_key(&point) && !st.pending.contains_key(&point),
            "payment contains inscription"
        );
    }
    anchor(rpc, st)?;
    Ok(Evidence { key, receipts })
}
fn payment_receipts(
    outputs: &[TxOut],
    pay_address: &str,
    price: u64,
    net: index::Net,
    txid: &str,
    height: u32,
) -> Result<Vec<Utxo>> {
    let pay = index::script_bytes(
        &parse_taddr_for(&pay_address, net.network_type())?
            .script()
            .into(),
    );
    let mut receipts = Vec::new();
    let mut total = 0u64;
    for (n, out) in outputs.iter().enumerate() {
        if index::script_bytes(out.script_pubkey()) == pay {
            // Output zero carries the failed inscription: do not consume it as a cash refund.
            anyhow::ensure!(
                n != 0,
                "payment shares inscription carrier; manual review required"
            );
            let value = out.value().into_u64();
            total = total.checked_add(value).context("payment overflow")?;
            receipts.push(Utxo {
                txid: txid.into(),
                n: u32::try_from(n)?,
                script: hex::encode(&pay),
                value,
                height,
            });
        }
    }
    anyhow::ensure!(
        total >= price,
        "sold-out attempt underpaid; no automatic refund"
    );
    anyhow::ensure!(
        !receipts.is_empty() && receipts.len() <= 100,
        "unsupported payment count"
    );
    Ok(receipts)
}
fn verify(rpc: &Rpc, st: &index::State, c: &Claim) -> Result<Evidence> {
    c.verify_signature()?;
    anyhow::ensure!(
        c.network == rpc.net().name() && c.genesis_hash == rpc.chain.genesis_hash,
        "claim chain mismatch"
    );
    parse_taddr_for(&c.destination, rpc.net().network_type())?;
    let e = evidence(rpc, st, &c.collection, &c.inscription)?;
    anyhow::ensure!(
        e.key == c.public_key && e.receipts.iter().map(|u| u.value).sum::<u64>() == c.received_zat,
        "claim signer/payment differs from original reveal"
    );
    Ok(e)
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Advance {
    version:u32,
    mode:String,
    reason:String,
    reserve_address:String,
    source:Utxo,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    claim: Claim,
    receipts: Vec<Utxo>,
    plan: Option<refund::RefundPlan>,
    confirmation: Option<refund::RefundConfirmation>,
    #[serde(default,skip_serializing_if="Option::is_none")]
    advance:Option<Advance>,
}
fn reserve(db: &Connection, c: &Claim, receipts: &[Utxo]) -> Result<Record> {
    let old: Option<String> = db
        .query_row(
            "SELECT json FROM kv WHERE ns='self-mint-refunds' AND k=?1",
            [&c.inscription],
            |r| r.get(0),
        )
        .optional()?;
    if let Some(raw) = old {
        let r: Record = serde_json::from_str(&raw)?;
        // Compare authorization, not ECDSA encoding (which can have equivalent signatures).
        anyhow::ensure!(
            r.claim.digest()? == c.digest()?
                && serde_json::to_value(&r.receipts)? == serde_json::to_value(receipts)?,
            "claim already reserved with different authorization/evidence"
        );
        return Ok(r);
    }
    for u in receipts {
        let point = format!("{}:{}", u.txid, u.n);
        db.execute(
            "INSERT INTO kv(ns,k,json) VALUES('self-mint-refund-inputs',?1,?2)",
            params![point, serde_json::to_string(&c.inscription)?],
        )?;
    }
    let r = Record {
        claim: c.clone(),
        receipts: receipts.to_vec(),
        plan: None,
        confirmation: None,
        advance:None,
    };
    save(db, &r)?;
    Ok(r)
}
fn save(db: &Connection, r: &Record) -> Result<()> {
    db.execute("INSERT INTO kv(ns,k,json) VALUES('self-mint-refunds',?1,?2) ON CONFLICT(ns,k) DO UPDATE SET json=excluded.json",params![r.claim.inscription,serde_json::to_string(r)?])?;
    Ok(())
}
fn advance_amounts(received:u64,mode:&str)->Result<(u64,u64)> {
    zat(received)?;
    let input=match mode {
        "normal"=>received,
        "project-fault"=>received.checked_add(10000).context("advance overflow")?,
        _=>bail!("choose normal or project-fault"),
    };
    let (refund,fee)=refund::amounts(input,1)?.context("small liability remains unpaid; no reserve signature created")?;
    anyhow::ensure!(fee==10000,"unexpected single-input refund fee");Ok((input,refund))
}
fn check_advance(db:&Connection,rpc:&Rpc,st:&index::State,r:&Record)->Result<()> {
    let a=r.advance.as_ref().context("missing advance")?;
    let p=r.plan.as_ref().context("advance lacks signed refund")?;
    let action_raw:String=db.query_row("SELECT json FROM kv WHERE ns='operator-actions' AND k=?1",[format!("self-mint-advance:{}",r.claim.inscription)],|row|row.get(0))?;
    let action:Value=serde_json::from_str(&action_raw)?;
    anyhow::ensure!(action["inscription"]==r.claim.inscription && action["mode"]==a.mode && action["reason"]==a.reason
        && action["source"]==format!("{}:{}",a.source.txid,a.source.n) && action["broadcast"]==false,"advance operator attribution changed");
    let (input,refund)=advance_amounts(r.claim.received_zat,&a.mode)?;
    anyhow::ensure!(a.version==1 && (1..=512).contains(&a.reason.trim().len()),"invalid advance attribution");
    p.validate(rpc)?;
    anyhow::ensure!(p.destination==r.claim.destination && p.input_zat==input && p.refund_zat==refund && p.fee_zat==10000 && p.funding.len()==1
        && serde_json::to_value(&p.funding[0])?==serde_json::to_value(&a.source)?,"advance plan differs from authorized liability/source");
    check_reserve_source(db,rpc.net(),st,r,&a.reserve_address,&a.source)?;
    let point=format!("{}:{}",a.source.txid,a.source.n);
    let owner:String=db.query_row("SELECT json FROM kv WHERE ns='self-mint-refund-inputs' AND k=?1",[&point],|row|row.get(0))?;
    anyhow::ensure!(serde_json::from_str::<String>(&owner)?==r.claim.inscription,"advance reservation owner changed");
    let conflict:bool=db.query_row("SELECT EXISTS(SELECT 1 FROM kv WHERE k=?1 AND ns IN ('reclaim-inputs','service-settlement-inputs','manual-inputs'))",[&point],|row|row.get(0))?;
    anyhow::ensure!(!conflict,"advance source overlaps another workflow");
    anyhow::ensure!(audit::receipt(rpc,&a.source,&a.reserve_address)?["state"]=="confirmed","advance source is not canonical");
    Ok(())
}
fn check_reserve_source(db:&Connection,net:index::Net,st:&index::State,r:&Record,address:&str,u:&Utxo)->Result<()> {
    let script=hex::encode(index::script_bytes(&parse_taddr_for(address,net.network_type())?.script().into()));
    anyhow::ensure!(u.script==script,"reserve address differs from source");
    let claimant=TransparentAddress::PublicKeyHash(inscribe::hash160(&hex::decode(&r.claim.public_key)?));
    let destination=parse_taddr_for(&r.claim.destination,net.network_type())?;
    anyhow::ensure!(script!=hex::encode(index::script_bytes(&claimant.script().into())) && script!=hex::encode(index::script_bytes(&destination.script().into()))
        && r.receipts.iter().all(|x|x.script!=script && x.txid!=u.txid),"use independent project reserve, not claimant, recipient or original payment funds");
    let point=format!("{}:{}",u.txid,u.n);
    anyhow::ensure!(!st.carriers.contains_key(&point) && !st.pending.contains_key(&point),"reserve carries an inscription");
    unrelated_inputs(db,&[u.clone()])?;
    service_payout::reserve_is_independent(db,address,u)
}
fn summary(r: &Record) -> Value {
    json!({"inscription":r.claim.inscription,"destination":r.claim.destination,"received_zat":r.claim.received_zat,
 "status":if r.confirmation.is_some(){"confirmed"}else if r.plan.is_some(){"signed_pending"}else{"registered_liability"},
 "refund_zat":r.plan.as_ref().map(|p|p.refund_zat),"fee_zat":r.plan.as_ref().map(|p|p.fee_zat),"txid":r.plan.as_ref().map(|p|&p.txid),"confirmation":r.confirmation,"confirmation_is_cached":true,"funding_mode":r.advance.as_ref().map(|a|a.mode.as_str()).unwrap_or("original_receipts"),"project_fee_zat":if r.advance.as_ref().is_some_and(|a|a.mode=="project-fault"){10000}else{0}})
}
pub fn command(args: &[String]) -> Result<Value> {
    let rpc = Rpc::open()?;
    let st = index::load_state()?;
    match args.first().map(String::as_str) {
        Some("refund-claim-compensation-plan" | "refund-claim-compensation-resume") => claim_fees::command(&rpc,args),
        Some("refund-claim-audit-fees") => {
            anyhow::ensure!(args.len()==2,"usage: refund-claim-audit-fees <inscription>");
            claim_fees::report(&rpc,&args[1])
        }
        Some("refund-claim-sign") => {
            anyhow::ensure!(
                args.len() == 5,
                "usage: refund-claim-sign <reveal-key-name> <collection> <inscription> <refund-address>"
            );
            parse_taddr_for(&args[4], rpc.net().network_type())?;
            let e = evidence(&rpc, &st, &args[2], &args[3])?;
            let key = Key::load(&args[1])?;
            anyhow::ensure!(
                hex::encode(key.pk.serialize()) == e.key,
                "key is not original reveal signer"
            );
            let mut c = Claim {
                version: 1,
                network: rpc.net().name().into(),
                genesis_hash: rpc.chain.genesis_hash.clone(),
                collection: args[2].clone(),
                inscription: args[3].clone(),
                destination: args[4].clone(),
                received_zat: e.receipts.iter().map(|u| u.value).sum(),
                public_key: e.key,
                signature: String::new(),
            };
            c.signature = hex::encode(
                secp256k1::ecdsa::sign(Message::from_digest(c.digest()?), &key.sk).serialize_der(),
            );
            Ok(serde_json::to_value(c)?)
        }
        Some("refund-claim-check" | "refund-claim-register") => {
            anyhow::ensure!(
                args.len() == 2,
                "usage: refund-claim-check|refund-claim-register <signed-claim.json>"
            );
            let bytes = fs::read(&args[1])?;
            anyhow::ensure!(bytes.len() <= 16384, "claim too large");
            let c: Claim = serde_json::from_slice(&bytes)?;
            let e = verify(&rpc, &st, &c)?;
            let mut db = index::Db::open(index::DB_FILE)?;
            unmanaged_claim(&db.conn, &c.inscription)?;
            unrelated_inputs(&db.conn, &e.receipts)?;
            if args[0] == "refund-claim-check" {
                return Ok(
                    json!({"eligible":true,"broadcast":false,"inscription":c.inscription,"received_zat":c.received_zat,"destination":c.destination}),
                );
            }
            let tx = db
                .conn
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            no_reorg(&tx)?;
            let current: String =
                tx.query_row("SELECT v FROM meta WHERE k='tip_hash'", [], |r| r.get(0))?;
            anyhow::ensure!(
                Some(current) == st.tip_hash,
                "index changed before claim reservation"
            );
            unmanaged_claim(&tx, &c.inscription)?;
            unrelated_inputs(&tx, &e.receipts)?;
            let r = reserve(&tx, &c, &e.receipts)?;
            anchor(&rpc, &st)?;
            tx.commit()?;
            Ok(summary(&r))
        }
        Some("refund-claim-pay") | Some("refund-claim-advance") | Some("refund-claim-resume") => {
            anyhow::ensure!(
                args.len() == match args[0].as_str() { "refund-claim-pay"=>3,"refund-claim-advance"=>6,_=>2 },
                "usage: refund-claim-pay <inscription> <treasury-key-name> | refund-claim-advance <inscription> <reserve-key> <txid:n> <normal|project-fault> <reason> | refund-claim-resume <inscription>"
            );
            let mut db = index::Db::open(index::DB_FILE)?;
            let tx = db
                .conn
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            no_reorg(&tx)?;
            let st = index::Db::load_from(&tx)?;
            let raw: String = tx.query_row(
                "SELECT json FROM kv WHERE ns='self-mint-refunds' AND k=?1",
                [&args[1]],
                |r| r.get(0),
            )?;
            let mut r: Record = serde_json::from_str(&raw)?;
            anyhow::ensure!(
                r.claim.inscription == args[1],
                "claim record identity mismatch"
            );
            let e = verify(&rpc, &st, &r.claim)?;
            anyhow::ensure!(
                serde_json::to_value(&r.receipts)? == serde_json::to_value(&e.receipts)?,
                "saved receipts differ from canonical payment"
            );
            for u in &e.receipts {
                let point = format!("{}:{}", u.txid, u.n);
                let owner: String = tx.query_row(
                    "SELECT json FROM kv WHERE ns='self-mint-refund-inputs' AND k=?1",
                    [&point],
                    |r| r.get(0),
                )?;
                anyhow::ensure!(
                    serde_json::from_str::<String>(&owner)? == r.claim.inscription,
                    "refund reservation differs"
                );
            }
            unmanaged_claim(&tx, &r.claim.inscription)?;
            unrelated_inputs(&tx, &e.receipts)?;
            if r.plan.is_none() {
                anyhow::ensure!(r.advance.is_none(),"advance attribution exists without original signed plan");
                anyhow::ensure!(args[0] != "refund-claim-resume","no signed refund; operator must prepare it first");
                let key = Key::load(&args[2])?;
                if args[0]=="refund-claim-advance" {
                    let (input,refund)=advance_amounts(r.claim.received_zat,&args[4])?;
                    anyhow::ensure!((1..=512).contains(&args[5].trim().len()),"provide attribution reason (1..512 bytes)");
                    let address=key.address_string(rpc.net());
                    let candidates:Vec<_>=rpc.utxos(&address)?.into_iter().filter(|u|format!("{}:{}",u.txid,u.n)==args[3]).collect();
                    anyhow::ensure!(candidates.len()==1,"specified reserve outpoint unavailable/ambiguous; never select a replacement");
                    let u=candidates[0].clone();
                    anyhow::ensure!(u.value==input,"reserve input must equal {input} zat; no change or extra funding");
                    anyhow::ensure!(!reserved_inputs(&tx)?.contains(&args[3]),"reserve input already allocated");
                    check_reserve_source(&tx,rpc.net(),&st,&r,&address,&u)?;
                    rpc.validate_utxo(&u)?;
                    anyhow::ensure!(audit::receipt(&rpc,&u,&address)?["state"]=="confirmed","reserve source is not canonical");
                    let plan=refund::RefundPlan::prepare(&rpc,&key,vec![u.clone()],&r.claim.destination)?.context("small liability remains unpaid")?;
                    anyhow::ensure!(plan.refund_zat==refund,"advance amount changed");
                    r.advance=Some(Advance{version:1,mode:args[4].clone(),reason:args[5].clone(),reserve_address:address,source:u});r.plan=Some(plan);
                    tx.execute("INSERT INTO kv(ns,k,json) VALUES('self-mint-refund-inputs',?1,?2)",params![args[3],serde_json::to_string(&r.claim.inscription)?])?;
                    tx.execute("INSERT INTO kv(ns,k,json) VALUES('operator-actions',?1,?2)",params![format!("self-mint-advance:{}",r.claim.inscription),serde_json::to_string(&json!({"inscription":r.claim.inscription,"mode":args[4],"reason":args[5],"source":args[3],"broadcast":false}))?])?;
                    check_advance(&tx,&rpc,&st,&r)?;
                } else {
                    // Original receipts cannot be used once a reserve-backed signature exists.
                    r.plan = refund::RefundPlan::prepare(&rpc, &key, e.receipts, &r.claim.destination)?;
                }
                save(&tx, &r)?;
                anchor(&rpc, &st)?;
                tx.commit()?;
                // Preparation deliberately does not broadcast. A second command recovers original bytes.
                return Ok(summary(&r));
            }
            let plan = r.plan.as_ref().unwrap();
            if let Some(a)=&r.advance {
                check_advance(&tx,&rpc,&st,&r)?;
                anyhow::ensure!(args[0]!="refund-claim-pay","reserve-backed signature exists; use refund-claim-resume");
                if args[0]=="refund-claim-advance" {
                    anyhow::ensure!(a.mode==args[4] && a.reason==args[5] && format!("{}:{}",a.source.txid,a.source.n)==args[3],"advance differs; signed refund must never be replaced");
                }
            } else {
                anyhow::ensure!(args[0]!="refund-claim-advance","original refund already signed; cannot create a second payment");
                anyhow::ensure!(plan.destination==r.claim.destination && plan.input_zat==r.claim.received_zat
                    && serde_json::to_value(&plan.funding)?==serde_json::to_value(&r.receipts)?,"signed refund differs from claim");
            }
            plan.validate(&rpc)?;
            if args[0] != "refund-claim-resume" {
                anchor(&rpc,&st)?;
                tx.commit()?;
                return Ok(summary(&r));
            }
            // While holding the SQLite writer lock, no competing claim can create a replacement.
            // Original bytes were committed by the earlier pay command, before any network side effect.
            r.confirmation = plan.resume(&rpc)?;
            anchor(&rpc,&st)?;
            save(&tx, &r)?;
            tx.commit()?;
            let mut result = summary(&r);
            result["confirmation_is_cached"] = json!(false);
            Ok(result)
        }
        _ => bail!("unknown refund claim command"),
    }
}

pub(crate) fn wallet_lock(path: &std::path::Path) -> Result<std::fs::File> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)?;
    lock.try_lock()
        .context("another wallet command is active for this runtime")?;
    Ok(lock)
}
pub fn reserved_inputs(db: &Connection) -> Result<std::collections::BTreeSet<String>> {
    let mut q =
        db.prepare("SELECT k FROM kv WHERE ns IN ('self-mint-refund-inputs','reclaim-inputs','service-settlement-inputs','manual-inputs')")?;
    Ok(q.query_map([], |r| r.get(0))?
        .collect::<rusqlite::Result<_>>()?)
}
fn no_reorg(db: &Connection) -> Result<()> {
    let barrier: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM meta WHERE k='reorg_pending')",
        [],
        |r| r.get(0),
    )?;
    anyhow::ensure!(!barrier, "reorg reconciliation pending");
    Ok(())
}
fn unmanaged_claim(db: &Connection, id: &str) -> Result<()> {
    let mut q = db.prepare("SELECT json FROM kv WHERE ns='orders'")?;
    for raw in q.query_map([], |r| r.get::<_,String>(0))? {
        let order: Value = serde_json::from_str(&raw?)?;
        anyhow::ensure!(order["mint_plan"]["result"]["inscription_id"].as_str() != Some(id),
            "mint belongs to a managed order; preserve its fixed refund address");
    }
    Ok(())
}
fn unrelated_inputs(db: &Connection, inputs: &[Utxo]) -> Result<()> {
    let mut q =
        db.prepare("SELECT ns,json FROM kv WHERE ns IN ('orders','cli-inscription-plans')")?;
    let rows = q.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
    for row in rows {
        let (ns, raw) = row?;
        let v: Value = serde_json::from_str(&raw)?;
        if ns == "orders" {
            let original_id = format!("{}i0", inputs.first().context("empty receipts")?.txid);
            anyhow::ensure!(
                v["mint_plan"]["result"]["inscription_id"].as_str() != Some(original_id.as_str()),
                "mint belongs to a managed order; preserve its fixed refund address"
            );
            if let Some(addr) = v["invoice_address"].as_str() {
                // All supported networks share the script; network was checked on claim and index.
                let net = inputs.first().context("empty receipts")?;
                for network in [NetworkType::Main, NetworkType::Test, NetworkType::Regtest] {
                    if let Ok(a) = parse_taddr_for(addr, network) {
                        anyhow::ensure!(
                            hex::encode(index::script_bytes(&a.script().into())) != net.script,
                            "payment belongs to managed invoice; use order refund workflow"
                        );
                    }
                }
            }
        }
        fn contains(v: &Value, u: &Utxo) -> bool {
            match v {
                Value::Object(m) => {
                    (m.get("txid").and_then(Value::as_str) == Some(u.txid.as_str())
                        && m.get("n").and_then(Value::as_u64) == Some(u.n as u64))
                        || m.values().any(|v| contains(v, u))
                }
                Value::Array(a) => a.iter().any(|v| contains(v, u)),
                _ => false,
            }
        }
        anyhow::ensure!(
            !inputs.iter().any(|u| contains(&v, u)),
            "payment already recorded by another funding workflow"
        );
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    fn claim() -> Claim {
        let key = Key::from_secret(&[7; 32]).unwrap();
        let mut c = Claim {
            version: 1,
            network: "regtest".into(),
            genesis_hash: "ab".repeat(32),
            collection: format!("{}i0", "01".repeat(32)),
            inscription: format!("{}i0", "02".repeat(32)),
            destination: key.address_string(index::Net::Regtest),
            received_zat: 5000000,
            public_key: hex::encode(key.pk.serialize()),
            signature: String::new(),
        };
        sign(&mut c);
        c
    }
    fn sign(c: &mut Claim) {
        let key = Key::from_secret(&[7; 32]).unwrap();
        c.signature = hex::encode(
            secp256k1::ecdsa::sign(Message::from_digest(c.digest().unwrap()), &key.sk)
                .serialize_der(),
        );
    }
    fn receipt() -> Utxo {
        Utxo {
            txid: "02".repeat(32),
            n: 1,
            script: "76".into(),
            value: 5000000,
            height: 20,
        }
    }
    fn db() -> Connection {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch("CREATE TABLE kv(ns TEXT,k TEXT,json TEXT,PRIMARY KEY(ns,k)); CREATE TABLE meta(k TEXT PRIMARY KEY,v TEXT)").unwrap();
        c
    }
    fn multipart_ins(bytes: &[u8]) -> index::Inscription {
        serde_json::from_value(json!({"id":format!("{}i0","01".repeat(32)),"family":"v1",
            "content_type":"application/json","content_len":bytes.len(),"content_sha256":hex::encode(Sha256::digest(bytes)),
            "content_hex":hex::encode(bytes),"genesis_height":10,"genesis_block_hash":"aa".repeat(32),
            "completion_height":11,"completion_block_hash":"bb".repeat(32),"owner":"later:0","owner_address":null,
            "history":[format!("h11 completed in {} -> {}:0","02".repeat(32),"02".repeat(32))]})).unwrap()
    }
    #[test]
    fn managed_multipart_identity_is_not_inferred_from_final_payment_txid() {
        let db=db();let id=format!("{}i0","01".repeat(32));
        let order=json!({"mint_plan":{"result":{"inscription_id":id}}});
        db.execute("INSERT INTO kv VALUES('orders','managed',?1)",[order.to_string()]).unwrap();
        assert!(unmanaged_claim(&db,&id).is_err());
        unmanaged_claim(&db,&format!("{}i0","02".repeat(32))).unwrap();
    }
    #[test]
    fn completion_locator_ignores_current_owner_but_rejects_malformed_history() {
        let mut ins = multipart_ins(b"{}");
        assert_eq!(completion_txid(&ins).unwrap(),"02".repeat(32));
        for history in [String::new(),format!("h10 completed in {} -> {}:0","02".repeat(32),"02".repeat(32)),
            format!("h11 completed in {} -> {}:1","02".repeat(32),"02".repeat(32)),
            format!("h11 completed in {} -> {}:0","02".repeat(32),"03".repeat(32))] {
            ins.history=vec![history]; assert!(completion_txid(&ins).is_err());
        }
    }
    #[test]
    fn backwards_reveals_reconstruct_exact_content_and_reject_gaps_duplicates_or_changed_commitment() {
        let bytes=vec![b' ';1100];let commitment=inscribe::commitment(b"application/json",&bytes);
        let pieces:Vec<_>=bytes.chunks(240).enumerate().map(|(i,b)|(i,b.to_vec())).collect();
        let env=|indexes:Vec<usize>|index::Envelope{ authenticated: false,total:pieces.len(),content_type:b"application/json".to_vec(),
            c:Some(commitment),pieces:indexes.into_iter().map(|i|pieces[i].clone()).collect()};
        let fresh=||RevealParts{total:pieces.len(),commitment,pieces:vec![]};
        let mut parts=fresh();parts.add_backwards(&env(vec![0])).unwrap();parts.add_backwards(&env(vec![4,3,2,1])).unwrap();
        assert_eq!(parts.finish(&multipart_ins(&bytes)).unwrap(),bytes);
        assert!(fresh().add_backwards(&env(vec![1])).is_err());
        let mut parts=fresh();parts.add_backwards(&env(vec![0])).unwrap();assert!(parts.add_backwards(&env(vec![0])).is_err());
        let mut bad=env(vec![0]);bad.c=Some([0;32]);assert!(fresh().add_backwards(&bad).is_err());
        bad=env(vec![0]);bad.content_type=b"text/plain".to_vec();assert!(fresh().add_backwards(&bad).is_err());
        assert!(fresh().finish(&multipart_ins(&bytes)).is_err());
    }
    #[test]
    fn reconstructed_content_must_match_all_saved_metadata_and_commitment() {
        let bytes=b"{}";let fresh=||RevealParts{total:1,commitment:inscribe::commitment(b"application/json",bytes),pieces:vec![bytes.to_vec()]};
        let ins=multipart_ins(bytes);assert_eq!(fresh().finish(&ins).unwrap(),bytes);
        let mut bad=ins.clone();bad.content_len+=1;assert!(fresh().finish(&bad).is_err());
        bad=ins.clone();bad.content_sha256="00".repeat(32);assert!(fresh().finish(&bad).is_err());
        bad=ins.clone();bad.content_hex="0000".into();assert!(fresh().finish(&bad).is_err());
        let mut parts=fresh();parts.commitment=[0;32];assert!(parts.finish(&ins).is_err());
    }
    #[test]
    fn reserve_refund_policy_accounts_for_every_zatoshi_and_keeps_small_liability() {
        assert_eq!(advance_amounts(50000,"normal").unwrap(),(50000,40000));
        assert_eq!(advance_amounts(50000,"project-fault").unwrap(),(60000,50000));
        assert!(advance_amounts(10545,"normal").is_err());
        assert_eq!(advance_amounts(10546,"normal").unwrap(),(10546,546));
        assert!(advance_amounts(545,"project-fault").is_err());
        assert_eq!(advance_amounts(546,"project-fault").unwrap(),(10546,546));
        assert!(advance_amounts(50000,"override").is_err());
        assert!(advance_amounts(u64::MAX,"project-fault").is_err());
    }
    #[test]
    fn reserve_wallet_cannot_borrow_claimant_original_payment_or_carrier_funds() {
        let db=db();let c=claim();let r=reserve(&db,&c,&[receipt()]).unwrap();let net=index::Net::Regtest;
        let reserve_key=Key::from_secret(&[8;32]).unwrap();let address=reserve_key.address_string(net);
        let u=Utxo{txid:"03".repeat(32),n:0,script:hex::encode(index::script_bytes(&reserve_key.address().script().into())),value:5000000,height:20};
        let mut st=index::State::default();check_reserve_source(&db,net,&st,&r,&address,&u).unwrap();
        let claimant=Key::from_secret(&[7;32]).unwrap();let mut bad=u.clone();bad.script=hex::encode(index::script_bytes(&claimant.address().script().into()));
        assert!(check_reserve_source(&db,net,&st,&r,&claimant.address_string(net),&bad).is_err());
        bad=u.clone();bad.txid=r.receipts[0].txid.clone();assert!(check_reserve_source(&db,net,&st,&r,&address,&bad).is_err());
        st.carriers.insert(format!("{}:0",u.txid),std::collections::BTreeSet::from(["inscription".into()]));
        assert!(check_reserve_source(&db,net,&st,&r,&address,&u).is_err());
        st.carriers.clear();db.execute("INSERT INTO kv VALUES('orders','managed',?1)",[json!({"invoice_address":address}).to_string()]).unwrap();
        assert!(check_reserve_source(&db,net,&st,&r,&address,&u).is_err());
    }
    #[test]
    fn legacy_claims_omit_advance_metadata_and_preserve_original_receipt_mode() {
        let db=db();let r=reserve(&db,&claim(),&[receipt()]).unwrap();let value=serde_json::to_value(&r).unwrap();
        assert!(value.get("advance").is_none());let decoded:Record=serde_json::from_value(value).unwrap();assert!(decoded.advance.is_none());
        assert_eq!(summary(&decoded)["funding_mode"],"original_receipts");assert_eq!(summary(&decoded)["project_fee_zat"],0);
    }
    #[test]
    fn every_authorization_field_is_signed() {
        let c = claim();
        c.verify_signature().unwrap();
        let v = serde_json::to_value(&c).unwrap();
        for (field, value) in [
            ("version", json!(2)),
            ("network", json!("mainnet")),
            ("genesis_hash", json!("cd".repeat(32))),
            ("collection", json!("03".repeat(32) + "i0")),
            ("inscription", json!("04".repeat(32) + "i0")),
            (
                "destination",
                json!(
                    Key::from_secret(&[8; 32])
                        .unwrap()
                        .address_string(index::Net::Regtest)
                ),
            ),
            ("received_zat", json!(1)),
            (
                "public_key",
                json!(hex::encode(
                    Key::from_secret(&[8; 32]).unwrap().pk.serialize()
                )),
            ),
        ] {
            let mut bad = v.clone();
            bad[field] = value;
            assert!(
                serde_json::from_value::<Claim>(bad)
                    .unwrap()
                    .verify_signature()
                    .is_err(),
                "{field}"
            );
        }
    }
    #[test]
    fn strict_schema_and_original_key_authorization() {
        let c = claim();
        let raw = serde_json::to_string(&c).unwrap();
        let duplicate = raw.trim_end_matches('}').to_string() + ",\"received_zat\":1}";
        assert!(serde_json::from_str::<Claim>(&duplicate).is_err());
        let mut v = serde_json::to_value(c).unwrap();
        v["operator_override"] = json!(true);
        assert!(serde_json::from_value::<Claim>(v).is_err());
        assert!(
            serde_json::from_str::<MintDeclaration>(
                r#"{"p":"overstory","op":"mint","d":"a","d":"b"}"#
            )
            .is_err()
        );
    }
    #[test]
    fn repeat_claim_is_idempotent_but_new_signed_address_is_not() {
        let mut db = db();
        let c = claim();
        let u = receipt();
        for _ in 0..2 {
            let tx = db.transaction().unwrap();
            reserve(&tx, &c, &[u.clone()]).unwrap();
            tx.commit().unwrap();
        }
        let count: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM kv WHERE ns='self-mint-refunds'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
        assert_eq!(
            reserved_inputs(&db).unwrap(),
            std::collections::BTreeSet::from([format!("{}:1", "02".repeat(32))])
        );
        let mut new = c.clone();
        new.destination = Key::from_secret(&[8; 32])
            .unwrap()
            .address_string(index::Net::Regtest);
        sign(&mut new);
        new.verify_signature().unwrap();
        let tx = db.transaction().unwrap();
        assert!(reserve(&tx, &new, &[u]).is_err());
    }
    #[test]
    fn outpoint_collision_rolls_back_all_partial_reservations() {
        let mut db = db();
        let c = claim();
        let u = receipt();
        {
            let tx = db.transaction().unwrap();
            reserve(&tx, &c, &[u.clone()]).unwrap();
            tx.commit().unwrap();
        }
        let mut other = c.clone();
        other.inscription = "05".repeat(32) + "i0";
        sign(&mut other);
        let mut fresh = u.clone();
        fresh.n = 2;
        {
            let tx = db.transaction().unwrap();
            assert!(reserve(&tx, &other, &[fresh, u]).is_err());
        }
        let count: i64 = db
            .query_row("SELECT COUNT(*) FROM kv", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 2);
    }
    #[test]
    fn changed_receipt_evidence_cannot_reuse_existing_claim() {
        let db = db();
        let c = claim();
        let mut u = receipt();
        reserve(&db, &c, &[u.clone()]).unwrap();
        u.value += 1;
        assert!(reserve(&db, &c, &[u]).is_err());
    }
    #[test]
    fn rejects_other_workflow_reservations_and_reorg_barrier() {
        let db = db();
        let u = receipt();
        unrelated_inputs(&db, &[u.clone()]).unwrap();
        no_reorg(&db).unwrap();
        db.execute(
            "INSERT INTO kv VALUES('cli-inscription-plans','a',?1)",
            [json!({"funding":[u]}).to_string()],
        )
        .unwrap();
        assert!(unrelated_inputs(&db, &[u]).is_err());
        db.execute("INSERT INTO meta VALUES('reorg_pending','{}')", [])
            .unwrap();
        assert!(no_reorg(&db).is_err());
    }
    #[test]
    fn sold_out_label_does_not_excuse_underpayment_or_spending_a_carrier() {
        let pay = Key::from_secret(&[7; 32]).unwrap();
        let recipient = Key::from_secret(&[8; 32]).unwrap();
        let output = |key: &Key, n| TxOut::new(zat(n).unwrap(), key.address().script().into());
        let inspect = |outputs: Vec<TxOut>| {
            payment_receipts(
                &outputs,
                &pay.address_string(index::Net::Regtest),
                50000,
                index::Net::Regtest,
                &"02".repeat(32),
                20,
            )
        };
        assert!(inspect(vec![output(&recipient, 546), output(&pay, 49999)]).is_err());
        assert!(inspect(vec![output(&recipient, 546), output(&recipient, 50000)]).is_err());
        assert!(inspect(vec![output(&pay, 546), output(&pay, 50000)]).is_err());
        let receipts = inspect(vec![
            output(&recipient, 546),
            output(&pay, 25000),
            output(&recipient, 300),
            output(&pay, 35000),
        ])
        .unwrap();
        assert_eq!(
            receipts.iter().map(|u| (u.n, u.value)).collect::<Vec<_>>(),
            vec![(1, 25000), (3, 35000)]
        );
        assert_eq!(
            refund::amounts(receipts.iter().map(|u| u.value).sum(), receipts.len()).unwrap(),
            Some((50000, 10000))
        );
    }
    #[test]
    fn wallet_lock_releases_after_owner_exits() {
        let path = std::env::temp_dir().join(format!(
            "overstory-wallet-lock-{}-{}.lock",
            std::process::id(),
            rand::random::<u64>()
        ));
        let first = wallet_lock(&path).unwrap();
        assert!(wallet_lock(&path).is_err());
        drop(first);
        drop(wallet_lock(&path).unwrap());
        std::fs::remove_file(path).unwrap();
    }
    #[test]
    fn service_mint_cannot_redirect_refund_through_self_claim_route() {
        let db = db();
        let u = receipt();
        let managed = json!({"invoice_address":Key::from_secret(&[9;32]).unwrap().address_string(index::Net::Regtest),"mint_plan":{"result":{"inscription_id":format!("{}i0",u.txid)}}});
        db.execute(
            "INSERT INTO kv VALUES('orders','service',?1)",
            [managed.to_string()],
        )
        .unwrap();
        assert!(unrelated_inputs(&db, &[u]).is_err());
    }
}
