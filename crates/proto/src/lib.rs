//! Prototype: transparent-only Zcash wallet operations against a Zebra JSON-RPC node,
//! used to prove the atomic listing/purchase flow (SIGHASH_SINGLE | ANYONECANPAY).
//!
//! Commands
//!   keygen <name>                       create keys/<name>.key, print address
//!   addr <name>                         print address for a key
//!   utxos <address>                     list UTXOs (getaddressutxos)
//!   send <from> <to-addr> <zat>         simple P2PKH spend
//!   list <seller> <txid:n> <price-zat> <expiry-height> > listing.json
//!   buy <buyer> listing.json <dest-addr>  complete and broadcast the purchase
//!
//! Keys are read from files, never from arguments or the environment.

pub use pczt;
pub mod index;
pub mod inscribe;
pub mod network;
#[path = "../../market_fee.rs"]
pub mod market_fee;
pub mod purchase;
pub mod payment_history;
pub mod settlement_audit;
pub mod service_settlement;
pub mod service_payout;
pub mod service_recovery;
pub mod service_late;
pub mod manual_review;
pub mod manual_cases;
pub mod refund_claim;
pub mod reclaim;
mod test_budget;

use std::{fs, path::PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use pczt::roles::{
    creator::Creator, io_finalizer::IoFinalizer, signer::Signer, spend_finalizer::SpendFinalizer,
    tx_extractor::TransactionExtractor, updater::Updater,
};
use rand_core::{OsRng, RngCore};
use secp256k1::{Message, PublicKey, SecretKey, ecdsa::Signature};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use zcash_address::ZcashAddress;
use zcash_primitives::transaction::{
    Transaction,
    builder::{BuildConfig, Builder, BundlePadding, Error as BuildError},
    fees::zip317::FeeRule,
};
use zcash_protocol::{
    consensus::{BlockHeight, NetworkType},
    local_consensus::LocalNetwork,
    value::Zatoshis,
};
use zcash_transparent::{
    address::{Script, TransparentAddress},
    bundle::{OutPoint, TxOut},
    sighash::{SighashType, SighashPolicy},
};

pub const RPC_URL_FILE: &str = "rpc.url"; // one line: http://host:port
pub const CARRIER_ZAT: u64 = 546;
const LISTING_SIGHASH_POLICY: SighashPolicy = SighashPolicy::EMPTY.permitting(SighashType::SINGLE_ANYONECANPAY);

// ---------------------------------------------------------------- network params

/// Regtest with every upgrade through NU6.3 active from height 1.
pub fn regtest() -> LocalNetwork {
    let h = Some(BlockHeight::from_u32(1));
    LocalNetwork {
        overwinter: h,
        sapling: h,
        blossom: h,
        heartwood: h,
        canopy: h,
        nu5: h,
        nu6: h,
        nu6_1: h,
        nu6_2: h,
        nu6_3: h,
        nu7: None,
    }
}

// ---------------------------------------------------------------- rpc

#[derive(Debug)]
pub struct RpcCallError { pub code: i64, pub message: String }
impl std::fmt::Display for RpcCallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { write!(f, "RPC {}: {}", self.code, self.message) }
}
impl std::error::Error for RpcCallError {}

pub mod rpc_usage;
mod rpc_pacing;
mod rpc_cookie;
pub mod market_relay;

pub struct Rpc {
    pub url: String,
    pub chain: network::ChainConfig,
    agent: ureq::Agent,
}

impl Rpc {
    pub fn open() -> Result<Self> {
        let url = fs::read_to_string(RPC_URL_FILE)
            .context("missing rpc.url (one line, e.g. http://127.0.0.1:18232)")?;
        let rpc = Self {
            url: url.trim().to_string(),
            chain: network::ChainConfig::load()?,
            agent: ureq::AgentBuilder::new()
                .redirects(0)
                .timeout_connect(std::time::Duration::from_secs(10))
                .timeout_read(std::time::Duration::from_secs(30))
                .timeout_write(std::time::Duration::from_secs(30))
                .build(),
        };
        rpc.checked_target()?;
        Ok(rpc)
    }
    pub fn call(&self, method: &str, params: Value) -> Result<Value> {
        let started=std::time::Instant::now();
        let result=self.call_inner(method,params);
        rpc_usage::record(method,result.is_err(),started.elapsed().as_millis().min(u64::MAX as u128) as u64);
        result
    }
    fn call_inner(&self, method: &str, params: Value) -> Result<Value> {
        rpc_pacing::wait(self.net() == index::Net::Regtest)?;
        let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
        let cookie = std::env::var_os("OVERSTORY_RPC_COOKIE_FILE");
        let auth = rpc_cookie::authorization(&self.url, cookie.as_deref().map(std::path::Path::new))?;
        let mut request = self.agent.post(&self.url);
        if let Some(auth) = auth { request = request.set("Authorization", &auth); }
        let (response, status) = match request.send_json(body) {
            Ok(r) => (r, None),
            Err(ureq::Error::Status(code, r)) => (r, Some(code)),
            Err(ureq::Error::Transport(t)) => bail!("RPC transport failure: {:?}", t.kind()),
        };
        let resp: Value = response.into_json().context("invalid RPC JSON response")?;
        if let Some(err) = resp.get("error").filter(|e| !e.is_null()) {
            return Err(RpcCallError { code: err["code"].as_i64().context("missing RPC error code")?, message: err["message"].as_str().context("missing RPC error message")?.into() }.into());
        }
        anyhow::ensure!(status.is_none(), "RPC HTTP status {}", status.unwrap_or(0));
        Ok(resp["result"].clone())
    }
    pub fn height(&self) -> Result<u32> {
        Ok(u32::try_from(
            self.call("getblockcount", json!([]))?
                .as_u64()
                .context("height")?,
        )?)
    }
    pub fn utxos(&self, addr: &str) -> Result<Vec<Utxo>> {
        parse_taddr_for(addr, self.net().network_type())?;
        let v = self.call("getaddressutxos", json!([{"addresses": [addr]}]))?;
        let mut out = vec![];
        for u in v.as_array().context("utxos array")? {
            out.push(Utxo {
                txid: u["txid"].as_str().context("txid")?.to_string(),
                n: u32::try_from(u["outputIndex"].as_u64().context("outputIndex")?)?,
                script: u["script"].as_str().context("script")?.to_string(),
                value: u["satoshis"].as_u64().context("satoshis")?,
                height: u32::try_from(u["height"].as_u64().context("UTXO height")?)?,
            });
        }
        Ok(out)
    }
    pub fn send_raw(&self, hex_tx: &str) -> Result<String> {
        let target = self.checked_target()?;
        let bytes = hex::decode(hex_tx)?;
        let mut cursor = std::io::Cursor::new(&bytes);
        let tx = Transaction::read(&mut cursor, self.net().branch_for(target))?;
        anyhow::ensure!(
            cursor.position() as usize == bytes.len(),
            "trailing transaction bytes"
        );
        let target = self.checked_window(u32::from(tx.expiry_height()))?;
        let branch = network::validate_window(self.net(), target, u32::from(tx.expiry_height()))?;
        anyhow::ensure!(
            tx.consensus_branch_id() == branch
                && tx.version()
                    == zcash_primitives::transaction::TxVersion::suggested_for_branch(branch),
            "transaction epoch/version mismatch"
        );
        manual_cases::check_raw(self, hex_tx)?;
        test_budget::before_broadcast(self, &tx, hex_tx)?;
        let id = self
            .call("sendrawtransaction", json!([hex_tx]))
            .with_context(|| format!("broadcast not acknowledged; check transaction {} before retrying", tx.txid()))?
            .as_str()
            .context("txid")?
            .to_owned();
        anyhow::ensure!(
            id == tx.txid().to_string(),
            "broadcast response txid mismatch; check local txid before retrying"
        );
        Ok(id)
    }
}

/// Carrier lock: UTXOs the indexer knows to carry an inscription (plus outputs of
/// incomplete chains) are never selected for fees or plain value sends. Only `transfer`
/// and `list` may name a carrier explicitly.
pub fn locked_outpoints() -> Result<std::collections::BTreeSet<String>> {
    let st = index::load_state()?;
    let mut set: std::collections::BTreeSet<String> = st.carriers.keys().cloned().collect();
    set.extend(st.pending.keys().cloned());
    set.extend(refund_claim::reserved_inputs(&index::Db::open(index::DB_FILE)?.conn)?);
    Ok(set)
}

impl Rpc {
    /// UTXOs of `addr` that are safe to spend as plain value. Refuses to answer if the
    /// indexer is behind the chain tip by more than a block, because an unindexed block
    /// could contain a new carrier.
    pub fn spendable(&self, addr: &str) -> Result<Vec<Utxo>> {
        let st = index::load_state()?;
        service_settlement::ensure_spend_address(&index::Db::open(index::DB_FILE)?.conn,addr)?;
        let tip = self.checked_target()? - 1;
        anyhow::ensure!(
            st.network.as_deref() == Some(self.net().name()),
            "index network mismatch"
        );
        if st.height != tip {
            bail!(
                "indexer at height {} but chain tip is {tip}: run `proto index` before spending",
                st.height
            );
        }
        let mut locked: std::collections::BTreeSet<_> = st.carriers.keys().cloned().collect();
        locked.extend(st.pending.keys().cloned());
        locked.extend(refund_claim::reserved_inputs(&index::Db::open(index::DB_FILE)?.conn)?);
        let all = self.utxos(addr)?;
        anyhow::ensure!(
            self.height()? == tip,
            "chain advanced during coin selection; reindex and retry"
        );
        if let Some(expected) = &st.tip_hash {
            anyhow::ensure!(
                self.call("getblockhash", json!([tip]))?.as_str() == Some(expected.as_str()),
                "index no longer matches canonical chain"
            );
        }
        let (carriers, free): (Vec<_>, Vec<_>) = all
            .into_iter()
            .partition(|u| locked.contains(&format!("{}:{}", u.txid, u.n)));
        if !carriers.is_empty() {
            eprintln!(
                "funding lock: {} UTXO(s) at {addr} carry inscriptions or refund reservations and were excluded",
                carriers.len()
            );
        }
        let mut ready = vec![];
        for u in free {
            if self.validate_utxo(&u).is_ok() {
                ready.push(u);
            }
        }
        anyhow::ensure!(
            self.checked_target()? - 1 == tip,
            "chain advanced during input verification"
        );
        Ok(ready)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Utxo {
    pub txid: String, // display order (big-endian hex)
    pub n: u32,
    pub script: String,
    pub value: u64,
    pub height: u32,
}

impl Utxo {
    pub fn outpoint(&self) -> Result<OutPoint> {
        Ok(OutPoint::new(txid_bytes(&self.txid)?, self.n))
    }
    pub fn coin(&self) -> Result<TxOut> {
        Ok(TxOut::new(
            zat(self.value)?,
            script_from_raw(&hex::decode(&self.script)?)?,
        ))
    }
}

/// `Script::read` expects a length-prefixed encoding; the RPC gives raw script bytes.
pub fn script_from_raw(raw: &[u8]) -> Result<Script> {
    let mut buf = Vec::with_capacity(raw.len() + 3);
    match raw.len() {
        n if n < 253 => buf.push(n as u8),
        n if n <= 0xffff => {
            buf.push(0xfd);
            buf.extend_from_slice(&(n as u16).to_le_bytes());
        }
        _ => bail!("script too long"),
    }
    buf.extend_from_slice(raw);
    Ok(Script::read(&buf[..])?)
}

/// Display-order txid hex -> internal byte order.
pub fn txid_bytes(display_hex: &str) -> Result<[u8; 32]> {
    let mut b: Vec<u8> = hex::decode(display_hex)?;
    b.reverse();
    b.try_into().map_err(|_| anyhow!("txid must be 32 bytes"))
}

pub fn zat(v: u64) -> Result<Zatoshis> {
    Zatoshis::from_u64(v).map_err(|_| anyhow!("bad amount {v}"))
}

// ---------------------------------------------------------------- keys

pub struct Key {
    pub sk: SecretKey,
    pub pk: PublicKey,
}

impl Key {
    pub fn path(name: &str) -> PathBuf {
        PathBuf::from("keys").join(format!("{name}.key"))
    }
    pub fn generate(name: &str) -> Result<Self> {
        let mut raw = [0u8; 32];
        OsRng.fill_bytes(&mut raw);
        fs::create_dir_all("keys")?;
        let p = Self::path(name);
        if p.exists() {
            bail!("{} already exists", p.display());
        }
        fs::write(&p, hex::encode(raw))?;
        Self::load(name)
    }
    pub fn from_secret(raw: &[u8]) -> Result<Self> {
        let sk = SecretKey::from_secret_bytes(raw.try_into().context("secret must be 32 bytes")?)?;
        let pk = PublicKey::from_secret_key(&sk);
        Ok(Self { sk, pk })
    }
    pub fn random() -> Self {
        let mut raw = [0u8; 32];
        OsRng.fill_bytes(&mut raw);
        Self::from_secret(&raw).expect("random key")
    }
    pub fn secret_hex(&self) -> String {
        hex::encode(self.sk.to_secret_bytes())
    }
    pub fn load(name: &str) -> Result<Self> {
        let raw = hex::decode(fs::read_to_string(Self::path(name))?.trim())?;
        let sk = SecretKey::from_secret_bytes(raw.as_slice().try_into().context("secret must be 32 bytes")?)?;
        let pk = PublicKey::from_secret_key(&sk);
        Ok(Self { sk, pk })
    }
    pub fn address(&self) -> TransparentAddress {
        TransparentAddress::from_pubkey(&self.pk)
    }
    pub fn address_string(&self, net: index::Net) -> String {
        self.address().to_zcash_address(net.network_type()).encode()
    }
}

pub fn parse_taddr(s: &str) -> Result<TransparentAddress> {
    ZcashAddress::try_from_encoded(s)
        .map_err(|e| anyhow!("address parse: {e}"))?
        .convert::<TransparentAddress>()
        .map_err(|e| anyhow!("not a transparent address: {e:?}"))
}

pub fn parse_taddr_for(s: &str, network: NetworkType) -> Result<TransparentAddress> {
    let addr = parse_taddr(s)?;
    anyhow::ensure!(
        addr.to_zcash_address(network).encode() == s,
        "transparent address belongs to another network"
    );
    Ok(addr)
}

// ---------------------------------------------------------------- tx building

pub fn build_config() -> BuildConfig {
    BuildConfig::Standard {
        sapling_anchor: None,
        orchard_anchor: None,
        ironwood_anchor: None,
        orchard_padding: BundlePadding::DEFAULT,
        ironwood_padding: BundlePadding::DEFAULT,
    }
}

pub struct InputSpec {
    pub pubkey: PublicKey,
    pub outpoint: OutPoint,
    pub coin: TxOut,
}

pub struct OutputSpec {
    pub to: TransparentAddress,
    pub value: u64,
}

/// Builds a PCZT with the given inputs/outputs in exactly the given order, appending a
/// change output to `change_to` if the balance requires it.
pub fn build_pczt(
    net: index::Net,
    target_height: u32,
    expiry_height: u32,
    inputs: &[InputSpec],
    outputs: &[OutputSpec],
    change_to: &TransparentAddress,
) -> Result<pczt::Pczt> {
    network::validate_window(net, target_height, expiry_height)?;
    const DUST: u64 = 5_000;
    let total_in = inputs.iter().try_fold(0u64, |v, i| {
        v.checked_add(i.coin.value().into_u64())
            .context("input total overflow")
    })?;
    let total_out = outputs.iter().try_fold(0u64, |v, o| {
        v.checked_add(o.value).context("output total overflow")
    })?;
    zat(total_in)?;
    zat(total_out)?;
    let make = |change: Option<u64>| -> Result<Builder<index::Net, ()>> {
        let mut b = Builder::new(net, BlockHeight::from_u32(target_height), build_config())
            .with_expiry_height(BlockHeight::from_u32(expiry_height));
        for i in inputs {
            b.add_transparent_p2pkh_input(i.pubkey, i.outpoint.clone(), i.coin.clone())
                .map_err(|e| anyhow!("add input: {e:?}"))?;
        }
        for o in outputs {
            b.add_transparent_output(&o.to, zat(o.value)?)
                .map_err(|e| anyhow!("add output: {e:?}"))?;
        }
        if let Some(c) = change {
            b.add_transparent_output(change_to, zat(c)?)
                .map_err(|e| anyhow!("add change: {e:?}"))?;
        }
        Ok(b)
    };
    let mut change: Option<u64> = None;
    for _attempt in 0..4 {
        match make(change)?.build_for_pczt(rand::rng(), &FeeRule::standard()) {
            Ok(res) => {
                return Creator::build_from_parts(res.pczt_parts)
                    .context("tx version incompatible with PCZT");
            }
            Err(BuildError::ChangeRequired(amt)) => {
                let amt = i64::from(amt) as u64;
                change = Some(change.unwrap_or(0) + amt);
            }
            Err(BuildError::InsufficientFunds(amt)) => {
                let amt = i64::from(amt) as u64;
                match change {
                    Some(c) if c > amt + DUST => change = Some(c - amt),
                    Some(_) => break, // remainder too small to be worth an output: fold it into the fee
                    None => bail!("insufficient funds: short by {amt} zat"),
                }
            }
            Err(e) => bail!("build: {e:?}"),
        }
    }
    // Fixed fee = everything left after the requested outputs (no change output).
    let fee = total_in
        .checked_sub(total_out)
        .context("insufficient funds")?;
    anyhow::ensure!(
        fee <= 5_000 * inputs.len().max(outputs.len()).max(2) as u64 + 10_000,
        "refusing excessive fallback fee"
    );
    let fixed = zcash_primitives::transaction::fees::fixed::FeeRule::non_standard(zat(fee)?);
    match make(None)?.build_for_pczt(rand::rng(), &fixed) {
        Ok(res) => {
            Creator::build_from_parts(res.pczt_parts).context("tx version incompatible with PCZT")
        }
        Err(e) => bail!("build with fixed fee {fee}: {e:?}"),
    }
}

pub fn finalize_tx(signed: pczt::Pczt) -> Result<Transaction> {
    finalize_tx_with_policy(signed, SighashPolicy::ALL_ONLY)
}
fn finalize_tx_with_policy(signed: pczt::Pczt, policy: SighashPolicy) -> Result<Transaction> {
    let finalized = SpendFinalizer::new(signed)
        .with_sighash_policy(policy)
        .finalize_spends()
        .map_err(|e| anyhow!("finalize spends: {e:?}"))?;
    TransactionExtractor::new(finalized)
        .extract(rand::rng())
        .map_err(|e| anyhow!("extract: {e:?}"))
}

pub fn finish_and_broadcast(rpc: &Rpc, signed: pczt::Pczt) -> Result<String> {
    let tx = finalize_tx(signed)?;
    let mut raw = vec![];
    tx.write(&mut raw)?;
    let local_txid = tx.txid().to_string();
    let txid = rpc.send_raw(&hex::encode(&raw))?;
    println!(
        "broadcast ok  txid={txid}  (local {local_txid})  bytes={}",
        raw.len()
    );
    Ok(txid)
}

// ---------------------------------------------------------------- listing format

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct Listing {
    pub version: u32,
    pub network: String,
    pub branch: String,
    pub carrier_txid: String,
    pub carrier_vout: u32,
    pub carrier_value: u64,
    pub carrier_script: String,
    pub seller_pubkey: String,
    pub payout_address: String,
    pub price_zat: u64,
    pub expiry_height: u32,
    /// Index at which the carrier input and payout output must sit in the final tx.
    pub slot: usize,
    /// DER signature (no sighash byte), SIGHASH_SINGLE|ANYONECANPAY over slot input/output.
    pub signature_der: String,
}

// ---------------------------------------------------------------- commands

pub fn cmd_keygen(name: &str) -> Result<()> {
    let net = network::ChainConfig::load()?.net()?;
    let k = Key::generate(name)?;
    println!("{}", k.address_string(net));
    Ok(())
}

pub fn cmd_addr(name: &str) -> Result<()> {
    println!(
        "{}",
        Key::load(name)?.address_string(network::ChainConfig::load()?.net()?)
    );
    Ok(())
}

pub fn cmd_utxos(addr: &str) -> Result<()> {
    let rpc = Rpc::open()?;
    let tip = rpc.height()?;
    for u in rpc.utxos(addr)? {
        println!(
            "{}:{}  {} zat  h={} conf={}",
            u.txid,
            u.n,
            u.value,
            u.height,
            tip + 1 - u.height
        );
    }
    Ok(())
}

pub fn cmd_send(from: &str, to: &str, amount: u64) -> Result<()> {
    let rpc = Rpc::open()?;
    let key = Key::load(from)?;
    let me = key.address();
    let tip = rpc.height()?;
    let mut utxos = rpc.spendable(&key.address_string(rpc.net()))?;
    // Prefer older UTXOs so coinbase outputs are mature; then larger first.
    utxos.sort_by_key(|u| (u.height, std::cmp::Reverse(u.value)));
    let mut picked = vec![];
    let mut total = 0u64;
    for u in utxos {
        total += u.value;
        picked.push(u);
        if total >= amount + 50_000 {
            break;
        }
    }
    if total < amount + 10_000 {
        bail!("not enough funds: have {total}, need {amount}+fee");
    }
    let inputs: Vec<InputSpec> = picked
        .iter()
        .map(|u| {
            Ok(InputSpec {
                pubkey: key.pk,
                outpoint: u.outpoint()?,
                coin: u.coin()?,
            })
        })
        .collect::<Result<_>>()?;
    let outputs = vec![OutputSpec {
        to: parse_taddr_for(to, rpc.net().network_type())?,
        value: amount,
    }];
    let pczt = build_pczt(
        rpc.net(),
        rpc.checked_window(tip + 40)?,
        tip + 40,
        &inputs,
        &outputs,
        &me,
    )?;
    let pczt = IoFinalizer::new(pczt)
        .finalize_io(rand::rng())
        .map_err(|e| anyhow!("io finalize: {e:?}"))?;
    let mut signer = Signer::new(pczt).map_err(|e| anyhow!("signer: {e:?}"))?;
    for i in 0..inputs.len() {
        signer
            .sign_transparent(i, &key.sk)
            .map_err(|e| anyhow!("sign {i}: {e:?}"))?;
    }
    finish_and_broadcast(&rpc, signer.finish())?;
    Ok(())
}

/// `transfer <key> <txid:n> <dest>`: spend a carrier so that the inscription lands on output 0.
pub fn cmd_transfer(from: &str, outpoint: &str, dest: &str) -> Result<()> {
    let rpc = Rpc::open()?;
    let key = Key::load(from)?;
    let me = key.address();
    let (txid, n) = outpoint.split_once(':').context("outpoint txid:n")?;
    let n: u32 = n.parse()?;
    let carrier = rpc
        .utxos(&key.address_string(rpc.net()))?
        .into_iter()
        .find(|u| u.txid == txid && u.n == n)
        .context("carrier not found")?;
    let mut utxos = rpc.spendable(&key.address_string(rpc.net()))?;
    utxos.sort_by_key(|u| std::cmp::Reverse(u.value));
    let fee_src = utxos
        .into_iter()
        .find(|u| u.value >= 100_000)
        .context("no fee UTXO")?;
    let tip = rpc.height()?;
    let inputs = vec![
        InputSpec {
            pubkey: key.pk,
            outpoint: carrier.outpoint()?,
            coin: carrier.coin()?,
        },
        InputSpec {
            pubkey: key.pk,
            outpoint: fee_src.outpoint()?,
            coin: fee_src.coin()?,
        },
    ];
    let outputs = vec![OutputSpec {
        to: parse_taddr_for(dest, rpc.net().network_type())?,
        value: carrier.value,
    }];
    let pczt = build_pczt(
        rpc.net(),
        rpc.checked_window(tip + 40)?,
        tip + 40,
        &inputs,
        &outputs,
        &me,
    )?;
    let pczt = IoFinalizer::new(pczt)
        .finalize_io(rand::rng())
        .map_err(|e| anyhow!("io finalize: {e:?}"))?;
    let mut signer = Signer::new(pczt).map_err(|e| anyhow!("signer: {e:?}"))?;
    for i in 0..2 {
        signer
            .sign_transparent(i, &key.sk)
            .map_err(|e| anyhow!("sign {i}: {e:?}"))?;
    }
    finish_and_broadcast(&rpc, signer.finish())?;
    Ok(())
}

// ---------------------------------------------------------------- market

/// A listing without its signature yet, plus the digest the seller must sign.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ListingTemplate {
    pub listing: Listing,
    pub digest: String, // hex, 32 bytes; SIGHASH_SINGLE|ANYONECANPAY over slot input/output
}

fn listing_template_pczt(
    listing: &Listing,
    seller_pk: &PublicKey,
    target_height: u32,
) -> Result<pczt::Pczt> {
    let net = index::Net::parse(&listing.network)?;
    anyhow::ensure!(
        listing.version == 2 && listing.slot == 1 && listing.carrier_value == CARRIER_ZAT,
        "unsupported listing shape"
    );
    anyhow::ensure!(
        listing.branch
            == network::branch_name(network::validate_window(
                net,
                target_height,
                listing.expiry_height
            )?),
        "listing consensus mismatch"
    );
    zat(listing.price_zat)?;
    anyhow::ensure!(listing.price_zat > 0, "zero listing price");
    let payout = parse_taddr_for(&listing.payout_address, net.network_type())?;
    let expected_script: Script = TransparentAddress::from_pubkey(seller_pk).script().into();
    anyhow::ensure!(
        hex::decode(&listing.carrier_script)? == index::script_bytes(&expected_script),
        "carrier is not owned by seller key"
    );
    anyhow::ensure!(
        payout == TransparentAddress::from_pubkey(seller_pk),
        "payout must belong to seller key"
    );
    let slot = listing.slot;
    // Placeholder slot 0: values are irrelevant to the SINGLE|ANYONECANPAY digest, but the
    // builder insists on a balanced transaction, so make it balance exactly.
    let fee_guess = 10_000u64; // 2 inputs / 2 outputs under ZIP 317
    let ph_in_value = listing
        .price_zat
        .checked_add(fee_guess + 1_000)
        .context("listing price overflow")?;
    let ph_out_value = ph_in_value + listing.carrier_value - listing.price_zat - fee_guess;
    let carrier = Utxo {
        txid: listing.carrier_txid.clone(),
        n: listing.carrier_vout,
        script: listing.carrier_script.clone(),
        value: listing.carrier_value,
        height: 0,
    };
    let placeholder = InputSpec {
        pubkey: *seller_pk,
        outpoint: OutPoint::new([0x11; 32], 0),
        coin: TxOut::new(zat(ph_in_value)?, payout.script().into()),
    };
    let mut inputs = vec![placeholder];
    inputs.insert(
        slot,
        InputSpec {
            pubkey: *seller_pk,
            outpoint: carrier.outpoint()?,
            coin: carrier.coin()?,
        },
    );
    let mut outputs = vec![OutputSpec {
        to: payout.clone(),
        value: ph_out_value,
    }];
    outputs.insert(
        slot,
        OutputSpec {
            to: payout.clone(),
            value: listing.price_zat,
        },
    );
    let pczt = build_pczt(
        net,
        target_height,
        listing.expiry_height,
        &inputs,
        &outputs,
        &payout,
    )?;
    set_slot_sighash(pczt, slot, seller_pk)
}

/// Builds the listing template for `carrier` (must be a P2PKH output of `seller_pk`).
pub fn prepare_listing(
    rpc: &Rpc,
    carrier: &Utxo,
    seller_pk: &PublicKey,
    price: u64,
    expiry: u32,
    network: &str,
    ntype: NetworkType,
) -> Result<ListingTemplate> {
    let payout = TransparentAddress::from_pubkey(seller_pk)
        .to_zcash_address(ntype)
        .encode();
    let target = rpc.checked_window(expiry)?;
    rpc.validate_utxo(carrier)?;
    anyhow::ensure!(
        rpc.index_snapshot()?
            .single_carrier(&format!("{}:{}", carrier.txid, carrier.n))
            .is_some(),
        "listing requires one indexed inscription"
    );
    anyhow::ensure!(
        network == rpc.net().name() && ntype == rpc.net().network_type(),
        "requested listing network mismatch"
    );
    let listing = Listing {
        version: 2,
        branch: network::branch_name(rpc.net().branch_for(target)).into(),
        network: network.to_string(),
        carrier_txid: carrier.txid.clone(),
        carrier_vout: carrier.n,
        carrier_value: carrier.value,
        carrier_script: carrier.script.clone(),
        seller_pubkey: hex::encode(seller_pk.serialize()),
        payout_address: payout,
        price_zat: price,
        expiry_height: expiry,
        slot: 1,
        signature_der: String::new(),
    };
    let pczt = listing_template_pczt(&listing, seller_pk, target)?;
    let signer = Signer::new(pczt).map_err(|e| anyhow!("signer: {e:?}"))?
        .with_transparent_sighash_policy(LISTING_SIGHASH_POLICY);
    let digest = signer
        .transparent_sighash(listing.slot)
        .map_err(|e| anyhow!("sighash: {e:?}"))?;
    Ok(ListingTemplate {
        listing,
        digest: hex::encode(digest),
    })
}

/// Verifies `sig_der` against the template (through the library's own check) and returns
/// the completed listing.
pub fn finalize_listing(rpc: &Rpc, template: &ListingTemplate, sig_der: &str) -> Result<Listing> {
    let seller_pk = PublicKey::from_slice(&hex::decode(&template.listing.seller_pubkey)?)?;
    let sig = Signature::from_der(&hex::decode(sig_der)?)?;
    anyhow::ensure!(
        template.listing.network == rpc.net().name(),
        "listing network mismatch"
    );
    let target = rpc.checked_window(template.listing.expiry_height)?;
    let pczt = listing_template_pczt(&template.listing, &seller_pk, target)?;
    let mut signer = Signer::new(pczt).map_err(|e| anyhow!("signer: {e:?}"))?
        .with_transparent_sighash_policy(LISTING_SIGHASH_POLICY);
    signer
        .append_transparent_signature(template.listing.slot, sig)
        .map_err(|e| anyhow!("listing signature rejected: {e:?}"))?;
    let mut l = template.listing.clone();
    l.signature_der = sig_der.to_string();
    Ok(l)
}

pub fn set_slot_sighash(
    pczt: pczt::Pczt,
    slot: usize,
    seller_pk: &PublicKey,
) -> Result<pczt::Pczt> {
    let pk_bytes = seller_pk.serialize().to_vec();
    Updater::new(pczt)
        .update_transparent_with(|mut u| {
            u.update_input_with(slot, |mut iu| {
                iu.set_sighash_type(SighashType::SINGLE_ANYONECANPAY)?;
                iu.set_hash160_preimage(pk_bytes);
                Ok(())
            })
        })
        .map_err(|e| anyhow!("updater: {e:?}"))
        .map(|u| u.finish())
}

/// Executes a purchase: `funding` inputs (all controlled by `funder`) plus the listed
/// carrier -> [dest (postage), seller payout, change -> change_to]. Returns the txid.
pub fn execute_purchase(
    rpc: &Rpc,
    listing: &Listing,
    funder: &Key,
    funding: &[Utxo],
    dest: &str,
    change_to: &TransparentAddress,
) -> Result<String> {
    execute_purchase_with(rpc, listing, funder, funding, dest, change_to, vec![])
}

#[allow(clippy::too_many_arguments)]
pub fn execute_purchase_with(
    rpc: &Rpc,
    listing: &Listing,
    funder: &Key,
    funding: &[Utxo],
    dest: &str,
    change_to: &TransparentAddress,
    extra: Vec<OutputSpec>,
) -> Result<String> {
    anyhow::ensure!(
        listing.network == rpc.net().name(),
        "listing network mismatch"
    );
    let target = rpc.checked_window(listing.expiry_height)?;
    let seller = PublicKey::from_slice(&hex::decode(&listing.seller_pubkey)?)?;
    listing_template_pczt(listing, &seller, target)?;
    let tip = target - 1;
    if listing.expiry_height <= tip {
        bail!("listing expired at {} (tip {tip})", listing.expiry_height);
    }
    let st = rpc.index_snapshot()?;
    let point = format!("{}:{}", listing.carrier_txid, listing.carrier_vout);
    anyhow::ensure!(
        st.single_carrier(&point).is_some(),
        "carrier must contain exactly one indexed inscription"
    );
    let carrier = Utxo {
        txid: listing.carrier_txid.clone(),
        n: listing.carrier_vout,
        value: listing.carrier_value,
        script: listing.carrier_script.clone(),
        height: tip,
    };
    rpc.validate_utxo(&carrier)?;
    let locked = locked_outpoints()?;
    for u in funding {
        anyhow::ensure!(
            !locked.contains(&format!("{}:{}", u.txid, u.n)),
            "funding would consume an inscription"
        );
        rpc.validate_utxo(u)?;
    }
    let tx = build_purchase(
        rpc.net(),
        target,
        listing,
        funder,
        funding,
        dest,
        change_to,
        extra,
        50_000,
    )?;
    let mut raw = vec![];
    tx.write(&mut raw)?;
    rpc.send_raw(&hex::encode(raw))
}

/// Official-market construction. The recipient and maximum fee are explicit buyer approvals.
#[allow(clippy::too_many_arguments)]
pub fn build_market_purchase(
    net: index::Net, target: u32, listing: &Listing, funder: &Key,
    funding: &[Utxo], dest: &str, change_to: &TransparentAddress,
    fee_recipient: &str, max_market_fee: u64, max_network_fee: u64,
) -> Result<Transaction> {
    let q = market_fee::quote(listing.price_zat).map_err(anyhow::Error::msg)?;
    anyhow::ensure!(q.market_fee_zat <= max_market_fee, "market fee exceeds approval");
    let recipient = parse_taddr_for(fee_recipient, net.network_type())?;
    anyhow::ensure!(matches!(recipient, TransparentAddress::PublicKeyHash(_)), "market recipient must be P2PKH");
    build_purchase(net, target, listing, funder, funding, dest, change_to,
        vec![OutputSpec { to: recipient, value: q.market_fee_zat }], max_network_fee)
}

#[allow(clippy::too_many_arguments)]
pub fn build_purchase(
    net: index::Net,
    target: u32,
    listing: &Listing,
    funder: &Key,
    funding: &[Utxo],
    dest: &str,
    change_to: &TransparentAddress,
    extra: Vec<OutputSpec>,
    max_fee: u64,
) -> Result<Transaction> {
    anyhow::ensure!(listing.network == net.name(), "listing network mismatch");
    let seller_pk = PublicKey::from_slice(&hex::decode(&listing.seller_pubkey)?)?;
    listing_template_pczt(listing, &seller_pk, target)?;
    let mut seen = std::collections::BTreeSet::new();
    seen.insert(format!("{}:{}", listing.carrier_txid, listing.carrier_vout));
    let buyer_script = index::script_bytes(&funder.address().script().into());
    for u in funding {
        anyhow::ensure!(
            seen.insert(format!("{}:{}", u.txid, u.n)),
            "duplicate purchase input"
        );
        anyhow::ensure!(
            hex::decode(&u.script)? == buyer_script,
            "funding belongs to another key"
        );
    }
    let seller_sig = Signature::from_der(&hex::decode(&listing.signature_der)?)?;
    let carrier = Utxo {
        txid: listing.carrier_txid.clone(),
        n: listing.carrier_vout,
        script: listing.carrier_script.clone(),
        value: listing.carrier_value,
        height: 0,
    };
    if funding.is_empty() {
        bail!("no funding inputs");
    }
    let mut inputs: Vec<InputSpec> = funding
        .iter()
        .map(|u| {
            Ok(InputSpec {
                pubkey: funder.pk,
                outpoint: u.outpoint()?,
                coin: u.coin()?,
            })
        })
        .collect::<Result<_>>()?;
    inputs.insert(
        listing.slot,
        InputSpec {
            pubkey: seller_pk,
            outpoint: carrier.outpoint()?,
            coin: carrier.coin()?,
        },
    );
    // Output 0 receives the inscription (first non-data transparent output); output at
    // `slot` is the seller payout (SIGHASH_SINGLE pairs it with the carrier input).
    let mut outputs = vec![OutputSpec {
        to: parse_taddr_for(dest, net.network_type())?,
        value: CARRIER_ZAT,
    }];
    outputs.insert(
        listing.slot,
        OutputSpec {
            to: parse_taddr_for(&listing.payout_address, net.network_type())?,
            value: listing.price_zat,
        },
    );
    outputs.extend(extra);
    let pczt = build_pczt(
        net,
        target,
        listing.expiry_height,
        &inputs,
        &outputs,
        change_to,
    )?;
    let total_in = pczt.transparent().inputs().iter().try_fold(0u64, |a, i| {
        a.checked_add(*i.value()).context("input overflow")
    })?;
    let total_out = pczt.transparent().outputs().iter().try_fold(0u64, |a, o| {
        a.checked_add(*o.value()).context("output overflow")
    })?;
    let fee = total_in.checked_sub(total_out).context("negative fee")?;
    anyhow::ensure!(fee <= max_fee, "purchase exceeds approved network fee");
    let pczt = set_slot_sighash(pczt, listing.slot, &seller_pk)?;
    let pczt = IoFinalizer::new(pczt)
        .finalize_io(rand::rng())
        .map_err(|e| anyhow!("io finalize: {e:?}"))?;
    let mut signer = Signer::new(pczt).map_err(|e| anyhow!("signer: {e:?}"))?
        .with_transparent_sighash_policy(LISTING_SIGHASH_POLICY);
    signer
        .append_transparent_signature(listing.slot, seller_sig)
        .map_err(|e| anyhow!("seller signature rejected: {e:?}"))?;
    signer = signer.with_transparent_sighash_policy(SighashPolicy::ALL_ONLY);
    for i in 0..inputs.len() {
        if i != listing.slot {
            signer
                .sign_transparent(i, &funder.sk)
                .map_err(|e| anyhow!("sign buyer input {i}: {e:?}"))?;
        }
    }
    finalize_tx_with_policy(signer.finish(), SighashPolicy::ALL_ONLY.permitting(SighashType::SINGLE_ANYONECANPAY))
}

/// Seller side: sign only "my carrier input (slot 1) -> payout to me (slot 1)".
pub fn cmd_list(seller: &str, outpoint: &str, price: u64, expiry: u32) -> Result<()> {
    let rpc = Rpc::open()?;
    let key = Key::load(seller)?;
    let (txid, n) = outpoint.split_once(':').context("outpoint txid:n")?;
    let n: u32 = n.parse()?;
    let carrier = rpc
        .utxos(&key.address_string(rpc.net()))?
        .into_iter()
        .find(|u| u.txid == txid && u.n == n)
        .context("carrier UTXO not found at seller address")?;
    anyhow::ensure!(
        index::load_state()?.single_carrier(outpoint).is_some(),
        "single-item listing requires exactly one indexed inscription"
    );
    let template = prepare_listing(
        &rpc,
        &carrier,
        &key.pk,
        price,
        expiry,
        rpc.net().name(),
        rpc.net().network_type(),
    )?;
    let digest: [u8; 32] = hex::decode(&template.digest)?.try_into().unwrap();
    let sig = secp256k1::ecdsa::sign(Message::from_digest(digest), &key.sk);
    let listing = finalize_listing(&rpc, &template, &hex::encode(sig.serialize_der()))?;
    println!("{}", serde_json::to_string_pretty(&listing)?);
    Ok(())
}

pub fn run(args: Vec<String>) -> Result<()> {
    let a =
        |i: usize| -> Result<&str> { args.get(i).map(|s| s.as_str()).context("missing argument") };
    // Serialize local wallet commands with claim registration, so a refund reservation
    // cannot race a plain-value selection in this same runtime. Locks release on crash.
    let _wallet_lock = if matches!(a(0)?, "send"|"transfer"|"list"|"buy-plan"|"buy-broadcast"|"broadcast-signed"|"inscribe"|"inscribe-resume"|"deploy"|"mint"|"refund-claim-compensation-plan"|"refund-claim-compensation-resume"|"refund-claim-register"|"refund-claim-pay"|"refund-claim-advance"|"refund-claim-resume"|"inscribe-reclaim-plan"|"inscribe-reclaim-resume") {
        Some(refund_claim::wallet_lock(std::path::Path::new("indexer/wallet.lock"))?)
    } else {None};
    match a(0)? {
        "inscribe-reclaim-plan" | "inscribe-reclaim-resume" => {
            println!("{}",serde_json::to_string_pretty(&reclaim::command(&args)?)?);Ok(())
        }
        "refund-claim-compensation-plan" | "refund-claim-compensation-resume" | "refund-claim-audit-fees" | "refund-claim-sign" | "refund-claim-check" | "refund-claim-register" | "refund-claim-pay" | "refund-claim-advance" | "refund-claim-resume" => {
            println!("{}",serde_json::to_string_pretty(&refund_claim::command(&args)?)?);Ok(())
        }
        "audit-payment-history" => {
            anyhow::ensure!(args.len()==4,"usage: proto audit-payment-history <order-id> <start-height> <end-height>; at most 2000 blocks, read-only");
            let report=payment_history::audit(&Rpc::open()?,index::DB_FILE,a(1)?,a(2)?.parse()?,a(3)?.parse()?)?;
            println!("{}",serde_json::to_string_pretty(&report)?);Ok(())
        }
        "audit-settlement-late" => {
            anyhow::ensure!(args.len()==2,"usage: proto audit-settlement-late <order-id>; read-only, no payout authorization");
            let report=service_late::audit(&Rpc::open()?,index::DB_FILE,a(1)?)?;
            println!("{}",serde_json::to_string_pretty(&report)?);Ok(())
        }
        "audit-service-settlement" => {
            anyhow::ensure!(args.len()==2,"usage: proto audit-service-settlement <order-id>; read-only, no payout authorization");
            let report=settlement_audit::audit(&Rpc::open()?,index::DB_FILE,a(1)?)?;
            println!("{}",serde_json::to_string_pretty(&report)?);Ok(())
        }
        "review-cases" => {
            anyhow::ensure!(args.len()<=2,"usage: proto review-cases [order-id]; local read-only inventory, no payment authorization");
            println!("{}",serde_json::to_string_pretty(&manual_review::report(index::DB_FILE,args.get(1).map(String::as_str))?)?);Ok(())
        }
        "audit-orders" => {
            anyhow::ensure!(args.len()<=2,"usage: proto audit-orders [order-id]");
            let report=audit::orders(&Rpc::open()?,index::DB_FILE,args.get(1).map(String::as_str))?;
            println!("{}",serde_json::to_string_pretty(&report)?);
            Ok(())
        }
        "check-block" => {
            let rpc = Rpc::open()?;
            let height: u32 = a(1)?.parse()?;
            anyhow::ensure!(height <= rpc.checked_target()? - 1, "height beyond node tip");
            let hash = rpc.call("getblockhash", json!([height]))?;
            let raw = rpc.call("getblock", json!([hash, 0]))?;
            let block = index::parse_block(&hex::decode(raw.as_str().context("block hex")?)?, rpc.net().branch_for(height))?;
            anyhow::ensure!(hash.as_str() == Some(block.hash.as_str()), "block hash mismatch");
            anyhow::ensure!(rpc.call("getblockhash", json!([height]))? == hash, "chain changed during check");
            println!("{}", serde_json::to_string_pretty(&json!({"height":height,"hash":block.hash,"transactions":block.txs.len(),"branch":network::branch_name(rpc.net().branch_for(height)),"scope":"raw block parsing and identity only; not independent consensus validation"}))?);
            Ok(())
        }
        "check-node" => {
            let rpc = Rpc::open()?;
            let target = rpc.checked_target()?;
            let expiry = target.checked_add(20).context("height overflow")?;
            rpc.checked_window(expiry)?;
            println!("{}", serde_json::to_string_pretty(&json!({
                "network": rpc.net().name(), "genesis_hash": rpc.chain.genesis_hash,
                "target_height": target, "expiry_height": expiry,
                "branch": network::branch_name(rpc.net().branch_for(target)),
                "scope": "identity and epoch checks only; not transaction or full-node validation"
            }))?);
            Ok(())
        }
        "keygen" => cmd_keygen(a(1)?),
        "addr" => cmd_addr(a(1)?),
        "utxos" => cmd_utxos(a(1)?),
        "send" => cmd_send(a(1)?, a(2)?, a(3)?.parse()?),
        "list" => cmd_list(a(1)?, a(2)?, a(3)?.parse()?, a(4)?.parse()?),
        "buy" => bail!(
            "use buy-plan <key> <listing> <dest> <inscription> <collection> <max-price-zat> <max-fee-zat> <plan-path>, review it, then buy-broadcast <plan-path>"
        ),
        "buy-plan" => purchase::plan(
            a(1)?,
            a(2)?,
            a(3)?,
            a(4)?,
            a(5)?,
            a(6)?.parse()?,
            a(7)?.parse()?,
            a(8)?,
        ),
        "buy-broadcast" => purchase::broadcast(a(1)?),
        "broadcast-signed" => purchase::broadcast_saved(a(1)?),
        "transfer" => cmd_transfer(a(1)?, a(2)?, a(3)?),
        "inscribe" => {
            let pay = match (args.get(5), args.get(6)) {
                (Some(addr), Some(amt)) => Some((addr.as_str(), amt.parse::<u64>()?)),
                _ => None,
            };
            inscribe::cmd_inscribe(a(1)?, a(2)?, a(3)?, a(4)?, pay)
        }
        "inscribe-resume" => inscribe::resume_cli_plan(a(1)?),
        "index" | "index-key-free" => {
            let max_blocks = match args.as_slice() {
                [_] => u32::MAX,
                [_, flag, value] if flag == "--max-blocks" => {
                    let n = value.parse::<u32>().context("max-blocks must be an integer from 1 to 10000")?;
                    anyhow::ensure!((1..=10000).contains(&n), "max-blocks must be from 1 to 10000");
                    n
                }
                _ => bail!("usage: proto index [--max-blocks <1..10000>]"),
            };
            index::cmd_index_mode(max_blocks, args[0] == "index-key-free")
        },
        // deploy <funder> <name> <supply> <max_per_addr> <price> <pay-addr> [renderer-id]
        "deploy" => {
            let body = serde_json::json!({
                "p": index::PROTOCOL, "v": 1, "op": "deploy",
                "name": a(2)?, "supply": a(3)?.parse::<u64>()?, "max_per_addr": a(4)?.parse::<u64>()?,
                "price": a(5)?.parse::<u64>()?, "pay": a(6)?, "renderer": args.get(7).cloned().unwrap_or_default(),
            });
            let rpc = Rpc::open()?;
            let key = Key::load(a(1)?)?;
            parse_taddr_for(a(6)?, rpc.net().network_type())?;
            anyhow::ensure!(
                !a(2)?.is_empty() && (1..=100_000).contains(&a(3)?.parse::<u64>()?),
                "invalid collection name/supply"
            );
            zat(a(5)?.parse()?)?;
            anyhow::ensure!(
                serde_json::to_vec(&body)?.len() <= 4096,
                "collection declaration too large"
            );
            let renderer = body["renderer"].as_str().context("renderer")?;
            if !(renderer.is_empty() && rpc.net() == index::Net::Regtest) {
                let st = rpc.index_snapshot()?;
                anyhow::ensure!(
                    st.inscriptions
                        .get(renderer)
                        .is_some_and(|r| r.family == "v1" && r.authenticated
                            && r.content_type.starts_with("text/")
                            && !r.content_hex.is_empty()),
                    "renderer must reference indexed verified source"
                );
            }
            let dest = key.address_string(rpc.net());
            inscribe::inscribe(
                &rpc,
                &key,
                &serde_json::to_vec(&body)?,
                b"application/json",
                &dest,
                None,
                &key.address(),
            )?;
            Ok(())
        }
        // mint <funder> <deploy-id> <dest> [pay-addr pay-zat]  (pay defaults come from the indexer state)
        "mint" => {
            let body = serde_json::json!({"p": index::PROTOCOL, "op": "mint", "d": a(2)?});
            let rpc = Rpc::open()?;
            let key = Key::load(a(1)?)?;
            let st = rpc.index_snapshot()?;
            let col = st
                .collections
                .get(a(2)?)
                .context("collection not indexed")?;
            validate_mint_request(
                col,
                a(3)?,
                rpc.net(),
                rpc.checked_target()?,
                args.get(4).map(String::as_str),
                args.get(5).map(String::as_str),
            )?;
            let pay = if col.price > 0 {
                Some((col.pay.as_str(), col.price))
            } else {
                None
            };
            inscribe::inscribe(
                &rpc,
                &key,
                &serde_json::to_vec(&body)?,
                b"application/json",
                a(3)?,
                pay,
                &key.address(),
            )?;
            Ok(())
        }
        other => bail!("unknown command {other}"),
    }
}

/// Preflight does not reserve supply; competing transactions can still win the last mint.
pub fn validate_mint_request(
    col: &index::Collection,
    dest: &str,
    net: index::Net,
    target: u32,
    pay: Option<&str>,
    amount: Option<&str>,
) -> Result<()> {
    anyhow::ensure!(net == index::Net::Regtest || col.authenticated, "new paid mint requires an authenticated collection");
    parse_taddr_for(dest, net.network_type())?;
    parse_taddr_for(&col.pay, net.network_type())?;
    zat(col.price)?;
    anyhow::ensure!(target >= col.start, "mint has not started");
    anyhow::ensure!(col.minted < col.supply, "collection sold out");
    anyhow::ensure!(
        col.max_per_addr == 0 || col.per_addr.get(dest).copied().unwrap_or(0) < col.max_per_addr,
        "address mint cap reached"
    );
    match (pay, amount) {
        (None, None) => {}
        (Some(p), Some(v)) => anyhow::ensure!(
            p == col.pay && v.parse::<u64>()? == col.price,
            "payment override differs from collection rules"
        ),
        _ => bail!("payment address and amount must be supplied together"),
    }
    Ok(())
}
impl Rpc {
    pub fn index_snapshot(&self) -> Result<index::State> {
        let st = index::load_state()?;
        let tip = self.checked_target()? - 1;
        anyhow::ensure!(
            st.network.as_deref() == Some(self.net().name()) && st.height == tip,
            "index must match selected network and exact chain tip"
        );
        anyhow::ensure!(
            st.tip_hash.as_deref() == self.call("getblockhash", json!([tip]))?.as_str(),
            "index canonical hash mismatch"
        );
        Ok(st)
    }
    /// Check both the confirmed raw parent and the mempool-aware live UTXO set.
    pub fn validate_utxo(&self, u: &Utxo) -> Result<()> {
        let live = self.call("gettxout", json!([u.txid, u.n, true]))?;
        anyhow::ensure!(!live.is_null(), "input spent or unavailable");
        let conf = live["confirmations"]
            .as_u64()
            .context("missing UTXO confirmations")?;
        anyhow::ensure!(conf > 0, "unconfirmed funding is not supported");
        let coinbase = live["coinbase"]
            .as_bool()
            .context("missing coinbase flag")?;
        anyhow::ensure!(!coinbase || conf >= 100, "immature coinbase input");
        let raw = self.call("getrawtransaction", json!([u.txid, 0]))?;
        let bytes = hex::decode(raw.as_str().context("raw parent")?)?;
        let mut cursor = std::io::Cursor::new(&bytes);
        let tx = Transaction::read(&mut cursor, self.net().branch_for(u.height.max(1)))?;
        anyhow::ensure!(
            cursor.position() as usize == bytes.len() && tx.txid().to_string() == u.txid,
            "parent transaction identity mismatch"
        );
        let out = tx
            .transparent_bundle()
            .and_then(|b| b.vout.get(u.n as usize))
            .context("parent output missing")?;
        anyhow::ensure!(
            out.value().into_u64() == u.value
                && index::script_bytes(out.script_pubkey()) == hex::decode(&u.script)?,
            "input amount/script differs from raw chain output"
        );
        Ok(())
    }
}

#[cfg(test)]
mod market_tests;

#[cfg(test)]
mod recovery_tests;

pub mod refund;

pub mod audit;
pub mod reorg;
