//! Indexer: replays blocks from the node (one `getblock` per block, parsed locally),
//! detects envelope inscriptions on input 0 of a transaction, tracks carrier-output
//! ownership, and applies the collection protocol (deploy / mint).
//!
//! Working set lives in memory (`State`); every processed block is persisted to SQLite
//! (`Db`) so a restart resumes from the last height. Content bytes are kept only for
//! protocol-relevant inscriptions (small JSON / text); everything else keeps its hash.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::{BlockHeight, BranchId, MAIN_NETWORK, NetworkType, TEST_NETWORK};
use zcash_transparent::address::{Script, TransparentAddress};

use crate::Rpc;
use crate::inscribe::{authenticated_redeem_script, commitment, hash160, redeem_script, script_sig};

fn is_false(value: &bool) -> bool { !*value }

pub const PROTOCOL: &str = "overstory";
pub const DB_FILE: &str = "indexer/index.sqlite";

/// Which chain the indexer reads; decides branch ids and address encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Net {
    Regtest,
    Testnet,
    Mainnet,
}

impl Net {
    pub fn parse(s: &str) -> Result<Self> {
        Ok(match s {
            "regtest" => Net::Regtest,
            "testnet" => Net::Testnet,
            "mainnet" => Net::Mainnet,
            other => anyhow::bail!("unknown network {other}"),
        })
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::Regtest => "regtest",
            Self::Testnet => "testnet",
            Self::Mainnet => "mainnet",
        }
    }
    pub fn network_type(self) -> NetworkType {
        match self {
            Net::Regtest => NetworkType::Regtest,
            Net::Testnet => NetworkType::Test,
            Net::Mainnet => NetworkType::Main,
        }
    }
    pub fn branch_for(self, height: u32) -> BranchId {
        let h = BlockHeight::from_u32(height);
        match self {
            Net::Regtest => BranchId::for_height(&crate::regtest(), h),
            Net::Testnet => BranchId::for_height(&TEST_NETWORK, h),
            Net::Mainnet => BranchId::for_height(&MAIN_NETWORK, h),
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct State {
    pub height: u32,
    pub tip_hash: Option<String>,
    pub network: Option<String>,
    /// First block of a fresh replay; absent for legacy or unproven history.
    #[serde(default)]
    pub replay_from: Option<u32>,
    pub inscriptions: BTreeMap<String, Inscription>,
    /// A carrier can hold multiple inscriptions after a merge. Never discard members.
    pub carriers: BTreeMap<String, BTreeSet<String>>,
    /// continuation outpoint "txid:0" -> incomplete chain
    #[serde(default)]
    pub pending: BTreeMap<String, Pending>,
    /// deploy inscription id -> collection
    #[serde(default)]
    pub collections: BTreeMap<String, Collection>,
    /// mint inscription id -> membership
    #[serde(default)]
    pub mints: BTreeMap<String, Mint>,
    /// audit trail of rejected declarations
    #[serde(default)]
    pub rejected: Vec<String>,
}

impl State {
    /// Local replay provenance, not independent consensus or checkpoint verification.
    pub fn history_scope(&self) -> &'static str {
        match self.replay_from { Some(1) => "from_first_block", Some(_) => "partial", None => "unknown" }
    }
    fn record_replay_start(&mut self, before: &State, height: u32) {
        if before.height == 0 && before.tip_hash.is_none() && before.network.is_none()
            && before.inscriptions.is_empty() && before.carriers.is_empty() && before.pending.is_empty()
            && before.collections.is_empty() && before.mints.is_empty() && before.rejected.is_empty() {
            self.replay_from = Some(height);
        }
    }

    pub fn single_carrier(&self, outpoint: &str) -> Option<&String> {
        let ids = self.carriers.get(outpoint)?;
        if ids.len() == 1 { ids.first() } else { None }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Collection {
    #[serde(default, skip_serializing_if = "is_false")]
    pub authenticated: bool,
    pub id: String,
    pub name: String,
    pub supply: u64,
    pub max_per_addr: u64,
    pub price: u64,
    pub pay: String,
    pub start: u32,
    pub renderer: String,
    pub deployed_height: u32,
    pub minted: u64,
    #[serde(default)]
    pub per_addr: BTreeMap<String, u64>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Mint {
    pub inscription: String,
    pub collection: String,
    pub number: u64,
    pub minter: String,
    pub height: u32,
    pub seed: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Inscription {
    #[serde(default, skip_serializing_if = "is_false")]
    pub authenticated: bool,
    pub id: String,
    pub family: String, // "v1" (commitment verified) | "legacy"
    pub content_type: String,
    pub content_len: usize,
    pub content_sha256: String,
    /// Kept only for protocol-relevant content (see `keep_content`); empty otherwise.
    #[serde(default)]
    pub content_hex: String,
    pub genesis_height: u32,
    pub genesis_block_hash: String,
    pub completion_height: u32,
    pub completion_block_hash: String,
    pub owner: String, // "txid:n" | "burned" | "shielded"
    pub owner_address: Option<String>,
    pub history: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct Pending {
    #[serde(default, skip_serializing_if = "is_false")]
    pub authenticated: bool,
    pub genesis_txid: String,
    pub genesis_height: u32,
    pub genesis_block_hash: String,
    pub total: usize,
    pub content_type: Vec<u8>,
    pub pieces: BTreeMap<usize, String>, // index -> hex
    pub c: Option<String>,
    pub consistent: bool,
    pub reveals: usize,
}

fn keep_content(content_type: &str, len: usize) -> bool {
    (content_type == "application/json" && len <= 4096)
        || (content_type.starts_with("text/") && len <= 65_536)
}

// ---------------------------------------------------------------- script helpers

pub fn script_bytes(s: &Script) -> Vec<u8> {
    let mut v = vec![];
    s.write(&mut v).expect("script write");
    let (len, off) = match v[0] {
        n @ 0..=252 => (n as usize, 1),
        253 => (u16::from_le_bytes([v[1], v[2]]) as usize, 3),
        _ => (u32::from_le_bytes([v[1], v[2], v[3], v[4]]) as usize, 5),
    };
    v[off..off + len].to_vec()
}

pub fn address_of(script: &[u8], net: NetworkType) -> Option<String> {
    let addr = match script {
        [0x76, 0xa9, 0x14, h @ .., 0x88, 0xac] if h.len() == 20 => {
            TransparentAddress::PublicKeyHash(h.try_into().unwrap())
        }
        [0xa9, 0x14, h @ .., 0x87] if h.len() == 20 => {
            TransparentAddress::ScriptHash(h.try_into().unwrap())
        }
        _ => return None,
    };
    Some(addr.to_zcash_address(net).encode())
}

/// Parses a push-only script into data items. Small-number opcodes become one byte.
pub fn parse_pushes(s: &[u8]) -> Option<Vec<Vec<u8>>> {
    let mut out = vec![];
    let mut i = 0;
    while i < s.len() {
        let op = s[i];
        i += 1;
        let (len, hdr) = match op {
            0x00 => {
                out.push(vec![0]);
                continue;
            }
            0x01..=0x4b => (op as usize, 0),
            0x4c => (*s.get(i)? as usize, 1),
            0x4d => (u16::from_le_bytes([*s.get(i)?, *s.get(i + 1)?]) as usize, 2),
            0x51..=0x60 => {
                out.push(vec![op - 0x50]);
                continue;
            }
            _ => return None,
        };
        i += hdr;
        out.push(s.get(i..i + len)?.to_vec());
        i += len;
    }
    Some(out)
}

pub struct Envelope {
    pub authenticated: bool,
    pub total: usize,
    pub content_type: Vec<u8>,
    pub pieces: Vec<(usize, Vec<u8>)>,
    /// Commitment C from the redeem script, if it has the v1 shape.
    pub c: Option<[u8; 32]>,
}

fn parse_legacy_envelope(script: &[u8]) -> Option<Envelope> {
    if script.len() > 1_650 {
        return None;
    }
    let items = parse_pushes(script)?;
    if items.len() < 7 || items[0] != b"ord" || items[1].len() != 1 {
        return None;
    }
    let total = items[1][0] as usize;
    let content_type = items[2].clone();
    if total == 0
        || !(3..=96).contains(&content_type.len())
        || !content_type.iter().all(|b| (0x21..=0x7e).contains(b))
        || !content_type.contains(&b'/')
    {
        return None;
    }
    let redeem = items.last()?;
    let sig = &items[items.len() - 2];
    let body = &items[3..items.len() - 2];
    if body.is_empty() || body.len() % 2 != 0 || body.len() / 2 > 4 {
        return None;
    }
    let mut pieces = Vec::new();
    let mut previous = total;
    for pair in body.chunks_exact(2) {
        if pair[0].len() != 1 {
            return None;
        }
        let i = pair[0][0] as usize;
        let data = &pair[1];
        // The encoder slices in content order, then sends in reverse order.
        // The highest index is the only piece allowed to be shorter than 240 bytes.
        if i >= total
            || i >= previous
            || data.is_empty()
            || data.len() > 240
            || (i != total - 1 && data.len() != 240)
        {
            return None;
        }
        if previous != total && i + 1 != previous {
            return None;
        }
        previous = i;
        pieces.push((i, data.clone()));
    }
    let refs: Vec<_> = pieces.iter().map(|(i, p)| (*i, p.as_slice())).collect();
    if script_sig(&content_type, total, &refs, sig, redeem) != script {
        return None;
    }
    let c = if redeem.len() >= 68 {
        let pk: [u8; 33] = redeem.get(1..34)?.try_into().ok()?;
        let c: [u8; 32] = redeem[36..68].try_into().ok()?;
        if secp256k1::PublicKey::from_slice(&pk).is_ok()
            && redeem_script(&pk, &c, pieces.len()) == *redeem
        {
            Some(c)
        } else {
            None
        }
    } else {
        None
    };
    Some(Envelope {
        authenticated: false,
        total,
        content_type,
        pieces,
        c,
    })
}

/// Decode actual push-stack bytes, including equivalent non-minimal encodings.
fn consensus_pushes(s: &[u8]) -> Option<Vec<Vec<u8>>> {
    if s.len() > 10_000 { return None; }
    let mut out = Vec::new();
    let mut i: usize = 0;
    while i < s.len() {
        let op = s[i]; i += 1;
        let len = match op {
            0 => { out.push(Vec::new()); continue; }
            1..=75 => op as usize,
            0x4c => { let n = *s.get(i)? as usize; i += 1; n }
            0x4d => { let n = u16::from_le_bytes(s.get(i..i+2)?.try_into().ok()?) as usize; i += 2; n }
            0x4e => { let n = u32::from_le_bytes(s.get(i..i+4)?.try_into().ok()?) as usize; i += 4; n }
            0x4f => { out.push(vec![0x81]); continue; }
            0x51..=0x60 => { out.push(vec![op - 0x50]); continue; }
            _ => return None,
        };
        if len > 520 { return None; }
        let end = i.checked_add(len)?;
        out.push(s.get(i..end)?.to_vec()); i = end;
    }
    Some(out)
}

fn parse_authenticated_envelope(script: &[u8]) -> Option<Envelope> {
    let items = consensus_pushes(script)?;
    if items.len() < 7 || items[0] != b"ord" || items[1].len() != 1 { return None; }
    let total = items[1][0] as usize;
    let content_type = items[2].clone();
    if total == 0 || !(3..=96).contains(&content_type.len())
        || !content_type.iter().all(|b| (0x21..=0x7e).contains(b))
        || !content_type.contains(&b'/') { return None; }
    let redeem = items.last()?;
    let body = &items[3..items.len()-2];
    if body.is_empty() || body.len()%2 != 0 || body.len()/2 > 4 { return None; }
    let mut pieces = Vec::new();
    let mut previous = total;
    for pair in body.chunks_exact(2) {
        let i = match pair[0].as_slice() { [] => 0, [n] if *n != 0 => *n as usize, _ => return None };
        let data = &pair[1];
        if i >= total || i >= previous || data.is_empty() || data.len() > 240
            || (i != total-1 && data.len() != 240)
            || (previous != total && i+1 != previous) { return None; }
        previous = i; pieces.push((i, data.clone()));
    }
    let pk: [u8;33] = redeem.get(1..34)?.try_into().ok()?;
    let c: [u8;32] = redeem.get(36..68)?.try_into().ok()?;
    secp256k1::PublicKey::from_slice(&pk).ok()?;
    let refs: Vec<_> = pieces.iter().map(|(i,p)| (*i,p.as_slice())).collect();
    if authenticated_redeem_script(&pk,&c,&content_type,total,&refs) != *redeem { return None; }
    Some(Envelope { authenticated: true, total, content_type, pieces, c: Some(c) })
}

pub fn parse_envelope(script: &[u8]) -> Option<Envelope> {
    parse_authenticated_envelope(script).or_else(|| parse_legacy_envelope(script))
}

// ---------------------------------------------------------------- block parsing

fn read_compact(b: &[u8], pos: &mut usize) -> Result<u64> {
    let first = *b.get(*pos).context("truncated CompactSize")?;
    *pos += 1;
    let width = match first {
        0..=252 => return Ok(first as u64),
        253 => 2,
        254 => 4,
        _ => 8,
    };
    let end = pos.checked_add(width).context("CompactSize overflow")?;
    let data = b.get(*pos..end).context("truncated CompactSize payload")?;
    let mut bytes = [0u8; 8];
    bytes[..width].copy_from_slice(data);
    *pos = end;
    let n = u64::from_le_bytes(bytes);
    anyhow::ensure!(
        match width {
            2 => n >= 253,
            4 => n > u16::MAX as u64,
            _ => n > u32::MAX as u64,
        },
        "noncanonical CompactSize"
    );
    Ok(n)
}

pub struct Block {
    pub hash: String,
    pub previous_hash: String,
    pub txs: Vec<(String, Transaction)>,
}

pub fn parse_block(raw: &[u8], branch: BranchId) -> Result<Block> {
    let mut pos = 140usize;
    let sol_len = usize::try_from(read_compact(raw, &mut pos)?).context("solution size")?;
    pos = pos.checked_add(sol_len).context("header size overflow")?;
    let header = raw.get(..pos).context("truncated solution")?;
    let mut previous = raw.get(4..36).context("truncated parent hash")?.to_vec();
    previous.reverse();
    let mut h = Sha256::digest(Sha256::digest(header)).to_vec();
    h.reverse();
    let count = usize::try_from(read_compact(raw, &mut pos)?).context("transaction count")?;
    anyhow::ensure!(
        count > 0 && count <= raw.len().saturating_sub(pos),
        "invalid transaction count"
    );
    let mut txs = Vec::new();
    for _ in 0..count {
        let mut cur = std::io::Cursor::new(raw.get(pos..).context("transaction offset")?);
        let tx = Transaction::read(&mut cur, branch)?;
        pos = pos
            .checked_add(usize::try_from(cur.position())?)
            .context("transaction size overflow")?;
        txs.push((tx.txid().to_string(), tx));
    }
    anyhow::ensure!(pos == raw.len(), "trailing block bytes");
    Ok(Block {
        hash: hex::encode(h),
        previous_hash: hex::encode(previous),
        txs,
    })
}

// ---------------------------------------------------------------- declarations

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeployDeclaration {
    p: String,
    v: u32,
    op: String,
    name: String,
    supply: u64,
    max_per_addr: u64,
    price: u64,
    pay: String,
    #[serde(default)]
    start: u32,
    renderer: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MintDeclaration {
    p: String,
    op: String,
    d: String,
}

fn inscription_id(s: &str) -> bool {
    s.len() == 66
        && s.ends_with("i0")
        && s.as_bytes()[..64]
            .iter()
            .copied()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn apply_declaration(
    st: &mut State,
    ch: &mut Changes,
    ins: &Inscription,
    pay_outputs: &[(Option<String>, u64)],
    net: Net,
) {
    if ins.content_type != "application/json" || ins.content_hex.is_empty() {
        return;
    }
    let Ok(bytes) = hex::decode(&ins.content_hex) else {
        return;
    };
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return;
    };
    if v["p"].as_str() != Some(PROTOCOL) {
        return;
    }
    let reject = |st: &mut State, ch: &mut Changes, why: &str| {
        let line = format!("{} {}: {why}", ins.id, v["op"].as_str().unwrap_or("?"));
        st.rejected.push(line.clone());
        ch.rejected.push(line);
    };
    if ins.family != "v1" {
        return reject(st, ch, "unverified content commitment");
    }
    match v["op"].as_str() {
        Some("deploy") => {
            let Ok(d) = serde_json::from_slice::<DeployDeclaration>(&bytes) else {
                return reject(st, ch, "invalid deploy schema");
            };
            if d.p != PROTOCOL
                || d.op != "deploy"
                || d.v != 1
                || d.name.is_empty()
                || !(1..=100_000).contains(&d.supply)
                || crate::zat(d.price).is_err()
                || crate::parse_taddr_for(&d.pay, net.network_type()).is_err()
            {
                return reject(st, ch, "invalid deploy parameters");
            }
            let Some(min_start) = ins.completion_height.checked_add(1) else {
                return reject(st, ch, "start height overflow");
            };
            // An empty renderer is allowed only for private development collections.
            if !(d.renderer.is_empty() && net == Net::Regtest) {
                if !inscription_id(&d.renderer)
                    || !st.inscriptions.get(&d.renderer).is_some_and(|r| {
                        r.family == "v1"
                            && (!ins.authenticated || r.authenticated)
                            && r.content_type.starts_with("text/")
                            && !r.content_hex.is_empty()
                            && r.completion_height <= ins.completion_height
                    })
                {
                    return reject(st, ch, "renderer must reference verified source content");
                }
            }
            if st.collections.contains_key(&ins.id) {
                return reject(st, ch, "duplicate deploy");
            }
            st.collections.insert(
                ins.id.clone(),
                Collection {
                    authenticated: ins.authenticated,
                    id: ins.id.clone(),
                    name: d.name,
                    supply: d.supply,
                    max_per_addr: d.max_per_addr,
                    price: d.price,
                    pay: d.pay,
                    start: d.start.max(min_start),
                    renderer: d.renderer,
                    deployed_height: ins.completion_height,
                    minted: 0,
                    per_addr: BTreeMap::new(),
                },
            );
            ch.collections.insert(ins.id.clone());
        }
        Some("mint") => {
            let Ok(m) = serde_json::from_slice::<MintDeclaration>(&bytes) else {
                return reject(st, ch, "invalid mint schema");
            };
            if m.p != PROTOCOL || m.op != "mint" || !inscription_id(&m.d) {
                return reject(st, ch, "invalid collection id");
            }
            let Some(col) = st.collections.get(&m.d).cloned() else {
                return reject(st, ch, "unknown collection");
            };
            if col.authenticated && !ins.authenticated {
                return reject(st, ch, "collection requires authenticated envelope");
            }
            if st.mints.contains_key(&ins.id) {
                return reject(st, ch, "duplicate mint");
            }
            if ins.completion_height < col.start {
                return reject(st, ch, "before start height");
            }
            if col.minted >= col.supply {
                return reject(st, ch, "supply exhausted");
            }
            let Some(minter) = ins.owner_address.clone() else {
                return reject(st, ch, "no owner address");
            };
            if crate::parse_taddr_for(&minter, net.network_type()).is_err() {
                return reject(st, ch, "wrong destination network");
            }
            if col.max_per_addr > 0
                && col.per_addr.get(&minter).copied().unwrap_or(0) >= col.max_per_addr
            {
                return reject(st, ch, "per-address cap");
            }
            let paid = pay_outputs
                .iter()
                .filter(|(a, _)| a.as_deref() == Some(col.pay.as_str()))
                .try_fold(0u64, |sum, (_, v)| sum.checked_add(*v));
            let Some(paid) = paid else {
                return reject(st, ch, "payment overflow");
            };
            if paid < col.price {
                return reject(st, ch, "underpaid");
            }
            let Ok(mut seed_in) = hex::decode(ins.id.strip_suffix("i0").unwrap_or("")) else {
                return reject(st, ch, "invalid inscription id");
            };
            let Ok(block_hash) = hex::decode(&ins.completion_block_hash) else {
                return reject(st, ch, "invalid block hash");
            };
            if seed_in.len() != 32 || block_hash.len() != 32 {
                return reject(st, ch, "invalid seed inputs");
            }
            seed_in.extend(block_hash);
            let seed = hex::encode(Sha256::digest(&seed_in));
            let number = col.minted + 1;
            let c = st.collections.get_mut(&m.d).unwrap();
            c.minted = number;
            *c.per_addr.entry(minter.clone()).or_insert(0) += 1;
            st.mints.insert(
                ins.id.clone(),
                Mint {
                    inscription: ins.id.clone(),
                    collection: m.d.clone(),
                    number,
                    minter,
                    height: ins.completion_height,
                    seed,
                },
            );
            ch.collections.insert(m.d);
            ch.mints.insert(ins.id.clone());
        }
        _ => {}
    }
}

// ---------------------------------------------------------------- persistence

/// What a block changed; written to SQLite in one transaction.
#[derive(Default)]
pub struct Changes {
    pub inscriptions: BTreeSet<String>,
    pub carriers_put: BTreeSet<String>,
    pub carriers_del: BTreeSet<String>,
    pub pending_put: BTreeSet<String>,
    pub pending_del: BTreeSet<String>,
    pub collections: BTreeSet<String>,
    pub mints: BTreeSet<String>,
    pub rejected: Vec<String>,
}

/// Includes authenticated-envelope indexing rules; older databases require a fresh replay.
pub const SCHEMA_VERSION: &str = "4";

pub struct Db {
    pub conn: Connection,
}

impl Db {
    pub fn open(path: &str) -> Result<Db> {
        if let Some(dir) = std::path::Path::new(path).parent() {
            std::fs::create_dir_all(dir)?;
        }
        let conn = Connection::open(path)?;
        let existing: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='meta')",
            [],
            |r| r.get(0),
        )?;
        if existing {
            let version = conn
                .query_row("SELECT v FROM meta WHERE k='schema_version'", [], |r| {
                    r.get::<_, String>(0)
                })
                .ok();
            anyhow::ensure!(
                version.as_deref() == Some(SCHEMA_VERSION),
                "index schema changed: preserve this database and replay from the first block into a fresh database in a new directory; do not delete order records"
            );
        }
        conn.execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
             CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT);
             CREATE TABLE IF NOT EXISTS inscriptions(id TEXT PRIMARY KEY, json TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS carriers(outpoint TEXT NOT NULL, inscription TEXT NOT NULL, PRIMARY KEY(outpoint, inscription));
             CREATE TABLE IF NOT EXISTS pending(outpoint TEXT PRIMARY KEY, json TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS collections(id TEXT PRIMARY KEY, json TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS mints(inscription TEXT PRIMARY KEY, json TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS rejected(line TEXT);
             CREATE TABLE IF NOT EXISTS kv(ns TEXT, k TEXT, json TEXT NOT NULL, PRIMARY KEY(ns, k));",
        )?;
        conn.execute(
            "INSERT OR IGNORE INTO meta(k,v) VALUES('schema_version',?1)",
            [SCHEMA_VERSION],
        )?;
        Ok(Db { conn })
    }

    pub(crate) fn check_schema(conn: &Connection) -> Result<()> {
        let version: Option<String> = conn.query_row("SELECT v FROM meta WHERE k='schema_version'", [], |r| r.get(0)).optional()?;
        anyhow::ensure!(version.as_deref() == Some(SCHEMA_VERSION),
            "index schema changed: preserve this database and replay from the first block into a fresh database in a new directory; do not delete order records");
        Ok(())
    }

    pub fn load(&self) -> Result<State> { Self::load_from(&self.conn) }

    pub(crate) fn load_from(conn: &Connection) -> Result<State> {
        Self::check_schema(conn)?;
        let mut st = State::default();
        let height: Option<String> = conn
            .query_row("SELECT v FROM meta WHERE k='height'", [], |r| r.get(0))
            .optional()?;
        st.height = height
            .map(|v| v.parse::<u32>())
            .transpose()
            .context("corrupt index height")?
            .unwrap_or(0);
        st.tip_hash = conn
            .query_row("SELECT v FROM meta WHERE k='tip_hash'", [], |r| r.get(0))
            .optional()?;
        st.network = conn
            .query_row("SELECT v FROM meta WHERE k='network'", [], |r| r.get(0))
            .optional()?;
        if st.height > 0 {
            anyhow::ensure!(
                st.tip_hash
                    .as_ref()
                    .is_some_and(|h| h.len() == 64 && hex::decode(h).is_ok()),
                "index missing canonical tip hash"
            );
            anyhow::ensure!(
                st.network.as_deref().is_some_and(|n| Net::parse(n).is_ok()),
                "index missing network identity"
            );
        }
        st.replay_from = conn.query_row("SELECT v FROM meta WHERE k='replay_from'", [], |r| r.get::<_, String>(0)).optional()?
            .map(|v| v.parse::<u32>()).transpose().context("corrupt replay provenance")?;
        if let Some(first) = st.replay_from {
            anyhow::ensure!(first > 0 && first <= st.height && st.tip_hash.is_some() && st.network.is_some(), "invalid replay provenance");
        }
        if st.replay_from.is_some() {
            let anchor_height: Option<String> = conn.query_row("SELECT v FROM meta WHERE k='replay_tip_height'", [], |r|r.get(0)).optional()?;
            let anchor_hash: Option<String> = conn.query_row("SELECT v FROM meta WHERE k='replay_tip_hash'", [], |r|r.get(0)).optional()?;
            if anchor_height.as_deref() != Some(st.height.to_string().as_str()) || anchor_hash != st.tip_hash {
                st.replay_from = None; // An older writer may have advanced or replaced this index.
            }
        }
        let mut q = conn.prepare("SELECT id, json FROM inscriptions")?;
        for row in q.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))? {
            let (id, j) = row?;
            st.inscriptions.insert(id, serde_json::from_str(&j)?);
        }
        let mut q = conn
            .prepare("SELECT outpoint, inscription FROM carriers")?;
        for row in q.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))? {
            let (k, v) = row?;
            st.carriers.entry(k).or_default().insert(v);
        }
        let mut q = conn.prepare("SELECT outpoint, json FROM pending")?;
        for row in q.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))? {
            let (k, j) = row?;
            st.pending.insert(k, serde_json::from_str(&j)?);
        }
        let mut q = conn.prepare("SELECT id, json FROM collections")?;
        for row in q.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))? {
            let (k, j) = row?;
            st.collections.insert(k, serde_json::from_str(&j)?);
        }
        let mut q = conn.prepare("SELECT inscription, json FROM mints")?;
        for row in q.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))? {
            let (k, j) = row?;
            st.mints.insert(k, serde_json::from_str(&j)?);
        }
        let mut q = conn.prepare("SELECT line FROM rejected")?;
        for row in q.query_map([], |r| r.get::<_, String>(0))? {
            st.rejected.push(row?);
        }
        for (out, ids) in &st.carriers {
            for id in ids {
                anyhow::ensure!(
                    st.inscriptions.get(id).is_some_and(|i| i.owner == *out),
                    "corrupt carrier ownership"
                );
            }
        }
        for (id, ins) in &st.inscriptions {
            anyhow::ensure!(ins.id == *id, "corrupt inscription identity");
            if !matches!(ins.owner.as_str(), "burned" | "shielded") {
                anyhow::ensure!(
                    st.carriers
                        .get(&ins.owner)
                        .is_some_and(|ids| ids.contains(id)),
                    "missing live carrier"
                );
            }
        }
        Ok(st)
    }

    pub fn apply(&mut self, st: &State, ch: &Changes) -> Result<()> {
        let tx = self.conn.transaction()?;
        Self::apply_tx(&tx, st, ch)?;
        tx.commit()?;
        Ok(())
    }

    pub(crate) fn apply_tx(tx: &rusqlite::Transaction<'_>, st: &State, ch: &Changes) -> Result<()> {
        Self::check_schema(tx)?;
        for id in &ch.inscriptions {
            if let Some(i) = st.inscriptions.get(id) {
                tx.execute(
                    "INSERT OR REPLACE INTO inscriptions(id, json) VALUES(?1, ?2)",
                    params![id, serde_json::to_string(i)?],
                )?;
            }
        }
        for k in &ch.carriers_del {
            tx.execute("DELETE FROM carriers WHERE outpoint=?1", params![k])?;
        }
        for k in &ch.carriers_put {
            tx.execute("DELETE FROM carriers WHERE outpoint=?1", params![k])?;
            if let Some(ids) = st.carriers.get(k) {
                for id in ids {
                    tx.execute(
                        "INSERT INTO carriers(outpoint,inscription) VALUES(?1,?2)",
                        params![k, id],
                    )?;
                }
            }
        }
        for k in &ch.pending_del {
            tx.execute("DELETE FROM pending WHERE outpoint=?1", params![k])?;
        }
        for k in &ch.pending_put {
            if let Some(p) = st.pending.get(k) {
                tx.execute(
                    "INSERT OR REPLACE INTO pending(outpoint, json) VALUES(?1, ?2)",
                    params![k, serde_json::to_string(p)?],
                )?;
            }
        }
        for k in &ch.collections {
            if let Some(c) = st.collections.get(k) {
                tx.execute(
                    "INSERT OR REPLACE INTO collections(id, json) VALUES(?1, ?2)",
                    params![k, serde_json::to_string(c)?],
                )?;
            }
        }
        for k in &ch.mints {
            if let Some(m) = st.mints.get(k) {
                tx.execute(
                    "INSERT OR REPLACE INTO mints(inscription, json) VALUES(?1, ?2)",
                    params![k, serde_json::to_string(m)?],
                )?;
            }
        }
        tx.execute("DELETE FROM meta WHERE k IN ('replay_from','replay_tip_height','replay_tip_hash')", [])?;
        if let Some(first) = st.replay_from {
            anyhow::ensure!(first > 0 && first <= st.height, "invalid replay provenance");
            tx.execute("INSERT INTO meta(k,v) VALUES('replay_from',?1)", [first.to_string()])?;
            let hash = st.tip_hash.as_ref().context("replay provenance lacks tip hash")?;
            tx.execute("INSERT INTO meta(k,v) VALUES('replay_tip_height',?1)", [st.height.to_string()])?;
            tx.execute("INSERT INTO meta(k,v) VALUES('replay_tip_hash',?1)", [hash])?;
        }
        for line in &ch.rejected {
            tx.execute("INSERT INTO rejected(line) VALUES(?1)", params![line])?;
        }
        tx.execute(
            "INSERT OR REPLACE INTO meta(k, v) VALUES('height', ?1)",
            params![st.height.to_string()],
        )?;
        if let Some(h) = &st.tip_hash {
            tx.execute(
                "INSERT OR REPLACE INTO meta(k,v) VALUES('tip_hash',?1)",
                params![h],
            )?;
        }
        if let Some(n) = &st.network {
            tx.execute(
                "INSERT OR REPLACE INTO meta(k,v) VALUES('network',?1)",
                params![n],
            )?;
        }
        Ok(())
    }

    // Generic JSON key/value store for the service (orders, listings).
    pub fn kv_put(&self, ns: &str, k: &str, v: &impl Serialize) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO kv(ns, k, json) VALUES(?1, ?2, ?3)",
            params![ns, k, serde_json::to_string(v)?],
        )?;
        Ok(())
    }
    pub fn kv_all<T: for<'de> Deserialize<'de>>(&self, ns: &str) -> Result<BTreeMap<String, T>> {
        let mut q = self.conn.prepare("SELECT k, json FROM kv WHERE ns=?1")?;
        let mut out = BTreeMap::new();
        for row in q.query_map([ns], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
        })? {
            let (k, j) = row?;
            out.insert(k, serde_json::from_str(&j)?);
        }
        Ok(out)
    }
}

/// Opens (or creates) the default database and loads its state.
pub fn load_state() -> Result<State> {
    let db=Db::open(DB_FILE)?;
    anyhow::ensure!(crate::reorg::pending(&db)?.is_none(),"reorg order reconciliation pending; spending disabled");
    db.load()
}

// ---------------------------------------------------------------- indexing

pub fn cmd_index(max_blocks: u32) -> Result<()> { cmd_index_mode(max_blocks, false) }
pub fn cmd_index_mode(max_blocks: u32, key_free_recovery: bool) -> Result<()> {
    std::fs::create_dir_all("indexer")?;
    let lock = std::fs::OpenOptions::new().create(true).truncate(false).read(true).write(true).open("indexer/index-writer.lock")?;
    lock.try_lock().context("another CLI index writer is active")?;
    anyhow::ensure!(max_blocks > 0, "index block limit must be positive");
    let rpc = Rpc::open()?;
    let mut db = Db::open(DB_FILE)?;
    let mut st = db.load()?;
    if key_free_recovery {
        if let Some(recovery) = crate::reorg::recover_key_free(&rpc, &mut db, &mut st, std::path::Path::new("."))? {
            println!("key-free index recovery: {}", serde_json::to_string(&recovery)?);
        }
    }
    index_to_tip(
        &rpc,
        &mut st,
        Some(&mut db),
        rpc.net(),
        0,
        true,
        max_blocks,
    )?;
    println!(
        "indexed to height {} ; {} inscriptions, {} live carriers",
        st.height,
        st.inscriptions.len(),
        st.carriers.len()
    );
    // The daemon needs a checkpoint, not a dump of every historical inscription.
    if key_free_recovery { return Ok(()); }
    for ins in st.inscriptions.values() {
        println!(
            "  {} {} {}B owner={} ({})",
            ins.id,
            ins.content_type,
            ins.content_len,
            ins.owner,
            ins.owner_address.clone().unwrap_or_default()
        );
    }
    for c in st.collections.values() {
        println!(
            "  collection {} \"{}\" minted {}/{}",
            c.id, c.name, c.minted, c.supply
        );
    }
    for m in st.mints.values() {
        println!(
            "    #{} {} minter={} seed={}",
            m.number, m.inscription, m.minter, m.seed
        );
    }
    for r in &st.rejected {
        println!("  rejected: {r}");
    }
    Ok(())
}

/// Advances `st` towards the chain tip, persisting at most `max_blocks` blocks.
/// A nonzero start on an empty index is a scoped replay, NOT proof of complete history.
/// Existing indexes must remain contiguous; raising start_height cannot skip blocks.
fn next_index_height(st: &State, start_height: u32) -> Result<u32> {
    let next = st.height.checked_add(1).context("height overflow")?;
    if st.height > 0 || st.tip_hash.is_some() {
        anyhow::ensure!(start_height <= next, "start_height would skip unprocessed blocks; preserve the index and reconcile configuration");
    }
    Ok(next.max(start_height))
}

/// Returns the number of blocks processed; never advances state past the block budget.
pub fn index_to_tip(
    rpc: &Rpc,
    st: &mut State,
    mut db: Option<&mut Db>,
    net: Net,
    start_height: u32,
    verbose: bool,
    max_blocks: u32,
) -> Result<u32> {
    anyhow::ensure!(
        st.network.as_deref().is_none_or(|n| n == net.name()),
        "index belongs to another network"
    );
    anyhow::ensure!(rpc.net()==net,"RPC and index network mismatch");
    let start = next_index_height(st, start_height)?;
    let tip = rpc.checked_target()? - 1;
    if tip < st.height {
        return Err(crate::reorg::ForkDetected("chain tip moved behind index; rebuild/reorg recovery required").into());
    }
    if let Some(expected) = &st.tip_hash {
        if rpc.call("getblockhash", json!([st.height]))?.as_str() != Some(expected) {
            return Err(crate::reorg::ForkDetected("chain reorganization detected; signing must remain disabled until recovery").into());
        }
    }
    let mut done = 0;
    for h in start..=tip {
        if done >= max_blocks {
            break;
        }
        let hash = rpc
            .call("getblockhash", json!([h]))?
            .as_str()
            .context("block hash")?
            .to_owned();
        let raw = rpc.call("getblock", json!([hash, 0]))?;
        let block = parse_block(
            &hex::decode(raw.as_str().context("block hex")?)?,
            net.branch_for(h),
        )?;
        anyhow::ensure!(block.hash == hash, "node returned wrong block");
        if h == st.height + 1 {
            if let Some(parent) = &st.tip_hash {
                anyhow::ensure!(block.previous_hash == *parent, "block parent mismatch");
            }
        }
        // Commit the in-memory state only after the full block and SQLite transaction succeed.
        let mut next = st.clone();
        let mut ch = Changes::default();
        for (txid, tx) in &block.txs {
            let prev_script = if let Some(tb) = tx
                .transparent_bundle()
                .filter(|b| !b.is_coinbase() && !b.vin.is_empty())
            {
                let ss = script_bytes(tb.vin[0].script_sig());
                if parse_envelope(&ss).is_some() {
                    let prev = tb.vin[0].prevout();
                    let mut bytes = *prev.hash();
                    bytes.reverse();
                    let parent_id = hex::encode(bytes);
                    if let Some((_, parent)) = block.txs.iter().find(|(id, _)| *id == parent_id) {
                        Some(script_bytes(
                            parent
                                .transparent_bundle()
                                .and_then(|b| b.vout.get(prev.n() as usize))
                                .context("missing parent output")?
                                .script_pubkey(),
                        ))
                    } else {
                        let parent = rpc.call("getrawtransaction", json!([parent_id, 1]))?;
                        Some(hex::decode(
                            parent["vout"][prev.n() as usize]["scriptPubKey"]["hex"]
                                .as_str()
                                .context("parent output script unavailable")?,
                        )?)
                    }
                } else {
                    None
                }
            } else {
                None
            };
            apply_transaction(
                &mut next,
                &mut ch,
                txid,
                tx,
                h,
                &block.hash,
                net,
                prev_script.as_deref(),
            )?;
        }
        anyhow::ensure!(
            rpc.call("getblockhash", json!([h]))?.as_str() == Some(hash.as_str()),
            "chain changed while indexing block"
        );
        next.record_replay_start(st, h);
        next.height = h;
        next.tip_hash = Some(hash);
        next.network = Some(net.name().into());
        if let Some(db) = db.as_deref_mut() {
            crate::reorg::apply_block(db, st, &next, &ch)?;
        }
        *st = next;
        done += 1;
        if verbose {
            println!("indexed block {h}");
        }
    }
    Ok(done)
}

fn apply_transaction(
    st: &mut State,
    ch: &mut Changes,
    txid: &str,
    tx: &Transaction,
    h: u32,
    block_hash: &str,
    net: Net,
    prev_script: Option<&[u8]>,
) -> Result<()> {
    let Some(tb) = tx.transparent_bundle() else {
        return Ok(());
    };
    let outputs: Vec<_> = tb
        .vout
        .iter()
        .map(|o| script_bytes(o.script_pubkey()))
        .collect();
    let first = outputs.iter().position(|s| s.first() != Some(&0x6a));
    let has_shielded = tx.sapling_bundle().is_some() || tx.orchard_bundle().is_some();
    let mut continuation = None;
    for (i, vin) in tb.vin.iter().enumerate() {
        let mut hash = *vin.prevout().hash();
        hash.reverse();
        let key = format!("{}:{}", hex::encode(hash), vin.prevout().n());
        if let Some(p) = st.pending.remove(&key) {
            ch.pending_del.insert(key.clone());
            if i == 0 {
                continuation = Some(p);
            }
        }
        if let Some(ids) = st.carriers.remove(&key) {
            ch.carriers_del.insert(key);
            for id in ids {
                let ins = st
                    .inscriptions
                    .get_mut(&id)
                    .context("carrier references missing inscription")?;
                if let Some(n) = first {
                    let out = format!("{txid}:{n}");
                    ins.owner = out.clone();
                    ins.owner_address = address_of(&outputs[n], net.network_type());
                    ins.history.push(format!("h{h} transfer -> {out}"));
                    st.carriers
                        .entry(out.clone())
                        .or_default()
                        .insert(id.clone());
                    ch.carriers_put.insert(out);
                } else {
                    ins.owner = if has_shielded { "shielded" } else { "burned" }.into();
                    ins.owner_address = None;
                    ins.history
                        .push(format!("h{h} terminal {} in {txid}", ins.owner));
                }
                ch.inscriptions.insert(id);
            }
        }
    }
    if tb.is_coinbase() || tb.vin.is_empty() {
        return Ok(());
    }
    let ss = script_bytes(tb.vin[0].script_sig());
    let Some(env) = parse_envelope(&ss) else {
        return Ok(());
    };
    let pushes = if env.authenticated { consensus_pushes(&ss) } else { parse_pushes(&ss) }.context("envelope pushes")?;
    let redeem = pushes.last().context("redeem")?;
    let expected_script: Script = TransparentAddress::ScriptHash(hash160(redeem))
        .script()
        .into();
    let proven = env.c.is_some() && prev_script == Some(script_bytes(&expected_script).as_slice());
    let mut pend = continuation.unwrap_or_else(|| Pending {
        authenticated: env.authenticated && proven,
        genesis_txid: txid.into(),
        genesis_height: h,
        genesis_block_hash: block_hash.into(),
        total: env.total,
        content_type: env.content_type.clone(),
        pieces: BTreeMap::new(),
        c: env.c.map(hex::encode),
        consistent: proven,
        reveals: 0,
    });
    if pend.total != env.total
        || pend.content_type != env.content_type
        || pend.c != env.c.map(hex::encode)
        || pend.reveals >= 64
    {
        return Ok(());
    }
    pend.consistent &= proven;
    pend.authenticated &= env.authenticated && proven;
    pend.reveals += 1;
    for (i, piece) in &env.pieces {
        if pend.pieces.len() >= pend.total || *i != pend.total - pend.pieces.len() - 1 {
            return Ok(());
        }
        pend.pieces.insert(*i, hex::encode(piece));
    }
    if pend.pieces.len() < pend.total {
        if pend.reveals >= 64
            || outputs.is_empty()
            || !matches!(address_of(&outputs[0], net.network_type()), Some(_))
        {
            return Ok(());
        }
        let out = format!("{txid}:0");
        st.pending.insert(out.clone(), pend);
        ch.pending_put.insert(out);
        return Ok(());
    }
    if first != Some(0) {
        return Ok(());
    }
    let content: Vec<u8> = pend
        .pieces
        .values()
        .map(hex::decode)
        .collect::<std::result::Result<Vec<_>, _>>()?
        .into_iter()
        .flatten()
        .collect();
    if content.len() > 61_200 {
        return Ok(());
    }
    let committed = pend.consistent
        && pend.c.as_deref()
            == Some(hex::encode(commitment(&pend.content_type, &content)).as_str());
    let id = format!("{}i0", pend.genesis_txid);
    let owner = format!("{txid}:0");
    let content_type = String::from_utf8(pend.content_type)?;
    let ins = Inscription {
        authenticated: pend.authenticated && committed,
        id: id.clone(),
        family: if committed { "v1" } else { "legacy" }.into(),
        content_len: content.len(),
        content_sha256: hex::encode(Sha256::digest(&content)),
        content_hex: if keep_content(&content_type, content.len()) {
            hex::encode(&content)
        } else {
            String::new()
        },
        content_type,
        genesis_height: pend.genesis_height,
        genesis_block_hash: pend.genesis_block_hash,
        completion_height: h,
        completion_block_hash: block_hash.into(),
        owner: owner.clone(),
        owner_address: address_of(&outputs[0], net.network_type()),
        history: vec![format!("h{h} completed in {txid} -> {owner}")],
    };
    st.carriers
        .entry(owner.clone())
        .or_default()
        .insert(id.clone());
    ch.carriers_put.insert(owner);
    ch.inscriptions.insert(id.clone());
    let payments: Vec<_> = tb
        .vout
        .iter()
        .map(|o| {
            (
                address_of(&script_bytes(o.script_pubkey()), net.network_type()),
                o.value().into_u64(),
            )
        })
        .collect();
    st.inscriptions.insert(id, ins.clone());
    apply_declaration(st, ch, &ins, &payments, net);
    Ok(())
}

#[cfg(test)]
#[path = "index_tests.rs"]
mod tests;
