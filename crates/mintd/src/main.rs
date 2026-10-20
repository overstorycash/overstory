//! mintd: indexer + mint proxy service + read API + static web.
//!
//! Config file `mintd.json` in the working directory:
//! { "bind": "127.0.0.1:8795", "collection": "<deploy inscription id>", "network": "regtest",
//!   "service_fee_zat": 10000, "fee_address": "tm...", "web_dir": "web", "order_ttl_secs": 7200 }
//!
//! Orders: one fresh invoice key per order (keys/orders/<id>.key). The service holds the
//! paid ZEC only between confirmation and the reveal, then either delivers the
//! inscription to the order's destination or refunds to it.

use std::{
    collections::BTreeMap,
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, anyhow};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tower_http::{cors::CorsLayer, services::ServeDir};

use overstory_render::{PALETTE, grid_hash, render};
use proto::{
    Key, Listing, ListingTemplate, OutputSpec, Rpc, Utxo, execute_purchase_with, finalize_listing,
    index::{DB_FILE, Db, Net, State as Index, index_to_tip},
    inscribe::{RecoveryRequired, SignedInscription, inscription_cost, prepare_inscription},
    prepare_listing,
};
use zcash_transparent::address::TransparentAddress;

const COMMIT_FEE_ESTIMATE: u64 = 10_000; // 1 input, 2 outputs under ZIP 317; any remainder folds into the fee or returns as change
const NS_ORDERS: &str = "orders";
const NS_LISTINGS: &str = "listings";
const LISTING_TTL_BLOCKS: u32 = 2_000;

#[derive(Clone, Deserialize)]
struct Config {
    #[serde(default="default_poll_interval")]
    poll_interval_secs:u64,
    bind: String,
    collection: String,
    network: String,
    service_fee_zat: u64,
    #[serde(default = "default_max_saved_orders")]
    max_saved_orders: usize,
    #[serde(default)]
    mint_total_zat: Option<u64>,
    fee_address: String,
    web_dir: String,
    order_ttl_secs: u64,
    #[serde(default)]
    market_open: Option<bool>,
    #[serde(default)]
    explorer_url: Option<String>,
    /// first block worth reading (protocol activity starts here); 0 = genesis
    #[serde(default)]
    start_height: u32,
    /// when set, every read endpoint is also written as a static file tree under this
    /// directory after each block, ready to be published to a CDN (see deploy/README.md)
    #[serde(default)]
    export_dir: Option<String>,
    /// absolute origin of this service as seen from the published static site
    /// (written into the snapshot's config.js so browsers send orders here)
    #[serde(default)]
    public_origin: String,
}

fn default_poll_interval()->u64 {15}
fn default_max_saved_orders()->usize {10_000}

fn market_is_open(app: &App) -> bool {
    app.cfg.market_open == Some(true)
        && matches!(proto::parse_taddr_for(&app.cfg.fee_address, app.net.network_type()), Ok(TransparentAddress::PublicKeyHash(_)))
        && app.healthy
        && app.index.height == app.tip
        && app.index.collections.get(&app.cfg.collection)
            .is_some_and(|c| c.supply > 0 && c.minted == c.supply)
}

#[derive(Clone, Serialize, Deserialize)]
struct Order {
    id: String,
    dest: String,
    invoice_address: String,
    amount_zat: u64,
    created: u64,
    #[serde(default)]
    payment_start_height: Option<u32>,
    #[serde(default)]
    payment_review_until: u64,
    expires: u64,
    status: String, // payment/mint states plus refunding, refund_pending_small, recovery_required
    paid_zat: u64,
    inscription_id: Option<String>,
    txids: Vec<String>,
    number: Option<u64>,
    seed: Option<String>,
    error: Option<String>,
    #[serde(default)]
    attempts: u32,
    #[serde(default = "kind_mint")]
    kind: String, // mint | purchase
    #[serde(default)]
    listing_id: Option<String>,
    #[serde(default)]
    mint_journal_version: u32,
    #[serde(default)]
    mint_plan: Option<SignedInscription>,
    #[serde(default)]
    retry_after: u64,
    #[serde(default)]
    accounting_version: u32,
    #[serde(default)]
    receipts: BTreeMap<String, Utxo>,
    #[serde(default)]
    refunds: Vec<RefundRecord>,
    #[serde(default)]
    refund_mode: bool,
    #[serde(default)]
    quote: Option<MintQuote>,
    #[serde(default)]
    refund_address: Option<String>,
    #[serde(default)]
    settlement_hold: bool,
    #[serde(default, skip_serializing_if="Option::is_none")]
    invoice_intent: Option<InvoiceIntent>,
}

#[derive(Clone, Serialize, Deserialize)]
struct RefundRecord {
    plan: proto::refund::RefundPlan,
    confirmation: Option<proto::refund::RefundConfirmation>,
}

// Signed plans are durable internal state, never part of the public order response.
fn public_order(o: &Order) -> serde_json::Value {
    let mut v = serde_json::to_value(o).expect("serialize order");
    v.as_object_mut().unwrap().remove("mint_plan");
    v.as_object_mut().unwrap().remove("invoice_intent");
    v.as_object_mut().unwrap().remove("receipts");
    v["refunds"] = json!(
        o.refunds
            .iter()
            .map(|r| json!({
                "txid":r.plan.txid,"refund_zat":r.plan.refund_zat,"fee_zat":r.plan.fee_zat,
                "confirmation":r.confirmation
            }))
            .collect::<Vec<_>>()
    );
    if o.settlement_hold {
        v["status"]=json!("recovery_required");
        v["error"]=json!("order held for exceptional settlement; do not send more funds");
    }
    v["accounting"] = match ledger(o) {
        Ok(v) => v,
        Err(_) => json!({"available":false}),
    };
    v
}

fn require_unsigned_order_terms(o: &Order) -> Result<()> {
    if o.quote.is_none() || o.refund_address.is_none() {
        return Err(RecoveryRequired("legacy unsigned order lacks confirmed terms; do not send more funds".into()).into());
    }
    Ok(())
}

fn ensure_not_settling(o:&Order)->Result<()> {
    if o.settlement_hold {return Err(RecoveryRequired("order held for exceptional settlement".into()).into());}
    Ok(())
}

fn refund_destination(o: &Order) -> Result<&str> {
    o.refund_address.as_deref().ok_or_else(||RecoveryRequired("legacy order has no confirmed refund address; reconcile before signing".into()).into())
}

fn kind_mint() -> String {
    "mint".into()
}

struct App {
    cfg: Config,
    index: Index,
    db: Db,
    net: Net,
    genesis_hash: String,
    orders: BTreeMap<String, Order>,
    tip: u32,
    healthy: bool,
    /// set when something other than a block changed the read views (new listing)
    export_dirty: bool,
    /// active listings keyed by carrier outpoint "txid:n"
    listings: BTreeMap<String, Listing>,
    /// prepared (unsigned) listings keyed by prepare id
    prepared: BTreeMap<String, ListingTemplate>,
}

fn save_listing(db: &Db, key: &str, l: &Listing) -> Result<()> {
    db.kv_put(NS_LISTINGS, key, l)
}

/// A listing is live while its carrier is still the inscription's owner and it has not expired.
fn listing_live(app: &App, l: &Listing) -> bool {
    let key = format!("{}:{}", l.carrier_txid, l.carrier_vout);
    app.healthy
        && proto::market_fee::quote(l.price_zat).is_ok()
        && l.version == 2
        && l.network == app.net.name()
        && l.branch == proto::network::branch_name(app.net.branch_for(app.tip.saturating_add(1)))
        && app.index.single_carrier(&key).is_some()
        && l.expiry_height > app.tip
}

type Shared = Arc<Mutex<App>>;

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn mint_declaration(collection: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({"p": proto::index::PROTOCOL, "op": "mint", "d": collection}))
        .unwrap()
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct MintQuote {
    version: u32,
    collection: String,
    network: String,
    genesis_hash: String,
    price_zat: u64,
    pay: String,
    fee_address: String,
    service_fee_zat: u64,

    inclusive: bool,
    total_zat: u64,
}
fn mint_quote(app: &App) -> Result<MintQuote> {
    let col = app.index.collections.get(&app.cfg.collection).context("collection not indexed")?;
    anyhow::ensure!(app.net == Net::Regtest || col.authenticated, "new invoices require an authenticated collection");
    let cost = inscription_cost(&mint_declaration(&col.id), b"application/json", if col.price>0 {2}else{1},col.price);
    let total = match app.cfg.mint_total_zat {
        Some(total) => {
            anyhow::ensure!(app.cfg.service_fee_zat==0,"inclusive price and additional service fee are mutually exclusive");
            anyhow::ensure!(total >= cost.checked_add(COMMIT_FEE_ESTIMATE+proto::CARRIER_ZAT).context("quote overflow")?,"inclusive price too low");
            total
        }
        None => cost.checked_add(COMMIT_FEE_ESTIMATE).and_then(|v|v.checked_add(app.cfg.service_fee_zat)).context("quote overflow")?,
    };
    proto::zat(total)?;
    proto::parse_taddr_for(&app.cfg.fee_address, app.net.network_type())?;
    Ok(MintQuote { version:1, collection:col.id.clone(),network:app.net.name().into(),genesis_hash:app.genesis_hash.clone(),
        price_zat:col.price,pay:col.pay.clone(),fee_address:app.cfg.fee_address.clone(),service_fee_zat:app.cfg.service_fee_zat,
        inclusive:app.cfg.mint_total_zat.is_some(),total_zat:total })
}
fn order_amount(app: &App) -> Option<u64> { mint_quote(app).ok().map(|q|q.total_zat) }
fn next_block_can_mint(tip: u32, start: u32) -> bool {
    tip.checked_add(1).is_some_and(|next| next >= start)
}

fn checked_order_quote(app: &App, o: &Order) -> Result<MintQuote> {
    let q=o.quote.clone().ok_or_else(||RecoveryRequired("legacy order has no frozen quote; reconcile before minting".into()))?;
    let col=app.index.collections.get(&q.collection).ok_or_else(||RecoveryRequired("quoted collection not indexed; reconcile before minting".into()))?;
    if !(q.version==1 && q.network==app.net.name() && q.genesis_hash==app.genesis_hash
        && q.total_zat==o.amount_zat && q.price_zat==col.price && q.pay==col.pay) {
        return Err(RecoveryRequired("saved quote no longer matches chain or order".into()).into());
    }
    proto::zat(q.total_zat)?;
    Ok(q)
}

fn save_order(db: &Db, o: &Order) -> Result<()> {
    db.kv_put(NS_ORDERS, &o.id, o)
}

fn order_key_path(id: &str) -> String {
    format!("keys/orders/{id}.key")
}

fn load_order_key(id: &str) -> Result<Key> {
    let raw = hex::decode(std::fs::read_to_string(order_key_path(id))?.trim())?;
    Key::from_secret(&raw)
}

// ---------------------------------------------------------------- worker

fn worker(shared: Shared) {
    let rpc = Rpc::open().expect("rpc.url");
    let mut exporter = Exporter::default();
    let mut usage_report=std::time::Instant::now();
    loop {
        if let Err(e) = worker_pass(&shared, &rpc, &mut exporter) {
            eprintln!("worker: {e:#}");
        }
        if usage_report.elapsed()>=Duration::from_secs(60) {
            println!("rpc_usage {}",serde_json::to_string(&proto::rpc_usage::snapshot()).unwrap_or_default());
            usage_report=std::time::Instant::now();
        }
        let interval=shared.lock().unwrap().cfg.poll_interval_secs.clamp(4,300);
        std::thread::sleep(Duration::from_secs(interval));
    }
}

fn worker_pass(shared: &Shared, rpc: &Rpc, exporter: &mut Exporter) -> Result<()> {
    // 1. index, 8 blocks per lock hold to bound ordinary catch-up work under RPC pacing
    shared.lock().unwrap().healthy = false;
    let tip = rpc.checked_target()? - 1;
    let hash=rpc.call("getblockhash",json!([tip]))?;
    let unchanged={let app=shared.lock().unwrap();app.index.height==tip && app.index.tip_hash.as_deref()==hash.as_str()};
    if !unchanged {
    loop {
        let mut app = shared.lock().unwrap();
        app.tip = tip;
        let App {
            index,
            db,
            net,
            cfg,
            ..
        } = &mut *app;
        let n = match index_to_tip(rpc, index, Some(db), *net, cfg.start_height, false, 8) {
            Ok(n)=>n,
            Err(e) if e.downcast_ref::<proto::reorg::ForkDetected>().is_some()=>{
                proto::reorg::rollback_to_ancestor(rpc,db,index)?;
                continue;
            }
            Err(e)=>return Err(e),
        };
        if n < 8 {
            break;
        }
        // Give queued API readers a scheduling window before taking the lock again.
        drop(app);
        std::thread::sleep(Duration::from_millis(1));
    }
    let synced_tip=rpc.checked_target()? - 1;
    let synced_hash=rpc.call("getblockhash",json!([synced_tip]))?;
    {
        let mut app=shared.lock().unwrap();
        anyhow::ensure!(app.index.height==synced_tip && app.index.tip_hash.as_deref()==synced_hash.as_str(),"chain changed after indexing; keep service paused");
        app.tip=synced_tip;
    }
    }
    if unchanged {shared.lock().unwrap().tip=tip;}
    reorg_orders::reconcile(shared,rpc)?;
    // 2. orders
    let pending: Vec<Order> = {
        let app = shared.lock().unwrap();
        app.orders
            .values()
            .filter(|o| order_due(o, now()))
            .cloned()
            .collect()
    };
    let (height,hash)={let app=shared.lock().unwrap();(app.index.height,app.index.tip_hash.clone().context("missing indexed tip")?)};
    let deferred=exporter.payments.deferred(rpc,&pending,height,&hash,now())?;
    shared.lock().unwrap().healthy=true;
    for mut o in pending {
        if deferred.contains(&o.id) {continue;}
        let result = process_order(shared, rpc, &mut o);
        record_outcome(&mut o, result);
        let mut app = shared.lock().unwrap();
        save_order(&app.db, &o)?;
        app.orders.insert(o.id.clone(), o);
    }
    // 3. static snapshot
    export_snapshot(shared, exporter)?;
    Ok(())
}

fn reopen_payment_watch(o: &mut Order, time: u64) -> Result<()> {
    ensure_not_settling(o)?;
    anyhow::ensure!(matches!(o.status.as_str(), "done" | "expired" | "refunded" | "refund_pending_small"),
        "only settled orders can reopen late-payment observation; manual holds require separate reconciliation");
    anyhow::ensure!(o.accounting_version==1 && o.kind=="mint" && o.refund_address.is_some() && o.quote.is_some(),
        "late-payment review needs immutable terms and confirmed refund address");
    anyhow::ensure!(o.status!="done" || o.mint_plan.is_some(), "completed order lacks mint plan");
    ledger(o)?;
    o.payment_review_until=o.payment_review_until.max(time.checked_add(86400).context("review window overflow")?);
    // Keep status, expiry, retry/backoff, allocations, quote and every signed byte intact.
    Ok(())
}

fn cmd_watch_late_payment(id:&str)->Result<()> {
    let rpc=Rpc::open()?;
    let mut db=Db::open(DB_FILE)?;
    anyhow::ensure!(proto::reorg::pending(&db)?.is_none(),"reorg reconciliation pending");
    let before_raw:String=db.conn.query_row("SELECT json FROM kv WHERE ns='orders' AND k=?1",[id],|r|r.get(0))?;
    let mut o:Order=serde_json::from_str(&before_raw)?;
    anyhow::ensure!(o.id==id,"order identity mismatch");
    let before=serde_json::to_value(&o)?;let requested=now();
    reopen_payment_watch(&mut o,requested)?;
    let quote=o.quote.as_ref().context("missing quote")?;
    anyhow::ensure!(quote.network==rpc.net().name() && quote.genesis_hash==rpc.chain.genesis_hash,"order chain mismatch");
    proto::parse_taddr_for(refund_destination(&o)?,rpc.net().network_type())?;
    let action=json!({"action":"watch_late_payment","order_id":id,"requested_at":requested,
        "previous_review_until":before["payment_review_until"],"review_until":o.payment_review_until,
        "status_unchanged":true,"broadcast":false});
    let t=db.conn.transaction()?;
    let current:String=t.query_row("SELECT json FROM kv WHERE ns='orders' AND k=?1",[id],|r|r.get(0))?;
    anyhow::ensure!(current==before_raw,"order changed during review request");
    t.execute("UPDATE kv SET json=?1 WHERE ns='orders' AND k=?2",(serde_json::to_string(&o)?,id))?;
    t.execute("INSERT INTO kv(ns,k,json) VALUES('operator-actions',?1,?2)",
        (format!("{id}:{requested}:{}",rand::random::<u64>()),serde_json::to_string(&action)?))?;
    t.commit()?;
    println!("{}",serde_json::to_string_pretty(&action)?);Ok(())
}

fn order_due(o: &Order, time: u64) -> bool {
    if o.settlement_hold || o.retry_after > time || matches!(o.status.as_str(), "recovery_required" | "error") { return false; }
    matches!(o.status.as_str(), "awaiting_payment" | "paid" | "inscribing" | "purchasing" | "refunding")
        || (matches!(o.status.as_str(), "expired" | "refunded" | "refund_pending_small" | "done")
            && (time < o.expires.saturating_add(7 * 86_400).max(o.payment_review_until)
                || o.refunds.iter().any(|r| r.confirmation.is_none())))
}

/// Only consecutive failed attempts exhaust an unsigned order's retry budget.
fn record_outcome(o: &mut Order, result: Result<()>) {
    if let Err(e) = result {
        o.attempts = o.attempts.saturating_add(1);
        o.retry_after = now().saturating_add((4u64 << o.attempts.min(6)).min(300));
        o.error = Some(format!("{e:#}"));
        eprintln!("order {} (attempt {}): {e:#}", o.id, o.attempts);
        if e.downcast_ref::<RecoveryRequired>().is_some() {
            o.status = "recovery_required".into();
        } else if o.attempts >= 8
            && o.mint_plan.is_none()
            && o.refunds.iter().all(|r| r.confirmation.is_some())
        {
            o.status = "error".into();
        }
    } else {
        o.attempts = 0;
        o.retry_after = 0;
    }
}

// ---------------------------------------------------------------- static snapshot

/// Tracks what has already been written so an unchanged block costs no disk writes.
#[derive(Default)]
struct Exporter {
    payments:payment_watch::PaymentWatch,
    written: HashMap<String, u64>,
    last_height: u32,
    last_tip_hash: Option<String>,
}

fn bytes_hash(b: &[u8]) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    b.hash(&mut h);
    h.finish()
}

/// Writes every read endpoint as a file under `export_dir`, mirroring the URL layout
/// (`/api/items.json`, `/api/items/<id>.json`, `/api/items/<id>/image.png`, ...).
/// Documents are collected under the lock, files are written after it is released.
fn export_snapshot(shared: &Shared, ex: &mut Exporter) -> Result<()> {
    let (dir, docs, images, height, tip_hash) = {
        let mut app = shared.lock().unwrap();
        let Some(dir) = app.cfg.export_dir.clone() else {
            return Ok(());
        };
        if app.index.height == ex.last_height
            && app.index.tip_hash == ex.last_tip_hash
            && !app.export_dirty
        {
            return Ok(());
        }
        app.export_dirty = false;
        let mut docs: Vec<(String, Vec<u8>)> = vec![];
        docs.push((
            "config.js".into(),
            format!(
                "window.OVERSTORY = {{ origin: {:?} }};\n",
                app.cfg.public_origin
            )
            .into_bytes(),
        ));
        docs.push((
            "api/collection.json".into(),
            serde_json::to_vec(&collection_json(&app))?,
        ));
        docs.push((
            "api/stats.json".into(),
            serde_json::to_vec(&stats_json(&app))?,
        ));
        docs.push((
            "api/listings.json".into(),
            serde_json::to_vec(&listings_json(&app))?,
        ));
        let items = items_json(&app);
        docs.push(("api/items.json".into(), serde_json::to_vec(&items)?));
        let mut by_addr: BTreeMap<String, Vec<serde_json::Value>> = BTreeMap::new();
        let mut images: Vec<(String, String)> = vec![];
        for it in &items {
            let id = it["id"].as_str().unwrap_or_default().to_string();
            docs.push((format!("api/items/{id}.json"), serde_json::to_vec(it)?));
            if let Some(a) = it["owner_address"].as_str() {
                by_addr.entry(a.to_string()).or_default().push(it.clone());
            }
            if let Some(seed) = it["seed"].as_str() {
                images.push((format!("api/items/{id}/image.png"), seed.to_string()));
                images.push((format!("api/seed/{seed}.png"), seed.to_string()));
            }
        }
        for (a, v) in by_addr {
            docs.push((format!("api/address/{a}.json"), serde_json::to_vec(&v)?));
        }
        // fixed seeds the pages use as decoration: the favicon (1) and the home wall fillers (11..=18)
        for n in std::iter::once(1u32).chain(11..=18) {
            let seed = format!("{n:064x}");
            images.push((format!("api/seed/{seed}.png"), seed));
        }
        (
            dir,
            docs,
            images,
            app.index.height,
            app.index.tip_hash.clone(),
        )
    };
    let root = std::path::Path::new(&dir);
    let mut n = 0;
    // Invalidate first: a failed dirty-only export must retry at the same height too.
    ex.last_height = u32::MAX;
    ex.last_tip_hash = None;
    for (rel, seed) in images {
        n += write_snapshot_image(root, &rel, &seed, ex)? as usize;
    }
    for (rel, bytes) in docs {
        let h = bytes_hash(&bytes);
        let path = root.join(&rel);
        if ex.written.get(&rel) == Some(&h) && path.is_file() {
            continue;
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&path, &bytes)?;
        ex.written.insert(rel, h);
        n += 1;
    }
    // Failed writes must be retried even when the next pass sees the same tip.
    ex.last_height = height;
    ex.last_tip_hash = tip_hash;
    if n > 0 {
        println!(
            "snapshot: {n} file(s) written to {dir} at height {}",
            ex.last_height
        );
    }
    Ok(())
}

/// Mutable item URLs must be refreshed if their seed changes, including after restart.
fn write_snapshot_image(
    root: &std::path::Path,
    rel: &str,
    seed: &str,
    ex: &mut Exporter,
) -> Result<bool> {
    let path = root.join(rel);
    let fingerprint = bytes_hash(seed.as_bytes());
    if ex.written.get(rel) == Some(&fingerprint) && path.is_file() {
        return Ok(false);
    }
    let bytes = png_for_seed(seed, 4)?;
    let changed = match std::fs::read(&path) {
        Ok(old) => old != bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => true,
        Err(e) => return Err(e.into()),
    };
    if changed {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&path, bytes)?;
    }
    ex.written.insert(rel.into(), fingerprint);
    Ok(changed)
}

fn process_order(shared: &Shared, rpc: &Rpc, o: &mut Order) -> Result<()> {
    ensure_not_settling(o)?;
    // Old signed mint jobs remain recoverable; old unsigned payment histories require review.
    if o.mint_plan.is_some() {
        if o.accounting_version == 1 {
            observe(o, &rpc.spendable(&o.invoice_address)?)?;
            ledger(o)?;
        }
        resume_mint(shared, rpc, o)?;
        if o.status == "done" && o.accounting_version == 1 {
            settle_refund(shared, rpc, o, true)?;
        }
        return Ok(());
    }
    if o.accounting_version != 1
        || o.kind != "mint"
        || o.mint_journal_version != 1
        || o.status == "inscribing"
    {
        return Err(RecoveryRequired(
            "legacy/missing payment journal; reconcile before continuing".into(),
        )
        .into());
    }
    if o.refund_mode {
        return refund(shared, rpc, o);
    }
    require_unsigned_order_terms(o)?;
    match o.status.as_str() {
        "awaiting_payment" | "expired" => {
            observe(o, &rpc.spendable(&o.invoice_address)?)?;
            if now() >= o.expires || o.status == "expired" {
                o.refund_mode = true;
                return refund(shared, rpc, o);
            }
            if o.paid_zat >= o.amount_zat {
                o.status = "paid".into();
                persist_order(shared, o)?;
                return process_order(shared, rpc, o);
            }
            Ok(())
        }
        "paid" if o.kind == "purchase" => {
            let (listing, cfg, live) = {
                let app = shared.lock().unwrap();
                let l = o
                    .listing_id
                    .as_ref()
                    .and_then(|id| app.listings.get(id).cloned());
                let live = l.as_ref().map(|l| listing_live(&app, l)).unwrap_or(false);
                (l, app.cfg.clone(), live)
            };
            let Some(listing) = listing.filter(|_| live) else {
                refund(shared, rpc, o)?;
                o.error = Some("listing no longer available".into());
                return Ok(());
            };
            let key = load_order_key(&o.id)?;
            let funding: Vec<Utxo> = rpc.utxos(&o.invoice_address)?;
            let dest_addr = proto::parse_taddr_for(&o.dest, rpc.net().network_type())?;
            let fee_out = (cfg.service_fee_zat > 0)
                .then(|| OutputSpec {
                    to: proto::parse_taddr_for(&cfg.fee_address, rpc.net().network_type())
                        .expect("validated fee address"),
                    value: cfg.service_fee_zat,
                })
                .into_iter()
                .collect();
            let txid =
                execute_purchase_with(rpc, &listing, &key, &funding, &o.dest, &dest_addr, fee_out)?;
            o.txids.push(txid);
            o.inscription_id = shared
                .lock()
                .unwrap()
                .index
                .single_carrier(&format!(
                    "{}:{}",
                    listing.carrier_txid, listing.carrier_vout
                ))
                .cloned();
            o.status = "purchasing".into();
            Ok(())
        }
        "purchasing" => {
            let id = o.inscription_id.clone().unwrap_or_default();
            let app = shared.lock().unwrap();
            if let Some(ins) = app.index.inscriptions.get(&id) {
                if ins.owner_address.as_deref() == Some(o.dest.as_str()) {
                    o.status = "done".into();
                    o.number = app.index.mints.get(&id).map(|m| m.number);
                }
            }
            Ok(())
        }
        "paid" => {
            if now() >= o.expires { return refund(shared,rpc,o); }
            let (col, quote, tip) = {
                let app = shared.lock().unwrap();
                let quote = checked_order_quote(&app, o)?;
                (app.index.collections.get(&quote.collection).cloned().context("collection not indexed")?, quote, app.tip)
            };
            // Never prepare an early reveal; a deferred paid invoice still expires normally.
            if !next_block_can_mint(tip,col.start) { return Ok(()); }
            let in_flight = {
                let app = shared.lock().unwrap();
                app.orders
                    .values()
                    .filter(|x| x.status == "inscribing" && x.id != o.id)
                    .count() as u64
            };
            if col.minted + in_flight >= col.supply {
                refund(shared, rpc, o)?;
                o.error = Some("sold out".into());
                return Ok(());
            }
            let key = load_order_key(&o.id)?;
            let decl = mint_declaration(&col.id);
            let pay = (col.price > 0).then(|| (col.pay.as_str(), col.price));
            let dest_addr = proto::parse_taddr_for(refund_destination(o)?, rpc.net().network_type())?;
            let service_to=proto::parse_taddr_for(&quote.fee_address,rpc.net().network_type())?;
            let plan = if quote.inclusive {
                proto::inscribe::prepare_inclusive_inscription(rpc,&key,&decl,b"application/json",&o.dest,pay,&dest_addr,
                    proto::inscribe::InclusiveBudget {total_zat:quote.total_zat,service_to})?
            } else {
                let fee_out=(quote.service_fee_zat>0).then(||OutputSpec {to:service_to,value:quote.service_fee_zat}).into_iter().collect();
                prepare_inscription(rpc,&key,&decl,b"application/json",&o.dest,pay,&dest_addr,fee_out)?
            };
            plan.validate(rpc)?;
            o.inscription_id = Some(plan.result.inscription_id.clone());
            o.txids = plan.transactions.iter().map(|t| t.txid.clone()).collect();
            observe(o, &plan.funding)?;
            o.mint_plan = Some(plan);
            ledger(o)?;
            o.status = "inscribing".into();
            // One SQLite record contains both intent and every signed byte. FULL sync
            // must complete before the first external side effect.
            {
                let mut app = shared.lock().unwrap();
                save_order(&app.db, o)?;
                app.orders.insert(o.id.clone(), o.clone());
            }
            resume_mint(shared, rpc, o)
        }
        "inscribing" => {
            let id = o.inscription_id.clone().unwrap_or_default();
            let app = shared.lock().unwrap();
            if let Some(m) = app.index.mints.get(&id) {
                o.number = Some(m.number);
                o.seed = Some(m.seed.clone());
                o.status = "done".into();
            } else if let Some(ins) = app.index.inscriptions.get(&id) {
                // Indexed but not a member: find why.
                let why = app
                    .index
                    .rejected
                    .iter()
                    .find(|r| r.starts_with(&id))
                    .cloned();
                if let Some(w) = why {
                    o.status = "error".into();
                    o.error = Some(format!("inscribed at {} but rejected: {w}", ins.owner));
                }
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn resume_mint(shared: &Shared, rpc: &Rpc, o: &mut Order) -> Result<()> {
    ensure_not_settling(o)?;
    let plan = o.mint_plan.as_ref().context("missing mint plan")?;
    anyhow::ensure!(
        plan.destination == o.dest,
        "order destination differs from saved plan"
    );
    plan.validate(rpc)?;
    let id = &plan.result.inscription_id;
    {
        let app = shared.lock().unwrap();
        if let Some(m) = app.index.mints.get(id) {
            o.number = Some(m.number);
            o.seed = Some(m.seed.clone());
            o.status = "done".into();
            o.error = None;
            o.retry_after = 0;
            return Ok(());
        }
        if let Some(why) = app.index.rejected.iter().find(|r| r.starts_with(id)) {
            return Err(RecoveryRequired(format!(
                "saved mint was indexed but rejected: {why}; inspect payment before refund"
            ))
            .into());
        }
    }
    plan.resume(rpc)?;
    o.status = "inscribing".into();
    o.error = None;
    o.retry_after = 0;
    Ok(())
}

fn persist_order(shared: &Shared, o: &Order) -> Result<()> {
    let mut app = shared.lock().unwrap();
    save_order(&app.db, o)?;
    app.orders.insert(o.id.clone(), o.clone());
    Ok(())
}

fn point(u: &Utxo) -> String {
    format!("{}:{}", u.txid, u.n)
}
fn observe(o: &mut Order, current: &[Utxo]) -> Result<()> {
    for u in current {
        if let Some(old) = o.receipts.get(&point(u)) {
            anyhow::ensure!(
                old.value == u.value && old.script == u.script,
                "receipt changed"
            );
        } else {
            o.receipts.insert(point(u), u.clone());
        }
    }
    o.paid_zat = o.receipts.values().try_fold(0u64, |n, u| {
        n.checked_add(u.value).context("receipt overflow")
    })?;
    proto::zat(o.paid_zat)?;
    Ok(())
}

/// Gross confirmed plain-payment inputs, partitioned without double allocation.
/// Mint allocation includes any change returned by the commit to the destination.
fn allocations(o: &Order) -> Result<BTreeMap<String, &'static str>> {
    let mut used = BTreeMap::new();
    let mut add = |funding: &[Utxo], kind| -> Result<()> {
        for u in funding {
            let old = o
                .receipts
                .get(&point(u))
                .context("allocated input has no receipt")?;
            anyhow::ensure!(
                old.value == u.value && old.script == u.script,
                "allocated receipt mismatch"
            );
            anyhow::ensure!(
                used.insert(point(u), kind).is_none(),
                "payment allocated twice"
            );
        }
        Ok(())
    };
    if let Some(p) = &o.mint_plan {
        anyhow::ensure!(!p.funding.is_empty(), "mint funding history missing");
        add(&p.funding, "mint")?;
    }
    for r in &o.refunds {
        let total = r.plan.funding.iter().try_fold(0u64, |n, u| {
            n.checked_add(u.value).context("refund allocation overflow")
        })?;
        anyhow::ensure!(
            total == r.plan.input_zat,
            "refund allocated input total mismatch"
        );
        add(
            &r.plan.funding,
            if r.confirmation.is_some() {
                "refunded"
            } else {
                "reserved"
            },
        )?;
    }
    Ok(used)
}
fn ledger(o: &Order) -> Result<serde_json::Value> {
    anyhow::ensure!(o.accounting_version == 1, "legacy accounting unavailable");
    let used = allocations(o)?;
    let mut sums = BTreeMap::<&str, u64>::new();
    for (p, u) in &o.receipts {
        anyhow::ensure!(*p == point(u), "receipt outpoint key mismatch");
        let n = sums
            .entry(used.get(p).copied().unwrap_or("unallocated"))
            .or_default();
        *n = n.checked_add(u.value).context("ledger overflow")?;
    }
    let mut paid = 0u64;
    let mut fees = 0u64;
    for r in &o.refunds {
        anyhow::ensure!(
            r.plan.input_zat
                == r.plan
                    .refund_zat
                    .checked_add(r.plan.fee_zat)
                    .context("refund sum overflow")?,
            "refund sum mismatch"
        );
        if r.confirmation.is_some() {
            paid = paid
                .checked_add(r.plan.refund_zat)
                .context("refund overflow")?;
            fees = fees.checked_add(r.plan.fee_zat).context("fee overflow")?;
        }
    }
    let sum = |k| sums.get(k).copied().unwrap_or(0);
    anyhow::ensure!(
        sum("refunded") == paid.checked_add(fees).context("settlement overflow")?,
        "settlement mismatch"
    );
    let total = sums
        .values()
        .try_fold(0u64, |n, v| n.checked_add(*v).context("total overflow"))?;
    proto::zat(total)?;
    anyhow::ensure!(total == o.paid_zat, "receipt total mismatch");
    Ok(
        json!({"available":true,"observed_received_zat":total,"mint_allocated_input_zat":sum("mint"),
        "refund_confirmed_zat":paid,"refund_network_fee_zat":fees,"refund_pending_input_zat":sum("reserved"),
        "unallocated_received_zat":sum("unallocated"),"monitor_until":o.expires.saturating_add(7*86400).max(o.payment_review_until)}),
    )
}

/// Persist all signed bytes and input reservations before making a network side effect.
fn refund(shared: &Shared, rpc: &Rpc, o: &mut Order) -> Result<()> {
    anyhow::ensure!(o.mint_plan.is_none(), "mint allocation requires manual refund reconciliation");
    settle_refund(shared, rpc, o, false)
}

// A successful NFT delivery can coexist with a refund of unrelated later deposits.
// Mint inputs remain permanently allocated; only unallocated plain receipts are eligible.
fn settle_refund(shared: &Shared, rpc: &Rpc, o: &mut Order, completed_mint: bool) -> Result<()> {
    ensure_not_settling(o)?;
    anyhow::ensure!(
        if completed_mint {o.mint_plan.is_some() && o.status == "done"} else {o.mint_plan.is_none()},
        "invalid surplus refund state"
    );
    o.refund_mode = !completed_mint;
    ledger(o)?;
    if let Some(i) = o.refunds.iter().position(|r| r.confirmation.is_none()) {
        anyhow::ensure!(
            o.refunds[i].plan.destination == o.refund_address.as_deref().unwrap_or(&o.dest),
            "refund destination changed"
        );
        let confirmation = o.refunds[i].plan.resume(rpc)?;
        if confirmation.is_none() {
            o.status = if completed_mint {"done"} else {"refunding"}.into();
            o.retry_after = 0;
            return Ok(());
        }
        o.refunds[i].confirmation = confirmation;
        ledger(o)?;
        persist_order(shared, o)?;
    }
    let current = rpc.spendable(&o.invoice_address)?;
    observe(o, &current)?;
    let used = allocations(o)?;
    let available: BTreeMap<_, _> = current.iter().map(|u| (point(u), u)).collect();
    for p in o.receipts.keys().filter(|p| !used.contains_key(*p)) {
        if !available.contains_key(p) {
            return Err(RecoveryRequired(format!(
                "unallocated payment {p} no longer spendable; reconcile before refund"
            ))
            .into());
        }
    }
    let funding: Vec<_> = current
        .into_iter()
        .filter(|u| !used.contains_key(&point(u)))
        .collect();
    if funding.is_empty() {
        o.status = if completed_mint {
            "done"
        } else if o.refunds.is_empty() {
            "expired"
        } else {
            "refunded"
        }
        .into();
        o.error = None;
        o.retry_after = 0;
        return Ok(());
    }
    if funding.len() > 100 {
        return Err(RecoveryRequired(
            "refund has more than 100 inputs; review batching and fees".into(),
        )
        .into());
    }
    let total = funding.iter().try_fold(0u64, |n, u| {
        n.checked_add(u.value).context("refund overflow")
    })?;
    if proto::refund::amounts(total, funding.len())?.is_none() {
        o.status = if completed_mint {"done"} else {"refund_pending_small"}.into();
        o.error = None;
        o.retry_after = 0;
        return Ok(());
    }
    let key = load_order_key(&o.id)?;
    let plan = proto::refund::RefundPlan::prepare(rpc, &key, funding, refund_destination(o)?)?
        .context("refund amount changed")?;
    o.txids.push(plan.txid.clone());
    o.refunds.push(RefundRecord {
        plan,
        confirmation: None,
    });
    o.status = if completed_mint {"done"} else {"refunding"}.into();
    o.error = None;
    o.retry_after = 0;
    ledger(o)?;
    persist_order(shared, o)?;
    // A broadcast receipt is deliberately not a confirmation.
    o.refunds.last().unwrap().plan.resume(rpc)?;
    Ok(())
}

// ---------------------------------------------------------------- api

fn item_json(app: &App, id: &str) -> Option<serde_json::Value> {
    let ins = app.index.inscriptions.get(id)?;
    let m = app.index.mints.get(id);
    let traits = m.map(|m| {
        let seed: [u8; 32] = hex::decode(&m.seed).unwrap().try_into().unwrap();
        let (g, t) = render(&seed);
        json!({"traits": t, "matrix_sha256": grid_hash(&g)})
    });
    let listing = app.listings.get(&ins.owner).filter(|l| market_is_open(app) && listing_live(app, l)).map(|l| json!({
        "market_fee_zat":proto::market_fee::quote(l.price_zat).ok().map(|q|q.market_fee_zat),"purchase_total_zat":proto::market_fee::quote(l.price_zat).ok().map(|q|q.purchase_total_zat),
        "id": ins.owner, "price_zat": l.price_zat, "expiry_height": l.expiry_height, "payout_address": l.payout_address,
    }));
    Some(json!({
        "id": id, "owner_address": ins.owner_address, "owner": ins.owner, "listing": listing, "chain_ready":app.healthy,
        "genesis_height": ins.genesis_height, "completion_height": ins.completion_height, "completion_block_hash": ins.completion_block_hash, "carrier_count": app.index.carriers.get(&ins.owner).map(|ids|ids.len()).unwrap_or(0), "content_type": ins.content_type, "family": ins.family,
        "number": m.map(|m| m.number), "seed": m.map(|m| m.seed.clone()), "minter": m.map(|m| m.minter.clone()),
        "render": traits, "history": ins.history, "content_hex": ins.content_hex, "content_len": ins.content_len,
        "content_sha256": ins.content_sha256, "genesis_block_hash": ins.genesis_block_hash, "collection": m.map(|m| m.collection.clone()),
    }))
}

async fn api_collection(State(s): State<Shared>) -> Json<serde_json::Value> {
    Json(collection_json(&s.lock().unwrap()))
}

fn collection_json(app: &App) -> serde_json::Value {
    let col = app.index.collections.get(&app.cfg.collection);
    let holders = app
        .index
        .mints
        .values()
        .filter(|m| m.collection == app.cfg.collection)
        .filter_map(|m| {
            app.index
                .inscriptions
                .get(&m.inscription)
                .and_then(|i| i.owner_address.clone())
        })
        .collect::<std::collections::BTreeSet<_>>()
        .len();
    let listed = app
        .listings
        .values()
        .filter(|l| market_is_open(app) && listing_live(app, l))
        .count();
    json!({
        "network": app.cfg.network, "genesis_hash": app.genesis_hash, "tip": app.tip, "healthy": app.healthy, "indexed_height": app.index.height,
        "index_history": {"scope":app.index.history_scope(),"replay_from":app.index.replay_from,"independently_verified":false},
        "collection": col, "order_amount_zat": order_amount(app), "mint_quote":mint_quote(app).ok(), "service_fee_zat": app.cfg.service_fee_zat,
        "market_fee_bps":proto::market_fee::BASIS_POINTS,"market_fee_address":app.cfg.fee_address,"market_min_price_zat":proto::market_fee::MIN_PRICE_ZAT,
        "commit_fee_estimate_zat": COMMIT_FEE_ESTIMATE, "market_open": market_is_open(app), "holders": holders,
        "listed": if app.healthy {Some(listed)} else {None}, "explorer_url": app.cfg.explorer_url, "branch": proto::network::branch_name(app.net.branch_for(app.tip.saturating_add(1))),
    })
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct InvoiceIntent {
    request_id: String,
    quote: MintQuote,
}
impl InvoiceIntent {
    fn valid_id(&self) -> bool {
        self.request_id.len()==64 && self.request_id.bytes().all(|c|c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    }
}
// Read durable state, including after a lost response or an ambiguous database write.
fn prior_intent(app: &App, intent: &InvoiceIntent, dest: &str, refund: &str) -> Result<Option<Order>> {
    anyhow::ensure!(intent.quote.network==app.net.name() && intent.quote.genesis_hash==app.genesis_hash && intent.quote.collection==app.cfg.collection,"invoice intent belongs to another chain or collection");
    let mut query=app.db.conn.prepare("SELECT k,json FROM kv WHERE ns=?1 AND json_extract(json,'$.invoice_intent.request_id')=?2")?;
    let mut rows=query.query([NS_ORDERS,intent.request_id.as_str()])?;
    let Some(row)=rows.next()? else { return Ok(None) };
    let key:String=row.get(0)?;
    let order:Order=serde_json::from_str(&row.get::<_,String>(1)?)?;
    anyhow::ensure!(rows.next()?.is_none(),"duplicate request identity; operator reconciliation required");
    anyhow::ensure!(key==order.id && order.kind=="mint" && order.invoice_intent.as_ref()==Some(intent)
        && order.quote.as_ref()==Some(&intent.quote) && order.amount_zat==intent.quote.total_zat
        && order.dest==dest && order.refund_address.as_deref()==Some(refund),"request identity conflicts with saved invoice");
    anyhow::ensure!(app.orders.contains_key(&key),"saved invoice requires service reconciliation");
    Ok(Some(order))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NewOrder {
    dest: String,
    refund_address: String,
    refund_confirmed: bool,
    #[serde(default)]
    intent: Option<InvoiceIntent>,
}
fn validate_order_addresses(req: &NewOrder, net: Net) -> Result<(String,String)> {
    anyhow::ensure!(req.refund_confirmed,"confirm the refund address before creating an invoice");
    let dest=req.dest.trim().to_string();
    let refund=req.refund_address.trim().to_string();
    proto::parse_taddr_for(&dest,net.network_type())?;
    proto::parse_taddr_for(&refund,net.network_type())?;
    Ok((dest,refund))
}

mod order_backup;
async fn api_new_order(State(s): State<Shared>, Json(req): Json<NewOrder>) -> Response {
    let response = prepare_new_order(&s, req);
    if !response.status().is_success() { return response; }
    let body = match axum::body::to_bytes(response.into_body(), 128 * 1024).await {
        Ok(body) => body, Err(_) => return order_backup::unavailable(),
    };
    let value = match serde_json::from_slice::<serde_json::Value>(&body) {
        Ok(value) => value, Err(_) => return order_backup::unavailable(),
    };
    let Some(id) = value["id"].as_str() else { return order_backup::unavailable() };
    if order_backup::confirm(&s, id).await.is_err() { return order_backup::unavailable(); }
    let app=s.lock().unwrap();
    match app.orders.get(id) {
        Some(order) if order_backup::ready(&app, order) => Json(order_view(&app, order)).into_response(),
        _ => order_backup::unavailable(),
    }
}
fn prepare_new_order(s: &Shared, req: NewOrder) -> Response {
    let (dest,refund_address)=match validate_order_addresses(&req,s.lock().unwrap().net) {
        Ok(v)=>v,
        Err(_)=>return (StatusCode::BAD_REQUEST,Json(json!({"error":"provide valid transparent destination and refund addresses for this network, and explicitly confirm the refund address"}))).into_response(),
    };
    let mut app = s.lock().unwrap();
    if let Some(intent)=&req.intent {
        if !intent.valid_id() {
            return (StatusCode::BAD_REQUEST,Json(json!({"error":"request_id must be 32 random bytes encoded as lowercase hex"}))).into_response();
        }
        match prior_intent(&app,intent,&dest,&refund_address) {
            Ok(Some(order))=>return Json(order_view(&app,&order)).into_response(),
            Ok(None)=>{},
            Err(_)=>return (StatusCode::CONFLICT,Json(json!({"error":"request identity conflicts or requires reconciliation; do not create a replacement invoice"}))).into_response(),
        }
        if mint_quote(&app).ok().as_ref()!=Some(&intent.quote) {
            return (StatusCode::CONFLICT,Json(json!({"error":"quote changed; refresh and confirm the new terms"}))).into_response();
        }
    } else if app.net!=Net::Regtest {
        return (StatusCode::BAD_REQUEST,Json(json!({"error":"a bound invoice intent is required"}))).into_response();
    }
    if !app.healthy {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error":"index is not ready"})),
        )
            .into_response();
    }
    let Some(amount) = order_amount(&app) else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "collection not indexed yet"})),
        )
            .into_response();
    };
    let col = app.index.collections.get(&app.cfg.collection).unwrap();
    if !next_block_can_mint(app.tip,col.start) {
        return (StatusCode::CONFLICT,Json(json!({"error":format!("minting starts at block {}; invoices are not open yet",col.start)}))).into_response();
    }
    if col.minted >= col.supply {
        return (StatusCode::GONE, Json(json!({"error": "sold out"}))).into_response();
    }
    // Storage safety ceiling, not a per-address mint limit. Never delete financial records to make room.
    if app.orders.len() >= app.cfg.max_saved_orders {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"error":"invoice capacity reached; existing invoices remain valid; contact the operator"}))).into_response();
    }
    // Serialize creation with operator pause acknowledgement; prior intent retries returned above.
    let _admission_guard = match invoice_control::lock(std::path::Path::new("mintd/admission.lock")) {
        Ok(guard) => guard,
        Err(_) => return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"error":"invoice admission busy; retry the same request"}))).into_response(),
    };
    match invoice_control::read(&app.db) {
        Ok(control) if !control.paused => {},
        _ => return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"error":"new invoices are paused; existing invoices remain valid"}))).into_response(),
    }
    match new_order(&mut app, dest, refund_address, amount, "mint", None, req.intent) {
        Ok(o) => Json(public_order(&o)).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

fn new_order(
    app: &mut App,
    dest: String,
    refund_address: String,
    amount: u64,
    kind: &str,
    listing_id: Option<String>,
    invoice_intent: Option<InvoiceIntent>,
) -> Result<Order> {
    let quote=mint_quote(app)?;
    anyhow::ensure!(kind=="mint" && amount==quote.total_zat,"order quote mismatch");
    let key = Key::random();
    let id = hex::encode(&Key::random().sk.to_secret_bytes()[..8]);
    std::fs::create_dir_all("keys/orders")?;
    {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(order_key_path(&id))?;
        file.write_all(key.secret_hex().as_bytes())?;
        file.sync_all()?;
    }
    let o = Order {
        id: id.clone(),
        dest,
        invoice_address: key.address_string(app.net),
        amount_zat: amount,
        created: now(),
        payment_start_height: Some(app.index.height),
        payment_review_until: 0,
        expires: now() + app.cfg.order_ttl_secs,
        status: "awaiting_payment".into(),
        paid_zat: 0,
        inscription_id: None,
        txids: vec![],
        number: None,
        seed: None,
        error: None,
        attempts: 0,
        kind: kind.into(),
        listing_id,
        mint_journal_version: 1,
        mint_plan: None,
        retry_after: 0,
        accounting_version: 1,
        receipts: BTreeMap::new(),
        refunds: vec![],
        refund_mode: false,
        quote: Some(quote),
        refund_address: Some(refund_address),
        settlement_hold: false,
        invoice_intent,
    };
    save_order(&app.db, &o)?;
    app.orders.insert(id, o.clone());
    Ok(o)
}

async fn api_new_purchase() -> Response {
    (StatusCode::GONE,Json(json!({"error":"custodial purchase invoices are disabled; use local wallet purchase preparation"}))).into_response()
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PreparePurchase {
    listing_id: String,
    inscription_id: String,
    collection: String,
    buyer_pubkey: String,
    market_fee_address: String,
    max_market_fee_zat: u64,
    max_price_zat: u64,
    max_fee_zat: u64,
}
// Shared admission limit for public endpoints that query or broadcast through the project RPC.
// The worker is outside this pool so HTTP bursts cannot occupy every admitted API job.
fn chain_api_permit()->std::result::Result<tokio::sync::OwnedSemaphorePermit,Response> {
    static JOBS:std::sync::OnceLock<Arc<tokio::sync::Semaphore>>=std::sync::OnceLock::new();
    JOBS.get_or_init(||Arc::new(tokio::sync::Semaphore::new(2))).clone().try_acquire_owned()
        .map_err(|_|(StatusCode::TOO_MANY_REQUESTS,Json(json!({"error":"market service busy; preserve any signed transaction and retry later"}))).into_response())
}
async fn api_prepare_purchase(
    State(s): State<Shared>,
    Json(req): Json<PreparePurchase>,
) -> Response {
    let permit=match chain_api_permit(){Ok(p)=>p,Err(r)=>return r};
    let (listing, market_fee_address) = {
        let app = s.lock().unwrap();
        if !app.healthy || !market_is_open(&app) {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error":"market/index not ready"})),
            )
                .into_response();
        }
        if app.index.single_carrier(&req.listing_id) != Some(&req.inscription_id)
            || !app.index.mints.get(&req.inscription_id).is_some_and(|m| {
                m.collection == req.collection && m.collection == app.cfg.collection
            })
        {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error":"expected asset membership mismatch"})),
            )
                .into_response();
        }
        match app
            .listings
            .get(&req.listing_id)
            .filter(|l| listing_live(&app, l))
        {
            Some(l) => (l.clone(), app.cfg.fee_address.clone()),
            None => {
                return (
                    StatusCode::GONE,
                    Json(json!({"error":"listing unavailable"})),
                )
                    .into_response();
            }
        }
    };
    let result=tokio::task::spawn_blocking(move || -> Result<serde_json::Value> {
        let _permit=permit;
        anyhow::ensure!(listing.price_zat<=req.max_price_zat,"price exceeds buyer approval");
        proto::zat(req.max_fee_zat)?;
        let quote=proto::market_fee::quote(listing.price_zat).map_err(anyhow::Error::msg)?;
        anyhow::ensure!(req.market_fee_address==market_fee_address && quote.market_fee_zat<=req.max_market_fee_zat,"market fee differs from buyer approval");
        let rpc=Rpc::open()?;let st=rpc.index_snapshot()?;
        anyhow::ensure!(st.single_carrier(&req.listing_id)==Some(&req.inscription_id),"asset moved; refresh");
        let pk=secp256k1::PublicKey::from_slice(&hex::decode(&req.buyer_pubkey)?)?;
        let addr=TransparentAddress::from_pubkey(&pk).to_zcash_address(rpc.net().network_type()).encode();
        let carrier=Utxo{txid:listing.carrier_txid.clone(),n:listing.carrier_vout,script:listing.carrier_script.clone(),value:listing.carrier_value,height:st.height};rpc.validate_utxo(&carrier)?;
        let needed=quote.purchase_total_zat.checked_add(req.max_fee_zat).context("amount overflow")?;
        let mut all=rpc.spendable(&addr)?;all.sort_by_key(|u|std::cmp::Reverse(u.value));
        let fund=all.into_iter().find(|u|u.value>=needed).context("fund this vault with a confirmed plain ZEC output before buying")?;
        let target=rpc.checked_window(listing.expiry_height)?;
        Ok(json!({"network":rpc.net().name(),"genesis_hash":rpc.chain.genesis_hash,"target_height":target,"inscription_id":req.inscription_id,"collection":req.collection,"listing":listing,"funding":[fund],"market_fee_address":market_fee_address,"market_fee_zat":quote.market_fee_zat,"purchase_total_zat":quote.purchase_total_zat}))
    }).await;
    match result {
        Ok(Ok(v)) => Json(v).into_response(),
        Ok(Err(e)) => (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":e.to_string()})),
        )
            .into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error":"preparation failed"})),
        )
            .into_response(),
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Broadcast {
    raw_transaction: String,
}
fn validate_known_transaction_status(v:&serde_json::Value,txid:&str,pool:impl FnOnce()->Result<serde_json::Value>)->Result<()> {
    match v["confirmations"].as_i64() {
        Some(n) if n > 0 => Ok(()),
        Some(n) if n < 0 => anyhow::bail!("transaction is not on the current chain"),
        _ => {
            // Missing confirmation metadata is not evidence of mempool acceptance.
            let ids=pool()?;
            anyhow::ensure!(ids.as_array().is_some_and(|ids|ids.iter().any(|id|id.as_str()==Some(txid))),"transaction is not on the current chain or mempool");
            Ok(())
        }
    }
}

async fn api_broadcast(State(s): State<Shared>, Json(req): Json<Broadcast>) -> Response {
    let reviewed=(||->Result<(Listing,String,bool)> {
        let app=s.lock().unwrap();
        anyhow::ensure!(app.healthy && market_is_open(&app),"market/chain checks pending");
        let target=app.tip.checked_add(1).context("height overflow")?;
        let (point,id)=proto::market_relay::candidate(&req.raw_transaction,app.net,target)?;
        let l=app.listings.get(&point).context("public relay accepts published project listings only; mint with your own RPC")?;
        proto::market_relay::validate_with_fee(&req.raw_transaction,app.net,target,l,&app.index,&app.cfg.collection,&app.cfg.fee_address)?;
        Ok((l.clone(),id,listing_live(&app,l)))
    })();
    let (listing,txid,live)=match reviewed {
        Ok(v)=>v,
        Err(e)=>return (if s.lock().unwrap().healthy {StatusCode::BAD_REQUEST}else{StatusCode::SERVICE_UNAVAILABLE},Json(json!({"error":e.to_string()}))).into_response(),
    };
    let permit=match chain_api_permit(){Ok(p)=>p,Err(r)=>return r};
    let result = tokio::task::spawn_blocking(move || -> Result<String> {
        let _permit=permit;
        anyhow::ensure!(market_is_open(&s.lock().unwrap()),"market/chain checks pending; broadcast paused");
        let rpc=Rpc::open()?;
        let st=rpc.index_snapshot()?;
        let (collection,fee_address)={let app=s.lock().unwrap();(app.cfg.collection.clone(),app.cfg.fee_address.clone())};
        proto::market_relay::validate_with_fee(&req.raw_transaction,rpc.net(),st.height.checked_add(1).context("height overflow")?,&listing,&st,&collection,&fee_address)?;
        // A lost acknowledgement must not cause a new transaction. Report only exact known bytes.
        match rpc.call("getrawtransaction",json!([txid,1])) {
            Ok(v)=>{
                anyhow::ensure!(v["hex"].as_str().and_then(|h|hex::decode(h).ok())==hex::decode(&req.raw_transaction).ok(),"known transaction bytes mismatch");
                validate_known_transaction_status(&v,&txid,||rpc.call("getrawmempool",json!([])))?;
                return Ok(txid);
            },
            Err(e) if e.downcast_ref::<proto::RpcCallError>().is_some_and(|e|e.code == -5)=>{},
            Err(e)=>return Err(e),
        }
        anyhow::ensure!(live,"listing already spent or expired; check your saved transaction");
        rpc.send_raw(&req.raw_transaction)
    })
    .await;
    match result {
        Ok(Ok(id)) => Json(json!({"txid":id})).into_response(),
        Ok(Err(e)) => (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":e.to_string()})),
        )
            .into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error":"broadcast failed; check saved txid before retry"})),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
struct PrepareListing {
    inscription_id: String,
    price_zat: u64,
    seller_pubkey: String,
    expiry_height: Option<u32>,
}

async fn api_prepare_listing(State(s): State<Shared>, Json(req): Json<PrepareListing>) -> Response {
    let permit=match chain_api_permit(){Ok(p)=>p,Err(r)=>return r};
    let pk = match hex::decode(&req.seller_pubkey)
        .ok()
        .and_then(|b| secp256k1::PublicKey::from_slice(&b).ok())
    {
        Some(pk) => pk,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "bad seller_pubkey"})),
            )
                .into_response();
        }
    };
    let ntype = s.lock().unwrap().net.network_type();
    let seller_addr = TransparentAddress::from_pubkey(&pk)
        .to_zcash_address(ntype)
        .encode();
    let (owner_outpoint, network) = {
        let app = s.lock().unwrap();
        if !app.healthy || !market_is_open(&app) {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({"error": "market opens after the mint"})),
            )
                .into_response();
        }
        let Some(ins) = app.index.inscriptions.get(&req.inscription_id) else {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "unknown inscription"})),
            )
                .into_response();
        };
        if app.index.single_carrier(&ins.owner) != Some(&req.inscription_id) {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error":"carrier must hold exactly one inscription"})),
            )
                .into_response();
        }
        if ins.owner_address.as_deref() != Some(seller_addr.as_str()) {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({"error": "that key does not own this inscription"})),
            )
                .into_response();
        }
        (ins.owner.clone(), app.cfg.network.clone())
    };
    if proto::market_fee::quote(req.price_zat).is_err() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Invalid price: official market minimum is 0.00027251 ZEC"})),
        )
            .into_response();
    }
    let (txid, n) = owner_outpoint.split_once(':').unwrap();
    let (txid, n) = (txid.to_string(), n.parse::<u32>().unwrap());
    let res = tokio::task::spawn_blocking(move || -> Result<ListingTemplate> {
        let _permit=permit;
        let rpc = Rpc::open()?;
        let carrier = rpc
            .utxos(&seller_addr)?
            .into_iter()
            .find(|u| u.txid == txid && u.n == n)
            .context("carrier not found on chain")?;
        let tip = rpc.height()?;
        anyhow::ensure!(
            carrier.value == proto::CARRIER_ZAT,
            "single-item marketplace requires standard carrier value"
        );
        let max_expiry = tip
            .checked_add(LISTING_TTL_BLOCKS)
            .context("expiry overflow")?;
        let expiry = req.expiry_height.unwrap_or(max_expiry);
        anyhow::ensure!(
            expiry > tip && expiry <= max_expiry,
            "invalid listing expiry"
        );
        prepare_listing(&rpc, &carrier, &pk, req.price_zat, expiry, &network, ntype)
    })
    .await
    .unwrap();
    match res {
        Ok(t) => {
            let id = hex::encode(&Key::random().sk.to_secret_bytes()[..8]);
            let mut app = s.lock().unwrap();
            app.prepared.insert(id.clone(), t.clone());
            Json(json!({"prepare_id": id, "digest": t.digest, "listing": t.listing}))
                .into_response()
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
struct SignListing {
    signature_der: String,
}

async fn api_sign_listing(
    State(s): State<Shared>,
    Path(id): Path<String>,
    Json(req): Json<SignListing>,
) -> Response {
    let permit=match chain_api_permit(){Ok(p)=>p,Err(r)=>return r};
    if !market_is_open(&s.lock().unwrap()) {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error":"market closed or index is not ready"})),
        )
            .into_response();
    }
    let Some(t) = s.lock().unwrap().prepared.get(&id).cloned() else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "unknown prepare id"})),
        )
            .into_response();
    };
    let sig = req.signature_der.clone();
    let res = tokio::task::spawn_blocking(move || -> Result<Listing> {
        let _permit=permit;
        let rpc = Rpc::open()?;
        finalize_listing(&rpc, &t, &sig)
    })
    .await
    .unwrap();
    match res {
        Ok(l) => {
            let mut app = s.lock().unwrap();
            if !market_is_open(&app) || !listing_live(&app, &l) {
                return (
                    StatusCode::CONFLICT,
                    Json(json!({"error":"listing is no longer live"})),
                )
                    .into_response();
            }
            let key = format!("{}:{}", l.carrier_txid, l.carrier_vout);
            if let Err(e) = save_listing(&app.db, &key, &l) {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error":e.to_string()})),
                )
                    .into_response();
            }
            app.prepared.remove(&id);
            app.listings.insert(key, l.clone());
            app.export_dirty = true;
            Json(l).into_response()
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

async fn api_listings(State(s): State<Shared>) -> Response {
    let app=s.lock().unwrap();
    if !app.healthy {
        return (StatusCode::SERVICE_UNAVAILABLE,Json(json!({"error":"Chain state is being checked; listings are temporarily unavailable."}))).into_response();
    }
    Json(listings_json(&app)).into_response()
}

fn listings_json(app: &App) -> serde_json::Value {
    if !market_is_open(app) { return json!([]); }
    let mut out = vec![];
    for (key, l) in &app.listings {
        if !listing_live(app, l) {
            continue;
        }
        let Some(ins_id) = app.index.single_carrier(key) else {
            continue;
        };
        let mut v = item_json(app, ins_id).unwrap_or_default();
        v["listing_id"] = json!(key);
        v["price_zat"] = json!(l.price_zat);
        if let Ok(q)=proto::market_fee::quote(l.price_zat) {v["market_fee_zat"]=json!(q.market_fee_zat);v["purchase_total_zat"]=json!(q.purchase_total_zat);} else {continue;}
        out.push(v);
    }
    json!(out)
}

async fn api_stats(State(s): State<Shared>) -> Json<serde_json::Value> {
    Json(stats_json(&s.lock().unwrap()))
}

fn stats_json(app: &App) -> serde_json::Value {
    let mut dist: BTreeMap<String, BTreeMap<String, u64>> = BTreeMap::new();
    let mut n = 0u64;
    for m in app
        .index
        .mints
        .values()
        .filter(|m| m.collection == app.cfg.collection)
    {
        let seed: [u8; 32] = hex::decode(&m.seed).unwrap().try_into().unwrap();
        let (_, t) = render(&seed);
        n += 1;
        for (k, v) in [
            ("species", t.species.clone()),
            ("season", t.season.clone()),
            ("sky", t.sky.clone()),
            ("form", t.form.clone()),
            ("generations", t.generations.to_string()),
            ("anchor", t.anchor.to_string()),
            ("fruit", t.fruit.to_string()),
            ("easter", t.easter.clone()),
        ] {
            *dist.entry(k.into()).or_default().entry(v).or_insert(0) += 1;
        }
    }
    json!({"minted": n, "traits": dist})
}

#[derive(Deserialize)]
struct SearchQ {
    q: String,
}

async fn api_search(
    State(s): State<Shared>,
    axum::extract::Query(q): axum::extract::Query<SearchQ>,
) -> Json<serde_json::Value> {
    let app = s.lock().unwrap();
    let q = q.q.trim().trim_start_matches('#').to_string();
    let mut ids: Vec<String> = vec![];
    if let Ok(n) = q.parse::<u64>() {
        ids.extend(
            app.index
                .mints
                .values()
                .filter(|m| m.collection == app.cfg.collection && m.number == n)
                .map(|m| m.inscription.clone()),
        );
    }
    if app.index.inscriptions.contains_key(&q) {
        ids.push(q.clone());
    } else if let Some(id) = app
        .index
        .inscriptions
        .keys()
        .find(|k| k.starts_with(&q) && q.len() >= 8)
    {
        ids.push(id.clone());
    }
    if q.starts_with('t') && q.len() > 20 {
        let mut mine: Vec<(u64, String)> = app
            .index
            .mints
            .values()
            .filter(|m| {
                m.collection == app.cfg.collection
                    && app
                        .index
                        .inscriptions
                        .get(&m.inscription)
                        .and_then(|i| i.owner_address.as_deref())
                        == Some(q.as_str())
            })
            .map(|m| (m.number, m.inscription.clone()))
            .collect();
        mine.sort();
        ids.extend(mine.into_iter().map(|(_, id)| id));
    }
    ids.dedup();
    Json(json!(
        ids.iter()
            .filter_map(|id| item_json(&app, id))
            .collect::<Vec<_>>()
    ))
}

async fn api_item_content(State(s): State<Shared>, Path(id): Path<String>) -> Response {
    let app = s.lock().unwrap();
    match app.index.inscriptions.get(&id) {
        Some(ins) if ins.content_hex.is_empty() && ins.content_len > 0 => {
            // bytes not retained (only small JSON / text are kept); the hash is still served in the item JSON
            (StatusCode::NOT_FOUND, Json(json!({"error": "content not retained by this indexer", "content_sha256": ins.content_sha256}))).into_response()
        }
        Some(ins) => match hex::decode(&ins.content_hex) {
            Ok(bytes) => {
                ([
                    (header::CONTENT_TYPE, "application/octet-stream"),
                    (header::CONTENT_DISPOSITION, "attachment; filename=inscription.bin"),
                    (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
                    (header::CONTENT_SECURITY_POLICY, "default-src 'none'; sandbox"),
                ], bytes).into_response()
            }
            Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        },
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

fn order_view(app: &App, o: &Order) -> serde_json::Value {
            let mut view=public_order(o);
            if o.settlement_hold {
                view["settlement"]=proto::service_payout::public_cached(&app.db.conn,&o.id,app.net,&app.genesis_hash)
                    .unwrap_or_else(|_|json!({"available":false,"held":true,"state":"review_required","confirmation_is_historical":true}));
                view["late_settlement"]=proto::service_late::public_cached(&app.db.conn,&o.id,app.net,&app.genesis_hash)
                    .unwrap_or_else(|_|json!({"available":false,"state":"review_required","confirmation_is_historical":true}));
            }
            if !app.healthy {
                view["saved_status"]=view["status"].clone();
                view["status"]=json!("chain_check_pending");
            }
    view
}
async fn api_order(State(s): State<Shared>, Path(id): Path<String>) -> Response {
    let app = s.lock().unwrap();
    match app.orders.get(&id) {
        Some(o) if order_backup::ready(&app,o) => Json(order_view(&app,o)).into_response(),
        Some(_) => order_backup::unavailable(),
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "no such order"})),
        )
            .into_response(),
    }
}

async fn api_items(State(s): State<Shared>) -> Json<serde_json::Value> {
    Json(json!(items_json(&s.lock().unwrap())))
}

/// Every item of the configured collection, in mint order.
fn items_json(app: &App) -> Vec<serde_json::Value> {
    let mut ids: Vec<(u64, String)> = app
        .index
        .mints
        .values()
        .filter(|m| m.collection == app.cfg.collection)
        .map(|m| (m.number, m.inscription.clone()))
        .collect();
    ids.sort();
    ids.iter()
        .filter_map(|(_, id)| item_json(app, id))
        .collect()
}

async fn api_item(State(s): State<Shared>, Path(id): Path<String>) -> Response {
    let app = s.lock().unwrap();
    match item_json(&app, id.trim_end_matches(".json")) {
        Some(v) => Json(v).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "unknown inscription"})),
        )
            .into_response(),
    }
}

async fn api_address_items(
    State(s): State<Shared>,
    Path(addr): Path<String>,
) -> Json<serde_json::Value> {
    let addr = addr.trim_end_matches(".json").to_string();
    let app = s.lock().unwrap();
    let mut ids: Vec<(u64, String)> = app
        .index
        .mints
        .values()
        .filter(|m| {
            m.collection == app.cfg.collection
                && app
                    .index
                    .inscriptions
                    .get(&m.inscription)
                    .and_then(|i| i.owner_address.as_deref())
                    == Some(addr.as_str())
        })
        .map(|m| (m.number, m.inscription.clone()))
        .collect();
    ids.sort();
    Json(json!(
        ids.iter()
            .filter_map(|(_, id)| item_json(&app, id))
            .collect::<Vec<_>>()
    ))
}

fn png_for_seed(seed_hex: &str, scale: usize) -> Result<Vec<u8>> {
    let seed: [u8; 32] = hex::decode(seed_hex)?
        .try_into()
        .map_err(|_| anyhow!("seed length"))?;
    let (g, _) = render(&seed);
    let (w, h) = (64 * scale, 64 * scale);
    let mut rgb = vec![0u8; w * h * 3];
    for y in 0..h {
        for x in 0..w {
            let (r, gg, b) = PALETTE[g[y / scale][x / scale] as usize];
            let o = (y * w + x) * 3;
            rgb[o] = r;
            rgb[o + 1] = gg;
            rgb[o + 2] = b;
        }
    }
    let mut buf = vec![];
    {
        let mut enc = png::Encoder::new(&mut buf, w as u32, h as u32);
        enc.set_color(png::ColorType::Rgb);
        enc.set_depth(png::BitDepth::Eight);
        let mut wr = enc.write_header()?;
        wr.write_image_data(&rgb)?;
    }
    Ok(buf)
}

async fn api_item_image(State(s): State<Shared>, Path(id): Path<String>) -> Response {
    let id = id.trim_end_matches(".png").to_string();
    let seed = {
        s.lock()
            .unwrap()
            .index
            .mints
            .get(&id)
            .map(|m| m.seed.clone())
    };
    let Some(seed) = seed else { return StatusCode::NOT_FOUND.into_response(); };
    limited_png(seed, true).await
}

async fn limited_png(seed: String, item: bool) -> Response {
    static QUEUE: std::sync::OnceLock<Arc<tokio::sync::Semaphore>> = std::sync::OnceLock::new();
    static RENDERS: std::sync::OnceLock<Arc<tokio::sync::Semaphore>> = std::sync::OnceLock::new();
    let queued = match QUEUE.get_or_init(||Arc::new(tokio::sync::Semaphore::new(16))).clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => return (StatusCode::TOO_MANY_REQUESTS, [(header::RETRY_AFTER, "1")]).into_response(),
    };
    let permit = RENDERS.get_or_init(||Arc::new(tokio::sync::Semaphore::new(2))).clone().acquire_owned().await.unwrap();    // Permit lives with the CPU work even if the requesting client disconnects.
    let rendered = tokio::task::spawn_blocking(move || {let _permit=permit; let _queued=queued; png_for_seed(&seed,4)}).await;
    match rendered.ok().and_then(Result::ok) {
        Some(png) => (
            [
                (header::CONTENT_TYPE, "image/png"),
                (header::CACHE_CONTROL, "no-store"),
            ],
            png,
        )
            .into_response(),
        None => (if item {StatusCode::NOT_FOUND} else {StatusCode::BAD_REQUEST}).into_response(),
    }
}

async fn api_seed_image(Path(seed): Path<String>) -> Response {
    limited_png(seed.trim_end_matches(".png").to_string(), false).await
}
/// One-time import of the pre-SQLite JSON files; the file is renamed afterwards.
fn migrate_legacy<T: Serialize + for<'de> Deserialize<'de>>(
    db: &Db,
    ns: &str,
    path: &str,
) -> Result<()> {
    if !std::path::Path::new(path).exists() {
        return Ok(());
    }
    let items: BTreeMap<String, T> = serde_json::from_str(&std::fs::read_to_string(path)?)?;
    for (k, v) in &items {
        db.kv_put(ns, k, v)?;
    }
    std::fs::rename(path, format!("{path}.migrated"))?;
    println!("migrated {} {ns} from {path}", items.len());
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let control_args: Vec<String> = std::env::args().skip(1).collect();
    if control_args.first().is_some_and(|arg| matches!(arg.as_str(), "invoices-status" | "invoices-pause" | "invoices-resume")) {
        return invoice_control::command(&control_args);
    }
    // OS lock is released even on a hard kill. Different ports must not create
    // two workers selecting/signing for the same order database.
    std::fs::create_dir_all("mintd")?;
    let process_lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open("mintd/worker.lock")?;
    process_lock
        .try_lock()
        .context("another mintd worker is active for this runtime")?;

    let args:Vec<String>=std::env::args().skip(1).collect();
    if !args.is_empty() {
        if args.len()==3 && args[0]=="manual-hold" {
            let report=proto::manual_cases::hold(DB_FILE,&proto::network::ChainConfig::load()?,&args[1],&args[2])?;
            println!("{}",serde_json::to_string_pretty(&report)?);return Ok(());
        }
        if args.len()==6 && args[0]=="manual-payment-register" {
            let report=proto::manual_cases::register(&Rpc::open()?,DB_FILE,&args[1],&args[2],&args[3],args[4].parse()?,&args[5])?;
            println!("{}",serde_json::to_string_pretty(&report)?);return Ok(());
        }
        if args.len()==2 && args[0]=="manual-report" {
            let report=proto::manual_cases::report(&Rpc::open()?,DB_FILE,&args[1])?;
            println!("{}",serde_json::to_string_pretty(&report)?);return Ok(());
        }
        if args.len()==4 && args[0]=="settlement-late-plan" {
            anyhow::ensure!(args[3]=="external-payments-reconciled","reconcile external/manual late refunds first");
            let report=proto::service_late::command(&Rpc::open()?,DB_FILE,&args[1],Some(&args[2]))?;
            println!("{}",serde_json::to_string_pretty(&report)?);return Ok(());
        }
        if args.len()==2 && args[0]=="settlement-late-resume" {
            let report=proto::service_late::command(&Rpc::open()?,DB_FILE,&args[1],None)?;
            println!("{}",serde_json::to_string_pretty(&report)?);return Ok(());
        }
        if args.len()==4 && args[0]=="settlement-recovery-plan" {
            let report=proto::service_recovery::command(&Rpc::open()?,DB_FILE,&args[1],Some((&args[2],&args[3])))?;
            println!("{}",serde_json::to_string_pretty(&report)?);return Ok(());
        }
        if args.len()==2 && args[0]=="settlement-recovery-resume" {
            let report=proto::service_recovery::command(&Rpc::open()?,DB_FILE,&args[1],None)?;
            println!("{}",serde_json::to_string_pretty(&report)?);return Ok(());
        }
        if args.len()==6 && args[0]=="settlement-plan" {
            let report=proto::service_payout::prepare(&Rpc::open()?,DB_FILE,&args[1],&args[2],&args[3],&args[4],&args[5])?;
            println!("{}",serde_json::to_string_pretty(&report)?);return Ok(());
        }
        if args.len()==2 && args[0]=="settlement-resume" {
            let report=proto::service_payout::resume(&Rpc::open()?,DB_FILE,&args[1])?;
            println!("{}",serde_json::to_string_pretty(&report)?);return Ok(());
        }
        if args.len()==2 && args[0]=="settlement-hold" {
            let report=proto::service_settlement::hold(&Rpc::open()?,DB_FILE,&args[1])?;
            println!("{}",serde_json::to_string_pretty(&report)?);return Ok(());
        }
        anyhow::ensure!(args.len()==2 && args[0]=="watch-late-payment","usage: mintd [manual-hold <id> <reason> | manual-payment-register <id> <txid:vout> <address> <zat> <evidence-file> | manual-report <id> | watch-late-payment <id> | settlement-hold <id> | settlement-plan <id> <reserve-key> <txid:n> <normal|project-fault> <reason> | settlement-resume <id> | settlement-recovery-plan <id> <invoice-key> <service-key> | settlement-recovery-resume <id> | settlement-late-plan <id> <invoice-key> external-payments-reconciled | settlement-late-resume <id>]");
        return cmd_watch_late_payment(&args[1]);
    }
    let cfg: Config =
        serde_json::from_str(&std::fs::read_to_string("mintd.json").context("mintd.json")?)?;
    let net = Net::parse(&cfg.network)?;
    let rpc = Rpc::open()?;
    anyhow::ensure!(rpc.net() == net, "mintd network differs from chain.json");
    proto::parse_taddr_for(&cfg.fee_address, net.network_type())?;
    let db = Db::open(DB_FILE)?;
    let index = db.load()?;
    migrate_legacy::<Order>(&db, NS_ORDERS, "mintd/orders.json")?;
    migrate_legacy::<Listing>(&db, NS_LISTINGS, "mintd/listings.json")?;
    let orders: BTreeMap<String, Order> = db.kv_all(NS_ORDERS)?;
    let listings: BTreeMap<String, Listing> = db.kv_all(NS_LISTINGS)?;
    println!(
        "loaded {} inscriptions, {} orders, {} listings; indexed to {}",
        index.inscriptions.len(),
        orders.len(),
        listings.len(),
        index.height
    );
    let invoice_policy=invoice_gate::Policy::from_env(net==Net::Regtest)?;
    let bind = cfg.bind.clone();
    let web_dir = cfg.web_dir.clone();
    let shared: Shared = Arc::new(Mutex::new(App {
        cfg,
        index,
        db,
        net,
        genesis_hash: rpc.chain.genesis_hash.clone(),
        orders,
        tip: 0,
        healthy: false,
        export_dirty: false,
        listings,
        prepared: BTreeMap::new(),
    }));
    {
        let w = shared.clone();
        std::thread::spawn(move || worker(w));
    }
    let app = Router::new()
        .route("/api/collection", get(api_collection))
        .route("/api/collection.json", get(api_collection))
        .route("/api/items.json", get(api_items))
        .route("/api/listings.json", get(api_listings))
        .route("/api/stats.json", get(api_stats))
        .route("/api/address/{addr}", get(api_address_items))
        .route("/api/orders", post(api_new_order))
        .route("/api/orders/{id}", get(api_order))
        .route("/api/purchases", post(api_new_purchase))
        .route("/api/purchases/prepare", post(api_prepare_purchase))
        .route("/api/transactions", post(api_broadcast))
        .route("/api/listings", get(api_listings))
        .route("/api/listings/prepare", post(api_prepare_listing))
        .route("/api/listings/{id}/sign", post(api_sign_listing))
        .route("/api/items", get(api_items))
        .route("/api/items/{id}", get(api_item))
        .route("/api/items/{id}/image.png", get(api_item_image))
        .route("/api/items/{id}/content", get(api_item_content))
        .route("/api/stats", get(api_stats))
        .route("/api/search", get(api_search))
        .route("/api/address/{addr}/items", get(api_address_items))
        .route("/api/seed/{seed}", get(api_seed_image))
        .fallback_service(ServeDir::new(web_dir))
        .layer(axum::middleware::from_fn(admission::middleware))
        .layer(axum::middleware::from_fn_with_state(invoice_policy,invoice_gate::middleware))
        .layer(CorsLayer::permissive())
        .layer(axum::middleware::from_fn(security::middleware))
        .with_state(shared);
    println!("mintd listening on http://{bind}");
    let listener = tokio::net::TcpListener::bind(&bind).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

#[cfg(test)]
mod accounting_tests;

mod reorg_orders;
mod payment_watch;

mod admission;





mod security;

mod invoice_gate;
mod invoice_control;
