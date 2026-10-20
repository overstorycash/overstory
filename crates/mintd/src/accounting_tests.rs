use super::*;
// These API fixtures share the process runtime directory and its admission lock.
static INVOICE_RUNTIME_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
fn fixture() -> Order {
    serde_json::from_value(json!({"id":"fixture","dest":"destination","invoice_address":"invoice","amount_zat":45546,
        "created":1,"expires":2,"status":"expired","paid_zat":0,"inscription_id":null,"txids":[],"number":null,"seed":null,"error":null,
        "mint_journal_version":1,"accounting_version":1})).unwrap()
}
fn coin(n: u32, value: u64) -> Utxo {
    Utxo {
        txid: "11".repeat(32),
        n,
        script: "76".into(),
        value,
        height: 1,
    }
}
fn record(u: Utxo) -> RefundRecord {
    RefundRecord {
        plan: proto::refund::RefundPlan {
            version: 1,
            network: "regtest".into(),
            genesis_hash: "11".repeat(32),
            target_height: 2,
            expiry_height: 41,
            destination: "destination".into(),
            input_zat: u.value,
            refund_zat: u.value - 10000,
            fee_zat: 10000,
            funding: vec![u],
            txid: "22".repeat(32),
            raw_transaction: "sensitive-signed-bytes".into(),
        },
        confirmation: None,
    }
}
#[test]
fn receipt_replay_is_idempotent_and_changed_amount_rejected() {
    let mut o = fixture();
    observe(&mut o, &[coin(0, 30000)]).unwrap();
    observe(&mut o, &[coin(0, 30000)]).unwrap();
    assert_eq!(o.paid_zat, 30000);
    assert_eq!(o.receipts.len(), 1);
    assert!(observe(&mut o, &[coin(0, 30001)]).is_err());
}
#[test]
fn ledger_preserves_reservations_confirmations_fees_and_late_payments() {
    let mut o = fixture();
    observe(&mut o, &[coin(0, 30000), coin(1, 5000)]).unwrap();
    o.refunds.push(record(coin(0, 30000)));
    let v = ledger(&o).unwrap();
    assert_eq!(v["refund_pending_input_zat"], 30000);
    assert_eq!(v["refund_confirmed_zat"], 0);
    assert_eq!(v["unallocated_received_zat"], 5000);
    o.refunds[0].confirmation = Some(proto::refund::RefundConfirmation {
        height: 3,
        block_hash: "33".repeat(32),
    });
    observe(&mut o, &[coin(2, 20000)]).unwrap();
    let v = ledger(&o).unwrap();
    assert_eq!(v["observed_received_zat"], 55000);
    assert_eq!(v["refund_confirmed_zat"], 20000);
    assert_eq!(v["refund_network_fee_zat"], 10000);
    assert_eq!(v["unallocated_received_zat"], 25000);
    let public = public_order(&o).to_string();
    assert!(!public.contains("sensitive-signed-bytes"));
    assert!(!public.contains("receipts"));
    assert!(!public.contains("mint_plan"));
}
#[test]
fn duplicate_allocation_unknown_receipt_and_legacy_ledger_are_rejected() {
    let mut o = fixture();
    o.refunds.push(record(coin(0, 30000)));
    assert!(ledger(&o).is_err());
    observe(&mut o, &[coin(0, 30000)]).unwrap();
    assert!(ledger(&o).is_ok());
    let mut bad = o.clone();
    bad.refunds[0].plan.input_zat += 1;
    assert!(ledger(&bad).is_err());
    let mut bad = o.clone();
    bad.receipts.insert("wrong-key".into(), coin(1, 1));
    assert!(ledger(&bad).is_err());
    o.refunds.push(record(coin(0, 30000)));
    assert!(ledger(&o).is_err());
    o.refunds.clear();
    o.accounting_version = 0;
    assert!(ledger(&o).is_err());
}

#[test]
fn only_consecutive_failures_exhaust_retries_and_signed_refunds_remain_recoverable() {
    let mut o = fixture();
    o.status = "awaiting_payment".into();
    for _ in 0..12 {
        record_outcome(&mut o, Err(anyhow!("temporary RPC failure")));
        assert_eq!(o.attempts, 1);
        assert_eq!(o.status, "awaiting_payment");
        record_outcome(&mut o, Ok(()));
        assert_eq!(o.attempts, 0);
        assert_eq!(o.retry_after, 0);
    }
    for _ in 0..8 {
        record_outcome(&mut o, Err(anyhow!("persistent RPC failure")));
    }
    assert_eq!(o.status, "error");
    o.status = "refunding".into();
    o.refunds.push(record(coin(0, 30000)));
    for _ in 0..12 {
        record_outcome(&mut o, Err(anyhow!("refund lookup unavailable")));
    }
    assert_eq!(o.status, "refunding");
    record_outcome(
        &mut o,
        Err(RecoveryRequired("expired refund".into()).into()),
    );
    assert_eq!(o.status, "recovery_required");
}

#[test]
fn snapshot_image_refreshes_after_seed_change_restart_and_missing_file() {
    let root = std::env::temp_dir().join(format!(
        "overstory-image-test-{}",
        Key::random().secret_hex()
    ));
    let rel = "api/items/example/image.png";
    let mut ex = Exporter::default();
    let a = "11".repeat(32);
    let b = "22".repeat(32);
    assert!(write_snapshot_image(&root, rel, &a, &mut ex).unwrap());
    assert!(!write_snapshot_image(&root, rel, &a, &mut ex).unwrap());
    let first = std::fs::read(root.join(rel)).unwrap();
    assert!(write_snapshot_image(&root, rel, &b, &mut ex).unwrap());
    assert_ne!(std::fs::read(root.join(rel)).unwrap(), first);
    let mut restarted = Exporter::default();
    assert!(write_snapshot_image(&root, rel, &a, &mut restarted).unwrap());
    assert_eq!(std::fs::read(root.join(rel)).unwrap(), first);
    std::fs::remove_file(root.join(rel)).unwrap();
    assert!(write_snapshot_image(&root, rel, &a, &mut restarted).unwrap());
}

#[test]
fn snapshot_tracks_same_height_forks_and_retries_failed_dirty_export() {
    let root = std::env::temp_dir().join(format!(
        "overstory-export-test-{}",
        Key::random().secret_hex()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let output = root.join("public");
    let cfg:Config=serde_json::from_value(json!({"bind":"127.0.0.1:0","collection":"fixture","network":"regtest","service_fee_zat":0,"fee_address":"unused","web_dir":"unused","order_ttl_secs":60,"export_dir":output.to_str().unwrap()})).unwrap();
    let shared = Arc::new(Mutex::new(App {
        cfg,
        index: Index {
            height: 10,
            tip_hash: Some("11".repeat(32)),
            ..Default::default()
        },
        db: Db::open(root.join("test.sqlite").to_str().unwrap()).unwrap(),
        net: Net::Regtest,
        genesis_hash: "22".repeat(32),
        orders: BTreeMap::new(),
        tip: 10,
        healthy: true,
        export_dirty: false,
        listings: BTreeMap::new(),
        prepared: BTreeMap::new(),
    }));
    let mut ex = Exporter::default();
    export_snapshot(&shared, &mut ex).unwrap();
    shared.lock().unwrap().index.tip_hash = Some("33".repeat(32));
    export_snapshot(&shared, &mut ex).unwrap();
    assert_eq!(ex.last_tip_hash, Some("33".repeat(32)));
    let blocked = root.join("blocked");
    std::fs::write(&blocked, b"not a directory").unwrap();
    {
        let mut a = shared.lock().unwrap();
        a.cfg.export_dir = Some(blocked.to_str().unwrap().into());
        a.export_dirty = true;
    }
    assert!(export_snapshot(&shared, &mut ex).is_err());
    assert_ne!(ex.last_height, 10);
    std::fs::remove_file(&blocked).unwrap();
    export_snapshot(&shared, &mut ex).unwrap();
    assert_eq!(ex.last_height, 10);
    assert!(blocked.join("api/items.json").exists());
    assert!(
        blocked
            .join("api/seed/0000000000000000000000000000000000000000000000000000000000000001.png")
            .exists()
    );
}

fn quote_app() -> App {
    let root=std::env::temp_dir().join(format!("overstory-quote-{}",Key::random().secret_hex()));
    std::fs::create_dir_all(&root).unwrap();
    let addr=Key::from_secret(&[7;32]).unwrap().address_string(Net::Regtest);
    let id=format!("{}i0","11".repeat(32));
    let cfg:Config=serde_json::from_value(json!({"bind":"127.0.0.1:0","collection":id,"network":"regtest","service_fee_zat":0,"mint_total_zat":10000000,"fee_address":addr,"web_dir":"unused","order_ttl_secs":60})).unwrap();
    let mut index=Index::default();
    index.collections.insert(id.clone(),serde_json::from_value(json!({"id":id,"name":"fixture","supply":3000,"max_per_addr":0,"price":5000000,"pay":addr,"start":1,"renderer":"","deployed_height":0,"minted":0})).unwrap());
    App {cfg,index,db:Db::open(root.join("db.sqlite").to_str().unwrap()).unwrap(),net:Net::Regtest,genesis_hash:"22".repeat(32),orders:BTreeMap::new(),tip:1,healthy:true,export_dirty:false,listings:BTreeMap::new(),prepared:BTreeMap::new()}
}
#[test]
fn frozen_quote_survives_restart_and_configuration_changes() {
    let mut app=quote_app();let q=mint_quote(&app).unwrap();assert_eq!(q.total_zat,10000000);
    let mut order=fixture();order.amount_zat=q.total_zat;order.quote=Some(q);
    save_order(&app.db,&order).unwrap();
    let loaded:Order=app.db.kv_all::<Order>(NS_ORDERS).unwrap().remove(&order.id).unwrap();
    app.cfg.mint_total_zat=Some(20000000);app.cfg.service_fee_zat=90000;app.cfg.fee_address="invalid-new-config".into();app.cfg.collection="different".into();
    let saved=checked_order_quote(&app,&loaded).unwrap();assert_eq!(saved.total_zat,10000000);assert_eq!(saved.service_fee_zat,0);
    assert_ne!(saved.fee_address,app.cfg.fee_address);
    let mut wrong=loaded.clone();wrong.amount_zat+=1;assert!(checked_order_quote(&app,&wrong).is_err());
    app.genesis_hash="33".repeat(32);assert!(checked_order_quote(&app,&loaded).is_err());
}
#[test]
fn ambiguous_underfunded_and_legacy_quotes_fail_closed() {
    let mut app=quote_app();assert!(checked_order_quote(&app,&fixture()).is_err());
    app.cfg.service_fee_zat=1;assert!(mint_quote(&app).is_err());
    app.cfg.service_fee_zat=0;app.cfg.mint_total_zat=Some(5000000);assert!(mint_quote(&app).is_err());
    app.cfg.mint_total_zat=Some(u64::MAX);assert!(mint_quote(&app).is_err());
    app.cfg.mint_total_zat=None;app.cfg.service_fee_zat=u64::MAX;assert!(mint_quote(&app).is_err());
}

#[test]
fn refund_address_requires_explicit_confirmation_and_correct_network() {
    let dest=Key::from_secret(&[10;32]).unwrap().address_string(Net::Regtest);
    let refund=Key::from_secret(&[11;32]).unwrap().address_string(Net::Regtest);
    let mut req=NewOrder {dest:dest.clone(),refund_address:refund.clone(),refund_confirmed:false,intent:None};
    assert!(validate_order_addresses(&req,Net::Regtest).is_err());
    req.refund_confirmed=true;
    assert_eq!(validate_order_addresses(&req,Net::Regtest).unwrap(),(dest,refund.clone()));
    req.refund_address=Key::from_secret(&[11;32]).unwrap().address_string(Net::Mainnet);
    assert!(validate_order_addresses(&req,Net::Regtest).is_err());
    req.refund_address=String::new();assert!(validate_order_addresses(&req,Net::Regtest).is_err());
    let mut old=fixture();assert!(refund_destination(&old).is_err());
    old.refund_address=Some(refund.clone());assert_eq!(refund_destination(&old).unwrap(),refund);
}

#[test]
fn legacy_unsigned_invoices_stop_before_accepting_more_payment() {
    let app=quote_app();let mut o=fixture();o.status="awaiting_payment".into();
    assert!(require_unsigned_order_terms(&o).unwrap_err().downcast_ref::<RecoveryRequired>().is_some());
    o.quote=Some(mint_quote(&app).unwrap());assert!(require_unsigned_order_terms(&o).is_err());
    o.refund_address=Some(Key::from_secret(&[12;32]).unwrap().address_string(Net::Regtest));
    assert!(require_unsigned_order_terms(&o).is_ok());
}


#[tokio::test]
async fn order_api_refuses_before_start_without_creating_an_invoice() {
    let mut app=quote_app();app.tip=98;
    app.index.collections.get_mut(&app.cfg.collection).unwrap().start=100;
    let shared=Arc::new(Mutex::new(app));
    let addr=Key::from_secret(&[12;32]).unwrap().address_string(Net::Regtest);
    let req=||NewOrder {dest:addr.clone(),refund_address:addr.clone(),refund_confirmed:true,intent:None};
    let response=api_new_order(State(shared.clone()),Json(req())).await;
    assert_eq!(response.status(),StatusCode::CONFLICT);
    assert!(shared.lock().unwrap().orders.is_empty());
    shared.lock().unwrap().tip=u32::MAX;
    let response=api_new_order(State(shared.clone()),Json(req())).await;
    assert_eq!(response.status(),StatusCode::CONFLICT);
    assert!(shared.lock().unwrap().orders.is_empty());
    assert!(next_block_can_mint(99,100));
}

#[tokio::test]
async fn raw_inscription_download_cannot_execute_as_same_origin_html() {
    let mut app=quote_app();
    let body=b"<script>localStorage.clear()</script>";
    let id=format!("{}i0","55".repeat(32));
    app.index.inscriptions.insert(id.clone(),proto::index::Inscription { authenticated: false,
        id:id.clone(),family:"v1".into(),content_type:"text/html".into(),content_len:body.len(),
        content_sha256:"unused".into(),content_hex:hex::encode(body),genesis_height:1,
        genesis_block_hash:"11".repeat(32),completion_height:1,completion_block_hash:"11".repeat(32),
        owner:"burned".into(),owner_address:None,history:vec![],
    });
    let response=api_item_content(State(Arc::new(Mutex::new(app))),Path(id)).await;
    assert_eq!(response.status(),StatusCode::OK);
    assert_eq!(response.headers()[header::CONTENT_TYPE],"application/octet-stream");
    assert_eq!(response.headers()[header::CONTENT_DISPOSITION],"attachment; filename=inscription.bin");
    assert_eq!(response.headers()[header::X_CONTENT_TYPE_OPTIONS],"nosniff");
    assert_eq!(response.headers()[header::CONTENT_SECURITY_POLICY],"default-src 'none'; sandbox");
    assert_eq!(axum::body::to_bytes(response.into_body(),1024).await.unwrap().as_ref(),body);
}

#[tokio::test]
async fn order_api_hides_stale_confirmation_status_while_chain_is_quarantined() {
    let mut app=quote_app();let mut o=fixture();o.status="refunded".into();let id=o.id.clone();
    app.orders.insert(id.clone(),o);app.healthy=false;let shared=Arc::new(Mutex::new(app));
    let response=api_order(State(shared.clone()),Path(id.clone())).await;
    let body=axum::body::to_bytes(response.into_body(),65536).await.unwrap();let v:serde_json::Value=serde_json::from_slice(&body).unwrap();
    assert_eq!(v["status"],"chain_check_pending");assert_eq!(v["saved_status"],"refunded");assert_eq!(shared.lock().unwrap().orders[&id].status,"refunded");
    shared.lock().unwrap().healthy=true;
    let response=api_order(State(shared),Path(id)).await;
    let body=axum::body::to_bytes(response.into_body(),65536).await.unwrap();let v:serde_json::Value=serde_json::from_slice(&body).unwrap();assert_eq!(v["status"],"refunded");
}

#[tokio::test]
async fn public_broadcast_is_disabled_before_any_rpc_while_chain_is_quarantined() {
    let mut app=quote_app();app.healthy=false;
    let response=api_broadcast(State(Arc::new(Mutex::new(app))),Json(Broadcast {raw_transaction:"not-even-parsed".into()})).await;
    assert_eq!(response.status(),StatusCode::SERVICE_UNAVAILABLE);
}
#[tokio::test]
async fn public_broadcast_rejects_mint_before_opening_rpc() {
 let mut app=quote_app();app.healthy=true;app.cfg.market_open=Some(true);app.tip=107;app.index.height=107;
 app.index.collections.get_mut(&app.cfg.collection).unwrap().minted=3000;
 let fixture:serde_json::Value=serde_json::from_str(include_str!("../../proto/tests/market-relay.json")).unwrap();
 let response=api_broadcast(State(Arc::new(Mutex::new(app))),Json(Broadcast {raw_transaction:fixture["mint_raws"][0].as_str().unwrap().into()})).await;
 assert_eq!(response.status(),StatusCode::BAD_REQUEST);
 let bytes=axum::body::to_bytes(response.into_body(),10000).await.unwrap();let v:serde_json::Value=serde_json::from_slice(&bytes).unwrap();assert!(v["error"].as_str().unwrap().contains("market purchases only"));
}
#[tokio::test]
async fn public_rpc_admission_survives_cancel_and_releases_when_work_finishes() {
 let first=chain_api_permit().ok().unwrap();let second=chain_api_permit().ok().unwrap();
 let (started_tx,started_rx)=tokio::sync::oneshot::channel();
 let (release_tx,release_rx)=std::sync::mpsc::channel();
 let (finished_tx,finished_rx)=tokio::sync::oneshot::channel();
 let request=tokio::spawn(async move {
  tokio::task::spawn_blocking(move || {
   let permit=first;let _=started_tx.send(());let _=release_rx.recv();drop(permit);let _=finished_tx.send(());
  }).await.unwrap();
 });
 started_rx.await.unwrap();request.abort();let _=request.await;
 assert_eq!(chain_api_permit().err().unwrap().status(),StatusCode::TOO_MANY_REQUESTS);
 release_tx.send(()).unwrap();finished_rx.await.unwrap();
 let replacement=chain_api_permit().ok().unwrap();drop(replacement);drop(second);
 assert!(chain_api_permit().is_ok());
}

#[test]
fn retry_requires_positive_chain_or_mempool_evidence() {
 let id="ab".repeat(32);
 assert!(validate_known_transaction_status(&json!({"confirmations":1}),&id,||panic!("confirmed needs no mempool call")).is_ok());
 assert!(validate_known_transaction_status(&json!({"confirmations":-1}),&id,||panic!("orphan cannot be rescued by mempool")).is_err());
 for v in [json!({}),json!({"confirmations":0}),json!({"confirmations":null})] {
  assert!(validate_known_transaction_status(&v,&id,||Ok(json!([id]))).is_ok());
  assert!(validate_known_transaction_status(&v,&id,||Ok(json!([]))).is_err());
  assert!(validate_known_transaction_status(&v,&id,||Ok(json!({id.clone():{}}))).is_err());
  assert!(validate_known_transaction_status(&v,&id,||anyhow::bail!("RPC unavailable")).is_err());
 }
}

#[test]
fn pending_surplus_refund_outlives_discovery_window_without_unpausing_manual_holds() {
    let mut o=fixture();o.status="done".into();let after=o.expires+8*86400;
    assert!(!order_due(&o,after));
    o.refunds.push(record(coin(0,30000)));
    assert!(order_due(&o,after));
    o.retry_after=after+1;assert!(!order_due(&o,after));o.retry_after=0;
    for status in ["recovery_required","error"] {o.status=status.into();assert!(!order_due(&o,after));}
    o.status="done".into();o.refunds[0].confirmation=Some(proto::refund::RefundConfirmation {height:1,block_hash:"11".repeat(32)});
    assert!(!order_due(&o,after));assert!(order_due(&o,o.expires+1));
}

#[test]
fn local_late_payment_review_changes_only_observation_window() {
    let mut o=fixture();o.quote=Some(mint_quote(&quote_app()).unwrap());o.refund_address=Some("confirmed".into());
    let before=serde_json::to_value(&o).unwrap();let time=o.expires+8*86400;
    reopen_payment_watch(&mut o,time).unwrap();assert!(order_due(&o,time));
    let mut after=serde_json::to_value(&o).unwrap();after["payment_review_until"]=before["payment_review_until"].clone();
    assert_eq!(before,after);
    for status in ["recovery_required","error","paid","inscribing","awaiting_payment"] {
        o.status=status.into();assert!(reopen_payment_watch(&mut o,time).is_err());
    }
}

#[test]
fn settlement_hold_blocks_worker_and_review_even_if_status_changes() {
    let mut o=fixture();o.settlement_hold=true;
    for status in ["awaiting_payment","paid","inscribing","refunding","done","expired","refunded","refund_pending_small"] {
        o.status=status.into();
        assert!(!order_due(&o,0));assert!(ensure_not_settling(&o).is_err());
        assert!(reopen_payment_watch(&mut o,0).is_err());
    }
    let v=public_order(&o);assert_eq!(v["settlement_hold"],true);assert_eq!(v["status"],"recovery_required");
    assert!(v.get("mint_plan").is_none());
}

#[test]
fn market_requires_sellout_verified_index_and_explicit_release() {
 let mut app=quote_app();app.index.height=app.tip;
 for permission in [None,Some(false),Some(true)] {
  app.cfg.market_open=permission;assert!(!market_is_open(&app));
 }
 app.index.collections.get_mut(&app.cfg.collection).unwrap().minted=3000;
 app.cfg.market_open=None;assert!(!market_is_open(&app));
 app.cfg.market_open=Some(false);assert!(!market_is_open(&app));
 app.cfg.market_open=Some(true);assert!(market_is_open(&app));
 app.healthy=false;assert!(!market_is_open(&app));
 app.healthy=true;app.index.height=app.tip+1;assert!(!market_is_open(&app));
 app.index.height=app.tip;app.index.collections.get_mut(&app.cfg.collection).unwrap().minted=2999;
 assert!(!market_is_open(&app));assert_eq!(listings_json(&app),json!([]));
 app.index.collections.clear();assert!(!market_is_open(&app));
}
#[tokio::test]
async fn closed_market_rejects_stale_listing_signature_without_rpc() {
 let mut app=quote_app();app.cfg.market_open=Some(true);
 let r=api_sign_listing(State(Arc::new(Mutex::new(app))),Path("old-prepare".into()),Json(SignListing {signature_der:"00".into()})).await;
 assert_eq!(r.status(),StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn capacity_blocks_only_new_invoices_and_keeps_old_records() {
    let mut app=quote_app();app.cfg.max_saved_orders=1;
    let order=fixture();save_order(&app.db,&order).unwrap();app.orders.insert(order.id.clone(),order);
    let shared=Arc::new(Mutex::new(app));
    let addr=Key::from_secret(&[12;32]).unwrap().address_string(Net::Regtest);
    let response=api_new_order(State(shared.clone()),Json(NewOrder {dest:addr.clone(),refund_address:addr,refund_confirmed:true,intent:None})).await;
    assert_eq!(response.status(),StatusCode::SERVICE_UNAVAILABLE);
    let app=shared.lock().unwrap();assert_eq!(app.orders.len(),1);
    assert_eq!(app.db.kv_all::<Order>(NS_ORDERS).unwrap().len(),1);
    assert_eq!(app.orders["fixture"].status,"expired");
}


#[tokio::test]
async fn intent_retries_survive_lost_response_reload_and_concurrency() {
    let _runtime = INVOICE_RUNTIME_TEST_LOCK.lock().unwrap();
    let shared=Arc::new(Mutex::new(quote_app()));
    let addr=Key::from_secret(&[12;32]).unwrap().address_string(Net::Regtest);
    let intent=InvoiceIntent { request_id:"ab".repeat(32),quote:mint_quote(&shared.lock().unwrap()).unwrap() };
    let req=||NewOrder {dest:addr.clone(),refund_address:addr.clone(),refund_confirmed:true,intent:Some(intent.clone())};
    // Both submissions reach the same durable invoice even if the first response is lost.
    let barrier=Arc::new(std::sync::Barrier::new(2));
    let tasks:Vec<_>=(0..2).map(|_| {
        let state=shared.clone();let request=req();let barrier=barrier.clone();
        std::thread::spawn(move || {barrier.wait();tokio::runtime::Runtime::new().unwrap().block_on(api_new_order(State(state),Json(request)))})
    }).collect();
    let mut replies=tasks.into_iter().map(|t|t.join().unwrap());
    let a=replies.next().unwrap();let b=replies.next().unwrap();
    assert_eq!(a.status(),StatusCode::OK);assert_eq!(b.status(),StatusCode::OK);
    let first:serde_json::Value=serde_json::from_slice(&axum::body::to_bytes(a.into_body(),1024*1024).await.unwrap()).unwrap();
    let second:serde_json::Value=serde_json::from_slice(&axum::body::to_bytes(b.into_body(),1024*1024).await.unwrap()).unwrap();
    assert_eq!(first["id"],second["id"]);assert!(first.get("invoice_intent").is_none());
    {
        let mut app=shared.lock().unwrap();
        assert_eq!(app.orders.len(),1);assert_eq!(app.db.kv_all::<Order>(NS_ORDERS).unwrap().len(),1);
        app.orders=app.db.kv_all(NS_ORDERS).unwrap();
        app.cfg.max_saved_orders=0;app.healthy=false;
    }
    let reply=api_new_order(State(shared.clone()),Json(req())).await;
    assert_eq!(reply.status(),StatusCode::OK);
    let replay:serde_json::Value=serde_json::from_slice(&axum::body::to_bytes(reply.into_body(),1024*1024).await.unwrap()).unwrap();
    assert_eq!(replay["id"],first["id"]);assert_eq!(replay["status"],"chain_check_pending");
    let mut changed=req();changed.refund_address=Key::from_secret(&[13;32]).unwrap().address_string(Net::Regtest);
    assert_eq!(api_new_order(State(shared.clone()),Json(changed)).await.status(),StatusCode::CONFLICT);
    let mut changed=req();changed.intent.as_mut().unwrap().quote.total_zat+=1;
    assert_eq!(api_new_order(State(shared.clone()),Json(changed)).await.status(),StatusCode::CONFLICT);
    assert_eq!(shared.lock().unwrap().orders.len(),1);
}
#[test]
fn intent_ambiguous_storage_and_duplicate_records_fail_closed() {
    let mut app=quote_app();let mut o=fixture();let q=mint_quote(&app).unwrap();
    let intent=InvoiceIntent {request_id:"cd".repeat(32),quote:q.clone()};
    o.id="1111111111111111".into();o.dest="dest".into();o.refund_address=Some("refund".into());o.amount_zat=q.total_zat;o.quote=Some(q);o.invoice_intent=Some(intent.clone());
    save_order(&app.db,&o).unwrap();
    assert!(prior_intent(&app,&intent,"dest","refund").is_err());
    app.orders.insert(o.id.clone(),o.clone());assert!(prior_intent(&app,&intent,"dest","refund").unwrap().is_some());
    let mut changed=intent.clone();changed.quote.genesis_hash="33".repeat(32);assert!(prior_intent(&app,&changed,"dest","refund").is_err());
    o.id="2222222222222222".into();save_order(&app.db,&o).unwrap();
    assert!(prior_intent(&app,&intent,"dest","refund").is_err());
    let mut bad=intent;bad.request_id="AB".repeat(32);assert!(!bad.valid_id());
}

#[tokio::test]
async fn intent_sqlite_abort_does_not_publish_or_duplicate_an_invoice() {
    let _runtime = INVOICE_RUNTIME_TEST_LOCK.lock().unwrap();
    let shared=Arc::new(Mutex::new(quote_app()));
    let addr=Key::from_secret(&[12;32]).unwrap().address_string(Net::Regtest);
    let intent=InvoiceIntent {request_id:"ef".repeat(32),quote:mint_quote(&shared.lock().unwrap()).unwrap()};
    let req=||NewOrder {dest:addr.clone(),refund_address:addr.clone(),refund_confirmed:true,intent:Some(intent.clone())};
    shared.lock().unwrap().db.conn.execute_batch("CREATE TRIGGER fail_invoice AFTER INSERT ON kv WHEN NEW.ns='orders' BEGIN SELECT RAISE(ABORT,'injected'); END;").unwrap();
    assert_eq!(api_new_order(State(shared.clone()),Json(req())).await.status(),StatusCode::INTERNAL_SERVER_ERROR);
    {
        let app=shared.lock().unwrap();assert!(app.orders.is_empty());assert!(app.db.kv_all::<Order>(NS_ORDERS).unwrap().is_empty());
        app.db.conn.execute_batch("DROP TRIGGER fail_invoice;").unwrap();
    }
    assert_eq!(api_new_order(State(shared.clone()),Json(req())).await.status(),StatusCode::OK);
    assert_eq!(api_new_order(State(shared.clone()),Json(req())).await.status(),StatusCode::OK);
    assert_eq!(shared.lock().unwrap().db.kv_all::<Order>(NS_ORDERS).unwrap().len(),1);
}

#[test]
fn legacy_orders_do_not_gain_a_null_protected_intent_field() {
    let order=fixture();assert!(order.invoice_intent.is_none());
    assert!(serde_json::to_value(order).unwrap().get("invoice_intent").is_none());
}

#[tokio::test]
async fn operator_pause_blocks_new_intents_but_preserves_existing_retry_and_worker() {
    let _runtime = INVOICE_RUNTIME_TEST_LOCK.lock().unwrap();
    let shared=Arc::new(Mutex::new(quote_app()));
    let addr=Key::from_secret(&[12;32]).unwrap().address_string(Net::Regtest);
    let intent=InvoiceIntent {request_id:"92".repeat(32),quote:mint_quote(&shared.lock().unwrap()).unwrap()};
    let req=||NewOrder {dest:addr.clone(),refund_address:addr.clone(),refund_confirmed:true,intent:Some(intent.clone())};
    assert_eq!(api_new_order(State(shared.clone()),Json(req())).await.status(),StatusCode::OK);
    {
        let app=shared.lock().unwrap();invoice_control::set(&app.db,true,"operator incident").unwrap();
        let order=app.orders.values().next().unwrap();assert!(!order.settlement_hold);
    }
    assert_eq!(api_new_order(State(shared.clone()),Json(req())).await.status(),StatusCode::OK);
    let mut fresh=req();fresh.intent.as_mut().unwrap().request_id="93".repeat(32);
    assert_eq!(api_new_order(State(shared.clone()),Json(fresh)).await.status(),StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(shared.lock().unwrap().orders.len(),1);
    invoice_control::set(&shared.lock().unwrap().db,false,"resolved").unwrap();
    let mut fresh=req();fresh.intent.as_mut().unwrap().request_id="93".repeat(32);
    assert_eq!(api_new_order(State(shared.clone()),Json(fresh)).await.status(),StatusCode::OK);
    assert_eq!(shared.lock().unwrap().orders.len(),2);
}

#[tokio::test]
async fn unbacked_mainnet_invoice_query_never_exposes_payment_address() {
    let mut app=quote_app();app.net=Net::Mainnet;
    let mut o=fixture();o.id="0123456789abcdef".into();
    app.orders.insert(o.id.clone(),o.clone());
    assert!(!order_backup::ready(&app,&o));
    let response=api_order(State(Arc::new(Mutex::new(app))),Path(o.id)).await;
    assert_eq!(response.status(),StatusCode::SERVICE_UNAVAILABLE);
    let bytes=axum::body::to_bytes(response.into_body(),4096).await.unwrap();
    let value:serde_json::Value=serde_json::from_slice(&bytes).unwrap();
    assert!(value.get("invoice_address").is_none());
    assert!(value.get("amount_zat").is_none());
}

#[test]
fn backup_receipt_binds_immutable_order_terms_not_mutable_progress() {
    let mut app=quote_app();app.net=Net::Mainnet;
    let mut o=fixture();o.id="0123456789abcdef".into();
    let receipt=json!({"stored":true,"terms":order_backup::terms(&app,&o),"cipher_sha256":"a".repeat(64)});
    app.db.kv_put("invoice_backup_v1",&o.id,&receipt).unwrap();
    assert!(order_backup::ready(&app,&o));
    o.status="done".into();o.attempts=3;
    assert!(order_backup::ready(&app,&o));
    o.refund_address=Some("changed".into());
    assert!(!order_backup::ready(&app,&o));
    o.refund_address=None;o.amount_zat+=1;
    assert!(!order_backup::ready(&app,&o));
}

#[test]
fn backup_receipt_rejects_corruption_and_wrong_network() {
    let mut app=quote_app();app.net=Net::Mainnet;
    let mut o=fixture();o.id="0123456789abcdef".into();
    let mut receipt=json!({"stored":true,"terms":order_backup::terms(&app,&o),"cipher_sha256":"a".repeat(64)});
    receipt["terms"]["network"]=json!("regtest");
    app.db.kv_put("invoice_backup_v1",&o.id,&receipt).unwrap();
    assert!(!order_backup::ready(&app,&o));
    receipt["terms"]=order_backup::terms(&app,&o);receipt["cipher_sha256"]=json!("invalid");
    app.db.kv_put("invoice_backup_v1",&o.id,&receipt).unwrap();
    assert!(!order_backup::ready(&app,&o));
}
#[cfg(unix)]
// Explicit integration only: uses the installed private helper and no blockchain RPC.
#[tokio::test]
#[ignore = "requires the operator-approved private backup transport"]
async fn live_invoice_backup_ack_survives_database_reopen() {
    use std::os::unix::fs::PermissionsExt;
    let root=std::env::temp_dir().join(format!("overstory-backup-http-{}",hex::encode(&Key::random().sk.to_secret_bytes()[..8])));
    std::fs::create_dir(&root).unwrap();std::fs::set_permissions(&root,std::fs::Permissions::from_mode(0o700)).unwrap();
    let original=std::env::current_dir().unwrap();std::env::set_current_dir(&root).unwrap();
    let mut app=quote_app();app.net=Net::Mainnet;app.cfg.network="mainnet".into();
    let address=Key::from_secret(&[7;32]).unwrap().address_string(Net::Mainnet);
    app.cfg.fee_address=address.clone();app.index.collections.get_mut(&app.cfg.collection).unwrap().pay=address.clone();
    app.index.collections.get_mut(&app.cfg.collection).unwrap().authenticated=true;
    let intent=InvoiceIntent{request_id:"19".repeat(32),quote:mint_quote(&app).unwrap()};
    let request=NewOrder{dest:address.clone(),refund_address:address.clone(),refund_confirmed:true,intent:Some(intent.clone())};
    let db_path=app.db.conn.path().unwrap().to_string();
    let shared=Arc::new(Mutex::new(app));
    let backup_lock=invoice_control::lock(std::path::Path::new("/var/lib/overstory/order-backup-spool/.lock")).unwrap();
    let failed=api_new_order(State(shared.clone()),Json(NewOrder{dest:address.clone(),refund_address:address.clone(),refund_confirmed:true,intent:Some(intent.clone())})).await;
    assert_eq!(failed.status(),StatusCode::SERVICE_UNAVAILABLE);
    let blocked_body=axum::body::to_bytes(failed.into_body(),4096).await.unwrap();
    let blocked:serde_json::Value=serde_json::from_slice(&blocked_body).unwrap();
    assert!(blocked.get("invoice_address").is_none());
    let pending_id={let app=shared.lock().unwrap();assert_eq!(app.orders.len(),1);app.orders.keys().next().unwrap().clone()};
    assert_eq!(api_order(State(shared.clone()),Path(pending_id.clone())).await.status(),StatusCode::SERVICE_UNAVAILABLE);
    drop(backup_lock);
    let response=api_new_order(State(shared.clone()),Json(request)).await;
    assert_eq!(response.status(),StatusCode::OK);
    let body=axum::body::to_bytes(response.into_body(),128*1024).await.unwrap();
    let returned:serde_json::Value=serde_json::from_slice(&body).unwrap();
    let id=returned["id"].as_str().unwrap().to_string();
    let invoice=returned["invoice_address"].as_str().unwrap().to_string();
    assert_eq!(id,pending_id);
    {
        let mut app=shared.lock().unwrap();
        assert_eq!(app.orders.len(),1);
        let saved=app.orders.get(&id).unwrap().clone();
        assert!(order_backup::ready(&app,&saved));
        app.db=Db::open(&db_path).unwrap();
        app.orders=app.db.kv_all(NS_ORDERS).unwrap();
        assert!(order_backup::ready(&app,app.orders.get(&id).unwrap()));
    }
    let request=NewOrder{dest:address.clone(),refund_address:address,refund_confirmed:true,intent:Some(intent)};
    let retry=api_new_order(State(shared.clone()),Json(request)).await;
    assert_eq!(retry.status(),StatusCode::OK);
    let body=axum::body::to_bytes(retry.into_body(),128*1024).await.unwrap();
    let retried:serde_json::Value=serde_json::from_slice(&body).unwrap();
    assert_eq!(retried["id"],id);assert_eq!(retried["invoice_address"],invoice);
    let app=shared.lock().unwrap();assert_eq!(app.orders.len(),1);
    let receipt:serde_json::Value=app.db.kv_all::<serde_json::Value>("invoice_backup_v1").unwrap().remove(&id).unwrap();
    std::fs::write(root.join("acceptance.json"),serde_json::to_vec_pretty(&json!({"order_id":id,"invoice_address":invoice,"cipher_sha256":receipt["cipher_sha256"],"backup_busy_hides_address":true,"same_order_after_backup_failure":true,"database_reopen":true,"same_intent_same_invoice":true,"blockchain_rpc_calls":0,"scope":"unfunded synthetic mainnet-shaped order"})).unwrap()).unwrap();
    println!("backup acceptance evidence: {}",root.join("acceptance.json").display());
    std::env::set_current_dir(original).unwrap();
}