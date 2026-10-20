use super::*;
use crate::inscribe::{
    InscribeResult, RecoveryRequired, RevealPlan, SignedInscription, SignedTransaction,
};
use std::{
    collections::BTreeMap,
    io::{BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
};
#[derive(Default)]
struct Node {
    known: BTreeMap<String, String>,
    sends: BTreeMap<String, u32>,
    drop_next: bool,
    lookup_error: Option<i64>,
    tip: u32,
    confirmed: bool,
    omit_confirmations: bool,
    omit_mempool_member: bool,
    noncanonical: bool,
    advance_on_lookup: bool,
    omit_member: bool,
    hashes: BTreeMap<u32,String>,
    advance_on_hash: bool,
}
struct Mock {
    rpc: Rpc,
    state: Arc<Mutex<Node>>,
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}
impl Mock {
    fn new() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let state = Arc::new(Mutex::new(Node {
            tip: 1,
            ..Node::default()
        }));
        let stop = Arc::new(AtomicBool::new(false));
        let (st, done) = (state.clone(), stop.clone());
        let worker = thread::spawn(move || {
            for socket in listener.incoming() {
                let mut socket = socket.unwrap();
                if done.load(Ordering::SeqCst) {
                    break;
                }
                socket
                    .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                    .unwrap();
                let mut reader = BufReader::new(socket.try_clone().unwrap());
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                let mut length = 0;
                loop {
                    line.clear();
                    reader.read_line(&mut line).unwrap();
                    if line == "\r\n" {
                        break;
                    }
                    if line.to_lowercase().starts_with("content-length:") {
                        length = line
                            .split(':')
                            .nth(1)
                            .unwrap()
                            .trim()
                            .parse::<usize>()
                            .unwrap();
                    }
                }
                let mut bytes = vec![0; length];
                reader.read_exact(&mut bytes).unwrap();
                let q: Value = serde_json::from_slice(&bytes).unwrap();
                let mut node = st.lock().unwrap();
                let mut error = None;
                let mut status = 200;
                let result = match q["method"].as_str().unwrap() {
                    "getblockhash" => {
                        if node.advance_on_hash {node.tip+=1;node.advance_on_hash=false;}
                        let height=q["params"][0].as_u64().unwrap() as u32;
                        json!(node.hashes.get(&height).cloned().unwrap_or_else(||if node.noncanonical && height!=0 {"22".repeat(32)} else {"11".repeat(32)}))
                    }
                    "getblock" => {
                        json!({"height":2,"tx":if node.omit_member {vec![]}else{node.known.keys().cloned().collect::<Vec<_>>()}})
                    }
                    "getblockchaininfo" => {
                        json!({"chain":"regtest","blocks":node.tip,"consensus":{"nextblock":"37a5165b"},"upgrades":{}})
                    }
                    "getrawtransaction" => {
                        if node.advance_on_lookup {
                            node.tip += 1;
                            node.advance_on_lookup = false;
                        }
                        let id = q["params"][0].as_str().unwrap();
                        if let Some(code) = node.lookup_error {
                            error = Some(json!({"code":code,"message":"fixture unavailable"}));
                            Value::Null
                        } else if let Some(raw) = node.known.get(id) {
                            if q["params"][1].as_u64() == Some(1) {
                                let mut value=json!({"hex":raw,"confirmations":if node.confirmed {1}else{0},"blockhash":"11".repeat(32)});
                                if node.omit_confirmations {value.as_object_mut().unwrap().remove("confirmations");}
                                value
                            } else {
                                json!(raw)
                            }
                        } else {
                            status = 500;
                            error = Some(json!({"code":-5,"message":"not found"}));
                            Value::Null
                        }
                    }
                    "getrawmempool" => {
                        json!(if node.omit_mempool_member {vec![]} else {node.known.keys().cloned().collect::<Vec<_>>()})
                    }
                    "sendrawtransaction" => {
                        let raw = q["params"][0].as_str().unwrap();
                        let tx = Transaction::read(
                            &hex::decode(raw).unwrap()[..],
                            zcash_protocol::consensus::BranchId::Nu6_3,
                        )
                        .unwrap();
                        let id = tx.txid().to_string();
                        *node.sends.entry(id.clone()).or_default() += 1;
                        node.known.insert(id.clone(), raw.into());
                        if node.drop_next {
                            node.drop_next = false;
                            continue;
                        }
                        json!(id)
                    }
                    other => panic!("unexpected RPC {other}"),
                };
                let body =
                    serde_json::to_vec(&json!({"id":1,"result":result,"error":error})).unwrap();
                write!(
                    socket,
                    "HTTP/1.1 {status} {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    if status == 200 { "OK" } else { "Error" },
                    body.len()
                )
                .unwrap();
                socket.write_all(&body).unwrap();
            }
        });
        Self {
            rpc: Rpc {
                url: format!("http://{address}"),
                chain: network::ChainConfig {
                    network: "regtest".into(),
                    genesis_hash: "11".repeat(32),
                },
                agent: ureq::AgentBuilder::new()
                    .timeout(std::time::Duration::from_secs(5))
                    .build(),
            },
            state,
            stop,
            thread: Some(worker),
        }
    }
}
impl Drop for Mock {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.rpc.url.trim_start_matches("http://"));
        self.thread.take().unwrap().join().unwrap();
    }
}
fn fixture() -> SignedInscription {
    let key = Key::from_secret(&[5; 32]).unwrap();
    let ct = b"text/plain";
    let content = vec![42; 480];
    let commitment = inscribe::commitment(ct, &content);
    let redeem = inscribe::redeem_script(&key.pk.serialize(), &commitment, 1);
    let address = TransparentAddress::ScriptHash(inscribe::hash160(&redeem));
    let input = InputSpec {
        pubkey: key.pk,
        outpoint: zcash_transparent::bundle::OutPoint::new([9; 32], 0),
        coin: TxOut::new(zat(1_000_000).unwrap(), key.address().script().into()),
    };
    let pczt = build_pczt(
        index::Net::Regtest,
        2,
        42,
        &[input],
        &[OutputSpec {
            to: address.clone(),
            value: 100000,
        }],
        &key.address(),
    )
    .unwrap();
    let pczt = IoFinalizer::new(pczt).finalize_io(rand::rng()).unwrap();
    let mut signer = Signer::new(pczt).unwrap();
    signer.sign_transparent(0, &key.sk).unwrap();
    let tx = finalize_tx(signer.finish()).unwrap();
    let mut raw = vec![];
    tx.write(&mut raw).unwrap();
    let mut transactions = vec![SignedTransaction {
        txid: tx.txid().to_string(),
        raw: hex::encode(raw),
    }];
    let mut previous = zcash_transparent::bundle::OutPoint::new(*tx.txid().as_ref(), 0);
    for i in 0..2 {
        let outputs = vec![TxOut::new(
            zat(if i == 0 { 50000 } else { CARRIER_ZAT }).unwrap(),
            if i == 0 {
                address.script().into()
            } else {
                key.address().script().into()
            },
        )];
        let plan = RevealPlan {
            branch: zcash_protocol::consensus::BranchId::Nu6_3,
            commit_outpoint: previous,
            commit_value: if i == 0 { 100000 } else { 50000 },
            commit_script: address.script().into(),
            redeem: redeem.clone(),
            content_type: ct.to_vec(),
            total: 2,
            pieces: vec![(1 - i, vec![42; 240])],
            outputs,
            expiry: 42,
        };
        let tx = inscribe::build_reveal(&plan, &key).unwrap();
        let mut raw = vec![];
        tx.write(&mut raw).unwrap();
        previous = zcash_transparent::bundle::OutPoint::new(*tx.txid().as_ref(), 0);
        transactions.push(SignedTransaction {
            txid: tx.txid().to_string(),
            raw: hex::encode(raw),
        });
    }
    let result = InscribeResult {
        commit_txid: transactions[0].txid.clone(),
        inscription_id: format!("{}i0", transactions[1].txid),
        reveal_txids: transactions[1..].iter().map(|t| t.txid.clone()).collect(),
        total_cost: 100000,
    };
    SignedInscription {
        funding: vec![],
        version: 1,
        network: "regtest".into(),
        genesis_hash: "11".repeat(32),
        target_height: 2,
        expiry_height: 42,
        commit_vout: 0,
        destination: key.address_string(index::Net::Regtest),
        transactions,
        result,
    }
}
#[test]
fn lost_commit_receipt_resumes_two_reveals_without_resigning_or_resending_commit() {
    let node = Mock::new();
    let plan = fixture();
    node.state.lock().unwrap().drop_next = true;
    assert!(plan.resume(&node.rpc).is_err());
    let restored: SignedInscription =
        serde_json::from_str(&serde_json::to_string(&plan).unwrap()).unwrap();
    assert_eq!(
        restored.resume(&node.rpc).unwrap().inscription_id,
        plan.result.inscription_id
    );
    let st = node.state.lock().unwrap();
    assert_eq!(st.sends.len(), 3);
    assert!(st.sends.values().all(|n| *n == 1));
    drop(st);
    node.state.lock().unwrap().tip = 100;
    assert!(restored.resume(&node.rpc).is_ok());
    assert!(node.state.lock().unwrap().sends.values().all(|n| *n == 1));
}
#[test]
fn missing_expired_reveal_stops_without_new_inputs_or_refund() {
    let node = Mock::new();
    let plan = fixture();
    let mut st = node.state.lock().unwrap();
    st.tip = 100;
    st.known.insert(
        plan.transactions[0].txid.clone(),
        plan.transactions[0].raw.clone(),
    );
    drop(st);
    let err = plan.resume(&node.rpc).err().unwrap();
    assert!(err.downcast_ref::<RecoveryRequired>().is_some());
    assert!(node.state.lock().unwrap().sends.is_empty());
}
#[test]
fn lookup_failure_is_not_treated_as_missing_transaction() {
    let node = Mock::new();
    let plan = fixture();
    node.state.lock().unwrap().lookup_error = Some(-28);
    let err = plan.resume(&node.rpc).err().unwrap();
    assert_eq!(err.downcast_ref::<RpcCallError>().unwrap().code, -28);
    assert!(node.state.lock().unwrap().sends.is_empty());
}
#[test]
fn corrupt_or_wrong_chain_plan_never_broadcasts() {
    let node = Mock::new();
    let plan = fixture();
    for change in 0..4 {
        let mut bad = plan.clone();
        match change {
            0 => bad.genesis_hash = "22".repeat(32),
            1 => bad.transactions[1].raw.push_str("00"),
            2 => bad.transactions.swap(1, 2),
            _ => {
                bad.destination = Key::from_secret(&[6; 32])
                    .unwrap()
                    .address_string(index::Net::Regtest)
            }
        };
        assert!(bad.resume(&node.rpc).is_err());
    }
    assert!(node.state.lock().unwrap().sends.is_empty());
}

fn refund_fixture() -> crate::refund::RefundPlan {
    let key = Key::from_secret(&[5; 32]).unwrap();
    let u = Utxo {
        txid: "09".repeat(32),
        n: 0,
        script: hex::encode(index::script_bytes(&key.address().script().into())),
        value: 30000,
        height: 1,
    };
    let pczt = build_pczt(
        index::Net::Regtest,
        2,
        41,
        &[InputSpec {
            pubkey: key.pk,
            outpoint: u.outpoint().unwrap(),
            coin: u.coin().unwrap(),
        }],
        &[OutputSpec {
            to: key.address(),
            value: 20000,
        }],
        &key.address(),
    )
    .unwrap();
    let pczt = IoFinalizer::new(pczt).finalize_io(rand::rng()).unwrap();
    let mut signer = Signer::new(pczt).unwrap();
    signer.sign_transparent(0, &key.sk).unwrap();
    let tx = finalize_tx(signer.finish()).unwrap();
    let mut raw = vec![];
    tx.write(&mut raw).unwrap();
    crate::refund::RefundPlan {
        version: 1,
        network: "regtest".into(),
        genesis_hash: "11".repeat(32),
        target_height: 2,
        expiry_height: 41,
        destination: key.address_string(index::Net::Regtest),
        funding: vec![u],
        input_zat: 30000,
        refund_zat: 20000,
        fee_zat: 10000,
        txid: tx.txid().to_string(),
        raw_transaction: hex::encode(raw),
    }
}
#[test]
fn refund_lost_ack_resumes_exact_bytes_and_waits_for_canonical_confirmation() {
    let node = Mock::new();
    let plan = refund_fixture();
    node.state.lock().unwrap().drop_next = true;
    assert!(plan.resume(&node.rpc).is_err());
    let restored: crate::refund::RefundPlan =
        serde_json::from_str(&serde_json::to_string(&plan).unwrap()).unwrap();
    assert!(restored.resume(&node.rpc).unwrap().is_none());
    node.state.lock().unwrap().confirmed = true;
    assert_eq!(restored.resume(&node.rpc).unwrap().unwrap().height, 2);
    assert_eq!(node.state.lock().unwrap().sends[&plan.txid], 1);
    node.state.lock().unwrap().noncanonical = true;
    assert!(restored.resume(&node.rpc).is_err());
}
#[test]
fn refund_rpc_failure_is_not_missing_and_expired_plan_never_replaced() {
    let node = Mock::new();
    let plan = refund_fixture();
    node.state.lock().unwrap().lookup_error = Some(-28);
    assert!(plan.resume(&node.rpc).is_err());
    assert!(node.state.lock().unwrap().sends.is_empty());
    {
        let mut st = node.state.lock().unwrap();
        st.lookup_error = None;
        st.tip = 100;
    }
    assert!(
        plan.resume(&node.rpc)
            .unwrap_err()
            .downcast_ref::<RecoveryRequired>()
            .is_some()
    );
    assert!(node.state.lock().unwrap().sends.is_empty());
}
#[test]
fn refund_plan_rejects_destination_amount_input_and_epoch_corruption() {
    let node = Mock::new();
    let p = refund_fixture();
    p.validate(&node.rpc).unwrap();
    let mut bad = p.clone();
    bad.destination = Key::from_secret(&[8; 32])
        .unwrap()
        .address_string(index::Net::Regtest);
    assert!(bad.validate(&node.rpc).is_err());
    let mut bad = p.clone();
    bad.fee_zat += 1;
    assert!(bad.validate(&node.rpc).is_err());
    let mut bad = p.clone();
    bad.funding[0].value += 1;
    assert!(bad.validate(&node.rpc).is_err());
    let mut bad = p.clone();
    bad.funding.push(bad.funding[0].clone());
    assert!(bad.validate(&node.rpc).is_err());
    let mut bad = p.clone();
    bad.genesis_hash = "00".repeat(32);
    assert!(bad.validate(&node.rpc).is_err());
    let mut bad = p;
    bad.expiry_height += 1;
    assert!(bad.validate(&node.rpc).is_err());
    assert!(node.state.lock().unwrap().sends.is_empty());
}

fn audit_db(plan: &crate::refund::RefundPlan) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "overstory-audit-test-{}",
        Key::random().secret_hex()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("fixture.sqlite");
    let mut db = index::Db::open(path.to_str().unwrap()).unwrap();
    db.apply(
        &index::State {
            height: 10,
            tip_hash: Some("11".repeat(32)),
            network: Some("regtest".into()),
            ..Default::default()
        },
        &index::Changes::default(),
    )
    .unwrap();
    db.kv_put("orders","test-order",&json!({"id":"test-order","status":"refunded","dest":plan.destination,"accounting_version":1,"refunds":[{"plan":plan,"confirmation":{"height":2,"block_hash":"11".repeat(32)}}]})).unwrap();
    path
}
#[test]
fn audit_distinguishes_chain_states_without_any_broadcast() {
    let node = Mock::new();
    let p = refund_fixture();
    let check = || crate::audit::transaction(&node.rpc, &p.txid, &p.raw_transaction).unwrap();
    assert_eq!(check()["state"], "missing");
    node.state.lock().unwrap().lookup_error = Some(-28);
    assert_eq!(check()["state"], "lookup_unavailable");
    {
        let mut st = node.state.lock().unwrap();
        st.lookup_error = None;
        st.known.insert(p.txid.clone(), p.raw_transaction.clone());
    }
    assert_eq!(check()["state"], "unconfirmed");
    node.state.lock().unwrap().confirmed = true;
    assert_eq!(check()["state"], "confirmed");
    node.state.lock().unwrap().noncanonical = true;
    assert_eq!(check()["state"], "noncanonical");
    node.state.lock().unwrap().omit_member = true;
    assert!(crate::audit::transaction(&node.rpc, &p.txid, &p.raw_transaction).is_err());
    assert!(node.state.lock().unwrap().sends.is_empty());
}
#[test]
fn order_audit_reports_stale_confirmations_and_preserves_database_and_secrets() {
    let node = Mock::new();
    let p = refund_fixture();
    let path = audit_db(&p);
    let before = std::fs::read(&path).unwrap();
    {
        let mut st = node.state.lock().unwrap();
        st.tip = 10;
        st.known.insert(p.txid.clone(), p.raw_transaction.clone());
        st.confirmed = true;
    }
    let report =
        crate::audit::orders(&node.rpc, path.to_str().unwrap(), Some("test-order")).unwrap();
    assert_eq!(report["index_state"], "canonical");
    assert_eq!(report["orders"][0]["issues"], json!([]));
    assert_eq!(report["authorizes_resume"], false);
    let text = report.to_string();
    assert!(!text.contains(&p.raw_transaction));
    assert!(!text.contains("funding"));
    node.state.lock().unwrap().noncanonical = true;
    let report = crate::audit::orders(&node.rpc, path.to_str().unwrap(), None).unwrap();
    assert_eq!(report["index_state"], "noncanonical");
    assert!(
        report["orders"][0]["issues"]
            .as_array()
            .unwrap()
            .contains(&json!("saved_refund_confirmation_changed"))
    );
    assert_eq!(std::fs::read(&path).unwrap(), before);
    assert!(node.state.lock().unwrap().sends.is_empty());
}
#[test]
fn order_audit_discards_report_when_chain_moves_during_checks() {
    let node = Mock::new();
    let p = refund_fixture();
    let path = audit_db(&p);
    {
        let mut st = node.state.lock().unwrap();
        st.tip = 10;
        st.advance_on_lookup = true;
    }
    let e = crate::audit::orders(&node.rpc, path.to_str().unwrap(), None).unwrap_err();
    assert!(e.to_string().contains("chain changed during audit"));
    assert!(node.state.lock().unwrap().sends.is_empty());
}
#[test]
fn index_fork_and_shorter_chain_stop_without_mutating_orders_or_index() {
    let node = Mock::new();
    let p = refund_fixture();
    let path = audit_db(&p);
    let mut db = index::Db::open(path.to_str().unwrap()).unwrap();
    let mut st = db.load().unwrap();
    let original = serde_json::to_value(&st).unwrap();
    let orders: std::collections::BTreeMap<String, Value> = db.kv_all("orders").unwrap();
    {
        let mut n = node.state.lock().unwrap();
        n.tip = 10;
        n.noncanonical = true;
    }
    assert!(
        index::index_to_tip(
            &node.rpc,
            &mut st,
            Some(&mut db),
            index::Net::Regtest,
            0,
            false,
            200
        )
        .is_err()
    );
    {
        let mut n = node.state.lock().unwrap();
        n.tip = 9;
        n.noncanonical = false;
    }
    assert!(
        index::index_to_tip(
            &node.rpc,
            &mut st,
            Some(&mut db),
            index::Net::Regtest,
            0,
            false,
            200
        )
        .is_err()
    );
    assert_eq!(serde_json::to_value(&st).unwrap(), original);
    assert_eq!(serde_json::to_value(db.load().unwrap()).unwrap(), original);
    assert_eq!(db.kv_all::<Value>("orders").unwrap(), orders);
    assert!(node.state.lock().unwrap().sends.is_empty());
}

#[test]
fn audit_checks_confirmed_refund_address_separately_from_nft_destination() {
    let node=Mock::new();let p=refund_fixture();let path=audit_db(&p);
    {let mut st=node.state.lock().unwrap();st.tip=10;st.confirmed=true;st.known.insert(p.txid.clone(),p.raw_transaction.clone());}
    let db=index::Db::open(path.to_str().unwrap()).unwrap();
    let mut order=json!({"id":"test-order","status":"refunded","dest":"different-nft-destination","refund_address":p.destination,"accounting_version":1,"refunds":[{"plan":p,"confirmation":{"height":2,"block_hash":"11".repeat(32)}}]});
    db.kv_put("orders","test-order",&order).unwrap();
    let r=crate::audit::orders(&node.rpc,path.to_str().unwrap(),None).unwrap();
    assert_eq!(r["orders"][0]["issues"],json!([]));
    order["refund_address"]=json!("changed-refund-address");db.kv_put("orders","test-order",&order).unwrap();
    let before=std::fs::read(&path).unwrap();
    let r=crate::audit::orders(&node.rpc,path.to_str().unwrap(),None).unwrap();
    assert!(r["orders"][0]["issues"].as_array().unwrap().contains(&json!("invalid_refund_plan")));
    assert_eq!(std::fs::read(&path).unwrap(),before);assert!(node.state.lock().unwrap().sends.is_empty());
}

fn undo_fixture() -> (index::Db,index::State) {
    let path=std::env::temp_dir().join(format!("overstory-undo-{}.sqlite",Key::random().secret_hex()));
    let mut db=index::Db::open(path.to_str().unwrap()).unwrap();
    let mut st=index::State {height:1,tip_hash:Some("11".repeat(32)),network:Some("regtest".into()),..Default::default()};
    let ins=index::Inscription { authenticated: false,id:"one".into(),family:"v1".into(),content_type:"text/plain".into(),content_len:1,content_sha256:"unused".into(),content_hex:"61".into(),genesis_height:1,genesis_block_hash:"11".repeat(32),completion_height:1,completion_block_hash:"11".repeat(32),owner:"first:0".into(),owner_address:None,history:vec![]};
    st.inscriptions.insert("one".into(),ins);st.carriers.insert("first:0".into(),["one".into()].into());
    st.pending.insert("old:0".into(),index::Pending::default());
    st.collections.insert("collection".into(),index::Collection { authenticated: false,id:"collection".into(),name:"fixture".into(),supply:3000,max_per_addr:0,price:5000000,pay:"pay".into(),start:1,renderer:"".into(),deployed_height:1,minted:1,per_addr:BTreeMap::new()});
    st.mints.insert("one".into(),index::Mint {inscription:"one".into(),collection:"collection".into(),number:1,minter:"minter".into(),height:1,seed:"aa".repeat(32)});
    st.rejected.push("older rejection".into());
    let ch=index::Changes {inscriptions:["one".into()].into(),carriers_put:["first:0".into()].into(),pending_put:["old:0".into()].into(),collections:["collection".into()].into(),mints:["one".into()].into(),rejected:st.rejected.clone(),..Default::default()};
    db.apply(&st,&ch).unwrap();
    db.kv_put("orders","invoice",&json!({"status":"done","signed_bytes":"must-survive","refunds":[{"txid":"original"}]})).unwrap();
    (db,st)
}
fn undo_next(st:&index::State,height:u32,hash:&str)->(index::State,index::Changes) {
    let mut next=st.clone();next.height=height;next.tip_hash=Some(hash.into());
    let mut ch=index::Changes::default();
    for (id,ins) in next.inscriptions.iter_mut(){ins.owner=format!("block{height}:0");ins.history.push(format!("moved {height}"));ch.inscriptions.insert(id.clone());}
    if height==2 {
        let mut added=next.inscriptions["one"].clone();added.id="two".into();next.inscriptions.insert("two".into(),added);ch.inscriptions.insert("two".into());
        let mut mint=next.mints["one"].clone();mint.inscription="two".into();mint.number=2;next.mints.insert("two".into(),mint);ch.mints.insert("two".into());
        let mut col=next.collections["collection"].clone();col.id="new-collection".into();next.collections.insert(col.id.clone(),col);ch.collections.insert("new-collection".into());
    }
    ch.carriers_del.extend(next.carriers.keys().cloned());next.carriers.clear();
    let owner=format!("block{height}:0");next.carriers.insert(owner.clone(),next.inscriptions.keys().cloned().collect());ch.carriers_put.insert(owner);
    ch.pending_del.extend(next.pending.keys().cloned());next.pending.clear();let pending=format!("pending{height}:0");next.pending.insert(pending.clone(),index::Pending::default());ch.pending_put.insert(pending);
    next.collections.get_mut("collection").unwrap().minted=2;ch.collections.insert("collection".into());
    next.mints.get_mut("one").unwrap().seed=hash.into();ch.mints.insert("one".into());
    let rejection=format!("rejected at {height}");next.rejected.push(rejection.clone());ch.rejected.push(rejection);
    (next,ch)
}
#[test]
fn undo_restores_every_index_table_and_preserves_orders_and_signed_bytes() {
    let mock=Mock::new();mock.state.lock().unwrap().tip=3;
    let (mut db,before)=undo_fixture();let original=serde_json::to_value(&before).unwrap();let orders=db.kv_all::<Value>("orders").unwrap();
    let (second,ch)=undo_next(&before,2,&"22".repeat(32));crate::reorg::apply_block(&mut db,&before,&second,&ch).unwrap();
    let (mut third,ch)=undo_next(&second,3,&"33".repeat(32));crate::reorg::apply_block(&mut db,&second,&third,&ch).unwrap();
    let recovery=crate::reorg::rollback_to_ancestor(&mock.rpc,&mut db,&mut third).unwrap().unwrap();
    assert_eq!(recovery.blocks_rolled_back,2);assert_eq!(recovery.ancestor_height,1);
    assert_eq!(serde_json::to_value(&third).unwrap(),original);assert_eq!(serde_json::to_value(db.load().unwrap()).unwrap(),original);
    assert_eq!(db.kv_all::<Value>("orders").unwrap(),orders);assert!(crate::reorg::pending(&db).unwrap().is_some());
    assert!(crate::reorg::rollback_to_ancestor(&mock.rpc,&mut db,&mut third).is_err());
    assert!(mock.state.lock().unwrap().sends.is_empty());
    // Replaying replacement block state changes the seed and ownership, never the order journal.
    let (replacement,ch)=undo_next(&third,2,&"44".repeat(32));crate::reorg::apply_block(&mut db,&third,&replacement,&ch).unwrap();
    assert_eq!(serde_json::to_value(db.load().unwrap()).unwrap(),serde_json::to_value(replacement).unwrap());
    assert_eq!(db.kv_all::<Value>("orders").unwrap(),orders);assert!(crate::reorg::pending(&db).unwrap().is_some());
}
#[test]
fn undo_depth_limit_and_missing_history_leave_index_and_orders_untouched() {
    let mock=Mock::new();let (mut db,mut st)=undo_fixture();
    for height in 2..=crate::reorg::UNDO_DEPTH+2 {
        let mut next=st.clone();next.height=height;next.tip_hash=Some(format!("{height:064x}"));
        crate::reorg::apply_block(&mut db,&st,&next,&index::Changes::default()).unwrap();st=next;
    }
    let saved=serde_json::to_value(&st).unwrap();let orders=db.kv_all::<Value>("orders").unwrap();
    assert_eq!(db.conn.query_row("SELECT COUNT(*) FROM index_undo",[],|r|r.get::<_,u32>(0)).unwrap(),crate::reorg::UNDO_DEPTH);
    assert!(crate::reorg::rollback_to_ancestor(&mock.rpc,&mut db,&mut st).is_err());
    assert_eq!(serde_json::to_value(db.load().unwrap()).unwrap(),saved);assert_eq!(serde_json::to_value(st).unwrap(),saved);
    assert!(crate::reorg::pending(&db).unwrap().is_none());assert_eq!(db.kv_all::<Value>("orders").unwrap(),orders);
    let (mut db,mut st)=undo_fixture();mock.state.lock().unwrap().noncanonical=true;
    assert!(crate::reorg::rollback_to_ancestor(&mock.rpc,&mut db,&mut st).unwrap_err().to_string().contains("no undo history"));
    assert!(crate::reorg::pending(&db).unwrap().is_none());
}
#[test]
fn moving_chain_and_corrupt_restore_abort_without_partial_rollback() {
    let mock=Mock::new();let (mut db,before)=undo_fixture();let (mut st,ch)=undo_next(&before,2,&"22".repeat(32));
    crate::reorg::apply_block(&mut db,&before,&st,&ch).unwrap();let saved=serde_json::to_value(&st).unwrap();
    {let mut n=mock.state.lock().unwrap();n.tip=2;n.advance_on_hash=true;}
    assert!(crate::reorg::rollback_to_ancestor(&mock.rpc,&mut db,&mut st).unwrap_err().to_string().contains("chain changed"));
    assert_eq!(serde_json::to_value(db.load().unwrap()).unwrap(),saved);assert!(crate::reorg::pending(&db).unwrap().is_none());
    let raw:String=db.conn.query_row("SELECT json FROM index_undo WHERE height=2",[],|r|r.get(0)).unwrap();
    let mut bad:Value=serde_json::from_str(&raw).unwrap();bad["rows"][0]["one"]=json!("corrupt old JSON");
    db.conn.execute("UPDATE index_undo SET json=?1 WHERE height=2",[bad.to_string()]).unwrap();
    assert!(crate::reorg::rollback_to_ancestor(&mock.rpc,&mut db,&mut st).is_err());
    assert_eq!(serde_json::to_value(db.load().unwrap()).unwrap(),saved);assert_eq!(serde_json::to_value(st).unwrap(),saved);assert!(crate::reorg::pending(&db).unwrap().is_none());
    assert_eq!(db.conn.query_row("SELECT COUNT(*) FROM index_undo",[],|r|r.get::<_,u32>(0)).unwrap(),1);
}
#[test]
fn block_and_undo_journal_commit_atomically_on_database_failure() {
    let (mut db,before)=undo_fixture();let (next,ch)=undo_next(&before,2,&"22".repeat(32));
    db.conn.execute_batch("CREATE TRIGGER fail_mint BEFORE INSERT ON mints BEGIN SELECT RAISE(ABORT,'fixture write failure'); END").unwrap();
    assert!(crate::reorg::apply_block(&mut db,&before,&next,&ch).is_err());
    assert_eq!(serde_json::to_value(db.load().unwrap()).unwrap(),serde_json::to_value(before).unwrap());
    let exists:bool=db.conn.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='index_undo')",[],|r|r.get(0)).unwrap();assert!(!exists);
    assert!(crate::reorg::pending(&db).unwrap().is_none());
}

#[test]
fn receipt_audit_checks_canonical_source_amount_and_invoice_without_spending() {
    let mock=Mock::new();let p=fixture();let last=p.transactions.last().unwrap();
    let script=hex::encode(index::script_bytes(&parse_taddr_for(&p.destination,index::Net::Regtest.network_type()).unwrap().script().into()));
    let mut u=Utxo {txid:last.txid.clone(),n:0,script,value:CARRIER_ZAT,height:2};
    assert_eq!(audit::receipt(&mock.rpc,&u,&p.destination).unwrap()["state"],"missing");
    {let mut node=mock.state.lock().unwrap();node.known.insert(last.txid.clone(),last.raw.clone());node.confirmed=true;node.tip=2;}
    assert_eq!(audit::receipt(&mock.rpc,&u,&p.destination).unwrap()["state"],"confirmed");
    u.value+=1;assert_eq!(audit::receipt(&mock.rpc,&u,&p.destination).unwrap()["state"],"invalid_receipt");u.value-=1;
    let wrong=Key::from_secret(&[19;32]).unwrap().address_string(index::Net::Regtest);
    assert_eq!(audit::receipt(&mock.rpc,&u,&wrong).unwrap()["state"],"invalid_receipt");
    mock.state.lock().unwrap().noncanonical=true;assert_eq!(audit::receipt(&mock.rpc,&u,&p.destination).unwrap()["state"],"noncanonical");
    mock.state.lock().unwrap().lookup_error=Some(-28);assert_eq!(audit::receipt(&mock.rpc,&u,&p.destination).unwrap()["state"],"lookup_unavailable");
    assert!(mock.state.lock().unwrap().sends.is_empty());
}

#[test]
fn reconciliation_barrier_is_atomic_and_refuses_changed_order_snapshots() {
    let mock=Mock::new();let (mut db,before)=undo_fixture();let (mut st,ch)=undo_next(&before,2,&"22".repeat(32));
    crate::reorg::apply_block(&mut db,&before,&st,&ch).unwrap();
    let recovery=crate::reorg::rollback_to_ancestor(&mock.rpc,&mut db,&mut st).unwrap().unwrap();
    let expected=db.kv_all::<Value>("orders").unwrap();let mut updates=expected.clone();updates.get_mut("invoice").unwrap()["status"]=json!("recovery_required");
    db.conn.execute_batch("CREATE TRIGGER fail_reconcile BEFORE UPDATE ON kv WHEN NEW.ns='orders' BEGIN SELECT RAISE(ABORT,'fixture reconciliation failure'); END").unwrap();
    assert!(crate::reorg::commit_reconciliation(&mut db,&recovery,1,&"11".repeat(32),&expected,&updates,&json!({})).is_err());
    assert_eq!(db.kv_all::<Value>("orders").unwrap(),expected);assert!(crate::reorg::pending(&db).unwrap().is_some());
    assert!(db.kv_all::<Value>("reorg_history").unwrap().is_empty());
    db.conn.execute_batch("DROP TRIGGER fail_reconcile").unwrap();
    db.kv_put("orders","invoice",&json!({"status":"concurrent-change"})).unwrap();
    assert!(crate::reorg::commit_reconciliation(&mut db,&recovery,1,&"11".repeat(32),&expected,&updates,&json!({})).is_err());
    assert!(crate::reorg::pending(&db).unwrap().is_some());
    db.kv_put("orders","invoice",expected.get("invoice").unwrap()).unwrap();
    crate::reorg::commit_reconciliation(&mut db,&recovery,1,&"11".repeat(32),&expected,&updates,&json!({"read_only":true})).unwrap();
    assert!(crate::reorg::pending(&db).unwrap().is_none());assert_eq!(db.kv_all::<Value>("orders").unwrap(),updates);
    assert_eq!(db.kv_all::<Value>("reorg_history").unwrap().len(),1);
    assert_eq!(serde_json::to_value(db.load().unwrap()).unwrap(),serde_json::to_value(before).unwrap());
}

#[test]
fn journal_and_rollback_preserve_current_schema_and_orders() {
    let mock=Mock::new();let (mut db,before)=undo_fixture();let orders=db.kv_all::<Value>("orders").unwrap();
    let (mut next,ch)=undo_next(&before,2,&"22".repeat(32));crate::reorg::apply_block(&mut db,&before,&next,&ch).unwrap();
    let version:String=db.conn.query_row("SELECT v FROM meta WHERE k='schema_version'",[],|r|r.get(0)).unwrap();
    assert_eq!(version,index::SCHEMA_VERSION);assert_eq!(db.kv_all::<Value>("orders").unwrap(),orders);
    assert_eq!(serde_json::to_value(db.load().unwrap()).unwrap(),serde_json::to_value(&next).unwrap());
    crate::reorg::rollback_to_ancestor(&mock.rpc,&mut db,&mut next).unwrap().unwrap();
    let version:String=db.conn.query_row("SELECT v FROM meta WHERE k='schema_version'",[],|r|r.get(0)).unwrap();
    assert_eq!(version,index::SCHEMA_VERSION);assert_eq!(db.kv_all::<Value>("orders").unwrap(),orders);
}

#[test]
fn journal_refuses_changed_schema_without_upgrading_or_rewriting_orders() {
    let (mut db,before)=undo_fixture();let orders=db.kv_all::<Value>("orders").unwrap();
    db.conn.execute("UPDATE meta SET v='3' WHERE k='schema_version'",[]).unwrap();
    let (next,ch)=undo_next(&before,2,&"22".repeat(32));
    assert!(crate::reorg::apply_block(&mut db,&before,&next,&ch).is_err());
    let version:String=db.conn.query_row("SELECT v FROM meta WHERE k='schema_version'",[],|r|r.get(0)).unwrap();
    assert_eq!(version,"3");assert_eq!(db.kv_all::<Value>("orders").unwrap(),orders);
    assert!(db.load().is_err());
}

#[test]
fn cli_signed_chain_survives_lost_commit_reply_and_refuses_overwrite() {
 let path=std::env::temp_dir().join(format!("cli-plan-{}.sqlite",hex::encode(Key::random().sk.to_secret_bytes())));
 let plan=fixture();let mock=Mock::new();mock.state.lock().unwrap().drop_next=true;
 {
  let mut db=index::Db::open(path.to_str().unwrap()).unwrap();inscribe::save_cli_plan(&mut db,&plan).unwrap();
  assert!(plan.resume(&mock.rpc).is_err());
  let mut changed=plan.clone();changed.transactions[1].raw.push_str("00");assert!(inscribe::save_cli_plan(&mut db,&changed).is_err());
 }
 let db=index::Db::open(path.to_str().unwrap()).unwrap();let saved:SignedInscription=db.kv_all("cli-inscription-plans").unwrap().remove(&plan.result.inscription_id).unwrap();
 assert_eq!(serde_json::to_value(&saved).unwrap(),serde_json::to_value(&plan).unwrap());
 saved.resume(&mock.rpc).unwrap();let state=mock.state.lock().unwrap();
 for t in &plan.transactions {assert_eq!(state.sends.get(&t.txid),Some(&1));}
 drop(state);drop(db);std::fs::remove_file(path).unwrap();
}

#[test]
fn refund_missing_confirmations_requires_mempool_and_never_resends() {
    let node=Mock::new();let plan=refund_fixture();
    {let mut st=node.state.lock().unwrap();st.known.insert(plan.txid.clone(),plan.raw_transaction.clone());st.omit_confirmations=true;}
    assert!(plan.resume(&node.rpc).unwrap().is_none());
    node.state.lock().unwrap().omit_mempool_member=true;
    assert!(plan.resume(&node.rpc).unwrap_err().to_string().contains("neither confirmed nor in mempool"));
    node.state.lock().unwrap().omit_confirmations=false;
    assert!(plan.resume(&node.rpc).is_err());
    {let mut st=node.state.lock().unwrap();st.confirmed=true;st.omit_member=true;}
    assert!(plan.resume(&node.rpc).unwrap_err().to_string().contains("absent from reported confirmation block"));
    node.state.lock().unwrap().omit_member=false;
    assert_eq!(plan.resume(&node.rpc).unwrap().unwrap().height,2);
    assert!(node.state.lock().unwrap().sends.is_empty());
}


// Synthetic transparent transactions + simulated confirmations; no consensus claim.
#[test]
fn service_settlement_audit_reconciles_and_fails_closed_without_writes_or_sends() {
    use zcash_primitives::transaction::{Authorized, TransactionData, TxVersion};
    use zcash_transparent::bundle::{self, Bundle, TxIn};
    let mock=Mock::new();
    fn tx(prev:OutPoint,outputs:Vec<TxOut>)->Transaction {
        TransactionData::<Authorized>::from_parts(TxVersion::suggested_for_branch(zcash_protocol::consensus::BranchId::Nu6_3),
            zcash_protocol::consensus::BranchId::Nu6_3,0,BlockHeight::from_u32(42),
            Some(Bundle{vin:vec![TxIn::from_parts(prev,script_from_raw(&[]).unwrap(),u32::MAX)],vout:outputs,authorization:bundle::Authorized}),None,None,None).freeze().unwrap()
    }
    fn saved(tx:&Transaction)->SignedTransaction {let mut raw=vec![];tx.write(&mut raw).unwrap();SignedTransaction{txid:tx.txid().to_string(),raw:hex::encode(raw)}}
    let key=Key::from_secret(&[5;32]).unwrap();let address=key.address_string(index::Net::Regtest);
    let output=|v|TxOut::new(zat(v).unwrap(),key.address().script().into());
    let deposit=tx(OutPoint::new([9;32],0),vec![output(110000)]);
    let commit=tx(OutPoint::new(*deposit.txid().as_ref(),0),vec![output(65546),output(24454),output(10000)]);
    let reveal=tx(OutPoint::new(*commit.txid().as_ref(),0),vec![output(546),output(50000)]);
    let transactions=vec![saved(&commit),saved(&reveal)];
    let u=Utxo{txid:deposit.txid().to_string(),n:0,value:110000,script:hex::encode(index::script_bytes(&key.address().script().into())),height:2};
    let plan=SignedInscription{funding:vec![u.clone()],version:1,network:"regtest".into(),genesis_hash:"11".repeat(32),target_height:2,expiry_height:42,commit_vout:0,destination:address.clone(),
        result:InscribeResult{commit_txid:transactions[0].txid.clone(),inscription_id:format!("{}i0",transactions[1].txid),reveal_txids:vec![transactions[1].txid.clone()],total_cost:100000},transactions};
    let path=std::env::temp_dir().join(format!("overstory-settlement-test-{}.sqlite",rand::random::<u64>()));
    let db=index::Db::open(path.to_str().unwrap()).unwrap();
    for (k,v) in [("height","100".to_owned()),("network","regtest".into()),("tip_hash","11".repeat(32))] {db.conn.execute("INSERT OR REPLACE INTO meta(k,v) VALUES(?1,?2)",(k,v)).unwrap();}
    let col=json!({"id":"collection","name":"fixture","supply":1,"max_per_addr":0,"price":50000,"pay":address,"start":1,"renderer":"","deployed_height":1,"minted":0});
    db.conn.execute("INSERT INTO collections(id,json) VALUES('collection',?1)",[col.to_string()]).unwrap();
    let order=json!({"id":"order","kind":"mint","dest":address,"invoice_address":address,"refund_address":address,"accounting_version":1,"amount_zat":100000,"paid_zat":110000,
        "receipts":{format!("{}:0",u.txid):u},"mint_plan":plan,"refunds":[],"quote":{"version":1,"inclusive":true,"network":"regtest","genesis_hash":"11".repeat(32),"collection":"collection","total_zat":100000,"price_zat":50000,"pay":address,"fee_address":address}});
    db.kv_put("orders","order",&order).unwrap();
    {let mut n=mock.state.lock().unwrap();n.tip=100;n.confirmed=true;for tx in [&deposit,&commit]{let t=saved(tx);n.known.insert(t.txid,t.raw);}}
    let run=||crate::settlement_audit::audit(&mock.rpc,path.to_str().unwrap(),"order");
    let report=run().unwrap();assert_eq!(report["unearned_service_paid_zat"],24454);assert_eq!(report["confirmed_returned_zat"],10000);
    assert_eq!(report["conditional_liability"]["normal_failure_remaining_before_future_fees_zat"],90000);
    assert_eq!(report["conditional_liability"]["project_fault_remaining_before_future_fees_zat"],100000);
    for mode in 0..5 {
        {let mut n=mock.state.lock().unwrap();n.lookup_error=if mode==0{Some(-28)}else{None};n.noncanonical=mode==1;n.omit_member=mode==2;n.omit_confirmations=mode==3;n.advance_on_lookup=mode==4;}
        assert!(run().is_err());
    }
    {let mut n=mock.state.lock().unwrap();n.tip=100;n.advance_on_lookup=false;n.known.insert(saved(&reveal).txid,saved(&reveal).raw);}
    assert!(run().is_err()); // final reveal known: incomplete-order assumption is no longer valid
    mock.state.lock().unwrap().known.remove(&reveal.txid().to_string());
    let old=mock.state.lock().unwrap().known.remove(&commit.txid().to_string()).unwrap();
    let before_commit=run().unwrap();assert_eq!(before_commit["confirmed_network_fees_zat"],0);assert_eq!(before_commit["unearned_service_paid_zat"],0);
    assert_eq!(before_commit["conditional_liability"]["normal_failure_remaining_before_future_fees_zat"],110000);
    mock.state.lock().unwrap().known.insert(commit.txid().to_string(),old);
    db.kv_put("expired-reclaims",&plan.result.inscription_id,&json!({})).unwrap();assert!(run().is_err());
    db.conn.execute("DELETE FROM kv WHERE ns='expired-reclaims'",[]).unwrap();
    db.conn.execute("INSERT INTO meta(k,v) VALUES('reorg_pending','{}')",[]).unwrap();assert!(run().is_err());
    let after:String=db.conn.query_row("SELECT json FROM kv WHERE ns='orders' AND k='order'",[],|r|r.get(0)).unwrap();assert_eq!(serde_json::from_str::<Value>(&after).unwrap(),order);
    db.conn.execute("DELETE FROM meta WHERE k='reorg_pending'",[]).unwrap();
    let reserved=format!("{}:0",commit.txid());
    db.kv_put("reclaim-inputs",&reserved,&json!({"other":"reservation"})).unwrap();
    assert!(crate::service_settlement::hold(&mock.rpc,path.to_str().unwrap(),"order").is_err());
    db.conn.execute("DELETE FROM kv WHERE ns='reclaim-inputs'",[]).unwrap();
    // Abort the last write to verify order, reservations and record roll back together.
    db.conn.execute_batch("CREATE TRIGGER reject_settlement BEFORE INSERT ON kv WHEN NEW.ns='operator-actions' BEGIN SELECT RAISE(ABORT,'fixture fail'); END;").unwrap();
    assert!(crate::service_settlement::hold(&mock.rpc,path.to_str().unwrap(),"order").is_err());
    let count:i64=db.conn.query_row("SELECT COUNT(*) FROM kv WHERE ns IN ('service-settlements','service-settlement-inputs')",[],|r|r.get(0)).unwrap();assert_eq!(count,0);
    let after_fail:String=db.conn.query_row("SELECT json FROM kv WHERE ns='orders' AND k='order'",[],|r|r.get(0)).unwrap();assert_eq!(after_fail,after);
    db.conn.execute_batch("DROP TRIGGER reject_settlement").unwrap();
    let held=crate::service_settlement::hold(&mock.rpc,path.to_str().unwrap(),"order").unwrap();assert_eq!(held["authorizes_payment"],false);
    assert_eq!(held,crate::service_settlement::hold(&mock.rpc,path.to_str().unwrap(),"order").unwrap());
    let locked=crate::refund_claim::reserved_inputs(&db.conn).unwrap();assert!(locked.contains(&reserved));assert!(locked.contains(&format!("{}:1",commit.txid())));assert!(!locked.contains(&format!("{}:2",commit.txid())));
    let raw:String=db.conn.query_row("SELECT json FROM kv WHERE ns='orders' AND k='order'",[],|r|r.get(0)).unwrap();let mut changed:Value=serde_json::from_str(&raw).unwrap();
    assert_eq!(changed["mint_plan"],order["mint_plan"]);assert_eq!(changed["settlement_hold"],true);
    changed["refund_address"]=json!("changed");db.kv_put("orders","order",&changed).unwrap();assert!(crate::service_settlement::hold(&mock.rpc,path.to_str().unwrap(),"order").is_err());
    assert!(mock.state.lock().unwrap().sends.is_empty());drop(db);let _=std::fs::remove_file(path);
}

#[test]
fn key_free_recovery_rejects_funded_runtime_and_recovers_or_resumes_without_broadcast() {
    let mock=Mock::new();mock.state.lock().unwrap().tip=3;
    let (mut db,before)=undo_fixture();
    let root=std::env::temp_dir().join(format!("overstory-keyfree-{}",Key::random().secret_hex()));
    std::fs::create_dir(&root).unwrap();
    let (mut st,ch)=undo_next(&before,2,&"22".repeat(32));
    crate::reorg::apply_block(&mut db,&before,&st,&ch).unwrap();
    assert!(crate::reorg::recover_key_free(&mock.rpc,&mut db,&mut st,&root).is_err());
    assert_eq!(st.height,2);
    db.conn.execute("DELETE FROM kv WHERE ns='orders'",[]).unwrap();
    std::fs::create_dir(root.join("keys")).unwrap();
    assert!(crate::reorg::recover_key_free(&mock.rpc,&mut db,&mut st,&root).is_err());
    assert_eq!(st.height,2);std::fs::remove_dir(root.join("keys")).unwrap();
    let r=crate::reorg::recover_key_free(&mock.rpc,&mut db,&mut st,&root).unwrap().unwrap();
    assert_eq!(r.blocks_rolled_back,1);assert_eq!(st.height,1);
    assert!(crate::reorg::pending(&db).unwrap().is_none());
    assert_eq!(db.kv_all::<Value>("reorg_history").unwrap().len(),1);
    assert!(crate::reorg::recover_key_free(&mock.rpc,&mut db,&mut st,&root).unwrap().is_none());
    let (mut next,ch)=undo_next(&st,2,&"33".repeat(32));
    crate::reorg::apply_block(&mut db,&st,&next,&ch).unwrap();
    crate::reorg::rollback_to_ancestor(&mock.rpc,&mut db,&mut next).unwrap();
    assert!(crate::reorg::pending(&db).unwrap().is_some());
    crate::reorg::recover_key_free(&mock.rpc,&mut db,&mut next,&root).unwrap();
    assert!(crate::reorg::pending(&db).unwrap().is_none());
    assert!(mock.state.lock().unwrap().sends.is_empty());
    std::fs::remove_dir(root).unwrap();
}
