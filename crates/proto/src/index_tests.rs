use super::*;
use serde_json::json;
use zcash_primitives::transaction::{Authorized, TransactionData};
use zcash_transparent::bundle::{self, Bundle, OutPoint, TxIn, TxOut};

fn key() -> crate::Key {
    crate::Key::from_secret(&[1; 32]).unwrap()
}
fn addr() -> String {
    key().address_string(Net::Regtest)
}
fn id(n: u8) -> String {
    format!("{}i0", format!("{n:02x}").repeat(32))
}
fn inscription(n: u8, v: serde_json::Value, genesis: u32, complete: u32) -> Inscription {
    Inscription {
        authenticated: false,
        id: id(n),
        family: "v1".into(),
        content_type: "application/json".into(),
        content_hex: hex::encode(serde_json::to_vec(&v).unwrap()),
        content_len: 0,
        content_sha256: String::new(),
        genesis_height: genesis,
        genesis_block_hash: "aa".repeat(32),
        completion_height: complete,
        completion_block_hash: "bb".repeat(32),
        owner: format!("{}:0", format!("{n:02x}").repeat(32)),
        owner_address: Some(addr()),
        history: vec!["this text is not consensus data".into()],
    }
}
fn declaration() -> serde_json::Value {
    json!({"p":"overstory","v":1,"op":"deploy","name":"test","supply":2,"max_per_addr":0,"price":100000,"pay":addr(),"renderer":""})
}
fn deploy(st: &mut State, ch: &mut Changes, v: serde_json::Value) -> Inscription {
    let d = inscription(1, v, 10, 20);
    apply_declaration(st, ch, &d, &[], Net::Regtest);
    d
}
fn mint(st: &mut State, ch: &mut Changes, n: u8, h: u32, paid: u64) -> Inscription {
    let m = inscription(n, json!({"p":"overstory","op":"mint","d":id(1)}), h, h);
    apply_declaration(st, ch, &m, &[(Some(addr()), paid)], Net::Regtest);
    m
}

#[test]
fn rejects_legacy_deploy_and_mint() {
    let mut st = State::default();
    let mut ch = Changes::default();
    let mut d = inscription(1, declaration(), 10, 20);
    d.family = "legacy".into();
    apply_declaration(&mut st, &mut ch, &d, &[], Net::Regtest);
    assert!(st.collections.is_empty());
    d.family = "v1".into();
    apply_declaration(&mut st, &mut ch, &d, &[], Net::Regtest);
    let mut m = inscription(2, json!({"p":"overstory","op":"mint","d":id(1)}), 21, 21);
    m.family = "legacy".into();
    apply_declaration(
        &mut st,
        &mut ch,
        &m,
        &[(Some(addr()), 100000)],
        Net::Regtest,
    );
    assert!(st.mints.is_empty());
}
#[test]
fn completion_height_controls_start_not_history_or_genesis() {
    let mut st = State::default();
    let mut ch = Changes::default();
    deploy(&mut st, &mut ch, declaration());
    assert_eq!(st.collections[&id(1)].start, 21);
    assert_eq!(st.collections[&id(1)].deployed_height, 20);
    mint(&mut st, &mut ch, 2, 20, 100000);
    assert!(st.mints.is_empty());
    mint(&mut st, &mut ch, 3, 21, 100000);
    assert_eq!(st.mints[&id(3)].height, 21);
}
#[test]
fn paid_mint_supply_cap_and_underpayment() {
    let mut st = State::default();
    let mut ch = Changes::default();
    deploy(&mut st, &mut ch, declaration());
    mint(&mut st, &mut ch, 2, 21, 99999);
    assert!(st.mints.is_empty());
    mint(&mut st, &mut ch, 3, 21, 100000);
    mint(&mut st, &mut ch, 4, 21, 100001);
    mint(&mut st, &mut ch, 5, 21, 100000);
    assert_eq!(st.mints.len(), 2);
    assert_eq!(st.mints[&id(3)].number, 1);
    assert_eq!(st.mints[&id(4)].number, 2);
}
#[test]
fn per_address_cap_is_cumulative() {
    let mut st = State::default();
    let mut ch = Changes::default();
    let mut d = declaration();
    d["max_per_addr"] = json!(1);
    deploy(&mut st, &mut ch, d);
    mint(&mut st, &mut ch, 2, 21, 100000);
    mint(&mut st, &mut ch, 3, 21, 100000);
    assert_eq!(st.mints.len(), 1);
}
#[test]
fn rejects_invalid_financial_fields_and_version() {
    for (field, value) in [
        ("price", json!("100000")),
        ("price", json!(-1)),
        ("price", json!(u64::MAX)),
        ("max_per_addr", json!(-1)),
        ("start", json!(4294967300u64)),
        ("v", json!(99)),
        ("supply", json!(0)),
        ("unexpected", json!(true)),
    ] {
        let mut st = State::default();
        let mut ch = Changes::default();
        let mut v = declaration();
        v[field] = value;
        deploy(&mut st, &mut ch, v);
        assert!(st.collections.is_empty(), "{field}");
    }
    for field in ["price", "max_per_addr", "v", "renderer"] {
        let mut st = State::default();
        let mut ch = Changes::default();
        let mut v = declaration();
        v.as_object_mut().unwrap().remove(field);
        deploy(&mut st, &mut ch, v);
        assert!(st.collections.is_empty(), "{field}");
    }
}
#[test]
fn rejects_duplicate_json_keys() {
    let mut st = State::default();
    let mut ch = Changes::default();
    let mut d = inscription(1, declaration(), 10, 20);
    let mut raw = serde_json::to_string(&declaration()).unwrap();
    raw.pop();
    raw.push_str(",\"price\":0}");
    d.content_hex = hex::encode(raw);
    apply_declaration(&mut st, &mut ch, &d, &[], Net::Regtest);
    assert!(st.collections.is_empty());
}
#[test]
fn rejects_wrong_network_payment_address() {
    let mut st = State::default();
    let mut ch = Changes::default();
    let mut d = declaration();
    d["pay"] = json!(key().address().to_zcash_address(NetworkType::Main).encode());
    deploy(&mut st, &mut ch, d);
    assert!(st.collections.is_empty());
}
#[test]
fn public_network_requires_verified_renderer() {
    let mut st = State::default();
    let mut ch = Changes::default();
    let d = inscription(1, declaration(), 10, 20);
    apply_declaration(&mut st, &mut ch, &d, &[], Net::Testnet);
    assert!(st.collections.is_empty());
}
#[test]
fn seed_uses_completion_block_and_display_order() {
    let mut st = State::default();
    let mut ch = Changes::default();
    deploy(&mut st, &mut ch, declaration());
    let m = mint(&mut st, &mut ch, 2, 21, 100000);
    let mut bytes = vec![2u8; 32];
    bytes.extend([0xbb; 32]);
    assert_eq!(st.mints[&m.id].seed, hex::encode(Sha256::digest(bytes)));
}
#[test]
fn duplicate_mint_cannot_consume_supply_twice() {
    let mut st = State::default();
    let mut ch = Changes::default();
    deploy(&mut st, &mut ch, declaration());
    mint(&mut st, &mut ch, 2, 21, 100000);
    mint(&mut st, &mut ch, 2, 21, 100000);
    assert_eq!(st.collections[&id(1)].minted, 1);
}
fn envelope(ct: &[u8], total: usize, pieces: &[(usize, &[u8])]) -> Vec<u8> {
    let r = redeem_script(&key().pk.serialize(), &[1; 32], pieces.len());
    script_sig(ct, total, pieces, &[1; 72], &r)
}
#[test]
fn envelope_rejects_duplicates_bad_type_and_piece_size() {
    for s in [
        envelope(b"application/json", 1, &[(0, b"a"), (0, b"b")]),
        envelope(b"x", 1, &[(0, b"a")]),
        envelope(b"application/json", 1, &[(0, &[1; 300])]),
        envelope(b"application/json", 2, &[(0, b"short")]),
    ] {
        assert!(parse_envelope(&s).is_none());
    }
}
#[test]
fn envelope_requires_full_redeem_and_canonical_encoding() {
    let redeem = redeem_script(&key().pk.serialize(), &[1; 32], 1);
    let s = script_sig(
        b"application/json",
        1,
        &[(0, b"a")],
        &[1; 72],
        &redeem[..68],
    );
    assert!(parse_envelope(&s).unwrap().c.is_none());
    let mut s = envelope(b"application/json", 1, &[(0, b"a")]);
    s.splice(4..5, [1, 1]);
    assert!(parse_envelope(&s).is_none());
}
#[test]
fn valid_short_highest_piece_and_full_lower_piece_parse() {
    assert!(
        parse_envelope(&envelope(b"text/plain", 2, &[(1, b"tail"), (0, &[1; 240])]))
            .unwrap()
            .c
            .is_some()
    );
}
#[test]
fn malformed_blocks_never_panic() {
    let mut cases = vec![vec![], vec![0; 1], vec![0; 140], vec![0; 141]];
    let mut b = vec![0; 141];
    b[140] = 5;
    cases.push(b);
    for prefix in [253u8, 254, 255] {
        let mut b = vec![0; 141];
        b[140] = prefix;
        cases.push(b);
    }
    for b in cases {
        let result = std::panic::catch_unwind(|| parse_block(&b, BranchId::Nu6_3));
        assert!(result.is_ok());
        assert!(result.unwrap().is_err());
    }
}
fn tx(inputs: Vec<([u8; 32], u32, Vec<u8>)>, outputs: Vec<Vec<u8>>) -> Transaction {
    let b = Bundle {
        vin: inputs
            .into_iter()
            .map(|(h, n, s)| {
                TxIn::from_parts(
                    OutPoint::new(h, n),
                    crate::script_from_raw(&s).unwrap(),
                    u32::MAX,
                )
            })
            .collect(),
        vout: outputs
            .into_iter()
            .map(|s| {
                TxOut::new(
                    crate::zat(546).unwrap(),
                    crate::script_from_raw(&s).unwrap(),
                )
            })
            .collect(),
        authorization: bundle::Authorized,
    };
    TransactionData::<Authorized>::from_parts_v6(
        BranchId::Nu6_3,
        0,
        BlockHeight::from_u32(100),
        Some(b),
        None,
        None,
        None,
    )
    .freeze()
    .unwrap()
}
fn output() -> Vec<u8> {
    script_bytes(&key().address().script().into())
}
#[test]
fn merged_carriers_remain_tracked_through_next_spend_and_database() {
    let mut st = State::default();
    let mut ch = Changes::default();
    for n in [1, 2] {
        let ins = inscription(n, json!({}), 1, 1);
        st.carriers
            .entry(ins.owner.clone())
            .or_default()
            .insert(ins.id.clone());
        st.inscriptions.insert(ins.id.clone(), ins);
    }
    let t = tx(
        vec![([1; 32], 0, vec![]), ([2; 32], 0, vec![])],
        vec![output()],
    );
    let tid = t.txid().to_string();
    apply_transaction(
        &mut st,
        &mut ch,
        &tid,
        &t,
        2,
        &"11".repeat(32),
        Net::Regtest,
        None,
    )
    .unwrap();
    let carrier = format!("{tid}:0");
    assert_eq!(st.carriers[&carrier].len(), 2);
    assert!(st.single_carrier(&carrier).is_none());
    let dir = std::env::temp_dir().join(format!("overstory-test-{}-merge", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("state.sqlite");
    let mut db = Db::open(path.to_str().unwrap()).unwrap();
    db.apply(&st, &ch).unwrap();
    assert_eq!(db.load().unwrap().carriers[&carrier].len(), 2);
    let t2 = tx(
        vec![(crate::txid_bytes(&tid).unwrap(), 0, vec![])],
        vec![output()],
    );
    let tid2 = t2.txid().to_string();
    apply_transaction(
        &mut st,
        &mut ch,
        &tid2,
        &t2,
        2,
        &"11".repeat(32),
        Net::Regtest,
        None,
    )
    .unwrap();
    db.apply(&st, &ch).unwrap();
    let loaded = db.load().unwrap();
    assert!(!loaded.carriers.contains_key(&carrier));
    assert_eq!(loaded.carriers[&format!("{tid2}:0")].len(), 2);
    drop(db);
    std::fs::remove_file(path).unwrap();
}
#[test]
fn genesis_requires_output_zero_not_next_nondata_output() {
    let content = b"hello";
    let c = commitment(b"text/plain", content);
    let r = redeem_script(&key().pk.serialize(), &c, 1);
    let script = script_sig(b"text/plain", 1, &[(0, content)], &[1; 72], &r);
    let parent = script_bytes(&TransparentAddress::ScriptHash(hash160(&r)).script().into());
    let t = tx(vec![([7; 32], 0, script)], vec![vec![0x6a], output()]);
    let mut st = State::default();
    apply_transaction(
        &mut st,
        &mut Changes::default(),
        &t.txid().to_string(),
        &t,
        1,
        &"11".repeat(32),
        Net::Regtest,
        Some(&parent),
    )
    .unwrap();
    assert!(st.inscriptions.is_empty());
}
#[test]
fn actual_parent_script_is_required_for_v1() {
    let content = b"hello";
    let c = commitment(b"text/plain", content);
    let r = redeem_script(&key().pk.serialize(), &c, 1);
    let script = script_sig(b"text/plain", 1, &[(0, content)], &[1; 72], &r);
    let parent = script_bytes(&TransparentAddress::ScriptHash(hash160(&r)).script().into());
    let t = tx(vec![([7; 32], 0, script)], vec![output()]);
    for (parent, expected) in [
        (Some(parent.as_slice()), "v1"),
        (None, "legacy"),
        (Some([0x51].as_slice()), "legacy"),
    ] {
        let mut st = State::default();
        apply_transaction(
            &mut st,
            &mut Changes::default(),
            &t.txid().to_string(),
            &t,
            1,
            &"11".repeat(32),
            Net::Regtest,
            parent,
        )
        .unwrap();
        assert_eq!(st.inscriptions.values().next().unwrap().family, expected);
    }
}
#[test]
fn old_schema_is_refused_without_deleting_orders() {
    let dir = std::env::temp_dir().join(format!("overstory-test-{}-old", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let p = dir.join("old.sqlite");
    let conn = Connection::open(&p).unwrap();
    conn.execute_batch("CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY,v TEXT); CREATE TABLE IF NOT EXISTS kv(ns TEXT,k TEXT,json TEXT);").unwrap();
    conn.execute("INSERT INTO kv VALUES('orders','keep','{}')", [])
        .unwrap();
    drop(conn);
    assert!(Db::open(p.to_str().unwrap()).is_err());
    let conn = Connection::open(&p).unwrap();
    assert_eq!(
        conn.query_row("SELECT count(*) FROM kv", [], |r| r.get::<_, u32>(0))
            .unwrap(),
        1
    );
    drop(conn);
    std::fs::remove_file(p).unwrap();
}

#[test]
fn inscription_ids_reject_unicode_without_panicking() {
    for s in ["é".repeat(32) + "i0", "1".repeat(63) + "é" + "0"] {
        assert!(!inscription_id(&s));
    }
}
#[test]
fn multi_reveal_roundtrip_and_invalid_continuation() {
    let content = vec![b'a'; 1276];
    let parts = crate::inscribe::pieces_of(&content);
    let c = commitment(b"text/plain", &content);
    let mut state = State::default();
    let mut ch = Changes::default();
    let mut prev = ([9u8; 32], 0);
    let mut first_id = String::new();
    for (step, indices) in [vec![5, 4, 3, 2], vec![1, 0]].into_iter().enumerate() {
        let r = redeem_script(&key().pk.serialize(), &c, indices.len());
        let ps: Vec<_> = indices.iter().map(|i| (*i, parts[*i])).collect();
        let ss = script_sig(b"text/plain", 6, &ps, &[1; 72], &r);
        let parent = script_bytes(&TransparentAddress::ScriptHash(hash160(&r)).script().into());
        let next = if step == 0 {
            let next_r = redeem_script(&key().pk.serialize(), &c, 2);
            script_bytes(
                &TransparentAddress::ScriptHash(hash160(&next_r))
                    .script()
                    .into(),
            )
        } else {
            output()
        };
        let t = tx(vec![(prev.0, prev.1, ss)], vec![next]);
        let tid = t.txid().to_string();
        if step == 0 {
            first_id = format!("{tid}i0");
        }
        apply_transaction(
            &mut state,
            &mut ch,
            &tid,
            &t,
            10 + step as u32,
            &format!("{:02x}", 10 + step).repeat(32),
            Net::Regtest,
            Some(&parent),
        )
        .unwrap();
        prev = (crate::txid_bytes(&tid).unwrap(), 0);
    }
    let i = &state.inscriptions[&first_id];
    assert_eq!(hex::decode(&i.content_hex).unwrap(), content);
    assert_eq!(i.family, "v1");
    assert_eq!(i.genesis_height, 10);
    assert_eq!(i.completion_height, 11);
    assert_ne!(i.genesis_block_hash, i.completion_block_hash);
    assert!(state.pending.is_empty());
}
#[test]
fn malformed_continuation_spend_removes_pending() {
    let mut st = State::default();
    st.pending
        .insert(format!("{}:0", "09".repeat(32)), Pending::default());
    let t = tx(vec![([9; 32], 0, vec![0x51])], vec![output()]);
    apply_transaction(
        &mut st,
        &mut Changes::default(),
        &t.txid().to_string(),
        &t,
        2,
        &"11".repeat(32),
        Net::Regtest,
        None,
    )
    .unwrap();
    assert!(st.pending.is_empty());
}
#[test]
fn continuation_cannot_start_at_middle_piece() {
    let ss = envelope(b"text/plain", 3, &[(1, &[1; 240]), (0, &[1; 240])]);
    let t = tx(vec![([7; 32], 0, ss)], vec![output()]);
    let mut st = State::default();
    apply_transaction(
        &mut st,
        &mut Changes::default(),
        &t.txid().to_string(),
        &t,
        2,
        &"11".repeat(32),
        Net::Regtest,
        None,
    )
    .unwrap();
    assert!(st.pending.is_empty());
    assert!(st.inscriptions.is_empty());
}
#[test]
fn carrier_without_nondat_output_burns_all_members() {
    let mut st = State::default();
    for n in [1, 2] {
        let mut i = inscription(n, json!({}), 1, 1);
        i.owner = format!("{}:0", "09".repeat(32));
        st.carriers
            .entry(i.owner.clone())
            .or_default()
            .insert(i.id.clone());
        st.inscriptions.insert(i.id.clone(), i);
    }
    let t = tx(vec![([9; 32], 0, vec![])], vec![vec![0x6a]]);
    apply_transaction(
        &mut st,
        &mut Changes::default(),
        &t.txid().to_string(),
        &t,
        2,
        &"11".repeat(32),
        Net::Regtest,
        None,
    )
    .unwrap();
    assert!(st.carriers.is_empty());
    assert!(st.inscriptions.values().all(|i| i.owner == "burned"));
}

#[test]
fn corrupt_height_does_not_reset_index_to_zero() {
    let db = Db::open(":memory:").unwrap();
    db.conn
        .execute("INSERT INTO meta(k,v) VALUES('height','broken')", [])
        .unwrap();
    assert!(db.load().is_err());
}

#[test]
fn index_resume_cannot_skip_history_when_start_configuration_changes() {
    let mut state = State::default();
    assert_eq!(next_index_height(&state, 0).unwrap(), 1);
    // Existing explicitly scoped fixtures may start empty at a later block.
    assert_eq!(next_index_height(&state, 100).unwrap(), 100);
    state.height = 100;
    state.tip_hash = Some("ab".repeat(32));
    assert_eq!(next_index_height(&state, 0).unwrap(), 101);
    assert_eq!(next_index_height(&state, 101).unwrap(), 101);
    assert!(next_index_height(&state, 102).is_err());
    state.height = 0;
    assert!(next_index_height(&state, 2).is_err());
    state.height = u32::MAX;
    assert!(next_index_height(&state, 0).is_err());
}

#[test]
fn replay_provenance_never_upgrades_existing_or_partial_history() {
    let empty=State::default();
    let mut next=empty.clone(); next.record_replay_start(&empty,1);
    assert_eq!(next.history_scope(),"from_first_block");
    next.record_replay_start(&empty,100); next.height=100; next.tip_hash=Some("ab".repeat(32)); next.network=Some("regtest".into());
    let mut resumed=next.clone(); resumed.record_replay_start(&next,101);
    assert_eq!(resumed.replay_from,Some(100)); assert_eq!(resumed.history_scope(),"partial");
    let mut legacy=next.clone();legacy.replay_from=None;
    let mut resumed=legacy.clone();resumed.record_replay_start(&legacy,101);
    assert_eq!(resumed.history_scope(),"unknown");
    let mut dirty=empty.clone(); dirty.pending.insert("existing".into(),Pending::default());
    let mut resumed=dirty.clone();resumed.record_replay_start(&dirty,1);
    assert_eq!(resumed.replay_from,None);
}
#[test]
fn replay_provenance_is_persistent_and_corruption_is_rejected() {
    let mut db=Db::open(":memory:").unwrap();
    let st=State{height:100,tip_hash:Some("ab".repeat(32)),network:Some("regtest".into()),replay_from:Some(90),..Default::default()};
    db.apply(&st,&Changes::default()).unwrap();
    assert_eq!(db.load().unwrap().replay_from,Some(90));
    for invalid in ["0","101","invalid"] {
        db.conn.execute("UPDATE meta SET v=?1 WHERE k='replay_from'",[invalid]).unwrap();
        assert!(db.load().is_err());
    }
    db.conn.execute("DELETE FROM meta WHERE k='replay_from'",[]).unwrap();
    assert_eq!(db.load().unwrap().history_scope(),"unknown");
}

#[test]
fn old_writer_cannot_preserve_stale_replay_provenance() {
    for mutation in ["UPDATE meta SET v='101' WHERE k='height'", "UPDATE meta SET v='cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd' WHERE k='tip_hash'", "DELETE FROM meta WHERE k='replay_tip_height'"] {
        let mut db=Db::open(":memory:").unwrap();
        let st=State{height:100,tip_hash:Some("ab".repeat(32)),network:Some("regtest".into()),replay_from:Some(1),..Default::default()};
        db.apply(&st,&Changes::default()).unwrap();assert_eq!(db.load().unwrap().history_scope(),"from_first_block");
        db.conn.execute_batch(mutation).unwrap();
        assert_eq!(db.load().unwrap().history_scope(),"unknown");
    }
}


fn authenticated_envelope(ct: &[u8], content: &[u8], total: usize, pieces: &[(usize, &[u8])]) -> Vec<u8> {
    let redeem = authenticated_redeem_script(&key().pk.serialize(), &commitment(ct, content), ct, total, pieces);
    script_sig(ct, total, pieces, &[1;72], &redeem)
}

#[test]
fn authenticated_push_semantics_and_mutations() {
    let script = authenticated_envelope(b"text/plain", b"hello", 1, &[(0,b"hello")]);
    let env = parse_envelope(&script).unwrap();
    assert!(env.authenticated);
    let items = consensus_pushes(&script).unwrap();
    assert!(items[3].is_empty());
    // PUSHDATA4 has identical executed bytes, including the empty index-zero push.
    let mut alternate = Vec::new();
    for item in &items {
        alternate.push(0x4e);
        alternate.extend_from_slice(&(item.len() as u32).to_le_bytes());
        alternate.extend_from_slice(item);
    }
    assert!(parse_envelope(&alternate).unwrap().authenticated);
    for item in 0..5 {
        let mut changed = items.clone();
        if changed[item].is_empty() { changed[item].push(1); } else { changed[item][0] ^= 1; }
        let mut s = Vec::new();
        for data in changed { crate::inscribe::push_bytes(&mut s,&data); }
        assert!(!parse_envelope(&s).is_some_and(|e| e.authenticated), "item {item}");
    }
    // A nonempty zero is numerically equivalent but hashes differently: never authenticate it.
    let mut changed = items.clone(); changed[3] = vec![0];
    let mut s=Vec::new(); for data in changed { crate::inscribe::push_bytes(&mut s,&data); }
    assert!(!parse_envelope(&s).is_some_and(|e| e.authenticated));
}

#[test]
fn authenticated_does_not_use_standardness_size_limit() {
    let content = vec![b'a';960];
    let parts: Vec<_> = content.chunks(240).enumerate().rev().collect();
    let mut ct=b"text/".to_vec(); ct.extend(vec![b'a';91]);
    let script = authenticated_envelope(&ct, &content, 4, &parts);
    let items = consensus_pushes(&script).unwrap();
    // Maximum content-type and four full pieces cross 1650 with equivalent
    // PUSHDATA4 pushes, while every pushed element remains within consensus limits.
    let mut script=Vec::new();
    for item in &items {
        script.push(0x4e); script.extend_from_slice(&(item.len() as u32).to_le_bytes()); script.extend(item);
    }
    assert!(script.len()>1650);
    assert!(parse_envelope(&script).unwrap().authenticated);
}

#[test]
fn authenticated_collection_rejects_unauthenticated_mint_and_renderer() {
    let mut st=State::default(); let mut ch=Changes::default();
    let mut d=inscription(1,declaration(),10,20); d.authenticated=true;
    apply_declaration(&mut st,&mut ch,&d,&[],Net::Regtest);
    assert!(st.collections[&id(1)].authenticated);
    mint(&mut st,&mut ch,2,21,100000);
    assert!(st.mints.is_empty());
    let mut m=inscription(3,json!({"p":"overstory","op":"mint","d":id(1)}),21,21); m.authenticated=true;
    apply_declaration(&mut st,&mut ch,&m,&[(Some(addr()),100000)],Net::Regtest);
    assert_eq!(st.mints.len(),1);
    let mut renderer=inscription(8,json!({}),1,2);
    renderer.content_type="text/javascript".into();
    st.inscriptions.insert(id(8),renderer.clone());
    let mut dec=declaration(); dec["renderer"]=json!(id(8));
    let mut d=inscription(9,dec,10,20); d.authenticated=true;
    apply_declaration(&mut st,&mut ch,&d,&[],Net::Regtest);
    assert!(!st.collections.contains_key(&id(9)));
    renderer.authenticated=true; st.inscriptions.insert(id(8),renderer);
    apply_declaration(&mut st,&mut ch,&d,&[],Net::Regtest);
    assert!(st.collections[&id(9)].authenticated);
}

#[test]
fn authentication_is_preserved_only_across_fully_proven_reveals() {
    for authenticated_steps in [[true,true],[true,false],[false,true]] {
        let content=vec![b'a';480]; let parts=crate::inscribe::pieces_of(&content);
        let c=commitment(b"text/plain",&content); let mut st=State::default();
        let mut prev=([9;32],0); let mut first=String::new();
        for step in 0..2 {
            let ps=[(1-step,parts[1-step])];
            let r=if authenticated_steps[step] { authenticated_redeem_script(&key().pk.serialize(),&c,b"text/plain",2,&ps) }
                else { redeem_script(&key().pk.serialize(),&c,1) };
            let parent=script_bytes(&TransparentAddress::ScriptHash(hash160(&r)).script().into());
            let t=tx(vec![(prev.0,prev.1,script_sig(b"text/plain",2,&ps,&[1;72],&r))],vec![output()]);
            let tid=t.txid().to_string(); if step==0 { first=format!("{tid}i0"); }
            apply_transaction(&mut st,&mut Changes::default(),&tid,&t,10+step as u32,&"11".repeat(32),Net::Regtest,Some(&parent)).unwrap();
            prev=(crate::txid_bytes(&tid).unwrap(),0);
        }
        let ins=&st.inscriptions[&first];
        assert_eq!(ins.family,"v1");
        assert_eq!(ins.authenticated,authenticated_steps.iter().all(|v|*v));
    }
}

#[test]
fn absent_authentication_fields_preserve_historical_serialization() {
    let old=inscription(1,declaration(),10,20);
    let value=serde_json::to_value(&old).unwrap();
    assert!(value.get("authenticated").is_none());
    assert!(!serde_json::from_value::<Inscription>(value).unwrap().authenticated);
    let pending=serde_json::to_value(Pending::default()).unwrap();
    assert!(pending.get("authenticated").is_none());
    assert!(!serde_json::from_value::<Pending>(pending).unwrap().authenticated);
}


#[test]
fn authenticated_envelope_still_requires_actual_parent_script() {
    let ss=authenticated_envelope(b"text/plain",b"hello",1,&[(0,b"hello")]);
    let pushes=consensus_pushes(&ss).unwrap();
    let parent=script_bytes(&TransparentAddress::ScriptHash(hash160(pushes.last().unwrap())).script().into());
    let t=tx(vec![([7;32],0,ss)],vec![output()]);
    for (parent,expected) in [(Some(parent.as_slice()),true),(None,false),(Some([0x51].as_slice()),false)] {
        let mut st=State::default();
        apply_transaction(&mut st,&mut Changes::default(),&t.txid().to_string(),&t,1,&"11".repeat(32),Net::Regtest,parent).unwrap();
        assert_eq!(st.inscriptions.values().next().unwrap().authenticated,expected);
    }
}

#[test]
fn pre_authenticated_schema_is_refused_and_preserved() {
    for version in ["2", "3"] {
        let dir=std::env::temp_dir().join(format!("overstory-schema-{}-{}",std::process::id(),version));
        std::fs::create_dir_all(&dir).unwrap();let path=dir.join("index.sqlite");
        {let db=Db::open(path.to_str().unwrap()).unwrap();
         db.conn.execute("UPDATE meta SET v=?1 WHERE k='schema_version'",[version]).unwrap();
         db.kv_put("orders","preserve",&serde_json::json!({"paid":true})).unwrap();}
        let before=std::fs::read(&path).unwrap();
        let err=Db::open(path.to_str().unwrap()).err().unwrap().to_string();
        assert!(err.contains("new directory"));assert!(err.contains("do not delete order records"));
        assert_eq!(std::fs::read(&path).unwrap(),before);
        {let conn=Connection::open(&path).unwrap();
         assert_eq!(conn.query_row("SELECT count(*) FROM kv WHERE ns='orders'",[],|r|r.get::<_,u32>(0)).unwrap(),1);
         assert!(Db::load_from(&conn).is_err());}
        std::fs::remove_dir_all(dir).unwrap();
    }
}
