use super::*;
use zcash_protocol::consensus::{NetworkUpgrade, Parameters};
fn key(n: u8) -> Key {
    Key::from_secret(&[n; 32]).unwrap()
}
fn fixture(net: index::Net, target: u32) -> (Listing, Key, Utxo) {
    let seller = key(1);
    let buyer = key(2);
    let mut l = Listing {
        version: 2,
        network: net.name().into(),
        branch: network::branch_name(net.branch_for(target)).into(),
        carrier_txid: "11".repeat(32),
        carrier_vout: 0,
        carrier_value: 546,
        carrier_script: hex::encode(index::script_bytes(&seller.address().script().into())),
        seller_pubkey: hex::encode(seller.pk.serialize()),
        payout_address: seller.address_string(net),
        price_zat: 100_000,
        expiry_height: target + 20,
        slot: 1,
        signature_der: String::new(),
    };
    let signer = Signer::new(listing_template_pczt(&l, &seller.pk, target).unwrap()).unwrap().with_transparent_sighash_policy(LISTING_SIGHASH_POLICY);
    let h = signer.transparent_sighash(1).unwrap();
    let sig = secp256k1::ecdsa::sign(Message::from_digest(h), &seller.sk);
    l.signature_der = hex::encode(sig.serialize_der());
    let u = Utxo {
        txid: "22".repeat(32),
        n: 0,
        script: hex::encode(index::script_bytes(&buyer.address().script().into())),
        value: 1_000_000,
        height: target - 1,
    };
    (l, buyer, u)
}
#[test]
fn all_network_epochs_match_browser_digest_and_build_atomic_purchase() {
    let mut vectors = vec![];
    for net in [
        index::Net::Regtest,
        index::Net::Testnet,
        index::Net::Mainnet,
    ] {
        for upgrade in [
            NetworkUpgrade::Nu5,
            NetworkUpgrade::Nu6,
            NetworkUpgrade::Nu6_1,
            NetworkUpgrade::Nu6_2,
            NetworkUpgrade::Nu6_3,
            NetworkUpgrade::Nu7,
        ] {
            let Some(height) = net.activation_height(upgrade) else { continue };
            let target = u32::from(height) + 1;
            let (l, buyer, u) = fixture(net, target);
            let seller = key(1);
            let pczt = listing_template_pczt(&l, &seller.pk, target).unwrap();
            let h = Signer::new(pczt).unwrap().with_transparent_sighash_policy(LISTING_SIGHASH_POLICY).transparent_sighash(1).unwrap();
            let request = json!({"network":net.name(),"branch":l.branch,"carrier_txid":l.carrier_txid,"carrier_vout":l.carrier_vout,"carrier_value":l.carrier_value,"carrier_script":l.carrier_script,"payout_script":hex::encode(index::script_bytes(&seller.address().script().into())),"price_zat":l.price_zat,"expiry_height":l.expiry_height,"slot":l.slot});
            vectors.push(json!({"network":net.name(),"request":request,"expected":hex::encode(h)}));
            assert_eq!(
                hex::encode(h),
                overstory_sighash::digest_json(&request.to_string()).unwrap(),
                "{} {}",
                net.name(),
                l.branch
            );
            let tx = build_purchase(
                net,
                target,
                &l,
                &buyer,
                &[u.clone()],
                &buyer.address_string(net),
                &buyer.address(),
                vec![],
                20_000,
            )
            .unwrap();
            assert_eq!(tx.consensus_branch_id(), net.branch_for(target));
            assert_eq!(
                tx.version(),
                zcash_primitives::transaction::TxVersion::suggested_for_branch(
                    net.branch_for(target)
                )
            );
            let browser_request = json!({"listing":l,"funding":[u],"destination_script":hex::encode(index::script_bytes(&buyer.address().script().into())),"payout_script":hex::encode(index::script_bytes(&seller.address().script().into())),"max_price_zat":l.price_zat,"max_fee_zat":20_000,"target_height":target});
            let browser: Value = serde_json::from_str(
                &overstory_sighash::purchase::build(
                    &browser_request.to_string(),
                    &buyer.secret_hex(),
                )
                .unwrap(),
            )
            .unwrap();
            let mut native_raw = vec![];
            tx.write(&mut native_raw).unwrap();
            assert_eq!(browser["raw_transaction"], hex::encode(native_raw));
            if let Some(v) = vectors.last_mut() {
                v["purchase_request"] = browser_request;
                v["test_secret"] = json!(buyer.secret_hex());
                v["purchase_txid"] = browser["txid"].clone();
            }
            let b = tx.transparent_bundle().unwrap();
            assert_eq!(b.vin.len(), 2);
            assert_eq!(b.vout[0].value().into_u64(), 546);
            assert_eq!(b.vout[0].script_pubkey(), &buyer.address().script().into());
            assert_eq!(b.vout[1].value().into_u64(), l.price_zat);
            assert_eq!(b.vout[1].script_pubkey(), &seller.address().script().into());
            let fee = u.value + 546 - b.vout.iter().map(|o| o.value().into_u64()).sum::<u64>();
            assert!(fee <= 20_000);
            let mut raw = vec![];
            tx.write(&mut raw).unwrap();
            assert_eq!(
                Transaction::read(&raw[..], net.branch_for(target))
                    .unwrap()
                    .txid(),
                tx.txid()
            );
        }
    }
    if let Ok(path) = std::env::var("OVERSTORY_DIGEST_VECTORS") {
        fs::write(path, serde_json::to_vec_pretty(&vectors).unwrap()).unwrap();
    }
}
#[test]
fn malicious_listing_and_funding_are_rejected() {
    let net = index::Net::Regtest;
    let (l, b, u) = fixture(net, 100);
    let run = |l: &Listing, us: &[Utxo], fee| {
        build_purchase(
            net,
            100,
            l,
            &b,
            us,
            &b.address_string(net),
            &b.address(),
            vec![],
            fee,
        )
    };
    assert!(run(&l, &[u.clone()], 1).is_err());
    assert!(run(&l, &[u.clone(), u.clone()], 50_000).is_err());
    let mut bad = u.clone();
    bad.txid = l.carrier_txid.clone();
    assert!(run(&l, &[bad], 50_000).is_err());
    let mut bad = u.clone();
    bad.script = "51".into();
    assert!(run(&l, &[bad], 50_000).is_err());
    for change in 0..8 {
        let mut x = l.clone();
        match change {
            0 => x.slot = usize::MAX,
            1 => x.network = "mainnet".into(),
            2 => x.branch = "nu6_2".into(),
            3 => x.price_zat = u64::MAX,
            4 => x.price_zat += 1,
            5 => x.carrier_value += 1,
            6 => x.payout_address = b.address_string(net),
            _ => x.version = 1,
        };
        assert!(run(&x, &[u.clone()], 50_000).is_err(), "mutation {change}");
    }
}
#[test]
fn paid_mint_preflight_requires_exact_collection_payment() {
    let net = index::Net::Regtest;
    let dest = key(2).address_string(net);
    let mut c = index::Collection { authenticated: false,
        id: "x".into(),
        name: "x".into(),
        supply: 3,
        max_per_addr: 1,
        price: 10_000,
        pay: key(1).address_string(net),
        start: 100,
        renderer: String::new(),
        deployed_height: 99,
        minted: 0,
        per_addr: Default::default(),
    };
    assert!(validate_mint_request(&c, &dest, net, 100, None, None).is_ok());
    assert!(validate_mint_request(&c, &dest, net, 100, Some(&c.pay), Some("10000")).is_ok());
    assert!(validate_mint_request(&c, &dest, net, 100, Some(&c.pay), Some("0")).is_err());
    assert!(validate_mint_request(&c, &dest, net, 100, Some(&dest), Some("10000")).is_err());
    assert!(validate_mint_request(&c, &dest, net, 100, None, Some("10000")).is_err());
    assert!(validate_mint_request(&c, &dest, net, 99, None, None).is_err());
    c.minted = 3;
    assert!(validate_mint_request(&c, &dest, net, 100, None, None).is_err());
    c.minted = 0;
    c.per_addr.insert(dest.clone(), 1);
    assert!(validate_mint_request(&c, &dest, net, 100, None, None).is_err());
    c.max_per_addr = 0;
    assert!(validate_mint_request(&c, &dest, net, 100, None, None).is_ok());
}

#[test]
fn production_mint_requires_authenticated_collection_before_payment() {
    let key=Key::from_secret(&[21;32]).unwrap();
    let addr=key.address_string(index::Net::Mainnet);
    let mut col=index::Collection{authenticated:false,id:"test".into(),name:"test".into(),supply:3000,max_per_addr:0,price:5_000_000,pay:addr.clone(),start:1,renderer:"test".into(),deployed_height:1,minted:0,per_addr:Default::default()};
    let err=validate_mint_request(&col,&addr,index::Net::Mainnet,2,None,None).unwrap_err();
    assert!(err.to_string().contains("authenticated"));
    col.authenticated=true;
    validate_mint_request(&col,&addr,index::Net::Mainnet,2,None,None).unwrap();
}

#[test]
fn official_market_fee_matches_browser_and_preserves_seller_signature() {
    let net = index::Net::Regtest;
    let (l, buyer, u) = fixture(net, 100);
    let recipient = key(3);
    let tx = build_market_purchase(net, 100, &l, &buyer, &[u.clone()],
        &buyer.address_string(net), &buyer.address(), &recipient.address_string(net),
        2_000, 25_000).unwrap();
    let request = json!({"listing":l,"funding":[u],
        "destination_script":hex::encode(index::script_bytes(&buyer.address().script().into())),
        "payout_script":hex::encode(index::script_bytes(&key(1).address().script().into())),
        "max_price_zat":l.price_zat,"max_fee_zat":25_000,"target_height":100,
        "market_fee":{"recipient_script":hex::encode(index::script_bytes(&recipient.address().script().into())),"max_amount_zat":2_000}});
    let browser: Value = serde_json::from_str(&overstory_sighash::purchase::build(
        &request.to_string(), &buyer.secret_hex()).unwrap()).unwrap();
    let mut raw = vec![]; tx.write(&mut raw).unwrap();
    assert_eq!(browser["raw_transaction"],hex::encode(raw));
    let out = &tx.transparent_bundle().unwrap().vout;
    assert_eq!(out[1].value().into_u64(), l.price_zat);
    assert_eq!(out[2].value().into_u64(), 2_000);
    assert_eq!(out[2].script_pubkey(), &recipient.address().script().into());
    assert_eq!(browser["market_fee_zat"], 2_000);
    let mut st=index::State::default();
    let inscription="44".repeat(32)+"i0";
    let collection="55".repeat(32)+"i0";
    st.carriers.insert(format!("{}:{}",l.carrier_txid,l.carrier_vout),std::collections::BTreeSet::from([inscription.clone()]));
    st.mints.insert(inscription.clone(),index::Mint{inscription,collection:collection.clone(),number:1,minter:"test".into(),height:1,seed:"66".repeat(32)});
    let recipient_address=recipient.address_string(net);
    let validate=|tx:&Transaction| {let mut b=vec![];tx.write(&mut b).unwrap();crate::market_relay::validate_with_fee(&hex::encode(b),net,100,&l,&st,&collection,&recipient_address)};
    assert!(validate(&tx).is_ok());
    for (amount,to) in [(1_999,recipient.address()),(2_001,recipient.address()),(2_000,buyer.address())] {
        let bad=build_purchase(net,100,&l,&buyer,&[u.clone()],&buyer.address_string(net),&buyer.address(),vec![OutputSpec{to,value:amount}],25_000).unwrap();
        assert!(validate(&bad).is_err());
    }
    let missing=build_purchase(net,100,&l,&buyer,&[u.clone()],&buyer.address_string(net),&buyer.address(),vec![],25_000).unwrap();
    assert!(validate(&missing).is_err());

    let mut denied = request.clone(); denied["market_fee"]["max_amount_zat"] = json!(1_999);
    assert!(overstory_sighash::purchase::build(&denied.to_string(), &buyer.secret_hex()).is_err());
    denied = request.clone(); denied["market_fee"]["recipient_script"] = json!("6a");
    assert!(overstory_sighash::purchase::build(&denied.to_string(), &buyer.secret_hex()).is_err());
    assert!(build_market_purchase(net,100,&l,&buyer,&[u],&buyer.address_string(net),
        &buyer.address(),&recipient.address_string(net),1_999,25_000).is_err());
}
