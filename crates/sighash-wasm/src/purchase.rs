//! Transparent-only atomic purchases, constructed and signed locally.
use super::*;
use secp256k1::{Message, PublicKey, SecretKey, ecdsa::Signature};
use serde_json::json;
use zcash_primitives::transaction::Authorized;
use zcash_protocol::consensus::{MAIN_NETWORK, TEST_NETWORK};
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Listing {
    version: u32,
    network: String,
    branch: String,
    carrier_txid: String,
    carrier_vout: u32,
    carrier_value: u64,
    carrier_script: String,
    seller_pubkey: String,
    payout_address: String,
    price_zat: u64,
    expiry_height: u32,
    slot: usize,
    signature_der: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Funding {
    txid: String,
    n: u32,
    script: String,
    value: u64,
    height: u32,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MarketFee {
    recipient_script: String,
    max_amount_zat: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    listing: Listing,
    funding: Vec<Funding>,
    destination_script: String,
    payout_script: String,
    max_price_zat: u64,
    max_fee_zat: u64,
    target_height: u32,
    #[serde(default)]
    market_fee: Option<MarketFee>,
}
fn ensure(ok: bool, why: &str) -> Result<(), String> {
    if ok { Ok(()) } else { Err(why.into()) }
}
fn decode(s: &str) -> Result<Vec<u8>, String> {
    hex::decode(s).map_err(|e| e.to_string())
}
fn point(id: &str, n: u32) -> Result<OutPoint, String> {
    let mut b = decode(id)?;
    b.reverse();
    Ok(OutPoint::new(b.try_into().map_err(|_| "bad txid")?, n))
}
fn push(s: &mut Vec<u8>, v: &[u8]) {
    s.push(v.len() as u8);
    s.extend_from_slice(v);
}
fn branch(l: &Listing, target: u32) -> Result<BranchId, String> {
    ensure(
        target > 0 && l.expiry_height >= target && l.expiry_height < 500_000_000,
        "invalid height window",
    )?;
    epoch_guard::check(&l.network, l.expiry_height)?;
    let at = |h| match l.network.as_str() {
        "mainnet" => Ok(BranchId::for_height(
            &MAIN_NETWORK,
            BlockHeight::from_u32(h),
        )),
        "testnet" => Ok(BranchId::for_height(
            &TEST_NETWORK,
            BlockHeight::from_u32(h),
        )),
        "regtest" => Ok(BranchId::Nu6_3),
        _ => Err("unknown network".to_string()),
    };
    let b = at(target)?;
    ensure(at(l.expiry_height)? == b, "expiry crosses upgrade")?;
    let name = match b {
        BranchId::Nu5 => "nu5",
        BranchId::Nu6 => "nu6",
        BranchId::Nu6_1 => "nu6_1",
        BranchId::Nu6_2 => "nu6_2",
        BranchId::Nu6_3 => "nu6_3",
        BranchId::Nu7 => "nu7",
        _ => return Err("unsupported epoch".into()),
    };
    ensure(name == l.branch, "listing epoch mismatch")?;
    Ok(b)
}
pub fn build(json_text: &str, secret: &str) -> Result<String, String> {
    let r: Request = serde_json::from_str(json_text).map_err(|e| e.to_string())?;
    let l = &r.listing;
    ensure(
        l.version == 2 && l.slot == 1 && l.carrier_value == 546,
        "unsupported listing shape",
    )?;
    ensure(
        l.price_zat > 0 && l.price_zat <= r.max_price_zat,
        "price exceeds approval",
    )?;
    zat(l.price_zat)?;
    ensure(
        !r.funding.is_empty() && r.funding.len() <= 20,
        "unsupported funding count",
    )?;
    let branch = branch(l, r.target_height)?;
    let sk = SecretKey::from_secret_bytes(decode(secret)?.try_into().map_err(|_| "secret must be 32 bytes")?).map_err(|e| e.to_string())?;
    let pk = PublicKey::from_secret_key(&sk);
    let buyer_script: Script = TransparentAddress::from_pubkey(&pk).script().into();
    let seller = PublicKey::from_slice(&decode(&l.seller_pubkey)?).map_err(|e| e.to_string())?;
    let seller_script: Script = TransparentAddress::from_pubkey(&seller).script().into();
    let payout = script(&decode(&r.payout_script)?)?;
    ensure(
        payout == seller_script && script(&decode(&l.carrier_script)?)? == seller_script,
        "seller scripts mismatch",
    )?;
    let nt = match l.network.as_str() {
        "mainnet" => zcash_protocol::consensus::NetworkType::Main,
        "testnet" => zcash_protocol::consensus::NetworkType::Test,
        _ => zcash_protocol::consensus::NetworkType::Regtest,
    };
    ensure(
        TransparentAddress::from_pubkey(&seller)
            .to_zcash_address(nt)
            .encode()
            == l.payout_address,
        "payout address mismatch",
    )?;
    let dest = script(&decode(&r.destination_script)?)?;
    // Current browser flow receives and changes to its own vault only.
    ensure(
        dest == buyer_script,
        "destination must be the signing vault",
    )?;
    let mut total = 546u64;
    let mut points = vec![];
    let mut amounts = vec![];
    let mut scripts = vec![];
    let carrier = point(&l.carrier_txid, l.carrier_vout)?;
    for u in &r.funding {
        ensure(
            u.height > 0 && u.height < r.target_height,
            "funding not confirmed",
        )?;
        let out = point(&u.txid, u.n)?;
        ensure(out != carrier && !points.contains(&out), "duplicate input")?;
        ensure(
            script(&decode(&u.script)?)? == buyer_script,
            "funding key mismatch",
        )?;
        total = total.checked_add(u.value).ok_or("input overflow")?;
        zat(total)?;
        points.push(out);
        amounts.push(zat(u.value)?);
        scripts.push(buyer_script.clone());
    }
    points.insert(1, carrier);
    amounts.insert(1, zat(546)?);
    scripts.insert(1, seller_script.clone());
    let market = if let Some(approved) = &r.market_fee {
        let quote = crate::market_fee::quote(l.price_zat)?;
        ensure(quote.market_fee_zat <= approved.max_amount_zat, "market fee exceeds approval")?;
        let raw = decode(&approved.recipient_script)?;
        ensure(raw.len() == 25 && raw[..3] == [0x76, 0xa9, 0x14]
            && raw[23..] == [0x88, 0xac], "market recipient must be P2PKH")?;
        Some((quote.market_fee_zat, script(&raw)?))
    } else { None };
    let market_zat = market.as_ref().map_or(0, |m| m.0);
    let fee = 5_000u64 * points.len().max(if market.is_some() {4} else {3}) as u64;
    let change = total
        .checked_sub(546 + l.price_zat)
        .and_then(|x| x.checked_sub(market_zat))
        .and_then(|x| x.checked_sub(fee))
        .ok_or("insufficient funds")?;
    let mut outputs = vec![
        TxOut::new(zat(546)?, dest),
        TxOut::new(zat(l.price_zat)?, payout),
    ];
    if let Some((amount, recipient)) = market { outputs.push(TxOut::new(zat(amount)?, recipient)); }
    if change >= 5_000 {
        outputs.push(TxOut::new(zat(change)?, buyer_script.clone()));
    }
    let actual_fee = if change >= 5_000 { fee } else { fee + change };
    ensure(actual_fee <= r.max_fee_zat, "network fee exceeds approval")?;
    let unsigned = TransactionData::<TxAuth>::from_parts(
        TxVersion::suggested_for_branch(branch),
        branch,
        0,
        BlockHeight::from_u32(l.expiry_height),
        Some(Bundle {
            vin: points
                .iter()
                .map(|p| TxIn::<Auth>::from_parts(p.clone(), (), u32::MAX))
                .collect(),
            vout: outputs.clone(),
            authorization: Auth {
                amounts: amounts.clone(),
                scripts: scripts.clone(),
            },
        }),
        None,
        None,
        None,
    );
    let bundle = unsigned.transparent_bundle().ok_or("bundle")?;
    let digests = unsigned.digest(TxIdDigester);
    let mut signed_inputs = vec![];
    for i in 0..points.len() {
        let ty = if i == 1 {
            SighashType::SINGLE_ANYONECANPAY
        } else {
            SighashType::ALL
        };
        let input = zcash_transparent::sighash::SignableInput::from_parts(
            bundle,
            ty,
            i,
            &scripts[i],
            &scripts[i],
            amounts[i],
        )
        .map_err(|e| format!("{e:?}"))?;
        let hash = signature_hash(&unsigned, &SignableInput::Transparent(input), &digests);
        let msg = Message::from_digest(*hash.as_ref());
        let sig = if i == 1 {
            let s = Signature::from_der(&decode(&l.signature_der)?).map_err(|e| e.to_string())?;
            secp256k1::ecdsa::verify(&s, msg, &seller)
                .map_err(|_| "invalid seller signature")?;
            s
        } else {
            secp256k1::ecdsa::sign(msg, &sk)
        };
        let mut sb = sig.serialize_der().to_vec();
        sb.push(ty.encode());
        let mut ss = vec![];
        push(&mut ss, &sb);
        push(
            &mut ss,
            &if i == 1 {
                seller.serialize()
            } else {
                pk.serialize()
            },
        );
        signed_inputs.push(TxIn::from_parts(points[i].clone(), script(&ss)?, u32::MAX));
    }
    let tx = TransactionData::<Authorized>::from_parts(
        TxVersion::suggested_for_branch(branch),
        branch,
        0,
        BlockHeight::from_u32(l.expiry_height),
        Some(Bundle {
            vin: signed_inputs,
            vout: outputs,
            authorization: bundle::Authorized,
        }),
        None,
        None,
        None,
    )
    .freeze()
    .map_err(|e| e.to_string())?;
    let mut raw = vec![];
    tx.write(&mut raw).map_err(|e| e.to_string())?;
    Ok(json!({"raw_transaction":hex::encode(raw),"txid":tx.txid().to_string(),"price_zat":l.price_zat,"market_fee_zat":market_zat,"fee_zat":actual_fee,"change_zat":if change>=5000{change}else{0}}).to_string())
}
#[wasm_bindgen]
pub fn sign_purchase(request: &str, secret: &str) -> Result<String, JsValue> {
    build(request, secret).map_err(|e| JsValue::from_str(&e))
}
