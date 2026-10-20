//! Browser-side ZIP 244 sighash for a listing: SIGHASH_SINGLE | ANYONECANPAY over
//! "carrier input at slot 1 -> payout output at slot 1". Same library code the service
//! uses, compiled to WebAssembly, so a seller can check the digest before signing it.
//!
//! The digest does not depend on the other inputs/outputs (ANYONECANPAY drops them, SINGLE
//! only commits to the output at the same index), so placeholders fill slot 0.

#[path = "../../epoch_guard.rs"]
mod epoch_guard;
#[path = "../../market_fee.rs"]
pub mod market_fee;
pub mod purchase;
use serde::Deserialize;
use wasm_bindgen::prelude::*;
use zcash_primitives::transaction::{
    Authorization, TransactionData, TxVersion,
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

#[derive(Debug)]
struct Auth {
    amounts: Vec<Zatoshis>,
    scripts: Vec<Script>,
}
impl bundle::Authorization for Auth {
    type ScriptSig = ();
}
impl TransparentAuthorizingContext for Auth {
    fn input_amounts(&self) -> Vec<Zatoshis> {
        self.amounts.clone()
    }
    fn input_scriptpubkeys(&self) -> Vec<Script> {
        self.scripts.clone()
    }
}
#[derive(Debug)]
struct TxAuth;
impl Authorization for TxAuth {
    type TransparentAuth = Auth;
    type SaplingAuth = sapling::bundle::Authorized;
    type OrchardAuth = orchard::bundle::Authorized;
}

#[derive(Deserialize)]
struct Req {
    network: String,
    /// Explicit epoch committed by the listing; unknown epochs are rejected.
    branch: String,
    /// display-order hex
    carrier_txid: String,
    carrier_vout: u32,
    carrier_value: u64,
    /// raw scriptPubKey hex of the carrier output
    carrier_script: String,
    /// raw scriptPubKey hex of the payout output
    payout_script: String,
    price_zat: u64,
    expiry_height: u32,
    slot: usize,
}

fn script(raw: &[u8]) -> Result<Script, String> {
    let mut buf = Vec::with_capacity(raw.len() + 3);
    match raw.len() {
        n if n < 253 => buf.push(n as u8),
        n if n <= 0xffff => {
            buf.push(0xfd);
            buf.extend_from_slice(&(n as u16).to_le_bytes());
        }
        _ => return Err("script too long".into()),
    }
    buf.extend_from_slice(raw);
    Script::read(&buf[..]).map_err(|e| e.to_string())
}

fn zat(v: u64) -> Result<Zatoshis, String> {
    Zatoshis::from_u64(v).map_err(|_| format!("bad amount {v}"))
}

fn digest(req: &Req) -> Result<String, String> {
    epoch_guard::check(&req.network, req.expiry_height)?;
    let branch = match req.branch.as_str() {
        "nu5" => BranchId::Nu5,
        "nu6" => BranchId::Nu6,
        "nu6_1" => BranchId::Nu6_1,
        "nu6_3" => BranchId::Nu6_3,
        "nu7" => BranchId::Nu7,
        "nu6_2" => BranchId::Nu6_2,
        other => return Err(format!("unsupported branch {other}")),
    };
    let expected = match req.network.as_str() {
        "mainnet" => BranchId::for_height(&zcash_protocol::consensus::MAIN_NETWORK, BlockHeight::from_u32(req.expiry_height)),
        "testnet" => BranchId::for_height(&zcash_protocol::consensus::TEST_NETWORK, BlockHeight::from_u32(req.expiry_height)),
        "regtest" => BranchId::Nu6_3,
        _ => return Err("unknown network".into()),
    };
    if req.expiry_height == 0 || req.expiry_height >= 500_000_000 || branch != expected {
        return Err("listing epoch/expiry mismatch".into());
    }
    if req.slot != 1 {
        return Err("slot must be 1".into());
    }
    let mut txid = hex::decode(&req.carrier_txid).map_err(|e| e.to_string())?;
    txid.reverse();
    let txid: [u8; 32] = txid.try_into().map_err(|_| "txid must be 32 bytes")?;
    let carrier_script = script(&hex::decode(&req.carrier_script).map_err(|e| e.to_string())?)?;
    let payout_script = script(&hex::decode(&req.payout_script).map_err(|e| e.to_string())?)?;
    // Placeholder slot 0 (never signed, never committed to under SINGLE|ANYONECANPAY).
    let ph_script: Script = TransparentAddress::PublicKeyHash([0u8; 20]).script().into();
    let vin = vec![
        TxIn::<Auth>::from_parts(OutPoint::new([0x11; 32], 0), (), u32::MAX),
        TxIn::<Auth>::from_parts(OutPoint::new(txid, req.carrier_vout), (), u32::MAX),
    ];
    let vout = vec![
        TxOut::new(zat(1_000)?, ph_script.clone()),
        TxOut::new(zat(req.price_zat)?, payout_script),
    ];
    let auth = Auth {
        amounts: vec![zat(1_000)?, zat(req.carrier_value)?],
        scripts: vec![ph_script, carrier_script.clone()],
    };
    let tx = TransactionData::<TxAuth>::from_parts(
        TxVersion::suggested_for_branch(branch),
        branch,
        0,
        BlockHeight::from_u32(req.expiry_height),
        Some(Bundle {
            vin,
            vout,
            authorization: auth,
        }),
        None,
        None,
        None,
    );
    debug_assert_eq!(tx.version(), TxVersion::suggested_for_branch(branch));
    let bundle = tx.transparent_bundle().ok_or("bundle")?;
    let signable = zcash_transparent::sighash::SignableInput::from_parts(
        bundle,
        SighashType::SINGLE_ANYONECANPAY,
        1,
        &carrier_script,
        &carrier_script,
        zat(req.carrier_value)?,
    )
    .map_err(|e| format!("{e:?}"))?;
    let h = signature_hash(
        &tx,
        &SignableInput::Transparent(signable),
        &tx.digest(TxIdDigester),
    );
    Ok(hex::encode(h.as_ref()))
}

/// JSON in, hex digest out. Throws a JS error with the reason on failure.
#[wasm_bindgen]
pub fn listing_digest(json: &str) -> Result<String, JsValue> {
    digest_json(json).map_err(|e| JsValue::from_str(&e))
}

pub fn digest_json(json: &str) -> Result<String, String> {
    let req: Req = serde_json::from_str(json).map_err(|e| e.to_string())?;
    digest(&req)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses() {
        let r = Req {
            network: "regtest".into(),
            branch: "nu6_3".into(),
            carrier_txid: "00".repeat(32),
            carrier_vout: 0,
            carrier_value: 546,
            carrier_script: "76a914".to_string() + &"11".repeat(20) + "88ac",
            payout_script: "76a914".to_string() + &"22".repeat(20) + "88ac",
            price_zat: 1000,
            expiry_height: 100,
            slot: 1,
        };
        assert_eq!(digest(&r).unwrap().len(), 64);
    }
}
