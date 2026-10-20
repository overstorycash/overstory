//! Reviewable local purchase plans. No buyer funds or secret keys are sent to a market service.
use crate::*;
use std::io::Write;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PurchasePlan {
    version: u32,
    network: String,
    genesis_hash: String,
    inscription: String,
    collection: String,
    destination: String,
    max_price_zat: u64,
    max_fee_zat: u64,
    fee_zat: u64,
    listing: Listing,
    funding: Vec<Utxo>,
    outputs: Vec<Value>,
    txid: String,
    raw_transaction: String,
}
fn verify_asset(rpc: &Rpc, l: &Listing, id: &str, collection: &str) -> Result<()> {
    let st = rpc.index_snapshot()?;
    let out = format!("{}:{}", l.carrier_txid, l.carrier_vout);
    anyhow::ensure!(
        st.single_carrier(&out).map(String::as_str) == Some(id),
        "listing does not carry the expected inscription"
    );
    anyhow::ensure!(
        st.mints.get(id).is_some_and(|m| m.collection == collection),
        "inscription is not a valid member of the expected collection"
    );
    let carrier = Utxo {
        txid: l.carrier_txid.clone(),
        n: l.carrier_vout,
        value: l.carrier_value,
        script: l.carrier_script.clone(),
        height: st.height,
    };
    rpc.validate_utxo(&carrier)?;
    Ok(())
}
#[allow(clippy::too_many_arguments)]
pub fn plan(
    buyer: &str,
    path: &str,
    dest: &str,
    id: &str,
    collection: &str,
    max_price: u64,
    max_fee: u64,
    output: &str,
) -> Result<()> {
    let rpc = Rpc::open()?;
    let key = Key::load(buyer)?;
    let l: Listing = serde_json::from_str(&fs::read_to_string(path)?)?;
    anyhow::ensure!(l.price_zat <= max_price, "price exceeds buyer approval");
    zat(max_price)?;
    zat(max_fee)?;
    verify_asset(&rpc, &l, id, collection)?;
    let mut funding = rpc.spendable(&key.address_string(rpc.net()))?;
    funding.sort_by_key(|u| std::cmp::Reverse(u.value));
    let mut picked = vec![];
    let mut total = 0u64;
    for u in funding {
        total = total.checked_add(u.value).context("funding overflow")?;
        picked.push(u);
        if total >= l.price_zat.checked_add(max_fee).context("price overflow")? {
            break;
        }
    }
    let target = rpc.checked_window(l.expiry_height)?;
    let tx = build_purchase(
        rpc.net(),
        target,
        &l,
        &key,
        &picked,
        dest,
        &key.address(),
        vec![],
        max_fee,
    )?;
    let b = tx.transparent_bundle().context("bundle")?;
    let fee = total + l.carrier_value - b.vout.iter().map(|o| o.value().into_u64()).sum::<u64>();
    let outputs=b.vout.iter().map(|o|json!({"value_zat":o.value().into_u64(),"script":hex::encode(index::script_bytes(o.script_pubkey()))})).collect();
    let mut raw = vec![];
    tx.write(&mut raw)?;
    let plan = PurchasePlan {
        version: 1,
        network: rpc.net().name().into(),
        genesis_hash: rpc.chain.genesis_hash.clone(),
        inscription: id.into(),
        collection: collection.into(),
        destination: dest.into(),
        max_price_zat: max_price,
        max_fee_zat: max_fee,
        fee_zat: fee,
        listing: l,
        funding: picked,
        outputs,
        txid: tx.txid().to_string(),
        raw_transaction: hex::encode(raw),
    };
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(output)?;
    file.write_all(&serde_json::to_vec_pretty(&plan)?)?;
    file.sync_all()?;
    println!(
        "purchase plan saved: {} | price {} zat | network fee {} zat | txid {} | not broadcast",
        output, plan.listing.price_zat, fee, plan.txid
    );
    Ok(())
}
pub fn broadcast(path: &str) -> Result<()> {
    let plan: PurchasePlan = serde_json::from_str(&fs::read_to_string(path)?)?;
    let rpc = Rpc::open()?;
    anyhow::ensure!(
        plan.version == 1
            && plan.network == rpc.net().name()
            && plan.genesis_hash == rpc.chain.genesis_hash,
        "purchase plan chain mismatch"
    );
    anyhow::ensure!(
        plan.listing.price_zat <= plan.max_price_zat && plan.fee_zat <= plan.max_fee_zat,
        "plan exceeds approval"
    );
    verify_asset(&rpc, &plan.listing, &plan.inscription, &plan.collection)?;
    let st = rpc.index_snapshot()?;
    for u in &plan.funding {
        let point = format!("{}:{}", u.txid, u.n);
        anyhow::ensure!(
            !st.carriers.contains_key(&point) && !st.pending.contains_key(&point),
            "purchase funding is now inscription-locked"
        );
        rpc.validate_utxo(u)?;
    }
    let bytes = hex::decode(&plan.raw_transaction)?;
    let target = rpc.checked_window(plan.listing.expiry_height)?;
    let tx = Transaction::read(&bytes[..], rpc.net().branch_for(target))?;
    anyhow::ensure!(tx.txid().to_string() == plan.txid, "plan txid mismatch");
    let b = tx.transparent_bundle().context("bundle")?;
    let actual:Vec<Value>=b.vout.iter().map(|o|json!({"value_zat":o.value().into_u64(),"script":hex::encode(index::script_bytes(o.script_pubkey()))})).collect();
    anyhow::ensure!(actual == plan.outputs, "plan output summary mismatch");
    let dest = parse_taddr_for(&plan.destination, rpc.net().network_type())?;
    let seller = parse_taddr_for(&plan.listing.payout_address, rpc.net().network_type())?;
    anyhow::ensure!(
        b.vout.len() >= 2 && b.vout.len() <= 3,
        "unexpected purchase outputs"
    );
    anyhow::ensure!(
        b.vout[0].value().into_u64() == CARRIER_ZAT
            && *b.vout[0].script_pubkey() == dest.script().into(),
        "plan destination mismatch"
    );
    anyhow::ensure!(
        b.vout[1].value().into_u64() == plan.listing.price_zat
            && *b.vout[1].script_pubkey() == seller.script().into(),
        "plan seller payout mismatch"
    );
    anyhow::ensure!(
        !plan.funding.is_empty() && b.vin.len() == plan.funding.len() + 1,
        "plan input count mismatch"
    );
    let change = hex::decode(&plan.funding[0].script)?;
    anyhow::ensure!(
        plan.funding
            .iter()
            .all(|u| hex::decode(&u.script).ok().as_ref() == Some(&change)),
        "plan funding keys differ"
    );
    if b.vout.len() == 3 {
        anyhow::ensure!(
            index::script_bytes(b.vout[2].script_pubkey()) == change,
            "plan change mismatch"
        );
    }
    let mut expected: Vec<_> = plan
        .funding
        .iter()
        .map(Utxo::outpoint)
        .collect::<Result<_>>()?;
    expected.insert(
        1,
        zcash_transparent::bundle::OutPoint::new(
            txid_bytes(&plan.listing.carrier_txid)?,
            plan.listing.carrier_vout,
        ),
    );
    for (input, point) in b.vin.iter().zip(&expected) {
        anyhow::ensure!(input.prevout() == point, "plan input outpoint mismatch");
    }
    let total_in = plan
        .funding
        .iter()
        .try_fold(plan.listing.carrier_value, |v, u| {
            v.checked_add(u.value).context("input overflow")
        })?;
    let total_out = b.vout.iter().try_fold(0u64, |v, o| {
        v.checked_add(o.value().into_u64())
            .context("output overflow")
    })?;
    anyhow::ensure!(
        total_in.checked_sub(total_out) == Some(plan.fee_zat),
        "plan fee summary mismatch"
    );
    anyhow::ensure!(
        u32::from(tx.expiry_height()) == plan.listing.expiry_height,
        "plan expiry mismatch"
    );
    println!(
        "purchase broadcast {}",
        rpc.send_raw(&plan.raw_transaction)?
    );
    Ok(())
}

/// Broadcast the exact browser-signed bytes through the user's own pinned RPC.
/// The file must be a previously reviewed local wallet export, never an unsolicited file.
pub fn broadcast_saved(path: &str) -> Result<()> {
    let saved: Value = serde_json::from_str(&fs::read_to_string(path)?)?;
    let rpc = Rpc::open()?;
    anyhow::ensure!(
        saved["network"].as_str() == Some(rpc.net().name())
            && saved["genesis_hash"].as_str() == Some(rpc.chain.genesis_hash.as_str()),
        "saved transaction chain mismatch"
    );
    let raw = saved["raw_transaction"]
        .as_str()
        .context("missing signed transaction")?;
    let bytes = hex::decode(raw)?;
    let tx = Transaction::read(&bytes[..], rpc.net().branch_for(rpc.checked_target()?))?;
    anyhow::ensure!(
        saved["txid"].as_str() == Some(tx.txid().to_string().as_str()),
        "saved transaction id mismatch"
    );
    println!("broadcast {}", rpc.send_raw(raw)?);
    Ok(())
}
