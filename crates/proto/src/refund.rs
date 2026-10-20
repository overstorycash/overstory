//! Persistable refund transaction. No signing or input selection during recovery.
use crate::inscribe::RecoveryRequired;
use crate::*;
use std::collections::BTreeSet;
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RefundPlan {
    pub version: u32,
    pub network: String,
    pub genesis_hash: String,
    pub target_height: u32,
    pub expiry_height: u32,
    pub destination: String,
    pub funding: Vec<Utxo>,
    pub input_zat: u64,
    pub refund_zat: u64,
    pub fee_zat: u64,
    pub txid: String,
    pub raw_transaction: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RefundConfirmation {
    pub height: u32,
    pub block_hash: String,
}
/// Preserve small liabilities instead of pretending they were refunded.
pub fn amounts(total: u64, inputs: usize) -> Result<Option<(u64, u64)>> {
    anyhow::ensure!(
        inputs > 0 && inputs <= 100,
        "refund requires 1..100 inputs; review larger batches"
    );
    zat(total)?;
    let fee = 5000u64
        .checked_mul(inputs.max(2) as u64)
        .context("fee overflow")?;
    Ok(total
        .checked_sub(fee)
        .filter(|n| *n >= CARRIER_ZAT)
        .map(|amount| (amount, fee)))
}
impl RefundPlan {
    pub fn prepare(
        rpc: &Rpc,
        key: &Key,
        funding: Vec<Utxo>,
        destination: &str,
    ) -> Result<Option<Self>> {
        let total = funding.iter().try_fold(0u64, |v, u| {
            v.checked_add(u.value).context("refund total overflow")
        })?;
        let Some((amount, fee)) = amounts(total, funding.len())? else {
            return Ok(None);
        };
        let dest = parse_taddr_for(destination, rpc.net().network_type())?;
        let mut seen = BTreeSet::new();
        let inputs = funding
            .iter()
            .map(|u| -> Result<InputSpec> {
                anyhow::ensure!(seen.insert((u.txid.clone(), u.n)), "duplicate refund input");
                anyhow::ensure!(
                    u.script == hex::encode(index::script_bytes(&key.address().script().into())),
                    "refund input not owned by invoice key"
                );
                rpc.validate_utxo(u)?;
                Ok(InputSpec {
                    pubkey: key.pk,
                    outpoint: u.outpoint()?,
                    coin: u.coin()?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let target = rpc.checked_target()?;
        let expiry = target.checked_add(39).context("expiry overflow")?;
        let pczt = build_pczt(
            rpc.net(),
            target,
            expiry,
            &inputs,
            &[OutputSpec {
                to: dest.clone(),
                value: amount,
            }],
            &dest,
        )?;
        let pczt = IoFinalizer::new(pczt)
            .finalize_io(rand::rng())
            .map_err(|e| anyhow!("finalize refund: {e:?}"))?;
        let mut signer = Signer::new(pczt).map_err(|e| anyhow!("refund signer: {e:?}"))?;
        for i in 0..inputs.len() {
            signer
                .sign_transparent(i, &key.sk)
                .map_err(|e| anyhow!("refund sign: {e:?}"))?;
        }
        let tx = finalize_tx(signer.finish())?;
        let mut raw = vec![];
        tx.write(&mut raw)?;
        let plan = Self {
            version: 1,
            network: rpc.net().name().into(),
            genesis_hash: rpc.chain.genesis_hash.clone(),
            target_height: target,
            expiry_height: expiry,
            destination: destination.into(),
            funding,
            input_zat: total,
            refund_zat: amount,
            fee_zat: fee,
            txid: tx.txid().to_string(),
            raw_transaction: hex::encode(raw),
        };
        plan.validate(rpc)?;
        Ok(Some(plan))
    }
    pub fn validate(&self, rpc: &Rpc) -> Result<()> {
        self.validate_for_chain(rpc.net(),&rpc.chain.genesis_hash)
    }
    /// Static validation for cached read views; never contacts a node.
    pub(crate) fn validate_for_chain(&self, net:index::Net, genesis_hash:&str) -> Result<()> {
        anyhow::ensure!(
            (self.version == 1 || self.version == 2)
                && self.network == net.name()
                && self.genesis_hash == genesis_hash,
            "refund chain mismatch"
        );
        let branch = network::validate_window(net, self.target_height, self.expiry_height)?;
        let bytes = hex::decode(&self.raw_transaction)?;
        let mut cursor = std::io::Cursor::new(&bytes);
        let tx = Transaction::read(&mut cursor, branch)?;
        anyhow::ensure!(
            cursor.position() as usize == bytes.len()
                && tx.txid().to_string() == self.txid
                && tx.consensus_branch_id() == branch
                && tx.version()
                    == zcash_primitives::transaction::TxVersion::suggested_for_branch(branch)
                && u32::from(tx.expiry_height()) == self.expiry_height,
            "refund identity/epoch mismatch"
        );
        let b = tx.transparent_bundle().context("refund bundle")?;
        let dest = parse_taddr_for(&self.destination, net.network_type())?;
        let refund_index = if self.version==2 {
            anyhow::ensure!(b.vin.len()==1 && self.funding.len()==1,"authenticated reclaim requires one input");
            reclaim::validate_spend(&tx,2,self.fee_zat)?;
            let pushes=index::parse_pushes(&index::script_bytes(b.vin[0].script_sig())).context("reclaim pushes")?;
            let redeem=pushes.last().context("reclaim redeem")?;
            let expected:Script=TransparentAddress::ScriptHash(inscribe::hash160(redeem)).script().into();
            anyhow::ensure!(self.funding[0].script==hex::encode(index::script_bytes(&expected)),"reclaim source commitment mismatch");
            1
        }else{0};
        anyhow::ensure!(
            b.vout.len() == refund_index+1
                && b.vout[refund_index].value().into_u64() == self.refund_zat
                && *b.vout[refund_index].script_pubkey() == dest.script().into(),
            "refund destination/amount mismatch"
        );
        anyhow::ensure!(
            b.vin.len() == self.funding.len(),
            "refund input count mismatch"
        );
        let mut seen = BTreeSet::new();
        let mut total = 0u64;
        for (input, u) in b.vin.iter().zip(&self.funding) {
            anyhow::ensure!(
                seen.insert((u.txid.clone(), u.n)) && input.prevout() == &u.outpoint()?,
                "refund input mismatch/duplicate"
            );
            total = total
                .checked_add(u.value)
                .context("refund input overflow")?;
        }
        anyhow::ensure!(
            total == self.input_zat
                && if self.version==1 { amounts(total, self.funding.len())? == Some((self.refund_zat, self.fee_zat)) }
                   else { self.refund_zat>=CARRIER_ZAT && self.refund_zat.checked_add(self.fee_zat)==Some(total) },
            "refund accounting mismatch"
        );
        Ok(())
    }
    /// Only an exact raw transaction with a positive, canonical confirmation settles the liability.
    pub fn resume(&self, rpc: &Rpc) -> Result<Option<RefundConfirmation>> {
        crate::manual_cases::check_raw(rpc,&self.raw_transaction)?;
        self.validate(rpc)?;
        match rpc.call("getrawtransaction", json!([self.txid, 1])) {
            Ok(v) => {
                anyhow::ensure!(
                    hex::decode(v["hex"].as_str().context("missing known refund bytes")?)?
                        == hex::decode(&self.raw_transaction)?,
                    "known refund differs from saved bytes"
                );
                let n = match v.get("confirmations") {
                    None => 0,
                    Some(value) => value.as_i64().context("invalid refund confirmations")?,
                };
                anyhow::ensure!(n >= 0, "refund is not on the canonical chain; reconcile before recovery");
                if n == 0 {
                    let pool = rpc.call("getrawmempool", json!([]))?;
                    anyhow::ensure!(
                        pool.as_array().context("invalid refund mempool response")?
                            .iter().any(|id| id.as_str() == Some(self.txid.as_str())),
                        "known refund is neither confirmed nor in mempool; reconcile before recovery"
                    );
                    return Ok(None);
                }
                let hash = v["blockhash"]
                    .as_str()
                    .context("missing refund block hash")?;
                let block = rpc.call("getblock", json!([hash, 1]))?;
                let height =
                    u32::try_from(block["height"].as_u64().context("refund block height")?)?;
                anyhow::ensure!(
                    block["tx"].as_array().context("missing refund block transaction list")?
                        .iter().any(|id| id.as_str() == Some(self.txid.as_str())),
                    "refund absent from reported confirmation block"
                );
                anyhow::ensure!(
                    rpc.call("getblockhash", json!([height]))?.as_str() == Some(hash),
                    "refund block is not canonical"
                );
                return Ok(Some(RefundConfirmation {
                    height,
                    block_hash: hash.into(),
                }));
            }
            Err(e)
                if e.downcast_ref::<RpcCallError>()
                    .is_some_and(|e| e.code == -5) => {}
            Err(e) => return Err(e),
        }
        if rpc.checked_target()? > self.expiry_height {
            return Err(RecoveryRequired(format!(
                "refund {} expired; reconcile before replacement",
                self.txid
            ))
            .into());
        }
        rpc.send_raw(&self.raw_transaction)?;
        Ok(None)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn small_refunds_remain_liabilities() {
        assert_eq!(amounts(9999, 1).unwrap(), None);
        assert_eq!(amounts(10545, 1).unwrap(), None);
        assert_eq!(amounts(10546, 1).unwrap(), Some((546, 10000)));
        assert_eq!(amounts(15000, 1).unwrap(), Some((5000, 10000)));
    }
    #[test]
    fn fee_math_never_underflows_for_many_small_inputs() {
        assert_eq!(amounts(20000, 5).unwrap(), None);
        assert_eq!(amounts(50000, 5).unwrap(), Some((25000, 25000)));
        assert!(amounts(u64::MAX, 1).is_err());
        assert!(amounts(50000, 0).is_err());
        assert!(amounts(50000, 101).is_err());
    }
}
