//! Explicit network selection and fail-closed node/upgrade checks.
#[path = "../../epoch_guard.rs"]
mod epoch_guard;
use crate::{Rpc, index::Net};
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use serde_json::{Value, json};
use zcash_primitives::transaction::TxVersion;
use zcash_protocol::consensus::{
    BlockHeight, BranchId, MAIN_NETWORK, NetworkType, NetworkUpgrade, Parameters, TEST_NETWORK,
};

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChainConfig {
    pub network: String,
    /// Independently verified genesis hash; never auto-enrol a node on first use.
    pub genesis_hash: String,
}
impl ChainConfig {
    pub fn load() -> Result<Self> {
        let c: Self =
            serde_json::from_str(&std::fs::read_to_string("chain.json").context(
                "missing chain.json: explicit network and verified genesis_hash required",
            )?)?;
        c.net()?;
        ensure!(
            c.genesis_hash.len() == 64
                && c.genesis_hash
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "invalid genesis hash"
        );
        Ok(c)
    }
    pub fn net(&self) -> Result<Net> {
        Net::parse(&self.network)
    }
}
impl Parameters for Net {
    fn network_type(&self) -> NetworkType {
        (*self).network_type()
    }
    fn activation_height(&self, nu: NetworkUpgrade) -> Option<BlockHeight> {
        match self {
            Net::Regtest => crate::regtest().activation_height(nu),
            Net::Testnet => TEST_NETWORK.activation_height(nu),
            Net::Mainnet => MAIN_NETWORK.activation_height(nu),
        }
    }
}
pub fn branch_name(b: BranchId) -> &'static str {
    match b {
        BranchId::Nu5 => "nu5",
        BranchId::Nu6 => "nu6",
        BranchId::Nu6_1 => "nu6_1",
        BranchId::Nu6_2 => "nu6_2",
        BranchId::Nu6_3 => "nu6_3",
        BranchId::Nu7 => "nu7",
        _ => "unsupported",
    }
}
pub fn validate_window(net: Net, target: u32, expiry: u32) -> Result<BranchId> {
    ensure!(
        target > 0 && expiry >= target && expiry < 500_000_000,
        "invalid transaction height window"
    );
    epoch_guard::check(net.name(), expiry).map_err(anyhow::Error::msg)?;
    let b = net.branch_for(target);
    ensure!(
        matches!(
            TxVersion::suggested_for_branch(b),
            TxVersion::V5 | TxVersion::V6
        ),
        "only ZIP 244 transaction epochs supported"
    );
    ensure!(
        net.branch_for(expiry) == b,
        "expiry crosses a network upgrade; shorten expiry"
    );
    Ok(b)
}
pub fn validate_node(c: &ChainConfig, info: &Value, genesis: &str) -> Result<u32> {
    let net = c.net()?;
    ensure!(
        genesis == c.genesis_hash,
        "node genesis does not match pinned chain identity"
    );
    let label = info["chain"].as_str().context("missing node chain")?;
    ensure!(
        match net {
            Net::Mainnet => label == "main",
            Net::Testnet => label == "test",
            Net::Regtest => label == "regtest" || label == "test",
        },
        "node network label mismatch"
    );
    let tip = u32::try_from(info["blocks"].as_u64().context("missing node blocks")?)?;
    let target = tip.checked_add(1).context("height overflow")?;
    ensure!(
        target < 500_000_000,
        "node height outside supported transaction range"
    );
    epoch_guard::check(net.name(), target).map_err(anyhow::Error::msg)?;
    let node = info["consensus"]["nextblock"]
        .as_str()
        .context("node must expose consensus.nextblock")?;
    let expected = format!("{:08x}", u32::from(net.branch_for(target)));
    ensure!(
        node == expected,
        "node consensus differs from compiled network schedule; update and verify before signing"
    );
    Ok(target)
}
fn validate_announced_upgrades(
    info: &Value,
    target: u32,
    expiry: u32,
    branch: BranchId,
) -> Result<()> {
    let upgrades = info["upgrades"]
        .as_object()
        .context("node must expose upgrade schedule")?;
    for (id, upgrade) in upgrades {
        let height = upgrade["activationheight"]
            .as_u64()
            .context("missing upgrade activation height")?;
        if height > u64::from(target) && height <= u64::from(expiry) {
            ensure!(
                id == &format!("{:08x}", u32::from(branch)),
                "node schedules an upgrade inside the transaction window"
            );
        }
    }
    Ok(())
}
impl Rpc {
    pub fn checked_target(&self) -> Result<u32> {
        let info = self.call("getblockchaininfo", json!([]))?;
        let genesis = self.call("getblockhash", json!([0]))?;
        validate_node(
            &self.chain,
            &info,
            genesis.as_str().context("genesis hash")?,
        )
    }
    pub fn net(&self) -> Net {
        self.chain.net().expect("validated ChainConfig")
    }
    pub fn checked_window(&self, expiry: u32) -> Result<u32> {
        let target = self.checked_target()?;
        let branch = validate_window(self.net(), target, expiry)?;
        let info = self.call("getblockchaininfo", json!([]))?;
        ensure!(
            info["blocks"].as_u64() == Some(u64::from(target - 1)),
            "chain advanced during epoch check"
        );
        validate_announced_upgrades(&info, target, expiry, branch)?;
        Ok(target)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn c() -> ChainConfig {
        ChainConfig {
            network: "regtest".into(),
            genesis_hash: "11".repeat(32),
        }
    }
    fn info() -> Value {
        json!({"chain":"test","blocks":100,"consensus":{"nextblock":format!("{:08x}",u32::from(BranchId::Nu6_3))}})
    }
    #[test]
    fn independently_announced_nu7_rejects_old_nodes_and_crossing_windows() {
        let h = epoch_guard::TESTNET_NU7_HEIGHT;
        let c = ChainConfig { network: "testnet".into(), genesis_hash: "11".repeat(32) };
        let mut i = info();
        i["blocks"] = json!(h - 2);
        assert!(validate_node(&c, &i, &c.genesis_hash).is_ok());
        i["blocks"] = json!(h - 1);
        // A stale node can agree with a stale SDK. Independent cutoff must still reject it.
        assert!(validate_node(&c, &i, &c.genesis_hash).unwrap_err().to_string().contains("consensus"));
        i["consensus"]["nextblock"] = json!("77190ad9");
        assert!(validate_node(&c, &i, &c.genesis_hash).is_ok());
        assert!(validate_window(Net::Testnet, h - 20, h - 1).is_ok());
        assert!(validate_window(Net::Testnet, h - 20, h).is_err());
        assert!(validate_window(Net::Testnet, h, h + 20).is_ok());
        assert!(validate_window(Net::Regtest, h, h + 20).is_ok());
        assert!(validate_window(Net::Mainnet, h, h + 20).is_ok());
    }
    #[test]
    fn node_checks_identity_and_schedule() {
        assert_eq!(
            validate_node(&c(), &info(), &c().genesis_hash).unwrap(),
            101
        );
        assert!(validate_node(&c(), &info(), &"22".repeat(32)).is_err());
        let mut i = info();
        i["chain"] = json!("main");
        assert!(validate_node(&c(), &i, &c().genesis_hash).is_err());
        i = info();
        i["consensus"]["nextblock"] = json!("00000000");
        assert!(validate_node(&c(), &i, &c().genesis_hash).is_err());
        i = info();
        i["blocks"] = json!(u64::MAX);
        assert!(validate_node(&c(), &i, &c().genesis_hash).is_err());
        i = info();
        i["consensus"] = json!({});
        assert!(validate_node(&c(), &i, &c().genesis_hash).is_err());
    }
    #[test]
    fn unknown_announced_upgrade_also_bounds_expiry() {
        let v = json!({"upgrades":{"ffffffff":{"activationheight":105}}});
        assert!(validate_announced_upgrades(&v, 101, 110, BranchId::Nu6_3).is_err());
        assert!(validate_announced_upgrades(&v, 101, 104, BranchId::Nu6_3).is_ok());
        assert!(validate_announced_upgrades(&json!({}), 101, 104, BranchId::Nu6_3).is_err());
    }
    #[test]
    fn rejects_upgrade_crossing_and_invalid_heights() {
        assert!(validate_window(Net::Regtest, 100, 200).is_ok());
        assert!(validate_window(Net::Regtest, 101, 100).is_err());
        assert!(validate_window(Net::Regtest, 0, 100).is_err());
        assert!(validate_window(Net::Regtest, 100, 500_000_000).is_err());
        for net in [Net::Mainnet, Net::Testnet] {
            let h = u32::from(net.activation_height(NetworkUpgrade::Nu6).unwrap());
            assert!(validate_window(net, h - 1, h).is_err());
            assert!(validate_window(net, h, h + 1).is_ok());
        }
    }
}
