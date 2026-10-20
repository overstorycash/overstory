//! Independently pinned NU7 parameters guard against stale dependency schedules.
//! Source: ZcashFoundation/zebra release v7.0.0-rc.0 (ZIP 259).
use zcash_protocol::consensus::{BlockHeight, BranchId, NetworkUpgrade, Parameters, TEST_NETWORK};
pub const TESTNET_NU7_HEIGHT: u32 = 4_465_026;
pub fn check(network: &str, last_height: u32) -> Result<(), &'static str> {
    match network {
        "testnet" => {
            if TEST_NETWORK.activation_height(NetworkUpgrade::Nu7) != Some(BlockHeight::from_u32(TESTNET_NU7_HEIGHT))
                || u32::from(BranchId::Nu7) != 0x7719_0ad9
                || (last_height >= TESTNET_NU7_HEIGHT && BranchId::for_height(&TEST_NETWORK, BlockHeight::from_u32(last_height)) != BranchId::Nu7) {
                return Err("compiled Testnet NU7 parameters differ from independently verified values");
            }
            Ok(())
        }
        "regtest" | "mainnet" => Ok(()),
        _ => Err("unknown network"),
    }
}
