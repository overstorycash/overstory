//! Bounded index fixture for fresh public-Testnet acceptance wallets only.
//! Never use this partial-history index with existing wallets or on Mainnet.
use anyhow::{Context, Result, ensure};
use proto::{Rpc, index::{Db, Net, DB_FILE, index_to_tip}};
use serde_json::json;
fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    ensure!(args.len() == 2, "usage: testnet-index <first-height> <previous-block-hash>");
    let first: u32 = args[0].parse()?;
    ensure!(first > 0, "positive first height required");
    let rpc = Rpc::open()?;
    ensure!(rpc.net() == Net::Testnet, "fixture only supports public Testnet");
    let tip = rpc.checked_target()? - 1;
    ensure!(first <= tip && tip - first < 5000, "fixture start must be mined and history below 5000 blocks");
    let anchor = rpc.call("getblockhash", json!([first - 1]))?;
    ensure!(anchor.as_str() == Some(args[1].as_str()), "fixture anchor changed");
    let scope = json!({"first_height":first,"previous_hash":args[1],"purpose":"fresh test wallets only; incomplete global inscription history"});
    let mut db = Db::open(DB_FILE)?;
    let scopes = db.kv_all::<serde_json::Value>("testnet-fixture")?;
    let mut st = db.load()?;
    if let Some(saved) = scopes.get("scope") { ensure!(saved == &scope, "fixture scope changed"); }
    else { ensure!(st.height == 0 && st.inscriptions.is_empty(), "requires fresh database"); db.kv_put("testnet-fixture", "scope", &scope)?; }
    if st.height == 0 {
        st.height = first - 1;
        st.tip_hash = Some(anchor.as_str().context("anchor")?.into());
        st.network = Some("testnet".into());
        db.apply(&st, &proto::index::Changes::default())?;
    }
    ensure!(st.height >= first - 1, "index precedes fixture anchor");
    let n = index_to_tip(&rpc, &mut st, Some(&mut db), Net::Testnet, first, false, 5000)?;
    println!("{}",json!({"blocks_indexed":n,"tip":st.height,"inscriptions":st.inscriptions.len(),"collections":st.collections.len(),"mints":st.mints.len(),"scope":scope}));
    Ok(())
}
