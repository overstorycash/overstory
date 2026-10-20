//! Per-process RPC counters. Never retain URLs, parameters, addresses or transaction bytes.
use serde::Serialize;
use std::{collections::BTreeMap,sync::{Mutex,OnceLock}};
#[derive(Clone,Default,Serialize)]
pub struct MethodUsage { pub requests:u64,pub failures:u64,pub elapsed_ms:u64 }
static COUNTERS:OnceLock<Mutex<BTreeMap<String,MethodUsage>>>=OnceLock::new();
pub(crate) fn record(method:&str,failed:bool,elapsed_ms:u64) {
 let mut counts=COUNTERS.get_or_init(Default::default).lock().unwrap_or_else(|e|e.into_inner());
 // Fixed buckets prevent arbitrary method strings from becoming log content or unbounded labels.
 let name=match method {"getblockchaininfo"|"getblockcount"|"getblockhash"|"getblock"|"getrawtransaction"|"getaddressutxos"|"getaddresstxids"|"gettxout"|"getrawmempool"|"sendrawtransaction"=>method,_=>"other"};
 let c=counts.entry(name.into()).or_default();c.requests=c.requests.saturating_add(1);c.failures=c.failures.saturating_add(u64::from(failed));c.elapsed_ms=c.elapsed_ms.saturating_add(elapsed_ms);
}
pub fn snapshot()->BTreeMap<String,MethodUsage> { COUNTERS.get_or_init(Default::default).lock().unwrap_or_else(|e|e.into_inner()).clone() }
#[cfg(test)]mod tests {
 use super::*;
 #[test]fn unknown_labels_cannot_leak_secrets(){record("https://secret-endpoint/token",true,42);let s=serde_json::to_string(&snapshot()).unwrap();assert!(!s.contains("secret-endpoint"));assert!(snapshot()["other"].failures>=1);}
}
