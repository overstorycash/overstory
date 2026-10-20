//! Empty invoice discovery only. A positive match always uses the original spending checks.
use super::*;
use std::collections::BTreeSet;
const BATCH:usize=100;
#[derive(Default)]
pub(super) struct PaymentWatch {anchor:Option<(u32,String)>,empty:BTreeSet<String>}
fn may_defer(o:&Order,time:u64)->bool {
 if o.error.is_some() {return false;}
 match o.status.as_str() {
  "awaiting_payment"=>time<o.expires && o.paid_zat==0 && o.receipts.is_empty() && o.mint_plan.is_none() && o.refunds.is_empty(),
  "expired"=>o.paid_zat==0 && o.receipts.is_empty() && o.mint_plan.is_none() && o.refunds.is_empty(),
  "done"=>o.mint_plan.is_some() && o.refunds.is_empty() && ledger(o).is_ok_and(|v|v["unallocated_received_zat"]==0),
  "refunded"=>o.mint_plan.is_none() && !o.refunds.is_empty() && o.refunds.iter().all(|r|r.confirmation.is_some()) && ledger(o).is_ok_and(|v|v["unallocated_received_zat"]==0),
  _=>false,
 }
}
fn nonempty(rpc:&Rpc,addresses:&[String],result:&serde_json::Value)->Result<BTreeSet<String>> {
 let scripts=addresses.iter().map(|a|Ok((hex::encode(proto::index::script_bytes(&proto::parse_taddr_for(a,rpc.net().network_type())?.script().into())),a.clone()))).collect::<Result<BTreeMap<_,_>>>()?;
 let mut found=BTreeSet::new();
 for row in result.as_array().context("batch UTXO response is not an array")? {
  let script=row["script"].as_str().context("batch UTXO lacks script")?;
  let address=scripts.get(&script.to_ascii_lowercase()).context("batch UTXO has unexpected address script")?;
  if let Some(reported)=row.get("address") {anyhow::ensure!(reported.as_str()==Some(address.as_str()),"batch UTXO address mismatch");}
  found.insert(address.clone());
 }
 Ok(found)
}
impl PaymentWatch {
 pub(super) fn deferred(&mut self,rpc:&Rpc,orders:&[Order],height:u32,hash:&str,time:u64)->Result<BTreeSet<String>> {
  let anchor=(height,hash.to_owned());
  if self.anchor.as_ref()!=Some(&anchor) {self.empty.clear();self.anchor=None;}
  let eligible:BTreeSet<String>=orders.iter().filter(|o|may_defer(o,time)).map(|o|o.invoice_address.clone()).collect();
  self.empty.retain(|a|eligible.contains(a));
  let query:Vec<String>=eligible.difference(&self.empty).cloned().collect();
  if !query.is_empty() {
   let mut newly_empty=BTreeSet::new();
   for chunk in query.chunks(BATCH) {
    let result=rpc.call("getaddressutxos",json!([{"addresses":chunk}]))?;
    let found=nonempty(rpc,chunk,&result)?;
    newly_empty.extend(chunk.iter().filter(|a|!found.contains(*a)).cloned());
   }
   anyhow::ensure!(rpc.checked_target()? - 1==height && rpc.call("getblockhash",json!([height]))?.as_str()==Some(hash),"chain changed during invoice discovery");
   self.empty.extend(newly_empty);
  }
  self.anchor=Some(anchor);
  Ok(orders.iter().filter(|o|may_defer(o,time)&&self.empty.contains(&o.invoice_address)).map(|o|o.id.clone()).collect())
 }
}
#[cfg(test)]mod tests {
 use super::*;
 #[test]fn only_quiet_orders_can_be_deferred(){
  let mut o:Order=serde_json::from_value(json!({"id":"empty","dest":"dest","invoice_address":"invoice","amount_zat":10000000,"created":1,"expires":100,"status":"awaiting_payment","paid_zat":0,"inscription_id":null,"txids":[],"number":null,"seed":null,"error":null})).unwrap();
  assert!(may_defer(&o,99));assert!(!may_defer(&o,100));
  o.paid_zat=1;assert!(!may_defer(&o,99));o.paid_zat=0;
  for status in ["paid","inscribing","purchasing","refunding","recovery_required","refund_pending_small","done","refunded"] {o.status=status.into();assert!(!may_defer(&o,99),"{status}");}
  o.status="expired".into();assert!(may_defer(&o,101));o.error=Some("review".into());assert!(!may_defer(&o,101));
 }
}
