//! Optional, fail-closed spend ledger for an isolated mainnet acceptance runtime.
//! Reservations survive ambiguous RPC outcomes and are never automatically released.
use crate::*;
use rusqlite::{Connection, TransactionBehavior, OptionalExtension};
#[derive(Deserialize,Serialize)]
#[serde(deny_unknown_fields)]
struct Policy {
 network:String,
 approved:bool,
 max_fee_zat:u64,
 return_reserve_zat:u64,
 max_transaction_fee_zat:u64,
 return_address:String,
}
fn reserve(db:&mut Connection,policy:&str,txid:&str,raw:&str,fee:u64,ceiling:u64)->Result<()> {
 db.execute_batch("PRAGMA synchronous=FULL; CREATE TABLE IF NOT EXISTS policy(id INTEGER PRIMARY KEY CHECK(id=1), json TEXT NOT NULL); CREATE TABLE IF NOT EXISTS reservations(txid TEXT PRIMARY KEY, raw TEXT NOT NULL, fee INTEGER NOT NULL CHECK(fee>=0));")?;
 let t=db.transaction_with_behavior(TransactionBehavior::Immediate)?;
 let saved:Option<String>=t.query_row("SELECT json FROM policy WHERE id=1",[],|r|r.get(0)).optional()?;
 if let Some(saved)=saved {anyhow::ensure!(saved==policy,"test budget policy changed; manual review required");}
 else {t.execute("INSERT INTO policy VALUES(1,?1)",[policy])?;}
 let old:Option<(String,u64)>=t.query_row("SELECT raw,fee FROM reservations WHERE txid=?1",[txid],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
 if let Some((old,old_fee))=old {anyhow::ensure!(old==raw && old_fee==fee,"saved transaction bytes or fee changed");t.commit()?;return Ok(());}
 let used:u64=t.query_row("SELECT COALESCE(SUM(fee),0) FROM reservations",[],|r|r.get(0))?;
 anyhow::ensure!(used.checked_add(fee).is_some_and(|n|n<=ceiling),"test network fee budget exhausted; no broadcast");
 t.execute("INSERT INTO reservations VALUES(?1,?2,?3)",rusqlite::params![txid,raw,fee])?;
 t.commit()?;Ok(())
}
fn fee_from_parents(tx:&Transaction,mut parent_raw:impl FnMut(&str)->Result<String>)->Result<u64> {
 let bundle=tx.transparent_bundle().context("missing transparent transaction")?;
 let mut seen=std::collections::BTreeSet::new();let mut input=0u64;
 for vin in &bundle.vin {
  let point=vin.prevout();let mut hash=*point.hash();hash.reverse();let id=hex::encode(hash);
  anyhow::ensure!(seen.insert((id.clone(),point.n())),"duplicate input");
  let bytes=hex::decode(parent_raw(&id)?)?;let mut cursor=std::io::Cursor::new(&bytes);
  let parent=Transaction::read(&mut cursor,tx.consensus_branch_id())?;
  anyhow::ensure!(cursor.position() as usize==bytes.len() && parent.txid().to_string()==id,"budget parent identity mismatch");
  let value=parent.transparent_bundle().and_then(|b|b.vout.get(point.n() as usize)).context("budget parent output missing")?.value().into_u64();
  input=input.checked_add(value).context("budget input overflow")?;
 }
 let output=bundle.vout.iter().try_fold(0u64,|total,out|total.checked_add(out.value().into_u64()).context("budget output overflow"))?;
 input.checked_sub(output).context("negative network fee")
}
fn known_parent(db:&Connection,exists:bool,id:&str,fetch:impl FnOnce()->Result<String>)->Result<String> {
 if exists {
  if let Some(raw)=db.query_row("SELECT raw FROM reservations WHERE txid=?1",[id],|r|r.get::<_,String>(0)).optional()? {return Ok(raw);}
 }
 fetch()
}
pub fn before_broadcast(rpc:&Rpc,tx:&Transaction,raw:&str)->Result<()> {
 let path=std::path::Path::new("test-spend-policy.json");
 let policy=match fs::read_to_string(path) {Ok(p)=>p,Err(e) if e.kind()==std::io::ErrorKind::NotFound=>return Ok(()),Err(e)=>return Err(e.into())};
 let p:Policy=serde_json::from_str(&policy)?;
 anyhow::ensure!(p.approved && p.network=="mainnet" && rpc.net()==index::Net::Mainnet,"test budget requires approved mainnet policy");
 anyhow::ensure!(p.max_fee_zat>0 && p.max_fee_zat<=300_000 && p.return_reserve_zat>=30_000 && p.return_reserve_zat<p.max_fee_zat && p.max_transaction_fee_zat<=30_000,"invalid acceptance fee limits");
 anyhow::ensure!(tx.sapling_bundle().is_none() && tx.orchard_bundle().is_none(),"test budget only supports transparent transactions");
 let bundle=tx.transparent_bundle().context("missing transparent transaction")?;
 anyhow::ensure!(!bundle.vin.is_empty() && !bundle.vout.is_empty(),"empty test transaction");
 // Our persisted parent bytes are already identity-checked below. A just-broadcast
 // commit may not yet be visible on another provider backend; do not depend on that
 // propagation to calculate fees. Node consensus still validates spendability.
 let mut db=Connection::open("test-spend-ledger.sqlite")?;
 let exists:bool=db.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='reservations')",[],|r|r.get(0))?;
 let fee=fee_from_parents(tx,|id|known_parent(&db,exists,id,||Ok(rpc.call("getrawtransaction",json!([id,0]))?.as_str().context("raw parent")?.to_owned())))?;
 anyhow::ensure!(fee<=p.max_transaction_fee_zat,"test per-transaction network fee cap exceeded");
 let return_script:Script=parse_taddr_for(&p.return_address,rpc.net().network_type())?.script().into();
 // Only a pure return to the approved address can consume the reserved return budget.
 let returning=bundle.vout.iter().all(|out|*out.script_pubkey()==return_script);
 let ceiling=if returning {p.max_fee_zat}else{p.max_fee_zat-p.return_reserve_zat};
 reserve(&mut db,&serde_json::to_string(&p)?,&tx.txid().to_string(),&hex::encode(hex::decode(raw)?),fee,ceiling)
}
#[cfg(test)]mod tests {
 use super::*;
 #[test]fn persisted_parent_survives_provider_visibility_delay(){
  let mut db=Connection::open_in_memory().unwrap();reserve(&mut db,"p","id","parent-bytes",10,100).unwrap();
  assert_eq!(known_parent(&db,true,"id",||anyhow::bail!("RPC -5")).unwrap(),"parent-bytes");
  assert!(known_parent(&db,true,"unknown",||anyhow::bail!("RPC -5")).is_err());
 }
 #[test]fn real_reveal_fee_is_derived_from_verified_parent_bytes(){
  let fixture:Value=serde_json::from_str(include_str!("../tests/market-relay.json")).unwrap();
  let raws=fixture["mint_raws"].as_array().unwrap();
  let parse=|raw:&str|Transaction::read(std::io::Cursor::new(hex::decode(raw).unwrap()),index::Net::Regtest.branch_for(108)).unwrap();
  let parents:std::collections::BTreeMap<_,_>=raws.iter().map(|v|{let raw=v.as_str().unwrap();(parse(raw).txid().to_string(),raw.to_owned())}).collect();
  let reveal=raws.iter().map(|v|parse(v.as_str().unwrap())).find(|tx|tx.transparent_bundle().unwrap().vin.iter().all(|vin|{let mut id=*vin.prevout().hash();id.reverse();parents.contains_key(&hex::encode(id))})).expect("fixture must contain a reveal and its parent");
  let fee=fee_from_parents(&reveal,|id|Ok(parents.get(id).context("fixture parent")?.clone())).unwrap();
  assert!(fee>=10000 && fee<=30000);
  assert!(fee_from_parents(&reveal,|_|Ok(fixture["raw"].as_str().unwrap().to_owned())).is_err());
  assert!(fee_from_parents(&reveal,|_|anyhow::bail!("parent unavailable")).is_err());
 }
 #[test]fn limits_exact_retries_and_policy_changes_are_fail_closed(){
  let mut db=Connection::open_in_memory().unwrap();
  reserve(&mut db,"policy","first","aa",10,20).unwrap();
  reserve(&mut db,"policy","first","aa",10,20).unwrap();
  assert!(reserve(&mut db,"policy","first","bb",10,20).is_err());
  assert!(reserve(&mut db,"other","second","cc",10,20).is_err());
  assert!(reserve(&mut db,"policy","second","cc",11,20).is_err());
  reserve(&mut db,"policy","second","cc",10,20).unwrap();
  assert_eq!(db.query_row("SELECT SUM(fee) FROM reservations",[],|r|r.get::<_,u64>(0)).unwrap(),20);
 }
 #[test]fn reservation_persists_when_broadcast_result_is_unknown(){
  let path=std::env::temp_dir().join(format!("overstory-budget-{}.sqlite",hex::encode(Key::random().sk.to_secret_bytes())));
  {let mut db=Connection::open(&path).unwrap();reserve(&mut db,"p","id","aa",10,10).unwrap();}
  {let mut db=Connection::open(&path).unwrap();reserve(&mut db,"p","id","aa",10,10).unwrap();assert!(reserve(&mut db,"p","new","bb",1,10).is_err());}
  fs::remove_file(path).unwrap();
 }
}
