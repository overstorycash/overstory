//! Permanent local quarantine and externally-paid evidence. Never signs or broadcasts.
//! A receipt is not a liability calculation, an entitlement proof, or case closure.
use crate::*;
use rusqlite::{Connection, OptionalExtension, TransactionBehavior};
use sha2::{Digest,Sha256};
use std::collections::{BTreeMap,BTreeSet};
const NS:&str="manual-cases";
fn digest(b:&[u8])->String {hex::encode(Sha256::digest(b))}
fn raw_tx(raw:&str,net:index::Net)->Result<Transaction> {
 let bytes=hex::decode(raw)?;let mut c=std::io::Cursor::new(&bytes);
 let tx=Transaction::read(&mut c,net.branch_for(1))?;
 anyhow::ensure!(c.position() as usize==bytes.len(),"trailing transaction bytes");Ok(tx)
}
fn point(p:&OutPoint)->String {let mut h=*p.hash();h.reverse();format!("{}:{}",hex::encode(h),p.n())}
#[derive(Default,Serialize,Deserialize)]
struct Inventory {known_ids:BTreeSet<String>,points:BTreeSet<String>,transactions:BTreeMap<String,String>,incomplete:bool}
fn inventory(v:&Value,net:index::Net,out:&mut Inventory) {
 match v {
  Value::Array(a)=>for x in a {inventory(x,net,out)},
  Value::Object(m)=>{
   if let (Some(id),Some(n))=(v["txid"].as_str(),v["n"].as_u64()) {
    if id.len()==64 && hex::decode(id).is_ok() && n<=u32::MAX as u64 {out.points.insert(format!("{id}:{n}"));}
    else {out.incomplete=true;}
   }
   if let Some(ins)=m.get("inscription_id").and_then(Value::as_str) {
    if let Some((id,_))=ins.split_once('i') {if id.len()==64 && hex::decode(id).is_ok(){out.known_ids.insert(id.to_ascii_lowercase());}else{out.incomplete=true;}}
   }
   if let Some(ids)=m.get("txids") {
    if let Some(ids)=ids.as_array() {for id in ids {if let Some(id)=id.as_str().filter(|s|s.len()==64 && hex::decode(s).is_ok()) {out.known_ids.insert(id.to_ascii_lowercase());}else{out.incomplete=true;}}}else{out.incomplete=true;}
   }
   if let Some(id)=v["txid"].as_str().filter(|_|!m.contains_key("n")) {out.known_ids.insert(id.to_ascii_lowercase());}
   for (k,x) in m {
    if k=="raw" || k=="raw_transaction" {
     let parsed=x.as_str().and_then(|r|raw_tx(r,net).ok());
     if let Some(tx)=parsed {
      let id=tx.txid().to_string();out.known_ids.insert(id.clone());out.transactions.insert(id.clone(),x.as_str().unwrap().into());
      if let Some(b)=tx.transparent_bundle() {
       for i in &b.vin {out.points.insert(point(i.prevout()));}
       for n in 0..b.vout.len(){out.points.insert(format!("{id}:{n}"));}
      } else {out.incomplete=true;}
     } else {out.incomplete=true;}
    }
    inventory(x,net,out);
   }
  },_=>{}
 }
}
fn records(db:&Connection)->Result<Vec<Value>> {
 let mut q=db.prepare("SELECT json FROM kv WHERE ns=?1")?;
 let mut out=Vec::new();
 for row in q.query_map([NS],|r|r.get::<_,String>(0))? {
  let v:Value=serde_json::from_str(&row?)?;
  anyhow::ensure!(v["version"]==1 && v["state"]=="held","invalid manual quarantine record");
  out.push(v);
 }
 Ok(out)
}
pub fn ensure_standard_allowed(db:&Connection,id:&str)->Result<()> {
 let exists:bool=db.query_row("SELECT EXISTS(SELECT 1 FROM kv WHERE ns=?1 AND k=?2)",(NS,id),|r|r.get(0))?;
 anyhow::ensure!(!exists,"manual takeover active; standard settlement is disabled");Ok(())
}
pub fn ensure_address(db:&Connection,address:&str)->Result<()> {
 for v in records(db)? {
  let invoice=v["original_order"]["invoice_address"].as_str().context("manual invoice missing")?;
  anyhow::ensure!(invoice!=address,"invoice under manual takeover, including late funds");
  anyhow::ensure!(v["inventory"]["incomplete"]==false,"manual inventory incomplete; local spending paused");
 }
 Ok(())
}
fn held(db:&Connection,id:&str)->Result<Value> {
 let raw:String=db.query_row("SELECT json FROM kv WHERE ns=?1 AND k=?2",(NS,id),|r|r.get(0))?;
 let v:Value=serde_json::from_str(&raw)?;
 let order:String=db.query_row("SELECT json FROM kv WHERE ns='orders' AND k=?1",[id],|r|r.get(0))?;
 let o:Value=serde_json::from_str(&order)?;
 anyhow::ensure!(v["version"]==1 && v["order_id"]==id && v["state"]=="held" && o["settlement_hold"]==true,"manual takeover marker mismatch");
 // Worker/reorg metadata may change; original signatures, money and destinations may not.
 let mut a=o;let mut b=v["original_order"].clone();
 for x in [&mut a,&mut b] {if let Some(rs)=x["refunds"].as_array_mut(){for r in rs{if let Some(m)=r.as_object_mut(){m.remove("confirmation");}}}if let Some(m)=x.as_object_mut(){for k in ["status","error","retry_after","attempts","number","seed","settlement_hold"]{m.remove(k);}}}
 anyhow::ensure!(a==b,"manual original terms changed; preserve evidence and investigate");Ok(v)
}
fn summary(v:&Value)->Value {json!({"order_id":v["order_id"],"state":"manual_hold","signs":false,"broadcast":false,"authorizes_payment":false,"case_closed":false,"remaining_liability":null,"inventory_incomplete":v["inventory"]["incomplete"],"scope":"same-runtime quarantine only; existing signatures and external wallets remain outside its control"})}
fn hold_tx(db:&mut Connection,chain:&network::ChainConfig,id:&str,reason:&str)->Result<Value> {
 anyhow::ensure!(!reason.trim().is_empty() && reason.len()<=2000,"give a nonempty reason, at most 2000 bytes");
 let tx=db.transaction_with_behavior(TransactionBehavior::Immediate)?;
 let exists:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM kv WHERE ns=?1 AND k=?2)",(NS,id),|r|r.get(0))?;
 if exists {let v=held(&tx,id)?;anyhow::ensure!(v["network"]==chain.network && v["genesis_hash"]==chain.genesis_hash,"manual chain mismatch");return Ok(summary(&v));}
 let raw:String=tx.query_row("SELECT json FROM kv WHERE ns='orders' AND k=?1",[id],|r|r.get(0))?;
 let o:Value=serde_json::from_str(&raw)?;anyhow::ensure!(o["id"]==id,"order id mismatch");
 parse_taddr_for(o["invoice_address"].as_str().context("missing invoice address")?,chain.net()?.network_type())?;
 let mut related=BTreeMap::new();
 let inscription=o["mint_plan"]["result"]["inscription_id"].as_str().or_else(||o["inscription_id"].as_str()).unwrap_or("");
 {let mut q=tx.prepare("SELECT ns,json FROM kv WHERE (k=?1 AND ns IN ('service-settlements','service-settlement-payouts','service-settlement-recoveries','service-settlement-late')) OR (k=?2 AND ns IN ('cli-inscription-plans','expired-reclaims','self-mint-refunds'))")?;
 for row in q.query_map([id,inscription],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?)))?{let(n,r)=row?;related.insert(n,serde_json::from_str::<Value>(&r)?);}}
 let mut inv=Inventory::default();inventory(&o,chain.net()?,&mut inv);inventory(&json!(related),chain.net()?,&mut inv);
 for (ns,r) in &related {
  let refund_ok=|p:&Value|serde_json::from_value::<refund::RefundPlan>(p.clone()).is_ok();
  let valid=match ns.as_str() {
   "service-settlement-payouts"|"expired-reclaims"=>refund_ok(&r["plan"]),
   "service-settlement-recoveries"=>r["plans"].as_array().is_some_and(|ps|!ps.is_empty() && ps.iter().all(refund_ok)),
   "service-settlement-late"=>r["observed"].is_object() && r["batches"].as_array().is_some_and(|bs|bs.iter().all(|b|refund_ok(&b["plan"]))),
   "cli-inscription-plans"=>serde_json::from_value::<inscribe::SignedInscription>(r.clone()).is_ok(),
   "service-settlements"=>r["original_order"].is_object() && r["reserved_outpoints"].is_array(),
   "self-mint-refunds"=>r["claim"].is_object() && r.get("plan").is_some_and(|p|p.is_null() || refund_ok(p)),
   _=>false,
  };if !valid {inv.incomplete=true;}
 }
 let mut reservations=BTreeMap::new();
 {let mut q=tx.prepare("SELECT k,json FROM kv WHERE ns='service-settlement-inputs'")?;
 for row in q.query_map([],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?)))? {
  let (point,raw)=row?;let owner:Value=serde_json::from_str(&raw)?;
  if owner["order_id"]==id {inv.points.insert(point.clone());reservations.insert(point,owner);}
 }}
 if inv.known_ids.iter().any(|id|!inv.transactions.contains_key(id)){inv.incomplete=true;}
 if o["refunds"].as_array().is_some_and(|rs|rs.iter().any(|r|serde_json::from_value::<refund::RefundPlan>(r["plan"].clone()).is_err())) {inv.incomplete=true;}
 if o["receipts"].as_object().is_some_and(|rs|rs.values().any(|r|serde_json::from_value::<Utxo>(r.clone()).is_err())) {inv.incomplete=true;}
 // Invalid journals must never be interpreted as an empty set of signed transactions.
 if !o["refunds"].is_array() || !o["receipts"].is_object() || (!o["mint_plan"].is_null() && serde_json::from_value::<inscribe::SignedInscription>(o["mint_plan"].clone()).is_err()) {inv.incomplete=true;}
 let record=json!({"version":1,"state":"held","order_id":id,"network":chain.network,"genesis_hash":chain.genesis_hash,"reason":reason,"original_order":o,"original_sha256":digest(raw.as_bytes()),"related":related,"prior_reservations":reservations,"inventory":inv});
 let mut frozen=o;frozen["settlement_hold"]=json!(true);frozen["status"]=json!("recovery_required");frozen["error"]=json!("manual takeover: automatic execution disabled; liability remains unresolved");
 for p in &inv.points {tx.execute("INSERT OR IGNORE INTO kv(ns,k,json) VALUES('manual-inputs',?1,?2)",(p,json!({"order_id":id}).to_string()))?;}
 tx.execute("INSERT INTO kv(ns,k,json) VALUES(?1,?2,?3)",(NS,id,record.to_string()))?;
 tx.execute("UPDATE kv SET json=?1 WHERE ns='orders' AND k=?2",(frozen.to_string(),id))?;
 tx.execute("INSERT INTO kv(ns,k,json) VALUES('operator-actions',?1,?2)",(format!("manual-hold:{id}"),summary(&record).to_string()))?;
 tx.commit()?;Ok(summary(&record))
}
/// Caller holds mintd worker lock. No node or key access is needed to quarantine.
pub fn hold(path:&str,chain:&network::ChainConfig,id:&str,reason:&str)->Result<Value> {
 let _lock=refund_claim::wallet_lock(&std::path::Path::new(path).parent().context("database parent")?.join("wallet.lock"))?;
 let mut db=index::Db::open(path)?;hold_tx(&mut db.conn,chain,id,reason)
}
/// Guard raw replay as well as fresh sends. Missing previous outputs fail closed.
pub fn check_raw(rpc:&Rpc,raw:&str)->Result<()> {check_raw_inner(rpc,raw,true)}
pub fn check_saved(rpc:&Rpc,raw:&str)->Result<()> {check_raw_inner(rpc,raw,false)}
fn check_raw_inner(rpc:&Rpc,raw:&str,check_previous_outputs:bool)->Result<()> {
 if !std::path::Path::new(index::DB_FILE).exists(){return Ok(());}
 let db=Connection::open_with_flags(index::DB_FILE,rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
 let cases=records(&db)?;if cases.is_empty(){return Ok(());}
 let tx=raw_tx(raw,rpc.net())?;let id=tx.txid().to_string();let b=tx.transparent_bundle().context("manual guard requires transparent transaction")?;
 let mut scripts=BTreeSet::new();
 for v in cases {
  anyhow::ensure!(v["network"]==rpc.chain.network && v["genesis_hash"]==rpc.chain.genesis_hash,"manual guard chain mismatch");
  let inv:Inventory=serde_json::from_value(v["inventory"].clone())?;
  anyhow::ensure!(!inv.incomplete,"manual inventory incomplete; local broadcast paused");
  anyhow::ensure!(!inv.known_ids.contains(&id) && b.vin.iter().all(|i|!inv.points.contains(&point(i.prevout()))),"transaction or input is under manual takeover");
  let address=v["original_order"]["invoice_address"].as_str().context("manual invoice missing")?;
  scripts.insert(index::script_bytes(&parse_taddr_for(address,rpc.net().network_type())?.script().into()));
 }
 if !check_previous_outputs {return Ok(());}
 for i in &b.vin {
  let p=point(i.prevout());let (id,n)=p.split_once(':').unwrap();
  let raw=rpc.call("getrawtransaction",json!([id,0]))?;let prev=raw_tx(raw.as_str().context("missing input transaction")?,rpc.net())?;
  anyhow::ensure!(prev.txid().to_string()==id,"input transaction identity mismatch");
  let output=prev.transparent_bundle().and_then(|b|b.vout.get(n.parse::<usize>().ok()?)).context("missing input output")?;
  anyhow::ensure!(!scripts.contains(&index::script_bytes(output.script_pubkey())),"late invoice funds are under manual takeover");
 }
 Ok(())
}
fn save_payment(db:&mut Connection,id:&str,key:&str,record:&Value)->Result<Value> {
 let tx=db.transaction_with_behavior(TransactionBehavior::Immediate)?;let _=held(&tx,id)?;
 let old:Option<String>=tx.query_row("SELECT json FROM kv WHERE ns='manual-payments' AND k=?1",[key],|r|r.get(0)).optional()?;
 if let Some(old)=old {
  let old:Value=serde_json::from_str(&old)?;
  for k in ["order_id","network","genesis_hash","point","address","amount_zat","raw_sha256","evidence_sha256"] {anyhow::ensure!(old[k]==record[k],"payment output already registered with different case or evidence");}
  return Ok(json!({"registered":true,"duplicate":true,"case_closed":false,"remaining_liability":null}));
 }
 tx.execute("INSERT INTO kv(ns,k,json) VALUES('manual-payments',?1,?2)",(key,record.to_string()))?;
 tx.execute("INSERT INTO kv(ns,k,json) VALUES('operator-actions',?1,?2)",(format!("manual-payment:{key}"),json!({"order_id":id,"point":key,"case_closed":false,"broadcast":false}).to_string()))?;
 tx.commit()?;Ok(json!({"registered":true,"duplicate":false,"case_closed":false,"remaining_liability":null,"broadcast":false}))
}
/// Records already-paid transparent output; never marks a case paid/closed or lifts a hold.
pub fn register(rpc:&Rpc,path:&str,id:&str,point:&str,address:&str,amount:u64,evidence_path:&str)->Result<Value> {
 let _lock=refund_claim::wallet_lock(&std::path::Path::new(path).parent().context("database parent")?.join("wallet.lock"))?;
 let evidence=fs::read(evidence_path)?;anyhow::ensure!(!evidence.is_empty() && evidence.len()<=65536,"evidence must be 1..65536 bytes");
 let mut db=index::Db::open(path)?;let v=held(&db.conn,id)?;
 anyhow::ensure!(v["network"]==rpc.chain.network && v["genesis_hash"]==rpc.chain.genesis_hash,"manual payment chain mismatch");
 let expected=v["original_order"]["refund_address"].as_str().filter(|x|!x.is_empty());
 if let Some(expected)=expected {anyhow::ensure!(address==expected,"fixed refund address mismatch");}
 parse_taddr_for(address,rpc.net().network_type())?;anyhow::ensure!(amount>0,"zero payment");zat(amount)?;
 let (txid,n)=point.split_once(':').context("expected txid:vout")?;let n:u32=n.parse()?;
 anyhow::ensure!(txid.len()==64 && hex::decode(txid)?.len()==32 && point==format!("{}:{n}",txid.to_ascii_lowercase()),"noncanonical payment outpoint");
 let start=rpc.height()?;let start_hash=rpc.call("getblockhash",json!([start]))?;
 let raw=rpc.call("getrawtransaction",json!([txid,0]))?;let raw=raw.as_str().context("payment bytes missing")?;
 let tx=raw_tx(raw,rpc.net())?;anyhow::ensure!(tx.txid().to_string()==txid,"payment transaction mismatch");
 let output=tx.transparent_bundle().and_then(|b|b.vout.get(n as usize)).context("payment output missing")?;
 anyhow::ensure!(output.value().into_u64()==amount && index::script_bytes(output.script_pubkey())==index::script_bytes(&parse_taddr_for(address,rpc.net().network_type())?.script().into()),"payment amount or destination mismatch");
 let confirmation=audit::transaction(rpc,txid,raw)?;anyhow::ensure!(confirmation["state"]=="confirmed","payment not canonically confirmed");
 // A saved automatic payment cannot also be attributed as a new external/manual payment.
 {let mut q=db.conn.prepare("SELECT json FROM kv WHERE ns IN ('orders','service-settlement-payouts','service-settlement-recoveries','service-settlement-late','self-mint-refunds','cli-inscription-plans','expired-reclaims','service-settlements','manual-cases')")?;
 for row in q.query_map([],|r|r.get::<_,String>(0))? {let mut inv=Inventory::default();inventory(&serde_json::from_str::<Value>(&row?)?,rpc.net(),&mut inv);anyhow::ensure!(!inv.known_ids.contains(txid),"payment is already part of an automatic plan");}}
 let mut original=Vec::new();let inv:Inventory=serde_json::from_value(v["inventory"].clone())?;
 for (id,raw) in &inv.transactions {original.push(audit::transaction(rpc,id,raw)?);}
 anyhow::ensure!(rpc.height()?==start && rpc.call("getblockhash",json!([start]))?==start_hash,"chain changed during payment verification");
 let record=json!({"version":1,"order_id":id,"network":rpc.chain.network,"genesis_hash":rpc.chain.genesis_hash,"point":point,"txid":txid,"raw":raw,"raw_sha256":digest(raw.as_bytes()),"address":address,"amount_zat":amount,"evidence_sha256":digest(&evidence),"evidence":String::from_utf8(evidence)?,"confirmation_observed":confirmation,"original_transactions_observed":original,"authorization_verified":false,"fixed_address_present":expected.is_some(),"case_closed":false,"remaining_liability":null});
 save_payment(&mut db.conn,id,point,&record)
}
pub fn report(rpc:&Rpc,path:&str,id:&str)->Result<Value> {
 let db=index::Db::open(path)?;let v=held(&db.conn,id)?;
 anyhow::ensure!(v["network"]==rpc.chain.network && v["genesis_hash"]==rpc.chain.genesis_hash,"manual report chain mismatch");
 let height=rpc.height()?;let hash=rpc.call("getblockhash",json!([height]))?;
 let mut payments=Vec::new();let mut q=db.conn.prepare("SELECT json FROM kv WHERE ns='manual-payments'")?;
 for row in q.query_map([],|r|r.get::<_,String>(0))?{let p:Value=serde_json::from_str(&row?)?;if p["order_id"]==id {let checked=audit::transaction(rpc,p["txid"].as_str().context("txid")?,p["raw"].as_str().context("raw")?)?;payments.push(json!({"point":p["point"],"amount_zat":p["amount_zat"],"current_observation":checked,"historical_confirmation":p["confirmation_observed"]}));}}
 let inv:Inventory=serde_json::from_value(v["inventory"].clone())?;let mut original=Vec::new();for (id,raw) in inv.transactions {original.push(audit::transaction(rpc,&id,&raw)?);}
 anyhow::ensure!(rpc.height()?==height && rpc.call("getblockhash",json!([height]))?==hash,"chain changed during manual report");
 Ok(json!({"case":summary(&v),"payments":payments,"original_transactions":original,"read_only":true,"authorizes_payment":false,"case_closed":false,"remaining_liability":null}))
}
#[cfg(test)]
mod tests {
 use super::*;
 fn setup()->(Connection,network::ChainConfig,String) {
  let db=Connection::open_in_memory().unwrap();db.execute_batch("CREATE TABLE kv(ns TEXT,k TEXT,json TEXT,PRIMARY KEY(ns,k));").unwrap();
  let chain=network::ChainConfig{network:"regtest".into(),genesis_hash:"01".repeat(32)};let addr=Key::from_secret(&[7;32]).unwrap().address_string(index::Net::Regtest);
  let o=json!({"id":"a","invoice_address":addr,"refund_address":addr,"refunds":[],"receipts":{},"mint_plan":null,"status":"awaiting_payment"});
  db.execute("INSERT INTO kv VALUES('orders','a',?1)",[o.to_string()]).unwrap();(db,chain,addr)
 }
 #[test] fn legacy_hold_needs_no_rpc_and_is_idempotent(){let(mut db,c,a)=setup();hold_tx(&mut db,&c,"a","legacy review").unwrap();hold_tx(&mut db,&c,"a","again").unwrap();assert!(ensure_address(&db,&a).is_err());assert!(ensure_standard_allowed(&db,"a").is_err());assert!(ensure_standard_allowed(&db,"other").is_ok());assert_eq!(held(&db,"a").unwrap()["original_order"]["status"],"awaiting_payment");}
 #[test] fn hold_sql_failure_rolls_back(){let(mut db,c,_)=setup();db.execute_batch("CREATE TRIGGER fail BEFORE INSERT ON kv WHEN NEW.ns='operator-actions' BEGIN SELECT RAISE(ABORT,'fail'); END;").unwrap();assert!(hold_tx(&mut db,&c,"a","review").is_err());assert!(ensure_standard_allowed(&db,"a").is_ok());let raw:String=db.query_row("SELECT json FROM kv WHERE ns='orders'",[],|r|r.get(0)).unwrap();assert!(serde_json::from_str::<Value>(&raw).unwrap()["settlement_hold"].is_null());}
 #[test] fn original_terms_cannot_change(){let(mut db,c,_)=setup();hold_tx(&mut db,&c,"a","review").unwrap();let mut o=held(&db,"a").unwrap()["original_order"].clone();o["settlement_hold"]=json!(true);o["refund_address"]=json!("changed");db.execute("UPDATE kv SET json=?1 WHERE ns='orders'",[o.to_string()]).unwrap();assert!(held(&db,"a").is_err());}
 #[test] fn duplicate_payment_is_idempotent_but_different_terms_rejected(){let(mut db,c,a)=setup();hold_tx(&mut db,&c,"a","review").unwrap();let r=json!({"order_id":"a","point":"p:0","address":a,"amount_zat":100,"network":c.network,"genesis_hash":c.genesis_hash,"raw_sha256":"x","evidence_sha256":"y"});assert_eq!(save_payment(&mut db,"a","p:0",&r).unwrap()["duplicate"],false);assert_eq!(save_payment(&mut db,"a","p:0",&r).unwrap()["duplicate"],true);let mut changed=r;changed["amount_zat"]=json!(101);assert!(save_payment(&mut db,"a","p:0",&changed).is_err());assert_eq!(held(&db,"a").unwrap()["state"],"held");}
 #[test] fn payment_write_failure_rolls_back(){let(mut db,c,_)=setup();hold_tx(&mut db,&c,"a","review").unwrap();db.execute_batch("CREATE TRIGGER fail BEFORE INSERT ON kv WHEN NEW.ns='operator-actions' BEGIN SELECT RAISE(ABORT,'fail'); END;").unwrap();assert!(save_payment(&mut db,"a","p:0",&json!({"order_id":"a"})).is_err());let n:u64=db.query_row("SELECT COUNT(*) FROM kv WHERE ns='manual-payments'",[],|r|r.get(0)).unwrap();assert_eq!(n,0);assert!(held(&db,"a").is_ok());}
 #[test] fn damaged_related_journal_and_reservations_are_quarantined(){let(mut db,c,_)=setup();db.execute("INSERT INTO kv VALUES('service-settlement-payouts','a','{}')",[]).unwrap();db.execute("INSERT INTO kv VALUES('service-settlement-inputs','reserve:0',?1)",[json!({"order_id":"a"}).to_string()]).unwrap();assert_eq!(hold_tx(&mut db,&c,"a","broken record").unwrap()["inventory_incomplete"],true);let v=held(&db,"a").unwrap();assert!(v["inventory"]["points"].as_array().unwrap().contains(&json!("reserve:0")));}
 #[test] fn legacy_txids_without_bytes_force_quarantine(){let(mut db,c,_)=setup();let mut o:Value=serde_json::from_str(&db.query_row("SELECT json FROM kv WHERE ns='orders'",[],|r|r.get::<_,String>(0)).unwrap()).unwrap();o["txids"]=json!(["ab".repeat(32)]);db.execute("UPDATE kv SET json=?1 WHERE ns='orders'",[o.to_string()]).unwrap();let r=hold_tx(&mut db,&c,"a","legacy").unwrap();assert_eq!(r["inventory_incomplete"],true);}
 #[test] fn malformed_signed_bytes_are_not_empty_inventory(){let mut i=Inventory::default();inventory(&json!({"plan":{"raw":"bad"}}),index::Net::Regtest,&mut i);assert!(i.incomplete);}
}
