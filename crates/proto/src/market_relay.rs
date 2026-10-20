//! Narrow public relay policy: only the website's transparent project-market purchase shape.
//! This is not transaction consensus validation; the node still verifies every signature/input.
use crate::*;
fn parse(raw:&str,net:index::Net,target:u32)->Result<Transaction> {
 anyhow::ensure!(raw.len()<=128_000,"transaction too large");
 let bytes=hex::decode(raw)?;let mut cursor=std::io::Cursor::new(&bytes);
 let tx=Transaction::read(&mut cursor,net.branch_for(target))?;
 anyhow::ensure!(cursor.position() as usize==bytes.len(),"trailing transaction bytes");
 anyhow::ensure!(tx.sapling_bundle().is_none() && tx.orchard_bundle().is_none(),"public market relay is transparent only");
 anyhow::ensure!(matches!(tx.version(),zcash_primitives::transaction::TxVersion::V5|zcash_primitives::transaction::TxVersion::V6),"unsupported market transaction version");
 let b=tx.transparent_bundle().context("missing transparent purchase")?;
 anyhow::ensure!(b.vin.len()==2 && (2..=4).contains(&b.vout.len()),"public relay accepts market purchases only; mint with your own RPC");
 Ok(tx)
}
fn point(p:&OutPoint)->String {let mut h=*p.hash();h.reverse();format!("{}:{}",hex::encode(h),p.n())}
pub fn candidate(raw:&str,net:index::Net,target:u32)->Result<(String,String)> {
 let tx=parse(raw,net,target)?;Ok((point(tx.transparent_bundle().unwrap().vin[1].prevout()),tx.txid().to_string()))
}
fn unlock(script:&[u8],hash_type:u8)->Result<(Vec<u8>,PublicKey)> {
 let n=usize::from(*script.first().context("missing signature push")?);
 anyhow::ensure!((9..=73).contains(&n) && script.len()==n+35 && script[n+1]==33 && script[n]==hash_type,"nonstandard purchase input");
 let sig=script[1..n].to_vec();Signature::from_der(&sig)?;
 let key=PublicKey::from_slice(&script[n+2..])?;
 Ok((sig,key))
}
pub fn validate(raw:&str,net:index::Net,target:u32,l:&Listing,st:&index::State,collection:&str)->Result<String> {
 validate_policy(raw,net,target,l,st,collection,None)
}
pub fn validate_with_fee(raw:&str,net:index::Net,target:u32,l:&Listing,st:&index::State,collection:&str,recipient:&str)->Result<String> {
 validate_policy(raw,net,target,l,st,collection,Some(recipient))
}
fn validate_policy(raw:&str,net:index::Net,target:u32,l:&Listing,st:&index::State,collection:&str,recipient:Option<&str>)->Result<String> {
 let tx=parse(raw,net,target)?;let b=tx.transparent_bundle().unwrap();
 anyhow::ensure!(l.version==2 && l.slot==1 && l.network==net.name() && l.branch==network::branch_name(tx.consensus_branch_id()),"listing network/version mismatch");
 anyhow::ensure!(u32::from(tx.expiry_height())==l.expiry_height,"listing expiry mismatch");
 anyhow::ensure!(point(b.vin[1].prevout())==format!("{}:{}",l.carrier_txid,l.carrier_vout),"wrong listed carrier");
 let funding=point(b.vin[0].prevout());
 anyhow::ensure!(!st.carriers.contains_key(&funding) && !st.pending.contains_key(&funding),"funding consumes another inscription");
 // Membership survives transfers; retries may refer to a carrier already spent by this same transaction.
 let id=format!("{}:{}",l.carrier_txid,l.carrier_vout);
 let member=st.single_carrier(&id).or_else(||st.single_carrier(&format!("{}:0",tx.txid())));
 anyhow::ensure!(member.is_some_and(|id|st.mints.get(id).is_some_and(|m|m.collection==collection)),"not a project market asset");
 let (_,buyer)=unlock(&index::script_bytes(b.vin[0].script_sig()),1)?;
 let (seller_sig,seller)=unlock(&index::script_bytes(b.vin[1].script_sig()),0x83)?;
 anyhow::ensure!(hex::encode(seller.serialize())==l.seller_pubkey && hex::decode(&l.signature_der)?==seller_sig,"input differs from published seller authorization");
 let seller_script:Script=parse_taddr_for(&l.payout_address,net.network_type())?.script().into();
 anyhow::ensure!(b.vout[1].value().into_u64()==l.price_zat && *b.vout[1].script_pubkey()==seller_script,"seller payout differs from listing");
 let buyer_script:Script=TransparentAddress::from_pubkey(&buyer).script().into();
 anyhow::ensure!(b.vout[0].value().into_u64()==CARRIER_ZAT && *b.vout[0].script_pubkey()==buyer_script,"purchase recipient differs from signing buyer");
 let change_index = if let Some(recipient) = recipient {
  let q=crate::market_fee::quote(l.price_zat).map_err(anyhow::Error::msg)?;
  let address=parse_taddr_for(recipient,net.network_type())?;
  anyhow::ensure!(matches!(address,TransparentAddress::PublicKeyHash(_)),"market recipient must be P2PKH");
  let expected:Script=address.script().into();
  anyhow::ensure!((3..=4).contains(&b.vout.len()),"missing market fee output");
  anyhow::ensure!(b.vout[2].value().into_u64()==q.market_fee_zat && *b.vout[2].script_pubkey()==expected,"incorrect market fee or recipient");
  3
 } else {anyhow::ensure!(b.vout.len()<=3,"unexpected purchase output");2};
 if b.vout.len()>change_index {anyhow::ensure!(*b.vout[change_index].script_pubkey()==buyer_script,"purchase change differs from signing buyer");}
 Ok(tx.txid().to_string())
}
#[cfg(test)]mod tests {
 use super::*;
 fn fixture()->(Value,Listing,index::State) {
  let v:Value=serde_json::from_str(include_str!("../tests/market-relay.json")).unwrap();let l:Listing=serde_json::from_value(v["listing"].clone()).unwrap();let mut st=index::State::default();let id=v["inscription"].as_str().unwrap().to_string();
  st.carriers.insert(format!("{}:{}",l.carrier_txid,l.carrier_vout),std::collections::BTreeSet::from([id.clone()]));
  st.mints.insert(id.clone(),index::Mint {inscription:id,collection:v["collection"].as_str().unwrap().into(),number:1,minter:"fixture".into(),height:1,seed:"11".repeat(32)});
  (v,l,st)
 }
 #[test]fn actual_wasm_purchase_and_exact_retry_pass_local_policy() {
  let(v,l,mut st)=fixture();let raw=v["raw"].as_str().unwrap();let id=v["txid"].as_str().unwrap();let col=v["collection"].as_str().unwrap();
  assert_eq!(validate(raw,index::Net::Regtest,108,&l,&st,col).unwrap(),id);
  let members=st.carriers.remove(&format!("{}:{}",l.carrier_txid,l.carrier_vout)).unwrap();st.carriers.insert(format!("{id}:0"),members);
  assert_eq!(validate(raw,index::Net::Regtest,108,&l,&st,col).unwrap(),id);
 }
 #[test]fn mint_malformed_foreign_asset_and_changed_terms_are_rejected() {
  let(v,l,st)=fixture();let raw=v["raw"].as_str().unwrap();let col=v["collection"].as_str().unwrap();
  for mint in v["mint_raws"].as_array().unwrap(){assert!(candidate(mint.as_str().unwrap(),index::Net::Regtest,108).is_err());}
  assert!(candidate(&format!("{raw}00"),index::Net::Regtest,108).is_err());
  assert!(validate(raw,index::Net::Regtest,108,&l,&st,"foreign").is_err());
  assert!(validate(raw,index::Net::Regtest,108,&l,&index::State::default(),col).is_err());
  for name in ["price","expiry","signature","network","pubkey"] {
   let mut changed=l.clone();match name {"price"=>changed.price_zat+=1,"expiry"=>changed.expiry_height+=1,"signature"=>changed.signature_der="00".into(),"network"=>changed.network="mainnet".into(),_=>changed.seller_pubkey="00".into()};
   assert!(validate(raw,index::Net::Regtest,108,&changed,&st,col).is_err(),"{name}");
  }
  let changed=raw.replacen("22020000000000001976a914","23020000000000001976a914",1);assert_ne!(changed,raw);assert!(validate(&changed,index::Net::Regtest,108,&l,&st,col).is_err());
 }
}
