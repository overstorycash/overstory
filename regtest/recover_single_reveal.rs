//! Recovery of an already planned single reveal. Saves a checked plan; never broadcasts.
use anyhow::{Result,Context,ensure};
use proto::{Rpc,Key,index::Db,inscribe::{SignedInscription,SignedTransaction,InscribeResult,RevealPlan}};
use zcash_primitives::transaction::Transaction;
use zcash_transparent::{bundle::{OutPoint,TxOut},address::{Script,TransparentAddress}};
use zcash_protocol::value::Zatoshis;
fn main()->Result<()> {
 let args:Vec<String>=std::env::args().skip(1).collect();ensure!(args.len()==6,"recover-single-reveal <commit> <expected-reveal> <file> <mime> <key> <destination>");
 let rpc=Rpc::open()?;let target=rpc.checked_target()?;let key=Key::load(&args[4])?;
 let conn=rusqlite::Connection::open_with_flags("test-spend-ledger.sqlite",rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
 let raw:String=conn.query_row("SELECT raw FROM reservations WHERE txid=?1",[&args[0]],|r|r.get(0))?;
 let known=rpc.call("getrawtransaction",serde_json::json!([args[0],0]))?;ensure!(known.as_str()==Some(raw.as_str()),"commit not visible with exact saved bytes");
 let commit=Transaction::read(std::io::Cursor::new(hex::decode(&raw)?),rpc.net().branch_for(target))?;ensure!(commit.txid().to_string()==args[0],"commit identity mismatch");
 let expiry=u32::from(commit.expiry_height());ensure!(target<=expiry,"original reveal expired; do not rebuild");
 let content=std::fs::read(&args[2])?;let pieces=proto::inscribe::pieces_of(&content);ensure!(!pieces.is_empty() && pieces.len()<=4,"only one-reveal recovery supported");
 let commitment=proto::inscribe::commitment(args[3].as_bytes(),&content);let redeem=proto::inscribe::redeem_script(&key.pk.serialize(),&commitment,pieces.len());
 let script:Script=TransparentAddress::ScriptHash(proto::inscribe::hash160(&redeem)).script().into();
 let outs=&commit.transparent_bundle().context("transparent commit")?.vout;
 let selected:Vec<_>=outs.iter().enumerate().filter(|(_,out)|*out.script_pubkey()==script).collect();ensure!(selected.len()==1,"commit output ambiguous");let (n,out)=selected[0];
 let reveal=proto::inscribe::build_reveal(&RevealPlan {branch:commit.consensus_branch_id(),commit_outpoint:OutPoint::new(*commit.txid().as_ref(),n as u32),commit_value:out.value().into_u64(),commit_script:script,redeem,content_type:args[3].as_bytes().to_vec(),total:pieces.len(),pieces:pieces.iter().enumerate().rev().map(|(i,p)|(i,p.to_vec())).collect(),outputs:vec![TxOut::new(Zatoshis::from_u64(proto::CARRIER_ZAT)?,proto::parse_taddr_for(&args[5],rpc.net().network_type())?.script().into())],expiry},&key)?;
 ensure!(reveal.txid().to_string()==args[1],"reconstructed reveal differs from originally logged transaction identity; stop");
 let mut bytes=Vec::new();reveal.write(&mut bytes)?;
 let id=format!("{}i0",args[1]);let plan=SignedInscription {funding:vec![],version:1,network:rpc.net().name().into(),genesis_hash:rpc.chain.genesis_hash.clone(),target_height:expiry.checked_sub(39).context("expiry")?,expiry_height:expiry,commit_vout:n as u32,destination:args[5].clone(),transactions:vec![SignedTransaction{txid:args[0].clone(),raw},SignedTransaction{txid:args[1].clone(),raw:hex::encode(bytes)}],result:InscribeResult{inscription_id:id.clone(),commit_txid:args[0].clone(),reveal_txids:vec![args[1].clone()],total_cost:out.value().into_u64()}};
 plan.validate(&rpc)?;proto::inscribe::save_cli_plan(&mut Db::open(proto::index::DB_FILE)?,&plan)?;
 println!("Saved recovery plan {id}; expected reveal identity matched; no broadcast performed.");Ok(())
}
