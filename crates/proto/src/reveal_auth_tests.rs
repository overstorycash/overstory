//! Offline real-signature checks using the Zcash script interpreter, not a mock checker.
use super::*;
use zcash_script::{script::Raw, interpreter::{Flags, CallbackTransactionSignatureChecker}};

fn plan(count: usize, authenticated: bool) -> (Key, RevealPlan) {
    let key=Key::from_secret(&[17;32]).unwrap();
    let content=vec![42;240*count];
    let ct=b"application/json".to_vec();
    let c=commitment(&ct,&content);
    let pieces:Vec<_>=(0..count).rev().map(|i|(i,content[i*240..(i+1)*240].to_vec())).collect();
    let refs:Vec<_>=pieces.iter().map(|(i,p)|(*i,p.as_slice())).collect();
    let redeem=if authenticated {authenticated_redeem_script(&key.pk.serialize(),&c,&ct,count,&refs)} else {redeem_script(&key.pk.serialize(),&c,count)};
    let script=TransparentAddress::ScriptHash(hash160(&redeem)).script().into();
    let p=RevealPlan {branch:BranchId::Nu6_3,commit_outpoint:OutPoint::new([9;32],0),commit_value:1_000_000,commit_script:script,redeem,content_type:ct,total:count,pieces,
        outputs:vec![TxOut::new(zat(546).unwrap(),key.address().script().into()),TxOut::new(zat(500_000).unwrap(),key.address().script().into())],expiry:42};
    (key,p)
}

fn accepts(tx:&Transaction, plan:&RevealPlan, sig:Vec<u8>) -> bool {
    let b=tx.transparent_bundle().unwrap();
    let unsigned=TransactionData::<RevealTxAuth>::from_parts(tx.version(),tx.consensus_branch_id(),tx.lock_time(),tx.expiry_height(),Some(Bundle {
        vin:b.vin.iter().map(|i|TxIn::<RevealAuth>::from_parts(i.prevout().clone(),(),i.sequence())).collect(),
        vout:b.vout.clone(),authorization:RevealAuth{amounts:vec![zat(plan.commit_value).unwrap()],scripts:vec![plan.commit_script.clone()]}}),None,None,None);
    let callback=|code:&zcash_script::script::Code, ht:&zcash_script::signature::HashType| {
        if ht.raw_bits()!=1 { return None; }
        let redeem=script_from_raw(&code.0).ok()?;
        let input=zcash_transparent::sighash::SignableInput::from_parts(unsigned.transparent_bundle()?,SighashType::ALL,0,&redeem,&plan.commit_script,zat(plan.commit_value).ok()?).ok()?;
        Some(*signature_hash(&unsigned,&SignableInput::Transparent(input),&unsigned.digest(TxIdDigester)).as_ref())
    };
    let checker=CallbackTransactionSignatureChecker{sighash:&callback,lock_time:tx.lock_time() as i64,is_final:true};
    // Deliberately omit MinimalData and CleanStack policy flags.
    Raw::from_raw_parts(sig,crate::index::script_bytes(&plan.commit_script)).eval(Flags::P2SH,&checker)==Ok(true)
}

fn pushes(items:&[Vec<u8>], wide:bool)->Vec<u8> {
    let mut s=vec![];
    for item in items {
        if wide { s.push(0x4e);s.extend_from_slice(&(item.len() as u32).to_le_bytes());s.extend_from_slice(item); }
        else { push_bytes(&mut s,item); }
    }
    s
}

#[test]
fn legacy_gap_is_reproduced_by_real_signature_interpreter() {
    let (key,p)=plan(1,false);let tx=build_reveal(&p,&key).unwrap();
    let mut ss=crate::index::script_bytes(tx.transparent_bundle().unwrap().vin[0].script_sig());
    assert!(accepts(&tx,&p,ss.clone()));
    ss[1..4].copy_from_slice(b"bad");
    assert!(accepts(&tx,&p,ss.clone()));
    assert!(crate::index::parse_envelope(&ss).is_none());
}

#[test]
fn authenticated_single_and_four_piece_scripts_reject_every_changed_element() {
    for count in [1,4] {
        let (key,p)=plan(count,true);let tx=build_reveal(&p,&key).unwrap();
        let ss=crate::index::script_bytes(tx.transparent_bundle().unwrap().vin[0].script_sig());
        assert!(accepts(&tx,&p,ss.clone()));
        let parsed=crate::index::parse_pushes(&ss).unwrap();
        let mut items=envelope_stack(&p.content_type,p.total,&p.pieces.iter().map(|(i,v)|(*i,v.as_slice())).collect::<Vec<_>>());
        let n=items.len();items.extend_from_slice(&parsed[parsed.len()-2..]);
        for i in 0..n {
            let mut changed=items.clone(); changed[i].push(1);
            assert!(!accepts(&tx,&p,pushes(&changed,false)),"element {i}");
        }
        let mut extra=vec![vec![9]];extra.extend(items.clone());
        assert!(!accepts(&tx,&p,pushes(&extra,false)),"extra bottom stack item");
        let wide=pushes(&items,true);
        assert!(accepts(&tx,&p,wide.clone()),"equivalent push encoding");
        assert!(crate::index::parse_envelope(&wide).unwrap().authenticated);
        let mut wrong_sig=items.clone();wrong_sig[n][8]^=1;
        assert!(!accepts(&tx,&p,pushes(&wrong_sig,false)),"signature must really verify");
        assert!(p.redeem.len()<=520);
        assert!(ss.len()<=1650);
    }
}

#[test]
fn authenticated_reclaim_uses_same_checks_and_signed_non_mint_outputs() {
    let (key,mut p)=plan(4,true);
    p.outputs=vec![TxOut::new(zat(0).unwrap(),script_from_raw(&reclaim_marker()).unwrap()),TxOut::new(zat(800_000).unwrap(),key.address().script().into())];
    let tx=build_reclaim(&p,&key).unwrap();let ss=crate::index::script_bytes(tx.transparent_bundle().unwrap().vin[0].script_sig());
    assert!(accepts(&tx,&p,ss));
    p.outputs.remove(0);assert!(build_reclaim(&p,&key).is_err());
}

#[test]
fn original_signature_cannot_authorize_a_different_payment_output() {
    let (key,p)=plan(1,true);let tx=build_reveal(&p,&key).unwrap();
    let b=tx.transparent_bundle().unwrap();
    let ss=crate::index::script_bytes(b.vin[0].script_sig());
    let mut outputs=b.vout.clone();
    outputs[1]=TxOut::new(zat(499_999).unwrap(),key.address().script().into());
    let changed=TransactionData::<Authorized>::from_parts(tx.version(),tx.consensus_branch_id(),tx.lock_time(),tx.expiry_height(),Some(Bundle {
        vin:b.vin.clone(),vout:outputs,authorization:bundle::Authorized}),None,None,None).freeze().unwrap();
    assert!(!accepts(&changed,&p,ss));
}
