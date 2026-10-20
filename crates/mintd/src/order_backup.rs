//! Invoice recovery protection. No remote wait while holding the worker mutex.
use super::*;
use sha2::{Digest, Sha256};
use std::process::Stdio;
use tokio::io::AsyncWriteExt;
const NS: &str = "invoice_backup_v1";

pub(super) fn terms(app: &App, order: &Order) -> serde_json::Value {
    json!({"version":1,"network":app.net.name(),"genesis_hash":app.genesis_hash,
        "collection":app.cfg.collection,"order":{
            "id":order.id,"dest":order.dest,"invoice_address":order.invoice_address,
            "amount_zat":order.amount_zat,"created":order.created,"expires":order.expires,
            "payment_start_height":order.payment_start_height,"kind":order.kind,
            "refund_address":order.refund_address,"quote":order.quote,"invoice_intent":order.invoice_intent}})
}
fn hex_digest(v: &serde_json::Value) -> bool {
    v.as_str().is_some_and(|s|s.len()==64 && s.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b)))
}
pub(super) fn ready(app: &App, order: &Order) -> bool {
    if app.net == Net::Regtest { return true; }
    let raw: Result<String, _> = app.db.conn.query_row("SELECT json FROM kv WHERE ns=?1 AND k=?2", [NS,&order.id], |r|r.get(0));
    let Ok(raw)=raw else {return false};
    let Ok(receipt)=serde_json::from_str::<serde_json::Value>(&raw) else {return false};
    receipt["terms"]==terms(app,order) && receipt["stored"]==true && hex_digest(&receipt["cipher_sha256"])
}
pub(super) fn unavailable() -> Response {
    (StatusCode::SERVICE_UNAVAILABLE,Json(json!({"error":"invoice backup pending; retry the same request; no payment address is available"}))).into_response()
}
async fn invoke(packet: Vec<u8>) -> Result<serde_json::Value> {
    let result=tokio::time::timeout(Duration::from_secs(15),async move {
        let mut child=tokio::process::Command::new("/usr/bin/python3")
            .arg("/opt/overstory-order-backup/order_backup_sender.py")
            .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null())
            .kill_on_drop(true).spawn()?;
        let mut input=child.stdin.take().context("missing helper input")?;
        input.write_all(&packet).await?;drop(input);
        let output=child.wait_with_output().await?;
        anyhow::ensure!(output.status.success() && output.stdout.len()<=4096,"backup helper failed");
        Ok::<_,anyhow::Error>(serde_json::from_slice::<serde_json::Value>(&output.stdout)?)
    }).await.context("backup deadline")??;
    Ok(result)
}
pub(super) async fn confirm(shared: &Shared, id: &str) -> Result<()> {
    // One admission backup at a time. A busy backup must not stall the order worker.
    static SLOT:std::sync::OnceLock<Arc<tokio::sync::Semaphore>>=std::sync::OnceLock::new();
    let (public,packet)={
        let app=shared.lock().unwrap();
        let o=app.orders.get(id).context("missing saved order")?;
        if ready(&app,o) {return Ok(())}
        let public=terms(&app,o);
        let key=load_order_key(id)?;
        anyhow::ensure!(key.address_string(app.net)==o.invoice_address,"invoice key mismatch");
        let mut packet=public.clone();packet["key_hex"]=json!(key.secret_hex());
        (public,serde_json::to_vec(&packet)?)
    };
    let _permit=SLOT.get_or_init(||Arc::new(tokio::sync::Semaphore::new(1))).clone().try_acquire_owned()?;
    let expected=hex::encode(Sha256::digest(&packet));
    let ack=invoke(packet).await?;
    anyhow::ensure!(ack["stored"]==true && ack["packet_sha256"]==expected && hex_digest(&ack["cipher_sha256"]),"backup acknowledgement mismatch");
    let app=shared.lock().unwrap();
    let o=app.orders.get(id).context("missing saved order")?;
    anyhow::ensure!(terms(&app,o)==public,"saved order terms changed during backup");
    app.db.kv_put(NS,id,&json!({"terms":public,"stored":true,"cipher_sha256":ack["cipher_sha256"]}))?;
    Ok(())
}
