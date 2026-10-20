//! Origin protection for invoice creation behind a trusted admission gateway.
//! This is not the human challenge itself; the gateway must verify it and replace client headers.
use anyhow::{Context,Result};
use axum::{extract::{Request,State},middleware::Next,http::{Method,StatusCode},response::{IntoResponse,Response},Json};
use serde_json::json;
use std::{path::Path,sync::Arc};
const HEADER:&str="x-overstory-invoice-gate";
#[derive(Clone)]
pub enum Policy { RegtestOpen, Closed, Trusted(Arc<[u8;64]>) }
impl Policy {
    pub fn from_env(regtest:bool)->Result<Self> {
        match std::env::var("OVERSTORY_INVOICE_GATE_KEY_FILE") {
            Ok(path)=>Self::load(Path::new(&path)),
            Err(std::env::VarError::NotPresent)=>Ok(if regtest {Self::RegtestOpen}else{Self::Closed}),
            Err(_)=>anyhow::bail!("invalid invoice gateway key path"),
        }
    }
    fn load(path:&Path)->Result<Self> {
        let metadata=std::fs::symlink_metadata(path).context("invoice gateway key unavailable")?;
        anyhow::ensure!(metadata.is_file() && metadata.len()<=256,"invalid invoice gateway key file");
        #[cfg(unix)] {
            use std::os::unix::fs::PermissionsExt;
            anyhow::ensure!(metadata.permissions().mode()&0o077==0,"invoice gateway key must be private (0600)");
        }
        let bytes=std::fs::read(path).context("invoice gateway key unavailable")?;
        let value=std::str::from_utf8(&bytes).context("invalid invoice gateway key encoding")?.trim();
        anyhow::ensure!(value.len()==64 && value.bytes().all(|c|c.is_ascii_hexdigit()) && value.bytes().any(|c|c!=b'0'),"invoice gateway key must be 32 random bytes encoded as 64 hex characters");
        Ok(Self::Trusted(Arc::new(value.as_bytes().try_into().unwrap())))
    }
    fn allows(&self,value:Option<&[u8]>)->bool {
        match self {
            Self::RegtestOpen=>true,
            Self::Closed=>false,
            Self::Trusted(secret)=>{
                let Some(value)=value.filter(|v|v.len()==64) else{return false};
                // Fixed-length comparison; never expose the expected header in errors or logs.
                secret.iter().zip(value).fold(0u8,|difference,(a,b)|difference|(a^b))==0
            }
        }
    }
}
pub async fn middleware(State(policy):State<Policy>,mut request:Request,next:Next)->Response {
    let duplicate=request.headers().get_all(HEADER).iter().count()>1;
    let provided=request.headers_mut().remove(HEADER);
    if request.method()==Method::POST && request.uri().path()=="/api/orders" && (duplicate || !policy.allows(provided.as_ref().map(|h|h.as_bytes()))) {
        let (status,message)=match policy {Policy::Closed=>(StatusCode::SERVICE_UNAVAILABLE,"new invoices are paused until admission is configured"),_=>(StatusCode::FORBIDDEN,"invoice admission required; existing invoices remain valid")};
        return (status,Json(json!({"error":message}))).into_response();
    }
    next.run(request).await
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn closed_and_trusted_policies_reject_bypass() {
        let key=[b'1';64];let trusted=Policy::Trusted(Arc::new(key));
        for value in [None,Some(&b""[..]),Some(&b"forged"[..]),Some(&[b'2';64][..])] {assert!(!trusted.allows(value));assert!(!Policy::Closed.allows(value));}
        assert!(trusted.allows(Some(&key)));assert!(!Policy::Closed.allows(Some(&key)));assert!(Policy::RegtestOpen.allows(None));
        for position in 0..64 {let mut wrong=key;wrong[position]=b'2';assert!(!trusted.allows(Some(&wrong)));}
    }
    #[tokio::test]
    async fn http_gate_only_blocks_new_invoices_and_strips_the_header() {
        use axum::{Router,routing::{get,post},http::HeaderMap};
        use tokio::io::{AsyncReadExt,AsyncWriteExt};
        for (policy,header,expected) in [
            (Policy::Closed,None,503),
            (Policy::Trusted(Arc::new([b'1';64])),None,403),
            (Policy::Trusted(Arc::new([b'1';64])),Some("2".repeat(64)),403),
            (Policy::Trusted(Arc::new([b'1';64])),Some("1".repeat(64)),200),
            (Policy::Trusted(Arc::new([b'1';64])),Some(format!("{}\r\n{HEADER}: {}","1".repeat(64),"1".repeat(64))),403),
            (Policy::RegtestOpen,None,200),
        ] {
            let app=Router::new().route("/api/orders",post(|headers:HeaderMap|async move {
                assert!(!headers.contains_key(HEADER));Json(json!({"accepted":true}))
            })).route("/api/orders/existing",get(||async{"existing invoice"}))
              .layer(axum::middleware::from_fn_with_state(policy,middleware));
            let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();let address=listener.local_addr().unwrap();
            let server=tokio::spawn(async move {axum::serve(listener,app).await.unwrap()});
            for (method,path,status) in [("POST","/api/orders?retry=1",expected),("GET","/api/orders/existing",200),("POST","/api/%6frders",404),("POST","/api/orders/",404),("POST","/api//orders",404)] {
                let mut stream=tokio::net::TcpStream::connect(address).await.unwrap();
                let credential=header.as_ref().map(|h|format!("{HEADER}: {h}\r\n")).unwrap_or_default();
                stream.write_all(format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Length: 0\r\n{credential}\r\n").as_bytes()).await.unwrap();
                let mut reply=String::new();stream.read_to_string(&mut reply).await.unwrap();assert!(reply.starts_with(&format!("HTTP/1.1 {status}")),"{reply}");
            }
            server.abort();
        }
    }

    #[test]
    fn unsafe_key_files_are_rejected() {
        let root=std::env::temp_dir().join(format!("overstory-gate-test-{}",rand::random::<u64>()));std::fs::create_dir(&root).unwrap();
        let key=root.join("key");assert!(Policy::load(&key).is_err());assert!(Policy::load(&root).is_err());
        for value in [vec![],vec![b'1';63],vec![b'0';64],vec![b'z';64],vec![255;64],vec![b'1';300]] {
            std::fs::write(&key,value).unwrap();
            #[cfg(unix)] {use std::os::unix::fs::PermissionsExt;std::fs::set_permissions(&key,std::fs::Permissions::from_mode(0o600)).unwrap();}
            assert!(Policy::load(&key).is_err());
        }
        std::fs::write(&key,vec![b'1';64]).unwrap();assert!(Policy::load(&key).is_ok());
        #[cfg(unix)] {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key,std::fs::Permissions::from_mode(0o644)).unwrap();assert!(Policy::load(&key).is_err());
            std::fs::set_permissions(&key,std::fs::Permissions::from_mode(0o600)).unwrap();
            let link=root.join("link");std::os::unix::fs::symlink(&key,&link).unwrap();assert!(Policy::load(&link).is_err());std::fs::remove_file(link).unwrap();
        }
        std::fs::remove_file(key).unwrap();std::fs::remove_dir(root).unwrap();
    }

}
