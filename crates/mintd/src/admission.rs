//! Process-wide admission limits; forwarded client IPs cannot bypass them.
use axum::{extract::Request, middleware::Next, http::{Method, StatusCode, header}, response::{IntoResponse, Response}, Json};
use serde_json::json;
use std::sync::{Mutex, OnceLock};
use std::time::Instant;
struct Bucket { tokens: f64, burst: f64, rate: f64, updated: Instant }
impl Bucket {
    fn new(burst: u32, rate: u32) -> Self {
        Self { tokens: burst as f64, burst: burst as f64, rate: rate as f64, updated: Instant::now() }
    }
    fn take(&mut self, now: Instant) -> bool {
        self.tokens = (self.tokens + now.saturating_duration_since(self.updated).as_secs_f64() * self.rate).min(self.burst);
        self.updated = now;
        if self.tokens < 1.0 { return false; }
        self.tokens -= 1.0; true
    }
}
struct Limits { writes: Bucket, invoices: Bucket }
impl Limits {
    fn new() -> Self { Self { writes: Bucket::new(20, 10), invoices: Bucket::new(10, 1) } }
    fn admit(&mut self, invoice: bool, now: Instant) -> bool {
        if !self.writes.take(now) { return false; }
        !invoice || self.invoices.take(now)
    }
}
pub async fn middleware(request: Request, next: Next) -> Response {
    static LIMITS: OnceLock<Mutex<Limits>> = OnceLock::new();
    if request.method() == Method::POST && request.uri().path().starts_with("/api/") {
        let accepted = LIMITS.get_or_init(||Mutex::new(Limits::new())).lock().unwrap()
            .admit(request.uri().path() == "/api/orders", Instant::now());
        if !accepted {
            return (StatusCode::TOO_MANY_REQUESTS, [(header::RETRY_AFTER, "1")], Json(json!({"error":"service busy; retain your existing invoice or signed transaction and retry later"}))).into_response();
        }
    }
    next.run(request).await
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::{sync::{Arc, atomic::{AtomicUsize, Ordering}}, time::Duration};
    #[test]
    fn concurrent_admission_cannot_exceed_invoice_burst() {
        let limits=Arc::new(Mutex::new(Limits::new()));let accepted=Arc::new(AtomicUsize::new(0));let time=Instant::now();
        std::thread::scope(|scope| for _ in 0..100 {
            let limits=limits.clone(); let accepted=accepted.clone();
            scope.spawn(move || if limits.lock().unwrap().admit(true,time) {accepted.fetch_add(1,Ordering::SeqCst);});
        });
        assert_eq!(accepted.load(Ordering::SeqCst),10);
        let mut limits=limits.lock().unwrap();
        assert!(limits.admit(true,time+Duration::from_secs(1)));
        assert!(!limits.admit(true,time+Duration::from_secs(1)));
    }
    #[test]
    fn write_burst_is_shared_and_refill_is_bounded() {
        let mut limits=Limits::new();let time=Instant::now();
        assert_eq!((0..100).filter(|_|limits.admit(false,time)).count(),20);
        assert_eq!((0..100).filter(|_|limits.admit(false,time+Duration::from_secs(10))).count(),20);
    }
}
