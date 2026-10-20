//! Shared browser policy. Raw inscription downloads retain their stricter sandbox CSP.
use axum::{extract::Request, middleware::Next, http::{header, HeaderValue}, response::Response};
const CSP: &str = include_str!("../../../web/security-policy.txt");
fn protect(response: &mut Response) {
    let headers=response.headers_mut();
    headers.entry(header::CONTENT_SECURITY_POLICY).or_insert(HeaderValue::from_str(CSP.trim().trim_start_matches('\u{feff}')).expect("checked static CSP"));
    headers.entry(header::X_CONTENT_TYPE_OPTIONS).or_insert(HeaderValue::from_static("nosniff"));
    headers.entry(header::REFERRER_POLICY).or_insert(HeaderValue::from_static("no-referrer"));
    headers.entry(header::X_FRAME_OPTIONS).or_insert(HeaderValue::from_static("DENY"));
}
pub async fn middleware(request: Request, next: Next) -> Response {
    let mut response=next.run(request).await;protect(&mut response);response
}
#[cfg(test)]
mod tests {
    use super::*;
    use axum::response::IntoResponse;
    #[test]
    fn errors_and_documents_get_headers_but_download_sandbox_is_preserved() {
        for status in [200,404,429,503] {
            let mut response=axum::http::StatusCode::from_u16(status).unwrap().into_response();protect(&mut response);
            assert_eq!(response.headers()[header::CONTENT_SECURITY_POLICY],CSP.trim().trim_start_matches('\u{feff}'));
            assert_eq!(response.headers()[header::X_FRAME_OPTIONS],"DENY");
        }
        let mut response=().into_response();
        response.headers_mut().insert(header::CONTENT_SECURITY_POLICY,HeaderValue::from_static("default-src 'none'; sandbox"));
        protect(&mut response);assert_eq!(response.headers()[header::CONTENT_SECURITY_POLICY],"default-src 'none'; sandbox");
    }
}
