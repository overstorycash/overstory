//! Optional local-node cookie authentication. Reload on every request after node restarts.
use anyhow::{ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use std::{fs::File, io::Read, path::Path};

fn local_endpoint(url: &str) -> bool {
    let Some(port) = url.strip_prefix("http://127.0.0.1:").or_else(|| url.strip_prefix("http://[::1]:")) else { return false; };
    let port = port.strip_suffix('/').unwrap_or(port);
    !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) && port.parse::<u16>().is_ok_and(|p| p > 0)
}

pub(crate) fn authorization(url: &str, cookie: Option<&Path>) -> Result<Option<String>> {
    let Some(path) = cookie else { return Ok(None); };
    ensure!(local_endpoint(url), "RPC cookie requires a literal loopback HTTP endpoint with an explicit port");
    let mut raw = Vec::new();
    File::open(path).context("cannot open RPC cookie file")?.take(4097).read_to_end(&mut raw).context("cannot read RPC cookie file")?;
    ensure!(raw.len() <= 4096, "RPC cookie is too large");
    let text = std::str::from_utf8(&raw).context("invalid RPC cookie encoding")?.trim_end_matches(['\r', '\n']);
    let secret = text.strip_prefix("__cookie__:").context("invalid RPC cookie username")?;
    ensure!(!secret.is_empty() && secret.bytes().all(|b| b.is_ascii_graphic()), "invalid RPC cookie secret");
    Ok(Some(format!("Basic {}", STANDARD.encode(text))))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn refuses_remote_urls_and_ambiguous_local_forms() {
        for url in ["https://example.com", "http://localhost:8232", "http://127.0.0.1:8232@evil.test", "http://127.0.0.1:8232/path", "http://127.0.0.1:0", "http://127.0.0.1:65536", "http://127.0.0.1:8232?x=1", "http://127.0.0.1:8232#x"] {
            assert!(!local_endpoint(url), "{url}");
        }
        assert!(local_endpoint("http://127.0.0.1:8232/"));
        assert!(local_endpoint("http://[::1]:8232"));
        assert!(authorization("https://provider.example", None).unwrap().is_none());
    }
    #[test]
    fn rereads_cookie_and_fails_closed_after_removal_or_corruption() {
        let dir = std::env::temp_dir().join(format!("overstory-cookie-{}-{}", std::process::id(), rand::random::<u64>()));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("cookie");
        let url = "http://127.0.0.1:8232";
        std::fs::write(&path, "__cookie__:first\n").unwrap();
        assert_eq!(authorization(url, Some(&path)).unwrap(), Some(format!("Basic {}", STANDARD.encode("__cookie__:first"))));
        std::fs::write(&path, "__cookie__:second\r\n").unwrap();
        assert_eq!(authorization(url, Some(&path)).unwrap(), Some(format!("Basic {}", STANDARD.encode("__cookie__:second"))));
        for bad in ["", "user:secret", "__cookie__:", "__cookie__:bad\nline"] {
            std::fs::write(&path,bad).unwrap(); assert!(authorization(url,Some(&path)).is_err());
        }
        std::fs::write(&path, vec![b'x';4097]).unwrap(); assert!(authorization(url,Some(&path)).is_err());
        std::fs::remove_file(&path).unwrap(); assert!(authorization(url,Some(&path)).is_err());
        std::fs::remove_dir(dir).unwrap();
    }
}
