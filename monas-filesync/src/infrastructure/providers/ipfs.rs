use std::time::SystemTime;

use crate::infrastructure::{AuthSession, FetchError, StorageProvider};

pub struct IpfsProvider {
    pub gateway: String,
}

impl IpfsProvider {
    pub fn new(gateway: impl Into<String>) -> Self {
        Self {
            gateway: gateway.into(),
        }
    }

    #[cfg(not(feature = "cloud-connectivity"))]
    fn feature_disabled_error(op: &str) -> FetchError {
        FetchError {
            message: format!(
                "IPFS {op} requires the `cloud-connectivity` feature (enables reqwest)"
            ),
        }
    }

    #[cfg(feature = "cloud-connectivity")]
    fn 
    extract_cid(path: &str) -> Result<&str, FetchError> {
        const PREFIX: &str = "ipfs://";

        if !path.starts_with(PREFIX) {
            return Err(FetchError {
                message: format!("unsupported IPFS URI: {path}"),
            });
        }

        let cid = &path[PREFIX.len()..];
        if cid.is_empty() {
            return Err(FetchError {
                message: "IPFS URI is missing a CID".into(),
            });
        }

        // CID must not contain a slash (we only support raw blocks for now).
        // If you need directory/path support later, use `/ipfs/<cid>/...` style in a new scheme.
        if cid.contains('/') {
            return Err(FetchError {
                message: format!(
                    "invalid IPFS CID URI: {path} (expected `ipfs://<cid>` without subpaths)"
                ),
            });
        }

        Ok(cid)
    }

    #[cfg(feature = "cloud-connectivity")]
    fn api_base(&self) -> Result<String, FetchError> {
        let base = self.gateway.trim_end_matches('/').to_string();
        if base.is_empty() {
            return Err(FetchError {
                message: "IPFS api endpoint is empty".into(),
            });
        }
        Ok(base)
    }

    #[cfg(feature = "cloud-connectivity")]
    fn http_client() -> reqwest::Client {
        reqwest::Client::new()
    }

    #[cfg(feature = "cloud-connectivity")]
    fn apply_auth<'a>(
        mut req: reqwest::RequestBuilder,
        auth: &'a AuthSession,
    ) -> reqwest::RequestBuilder {
        let token = auth.access_token.trim();
        if !token.is_empty() {
            req = req.bearer_auth(token);
        }
        req
    }

    #[cfg(feature = "cloud-connectivity")]
    async fn send_expect_success(
        req: reqwest::RequestBuilder,
        err_prefix: &'static str,
    ) -> Result<reqwest::Response, FetchError> {
        let resp = req.send().await.map_err(|err| FetchError {
            message: format!("{err_prefix}: {err}"),
        })?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(FetchError {
                message: format!("{err_prefix} with status {status}: {body}"),
            });
        }

        Ok(resp)
    }

    #[cfg(feature = "cloud-connectivity")]
    async fn fetch_remote(&self, auth: &AuthSession, path: &str) -> Result<Vec<u8>, FetchError> {
        let cid = Self::extract_cid(path)?;
        let base = self.api_base()?;
        let url = format!("{base}/api/v0/block/get?arg={}", urlencoding::encode(cid));

        let client = Self::http_client();
        let req = Self::apply_auth(client.post(url), auth);
        let resp = Self::send_expect_success(req, "IPFS fetch request failed").await?;
        let bytes = resp.bytes().await.map_err(|err| FetchError {
            message: format!("IPFS fetch failed to read body: {err}"),
        })?;
        Ok(bytes.to_vec())
    }

    #[cfg(feature = "cloud-connectivity")]
    async fn size_remote(&self, auth: &AuthSession, path: &str) -> Result<u64, FetchError> {
        let cid = Self::extract_cid(path)?;
        let base = self.api_base()?;
        let url = format!("{base}/api/v0/block/stat?arg={}", urlencoding::encode(cid));

        let client = Self::http_client();
        let req = Self::apply_auth(client.post(url), auth);
        let resp = Self::send_expect_success(req, "IPFS stat request failed").await?;

        #[derive(serde::Deserialize)]
        struct BlockStat {
            #[serde(rename = "Size")]
            size: u64,
        }

        let value: BlockStat = resp.json().await.map_err(|err| FetchError {
            message: format!("IPFS stat JSON decode failed: {err}"),
        })?;
        Ok(value.size)
    }

    #[cfg(feature = "cloud-connectivity")]
    async fn save_remote(
        &self,
        auth: &AuthSession,
        path: &str,
        data: &[u8],
    ) -> Result<(), FetchError> {
        let expected_cid = Self::extract_cid(path)?;
        let base = self.api_base()?;

        // Store as a raw block so that CIDv1 + codec=raw matches Monas `ContentId`.
        let put_url = format!("{base}/api/v0/block/put?format=raw&mhtype=sha2-256");

        let client = Self::http_client();
        let form = reqwest::multipart::Form::new().part(
            "data",
            reqwest::multipart::Part::bytes(data.to_vec())
                .mime_str("application/octet-stream")
                .map_err(|err| FetchError {
                    message: format!("failed to set IPFS multipart mime type: {err}"),
                })?,
        );
        let req = Self::apply_auth(client.post(put_url).multipart(form), auth);
        let resp = Self::send_expect_success(req, "IPFS block/put request failed").await?;

        #[derive(serde::Deserialize)]
        struct BlockPut {
            #[serde(rename = "Key")]
            key: String,
        }

        let value: BlockPut = resp.json().await.map_err(|err| FetchError {
            message: format!("IPFS block/put JSON decode failed: {err}"),
        })?;
        let actual_cid = value.key.as_str();

        if actual_cid != expected_cid {
            return Err(FetchError {
                message: format!(
                    "IPFS CID mismatch: expected {expected_cid}, got {actual_cid}"
                ),
            });
        }

        // Ensure retention (Monas default pin strategy).
        let pin_url = format!("{base}/api/v0/pin/add?arg={}", urlencoding::encode(actual_cid));
        let pin_req = Self::apply_auth(client.post(pin_url), auth);
        let _pin_resp = Self::send_expect_success(pin_req, "IPFS pin/add request failed").await?;

        Ok(())
    }
}

#[async_trait::async_trait]
impl StorageProvider for IpfsProvider {
    async fn fetch(
        &self,
        auth: &AuthSession,
        path: &str,
    ) -> Result<Vec<u8>, crate::infrastructure::FetchError> {
        #[cfg(feature = "cloud-connectivity")]
        {
            return self.fetch_remote(auth, path).await;
        }

        #[cfg(not(feature = "cloud-connectivity"))]
        {
            let _ = (auth, path);
            Err(Self::feature_disabled_error("fetch"))
        }
    }

    async fn size_and_mtime(
        &self,
        auth: &AuthSession,
        path: &str,
    ) -> Result<(u64, SystemTime), crate::infrastructure::FetchError> {
        #[cfg(feature = "cloud-connectivity")]
        {
            let size = self.size_remote(auth, path).await?;
            // IPFS blocks do not have an intrinsic mtime; caller should manage it as metadata.
            return Ok((size, SystemTime::UNIX_EPOCH));
        }

        #[cfg(not(feature = "cloud-connectivity"))]
        {
            let _ = (auth, path);
            Err(Self::feature_disabled_error("size_and_mtime"))
        }
    }

    async fn save(
        &self,
        auth: &AuthSession,
        path: &str,
        data: &[u8],
    ) -> Result<(), crate::infrastructure::FetchError> {
        #[cfg(feature = "cloud-connectivity")]
        {
            return self.save_remote(auth, path, data).await;
        }

        #[cfg(not(feature = "cloud-connectivity"))]
        {
            let _ = (auth, path, data);
            Err(Self::feature_disabled_error("save"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infrastructure::AuthSession;

    #[test]
    fn test_ipfs_provider_new() {
        let provider = IpfsProvider::new("https://ipfs.io");
        assert_eq!(provider.gateway, "https://ipfs.io");

        // Test with String type
        let gateway = String::from("https://gateway.ipfs.io");
        let provider = IpfsProvider::new(gateway.clone());
        assert_eq!(provider.gateway, gateway);
    }

    #[tokio::test]
    async fn test_ipfs_provider_fetch() {
        let provider = IpfsProvider::new("https://ipfs.io");
        let auth = AuthSession {
            access_token: "test_token".to_string(),
        };

        let result = provider.fetch(&auth, "ipfs://QmHash").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_ipfs_provider_size_and_mtime() {
        let provider = IpfsProvider::new("https://ipfs.io");
        let auth = AuthSession {
            access_token: "test_token".to_string(),
        };

        let result = provider.size_and_mtime(&auth, "ipfs://QmHash").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    #[cfg(not(feature = "cloud-connectivity"))]
    async fn test_ipfs_provider_save() {
        let provider = IpfsProvider::new("https://ipfs.io");
        let auth = AuthSession {
            access_token: "test_token".to_string(),
        };

        let result = provider.save(&auth, "ipfs://bafyTEST", b"test data").await;
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("cloud-connectivity"));
    }

    #[tokio::test]
    #[cfg(feature = "cloud-connectivity")]
    async fn test_ipfs_provider_save_block_put_and_pin_success() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::net::Shutdown;
        use std::sync::mpsc;
        use std::thread;

        // Minimal HTTP server to capture two requests without extra dependencies.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let base_url = format!("http://{}", addr);

        let (tx, rx) = mpsc::channel::<Vec<(String, Vec<(String, String)>, Vec<u8>)>>();
        thread::spawn(move || {
            fn read_one(stream: &mut std::net::TcpStream) -> (String, Vec<(String, String)>, Vec<u8>) {
                let mut buf = Vec::new();
                let mut tmp = [0u8; 1024];
                loop {
                    let n = stream.read(&mut tmp).unwrap();
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&tmp[..n]);
                    if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }

                let header_end = buf
                    .windows(4)
                    .position(|w| w == b"\r\n\r\n")
                    .unwrap()
                    + 4;
                let header_bytes = &buf[..header_end];
                let mut body = buf[header_end..].to_vec();

                let header_str = String::from_utf8_lossy(header_bytes);
                let mut lines = header_str.split("\r\n");
                let request_line = lines.next().unwrap_or("").to_string();

                let mut headers = Vec::new();
                let mut content_length: usize = 0;
                for line in lines {
                    if line.is_empty() {
                        break;
                    }
                    if let Some((k, v)) = line.split_once(':') {
                        let key = k.trim().to_string();
                        let val = v.trim().to_string();
                        if key.eq_ignore_ascii_case("content-length") {
                            content_length = val.parse().unwrap_or(0);
                        }
                        headers.push((key, val));
                    }
                }

                while body.len() < content_length {
                    let n = stream.read(&mut tmp).unwrap();
                    if n == 0 {
                        break;
                    }
                    body.extend_from_slice(&tmp[..n]);
                }
                (request_line, headers, body)
            }

            let mut captured = Vec::new();

            // 1st request: block/put
            let (mut stream1, _) = listener.accept().unwrap();
            let (req1, headers1, body1) = read_one(&mut stream1);
            captured.push((req1, headers1, body1));
            let resp1 =
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 18\r\nConnection: close\r\n\r\n{\"Key\":\"bafyTEST\"}";
            stream1.write_all(resp1).unwrap();
            let _ = stream1.shutdown(Shutdown::Both);
            drop(stream1);

            // 2nd request: pin/add
            let (mut stream2, _) = listener.accept().unwrap();
            let (req2, headers2, body2) = read_one(&mut stream2);
            captured.push((req2, headers2, body2));
            let resp2 = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            stream2.write_all(resp2).unwrap();
            let _ = stream2.shutdown(Shutdown::Both);

            tx.send(captured).unwrap();
        });

        let provider = IpfsProvider::new(base_url);
        let auth = AuthSession {
            access_token: "test_token".to_string(),
        };

        provider
            .save(&auth, "ipfs://bafyTEST", b"test data")
            .await
            .unwrap();

        let captured = rx.recv().unwrap();
        assert_eq!(captured.len(), 2);

        let (req1, headers1, body1) = &captured[0];
        assert!(
            req1.starts_with("POST /api/v0/block/put?format=raw&mhtype=sha2-256 HTTP/1.1"),
            "unexpected request line: {req1}"
        );
        let mut has_multipart = false;
        let mut has_auth = false;
        for (k, v) in headers1 {
            if k.eq_ignore_ascii_case("content-type") && v.contains("multipart/form-data") {
                has_multipart = true;
            }
            if k.eq_ignore_ascii_case("authorization") && v == "Bearer test_token" {
                has_auth = true;
            }
        }
        assert!(has_multipart, "missing multipart Content-Type header");
        assert!(has_auth, "missing Authorization header");
        assert!(
            body1.windows(b"test data".len()).any(|w| w == b"test data"),
            "multipart body did not contain payload"
        );
        let body_str = String::from_utf8_lossy(body1);
        assert!(
            body_str.contains("Content-Disposition: form-data; name=\"data\""),
            "missing multipart field name=data"
        );

        let (req2, _headers2, _body2) = &captured[1];
        assert!(
            req2.starts_with("POST /api/v0/pin/add?arg=bafyTEST HTTP/1.1"),
            "unexpected pin request line: {req2}"
        );
    }
}
