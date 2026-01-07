use std::time::SystemTime;

use crate::infrastructure::{AuthSession, FetchError, FetchResult, StorageProvider};

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
    fn extract_cid(path: &str) -> Result<&str, FetchError> {
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
    fn apply_auth(mut req: reqwest::RequestBuilder, auth: &AuthSession) -> reqwest::RequestBuilder {
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
            "file",
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
                message: format!("IPFS CID mismatch: expected {expected_cid}, got {actual_cid}"),
            });
        }

        // Ensure retention (Monas default pin strategy).
        let pin_url = format!(
            "{base}/api/v0/pin/add?arg={}",
            urlencoding::encode(actual_cid)
        );
        let pin_req = Self::apply_auth(client.post(pin_url), auth);
        let _pin_resp = Self::send_expect_success(pin_req, "IPFS pin/add request failed").await?;

        Ok(())
    }
}

#[async_trait::async_trait]
impl StorageProvider for IpfsProvider {
    async fn fetch(&self, auth: &AuthSession, path: &str) -> FetchResult<Vec<u8>> {
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
    ) -> FetchResult<(u64, SystemTime)> {
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

    async fn save(&self, auth: &AuthSession, path: &str, data: &[u8]) -> FetchResult<()> {
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

    #[test]
    fn new_stores_gateway() {
        let gw1 = "https://ipfs.io";
        let gw2 = String::from("https://gateway.ipfs.io");

        let p1 = IpfsProvider::new(gw1);
        let p2 = IpfsProvider::new(gw2.clone());

        assert_eq!(p1.gateway, gw1);
        assert_eq!(p2.gateway, gw2);
    }

    fn auth(token: &str) -> AuthSession {
        AuthSession {
            access_token: token.to_string(),
        }
    }

    #[cfg(not(feature = "cloud-connectivity"))]
    mod without_cloud_connectivity {
        use super::*;

        #[tokio::test]
        async fn fetch_returns_feature_disabled_error() {
            let provider = IpfsProvider::new("https://ipfs.io");
            let auth = auth("test_token");

            let err = provider.fetch(&auth, "ipfs://bafyTEST").await.unwrap_err();

            assert!(err.message.contains("cloud-connectivity"));
            assert!(err.message.contains("IPFS fetch"));
        }

        #[tokio::test]
        async fn size_and_mtime_returns_feature_disabled_error() {
            let provider = IpfsProvider::new("https://ipfs.io");
            let auth = auth("test_token");

            let err = provider
                .size_and_mtime(&auth, "ipfs://bafyTEST")
                .await
                .unwrap_err();

            assert!(err.message.contains("cloud-connectivity"));
            assert!(err.message.contains("IPFS size_and_mtime"));
        }

        #[tokio::test]
        async fn save_returns_feature_disabled_error() {
            let provider = IpfsProvider::new("https://ipfs.io");
            let auth = auth("test_token");

            let err = provider
                .save(&auth, "ipfs://bafyTEST", b"test data")
                .await
                .unwrap_err();

            assert!(err.message.contains("cloud-connectivity"));
            assert!(err.message.contains("IPFS save"));
        }
    }

    #[cfg(feature = "cloud-connectivity")]
    mod with_cloud_connectivity {
        use super::*;
        use std::io::{Read, Write};
        use std::net::{Shutdown, TcpListener};
        use std::sync::mpsc;
        use std::thread;

        #[derive(Debug)]
        struct CapturedRequest {
            request_line: String,
            headers: Vec<(String, String)>,
            body: Vec<u8>,
        }

        fn http_response(status_line: &str, headers: &[(&str, String)], body: &[u8]) -> Vec<u8> {
            let mut out = Vec::new();
            out.extend_from_slice(status_line.as_bytes());
            out.extend_from_slice(b"\r\n");
            out.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
            for (k, v) in headers {
                out.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
            }
            out.extend_from_slice(b"Connection: close\r\n\r\n");
            out.extend_from_slice(body);
            out
        }

        fn http_json_response(body_json: &str) -> Vec<u8> {
            http_response(
                "HTTP/1.1 200 OK",
                &[("Content-Type", "application/json".to_string())],
                body_json.as_bytes(),
            )
        }

        fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
            headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.as_str())
        }

        fn start_server_with_responses(
            responses: Vec<Vec<u8>>,
        ) -> (String, mpsc::Receiver<Vec<CapturedRequest>>) {
            // Minimal HTTP server to capture N requests without extra dependencies.
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap();
            let base_url = format!("http://{addr}");

            let (tx, rx) = mpsc::channel::<Vec<CapturedRequest>>();
            thread::spawn(move || {
                fn read_one(stream: &mut std::net::TcpStream) -> CapturedRequest {
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

                    let header_end = buf.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
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

                    CapturedRequest {
                        request_line,
                        headers,
                        body,
                    }
                }

                let mut captured = Vec::new();
                for response in responses {
                    let (mut stream, _) = listener.accept().unwrap();
                    let req = read_one(&mut stream);
                    captured.push(req);
                    stream.write_all(&response).unwrap();
                    let _ = stream.shutdown(Shutdown::Both);
                }
                tx.send(captured).unwrap();
            });

            (base_url, rx)
        }

        #[tokio::test]
        async fn fetch_sends_block_get_with_auth_and_returns_bytes() {
            let expected = b"hello-ipfs".to_vec();
            let resp = http_response("HTTP/1.1 200 OK", &[], &expected);
            let (base_url, rx) = start_server_with_responses(vec![resp]);
            let provider = IpfsProvider::new(base_url);
            let auth = auth("test_token");

            let actual = provider.fetch(&auth, "ipfs://bafyTEST").await.unwrap();

            assert_eq!(actual, expected);
            let captured = rx.recv().unwrap();
            assert_eq!(captured.len(), 1);
            let req = &captured[0];
            assert!(
                req.request_line
                    .starts_with("POST /api/v0/block/get?arg=bafyTEST HTTP/1.1"),
                "unexpected request line: {}",
                req.request_line
            );
            assert_eq!(
                header_value(&req.headers, "authorization"),
                Some("Bearer test_token")
            );
        }

        #[tokio::test]
        async fn size_and_mtime_sends_block_stat_and_returns_size_and_epoch() {
            let resp = http_json_response("{\"Size\":123}");
            let (base_url, rx) = start_server_with_responses(vec![resp]);
            let provider = IpfsProvider::new(base_url);
            let auth = auth("test_token");

            let (size, mtime) = provider
                .size_and_mtime(&auth, "ipfs://bafyTEST")
                .await
                .unwrap();

            assert_eq!(size, 123);
            assert_eq!(mtime, SystemTime::UNIX_EPOCH);
            let captured = rx.recv().unwrap();
            assert_eq!(captured.len(), 1);
            let req = &captured[0];
            assert!(
                req.request_line
                    .starts_with("POST /api/v0/block/stat?arg=bafyTEST HTTP/1.1"),
                "unexpected request line: {}",
                req.request_line
            );
            assert_eq!(
                header_value(&req.headers, "authorization"),
                Some("Bearer test_token")
            );
        }

        #[tokio::test]
        async fn save_sends_block_put_then_pin_add_with_auth_and_payload() {
            let resp_put = http_json_response("{\"Key\":\"bafyTEST\"}");
            let resp_pin = http_response("HTTP/1.1 200 OK", &[], &[]);
            let (base_url, rx) = start_server_with_responses(vec![resp_put, resp_pin]);

            let provider = IpfsProvider::new(base_url);
            let auth = auth("test_token");
            let path = "ipfs://bafyTEST";
            let data = b"test data";

            provider.save(&auth, path, data).await.unwrap();

            let captured = rx.recv().unwrap();
            assert_eq!(captured.len(), 2);

            let req1 = &captured[0];
            assert!(
                req1.request_line
                    .starts_with("POST /api/v0/block/put?format=raw&mhtype=sha2-256 HTTP/1.1"),
                "unexpected request line: {}",
                req1.request_line
            );
            let content_type = header_value(&req1.headers, "content-type").unwrap_or("");
            assert!(content_type.contains("multipart/form-data"));
            assert_eq!(
                header_value(&req1.headers, "authorization"),
                Some("Bearer test_token")
            );
            assert!(req1.body.windows(data.len()).any(|w| w == data));
            let body_str = String::from_utf8_lossy(&req1.body);
            assert!(body_str.contains("Content-Disposition: form-data; name=\"file\""));

            let req2 = &captured[1];
            assert!(
                req2.request_line
                    .starts_with("POST /api/v0/pin/add?arg=bafyTEST HTTP/1.1"),
                "unexpected pin request line: {}",
                req2.request_line
            );
            assert_eq!(
                header_value(&req2.headers, "authorization"),
                Some("Bearer test_token")
            );
        }
    }
}
