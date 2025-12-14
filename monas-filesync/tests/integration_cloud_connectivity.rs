#![cfg(feature = "cloud-connectivity")]
use std::{env, time::SystemTime};

#[tokio::test]
async fn google_drive_connectivity() {
    let token = match env::var("GOOGLE_DRIVE_TOKEN") {
        Ok(v) if !v.is_empty() => v,
        _ => return, // skip when token is not provided
    };
    let file_id = match env::var("GOOGLE_DRIVE_FILE_ID") {
        Ok(v) if !v.is_empty() => v,
        _ => return, // skip when id is not provided
    };

    let url = format!("https://www.googleapis.com/drive/v3/files/{file_id}?alt=media");

    let client = reqwest::Client::builder()
        .http2_prior_knowledge()
        .build()
        .unwrap();

    let resp = client
        .get(url)
        .bearer_auth(token)
        .send()
        .await
        .expect("request failed");

    assert!(
        resp.status().is_success(),
        "Google Drive GET failed: {}",
        resp.status()
    );
}

#[tokio::test]
async fn onedrive_connectivity() {
    let token = match env::var("ONEDRIVE_TOKEN") {
        Ok(v) if !v.is_empty() => v,
        _ => return, // skip when token is not provided
    };
    let item_id = match env::var("ONEDRIVE_ITEM_ID") {
        Ok(v) if !v.is_empty() => v,
        _ => return, // skip when id is not provided
    };

    let url = format!("https://graph.microsoft.com/v1.0/drive/items/{item_id}?select=size");

    let client = reqwest::Client::builder()
        .http2_prior_knowledge()
        .build()
        .unwrap();

    let resp = client
        .get(url)
        .bearer_auth(token)
        .send()
        .await
        .expect("request failed");

    assert!(
        resp.status().is_success(),
        "OneDrive GET failed: {}",
        resp.status()
    );
}

#[tokio::test]
async fn onedrive_put_connectivity() {
    let token = match env::var("ONEDRIVE_TOKEN") {
        Ok(v) if !v.is_empty() => v,
        _ => return, // skip when token is not provided
    };
    let item_id = match env::var("ONEDRIVE_UPLOAD_ITEM_ID") {
        Ok(v) if !v.is_empty() => v,
        _ => return, // skip when upload target is not provided
    };

    let url = format!("https://graph.microsoft.com/v1.0/drive/items/{item_id}/content");

    let client = reqwest::Client::builder()
        .http2_prior_knowledge()
        .build()
        .unwrap();

    let payload = format!(
        "monas-filesync connectivity test payload {}",
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or_default()
    );

    let resp = client
        .put(url)
        .bearer_auth(token)
        .header("Content-Type", "application/octet-stream")
        .body(payload)
        .send()
        .await
        .expect("request failed");

    assert!(
        resp.status().is_success(),
        "OneDrive PUT failed: {}",
        resp.status()
    );
}
