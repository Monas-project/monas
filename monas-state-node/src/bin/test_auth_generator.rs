use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use p256::ecdsa::{signature::Signer, SigningKey};
use p256::elliptic_curve::rand_core::OsRng;
use serde_json::json;
use sha3::{Digest, Keccak256};
use std::env;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: {} <command> [args...]", args[0]);
        eprintln!("Commands:");
        eprintln!("  generate-token [content_id]  - Generate an auth token");
        eprintln!("  generate-signature <data>    - Generate a request signature");
        eprintln!("  generate-keys                - Generate a new keypair");
        eprintln!("  test-auth                    - Generate complete test auth data");
        eprintln!("  generate-share-token         - Generate a share token for another user");
        eprintln!("    --owner-key <hex>          Owner's private key (hex)");
        eprintln!("    --recipient-key <hex>      Recipient's public key (hex)");
        eprintln!("    --content-id <id>          Content ID");
        eprintln!(
            "    --capabilities <caps>      Comma-separated capabilities (read,write,delete,share)"
        );
        eprintln!("    --expiry <seconds>         Token expiry in seconds (default: 3600)");
        std::process::exit(1);
    }

    let command = &args[1];

    match command.as_str() {
        "generate-token" => {
            let content_id = args.get(2).cloned();
            generate_auth_token(content_id);
        }
        "generate-signature" => {
            if args.len() < 3 {
                eprintln!("Error: Please provide data to sign");
                std::process::exit(1);
            }
            let data = &args[2];
            generate_request_signature(data);
        }
        "generate-keys" => {
            generate_keypair();
        }
        "test-auth" => {
            generate_test_auth_data();
        }
        "generate-share-token" => {
            generate_share_token(&args[2..]);
        }
        _ => {
            eprintln!("Unknown command: {}", command);
            std::process::exit(1);
        }
    }
}

fn generate_keypair() {
    // Generate a new P-256 keypair
    let signing_key = SigningKey::random(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    // Get the public key in SEC1 uncompressed format (65 bytes, starting with 0x04)
    let public_key_bytes = verifying_key.to_encoded_point(false).as_bytes().to_vec();
    let public_key_hex = hex::encode(&public_key_bytes);

    // Get the private key as bytes
    let private_key_bytes = signing_key.to_bytes();
    let private_key_hex = hex::encode(private_key_bytes);

    println!("=== Generated P-256 Keypair ===");
    println!("Private Key (hex): {}", private_key_hex);
    println!("Public Key (hex):  {}", public_key_hex);
    println!(
        "Public Key (base64): {}",
        STANDARD.encode(&public_key_bytes)
    );
}

fn generate_auth_token(content_id: Option<String>) {
    // Create test signing key
    let signing_key = SigningKey::random(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    // Get the public key in SEC1 uncompressed format
    let public_key_bytes = verifying_key.to_encoded_point(false).as_bytes().to_vec();

    // Create key_id from public key hash
    let mut hasher = Keccak256::new();
    hasher.update(&public_key_bytes);
    let key_id = hasher.finalize().to_vec();

    // Create capabilities
    let mut capabilities = vec![];
    if let Some(cid) = content_id {
        capabilities.push(json!({
            "with": format!("monas://content/{}", cid),
            "can": "write"  // write implies read
        }));
    } else {
        capabilities.push(json!({
            "with": "monas://content/*",
            "can": "write"  // write implies read
        }));
    }

    // Create JWT header
    let header = json!({
        "alg": "ES256",
        "typ": "JWT",
        "ver": "1.0"
    });

    // Create JWT payload
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let payload = json!({
        "iss": hex::encode(&key_id),
        "aud": hex::encode(&key_id),  // Self-issued for testing
        "exp": now + 3600,  // 1 hour from now
        "iat": now,
        "jti": Uuid::new_v4().to_string(),
        "att": capabilities
    });

    // Encode header and payload
    let header_b64 = URL_SAFE_NO_PAD.encode(header.to_string());
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload.to_string());

    // Create signing input
    let signing_input = format!("{}.{}", header_b64, payload_b64);

    // Sign the input
    let signature: p256::ecdsa::Signature = signing_key.sign(signing_input.as_bytes());
    let signature_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());

    // Assemble JWT
    let token_str = format!("{}.{}.{}", header_b64, payload_b64, signature_b64);

    println!("=== Generated Auth Token ===");
    println!("Token: {}", token_str);
    println!();
    println!("Public Key (hex): {}", hex::encode(&public_key_bytes));
    println!(
        "Public Key (base64): {}",
        STANDARD.encode(&public_key_bytes)
    );
    println!("Key ID (hex): {}", hex::encode(&key_id));
    println!();
    println!("Usage:");
    println!("  curl -H \"Authorization: Bearer {}\" ...", token_str);
}

fn generate_request_signature(data: &str) {
    // Create test signing key
    let signing_key = SigningKey::random(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    let public_key_bytes = verifying_key.to_encoded_point(false).as_bytes().to_vec();

    // Hash the data with Keccak256
    let mut hasher = Keccak256::new();
    hasher.update(data.as_bytes());
    let hash = hasher.finalize();

    // Sign the hash
    let signature: p256::ecdsa::Signature = signing_key.sign(&hash);
    let signature_bytes = signature.to_bytes();
    let signature_base64 = STANDARD.encode(signature_bytes);

    println!("=== Generated Request Signature ===");
    println!("Data: {}", data);
    println!("Signature: {}", signature_base64);
    println!("Public Key (hex): {}", hex::encode(&public_key_bytes));
    println!(
        "Public Key (base64): {}",
        STANDARD.encode(&public_key_bytes)
    );
    println!();
    println!("Usage:");
    println!(
        "  curl -H \"X-Request-Signature: {}\" ...",
        signature_base64
    );
}

fn generate_share_token(args: &[String]) {
    // Parse arguments
    let mut owner_key_hex = String::new();
    let mut recipient_key_hex = String::new();
    let mut content_id = String::new();
    let mut capabilities_str = "read,write".to_string();
    let mut expiry: u64 = 3600;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--owner-key" => {
                i += 1;
                if i < args.len() {
                    owner_key_hex = args[i].clone();
                }
            }
            "--recipient-key" => {
                i += 1;
                if i < args.len() {
                    recipient_key_hex = args[i].clone();
                }
            }
            "--content-id" => {
                i += 1;
                if i < args.len() {
                    content_id = args[i].clone();
                }
            }
            "--capabilities" => {
                i += 1;
                if i < args.len() {
                    capabilities_str = args[i].clone();
                }
            }
            "--expiry" => {
                i += 1;
                if i < args.len() {
                    expiry = args[i].parse().unwrap_or(3600);
                }
            }
            _ => {}
        }
        i += 1;
    }

    if owner_key_hex.is_empty() || recipient_key_hex.is_empty() || content_id.is_empty() {
        eprintln!("Error: --owner-key, --recipient-key, and --content-id are required");
        std::process::exit(1);
    }

    // Parse owner's private key
    let owner_key_bytes = hex::decode(&owner_key_hex).unwrap_or_else(|e| {
        eprintln!("Error: Invalid owner key hex: {}", e);
        std::process::exit(1);
    });
    let owner_signing_key =
        SigningKey::from_bytes((&owner_key_bytes[..]).into()).unwrap_or_else(|e| {
            eprintln!("Error: Invalid owner private key: {}", e);
            std::process::exit(1);
        });
    let owner_verifying_key = owner_signing_key.verifying_key();
    let owner_public_key_bytes = owner_verifying_key
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();

    // Compute owner's key_id (monas:user:<keccak256_hash_prefix>)
    let mut hasher = Keccak256::new();
    hasher.update(&owner_public_key_bytes);
    let owner_key_id_bytes = hasher.finalize().to_vec();
    let owner_key_id = format!("monas:user:{}", hex::encode(&owner_key_id_bytes));

    // Parse recipient's public key
    let recipient_public_key_bytes = hex::decode(&recipient_key_hex).unwrap_or_else(|e| {
        eprintln!("Error: Invalid recipient key hex: {}", e);
        std::process::exit(1);
    });

    // Compute recipient's key_id
    let mut hasher = Keccak256::new();
    hasher.update(&recipient_public_key_bytes);
    let recipient_key_id_bytes = hasher.finalize().to_vec();
    let recipient_key_id = format!("monas:user:{}", hex::encode(&recipient_key_id_bytes));

    // Parse capabilities
    let caps: Vec<serde_json::Value> = capabilities_str
        .split(',')
        .map(|c| {
            let action = c.trim();
            json!({
                "with": format!("monas://content/{}", content_id),
                "can": action
            })
        })
        .collect();

    // Create JWT
    let header = json!({
        "alg": "ES256",
        "typ": "JWT",
        "ver": "1.0"
    });

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let jti = Uuid::new_v4().to_string();

    let payload = json!({
        "iss": owner_key_id,
        "aud": recipient_key_id,
        "exp": now + expiry,
        "iat": now,
        "jti": jti,
        "att": caps
    });

    let header_b64 = URL_SAFE_NO_PAD.encode(header.to_string());
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload.to_string());

    let signing_input = format!("{}.{}", header_b64, payload_b64);

    // Sign with owner's key
    let signature: p256::ecdsa::Signature = owner_signing_key.sign(signing_input.as_bytes());
    let signature_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());

    let token_str = format!("{}.{}.{}", header_b64, payload_b64, signature_b64);

    // Generate recipient's request signature
    // The recipient would need their own private key to sign, but for the test tool
    // we just output the token. The recipient signs "{iss}:{aud}:{jti}" with their private key.
    let request_message = format!("{}:{}:{}", owner_key_id, recipient_key_id, jti);

    // Machine-readable output for script consumption
    println!("SHARE_TOKEN={}", token_str);
    println!("OWNER_PUBLIC_KEY={}", hex::encode(&owner_public_key_bytes));
    println!("RECIPIENT_PUBLIC_KEY={}", recipient_key_hex);
    println!("OWNER_KEY_ID={}", owner_key_id);
    println!("RECIPIENT_KEY_ID={}", recipient_key_id);
    println!("REQUEST_MESSAGE={}", request_message);
    println!("CONTENT_ID={}", content_id);
    println!("JTI={}", jti);
}

fn generate_test_auth_data() {
    // Create test signing key
    let signing_key = SigningKey::random(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    let public_key_bytes = verifying_key.to_encoded_point(false).as_bytes().to_vec();

    // Create key_id from public key hash
    let mut hasher = Keccak256::new();
    hasher.update(&public_key_bytes);
    let key_id = hasher.finalize().to_vec();

    // Generate auth token
    let capabilities = vec![json!({
        "with": "monas://content/*",
        "can": "write"  // write implies read
    })];

    // Create JWT header and payload
    let header = json!({
        "alg": "ES256",
        "typ": "JWT",
        "ver": "1.0"
    });

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let payload = json!({
        "iss": hex::encode(&key_id),
        "aud": hex::encode(&key_id),  // Self-issued for testing
        "exp": now + 3600,  // 1 hour from now
        "iat": now,
        "jti": Uuid::new_v4().to_string(),
        "att": capabilities
    });

    // Encode header and payload
    let header_b64 = URL_SAFE_NO_PAD.encode(header.to_string());
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload.to_string());

    // Create signing input
    let signing_input = format!("{}.{}", header_b64, payload_b64);

    // Sign the input
    let signature: p256::ecdsa::Signature = signing_key.sign(signing_input.as_bytes());
    let signature_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());

    // Assemble JWT
    let token_str = format!("{}.{}.{}", header_b64, payload_b64, signature_b64);

    // Generate a sample request body and its signature
    let request_body = json!({
        "data": "SGVsbG8sIFdvcmxkIQ=="  // "Hello, World!" in base64
    });
    let request_body_str = request_body.to_string();

    // Hash and sign the request body
    let mut hasher = Keccak256::new();
    hasher.update(request_body_str.as_bytes());
    let hash = hasher.finalize();

    let req_signature: p256::ecdsa::Signature = signing_key.sign(&hash);
    let req_signature_bytes = req_signature.to_bytes();
    let req_signature_base64 = STANDARD.encode(req_signature_bytes);

    println!("=== Complete Test Authentication Data ===");
    println!();
    println!("# Environment variables to set:");
    println!("export TEST_AUTH_TOKEN=\"{}\"", token_str);
    println!("export TEST_REQUEST_SIGNATURE=\"{}\"", req_signature_base64);
    println!(
        "export TEST_PUBLIC_KEY=\"{}\"",
        hex::encode(&public_key_bytes)
    );
    println!();
    println!("# Example curl command:");
    println!("curl -X POST http://127.0.0.1:8080/content \\");
    println!("  -H \"Content-Type: application/json\" \\");
    println!("  -H \"Authorization: Bearer $TEST_AUTH_TOKEN\" \\");
    println!("  -H \"X-Request-Signature: $TEST_REQUEST_SIGNATURE\" \\");
    println!("  -d '{}'", request_body_str);
    println!();
    println!("# Token details:");
    println!("  Issuer: {}", hex::encode(&key_id));
    println!("  Audience: {}", hex::encode(&key_id));
    println!("  Capabilities: read, write on all content");
    println!("  Valid for: 1 hour from now");
}
