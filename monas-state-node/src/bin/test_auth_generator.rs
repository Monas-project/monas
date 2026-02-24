use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use p256::ecdsa::{signature::Signer, SigningKey};
use p256::elliptic_curve::rand_core::OsRng;
use serde_json::json;
use sha2::{Digest as Sha2Digest, Sha256};
use std::env;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        print_usage(&args[0]);
        std::process::exit(1);
    }

    let command = &args[1];

    match command.as_str() {
        "generate-keys" => {
            generate_keypair();
        }
        "sign-request" => {
            sign_request(&args[2..]);
        }
        "test-auth" => {
            generate_test_auth_data();
        }
        "generate-token" => {
            let content_id = args.get(2).cloned();
            generate_auth_token(content_id);
        }
        "generate-share-token" => {
            generate_share_token(&args[2..]);
        }
        "sign-key-id" => {
            sign_key_id(&args[2..]);
        }
        "help" | "--help" | "-h" => {
            print_usage(&args[0]);
        }
        _ => {
            eprintln!("Unknown command: {}", command);
            print_usage(&args[0]);
            std::process::exit(1);
        }
    }
}

fn print_usage(program: &str) {
    eprintln!("Usage: {} <command> [args...]", program);
    eprintln!("Commands:");
    eprintln!("  generate-keys                        - Generate a new P-256 keypair");
    eprintln!(
        "  test-auth                            - Generate keypair + key_id (machine-readable)"
    );
    eprintln!("  sign-request                         - Sign a request message");
    eprintln!("    --private-key <hex>                  Private key (hex)");
    eprintln!("    --operation <op>                     Operation (create/update/delete/read/...)");
    eprintln!("    --resource <res>                     Resource (content_id or 'content')");
    eprintln!("    --timestamp <ts>                     Unix timestamp");
    eprintln!("    [--body <base64>]                    Request body (base64, for create/update)");
    eprintln!("  generate-token [content_id]           - Generate an auth token (JWT)");
    eprintln!("  generate-share-token                  - Generate a share token for another user");
    eprintln!("  sign-key-id                          - Sign a key_id for proof-of-possession");
    eprintln!("    --private-key <hex>                  Private key (hex)");
    eprintln!("    --key-id <key_id>                    Key ID to sign");
}

/// Generate a P-256 keypair and output in machine-readable format.
fn generate_keypair() {
    let signing_key = SigningKey::random(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    let public_key_bytes = verifying_key.to_encoded_point(false).as_bytes().to_vec();
    let private_key_bytes = signing_key.to_bytes();

    println!("PRIVATE_KEY={}", hex::encode(private_key_bytes));
    println!("PUBLIC_KEY={}", hex::encode(&public_key_bytes));
}

/// Generate test auth data: keypair + key_id, in machine-readable format.
fn generate_test_auth_data() {
    let signing_key = SigningKey::random(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    let public_key_bytes = verifying_key.to_encoded_point(false).as_bytes().to_vec();
    let private_key_bytes = signing_key.to_bytes();

    // Machine-readable output for script consumption
    println!("PRIVATE_KEY={}", hex::encode(private_key_bytes));
    println!("PUBLIC_KEY={}", hex::encode(&public_key_bytes));
}

/// Sign a request with the correct message format.
///
/// For requests WITH body (create/update):
///   message = hex(sha256(body_bytes + timestamp_be_bytes))
///
/// For requests WITHOUT body (delete/read/invalidate/manage/revoke):
///   message = "{operation}:{resource}:{timestamp}"
fn sign_request(args: &[String]) {
    let mut private_key_hex = String::new();
    let mut operation = String::new();
    let mut resource = String::new();
    let mut timestamp_str = String::new();
    let mut body_b64 = String::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--private-key" => {
                i += 1;
                if i < args.len() {
                    private_key_hex = args[i].clone();
                }
            }
            "--operation" => {
                i += 1;
                if i < args.len() {
                    operation = args[i].clone();
                }
            }
            "--resource" => {
                i += 1;
                if i < args.len() {
                    resource = args[i].clone();
                }
            }
            "--timestamp" => {
                i += 1;
                if i < args.len() {
                    timestamp_str = args[i].clone();
                }
            }
            "--body" => {
                i += 1;
                if i < args.len() {
                    body_b64 = args[i].clone();
                }
            }
            _ => {}
        }
        i += 1;
    }

    if private_key_hex.is_empty() || operation.is_empty() || resource.is_empty() {
        eprintln!("Error: --private-key, --operation, --resource are required");
        std::process::exit(1);
    }

    let timestamp: u64 = if timestamp_str.is_empty() {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    } else {
        timestamp_str.parse().unwrap_or_else(|e| {
            eprintln!("Error: Invalid timestamp: {}", e);
            std::process::exit(1);
        })
    };

    // Parse private key
    let private_key_bytes = hex::decode(&private_key_hex).unwrap_or_else(|e| {
        eprintln!("Error: Invalid private key hex: {}", e);
        std::process::exit(1);
    });
    let signing_key = SigningKey::from_bytes((&private_key_bytes[..]).into()).unwrap_or_else(|e| {
        eprintln!("Error: Invalid private key: {}", e);
        std::process::exit(1);
    });

    // Construct the signing message
    let message = if !body_b64.is_empty() {
        // Body-based signing: hex(sha256(body_bytes + timestamp_be_bytes))
        let body_bytes = STANDARD.decode(&body_b64).unwrap_or_else(|e| {
            eprintln!("Error: Invalid body base64: {}", e);
            std::process::exit(1);
        });
        let mut hasher = Sha256::new();
        hasher.update(&body_bytes);
        hasher.update(timestamp.to_be_bytes());
        hex::encode(hasher.finalize())
    } else {
        // Metadata-based signing: {operation}:{resource}:{timestamp}
        format!("{}:{}:{}", operation, resource, timestamp)
    };

    // Sign the message
    let signature: p256::ecdsa::Signature = signing_key.sign(message.as_bytes());
    let signature_base64 = STANDARD.encode(signature.to_bytes());

    // Machine-readable output
    println!("SIGNATURE={}", signature_base64);
    println!("TIMESTAMP={}", timestamp);
    println!("MESSAGE={}", message);
}

fn generate_auth_token(content_id: Option<String>) {
    let signing_key = SigningKey::random(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    let public_key_bytes = verifying_key.to_encoded_point(false).as_bytes().to_vec();

    let mut capabilities = vec![];
    if let Some(cid) = content_id {
        capabilities.push(json!({
            "with": format!("monas://content/{}", cid),
            "can": "write"
        }));
    } else {
        capabilities.push(json!({
            "with": "monas://content/*",
            "can": "write"
        }));
    }

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
        "iss": format!("user:{}", &hex::encode(&public_key_bytes)[..16]),
        "aud": format!("user:{}", &hex::encode(&public_key_bytes)[..16]),
        "exp": now + 3600,
        "iat": now,
        "jti": Uuid::new_v4().to_string(),
        "att": capabilities
    });

    let header_b64 = URL_SAFE_NO_PAD.encode(header.to_string());
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload.to_string());
    let signing_input = format!("{}.{}", header_b64, payload_b64);

    let signature: p256::ecdsa::Signature = signing_key.sign(signing_input.as_bytes());
    let signature_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());

    let token_str = format!("{}.{}.{}", header_b64, payload_b64, signature_b64);

    println!("TOKEN={}", token_str);
    println!("PUBLIC_KEY={}", hex::encode(&public_key_bytes));
}

fn generate_share_token(args: &[String]) {
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

    let owner_key_id = format!("user:{}", &hex::encode(&owner_public_key_bytes)[..16]);

    let recipient_public_key_bytes = hex::decode(&recipient_key_hex).unwrap_or_else(|e| {
        eprintln!("Error: Invalid recipient key hex: {}", e);
        std::process::exit(1);
    });

    let recipient_key_id = format!("user:{}", &hex::encode(&recipient_public_key_bytes)[..16]);

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

    let signature: p256::ecdsa::Signature = owner_signing_key.sign(signing_input.as_bytes());
    let signature_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());

    let token_str = format!("{}.{}.{}", header_b64, payload_b64, signature_b64);

    println!("SHARE_TOKEN={}", token_str);
    println!("OWNER_PUBLIC_KEY={}", hex::encode(&owner_public_key_bytes));
    println!("RECIPIENT_PUBLIC_KEY={}", recipient_key_hex);
    println!("OWNER_KEY_ID={}", owner_key_id);
    println!("RECIPIENT_KEY_ID={}", recipient_key_id);
    println!("CONTENT_ID={}", content_id);
    println!("JTI={}", jti);
}

/// Sign a key_id for proof-of-possession during key registration.
///
/// Uses SHA-256 digest signing (matching verify_p256_signature in crypto.rs).
fn sign_key_id(args: &[String]) {
    let mut private_key_hex = String::new();
    let mut key_id = String::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--private-key" => {
                i += 1;
                if i < args.len() {
                    private_key_hex = args[i].clone();
                }
            }
            "--key-id" => {
                i += 1;
                if i < args.len() {
                    key_id = args[i].clone();
                }
            }
            _ => {}
        }
        i += 1;
    }

    if private_key_hex.is_empty() || key_id.is_empty() {
        eprintln!("Error: --private-key and --key-id are required");
        std::process::exit(1);
    }

    let private_key_bytes = hex::decode(&private_key_hex).unwrap_or_else(|e| {
        eprintln!("Error: Invalid private key hex: {}", e);
        std::process::exit(1);
    });
    let signing_key = SigningKey::from_bytes((&private_key_bytes[..]).into()).unwrap_or_else(|e| {
        eprintln!("Error: Invalid private key: {}", e);
        std::process::exit(1);
    });

    // Sign with SHA-256 digest (matching verify_p256_signature in crypto.rs)
    use p256::ecdsa::signature::DigestSigner;
    let signature: p256::ecdsa::Signature =
        signing_key.sign_digest(Sha256::new_with_prefix(key_id.as_bytes()));
    let signature_hex = hex::encode(signature.to_bytes());

    println!("SIGNATURE_HEX={}", signature_hex);
}
