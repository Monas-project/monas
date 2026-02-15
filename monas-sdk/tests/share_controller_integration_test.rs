use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use mockito::Server;
use monas_sdk::models::content::{ContentMetadata, CreateContentInput};
use monas_sdk::models::keypair::{GenerateKeypairInput, KeyType};
use monas_sdk::models::share::{Permission, ShareContentInput};
use monas_sdk::MonasController;

mod support;
use support::{acquire_test_lock, cleanup_content_artifacts};

#[tokio::test(flavor = "multi_thread")]
async fn share_content_succeeds_after_content_creation() {
    let _guard = acquire_test_lock();
    let mut server = Server::new_async().await;
    let create_mock = server
        .mock("POST", "/content")
        .with_status(200)
        .create_async()
        .await;

    let controller = MonasController::with_state_node_url(server.url());

    let sender = controller
        .generate_keypair(GenerateKeypairInput {
            key_type: KeyType::Secp256r1,
        })
        .data
        .expect("sender keypair should be generated");
    let recipient = controller
        .generate_keypair(GenerateKeypairInput {
            key_type: KeyType::Secp256r1,
        })
        .data
        .expect("recipient keypair should be generated");

    let create_response = controller.create_content(CreateContentInput {
        content: URL_SAFE_NO_PAD.encode(b"share-target-content"),
        metadata: Some(ContentMetadata {
            name: Some("share.txt".to_string()),
            content_type: Some("text/plain".to_string()),
            created_at: None,
            updated_at: None,
        }),
    });
    assert!(create_response.success, "create_content should succeed");
    let created = create_response.data.expect("create should return data");
    create_mock.assert();

    let share_response = controller.share_content(ShareContentInput {
        content_id: created.content_id.clone(),
        sender_public_key: sender.public_key.clone(),
        recipient_public_key: recipient.public_key.clone(),
        permissions: vec![Permission::Read],
    });

    assert!(
        share_response.success,
        "share_content should succeed: {:?}",
        share_response.error
    );
    assert!(share_response.error.is_none(), "unexpected share error");
    let shared = share_response.data.expect("share should return data");

    assert_eq!(shared.content_id, created.content_id);
    assert_eq!(shared.recipient_public_key, recipient.public_key);
    assert!(
        !shared.sender_key_id.is_empty(),
        "sender_key_id should be set"
    );
    assert!(
        !shared.recipient_key_id.is_empty(),
        "recipient_key_id should be set"
    );
    assert!(
        !shared.key_envelope.enc.is_empty(),
        "key_envelope.enc should be set"
    );
    assert!(
        !shared.key_envelope.wrapped_cek.is_empty(),
        "key_envelope.wrapped_cek should be set"
    );
    assert!(
        !shared.key_envelope.ciphertext.is_empty(),
        "key_envelope.ciphertext should be set"
    );

    cleanup_content_artifacts();
}
