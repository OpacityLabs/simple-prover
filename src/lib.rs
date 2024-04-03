use elliptic_curve::pkcs8::DecodePrivateKey;
use futures::{AsyncRead, AsyncWrite};

use tlsn_verifier::tls::{Verifier, VerifierConfig};

const NOTARY_KEY_STR: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgEvBc/VMWn3E4PGfe
ETc/ekdTRmRwNN9J6eKDPxJ98ZmhRANCAAQG/foUjhkWzMlrQNAUnfBYJe9UsWtx
HMwbmRpN4cahLMO7pwWrHe4RZikUajoLQQ5SB/6YSBuS0utehy/nIfMq
-----END PRIVATE KEY-----";

/// Runs a simple Notary with the provided connection to the Prover.
pub async fn run_notary<T: AsyncWrite + AsyncRead + Send + Unpin + 'static>(conn: T) {

    let signing_key = p256::ecdsa::SigningKey::from_pkcs8_pem(NOTARY_KEY_STR).unwrap();

    // Setup default config. Normally a different ID would be generated
    // for each notarization.
    let config = VerifierConfig::builder().id("example").build().unwrap();

    Verifier::new(config)
        .notarize::<_, p256::ecdsa::Signature>(conn, &signing_key)
        .await
        .unwrap();
}

