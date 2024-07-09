// Runs a simple Prover which connects to the Notary and notarizes a request/response from
// example.com. The Prover then generates a proof and writes it to disk.

use dotenv::dotenv;
use http_body_util::{BodyExt, Empty};
use hyper::{body::Bytes, Request, StatusCode};
use hyper_util::rt::TokioIo;
use opacity::{read_env_vars, tls_prover};
use serde::{Deserialize, Serialize};
use std::env;
use std::ops::Range;
use tlsn_core::proof::TlsProof;
use tlsn_prover::tls::{state::Notarize, Prover, ProverConfig};
use tokio::io::AsyncWriteExt as _;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
const MAX_SENT_DATA: usize = 1 << 13;
const MAX_RECV_DATA: usize = 1 << 13;

#[derive(Serialize, Deserialize, Clone, Debug)]
struct NotarizationRequest {
    host: String,
    path: String,
    headers: Vec<(String, String)>,
    redact_string: String,
}

const NOTARIZATION_REQUEST_STR: &str = r###"
{
    "host":"trading-api.kalshi.com",
    "path":"/trade-api/v2/exchange/schedule",
    "headers":[["Accept","application/json"],["Accept-Encoding","Identity"],["Host","trading-api.kalshi.com"],["Connection","close"], ["User-Agent","Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15"]],
    "redact_string":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15"
}
"###;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let (notary_host, notary_port) = read_env_vars();

    let notarization_request: NotarizationRequest =
        serde_json::from_str(NOTARIZATION_REQUEST_STR).unwrap();

    let (notary_socket, session_id) = tls_prover(notary_host, notary_port).await;

    let prover_config = ProverConfig::builder()
        .id(session_id)
        .server_dns(notarization_request.clone().host)
        .max_sent_data(MAX_SENT_DATA)
        .max_recv_data(MAX_RECV_DATA)
        // .root_cert_store(root_cert_store)
        .build()
        .unwrap();

    println!("Setting up prover");
    let prover = Prover::new(prover_config)
        .setup(notary_socket.compat())
        .await
        .unwrap();

    println!("Setup prover");
    let client_socket = tokio::net::TcpStream::connect((notarization_request.host.as_str(), 443))
        .await
        .unwrap_or_else(|err| panic!("Can't connect to server"));

    let (tls_connection, prover_fut) = prover.connect(client_socket.compat()).await.unwrap();

    let prover_task = tokio::spawn(prover_fut);

    let (mut request_sender, connection) =
        hyper::client::conn::http1::handshake(TokioIo::new(tls_connection.compat()))
            .await
            .unwrap();

    tokio::spawn(connection);

    let mut builder = Request::builder().uri(notarization_request.path);

    for (header_name, header_value) in notarization_request.headers.clone() {
        builder = builder.header(header_name, header_value);
    }

    let request = builder.body(Empty::<Bytes>::new()).unwrap();

    println!("Sending request to server: {:?}", request);

    let response = request_sender.send_request(request).await.unwrap();

    assert!(response.status() == StatusCode::OK);

    let payload = response.into_body().collect().await.unwrap().to_bytes();
    println!(
        "Received response from server: {:?}",
        &String::from_utf8_lossy(&payload)
    );

    // server_task.await.unwrap().unwrap();

    let prover = prover_task.await.unwrap().unwrap().start_notarize();

    let redact = notarization_request.redact_string.is_empty();
    let proof = if !redact {
        build_proof_without_redactions(prover).await
    } else {
        build_proof_with_redactions(prover, &notarization_request.redact_string).await
    };

    let mut file = tokio::fs::File::create("simple_proof.json").await.unwrap();
    file.write_all(serde_json::to_string_pretty(&proof).unwrap().as_bytes())
        .await
        .unwrap();

    println!("Notarization completed successfully!");
    println!("The proof has been written to `simple_proof.json`");
}

/// Find the ranges of the public and private parts of a sequence.
///
/// Returns a tuple of `(public, private)` ranges.
fn find_ranges(seq: &[u8], private_seq: &[&[u8]]) -> (Vec<Range<usize>>, Vec<Range<usize>>) {
    let mut private_ranges = Vec::new();
    for s in private_seq {
        for (idx, w) in seq.windows(s.len()).enumerate() {
            if w == *s {
                private_ranges.push(idx..(idx + w.len()));
            }
        }
    }

    let mut sorted_ranges = private_ranges.clone();
    sorted_ranges.sort_by_key(|r| r.start);

    let mut public_ranges = Vec::new();
    let mut last_end = 0;
    for r in sorted_ranges {
        if r.start > last_end {
            public_ranges.push(last_end..r.start);
        }
        last_end = r.end;
    }

    if last_end < seq.len() {
        public_ranges.push(last_end..seq.len());
    }

    (public_ranges, private_ranges)
}

async fn build_proof_without_redactions(mut prover: Prover<Notarize>) -> TlsProof {
    let sent_len = prover.sent_transcript().data().len();
    let recv_len = prover.recv_transcript().data().len();

    let builder = prover.commitment_builder();
    let sent_commitment = builder.commit_sent(&(0..sent_len)).unwrap();
    let recv_commitment = builder.commit_recv(&(0..recv_len)).unwrap();

    // Finalize, returning the notarized session
    let notarized_session = prover.finalize().await.unwrap();

    // Create a proof for all committed data in this session
    let mut proof_builder = notarized_session.data().build_substrings_proof();

    // Reveal all the public ranges
    proof_builder.reveal_by_id(sent_commitment).unwrap();
    proof_builder.reveal_by_id(recv_commitment).unwrap();

    let substrings_proof = proof_builder.build().unwrap();

    TlsProof {
        session: notarized_session.session_proof(),
        substrings: substrings_proof,
    }
}

async fn build_proof_with_redactions(
    mut prover: Prover<Notarize>,
    redact_string: &str,
) -> TlsProof {
    // Identify the ranges in the outbound data which contain data which we want to disclose
    let (sent_public_ranges, _) = find_ranges(
        prover.sent_transcript().data(),
        &[
            // Redact the value of the "User-Agent" header. It will NOT be disclosed.
            redact_string.as_bytes(),
        ],
    );

    // Identify the ranges in the inbound data which contain data which we want to disclose
    let (recv_public_ranges, _) = find_ranges(
        prover.recv_transcript().data(),
        &[
            // Redact the value of the title. It will NOT be disclosed.
            "Example Domain".as_bytes(),
        ],
    );

    let builder = prover.commitment_builder();

    // Commit to each range of the public outbound data which we want to disclose
    let sent_commitments: Vec<_> = sent_public_ranges
        .iter()
        .map(|range| builder.commit_sent(range).unwrap())
        .collect();
    // Commit to each range of the public inbound data which we want to disclose
    let recv_commitments: Vec<_> = recv_public_ranges
        .iter()
        .map(|range| builder.commit_recv(range).unwrap())
        .collect();

    // Finalize, returning the notarized session
    let notarized_session = prover.finalize().await.unwrap();

    // Create a proof for all committed data in this session
    let mut proof_builder = notarized_session.data().build_substrings_proof();

    // Reveal all the public ranges
    for commitment_id in sent_commitments {
        proof_builder.reveal_by_id(commitment_id).unwrap();
    }
    for commitment_id in recv_commitments {
        proof_builder.reveal_by_id(commitment_id).unwrap();
    }

    let substrings_proof = proof_builder.build().unwrap();

    TlsProof {
        session: notarized_session.session_proof(),
        substrings: substrings_proof,
    }
}
