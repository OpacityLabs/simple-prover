// Runs a simple Prover which connects to the Notary and notarizes a request/response from
// example.com. The Prover then generates a proof and writes it to disk.

use http_body_util::Empty;
use hyper::{body::Bytes, Request, StatusCode};
use hyper_util::rt::TokioIo;
use std::ops::Range;
use tlsn_core::proof::TlsProof;
use tokio::io::AsyncWriteExt as _;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use opacity::run_notary;
use tlsn_prover::tls::{state::Notarize, Prover, ProverConfig};
use std::str;
use serde::{Deserialize, Serialize};


#[derive(Serialize, Deserialize, Clone, Debug)]
struct NotarizationRequest {
    host: String,
    path: String,
    headers: Vec<(String, String)>,
    redact_strings: Vec<String>,
}


const NOTARIZATION_REQUEST_STR:&str = r###"
{
    "host":"trading-api.kalshi.com",
    "path":"/trade-api/v2/exchange/schedule",
    "headers":[["Accept","application/json"],["Accept-Encoding","Identity"],["Host","trading-api.kalshi.com"],["Connection","close"]],
    "redact_strings":[]
}
"###;


#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let notarization_request: NotarizationRequest = serde_json::from_str(NOTARIZATION_REQUEST_STR).unwrap();
    let (prover_socket, notary_socket) = tokio::io::duplex(1 << 16);
    
    // // Start a local simple notary service
    tokio::spawn(run_notary(notary_socket.compat()));

    println!("Notarization request sent to the Notary");


    // A Prover configuration
    let config = ProverConfig::builder()
    .id("example")

        .server_dns(notarization_request.clone().host)
        .build()
        .unwrap();

    // Create a Prover and set it up with the Notary
    // This will set up the MPC backend prior to connecting to the server.
    let prover = Prover::new(config)
        .setup(prover_socket.compat())
        .await
        .unwrap();

    // Connect to the Server via TCP. This is the TLS client socket.
    let client_socket = tokio::net::TcpStream::connect((notarization_request.clone().host, 443))
        .await
        .unwrap();

    // Bind the Prover to the server connection.
    // The returned `mpc_tls_connection` is an MPC TLS connection to the Server: all data written
    // to/read from it will be encrypted/decrypted using MPC with the Notary.
    let (mpc_tls_connection, prover_fut) = prover.connect(client_socket.compat()).await.unwrap();
    let mpc_tls_connection = TokioIo::new(mpc_tls_connection.compat());

    // Spawn the Prover task to be run concurrently
    let prover_task = tokio::spawn(prover_fut);

    // Attach the hyper HTTP client to the MPC TLS connection
    let (mut request_sender, connection) =
        hyper::client::conn::http1::handshake(mpc_tls_connection)
            .await
            .unwrap();

    // Spawn the HTTP task to be run concurrently
    tokio::spawn(connection);

    // Build a simple HTTP request with common headers
    let mut builder = Request::builder()
    .uri(notarization_request.clone().path);

    for (header_name, header_value) in notarization_request.clone().headers.clone() {

        builder = builder.header(header_name, header_value);
    }

    let request = builder.body(Empty::<Bytes>::new()).unwrap();


    println!("Starting an MPC TLS connection with the server");

    // Send the request to the Server and get a response via the MPC TLS connection
    let response = request_sender.send_request(request).await.unwrap();

    println!("Got a response from the server");

    assert!(response.status() == StatusCode::OK);

    // The Prover task should be done now, so we can grab the Prover.
    let prover = prover_task.await.unwrap().unwrap();

    // Prepare for notarization.
    let prover = prover.start_notarize();

    // Build proof (with or without redactions);
    let proof =  build_proof_with_redactions(prover, notarization_request.clone().redact_strings).await;

    // Write the proof to a file
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

async fn build_proof_with_redactions(mut prover: Prover<Notarize>, redact_strings: Vec<String>) -> TlsProof {
    // Identify the ranges in the outbound data which contain data which we want to disclose
    let mut redact_strings_vec: Vec<Vec<u8>> = Vec::new();

    redact_strings.iter().for_each(|(redacted)| {
        redact_strings_vec.push(redacted.as_bytes().to_vec());
    });

    let (sent_public_ranges, _) = find_ranges(
        prover.sent_transcript().data(),
        redact_strings_vec
            .iter()
            .map(|r| r.as_slice())
            .collect::<Vec<_>>()
            .as_slice(),
    );

    // Identify the ranges in the inbound data which contain data which we want to disclose
    let (recv_public_ranges, _) = find_ranges(
        prover.recv_transcript().data(),
        redact_strings_vec
            .iter()
            .map(|r| r.as_slice())
            .collect::<Vec<_>>()
            .as_slice(),
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
