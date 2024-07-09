use dotenv::dotenv;
use notary_client::{NotarizationRequest, NotaryClient, NotaryConnection};
use notary_server::read_pem_file;
use rustls::{Certificate, RootCertStore};
use serde::{Deserialize, Serialize};
use std::env;

/// Response object of the /info API

const MAX_SENT_DATA: usize = 1 << 13;
const MAX_RECV_DATA: usize = 1 << 13;

pub fn read_env_vars() -> (String, u16) {
    dotenv().ok();
    let notary_host = env::var("NOTARY_HOST").unwrap_or_else(|_| panic!("$NOTARY_HOST not set"));

    let notary_port_string =
        env::var("NOTARY_PORT").unwrap_or_else(|_| panic!("$NOTARY_HOST not set"));

    let notary_port = notary_port_string
        .parse::<u16>()
        .unwrap_or_else(|_| panic!("$NOTARY_PORT must be a number"));

    (notary_host, notary_port)
}

pub async fn tls_prover(host: String, port: u16) -> (NotaryConnection, String) {
    let mut certificate_file_reader = read_pem_file("fixture/opacityCA.crt").await.unwrap();
    let mut certificates: Vec<Certificate> = rustls_pemfile::certs(&mut certificate_file_reader)
        .unwrap()
        .into_iter()
        .map(Certificate)
        .collect();
    let certificate = certificates.remove(0);

    let mut root_cert_store = RootCertStore::empty();
    root_cert_store.add(&certificate).unwrap();

    let notary_client = NotaryClient::builder()
        .host(&host)
        .port(port)
        .root_cert_store(root_cert_store)
        .build()
        .unwrap();

    let notarization_request = NotarizationRequest::builder()
        .max_sent_data(MAX_SENT_DATA)
        .max_recv_data(MAX_RECV_DATA)
        .build()
        .unwrap();

    let accepted_request = notary_client
        .request_notarization(notarization_request)
        .await
        .unwrap();

    (accepted_request.io, accepted_request.id)
}
