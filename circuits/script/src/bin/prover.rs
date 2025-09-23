use axum::{routing::post, serve, Json, Router};
use serde::{Deserialize, Serialize};
use sp1_sdk::{include_elf, ProverClient, SP1ProofWithPublicValues, SP1Stdin};
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tower_http::cors::{Any, CorsLayer};
use zkpdf_lib::types::PDFCircuitInput;

pub const ZKPDF_ELF: &[u8] = include_elf!("zkpdf-program");

#[derive(Deserialize)]
struct ProofRequest {
    pdf_bytes: Vec<u8>,
    page_number: u8,
    sub_string: String,
    offset: Option<usize>,
}

#[derive(Serialize)]
struct VerifyResponse {
    valid: bool,
    error: Option<String>,
}

async fn prove(Json(body): Json<ProofRequest>) -> Json<SP1ProofWithPublicValues> {
    let client = ProverClient::from_env();
    let (pk, _vk) = client.setup(ZKPDF_ELF);

    let ProofRequest {
        pdf_bytes,
        page_number,
        sub_string,
        offset,
    } = body;

    let offset = offset.expect("Offset must be provided in the request");
    let offset_u32 = u32::try_from(offset).expect("offset does not fit in u32");

    let proof_input = PDFCircuitInput {
        pdf_bytes,
        page_number,
        offset: offset_u32,
        substring: sub_string,
    };

    let mut stdin = SP1Stdin::new();
    stdin.write(&proof_input);

    let proof = client
        .prove(&pk, &stdin)
        .groth16()
        .run()
        .expect("failed to generate proof");

    Json(proof)
}

async fn verify(Json(proof): Json<SP1ProofWithPublicValues>) -> Json<VerifyResponse> {
    let client = ProverClient::from_env();
    let (_pk, vk) = client.setup(ZKPDF_ELF);

    match client.verify(&proof, &vk) {
        Ok(_) => Json(VerifyResponse {
            valid: true,
            error: None,
        }),
        Err(e) => Json(VerifyResponse {
            valid: false,
            error: Some(format!("Verification failed: {}", e)),
        }),
    }
}

#[tokio::main]
async fn main() {
    sp1_sdk::utils::setup_logger();
    dotenv::dotenv().ok();

    let prover = std::env::var("SP1_PROVER").unwrap_or_default();
    let key = std::env::var("NETWORK_PRIVATE_KEY").unwrap_or_default();

    assert_eq!(prover, "network", "SP1_PROVER must be set to 'network'");
    assert!(
        key.starts_with("0x") && key.len() > 10,
        "Invalid or missing NETWORK_PRIVATE_KEY"
    );

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        .route("/prove", post(prove))
        .route("/verify", post(verify))
        .layer(cors);

    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(3001);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    tracing::info!("listening on {}", addr);

    let listener = TcpListener::bind(addr).await.unwrap();
    serve(listener, app.into_make_service()).await.unwrap();
}
