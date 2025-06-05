use axum::{routing::post, serve, Json, Router};
use serde::{Deserialize, Serialize};
use sp1_sdk::{include_elf, ProverClient, SP1ProofWithPublicValues, SP1Stdin};
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tower_http::cors::{Any, CorsLayer};

pub const FIBONACCI_ELF: &[u8] = include_elf!("fibonacci-program");

#[derive(Deserialize)]
struct ProofRequest {
    pdf_bytes: Vec<u8>,
    page_number: u8,
    sub_string: String,
}

#[derive(Serialize)]
struct VerifyResponse {
    valid: bool,
    error: Option<String>,
}

async fn prove(Json(body): Json<ProofRequest>) -> Json<SP1ProofWithPublicValues> {
    let client = ProverClient::from_env();
    let (pk, vk) = client.setup(FIBONACCI_ELF);

    let mut stdin = SP1Stdin::new();
    stdin.write(&body.pdf_bytes);
    stdin.write(&body.page_number);
    stdin.write(&body.sub_string);

    let proof = client
        .prove(&pk, &stdin)
        .groth16()
        .run()
        .expect("failed to generate proof");

    Json(proof)
}

async fn verify(Json(proof): Json<SP1ProofWithPublicValues>) -> Json<VerifyResponse> {
    let client = ProverClient::from_env();
    let (_pk, vk) = client.setup(FIBONACCI_ELF);

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
