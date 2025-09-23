//! An end-to-end example of using the SP1 SDK to generate a proof of a program that can have an
//! EVM-Compatible proof generated which can be verified on-chain.
//!
//! You can run this script using the following command:
//! ```shell
//! RUST_LOG=info cargo run --release --bin evm -- --system groth16
//! ```
//! or
//! ```shell
//! RUST_LOG=info cargo run --release --bin evm -- --system plonk
//! ```

use alloy_sol_types::SolType;
use clap::{Parser, ValueEnum};
use serde::{Deserialize, Serialize};
use sp1_sdk::{
    include_elf, HashableKey, ProverClient, SP1ProofWithPublicValues, SP1Stdin, SP1VerifyingKey,
};
use std::path::PathBuf;
use zkpdf_lib::{types::PDFCircuitInput, PublicValuesStruct};

/// The ELF (executable and linkable format) file for the Succinct RISC-V zkVM.
pub const ZKPDF_ELF: &[u8] = include_elf!("zkpdf-program");

/// The arguments for the EVM command.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct EVMArgs {
    #[arg(
        long,
        default_value = "../../pdf-utils/sample-pdfs/digitally_signed.pdf"
    )]
    pdf_path: String,

    #[arg(long, value_enum, default_value = "groth16")]
    system: ProofSystem,

    #[arg(long, default_value_t = 0)]
    page: u8,

    #[arg(long, default_value = "Sample Signed PDF Document")]
    substring: String,

    #[arg(long, default_value_t = 0)]
    offset: usize,
}

/// Enum representing the available proof systems
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum ProofSystem {
    Plonk,
    Groth16,
}

/// A fixture that can be used to test the verification of SP1 zkVM proofs inside Solidity.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SP1ZkPdfProofFixture {
    substring_matches: bool,
    message_digest_hash: String,
    signer_key_hash: String,
    substring_hash: String,
    nullifier: String,
    vkey: String,
    public_values: String,
    proof: String,
}

fn main() {
    // Setup the logger.
    sp1_sdk::utils::setup_logger();

    // Parse the command line arguments.
    let EVMArgs {
        pdf_path,
        system,
        page,
        substring,
        offset,
    } = EVMArgs::parse();

    // Setup the prover client.
    let client = ProverClient::from_env();

    // Load the PDF bytes from the provided path
    let pdf_bytes = std::fs::read(&pdf_path)
        .unwrap_or_else(|_| panic!("Failed to read PDF file at {}", pdf_path));

    // Setup the program.
    let (pk, vk) = client.setup(ZKPDF_ELF);

    // Setup the inputs.
    let page_number: u8 = page;
    let sub_string = substring;

    println!("pdf_path: {}", pdf_path);
    println!("page: {}", page_number);
    println!("substring: {}", sub_string);
    println!("offset: {}", offset);
    println!("Proof System: {:?}", system);

    let offset_u32 = u32::try_from(offset).expect("offset does not fit in u32");
    let proof_input = PDFCircuitInput {
        pdf_bytes,
        page_number,
        offset: offset_u32,
        substring: sub_string,
    };

    let mut stdin = SP1Stdin::new();
    stdin.write(&proof_input);

    // Generate the proof based on the selected proof system.
    let proof = match system {
        ProofSystem::Plonk => client.prove(&pk, &stdin).plonk().run(),
        ProofSystem::Groth16 => client.prove(&pk, &stdin).groth16().run(),
    }
    .expect("failed to generate proof");

    create_proof_fixture(&proof, &vk, system);
}

/// Create a fixture for the given proof.
fn create_proof_fixture(
    proof: &SP1ProofWithPublicValues,
    vk: &SP1VerifyingKey,
    system: ProofSystem,
) {
    // Deserialize the public values.
    let bytes = proof.public_values.as_slice();
    let decoded = PublicValuesStruct::abi_decode(bytes, false).unwrap();

    // Create the testing fixture so we can test things end-to-end.
    let fixture = SP1ZkPdfProofFixture {
        substring_matches: decoded.substringMatches,
        message_digest_hash: format!("0x{}", hex::encode(decoded.messageDigestHash.as_slice())),
        signer_key_hash: format!("0x{}", hex::encode(decoded.signerKeyHash.as_slice())),
        substring_hash: format!("0x{}", hex::encode(decoded.substringHash.as_slice())),
        nullifier: format!("0x{}", hex::encode(decoded.nullifier.as_slice())),
        vkey: vk.bytes32().to_string(),
        public_values: format!("0x{}", hex::encode(bytes)),
        proof: format!("0x{}", hex::encode(proof.bytes())),
    };

    // The verification key is used to verify that the proof corresponds to the execution of the
    // program on the given input.
    println!("Verification Key: {}", fixture.vkey);
    println!(
        "Substring matches: {}\nmessageDigestHash: {}\nsignerKeyHash: {}\nsubstringHash: {}\nnullifier: {}",
        fixture.substring_matches,
        fixture.message_digest_hash,
        fixture.signer_key_hash,
        fixture.substring_hash,
        fixture.nullifier
    );
    println!("Public Values: {}", fixture.public_values);
    println!("Proof Bytes: {}", fixture.proof);

    // Save the fixture to a file.
    let fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../contracts/src/fixtures");
    std::fs::create_dir_all(&fixture_path).expect("failed to create fixture path");
    std::fs::write(
        fixture_path.join(format!("{:?}-fixture.json", system).to_lowercase()),
        serde_json::to_string_pretty(&fixture).unwrap(),
    )
    .expect("failed to write fixture");
}
