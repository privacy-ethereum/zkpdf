//! An end-to-end example of using the SP1 SDK to generate a proof of a program that can be executed
//! or have a core proof generated.
//!
//! You can run this script using the following command:
//! ```shell
//! RUST_LOG=info cargo run --release -- --execute
//! ```
//! or
//! ```shell
//! RUST_LOG=info cargo run --release -- --prove
//! ```

use alloy_sol_types::SolType;
use clap::Parser;
use sp1_sdk::{include_elf, ProverClient, SP1Stdin};
use zkpdf_lib::{types::PDFCircuitInput, PublicValuesStruct};

/// The ELF (executable and linkable format) file for the Succinct RISC-V zkVM.
pub const ZKPDF_ELF: &[u8] = include_elf!("zkpdf-program");

/// The arguments for the command.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(long)]
    execute: bool,

    #[arg(long)]
    prove: bool,

    #[arg(
        long,
        default_value = "../../pdf-utils/sample-pdfs/digitally_signed.pdf"
    )]
    pdf_path: String,

    #[arg(long, default_value_t = 0)]
    page: u8,

    #[arg(long, default_value = "Sample Signed PDF Document")]
    substring: String,

    #[arg(long, default_value_t = 0)]
    offset: usize,
}

fn main() {
    // Setup the logger.
    sp1_sdk::utils::setup_logger();
    dotenv::dotenv().ok();

    // Parse the command line arguments.
    let Args {
        execute,
        prove,
        pdf_path,
        page,
        substring,
        offset,
    } = Args::parse();

    if execute == prove {
        eprintln!("Error: You must specify either --execute or --prove");
        std::process::exit(1);
    }

    // Setup the prover client.
    let client = ProverClient::from_env();

    // Load the PDF bytes from the provided path
    let pdf_bytes = std::fs::read(&pdf_path)
        .unwrap_or_else(|_| panic!("Failed to read PDF file at {}", pdf_path));

    let page_number: u8 = page;
    let sub_string = substring;

    println!("pdf_path: {}", pdf_path);
    println!("page: {}", page_number);
    println!("substring: {}", sub_string);
    println!("offset: {}", offset);

    let offset_u32 = u32::try_from(offset).expect("offset does not fit in u32");
    let proof_input = PDFCircuitInput {
        pdf_bytes,
        page_number,
        offset: offset_u32,
        substring: sub_string,
    };

    // Setup the inputs.
    let mut stdin = SP1Stdin::new();
    stdin.write(&proof_input);

    if execute {
        // Execute the program
        let (output, report) = client.execute(ZKPDF_ELF, &stdin).run().unwrap();
        println!("Program executed successfully.");

        // Read the output.
        let decoded = PublicValuesStruct::abi_decode(output.as_slice(), true).unwrap();
        println!("Substring matches: {}", decoded.substringMatches);
        println!(
            "Message digest hash: 0x{}",
            hex::encode(decoded.messageDigestHash.as_slice())
        );
        println!(
            "Signer key hash: 0x{}",
            hex::encode(decoded.signerKeyHash.as_slice())
        );
        println!(
            "Substring hash: 0x{}",
            hex::encode(decoded.substringHash.as_slice())
        );
        println!("Nullifier: 0x{}", hex::encode(decoded.nullifier.as_slice()));
        println!("Number of cycles: {}", report.total_instruction_count());
    } else {
        // Setup the program for proving.
        let (pk, vk) = client.setup(ZKPDF_ELF);

        // Generate the proof
        let proof = client
            .prove(&pk, &stdin)
            .run()
            .expect("failed to generate proof");

        println!("Successfully generated proof!");

        // Verify the proof.
        client.verify(&proof, &vk).expect("failed to verify proof");
        println!("Successfully verified proof!");
    }
}
