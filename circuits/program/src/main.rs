#![no_main]
sp1_zkvm::entrypoint!(main);

use alloy_sol_types::SolType;
use zkpdf_lib::{
    types::{PDFCircuitInput, PDFCircuitOutput},
    verify_pdf_claim, PublicValuesStruct,
};

pub fn main() {
    let input = sp1_zkvm::io::read::<PDFCircuitInput>();
    let output = verify_pdf_claim(input).unwrap_or_else(|_| PDFCircuitOutput::failure());
    let public_values: PublicValuesStruct = output.into();
    let bytes = PublicValuesStruct::abi_encode(&public_values);

    // Commit to the public values of the program. The final proof will have a commitment to all the
    // bytes that were committed to.
    sp1_zkvm::io::commit_slice(&bytes);
}
