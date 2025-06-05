#![no_main]
sp1_zkvm::entrypoint!(main);

use core::verify_text;

use alloy_sol_types::SolType;
use fibonacci_lib::PublicValuesStruct;

pub fn main() {
    let pdf_bytes = sp1_zkvm::io::read::<Vec<u8>>();
    let page_number = sp1_zkvm::io::read::<u8>();
    let sub_string = sp1_zkvm::io::read::<String>();

    let is_valid = verify_text(pdf_bytes, page_number, &sub_string).is_ok();

    let bytes = PublicValuesStruct::abi_encode(&PublicValuesStruct { result: is_valid });

    // Commit to the public values of the program. The final proof will have a commitment to all the
    // bytes that were committed to.
    sp1_zkvm::io::commit_slice(&bytes);
}
