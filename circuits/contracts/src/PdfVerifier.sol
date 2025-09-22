// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ISP1Verifier} from "@sp1-contracts/ISP1Verifier.sol";

struct PublicValuesStruct {
    bool result;
}

/// @title PdfVerifier
/// @notice Verifies SP1 proofs for the zkPDF program and returns the attested result.
contract PdfVerifier {
    /// @notice Address of the on-chain SP1 verifier contract.
    address public verifier;

    /// @notice Verification key for the zkPDF program.
    bytes32 public programVKey;

    constructor(address _verifier, bytes32 _programVKey) {
        verifier = _verifier;
        programVKey = _programVKey;
    }

    /// @notice Verifies a zkPDF proof and returns the attested result flag.
    /// @param _publicValues ABI-encoded public values emitted by the zkPDF program.
    /// @param _proofBytes Encoded SP1 proof bytes.
    function verifyPdfProof(
        bytes calldata _publicValues,
        bytes calldata _proofBytes
    ) public view returns (bool) {
        ISP1Verifier(verifier).verifyProof(
            programVKey,
            _publicValues,
            _proofBytes
        );
        PublicValuesStruct memory publicValues = abi.decode(
            _publicValues,
            (PublicValuesStruct)
        );
        return publicValues.result;
    }
}
