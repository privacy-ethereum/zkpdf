# On-chain Verification

This section covers how to verify ZKPDF proofs on blockchain networks and integrate them into your applications.

## Overview

ZKPDF generates zero-knowledge proofs that can be verified on-chain using smart contracts. The verification process ensures document authenticity without revealing sensitive content.

## Smart Contract Integration

The `PdfVerifier` contract provides on-chain proof verification:

```solidity
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
```

### Deployment

#### 1. Deploy SP1 Verifier Contract

First, deploy the SP1 verifier contract to your target network:

```bash
# Get the SP1 verifier contract address
# This is typically provided by Succinct Labs
export SP1_VERIFIER_ADDRESS="0x..."

# Deploy using Foundry
forge create --rpc-url $RPC_URL \
  --private-key $PRIVATE_KEY \
  src/PdfVerifier.sol:PdfVerifier \
  --constructor-args $SP1_VERIFIER_ADDRESS $PROGRAM_VKEY
```

#### 2. Get Program Verification Key

Generate the program verification key:

```bash
cd circuits/script
cargo run --release --bin vkey
```

This will output the verification key hash that you need for contract deployment.

#### 3. Deploy PdfVerifier Contract

```bash
# Deploy the contract with the SP1 verifier address and program key
forge create --rpc-url $RPC_URL \
  --private-key $PRIVATE_KEY \
  src/PdfVerifier.sol:PdfVerifier \
  --constructor-args $SP1_VERIFIER_ADDRESS $PROGRAM_VKEY
```

## Next Steps

Now that you understand on-chain verification, you can:

- **[Custom Circuits](./custom-circuits.md)**: Build custom verification logic
- **[Proving](./proving.md)**: Set up proof generation workflows
- **[Introduction](./introduction.md)**: Learn more about ZKPDF architecture
