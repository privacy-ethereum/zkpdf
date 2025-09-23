// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {PdfVerifier} from "../src/PdfVerifier.sol";
import {SP1VerifierGateway} from "@sp1-contracts/SP1VerifierGateway.sol";

struct SP1ProofFixtureJson {
    bool substringMatches;
    bytes proof;
    bytes publicValues;
    bytes32 vkey;
}

contract PdfVerifierGroth16Test is Test {
    using stdJson for string;

    address verifier;
    PdfVerifier public pdfVerifier;

    function loadFixture() public view returns (SP1ProofFixtureJson memory) {
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/src/fixtures/groth16-fixture.json");
        string memory json = vm.readFile(path);
        bytes memory jsonBytes = json.parseRaw(".");
        return abi.decode(jsonBytes, (SP1ProofFixtureJson));
    }

    function setUp() public {
        SP1ProofFixtureJson memory fixture = loadFixture();

        verifier = address(new SP1VerifierGateway(address(1)));
        pdfVerifier = new PdfVerifier(verifier, fixture.vkey);
    }

    function test_ValidPdfProof() public {
        SP1ProofFixtureJson memory fixture = loadFixture();

        vm.mockCall(verifier, abi.encodeWithSelector(SP1VerifierGateway.verifyProof.selector), abi.encode(true));

        PublicValuesStruct memory expected = abi.decode(fixture.publicValues, (PublicValuesStruct));
        PublicValuesStruct memory publicValues = pdfVerifier.verifyPdfProof(fixture.publicValues, fixture.proof);
        assertTrue(publicValues.substringMatches == fixture.substringMatches);
        assertEq(publicValues.messageDigestHash, expected.messageDigestHash);
        assertEq(publicValues.signerKeyHash, expected.signerKeyHash);
        assertEq(publicValues.substringHash, expected.substringHash);
        assertEq(publicValues.nullifier, expected.nullifier);
    }

    function testRevert_InvalidPdfProof() public {
        vm.expectRevert();

        SP1ProofFixtureJson memory fixture = loadFixture();

        bytes memory fakeProof = new bytes(fixture.proof.length);

        pdfVerifier.verifyPdfProof(fixture.publicValues, fakeProof);
    }
}

contract PdfVerifierPlonkTest is Test {
    using stdJson for string;

    address verifier;
    PdfVerifier public pdfVerifier;

    function loadFixture() public view returns (SP1ProofFixtureJson memory) {
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/src/fixtures/plonk-fixture.json");
        string memory json = vm.readFile(path);
        bytes memory jsonBytes = json.parseRaw(".");
        return abi.decode(jsonBytes, (SP1ProofFixtureJson));
    }

    function setUp() public {
        SP1ProofFixtureJson memory fixture = loadFixture();

        verifier = address(new SP1VerifierGateway(address(1)));
        pdfVerifier = new PdfVerifier(verifier, fixture.vkey);
    }

    function test_ValidPdfProof() public {
        SP1ProofFixtureJson memory fixture = loadFixture();

        vm.mockCall(verifier, abi.encodeWithSelector(SP1VerifierGateway.verifyProof.selector), abi.encode(true));

        PublicValuesStruct memory expected = abi.decode(fixture.publicValues, (PublicValuesStruct));
        PublicValuesStruct memory publicValues = pdfVerifier.verifyPdfProof(fixture.publicValues, fixture.proof);
        assertTrue(publicValues.substringMatches == fixture.substringMatches);
        assertEq(publicValues.messageDigestHash, expected.messageDigestHash);
        assertEq(publicValues.signerKeyHash, expected.signerKeyHash);
        assertEq(publicValues.substringHash, expected.substringHash);
        assertEq(publicValues.nullifier, expected.nullifier);
    }

    function testRevert_InvalidPdfProof() public {
        vm.expectRevert();

        SP1ProofFixtureJson memory fixture = loadFixture();

        bytes memory fakeProof = new bytes(fixture.proof.length);

        pdfVerifier.verifyPdfProof(fixture.publicValues, fakeProof);
    }
}
