"use client";
import React, {
  useState,
  ChangeEvent,
  useEffect,
  useMemo,
  useCallback,
} from "react";
import * as asn1js from "asn1js";
import { setEngine, CryptoEngine } from "pkijs";
import { ContentInfo, SignedData, Certificate } from "pkijs";
import { loadWasm } from "./lib/wasm";

function initPKIjs() {
  if ((window as any).__PKIJS_ENGINE_INITIALIZED__) return;
  const crypto = window.crypto;
  setEngine(
    "browser_crypto",
    crypto as any,
    new CryptoEngine({
      name: "browser_crypto",
      crypto: crypto as any,
      subtle: (crypto as any).subtle,
    })
  );
  (window as any).__PKIJS_ENGINE_INITIALIZED__ = true;
}

function publicKeyInfoToPEM(spkiBuffer: ArrayBuffer): string {
  const b64 = window.btoa(
    String.fromCharCode.apply(null, Array.from(new Uint8Array(spkiBuffer)))
  );
  const lines = b64.match(/.{1,64}/g) || [];
  return [
    "-----BEGIN PUBLIC KEY-----",
    ...lines,
    "-----END PUBLIC KEY-----",
  ].join("\n");
}

const Home: React.FC = () => {
  const [status, setStatus] = useState(
    "Drop a PDF file here or click to select"
  );
  const [publicKeyPEM, setPublicKeyPEM] = useState<string | null>(null);
  const [signatureValid, setSignatureValid] = useState<boolean | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [pdfBytes, setPdfBytes] = useState<Uint8Array | null>(null);
  const [pages, setPages] = useState<string[]>([]);
  const [selectedPage, setSelectedPage] = useState<number>(0);
  const [selectedText, setSelectedText] = useState<string>("");
  const [selectionStart, setSelectionStart] = useState<number>(0);
  const [verificationResult, setVerificationResult] = useState<any>(null);
  const [proofData, setProofData] = useState<string | null>(null);
  const [proofError, setProofError] = useState<string | null>(null);
  const [proofLoading, setProofLoading] = useState<boolean>(false);
  const [showDecoded, setShowDecoded] = useState(false);
  const [proofVerified, setProofVerified] = useState<boolean | null>(null);
  const [verificationMode, setVerificationMode] = useState<
    "signature" | "text" | "extract" | "substring"
  >("extract");
  const [showSearchOptions, setShowSearchOptions] = useState(false);
  const [substringCheck, setSubstringCheck] = useState({
    text: "",
    page: 0,
  });
  const [wasmResults, setWasmResults] = useState<any>(null);
  const [isDragOver, setIsDragOver] = useState(false);
  const [calculatedOffset, setCalculatedOffset] = useState<number | null>(null);
  const [uploadedFileName, setUploadedFileName] = useState<string | null>(null);

  useEffect(() => {
    initPKIjs();
  }, []);

  const encoder = useMemo(() => new TextEncoder(), []);

  const resetState = useCallback(() => {
    setError(null);
    setSignatureValid(null);
    setPublicKeyPEM(null);
    setPdfBytes(null);
    setPages([]);
    setSelectedPage(0);
    setSelectedText("");
    setSelectionStart(0);
    setVerificationResult(null);
    setProofData(null);
    setProofError(null);
    setProofLoading(false);
    setShowDecoded(false);
    setProofVerified(null);
    setWasmResults(null);
    setShowSearchOptions(false);
    setSubstringCheck({ text: "", page: 0 });
    setCalculatedOffset(null);
    setUploadedFileName(null);
  }, []);

  const processFile = useCallback(
    async (file: File) => {
      setStatus("Processing PDF file...");
      resetState();
      setUploadedFileName(file.name);

      try {
        const buffer = await file.arrayBuffer();
        const uint8 = new Uint8Array(buffer);
        setPdfBytes(uint8);

        // Load WASM and run verification based on mode
        const wasm = await loadWasm();
        let result;

        switch (verificationMode) {
          case "extract":
            setStatus("Extracting text and verifying signature...");
            result = wasm.wasm_verify_and_extract(uint8);
            break;
          case "substring":
            // For substring mode, just extract text first
            setStatus("Extracting text for substring verification...");
            const pages = wasm.wasm_extract_text(uint8);
            setPages(pages);
            setStatus(
              "Text extracted. Use the verify button below to check substring."
            );
            return;
          default:
            setStatus("Extracting text and verifying signature...");
            result = wasm.wasm_verify_and_extract(uint8);
        }

        setWasmResults(result);

        // Parse the result
        if (result && typeof result === "object") {
          const resultObj = result as any;

          if (resultObj.success) {
            // Set verification result for substring mode
            if ((verificationMode as string) === "substring") {
              setVerificationResult(resultObj);
            }

            // Always extract text if available
            if (resultObj.pages) {
              setPages(resultObj.pages);
            }

            // Check signature validity
            const isValid = resultObj.signature?.is_valid || resultObj.is_valid;
            setSignatureValid(isValid);

            if ((verificationMode as string) === "substring") {
              // For substring mode, show different status
              const textFound = resultObj.substring_matches;
              setStatus(
                textFound
                  ? "✅ Substring found and verified"
                  : "❌ Substring not found at specified offset"
              );
            } else if (isValid) {
              // Signature is valid - show public key
              if (resultObj.signature?.public_key) {
                try {
                  const binaryString = atob(resultObj.signature.public_key);
                  const bytes = new Uint8Array(binaryString.length);
                  for (let i = 0; i < binaryString.length; i++) {
                    bytes[i] = binaryString.charCodeAt(i);
                  }
                  setPublicKeyPEM(publicKeyInfoToPEM(bytes.buffer));
                } catch (e) {
                  console.warn("Could not convert public key to PEM:", e);
                }
              }
              setStatus("✅ PDF processed successfully - Signature is valid");
            } else {
              // Signature is invalid - show search options
              setShowSearchOptions(true);
              setStatus(
                "⚠️ PDF processed - Signature is invalid. Use search options below."
              );
            }
          } else {
            // WASM function failed
            setError(resultObj.error || "PDF processing failed");
            setStatus("❌ PDF processing failed");
          }
        }
      } catch (err: any) {
        setError(err.message);
        setStatus("Error processing file");
      }
    },
    [verificationMode, resetState]
  );

  const onFileChange = async (e: ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      await processFile(file);
    }
  };

  const onDrop = useCallback(
    async (e: React.DragEvent) => {
      e.preventDefault();
      setIsDragOver(false);

      const file = e.dataTransfer.files[0];
      if (file && file.type === "application/pdf") {
        await processFile(file);
      } else {
        setError("Please drop a PDF file");
        setStatus("Invalid file type");
      }
    },
    [processFile]
  );

  const onDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragOver(true);
  }, []);

  const onDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragOver(false);
  }, []);

  const onTextSelect = (e: any) => {
    const t = e.target as HTMLTextAreaElement;
    const value = t.value;
    const start = t.selectionStart;
    const end = t.selectionEnd;
    setSelectedText(value.substring(start, end));
    setSelectionStart(encoder.encode(value.slice(0, start)).length);
  };

  const onVerifySelection = async () => {
    if (!pdfBytes || !selectedText) {
      setError("Please enter text to verify");
      return;
    }
    const wasm = await loadWasm();
    if (!wasm) return setError("WASM not loaded.");

    try {
      setStatus("Verifying text and signature...");
      const res = wasm.wasm_verify_text(
        pdfBytes,
        selectedPage,
        selectedText,
        selectionStart
      );
      setVerificationResult(res);

      if (res && typeof res === "object") {
        const resObj = res as any;
        if (resObj.success) {
          setSignatureValid(resObj.signature?.is_valid);
          setStatus("✅ Text verification completed successfully");

          // If signature is valid, show public key
          if (resObj.signature?.is_valid && resObj.signature?.public_key) {
            try {
              const binaryString = atob(resObj.signature.public_key);
              const bytes = new Uint8Array(binaryString.length);
              for (let i = 0; i < binaryString.length; i++) {
                bytes[i] = binaryString.charCodeAt(i);
              }
              setPublicKeyPEM(publicKeyInfoToPEM(bytes.buffer));
            } catch (e) {
              console.warn("Could not convert public key to PEM:", e);
            }
          }
        } else {
          setError(resObj.error || "Text verification failed");
          setStatus("❌ Text verification failed");
        }
      }
    } catch (err: any) {
      setError(`Verification error: ${err.message}`);
      setStatus("❌ Verification error");
    }
  };

  const onVerifySubstring = async () => {
    if (!pdfBytes || !substringCheck.text) {
      setError("Please enter text to verify");
      return;
    }

    const wasm = await loadWasm();
    if (!wasm) return setError("WASM not loaded.");

    try {
      setStatus("Verifying substring with signature...");

      // Calculate offset using the same logic as core test
      // Use the pages from verify_and_extract (same text that verify_text will use)
      const pageText = pages[substringCheck.page];
      if (!pageText) {
        setError(`Page ${substringCheck.page} not found`);
        return;
      }

      // Use the same find logic as the core test: pageText.find(substring)
      const calculatedOffset = pageText.indexOf(substringCheck.text);
      if (calculatedOffset === -1) {
        setError(
          `Text "${substringCheck.text}" not found on page ${substringCheck.page}`
        );
        return;
      }

      // Store the calculated offset for display
      setCalculatedOffset(calculatedOffset);
      console.log(
        `Found "${substringCheck.text}" at offset ${calculatedOffset} on page ${substringCheck.page}`
      );
      console.log(
        `Page text length: ${pageText.length}, substring length: ${substringCheck.text.length}`
      );

      console.log(`Calling wasm_verify_text with:`);
      console.log(`- page: ${substringCheck.page}`);
      console.log(`- text: "${substringCheck.text}"`);
      console.log(`- offset: ${calculatedOffset}`);

      const res = wasm.wasm_verify_text(
        pdfBytes,
        substringCheck.page,
        substringCheck.text,
        calculatedOffset
      );
      setVerificationResult(res);

      if (res && typeof res === "object") {
        const resObj = res as any;
        if (resObj.success) {
          setSignatureValid(resObj.signature?.is_valid);

          if (resObj.substring_matches) {
            setStatus("✅ Substring found and verified successfully");
          } else {
            setStatus("❌ Substring not found at calculated offset");
          }

          // If signature is valid, show public key
          if (resObj.signature?.is_valid && resObj.signature?.public_key) {
            try {
              const binaryString = atob(resObj.signature.public_key);
              const bytes = new Uint8Array(binaryString.length);
              for (let i = 0; i < binaryString.length; i++) {
                bytes[i] = binaryString.charCodeAt(i);
              }
              setPublicKeyPEM(publicKeyInfoToPEM(bytes.buffer));
            } catch (e) {
              console.warn("Could not convert public key to PEM:", e);
            }
          }
        } else {
          setError(resObj.error || "Substring verification failed");
          setStatus("❌ Substring verification failed");
        }
      }
    } catch (err: any) {
      setError(`Verification error: ${err.message}`);
      setStatus("❌ Verification error");
    }
  };

  const onGenerateProof = async () => {
    setStatus("Generating proof...");
    setProofLoading(true);
    setProofError(null);
    setProofData(null);
    try {
      const res = await fetch("http://localhost:3001/prove", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          pdf_bytes: Array.from(pdfBytes!),
          page_number: selectedPage,
          offset: selectionStart,
          sub_string: selectedText,
        }),
      });
      if (!res.ok) throw new Error(`Status ${res.status}`);
      const data = await res.json();
      setProofData(JSON.stringify(data, null, 2));
    } catch (e: any) {
      // Check if it's a connection error (API not running)
      if (
        e.message.includes("fetch") ||
        e.message.includes("Failed to fetch") ||
        e.message.includes("ECONNREFUSED")
      ) {
        setProofError(`Prover API is not setup. Please check how to setup local prover API to run this feature.

Setup Instructions:
1. Navigate to circuits/script directory
2. Set environment variables (if using Succinct Prover Network):
   export SP1_PROVER=network
   export NETWORK_PRIVATE_KEY=your_private_key
3. Run the prover server:
   cargo run --release --bin prover

The server will start on port 3001. You can also run without environment variables for local proving (slower but works).

For more details, see: circuits/README.md`);
      } else {
        setProofError(e.message);
      }
    } finally {
      setProofLoading(false);
      setStatus("Ready.");
    }
  };

  const decoded = useMemo(() => {
    if (!proofData) return null;
    try {
      return JSON.parse(proofData).public_values.buffer.data.map((v: number) =>
        Boolean(v)
      );
    } catch {
      return null;
    }
  }, [proofData]);

  const onVerifyProof = () => {
    if (decoded) setProofVerified(decoded[decoded.length - 1]);
  };

  return (
    <div className="min-h-screen flex flex-col bg-gray-900 text-white p-6">
      <header className="mb-6 text-center">
        <h1 className="text-4xl font-bold text-indigo-400 mb-2">
          zkPDF Compatibility Check
        </h1>
        <p className="text-gray-400">
          Drop a PDF file to verify signature and check zkPDF compatibility
        </p>
      </header>

      <div className="flex-1 grid grid-cols-1 lg:grid-cols-2 gap-6 overflow-hidden">
        <div className="bg-gray-800 p-6 rounded-lg shadow-lg flex flex-col space-y-6">
          {/* Verification Mode Selection */}
          <div className="space-y-3">
            <h3 className="font-medium text-white">Verification Mode:</h3>
            <div className="grid grid-cols-2 gap-3">
              <label className="flex items-center p-3 bg-gray-700 rounded cursor-pointer hover:bg-gray-600">
                <input
                  type="radio"
                  value="extract"
                  checked={verificationMode === "extract"}
                  onChange={(e) => setVerificationMode(e.target.value as any)}
                  className="mr-3"
                />
                <div>
                  <div className="font-medium text-sm">Extract + Verify</div>
                  <div className="text-xs text-gray-400">Default flow</div>
                </div>
              </label>
              <label className="flex items-center p-3 bg-gray-700 rounded cursor-pointer hover:bg-gray-600">
                <input
                  type="radio"
                  value="substring"
                  checked={verificationMode === "substring"}
                  onChange={(e) => setVerificationMode(e.target.value as any)}
                  className="mr-3"
                />
                <div>
                  <div className="font-medium text-sm">Check Substring</div>
                  <div className="text-xs text-gray-400">With offset</div>
                </div>
              </label>
            </div>
          </div>

          {/* Substring Check Options */}
          {verificationMode === "substring" && (
            <div className="space-y-3 bg-gray-700 p-4 rounded">
              <h4 className="font-medium text-white">
                Substring Check Parameters:
              </h4>
              <div className="bg-blue-900/20 border border-blue-500 rounded p-3 mb-3">
                <div className="text-blue-400 font-medium text-sm mb-1">
                  How to use:
                </div>
                <div className="text-blue-300 text-xs space-y-1">
                  <div>1. Upload PDF to extract text first</div>
                  <div>2. Enter the exact text you want to find</div>
                  <div>3. Specify which page (0-based index)</div>
                  <div>4. Click "Verify Substring" to check</div>
                  <div className="text-yellow-300 font-medium">
                    Note: Offset is calculated automatically!
                  </div>
                </div>
              </div>
              <div className="grid grid-cols-1 gap-3">
                <div>
                  <label className="block text-sm text-gray-300 mb-1">
                    Text to Check:
                  </label>
                  <input
                    type="text"
                    value={substringCheck.text}
                    onChange={(e) =>
                      setSubstringCheck((prev) => ({
                        ...prev,
                        text: e.target.value,
                      }))
                    }
                    placeholder="Enter exact text to search for (e.g., 'GST', 'Certificate')"
                    className="w-full bg-gray-800 text-white border-gray-600 rounded p-2 text-sm"
                  />
                </div>
                <div>
                  <label className="block text-sm text-gray-300 mb-1">
                    Page Number:
                  </label>
                  <input
                    type="number"
                    value={substringCheck.page}
                    onChange={(e) =>
                      setSubstringCheck((prev) => ({
                        ...prev,
                        page: parseInt(e.target.value) || 0,
                      }))
                    }
                    min="0"
                    placeholder="0"
                    className="w-full bg-gray-800 text-white border-gray-600 rounded p-2 text-sm"
                  />
                </div>
                <button
                  onClick={onVerifySubstring}
                  disabled={!substringCheck.text || !pdfBytes}
                  className="bg-blue-600 hover:bg-blue-700 disabled:bg-gray-600 disabled:cursor-not-allowed text-white font-medium py-2 px-4 rounded transition-colors"
                >
                  {!pdfBytes ? "Upload PDF First" : "Verify Substring"}
                </button>
              </div>
            </div>
          )}

          {/* Drag and Drop Area */}
          <div
            className={`border-2 border-dashed rounded-lg p-8 text-center transition-colors ${
              isDragOver
                ? "border-indigo-400 bg-indigo-900/20"
                : "border-gray-600 hover:border-gray-500"
            }`}
            onDrop={onDrop}
            onDragOver={onDragOver}
            onDragLeave={onDragLeave}
          >
            <input
              type="file"
              accept=".pdf"
              onChange={onFileChange}
              className="hidden"
              id="pdf-input"
            />
            <label htmlFor="pdf-input" className="cursor-pointer">
              <div className="text-4xl mb-4">📄</div>
              <div className="text-lg font-medium mb-2">{status}</div>
              <div className="text-sm text-gray-400">
                Click to select or drag and drop a PDF file
              </div>
            </label>
          </div>

          {/* Status and Results */}
          <div className="space-y-3">
            {/* Filename Display */}
            {uploadedFileName && (
              <div className="bg-blue-900/20 border border-blue-500 rounded p-3">
                <div className="text-blue-400 font-medium">File:</div>
                <div className="text-blue-300 text-sm">{uploadedFileName}</div>
              </div>
            )}

            {/* Show either error OR compatibility check, not both */}
            {error ? (
              <div className="bg-red-900/20 border border-red-500 rounded p-3">
                <div className="text-red-400 font-medium">Error:</div>
                <div className="text-red-300 text-sm">{error}</div>
              </div>
            ) : signatureValid !== null ? (
              <div
                className={`border rounded p-3 ${
                  signatureValid
                    ? "bg-green-900/20 border-green-500"
                    : "bg-red-900/20 border-red-500"
                }`}
              >
                {verificationMode === "substring" ? (
                  <>
                    <div
                      className={`font-medium ${
                        verificationResult?.substring_matches
                          ? "text-green-400"
                          : "text-red-400"
                      }`}
                    >
                      Substring Check:{" "}
                      {verificationResult?.substring_matches
                        ? "✅ Found"
                        : "❌ Not Found"}
                    </div>
                    <div className="text-sm text-gray-300">
                      Text: "{substringCheck.text}" found at offset{" "}
                      {calculatedOffset}
                    </div>
                    {calculatedOffset !== null && (
                      <div className="text-xs text-gray-400">
                        Page {substringCheck.page} text length:{" "}
                        {pages[substringCheck.page]?.length || 0} characters
                      </div>
                    )}
                    <div className="text-sm text-gray-300">
                      Signature Valid: {signatureValid ? "Yes" : "No"}
                    </div>
                  </>
                ) : (
                  <>
                    <div
                      className={`font-medium ${
                        signatureValid ? "text-green-400" : "text-red-400"
                      }`}
                    >
                      zkPDF Compatibility:{" "}
                      {signatureValid ? "✅ Compatible" : "❌ Not Compatible"}
                    </div>
                    <div className="text-sm text-gray-300">
                      Signature Valid: {signatureValid ? "Yes" : "No"}
                    </div>
                  </>
                )}
              </div>
            ) : null}
          </div>

          {/* Public Key Display */}
          {publicKeyPEM && (
            <div className="flex-1 bg-gray-700 p-4 rounded overflow-auto">
              <div className="font-medium text-indigo-300 mb-2">
                Signer's Public Key:
              </div>
              <pre className="bg-gray-600 p-2 rounded text-xs whitespace-pre-wrap">
                {publicKeyPEM}
              </pre>
            </div>
          )}
        </div>

        <div className="bg-gray-800 p-6 rounded-lg shadow-lg flex flex-col space-y-6">
          {pages.length > 0 ? (
            <>
              <div className="flex items-center justify-between">
                <h3 className="font-medium text-white">Extracted Text</h3>
                <div className="flex items-center space-x-3">
                  <label className="text-sm text-gray-300">Page:</label>
                  <select
                    value={selectedPage}
                    onChange={(e) => setSelectedPage(+e.target.value)}
                    className="bg-gray-700 text-white border-gray-600 rounded p-1 text-sm"
                  >
                    {pages.map((_, i) => (
                      <option key={i} value={i}>
                        {i + 1}
                      </option>
                    ))}
                  </select>
                </div>
              </div>

              <div className="border border-gray-600 rounded h-48 overflow-auto bg-gray-900 p-3">
                <textarea
                  readOnly
                  value={pages[selectedPage]}
                  onMouseUp={onTextSelect}
                  onSelect={onTextSelect}
                  className="w-full h-full font-mono text-sm bg-transparent text-white focus:outline-none resize-none"
                  placeholder="Text will appear here when extracted..."
                />
              </div>

              {showSearchOptions && (
                <>
                  <div className="space-y-3">
                    <div className="bg-yellow-900/20 border border-yellow-500 rounded p-3">
                      <div className="font-medium text-yellow-400 mb-2">
                        ⚠️ Signature Invalid - Search Options Available
                      </div>
                      <div className="text-sm text-yellow-300">
                        You can search for specific text with offset
                        verification
                      </div>
                    </div>

                    <label className="font-medium text-white">
                      Search for Substring with Offset
                    </label>
                    <div className="grid grid-cols-2 gap-3">
                      <input
                        type="text"
                        value={selectedText}
                        onChange={(e) => setSelectedText(e.target.value)}
                        placeholder="Text to search for"
                        className="bg-gray-700 text-white border-gray-600 rounded p-2 text-sm"
                      />
                      <input
                        type="number"
                        value={selectionStart}
                        onChange={(e) => setSelectionStart(+e.target.value)}
                        placeholder="Position (offset)"
                        className="bg-gray-700 text-white border-gray-600 rounded p-2 text-sm"
                      />
                    </div>
                    <button
                      onClick={onVerifySelection}
                      disabled={!selectedText}
                      className="w-full bg-blue-600 text-white py-2 rounded hover:bg-blue-700 transition disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                      Search & Verify Text
                    </button>
                  </div>

                  {verificationResult && (
                    <div
                      className={`border rounded p-3 ${
                        verificationResult.success
                          ? "bg-green-900/20 border-green-500"
                          : "bg-red-900/20 border-red-500"
                      }`}
                    >
                      <div
                        className={`font-medium ${
                          verificationResult.success
                            ? "text-green-400"
                            : "text-red-400"
                        }`}
                      >
                        Text Search Result:{" "}
                        {verificationResult.success
                          ? "✅ Found & Verified"
                          : "❌ Not Found"}
                      </div>
                      {verificationResult.error && (
                        <div className="text-red-300 text-sm mt-1">
                          {verificationResult.error}
                        </div>
                      )}
                      {verificationResult.success &&
                        verificationResult.substring_matches && (
                          <div className="text-green-300 text-sm mt-1">
                            Text found at specified position
                          </div>
                        )}
                    </div>
                  )}
                </>
              )}

              <div className="space-y-3">
                <label className="font-medium text-white">
                  Zero-Knowledge Proof Generation
                </label>
                <div className="text-sm text-gray-400">
                  Generate a zk-SNARK proof for the PDF verification
                </div>
                <button
                  onClick={onGenerateProof}
                  disabled={proofLoading || !pdfBytes}
                  className="flex items-center justify-center w-full bg-indigo-600 text-white py-2 rounded hover:bg-indigo-700 transition disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {proofLoading && (
                    <svg
                      className="animate-spin h-5 w-5 mr-3 text-white"
                      xmlns="http://www.w3.org/2000/svg"
                      fill="none"
                      viewBox="0 0 24 24"
                    >
                      <circle
                        className="opacity-25"
                        cx="12"
                        cy="12"
                        r="10"
                        stroke="currentColor"
                        strokeWidth="4"
                      ></circle>
                      <path
                        className="opacity-75"
                        fill="currentColor"
                        d="M4 12a8 8 0 018-8v4a4 4 0 00-4 4H4z"
                      ></path>
                    </svg>
                  )}
                  <span>
                    {proofLoading
                      ? "Generating Proof..."
                      : "Generate zk-SNARK Proof"}
                  </span>
                </button>
              </div>

              {proofError && (
                <div className="bg-red-900/20 border border-red-500 rounded p-3">
                  <div className="text-red-400 font-medium">Proof Error:</div>
                  <div className="text-red-300 text-sm whitespace-pre-line">
                    {proofError}
                  </div>
                </div>
              )}

              {proofData && (
                <div className="flex-1 flex flex-col space-y-4">
                  <div className="flex items-center justify-between">
                    <label className="font-medium text-white">
                      Generated Proof
                    </label>
                    <div className="flex items-center space-x-2">
                      <input
                        type="checkbox"
                        checked={showDecoded}
                        onChange={(e) => setShowDecoded(e.target.checked)}
                        className="h-4 w-4"
                      />
                      <label className="text-sm text-gray-300">
                        Show decoded
                      </label>
                      <button
                        onClick={onVerifyProof}
                        className="bg-green-600 text-white px-3 py-1 rounded hover:bg-green-700 transition text-sm"
                      >
                        Verify Proof
                      </button>
                    </div>
                  </div>
                  <pre className="h-32 overflow-auto bg-gray-900 p-3 rounded text-xs text-white">
                    {proofData}
                  </pre>
                  {showDecoded && decoded && (
                    <pre className="h-24 overflow-auto bg-gray-900 p-3 rounded text-xs text-white">
                      {JSON.stringify(decoded, null, 2)}
                    </pre>
                  )}
                  {proofVerified !== null && (
                    <div
                      className={`font-semibold text-center py-2 rounded ${
                        proofVerified
                          ? "bg-green-900/20 text-green-400 border border-green-500"
                          : "bg-red-900/20 text-red-400 border border-red-500"
                      }`}
                    >
                      {proofVerified ? "✅ Proof Valid" : "❌ Proof Invalid"}
                    </div>
                  )}
                </div>
              )}
            </>
          ) : (
            <div className="flex-1 flex items-center justify-center text-gray-500">
              <div className="text-center">
                <div className="text-4xl mb-4">📝</div>
                <div className="text-lg font-medium mb-2">
                  No Text Extracted
                </div>
                <div className="text-sm">
                  Upload a PDF file to see extracted text content
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default Home;
