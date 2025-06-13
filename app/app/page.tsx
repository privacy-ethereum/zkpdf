"use client";
import React, { useState, ChangeEvent, useEffect, useMemo } from "react";
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
  const [status, setStatus] = useState("No file selected.");
  const [publicKeyPEM, setPublicKeyPEM] = useState<string | null>(null);
  const [signatureValid, setSignatureValid] = useState<boolean | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [pdfBytes, setPdfBytes] = useState<Uint8Array | null>(null);
  const [pages, setPages] = useState<string[]>([]);
  const [selectedPage, setSelectedPage] = useState<number>(0);
  const [selectedText, setSelectedText] = useState<string>("");
  const [selectionStart, setSelectionStart] = useState<number>(0);
  const [verificationResult, setVerificationResult] = useState<boolean | null>(
    null
  );
  const [proofData, setProofData] = useState<string | null>(null);
  const [proofError, setProofError] = useState<string | null>(null);
  const [proofLoading, setProofLoading] = useState<boolean>(false);
  const [showDecoded, setShowDecoded] = useState(false);
  const [proofVerified, setProofVerified] = useState<boolean | null>(null);

  useEffect(() => {
    initPKIjs();
  }, []);

  const onFileChange = async (e: ChangeEvent<HTMLInputElement>) => {
    setStatus("Reading file...");
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

    if (!e.target.files?.length) {
      setError("No file chosen.");
      setStatus("Error.");
      return;
    }
    try {
      const file = e.target.files[0];
      const buffer = await file.arrayBuffer();
      const uint8 = new Uint8Array(buffer);
      setPdfBytes(uint8);
      setStatus("Scanning ByteRange...");
      const text = new TextDecoder("latin1").decode(uint8);
      const br = /\/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]/.exec(
        text
      );
      if (!br) throw new Error("ByteRange not found.");
      const [s1, l1, s2, l2] = br.slice(1).map(Number);
      const ct = /\/Contents\s*<([0-9A-Fa-f\s]+)>/.exec(text);
      if (!ct) throw new Error("Contents not found.");
      setStatus("Reassembling signed data...");
      const signed = new Uint8Array(l1 + l2);
      signed.set(uint8.slice(s1, s1 + l1), 0);
      signed.set(uint8.slice(s2, s2 + l2), l1);
      const der = new Uint8Array(
        ct[1]
          .replace(/\s+/g, "")
          .match(/.{1,2}/g)!
          .map((b) => parseInt(b, 16))
      );
      setStatus("Parsing PKCS#7...");
      const asn1 = asn1js.fromBER(der.buffer);
      if (asn1.offset === -1) throw new Error("ASN.1 parse failed.");
      const ci = new ContentInfo({ schema: asn1.result });
      const sd = new SignedData({ schema: ci.content });
      const ok = await sd.verify({
        signer: 0,
        trustedCerts: [],
        data: signed.buffer,
      });
      setSignatureValid(ok);
      if (!sd.certificates?.length) throw new Error("No certificates.");
      const cert = sd.certificates[0] as Certificate;
      const spki = cert.subjectPublicKeyInfo.toSchema().toBER(false);
      setPublicKeyPEM(publicKeyInfoToPEM(spki));
      setStatus("Extracting text...");
      const wasm = await loadWasm();
      setPages(wasm.wasm_extract_text(uint8));
      setStatus("Ready.");
    } catch (err: any) {
      setError(err.message);
      setStatus("Error.");
    }
  };

  const onTextSelect = (e: any) => {
    const t = e.target as HTMLTextAreaElement;
    setSelectedText(t.value.substring(t.selectionStart, t.selectionEnd));
    setSelectionStart(t.selectionStart);
  };

  const onVerifySelection = async () => {
    if (!pdfBytes) return;
    const wasm = await loadWasm();
    if (!wasm) return setError("WASM not loaded.");
    const res = wasm.wasm_verify_text(pdfBytes, selectedPage, selectedText);
    setVerificationResult(res);
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
      setProofError(e.message);
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
        <h1 className="text-3xl font-bold text-indigo-400">zkPDF Demo</h1>
      </header>
      <div className="flex-1 grid grid-cols-1 lg:grid-cols-2 gap-6 overflow-hidden">
        <div className="bg-gray-800 p-6 rounded-lg shadow-lg flex flex-col space-y-6">
          <input
            type="file"
            accept=".pdf"
            onChange={onFileChange}
            className="file:px-4 file:py-2 file:rounded-md file:border-0 file:bg-indigo-600 file:text-white hover:file:bg-indigo-700 transition"
          />
          <div className="space-y-2">
            <div>
              <span className="font-medium">Status:</span> {status}
            </div>
            {error && <div className="text-red-500">Error: {error}</div>}
            {signatureValid !== null && (
              <div>
                <span className="font-medium">Signature valid:</span>{" "}
                <span
                  className={signatureValid ? "text-green-400" : "text-red-400"}
                >
                  {signatureValid ? "Yes ✅" : "No ❌"}
                </span>
              </div>
            )}
          </div>
          {publicKeyPEM && (
            <div className="flex-1 bg-gray-700 p-4 rounded overflow-auto">
              <div className="font-medium text-indigo-300 mb-2">
                Signer’s Public Key:
              </div>
              <pre className="bg-gray-600 p-2 rounded text-xs whitespace-pre-wrap">
                {publicKeyPEM}
              </pre>
            </div>
          )}
        </div>

        <div className="bg-gray-800 p-6 rounded-lg shadow-lg flex flex-col space-y-6">
          {pages.length > 0 && (
            <>
              <div className="flex items-center space-x-3">
                <label className="font-medium text-white">Page:</label>
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

              <div className="border border-gray-600 rounded h-40 overflow-auto bg-gray-900 p-2">
                <textarea
                  readOnly
                  value={pages[selectedPage]}
                  onMouseUp={onTextSelect}
                  className="w-full h-full font-mono text-sm bg-transparent text-white focus:outline-none"
                />
              </div>

              <button
                onClick={async () => {
                  await onVerifySelection();
                }}
                className="bg-green-600 text-white px-4 py-1 rounded hover:bg-green-700 transition"
              >
                Verify Text
              </button>
              {verificationResult !== null && (
                <div
                  className={
                    verificationResult ? "text-green-400" : "text-red-400"
                  }
                >
                  {verificationResult ? "✅ Verified" : "❌ Not Verified"}
                </div>
              )}

              <div className="grid grid-cols-2 gap-4">
                <input
                  type="text"
                  value={selectedText}
                  onChange={(e) => setSelectedText(e.target.value)}
                  placeholder="Substring to prove"
                  className="bg-gray-700 text-white border-gray-600 rounded p-2 text-sm"
                />
                <input
                  type="number"
                  value={selectionStart}
                  onChange={(e) => setSelectionStart(+e.target.value)}
                  className="bg-gray-700 text-white border-gray-600 rounded p-2 text-sm"
                />
              </div>

              <button
                onClick={onGenerateProof}
                disabled={proofLoading}
                className="flex items-center justify-center w-full bg-indigo-600 text-white py-2 rounded hover:bg-indigo-700 transition disabled:opacity-50"
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
                  {proofLoading ? "Generating Proof..." : "Generate Proof"}
                </span>
              </button>
              {proofError && (
                <div className="text-red-500">Proof Error: {proofError}</div>
              )}

              {proofData && (
                <div className="flex-1 flex flex-col space-y-4">
                  <pre className="h-32 overflow-auto bg-gray-900 p-2 rounded text-xs text-white">
                    {proofData}
                  </pre>
                  <div className="flex items-center space-x-2">
                    <input
                      type="checkbox"
                      checked={showDecoded}
                      onChange={(e) => setShowDecoded(e.target.checked)}
                      className="h-4 w-4 text-white"
                    />
                    <label className="text-sm text-white">
                      Show decoded signals
                    </label>
                    <button
                      onClick={onVerifyProof}
                      className="ml-auto bg-green-600 text-white px-3 py-1 rounded hover:bg-green-700 transition"
                    >
                      Verify Proof
                    </button>
                  </div>
                  {showDecoded && decoded && (
                    <pre className="h-24 overflow-auto bg-gray-900 p-2 rounded text-xs text-white">
                      {JSON.stringify(decoded, null, 2)}
                    </pre>
                  )}
                  {proofVerified != null && (
                    <div
                      className={
                        proofVerified
                          ? "text-green-400 font-semibold"
                          : "text-red-400 font-semibold"
                      }
                    >
                      {proofVerified ? "✅ Proof Valid" : "❌ Proof Invalid"}
                    </div>
                  )}
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
};

export default Home;
