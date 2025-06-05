"use client";
import React, { useState, ChangeEvent, useEffect } from "react";
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

    if (!e.target.files || e.target.files.length === 0) {
      setError("No file chosen.");
      return;
    }

    try {
      const file = e.target.files[0];
      const arrayBuffer = await file.arrayBuffer();
      const uint8 = new Uint8Array(arrayBuffer);
      setPdfBytes(uint8);

      setStatus("Scanning for ByteRange and Contents…");

      const pdfText = new TextDecoder("latin1").decode(uint8);
      const byteRangeMatch =
        /\/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]/.exec(pdfText);
      if (!byteRangeMatch)
        throw new Error("Could not locate /ByteRange in PDF.");

      const [start1, len1, start2, len2] = byteRangeMatch
        .slice(1, 5)
        .map(Number);

      const contentsMatch = /\/Contents\s*<([0-9A-Fa-f\s]+)>/.exec(pdfText);
      if (!contentsMatch) throw new Error("Could not locate /Contents in PDF.");

      const signatureHex = contentsMatch[1].replace(/\s+/g, "");
      if (!signatureHex) throw new Error("Empty /Contents field.");

      setStatus("Reassembling signed data…");
      const signedData = new Uint8Array(len1 + len2);
      signedData.set(uint8.slice(start1, start1 + len1), 0);
      signedData.set(uint8.slice(start2, start2 + len2), len1);

      const signatureDer = new Uint8Array(
        signatureHex.match(/.{1,2}/g)!.map((b) => parseInt(b, 16))
      );

      setStatus("Parsing PKCS#7…");
      const asn1 = asn1js.fromBER(signatureDer.buffer);
      if (asn1.offset === -1)
        throw new Error("ASN.1 parse error on signature DER.");

      const contentInfo = new ContentInfo({ schema: asn1.result });
      if (contentInfo.contentType !== "1.2.840.113549.1.7.2") {
        throw new Error("Not a SignedData ContentInfo (OID mismatch).");
      }

      const signedDataPKI = new SignedData({ schema: contentInfo.content });
      const verified = await signedDataPKI.verify({
        signer: 0,
        trustedCerts: [],
        data: signedData.buffer,
      });

      setSignatureValid(!!verified);

      if (!signedDataPKI.certificates?.length) {
        throw new Error("No certificates embedded in this SignedData.");
      }

      const cert = signedDataPKI.certificates[0] as Certificate;
      const spkiBuf = cert.subjectPublicKeyInfo.toSchema().toBER(false);
      setPublicKeyPEM(publicKeyInfoToPEM(spkiBuf));

      setStatus("Signature OK. Extracting PDF text…");
      const wasm = await loadWasm();
      const extracted = wasm.wasm_extract_text(uint8);
      setPages(extracted);
      setSelectedPage(0);

      setStatus("Done.");
    } catch (err: any) {
      console.error(err);
      setError(err.message || String(err));
      setStatus("Error.");
    }
  };

  const onTextSelect = (e: React.SyntheticEvent<HTMLTextAreaElement>) => {
    const target = e.target as HTMLTextAreaElement;
    setSelectedText(
      target.value.substring(target.selectionStart, target.selectionEnd)
    );
    setSelectionStart(target.selectionStart);
  };

  const onVerifySelection = async () => {
    if (!pdfBytes) return;
    const wasm = await loadWasm();
    const ok = wasm.wasm_verify_text(pdfBytes, selectedPage, selectedText);
    setVerificationResult(ok);
  };

  return (
    <div className="max-w-2xl mx-auto mt-8 bg-white border border-gray-300 rounded-lg shadow p-6">
      <h2 className="text-2xl text-center text-blue-600 mb-4">
        🖨️ PDF Signature Verifier
      </h2>
      <p className="text-center text-gray-600 mb-6">
        Upload a signed PDF. We’ll check its PKCS#7 signature and let you verify
        selected text.
      </p>

      <input
        type="file"
        accept=".pdf"
        onChange={onFileChange}
        className="mb-4 file:mr-4 file:py-2 file:px-4 file:rounded file:border-0 file:bg-blue-600 file:text-white hover:file:bg-blue-700"
      />

      <div className="mt-4 font-bold text-green-600">
        <strong>Status:</strong> {status}
      </div>

      {error && (
        <div className="mt-4 text-red-600 font-bold">
          <strong>Error:</strong> {error}
        </div>
      )}

      {signatureValid !== null && (
        <div className="mt-4 font-bold">
          <strong>Signature valid:</strong>{" "}
          {signatureValid ? (
            <span className="text-green-600">Yes ✅</span>
          ) : (
            <span className="text-red-600">No ❌</span>
          )}
        </div>
      )}

      {publicKeyPEM && (
        <div className="mt-8 p-6 border border-gray-300 rounded-lg bg-white shadow">
          <div>
            <strong>Signer’s Public Key (PEM):</strong>
            <pre className="bg-gray-100 p-4 border border-gray-300 rounded overflow-x-auto whitespace-pre-wrap text-sm text-gray-800">
              {publicKeyPEM}
            </pre>
          </div>
        </div>
      )}

      {pages.length > 0 && (
        <div className="mt-8 p-6 border border-gray-300 rounded-lg bg-white shadow">
          <strong>Select or enter text to verify:</strong>

          <div className="mb-4 flex items-center">
            <label htmlFor="page-select" className="font-semibold mr-2">
              Page:
            </label>
            <select
              id="page-select"
              value={selectedPage}
              onChange={(e) => setSelectedPage(parseInt(e.target.value, 10))}
              className="border border-gray-300 rounded p-3"
            >
              {pages.map((_, i) => (
                <option key={i} value={i}>
                  {i + 1}
                </option>
              ))}
            </select>
          </div>

          <textarea
            value={pages[selectedPage]}
            readOnly
            onMouseUp={onTextSelect}
            rows={8}
            className="font-mono border border-gray-300 rounded p-3 mb-4 w-full resize-y"
          ></textarea>

          <div className="mt-6 flex gap-4 items-start">
            <div className="flex-1">
              <label>Substring to verify:</label>
              <input
                type="text"
                value={selectedText}
                onChange={(e) => setSelectedText(e.target.value)}
                placeholder="Either click in the textarea or type here"
                className="w-full border border-gray-300 rounded p-3"
              />
            </div>
            <div className="flex-1">
              <label>Offset:</label>
              <input
                type="number"
                value={selectionStart}
                onChange={(e) =>
                  setSelectionStart(parseInt(e.target.value, 10))
                }
                min={0}
                className="w-full border border-gray-300 rounded p-3"
              />
            </div>
          </div>

          <div className="mt-4">
            <button
              onClick={onVerifySelection}
              className="bg-green-600 text-white px-6 py-3 rounded hover:bg-green-700 transition-colors"
            >
              Verify Selected Text
            </button>
            {verificationResult !== null && (
              <span
                className={
                  "ml-4 font-bold " +
                  (verificationResult ? "text-green-600" : "text-red-600")
                }
              >
                {verificationResult ? "✅ Verified" : "❌ Not Verified"}
              </span>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

export default Home;
