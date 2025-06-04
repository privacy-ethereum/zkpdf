import React, { useState, type ChangeEvent } from "react";
import * as asn1js from "asn1js";
import { setEngine, CryptoEngine } from "pkijs";
import { ContentInfo, SignedData, Certificate } from "pkijs";
import { loadWasm } from "./wasm.ts";

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

export default function App() {
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

  initPKIjs();

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
    console.log(selectedPage);
    const ok = wasm.wasm_verify_text(
      pdfBytes,
      selectedPage,
      selectedText,
      selectionStart
    );
    setVerificationResult(ok);
  };

  return (
    <div
      style={{ maxWidth: 700, margin: "2rem auto", fontFamily: "sans-serif" }}
    >
      <h2>🖨️ PDF Signature Verifier</h2>
      <p>
        Select a signed PDF. This tool will verify its PKCS#7 signature and
        allow you to select and verify text.
      </p>

      <input type="file" accept=".pdf" onChange={onFileChange} />
      <div style={{ marginTop: "1rem" }}>
        <strong>Status:</strong> {status}
      </div>

      {error && (
        <div style={{ marginTop: "1rem", color: "crimson" }}>
          <strong>Error:</strong> {error}
        </div>
      )}

      {signatureValid !== null && (
        <div style={{ marginTop: "1rem" }}>
          <strong>Signature valid:</strong>{" "}
          {signatureValid ? (
            <span style={{ color: "green" }}>Yes ✅</span>
          ) : (
            <span style={{ color: "red" }}>No ❌</span>
          )}
        </div>
      )}

      {publicKeyPEM && (
        <div
          style={{
            marginTop: "1rem",
            whiteSpace: "pre-wrap",
            fontSize: "0.9rem",
          }}
        >
          <strong>Signer’s Public Key (PEM):</strong>
          <pre
            style={{
              background: "#f5f5f5",
              border: "1px solid #ddd",
              padding: "0.5rem",
              borderRadius: 4,
              overflowX: "auto",
              color: "#333",
            }}
          >
            {publicKeyPEM}
          </pre>
        </div>
      )}

      {pages.length > 0 && (
        <div
          style={{
            marginTop: "2rem",
            padding: "1rem",
            border: "1px solid #ccc",
            borderRadius: 4,
          }}
        >
          <strong>Select or enter text to verify</strong>

          <div style={{ marginTop: "0.5rem" }}>
            <label htmlFor="page-select">Page:</label>
            <select
              id="page-select"
              value={selectedPage}
              onChange={(e) => setSelectedPage(parseInt(e.target.value, 10))}
              style={{ marginLeft: "0.5rem" }}
            >
              {pages.map((_, i) => (
                <option key={i} value={i}>
                  {i + 1}
                </option>
              ))}
            </select>
          </div>

          <textarea
            style={{
              marginTop: "0.5rem",
              width: "100%",
              height: "150px",
              fontFamily: "monospace",
            }}
            value={pages[selectedPage]}
            readOnly
            onMouseUp={onTextSelect}
          />

          <div style={{ marginTop: "0.5rem", display: "flex", gap: "1rem" }}>
            <div style={{ flex: 1 }}>
              <label>Substring to verify:</label>
              <input
                type="text"
                value={selectedText}
                onChange={(e) => setSelectedText(e.target.value)}
                placeholder="Enter text manually or select from above"
                style={{ width: "100%", padding: "0.25rem" }}
              />
            </div>
            <div>
              <label>Offset:</label>
              <input
                type="number"
                value={selectionStart}
                onChange={(e) =>
                  setSelectionStart(parseInt(e.target.value, 10))
                }
                style={{ width: "80px", padding: "0.25rem" }}
              />
            </div>
          </div>

          <div style={{ marginTop: "0.75rem" }}>
            <button onClick={onVerifySelection}>Verify Selected Text</button>
            {verificationResult !== null && (
              <span style={{ marginLeft: "0.5rem" }}>
                {verificationResult ? "✅ Verified" : "❌ Not Verified"}
              </span>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
