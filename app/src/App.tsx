import React, { useState, type ChangeEvent } from "react";
import * as asn1js from "asn1js";
import { setEngine, CryptoEngine } from "pkijs";
import { ContentInfo, SignedData, Certificate } from "pkijs";

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
  const [status, setStatus] = useState<string>("No file selected.");
  const [publicKeyPEM, setPublicKeyPEM] = useState<string | null>(null);
  const [signatureValid, setSignatureValid] = useState<boolean | null>(null);
  const [error, setError] = useState<string | null>(null);

  const [objectIds, setObjectIds] = useState<string[]>([]);
  const [selectedObjectId, setSelectedObjectId] = useState<string>("");
  const [objectContents, setObjectContents] = useState<Record<string, string>>(
    {}
  );

  const [fullPdfText, setFullPdfText] = useState<string>("");

  initPKIjs();

  const onFileChange = async (e: ChangeEvent<HTMLInputElement>) => {
    setStatus("Reading file...");
    setError(null);
    setSignatureValid(null);
    setPublicKeyPEM(null);
    setObjectIds([]);
    setSelectedObjectId("");
    setObjectContents({});
    setFullPdfText("");

    if (!e.target.files || e.target.files.length === 0) {
      setError("No file chosen.");
      return;
    }

    try {
      const file = e.target.files[0];
      const arrayBuffer = await file.arrayBuffer();
      const uint8 = new Uint8Array(arrayBuffer);

      setStatus("Scanning for ByteRange and Contents…");

      const pdfText = new TextDecoder("latin1").decode(uint8);
      setFullPdfText(pdfText);

      const byteRangeMatch =
        /\/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]/.exec(pdfText);
      if (!byteRangeMatch) {
        throw new Error("Could not locate /ByteRange in PDF.");
      }

      const start1 = parseInt(byteRangeMatch[1], 10);
      const len1 = parseInt(byteRangeMatch[2], 10);
      const start2 = parseInt(byteRangeMatch[3], 10);
      const len2 = parseInt(byteRangeMatch[4], 10);

      const contentsMatch = /\/Contents\s*<([0-9A-Fa-f\s]+)>/.exec(pdfText);
      if (!contentsMatch) {
        throw new Error("Could not locate /Contents in PDF.");
      }
      const signatureHex = contentsMatch[1].replace(/\s+/g, "");
      if (!signatureHex) {
        throw new Error("Empty /Contents field.");
      }

      setStatus("Reassembling signed data…");

      const slice1 = uint8.slice(start1, start1 + len1);
      const slice2 = uint8.slice(start2, start2 + len2);
      const signedData = new Uint8Array(slice1.byteLength + slice2.byteLength);
      signedData.set(slice1, 0);
      signedData.set(slice2, slice1.byteLength);

      const signatureDer = new Uint8Array(
        signatureHex.match(/.{1,2}/g)!.map((byte) => parseInt(byte, 16))
      );

      setStatus("Parsing PKCS#7…");

      const asn1 = asn1js.fromBER(signatureDer.buffer);
      if (asn1.offset === -1) {
        throw new Error("ASN.1 parse error on signature DER.");
      }

      const contentInfo = new ContentInfo({ schema: asn1.result });
      if (contentInfo.contentType !== "1.2.840.113549.1.7.2") {
        throw new Error("Not a SignedData ContentInfo (OID mismatch).");
      }

      const signedDataPKI = new SignedData({ schema: contentInfo.content });
      const verification = await signedDataPKI.verify({
        signer: 0,
        trustedCerts: [],
        data: signedData.buffer,
      });

      setSignatureValid(!!verification);

      if (
        !signedDataPKI.certificates ||
        signedDataPKI.certificates.length === 0
      ) {
        throw new Error("No certificates embedded in this SignedData.");
      }
      const cert0 = signedDataPKI.certificates![0] as Certificate;
      const spkiBuf = cert0.subjectPublicKeyInfo.toSchema().toBER(false);
      setPublicKeyPEM(publicKeyInfoToPEM(spkiBuf));

      setStatus("Signature parsed. Now extracting object IDs and contents…");

      const objMatches = [...pdfText.matchAll(/(\d+)\s+\d+\s+obj/g)];
      const ids = Array.from(new Set(objMatches.map((m) => m[1])));
      setObjectIds(ids);

      const contentsMap: Record<string, string> = {};
      ids.forEach((id) => {
        const re = new RegExp(`${id}\\s+\\d+\\s+obj([\\s\\S]*?)endobj`, "g");
        const m = re.exec(pdfText);
        if (m && m[1] !== undefined) {
          contentsMap[id] = m[1].trim();
        } else {
          contentsMap[id] = "";
        }
      });
      setObjectContents(contentsMap);

      if (ids.length > 0) {
        setSelectedObjectId(ids[0]);
      }

      setStatus("Done. Signature OK and objects listed below.");
    } catch (err: any) {
      console.error(err);
      setError(err.message || String(err));
      setStatus("Error.");
    }
  };

  const onGenerateProof = () => {
    if (!selectedObjectId) {
      alert("Please pick an object ID first.");
      return;
    }
    alert(`Generate proof for object #${selectedObjectId}`);
  };

  return (
    <div
      style={{ maxWidth: 700, margin: "2rem auto", fontFamily: "sans-serif" }}
    >
      <h2>🖨️ PDF Signature Verifier & Inspector</h2>
      <p>
        1. Select a signed PDF. This page will extract its PKCS#7 signature,
        verify it against the embedded certificate, and then scan the PDF for
        “object” identifiers. 2. Pick one object ID from the list to view its
        raw PDF snippet or to generate a proof over it.
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

      {objectIds.length > 0 && (
        <div
          style={{
            marginTop: "2rem",
            padding: "1rem",
            border: "1px solid #ccc",
            borderRadius: 4,
          }}
        >
          <strong>
            Step 2: Pick an object ID to inspect or generate a proof
          </strong>
          <div style={{ marginTop: "0.5rem" }}>
            <label htmlFor="obj-select">Object IDs found in PDF:</label>
            <br />
            <select
              id="obj-select"
              value={selectedObjectId}
              onChange={(e) => setSelectedObjectId(e.target.value)}
              style={{
                marginTop: "0.25rem",
                padding: "0.25rem",
                minWidth: "100px",
              }}
            >
              {objectIds.map((id) => (
                <option key={id} value={id}>
                  {id}
                </option>
              ))}
            </select>
          </div>

          {/* Show the raw snippet for the currently selected object */}
          <div style={{ marginTop: "1rem" }}>
            <strong>Raw PDF snippet for object #{selectedObjectId}:</strong>
            <pre
              style={{
                background: "#f5f5f5",
                border: "1px solid #ddd",
                padding: "0.5rem",
                borderRadius: 4,
                overflowX: "auto",
                maxHeight: "200px",
                whiteSpace: "pre-wrap",
                wordBreak: "break-all",
                color: "#333",
              }}
            >
              {objectContents[selectedObjectId] || "(no content found)"}
            </pre>
          </div>

          <button
            onClick={onGenerateProof}
            style={{
              marginTop: "1rem",
              padding: "0.5rem 1rem",
              background: "#007ACC",
              color: "white",
              border: "none",
              borderRadius: 4,
              cursor: "pointer",
            }}
          >
            Generate Proof
          </button>
        </div>
      )}
    </div>
  );
}
