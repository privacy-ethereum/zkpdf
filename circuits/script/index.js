import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const API_PROVE = "http://localhost:3000/prove";
const API_VERIFY = "http://localhost:3000/verify";
const PDF_PATH = path.resolve(
  __dirname,
  "../../pdf-utils/sample-pdfs/digitally_signed.pdf"
);

const page_number = 0;
const offset = 0;
const sub_string = "Sample Signed PDF Document";

const pdfBuffer = fs.readFileSync(PDF_PATH);
const pdfBytes = Array.from(new Uint8Array(pdfBuffer));

const proofBody = {
  pdf_bytes: pdfBytes,
  page_number,
  offset,
  sub_string,
};

console.log("📤 Sending to /prove...");

const proveRes = await fetch(API_PROVE, {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify(proofBody),
});

if (!proveRes.ok) {
  console.error(`❌ /prove failed: ${proveRes.status}`);
  console.error(await proveRes.text());
  process.exit(1);
}

const proofData = await proveRes.json();
console.log("✅ Proof generated:\n", proofData);

console.log("\n🔎 Sending to /verify...");

const verifyRes = await fetch(API_VERIFY, {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify(proofData),
});

if (!verifyRes.ok) {
  console.error(`❌ /verify failed: ${verifyRes.status}`);
  console.error(await verifyRes.text());
  process.exit(1);
}

const verifyData = await verifyRes.json();
console.log("🔐 Verification result:\n", verifyData);
