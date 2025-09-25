# Server-Side Proving

Server-side proving is the recommended approach for production applications, providing better performance, security, and resource management.

## Prover Server Setup

ZKPDF includes a built-in prover server that handles PDF verification and proof generation requests.

### Starting the Prover Server

```bash
cd script
cargo run --release --bin prover
```

The server runs on port 3001 by default and provides two endpoints:

- `/prove` - Generate proofs
- `/verify` - Verify proofs

### Environment Configuration

Set up your environment variables:

```bash
export SP1_PROVER=network
export NETWORK_PRIVATE_KEY=your_private_key_here
export PORT=3001
```

## API Endpoints

### Generate Proof

**POST** `/prove`

```json
{
  "pdf_bytes": [
    /* PDF file bytes */
  ],
  "page_number": 0,
  "sub_string": "Important Document",
  "offset": 100
}
```

**Response:**

```json
{
  "proof": "/* SP1 proof bytes */",
  "public_values": "/* Public values */"
}
```

### Verify Proof

**POST** `/verify`

```json
{
  "proof": "/* SP1 proof bytes */",
  "public_values": "/* Public values */"
}
```

**Response:**

```json
{
  "valid": true,
  "error": null
}
```

## Integration Example

```javascript
// Generate proof
const response = await fetch("http://localhost:3001/prove", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({
    pdf_bytes: pdfBytes,
    page_number: 0,
    sub_string: "Important Document",
    offset: 100,
  }),
});

const proof = await response.json();

// Verify proof
const verifyResponse = await fetch("http://localhost:3001/verify", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify(proof),
});

const result = await verifyResponse.json();
console.log("Proof valid:", result.valid);
```

## Benefits

- **Scalability**: Handle multiple requests simultaneously
- **Security**: Keep proving keys on the server
- **Performance**: Optimized server resources
- **Reliability**: Enterprise-grade infrastructure
