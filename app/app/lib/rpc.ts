export interface JsonRpcResponse<T = unknown> {
  jsonrpc: "2.0";
  id: string;
  result: T;
}

interface JsonRpcError {
  code: number;
  message: string;
}

interface JsonRpcErrorResponse {
  jsonrpc: "2.0";
  id: string;
  error: JsonRpcError;
}

/**
 * Fetches the result from an Ethereum JSON-RPC endpoint.
 *
 * @param url    - The RPC endpoint URL
 * @param method - The JSON-RPC method name (e.g. "eth_blockNumber")
 * @param params - Optional parameters for the method
 * @returns The parsed `result` field from the JSON-RPC response
 */
export async function fetchJsonRpcResult<T = unknown>(
  url: string,
  method: string,
  params: unknown[] = []
): Promise<T> {
  const id = crypto.randomUUID();
  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id, method, params }),
  });

  if (!response.ok) {
    throw new Error(`RPC request failed with HTTP status ${response.status}`);
  }

  const json: JsonRpcResponse<T> | JsonRpcErrorResponse = await response.json();

  if ("error" in json) {
    throw new Error(`JSON-RPC error ${json.error.code}: ${json.error.message}`);
  }

  return json.result;
}
