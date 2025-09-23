/* tslint:disable */
/* eslint-disable */
/**
 * WebAssembly export: verify and extract content from PDF (signature verification + text extraction)
 */
export function wasm_verify_and_extract(pdf_bytes: Uint8Array): any;
/**
 * WebAssembly export: verify text and signature in a PDF at a specific offset
 * Returns a JSON object with success status and error message (if any)
 */
export function wasm_verify_text(pdf_bytes: Uint8Array, page_number: number, sub_string: string, offset: number): any;
/**
 * WebAssembly export: verify PDF signature only (no text extraction)
 * Returns a JSON object with signature verification results
 */
export function wasm_verify_pdf_signature(pdf_bytes: Uint8Array): any;
/**
 * WebAssembly export: extract raw text content per page
 */
export function wasm_extract_text(pdf_bytes: Uint8Array): any[];

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
  readonly memory: WebAssembly.Memory;
  readonly wasm_verify_and_extract: (a: number, b: number) => [number, number, number];
  readonly wasm_verify_text: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number];
  readonly wasm_verify_pdf_signature: (a: number, b: number) => [number, number, number];
  readonly wasm_extract_text: (a: number, b: number) => [number, number];
  readonly __wbindgen_malloc: (a: number, b: number) => number;
  readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
  readonly __wbindgen_export_2: WebAssembly.Table;
  readonly __externref_table_dealloc: (a: number) => void;
  readonly __externref_drop_slice: (a: number, b: number) => void;
  readonly __wbindgen_free: (a: number, b: number, c: number) => void;
  readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;
/**
* Instantiates the given `module`, which can either be bytes or
* a precompiled `WebAssembly.Module`.
*
* @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
*
* @returns {InitOutput}
*/
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
* If `module_or_path` is {RequestInfo} or {URL}, makes a request and
* for everything else, calls `WebAssembly.instantiate` directly.
*
* @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
*
* @returns {Promise<InitOutput>}
*/
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
