// global.d.ts
/// <reference types="vite/client" />

declare module "/pkg/wasm.js" {
  // `init()` is the default export that bootstraps the WASM module
  export default function init(): Promise<void>;

  // named exports exposed by wasm-bindgen
  export function wasm_extract_text(bytes: Uint8Array): string[];
  export function wasm_verify_text(
    bytes: Uint8Array,
    page_number: number,
    sub_string: string,
    position: number
  ): boolean;
}
