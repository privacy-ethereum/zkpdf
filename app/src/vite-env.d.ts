/// <reference types="vite/client" />

declare module "../../pdf-utils/wasm/pkg/wasm.js" {
  export default function init(): Promise<void>;
  export function wasm_extract_text(bytes: Uint8Array): string[];
  export function wasm_verify_text(
    bytes: Uint8Array,
    page_number: number,
    sub_string: string,
    position: number
  ): boolean;
}
