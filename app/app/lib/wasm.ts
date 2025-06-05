let mod: typeof import("../../public/pkg/wasm.js") | null = null;

export async function loadWasm() {
  if (!mod) {
    // Dynamically import from the public URL path "/pkg/wasm.js"
    mod = await import("../../public/pkg/wasm.js");
    // Call the default-exported init() to initialize the Rust-generated WASM bindings
    await mod.default();
  }
  return mod;
}
