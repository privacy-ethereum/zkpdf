let mod: typeof import("../public/pkg/wasm.js") | null = null;

export async function loadWasm() {
  if (!mod) {
    mod = await import("../public/pkg/wasm.js");
    await mod.default();
  }
  return mod;
}
