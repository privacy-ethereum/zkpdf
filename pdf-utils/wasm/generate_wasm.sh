echo "Generating WASM..."
wasm-pack build --target web --out-dir pkg
echo "WASM generated successfully."

echo "Copying WASM to app/public/pkg..."
cp -r pkg/* ../app/public/pkg/
echo "WASM copied to app/public/pkg successfully."