#!/bin/bash

# Generate WASM module for PDF verification
echo "🔨 Building WASM module..."

# Install wasm-pack if not available
if ! command -v wasm-pack &> /dev/null; then
    echo "Installing wasm-pack..."
    curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh
fi

# Build WASM module
wasm-pack build --target web --out-dir pkg

# Copy to app public directory
if [ -d "../../app/public/pkg" ]; then
    echo "📁 Copying WASM files to app/public/pkg..."
    cp -r pkg/* ../../app/public/pkg/
    echo "✅ WASM files copied successfully!"
else
    echo "⚠️  app/public/pkg directory not found. Creating it..."
    mkdir -p ../../app/public/pkg
    cp -r pkg/* ../../app/public/pkg/
    echo "✅ WASM files copied successfully!"
fi

echo "🎉 WASM build complete!"