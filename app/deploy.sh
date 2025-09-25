#!/bin/bash

# Build WASM module
echo "🔨 Building WASM module..."
cd ../pdf-utils/wasm
./generate_wasm.sh

# Go back to app directory
cd ../../app

# Build the app
echo "🏗️ Building Next.js app..."
yarn build

# Check if out directory exists
if [ -d "out" ]; then
    echo "✅ Build successful! Static files are in the 'out' directory."
    echo "📁 You can now:"
    echo "   1. Copy the 'out' directory contents to your GitHub Pages branch"
    echo "   2. Or push to main branch to trigger automatic deployment"
    echo ""
    echo "🌐 Your app will be available at:"
    echo "   https://privacy-ethereum.github.io/zkpdf/"
else
    echo "❌ Build failed! No 'out' directory found."
    exit 1
fi
