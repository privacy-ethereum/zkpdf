#!/bin/bash

# Deploy script for both app and documentation
echo "🚀 Deploying ZKPDF App and Documentation..."

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Build WASM module
echo "🔨 Building WASM module..."
cd pdf-utils/wasm
./generate_wasm.sh

# Go back to root directory
cd ../..

# Build the Next.js app
echo "🏗️ Building Next.js app..."
cd app
yarn build
cd ..

# Check if app build was successful
if [ -d "app/out" ]; then
    echo "✅ App build successful!"
else
    echo "❌ App build failed!"
    exit 1
fi

# Install mdbook if not already installed
if ! command_exists mdbook; then
    echo "📦 Installing mdbook..."
    cargo install mdbook
fi

# Build the documentation
echo "📚 Building documentation..."
cd docs
./build.sh
cd ..

# Check if docs build was successful
if [ -d "docs/book" ]; then
    echo "✅ Documentation build successful!"
else
    echo "❌ Documentation build failed!"
    exit 1
fi

echo ""
echo "🎉 Both app and documentation built successfully!"
echo ""
echo "📁 Deployment files:"
echo "   App: app/out/ (ready for GitHub Pages)"
echo "   Docs: docs/book/ (ready for GitHub Pages)"
echo ""
echo "🌐 Deployment URLs:"
echo "   App: https://privacy-ethereum.github.io/zkpdf/"
echo "   Docs: https://privacy-ethereum.github.io/zkpdf-docs/ (requires separate Pages site)"
echo ""
echo "📝 Next steps:"
echo "   1. Push to main/dev branch to trigger automatic deployment"
echo "   2. For docs: Configure a separate GitHub Pages site for the docs"
echo "   3. Or serve locally:"
echo "      - App: cd app && npx serve out"
echo "      - Docs: cd docs && mdbook serve"
