#!/bin/bash

# Build mdBook documentation
echo "📚 Building documentation..."

# Install mdbook if not already installed
if ! command -v mdbook &> /dev/null; then
    echo "📦 Installing mdbook..."
    cargo install mdbook
fi

# Build the documentation
echo "🔨 Building mdbook..."
mdbook build

# Check if build was successful
if [ -d "book" ]; then
    echo "✅ Documentation build successful!"
    echo "📁 Documentation files are in the 'book' directory."
    echo "🌐 You can serve locally with: mdbook serve"
else
    echo "❌ Documentation build failed!"
    exit 1
fi
