#!/bin/bash

# Unified deployment script for ZKPDF
# Usage: ./deploy.sh [app|docs|all]
# Default: all

set -e  # Exit on any error

# Default to deploy all
DEPLOY_TARGET="${1:-all}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to build WASM module
build_wasm() {
    print_status "Building WASM module..."
    cd pdf-utils/wasm
    
    if [ ! -f "generate_wasm.sh" ]; then
        print_error "generate_wasm.sh not found in pdf-utils/wasm/"
        exit 1
    fi
    
    chmod +x generate_wasm.sh
    ./generate_wasm.sh
    
    # Copy WASM files to app public directory
    print_status "Copying WASM files to app..."
    mkdir -p ../../app/public/pkg
    cp pkg/* ../../app/public/pkg/
    
    cd ../..
    print_success "WASM module built and copied successfully!"
}

# Function to build Next.js app
build_app() {
    print_status "Building Next.js app..."
    
    # Check if we're in the right directory
    if [ ! -f "app/package.json" ]; then
        print_error "app/package.json not found. Are you in the project root?"
        exit 1
    fi
    
    cd app
    
    # Check if yarn is available
    if ! command_exists yarn; then
        print_error "yarn is not installed. Please install it first."
        exit 1
    fi
    
    # Install dependencies if needed
    if [ ! -d "node_modules" ]; then
        print_status "Installing dependencies..."
        yarn install
    fi
    
    yarn build
    
    # Check if build was successful
    if [ -d "out" ]; then
        print_success "App build successful! Static files are in app/out/"
    else
        print_error "App build failed! No 'out' directory found."
        exit 1
    fi
    
    cd ..
}

# Function to build documentation
build_docs() {
    print_status "Building documentation..."
    
    # Install mdbook if not already installed
    if ! command_exists mdbook; then
        print_status "Installing mdbook..."
        cargo install mdbook
    fi
    
    cd docs
    
    if [ ! -f "build.sh" ]; then
        print_error "build.sh not found in docs/"
        exit 1
    fi
    
    chmod +x build.sh
    ./build.sh
    
    # Check if docs build was successful
    if [ -d "book" ]; then
        print_success "Documentation build successful! Files are in docs/book/"
    else
        print_error "Documentation build failed! No 'book' directory found."
        exit 1
    fi
    
    cd ..
}

# Function to create combined deployment
create_combined_deployment() {
    print_status "Creating combined deployment..."
    
    # Create a combined deployment directory
    mkdir -p combined-deploy
    
    # Copy app files to root
    cp -r app/out/* combined-deploy/
    
    # Copy docs to /docs subdirectory
    mkdir -p combined-deploy/docs
    cp -r docs/book/* combined-deploy/docs/
    
    # Create a simple index.html redirect for docs
    cat > combined-deploy/docs/index.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>ZKPDF Documentation</title>
    <meta http-equiv="refresh" content="0; url=./introduction.html">
</head>
<body>
    <p>Redirecting to documentation... <a href="./introduction.html">Click here</a></p>
</body>
</html>
EOF
    
    print_success "Combined deployment created in combined-deploy/"
}

# Main deployment logic
main() {
    print_status "🚀 Starting ZKPDF deployment (target: $DEPLOY_TARGET)..."
    
    case $DEPLOY_TARGET in
        "app")
            build_wasm
            build_app
            print_success "🎉 App deployment ready!"
            echo ""
            echo "📁 App files: app/out/ (ready for GitHub Pages)"
            echo "🌐 App URL: https://privacy-ethereum.github.io/zkpdf/"
            ;;
        "docs")
            build_docs
            print_success "🎉 Documentation deployment ready!"
            echo ""
            echo "📁 Docs files: docs/book/ (ready for GitHub Pages)"
            echo "🌐 Docs URL: https://privacy-ethereum.github.io/zkpdf-docs/"
            ;;
        "all")
            build_wasm
            build_app
            build_docs
            create_combined_deployment
            print_success "🎉 Complete deployment ready!"
            echo ""
            echo "📁 Deployment files:"
            echo "   App: app/out/ (ready for GitHub Pages)"
            echo "   Docs: docs/book/ (ready for GitHub Pages)"
            echo "   Combined: combined-deploy/ (app + docs in one site)"
            echo ""
            echo "🌐 Deployment URLs:"
            echo "   App: https://privacy-ethereum.github.io/zkpdf/"
            echo "   Docs: https://privacy-ethereum.github.io/zkpdf-docs/"
            echo "   Combined: https://privacy-ethereum.github.io/zkpdf/ (with /docs subdirectory)"
            ;;
        *)
            print_error "Invalid deployment target: $DEPLOY_TARGET"
            echo ""
            echo "Usage: $0 [app|docs|all]"
            echo "  app  - Deploy only the web application"
            echo "  docs - Deploy only the documentation"
            echo "  all  - Deploy both app and docs (default)"
            exit 1
            ;;
    esac
    
    echo ""
    echo "📝 Next steps:"
    echo "   1. Push to main/dev branch to trigger automatic deployment"
    echo "   2. Or serve locally:"
    echo "      - App: cd app && npx serve out"
    echo "      - Docs: cd docs && mdbook serve"
    echo "      - Combined: npx serve combined-deploy"
}

# Run main function
main "$@"