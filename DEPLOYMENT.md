# Deployment Guide

This repository deploys both the ZKPDF web application and documentation to GitHub Pages.

## 🌐 Deployment URLs

- **App**: https://privacy-ethereum.github.io/zkpdf/
- **Documentation**: https://privacy-ethereum.github.io/zkpdf-docs/

## 🚀 Automatic Deployment

### App Deployment

The main app is automatically deployed when you push to the `main` or `dev` branch. The deployment is handled by `.github/workflows/deploy.yml`.

### Documentation Deployment

The documentation is automatically deployed when you push changes to the `docs/` folder to the `main` or `dev` branch. The deployment is handled by `.github/workflows/deploy-docs.yml`.

## 🛠️ Manual Deployment

### Deploy Both App and Docs

```bash
./deploy-all.sh
```

### Deploy App Only

```bash
cd app
./deploy.sh
```

### Deploy Docs Only

```bash
cd docs
./build.sh
```

## 📋 Setup Requirements

### For App Deployment

- Node.js 18+
- Yarn package manager
- Rust toolchain with `wasm32-unknown-unknown` target

### For Documentation Deployment

- Rust toolchain
- mdbook (installed automatically by CI)

## 🔧 GitHub Pages Configuration

### App Pages

1. Go to repository Settings → Pages
2. Source: GitHub Actions
3. Environment: `github-pages`

### Documentation Pages

1. Go to repository Settings → Pages
2. Create a new environment: `github-pages-docs`
3. Source: GitHub Actions
4. Configure custom domain if needed (e.g., `docs.zkpdf.com`)

## 📁 Build Outputs

- **App**: `app/out/` directory contains static files
- **Docs**: `docs/book/` directory contains HTML documentation

## 🧪 Local Testing

### Test App Locally

```bash
cd app
yarn build
npx serve out
# Visit http://localhost:3000
```

### Test Docs Locally

```bash
cd docs
mdbook serve
# Visit http://localhost:3000
```

## 🔍 Troubleshooting

### Common Issues

1. **WASM Build Fails**: Ensure Rust toolchain is properly installed
2. **mdbook Not Found**: Install with `cargo install mdbook`
3. **Permission Denied**: Make scripts executable with `chmod +x *.sh`

### CI/CD Issues

1. Check GitHub Actions logs for specific error messages
2. Ensure all required secrets and permissions are set
3. Verify branch protection rules don't block deployments

## 📝 Contributing

When contributing to documentation:

1. Edit files in `docs/src/`
2. Test locally with `mdbook serve`
3. Push changes to trigger automatic deployment

When contributing to the app:

1. Edit files in `app/`
2. Test locally with `yarn dev`
3. Push changes to trigger automatic deployment
