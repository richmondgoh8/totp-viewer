# TOTP Viewer 🔐

A modern, premium, and browser-based TOTP (Time-Based One-Time Password) generator and validator, powered by **TinyGo WebAssembly**.

The application logic runs entirely in your browser using Go, ensuring high performance and absolute privacy. Your secrets never leave your device.

---

## 🏗️ Deep Dive: Architecture

This project is built using a **WebAssembly (Wasm)** architecture. If you're a junior developer, think of Wasm as a way to run "heavy-duty" languages like Go directly inside the web browser at near-native speeds.

### How it Works

The application follows a simple three-step lifecycle:

1.  **Development**: Go code in `wasm.go` is written using the `syscall/js` package to interact with the browser.
2.  **Compilation**: The TinyGo compiler takes that Go code and transforms it into a `main.wasm` binary file.
3.  **Execution**: When a user visits the site, `index.html` loads a small helper script (`wasm_exec.js`) which then streams and runs the `.wasm` binary directly in the browser.

When you enter a secret, JavaScript sends that data into the Wasm module, Go performs the cryptographic math, and sends the 6-digit code back to the UI.

### 📂 File Breakdown

- **`wasm.go`**: The engine. It contains the logic to decode Base32 secrets and calculate the 6-digit TOTP code. It uses `syscall/js` to make these functions available to the browser's JavaScript.
- **`main.go`**: The messenger. This file's only job is to provide a local web server so you can test the app. It serves the files in the `public/` folder to your browser.
- **`public/index.html`**: The UI. A premium, glassmorphic interface that users interact with.
- **`public/main.wasm`**: The compiled Go logic. This is what the browser actually runs.
- **`public/wasm_exec.js`**: The glue. A helper file provided by Go/TinyGo that allows the browser to understand how to run `.wasm` files.

### 🛡️ Why Wasm?

1.  **Privacy**: Cryptographic calculations happen locally. No secrets are ever sent to a server.
2.  **Performance**: Go's math operations are significantly faster than standard JavaScript for complex tasks.
3.  **Portability**: The same Go code can theoretically be used in a CLI tool or a mobile app.

---

## � Getting Started

### Prerequisites

- **Go**: [v1.25.5](https://go.dev/dl/) or later.
- **TinyGo**: [v0.40.1](https://tinygo.org/getting-started/install/) or later (required for small Wasm footprints).

### 1. Build the Module
Whenever you change `wasm.go`, you must rebuild the Wasm block:
```bash
tinygo build -o public/main.wasm -target wasm .
```

### 2. Run Locally
To test the app on your machine:
```bash
go run main.go
```
Visit: `http://localhost:8080/?secret=JBSWY3DPEHPK3PXP`

---

## 🌥️ Deployment (Cloudflare Pages)

The app is hosted as a **Static Site**. Deployment is handled by simply pushing the `public/` folder to GitHub.

1. Build the Wasm module locally.
2. Push your changes to GitHub.
3. Cloudflare Pages will serve the `public/` directory automatically.

> [!TIP]
> Make sure your hosting provider serves `.wasm` files with the `application/wasm` MIME type, otherwise the browser will refuse to execute the logic! (Our `main.go` and `wrangler.toml` handle this for you).

---

## ✨ Features

- **Bookmarkable**: Links like `?secret=...` make it easy to save your codes.
- **Bi-lingual**: Support for English and Chinese.
- **Themes**: Switch between Dark and Light mode.
- **Robust Validation**: Test your codes against a custom tolerance window.
