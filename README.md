# TOTP Viewer 🔐

A modern, premium, and browser-based TOTP (Time-Based One-Time Password) generator and validator, powered by pure **JavaScript** and the browser's native **SubtleCrypto API**.

The application logic runs entirely in your browser, ensuring absolute privacy. Your secrets never leave your device.

---

## 🏗️ Architecture

This project is now a lightweight, standalone application that runs entirely on the client side without any build steps or external dependencies.

### How it Works

The application uses the browser's built-in cryptographic capabilities:

1.  **Base32 Decoding**: A custom JavaScript implementation decodes the shared secret.
2.  **Cryptographic Math**: The `crypto.subtle` API performs the HMAC-SHA1 calculation required for TOTP.
3.  **UI Updates**: The interface updates every 30 seconds to reflect the current code, with a smooth progress bar.

### 📂 File Breakdown

- **`public/index.html`**: The entire application (HTML, CSS, and JS).
- **`README.md`**: Project documentation.

### 🛡️ Why JavaScript?

1.  **Zero Build Steps**: No need to compile Go to WebAssembly. Just open the file and it works.
2.  **Privacy**: Cryptographic calculations happen locally. No secrets are ever sent to a server.
3.  **Performance**: Modern browsers handle cryptographic operations extremely efficiently via the native SubtleCrypto API.
4.  **Portability**: Extremely easy to host on any static site provider (like Cloudflare Pages or GitHub Pages).

---

## 🚀 Getting Started

### Prerequisites

- A modern web browser (Chrome, Firefox, Safari, Edge).

### 1. Run Locally

Simply open `public/index.html` in your browser.

Alternatively, you can use any static file server:
```bash
npx serve public
```
Visit: `http://localhost:3000/?secret=JBSWY3DPEHPK3PXP`

---

## 🌥️ Deployment (Cloudflare Pages)

The app is hosted as a **Static Site**. Deployment is handled by simply pushing the repository to GitHub and pointing Cloudflare Pages to the `public/` directory.

---

## ✨ Features

- **Bookmarkable**: Links like `?secret=...` make it easy to save your codes.
- **Bi-lingual**: Support for English and Chinese.
- **Themes**: Switch between Dark and Light mode.
- **Robust Validation**: Test your codes against a custom tolerance window.
- **Micro-animations**: Premium glassmorphic interface with smooth transitions.
- **No Dependencies**: No external JS libraries or CSS frameworks.
