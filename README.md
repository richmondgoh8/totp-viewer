# TOTP Viewer 🔐

A modern, premium, and browser-based TOTP (Time-Based One-Time Password) generator and validator.

## 🛠️ The "Single Source of Truth" Workflow

This project is designed so that `main.go` is the master file. Any changes you make to the UI, styles, or logic should be done in `main.go`. Running it with the `--export` flag will automatically synchronize those changes to the Cloudflare Pages assets.

### 1. Edit
Make your changes to the templates or logic in `main.go`.

### 2. Export
Regenerate the `public/` and `functions/` directories:
```bash
go run main.go --export
```

### 3. Deploy/Test
Run locally with Wrangler or push to GitHub for Cloudflare Pages to deploy:
```bash
npx wrangler pages dev public
```

---

## 🚀 Setup & Development

### Prerequisites

- [Go](https://go.dev/dl/) (v1.25 or later)
- [Node.js](https://nodejs.org/) (v18 or later)
- [Wrangler](https://developers.cloudflare.com/workers/wrangler/install-and-update/)

### Local Development (Go Server)
If you just want to run the Go server directly:
```bash
go run main.go
```
The server will be available at `http://localhost:8080`. It serves the same premium UI as the Cloudflare version.

### Deployment to Cloudflare Pages

1.  **Regenerate assets**: `go run main.go --export`
2.  **Commit and Push**:
    ```bash
    git add .
    git commit -m "update totp logic"
    git push origin main
    ```
3.  **Cloudflare Configuration**:
    - **Build output directory**: `public`
    - **Build command**: (None needed if you export locally, or you can use `go run main.go --export` if Go is available in the build environment).

## Technologies Used

- **Go (Golang)**: The "Source of Truth" for the entire app.
- **HTML5/CSS3**: Premium glassmorphic UI.
- **JavaScript (Vanilla)**: Core client-side and serverless logic.
- **Cloudflare Pages**: High-performance serverless hosting.
