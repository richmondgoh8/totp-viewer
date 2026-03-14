# TOTP Viewer

Welcome to **TOTP Viewer**, a web based Time-Based One-Time Password tool. (NPM Module can be ignored, it is just purely used as a linter to check for errors)

A very tiny project built using some AI.

Users can securely share access using encrypted URL parameters without forcing anyone to download an app or create an account (not using any database, just simple json with local account).

Users can validate TOTP codes against different step windows to see how it behaves and is correct.

The idea is just to put the url with the secret and keep it as a bookmark either to for yourself or to share. For other users, they can also self host to just keep an entire web version which only they can see.

## Getting Started

If you want to spin this up locally:

1. Clone the repository.
2. Open `public/index.html` in any modern web browser.
   _That's literally it._

If you prefer testing it via a local development server:

```bash
npx serve public
```

Then visit: `http://localhost:3000/?secret=JBSWY3DPEHPK3PXP`

## Deployment

Deployment is entirely frictionless. The repository is optimized for **Cloudflare Pages**.
Simply point your Cloudflare deployment to the `/public` directory, and it will effortlessly ingest the `_headers` file and serve your application to the world in seconds.

### Standalone Binary Release

If you prefer to distribute this tool entirely offline without a web host, you can generate a standalone zip file of the deployment-ready code.

Because there are no dependencies or build steps, generating a release is instant:

```bash
npm run build:zip
```

This generates a `totp-viewer-standalone.zip` archive containing only the core static files. Users can download this zip, unzip it, and directly run `index.html` on any offline computer securely.
