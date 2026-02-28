# TOTP Viewer 🔐

Welcome to **TOTP Viewer**, a beautifully crafted, extremely secure Time-Based One-Time Password tool.

We believe that high-grade security shouldn't come at the cost of a clunky user experience. That’s why we’ve built this application entirely on the client side—meaning your secret keys _never_ leave your device. Whether you're here to evaluate the product for your business, market it to your audience, or dive deep into the code, we’ve laid out exactly why this tool might be perfect for you.

---

## � For Marketers & Partnerships

**"Security that actually looks good."**
Traditional 2FA tools look like they were built decades ago. We decided to fix that.

- **Premium Aesthetics:** Features a stunning "glassmorphic" interface with buttery smooth micro-animations that make security feel modern and high-end.
- **Frictionless Sharing:** Users can securely share access using encrypted URL parameters without forcing anyone to download an app or create an account.
- **Global Ready:** Fully bilingual out-of-the-box (English and Chinese) with built-in dark and light modes to match every user's preference.

## 💼 For Business Users & Managers

**"Zero server costs, zero data breaches."**
When evaluating software for your enterprise, the biggest liabilities are data storage and hosting fees.

- **Impenetrable Privacy:** The core architecture is 100% client-side. The shared secrets are processed entirely within the employee's browser. There is no database to hack, which significantly reduces your compliance burden.
- **Highest Security Ratings:** Out-of-the-box, the application scores an **A+ on the Mozilla Observatory** thanks to military-grade HTTP security headers (including strict HSTS and Content Security Policies).
- **Cost-Effective:** Because there is no backend server, you can host this on platforms like Cloudflare Pages or GitHub Pages for absolutely **free**.

## 🌱 For Junior Developers

**"The perfect learning sandbox."**
Sometimes, modern web development feels overwhelming with all the bundlers, frameworks, and build steps. We wanted to keep things beautifully simple here.

- **Zero Build Steps:** No Webpack. No React. No compilation required. You can literally just double-click `public/index.html` and it works instantly.
- **Clean Code Structure:** The HTML, CSS, and JS are perfectly modularized in the `public/` folder. It’s a fantastic way to study how raw vanilla Javascript, DOM manipulation, and CSS Grid truly work together.

## 🧠 For Expert Developers

**"No external dependencies. Pure native APIs."**
You know that the best code is the code you didn't have to write. We rely exclusively on the browser's native capabilities to generate the cryptographic hashes.

- **Native Cryptography:** The entire TOTP generation logic is powered by `crypto.subtle` (the Web Crypto API) using HMAC-SHA1. No heavy third-party NPM libraries are imported into the codebase.
- **Strict Security Posture:** The `public/_headers` file applies aggressive OWASP-recommended HTTP headers to the client. This enforces a `default-src 'none'` Content Security Policy, prevents MIME sniffing, denies frame embedding to stop clickjacking, and restricts permissions policies.
- **Modern Standards:** Linted using the brand new ESLint v9 Flat Config (`eslint.config.mjs`) to ensure squeaky-clean, compliant ES6+ code.

---

## 🚀 Getting Started

If you want to spin this up locally:

1. Clone the repository.
2. Open `public/index.html` in any modern web browser.
   _That's literally it._

If you prefer testing it via a local development server:

```bash
npx serve public
```

Then visit: `http://localhost:3000/?secret=JBSWY3DPEHPK3PXP`

## 🌥️ Deployment

Deployment is entirely frictionless. The repository is optimized for **Cloudflare Pages**.
Simply point your Cloudflare deployment to the `/public` directory, and it will effortlessly ingest the `_headers` file and serve your application to the world in seconds.
