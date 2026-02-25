package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// --- Constants & Config ---
const (
	StepSize    = 30
	DefaultPort = "8080"
)

// --- TOTP Logic ---

func decodeBase32(secret string) ([]byte, error) {
	secret = strings.ToUpper(strings.ReplaceAll(secret, " ", ""))
	if pad := len(secret) % 8; pad != 0 {
		secret += strings.Repeat("=", 8-pad)
	}
	return base32.StdEncoding.DecodeString(secret)
}

func generateHOTP(secretBytes []byte, counter uint64) string {
	h := hmac.New(sha1.New, secretBytes)
	binary.Write(h, binary.BigEndian, counter)
	sum := h.Sum(nil)
	offset := sum[len(sum)-1] & 0x0F
	value := int64(((int(sum[offset]) & 0x7F) << 24) |
		((int(sum[offset+1] & 0xFF)) << 16) |
		((int(sum[offset+2] & 0xFF)) << 8) |
		(int(sum[offset+3]) & 0xFF))
	mod := value % 1000000
	return fmt.Sprintf("%06d", mod)
}

func generateTOTP(secret string, t time.Time) (string, error) {
	secretBytes, err := decodeBase32(secret)
	if err != nil {
		return "", fmt.Errorf("invalid base32 secret")
	}
	counter := uint64(t.Unix() / StepSize)
	return generateHOTP(secretBytes, counter), nil
}

func validateTOTP(passcode string, secret string, windowSteps int) bool {
	secretBytes, err := decodeBase32(secret)
	if err != nil {
		return false
	}
	currentCounter := time.Now().Unix() / StepSize
	for i := -windowSteps; i <= windowSteps; i++ {
		counter := uint64(currentCounter + int64(i))
		if generateHOTP(secretBytes, counter) == passcode {
			return true
		}
	}
	return false
}

// --- Handler Logic ---

func handleUI(w http.ResponseWriter, r *http.Request) {
	secret := r.URL.Query().Get("secret")

	// Handle JSON request (parity with Cloudflare Functions)
	isJSON := strings.Contains(r.Header.Get("Accept"), "application/json") || r.URL.Query().Get("format") == "json"
	if secret != "" && isJSON {
		totp, err := generateTOTP(secret, time.Now())
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, `{"error":"invalid secret"}`)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"totp":"%s"}`, totp)
		return
	}

	// Serve the Premium UI
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, IndexHTML)
}

func handleValidate(w http.ResponseWriter, r *http.Request) {
	secret := r.URL.Query().Get("secret")
	code := r.URL.Query().Get("code")
	windowStr := r.URL.Query().Get("window")

	windowSteps := 1
	if windowStr != "" {
		if wInt, err := strconv.Atoi(windowStr); err == nil {
			windowSteps = wInt
		}
	}

	if secret == "" || code == "" {
		// If it's a browser visit, redirect to main UI
		if r.Header.Get("Accept") != "application/json" {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, `{"error":"missing secret or code"}`)
		return
	}

	isValid := validateTOTP(code, secret, windowSteps)
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"valid":%t}`, isValid)
}

// --- Exporter Logic ---

func exportAssets() {
	fmt.Println("📦 Exporting assets for Cloudflare Pages...")

	// Create directories
	dirs := []string{"public", "functions"}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			log.Fatalf("Failed to create directory %s: %v", dir, err)
		}
	}

	// Write public/index.html
	err := os.WriteFile(filepath.Join("public", "index.html"), []byte(IndexHTML), 0644)
	if err != nil {
		log.Fatalf("Failed to write index.html: %v", err)
	}

	// Write functions/index.js
	err = os.WriteFile(filepath.Join("functions", "index.js"), []byte(IndexJS), 0644)
	if err != nil {
		log.Fatalf("Failed to write index.js: %v", err)
	}

	// Write functions/validate.js
	err = os.WriteFile(filepath.Join("functions", "validate.js"), []byte(ValidateJS), 0644)
	if err != nil {
		log.Fatalf("Failed to write validate.js: %v", err)
	}

	// Write wrangler.toml
	wranglerConfig := fmt.Sprintf(`name = "totp-viewer"
compatibility_date = "2024-01-01"
pages_build_output_dir = "public"

[dev]
port = 8888
`)
	err = os.WriteFile("wrangler.toml", []byte(wranglerConfig), 0644)
	if err != nil {
		log.Fatalf("Failed to write wrangler.toml: %v", err)
	}

	fmt.Println("✅ Assets exported successfully to /public and /functions")
	fmt.Println("👉 Run 'npx wrangler pages dev public' to test locally.")
}

// --- Main Entry point ---

func main() {
	exportCmd := flag.Bool("export", false, "Regenerate Cloudflare Pages assets and exit")
	port := flag.String("port", DefaultPort, "Port to run the local server on")
	flag.Parse()

	if *exportCmd {
		exportAssets()
		return
	}

	http.HandleFunc("/", handleUI)
	http.HandleFunc("/validate", handleValidate)

	fmt.Printf("🚀 TOTP Server running at http://localhost:%s\n", *port)
	fmt.Printf("👉 Generator UI: http://localhost:%s/?secret=JBSWY3DPEHPK3PXP\n", *port)

	log.Fatal(http.ListenAndServe(":"+*port, nil))
}

// --- Templates ---

const IndexHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TOTP Viewer | Premium 2FA Experience</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --primary: #6366f1;
            --primary-glow: rgba(99, 102, 241, 0.4);
            --bg: #0f172a;
            --card-bg: rgba(30, 41, 59, 0.7);
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --success: #22c55e;
            --error: #ef4444;
            --input-bg: rgba(15, 23, 42, 0.8);
            --border: rgba(255, 255, 255, 0.1);
        }

        .light-mode {
            --bg: #f8fafc;
            --card-bg: rgba(255, 255, 255, 0.8);
            --text-main: #0f172a;
            --text-muted: #64748b;
            --input-bg: #ffffff;
            --border: rgba(0, 0, 0, 0.1);
            --primary-glow: rgba(99, 102, 241, 0.2);
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            transition: background-color 0.3s ease, color 0.3s ease, border-color 0.3s ease;
        }

        body {
            font-family: 'Outfit', sans-serif;
            background-color: var(--bg);
            background-image: 
                radial-gradient(circle at 0% 0%, rgba(99, 102, 241, 0.1) 0%, transparent 50%),
                radial-gradient(circle at 100% 100%, rgba(139, 92, 246, 0.1) 0%, transparent 50%);
            color: var(--text-main);
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            padding: 20px;
            overflow-x: hidden;
        }

        .top-nav {
            position: fixed;
            top: 20px;
            right: 20px;
            display: flex;
            gap: 12px;
            z-index: 100;
        }

        .nav-btn {
            background: var(--card-bg);
            backdrop-filter: blur(8px);
            border: 1px solid var(--border);
            padding: 8px 12px;
            border-radius: 12px;
            color: var(--text-main);
            font-family: inherit;
            font-weight: 600;
            font-size: 0.85rem;
            cursor: pointer;
            display: flex;
            align-items: center;
            gap: 6px;
        }

        .language-select {
            background: var(--card-bg);
            backdrop-filter: blur(8px);
            border: 1px solid var(--border);
            padding: 8px 12px;
            border-radius: 12px;
            color: var(--text-main);
            font-family: inherit;
            font-weight: 600;
            font-size: 0.85rem;
            cursor: pointer;
            outline: none;
        }

        .container {
            width: 100%;
            max-width: 480px;
            position: relative;
        }

        .card {
            background: var(--card-bg);
            backdrop-filter: blur(16px);
            -webkit-backdrop-filter: blur(16px);
            border: 1px solid var(--border);
            border-radius: 32px;
            padding: 40px;
            box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.3);
            text-align: center;
        }

        h1 {
            font-size: 1.75rem;
            font-weight: 700;
            margin-bottom: 8px;
            letter-spacing: -0.025em;
        }

        .subtitle {
            color: var(--text-muted);
            font-size: 0.9rem;
            margin-bottom: 32px;
        }

        .totp-display {
            background: var(--input-bg);
            border-radius: 20px;
            padding: 30px;
            margin-bottom: 32px;
            border: 1px solid var(--border);
            position: relative;
            overflow: hidden;
        }

        .code-container {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 16px;
            position: relative;
        }

        .code {
            font-size: 4rem;
            font-weight: 700;
            letter-spacing: 0.1em;
            color: var(--text-main);
            font-variant-numeric: tabular-nums;
        }

        .copy-btn {
            background: var(--primary);
            color: white;
            border: none;
            padding: 8px;
            border-radius: 10px;
            cursor: pointer;
            width: 40px;
            height: 40px;
            display: flex;
            align-items: center;
            justify-content: center;
            opacity: 0.8;
            transition: all 0.2s;
        }

        .copy-btn:hover {
            opacity: 1;
            transform: scale(1.05);
        }

        .copy-feedback {
            position: absolute;
            top: -30px;
            right: 0;
            background: var(--success);
            color: white;
            font-size: 0.7rem;
            padding: 4px 8px;
            border-radius: 6px;
            font-weight: 700;
            opacity: 0;
            transition: opacity 0.3s;
        }

        .copy-feedback.show {
            opacity: 1;
        }

        .timer-badge {
            position: absolute;
            bottom: 12px;
            right: 16px;
            font-size: 0.75rem;
            font-weight: 700;
            color: var(--primary);
            background: var(--primary-glow);
            padding: 2px 8px;
            border-radius: 6px;
        }

        .progress-bar-container {
            position: absolute;
            bottom: 0;
            left: 0;
            width: 100%;
            height: 4px;
            background: var(--border);
        }

        .progress-bar {
            height: 100%;
            background: var(--primary);
            width: 100%;
            transition: width 1s linear;
        }

        .secret-input-group {
            text-align: left;
            margin-bottom: 24px;
        }

        label {
            display: block;
            font-size: 0.7rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--text-muted);
            margin-bottom: 8px;
            margin-left: 4px;
        }

        input {
            width: 100%;
            background: var(--input-bg);
            border: 1px solid var(--border);
            border-radius: 14px;
            padding: 14px 16px;
            color: var(--text-main);
            font-family: inherit;
            font-size: 1rem;
            transition: all 0.2s ease;
        }

        input:focus {
            outline: none;
            border-color: var(--primary);
            box-shadow: 0 0 0 4px var(--primary-glow);
        }

        .actions {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 12px;
        }

        .btn-primary {
            background: var(--primary);
            color: white;
            padding: 14px;
            border-radius: 14px;
            border: none;
            font-weight: 700;
            cursor: pointer;
            box-shadow: 0 4px 12px var(--primary-glow);
        }

        .btn-secondary {
            background: var(--border);
            color: var(--text-main);
            padding: 14px;
            border-radius: 14px;
            border: 1px solid var(--border);
            font-weight: 700;
            cursor: pointer;
        }

        .about-section {
            margin-top: 40px;
            text-align: left;
            padding: 24px;
            background: var(--border);
            border-radius: 20px;
            font-size: 0.85rem;
            line-height: 1.5;
            color: var(--text-muted);
        }

        .about-title {
            color: var(--text-main);
            font-weight: 700;
            margin-bottom: 8px;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .github-link {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            margin-top: 16px;
            color: var(--primary);
            text-decoration: none;
            font-weight: 600;
            padding: 6px 12px;
            background: var(--primary-glow);
            border-radius: 10px;
        }

        .star-box {
            background: var(--primary);
            color: white;
            padding: 2px 6px;
            border-radius: 4px;
            font-size: 0.75rem;
        }

        .hidden { display: none; }

        @media (max-width: 480px) {
            .card { padding: 30px 20px; }
            .code { font-size: 3rem; }
        }
    </style>
</head>
<body>
    <div class="top-nav">
        <select id="langSelect" class="language-select">
            <option value="en">English</option>
            <option value="cn">中文</option>
        </select>
        <button id="themeToggle" class="nav-btn">
            <span id="themeIcon">🌙</span>
            <span id="themeText">Dark</span>
        </button>
    </div>

    <div class="container">
        <div class="card">
            <h1 id="titleTxt">TOTP Viewer</h1>
            <p class="subtitle" id="subtitleTxt">Secure Time-Based Passwords</p>

            <div class="totp-display" id="displayArea">
                <div class="code-container">
                    <div class="code" id="totpCode">------</div>
                    <button class="copy-btn" id="copyBtn" title="Copy to clipboard">
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
                    </button>
                    <div class="copy-feedback" id="copyFeedback">COPIED</div>
                </div>
                <div class="timer-badge"><span id="timerText">30</span>s <span id="remainingTxt">remaining</span></div>
                <div class="progress-bar-container">
                    <div class="progress-bar" id="progressBar"></div>
                </div>
            </div>

            <div class="secret-input-group">
                <label for="secret" id="labelSecret">Shared Secret</label>
                <input type="text" id="secret" readonly placeholder="?secret= in URL" autocomplete="off">
            </div>

            <div id="noSecretPrompt" class="hidden" style="margin-bottom: 24px; color: var(--text-muted); font-size: 0.8rem; background: var(--primary-glow); padding: 12px; border-radius: 12px; border: 1px dashed var(--primary);">
                <b id="missingTxt">Secret Missing:</b> <span id="promptTxt">Please use a URL with a secret parameter, e.g.:</span><br>
                <code id="exampleUrl" style="display: block; margin-top: 8px; color: var(--primary); cursor: pointer; text-decoration: underline;"></code>
            </div>

            <div class="actions">
                <button class="btn-primary hidden" id="generateBtn">Update</button>
                <button class="btn-secondary" id="toggleValidatorBtn" style="grid-column: span 2;">Validate Code</button>
            </div>

            <div id="validatorSection" class="validator-section hidden" style="margin-top:30px; border-top:1px solid var(--border); padding-top:20px;">
                <div id="statusBadge" class="status-badge hidden"></div>
                <div class="secret-input-group">
                    <label for="validateCode" id="labelVerify">Enter Code to Verify</label>
                    <input type="text" id="validateCode" placeholder="123456" maxlength="6">
                </div>
                <div class="secret-input-group">
                    <label for="windowSteps" id="labelSteps">Tolerance Window (Steps: 30s each)</label>
                    <input type="number" id="windowSteps" value="1" min="0" max="20">
                </div>
                <button class="btn-primary" style="width:100%" id="verifyBtn">Verify Now</button>
            </div>

            <div class="about-section">
                <div class="about-title">
                    <span>🛡️</span> <span id="aboutTitleText">About this Project</span>
                </div>
                <p id="aboutDescText">This is a ultra-secure, client-side TOTP viewer. Your secrets are processed only in your browser and never sent to any server. It supports bookmarkable URLs for quick access while maintaining a premium glassmorphic aesthetic.</p>
                <a href="https://github.com/richmondgoh8/totp-viewer" target="_blank" class="github-link">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor"><path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/></svg>
                    <span>GitHub</span>
                    <span class="star-box" id="starCount">24</span>
                </a>
            </div>
        </div>
    </div>

    <script>
        const i18n = {
            en: {
                title: "TOTP Viewer",
                subtitle: "Secure Time-Based Passwords",
                remaining: "remaining",
                secret: "Shared Secret",
                missing: "Secret Missing:",
                prompt: "Please use a URL with a secret parameter, e.g.:",
                update: "Update",
                validate: "Validate Code",
                verify_now: "Verify Now",
                label_verify: "Enter Code to Verify",
                label_steps: "Tolerance Window",
                verified: "VERIFIED",
                invalid: "INVALID CODE",
                about_title: "About this Project",
                about_desc: "This is a ultra-secure, client-side TOTP viewer. Your secrets are processed only in your browser and never sent to any server. It supports bookmarkable URLs for quick access while maintaining a premium glassmorphic aesthetic.",
                copied: "COPIED"
            },
            cn: {
                title: "TOTP 令牌生成器",
                subtitle: "安全的时间同步密码",
                remaining: "秒后更新",
                secret: "共享密钥",
                missing: "缺少密钥:",
                prompt: "请使用带有 secret 参数的 URL，例如：",
                update: "更新",
                validate: "验证代码",
                verify_now: "立即验证",
                label_verify: "输入要验证的代码",
                label_steps: "容差窗口",
                verified: "验证通过",
                invalid: "验证码错误",
                about_title: "关于本项目",
                about_desc: "这是一个超安全的客户端 TOTP 查看器。您的密钥仅在浏览器中处理，永远不会发送到任何服务器。它支持书签链接以实现快速访问，同时保持高端的磨砂玻璃审美。",
                copied: "已复制"
            }
        };

        const elements = {
            title: document.getElementById('titleTxt'),
            subtitle: document.getElementById('subtitleTxt'),
            remaining: document.getElementById('remainingTxt'),
            labelSecret: document.getElementById('labelSecret'),
            missing: document.getElementById('missingTxt'),
            prompt: document.getElementById('promptTxt'),
            update: document.getElementById('generateBtn'),
            validate: document.getElementById('toggleValidatorBtn'),
            verify_now: document.getElementById('verifyBtn'),
            label_verify: document.getElementById('labelVerify'),
            label_steps: document.getElementById('labelSteps'),
            about_title: document.getElementById('aboutTitleText'),
            about_desc: document.getElementById('aboutDescText'),
            copy_feedback: document.getElementById('copyFeedback')
        };

        const secretInput = document.getElementById('secret');
        const totpCode = document.getElementById('totpCode');
        const progressBar = document.getElementById('progressBar');
        const timerText = document.getElementById('timerText');
        const validatorSection = document.getElementById('validatorSection');
        const validateCodeInput = document.getElementById('validateCode');
        const windowStepsInput = document.getElementById('windowSteps');
        const statusBadge = document.getElementById('statusBadge');
        const noSecretPrompt = document.getElementById('noSecretPrompt');
        const exampleUrl = document.getElementById('exampleUrl');
        const displayArea = document.getElementById('displayArea');
        const langSelect = document.getElementById('langSelect');
        const themeToggle = document.getElementById('themeToggle');
        const copyBtn = document.getElementById('copyBtn');

        let currentLang = localStorage.getItem('totp-lang') || 'en';
        let currentTheme = localStorage.getItem('totp-theme') || 'dark';

        function applyLanguage(lang) {
            currentLang = lang;
            localStorage.setItem('totp-lang', lang);
            const t = i18n[lang];
            elements.title.textContent = t.title;
            elements.subtitle.textContent = t.subtitle;
            elements.remaining.textContent = t.remaining;
            elements.labelSecret.textContent = t.secret;
            elements.missing.textContent = t.missing;
            elements.prompt.textContent = t.prompt;
            elements.update.textContent = t.update;
            elements.validate.textContent = t.validate;
            elements.verify_now.textContent = t.verify_now;
            elements.label_verify.textContent = t.label_verify;
            elements.label_steps.textContent = t.label_steps;
            elements.about_title.textContent = t.about_title;
            elements.about_desc.textContent = t.about_desc;
            elements.copy_feedback.textContent = t.copied;
            langSelect.value = lang;
        }

        function toggleTheme() {
            currentTheme = currentTheme === 'dark' ? 'light' : 'dark';
            localStorage.setItem('totp-theme', currentTheme);
            document.body.classList.toggle('light-mode', currentTheme === 'light');
            document.getElementById('themeIcon').textContent = currentTheme === 'dark' ? '🌙' : '☀️';
            document.getElementById('themeText').textContent = currentTheme === 'dark' ? 'Dark' : 'Light';
        }

        async function copyToClipboard() {
            const text = totpCode.textContent;
            if (text === '------') return;
            try {
                await navigator.clipboard.writeText(text);
                elements.copy_feedback.classList.add('show');
                setTimeout(() => elements.copy_feedback.classList.remove('show'), 2000);
            } catch (err) {
                console.error('Copy failed', err);
            }
        }

        let refreshTimer = null;
        function updateProgress() {
            const now = new Date();
            const seconds = now.getSeconds() % 30;
            const remaining = 30 - seconds;
            const progress = (remaining / 30) * 100;
            progressBar.style.width = progress + '%';
            timerText.textContent = remaining;
            if (seconds === 0) fetchTotp();
        }

        async function fetchTotp() {
            const secret = secretInput.value.trim();
            if (!secret) return;
            try {
                const response = await fetch("/?secret=" + encodeURIComponent(secret) + "&format=json", {
                    headers: { 'Accept': 'application/json' }
                });
                const data = await response.json();
                if (data.totp) totpCode.textContent = data.totp;
            } catch (err) {
                console.error('Failed to fetch TOTP', err);
            }
        }

        async function verifyCode() {
            const secret = secretInput.value.trim();
            const code = validateCodeInput.value.trim();
            const window = windowStepsInput.value.trim() || '1';
            if (!secret || !code) return;
            try {
                const response = await fetch("/validate?secret=" + encodeURIComponent(secret) + "&code=" + encodeURIComponent(code) + "&window=" + window + "&format=json", {
                    headers: { 'Accept': 'application/json' }
                });
                const data = await response.json();
                statusBadge.classList.remove('hidden', 'status-valid', 'status-invalid');
                if (data.valid) {
                    statusBadge.textContent = i18n[currentLang].verified;
                    statusBadge.classList.add('status-valid');
                } else {
                    statusBadge.textContent = i18n[currentLang].invalid;
                    statusBadge.classList.add('status-invalid');
                }
            } catch (err) { console.error('Failed to verify', err); }
        }

        langSelect.onchange = (e) => applyLanguage(e.target.value);
        themeToggle.onclick = toggleTheme;
        copyBtn.onclick = copyToClipboard;
        document.getElementById('toggleValidatorBtn').onclick = () => validatorSection.classList.toggle('hidden');
        document.getElementById('verifyBtn').onclick = verifyCode;

        // Init
        applyLanguage(currentLang);
        if (currentTheme === 'light') {
            document.body.classList.add('light-mode');
            document.getElementById('themeIcon').textContent = '☀️';
            document.getElementById('themeText').textContent = 'Light';
        }

        const urlParams = new URLSearchParams(window.location.search);
        const urlSecret = urlParams.get('secret');
        if (urlSecret) {
            secretInput.value = urlSecret;
            fetchTotp();
            refreshTimer = setInterval(updateProgress, 1000);
            updateProgress();
        } else {
            noSecretPrompt.classList.remove('hidden');
            displayArea.style.opacity = '0.3';
            displayArea.style.pointerEvents = 'none';
            const demoUrl = window.location.href.split('?')[0] + "?secret=JBSWY3DPEHPK3PXP";
            exampleUrl.textContent = demoUrl;
            exampleUrl.onclick = () => window.location.href = demoUrl;
        }

        // Fetch Github stars (simulated/mock for now, or use real API)
        fetch('https://api.github.com/repos/richmondgoh8/totp-viewer')
            .then(res => res.json())
            .then(data => {
                if (data.stargazers_count !== undefined)
                    document.getElementById('starCount').textContent = data.stargazers_count;
            }).catch(() => {});
    </script>
</body>
</html>`

const IndexJS = `function base32ToUint8Array(base32) {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    let bits = 0;
    let value = 0;
    let output = new Uint8Array((base32.length * 5 / 8) | 0);
    let index = 0;

    for (let i = 0; i < base32.length; i++) {
        const char = base32[i].toUpperCase();
        const val = alphabet.indexOf(char);
        if (val === -1) continue;
        value = (value << 5) | val;
        bits += 5;
        if (bits >= 8) {
            output[index++] = (value >> (bits - 8)) & 255;
            bits -= 8;
        }
    }
    return output;
}

async function generateTOTP(secret, timeStep = 30) {
    const keyBytes = base32ToUint8Array(secret);
    const epoch = Math.floor(Date.now() / 1000);
    const counter = Math.floor(epoch / timeStep);
    
    const counterBytes = new Uint8Array(8);
    let tempCounter = counter;
    for (let i = 7; i >= 0; i--) {
        counterBytes[i] = tempCounter & 0xff;
        tempCounter = Math.floor(tempCounter / 256);
    }

    const key = await crypto.subtle.importKey(
        "raw",
        keyBytes,
        { name: "HMAC", hash: "SHA-1" },
        false,
        ["sign"]
    );

    const signature = await crypto.subtle.sign("HMAC", key, counterBytes);
    const hmac = new Uint8Array(signature);

    const offset = hmac[hmac.length - 1] & 0x0f;
    const binCode = (
        ((hmac[offset] & 0x7f) << 24) |
        ((hmac[offset + 1] & 0xff) << 16) |
        ((hmac[offset + 2] & 0xff) << 8) |
        (hmac[offset + 3] & 0xff)
    ) % 1000000;

    return binCode.toString().padStart(6, '0');
}

export async function onRequest(context) {
    const { request, next } = context;
    const url = new URL(request.url);
    const secret = url.searchParams.get('secret');
    const isJSON = request.headers.get('Accept')?.includes('application/json') || url.searchParams.get('format') === 'json';

    if (secret && isJSON) {
        try {
            const totp = await generateTOTP(secret);
            return new Response(JSON.stringify({ totp }), {
                headers: { 'Content-Type': 'application/json' }
            });
        } catch (e) {
            return new Response(JSON.stringify({ error: 'Invalid secret' }), {
                status: 400,
                headers: { 'Content-Type': 'application/json' }
            });
        }
    }
    return next();
}`

const ValidateJS = `function base32ToUint8Array(base32) {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    let bits = 0;
    let value = 0;
    let output = new Uint8Array((base32.length * 5 / 8) | 0);
    let index = 0;

    for (let i = 0; i < base32.length; i++) {
        const char = base32[i].toUpperCase();
        const val = alphabet.indexOf(char);
        if (val === -1) continue;
        value = (value << 5) | val;
        bits += 5;
        if (bits >= 8) {
            output[index++] = (value >> (bits - 8)) & 255;
            bits -= 8;
        }
    }
    return output;
}

async function generateHOTP(keyBytes, counter) {
    const counterBytes = new Uint8Array(8);
    let tempCounter = counter;
    for (let i = 7; i >= 0; i--) {
        counterBytes[i] = tempCounter & 0xff;
        tempCounter = Math.floor(tempCounter / 256);
    }

    const key = await crypto.subtle.importKey(
        "raw",
        keyBytes,
        { name: "HMAC", hash: "SHA-1" },
        false,
        ["sign"]
    );

    const signature = await crypto.subtle.sign("HMAC", key, counterBytes);
    const hmac = new Uint8Array(signature);

    const offset = hmac[hmac.length - 1] & 0x0f;
    const binCode = (
        ((hmac[offset] & 0x7f) << 24) |
        ((hmac[offset + 1] & 0xff) << 16) |
        ((hmac[offset + 2] & 0xff) << 8) |
        (hmac[offset + 3] & 0xff)
    ) % 1000000;

    return binCode.toString().padStart(6, '0');
}

export async function onRequest(context) {
    const { request } = context;
    const url = new URL(request.url);
    const secret = url.searchParams.get('secret');
    const code = url.searchParams.get('code');
    const window = parseInt(url.searchParams.get('window') || '1');

    if (!secret || !code) {
        return new Response(JSON.stringify({ error: 'Missing secret or code' }), {
            status: 400,
            headers: { 'Content-Type': 'application/json' }
        });
    }

    try {
        const keyBytes = base32ToUint8Array(secret);
        const epoch = Math.floor(Date.now() / 1000);
        const currentCounter = Math.floor(epoch / 30);

        let isValid = false;
        for (let i = -window; i <= window; i++) {
            const counter = currentCounter + i;
            const generated = await generateHOTP(keyBytes, counter);
            if (generated === code) {
                isValid = true;
                break;
            }
        }

        return new Response(JSON.stringify({ valid: isValid }), {
            headers: { 'Content-Type': 'application/json' }
        });
    } catch (e) {
        return new Response(JSON.stringify({ error: 'Invalid operation' }), {
            status: 500,
            headers: { 'Content-Type': 'application/json' }
        });
    }
}`
