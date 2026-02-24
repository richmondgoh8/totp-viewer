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
    <title>TOTP Viewer | Modern 2FA</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --primary: #6366f1;
            --primary-glow: rgba(99, 102, 241, 0.5);
            --bg: #0f172a;
            --card-bg: rgba(30, 41, 59, 0.7);
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --success: #22c55e;
            --error: #ef4444;
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Outfit', sans-serif;
            background-color: var(--bg);
            background-image: 
                radial-gradient(circle at 0% 0%, rgba(99, 102, 241, 0.15) 0%, transparent 50%),
                radial-gradient(circle at 100% 100%, rgba(139, 92, 246, 0.15) 0%, transparent 50%);
            color: var(--text-main);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
            overflow-x: hidden;
        }

        .container {
            width: 100%;
            max-width: 480px;
            position: relative;
        }

        .container::before {
            content: '';
            position: absolute;
            top: -50px;
            left: -50px;
            width: 150px;
            height: 150px;
            background: var(--primary);
            filter: blur(80px);
            opacity: 0.3;
            z-index: -1;
        }

        .card {
            background: var(--card-bg);
            backdrop-filter: blur(12px);
            -webkit-backdrop-filter: blur(12px);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 24px;
            padding: 40px;
            box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
            text-align: center;
            transition: transform 0.3s ease;
        }

        h1 {
            font-size: 1.5rem;
            font-weight: 700;
            margin-bottom: 8px;
            letter-spacing: -0.025em;
        }

        .subtitle {
            color: var(--text-muted);
            font-size: 0.875rem;
            margin-bottom: 32px;
        }

        .totp-display {
            background: rgba(15, 23, 42, 0.5);
            border-radius: 16px;
            padding: 24px 24px 34px 24px;
            margin-bottom: 32px;
            border: 1px solid rgba(255, 255, 255, 0.05);
            position: relative;
            overflow: hidden;
        }

        .code {
            font-size: 4rem;
            font-weight: 700;
            letter-spacing: 0.15em;
            color: var(--text-main);
            text-shadow: 0 0 20px rgba(255, 255, 255, 0.1);
            font-variant-numeric: tabular-nums;
        }

        .timer-badge {
            position: absolute;
            bottom: 12px;
            right: 16px;
            font-size: 0.75rem;
            font-weight: 700;
            color: var(--primary);
            background: rgba(99, 102, 241, 0.1);
            padding: 2px 8px;
            border-radius: 6px;
            letter-spacing: 0.05em;
        }

        .progress-bar-container {
            position: absolute;
            bottom: 0;
            left: 0;
            width: 100%;
            height: 4px;
            background: rgba(255, 255, 255, 0.05);
        }

        .progress-bar {
            height: 100%;
            background: var(--primary);
            width: 100%;
            transition: width 1s linear;
            box-shadow: 0 0 10px var(--primary-glow);
        }

        .secret-input-group {
            text-align: left;
            margin-bottom: 24px;
        }

        label {
            display: block;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--text-muted);
            margin-bottom: 8px;
            margin-left: 4px;
        }

        input {
            width: 100%;
            background: rgba(15, 23, 42, 0.8);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 12px;
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

        button {
            padding: 14px;
            border-radius: 12px;
            border: none;
            font-family: inherit;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s ease;
        }

        .btn-primary {
            background: var(--primary);
            color: white;
            box-shadow: 0 4px 12px var(--primary-glow);
        }

        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 16px var(--primary-glow);
        }

        .btn-secondary {
            background: rgba(255, 255, 255, 0.05);
            color: var(--text-main);
            border: 1px solid rgba(255, 255, 255, 0.1);
        }

        .btn-secondary:hover {
            background: rgba(255, 255, 255, 0.1);
        }

        .hidden {
            display: none;
        }

        .validator-section {
            margin-top: 32px;
            padding-top: 32px;
            border-top: 1px solid rgba(255, 255, 255, 0.1);
        }

        .status-badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 100px;
            font-size: 0.75rem;
            font-weight: 600;
            margin-bottom: 16px;
        }

        .status-valid { background: rgba(34, 197, 94, 0.2); color: var(--success); }
        .status-invalid { background: rgba(239, 68, 68, 0.2); color: var(--error); }

        @media (max-width: 480px) {
            .card {
                padding: 30px 20px;
            }
            .code {
                font-size: 3rem;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="card">
            <h1>TOTP Viewer</h1>
            <p class="subtitle">Secure Time-Based Passwords</p>

            <div class="totp-display" id="displayArea">
                <div class="code" id="totpCode">------</div>
                <div class="timer-badge"><span id="timerText">30</span>s remaining</div>
                <div class="progress-bar-container">
                    <div class="progress-bar" id="progressBar"></div>
                </div>
            </div>

            <div class="secret-input-group">
                <label for="secret">Shared Secret (Bookmarkable)</label>
                <input type="text" id="secret" readonly placeholder="Add ?secret= to URL" autocomplete="off">
            </div>

            <div id="noSecretPrompt" class="hidden" style="margin-bottom: 24px; color: var(--text-muted); font-size: 0.8rem; background: rgba(99, 102, 241, 0.1); padding: 12px; border-radius: 12px; border: 1px dashed var(--primary);">
                ⚠️ <b>Secret Missing:</b> Please use a URL with a secret parameter, e.g.:<br>
                <code id="exampleUrl" style="display: block; margin-top: 8px; color: var(--primary); cursor: pointer; text-decoration: underline;"></code>
            </div>

            <div class="actions">
                <button class="btn-primary hidden" id="generateBtn">Update Code</button>
                <button class="btn-secondary" id="toggleValidatorBtn" style="grid-column: span 2;">Validate Code</button>
            </div>

            <div id="validatorSection" class="validator-section hidden">
                <div id="statusBadge" class="status-badge hidden"></div>
                <div class="secret-input-group">
                    <label for="validateCode">Enter Code to Verify</label>
                    <input type="text" id="validateCode" placeholder="123456" maxlength="6">
                </div>
                <div class="secret-input-group">
                    <label for="windowSteps">Tolerance Window (Steps: 30s each)</label>
                    <input type="number" id="windowSteps" value="1" min="0" max="20">
                </div>
                <button class="btn-primary" style="width:100%" id="verifyBtn">Verify Now</button>
            </div>
        </div>
    </div>

    <script>
        const secretInput = document.getElementById('secret');
        const totpCode = document.getElementById('totpCode');
        const progressBar = document.getElementById('progressBar');
        const timerText = document.getElementById('timerText');
        const generateBtn = document.getElementById('generateBtn');
        const toggleValidatorBtn = document.getElementById('toggleValidatorBtn');
        const validatorSection = document.getElementById('validatorSection');
        const validateCodeInput = document.getElementById('validateCode');
        const windowStepsInput = document.getElementById('windowSteps');
        const verifyBtn = document.getElementById('verifyBtn');
        const statusBadge = document.getElementById('statusBadge');
        const noSecretPrompt = document.getElementById('noSecretPrompt');
        const exampleUrl = document.getElementById('exampleUrl');
        const displayArea = document.getElementById('displayArea');

        let refreshTimer = null;

        function updateProgress() {
            const now = new Date();
            const seconds = now.getSeconds() % 30;
            const remaining = 30 - seconds;
            const progress = (remaining / 30) * 100;
            
            progressBar.style.width = progress + '%';
            timerText.textContent = remaining;
            
            if (seconds === 0) {
                fetchTotp();
            }
        }

        async function fetchTotp() {
            const secret = secretInput.value.trim();
            if (!secret) return;

            try {
                const response = await fetch("/?secret=" + encodeURIComponent(secret) + "&format=json", {
                    headers: { 'Accept': 'application/json' }
                });
                const data = await response.json();
                if (data.totp) {
                    totpCode.textContent = data.totp;
                }
            } catch (err) {
                console.error('Failed to fetch TOTP', err);
            }
        }

        async function verifyCode() {
            const secret = secretInput.value.trim();
            const code = validateCodeInput.value.trim();
            const window = windowStepsInput.value.trim() || "1";
            if (!secret || !code) return;

            try {
                const response = await fetch("/validate?secret=" + encodeURIComponent(secret) + "&code=" + encodeURIComponent(code) + "&window=" + window + "&format=json", {
                    headers: { 'Accept': 'application/json' }
                });
                const data = await response.json();
                
                statusBadge.classList.remove('hidden', 'status-valid', 'status-invalid');
                if (data.valid) {
                    statusBadge.textContent = '✅ VERIFIED';
                    statusBadge.classList.add('status-valid');
                } else {
                    statusBadge.textContent = '❌ INVALID CODE';
                    statusBadge.classList.add('status-invalid');
                }
            } catch (err) {
                console.error('Failed to verify', err);
            }
        }

        generateBtn.addEventListener('click', () => {
            fetchTotp();
            if (!refreshTimer) {
                refreshTimer = setInterval(updateProgress, 1000);
                updateProgress();
            }
        });

        toggleValidatorBtn.addEventListener('click', () => {
            validatorSection.classList.toggle('hidden');
        });

        verifyBtn.addEventListener('click', verifyCode);

        const urlParams = new URLSearchParams(window.location.search);
        const urlSecret = urlParams.get('secret');
        
        if (urlSecret) {
            secretInput.value = urlSecret;
            fetchTotp();
            refreshTimer = setInterval(updateProgress, 1000);
            updateProgress();
        } else {
            // Show prompt if no secret in URL
            noSecretPrompt.classList.remove('hidden');
            displayArea.style.opacity = '0.3';
            displayArea.style.pointerEvents = 'none';
            
            const currentUrl = window.location.href.split('?')[0];
            const demoUrl = currentUrl + "?secret=JBSWY3DPEHPK3PXP";
            exampleUrl.textContent = demoUrl;
            exampleUrl.onclick = () => window.location.href = demoUrl;
        }
    </script>
</body>
</html>`

const IndexJS = `
function base32ToUint8Array(base32) {
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

    if (secret) {
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
}
`

const ValidateJS = `
function base32ToUint8Array(base32) {
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
}
`
