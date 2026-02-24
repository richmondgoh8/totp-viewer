package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// decodeBase32 cleans the secret and adds padding if necessary.
// Many authenticator apps provide unpadded base32 strings.
func decodeBase32(secret string) ([]byte, error) {
	secret = strings.ToUpper(strings.ReplaceAll(secret, " ", ""))
	if pad := len(secret) % 8; pad != 0 {
		secret += strings.Repeat("=", 8-pad)
	}
	return base32.StdEncoding.DecodeString(secret)
}

// generateHOTP generates a single HOTP code based on RFC 4226.
func generateHOTP(secretBytes []byte, counter uint64) string {
	// 1. Create HMAC-SHA1
	h := hmac.New(sha1.New, secretBytes)
	binary.Write(h, binary.BigEndian, counter)
	sum := h.Sum(nil)

	// 2. Dynamic truncation (RFC 4226)
	offset := sum[len(sum)-1] & 0x0F
	value := int64(((int(sum[offset]) & 0x7F) << 24) |
		((int(sum[offset+1] & 0xFF)) << 16) |
		((int(sum[offset+2] & 0xFF)) << 8) |
		(int(sum[offset+3]) & 0xFF))

	// 3. Return a 6-digit code
	mod := value % 1000000
	return fmt.Sprintf("%06d", mod)
}

// generateTOTP calculates the current time step and wraps generateHOTP.
func generateTOTP(secret string, t time.Time) (string, error) {
	secretBytes, err := decodeBase32(secret)
	if err != nil {
		return "", fmt.Errorf("invalid base32 secret")
	}
	counter := uint64(t.Unix() / 30) // Standard 30-second step
	return generateHOTP(secretBytes, counter), nil
}

// validateTOTP checks if a provided passcode is valid for the given secret.
// windowSteps defines the drift tolerance. Each step is 30 seconds.
//
//	windowSteps = 0  -> strict 30 second window (current time only)
//	windowSteps = 1  -> +/- 30 seconds (1 minute 30 seconds total validity window)
//	windowSteps = 10 -> +/- 5 minutes
func validateTOTP(passcode string, secret string, windowSteps int) bool {
	secretBytes, err := decodeBase32(secret)
	if err != nil {
		return false
	}

	currentCounter := time.Now().Unix() / 30

	// Check the current time, as well as 'windowSteps' before and after
	for i := -windowSteps; i <= windowSteps; i++ {
		counter := uint64(currentCounter + int64(i))
		if generateHOTP(secretBytes, counter) == passcode {
			return true
		}
	}
	return false
}

// UI Handler: Shows the TOTP on a web page, driven by the ?secret= URL parameter
func handleUI(w http.ResponseWriter, r *http.Request) {
	secret := r.URL.Query().Get("secret")
	if secret == "" {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `<h1>Missing Secret</h1><p>Provide a secret parameter, e.g.: <a href="/?secret=JBSWY3DPEHPK3PXP">/?secret=JBSWY3DPEHPK3PXP</a></p>`)
		return
	}

	totp, err := generateTOTP(secret, time.Now())
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "<h1>Error</h1><p>Invalid secret format.</p>")
		return
	}

	// Simple UI that auto-refreshes every 5 seconds to keep the TOTP updated visually
	html := `<!DOCTYPE html>
	<html>
	<head>
		<title>TOTP Generator</title>
		<meta http-equiv="refresh" content="5">
		<style>
			body { font-family: sans-serif; text-align: center; margin-top: 100px; background-color: #f4f4f9;}
			.totp { font-size: 5em; font-weight: bold; letter-spacing: 10px; color: #111; margin: 20px 0; }
			.secret { color: #555; font-size: 1.2em; }
			.refresh { color: #888; font-size: 0.9em; margin-top: 40px;}
		</style>
	</head>
	<body>
		<h2>Your Authentication Code</h2>
		<div class="totp">%s</div>
		<div class="secret">Secret: <code>%s</code></div>
		<div class="refresh">Page auto-refreshes every 5 seconds</div>
	</body>
	</html>`

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, html, totp, secret)
}

// Validation API and UI endpoint
func handleValidate(w http.ResponseWriter, r *http.Request) {
	secret := r.URL.Query().Get("secret")
	code := r.URL.Query().Get("code")
	windowStr := r.URL.Query().Get("window")

	// If no secret is in the URL, prompt the user to add it
	if secret == "" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `<div style="font-family:sans-serif; text-align:center; padding: 50px;">
			<h2>Missing Secret</h2>
			<p>Please provide a secret in the URL, e.g.: <br><code>/validate?secret=JBSWY3DPEHPK3PXP</code></p>
		</div>`)
		return
	}

	// Parse the window parameter (defaults to 0, strict 30s)
	windowSteps := 0
	if windowStr != "" {
		if wInt, err := strconv.Atoi(windowStr); err == nil {
			windowSteps = wInt
		}
	} else {
		windowStr = "0" // Default for the HTML form
	}

	// Determine the UI state (Neutral, Valid, or Invalid)
	resultHTML := `<div class="result neutral">Enter code to validate</div>`
	detailsHTML := `<div class="details">1 step = 30 seconds of allowance</div>`

	if code != "" {
		isValid := validateTOTP(code, secret, windowSteps)
		if isValid {
			resultHTML = `<div class="result valid">✅ VALID</div>`
			detailsHTML = fmt.Sprintf(`<div class="details">Code '%s' perfectly matches within a &plusmn;%d step (%d minute) window.</div>`, code, windowSteps, (windowSteps*30)/60)
		} else {
			resultHTML = `<div class="result invalid">❌ INVALID</div>`
			detailsHTML = fmt.Sprintf(`<div class="details">Code '%s' does not match the secret in the given window.</div>`, code)
		}
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// Pretty HTML UI with the secret hidden from the form inputs
	html := `<!DOCTYPE html>
	<html lang="en">
	<head>
		<meta charset="UTF-8">
		<title>TOTP Validator</title>
		<style>
			body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background-color: #f4f4f9; color: #333; display: flex; justify-content: center; padding-top: 50px; }
			.card { background: white; padding: 30px; border-radius: 12px; box-shadow: 0 4px 15px rgba(0,0,0,0.1); width: 100%%; max-width: 400px; text-align: center; }
			h2 { margin-top: 0; color: #222; }
			.secret-display { background: #f8f9fa; padding: 12px; border-radius: 6px; font-size: 0.9em; color: #555; margin-bottom: 20px; border: 1px solid #e9ecef; word-break: break-all; }
			.result { font-size: 1.5em; font-weight: bold; margin: 15px 0; padding: 15px; border-radius: 8px; }
			.valid { background-color: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
			.invalid { background-color: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
			.neutral { background-color: #e9ecef; color: #495057; border: 1px solid #dee2e6; font-size: 1.2em; }
			.details { font-size: 0.9em; color: #666; margin-bottom: 25px; min-height: 2em; }
			form { display: flex; flex-direction: column; gap: 15px; text-align: left; }
			label { font-weight: 600; font-size: 0.9em; color: #555; margin-bottom: 5px; display: block;}
			input[type="text"], input[type="number"] { padding: 10px; border: 1px solid #ccc; border-radius: 6px; font-size: 1.2em; width: 100%%; box-sizing: border-box; text-align: center; letter-spacing: 2px;}
			input:focus { border-color: #007bff; outline: none; box-shadow: 0 0 0 3px rgba(0,123,255,0.25); }
			button { padding: 12px; background-color: #007bff; color: white; border: none; border-radius: 6px; font-size: 1em; font-weight: bold; cursor: pointer; transition: background-color 0.2s; }
			button:hover { background-color: #0056b3; }
		</style>
	</head>
	<body>
		<div class="card">
			<h2>TOTP Validator</h2>
			<div class="secret-display">Validating against secret:<br><code>%s</code></div>
			
			%s
			%s
			
			<form method="GET" action="/validate">
				<!-- This hidden input ensures the secret stays in the URL when the form submits -->
				<input type="hidden" name="secret" value="%s">
				
				<div>
					<label>TOTP Code:</label>
					<input type="text" name="code" value="%s" placeholder="123456" autocomplete="off" autofocus required>
				</div>
				<div>
					<label>Tolerance Window (Steps):</label>
					<input type="number" name="window" value="%s" min="0" max="20" required>
				</div>
				<button type="submit">Verify Code</button>
			</form>
		</div>
	</body>
	</html>`

	// Inject variables into the HTML template
	fmt.Fprintf(w, html, secret, resultHTML, detailsHTML, secret, code, windowStr)
}

func main() {
	http.HandleFunc("/", handleUI)
	http.HandleFunc("/validate", handleValidate)

	fmt.Println("🚀 TOTP Server running at http://localhost:8080")
	fmt.Println("👉 Generator UI: http://localhost:8080/?secret=JBSWY3DPEHPK3PXP")
	fmt.Println("👉 Validator API: http://localhost:8080/validate?secret=JBSWY3DPEHPK3PXP&code=123456&window=10")

	log.Fatal(http.ListenAndServe(":8080", nil))
}
