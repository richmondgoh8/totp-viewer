//go:build wasm
package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"strings"
	"syscall/js"
	"time"
)

const StepSize = 30

func main() {
	c := make(chan struct{}, 0)

	js.Global().Set("generateTOTPGo", js.FuncOf(generateTOTPGo))
	js.Global().Set("validateTOTPGo", js.FuncOf(validateTOTPGo))

	<-c
}

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

// --- JS Wrappers ---

func generateTOTPGo(this js.Value, args []js.Value) any {
	if len(args) < 1 {
		return js.ValueOf(map[string]any{"error": "missing secret"})
	}
	secret := args[0].String()
	totp, err := generateTOTP(secret, time.Now())
	if err != nil {
		return js.ValueOf(map[string]any{"error": err.Error()})
	}
	return js.ValueOf(map[string]any{"totp": totp})
}

func validateTOTPGo(this js.Value, args []js.Value) any {
	if len(args) < 3 {
		return js.ValueOf(map[string]any{"error": "missing arguments"})
	}
	secret := args[0].String()
	code := args[1].String()
	window := args[2].Int()

	isValid := validateTOTP(code, secret, window)
	return js.ValueOf(map[string]any{"valid": isValid})
}
