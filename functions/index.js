
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
