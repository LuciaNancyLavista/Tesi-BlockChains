// fidoac.js – Client-side interceptor for SD-JWT Key Binding
//
// This module monkey-patches navigator.credentials.create() exclusively during
// the one-time Credential Registration phase. It is NOT active during Standard
// FIDO2 Login (navigator.credentials.get() is left completely unmodified).
//
// Updated binding formula:
//   c_modified = c || SHA-256(KB-JWT)
//
// The KB-JWT (Key Binding JWT) already contains sd_hash = SHA-256(SD-JWT_pres),
// so the FIDO2 hardware signature transitively covers the entire chain:
//   FIDO2_sig → KB-JWT → SD-JWT_pres
//
// This is stricter than the original c_modified = c || SHA-256(SD-JWT_pres):
// the FIDO2 signature now also commits to the holder's KB-JWT signature,
// meaning the hardware assertion cryptographically links:
//   (a) physical device presence  (FIDO2 hardware key)
//   (b) credential ownership      (holder private key, via KB-JWT)
//   (c) this specific session     (RP challenge c, in KB-JWT.nonce)
//   (d) this specific credential  (KB-JWT.sd_hash)

// Store originals before monkey-patching
const originalCredentialsCreate = navigator.credentials.create.bind(navigator.credentials);
const originalCredentialsGet    = navigator.credentials.get.bind(navigator.credentials);

// Shared state: the Wallet sets this to the KB-JWT string before triggering registration.
// fidoac.js reads it, hashes it, and injects the hash into the WebAuthn challenge.
window.__fidoac_kbjwt = null;

/**
 * Computes SHA-256 of a UTF-8 string and returns raw bytes as ArrayBuffer.
 */
async function sha256ToBytes(str) {
    return crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
}

/**
 * Initializes the fidoac.js interceptor.
 * Call once at application startup (before any WebAuthn operation).
 */
export function initFidoAC() {
    console.log('🔒 [fidoac.js] Initializing FIDO2 interceptor for Key-Bound Mediator-Free registration...');

    // ── Intercept create() for Credential Registration ────────────────────────
    navigator.credentials.create = async function (options) {
        if (options.publicKey && window.__fidoac_kbjwt) {
            console.log('🔒 [fidoac.js] KB-JWT found. Intercepting WebAuthn registration challenge...');

            // 1. Original challenge bytes (c)
            const c_bytes = new Uint8Array(options.publicKey.challenge);

            // 2. SHA-256(KB-JWT) bytes  ← NEW: hash the KB-JWT, not the raw SD-JWT
            const kbJwtHashBuf = await sha256ToBytes(window.__fidoac_kbjwt);
            const kbJwt_hash_bytes = new Uint8Array(kbJwtHashBuf);

            // 3. c_modified = c || SHA-256(KB-JWT)  [updated binding formula]
            const combined = new Uint8Array(c_bytes.length + kbJwt_hash_bytes.length);
            combined.set(c_bytes);
            combined.set(kbJwt_hash_bytes, c_bytes.length);

            console.log(`🔒 [fidoac.js] c_modified = c || SHA-256(KB-JWT). Appended ${kbJwt_hash_bytes.length} bytes.`);

            // 4. Inject modified challenge into WebAuthn options
            options.publicKey.challenge = combined;

            // 5. Let the hardware authenticator sign c_modified
            const credential = await originalCredentialsCreate(options);
            console.log('🔒 [fidoac.js] Hardware signature obtained on c_modified. Chain: FIDO2 → KB-JWT → SD-JWT.');
            return credential;
        }

        // No KB-JWT present: standard WebAuthn behavior (no modification)
        return originalCredentialsCreate(options);
    };

    // ── Leave get() completely untouched (Standard FIDO2 Login) ──────────────
    navigator.credentials.get = async function (options) {
        // Standard FIDO2 Login: fidoac.js does NOT intercept this call.
        // Zero SD-JWT overhead on all subsequent authentications.
        return originalCredentialsGet(options);
    };
}



