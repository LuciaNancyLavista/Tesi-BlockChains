// js-sha256 removed in favor of native Web Crypto API

// Store original methods before monkey-patching
const originalCredentialsCreate = navigator.credentials.create.bind(navigator.credentials);
const originalCredentialsGet = navigator.credentials.get.bind(navigator.credentials);

// Global state to hold the SD-JWT that the wallet wants to present
// In a real browser extension this would be isolated, but for a web demo we keep it here
window.__fidoac_sdjwt_presentation = null;



/**
 * Hashes a string using SHA-256 and returns a raw ArrayBuffer
 */
async function hashSDJWTToBytes(presentationStr) {
    const encoder = new TextEncoder();
    const data = encoder.encode(presentationStr);
    return await crypto.subtle.digest('SHA-256', data);
}

/**
 * Inject our fidoac.js logic into the browser
 */
export function initFidoAC() {
    console.log("🔒 [fidoac.js] Initializing FIDO2 Interceptor for Mediator-Free Binding...");

    navigator.credentials.create = async function (options) {
        if (options.publicKey && window.__fidoac_sdjwt_presentation) {
            console.log("🔒 [fidoac.js] SD-JWT Presentation found. Intercepting WebAuthn challenge...");
            
            // 1. Get raw bytes of original challenge (c)
            const c_bytes = new Uint8Array(options.publicKey.challenge);
            
            // 2. Get raw bytes of the SD-JWT Presentation hash
            const hashBuffer = await hashSDJWTToBytes(window.__fidoac_sdjwt_presentation);
            const hash_bytes = new Uint8Array(hashBuffer);
            
            // 3. Compute c_modified = c || SHA-256(SD-JWT) via byte concatenation
            const combined = new Uint8Array(c_bytes.length + hash_bytes.length);
            combined.set(c_bytes);
            combined.set(hash_bytes, c_bytes.length);
            
            console.log(`🔒 [fidoac.js] Challenge modified. Appended ${hash_bytes.length} bytes of SD-JWT hash.`);
            
            // 4. Inject back into options
            options.publicKey.challenge = combined;
            
            // 5. Let the hardware authenticator sign the modified challenge
            const credential = await originalCredentialsCreate(options);
            
            console.log("🔒 [fidoac.js] Hardware signature obtained on c_modified.");
            return credential;
        }

        // Standard behavior if no SD-JWT is present
        return originalCredentialsCreate(options);
    };

    navigator.credentials.get = async function (options) {
        // Standard FIDO2 Login uses unmodified WebAuthn (as per thesis)
        return originalCredentialsGet(options);
    };
}
