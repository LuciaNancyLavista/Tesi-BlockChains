// Wallet.js – Local Wallet with SD-JWT Key Binding (KB-JWT) support
// Two independent keys serve complementary roles:
//   1. holderPrivKey / holderPubKey  → ECDSA P-256 software key (Web Crypto)
//      Signs the Key Binding JWT, proving legitimate credential ownership.
//   2. SK_FIDO (hardware-bound)      → WebAuthn/FIDO2, non-exportable
//      Signs c_modified = c || SHA-256(KB-JWT), proving physical device presence.

export class LocalWallet {
    constructor() {
        this.credential = null;           
        this.disclosures = null;          
        this.tslIndex = null;             
        this.holderPrivKey = null;        
        this.holderPublicKeyJwk = null;   
    }

    // ─── Persistence (localStorage) ───────────────────────────────────────────
    
    async loadFromStorage() {
        const storedCred = localStorage.getItem('wallet_credential');
        if (storedCred) {
            const data = JSON.parse(storedCred);
            this.credential = data.credential;
            this.disclosures = data.disclosures;
            this.tslIndex = data.tslIndex;
            this.holderPublicKeyJwk = data.holderPublicKeyJwk;
            
            // Re-import the private key
            if (data.holderPrivKeyJwk) {
                this.holderPrivKey = await crypto.subtle.importKey(
                    'jwk',
                    data.holderPrivKeyJwk,
                    { name: 'ECDSA', namedCurve: 'P-256' },
                    true,
                    ['sign']
                );
            }
            console.log('💳 [Wallet] State restored from localStorage.');
            return true;
        }
        return false;
    }

    async saveToStorage() {
        // Export private key to save it (in a real app, use Secure Enclave or non-extractable IndexedDB)
        let privJwk = null;
        if (this.holderPrivKey) {
            privJwk = await crypto.subtle.exportKey('jwk', this.holderPrivKey);
        }

        const data = {
            credential: this.credential,
            disclosures: this.disclosures,
            tslIndex: this.tslIndex,
            holderPublicKeyJwk: this.holderPublicKeyJwk,
            holderPrivKeyJwk: privJwk
        };
        localStorage.setItem('wallet_credential', JSON.stringify(data));
    }

    clearStorage() {
        localStorage.removeItem('wallet_credential');
        this.credential = null;
        this.disclosures = null;
        this.tslIndex = null;
        this.holderPrivKey = null;
        this.holderPublicKeyJwk = null;
    }

    // ─── Holder Keypair ───────────────────────────────────────────────────────

    async generateHolderKeypair() {
        const keypair = await crypto.subtle.generateKey(
            { name: 'ECDSA', namedCurve: 'P-256' },
            true,          // set to true to allow saving in localStorage for the demo
            ['sign', 'verify']
        );
        this.holderPrivKey = keypair.privateKey;
        this.holderPublicKeyJwk = await crypto.subtle.exportKey('jwk', keypair.publicKey);
        console.log('💳 [Wallet] Holder keypair (ECDSA P-256) generated.');
        return this.holderPublicKeyJwk;
    }

    // ─── Credential Storage ───────────────────────────────────────────────────

    async storeCredential(sdjwt, disclosures, tslIndex) {
        this.credential = sdjwt;
        this.disclosures = disclosures;
        this.tslIndex = tslIndex;
        console.log(`💳 [Wallet] Credential stored. TSL Index: ${tslIndex}`);
        await this.saveToStorage();
    }

    // ─── Selective Disclosure ─────────────────────────────────────────────────

    createPresentation(requestedAttributes) {
        if (!this.credential) throw new Error('No credential in wallet');

        console.log(`💳 [Wallet] Creating selective disclosure for: ${requestedAttributes.join(', ')}`);

        const selectedDisclosures = {};
        for (const attr of requestedAttributes) {
            if (this.disclosures[attr]) {
                selectedDisclosures[attr] = this.disclosures[attr];
            } else {
                console.warn(`💳 [Wallet] Attribute '${attr}' not found in credential.`);
            }
        }

        window.__fidoac_sdjwt_presentation = this.credential;
        return { sdjwt: this.credential, disclosures: selectedDisclosures };
    }

    // ─── Key Binding JWT ──────────────────────────────────────────────────────

    async signKbJwt(originalChallenge, sdJwtPresentation, rpOrigin) {
        if (!this.holderPrivKey) {
            throw new Error('Holder keypair not initialized.');
        }

        const sdJwtBytes = new TextEncoder().encode(sdJwtPresentation);
        const sdHashBuf = await crypto.subtle.digest('SHA-256', sdJwtBytes);
        const sdHash = btoa(String.fromCharCode(...new Uint8Array(sdHashBuf)))
            .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');

        const header  = { alg: 'ES256', typ: 'kb+jwt' };
        const payload = {
            iat:     Math.floor(Date.now() / 1000),
            aud:     rpOrigin,
            nonce:   originalChallenge,   
            sd_hash: sdHash               
        };

        const b64url = (obj) => btoa(JSON.stringify(obj))
            .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');

        const signingInput = `${b64url(header)}.${b64url(payload)}`;

        const sigBuf = await crypto.subtle.sign(
            { name: 'ECDSA', hash: { name: 'SHA-256' } },
            this.holderPrivKey,
            new TextEncoder().encode(signingInput)
        );

        const sigB64url = btoa(String.fromCharCode(...new Uint8Array(sigBuf)))
            .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');

        const kbJwt = `${signingInput}.${sigB64url}`;
        return kbJwt;
    }

    clearPresentation() {
        window.__fidoac_sdjwt_presentation = null;
    }
}

