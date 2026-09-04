import { jwtVerify, importJWK } from 'jose';
import crypto from 'crypto';

// This validates b_sdjwt from the thesis
export async function verifySDJWT(sdJwt, disclosures, issuerPublicKeyJWK) {
    try {
        // 1. Verify Issuer Signature on the Base JWT
        const publicKey = await importJWK(issuerPublicKeyJWK, 'ES256');
        const { payload } = await jwtVerify(sdJwt, publicKey);
        
        // 1.5 Verify Token Status List (Revocation)
        if (payload.status && payload.status.status_list) {
            const idx = payload.status.status_list.idx;
            const tslRes = await fetch(payload.status.status_list.uri);
            const tsl = await tslRes.json();
            if (tsl.revoked.includes(idx)) {
                return { verified: false, error: `Credenziale REVOCATA (Token Status List all'indice bit ${idx} è 1)` };
            }
        }
        
        // 2. Extract the _sd array from the payload (these are the hashes the issuer signed)
        const signedHashes = payload._sd || [];
        
        // 3. Verify Disclosures
        const verifiedAttributes = {};
        
        for (const [claimName, disclosureString] of Object.entries(disclosures)) {
            // Hash the disclosure string provided by the wallet
            const hash = crypto.createHash('sha256').update(disclosureString).digest('base64url');
            
            // Check if this hash is in the _sd array signed by the Issuer
            if (!signedHashes.includes(hash)) {
                throw new Error(`Disclosure for ${claimName} is invalid or was not signed by the Issuer`);
            }
            
            // Parse the disclosure string: [salt, claimName, claimValue]
            const parsed = JSON.parse(Buffer.from(disclosureString, 'base64url').toString('utf-8'));
            if (parsed[1] !== claimName) {
                throw new Error(`Claim name mismatch in disclosure`);
            }
            
            // Store the verified value
            verifiedAttributes[claimName] = parsed[2];
        }
        
        return {
            verified: true,
            attributes: verifiedAttributes,
            issuerDid: payload.iss,
            cnfJwk: payload.cnf?.jwk || null,  // Return cnf.jwk for b_cnf verification
            tslIndex: payload.status?.status_list?.idx
        };
        
    } catch (error) {
        console.error("SD-JWT Verification failed:", error);
        return { verified: false, error: error.message };
    }
}

// ─── b_cnf: Key Binding JWT Verification ─────────────────────────────────────
//
// Verifies that the KB-JWT was signed by the holder of cnf.jwk embedded in the SD-JWT.
// This proves that the presenter is the legitimate credential owner, not just someone
// who obtained a copy of the SD-JWT.
//
// Verification steps:
//   1. Import cnf.jwk from the SD-JWT payload as an ECDSA P-256 public key
//   2. Verify the KB-JWT signature against that key
//   3. Verify that kbJwtPayload.sd_hash == SHA-256(sdJwtPresentation)
//      (ensures the KB-JWT is bound to this specific credential presentation)
//
// An attacker who obtains someone else's SD-JWT cannot produce a valid KB-JWT
// because they do not possess the corresponding holderPrivKey.
export async function verifyCnf(cnfJwk, kbJwt, sdJwtPresentation) {
    try {
        if (!cnfJwk) {
            throw new Error('SD-JWT does not contain a cnf claim. Key Binding is required.');
        }

        // 1. Import holder's public key from cnf.jwk
        const holderPublicKey = await importJWK(cnfJwk, 'ES256');

        // 2. Verify KB-JWT signature (jose handles ES256 verification)
        const { payload: kbPayload } = await jwtVerify(kbJwt, holderPublicKey, {
            typ: 'kb+jwt'
        });

        // 3. Verify sd_hash: KB-JWT must commit to this specific SD-JWT presentation
        const expectedSdHash = crypto
            .createHash('sha256')
            .update(sdJwtPresentation)
            .digest('base64url');

        if (kbPayload.sd_hash !== expectedSdHash) {
            throw new Error(
                `KB-JWT sd_hash mismatch: expected ${expectedSdHash}, got ${kbPayload.sd_hash}`
            );
        }

        console.log('[b_cnf] KB-JWT verified. Holder legitimacy confirmed.');
        return { verified: true, kbPayload };

    } catch (error) {
        console.error('[b_cnf] KB-JWT verification failed:', error.message);
        return { verified: false, error: error.message };
    }
}

