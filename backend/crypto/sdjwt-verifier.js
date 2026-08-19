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
            issuerDid: payload.iss
        };
        
    } catch (error) {
        console.error("SD-JWT Verification failed:", error);
        return { verified: false, error: error.message };
    }
}
