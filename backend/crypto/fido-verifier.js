import { verifyRegistrationResponse } from '@simplewebauthn/server';
import crypto from 'crypto';

// This validates b_FIDO from the thesis
export async function verifyFIDOSignature(credential, expectedChallenge, expectedOrigin) {
    try {
        const verification = await verifyRegistrationResponse({
            response: credential,
            expectedChallenge: expectedChallenge,
            expectedOrigin: expectedOrigin,
            expectedRPID: new URL(expectedOrigin).hostname,
            requireUserVerification: false
        });

        return verification.verified;
    } catch (error) {
        console.error("FIDO Verification failed:", error);
        return false;
    }
}

// In the thesis, the wallet sends c_modified = c || SHA-256(KB-JWT)
// We need to verify that the challenge signed by FIDO matches what we expect
export function buildExpectedModifiedChallenge(originalChallenge, kbJwt) {
    // 1. Get raw bytes of the original challenge
    const challengeBuffer = Buffer.from(originalChallenge, 'base64url');
    
    // 2. Get raw bytes of the KB-JWT hash
    const hashBuffer = crypto.createHash('sha256').update(kbJwt).digest(); // raw bytes
    
    // 3. c_modified = c || hash (byte concatenation)
    const combinedBuffer = Buffer.concat([challengeBuffer, hashBuffer]);
    
    // Return as base64url so SimpleWebAuthn can accept it
    return combinedBuffer.toString('base64url');
}
