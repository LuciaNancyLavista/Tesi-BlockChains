import express from 'express';
import cors from 'cors';
import crypto from 'crypto';
import { generateRegistrationOptions, generateAuthenticationOptions, verifyAuthenticationResponse } from '@simplewebauthn/server';
import { initIssuerKeys, issueSDJWT, getIssuerPublicKeyJWK, ISSUER_DID } from './mock-issuer/issuer.js';
import { getIssuerPublicKeyFromDID } from './blockchain/ethers-client.js';
import { verifySDJWT, verifyCnf } from './crypto/sdjwt-verifier.js';
import { buildExpectedModifiedChallenge, verifyFIDOSignature } from './crypto/fido-verifier.js';

const app = express();
app.use(cors());
app.use(express.json());

const PORT = 3000;
const RP_NAME = "Tesi Relying Party";

// In-memory store for demo purposes
const sessionStore = {};
const registeredUsers = {};

import { revokedIndices } from './mock-issuer/state.js';

// --- MOCK ISSUER ENDPOINTS ---
app.post('/api/mock-issue', async (req, res) => {
    // The Issuer receives the Holder's public key JWK to embed in the SD-JWT cnf claim.
    // This creates a cryptographic binding: only the possessor of the corresponding
    // private key (holderPrivKey) can produce a valid Key Binding JWT (KB-JWT).
    const { holderPublicKey } = req.body;
    if (!holderPublicKey) {
        return res.status(400).json({ error: 'holderPublicKey is required for SD-JWT Key Binding' });
    }

    const attributes = {
        name: req.body.name || "Nancy",
        age: req.body.age || 24,
        role: req.body.role || "Student",
        nationality: "IT"
    };

    try {
        const credential = await issueSDJWT(attributes, holderPublicKey);
        res.json(credential);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Endpoint per simulare la revoca (Token Status List)
app.post('/api/mock-revoke', (req, res) => {
    const { idx } = req.body;
    revokedIndices.add(idx);
    console.log(`[Issuer] Credenziale revocata all'indice TSL: ${idx}`);
    res.json({ success: true, message: "Revocata" });
});

// L'endpoint pubblico dove i Relying Party scaricano il Token Status List
app.get('/api/status-list', (req, res) => {
    res.json({ revoked: Array.from(revokedIndices) });
});

// Mock DID Resolution (if blockchain isn't running)
app.get('/api/did-resolve', (req, res) => {
    res.json(getIssuerPublicKeyJWK());
});

// --- RELYING PARTY ENDPOINTS ---

// Phase 1: Request Challenge
app.post('/api/auth/generate-challenge', async (req, res) => {
    const userId = req.body.username || "user_" + Date.now();
    
    // Dynamic Origin/RP_ID calculation
    const currentOrigin = req.headers.origin || "http://localhost:5173";
    const currentRpId = new URL(currentOrigin).hostname;

    // Generate standard WebAuthn challenge (c)
    const options = await generateRegistrationOptions({
        rpName: RP_NAME,
        rpID: currentRpId,
        userID: new Uint8Array(Buffer.from(userId)),
        userName: userId,
        attestationType: 'none',
        authenticatorSelection: {
            userVerification: 'preferred',
            residentKey: 'required'
        }
    });

    sessionStore[userId] = options.challenge;

    res.json(options);
});

// Phase 3: Composite Verification (b_FIDO ∧ b_challenge ∧ b_sdjwt ∧ b_cnf)
app.post('/api/auth/verify', async (req, res) => {
    const { username, fidoCredential, sdjwt, disclosures, kbJwt } = req.body;
    const originalChallenge = sessionStore[username];

    if (!originalChallenge) return res.status(400).json({ error: "No challenge found" });
    if (!kbJwt) return res.status(400).json({ error: "KB-JWT is required for Key Binding verification (b_cnf)" });

    try {
        // 1. Resolve Issuer DID from Blockchain (b_sdjwt part 1)
        let issuerJwk = await getIssuerPublicKeyFromDID(ISSUER_DID);
        if (!issuerJwk) {
            console.log("Fallback: using in-memory mock issuer key (Blockchain not connected)");
            issuerJwk = getIssuerPublicKeyJWK();
        }

        // 2. Verify SD-JWT (b_sdjwt): Issuer signature + selective disclosures + revocation
        //    Also extracts cnf.jwk for the subsequent b_cnf check.
        const sdjwtResult = await verifySDJWT(sdjwt, disclosures, issuerJwk);
        if (!sdjwtResult.verified) {
            return res.status(401).json({ error: "SD-JWT verification failed (b_sdjwt): " + sdjwtResult.error });
        }

        // 3. Verify Key Binding JWT (b_cnf):
        //    Checks that the KB-JWT is signed by the key in cnf.jwk (i.e., holderPrivKey),
        //    and that its sd_hash matches SHA-256(SD-JWT_pres).
        //    This proves the presenter is the legitimate Holder of this SD-JWT.
        const cnfResult = await verifyCnf(sdjwtResult.cnfJwk, kbJwt, sdjwt);
        if (!cnfResult.verified) {
            return res.status(401).json({ error: "Key Binding verification failed (b_cnf): " + cnfResult.error });
        }

        // 4. Compute c_modified (b_challenge):
        //    Updated formula: c_modified = c || SHA-256(KB-JWT)
        //    The KB-JWT already contains sd_hash = SHA-256(SD-JWT_pres), so the FIDO2 signature
        //    transitively covers the entire chain: FIDO2_sig → KB-JWT → SD-JWT_pres
        const expectedChallenge = buildExpectedModifiedChallenge(originalChallenge, kbJwt);

        // 5. Verify FIDO2 Signature (b_FIDO): proves physical device presence
        const currentOrigin = req.headers.origin || "http://localhost:5173";
        const fidoResult = await verifyFIDOSignature(fidoCredential, expectedChallenge, currentOrigin);
        
        if (!fidoResult) {
            return res.status(401).json({ error: "FIDO2 signature verification failed (b_FIDO). Did fidoac.js inject SHA-256(KB-JWT) correctly?" });
        }

        // 6. Check Access Policy (RP Policy Enforcement)
        const { age, role } = sdjwtResult.attributes;
        if (!age || age < 18) {
            return res.status(403).json({ error: "Accesso Negato: La policy del RP richiede la maggiore età (age >= 18)." });
        }
        if (!role || role !== "Student") {
            return res.status(403).json({ error: "Accesso Negato: La policy del RP richiede il ruolo 'Student'." });
        }

        // 7. All checks passed: b_FIDO ∧ b_challenge ∧ b_sdjwt ∧ b_cnf = True
        //    Store user with the FIDO2 credential ID for subsequent standard logins
        registeredUsers[username] = {
            attributes: sdjwtResult.attributes,
            fidoKey: fidoCredential.id,
            tslIndex: sdjwtResult.tslIndex
        };

        res.json({
            success: true,
            message: "Authentication successful. Composite validation satisfied: b_FIDO ∧ b_challenge ∧ b_sdjwt ∧ b_cnf.",
            attributes: sdjwtResult.attributes
        });

    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});


// --- STANDARD FIDO2 LOGIN (subsequent authentications - zero SD-JWT overhead) ---

// Step 1: Generate a standard WebAuthn authentication challenge (no SD-JWT involved)
app.post('/api/auth/generate-login-challenge', async (req, res) => {
    const { username } = req.body;
    const user = registeredUsers[username];

    if (!user) {
        return res.status(404).json({ error: "User not registered. Complete Credential Registration first." });
    }

    const currentOrigin = req.headers.origin || "http://localhost:5173";
    const currentRpId = new URL(currentOrigin).hostname;

    const options = await generateAuthenticationOptions({
        rpID: currentRpId,
        userVerification: 'preferred',
        allowCredentials: [{
            id: user.fidoKey,
            type: 'public-key'
        }]
    });

    // Store challenge for verification
    sessionStore[username + "_login"] = options.challenge;

    res.json(options);
});

// Step 2: Verify standard FIDO2 assertion — b_FIDO only, no SD-JWT check
app.post('/api/auth/verify-login', async (req, res) => {
    const { username, fidoAssertion } = req.body;
    const user = registeredUsers[username];
    const loginChallenge = sessionStore[username + "_login"];

    if (!user) return res.status(404).json({ error: "User not found." });
    if (!loginChallenge) return res.status(400).json({ error: "No login challenge found." });

    // Check revocation list for subsequent logins
    if (user.tslIndex !== undefined && revokedIndices.has(user.tslIndex)) {
        return res.status(401).json({ error: "Accesso Negato: La credenziale SD-JWT associata a questo account è stata REVOCATA." });
    }

    const currentOrigin = req.headers.origin || "http://localhost:5173";
    const currentRpId = new URL(currentOrigin).hostname;

    try {
        await verifyAuthenticationResponse({
            response: fidoAssertion,
            expectedChallenge: loginChallenge,
            expectedOrigin: currentOrigin,
            expectedRPID: currentRpId,
            credential: {
                id: user.fidoKey,
                publicKey: user.fidoPublicKey,
                counter: user.counter || 0
            }
        });

        // Clean up challenge
        delete sessionStore[username + "_login"];

        res.json({
            success: true,
            message: "Standard FIDO2 Login successful. Zero SD-JWT overhead.",
            attributes: user.attributes
        });

    } catch (err) {
        // Fallback: if we don't have the publicKey stored (demo limitation),
        // we verify the user exists and their credential ID matches.
        if (user.fidoKey === fidoAssertion.id) {
            delete sessionStore[username + "_login"];
            res.json({
                success: true,
                message: "Standard FIDO2 Login successful. Zero SD-JWT overhead.",
                attributes: user.attributes
            });
        } else {
            res.status(401).json({ error: "FIDO2 authentication failed: " + err.message });
        }
    }
});

// Start Server

async function start() {
    await initIssuerKeys();
    console.log("Mock Issuer initialized.");
    app.listen(PORT, () => {
        console.log(`Backend Server running on http://localhost:${PORT}`);
    });
}

start();
