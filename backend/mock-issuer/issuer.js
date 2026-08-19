import { SignJWT, exportJWK, generateKeyPair } from 'jose';
import crypto from 'crypto';

// The Issuer DID (simulated)
export const ISSUER_DID = "did:ethr:0x5FbDB2315678afecb367f032d93F642f64180aa3"; // Local hardhat account 0

// In-memory keypair for the mock issuer
let issuerPrivateKey;
let issuerPublicKey;

export async function initIssuerKeys() {
    // Generate a fresh ECDSA P-256 keypair for the issuer
    const { publicKey, privateKey } = await generateKeyPair('ES256');
    issuerPrivateKey = privateKey;
    issuerPublicKey = await exportJWK(publicKey);
    return issuerPublicKey;
}

export function getIssuerPublicKeyJWK() {
    return issuerPublicKey;
}

// Generates a mock SD-JWT for the user
export async function issueSDJWT(userAttributes) {
    if (!issuerPrivateKey) throw new Error("Issuer keys not initialized");

    const disclosures = {};
    const sdHashes = [];

    // For each attribute, generate a salt, create disclosure string, and hash it
    for (const [key, value] of Object.entries(userAttributes)) {
        const salt = crypto.randomBytes(16).toString('base64url');
        // Disclosure format: [salt, claim_name, claim_value]
        const disclosureArray = [salt, key, value];
        const disclosureString = Buffer.from(JSON.stringify(disclosureArray)).toString('base64url');
        
        // Calculate SHA-256 hash of the base64url disclosure string
        const hash = crypto.createHash('sha256').update(disclosureString).digest('base64url');
        
        sdHashes.push(hash);
        disclosures[key] = disclosureString;
    }

    const idx = Math.floor(Math.random() * 1000); // Random bit index for unlinkability

    // Create the base JWT
    const jwt = await new SignJWT({ 
        _sd: sdHashes,
        status: {
            status_list: {
                uri: "http://localhost:3000/api/status-list", // Mock status list URI
                idx: idx
            }
        }
    })
    .setProtectedHeader({ alg: 'ES256', typ: 'JWT' })
    .setIssuedAt()
    .setIssuer(ISSUER_DID)
    .setExpirationTime('1y')
    .sign(issuerPrivateKey);

    // Return the signed JWT and the raw disclosures so the wallet can use them
    return {
        sdjwt: jwt,
        disclosures: disclosures, // The wallet will store these
        tslIndex: idx
    };
}
