import { ethers } from 'ethers';

// Connect to local Hardhat node
const provider = new ethers.JsonRpcProvider('http://127.0.0.1:8545');

// Mock ABIs based on the contracts we wrote
const DID_REGISTRY_ABI = [
    "function resolveDID(string _did) view returns (tuple(address owner, string publicKey, string serviceEndpoint, uint256 createdAt, uint256 updatedAt, bool active))",
    "function isActive(string _did) view returns (bool)"
];

const TRUSTED_ISSUERS_ABI = [
    "function isTrusted(address _issuer) view returns (bool)"
];

const POLICY_REGISTRY_ABI = [
    "function getPolicy(address _rp) view returns (string)"
];

// Contract addresses will need to be updated after deployment
let didRegistryAddress = "0x5FbDB2315678afecb367f032d93F642f64180aa3";
let trustedIssuersAddress = "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512";
let policyRegistryAddress = "0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0";

export function setContractAddresses(did, trusted, policy) {
    didRegistryAddress = did;
    trustedIssuersAddress = trusted;
    policyRegistryAddress = policy;
}

export async function getIssuerPublicKeyFromDID(did) {
    const contract = new ethers.Contract(didRegistryAddress, DID_REGISTRY_ABI, provider);
    try {
        const doc = await contract.resolveDID(did);
        if (!doc.active) throw new Error("DID is revoked on-chain");
        
        // Return the JWK string stored on-chain
        return JSON.parse(doc.publicKey);
    } catch (err) {
        console.error("DID Resolution failed:", err);
        return null;
    }
}

export async function checkIssuerTrusted(issuerAddress) {
    const contract = new ethers.Contract(trustedIssuersAddress, TRUSTED_ISSUERS_ABI, provider);
    return await contract.isTrusted(issuerAddress);
}
