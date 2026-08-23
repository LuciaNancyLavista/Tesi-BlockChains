import { ethers } from 'ethers';

// Connect to public Sepolia node (as declared in the thesis)
const provider = new ethers.JsonRpcProvider('https://ethereum-sepolia-rpc.publicnode.com');

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

// Contract addresses on Sepolia Testnet
let didRegistryAddress = "0x013bd8e73c6882331feaf18039094d9922eeaeed";
let trustedIssuersAddress = "0x7ca28469468d7d4959595ee42ec235f7ff6c4be3";
let policyRegistryAddress = "0xeff80c2a3299edfb3c2e8d6a065d1c53cf59d0d1";

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
