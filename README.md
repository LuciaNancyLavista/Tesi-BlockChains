# SD-JWT Mediator-Free Architecture + FIDO2 Demonstrator

This repository contains the source code for the practical demonstrator developed for the thesis: **Design of a Decentralized Authentication Mechanism using Verifiable Credentials and FIDO2**.

The goal of this software is to practically demonstrate a *Mediator-Free* decentralized architecture. A user obtains an SD-JWT credential with *Selective Disclosure* and authenticates to a Relying Party using the WebAuthn (FIDO2) standard, without requiring external wallet apps or a centralized identity provider.

---

## Project Structure
- **/backend**: Node.js (Express) server. It simulates both the University Issuer (which issues the SD-JWT credential) and the Relying Party server (which verifies the FIDO2 signature, the *challenge modifier*, and the age/role policies). It actively connects to the **Ethereum Sepolia Testnet** for DID resolution.
- **/frontend**: React (Vite) app. Represents the user interface, acting as a Local Wallet (for data selective disclosure) and the Relying Party Portal. It includes the `fidoac.js` interceptor script to dynamically inject the SD-JWT hash into the FIDO2 payload.
- **/smart-contracts**: Solidity contracts deployed on the **Ethereum Sepolia Testnet**. They contain the on-chain logic for the DID Registry, Policy Registry, Trusted Issuers, and Token Status List (for credential revocation).

---

## Key Features Implemented
1. **Mediator-Free Binding**: Cryptographically links the FIDO2 authentication to an SD-JWT presentation without relying on external mediators.
2. **Selective Disclosure**: Allows users to withhold sensitive attributes (e.g., Name) while proving they meet specific RP policies (e.g., Age >= 18).
3. **Public Blockchain Integration**: Fully interacts with the public Ethereum Sepolia Testnet via RPC for decentralized identifier (DID) resolution.
4. **Standard FIDO2 Login**: Demonstrates that subsequent authentications after the initial registration incur **0 ms SD-JWT overhead**, functioning purely on standard WebAuthn APIs.

---

## Prerequisites
To run the project locally on your PC, you must have installed:
- [Node.js](https://nodejs.org/) (version 18 or higher)
- Git (to clone the repository)

---

## Quick Start Instructions

To test the system, follow the steps below by opening three different terminal windows.

### 1. Start the Backend
In one terminal, navigate to the `backend` folder, install the dependencies, and start the server:
```bash
cd backend
npm install
npm start
```
*(The server will listen on port 3000)*

### 2. Start the Frontend (Optimized)
In a **second terminal**, navigate to the `frontend` folder, install the libraries, build the code to maximize speed, and start the site:
```bash
cd frontend
npm install
npm run build
npm run preview
```
*(The site will respond locally on port 5173)*

### 3. Create a Tunnel for FIDO2 testing (Mandatory for Mobile)
**CRITICAL SECURITY NOTE:** The Apple/Google protocol for FIDO2 (WebAuthn) strictly blocks the use of FaceID/TouchID if the site is not served via a secure `HTTPS` connection. You cannot use a simple `localhost` link from your phone.

In a **third terminal**, generate a free and secure public tunnel (without installing anything) by running:
```bash
ssh -R 80:localhost:5173 nokey@localhost.run
```
The terminal will return a unique address (e.g., `https://ac12345.lhr.life`).
**Open this link from your smartphone**. The backend has been instructed to dynamically detect the tunnel domain, allowing you to complete the cryptographic validation smoothly.

---

## Smart Contracts (Sepolia Testnet)
The Solidity contracts have been successfully deployed on the public Ethereum Sepolia Testnet. The backend automatically queries these addresses through a public RPC node:
- **DIDRegistry**: `0x013bd8e73c6882331feaf18039094d9922eeaeed`
- **PolicyRegistry**: `0xeff80c2a3299edfb3c2e8d6a065d1c53cf59d0d1`
- **RevocationRegistry**: `0x8e933fdee94064c9a25c501445e4f71a93b942e5`
- **TrustedIssuers**: `0x7ca28469468d7d4959595ee42ec235f7ff6c4be3`
