# Dimostratore Architettura SD-JWT Mediator-Free + FIDO2

Questo repository contiene il codice sorgente del dimostratore pratico sviluppato per la tesi magistrale: **Progettazione di un Meccanismo di Autenticazione Decentralizzata tramite Verifiable Credentials e FIDO2**.

L'obiettivo di questo software è dimostrare fattivamente un'architettura decentralizzata *Mediator-Free*, in cui un utente ottiene una credenziale (SD-JWT) con *Selective Disclosure* e si autentica presso un Relying Party utilizzando lo standard WebAuthn (FIDO2), senza la necessità di un'entità terza (Mediator) che comprometterebbe l'unlinkability.

## 🚀 Funzionalità Chiave Dimostrate

1. **Selective Disclosure & Data Minimization:** Il wallet locale estrae e presenta solo gli attributi richiesti dalla policy del Relying Party, nascondendo gli altri (es. nome).
2. **Mediator-Free Binding:** L'iniezione dell'hash SD-JWT all'interno del challenge FIDO2 avviene in modo del tutto trasparente lato client, senza modifiche all'hardware o al browser.
3. **Zero Overhead sui Login Successivi:** Una volta completata la prima registrazione della credenziale, gli accessi successivi avvengono in puro standard FIDO2 (overhead di 0 ms, nessuna intercettazione fidoac.js).
4. **Blockchain Pubblica (Ethereum Sepolia):** Il sistema interagisce con veri Smart Contract eseguiti sulla Testnet pubblica Sepolia per la risoluzione dei Decentralized Identifiers (DID) e il controllo di fiducia (Trust Anchors), eliminando ogni singolo punto di fallimento.

---

## 🏗️ Struttura del Progetto
- **/backend**: Server Node.js (Express). Simula l'Issuer (che emette la SD-JWT) e implementa il motore di verifica composita del Relying Party (b_FIDO ∧ b_challenge ∧ b_sdjwt). Contiene il client `ethers.js` connesso a Sepolia.
- **/frontend**: App React (Vite). Rappresenta l'interfaccia utente (Wallet Locale per la selezione dei dati e Relying Party Portal).
- **/smart-contracts**: Contratti Solidity (DIDRegistry, PolicyRegistry, RevocationRegistry, TrustedIssuers). I contratti sono ufficialmente deployati sulla Testnet Sepolia.

---

## ⚙️ Prerequisiti
Per eseguire il progetto in autonomia sul proprio PC è necessario aver installato:
- [Node.js](https://nodejs.org/) (versione 18 o superiore)
- Git (per clonare il repository)

---

## 🏁 Istruzioni di Avvio Rapido

Per provare il sistema, seguire i passaggi sottostanti aprendo tre finestre del terminale differenti.

### 1. Avvio del Backend
In un terminale, posizionarsi nella cartella `backend`, installare le dipendenze e avviare il server:
```bash
cd backend
npm install
npm start
```
*(Il server resterà in ascolto sulla porta 3000 e si connetterà automaticamente al nodo RPC di Sepolia)*

### 2. Avvio del Frontend (Ottimizzato)
In un **secondo terminale**, posizionarsi nella cartella `frontend`, installare le librerie, compilare il codice per massimizzare la velocità, e avviare il sito:
```bash
cd frontend
npm install
npm run build
npm run preview
```
*(Il sito risponderà in locale sulla porta 5173)*

### 3. Creazione del Tunnel per test FIDO2 (Obbligatorio)
**NOTA FONDAMENTALE DI SICUREZZA:** Il protocollo Apple/Google per FIDO2 (WebAuthn) blocca categoricamente l'uso di FaceID/TouchID se il sito non è erogato tramite connessione sicura `HTTPS`.

In un **terzo terminale**, generare un tunnel pubblico gratuito ed eseguendo:
```bash
ssh -R 80:localhost:5173 nokey@localhost.run
```
Il terminale vi restituirà un indirizzo univoco (es. `https://ac12345.lhr.life`). 
**Aprite questo link dal vostro smartphone**. Il backend rileverà dinamicamente il dominio del tunnel, permettendovi di completare la validazione crittografica.

---

## 📜 Smart Contracts (Testnet Sepolia)
I contratti alla base dell'infrastruttura a chiave pubblica (PKI) sono deployati e verificabili sulla blockchain pubblica Sepolia (Ethereum):
- **DIDRegistry:** `0x013bd8e73c6882331feaf18039094d9922eeaeed`
- **PolicyRegistry:** `0xeff80c2a3299edfb3c2e8d6a065d1c53cf59d0d1`
- **RevocationRegistry:** `0x8e933fdee94064c9a25c501445e4f71a93b942e5`
- **TrustedIssuers:** `0x7ca28469468d7d4959595ee42ec235f7ff6c4be3`
