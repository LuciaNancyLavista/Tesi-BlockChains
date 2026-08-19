# Dimostratore Architettura SD-JWT Mediator-Free + FIDO2

Questo repository contiene il codice sorgente del dimostratore pratico sviluppato per la tesi: **Progettazione di un Meccanismo di Autenticazione Decentralizzata tramite Verifiable Credentials e FIDO2**.

L'obiettivo di questo software è dimostrare fattivamente un'architettura decentralizzata *Mediator-Free*, in cui un utente ottiene una credenziale (SD-JWT) con *Selective Disclosure* e si autentica presso un Relying Party utilizzando lo standard WebAuthn (FIDO2), senza la necessità di app-wallet esterne.

---

## Struttura del Progetto
- **/backend**: Server Node.js (Express). Simula sia l'Issuer Universitario (che emette il certificato SD-JWT) sia il server del Relying Party (che verifica la firma FIDO2, il *challenge modifier* e le policy di età e ruolo).
- **/frontend**: App React (Vite). Rappresenta l'interfaccia utente (Local Wallet per la selezione dei dati e Relying Party Portal).
- **/smart-contracts**: Contratti Solidity testati in ambiente Hardhat. Contengono la logica on-chain di base per il DID Registry, Policy Registry e Token Status List (per la revoca dei certificati).

---

## Prerequisiti
Per eseguire il progetto in autonomia sul proprio PC è necessario aver installato:
- [Node.js](https://nodejs.org/) (versione 18 o superiore)
- Git (per clonare il repository)

---

## Istruzioni di Avvio Rapido

Per provare il sistema, seguire i passaggi sottostanti aprendo tre finestre del terminale differenti.

### 1. Avvio del Backend
In un terminale, posizionarsi nella cartella `backend`, installare le dipendenze e avviare il server:
```bash
cd backend
npm install
node server.js
```
*(Il server resterà in ascolto sulla porta 3000)*

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
**NOTA FONDAMENTALE DI SICUREZZA:** Il protocollo Apple/Google per FIDO2 (WebAuthn) blocca categoricamente l'uso di FaceID/TouchID se il sito non è erogato tramite connessione sicura `HTTPS`. Non è possibile usare il semplice `localhost` dal telefono.

In un **terzo terminale**, generare un tunnel pubblico gratuito e sicuro (senza installare nulla) eseguendo:
```bash
ssh -R 80:localhost:5173 nokey@localhost.run
```
Il terminale vi restituirà un indirizzo univoco (es. `https://ac12345.lhr.life`). 
**Aprite questo link dal vostro smartphone**. Il backend è stato istruito per rilevare dinamicamente il dominio del tunnel, permettendovi di completare la validazione crittografica senza intoppi.

---

## Esecuzione Test Smart Contracts
I contratti Solidity sono corredati di test automatici che ne validano il funzionamento.
Per eseguirli (opzionale):
```bash
cd smart-contracts
npm install
npx hardhat test
```
