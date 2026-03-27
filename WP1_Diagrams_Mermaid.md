# WP1 - Diagrammi e Visualizzazioni

Questi diagrammi possono essere visualizzati su:
- https://mermaid.live (copia-incolla il codice)
- GitHub (supporta Mermaid nativamente)
- VS Code con estensione Mermaid

---

## 1. FIDO2 Registration Flow

```mermaid
sequenceDiagram
    participant U as User
    participant B as Browser
    participant S as Server
    participant A as Authenticator

    U->>B: Click "Register"
    B->>S: POST /register/start {username}
    S->>S: Generate challenge
    S->>B: Registration options + challenge
    B->>A: navigator.credentials.create()
    A->>U: "Touch fingerprint / Insert key"
    U->>A: 👆 Biometric confirmation
    A->>A: Generate key pair (private + public)
    A->>B: Public key + credential ID
    B->>S: POST /register/finish {credential}
    S->>S: Verify response
    S->>S: Save public key
    S->>B: {verified: true}
    B->>U: "✅ Registration successful!"
```

---

## 2. FIDO2 Authentication Flow

```mermaid
sequenceDiagram
    participant U as User
    participant B as Browser
    participant S as Server
    participant A as Authenticator

    U->>B: Click "Login"
    B->>S: POST /login/start {username}
    S->>S: Generate challenge
    S->>B: Authentication options + challenge
    B->>A: navigator.credentials.get()
    A->>U: "Touch fingerprint / Insert key"
    U->>A: 👆 Biometric confirmation
    A->>A: Find private key
    A->>A: Sign challenge with private key
    A->>B: Signature
    B->>S: POST /login/finish {signature}
    S->>S: Retrieve public key
    S->>S: Verify signature mathematically
    S->>B: {verified: true}
    B->>U: "✅ Login successful!"
```

---

## 3. DID/VC Trust Triangle

```mermaid
graph TD
    I[Issuer<br/>Università]
    H[Holder<br/>Studente]
    V[Verifier<br/>Portale Aziendale]
    
    I -->|1. Emette VC firmata| H
    H -->|2. Presenta VP firmata| V
    V -->|3. Verifica firma Issuer| I
    V -->|4. Verifica firma Holder| H
    
    style I fill:#e1f5e1
    style H fill:#e1e8f5
    style V fill:#f5e8e1
```

---

## 4. DID Document Structure

```mermaid
graph TB
    DID[DID<br/>did:key:z6Mkp...]
    
    DID --> VM[verificationMethod<br/>Chiavi Pubbliche]
    DID --> AUTH[authentication<br/>Quali chiavi autenticano]
    DID --> ASSERT[assertionMethod<br/>Quali chiavi firmano VC]
    DID --> SVC[service<br/>Endpoint opzionali]
    
    VM --> KEY1[Key #1<br/>Ed25519]
    VM --> KEY2[Key #2<br/>FIDO2 Public Key]
    
    AUTH --> KEY2
    ASSERT --> KEY1
    
    style DID fill:#667eea,color:#fff
    style KEY2 fill:#ffd700
```

---

## 5. The Binding - Complete Flow

```mermaid
sequenceDiagram
    participant U as User
    participant W as Wallet
    participant A as FIDO2 Authenticator
    participant I as Issuer
    participant V as Verifier
    participant VDR as DID Registry

    Note over U,VDR: FASE 1: REGISTRAZIONE & BINDING
    
    U->>W: Crea nuovo DID
    W->>W: Generate DID (es. did:key:z6Mkp...)
    W->>A: Request FIDO2 key generation
    A->>U: 👆 Touch for auth
    A->>A: Generate FIDO2 key pair
    A->>W: Return public key
    W->>W: Insert FIDO2 public key in DID Document
    W->>VDR: Publish DID Document
    
    U->>I: Request VC (es. Student ID)
    I->>I: Issue & sign VC
    I->>W: Send VC
    W->>W: Store VC in wallet
    
    Note over U,VDR: FASE 2: AUTENTICAZIONE (LOGIN)
    
    U->>V: Access protected resource
    V->>U: Request VC presentation
    V->>V: Generate challenge
    
    U->>W: Create Verifiable Presentation
    W->>W: Assemble VP (VC + challenge)
    W->>A: Sign VP with FIDO2 key
    A->>U: 👆 Touch for auth
    A->>A: Sign with FIDO2 private key
    A->>W: Return signature
    W->>V: Send signed VP
    
    V->>VDR: Resolve DID → get DID Document
    VDR->>V: Return DID Document
    V->>V: Extract FIDO2 public key from DID
    V->>V: Verify VP signature with FIDO2 public key
    V->>V: Verify VC signature from Issuer
    V->>V: Verify challenge matches
    
    alt All verifications pass
        V->>U: ✅ Access granted
    else Verification fails
        V->>U: ❌ Access denied
    end
```

---

## 6. Architecture Overview

```mermaid
graph TB
    subgraph "User Device"
        W[Wallet App]
        F[FIDO2 Authenticator<br/>Hardware/Biometric]
    end
    
    subgraph "Backend Services"
        WA[WebAuthn Server]
        DM[DID Manager]
        VM[VC Manager]
    end
    
    subgraph "External"
        VDR[Verifiable Data Registry<br/>Blockchain/IPFS]
        ISS[Issuers<br/>Universities, Gov, etc]
        VER[Verifiers<br/>Apps, Services]
    end
    
    W <--> F
    W <--> WA
    W <--> DM
    W <--> VM
    
    DM <--> VDR
    VM <--> ISS
    VM <--> VER
    
    style F fill:#ffd700
    style VDR fill:#667eea,color:#fff
```

---

## 7. Security Model

```mermaid
graph TD
    A[Security Properties]
    
    A --> P1[No Password<br/>Phishing Impossible]
    A --> P2[Hardware-Backed<br/>Private Key Protected]
    A --> P3[Per-Site Keys<br/>Isolation]
    A --> P4[Decentralized<br/>No Single Point of Failure]
    A --> P5[Privacy-Preserving<br/>Selective Disclosure]
    A --> P6[Revocable<br/>VC Lifecycle Management]
    
    P1 --> FIDO[FIDO2 Provides]
    P2 --> FIDO
    P3 --> FIDO
    
    P4 --> DID[DID/VC Provides]
    P5 --> DID
    P6 --> DID
    
    style FIDO fill:#e1f5e1
    style DID fill:#e1e8f5
    style A fill:#ffd700
```

---

## Come Usare Questi Diagrammi

### Opzione 1: Mermaid Live Editor
1. Vai su https://mermaid.live
2. Copia-incolla il codice del diagramma che ti interessa
3. Visualizza e esporta come PNG/SVG

### Opzione 2: VS Code
1. Installa estensione "Markdown Preview Mermaid Support"
2. Crea un file `.md` con questi diagrammi
3. Preview direttamente in VS Code

### Opzione 3: GitHub
1. Pusha questi diagrammi su GitHub in un file `.md`
2. GitHub li renderà automaticamente

---

## Tips per la Tesi

Questi diagrammi sono PERFETTI per:
- Capitolo 2 (Background) della tesi
- Slide della presentazione finale
- Documentazione D1.1
- Spiegare al relatore durante le review

Personalizzali come vuoi! Mermaid è molto flessibile.
