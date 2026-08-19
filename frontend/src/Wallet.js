export class LocalWallet {
    constructor() {
        this.credential = null;
        this.disclosures = null;
        this.tslIndex = null;
    }

    // Stores the credential received from the Mock Issuer
    storeCredential(sdjwt, disclosures, tslIndex) {
        this.credential = sdjwt;
        this.disclosures = disclosures;
        this.tslIndex = tslIndex;
        console.log(`💳 [Wallet] Credential stored. TSL Index: ${tslIndex}`);
    }

    // Creates a presentation by selecting only the requested attributes
    createPresentation(requestedAttributes) {
        if (!this.credential) throw new Error("No credential in wallet");

        console.log(`💳 [Wallet] Creating selective disclosure for: ${requestedAttributes.join(', ')}`);
        
        const selectedDisclosures = {};
        for (const attr of requestedAttributes) {
            if (this.disclosures[attr]) {
                selectedDisclosures[attr] = this.disclosures[attr];
            } else {
                console.warn(`💳 [Wallet] Attribute ${attr} not found in credential.`);
            }
        }

        // Expose to fidoac.js for injection
        window.__fidoac_sdjwt_presentation = this.credential;

        return {
            sdjwt: this.credential,
            disclosures: selectedDisclosures
        };
    }

    clearPresentation() {
        window.__fidoac_sdjwt_presentation = null;
    }
}
