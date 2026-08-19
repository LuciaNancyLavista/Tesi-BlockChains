import assert from "node:assert/strict";
import { describe, it, beforeEach } from "node:test";
import "@nomicfoundation/hardhat-toolbox-viem";
import { getAddress } from "viem";

describe("DIDRegistry", async function () {
  let viemClient: any;
  let registry: any;
  let publicClient: any;
  let ownerClient: any;
  let otherUserClient: any;
  let ownerAddress: string;
  let otherUserAddress: string;

  // Dati fittizi per simulare un DID
  const DID_1 = "did:ethr:0x1234567890123456789012345678901234567890";
  const PUB_KEY_1 = "0x02b97c30de767f084ce3080168ee293053ba33b235d7116a326ce07f99ff38";
  const ENDPOINT_1 = "https://example.com/did";

  const DID_2 = "did:ethr:0x0987654321098765432109876543210987654321";
  const PUB_KEY_2 = "0x03a1b2c3d4e5f6...";
  const ENDPOINT_2 = "https://example.com/did2";

  beforeEach(async function () {
    const { network } = await import("hardhat");
    const networkConnection = await network.create();
    viemClient = networkConnection.viem;
    publicClient = await viemClient.getPublicClient();
    const clients = await viemClient.getWalletClients();
    ownerClient = clients[0];
    otherUserClient = clients[1];

    ownerAddress = getAddress(ownerClient.account.address);
    otherUserAddress = getAddress(otherUserClient.account.address);

    // Deploy del contratto
    registry = await viemClient.deployContract("DIDRegistry");
  });

  describe("Registration", function () {
    it("Should allow a user to register a DID and emit an event", async function () {
      // 1. Inviamo la transazione e aspettiamo la ricevuta
      const txHash = await ownerClient.writeContract({
        address: registry.address,
        abi: registry.abi,
        functionName: "registerDID",
        args: [DID_1, PUB_KEY_1, ENDPOINT_1],
      });

      const receipt = await publicClient.waitForTransactionReceipt({ hash: txHash });
      const block = await publicClient.getBlock({ blockNumber: receipt.blockNumber });

      // 2. Leggiamo gli eventi emessi in quel blocco specifico
      const events = await publicClient.getContractEvents({
        address: registry.address,
        abi: registry.abi,
        eventName: "DIDRegistered",
        fromBlock: receipt.blockNumber,
        toBlock: receipt.blockNumber
      });

      // 3. Verifichiamo l'evento con il timestamp esatto del blocco
      assert.equal(events.length, 1);
      assert.equal(events[0].args.owner, ownerAddress);
      assert.equal(events[0].args.publicKey, PUB_KEY_1);
      assert.equal(events[0].args.timestamp, block.timestamp);

      // 4. Verifichiamo lo stato del contratto tramite resolveDID
      const doc = await registry.read.resolveDID([DID_1]);
      assert.equal(doc.owner, ownerAddress);
      assert.equal(doc.publicKey, PUB_KEY_1);
      assert.equal(doc.serviceEndpoint, ENDPOINT_1);
      assert.equal(doc.createdAt, block.timestamp);
      assert.equal(doc.active, true);
    });

    it("Should revert if the user is already registered", async function () {
      // Prima registrazione
      await registry.write.registerDID([DID_1, PUB_KEY_1, ENDPOINT_1]);
      
      // La seconda deve fallire per lo stesso utente (ownerClient)
      await assert.rejects(
        registry.write.registerDID([DID_2, PUB_KEY_2, ENDPOINT_2])
      );
    });
  });

  describe("Resolution and Verification", function () {
    it("Should return active=true for a registered DID", async function () {
      await registry.write.registerDID([DID_1, PUB_KEY_1, ENDPOINT_1]);
      
      const isActive = await registry.read.isActive([DID_1]);
      assert.equal(isActive, true);
    });

    it("Should revert resolveDID if the DID is not registered", async function () {
      await assert.rejects(
        registry.read.resolveDID(["did:ethr:ghost"])
      );
    });
  });

  describe("Updating", function () {
    beforeEach(async function () {
      await ownerClient.writeContract({
        address: registry.address,
        abi: registry.abi,
        functionName: "registerDID",
        args: [DID_1, PUB_KEY_1, ENDPOINT_1],
      });
    });

    it("Should allow the owner to update the DID and emit an event", async function () {
      const NEW_PUB_KEY = "0xnewpubkey";
      const NEW_ENDPOINT = "https://new.example.com";

      const txHash = await ownerClient.writeContract({ 
        address: registry.address,
        abi: registry.abi,
        functionName: "updateDID",
        args: [NEW_PUB_KEY, NEW_ENDPOINT],
      });

      const receipt = await publicClient.waitForTransactionReceipt({ hash: txHash });
      const block = await publicClient.getBlock({ blockNumber: receipt.blockNumber });

      const events = await publicClient.getContractEvents({
        address: registry.address,
        abi: registry.abi,
        eventName: "DIDUpdated",
        fromBlock: receipt.blockNumber,
        toBlock: receipt.blockNumber
      });

      assert.equal(events.length, 1);
      assert.equal(events[0].args.owner, ownerAddress);
      assert.equal(events[0].args.publicKey, NEW_PUB_KEY);
      assert.equal(events[0].args.timestamp, block.timestamp);

      // Verifichiamo che i dati siano stati aggiornati correttamente
      const doc = await registry.read.resolveDID([DID_1]);
      assert.equal(doc.publicKey, NEW_PUB_KEY);
      assert.equal(doc.serviceEndpoint, NEW_ENDPOINT);
      assert.equal(doc.updatedAt, block.timestamp);
    });

    it("Should revert if an unregistered user tries to update", async function () {
      await assert.rejects(
        otherUserClient.writeContract({
          address: registry.address,
          abi: registry.abi,
          functionName: "updateDID",
          args: [PUB_KEY_2, ENDPOINT_2],
        })
      );
    });
  });

  describe("Revocation", function () {
    beforeEach(async function () {
      await registry.write.registerDID([DID_1, PUB_KEY_1, ENDPOINT_1]);
    });

    it("Should allow the owner to revoke the DID and set active to false", async function () {
      const txHash = await ownerClient.writeContract({ 
        address: registry.address,
        abi: registry.abi,
        functionName: "revokeDID",
      });

      const receipt = await publicClient.waitForTransactionReceipt({ hash: txHash });
      const block = await publicClient.getBlock({ blockNumber: receipt.blockNumber });

      const events = await publicClient.getContractEvents({
        address: registry.address,
        abi: registry.abi,
        eventName: "DIDRevoked",
        fromBlock: receipt.blockNumber,
        toBlock: receipt.blockNumber
      });

      assert.equal(events.length, 1);
      assert.equal(events[0].args.owner, ownerAddress);
      assert.equal(events[0].args.timestamp, block.timestamp);

      // Verifichiamo che isActive ritorni false 
      const isActive = await registry.read.isActive([DID_1]);
      assert.equal(isActive, false);

      // Verifichiamo che il documento sia segnato come inattivo
      const doc = await registry.read.resolveDID([DID_1]);
      assert.equal(doc.active, false);
    });

    it("Should revert if trying to update a revoked DID", async function () {
      await registry.write.revokeDID();

      await assert.rejects(
        registry.write.updateDID([PUB_KEY_2, ENDPOINT_2])
      );
    });
  });
});
