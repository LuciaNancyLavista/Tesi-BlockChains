import assert from "node:assert/strict";
import { describe, it, beforeEach } from "node:test";
import "@nomicfoundation/hardhat-toolbox-viem";
import { getAddress } from "viem";

describe("RevocationRegistry", async function () {
  let viemClient: any;
  let registry: any;
  let publicClient: any;
  let issuerClient: any;
  let otherClient: any;
  let issuerAddress: string;

  const URI = "https://university.edu/status-list.json";
  const URI_2 = "https://university.edu/status-list-v2.json";

  beforeEach(async function () {
    const { network } = await import("hardhat");
    const networkConnection = await network.create();
    viemClient = networkConnection.viem;
    publicClient = await viemClient.getPublicClient();
    const clients = await viemClient.getWalletClients();
    issuerClient = clients[0];
    otherClient = clients[1];

    issuerAddress = getAddress(issuerClient.account.address);

    registry = await viemClient.deployContract("RevocationRegistry");
  });

  it("Should allow an issuer to publish a Status List URI", async function () {
    const txHash = await issuerClient.writeContract({
      address: registry.address,
      abi: registry.abi,
      functionName: "publishStatusListURI",
      args: [URI],
    });

    const receipt = await publicClient.waitForTransactionReceipt({ hash: txHash });
    const block = await publicClient.getBlock({ blockNumber: receipt.blockNumber });

    const events = await publicClient.getContractEvents({
      address: registry.address,
      abi: registry.abi,
      eventName: "StatusListURIPublished",
      fromBlock: receipt.blockNumber,
      toBlock: receipt.blockNumber
    });

    assert.equal(events.length, 1);
    assert.equal(events[0].args.issuer, issuerAddress);
    assert.equal(events[0].args.uri, URI);
    assert.equal(events[0].args.timestamp, block.timestamp);

    const retrievedURI = await registry.read.getStatusListURI([issuerAddress]);
    assert.equal(retrievedURI, URI);
  });

  it("Should allow an issuer to update their Status List URI", async function () {
    await registry.write.publishStatusListURI([URI]);
    await registry.write.publishStatusListURI([URI_2]);

    const retrievedURI = await registry.read.getStatusListURI([issuerAddress]);
    assert.equal(retrievedURI, URI_2);
  });

  it("Should revert if trying to get URI for an issuer with no published list", async function () {
    await assert.rejects(
      registry.read.getStatusListURI([getAddress(otherClient.account.address)])
    );
  });
});
