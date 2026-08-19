import assert from "node:assert/strict";
import { describe, it, beforeEach } from "node:test";
import "@nomicfoundation/hardhat-toolbox-viem";
import { getAddress } from "viem";

describe("TrustedIssuers", async function () {
  let viemClient: any;
  let registry: any;
  let publicClient: any;
  let adminClient: any;
  let nonAdminClient: any;
  let targetIssuerClient: any;
  let adminAddress: string;
  let targetIssuerAddress: string;

  beforeEach(async function () {
    const { network } = await import("hardhat");
    const networkConnection = await network.create();
    viemClient = networkConnection.viem;
    publicClient = await viemClient.getPublicClient();
    const clients = await viemClient.getWalletClients();
    adminClient = clients[0];
    nonAdminClient = clients[1];
    targetIssuerClient = clients[2];

    adminAddress = getAddress(adminClient.account.address);
    targetIssuerAddress = getAddress(targetIssuerClient.account.address);

    registry = await viemClient.deployContract("TrustedIssuers");
  });

  it("Should set the deployer as admin", async function () {
    const currentAdmin = await registry.read.admin();
    assert.equal(currentAdmin, adminAddress);
  });

  it("Should allow admin to add a trusted issuer", async function () {
    const txHash = await adminClient.writeContract({
      address: registry.address,
      abi: registry.abi,
      functionName: "addIssuer",
      args: [targetIssuerAddress],
    });

    const receipt = await publicClient.waitForTransactionReceipt({ hash: txHash });
    const block = await publicClient.getBlock({ blockNumber: receipt.blockNumber });

    const events = await publicClient.getContractEvents({
      address: registry.address,
      abi: registry.abi,
      eventName: "IssuerAdded",
      fromBlock: receipt.blockNumber,
      toBlock: receipt.blockNumber
    });

    assert.equal(events.length, 1);
    assert.equal(events[0].args.issuer, targetIssuerAddress);
    assert.equal(events[0].args.timestamp, block.timestamp);

    const isTrusted = await registry.read.isTrusted([targetIssuerAddress]);
    assert.equal(isTrusted, true);
  });

  it("Should revert if non-admin tries to add an issuer", async function () {
    await assert.rejects(
      nonAdminClient.writeContract({
        address: registry.address,
        abi: registry.abi,
        functionName: "addIssuer",
        args: [targetIssuerAddress],
      })
    );
  });

  it("Should allow admin to remove a trusted issuer", async function () {
    await registry.write.addIssuer([targetIssuerAddress]);

    const txHash = await adminClient.writeContract({
      address: registry.address,
      abi: registry.abi,
      functionName: "removeIssuer",
      args: [targetIssuerAddress],
    });

    const receipt = await publicClient.waitForTransactionReceipt({ hash: txHash });
    const block = await publicClient.getBlock({ blockNumber: receipt.blockNumber });

    const events = await publicClient.getContractEvents({
      address: registry.address,
      abi: registry.abi,
      eventName: "IssuerRemoved",
      fromBlock: receipt.blockNumber,
      toBlock: receipt.blockNumber
    });

    assert.equal(events.length, 1);
    assert.equal(events[0].args.issuer, targetIssuerAddress);
    assert.equal(events[0].args.timestamp, block.timestamp);

    const isTrusted = await registry.read.isTrusted([targetIssuerAddress]);
    assert.equal(isTrusted, false);
  });
  
  it("Should revert if non-admin tries to remove an issuer", async function () {
    await registry.write.addIssuer([targetIssuerAddress]);
    
    await assert.rejects(
      nonAdminClient.writeContract({
        address: registry.address,
        abi: registry.abi,
        functionName: "removeIssuer",
        args: [targetIssuerAddress],
      })
    );
  });
});
