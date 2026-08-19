import assert from "node:assert/strict";
import { describe, it, beforeEach } from "node:test";
import "@nomicfoundation/hardhat-toolbox-viem";
import { getAddress } from "viem";

describe("PolicyRegistry", async function () {
  let viemClient: any;
  let registry: any;
  let publicClient: any;
  let rpClient: any;
  let otherClient: any;
  let rpAddress: string;

  const POLICY_1 = '{"require":["age","role"],"minAge":18}';
  const POLICY_2 = '{"require":["role"],"roles":["Student","Professor"]}';

  beforeEach(async function () {
    const { network } = await import("hardhat");
    const networkConnection = await network.create();
    viemClient = networkConnection.viem;
    publicClient = await viemClient.getPublicClient();
    const clients = await viemClient.getWalletClients();
    rpClient = clients[0];
    otherClient = clients[1];

    rpAddress = getAddress(rpClient.account.address);

    registry = await viemClient.deployContract("PolicyRegistry");
  });

  it("Should allow an RP to publish a policy", async function () {
    const txHash = await rpClient.writeContract({
      address: registry.address,
      abi: registry.abi,
      functionName: "publishPolicy",
      args: [POLICY_1],
    });

    const receipt = await publicClient.waitForTransactionReceipt({ hash: txHash });
    const block = await publicClient.getBlock({ blockNumber: receipt.blockNumber });

    const events = await publicClient.getContractEvents({
      address: registry.address,
      abi: registry.abi,
      eventName: "PolicyPublished",
      fromBlock: receipt.blockNumber,
      toBlock: receipt.blockNumber
    });

    assert.equal(events.length, 1);
    assert.equal(events[0].args.rp, rpAddress);
    assert.equal(events[0].args.policy, POLICY_1);
    assert.equal(events[0].args.timestamp, block.timestamp);

    const retrievedPolicy = await registry.read.getPolicy([rpAddress]);
    assert.equal(retrievedPolicy, POLICY_1);
  });

  it("Should allow an RP to update their policy", async function () {
    await registry.write.publishPolicy([POLICY_1]);
    await registry.write.publishPolicy([POLICY_2]);

    const retrievedPolicy = await registry.read.getPolicy([rpAddress]);
    assert.equal(retrievedPolicy, POLICY_2);
  });

  it("Should revert if trying to get policy for an RP with no published policy", async function () {
    await assert.rejects(
      registry.read.getPolicy([getAddress(otherClient.account.address)])
    );
  });
});
