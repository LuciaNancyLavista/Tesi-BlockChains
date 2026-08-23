async function main() {
  const { network } = await import("hardhat");
  const networkConnection = await network.create();
  const viemClient = networkConnection.viem;
  
  const clients = await viemClient.getWalletClients();
  const owner = clients[0];
  console.log('Deploying from:', owner.account.address);
  
  const didReg = await viemClient.deployContract('DIDRegistry');
  console.log('DIDRegistry deployed to:', didReg.address);
  
  const polReg = await viemClient.deployContract('PolicyRegistry');
  console.log('PolicyRegistry deployed to:', polReg.address);
  
  const revReg = await viemClient.deployContract('RevocationRegistry');
  console.log('RevocationRegistry deployed to:', revReg.address);
  
  const trIss = await viemClient.deployContract('TrustedIssuers');
  console.log('TrustedIssuers deployed to:', trIss.address);
}

main().catch(console.error);