import { deployContract } from '@midnight-ntwrk/midnight-js-contracts';
import { httpClientProofProvider } from '@midnight-ntwrk/midnight-js-http-client-proof-provider';
import { walletProvider } from '@midnight-ntwrk/wallet-api';
import * as defenseLedger from './contract/contract/index.js';

async function main() {
  const providers = {
    privateStateProvider: httpClientProofProvider('http://127.0.0.1:6300'),
    zkConfigProvider: httpClientProofProvider('http://127.0.0.1:6300'),
    publicDataProvider: 'http://127.0.0.1:8088',
    walletProvider: walletProvider('0000000000000000000000000000000000000000000000000000000000000000')
  };

  console.log("Deploying contract...");
  const contract = await deployContract(providers, {
    compiledContract: defenseLedger.contract,
    initialPrivateState: {} // if no private state needed initially
  });
  const address = contract.deployTxData.public.contractAddress;
  console.log(`Deployed to: ${address}`);

  const testHash = "0x0000000000000000000000000000000000000000000000000000000000001234";

  console.log("Calling attestIndicator(severity: 50)...");
  await contract.attestIndicator(testHash, 50n);

  console.log("Calling queryIndicator...");
  const count1 = await contract.queryIndicator(testHash);
  console.log(`Corroboration count: ${count1}`);
}

main().catch(console.error);
