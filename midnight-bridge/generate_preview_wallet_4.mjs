import crypto from 'crypto';
import { setNetworkId } from '@midnight-ntwrk/midnight-js-network-id';
import { MidnightWalletProvider } from '@midnight-ntwrk/testkit-js';
import { MidnightBech32m } from '@midnight-ntwrk/wallet-sdk';
import pino from 'pino';

// Keep the same seed that the user already saved!
const PREVIEW_SEED = '64bec6f63b55eb27da454e2c368b7950ed8c516508cd979e469c77f6095b5deb';

const envConfig = {
  walletNetworkId: 'testnet', // Force testnet for address formatting
  networkId: 'testnet',
  indexer: 'https://indexer.preview.midnight.network/api/v4/graphql',
  indexerWS: 'wss://indexer.preview.midnight.network/api/v4/graphql/ws',
  node: 'https://rpc.preview.midnight.network',
  nodeWS: 'wss://rpc.preview.midnight.network',
  proofServer: 'http://localhost:6300',
};

async function main() {
  const logger = pino({ level: 'silent' });
  setNetworkId('testnet');
  
  const walletProvider = await MidnightWalletProvider.build(
    logger,
    envConfig,
    PREVIEW_SEED
  );

  console.log("\n=== Midnight Preview Wallet Setup (Testnet Format) ===");
  console.log("SEED (Keep using this):", PREVIEW_SEED);

  try {
    const shieldedObj = await walletProvider.wallet.shielded.getAddress();
    // Encode it with testnet prefix
    const shieldedString = MidnightBech32m.encode('testnet', shieldedObj).asString();
    console.log("SHIELDED ADDRESS (For Faucet!):", shieldedString);
  } catch (e) {
    console.log("Error getting shielded address:", e.message);
  }
  
  try {
    await walletProvider.stop();
  } catch(e) {}
  
  process.exit(0);
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
