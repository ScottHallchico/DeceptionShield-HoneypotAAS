import crypto from 'crypto';
import { setNetworkId } from '@midnight-ntwrk/midnight-js-network-id';
import { MidnightWalletProvider } from '@midnight-ntwrk/testkit-js';
import { MidnightBech32m } from '@midnight-ntwrk/wallet-sdk';
import pino from 'pino';

const PREVIEW_SEED = crypto.randomBytes(32).toString('hex');

const envConfig = {
  walletNetworkId: 'preview',
  networkId: 'preview',
  indexer: 'https://indexer.preview.midnight.network/api/v4/graphql',
  indexerWS: 'wss://indexer.preview.midnight.network/api/v4/graphql/ws',
  node: 'https://rpc.preview.midnight.network',
  nodeWS: 'wss://rpc.preview.midnight.network',
  proofServer: 'http://localhost:6300',
};

async function main() {
  const logger = pino({ level: 'info' });
  setNetworkId('preview');
  
  const walletProvider = await MidnightWalletProvider.build(
    logger,
    envConfig,
    PREVIEW_SEED
  );

  console.log("\n=== Midnight Preview Wallet Setup ===");
  console.log("SEED (Save to .env!):", PREVIEW_SEED);

  try {
    const shieldedObj = await walletProvider.wallet.shielded.getAddress();
    // Use the exposed MidnightBech32m to encode the address object directly
    const shieldedString = MidnightBech32m.encode('preview', shieldedObj).asString();
    console.log("SHIELDED ADDRESS (For Faucet!):", shieldedString);
  } catch (e) {
    console.log("Error getting shielded address:", e.message);
  }

  try {
    const unshieldedAddr = await walletProvider.unshieldedKeystore.getBech32Address();
    console.log("UNSHIELDED ADDRESS:", String(unshieldedAddr));
  } catch(e) {}

  try {
    await walletProvider.stop();
  } catch(e) {}
  
  process.exit(0);
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
