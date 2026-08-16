import crypto from 'crypto';
import { setNetworkId } from '@midnight-ntwrk/midnight-js-network-id';
import { MidnightWalletProvider } from '@midnight-ntwrk/testkit-js';
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

  console.log("SEED:", PREVIEW_SEED);
  try {
    const unshieldedAddr = await walletProvider.unshieldedKeystore.getBech32Address();
    console.log("UNSHIELDED ADDRESS:", unshieldedAddr);
  } catch(e) {}

  try {
    const dustObj = await walletProvider.wallet.dust.getAddress();
    // Dynamically access the MidnightBech32m codec representation which has toString()
    const dustCodec = dustObj[Object.getOwnPropertySymbols(dustObj)[0]];
    console.log("DUST ADDRESS:", String(dustCodec));
  } catch (e) {
    console.log("Error getting dust address:", e.message);
  }
  
  try {
    const shieldedObj = await walletProvider.wallet.shielded.getAddress();
    const shieldedCodec = shieldedObj[Object.getOwnPropertySymbols(shieldedObj)[0]];
    console.log("SHIELDED ADDRESS:", String(shieldedCodec));
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
