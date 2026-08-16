import crypto from 'crypto';
import { setNetworkId } from '@midnight-ntwrk/midnight-js-network-id';
import { MidnightWalletProvider } from '@midnight-ntwrk/testkit-js';
import { MidnightBech32m } from '@midnight-ntwrk/wallet-sdk';
import pino from 'pino';

const PREVIEW_SEED = '64bec6f63b55eb27da454e2c368b7950ed8c516508cd979e469c77f6095b5deb';

const envConfig = {
  walletNetworkId: 'test',
  networkId: 'test',
  indexer: 'https://indexer.preview.midnight.network/api/v4/graphql',
  indexerWS: 'wss://indexer.preview.midnight.network/api/v4/graphql/ws',
  node: 'https://rpc.preview.midnight.network',
  nodeWS: 'wss://rpc.preview.midnight.network',
  proofServer: 'http://localhost:6300',
};

async function main() {
  const logger = pino({ level: 'silent' });
  setNetworkId('test');
  
  const walletProvider = await MidnightWalletProvider.build(
    logger,
    envConfig,
    PREVIEW_SEED
  );

  try {
    const shieldedObj = await walletProvider.wallet.shielded.getAddress();
    const shieldedString = MidnightBech32m.encode('test', shieldedObj).asString();
    console.log("SHIELDED ADDRESS (test):", shieldedString);
  } catch (e) {
    console.log(e);
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
