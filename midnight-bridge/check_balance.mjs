import { setNetworkId } from '@midnight-ntwrk/midnight-js-network-id';
import { MidnightWalletProvider } from '@midnight-ntwrk/testkit-js';
import { filter, firstValueFrom } from 'rxjs';
import pino from 'pino';

const PREVIEW_SEED = '64bec6f63b55eb27da454e2c368b7950ed8c516508cd979e469c77f6095b5deb';

const envConfig = {
  walletNetworkId: 'preview',
  networkId: 'preview',
  indexer: 'https://indexer.preview.midnight.network/api/v4/graphql',
  indexerWS: 'wss://indexer.preview.midnight.network/api/v4/graphql/ws',
  node: 'https://rpc.preview.midnight.network',
  nodeWS: 'wss://rpc.preview.midnight.network',
  proofServer: 'http://localhost:6300',
  faucet: undefined
};

async function main() {
  const logger = pino({ level: 'silent' });
  setNetworkId('preview');

  const midnightWalletProvider = await MidnightWalletProvider.build(
    logger,
    envConfig,
    PREVIEW_SEED
  );

  console.log("Connecting and syncing with network to obtain DUST...");
  await midnightWalletProvider.start(false);
  
  const state = await firstValueFrom(midnightWalletProvider.wallet.state());

  const formatObj = (obj) => {
    return JSON.stringify(obj, (key, value) =>
      typeof value === 'bigint' ? value.toString() : value, 2);
  };
  
  console.log("Preview wallet balance:");
  console.log(formatObj({
    unshielded: state.unshielded.state.state,
    shielded: state.balances,
    syncProgress: state.unshielded.state.progress
  }));

  process.exit(0);
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
