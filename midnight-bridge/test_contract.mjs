import { deployContract } from '@midnight-ntwrk/midnight-js-contracts';
import { setNetworkId } from '@midnight-ntwrk/midnight-js-network-id';
import { MidnightWalletProvider, initializeMidnightProviders } from '@midnight-ntwrk/testkit-js';
import pino from 'pino';
import * as defenseLedger from './contract/contract/index.js';

const GENESIS_MINT_WALLET_SEED = '0000000000000000000000000000000000000000000000000000000000000001';

const indexerUrl = 'http://127.0.0.1:8088/api/v4/graphql';
const indexerWsUrl = 'ws://127.0.0.1:8088/api/v4/graphql/ws';
const proverUrl = 'http://127.0.0.1:6300';
const nodeUrl = 'http://127.0.0.1:9944';

async function main() {
  const logger = pino({ level: 'info' });
  setNetworkId('preview');
  
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

  // Seed with funded tNIGHT
  import dotenv from 'dotenv';
  dotenv.config();
  const PREVIEW_SEED = process.env.MIDNIGHT_WALLET_SEED;
  if (!PREVIEW_SEED) throw new Error("Missing MIDNIGHT_WALLET_SEED in .env");

  logger.info("Initializing Wallet with testkit-js...");
  const midnightWalletProvider = await MidnightWalletProvider.build(
    logger,
    envConfig,
    PREVIEW_SEED
  );

  logger.info("Starting wallet and waiting for funds...");
  // start(true) waits for funds!
  await midnightWalletProvider.start(true);

  logger.info("Setting up MidnightProviders...");
  const contractConfig = {
    privateStateStoreName: 'defense_ledger-private-state',
    zkConfigPath: './zk-configs',
  };
  
  const providers = initializeMidnightProviders(
    midnightWalletProvider,
    envConfig,
    contractConfig
  );

  const { ZKConfigProvider, createProverKey, createVerifierKey, createZKIR } = await import('@midnight-ntwrk/midnight-js-types');
  const fs = await import('fs/promises');
  const path = await import('path');

  class CustomZkConfigProvider extends ZKConfigProvider {
    constructor(zkConfigPath) {
      super();
      this.zkConfigPath = zkConfigPath;
    }
    async getProverKey(circuitId) {
      const circuitName = circuitId.split('#')[1] || circuitId;
      const filePath = path.resolve(this.zkConfigPath, 'keys', circuitName + '.prover');
      const buffer = await fs.readFile(filePath);
      return createProverKey(buffer);
    }
    async getVerifierKey(circuitId) {
      const circuitName = circuitId.split('#')[1] || circuitId;
      const filePath = path.resolve(this.zkConfigPath, 'keys', circuitName + '.vk');
      const buffer = await fs.readFile(filePath);
      return createVerifierKey(buffer);
    }
    async getZKIR(circuitId) {
      const circuitName = circuitId.split('#')[1] || circuitId;
      const filePath = path.resolve(this.zkConfigPath, 'zkir', circuitName + '.bzkir');
      const buffer = await fs.readFile(filePath);
      return createZKIR(buffer);
    }
  }

  providers.zkConfigProvider = new CustomZkConfigProvider('./contract');
  
  // Also proofProvider needs the new zkConfigProvider!
  const { httpClientProofProvider } = await import('@midnight-ntwrk/midnight-js-http-client-proof-provider');
  providers.proofProvider = httpClientProofProvider(envConfig.proofServer, providers.zkConfigProvider);

  const { CompiledContract } = await import('@midnight-ntwrk/compact-js');
  const contractInstance = CompiledContract.withWitnesses(
    CompiledContract.make('defenseLedger', defenseLedger.Contract),
    {}
  );

  logger.info("Deploying Defense Ledger contract...");
  const deployedContract = await deployContract(
    providers,
    {
      compiledContract: contractInstance,
      initialPrivateState: {}
    }
  );

  logger.info(`Contract deployed! Contract Address: ${deployedContract.deployTxData.public.contractAddress}`);

  logger.info("Contract deployment and interaction successful.");
  process.exit(0);
}

main().catch(error => {
  console.error(error);
  process.exit(1);
});
