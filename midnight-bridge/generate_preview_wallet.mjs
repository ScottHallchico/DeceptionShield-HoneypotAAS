/**
 * generate_preview_wallet.mjs
 * 
 * Generates a Midnight Preview wallet using testkit-js, prints the
 * Bech32m receiving address so the user can fund it via the faucet.
 * 
 * Usage: node generate_preview_wallet.mjs
 */

import crypto from 'crypto';
import { setNetworkId } from '@midnight-ntwrk/midnight-js-network-id';
import { MidnightWalletProvider } from '@midnight-ntwrk/testkit-js';
import pino from 'pino';

import dotenv from 'dotenv';
dotenv.config();
const PREVIEW_SEED = process.env.MIDNIGHT_WALLET_SEED;
if (!PREVIEW_SEED) throw new Error("Missing MIDNIGHT_WALLET_SEED in .env");

const envConfig = {
  walletNetworkId: 'preview',
  networkId: 'preview',
  indexer: 'https://indexer.preview.midnight.network/api/v4/graphql',
  indexerWS: 'wss://indexer.preview.midnight.network/api/v4/graphql/ws',
  node: 'https://rpc.preview.midnight.network',
  nodeWS: 'wss://rpc.preview.midnight.network',
  proofServer: 'http://localhost:6300',
  faucet: undefined,
};

async function main() {
  const logger = pino({ level: 'info' });
  
  console.log('\n=== Midnight Preview Wallet Generator ===\n');
  console.log(`Generated Wallet Seed (SAVE THIS): ${PREVIEW_SEED}`);
  console.log(`Network: preview`);
  console.log(`Indexer: ${envConfig.indexer}`);
  console.log(`Node:    ${envConfig.node}\n`);

  setNetworkId('preview');

  console.log('Building wallet provider (this connects to Preview indexer)...');
  const walletProvider = await MidnightWalletProvider.build(
    logger,
    envConfig,
    PREVIEW_SEED
  );

  // Don't call start(true) — that waits for funds from a faucet that doesn't exist on Preview.
  // Instead just start without waiting for balance.
  console.log('Starting wallet (without waiting for funds)...');
  await walletProvider.start(false);

  // Get the wallet's state / address
  const state = await walletProvider.state();
  console.log('\n=== WALLET STATE ===');
  console.log(JSON.stringify(state, (key, value) =>
    typeof value === 'bigint' ? value.toString() : value
  , 2));

  // Try to get the address directly
  if (state.address) {
    console.log(`\n>>> RECEIVING ADDRESS: ${state.address}`);
  }
  if (state.coinPublicKey) {
    console.log(`>>> COIN PUBLIC KEY: ${state.coinPublicKey}`);
  }

  // Also try balanceAndAddress if available
  try {
    const balance = await walletProvider.balanceAndAddress();
    console.log('\n=== BALANCE AND ADDRESS ===');
    console.log(JSON.stringify(balance, (key, value) =>
      typeof value === 'bigint' ? value.toString() : value
    , 2));
  } catch (e) {
    console.log('balanceAndAddress() not available:', e.message);
  }

  console.log('\n=== DONE ===');
  console.log('Copy the receiving address above and paste it into the Midnight Preview faucet.');
  console.log('Faucet URL: https://docs.midnight.network/getting-started');
  console.log(`\nWallet Seed (needed for deployment): ${PREVIEW_SEED}`);
  
  process.exit(0);
}

main().catch(err => {
  console.error('Failed:', err);
  process.exit(1);
});
