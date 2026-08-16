/**
 * midnight-bridge — Minimal internal HTTP service wrapping Midnight SDK calls.
 *
 * This is the ONLY component that talks to the Midnight proof server and wallet.
 * The Python backend calls it via normal internal HTTP requests, same pattern
 * already used for the pfSense REST API integration in the response engine.
 *
 * Endpoints:
 *   POST /attest         — submit an attestation (indicatorHash + severityScore)
 *   GET  /query/:hash    — look up corroboration count for an indicator
 *   GET  /stats          — return totalAttestations from ledger state
 *   GET  /health         — health check
 *
 * When MIDNIGHT_SIMULATE=true, all endpoints return realistic mock responses
 * without requiring a running proof server or deployed contract. This is the
 * default for local development.
 */

import dotenv from "dotenv";
dotenv.config();
import express from "express";
import cors from "cors";
import crypto from "crypto";

// Proven testkit-js pattern imports
import { deployContract } from '@midnight-ntwrk/midnight-js-contracts';
import { setNetworkId } from '@midnight-ntwrk/midnight-js-network-id';
import { MidnightWalletProvider, initializeMidnightProviders } from '@midnight-ntwrk/testkit-js';
import { httpClientProofProvider } from '@midnight-ntwrk/midnight-js-http-client-proof-provider';
import pino from 'pino';

const app = express();
app.use(cors());
app.use(express.json());

const PORT = parseInt(process.env.PORT || "3001", 10);
const SIMULATE = (process.env.MIDNIGHT_SIMULATE || "true") === "true";

// ─── In-memory simulation state ─────────────────────────────────────────────
const simState = {
  corroborationCount: new Map(),
  highConfidenceCount: new Map(),
  totalAttestations: 0,
  transactions: new Map(),
};

function simAttest(indicatorHash, severityScore) {
  const current = simState.corroborationCount.get(indicatorHash) || 0;
  simState.corroborationCount.set(indicatorHash, current + 1);
  simState.totalAttestations += 1;

  if (severityScore >= 70) {
    const currentHigh = simState.highConfidenceCount.get(indicatorHash) || 0;
    simState.highConfidenceCount.set(indicatorHash, currentHigh + 1);
  }

  const txHash = "0x" + crypto.randomBytes(32).toString("hex");
  simState.transactions.set(txHash, {
    indicatorHash,
    severityScore,
    timestamp: new Date().toISOString(),
    status: "confirmed",
  });

  return txHash;
}

function simQuery(indicatorHash) {
  return {
    corroborationCount: simState.corroborationCount.get(indicatorHash) || 0,
    highConfidenceCount: simState.highConfidenceCount.get(indicatorHash) || 0,
  };
}

let midnightContract = null;
let midnightProviders = null;
const logger = pino({ level: process.env.LOG_LEVEL || 'info' });

async function initMidnight() {
  if (SIMULATE) return;
  setNetworkId(process.env.MIDNIGHT_NETWORK_ID || 'undeployed');

  const envConfig = {
    walletNetworkId: process.env.MIDNIGHT_NETWORK_ID || 'undeployed',
    networkId: process.env.MIDNIGHT_NETWORK_ID || 'undeployed',
    indexer: process.env.MIDNIGHT_INDEXER_URL || 'http://127.0.0.1:8088/api/v4/graphql',
    indexerWS: process.env.MIDNIGHT_INDEXER_WS_URL || 'ws://127.0.0.1:8088/api/v4/graphql/ws',
    node: process.env.MIDNIGHT_NODE_URL || 'http://127.0.0.1:9944',
    nodeWS: (process.env.MIDNIGHT_NODE_URL || 'http://127.0.0.1:9944').replace('http', 'ws'),
    proofServer: process.env.MIDNIGHT_PROOF_SERVER_URL || 'http://127.0.0.1:6300',
    faucet: undefined,
  };

  const walletSeed = process.env.MIDNIGHT_WALLET_SEED;
  if (!walletSeed) throw new Error("MIDNIGHT_WALLET_SEED is required when MIDNIGHT_SIMULATE=false");

  const midnightWalletProvider = await MidnightWalletProvider.build(logger, envConfig, walletSeed);
  await midnightWalletProvider.start(true);

  midnightProviders = initializeMidnightProviders(
    midnightWalletProvider,
    envConfig,
    { privateStateStoreName: 'defense_ledger-private-state', zkConfigPath: process.env.MIDNIGHT_ZK_CONFIG_PATH || './zk-configs' },
  );

  const { ZKConfigProvider, createProverKey, createVerifierKey, createZKIR } = await import('@midnight-ntwrk/midnight-js-types');
  const fs = await import('fs/promises');
  const path = await import('path');
  
  class CustomZkConfigProvider extends ZKConfigProvider {
    constructor(zkConfigPath) { super(); this.zkConfigPath = zkConfigPath; }
    async getProverKey(circuitId) {
      const name = circuitId.split('#')[1] || circuitId;
      return createProverKey(await fs.readFile(path.resolve(this.zkConfigPath, 'keys', `${name}.prover`)));
    }
    async getVerifierKey(circuitId) {
      const name = circuitId.split('#')[1] || circuitId;
      return createVerifierKey(await fs.readFile(path.resolve(this.zkConfigPath, 'keys', `${name}.vk`)));
    }
    async getZKIR(circuitId) {
      const name = circuitId.split('#')[1] || circuitId;
      return createZKIR(await fs.readFile(path.resolve(this.zkConfigPath, 'zkir', `${name}.bzkir`)));
    }
  }

  midnightProviders.zkConfigProvider = new CustomZkConfigProvider(process.env.MIDNIGHT_ZK_CONFIG_PATH || '../midnight/contract/build/contract');
  midnightProviders.proofProvider = httpClientProofProvider(envConfig.proofServer, midnightProviders.zkConfigProvider);

  if (process.env.MIDNIGHT_CONTRACT_ADDRESS) {
    logger.info(`Joining existing contract at ${process.env.MIDNIGHT_CONTRACT_ADDRESS}`);
    // Contract attachment handled in deploy endpoint or custom init logic.
  } else {
    logger.info("No contract address provided, waiting for /deploy to be called...");
  }
}
initMidnight().catch(err => logger.error("Init failed:", err));

// ─── Routes ─────────────────────────────────────────────────────────────────

app.post("/deploy", async (req, res) => {
  if (SIMULATE) return res.status(400).json({ error: "Cannot deploy in simulate mode" });
  try {
     const { deployContract } = await import('@midnight-ntwrk/midnight-js-contracts');
     const defenseLedger = await import('../midnight/contract/build/defense_ledger.mjs');
     const { CompiledContract } = await import('@midnight-ntwrk/compact-js');
     
     if (!midnightProviders) throw new Error("Midnight providers not initialized");

     const contractInstance = CompiledContract.withWitnesses(
       CompiledContract.make('defenseLedger', defenseLedger.Contract),
       {}
     );
     
     midnightContract = await deployContract(midnightProviders, {
        compiledContract: contractInstance,
        initialPrivateState: {}
     });
     
     return res.json({
        contractAddress: midnightContract.deployTxData.public.contractAddress,
        status: "deployed"
     });
  } catch(err) {
     res.status(500).json({error: "Deploy failed", detail: String(err)});
  }
});

app.post("/attest", async (req, res) => {
  try {
    let { indicatorHash, severityScore } = req.body;
    if (indicatorHash.startsWith('0x')) indicatorHash = indicatorHash.slice(2);

    if (!indicatorHash || typeof indicatorHash !== "string") {
      return res.status(400).json({ error: "indicatorHash is required and must be a hex string" });
    }
    if (severityScore === undefined || typeof severityScore !== "number" || severityScore < 0 || severityScore > 100) {
      return res.status(400).json({ error: "severityScore is required and must be a number 0-100" });
    }

    if (SIMULATE) {
      const txHash = simAttest(indicatorHash, severityScore);
      logger.info(`[SIM] attestIndicator: hash=${indicatorHash.slice(0, 16)}… score=${severityScore} tx=${txHash.slice(0, 18)}…`);
      return res.json({ txHash, status: "confirmed" });
    }

    if (!midnightContract) throw new Error("Midnight contract not initialized. Have you deployed it?");

    logger.info(`[REAL] Sending attestIndicator for hash=${indicatorHash}`);
    
    // Hash conversion to Uint8Array
    const hashBytes = new Uint8Array(32);
    const buf = Buffer.from(indicatorHash, 'hex');
    hashBytes.set(buf.length > 32 ? buf.slice(0, 32) : buf);
    
    // Proper wrapper call interface for JS Contracts
    const tx = await midnightContract.callTx.attestIndicator(hashBytes, BigInt(severityScore));
    return res.json({ txHash: tx.public?.txHash || 'unknown_hash', status: "confirmed" });
  } catch (err) {
    logger.error("[ERROR] /attest failed:", err);
    return res.status(500).json({ error: "Attestation failed", detail: String(err), status: "failed" });
  }
});

app.get("/query/:hash", async (req, res) => {
  try {
    let { hash } = req.params;
    if (hash.startsWith('0x')) hash = hash.slice(2);

    if (SIMULATE) {
      const result = simQuery(hash);
      logger.info(`[SIM] queryIndicator: hash=${hash.slice(0, 16)}… corroboration=${result.corroborationCount}`);
      return res.json(result);
    }

    if (!midnightContract) throw new Error("Midnight contract not initialized.");

    logger.info(`[REAL] Querying queryIndicator for hash=${hash}`);
    
    const hashBytes = new Uint8Array(32);
    const buf = Buffer.from(hash, 'hex');
    hashBytes.set(buf.length > 32 ? buf.slice(0, 32) : buf);

    // Direct ledger read to bypass circuit execution constraints
    const publicState = await midnightProviders.publicDataProvider.queryContractState(midnightContract.deployTxData.public.contractAddress);
    const defenseLedger = await import('./contract/contract/index.js');
    const ledgerState = defenseLedger.ledger(publicState.data);

    const count = ledgerState.corroborationCount.member(hashBytes) 
      ? ledgerState.corroborationCount.lookup(hashBytes) 
      : 0n;

    return res.json({
      corroborationCount: Number(count),
      highConfidenceCount: ledgerState.highConfidenceCount.member(hashBytes)
        ? Number(ledgerState.highConfidenceCount.lookup(hashBytes))
        : 0
    });
  } catch (err) {
    logger.error("[ERROR] /query failed:", err);
    return res.status(500).json({ error: "Query failed", detail: String(err) });
  }
});

app.get("/stats", async (req, res) => {
  try {
    if (SIMULATE) {
      return res.json({
        totalAttestations: simState.totalAttestations,
        uniqueIndicators: simState.corroborationCount.size,
        networkMode: "simulate",
      });
    }

    if (!midnightContract) throw new Error("Midnight contract not initialized.");
    
    // Direct ledger state read
    const publicState = await midnightProviders.publicDataProvider.queryContractState(midnightContract.deployTxData.public.contractAddress);
    const defenseLedger = await import('./contract/contract/index.js');
    const ledgerState = defenseLedger.ledger(publicState.data);

    return res.json({
      totalAttestations: Number(ledgerState.totalAttestations),
      uniqueIndicators: Number(ledgerState.corroborationCount.size()),
      networkMode: process.env.MIDNIGHT_NETWORK || "real",
    });
  } catch (err) {
    logger.error("[ERROR] /stats failed:", err);
    return res.status(500).json({ error: "Stats query failed", detail: String(err) });
  }
});

app.get("/health", (req, res) => {
  res.json({
    status: "ok",
    service: "midnight-bridge",
    simulate: SIMULATE,
    network: process.env.MIDNIGHT_NETWORK || "local-devnet",
    contractAddress: process.env.MIDNIGHT_CONTRACT_ADDRESS || null,
    initialized: !!midnightContract
  });
});

// ─── Start ──────────────────────────────────────────────────────────────────

import { fileURLToPath } from 'url';
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  app.listen(PORT, () => {
    logger.info(`midnight-bridge listening on :${PORT} [simulate=${SIMULATE}]`);
  });
}

export default app;
