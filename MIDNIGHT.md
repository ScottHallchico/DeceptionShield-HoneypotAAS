# Midnight Integration Guide

## Overview

DeceptionShield integrates with the **Midnight** network to power its **Collective Defense Ledger**. This privacy-preserving ledger allows independent DeceptionShield deployments to securely share threat intelligence and collectively attest to attacker severity, without disclosing sensitive internal network details or the raw severity scores.

The smart contract is written in **Compact** and resides in `midnight/contract/src/defense_ledger.compact`.

## Setup and Compilation

We have fully verified the `defense_ledger.compact` contract using the official Compact compiler (`0.31.1`). 

### Compiling the Contract
The contract leverages `pragma language_version >= 0.23.0` and utilizes zero-knowledge predicates to verify high-confidence threats privately.

We provide a Dockerized build environment to guarantee reproducible compilation regardless of the host OS:
```bash
# Build the compiler image
docker build -t midnight-compiler3 -f midnight/contract/Dockerfile.compiler3 midnight/contract/

# Compile the contract to the bridge directory
docker run --rm -v "$(pwd):/app" -w /app/midnight/contract midnight-compiler3 bash -c "compact compile src/defense_ledger.compact /app/midnight-bridge/contract/"
```
This generates the TypeScript definitions and JavaScript bundle (`index.d.ts`, `index.js`) into `midnight-bridge/contract/contract/`.

## Deployment Status

**Current Status:** Integration Complete — Ready for Testnet Deployment

We have successfully resolved the previous blockers preventing end-to-end deployment:

1. **Empty Contract Interface (Fixed):** The `export` keywords were added to the `ledger` and `circuit` declarations in `defense_ledger.compact`. The contract now successfully compiles into complete TypeScript bindings with accessible state interfaces. We also secured the severity threshold check by wrapping it in `disclose()` to prevent private witness disclosure failures.
2. **SDK Provider API Migration (Fixed):** We refactored `midnight-bridge` to adopt the modern `@midnight-ntwrk/wallet` SDK architecture. We replaced the deprecated `createMidnightProvider` and `walletProvider` functions with the new `WalletBuilder` and discrete provider packages (e.g., `levelPrivateStateProvider`, `indexerPublicDataProvider`, `NodeZkConfigProvider`).

The application currently defaults to `MIDNIGHT_SIMULATE="true"` in the `docker-compose.yml` environment to allow rapid frontend/backend testing without requiring the heavy Midnight devnet to be running. 

To disable simulation and interact with the real deployed ledger, change `MIDNIGHT_SIMULATE="false"` in your docker-compose file!
