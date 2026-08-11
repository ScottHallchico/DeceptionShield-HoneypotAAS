# DeceptionShield × Midnight — Collective Defense Ledger

**Brainwave 2026 – Midnight Blockchain Track**

## Overview
DeceptionShield is a Honeypot-as-a-Service platform for SMBs. It detects and blocks attackers in real-time. By integrating **Midnight**, we upgrade this from an isolated security tool into a **privacy-preserving, collective threat-intelligence network**. 

The core problem we solve: Threat intelligence sharing usually requires disclosing who was attacked, the severity, and the attacker's identity. This exposes SMBs to competitive risk and makes them targets. By using Midnight's zero-knowledge capabilities, DeceptionShield allows SMBs to securely pool intelligence and prove the severity of threats without leaking any sensitive data. The more SMBs on the network, the smarter the autonomous defense gets for everyone.

Here is how our project addresses the Brainwave 2026 Midnight Track judging criteria:

---

## 1. Innovation & Creativity (25%)
**Why Midnight?** We didn't just bolt a blockchain onto a Web2 app. This use-case *requires* Midnight. On a transparent chain, corroborating an attack leaks competitive risk, internal security posture, and tips off the attacker. 
By utilizing Midnight's Data Protection capabilities, our `defense_ledger.compact` contract leverages ZK-proofs to prove:
* *"This honeypot's severity assessment of an attacker is above the high-confidence threshold"*
...disclosing only a boolean "yes", while keeping the actual severity score, the organization's identity, and the exact honeypot type completely hidden in the ZK Witness.

## 2. Technical Implementation (25%)
**How it Works:** 
- **Off-Chain Hashing:** `SHA-256(attacker_ip + per-deployment_salt)` is computed in the Python backend. The raw IP never touches the blockchain.
- **Node.js Bridge:** Because Midnight's SDK is TypeScript-first and our backend is Python, we built `midnight-bridge`—an internal HTTP sidecar that seamlessly wraps the Midnight SDK and wallet connections.
- **Compact Smart Contract:** We built `defense_ledger.compact` with two circuits:
  - `attestIndicator()`: State-mutating. Increments global counters and private threshold counters.
  - `queryIndicator()`: Read-only. Returns the current network corroboration count for an anonymized hash.

## 3. Impact & Problem Solving (20%)
**The Problem:** Small to medium businesses (SMBs) lack the budget for enterprise threat intel networks. They are isolated.
**The Solution:** DeceptionShield democratizes threat intelligence. When an attacker hits one SMB's honeypot, the system hashes the IP and calls `attestIndicator()`. Before another SMB's firewall blocks a suspicious ping, their response engine calls `queryIndicator()`. If the attacker has been corroborated on Midnight by other network peers, the blocking threshold drops by 30%. This makes collective intelligence a real, automated input to firewall decisions, not just a static log.

## 4. User Experience & Design (15%)
DeceptionShield is designed for security operators to instantly see the value of Midnight:
- **Live Threat Ledger:** A dedicated dashboard page visualizes the Midnight ZK-corroborations pulsing in real-time.
- **Verified Badges:** When the firewall blocks an IP, the Blocklist UI polls the Midnight bridge. Once the transaction confirms, a "Verified on Midnight ✓" badge appears with a direct link to the transaction on the Midnight Explorer.
- **Seamless:** Security admins do not need to understand ZK proofs. The entire Midnight attestation process happens silently in the background, autonomously fortifying their defenses.

## 5. Scalability & Feasibility (10%)
- **Data Minimization:** Only anonymized 32-byte hashes are stored on the ledger state (`Map<Bytes<32>, Uint<32>>`). This guarantees that ledger bloat is kept to an absolute minimum.
- **Stateless Integration:** The Python backend doesn't need to maintain a heavy blockchain node. It relies purely on the lightweight Node.js sidecar for attestation, allowing DeceptionShield deployments to scale horizontally.

## 6. Presentation & Demo (5%)
The demo showcases the complete end-to-end flow:
1. **Attack:** An attacker brute-forces a DeceptionShield Cowrie honeypot.
2. **Block & Attest:** The Python Response Engine evaluates the threat, blocks the IP locally, and simultaneously dispatches the ZK-proof via the Midnight bridge.
3. **Verification:** The "Verified on Midnight" badge pops up on the blocklist, linking to the actual on-chain transaction.
4. **Collective Intelligence:** The Threat Ledger increments the corroboration count, proving that the rest of the network is now instantly protected from that attacker.
