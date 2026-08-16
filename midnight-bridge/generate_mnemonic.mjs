import { generateMnemonicWords, mnemonicToWords, generateRandomSeed } from '@midnight-ntwrk/wallet-sdk';
import crypto from 'crypto';

async function generate() {
    const words = generateMnemonicWords();
    console.log("Mnemonic (24 words):");
    console.log(words.join(" "));
    // Wait, testkit-js MidnightWalletProvider doesn't take mnemonic directly,
    // but we can generate a random seed directly.
    console.log("If you need to import into Lace, use the 24 words above.");
}

generate();
