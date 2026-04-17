// SYNTHETIC FIXTURE -- not real code, not a real exploit, no real keys.
// Demonstrates the April 2026 Drift attack shape: a durable-nonce
// AdvanceNonce instruction built in the same tx-building function as a
// SetAuthority instruction. Pattern-detected by NONCE_ADVANCE_IN_MULTISIG.

import { Transaction, SystemProgram, PublicKey } from "@solana/web3.js";

const NONCE_ACCOUNT = new PublicKey("11111111111111111111111111111111");
const AUTHORITY = new PublicKey("11111111111111111111111111111111");
const NEW_AUTHORITY = new PublicKey("11111111111111111111111111111111");
const PROGRAM_ID = new PublicKey("11111111111111111111111111111111");

export function buildPreSignedAdminTransfer(feePayer: PublicKey): Transaction {
  const tx = new Transaction();

  // Step 1 -- advance the durable nonce so this tx can be held pre-signed
  // off-chain indefinitely. This is what the Drift attacker exploited.
  const advanceNonceIx = SystemProgram.nonceAdvance({
    noncePubkey: NONCE_ACCOUNT,
    authorizedPubkey: AUTHORITY,
  });
  tx.add(advanceNonceIx);

  // Step 2 -- change program authority. In the real exploit this was
  // wrapped in a Squads multisig and co-signed by compromised members.
  // Combining AdvanceNonce + SetAuthority in one tx is the tell.
  const setAuthIx = {
    keys: [
      { pubkey: PROGRAM_ID, isSigner: false, isWritable: true },
      { pubkey: AUTHORITY, isSigner: true, isWritable: false },
    ],
    programId: new PublicKey("BPFLoaderUpgradeab1e11111111111111111111111"),
    data: Buffer.from([4, ...NEW_AUTHORITY.toBytes()]), // synthetic SetAuthority discriminator
  };
  tx.add(setAuthIx);

  tx.feePayer = feePayer;
  return tx;
}
