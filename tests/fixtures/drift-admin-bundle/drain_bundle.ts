// SYNTHETIC FIXTURE — not real code, not a real exploit, no real keys.
// Demonstrates the April 2026 Drift "unbounded admin bundle" pattern:
// a single tx chains ComputeBudget + multiple admin-level instructions
// (SetAuthority + UpgradeProgram). Pattern-detected by
// UNBOUNDED_ADMIN_INSTRUCTION_BUNDLE.

import {
  Transaction,
  ComputeBudgetProgram,
  PublicKey,
  TransactionInstruction,
} from "@solana/web3.js";

const PROGRAM_ID = new PublicKey("11111111111111111111111111111111");
const AUTH = new PublicKey("11111111111111111111111111111111");
const NEW_AUTH = new PublicKey("11111111111111111111111111111111");

function setAuthorityIx(): TransactionInstruction {
  // Placeholder for a SetAuthority instruction.
  return {
    keys: [
      { pubkey: PROGRAM_ID, isSigner: false, isWritable: true },
      { pubkey: AUTH, isSigner: true, isWritable: false },
    ],
    programId: PROGRAM_ID,
    data: Buffer.from([6, ...NEW_AUTH.toBytes()]),
  } as TransactionInstruction;
}

function upgradeProgramIx(): TransactionInstruction {
  // Placeholder for an UpgradeProgram instruction.
  return {
    keys: [
      { pubkey: PROGRAM_ID, isSigner: false, isWritable: true },
      { pubkey: AUTH, isSigner: true, isWritable: false },
    ],
    programId: new PublicKey("BPFLoaderUpgradeab1e11111111111111111111111"),
    data: Buffer.from([3]),
  } as TransactionInstruction;
}

// BAD PATTERN — bundles ComputeBudget + SetAuthority + UpgradeProgram in
// one tx. Any one of these should sit in its own signed message.
export function buildDrainBundle(): Transaction {
  const tx = new Transaction();
  tx.add(ComputeBudgetProgram.setComputeUnitLimit({ units: 1_400_000 }));
  tx.add(ComputeBudgetProgram.setComputeUnitPrice({ microLamports: 10_000 }));
  tx.add(setAuthorityIx());
  tx.add(upgradeProgramIx());
  tx.add(setAuthorityIx());
  return tx;
}
