// SYNTHETIC FIXTURE — not real code, not a real exploit, no real keys.
// Demonstrates the April 2026 Drift "fake oracle collateral" vector:
// pushing a token onto the oracle allow-list without checking its
// liquidity / volume. Pattern-detected by LOW_LIQUIDITY_ORACLE_WHITELIST.

use anchor_lang::prelude::*;

#[derive(Accounts)]
pub struct AddOracle<'info> {
    #[account(mut)]
    pub admin: Signer<'info>,
    #[account(mut)]
    pub oracle_config: Account<'info, OracleConfig>,
}

#[account]
pub struct OracleConfig {
    pub admin: Pubkey,
    pub oracle_whitelist: Vec<Pubkey>,
}

// BAD PATTERN — no liquidity gate before the push.
// The real Drift exploit seeded "CarbonVote Token" via this code path.
pub fn add_oracle_bad(ctx: Context<AddOracle>, mint: Pubkey) -> Result<()> {
    require_keys_eq!(ctx.accounts.admin.key(), ctx.accounts.oracle_config.admin);

    // Directly pushes onto the allow-list — no liquidity / volume / depth
    // precondition anywhere above this line within the 30-line window.
    ctx.accounts.oracle_config.oracle_whitelist.push(mint);

    msg!("oracle added: {}", mint);
    Ok(())
}
