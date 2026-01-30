# Example 06: PDA Seed Collision Vulnerabilities

## Overview

This example demonstrates Program Derived Address (PDA) seed collision vulnerabilities. PDAs are fundamental to Solana program design, but improper seed derivation can lead to address collisions, allowing attackers to control supposedly unique accounts.

## The Vulnerability

PDAs use seeds deterministically derived from program ID and seed values. Without proper design:
1. **Predictable seeds** - Using only user-provided seeds enables collision
2. **Insufficient entropy** - Seeds without unique program-specific values
3. **Weak seed combinations** - Not combining all relevant parameters
4. **Reusable PDAs** - Same PDA used across different contexts
5. **User-controlled seeds** - Accepting arbitrary seed values

**Without protection, attackers can:**
- Collide with PDAs they don't own to control them
- Re-initialize closed PDAs with fake data
- Forge PDA proofs across different contexts
- Create cross-contract PDA conflicts

## Real-World Impact

### PDA Collision Exploits
- **Loss:** Multiple millions in aggregate
- **Root Cause:** Weak or user-controlled seed combinations
- **Pattern:** Accepting all seeds from instruction data
- **Impact:** Account ownership confusion, state manipulation

### Notable Incidents
- Stake pool protocols: Colliding PDAs enabled unauthorized withdrawals
- Liquidity pool implementations: Predictable seed patterns broke invariants
- NFT standards: PDA collisions created account ownership conflicts
- Governance systems: Colliding proposal PDAs enabled proposal interference

## Vulnerable Implementation

**Key Issues:**

```rust
// ❌ PROBLEM 1: User-controlled seed collision
pub fn create_user_account(ctx: Context<CreateUser>, user: Pubkey, custom_seed: String) -> Result<()> {
    // ❌ Attacker can choose custom_seed to collide with another user's PDA
    let (_pda, _bump) = Pubkey::find_program_address(
        &[b"user", user.as_ref(), custom_seed.as_bytes()],
        &crate::ID,
    );
    
    // Create account at this PDA
}

// ❌ PROBLEM 2: Insufficient entropy - only user key
pub fn create_vault(ctx: Context<CreateVault>, user: Pubkey) -> Result<()> {
    // ❌ Only user pubkey as seed - insufficient entropy
    let (pda, bump) = Pubkey::find_program_address(
        &[b"vault", user.as_ref()],
        &crate::ID,
    );
    
    // Any user can create multiple "vault" PDAs by using different user values
}

// ❌ PROBLEM 3: Reusable PDA across contexts
pub fn stake(ctx: Context<Stake>, amount: u64) -> Result<()> {
    // ❌ Same PDA used for both staking and lending
    // Attacker exploits this by colliding with lending account
}

pub fn lend(ctx: Context<Lend>, amount: u64) -> Result<()> {
    // ❌ Same seed pattern creates collision risk
}

// ❌ PROBLEM 4: User chooses all seeds
#[derive(Accounts)]
pub struct CreateAccount<'info> {
    #[account(
        init,
        payer = authority,
        space = 8 + MyAccount::LEN,
        seeds = [b"user", user_seed.as_bytes()],  // ❌ ALL from user!
        bump,
    )]
    pub account: Account<'info, MyAccount>,
    
    pub authority: Signer<'info>,
    // ... missing other constraints
}

// ❌ PROBLEM 5: No validation of PDA derivation in instruction
pub fn initialize_existing(ctx: Context<InitExisting>, seed: String) -> Result<()> {
    let (expected_pda, expected_bump) = Pubkey::find_program_address(
        &[b"account", seed.as_bytes()],
        &crate::ID,
    );
    
    // ❌ Attacker could pass wrong PDA and this won't catch it
    // Only validates if it matches computed value, but computation is weak
    require!(ctx.accounts.account.key() == expected_pda, ...);
}
```

## Secure Implementation

**Security Features:**

- Uses multiple seeds including unique identifiers
- Incorporates all relevant parameters into seed
- Limits entropy to program-controlled values
- Validates PDA derivation explicitly
- Creates separate PDA patterns for different purposes

```rust
// ✅ Secure PDA with user key + authority + counter
pub fn create_user_account(
    ctx: Context<CreateUser>,
    index: u32,  // User chooses which index they want
) -> Result<()> {
    // Seeds include:
    // 1. Context identifier (b"user")
    // 2. User's public key (unique per user)
    // 3. Authority address (prevents cross-user collision)
    // 4. Index counter (allows multiple accounts per user-authority pair)
    
    let seeds = [
        b"user".as_ref(),
        ctx.accounts.user.key().as_ref(),
        ctx.accounts.authority.key().as_ref(),
        index.to_le_bytes().as_ref(),
    ];
    
    let (pda, bump) = Pubkey::find_program_address(&seeds, &crate::ID);
    
    require!(
        ctx.accounts.account.key() == pda,
        ErrorCode::InvalidPDADerivation
    );
    
    Ok(())
}

// ✅ Anchor's constraint prevents collision automatically
#[derive(Accounts)]
pub struct CreateVault<'info> {
    #[account(
        init,
        payer = authority,
        space = 8 + Vault::LEN,
        seeds = [
            b"vault",
            authority.key().as_ref(),  // Unique per authority
            vault_id.to_le_bytes().as_ref(),  // Unique per vault
        ],
        bump,
    )]
    pub vault: Account<'info, Vault>,
    
    #[account(mut)]
    pub authority: Signer<'info>,
    
    pub system_program: Program<'info, System>,
}

pub fn create_vault(ctx: Context<CreateVault>, vault_id: u32) -> Result<()> {
    // ✅ Anchor automatically validates PDA derivation
    // ✅ Collision impossible because vault_id is unique per authority
    let vault = &mut ctx.accounts.vault;
    vault.authority = ctx.accounts.authority.key();
    vault.vault_id = vault_id;
    vault.bump = ctx.bumps.vault;  // Store canonical bump
    
    msg!("Vault created with ID: {}", vault_id);
    Ok(())
}

// ✅ Separate context for different account types prevents cross-context collision
#[derive(Accounts)]
pub struct CreateStakeAccount<'info> {
    #[account(
        init,
        payer = authority,
        space = 8 + StakeAccount::LEN,
        seeds = [
            b"stake",  // ✅ Different context prefix
            user.key().as_ref(),
            authority.key().as_ref(),
        ],
        bump,
    )]
    pub stake_account: Account<'info, StakeAccount>,
    
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct CreateLendAccount<'info> {
    #[account(
        init,
        payer = authority,
        space = 8 + LendAccount::LEN,
        seeds = [
            b"lend",  // ✅ Different context prefix
            user.key().as_ref(),
            authority.key().as_ref(),
        ],
        bump,
    )]
    pub lend_account: Account<'info, LendAccount>,
    
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

// ✅ Validate PDA derivation explicitly in code
pub fn use_account(ctx: Context<UseAccount>, expected_bump: u8) -> Result<()> {
    // Recompute PDA to verify it matches
    let seeds = [
        b"vault".as_ref(),
        ctx.accounts.user.key().as_ref(),
        ctx.accounts.vault_id.to_le_bytes().as_ref(),
    ];
    
    let (computed_pda, _) = Pubkey::find_program_address(&seeds, &crate::ID);
    
    require!(
        ctx.accounts.account.key() == computed_pda,
        ErrorCode::InvalidPDADerivation
    );
    
    // Validate bump matches expected
    require!(
        expected_bump == ctx.bumps["account"],
        ErrorCode::InvalidBump
    );
    
    Ok(())
}
```

## Testing

- **Exploit test** (`tests/exploit.ts`): Demonstrates PDA collision attacks
- **Secure test** (`tests/secure.ts`): Validates collision resistance

## Learning Objectives

1. Understand PDA derivation and collision mechanics
2. Design strong seed combinations
3. Implement collision-resistant PDA patterns
4. Use Anchor's PDA constraints properly
5. Test for collision vulnerabilities
6. Validate PDA derivation in critical functions

## Key Takeaways

- **Include program-controlled identifiers in all seeds**
- **Use both user key AND authority key to prevent collisions**
- **Add index/counter for multiple accounts per user-authority pair**
- **Use different seed prefixes for different account types** (b"vault" vs b"stake" vs b"lend")
- **Always validate PDA derivation matches expectations**
- **Never accept arbitrary seed values from instruction data**
- **Store and validate bump values in accounts**

## PDA Design Principles

1. **Entropy**: Seeds must be unique and deterministic
2. **Specificity**: Each account type needs unique seed prefix
3. **Immutability**: Seeds cannot change after creation
4. **Isolation**: Different purposes use different patterns
5. **Validation**: Always verify computed PDA matches passed account

## Files in This Example

- `programs/vulnerable/src/lib.rs` - Weak PDA seed design
- `programs/secure/src/lib.rs` - Collision-resistant PDA patterns
- `tests/exploit.ts` - Demonstrates PDA collision attacks
- `tests/secure.ts` - Validates secure PDA derivation
