use anchor_lang::prelude::*;

declare_id!("Secur3Va1id222222222222222222222222222222");

#[program]
pub mod missing_validation_secure {
    use super::*;

    /// Initialize a user account with proper PDA derivation
    ///
    /// SECURITY FEATURES:
    /// - Uses PDA with seeds for deterministic address
    /// - Implicit owner check via Account<> type
    /// - Stores canonical bump for future verification
    pub fn initialize(ctx: Context<Initialize>, name: String) -> Result<()> {
        let user_account = &mut ctx.accounts.user_account;
        
        // [SECURE] Account is properly initialized as PDA
        // [SECURE] Owner is implicitly verified by Account<> type
        // [SECURE] PDA seeds and bump are verified by Anchor
        user_account.authority = ctx.accounts.authority.key();
        user_account.name = name;
        user_account.points = 0;
        user_account.bump = ctx.bumps.user_account;  // Store canonical bump
        
        msg!("User account initialized securely for: {}", user_account.name);
        Ok(())
    }

    /// Transfer points between accounts with full validation
    ///
    /// SECURITY FEATURES:
    /// - Verifies PDA derivation with seeds and bump
    /// - Checks account ownership implicitly via Account<>
    /// - Requires authority to be signer
    /// - Uses has_one to validate authority relationship
    /// - Checked arithmetic prevents overflow/underflow
    pub fn transfer_points(
        ctx: Context<TransferPoints>,
        amount: u64,
    ) -> Result<()> {
        let from = &mut ctx.accounts.from;
        let to = &mut ctx.accounts.to;

        // [SECURE] Both accounts are verified PDAs (seeds/bump checked)
        // [SECURE] Account ownership verified (must be owned by this program)
        // [SECURE] Authority verified via has_one constraint
        // [SECURE] Authority must have signed (Signer<> type)
        
        // [SECURE] SECURE: Checked arithmetic with explicit error
        from.points = from.points
            .checked_sub(amount)
            .ok_or(ErrorCode::InsufficientPoints)?;
        
        to.points = to.points
            .checked_add(amount)
            .ok_or(ErrorCode::Overflow)?;

        msg!("Securely transferred {} points", amount);
        Ok(())
    }

    /// Withdraw funds from vault with complete validation
    ///
    /// SECURITY FEATURES:
    /// - PDA verification with stored bump
    /// - Authority must be signer
    /// - Authority relationship validated via has_one
    /// - Owner check implicit in Account<> type
    /// - No authority parameter (uses verified signer only)
    pub fn withdraw(
        ctx: Context<Withdraw>,
        amount: u64,
    ) -> Result<()> {
        // [SECURE] SECURE: No vault_authority parameter accepted
        // [SECURE] SECURE: Authority verified as signer
        // [SECURE] SECURE: has_one ensures vault.authority == authority.key()
        // [SECURE] SECURE: PDA verified with seeds and bump
        
        let vault = &mut ctx.accounts.vault;
        
        // [SECURE] SECURE: Checked arithmetic
        vault.balance = vault.balance
            .checked_sub(amount)
            .ok_or(ErrorCode::InsufficientBalance)?;
        
        // Transfer would happen here using CPI with authority as signer...
        msg!("Securely withdrew {} lamports", amount);
        Ok(())
    }

    /// Initialize vault with PDA
    pub fn initialize_vault(ctx: Context<InitializeVault>) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        vault.authority = ctx.accounts.authority.key();
        vault.balance = 0;
        vault.bump = ctx.bumps.vault;
        
        msg!("Vault initialized securely");
        Ok(())
    }
}

// ============================================================================
// SECURE ACCOUNT VALIDATION STRUCTS
// ============================================================================

#[derive(Accounts)]
pub struct Initialize<'info> {
    /// [SECURE] SECURE: PDA with seeds ensures deterministic address
    /// [SECURE] SECURE: Only this program can create this PDA
    /// [SECURE] SECURE: Account ownership verified implicitly
    #[account(
        init,
        payer = authority,
        space = 8 + UserAccount::LEN,
        seeds = [b"user", authority.key().as_ref()],
        bump,
    )]
    pub user_account: Account<'info, UserAccount>,
    
    #[account(mut)]
    pub authority: Signer<'info>,  // [SECURE] Must sign
    
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct TransferPoints<'info> {
    /// [SECURE] SECURE: PDA verification with seeds and stored bump
    /// [SECURE] SECURE: has_one verifies authority relationship
    /// [SECURE] SECURE: Owner check via Account<> type
    #[account(
        mut,
        seeds = [b"user", authority.key().as_ref()],
        bump = from.bump,  // Verify with stored bump
        has_one = authority,  // Verify authority matches
    )]
    pub from: Account<'info, UserAccount>,
    
    /// [SECURE] SECURE: Recipient account also verified as valid PDA
    #[account(
        mut,
        seeds = [b"user", to.authority.as_ref()],
        bump = to.bump,
    )]
    pub to: Account<'info, UserAccount>,
    
    /// [SECURE] SECURE: Must be signer
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    /// [SECURE] SECURE: PDA with seeds and bump verification
    /// [SECURE] SECURE: has_one links vault.authority to signer
    /// [SECURE] SECURE: Owner checked via Account<> type
    #[account(
        mut,
        seeds = [b"vault", authority.key().as_ref()],
        bump = vault.bump,
        has_one = authority,  // [SECURE] Ensures vault.authority == authority.key()
    )]
    pub vault: Account<'info, Vault>,
    
    /// [SECURE] SECURE: Must sign the transaction
    pub authority: Signer<'info>,
    
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct InitializeVault<'info> {
    #[account(
        init,
        payer = authority,
        space = 8 + Vault::LEN,
        seeds = [b"vault", authority.key().as_ref()],
        bump,
    )]
    pub vault: Account<'info, Vault>,
    
    #[account(mut)]
    pub authority: Signer<'info>,
    
    pub system_program: Program<'info, System>,
}

// ============================================================================
// ACCOUNT STRUCTURES
// ============================================================================

#[account]
pub struct UserAccount {
    pub authority: Pubkey,    // 32 bytes
    pub name: String,         // 4 + 50 bytes
    pub points: u64,          // 8 bytes
    pub bump: u8,             // 1 byte - stored for efficiency
}

impl UserAccount {
    pub const LEN: usize = 32 + 4 + 50 + 8 + 1;
}

#[account]
pub struct Vault {
    pub authority: Pubkey,    // 32 bytes
    pub balance: u64,         // 8 bytes
    pub bump: u8,             // 1 byte
}

impl Vault {
    pub const LEN: usize = 32 + 8 + 1;
}

// ============================================================================
// ERRORS
// ============================================================================

#[error_code]
pub enum ErrorCode {
    #[msg("Unauthorized access attempt")]
    Unauthorized,
    
    #[msg("Insufficient points for transfer")]
    InsufficientPoints,
    
    #[msg("Arithmetic overflow")]
    Overflow,
    
    #[msg("Insufficient balance in vault")]
    InsufficientBalance,
}

// ============================================================================
// SECURITY IMPLEMENTATION NOTES
// ============================================================================
//
// HOW THIS PREVENTS EXPLOITS:
//
// 1. PDA VERIFICATION (seeds + bump):
//    - Accounts derived deterministically from seeds
//    - Only program can create accounts at these addresses
//    - Attacker cannot pass arbitrary accounts
//    - Example: seeds = [b"user", authority.key()]
//      ensures each authority has unique user account
//
// 2. OWNER VALIDATION (Account<T> type):
//    - Account<> type automatically checks account.owner == program_id
//    - Fails deserialization if owner mismatch
//    - No way to pass accounts owned by other programs
//
// 3. AUTHORITY VERIFICATION (has_one):
//    - has_one = authority ensures account.authority == authority.key()
//    - Validates relationship between account and signer
//    - Prevents using someone else's account
//
// 4. SIGNER REQUIREMENT (Signer<'info>):
//    - Signer<> type requires account.is_signer == true
//    - Transaction must be signed by this keypair
//    - Cannot be spoofed with public key
//
// 5. CHECKED ARITHMETIC:
//    - checked_sub/checked_add return None on overflow/underflow
//    - ok_or converts None to error
//    - Transaction fails instead of wrapping
//
// 6. NO PARAMETER ACCEPTANCE:
//    - withdraw() doesn't accept vault_authority parameter
//    - Uses verified signer directly
//    - Prevents attacker-controlled input
//
// DEFENSE IN DEPTH:
// Each security feature provides a layer of protection.
// Even if one check is bypassed, others remain.
//
// ANCHOR CONSTRAINTS USED:
// - init: Creates new account with rent exemption
// - seeds: Specifies PDA derivation seeds
// - bump: Verifies canonical bump seed
// - has_one: Validates field relationship
// - mut: Allows account modification
// - Account<T>: Adds owner + discriminator checks
// - Signer<T>: Requires transaction signature
