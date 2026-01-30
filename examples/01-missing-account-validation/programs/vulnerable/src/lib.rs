use anchor_lang::prelude::*;

declare_id!("Va1idW2Kzzz1111111111111111111111111111111");

#[program]
pub mod missing_validation_vulnerable {
    use super::*;

    /// Initialize a user account
    /// 
    /// VULNERABILITY: Does not verify that the account is actually owned by this program
    /// or that it's derived from the correct PDA seeds
    pub fn initialize(ctx: Context<Initialize>, name: String) -> Result<()> {
        let user_account = &mut ctx.accounts.user_account;
        
        // [VULNERABLE] VULNERABLE: No check that user_account.owner == program_id
        // An attacker could pass ANY account they control here
        user_account.authority = ctx.accounts.authority.key();
        user_account.name = name;
        user_account.points = 0;
        
        msg!("User account initialized for: {}", user_account.name);
        Ok(())
    }

    /// Transfer points between accounts
    ///
    /// VULNERABILITY #1: Does not verify PDA derivation
    /// VULNERABILITY #2: Does not verify account ownership
    /// VULNERABILITY #3: Trusts account data without validation
    pub fn transfer_points(
        ctx: Context<TransferPoints>,
        amount: u64,
    ) -> Result<()> {
        let from = &mut ctx.accounts.from;
        let to = &mut ctx.accounts.to;

        // [VULNERABLE] VULNERABLE: No PDA verification
        // Attacker could pass their own account pretending to be the vault
        
        // [VULNERABLE] VULNERABLE: No owner check
        // These accounts might not be owned by our program!
        
        // [VULNERABLE] VULNERABLE: Unchecked arithmetic
        from.points -= amount;  // Can underflow!
        to.points += amount;    // Can overflow!

        msg!("Transferred {} points", amount);
        Ok(())
    }

    /// Withdraw funds from vault
    ///
    /// VULNERABILITY: Accepts vault_authority from instruction data instead of verifying
    pub fn withdraw(
        ctx: Context<Withdraw>,
        amount: u64,
        vault_authority: Pubkey,  // [VULNERABLE] ATTACKER CONTROLS THIS!
    ) -> Result<()> {
        // [VULNERABLE] VULNERABLE: Comparing against attacker-provided value
        require!(
            ctx.accounts.vault.authority == vault_authority,
            ErrorCode::Unauthorized
        );

        // [VULNERABLE] VULNERABLE: No verification that vault_authority actually signed
        // [VULNERABLE] VULNERABLE: No PDA derivation check for vault
        
        let vault = &mut ctx.accounts.vault;
        vault.balance -= amount;  // [VULNERABLE] Unchecked arithmetic
        
        // Transfer would happen here...
        msg!("Withdrew {} lamports", amount);
        Ok(())
    }
}

// ============================================================================
// VULNERABLE ACCOUNT VALIDATION STRUCTS
// ============================================================================

#[derive(Accounts)]
pub struct Initialize<'info> {
    /// [VULNERABLE] VULNERABLE: Uses init without seeds/bump
    /// This creates a regular account, not a PDA
    /// Attacker can pass ANY account here
    #[account(
        init,
        payer = authority,
        space = 8 + UserAccount::LEN
    )]
    pub user_account: Account<'info, UserAccount>,
    
    #[account(mut)]
    pub authority: Signer<'info>,
    
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct TransferPoints<'info> {
    /// [VULNERABLE] VULNERABLE: No owner verification
    /// [VULNERABLE] VULNERABLE: No PDA seed verification
    /// [VULNERABLE] VULNERABLE: No has_one constraint to verify authority
    #[account(mut)]
    pub from: Account<'info, UserAccount>,
    
    #[account(mut)]
    pub to: Account<'info, UserAccount>,
    
    /// [VULNERABLE] VULNERABLE: Not required to be signer!
    /// Attacker can pass any public key here
    pub authority: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    /// [VULNERABLE] VULNERABLE: No seeds/bump verification
    /// [VULNERABLE] VULNERABLE: No owner check
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    
    /// [VULNERABLE] VULNERABLE: Not required to be signer
    /// Also no has_one constraint linking to vault.authority
    pub authority: AccountInfo<'info>,
    
    pub system_program: Program<'info, System>,
}

// ============================================================================
// ACCOUNT STRUCTURES
// ============================================================================

#[account]
pub struct UserAccount {
    pub authority: Pubkey,    // 32 bytes
    pub name: String,         // 4 + 50 bytes (max 50 char name)
    pub points: u64,          // 8 bytes
}

impl UserAccount {
    pub const LEN: usize = 32 + 4 + 50 + 8;
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
    
    #[msg("Insufficient points")]
    InsufficientPoints,
}

// ============================================================================
// EXPLOITATION NOTES
// ============================================================================
//
// HOW TO EXPLOIT THIS PROGRAM:
//
// 1. MISSING OWNER VALIDATION:
//    - Create your own account with UserAccount structure
//    - Pass it as 'from' or 'to' in transfer_points
//    - Program won't check if account.owner == program_id
//    - Result: Can manipulate arbitrary accounts
//
// 2. MISSING PDA VERIFICATION:
//    - Create fake vault account
//    - Pass it as 'vault' in withdraw
//    - Program won't verify seeds/bump
//    - Result: Bypass vault security
//
// 3. AUTHORITY FROM INSTRUCTION DATA:
//    - Call withdraw() with YOUR pubkey as vault_authority param
//    - Program compares vault.authority to YOUR provided value
//    - Result: Bypass authority check
//
// 4. MISSING SIGNER CHECK:
//    - TransferPoints accepts AccountInfo for authority (not Signer)
//    - Can pass any pubkey without signing
//    - Result: Transfer points without permission
//
// 5. UNCHECKED ARITHMETIC:
//    - Transfer huge amount to cause underflow
//    - from.points wraps to u64::MAX
//    - Result: Unlimited points
