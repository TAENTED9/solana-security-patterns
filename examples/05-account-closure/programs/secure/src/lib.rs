use anchor_lang::prelude::*;

declare_id!("AccountClosureSecure11111111111111111111111111");

#[program]
pub mod account_closure_secure {
    use super::*;

    /// Initialize a vault
    pub fn initialize_vault(ctx: Context<InitializeVault>) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        vault.authority = ctx.accounts.authority.key();
        vault.balance = 1000;
        
        msg!("Vault securely initialized");
        Ok(())
    }

    /// Close vault securely using Anchor's close attribute.
    /// 
    /// Anchor's close attribute is the recommended approach. It atomically:
    /// - Transfers all lamports to the designated recipient
    /// - Zeros account data to prevent account reuse
    /// - Marks account for garbage collection
    /// - Validates authority via has_one constraint
    pub fn close_vault_safe(ctx: Context<CloseVaultSafe>) -> Result<()> {
        msg!("Vault securely closed");
        Ok(())
    }

    /// Close vault with explicit manual validation.
    /// 
    /// This approach manually implements what close attribute does. Use this
    /// only when you need custom logic. For standard closure, use close_vault_safe.
    pub fn close_vault_explicit(ctx: Context<CloseVaultExplicit>) -> Result<()> {
        let vault = &ctx.accounts.vault;
        
        // Verify the vault's stored authority matches the signer
        require_keys_eq!(
            vault.authority,
            ctx.accounts.authority.key(),
            ErrorCode::Unauthorized
        );
        
        // Verify the vault account is owned by this program
        require_keys_eq!(
            vault.to_account_info().owner,
            &crate::ID,
            ErrorCode::InvalidOwner
        );
        
        let vault_info = vault.to_account_info();
        let dest_info = ctx.accounts.authority.to_account_info();
        
        // Transfer all lamports to the authority
        let lamports = vault_info.lamports();
        
        **vault_info.try_borrow_mut_lamports()? -= lamports;
        **dest_info.try_borrow_mut_lamports()? += lamports;
        
        // Zero account data
        vault_info.realloc(0, false)?;
        
        msg!("Vault explicitly closed to authority");
        Ok(())
    }

    /// Close with explicit destination validation.
    /// 
    /// Validates that the destination account matches the vault's authority,
    /// preventing accidental or malicious fund redirection.
    pub fn close_with_validated_destination(
        ctx: Context<CloseValidatedDest>,
    ) -> Result<()> {
        let vault = &ctx.accounts.vault;
        
        // Ensure destination is the vault's authority
        require_keys_eq!(
            ctx.accounts.destination.key(),
            ctx.accounts.authority.key(),
            ErrorCode::InvalidDestination
        );
        
        let vault_info = vault.to_account_info();
        let dest_info = ctx.accounts.destination.to_account_info();
        
        let lamports = vault_info.lamports();
        
        **vault_info.try_borrow_mut_lamports()? -= lamports;
        **dest_info.try_borrow_mut_lamports()? += lamports;
        
        vault_info.realloc(0, false)?;
        
        msg!("Vault closed to validated destination");
        Ok(())
    }

    /// Close vault only if balance is zero.
    /// 
    /// This adds an additional state check to prevent accidental closure
    /// of vaults that still hold funds.
    pub fn close_if_empty(ctx: Context<CloseIfEmpty>) -> Result<()> {
        let vault = &ctx.accounts.vault;
        
        // Only allow closure if the vault's balance is zero
        require!(
            vault.balance == 0,
            ErrorCode::VaultNotEmpty
        );
        
        // Use Anchor's close (defined in context)
        msg!("Empty vault securely closed");
        Ok(())
    }
}

// ============================================================================
// ACCOUNT CONTEXTS
// ============================================================================

#[derive(Accounts)]
pub struct InitializeVault<'info> {
    #[account(
        init,
        payer = authority,
        space = 8 + Vault::LEN,
    )]
    pub vault: Account<'info, Vault>,
    
    #[account(mut)]
    pub authority: Signer<'info>,
    
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct CloseVaultSafe<'info> {
    #[account(
        mut,
        close = authority,  // Sends lamports to authority
        has_one = authority,  // Validates vault.authority == signer
    )]
    pub vault: Account<'info, Vault>,
    
    // Must sign to authorize closure
    #[account(mut)]
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct CloseVaultExplicit<'info> {
    #[account(
        mut,
        has_one = authority,
    )]
    pub vault: Account<'info, Vault>,
    
    #[account(mut)]
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct CloseValidatedDest<'info> {
    #[account(
        mut,
        has_one = authority,
    )]
    pub vault: Account<'info, Vault>,
    
    #[account(mut)]
    pub authority: Signer<'info>,
    
    // Validated in instruction to match authority
    #[account(mut)]
    pub destination: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct CloseIfEmpty<'info> {
    #[account(
        mut,
        close = authority,
        has_one = authority,
    )]
    pub vault: Account<'info, Vault>,
    
    #[account(mut)]
    pub authority: Signer<'info>,
}

// ============================================================================
// ACCOUNT STRUCTURES
// ============================================================================

#[account]
pub struct Vault {
    pub authority: Pubkey,    // 32 bytes
    pub balance: u64,         // 8 bytes
}

impl Vault {
    pub const LEN: usize = 32 + 8;
}

// ============================================================================
// ERRORS
// ============================================================================

#[error_code]
pub enum ErrorCode {
    #[msg("Unauthorized: caller is not vault authority")]
    Unauthorized,
    
    #[msg("Invalid owner: account not owned by program")]
    InvalidOwner,
    
    #[msg("Invalid destination: must match authority")]
    InvalidDestination,
    
    #[msg("Vault not empty: cannot close with remaining balance")]
    VaultNotEmpty,
}

// ============================================================================
// SECURITY IMPLEMENTATION NOTES
// ============================================================================
//
// HOW THIS PREVENTS EXPLOITS:
//
// 1. ANCHOR'S CLOSE ATTRIBUTE:
//    - Automatically transfers ALL lamports
//    - Zeros account data
//    - Validates authority via has_one
//    - Atomic operation (all or nothing)
//    - RECOMMENDED: Use this whenever possible
//
// 2. AUTHORITY VALIDATION:
//    - has_one = authority ensures vault.authority == signer
//    - Signer<'info> type requires signature
//    - No way to bypass authority check
//
// 3. OWNER VERIFICATION:
//    - Check account.owner == program_id
//    - Prevents closing accounts owned by other programs
//    - Protects against cross-program attacks
//
// 4. DESTINATION VALIDATION:
//    - Destination must match authority
//    - Or explicitly validated in instruction
//    - Prevents lamport theft to arbitrary addresses
//
// 5. STATE VALIDATION:
//    - Check balance is zero before close
//    - Additional safety for important accounts
//    - Prevents accidental fund loss
//
// COMPARISON TO VULNERABLE:
// Vulnerable:  authority: AccountInfo<'info>  (no signature)
// Secure:      authority: Signer<'info>       (must sign)
//
// Vulnerable:  close to any address
// Secure:      close = authority  (Anchor enforces)
//
// Vulnerable:  manual lamport manipulation
// Secure:      Anchor's close attribute (atomic, safe)
//
// BEST PRACTICE:
// Always use Anchor's close attribute unless you have
// specific requirements that need manual handling.