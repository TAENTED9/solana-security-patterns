use anchor_lang::prelude::*;

declare_id!("C1os3Vu1n999999999999999999999999999999");

#[program]
pub mod account_closure_vulnerable {
    use super::*;

    /// Initialize a vault
    pub fn initialize_vault(ctx: Context<InitializeVault>) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        vault.authority = ctx.accounts.authority.key();
        vault.balance = 1000;  // Initialize with some lamports
        
        msg!("Vault initialized");
        Ok(())
    }

    /// Close vault without authority check
    ///
    /// VULNERABILITY #1: No authority verification
    /// VULNERABILITY #2: Recipient from instruction data
    /// VULNERABILITY #3: No owner check
    pub fn close_vault_bad(
        ctx: Context<CloseVaultBad>,
        recipient: Pubkey,  // [VULNERABLE] ATTACKER CONTROLS THIS!
    ) -> Result<()> {
        let vault = ctx.accounts.vault.to_account_info();
        
        // [VULNERABLE] VULNERABLE: No check that closer is authority
        // Anyone can close any vault!
        
        // [VULNERABLE] VULNERABLE: Recipient from instruction data
        // Attacker specifies where lamports go
        
        let lamports = vault.lamports();
        
        // Drain lamports (WRONG - manual implementation)
        **vault.try_borrow_mut_lamports()? -= lamports;
        
        // Send to attacker-controlled address
        // (This would need the recipient account in context)
        
        msg!("Vault closed, funds sent to: {}", recipient);
        Ok(())
    }

    /// Close vault without signer check
    ///
    /// VULNERABILITY: Authority not required to sign
    pub fn close_vault_unsigned(
        ctx: Context<CloseVaultUnsigned>,
    ) -> Result<()> {
        let vault_info = ctx.accounts.vault.to_account_info();
        let dest_info = ctx.accounts.destination.to_account_info();
        
        // [VULNERABLE] VULNERABLE: No signature check on authority
        // authority is AccountInfo, not Signer
        
        let lamports = vault_info.lamports();
        
        // Transfer lamports
        **vault_info.try_borrow_mut_lamports()? -= lamports;
        **dest_info.try_borrow_mut_lamports()? += lamports;
        
        msg!("Vault closed without authority signature");
        Ok(())
    }

    /// Close account to arbitrary destination
    ///
    /// VULNERABILITY: No validation of destination
    pub fn close_to_any_destination(
        ctx: Context<CloseToAny>,
    ) -> Result<()> {
        let account_info = ctx.accounts.account.to_account_info();
        let dest_info = ctx.accounts.destination.to_account_info();
        
        // [VULNERABLE] VULNERABLE: destination could be anyone
        // No check that destination is safe or expected
        
        let lamports = account_info.lamports();
        
        **account_info.try_borrow_mut_lamports()? -= lamports;
        **dest_info.try_borrow_mut_lamports()? += lamports;
        
        // Clear data
        account_info.realloc(0, false)?;
        
        msg!("Closed to arbitrary destination");
        Ok(())
    }

    /// Close without owner verification
    ///
    /// VULNERABILITY: Doesn't verify account is owned by program
    pub fn close_without_owner_check(
        ctx: Context<CloseWithoutOwner>,
    ) -> Result<()> {
        let account_info = ctx.accounts.account.to_account_info();
        
        // [VULNERABLE] VULNERABLE: No owner check
        // Could be closing account owned by different program
        
        let lamports = account_info.lamports();
        
        **account_info.try_borrow_mut_lamports()? -= lamports;
        **ctx.accounts.destination.try_borrow_mut_lamports()? += lamports;
        
        msg!("Closed without owner verification");
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
pub struct CloseVaultBad<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    
    /// [VULNERABLE] VULNERABLE: Not required to be signer
    /// Not validated against vault.authority
    pub authority: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct CloseVaultUnsigned<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    
    /// [VULNERABLE] VULNERABLE: Not Signer!
    pub authority: AccountInfo<'info>,
    
    #[account(mut)]
    pub destination: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct CloseToAny<'info> {
    #[account(mut)]
    pub account: Account<'info, Vault>,
    
    pub authority: Signer<'info>,
    
    /// [VULNERABLE] VULNERABLE: Could be any account
    #[account(mut)]
    pub destination: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct CloseWithoutOwner<'info> {
    /// [VULNERABLE] VULNERABLE: No owner check
    #[account(mut)]
    pub account: AccountInfo<'info>,
    
    pub authority: Signer<'info>,
    
    #[account(mut)]
    pub destination: AccountInfo<'info>,
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
// EXPLOITATION NOTES
// ============================================================================
//
// HOW TO EXPLOIT:
//
// 1. CLOSE WITHOUT AUTHORITY (close_vault_bad):
//    - Call with ANY vault address
//    - Provide attacker's address as recipient
//    - Vault closed, funds stolen
//
// 2. UNSIGNED CLOSURE (close_vault_unsigned):
//    - Pass victim's vault
//    - Pass victim's authority pubkey (not signing!)
//    - Close vault, drain lamports
//
// 3. ARBITRARY DESTINATION (close_to_any_destination):
//    - Even if you have authority
//    - Send lamports to attacker's address
//    - Bypass intended recipient
//
// 4. NO OWNER CHECK (close_without_owner_check):
//    - Close accounts owned by other programs
//    - Break program invariants
//    - Steal rent-exempt lamports
//
// REAL-WORLD IMPACT:
// - Lending protocols: Unauthorized closures
// - NFT marketplaces: Lamport drainage
// - Stake pools: Fund theft
// - Governance: Treasury drainage