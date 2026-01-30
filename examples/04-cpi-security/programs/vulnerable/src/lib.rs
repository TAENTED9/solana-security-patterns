use anchor_lang::prelude::*;
use anchor_lang::solana_program::{instruction::Instruction, program::invoke};

declare_id!("CpiVu1n777777777777777777777777777777777");

#[program]
pub mod cpi_security_vulnerable {
    use super::*;

    /// Initialize a vault
    pub fn initialize_vault(ctx: Context<InitializeVault>) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        vault.authority = ctx.accounts.authority.key();
        vault.balance = 0;
        vault.locked = false;
        
        msg!("Vault initialized");
        Ok(())
    }

    /// Flash loan without reentrancy protection
    ///
    /// VULNERABILITY #1: No reentrancy guard
    /// VULNERABILITY #2: Doesn't reload accounts after CPI
    /// VULNERABILITY #3: Assumes balance unchanged during callback
    pub fn flash_loan(
        ctx: Context<FlashLoan>,
        amount: u64,
    ) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        
        // [VULNERABLE] VULNERABLE: No reentrancy guard
        // Attacker can call back into this function during callback
        
        let initial_balance = vault.balance;
        
        // Transfer funds out
        vault.balance -= amount;  // [VULNERABLE] Unchecked arithmetic
        
        // [VULNERABLE] VULNERABLE: Call external program without protection
        // Callback instruction could be ANYTHING
        // External program could call back into this program
        let callback_ix = Instruction {
            program_id: ctx.accounts.callback_program.key(),
            accounts: vec![],
            data: vec![],
        };
        
        invoke(
            &callback_ix,
            &[ctx.accounts.callback_program.to_account_info()],
        )?;
        
        // [VULNERABLE] VULNERABLE: Assumes vault.balance unchanged
        // External program could have modified it through reentrancy
        
        let fee = amount / 100;  // 1% fee
        
        // [VULNERABLE] VULNERABLE: No account reload after CPI
        // Using stale balance data
        require!(
            vault.balance >= initial_balance + fee,
            ErrorCode::NotRepaid
        );
        
        msg!("Flash loan repaid");
        Ok(())
    }

    /// Swap tokens with user-provided program ID
    ///
    /// VULNERABILITY: Confused deputy - accepts program ID from user
    pub fn swap_tokens(
        ctx: Context<SwapTokens>,
        amount: u64,
        dex_program_id: Pubkey,  // [VULNERABLE] ATTACKER CONTROLS THIS!
    ) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        
        // [VULNERABLE] VULNERABLE: User provides program ID
        // Could be attacker's malicious program, not real DEX
        let swap_ix = Instruction {
            program_id: dex_program_id,  // [VULNERABLE] ATTACKER'S PROGRAM!
            accounts: vec![],
            data: amount.to_le_bytes().to_vec(),
        };
        
        // [VULNERABLE] VULNERABLE: No program ID validation
        invoke(&swap_ix, &[])?;
        
        // [VULNERABLE] VULNERABLE: No return value validation
        // Assumes swap succeeded
        vault.balance -= amount;
        
        msg!("Swapped {} tokens", amount);
        Ok(())
    }

    /// Execute callback without validation
    ///
    /// VULNERABILITY: No validation of callback results
    pub fn execute_callback(
        ctx: Context<ExecuteCallback>,
        instruction_data: Vec<u8>,
    ) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        
        let callback_ix = Instruction {
            program_id: ctx.accounts.external_program.key(),
            accounts: vec![],
            data: instruction_data,
        };
        
        // [VULNERABLE] VULNERABLE: Ignore return value
        invoke(&callback_ix, &[])?;
        // Even if invoke returns Ok, the external program might have failed internally
        
        // [VULNERABLE] VULNERABLE: Update state assuming success
        vault.balance += 100;
        
        msg!("Callback executed");
        Ok(())
    }

    /// Transfer with external validation
    ///
    /// VULNERABILITY: Trusts external program to validate
    pub fn transfer_with_validation(
        ctx: Context<TransferWithValidation>,
        amount: u64,
        validator_program: Pubkey,  // [VULNERABLE] User controlled
    ) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        
        // [VULNERABLE] VULNERABLE: Call user-provided validator
        let validate_ix = Instruction {
            program_id: validator_program,
            accounts: vec![],
            data: vec![],
        };
        
        invoke(&validate_ix, &[])?;
        
        // [VULNERABLE] VULNERABLE: Assume validation passed
        // Attacker's program always returns success
        vault.balance -= amount;
        
        msg!("Transfer validated and executed");
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
pub struct FlashLoan<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    
    pub authority: Signer<'info>,
    
    /// [VULNERABLE] VULNERABLE: User provides callback program
    /// CHECK: No validation - could be malicious
    pub callback_program: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct SwapTokens<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct ExecuteCallback<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    
    pub authority: Signer<'info>,
    
    /// CHECK: External program, not validated
    pub external_program: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct TransferWithValidation<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    
    pub authority: Signer<'info>,
}

// ============================================================================
// ACCOUNT STRUCTURES
// ============================================================================

#[account]
pub struct Vault {
    pub authority: Pubkey,    // 32 bytes
    pub balance: u64,         // 8 bytes
    pub locked: bool,         // 1 byte
}

impl Vault {
    pub const LEN: usize = 32 + 8 + 1;
}

// ============================================================================
// ERRORS
// ============================================================================

#[error_code]
pub enum ErrorCode {
    #[msg("Flash loan not repaid")]
    NotRepaid,
    
    #[msg("Reentrancy detected")]
    Reentrant,
    
    #[msg("Invalid program")]
    InvalidProgram,
}

// ============================================================================
// EXPLOITATION NOTES
// ============================================================================
//
// HOW TO EXPLOIT:
//
// 1. REENTRANCY ATTACK (flash_loan):
//    - Borrow funds via flash_loan
//    - In callback, call flash_loan AGAIN (reentrancy)
//    - First call checks balance with stale data
//    - Drain vault completely
//
// 2. CONFUSED DEPUTY (swap_tokens):
//    - Provide attacker's program as dex_program_id
//    - Attacker's program doesn't perform swap
//    - Just returns success
//    - Vault balance decreased but tokens never swapped
//
// 3. FAKE VALIDATION (transfer_with_validation):
//    - Provide attacker's program as validator_program
//    - Attacker's program always returns Ok
//    - Bypass all validation logic
//
// 4. NO RETURN VALUE CHECK (execute_callback):
//    - External program fails internally
//    - But returns Ok to Solana runtime
//    - Our program assumes success and updates state
//
// REAL-WORLD IMPACT:
// - Bridge exploits: Billions lost
// - DeFi reentrancy: Multiple protocols
// - Confused deputy: Stake pool vulnerabilities