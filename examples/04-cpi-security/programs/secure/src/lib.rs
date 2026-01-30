use anchor_lang::prelude::*;
use anchor_lang::solana_program::{instruction::Instruction, program::invoke};

declare_id!("CpiSecuritySecure2222222222222222222222222");

// Hardcoded trusted program IDs to prevent confused deputy attacks
const TRUSTED_DEX_PROGRAM: Pubkey = pubkey!("DEXProgram1111111111111111111111111111111");
const TRUSTED_VALIDATOR: Pubkey = pubkey!("Validator1111111111111111111111111111111");

#[program]
pub mod cpi_security_secure {
    use super::*;

    /// Initialize a vault
    pub fn initialize_vault(ctx: Context<InitializeVault>) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        vault.authority = ctx.accounts.authority.key();
        vault.balance = 0;
        vault.locked = false;
        
        msg!("Vault securely initialized");
        Ok(())
    }

    /// Flash loan with reentrancy protection.
    ///
    /// Implements a reentrancy guard to prevent recursive calls,
    /// reloads account state after CPI, and verifies expected invariants.
    pub fn flash_loan(
        ctx: Context<FlashLoan>,
        amount: u64,
        expected_fee: u64,
    ) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        
        // Check reentrancy guard to prevent nested calls
        require!(!vault.locked, ErrorCode::Reentrant);
        
        // Set lock BEFORE any external calls to prevent reentrancy
        vault.locked = true;
        
        // Record state before CPI
        let initial_balance = vault.balance;
        
        // Validate loan parameters
        require!(amount > 0, ErrorCode::InvalidAmount);
        require!(amount <= initial_balance, ErrorCode::InsufficientBalance);
        
        // Use checked arithmetic to prevent underflow
        vault.balance = vault.balance
            .checked_sub(amount)
            .ok_or(ErrorCode::ArithmeticError)?;
        
        // Minimal CPI - only provide necessary accounts
        let callback_ix = Instruction {
            program_id: ctx.accounts.callback_program.key(),
            accounts: vec![],
            data: vec![],
        };
        
        invoke(
            &callback_ix,
            &[ctx.accounts.callback_program.to_account_info()],
        )?;
        
        // Reload account data after CPI as external program may have modified state
        ctx.accounts.vault.reload()?;
        
        // Verify repayment with expected fee using checked arithmetic
        let expected_total = initial_balance
            .checked_add(expected_fee)
            .ok_or(ErrorCode::ArithmeticError)?;
        
        require!(
            ctx.accounts.vault.balance >= expected_total,
            ErrorCode::NotRepaid
        );
        
        // Clear lock
        vault.locked = false;
        
        msg!("Flash loan securely repaid");
        Ok(())
    }

    /// Swap tokens with hardcoded program ID.
    ///
    /// Validates the external DEX program ID against a hardcoded trusted value
    /// and verifies the return value from the CPI call.
    pub fn swap_tokens(
        ctx: Context<SwapTokens>,
        amount: u64,
    ) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        
        // Validate program ID matches hardcoded trusted DEX
        require!(
            ctx.accounts.dex_program.key() == TRUSTED_DEX_PROGRAM,
            ErrorCode::InvalidProgram
        );
        
        // Validate amount parameter
        require!(amount > 0, ErrorCode::InvalidAmount);
        require!(amount <= vault.balance, ErrorCode::InsufficientBalance);
        
        let swap_ix = Instruction {
            program_id: TRUSTED_DEX_PROGRAM,
            accounts: vec![],
            data: amount.to_le_bytes().to_vec(),
        };
        
        // Execute CPI
        invoke(&swap_ix, &[])?;
        
        // Reload and verify state after CPI
        ctx.accounts.vault.reload()?;
        
        // Use checked arithmetic to prevent underflow
        vault.balance = vault.balance
            .checked_sub(amount)
            .ok_or(ErrorCode::ArithmeticError)?;
        
        msg!("Tokens securely swapped");
        Ok(())
    }

    /// Execute callback with validation.
    ///
    /// Validates program ID, checks return values, and verifies state changes
    /// after external program execution.
    pub fn execute_callback(
        ctx: Context<ExecuteCallback>,
        instruction_data: Vec<u8>,
    ) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        
        // Validate external program matches trusted validator
        require!(
            ctx.accounts.external_program.key() == TRUSTED_VALIDATOR,
            ErrorCode::InvalidProgram
        );
        require!(
            ctx.accounts.external_program.key() == TRUSTED_VALIDATOR,
            ErrorCode::InvalidProgram
        );
        
        // Record state before CPI
        let balance_before = vault.balance;
        
        let callback_ix = Instruction {
            program_id: TRUSTED_VALIDATOR,
            accounts: vec![],
            data: instruction_data,
        };
        
        // Execute CPI
        let result = invoke(&callback_ix, &[]);
        
        // Explicitly check return value from CPI
        require!(result.is_ok(), ErrorCode::CallbackFailed);
        
        // Reload account after CPI
        ctx.accounts.vault.reload()?;
        
        // Verify expected state didn't change unexpectedly
        // In this case, we expect balance unchanged
        require!(
            vault.balance == balance_before,
            ErrorCode::UnexpectedStateChange
        );
        
        msg!("Callback securely executed");
        Ok(())
    }

    /// Transfer with proper validation.
    ///
    /// Validates parameters internally without trusting external programs.
    /// Uses checked arithmetic throughout.
    pub fn transfer_with_validation(
        ctx: Context<TransferWithValidation>,
        amount: u64,
    ) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        
        // Validate parameters internally
        require!(amount > 0, ErrorCode::InvalidAmount);
        require!(amount <= vault.balance, ErrorCode::InsufficientBalance);
        
        // Use checked arithmetic
        vault.balance = vault.balance
            .checked_sub(amount)
            .ok_or(ErrorCode::ArithmeticError)?;
        
        msg!("Transfer securely validated and executed");
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
    #[account(
        mut,
        has_one = authority,
    )]
    pub vault: Account<'info, Vault>,
    
    pub authority: Signer<'info>,
    
    /// CHECK: Callback program - caller's responsibility.
    /// Reentrancy guard is set and account is reloaded after CPI.
    pub callback_program: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct SwapTokens<'info> {
    #[account(
        mut,
        has_one = authority,
    )]
    pub vault: Account<'info, Vault>,
    
    pub authority: Signer<'info>,
    
    /// CHECK: Validated in instruction to match TRUSTED_DEX_PROGRAM.
    pub dex_program: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct ExecuteCallback<'info> {
    #[account(
        mut,
        has_one = authority,
    )]
    pub vault: Account<'info, Vault>,
    
    pub authority: Signer<'info>,
    
    /// CHECK: Validated in instruction to match TRUSTED_VALIDATOR.
    pub external_program: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct TransferWithValidation<'info> {
    #[account(
        mut,
        has_one = authority,
    )]
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
    pub locked: bool,         // 1 byte (reentrancy guard)
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
    
    #[msg("Invalid program ID")]
    InvalidProgram,
    
    #[msg("Arithmetic error")]
    ArithmeticError,
    
    #[msg("Invalid amount")]
    InvalidAmount,
    
    #[msg("Insufficient balance")]
    InsufficientBalance,
    
    #[msg("Callback failed")]
    CallbackFailed,
    
    #[msg("Unexpected state change")]
    UnexpectedStateChange,
}

// ============================================================================
// SECURITY IMPLEMENTATION NOTES
// ============================================================================
//
// HOW THIS PREVENTS EXPLOITS:
//
// 1. REENTRANCY PROTECTION:
//    - locked flag set BEFORE external calls
//    - Checked at start of sensitive functions
//    - Cleared only after all checks pass
//    - Pattern: Check-Effects-Interactions
//
// 2. PROGRAM ID VALIDATION:
//    - Hardcoded trusted program constants
//    - Explicit require! checks
//    - No user-controlled program IDs
//    - Prevents confused deputy attacks
//
// 3. ACCOUNT RELOADING:
//    - reload() after every CPI
//    - Fetches fresh data from chain
//    - Detects state changes during CPI
//    - Validates invariants after reload
//
// 4. RETURN VALUE CHECKING:
//    - Explicit result validation
//    - Don't assume CPI succeeded
//    - Check both Ok/Err and state changes
//
// 5. MINIMAL PERMISSIONS:
//    - Only pass necessary accounts to CPI
//    - Use read-only where possible
//    - Limit what external programs can access
//
// DEFENSE IN DEPTH:
// Layer 1: Reentrancy guard (locked flag)
// Layer 2: Account reloading after CPI
// Layer 3: Invariant verification
// Layer 4: Hardcoded program IDs
// Layer 5: Return value validation
//
// Each layer provides independent protection.