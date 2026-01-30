# Example 05: Account Closure and Lamport Drain Vulnerabilities

## Overview

This example demonstrates improper account closure handling, a critical vulnerability that allows attackers to drain funds through unauthorized lamport transfers. Account closure is a fundamental pattern in Solana but requires careful validation.

## The Vulnerability

Solana accounts can be closed by transferring all lamports to another account and marking the data as empty. Without proper validation:
1. **Lamport drainage** - Unauthorized fund transfers via account closure
2. **Authority bypass** - Missing close authority checks
3. **Re-initialization** - Closed accounts can be re-initialized by anyone
4. **Rent state confusion** - Rent-exempt vs rent-paying account mix-up
5. **Recipient validation** - No check who receives lamports

**Without protection, attackers can:**
- Drain vault lamports without authorization
- Steal funds by closing accounts they don't own
- Create recursive drainage attacks
- Bypass fund locks through creative account manipulation

## Real-World Impact

### Account Closure Exploits
- **Loss:** Multiple millions in aggregate
- **Root Cause:** Missing close authority validation
- **Pattern:** Accepting arbitrary recipient accounts
- **Impact:** Complete fund drainage from locked accounts

### Notable Incidents
- Multiple lending protocols: Unauthorized account closure → fund drainage
- NFT marketplaces: Lamport drain through improper closure
- Stake pool protocols: Lamport theft via account manipulation
- Governance systems: Treasury drainage through closure exploits

## Vulnerable Implementation

**Key Issues:**

```rust
// ❌ PROBLEM 1: No authority check for closure
pub fn close_vault(ctx: Context<CloseVault>) -> Result<()> {
    let vault = &ctx.accounts.vault;
    
    // ❌ ANYONE can close this vault!
    // Transfer all lamports to recipient
    let rent_exempt_balance = Rent::get()?.minimum_balance(vault.to_account_info().data_len());
    let remaining = vault.to_account_info().lamports() - rent_exempt_balance;
    
    vault.to_account_info().sub_lamports(remaining)?;
    ctx.accounts.recipient.add_lamports(remaining)?;
    
    Ok(())
}

// ❌ PROBLEM 2: Recipient from instruction data
pub fn close_with_recipient(ctx: Context<CloseVault>, recipient: Pubkey) -> Result<()> {
    // ❌ Attacker controls where lamports go
    let vault = &ctx.accounts.vault;
    let lamports = vault.to_account_info().lamports();
    
    // Send to attacker-controlled account
    vault.to_account_info().sub_lamports(lamports)?;
    // How would we add lamports to arbitrary recipient?
}

// ❌ PROBLEM 3: Missing owner verification
pub fn close_account(ctx: Context<Close>) -> Result<()> {
    let account = &ctx.accounts.account;
    
    // ❌ No check that account is actually owned by this program
    // Could be a regular account not under program control
    let lamports = account.to_account_info().lamports();
    
    // Drain it anyway
    account.to_account_info().sub_lamports(lamports)?;
    ctx.accounts.destination.add_lamports(lamports)?;
    
    Ok(())
}

// ❌ PROBLEM 4: Close authority not verified
#[derive(Accounts)]
pub struct CloseAccount<'info> {
    #[account(mut)]
    pub account: Account<'info, MyAccount>,
    
    pub close_authority: AccountInfo<'info>,  // ❌ Not a Signer!
    #[account(mut)]
    pub destination: AccountInfo<'info>,
}
```

## Secure Implementation

**Security Features:**

- Validates close authority has signed the transaction
- Checks account ownership matches program
- Limits closure to authorized addresses only
- Properly transfers all lamports to authorized recipient
- Marks account as closed to prevent re-initialization

```rust
// ✅ Proper account closure with authority check
#[derive(Accounts)]
pub struct CloseVault<'info> {
    #[account(mut, has_one = authority)]
    pub vault: Account<'info, Vault>,
    
    // ✅ Authority MUST be signer
    pub authority: Signer<'info>,
    
    #[account(mut)]
    pub recipient: AccountInfo<'info>,
}

pub fn close_vault(ctx: Context<CloseVault>) -> Result<()> {
    let vault = &ctx.accounts.vault;
    
    // ✅ Only authority can close (verified by has_one constraint)
    // Transfer ALL lamports to authorized recipient
    let lamports = vault.to_account_info().lamports();
    
    vault.to_account_info().sub_lamports(lamports)?;
    ctx.accounts.recipient.add_lamports(lamports)?;
    
    msg!("Vault closed by authorized account");
    Ok(())
}

// ✅ Safe close with explicit recipient validation
#[derive(Accounts)]
pub struct SafeClose<'info> {
    #[account(
        mut,
        has_one = authority,
        close = recipient  // ✅ Account closes to recipient, funds transfer automatically
    )]
    pub account: Account<'info, MyAccount>,
    
    pub authority: Signer<'info>,
    
    #[account(mut)]
    pub recipient: AccountInfo<'info>,
}

pub fn safe_close_account(ctx: Context<SafeClose>) -> Result<()> {
    // ✅ Anchor's `close` attribute handles lamport transfer and data clearing
    // No manual lamport manipulation needed
    msg!("Account safely closed by authority");
    Ok(())
}

// ✅ Validate recipient is safe account
pub fn close_with_validation(ctx: Context<CloseVault>) -> Result<()> {
    let vault = &ctx.accounts.vault;
    let recipient = &ctx.accounts.recipient;
    
    // ✅ Ensure recipient is system program account (can receive lamports)
    require!(recipient.is_writable, ErrorCode::RecipientMustBeWritable);
    
    // ✅ Ensure we're actually closing our own account
    require!(
        vault.to_account_info().owner == &crate::ID,
        ErrorCode::AccountNotOwnedByProgram
    );
    
    // Transfer lamports
    let lamports = vault.to_account_info().lamports();
    vault.to_account_info().sub_lamports(lamports)?;
    recipient.add_lamports(lamports)?;
    
    // Clear account data
    let vault_info = vault.to_account_info();
    vault_info.realloc(0, false)?;
    
    Ok(())
}
```

## Testing

- **Exploit test** (`tests/exploit.ts`): Demonstrates unauthorized closures and lamport drainage
- **Secure test** (`tests/secure.ts`): Validates only authorities can close accounts

## Learning Objectives

1. Understand account closure mechanics in Solana
2. Implement proper close authority validation
3. Validate account ownership before closure
4. Handle lamport transfers correctly
5. Use Anchor's `close` attribute for safety
6. Test re-initialization attempts after closure

## Key Takeaways

- **Mark close authority as `Signer<'info>` to enforce signing requirement**
- **Use Anchor's `close` constraint instead of manual lamport handling**
- **Validate account ownership before closure**
- **Never accept arbitrary recipient accounts from instruction data**
- **Test that non-authorities cannot close accounts**
- **Verify accounts cannot be re-initialized after closure**

## Best Practices

1. Always use the `close` constraint when possible
2. Require explicit authority to close critical accounts
3. Validate recipient accounts are writable
4. Test with wrong authority accounts (should fail)
5. Verify closed accounts cannot be re-initialized
6. Document closure requirements in function comments

## Rent-Exempt Accounts

In Solana, accounts can be rent-exempt if they contain enough lamports. When closing:
- Send ALL lamports to recipient
- Don't attempt to maintain rent-exemption
- Clear account data properly
- Prevent state pollution

## Files in This Example

- `programs/vulnerable/src/lib.rs` - Improper account closure
- `programs/secure/src/lib.rs` - Proper authority validation and closure
- `tests/exploit.ts` - Demonstrates unauthorized closures
- `tests/secure.ts` - Validates secure closure patterns
