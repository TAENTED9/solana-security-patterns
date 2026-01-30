# Example 04: CPI Security / Reentrancy / Confused Deputy

## Overview

This example demonstrates Cross-Program Invocation (CPI) vulnerabilities, including reentrancy and confused deputy attacks. CPI is Solana's equivalent to Ethereum's call patterns, but with different security implications.

## The Vulnerability

Solana programs frequently invoke other programs via CPI. Without proper validation:
1. **Reentrancy** - Callee can invoke caller before first call completes
2. **Program confusion** - Calling wrong program version or attacker contract
3. **Return value ignored** - Assuming CPI succeeded without checking
4. **Authority delegation** - Using PDA authority without validation
5. **State invariant violation** - Changes during CPI break assumptions

**Without protection, attackers can:**
- Drain funds through reentrancy
- Call malicious token program to steal tokens
- Create fund loops through confused deputy attacks
- Bypass access control via authority issues

## Real-World Impact

### Reentrancy and CPI Exploits
- **Loss:** Billions across Solana DeFi protocols
- **Root Cause:** Missing CPI return value checks, unvalidated program IDs
- **Pattern:** Assuming CPI succeeds, trusting user-provided program addresses

### Notable Incidents
- Multiple bridge protocols: Incorrect CPI handling → fund drainage
- Stake pool protocols: Confused deputy via incorrect program validation
- Lending protocols: Reentrancy via missing transfer verification
- Token programs: Custom implementations used instead of official ones

## Vulnerable Implementation

**Key Issues:**

```rust
// ❌ PROBLEM 1: Ignored CPI return value
pub fn withdraw_and_transfer(ctx: Context<WithdrawTransfer>, amount: u64) -> Result<()> {
    // Call some external program
    invoke(
        &Instruction {
            program_id: ctx.accounts.external_program.key(),
            accounts: vec![...],
            data: ...,
        },
        &[],
    );  // ❌ Return value ignored! CPI could have failed silently
    
    // Assuming external program succeeded, we proceed
    ctx.accounts.vault.balance -= amount;
    Ok(())
}

// ❌ PROBLEM 2: User-provided program ID (Confused Deputy)
pub fn swap_tokens(ctx: Context<Swap>, amount: u64, program_id: Pubkey) -> Result<()> {
    // ❌ Attacker provides program_id - could be their own program
    invoke(
        &Instruction {
            program_id,  // ATTACKER CONTROLS THIS
            ...
        },
        &[],
    )?;
    
    // Update balances assuming legitimate swap occurred
}

// ❌ PROBLEM 3: Reentrancy vulnerability
pub fn transfer_and_callback(ctx: Context<Transfer>, amount: u64) -> Result<()> {
    // Transfer tokens (invokes external program)
    invoke(...)?;  // ❌ Attacker's program can call us again here
    
    // Update state after transfer
    ctx.accounts.vault.balance -= amount;  // Might use stale state!
}

// ❌ PROBLEM 4: PDA doesn't sign properly
pub fn complex_swap(ctx: Context<Swap>, amount: u64, bumps: SwapBumps) -> Result<()> {
    // Create instruction manually
    let ix = Instruction {
        program_id: EXTERNAL_PROGRAM,
        data: ...,
        accounts: vec![...],
    };
    
    // ❌ Doesn't actually sign with PDA - uses wrong seeds/bump
    invoke_signed(&ix, &[&[seeds, &[WRONG_BUMP]]], ...)?;
}
```

## Secure Implementation

**Security Features:**

- Validates all external program IDs match expected constants
- Checks CPI return values and validates state changes
- Implements proper reentrancy guards
- Uses correct `invoke_signed` with canonical PDAs
- Validates account relationships after CPI

```rust
// ✅ Proper CPI with return value validation
pub fn withdraw_and_transfer(ctx: Context<WithdrawTransfer>, amount: u64) -> Result<()> {
    // Verify target program is official token program
    require!(
        ctx.accounts.token_program.key() == spl_token::ID,
        ErrorCode::InvalidTokenProgram
    );
    
    // Perform transfer
    let transfer_ix = Transfer {
        from: ctx.accounts.user_token_account.to_account_info(),
        to: ctx.accounts.vault_token_account.to_account_info(),
        authority: ctx.accounts.user_authority.to_account_info(),
    };
    
    invoke(
        &transfer_ix.to_instruction(),
        &[
            ctx.accounts.user_token_account.to_account_info(),
            ctx.accounts.vault_token_account.to_account_info(),
            ctx.accounts.user_authority.to_account_info(),
            ctx.accounts.token_program.to_account_info(),
        ],
    )?;
    
    // Verify vault's token account received the tokens
    let vault_account = Account::<spl_token::state::Account>::try_from(
        &ctx.accounts.vault_token_account
    )?;
    require!(vault_account.amount >= amount, ErrorCode::TransferFailed);
    
    // Now update our state
    ctx.accounts.vault.balance = ctx.accounts.vault.balance
        .checked_add(amount)
        .ok_or(ErrorCode::ArithmeticError)?;
    
    Ok(())
}

// ✅ Hardcoded program IDs prevent confused deputy
pub fn swap_tokens(ctx: Context<Swap>, amount: u64) -> Result<()> {
    // Program ID is constant, attacker cannot override
    require!(
        ctx.accounts.dex_program.key() == OFFICIAL_DEX_PROGRAM_ID,
        ErrorCode::InvalidDexProgram
    );
    
    // Perform swap...
    Ok(())
}

// ✅ Check state before and after to detect reentrancy
pub fn transfer_with_guard(ctx: Context<Transfer>, amount: u64) -> Result<()> {
    // Record state before CPI
    let initial_balance = ctx.accounts.vault.balance;
    
    // Perform transfer (might be reentered)
    invoke(...)?;
    
    // Verify state is as expected
    require!(
        ctx.accounts.vault.balance == initial_balance,
        ErrorCode::ReentrancyDetected
    );
    
    // Update state
    ctx.accounts.vault.balance = initial_balance
        .checked_sub(amount)
        .ok_or(ErrorCode::InsufficientBalance)?;
    
    Ok(())
}

// ✅ Proper invoke_signed with canonical PDA
pub fn execute_with_pda(ctx: Context<Execute>, bumps: ExecuteBumps) -> Result<()> {
    let seeds = &[b"authority", &[bumps.authority]];
    
    let ix = Instruction {
        program_id: EXTERNAL_PROGRAM,
        accounts: vec![...],
        data: ...,
    };
    
    // ✅ Sign with correct PDA and canonical bump
    invoke_signed(
        &ix,
        &[ctx.accounts.authority.to_account_info()],
        &[seeds],
    )?;
    
    Ok(())
}
```

## Testing

- **Exploit test** (`tests/exploit.ts`): Demonstrates reentrancy, confused deputy, and CPI validation bypasses
- **Secure test** (`tests/secure.ts`): Validates proper program ID verification and CPI handling

## Learning Objectives

1. Understand Solana's CPI mechanism and differences from Ethereum calls
2. Implement proper program ID validation
3. Recognize reentrancy risks in Solana context
4. Validate CPI return values and account state changes
5. Use `invoke_signed` correctly with PDAs
6. Design reentrancy-resistant state transitions

## Key Takeaways

- **Always hardcode program IDs - never accept them from instructions**
- **Verify accounts are owned by expected program after CPI**
- **Check state before and after CPI to detect reentrancy**
- **Validate token account balances after transfer operations**
- **Use correct seeds and bump when invoking with PDAs**
- **Document assumptions about external program behavior**

## Best Practices

1. Use `spl_token::ID` constant instead of accepting token program as instruction
2. Validate all token transfers succeeded by checking account balances
3. Implement reentrancy guards for critical operations
4. Test with malicious external programs
5. Use Anchor's built-in CPI helpers when available
6. Keep PDA derivation logic separate and testable

## Files in This Example

- `programs/vulnerable/src/lib.rs` - Unsafe CPI patterns
- `programs/secure/src/lib.rs` - Proper CPI validation and reentrancy guards
- `tests/exploit.ts` - Demonstrates reentrancy and confused deputy attacks
- `tests/secure.ts` - Validates CPI security measures
