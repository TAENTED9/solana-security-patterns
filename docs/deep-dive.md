# Solana Security Patterns: A Comprehensive Deep Dive

**By Sam - Senior Security Engineer & Solana Developer**  
**Last Updated: January 27, 2026**

## Table of Contents

1. [Introduction](#introduction)
2. [The Solana Security Landscape](#the-solana-security-landscape)
3. [Core Security Patterns](#core-security-patterns)
4. [Framework Comparisons](#framework-comparisons)
5. [Defense in Depth](#defense-in-depth)
6. [Conclusion](#conclusion)

---

## Introduction

Security in blockchain development is not optional—it's fundamental. A single vulnerability can result in millions of dollars in losses, destroyed user trust, and protocol collapse. According to Sec3's 2025 Solana Security Ecosystem Review, which analyzed 163 security audits revealing 1,669 vulnerabilities, the landscape is clear: **85.5% of severe issues stem from business logic flaws, access control failures, and validation errors**—not exotic cryptographic attacks.

This guide provides an in-depth exploration of the seven most critical security patterns every Solana developer must master. We'll examine real-world exploits, understand the root causes, and implement secure alternatives using both Anchor and Pinocchio frameworks.

### Why This Matters

The numbers tell a sobering story:

- **$3.1 billion** stolen in the first half of 2025 alone—exceeding all of 2024's losses
- **59% of 2025 DeFi losses** attributed to access control vulnerabilities
- **Average of 10 issues per audit** with 1.4 High or Critical vulnerabilities
- Only **1% of exploits** come from low-level arithmetic or liveness problems

The good news? Most vulnerabilities are **preventable** through proper account validation, authority checks, and defensive programming patterns.

---

## The Solana Security Landscape

### Historical Context

Solana's security journey has been marked by both challenges and rapid evolution:

**2020-2022: Growing Pains**
- Wormhole bridge exploit: $325 million (February 2022)
- Multiple network outages due to transaction floods
- Application-layer exploits dominated incident reports

**2023-2024: Maturation**
- 100% uptime since February 2023
- Coordinated security response (August 2024 Agave vulnerability)
- Supply chain attack on web3.js library (December 2024, $164K loss)

**2025: Sophisticated Threats**
- Phishing via owner permission manipulation ($3M+ losses)
- DeFi protocol exploits targeting oracle manipulation
- Access control failures as primary attack vector

### The Three Pillars of Solana Security

**1. Account Model Security**

Solana's account model differs fundamentally from Ethereum's:
- Accounts store data and lamports (SOL balance)
- Programs are stateless and live in executable accounts
- Account ownership determines write permissions

This creates unique attack surfaces:
- **Account confusion**: Passing wrong account to instruction
- **Missing ownership validation**: Not verifying account.owner
- **Incorrect PDA derivation**: Accepting user-controlled addresses as PDAs

**2. Permission Boundaries**

Unlike Ethereum where `msg.sender` is implicit, Solana requires explicit signer verification:
- Signers must be marked in `AccountMeta`
- Programs must validate `account.is_signer`
- PDAs use `invoke_signed` for cross-program authorization

Failures here account for **59% of 2025's $1.6B+ in losses**.

**3. Cross-Program Invocation (CPI)**

CPIs enable composability but introduce trust boundaries:
- Called programs can modify passed accounts
- Return values must be validated
- Reentrancy is possible (though different from EVM)
- Confused deputy attacks when programs act on behalf of callers

---

## Core Security Patterns

### Pattern 1: Missing Account Validation

**The Vulnerability**

```rust
// ❌ VULNERABLE: No owner or PDA verification
#[derive(Accounts)]
pub struct Transfer<'info> {
    #[account(mut)]
    pub user_account: Account<'info, UserAccount>,
    #[account(mut)]
    pub vault: Account<'info, Vault>,
}
```

**Why It's Dangerous**

An attacker can:
1. Create their own account with matching structure
2. Pass it as `user_account` parameter
3. Bypass intended access controls
4. Manipulate program state

**Real-World Impact**

- **Wormhole Bridge ($325M)**: Signature verification bypass allowed forging guardian approvals
- **Multiple DeFi protocols**: Unchecked account ownership led to unauthorized withdrawals

**The Secure Pattern**

```rust
// ✅ SECURE: Proper validation with Anchor constraints
#[derive(Accounts)]
pub struct Transfer<'info> {
    #[account(
        mut,
        has_one = authority,  // Verify authority field matches
        constraint = user_account.owner == crate::ID  // Explicit owner check
    )]
    pub user_account: Account<'info, UserAccount>,
    
    #[account(
        mut,
        seeds = [b"vault", authority.key().as_ref()],
        bump,  // Verify canonical PDA derivation
    )]
    pub vault: Account<'info, Vault>,
    
    pub authority: Signer<'info>,
}
```

**Defense Layers**

1. **Owner Verification**: Ensure account is owned by your program
2. **PDA Validation**: Use `seeds` and `bump` to verify deterministic derivation
3. **Field Matching**: Use `has_one` to validate account relationships
4. **Type Safety**: Anchor's `Account<T>` provides 8-byte discriminator checking

---

### Pattern 2: Incorrect Authority / Signer Checks

**The Vulnerability**

```rust
// ❌ VULNERABLE: Trusting data without verifying signer
pub fn transfer(ctx: Context<Transfer>, amount: u64, authority: Pubkey) -> Result<()> {
    // Uses authority from instruction data instead of verified signer!
    require!(ctx.accounts.user.authority == authority, ErrorCode::Unauthorized);
    // ... transfer logic
}
```

**The Attack**

An attacker simply passes their own public key as `authority` parameter:
```typescript
await program.methods
  .transfer(
    new BN(1000),
    attackerKeypair.publicKey  // Attacker controls this!
  )
  .accounts({
    user: victimAccount,  // Victim's account
    // ...
  })
  .rpc();
```

**Real-World Impact**

Access control failures caused **$1.6 billion in losses** in H1 2025 alone, representing 59% of all DeFi exploits. Recent examples include:

- Phishing attacks via owner permission manipulation ($3M in single incident)
- DAO treasury drains from multisig bypass
- Token authority hijacking

**The Secure Pattern**

```rust
// ✅ SECURE: Verify actual signer, not claimed authority
#[derive(Accounts)]
pub struct Transfer<'info> {
    #[account(
        mut,
        has_one = authority  // authority must match account's stored value
    )]
    pub user: Account<'info, User>,
    
    pub authority: Signer<'info>,  // MUST be signer, not AccountInfo
    pub system_program: Program<'info, System>,
}

pub fn transfer(ctx: Context<Transfer>, amount: u64) -> Result<()> {
    // Authority is guaranteed to have signed the transaction
    // No need to accept authority as parameter
    ctx.accounts.user.balance -= amount;
    Ok(())
}
```

**Best Practices**

1. **Never accept authority as instruction parameter**
2. **Use `Signer<'info>` type, not `AccountInfo`**
3. **Validate with `has_one` constraint**
4. **For PDAs, use `invoke_signed` with proper seeds**

---

### Pattern 3: Unsafe Arithmetic / Overflow

**The Vulnerability**

```rust
// ❌ VULNERABLE: Unchecked arithmetic
pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
    ctx.accounts.vault.balance += amount;  // Can overflow!
    ctx.accounts.user.deposited += amount;
    Ok(())
}
```

**Why It Matters**

In Rust debug builds, integer overflow panics. In release builds (what gets deployed on-chain), it **wraps around**:

```rust
let max: u64 = u64::MAX;
let result = max + 1;  // Result is 0 in release mode!
```

This enables:
- **Balance manipulation**: Overflow large deposit to 0
- **Fee bypass**: Underflow fee calculation to negative (wraps to huge number)
- **Reward farming**: Manipulate accrual calculations

**Real-World Context**

Academic research on Solana vulnerabilities specifically calls out integer overflow as a recurring pattern. While not as prevalent as access control issues, when present it's often **critical severity**.

**The Secure Pattern**

```rust
// ✅ SECURE: Checked arithmetic with explicit error handling
pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
    ctx.accounts.vault.balance = ctx.accounts.vault.balance
        .checked_add(amount)
        .ok_or(ErrorCode::Overflow)?;
    
    ctx.accounts.user.deposited = ctx.accounts.user.deposited
        .checked_add(amount)
        .ok_or(ErrorCode::Overflow)?;
    
    Ok(())
}
```

**Advanced Patterns**

For DeFi applications requiring precision:

```rust
// Using fixed-point arithmetic with explicit rounding
use rust_decimal::Decimal;

pub fn calculate_interest(principal: u64, rate: u64, time: u64) -> Result<u64> {
    let principal_dec = Decimal::from(principal);
    let rate_dec = Decimal::from(rate) / Decimal::from(10000);  // basis points
    let time_dec = Decimal::from(time);
    
    let interest = principal_dec
        .checked_mul(rate_dec)
        .ok_or(ErrorCode::Overflow)?
        .checked_mul(time_dec)
        .ok_or(ErrorCode::Overflow)?;
    
    // Round down to avoid giving away more than calculated
    Ok(interest.floor().to_u64().ok_or(ErrorCode::Overflow)?)
}
```

---

### Pattern 4: CPI / Reentrancy / Confused Deputy

**The Vulnerability**

```rust
// ❌ VULNERABLE: CPI without validating results
pub fn flash_loan(ctx: Context<FlashLoan>, amount: u64) -> Result<()> {
    // 1. Transfer tokens to borrower
    token::transfer(
        CpiContext::new(
            ctx.accounts.token_program.to_account_info(),
            token::Transfer {
                from: ctx.accounts.vault.to_account_info(),
                to: ctx.accounts.borrower.to_account_info(),
                authority: ctx.accounts.vault_authority.to_account_info(),
            },
        ),
        amount,
    )?;
    
    // 2. Call borrower's program
    // ⚠️ Borrower can do ANYTHING here, including calling back!
    invoke(
        &callback_instruction,
        &[/* accounts */],
    )?;
    
    // 3. Check repayment
    // ❌ Assumes token balances haven't been manipulated
    require!(
        ctx.accounts.vault.amount >= initial_balance,
        ErrorCode::NotRepaid
    );
    Ok(())
}
```

**Attack Vectors**

1. **Reentrancy**: Borrower calls back into flash_loan during callback
2. **Confused Deputy**: Borrower manipulates vault's token account through other programs
3. **State Inconsistency**: External state changes aren't reflected in local state

**The Secure Pattern**

```rust
// ✅ SECURE: Defensive CPI with pre/post validation
pub fn flash_loan(ctx: Context<FlashLoan>, amount: u64) -> Result<()> {
    // 1. Record state BEFORE any external calls
    let initial_balance = ctx.accounts.vault.amount;
    let fee = amount.checked_mul(FEE_BASIS_POINTS)
        .ok_or(ErrorCode::Overflow)?
        .checked_div(10000)
        .ok_or(ErrorCode::Overflow)?;
    
    // 2. Set reentrancy guard
    require!(!ctx.accounts.vault.locked, ErrorCode::Reentrant);
    ctx.accounts.vault.locked = true;
    
    // 3. Transfer tokens
    token::transfer(
        CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            token::Transfer {
                from: ctx.accounts.vault.to_account_info(),
                to: ctx.accounts.borrower.to_account_info(),
                authority: ctx.accounts.vault_authority.to_account_info(),
            },
            &[&[b"vault", &[ctx.bumps.vault_authority]]],
        ),
        amount,
    )?;
    
    // 4. Call borrower with minimal permissions
    invoke(
        &callback_instruction,
        &[/* read-only accounts only */],
    )?;
    
    // 5. RELOAD account data after external call
    ctx.accounts.vault.reload()?;
    
    // 6. Verify repayment with fee
    let expected_balance = initial_balance
        .checked_add(fee)
        .ok_or(ErrorCode::Overflow)?;
    require!(
        ctx.accounts.vault.amount >= expected_balance,
        ErrorCode::NotRepaid
    );
    
    // 7. Clear reentrancy guard
    ctx.accounts.vault.locked = false;
    Ok(())
}
```

**Key Defenses**

1. **Reentrancy Guards**: Flag preventing recursive calls
2. **Account Reloading**: `reload()` fetches latest on-chain state
3. **Minimal Permissions**: Pass only necessary accounts to external programs
4. **Invariant Verification**: Check all assumptions after external calls
5. **Signer Seeds**: Use `invoke_signed` for PDA-owned CPIs

---

### Pattern 5: Account Closure / Lamport Drain

**The Vulnerability**

```rust
// ❌ VULNERABLE: No validation of closer or recipient
pub fn close_account(ctx: Context<CloseAccount>) -> Result<()> {
    let dest_starting_lamports = ctx.accounts.destination.lamports();
    
    **ctx.accounts.account.to_account_info().realloc(0, false)?;
    
    let account_lamports = ctx.accounts.account.to_account_info().lamports();
    **ctx.accounts.account.to_account_info().sub_lamports(account_lamports)?;
    **ctx.accounts.destination.to_account_info().add_lamports(account_lamports)?;
    
    Ok(())
}
```

**The Attack**

Attacker specifies their own address as `destination`:
```typescript
await program.methods
  .closeAccount()
  .accounts({
    account: victimAccountPubkey,
    destination: attackerKeypair.publicKey,  // Steals lamports!
  })
  .signers([attackerKeypair])
  .rpc();
```

**The Secure Pattern**

```rust
// ✅ SECURE: Validate authority and destination
#[derive(Accounts)]
pub struct CloseAccount<'info> {
    #[account(
        mut,
        close = authority,  // Anchor handles close + validation
        has_one = authority,  // Verify authority matches
    )]
    pub account: Account<'info, UserAccount>,
    
    #[account(mut)]
    pub authority: Signer<'info>,  // Must sign transaction
}

pub fn close_account(ctx: Context<CloseAccount>) -> Result<()> {
    // Anchor's `close` constraint automatically:
    // 1. Transfers lamports to authority
    // 2. Zeros account data
    // 3. Marks account as closed
    Ok(())
}
```

**Manual Close (when needed)**

```rust
pub fn close_account_manual(ctx: Context<CloseAccount>) -> Result<()> {
    // Verify closer authority
    require_keys_eq!(
        ctx.accounts.account.authority,
        ctx.accounts.authority.key(),
        ErrorCode::Unauthorized
    );
    
    // Verify destination is authority (prevents lamport theft)
    require_keys_eq!(
        ctx.accounts.authority.key(),
        ctx.accounts.destination.key(),
        ErrorCode::InvalidDestination
    );
    
    // Safe close
    let dest_starting_lamports = ctx.accounts.destination.lamports();
    let account_lamports = ctx.accounts.account.to_account_info().lamports();
    
    **ctx.accounts.account.to_account_info().sub_lamports(account_lamports)?;
    **ctx.accounts.destination.add_lamports(account_lamports)?;
    **ctx.accounts.account.to_account_info().realloc(0, false)?;
    
    Ok(())
}
```

---

### Pattern 6: PDA Seed Collision

**The Vulnerability**

```rust
// ❌ VULNERABLE: User-controlled seeds without collision prevention
#[derive(Accounts)]
#[instruction(seed: String)]
pub struct Initialize<'info> {
    #[account(
        init,
        payer = user,
        space = 8 + 32 + 8,
        seeds = [seed.as_bytes()],  // User controls seed!
        bump,
    )]
    pub account: Account<'info, MyAccount>,
    // ...
}
```

**The Attack**

Two different users can create accounts with same semantic meaning but different seeds:
- User A: seed = "vault_alice"
- User B: seed = "vault_alice" (collision!)

Or attacker finds seed collision to hijack existing PDA:
```typescript
// Attacker finds seed that collides with existing PDA
const existingPDA = findProgramAddress(["vault", userA.publicKey]);
const collisionSeed = findSeedCollision(existingPDA);
```

**Real-World Example**

Sec3 documented a **semantic inconsistency vulnerability** in Solana stake pools where insufficient seed uniqueness allowed manipulation of pool states.

**The Secure Pattern**

```rust
// ✅ SECURE: Program-controlled seeds with uniqueness
#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        init,
        payer = user,
        space = 8 + 32 + 8,
        seeds = [
            b"vault",  // Fixed prefix
            user.key().as_ref(),  // User's public key (unique)
            &[bump],  // Canonical bump
        ],
        bump,
    )]
    pub vault: Account<'info, Vault>,
    
    #[account(mut)]
    pub user: Signer<'info>,
    pub system_program: Program<'info, System>,
}
```

**Best Practices**

1. **Use fixed prefixes** (e.g., `b"vault"`, `b"config"`)
2. **Include unique identifiers** (public keys, not user-provided strings)
3. **Always use canonical bump** (highest valid bump)
4. **Store bump in account** to avoid recomputation
5. **Never accept seeds from instruction data**

---

### Pattern 7: Arithmetic Precision Loss

**The Vulnerability**

```rust
// ❌ VULNERABLE: Integer division loses precision
pub fn calculate_share_value(
    total_value: u64,  // $1,000,000 (6 decimals: 1_000_000_000_000)
    total_shares: u64,  // 3 shares
) -> u64 {
    total_value / total_shares  // = 333_333_333_333 (loses 1 unit)
    // Actual: 333,333.333333...
    // Result: 333,333.333333
    // Lost: 0.000001 per share
}
```

**Compound Effect**

Small precision losses compound in DeFi:
- LP token pricing
- Interest rate calculations
- Fee distributions
- Reward accruals

Over millions of transactions, this becomes **significant value extraction**.

**The Secure Pattern**

```rust
// ✅ SECURE: Proper precision handling
use rust_decimal::Decimal;

pub fn calculate_share_value(
    total_value: u64,
    total_shares: u64,
    decimals: u8,
) -> Result<u64> {
    require!(total_shares > 0, ErrorCode::ZeroShares);
    
    let total_value_dec = Decimal::from(total_value);
    let total_shares_dec = Decimal::from(total_shares);
    let scale = Decimal::from(10u64.pow(decimals as u32));
    
    let share_value = total_value_dec
        .checked_mul(scale)
        .ok_or(ErrorCode::Overflow)?
        .checked_div(total_shares_dec)
        .ok_or(ErrorCode::DivisionError)?;
    
    // Use floor() to prevent giving away more than calculated
    // Or use round_dp() for more sophisticated rounding
    Ok(share_value.floor().to_u64().ok_or(ErrorCode::Overflow)?)
}
```

**Rounding Strategies**

```rust
// For payments TO users: round DOWN (floor)
let user_reward = calculate_reward(amount).floor();

// For payments FROM users: round UP (ceil)
let user_fee = calculate_fee(amount).ceil();

// This ensures protocol never gives away more than it should
// and never takes less than it should
```

---

## Framework Comparisons

### Anchor vs. Pinocchio

| Feature | Anchor 0.32.1 | Pinocchio 0.10.0 |
|---------|---------------|------------------|
| **Abstraction Level** | High (opinionated) | Low (bare-metal) |
| **Security Defaults** | Built-in constraints | Manual validation |
| **Compute Usage** | Higher (deserialiation) | Lower (zero-copy) |
| **Development Speed** | Fast (macros) | Slower (manual) |
| **Binary Size** | Larger | Smaller (60%+ reduction) |
| **Best For** | Most applications | CU-critical programs |

**When to Use Anchor:**
- MVP and rapid prototyping
- Teams new to Solana
- Applications where CU limits aren't tight
- When development speed matters

**When to Use Pinocchio:**
- Production programs hitting CU limits
- High-frequency applications (DEX, liquidations)
- After proving product-market fit
- When binary size matters (deployment cost)

---

## Defense in Depth

Security is not a single check—it's layers:

### Layer 1: Type System
```rust
// Use strong types, not AccountInfo everywhere
pub struct Transfer<'info> {
    pub vault: Account<'info, Vault>,  // ✅ Typed
    pub authority: Signer<'info>,      // ✅ Verified signer
    // Not:
    // pub vault: AccountInfo<'info>,   // ❌ No type safety
}
```

### Layer 2: Constraints
```rust
#[account(
    mut,
    has_one = authority,    // Relationship validation
    constraint = vault.amount >= amount  // Business logic
)]
```

### Layer 3: Explicit Checks
```rust
require!(
    ctx.accounts.vault.locked == false,
    ErrorCode::Reentrant
);
require_keys_eq!(
    ctx.accounts.vault.owner,
    crate::ID,
    ErrorCode::InvalidOwner
);
```

### Layer 4: Testing
```typescript
// Test both exploit AND fix
it("Exploit: bypasses owner check", async () => {
    await expect(exploitAttempt()).to.be.rejected;
});

it("Secure: validates owner correctly", async () => {
    await expect(secureTransaction()).to.be.fulfilled;
});
```

### Layer 5: Audits
- Internal code review
- External security audit
- Bug bounty program
- Continuous monitoring

---

## Conclusion

Solana security is achievable through:

1. **Understanding the account model** and its unique attack surfaces
2. **Using framework constraints** (Anchor) or careful validation (Pinocchio)
3. **Validating every input** - owners, signers, PDAs, arithmetic
4. **Defensive CPI patterns** - guards, reloading, minimal permissions
5. **Comprehensive testing** - both exploits and fixes

Remember: **85.5% of severe vulnerabilities are preventable** through proper business logic, access control, and validation. The patterns in this repository represent the collective wisdom from 163 audits, $3.1B in losses, and countless hours of security research.

Build secure. Build confidently. Build on Solana.

---

**Resources:**
- [Sec3 2025 Security Review](https://solanasec25.sec3.dev/)
- [Anchor Security Docs](https://www.anchor-lang.com/docs)
- [Helius Security Guides](https://www.helius.dev/blog)
- [Solana Program Security](https://docs.solana.com/developing/programming-model/security)

**Author:** Sam - Senior Security Engineer & Solana Developer  
**Last Updated:** January 27, 2026  
**License:** MIT
