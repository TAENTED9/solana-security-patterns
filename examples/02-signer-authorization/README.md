# Example 02: Incorrect Signer Authorization / Authority Checks

## Overview

This example demonstrates incorrect signer authorization and authority validation, one of the most critical Solana security patterns. According to 2025 analysis, **59% of DeFi losses ($1.6B+) stem from access control vulnerabilities**, making this pattern essential for secure program design.

## The Vulnerability

Solana requires explicit authority verification. Unlike Ethereum's implicit `msg.sender`, Solana programs must:
1. **Mark accounts as Signer** - Use `Signer<'info>` type in context
2. **Verify authority relationships** - Confirm stored authority matches signer
3. **Validate permissions** - Ensure signers have required authority level
4. **Prevent privilege escalation** - Don't trust external authority values

**Without proper checks, attackers can:**
- Call privileged instructions without proper authorization
- Drain user funds by bypassing owner checks
- Escalate privileges to administrative functions
- Forge transaction signatures

## Real-World Impact

### 2025 DeFi Access Control Failures
- **Loss:** $1.6 billion in first half of 2025
- **Root Cause:** Missing signer validation or incorrect authority checks
- **Percentage:** 59% of all DeFi losses
- **Pattern:** Trusted user-provided authority instead of verifying signatures

### Notable Incidents
- Token bridge transfers without authority validation → $50M+ losses
- Governance exploits via incorrect authority checks → protocol compromise
- Wallet hijacking via missing signer verification → user fund loss

## Vulnerable Implementation

**Key Issues:**

```rust
// [VULNERABLE] PROBLEM 1: No Signer requirement
pub fn change_authority(ctx: Context<ChangeAuthority>, new_authority: Pubkey) -> Result<()> {
    // ctx.accounts.current_authority is NOT a Signer
    // Anyone can pass this account, signer or not
    let vault = &mut ctx.accounts.vault;
    vault.authority = new_authority;  // Attacker controls new_authority!
    Ok(())
}

// [VULNERABLE] PROBLEM 2: Authority from instruction data
pub fn withdraw(ctx: Context<Withdraw>, amount: u64, authority_check: Pubkey) -> Result<()> {
    require!(ctx.accounts.vault.authority == authority_check, ...);
    // Attacker provides authority_check, making this a useless check
}

// [VULNERABLE] PROBLEM 3: Missing has_one constraint
#[derive(Accounts)]
pub struct UpdateVault<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    pub authority: AccountInfo<'info>,  // NOT verified to match vault.authority
}

// [VULNERABLE] PROBLEM 4: Authority not marked as signer
pub fn admin_function(ctx: Context<AdminOp>) -> Result<()> {
    // Even if we compare keys, admin might not have actually signed
}
```

## Secure Implementation

**Security Features:**

- Uses `Signer<'info>` to enforce signature requirement
- Implements `has_one` constraint for authority validation
- Properly validates stored authority matches transaction signer
- Never trusts user-provided authority values
- Separates authority roles for fine-grained control

```rust
// [SECURE] Authority properly marked as Signer
#[derive(Accounts)]
pub struct ChangeAuthority<'info> {
    #[account(mut, has_one = authority)]
    pub vault: Account<'info, Vault>,
    pub authority: Signer<'info>,  // MUST be signer
    pub new_authority: UncheckedAccount<'info>,
}

// [SECURE] Authority comparison uses stored value, not instruction data
pub fn change_authority(ctx: Context<ChangeAuthority>, new_authority: Pubkey) -> Result<()> {
    let vault = &mut ctx.accounts.vault;
    vault.authority = new_authority;
    msg!("Authority changed to: {}", new_authority);
    Ok(())
}
```

## Testing

- **Exploit test** (`tests/exploit.ts`): Demonstrates unauthorized access by bypassing signer checks
- **Secure test** (`tests/secure.ts`): Validates that only the authority can perform privileged actions

## Learning Objectives

1. Understand Solana's explicit signer requirement vs Ethereum's implicit sender
2. Implement proper authority validation using `has_one` and `Signer`
3. Recognize privilege escalation attacks
4. Design role-based access control patterns
5. Never trust user-provided authority values

## Key Takeaways

- **Always mark critical accounts as `Signer<'info>`**
- **Use Anchor's `has_one` constraint to validate authority relationships**
- **Never accept authority/admin addresses from instruction data**
- **Test that unauthorized users cannot call privileged functions**
- **Document authority roles clearly in your code**

## Files in This Example

- `programs/vulnerable/src/lib.rs` - Flawed authority handling
- `programs/secure/src/lib.rs` - Proper signer authorization
- `tests/exploit.ts` - Demonstrates privilege escalation
- `tests/secure.ts` - Validates secure implementation
