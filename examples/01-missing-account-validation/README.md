# Example 01: Missing Account Validation

## Overview

This example demonstrates one of the most critical vulnerability patterns in Solana program development: **missing account validation**. According to Sec3's 2025 Security Review, validation errors contribute to 85.5% of severe vulnerabilities alongside business logic and permission issues.

## The Vulnerability

Solana programs must explicitly validate:
1. **Account Ownership** - Verify account.owner == expected_program_id
2. **PDA Derivation** - Validate seeds and bump for Program Derived Addresses
3. **Authority Relationships** - Confirm stored authority matches signer
4. **Signer Requirements** - Ensure critical accounts actually signed the transaction

**Without these checks, attackers can:**
- Pass accounts they control as "official" program accounts
- Forge PDAs with predictable seeds
- Bypass authority checks
- Manipulate program state

## Real-World Impact

### Wormhole Bridge Exploit (February 2022)
- **Loss:** $325 million
- **Root Cause:** Signature verification bypass allowed forging guardian approvals
- **Pattern:** Missing account validation enabled complete protocol drain

### Other Notable Incidents
- Multiple DeFi protocols: Unchecked account ownership → unauthorized withdrawals
- DAO treasuries: Missing signer verification → fund drainage
- Token programs: PDA bypass → unauthorized mints

## Vulnerable Implementation

**Key Issues:**

```rust
// [VULNERABLE] PROBLEM 1: No PDA verification
#[account(mut)]
pub vault: Account<'info, Vault>,
// Attacker can pass ANY account with Vault structure

// [VULNERABLE] PROBLEM 2: Authority from instruction data
pub fn withdraw(ctx: Context<Withdraw>, amount: u64, vault_authority: Pubkey) -> Result<()> {
    require!(ctx.accounts.vault.authority == vault_authority, ...);
    // Attacker controls vault_authority parameter!
}

// [VULNERABLE] PROBLEM 3: No signer check
pub authority: AccountInfo<'info>,
// Should be Signer<'info>

// [VULNERABLE] PROBLEM 4: No owner verification
// Account<> type provides this, but init without seeds doesn't enforce PDA
```

## Secure Implementation

**Security Features:**

```rust
// [SECURE] FIX 1: PDA with seeds and bump
#[account(
    mut,
    seeds = [b"vault", authority.key().as_ref()],
    bump = vault.bump,  // Verify stored canonical bump
)]
pub vault: Account<'info, Vault>,

// [SECURE] FIX 2: No authority parameter, use verified signer
pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
    // Authority verified via has_one constraint
    // No parameter means no attacker control
}

// [SECURE] FIX 3: Require signer
pub authority: Signer<'info>,
// Transaction must be signed by this key

// [SECURE] FIX 4: Validate relationship
#[account(
    has_one = authority,  // vault.authority == authority.key()
)]
```

## Anchor Security Constraints Used

| Constraint | Purpose | Example |
|------------|---------|---------|
| `seeds` | Specify PDA derivation | `seeds = [b"vault", authority.key().as_ref()]` |
| `bump` | Verify canonical bump | `bump = vault.bump` |
| `has_one` | Validate field relationship | `has_one = authority` |
| `Account<T>` | Owner + discriminator check | `Account<'info, Vault>` |
| `Signer<T>` | Require transaction signature | `Signer<'info>` |
| `init` | Create account safely | `init, payer = authority` |

## Attack Scenarios

### Scenario 1: Fake Vault

**Attack:**
```typescript
// Create fake vault controlled by attacker
const fakeVault = await createAccount(attackerKeypair);

// Pass it to withdraw
await program.methods
  .withdraw(1000, attackerKeypair.publicKey)
  .accounts({
    vault: fakeVault,  // Attacker's account, not real vault!
    authority: attackerKeypair,
  })
  .rpc();
```

**Why It Works (Vulnerable):**
- No PDA verification
- Program accepts ANY account with Vault structure
- Attacker drains their own fake vault

**Why It Fails (Secure):**
- PDA seeds constraint checks derivation
- Fake vault address != derived address
- Transaction fails

### Scenario 2: Authority Bypass

**Attack:**
```typescript
await program.methods
  .withdraw(
    1000,
    attackerKeypair.publicKey  // Attacker provides their own key!
  )
  .accounts({
    vault: victimVaultPubkey,
    authority: attackerKeypair,  // Not the real authority
  })
  .rpc();
```

**Why It Works (Vulnerable):**
- Program accepts authority as parameter
- Compares against attacker-provided value
- No signer check

**Why It Fails (Secure):**
- No authority parameter accepted
- has_one ensures vault.authority == signer.key()
- Signer<> type requires signature
- Transaction fails

### Scenario 3: Non-Signer Authority

**Attack:**
```typescript
await program.methods
  .transferPoints(100)
  .accounts({
    from: victimAccount,
    to: attackerAccount,
    authority: victimKeypair.publicKey,  // Public key, not signing!
  })
  .rpc();
```

**Why It Works (Vulnerable):**
- Authority is AccountInfo, not Signer
- Can pass any public key without signature
- Bypasses permission check

**Why It Fails (Secure):**
- authority is Signer<'info>
- Transaction rejected if not signed
- Solana runtime enforces this

## Running the Examples

### Build Both Programs

```bash
cd examples/01-missing-account-validation
anchor build
```

### Run Exploit Tests

```bash
# Test the vulnerable version
anchor test -- --features vulnerable

# Should show successful exploits
```

### Run Secure Tests

```bash
# Test the secure version
anchor test

# Should show exploit attempts failing
# Should show legitimate operations succeeding
```

### View Test Output

```bash
# Verbose output
anchor test -- --nocapture

# Specific test
anchor test -- test_name
```

## Key Takeaways

### Always Validate

1. **Account Ownership**
   - Use `Account<'info, T>` for automatic owner check
   - Or manually verify `account.owner == expected_program`

2. **PDA Derivation**
   - Use `seeds` and `bump` constraints
   - Store canonical bump in account
   - Never accept PDA address from user input

3. **Authority Relationships**
   - Use `has_one` to link account fields to signers
   - Store authority in account state
   - Validate against stored value, not parameters

4. **Signer Requirements**
   - Use `Signer<'info>` for accounts that must sign
   - Never use `AccountInfo` for security-critical accounts
   - Let Solana runtime enforce signature checks

### Defense in Depth

Each security measure provides a layer of protection:

```
Layer 1: Type System (Account<T> vs AccountInfo)
    ↓
Layer 2: Anchor Constraints (seeds, bump, has_one)
    ↓
Layer 3: Explicit Checks (require! macros)
    ↓
Layer 4: Runtime Enforcement (Solana's signature verification)
```

Even if one layer is bypassed, others remain.

## Common Mistakes

### [VULNERABLE] Don't Do This

```rust
// Accepting addresses from instruction data
pub fn init(ctx: Context<Init>, vault_address: Pubkey) -> Result<()> { ... }

// Using AccountInfo for security-critical accounts
pub authority: AccountInfo<'info>,

// Comparing against parameters
require!(vault.authority == provided_authority, ...);

// Skipping PDA verification
#[account(mut)]
pub vault: Account<'info, Vault>,  // No seeds!
```

### [SECURE] Do This Instead

```rust
// Derive addresses from seeds
#[account(
    seeds = [b"vault", authority.key().as_ref()],
    bump,
)]
pub vault: Account<'info, Vault>,

// Use Signer type
pub authority: Signer<'info>,

// Use has_one for validation
#[account(has_one = authority)]
pub vault: Account<'info, Vault>,

// No parameters for security-critical data
pub fn init(ctx: Context<Init>) -> Result<()> { ... }
```

## Further Reading

- [Anchor Account Constraints](https://www.anchor-lang.com/docs/account-constraints)
- [Solana Account Model](https://docs.solana.com/developing/programming-model/accounts)
- [PDA Documentation](https://www.anchor-lang.com/docs/pdas)
- [Sec3 2025 Security Review](https://solanasec25.sec3.dev/)
- [Wormhole Post-Mortem](https://wormhole.com/blog/wormhole-incident-report)

## Questions?

- Open an issue in the main repository
- Check the [deep-dive guide](../../docs/deep-dive.md)
- Review [references](../../docs/references.md) for more context

---

**⚠️ WARNING:** The vulnerable example is intentionally insecure. NEVER use vulnerable patterns in production. Always use secure implementations and conduct thorough security audits.
