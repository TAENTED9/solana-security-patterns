# Example 03: Arithmetic Overflow and Underflow

## Overview

This example demonstrates unsafe arithmetic operations in Solana programs, a critical vulnerability in DeFi applications. Integer overflow and underflow vulnerabilities can result in:
- Unauthorized token minting or burning
- Fund drainage through balance manipulation
- Protocol invariant violations

## The Vulnerability

Rust's default arithmetic operators (`+`, `-`, `*`) panic on overflow in debug mode, but in release mode they wrap around (two's complement). Smart contract code must use **checked arithmetic** to prevent:

1. **Overflow** - Adding beyond maximum value wraps to 0 or negative
2. **Underflow** - Subtracting beyond minimum value wraps to maximum
3. **Silent failures** - Operations fail silently rather than reverting
4. **Quantization errors** - Fixed-point arithmetic precision loss

**Without protection, attackers can:**
- Mint unlimited tokens via overflow
- Drain balances via underflow
- Manipulate price feeds through rounding errors
- Break protocol invariants

## Real-World Impact

### Integer Overflow in DeFi Protocols
- **Loss:** Varies, but can result in unlimited token minting
- **Root Cause:** Unchecked arithmetic in balance updates
- **Pattern:** Missing checked_add/checked_sub calls
- **Impact:** Protocol collapse, total fund loss

### Notable Incidents
- BurgerSwap exploit: Integer underflow in token swap → $7.5M loss
- Mochi Market: Unchecked arithmetic in collateral calculation
- Multiple AMM protocols: Overflow in liquidity calculation

## Vulnerable Implementation

**Key Issues:**

```rust
// [VULNERABLE] PROBLEM 1: Unchecked arithmetic (wraps on overflow/underflow)
pub fn transfer(ctx: Context<Transfer>, amount: u64) -> Result<()> {
    let from = &mut ctx.accounts.from;
    let to = &mut ctx.accounts.to;
    
    from.balance -= amount;  // [VULNERABLE] Underflows silently if amount > balance
    to.balance += amount;    // [VULNERABLE] Overflows silently if to.balance + amount > u64::MAX
    Ok(())
}

// [VULNERABLE] PROBLEM 2: No overflow check in accumulation
pub fn accumulate_rewards(ctx: Context<Accumulate>, reward: u64) -> Result<()> {
    let vault = &mut ctx.accounts.vault;
    vault.total_rewards += reward;  // [VULNERABLE] No check if this overflows
    Ok(())
}

// [VULNERABLE] PROBLEM 3: Precision loss in fixed-point math
pub fn calculate_swap_output(input: u64, rate: u64) -> u64 {
    (input * rate) / DECIMALS  // [VULNERABLE] Rounds down, losing precision
}

// [VULNERABLE] PROBLEM 4: Multiple unchecked operations
pub fn compound_calculation(a: u64, b: u64, c: u64) -> Result<u64> {
    Ok(a + b + c)  // [VULNERABLE] Each operation could overflow
}
```

## Secure Implementation

**Security Features:**

- Uses `checked_add`, `checked_sub`, `checked_mul` with explicit error handling
- Implements safe arithmetic with overflow protection
- Validates amounts don't exceed limits before operations
- Handles precision loss in fixed-point calculations
- Documents expected value ranges

```rust
// [SECURE] Safe arithmetic with explicit error handling
pub fn transfer(ctx: Context<Transfer>, amount: u64) -> Result<()> {
    let from = &mut ctx.accounts.from;
    let to = &mut ctx.accounts.to;
    
    // Verify sufficient balance before operation
    require!(from.balance >= amount, ErrorCode::InsufficientBalance);
    
    // Use checked arithmetic
    from.balance = from.balance
        .checked_sub(amount)
        .ok_or(ErrorCode::ArithmeticError)?;
    
    to.balance = to.balance
        .checked_add(amount)
        .ok_or(ErrorCode::ArithmeticError)?;
    
    msg!("Transferred {} tokens", amount);
    Ok(())
}

// [SECURE] Safe accumulation with bounds checking
pub fn accumulate_rewards(ctx: Context<Accumulate>, reward: u64) -> Result<()> {
    let vault = &mut ctx.accounts.vault;
    
    vault.total_rewards = vault.total_rewards
        .checked_add(reward)
        .ok_or(ErrorCode::RewardOverflow)?;
    
    require!(vault.total_rewards <= MAX_REWARDS, ErrorCode::ExceedsMaxRewards);
    Ok(())
}

// [SECURE] Proper fixed-point arithmetic with precision handling
pub fn calculate_swap_output(input: u64, rate: u64) -> Result<u64> {
    // Use checked multiplication to prevent overflow
    let product = input
        .checked_mul(rate)
        .ok_or(ErrorCode::CalculationOverflow)?;
    
    // Divide with truncation, rounding handled separately if needed
    Ok(product / DECIMALS)
}
```

## Testing

- **Exploit test** (`tests/exploit.ts`): Demonstrates overflow/underflow attacks
- **Secure test** (`tests/secure.ts`): Validates arithmetic safety

## Learning Objectives

1. Understand overflow and underflow in Rust context
2. Implement checked arithmetic operations
3. Validate amounts before arithmetic
4. Handle precision loss in fixed-point math
5. Test edge cases (max values, zero, minimum values)

## Key Takeaways

- **Always use `checked_add`, `checked_sub`, `checked_mul` for user-controlled amounts**
- **Validate amounts don't exceed limits before operations**
- **Test with maximum and minimum values**
- **Document expected value ranges in your code**
- **Consider precision loss in fixed-point arithmetic**
- **Use safe_math libraries for complex calculations**

## Best Practices

1. Validate all input amounts immediately
2. Use checked arithmetic for all user-controlled operations
3. Implement limits on accumulations (cap rewards, balances, etc.)
4. Test with boundary values (0, MAX, MAX-1)
5. Document expected ranges in comments

## Files in This Example

- `programs/vulnerable/src/lib.rs` - Unchecked arithmetic operations
- `programs/secure/src/lib.rs` - Safe arithmetic with validation
- `tests/exploit.ts` - Demonstrates overflow/underflow attacks
- `tests/secure.ts` - Validates arithmetic safety
