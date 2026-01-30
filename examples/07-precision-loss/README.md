# Example 07: Arithmetic Precision Loss in DeFi

## Overview

This example demonstrates precision loss vulnerabilities in DeFi calculations, a subtle but critical issue affecting token swaps, yield calculations, and liquidity provisioning. Incorrect fixed-point arithmetic can lead to fund loss or unlimited token generation.

## The Vulnerability

Solana uses integer-only arithmetic (no floating point). DeFi protocols must implement fixed-point math carefully:
1. **Rounding errors** - Division discards fractional parts (truncation)
2. **Order of operations** - Multiply before divide to preserve precision
3. **Scaling mismatches** - Different decimal places across tokens
4. **Accumulation errors** - Small errors compound across operations
5. **Price manipulation** - Attackers use rounding to their advantage

**Without protection, attackers can:**
- Extract value through rounding in favorable directions
- Manipulate LP token valuations
- Drain yield calculations through repetition
- Break protocol invariants through precision loss

## Real-World Impact

### Precision Loss Exploits
- **Loss:** Tens of millions across DeFi protocols
- **Root Cause:** Incorrect fixed-point arithmetic or rounding
- **Pattern:** Dividing before multiplying, ignoring decimal places
- **Impact:** Slow fund drainage, yield manipulation, LP theft

### Notable Incidents
- AMM protocols: Precision loss in swap calculation → MEV extraction
- Lending protocols: Rounding errors in interest calculation → governance manipulation
- Yield protocols: Accumulation errors → fund drainage
- Bridge protocols: Decimal mismatch → slippage exploitation

## Vulnerable Implementation

**Key Issues:**

```rust
// ❌ PROBLEM 1: Divide before multiply loses precision
pub fn calculate_swap_output(input: u64, rate: u64, decimals: u8) -> u64 {
    // ❌ WRONG ORDER: (input / SCALE) * rate loses fractional amount
    let scaled_input = input / (10_u64.pow(decimals as u32));
    scaled_input.saturating_mul(rate)
}

// Better but still wrong:
pub fn better_but_wrong(input: u64, rate: u64, decimals: u8) -> u64 {
    // ❌ Still loses precision: multiply then divide
    (input * rate) / (10_u64.pow(decimals as u32))
}

// ❌ PROBLEM 2: Ignoring decimal places
pub fn swap_tokens_wrong(amount: u64, price: u64) -> u64 {
    // ❌ Assumes same decimal places - wrong for USDC/SOL pair
    amount * price  // USDC has 6 decimals, SOL has 9!
}

// ❌ PROBLEM 3: Accumulation errors compound
pub fn calculate_accumulated_yield(principal: u64, rate_per_period: u64, periods: u64) -> u64 {
    let mut total = principal;
    for _ in 0..periods {
        let yield_amount = (total * rate_per_period) / 10_000;
        total += yield_amount;  // ❌ Rounding error accumulates
    }
    total
}

// ❌ PROBLEM 4: No overflow protection in multiplication
pub fn multiply_with_decimals(a: u64, b: u64, decimals: u8) -> u64 {
    let result = a * b;  // ❌ Could overflow before dividing!
    result / (10_u64.pow(decimals as u32))
}

// ❌ PROBLEM 5: Incorrect precision in oracle prices
pub fn price_from_oracle(base_price: u64, multiplier: u64) -> u64 {
    // ❌ No consideration for oracle decimal places
    (base_price * multiplier) / 1000  // Assumes fixed decimals
}
```

## Secure Implementation

**Security Features:**

- Multiplies before dividing to preserve precision
- Handles decimal place conversions explicitly
- Uses checked arithmetic to prevent overflow
- Implements rounding in favor of protocol
- Documents all precision assumptions

```rust
// ✅ CORRECT: Multiply before divide
pub fn calculate_swap_output(
    input: u64,
    rate: u64,
    input_decimals: u8,
    output_decimals: u8,
) -> Result<u64> {
    // Formula: output = (input * rate * 10^output_decimals) / (10^input_decimals)
    
    // Step 1: Convert input to base units (max precision)
    let input_scaled = input
        .checked_mul(rate)
        .ok_or(ErrorCode::CalculationOverflow)?;
    
    // Step 2: Handle decimal conversion
    let scale_factor = if output_decimals > input_decimals {
        10_u64.pow((output_decimals - input_decimals) as u32)
    } else {
        1
    };
    
    let result = input_scaled
        .checked_mul(scale_factor)
        .ok_or(ErrorCode::CalculationOverflow)?;
    
    // Step 3: Divide by input scale (preserves precision)
    let output = result / (10_u64.pow(input_decimals as u32));
    
    require!(output > 0, ErrorCode::InsufficientOutput);
    Ok(output)
}

// ✅ Proper fixed-point arithmetic for different decimals
pub fn cross_decimal_swap(
    token_a_amount: u64,
    price_a_to_b: u64,
    token_a_decimals: u8,
    token_b_decimals: u8,
) -> Result<u64> {
    // Both tokens might have different decimal places
    
    // Normalize to same scale (e.g., 18 decimals)
    const NORMALIZED_DECIMALS: u8 = 18;
    
    let a_normalized = scale_amount(
        token_a_amount,
        token_a_decimals,
        NORMALIZED_DECIMALS,
    )?;
    
    let b_normalized = a_normalized
        .checked_mul(price_a_to_b)
        .ok_or(ErrorCode::Overflow)?;
    
    let token_b_amount = descale_amount(
        b_normalized,
        NORMALIZED_DECIMALS,
        token_b_decimals,
    )?;
    
    Ok(token_b_amount)
}

// ✅ Helper: Scale amount up to normalized decimals
pub fn scale_amount(amount: u64, from_decimals: u8, to_decimals: u8) -> Result<u64> {
    if to_decimals >= from_decimals {
        amount
            .checked_mul(10_u64.pow((to_decimals - from_decimals) as u32))
            .ok_or(ErrorCode::CalculationOverflow)
    } else {
        Ok(amount / 10_u64.pow((from_decimals - to_decimals) as u32))
    }
}

// ✅ Helper: Scale amount down from normalized decimals
pub fn descale_amount(amount: u64, from_decimals: u8, to_decimals: u8) -> Result<u64> {
    if to_decimals <= from_decimals {
        Ok(amount / 10_u64.pow((from_decimals - to_decimals) as u32))
    } else {
        amount
            .checked_mul(10_u64.pow((to_decimals - from_decimals) as u32))
            .ok_or(ErrorCode::CalculationOverflow)
    }
}

// ✅ Secure yield calculation with rounding in protocol's favor
pub fn calculate_yield_secure(
    principal: u64,
    rate_per_period: u64,  // In basis points (100 = 1%)
    periods: u64,
    is_compound: bool,
) -> Result<u64> {
    require!(rate_per_period <= 10_000, ErrorCode::InvalidRate);
    
    if !is_compound {
        // Simple interest: only multiply
        let yield_amount = (principal * rate_per_period) / 10_000;
        principal.checked_add(yield_amount)
            .ok_or(ErrorCode::CalculationOverflow)
    } else {
        // Compound: use formula or iterate with precision tracking
        let mut amount = principal;
        
        for _ in 0..periods {
            let yield_this_period = (amount * rate_per_period) / 10_000;
            amount = amount
                .checked_add(yield_this_period)
                .ok_or(ErrorCode::CalculationOverflow)?;
        }
        
        Ok(amount)
    }
}

// ✅ Price feed with proper decimal handling
pub fn get_token_price(
    base_price: u64,
    base_decimals: u8,
    multiplier: u64,
    multiplier_decimals: u8,
) -> Result<u64> {
    // Normalize both to same scale before multiplying
    let normalized_base = scale_amount(base_price, base_decimals, 18)?;
    let normalized_multiplier = scale_amount(multiplier, multiplier_decimals, 18)?;
    
    let product = normalized_base
        .checked_mul(normalized_multiplier)
        .ok_or(ErrorCode::Overflow)?;
    
    // Scale back down to 18 decimals
    Ok(product / (10_u64.pow(18)))
}

// ✅ Slippage protection with proper precision
pub fn verify_min_output(
    actual_output: u64,
    expected_output: u64,
    max_slippage_bps: u16,  // Basis points (100 = 1%)
) -> Result<()> {
    require!(max_slippage_bps <= 10_000, ErrorCode::InvalidSlippage);
    
    let min_acceptable = expected_output
        .checked_mul((10_000 - max_slippage_bps as u64) as u64)
        .ok_or(ErrorCode::Overflow)?
        / 10_000;
    
    require!(
        actual_output >= min_acceptable,
        ErrorCode::ExcessiveSlippage
    );
    
    Ok(())
}
```

## Testing

- **Exploit test** (`tests/exploit.ts`): Demonstrates precision loss extraction through repeated operations
- **Secure test** (`tests/secure.ts`): Validates correct precision handling

## Learning Objectives

1. Understand fixed-point arithmetic in Solana
2. Handle decimal place conversion correctly
3. Implement proper multiplication before division
4. Recognize precision loss in accumulation
5. Design slippage-resistant swaps
6. Test with large numbers and edge cases

## Key Takeaways

- **Always multiply before dividing** - Never do `(a / b) * c`
- **Handle decimals explicitly** - Don't assume all tokens have same decimals
- **Check for overflow** - Use `checked_mul` before dividing large numbers
- **Document precision assumptions** - Clearly state decimal places in comments
- **Round in protocol's favor** - Truncation should benefit protocol, not users
- **Test with extreme values** - Use very large numbers and edge cases

## Best Practices

1. Create helper functions for common calculations
2. Always document decimal places for all amounts
3. Use normalized scale (e.g., 18 decimals) for internal calculations
4. Test with tokens having different decimals (6, 8, 9, 18)
5. Verify swap outputs don't violate invariants
6. Implement slippage checks to catch precision issues
7. Monitor actual vs expected outputs in monitoring

## Fixed-Point Arithmetic Rules

For amount in decimals `D₁` × price in decimals `D₂`:
- Result has decimals: `D₁ + D₂ - REFERENCE_DECIMALS`
- Always scale to common reference (e.g., 18) before multiplication
- Document all assumptions about decimal places
- Test with various decimal combinations

## Files in This Example

- `programs/vulnerable/src/lib.rs` - Incorrect precision handling
- `programs/secure/src/lib.rs` - Proper fixed-point arithmetic
- `tests/exploit.ts` - Demonstrates precision extraction attacks
- `tests/secure.ts` - Validates correct precision calculations
