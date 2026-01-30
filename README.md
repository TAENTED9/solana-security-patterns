# Solana Security Patterns: Educational Security Reference

An open-source educational repository demonstrating common Solana program vulnerabilities with side-by-side comparisons of vulnerable and secure implementations. This project teaches developers to recognize security pitfalls and understand how to fix them correctly.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Anchor](https://img.shields.io/badge/Anchor-0.32.1-purple)](https://www.anchor-lang.com/)
[![Rust](https://img.shields.io/badge/Rust-1.85.0+-orange)](https://www.rust-lang.org/)

## Overview

Security remains one of the biggest challenges in Solana program development. Many exploits do not come from complex attacks, but from simple mistakes: missing account validation, incorrect authority checks, unsafe arithmetic, or misunderstood CPI behavior.

Anchor and Pinocchio provide strong abstractions, but they do not automatically make programs safe. Developers still need to understand why a pattern is dangerous and how to fix it correctly.

This repository builds a clear, educational security reference for Solana developers by contrasting vulnerable code with secure alternatives. The goal is to make security concepts practical and obvious, especially for developers learning Anchor or Pinocchio.

## Project Goals

- Provide at least 5 Solana program examples with vulnerable and secure versions
- Include deliberately broken instructions with corresponding fixed versions
- Supply clear inline comments explaining what went wrong and how it was corrected
- Offer comprehensive testing (exploit demonstrations and fix validation)
- Create detailed educational content (written deep-dives)

## Repository Structure

```
solana-security-patterns/
+-- examples/                              # Security pattern implementations
�   +-- 01-missing-account-validation/     # Owner and PDA checks
�   +-- 02-signer-authorization/           # Authority verification
�   +-- 03-arithmetic-overflow/            # Checked math operations
�   +-- 04-cpi-security/                   # Cross-program invocation safety
�   +-- 05-account-closure/                # Safe account closure
�   +-- 06-pda-seed-collision/             # PDA uniqueness
�   +-- 07-precision-loss/                 # Decimal precision in DeFi
+-- docs/                                  # Documentation
�   +-- deep-dive.md                       # Comprehensive security patterns guide
�   +-- research-summary.md                # Vulnerability research and analysis
�   +-- references.md                      # Citations and sources
+-- scripts/                               # Build and test automation
+-- .github/workflows/                     # CI/CD pipeline
+-- README.md                              # This file
```

## Security Patterns Covered

### 1. Missing Account Validation
**Directory:** examples/01-missing-account-validation

**Vulnerability:** Programs fail to verify account ownership or PDA derivation, allowing attackers to substitute arbitrary accounts.

**Impact:** Real-world loss of $325M (Wormhole bridge exploit)

**Secure Pattern:** Use has_one constraint, owner checks, and PDA seed verification

**Learning Objectives:**
- Understand account ownership in Solana
- Implement proper PDA derivation checks
- Use Anchor constraints effectively

---

### 2. Incorrect Authority / Signer Checks
**Directory:** examples/02-signer-authorization

**Vulnerability:** Programs trust public keys without verifying signers, allowing unauthorized access.

**Impact:** Accounted for 59% of 2025 DeFi losses ($1.6B+)

**Secure Pattern:** Use #[account(signer)] constraint and proper authority validation

**Learning Objectives:**
- Distinguish between signing and account ownership
- Implement authority checks correctly
- Prevent privilege escalation attacks

---

### 3. Unsafe Arithmetic / Overflow
**Directory:** examples/03-arithmetic-overflow

**Vulnerability:** Unchecked arithmetic in token operations causes integer overflow or underflow.

**Impact:** Integer overflow exploits in DeFi protocols

**Secure Pattern:** Use checked_add, checked_sub, and explicit bounds checking

**Learning Objectives:**
- Recognize arithmetic edge cases
- Implement safe math operations
- Prevent quantization attacks

---

### 4. CPI / Reentrancy / Confused Deputy
**Directory:** examples/04-cpi-security

**Vulnerability:** Unsafe cross-program invocations without proper verification of return values or invariants.

**Impact:** Bridge and DeFi protocol exploits

**Secure Pattern:** Verify CPI returns, protect state invariants, validate program IDs

**Learning Objectives:**
- Understand cross-program invocation mechanics
- Recognize reentrancy risks
- Implement proper CPI validation

---

### 5. Account Closure / Lamport Drain
**Directory:** examples/05-account-closure

**Vulnerability:** Improper account closure validation allows unauthorized fund drainage.

**Impact:** Loss of funds through account manipulation

**Secure Pattern:** Validate close authority and recipient before draining lamports

**Learning Objectives:**
- Implement safe account closure
- Prevent lamport theft
- Validate closure permissions

---

### 6. PDA Seed Collision
**Directory:** examples/06-pda-seed-collision

**Vulnerability:** Predictable or user-controlled PDA seeds lead to collision attacks.

**Impact:** Semantic inconsistency in stake pool protocols

**Secure Pattern:** Use program-owned derivations with uniqueness guarantees

**Learning Objectives:**
- Understand PDA derivation mechanics
- Prevent seed collision attacks
- Design collision-resistant PDAs

---

### 7. Arithmetic Precision Loss
**Directory:** examples/07-precision-loss

**Vulnerability:** Inadequate precision in DeFi calculations causes rounding errors and manipulation.

**Impact:** Price manipulation and LP token exploits

**Secure Pattern:** Implement proper decimal handling and rounding strategies

**Learning Objectives:**
- Handle fixed-point arithmetic correctly
- Prevent precision loss
- Implement safe scaling operations

---

## Quick Start

### Prerequisites

Install the required development tools:

```bash
# Install Rust (stable toolchain)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install Solana CLI
sh -c "$(curl -sSfL https://release.solana.com/stable/install)"

# Install Anchor Framework
cargo install --git https://github.com/coral-xyz/anchor avm --locked
avm install 0.32.1
avm use 0.32.1

# Verify installations
rustc --version
solana --version
anchor --version
```

### Building and Testing

```bash
# Clone the repository
git clone <repository-url>
cd solana-security-patterns

# Build all programs
anchor build

# Run tests for a specific example
cd examples/01-missing-account-validation
anchor test

# Run tests with detailed output
anchor test -- --nocapture
```

## Example Structure

Each security pattern follows this structure:

```
examples/XX-pattern-name/
+-- programs/
   +-- vulnerable/              # Vulnerable implementation
      +-- src/lib.rs          # Flawed program code with comments
   +-- secure/                  # Secure implementation
       +-- src/lib.rs          # Fixed program with explanations
+-- tests/
   +-- exploit.ts              # Demonstrates the vulnerability
   +-- secure.ts               # Proves the fix works
+-- Anchor.toml                  # Anchor configuration
+-- README.md                    # Pattern-specific documentation
```

### File Descriptions

- **vulnerable/src/lib.rs**: Contains the security flaw with inline comments explaining the issue
- **secure/src/lib.rs**: Contains the fix with comments explaining the correction
- **tests/exploit.ts**: Test that demonstrates the vulnerability and how to exploit it
- **tests/secure.ts**: Test that validates the secure version prevents the attack

## Code Quality Standards

This project emphasizes clarity and education. Code follows these principles:

1. Clear Comments: Every vulnerable section includes comments explaining the security issue
2. Obvious Fixes: The secure version shows exactly what changed and why
3. Tested Examples: Both exploit and secure versions are thoroughly tested
4. Real-World Relevance: Examples are based on actual Solana security incidents

## Learning Path

### For Beginners

1. Start with docs/deep-dive.md for comprehensive security guide
2. Review examples/01-missing-account-validation first (foundational pattern)
3. Run the test suite to see vulnerabilities in action
4. Study the diff between vulnerable.rs and secure.rs

### For Intermediate Developers

1. Review docs/research-summary.md for real-world context
2. Examine exploit scripts in each example's /tests folder
3. Study Anchor constraints and their security implications
4. Compare different approaches to the same problem

### For Advanced Users

1. Analyze the Anchor constraint system in depth
2. Study the exploit methodologies and attack patterns
3. Review CI/CD security tooling integration
4. Contribute additional patterns or improvements

## Technical Stack

- Framework: Anchor 0.32.1
- Language: Rust 1.85.0+
- Test Framework: TypeScript with Anchor Test Suite
- Optional: Pinocchio 0.10.0 for advanced examples

## Testing Requirements

Each example includes:

- Exploit test: Demonstrates the vulnerability works as expected
- Secure test: Proves the fix prevents the attack
- Integration test: Validates real-world scenarios

Run all tests:

```bash
cd examples/01-missing-account-validation
anchor test
```

## Continuous Integration

Automated checks on every commit:

- Rust code formatting (cargo fmt)
- Linting (cargo clippy)
- Unit tests (cargo test)
- Integration tests (anchor test)
- Dependency audits (cargo audit)

## Validation Checklist

This project demonstrates:

- Solid understanding of Solana's account model
- Correct use of Anchor constraints and checks
- Awareness of CPI and reentrancy risks
- Safe handling of arithmetic and state mutation
- Clear reasoning with detailed explanations

## Bonus Features

- Tests that demonstrate exploits and fixes
- Clear README summaries per vulnerability
- Deep-dive documentation explaining each pattern
- Potential comparison between Anchor and Pinocchio approaches

## Contributing

This is an educational repository. Contributions are welcome:

1. Fork the repository
2. Create a feature branch
3. Add clear comments and tests
4. Submit a pull request

Areas for improvement:

- Additional security patterns (oracle manipulation, flash loans, etc.)
- Framework coverage (native Solana, Steel framework)
- Enhanced testing (property-based testing, fuzzing)
- Translations and educational content

## License

MIT License

You are free to:
- Use for commercial projects
- Modify and distribute
- Use for educational purposes
- Include in security audits

## Disclaimer

This repository contains intentionally vulnerable code for educational purposes. Never deploy vulnerable examples to mainnet. Always conduct thorough security audits before deploying production code.

## Support

For questions or issues:

1. Check docs/deep-dive.md for explanations
2. Review example READMEs in each pattern folder
3. Examine test files for usage examples
4. Open an issue for bugs or clarifications

---

Built as an educational security reference for the Solana developer community.
