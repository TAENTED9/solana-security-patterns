# Contributing to Solana Security Patterns

First off, thank you for considering contributing to Solana Security Patterns! This repository exists to help the Solana developer community build more secure applications, and your contributions make that possible.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How Can I Contribute?](#how-can-i-contribute)
- [Development Setup](#development-setup)
- [Contributing Examples](#contributing-examples)
- [Style Guidelines](#style-guidelines)
- [Commit Messages](#commit-messages)
- [Pull Request Process](#pull-request-process)

## Code of Conduct

This project follows the [Solana Code of Conduct](https://solana.com/community). By participating, you are expected to uphold this code. Please report unacceptable behavior to the maintainers.

## How Can I Contribute?

### Reporting Security Vulnerabilities

**IMPORTANT:** If you discover a security vulnerability in the REPOSITORY CODE ITSELF (not the intentionally vulnerable examples), please email security@example.com instead of creating a public issue.

For issues with the educational content or examples, please open a GitHub issue.

### Suggesting New Security Patterns

We welcome suggestions for additional security patterns! Before suggesting:

1. Check existing issues and PRs
2. Verify the pattern is relevant to Solana specifically
3. Provide real-world exploit examples or audit reports if possible

Create an issue with:
- Pattern name and description
- Why it's important (statistics, real exploits)
- Proposed vulnerable example
- Proposed secure fix
- Any relevant citations

### Improving Documentation

Documentation improvements are always welcome:

- Fixing typos or grammatical errors
- Clarifying explanations
- Adding diagrams or visual aids
- Translating documentation
- Adding code comments

### Adding Test Cases

More test coverage helps everyone:

- Additional exploit scenarios
- Edge case testing
- Integration tests
- Fuzzing tests

### Framework Coverage

We currently focus on Anchor, but welcome:

- Pinocchio implementations
- Native Solana examples
- Steel framework examples
- Other framework comparisons

## Development Setup

### Prerequisites

```bash
# Install Rust (1.85.0+)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install Solana CLI (2.1.15+)
sh -c "$(curl -sSfL https://release.solana.com/stable/install)"

# Install Anchor (0.32.1)
cargo install --git https://github.com/coral-xyz/anchor avm --locked
avm install 0.32.1
avm use 0.32.1

# Install Node.js (22+)
# Use nvm or your preferred method

# Verify installations
rustc --version
solana --version
anchor --version
node --version
```

### Clone and Build

```bash
git clone <your-fork-url>
cd solana-security-patterns

# Build all examples
cd examples/01-missing-account-validation
anchor build

# Run tests
anchor test
```

## Contributing Examples

### Example Structure

Each security pattern example should follow this structure:

```
examples/XX-pattern-name/
├── Anchor.toml                # Anchor configuration
├── Cargo.toml                 # Workspace Cargo.toml
├── README.md                  # Pattern-specific documentation
├── programs/
│   ├── vulnerable/            # Vulnerable implementation
│   │   ├── Cargo.toml
│   │   └── src/
│   │       └── lib.rs        # Vulnerable code
│   └── secure/                # Secure implementation
│       ├── Cargo.toml
│       └── src/
│           └── lib.rs        # Secure code
└── tests/
    ├── exploit.ts            # Demonstrates vulnerability
    └── secure.ts             # Proves fix works
```

### Writing Vulnerable Examples

```rust
// [VULNERABLE] VULNERABLE: Clear explanation of what's wrong
pub fn vulnerable_function(ctx: Context<VulnerableAccounts>) -> Result<()> {
    // Explain the vulnerability inline
    // Show what an attacker could do
    
    Ok(())
}
```

**Requirements:**
1. Must have clear `[VULNERABLE] VULNERABLE:` markers
2. Must include inline explanation of exploit
3. Must be realistic (based on real vulnerabilities)
4. Must compile and run
5. Should be exploitable in test

### Writing Secure Examples

```rust
// [SECURE] SECURE: Clear explanation of security features
pub fn secure_function(ctx: Context<SecureAccounts>) -> Result<()> {
    // Explain the security measures inline
    // Reference Anchor constraints used
    
    Ok(())
}
```

**Requirements:**
1. Must have clear `[SECURE] SECURE:` markers
2. Must include inline explanation of security features
3. Must properly prevent the vulnerability
4. Must compile and run
5. Should pass all security tests

### Writing Tests

**Exploit Test (`tests/exploit.ts`):**

```typescript
describe("Exploit: Pattern Name", () => {
  it("Demonstrates vulnerability X", async () => {
    // Setup
    // Attempt exploit
    // Verify it succeeds (proving vulnerability exists)
  });
});
```

**Secure Test (`tests/secure.ts`):**

```typescript
describe("Secure: Pattern Name", () => {
  it("Prevents vulnerability X", async () => {
    // Setup
    // Attempt same exploit
    // Verify it fails with expected error
  });
  
  it("Allows legitimate use", async () => {
    // Setup
    // Perform legitimate operation
    // Verify it succeeds
  });
});
```

### Example README Template

```markdown
# Pattern Name

## Vulnerability Description

Brief explanation of the vulnerability.

## Real-World Impact

- $ Amount lost in exploits
- Notable incidents
- Citation links

## How to Exploit

Step-by-step explanation.

## How to Fix

Detailed explanation of security measures.

## Running Tests

\`\`\`bash
anchor test
\`\`\`

## References

- [Source 1](url)
- [Source 2](url)
```

## Style Guidelines

### Rust Code

Follow Rust standard style:

```bash
cargo fmt --all
cargo clippy --all-targets -- -D warnings
```

**Additional Guidelines:**
- Use descriptive variable names
- Comment complex logic
- Mark vulnerabilities clearly ([VULNERABLE])
- Mark security features clearly ([SECURE])
- Include inline exploitation/security notes

### TypeScript Tests

```typescript
// Use descriptive test names
it("should reject unauthorized withdrawal attempts", async () => {
  // Use expect() for assertions
  // Include error message checks
});
```

### Documentation

- Use clear, simple language
- Include code examples
- Cite sources for claims
- Use proper Markdown formatting
- Check spelling and grammar

## Commit Messages

Follow conventional commits:

```
type(scope): subject

body (optional)

footer (optional)
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation
- `test`: Tests
- `refactor`: Code refactoring
- `chore`: Maintenance

**Examples:**
```
feat(examples): add arithmetic overflow pattern

docs(readme): fix broken link to deep-dive guide

test(01): add edge case for PDA collision
```

## Pull Request Process

### Before Submitting

1. **Update Documentation**
   - Update main README.md if adding new pattern
   - Create pattern-specific README
   - Update research-summary.md with citations

2. **Run All Checks**
   ```bash
   cargo fmt --all
   cargo clippy --all-targets -- -D warnings
   cargo test
   anchor test
   ```

3. **Write Tests**
   - Exploit test demonstrating vulnerability
   - Secure test proving fix
   - All tests must pass

4. **Add Citations**
   - Add sources to `docs/references.md`
   - Include in pattern README
   - Link to audit reports or exploits

### PR Template

```markdown
## Description

Brief description of changes.

## Type of Change

- [ ] New security pattern example
- [ ] Bug fix
- [ ] Documentation improvement
- [ ] Test coverage
- [ ] Other (describe)

## Security Pattern Details (if applicable)

- **Pattern Name:** 
- **Real-World Exploit:** 
- **Citation:** 

## Checklist

- [ ] Code follows style guidelines
- [ ] All tests pass
- [ ] Documentation updated
- [ ] Citations added
- [ ] Vulnerable code has [VULNERABLE] markers
- [ ] Secure code has [SECURE] markers
- [ ] README.md updated (if new pattern)

## Testing

Describe testing performed.

## Screenshots (if applicable)

Test output or visual examples.
```

### Review Process

1. **Automated Checks:** CI must pass
2. **Code Review:** Maintainer reviews code
3. **Security Review:** Vulnerability/fix validated
4. **Documentation Review:** Docs are clear and accurate
5. **Approval:** Two maintainer approvals required
6. **Merge:** Squash and merge to main

## Getting Help

- **Questions:** Open a GitHub Discussion
- **Bugs:** Open a GitHub Issue
- **Security:** Email security@example.com
- **Real-time:** Join Solana Discord #security channel

## Recognition

Contributors will be:
- Listed in CONTRIBUTORS.md
- Credited in relevant documentation
- Thanked in release notes

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

Thank you for helping make Solana development more secure! 🔒
