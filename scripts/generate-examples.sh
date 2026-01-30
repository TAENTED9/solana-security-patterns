#!/bin/bash

# Solana Security Patterns - Bulk Example Generator
# This script creates the directory structure for examples 02-07

set -e

BASE_DIR="/home/claude/solana-security-patterns/examples"

# Example definitions: "number|name|program_id_vulnerable|program_id_secure"
EXAMPLES=(
  "02|signer-authorization|SignVu1n333333333333333333333333333333333|SignS3c444444444444444444444444444444444"
  "03|arithmetic-overflow|ArithVu1n5555555555555555555555555555555|ArithS3c66666666666666666666666666666666"
  "04|cpi-security|CpiVu1n777777777777777777777777777777777|CpiS3c8888888888888888888888888888888888"
  "05|account-closure|C1os3Vu1n999999999999999999999999999999|C1os3S3cAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
  "06|pda-seed-collision|PdaVu1nBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB|PdaS3cCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
  "07|precision-loss|Pr3cisVu1nDDDDDDDDDDDDDDDDDDDDDDDDDDD|Pr3cisS3cEEEEEEEEEEEEEEEEEEEEEEEEEEEE"
)

echo "🚀 Generating example structures for examples 02-07..."

for example in "${EXAMPLES[@]}"; do
  IFS='|' read -r num name vuln_id secure_id <<< "$example"
  
  EXAMPLE_DIR="$BASE_DIR/$num-$name"
  echo "Creating $num-$name..."
  
  # Create directories
  mkdir -p "$EXAMPLE_DIR/programs/vulnerable/src"
  mkdir -p "$EXAMPLE_DIR/programs/secure/src"
  mkdir -p "$EXAMPLE_DIR/tests"
  
  # Create Anchor.toml
  cat > "$EXAMPLE_DIR/Anchor.toml" << EOF
[toolchain]
anchor_version = "0.32.1"

[features]
resolution = true
skip-lint = false

[programs.localnet]
${name//-/_}_vulnerable = "$vuln_id"
${name//-/_}_secure = "$secure_id"

[registry]
url = "https://api.apr.dev"

[provider]
cluster = "Localnet"
wallet = "~/.config/solana/id.json"

[scripts]
test = "yarn run ts-mocha -p ./tsconfig.json -t 1000000 tests/**/*.ts"

[test]
startup_wait = 10000
EOF

  # Create package.json
  cat > "$EXAMPLE_DIR/package.json" << EOF
{
  "name": "${name}-tests",
  "version": "1.0.0",
  "scripts": {
    "test": "anchor test"
  },
  "dependencies": {
    "@coral-xyz/anchor": "^0.32.1",
    "@solana/web3.js": "^1.95.8"
  },
  "devDependencies": {
    "chai": "^4.3.7",
    "mocha": "^10.2.0",
    "ts-mocha": "^10.0.0",
    "typescript": "^5.0.4"
  }
}
EOF

  # Create tsconfig.json
  cat > "$EXAMPLE_DIR/tsconfig.json" << EOF
{
  "compilerOptions": {
    "types": ["mocha", "chai"],
    "lib": ["es2015"],
    "module": "commonjs",
    "target": "es6",
    "esModuleInterop": true
  }
}
EOF

  echo "  [PASS] Created structure for $num-$name"
done

echo ""
echo "[PASS] All example structures created!"
echo "📁 Examples 02-07 are ready for implementation"
