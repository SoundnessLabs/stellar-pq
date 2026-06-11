#!/usr/bin/env bash
# Reproduce the cargo audit + cargo clippy scans across all three Rust
# crates. Captures evidence into the working directory.
#
# Requires:
#   - cargo (with the clippy component: `rustup component add clippy`)
#   - cargo-audit (`cargo install cargo-audit --locked`)
#
# Usage: from repo root:
#   bash docs/audit/dep-scan/run.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
OUT_DIR="$REPO_ROOT/docs/audit/dep-scan"

CRATES=(falcon-512-core soroban-falcon-smart-account soroban-falcon-verifier)

for c in "${CRATES[@]}"; do
  echo
  echo "=== clippy: $c ==="
  ( cd "$REPO_ROOT/contracts/$c" && cargo clippy --release --all-targets ) \
    > "$OUT_DIR/clippy-$c.txt" 2>&1 || true

  echo "=== cargo audit: $c ==="
  ( cd "$REPO_ROOT/contracts/$c" && cargo audit ) \
    > "$OUT_DIR/cargo-audit-$c.txt" 2>&1 || true
done

echo
echo "Done. Artifacts in $OUT_DIR/"
