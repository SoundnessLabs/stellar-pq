#!/usr/bin/env bash
# Re-run CoinFabrik Scout on the two Soroban contract crates.
# (falcon-512-core is excluded -- Scout requires one of ink, soroban, or
# substrate-pallets as a dependency, and falcon-512-core is the
# soroban-sdk-free crypto core.)
#
# Requires:
#   cargo install cargo-scout-audit --locked
#
# Usage: from repo root:
#   bash docs/audit/scout-scan/run.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
OUT_DIR="$REPO_ROOT/docs/audit/scout-scan"

CRATES=(soroban-falcon-smart-account soroban-falcon-verifier)

for c in "${CRATES[@]}"; do
  echo
  echo "=== scout-audit: $c ==="
  ( cd "$REPO_ROOT/contracts/$c" && cargo scout-audit --output-format md ) \
    2>&1 | perl -pe 's/\e\[[0-9;]*m//g' | tail -200 \
    > "$OUT_DIR/scout-$c.txt"
done

echo
echo "Done. Sanitized reports in $OUT_DIR/"
