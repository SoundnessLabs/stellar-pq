#!/usr/bin/env bash
# Reproduce the constant-time analysis of falcon-512-core.
#
# Requires:
#   - rustc (any recent stable; 1.94.1 used in the report)
#   - rustup target add aarch64-unknown-linux-gnu x86_64-unknown-linux-gnu
#   - uv (https://github.com/astral-sh/uv)
#   - The trail-of-bits constant-time-analysis Claude Code plugin, or
#     clone https://github.com/trailofbits/constant-time-analysis manually
#     and point ANALYZER at it.
#
# Usage: run from repo root:
#   bash docs/audit/ct-analysis/run.sh

set -euo pipefail

ANALYZER_DEFAULT="$HOME/.claude/plugins/cache/trailofbits/constant-time-analysis/0.1.0/ct_analyzer/analyzer.py"
ANALYZER="${ANALYZER:-$ANALYZER_DEFAULT}"

if [[ ! -f "$ANALYZER" ]]; then
  echo "analyzer.py not found at $ANALYZER" >&2
  echo "Set ANALYZER=/path/to/ct_analyzer/analyzer.py" >&2
  exit 1
fi

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

for SRC in falcon_ntt_standalone.rs falcon_verify_standalone.rs; do
  for ARCH in arm64 x86_64; do
    for OPT in Oz O3; do
      echo
      echo "=== $SRC | $ARCH | -$OPT ==="
      uv run --quiet "$ANALYZER" --arch "$ARCH" --opt-level "$OPT" "$DIR/$SRC" || true
    done
  done
done
