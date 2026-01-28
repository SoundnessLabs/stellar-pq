#!/bin/bash
#
# Deploy Falcon-512 Verifier to Soroban (Stellar)
#
# Usage:
#   ./deploy.sh --network testnet [--source <identity>]
#   ./deploy.sh --network mainnet [--source <identity>]
#
# Prerequisites:
#   - stellar CLI installed (https://developers.stellar.org/docs/tools/developer-tools)
#   - Identity created: stellar keys generate <name> --network <network>
#   - Account funded with XLM (testnet: use Friendbot, mainnet: transfer XLM)

set -e

# =============================================================================
# Configuration
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
WASM_PATH="$WORKSPACE_ROOT/target/wasm32v1-none/release/soroban_falcon_verifier.wasm"
OPTIMIZED_WASM_PATH="$WORKSPACE_ROOT/target/wasm32v1-none/release/soroban_falcon_verifier.optimized.wasm"

# Network configurations
TESTNET_RPC="https://soroban-testnet.stellar.org"
TESTNET_PASSPHRASE="Test SDF Network ; September 2015"

MAINNET_RPC="https://soroban.stellar.org"
MAINNET_PASSPHRASE="Public Global Stellar Network ; September 2015"

# =============================================================================
# Helper Functions
# =============================================================================

print_usage() {
    echo "Usage: $0 --network <testnet|mainnet> [--source <identity>]"
    echo ""
    echo "Options:"
    echo "  --network    Target network: testnet or mainnet (required)"
    echo "  --source     Stellar identity name for signing (default: default)"
    echo ""
    echo "Examples:"
    echo "  $0 --network testnet"
    echo "  $0 --network testnet --source my-wallet"
    echo "  $0 --network mainnet --source mainnet-deployer"
}

log_info() {
    echo "[INFO] $1"
}

log_success() {
    echo "[OK] $1"
}

log_error() {
    echo "[ERROR] $1" >&2
}

log_warn() {
    echo "[WARN] $1"
}

# =============================================================================
# Parse Arguments
# =============================================================================

NETWORK=""
SOURCE="default"

while [[ $# -gt 0 ]]; do
    case $1 in
        --network)
            NETWORK="$2"
            shift 2
            ;;
        --source)
            SOURCE="$2"
            shift 2
            ;;
        --help|-h)
            print_usage
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            print_usage
            exit 1
            ;;
    esac
done

# Validate network parameter
if [[ -z "$NETWORK" ]]; then
    log_error "Missing required --network parameter"
    print_usage
    exit 1
fi

if [[ "$NETWORK" != "testnet" && "$NETWORK" != "mainnet" ]]; then
    log_error "Invalid network: $NETWORK (must be 'testnet' or 'mainnet')"
    exit 1
fi

# =============================================================================
# Set Network Configuration
# =============================================================================

if [[ "$NETWORK" == "testnet" ]]; then
    RPC_URL="$TESTNET_RPC"
    NETWORK_PASSPHRASE="$TESTNET_PASSPHRASE"
    EXPLORER_BASE="https://stellar.expert/explorer/testnet/contract"
    FRIENDBOT_URL="https://friendbot.stellar.org"
else
    RPC_URL="$MAINNET_RPC"
    NETWORK_PASSPHRASE="$MAINNET_PASSPHRASE"
    EXPLORER_BASE="https://stellar.expert/explorer/public/contract"
fi

# =============================================================================
# Pre-flight Checks
# =============================================================================

log_info "Checking prerequisites..."

# Check stellar CLI
if ! command -v stellar &> /dev/null; then
    log_error "stellar CLI not found. Install it from:"
    log_error "  https://developers.stellar.org/docs/tools/developer-tools"
    exit 1
fi
log_success "stellar CLI found"

# Check identity exists
if ! stellar keys address "$SOURCE" &> /dev/null; then
    log_error "Identity '$SOURCE' not found."
    echo ""
    echo "Create a new identity with:"
    echo "  stellar keys generate $SOURCE --network $NETWORK"
    echo ""
    if [[ "$NETWORK" == "testnet" ]]; then
        echo "Fund it using Friendbot (testnet only):"
        echo "  curl \"$FRIENDBOT_URL?addr=\$(stellar keys address $SOURCE)\""
    else
        echo "Fund it by sending XLM to the address."
    fi
    exit 1
fi

SOURCE_ADDRESS=$(stellar keys address "$SOURCE")
log_success "Identity '$SOURCE' found: $SOURCE_ADDRESS"

# =============================================================================
# Mainnet Confirmation
# =============================================================================

if [[ "$NETWORK" == "mainnet" ]]; then
    echo ""
    log_warn "You are about to deploy to MAINNET!"
    log_warn "This will cost real XLM for transaction fees."
    echo ""
    read -p "Type 'mainnet' to confirm: " CONFIRM
    if [[ "$CONFIRM" != "mainnet" ]]; then
        log_error "Deployment cancelled."
        exit 1
    fi
    echo ""
fi

# =============================================================================
# Build Contract
# =============================================================================

log_info "Building contract..."
cd "$SCRIPT_DIR"

stellar contract build 2>&1 | while read line; do echo "  $line"; done

if [[ ! -f "$WASM_PATH" ]]; then
    log_error "WASM not found at $WASM_PATH"
    exit 1
fi

WASM_SIZE=$(wc -c < "$WASM_PATH" | tr -d ' ')
log_success "Contract built: $WASM_SIZE bytes"

# =============================================================================
# Optimize Contract (optional but recommended)
# =============================================================================

log_info "Optimizing contract..."

if stellar contract optimize --wasm "$WASM_PATH" --wasm-out "$OPTIMIZED_WASM_PATH" 2>&1 | while read line; do echo "  $line"; done; then
    if [[ -f "$OPTIMIZED_WASM_PATH" ]]; then
        OPTIMIZED_SIZE=$(wc -c < "$OPTIMIZED_WASM_PATH" | tr -d ' ')
        log_success "Optimized: $WASM_SIZE -> $OPTIMIZED_SIZE bytes"
        DEPLOY_WASM="$OPTIMIZED_WASM_PATH"
    else
        log_warn "Optimization produced no output, using unoptimized WASM"
        DEPLOY_WASM="$WASM_PATH"
    fi
else
    log_warn "Optimization failed, using unoptimized WASM"
    DEPLOY_WASM="$WASM_PATH"
fi

# =============================================================================
# Deploy Contract
# =============================================================================

log_info "Deploying to $NETWORK..."
log_info "RPC: $RPC_URL"

# Deploy contract (install + deploy in one command)
DEPLOY_OUTPUT=$(stellar contract deploy \
    --wasm "$DEPLOY_WASM" \
    --source "$SOURCE" \
    --rpc-url "$RPC_URL" \
    --network-passphrase "$NETWORK_PASSPHRASE" \
    2>&1)

# Extract contract ID (last line that looks like a contract ID)
CONTRACT_ID=$(echo "$DEPLOY_OUTPUT" | grep -E '^C[A-Z0-9]{55}$' | tail -1)

if [[ -z "$CONTRACT_ID" ]]; then
    log_error "Failed to extract contract ID from deployment output:"
    echo "$DEPLOY_OUTPUT"
    exit 1
fi

# =============================================================================
# Success Output
# =============================================================================

echo ""
echo "=============================================="
echo " Deployment Successful!"
echo "=============================================="
echo ""
echo "Network:     $NETWORK"
echo "Contract ID: $CONTRACT_ID"
echo "Explorer:    $EXPLORER_BASE/$CONTRACT_ID"
echo ""
echo "To invoke the contract:"
echo ""
echo "  stellar contract invoke \\"
echo "    --id $CONTRACT_ID \\"
echo "    --source $SOURCE \\"
echo "    --rpc-url $RPC_URL \\"
echo "    --network-passphrase \"$NETWORK_PASSPHRASE\" \\"
echo "    -- verify \\"
echo "    --public_key <hex> \\"
echo "    --message <hex> \\"
echo "    --signature <hex>"
echo ""

# Save contract ID to file for reference
echo "$CONTRACT_ID" > "$SCRIPT_DIR/.contract-id-$NETWORK"
log_info "Contract ID saved to .contract-id-$NETWORK"
