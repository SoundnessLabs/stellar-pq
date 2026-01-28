#!/bin/bash
#
# Deploy Falcon-512 Smart Account to Soroban (Stellar)
#
# Usage:
#   ./deploy.sh --network testnet --pubkey-file <path/to/pubkey.hex>
#   ./deploy.sh --network testnet --pubkey <897_BYTE_HEX_STRING>
#   ./deploy.sh --network mainnet --pubkey-file keys/my_falcon_pubkey.hex --source mainnet-deployer
#
# Prerequisites:
#   - stellar CLI installed (https://developers.stellar.org/docs/tools/developer-tools)
#   - Identity created: stellar keys generate <name> --network <network>
#   - Account funded with XLM (testnet: use Friendbot, mainnet: transfer XLM)
#   - Falcon-512 public key (897 bytes, hex-encoded)

set -e

# =============================================================================
# Configuration
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
WASM_PATH="$WORKSPACE_ROOT/target/wasm32v1-none/release/soroban_falcon_smart_account.wasm"
OPTIMIZED_WASM_PATH="$WORKSPACE_ROOT/target/wasm32v1-none/release/soroban_falcon_smart_account.optimized.wasm"

# Expected public key size in bytes
FALCON_512_PUBKEY_SIZE=897

# Network configurations
TESTNET_RPC="https://soroban-testnet.stellar.org"
TESTNET_PASSPHRASE="Test SDF Network ; September 2015"

MAINNET_RPC="https://soroban.stellar.org"
MAINNET_PASSPHRASE="Public Global Stellar Network ; September 2015"

# =============================================================================
# Helper Functions
# =============================================================================

print_usage() {
    echo "Usage: $0 --network <testnet|mainnet> <--pubkey <hex> | --pubkey-file <path>> [--source <identity>]"
    echo ""
    echo "Options:"
    echo "  --network      Target network: testnet or mainnet (required)"
    echo "  --pubkey       Falcon-512 public key as hex string (897 bytes = 1794 hex chars)"
    echo "  --pubkey-file  Path to file containing hex-encoded Falcon-512 public key"
    echo "  --source       Stellar identity name for signing (default: default)"
    echo ""
    echo "Examples:"
    echo "  $0 --network testnet --pubkey-file tests/fixtures/test_pubkey.hex"
    echo "  $0 --network testnet --pubkey 0902c671f64d92df6c..."
    echo "  $0 --network mainnet --pubkey-file keys/falcon_pubkey.hex --source mainnet-deployer"
    echo ""
    echo "Generate a Falcon keypair:"
    echo "  Use the falcon crate or falcon-cli to generate a keypair."
    echo "  The public key must be exactly 897 bytes (Falcon-512 format)."
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

# Validate hex string (only hex characters)
is_valid_hex() {
    local hex="$1"
    [[ "$hex" =~ ^[0-9a-fA-F]+$ ]]
}

# =============================================================================
# Parse Arguments
# =============================================================================

NETWORK=""
SOURCE="default"
PUBKEY_HEX=""
PUBKEY_FILE=""

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
        --pubkey)
            PUBKEY_HEX="$2"
            shift 2
            ;;
        --pubkey-file)
            PUBKEY_FILE="$2"
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

# =============================================================================
# Validate Arguments
# =============================================================================

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

# Validate public key parameter
if [[ -z "$PUBKEY_HEX" && -z "$PUBKEY_FILE" ]]; then
    log_error "Missing public key. Provide --pubkey or --pubkey-file"
    print_usage
    exit 1
fi

if [[ -n "$PUBKEY_HEX" && -n "$PUBKEY_FILE" ]]; then
    log_error "Provide either --pubkey or --pubkey-file, not both"
    exit 1
fi

# Read public key from file if specified
if [[ -n "$PUBKEY_FILE" ]]; then
    if [[ ! -f "$PUBKEY_FILE" ]]; then
        log_error "Public key file not found: $PUBKEY_FILE"
        exit 1
    fi
    PUBKEY_HEX=$(cat "$PUBKEY_FILE" | tr -d '[:space:]')
    log_info "Read public key from: $PUBKEY_FILE"
fi

# Validate public key format
if ! is_valid_hex "$PUBKEY_HEX"; then
    log_error "Invalid public key: must be hex-encoded"
    exit 1
fi

# Validate public key size (897 bytes = 1794 hex characters)
EXPECTED_HEX_LEN=$((FALCON_512_PUBKEY_SIZE * 2))
ACTUAL_HEX_LEN=${#PUBKEY_HEX}

if [[ $ACTUAL_HEX_LEN -ne $EXPECTED_HEX_LEN ]]; then
    log_error "Invalid public key size: expected $EXPECTED_HEX_LEN hex chars ($FALCON_512_PUBKEY_SIZE bytes), got $ACTUAL_HEX_LEN"
    exit 1
fi

# Validate Falcon-512 header byte (should be 0x09)
HEADER_BYTE="${PUBKEY_HEX:0:2}"
if [[ "$HEADER_BYTE" != "09" ]]; then
    log_warn "Unexpected public key header: 0x$HEADER_BYTE (expected 0x09 for Falcon-512)"
    log_warn "Continuing anyway, but this may not be a valid Falcon-512 public key"
fi

log_success "Public key validated: $FALCON_512_PUBKEY_SIZE bytes"

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
    log_warn "The smart account will be initialized with the provided public key."
    echo ""
    echo "Public key (first 32 chars): ${PUBKEY_HEX:0:32}..."
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
# Deploy Contract with Constructor
# =============================================================================

log_info "Deploying smart account to $NETWORK..."
log_info "RPC: $RPC_URL"
log_info "Public key: ${PUBKEY_HEX:0:32}...${PUBKEY_HEX: -8}"

# Deploy contract with constructor argument
# The -- separates deploy args from constructor args
DEPLOY_OUTPUT=$(stellar contract deploy \
    --wasm "$DEPLOY_WASM" \
    --source "$SOURCE" \
    --rpc-url "$RPC_URL" \
    --network-passphrase "$NETWORK_PASSPHRASE" \
    -- \
    --falcon_pubkey "$PUBKEY_HEX" \
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
echo " Falcon Smart Account Deployed Successfully!"
echo "=============================================="
echo ""
echo "Network:           $NETWORK"
echo "Contract ID:       $CONTRACT_ID"
echo "Public Key:        ${PUBKEY_HEX:0:32}...${PUBKEY_HEX: -8}"
echo "Explorer:          $EXPLORER_BASE/$CONTRACT_ID"
echo ""
echo "This contract is now a Falcon-512 authenticated smart account."
echo "Transactions must be signed with the corresponding Falcon private key."
echo ""
echo "To verify the public key is stored correctly:"
echo ""
echo "  stellar contract invoke \\"
echo "    --id $CONTRACT_ID \\"
echo "    --source $SOURCE \\"
echo "    --rpc-url $RPC_URL \\"
echo "    --network-passphrase \"$NETWORK_PASSPHRASE\" \\"
echo "    -- get_pubkey"
echo ""

# Save contract ID and metadata to file for reference
cat > "$SCRIPT_DIR/.contract-id-$NETWORK" << EOF
$CONTRACT_ID
EOF

cat > "$SCRIPT_DIR/.deployment-$NETWORK.json" << EOF
{
  "network": "$NETWORK",
  "contract_id": "$CONTRACT_ID",
  "deployer": "$SOURCE_ADDRESS",
  "pubkey_preview": "${PUBKEY_HEX:0:64}...",
  "deployed_at": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "explorer_url": "$EXPLORER_BASE/$CONTRACT_ID"
}
EOF

log_info "Contract ID saved to .contract-id-$NETWORK"
log_info "Deployment metadata saved to .deployment-$NETWORK.json"
