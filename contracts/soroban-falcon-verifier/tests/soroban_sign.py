#!/usr/bin/env python3
"""
Falcon-512 Signature Generator for Soroban On-Chain Verification

Generate Falcon-512 post-quantum signatures and verify them on-chain
using the Soroban smart contract on Stellar testnet.

================================================================================
SETUP INSTRUCTIONS
================================================================================

1. Clone the falcon.py repository:
   git clone https://github.com/tprest/falcon.py
   cd falcon.py

2. Install Python dependencies:
   pip install pycryptodome numpy

3. Install Stellar CLI:
   # macOS
   brew install stellar-cli
   # Or via cargo (any OS)
   cargo install stellar-cli --locked

4. Create and fund a testnet account:
   stellar keys generate --global alice --network testnet

   # Get your address
   stellar keys address alice

   # Fund it (visit this URL in browser, replace YOUR_ADDRESS):
   # https://friendbot.stellar.org/?addr=YOUR_ADDRESS

5. Run this script:
   python3 soroban_sign.py "Your message here"

================================================================================
USAGE
================================================================================

    python3 soroban_sign.py                          # Sign default message
    python3 soroban_sign.py "Your message here"      # Sign custom message
    python3 soroban_sign.py --file /path/to/file     # Sign file contents

The script will output a ready-to-run Stellar CLI command that verifies
your signature on-chain.

================================================================================
CONTRACT INFO
================================================================================

Contract ID: CCUXVGY7ABTWKKAMOJNUD536D7KVVEPG5DXA7SSALSSB3O7OAU3TL57S
Network: Stellar Testnet
Verification cost: ~400k CPU instructions (~0.4% of budget)

================================================================================
"""

import sys
import argparse
from falcon import Falcon, params, logn, HEAD_LEN, SALT_LEN
from encoding import compress, decompress
from common import q
from ntt import sub_zq, mul_zq


# Falcon-512 Verifier contract deployed on Stellar testnet
CONTRACT_ID = "CCUXVGY7ABTWKKAMOJNUD536D7KVVEPG5DXA7SSALSSB3O7OAU3TL57S"


def encode_public_key(h, n):
    """
    Encode public key polynomial h to bytes (MSB-first bit packing).

    Format: 1 byte header (logn) + 14 bits per coefficient
    For n=512: 1 + (512 * 14) / 8 = 1 + 896 = 897 bytes

    This matches the C reference implementation encoding.
    """
    header = bytes([logn[n]])  # 0x09 for Falcon-512

    # Pack coefficients: 14 bits each, MSB-first (big-endian)
    data = bytearray()
    acc = 0
    acc_len = 0

    for coef in h:
        # Add 14 bits to accumulator (MSB-first)
        acc = (acc << 14) | (coef & 0x3FFF)
        acc_len += 14

        # Extract full bytes
        while acc_len >= 8:
            acc_len -= 8
            data.append((acc >> acc_len) & 0xFF)

    # If there are remaining bits, they should be zero-padded
    if acc_len > 0:
        data.append((acc << (8 - acc_len)) & 0xFF)

    return header + bytes(data)


def generate_keypair():
    """
    Generate a Falcon-512 keypair.

    Returns:
        (falcon_instance, secret_key, verification_key, public_key_bytes, public_key_hex)
    """
    n = 512
    print("Generating Falcon-512 keypair...")
    falcon = Falcon(n)
    sk, vk = falcon.keygen()

    # Get h polynomial from sk to encode with header for on-chain format
    f, g, F, G, B0_fft, T_fft = sk
    from ntt import div_zq
    h = div_zq(g, f)
    pk_bytes = encode_public_key(h, n)

    print(f"  Public key: {len(pk_bytes)} bytes")
    assert len(pk_bytes) == 897, f"Expected 897 bytes, got {len(pk_bytes)}"

    return falcon, sk, vk, pk_bytes, pk_bytes.hex()


def sign_message(falcon, sk, message):
    """
    Sign a message with the secret key.

    Args:
        falcon: Falcon instance
        sk: Secret key tuple
        message: bytes to sign

    Returns:
        (signature_bytes, signature_hex, signature_info)
    """
    print(f"Signing message ({len(message)} bytes)...")

    sig = falcon.sign(sk, message)

    # Parse signature components
    header = sig[0]
    salt = sig[1:41]
    enc_s1 = sig[41:]

    # Decompress to get s1 for norm calculation
    s1 = decompress(enc_s1, len(enc_s1), 512)

    # Get h from sk
    f, g, F, G, B0_fft, T_fft = sk
    from ntt import div_zq
    h = div_zq(g, f)

    hashed = falcon.__hash_to_point__(message, salt)
    s0 = sub_zq(hashed, mul_zq(s1, h))
    s0 = [(coef + (q >> 1)) % q - (q >> 1) for coef in s0]

    # Compute signature norm
    norm = sum(c**2 for c in s0) + sum(c**2 for c in s1)

    info = {
        "header": f"0x{header:02x}",
        "format": "compressed" if (header & 0xF0) == 0x30 else "padded",
        "salt_hex": salt.hex(),
        "signature_len": len(sig),
        "squared_norm": norm,
        "bound": params[512].sig_bound,
    }

    print(f"  Signature: {len(sig)} bytes ({info['format']} format)")
    print(f"  Squared norm: {norm:,} (bound: {info['bound']:,})")

    return sig, sig.hex(), info


def verify_locally(falcon, vk, message, sig):
    """Verify signature locally before submitting to chain."""
    is_valid = falcon.verify(vk, message, sig)
    print(f"  Local verification: {'PASSED' if is_valid else 'FAILED'}")
    return is_valid


def main():
    parser = argparse.ArgumentParser(
        description="Generate Falcon-512 signatures for Soroban on-chain verification",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 soroban_sign.py "Hello, Soroban!"
  python3 soroban_sign.py --file document.pdf
  python3 soroban_sign.py --source bob --network testnet "My message"
        """
    )
    parser.add_argument(
        "message",
        nargs="?",
        default="Hello from Python Falcon!",
        help="Message to sign (default: 'Hello from Python Falcon!')"
    )
    parser.add_argument(
        "--file", "-f",
        help="Sign contents of this file instead of message argument"
    )
    parser.add_argument(
        "--source", "-s",
        default="alice",
        help="Stellar account name for transaction (default: alice)"
    )
    parser.add_argument(
        "--network", "-n",
        default="testnet",
        help="Stellar network (default: testnet)"
    )

    args = parser.parse_args()

    # Get message bytes
    if args.file:
        with open(args.file, 'rb') as f:
            message = f.read()
        print(f"Signing file: {args.file}")
    else:
        message = args.message.encode('utf-8')
        print(f"Signing message: \"{args.message}\"")

    print()

    # Generate keypair
    falcon, sk, vk, pk_bytes, pk_hex = generate_keypair()
    print()

    # Sign message
    sig, sig_hex, sig_info = sign_message(falcon, sk, message)
    print()

    # Verify locally
    if not verify_locally(falcon, vk, message, sig):
        print("\nERROR: Local verification failed!")
        sys.exit(1)

    # Output results
    print("\n" + "=" * 70)
    print("VERIFICATION COMMAND")
    print("=" * 70)
    print(f"""
Run this command to verify the signature on Stellar testnet:

stellar contract invoke \\
    --id {CONTRACT_ID} \\
    --source {args.source} \\
    --network {args.network} \\
    -- \\
    verify \\
    --public_key {pk_hex} \\
    --message {message.hex()} \\
    --signature {sig_hex}
""")

    print("=" * 70)
    print("Expected output: true")
    print("=" * 70)


if __name__ == "__main__":
    main()
