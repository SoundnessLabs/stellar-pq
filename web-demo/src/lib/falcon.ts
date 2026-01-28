/**
 * Falcon-512 WASM Interface
 *
 * This module provides real Falcon-512 key generation and signing
 * using the compiled WASM module from the falcon crate.
 */

import init, { Falcon512KeyPair } from 'falcon-wasm'

export interface FalconKeyPair {
  publicKey: Uint8Array
  privateKey: Uint8Array
}

export interface FalconSignature {
  signature: Uint8Array
}

// WASM initialization state
let wasmInitialized = false
let initPromise: Promise<void> | null = null

/**
 * Initialize the Falcon WASM module.
 * Must be called before any other functions.
 */
export async function initFalcon(): Promise<void> {
  if (wasmInitialized) return

  if (initPromise) {
    await initPromise
    return
  }

  initPromise = (async () => {
    try {
      await init()
      wasmInitialized = true
      console.log('Falcon WASM module initialized')
    } catch (error) {
      console.error('Failed to initialize Falcon WASM:', error)
      throw error
    }
  })()

  await initPromise
}

/**
 * Check if Falcon WASM is initialized.
 */
export function isFalconReady(): boolean {
  return wasmInitialized
}

/**
 * Generate a Falcon-512 keypair from a seed.
 *
 * @param seed - 48-byte seed for deterministic key generation
 * @returns KeyPair with public and private keys
 */
export async function generateKeypair(seed: Uint8Array): Promise<FalconKeyPair> {
  if (!wasmInitialized) {
    await initFalcon()
  }

  if (seed.length !== 48) {
    throw new Error('Seed must be exactly 48 bytes')
  }

  try {
    const keypair = new Falcon512KeyPair(seed)
    const publicKey = keypair.publicKeyBytes()
    const privateKey = keypair.privateKeyBytes()

    // Free the WASM object to prevent memory leaks
    keypair.free()

    return { publicKey, privateKey }
  } catch (error) {
    console.error('Key generation failed:', error)
    throw new Error(`Failed to generate keypair: ${error}`)
  }
}

/**
 * Sign a message with a Falcon-512 private key.
 *
 * @param privateKey - The private key bytes (not used directly, we regenerate from seed)
 * @param message - The message to sign
 * @param seed - The seed used to generate the keypair (needed for signing)
 * @returns The signature
 */
export async function sign(
  _privateKey: Uint8Array,
  message: Uint8Array,
  seed: Uint8Array
): Promise<FalconSignature> {
  if (!wasmInitialized) {
    await initFalcon()
  }

  if (seed.length !== 48) {
    throw new Error('Seed must be exactly 48 bytes')
  }

  try {
    // Regenerate keypair from seed (Falcon signing requires the full keypair context)
    const keypair = new Falcon512KeyPair(seed)

    // Sign with compressed format (header 0x39)
    // Use signPadded for padded format (header 0x29)
    const signature = keypair.sign(message, seed)

    keypair.free()

    return { signature }
  } catch (error) {
    console.error('Signing failed:', error)
    throw new Error(`Failed to sign message: ${error}`)
  }
}

/**
 * Sign a message with padded signature format.
 * This produces signatures with header 0x29 (fixed 666 bytes).
 */
export async function signPadded(
  _privateKey: Uint8Array,
  message: Uint8Array,
  seed: Uint8Array
): Promise<FalconSignature> {
  if (!wasmInitialized) {
    await initFalcon()
  }

  if (seed.length !== 48) {
    throw new Error('Seed must be exactly 48 bytes')
  }

  try {
    const keypair = new Falcon512KeyPair(seed)
    const signature = keypair.signPadded(message, seed)
    keypair.free()

    return { signature }
  } catch (error) {
    console.error('Signing failed:', error)
    throw new Error(`Failed to sign message: ${error}`)
  }
}

/**
 * Verify a signature locally (without on-chain verification).
 * This is useful for testing before submitting to the contract.
 */
export async function verifyLocally(
  _publicKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
  seed: Uint8Array
): Promise<boolean> {
  if (!wasmInitialized) {
    await initFalcon()
  }

  try {
    const keypair = new Falcon512KeyPair(seed)
    const result = keypair.verify(message, signature)
    keypair.free()
    return result
  } catch (error) {
    console.error('Verification failed:', error)
    return false
  }
}

/**
 * Validate a seed format.
 */
export function isValidSeed(seed: string): boolean {
  const cleanSeed = seed.startsWith('0x') ? seed.slice(2) : seed
  return /^[0-9a-fA-F]{96}$/.test(cleanSeed)
}

/**
 * Generate a random 48-byte seed using browser crypto.
 */
export function generateRandomSeed(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(48))
}
