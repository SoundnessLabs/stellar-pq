/**
 * Shared Stellar network configuration
 */

import * as StellarSdk from '@stellar/stellar-sdk'

// Network configuration (from environment variables with fallbacks)
export const NETWORK = import.meta.env.VITE_STELLAR_NETWORK || 'testnet'
export const RPC_URL = import.meta.env.VITE_STELLAR_RPC || 'https://soroban-testnet.stellar.org'
export const NETWORK_PASSPHRASE = NETWORK === 'mainnet' ? StellarSdk.Networks.PUBLIC : StellarSdk.Networks.TESTNET

// Falcon Verifier contract
export const FALCON_VERIFIER_ID = import.meta.env.VITE_FALCON_VERIFIER || 'CBUSI6FKYYA2OUXR5Z4APPHARJ3NOS3YPUDJU2YZC2YXH46BQZIIUPZR'

// XLM Stellar Asset Contract
export const XLM_SAC_ID = import.meta.env.VITE_XLM_SAC || 'CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC'

// Smart Account WASM hash (from previous installation)
export const SMART_ACCOUNT_WASM_HASH = import.meta.env.VITE_WASM_HASH || ''

// Pre-deployed Smart Account for demo
export const PRE_DEPLOYED_SMART_ACCOUNT = import.meta.env.VITE_SMART_ACCOUNT || ''

// The seed that was used to initialize the pre-deployed contract
export const PRE_DEPLOYED_SEED = '424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242'

// Demo account (pre-funded for gas)
// This is a testnet-only demo account - DO NOT use real funds
export const DEMO_SECRET = import.meta.env.VITE_STELLAR_SECRET || 'SDLMK4OHNKOXOELJ7LIAOYCPDRPFRLVCXLXX7A7FBYY4TH2CELI5J2E4'

/**
 * Get the demo account's public key.
 */
export function getDemoAccountPublicKey(): string {
  const sourceKeypair = StellarSdk.Keypair.fromSecret(DEMO_SECRET)
  return sourceKeypair.publicKey()
}

/**
 * Get explorer URL for a transaction
 */
export function getExplorerUrl(txHash: string): string {
  const explorerNetwork = NETWORK === 'mainnet' ? 'public' : 'testnet'
  return `https://stellar.expert/explorer/${explorerNetwork}/tx/${txHash}`
}

/**
 * Get explorer URL for a contract
 */
export function getContractExplorerUrl(contractId: string): string {
  const explorerNetwork = NETWORK === 'mainnet' ? 'public' : 'testnet'
  return `https://stellar.expert/explorer/${explorerNetwork}/contract/${contractId}`
}
