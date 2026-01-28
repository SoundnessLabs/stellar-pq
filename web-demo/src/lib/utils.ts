import { clsx, type ClassValue } from 'clsx'
import { twMerge } from 'tailwind-merge'

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

export function truncateHex(hex: string, startChars = 8, endChars = 8): string {
  if (hex.length <= startChars + endChars + 3) return hex
  return `${hex.slice(0, startChars)}...${hex.slice(-endChars)}`
}

export function truncateAddress(address: string, startChars = 8, endChars = 8): string {
  if (address.length <= startChars + endChars + 3) return address
  return `${address.slice(0, startChars)}...${address.slice(-endChars)}`
}

export function hexToBytes(hex: string): Uint8Array {
  const cleanHex = hex.startsWith('0x') ? hex.slice(2) : hex
  const bytes = new Uint8Array(cleanHex.length / 2)
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(cleanHex.substr(i * 2, 2), 16)
  }
  return bytes
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('')
}

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} bytes`
  return `${(bytes / 1024).toFixed(1)} KB`
}

export function formatXLM(stroops: bigint | number): string {
  const xlm = Number(stroops) / 10_000_000
  return xlm.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 7 })
}

export function parseXLM(xlm: string): bigint {
  const num = parseFloat(xlm)
  if (isNaN(num)) return BigInt(0)
  return BigInt(Math.floor(num * 10_000_000))
}

export async function copyToClipboard(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text)
    return true
  } catch {
    return false
  }
}

export function generateRandomSeed(length = 48): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(length))
}

export function isValidStellarAddress(address: string): boolean {
  // Basic validation for Stellar addresses (G... or C...)
  return /^[GC][A-Z2-7]{55}$/.test(address)
}
