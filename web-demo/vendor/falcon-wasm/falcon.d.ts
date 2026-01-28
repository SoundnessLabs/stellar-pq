/* tslint:disable */
/* eslint-disable */

export class Falcon1024KeyPair {
  free(): void;
  [Symbol.dispose](): void;
  /**
   * Generate a new key pair from a 48-byte seed.
   */
  constructor(seed: Uint8Array);
  /**
   * Get the public key bytes.
   */
  publicKeyBytes(): Uint8Array;
  /**
   * Get the private key bytes.
   */
  privateKeyBytes(): Uint8Array;
  /**
   * Sign a message with the private key.
   */
  sign(message: Uint8Array, seed: Uint8Array): Uint8Array;
  /**
   * Sign a message with padded signature format.
   */
  signPadded(message: Uint8Array, seed: Uint8Array): Uint8Array;
  /**
   * Verify a signature over a message.
   */
  verify(message: Uint8Array, signature: Uint8Array): boolean;
}

export class Falcon1024PublicKey {
  free(): void;
  [Symbol.dispose](): void;
  /**
   * Create a public key from raw bytes.
   */
  constructor(bytes: Uint8Array);
  /**
   * Verify a signature over a message.
   */
  verify(message: Uint8Array, signature: Uint8Array): boolean;
  /**
   * Get the public key as bytes.
   */
  toBytes(): Uint8Array;
}

export class Falcon512KeyPair {
  free(): void;
  [Symbol.dispose](): void;
  /**
   * Generate a new key pair from a 48-byte seed.
   *
   * The seed should be generated using `crypto.getRandomValues()` in JavaScript:
   * ```js
   * const seed = crypto.getRandomValues(new Uint8Array(48));
   * const keypair = new Falcon512KeyPair(seed);
   * ```
   */
  constructor(seed: Uint8Array);
  /**
   * Get the public key bytes.
   */
  publicKeyBytes(): Uint8Array;
  /**
   * Get the private key bytes.
   */
  privateKeyBytes(): Uint8Array;
  /**
   * Sign a message with the private key.
   *
   * Returns the signature bytes.
   */
  sign(message: Uint8Array, seed: Uint8Array): Uint8Array;
  /**
   * Sign a message with padded signature format.
   */
  signPadded(message: Uint8Array, seed: Uint8Array): Uint8Array;
  /**
   * Verify a signature over a message.
   */
  verify(message: Uint8Array, signature: Uint8Array): boolean;
}

export class Falcon512PublicKey {
  free(): void;
  [Symbol.dispose](): void;
  /**
   * Create a public key from raw bytes.
   */
  constructor(bytes: Uint8Array);
  /**
   * Verify a signature over a message.
   */
  verify(message: Uint8Array, signature: Uint8Array): boolean;
  /**
   * Get the public key as bytes.
   */
  toBytes(): Uint8Array;
}

/**
 * Get the private key size for Falcon-1024.
 */
export function falcon1024PrivateKeySize(): number;

/**
 * Get the public key size for Falcon-1024.
 */
export function falcon1024PublicKeySize(): number;

/**
 * Get the private key size for Falcon-512.
 */
export function falcon512PrivateKeySize(): number;

/**
 * Get the public key size for Falcon-512.
 */
export function falcon512PublicKeySize(): number;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
  readonly memory: WebAssembly.Memory;
  readonly __wbg_falcon512keypair_free: (a: number, b: number) => void;
  readonly falcon512keypair_new: (a: number, b: number) => [number, number, number];
  readonly falcon512keypair_publicKeyBytes: (a: number) => [number, number];
  readonly falcon512keypair_privateKeyBytes: (a: number) => [number, number];
  readonly falcon512keypair_sign: (a: number, b: number, c: number, d: number, e: number) => [number, number, number, number];
  readonly falcon512keypair_signPadded: (a: number, b: number, c: number, d: number, e: number) => [number, number, number, number];
  readonly falcon512keypair_verify: (a: number, b: number, c: number, d: number, e: number) => [number, number, number];
  readonly __wbg_falcon512publickey_free: (a: number, b: number) => void;
  readonly falcon512publickey_new: (a: number, b: number) => [number, number, number];
  readonly falcon512publickey_verify: (a: number, b: number, c: number, d: number, e: number) => [number, number, number];
  readonly falcon512publickey_toBytes: (a: number) => [number, number];
  readonly __wbg_falcon1024keypair_free: (a: number, b: number) => void;
  readonly falcon1024keypair_new: (a: number, b: number) => [number, number, number];
  readonly falcon1024keypair_publicKeyBytes: (a: number) => [number, number];
  readonly falcon1024keypair_privateKeyBytes: (a: number) => [number, number];
  readonly falcon1024keypair_sign: (a: number, b: number, c: number, d: number, e: number) => [number, number, number, number];
  readonly falcon1024keypair_signPadded: (a: number, b: number, c: number, d: number, e: number) => [number, number, number, number];
  readonly falcon1024keypair_verify: (a: number, b: number, c: number, d: number, e: number) => [number, number, number];
  readonly __wbg_falcon1024publickey_free: (a: number, b: number) => void;
  readonly falcon1024publickey_new: (a: number, b: number) => [number, number, number];
  readonly falcon1024publickey_verify: (a: number, b: number, c: number, d: number, e: number) => [number, number, number];
  readonly falcon1024publickey_toBytes: (a: number) => [number, number];
  readonly falcon512PublicKeySize: () => number;
  readonly falcon512PrivateKeySize: () => number;
  readonly falcon1024PublicKeySize: () => number;
  readonly falcon1024PrivateKeySize: () => number;
  readonly __wbindgen_externrefs: WebAssembly.Table;
  readonly __wbindgen_malloc: (a: number, b: number) => number;
  readonly __externref_table_dealloc: (a: number) => void;
  readonly __wbindgen_free: (a: number, b: number, c: number) => void;
  readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
* Instantiates the given `module`, which can either be bytes or
* a precompiled `WebAssembly.Module`.
*
* @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
*
* @returns {InitOutput}
*/
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
* If `module_or_path` is {RequestInfo} or {URL}, makes a request and
* for everything else, calls `WebAssembly.instantiate` directly.
*
* @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
*
* @returns {Promise<InitOutput>}
*/
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
