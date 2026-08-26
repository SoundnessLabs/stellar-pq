// Regenerates the two-step rotation fixtures:
//   test_pending_pubkey.hex : Falcon-512 pubkey of the "pending" keypair
//   test_accept_proof.hex   : signPadded(ACCEPT_DS || sha256(pending_pubkey))
// Seeds are fixed, so reruns are byte-identical. Signs with the vendored
// falcon-wasm (same signer as web-demo and e2e). That package's ESM
// falcon.js lacks "type": "module", so it gets copied to a .mjs name first.
//
// Run from this directory:  node gen_accept_fixtures.mjs
import { copyFileSync, readFileSync, writeFileSync } from 'fs'
import { dirname, join } from 'path'
import { fileURLToPath } from 'url'
import { createHash } from 'crypto'

const HERE = dirname(fileURLToPath(import.meta.url))
const VENDOR = join(HERE, '../../../../web-demo/vendor/falcon-wasm')

const shim = join(HERE, '.falcon-wasm-esm-shim.mjs')
copyFileSync(join(VENDOR, 'falcon.js'), shim)
const { default: init, Falcon512KeyPair } = await import(shim)
await init({ module_or_path: readFileSync(join(VENDOR, 'falcon_bg.wasm')) })

// Fixed 48-byte seeds (reproducible fixtures).
const keySeed = Uint8Array.from({ length: 48 }, (_, i) => i + 1)
const sigSeed = Uint8Array.from({ length: 48 }, (_, i) => 0xa0 ^ i)

const kp = new Falcon512KeyPair(keySeed)
const pk = kp.publicKeyBytes()

// Must match ACCEPT_DOMAIN_SEPARATOR in the contract's src/lib.rs.
const ACCEPT_DS = new TextEncoder().encode('soroban-falcon-smart-account-accept-v1')
const pkHash = createHash('sha256').update(pk).digest()
const msg = new Uint8Array(ACCEPT_DS.length + 32)
msg.set(ACCEPT_DS, 0)
msg.set(pkHash, ACCEPT_DS.length)

const proof = kp.signPadded(msg, sigSeed)

// falcon-wasm's verify() only accepts the natural compressed form, so
// sanity-check the key/message with that; the padded fixture itself is
// validated by the Rust verifier in tests/integration.rs.
if (!kp.verify(msg, kp.sign(msg, sigSeed))) throw new Error('self-verify failed')

console.log('pubkey len:', pk.length, 'header:', '0x' + pk[0].toString(16))
console.log('proof len:', proof.length, 'header:', '0x' + proof[0].toString(16))

const hex = (u8) => Buffer.from(u8).toString('hex')
writeFileSync(join(HERE, 'test_pending_pubkey.hex'), hex(pk) + '\n')
writeFileSync(join(HERE, 'test_accept_proof.hex'), hex(proof) + '\n')
console.log('fixtures written')
