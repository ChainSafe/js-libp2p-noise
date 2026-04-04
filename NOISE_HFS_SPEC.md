# Noise HFS Implementation Spec

**Protocol:** `Noise_XXhfs_25519+XWing_ChaChaPoly_SHA256`  
**libp2p protocol ID:** `/noise-pq/1.0.0`  
**Status:** Prototype / research implementation  
**Based on:** [Noise HFS spec](https://github.com/noiseprotocol/noise_hfs_spec), PQNoise (ePrint 2022/539), [draft-connolly-cfrg-xwing-kem](https://www.ietf.org/archive/id/draft-connolly-cfrg-xwing-kem-06.txt)

---

## 1. Overview

This document describes the `Noise_XXhfs_25519+XWing_ChaChaPoly_SHA256` handshake as implemented in `@chainsafe/libp2p-noise`. The handshake is a post-quantum hybrid of the classical Noise XX pattern that adds an ephemeral KEM step (the "HFS" tokens `e1` and `ekem1`) alongside the existing ECDH operations.

The result is a protocol where forward secrecy is secure if **either** X25519 **or** ML-KEM-768 is unbroken. Classical security is preserved; quantum-safe forward secrecy is added on top.

---

## 2. Algorithm Identifiers

| Role | Algorithm | Library |
|------|-----------|---------|
| KEM | X-Wing (ML-KEM-768 + X25519 combiner) | `@noble/post-quantum` v0.6.0 |
| DH | X25519 | `@noble/curves` (via pureJsCrypto) |
| AEAD | ChaCha20-Poly1305 | `@noble/ciphers` |
| Hash / HKDF | SHA-256 | Web Crypto / noble |

X-Wing is defined in [draft-connolly-cfrg-xwing-kem](https://www.ietf.org/archive/id/draft-connolly-cfrg-xwing-kem-06.txt). It combines ML-KEM-768 (FIPS 203) with X25519, using SHA3-256 as the combiner. The 32-byte combined shared secret is the output fed into `MixKey()`.

---

## 3. Handshake Pattern

The XXhfs pattern adds two tokens to the classical XX pattern:

```
Noise_XXhfs_25519+XWing_ChaChaPoly_SHA256:
  <- s
  ...
  -> e, e1
  <- e, ee, ekem1, s, es
  -> s, se
```

The `e1` token carries the initiator's KEM ephemeral public key. The `ekem1` token carries the responder's KEM encapsulation (ciphertext encrypted under the `ee`-derived key), and mixes the resulting KEM shared secret into the chaining key.

---

## 4. IKem Interface

The KEM is abstracted behind `IKem` in `src/kem.ts`:

```ts
interface IKem {
  PUBKEY_LEN: number   // X-Wing: 1216
  CT_LEN:     number   // X-Wing: 1120
  SS_LEN:     number   // X-Wing: 32
  SK_LEN:     number   // X-Wing: 32 (seed, not expanded key)

  generateKemKeyPair(): KemKeyPair
  encapsulate(remotePublicKey: Uint8Array): KemEncapsulateResult
  decapsulate(cipherText: Uint8Array, secretKey: Uint8Array): Uint8Array
}
```

The default implementation is `pqcKem` from `src/crypto/pqc.ts`, which uses `XWing` from `@noble/post-quantum/hybrid.js`. Any object conforming to `IKem` can be passed as `kemBackend` in `NoiseHFSInit`.

---

## 5. Wire Format

All sizes assume an empty libp2p handshake payload (no `NoiseHandshakePayload`).

### 5.1 Message A: initiator to responder

```
+-------------------+-----------------------+---------+
| e.publicKey       | e1.publicKey          | payload |
| 32 bytes          | 1216 bytes            | 0 bytes |
+-------------------+-----------------------+---------+
                    Total: 1248 bytes
```

- `e.publicKey`: X25519 ephemeral public key, sent in plaintext (no cipher key exists yet).
- `e1.publicKey`: X-Wing ephemeral public key (1184-byte ML-KEM-768 encapsulation key + 32-byte X25519 public key). Sent via `encryptAndHash()`, which is a plain `MixHash()` at this stage because there is no cipher key.

### 5.2 Message B: responder to initiator

```
+-------------------+-----------------------+--------------------+---------+
| e.publicKey       | enc(KEM ciphertext)   | enc(s.publicKey)   | payload |
| 32 bytes          | 1136 bytes            | 48 bytes           | 16 bytes|
+-------------------+-----------------------+--------------------+---------+
                    Total: 1232 bytes (16-byte payload AEAD tag)
```

- `e.publicKey`: Responder's X25519 ephemeral, plaintext.
- After `ee`: `MixKey(DH(e_R, e_I))` establishes the first cipher key.
- `enc(KEM ciphertext)`: Responder encapsulates to `e1.publicKey`, producing a 1120-byte X-Wing ciphertext. The ciphertext is AEAD-encrypted under the `ee`-derived key (adds 16-byte tag). Total: 1136 bytes.
- After `ekem1`: `MixKey(kemSharedSecret)` strengthens the chaining key.
- `enc(s.publicKey)`: Responder static public key (32 bytes + 16-byte AEAD tag = 48 bytes), encrypted under the KEM-strengthened key.
- After `es`: `MixKey(DH(e_I, s_R))` mixes classical auth.
- `payload`: `encryptAndHash(NoiseHandshakePayload)` -- 16-byte AEAD tag on empty payload.

### 5.3 Message C: initiator to responder

```
+--------------------+---------+
| enc(s.publicKey)   | payload |
| 48 bytes           | 16 bytes|
+--------------------+---------+
                    Total: 64 bytes (empty payload)
```

This message is identical to the classical Noise XX pattern. The initiator sends its static key (`se` completes the mutual authentication).

### 5.4 Compared to classical XX

| Message | Classical XX | XXhfs (PQ) | Delta |
|---------|------------:|----------:|------:|
| Msg A (initiator to responder) | 32 B | 1,248 B | +1,216 B |
| Msg B (responder to initiator) | 96 B | 1,232 B | +1,136 B |
| Msg C (initiator to responder) | 64 B | 64 B | 0 B |
| Total | 192 B | 2,544 B | +2,352 B |

Real libp2p handshakes include a `NoiseHandshakePayload` (signed identity key + extensions). With Ed25519 identity (~108 bytes per side), total is approximately 2,852 bytes for XXhfs vs approximately 500 bytes for classical XX.

---

## 6. Token Ordering

The ordering of `ekem1` operations is critical and must match exactly on both sides:

```
writeEkem1():
  1. encapsulate(re1)  -> { cipherText, sharedSecret }
  2. encryptAndHash(cipherText)       // encrypted under ee-derived key
  3. mixKey(sharedSecret)             // AFTER encrypt, strengthens subsequent tokens

readEkem1():
  1. decryptAndHash(raw)              // decrypt ciphertext (throws on AEAD failure)
  2. decapsulate(cipherText, e1.secretKey) -> sharedSecret
  3. mixKey(sharedSecret)             // must match write ordering
```

Swapping steps 2 and 3 would produce divergent chaining keys and is incorrect.

---

## 7. State Machine

```
Initiator                               Responder
---------                               ---------
generate e (X25519)
generate e1 (X-Wing)
writeMessageA(payload=empty)
  -> e, e1
                                        readMessageA()
                                          read e (32 bytes)
                                          read e1 (1216 bytes, store as re1)

                                        generate e (X25519)
                                        writeMessageB(payload)
                                          -> e
                                          ee = DH(e_R, e_I)  MixKey(ee)
                                          -> ekem1 = encapsulate(re1)
                                               encryptAndHash(cipherText)
                                               mixKey(sharedSecret)
                                          -> s (encrypted)
                                          es = DH(e_I, s_R)  MixKey(es)
                                          -> payload (signed identity)
readMessageB()
  read e (32 bytes)
  MixKey(DH(ee))
  readEkem1 (1136 bytes)
    decryptAndHash(cipherText)
    decapsulate(cipherText, e1.secretKey)
    mixKey(sharedSecret)
  readS (48 bytes)
  MixKey(DH(es))
  decode and verify payload

writeMessageC(payload)
  -> s (encrypted, 48 bytes)
  se = DH(s_I, e_R)  MixKey(se)
  -> payload (signed identity)
                                        readMessageC()
                                          readS (48 bytes)
                                          MixKey(DH(se))
                                          decode and verify payload

[cs1, cs2] = split()                    [cs1, cs2] = split()
encrypt = cs1                           encrypt = cs2
decrypt = cs2                           decrypt = cs1
```

Both sides must derive the same `cs1` and `cs2`. Any deviation (AEAD failure, KEM implicit rejection, tampered DH key) causes the handshake to abort with `InvalidCryptoExchangeError`.

---

## 8. Cipher State Split

After `split()`, two cipher states `cs1` and `cs2` are produced from the final chaining key via HKDF. They are directional:

| Direction | Initiator uses | Responder uses |
|-----------|---------------|---------------|
| Initiator to responder | `cs1.encryptWithAd(ZEROLEN, plaintext)` | `cs1.decryptWithAd(ZEROLEN, ciphertext)` |
| Responder to initiator | `cs2.decryptWithAd(ZEROLEN, ciphertext)` | `cs2.encryptWithAd(ZEROLEN, plaintext)` |

---

## 9. ML-KEM Implicit Rejection

ML-KEM-768 (FIPS 203 Section 6.4) uses implicit rejection: `Decaps()` never throws even when given a ciphertext encrypted for a different key. Instead it returns a pseudorandom shared secret derived from a secret implicit rejection value. This means:

- A tampered or wrong-key ciphertext produces a divergent shared secret rather than an error.
- The divergence causes all subsequent AEAD operations (`s`, `es`, payload) to fail authentication.
- This is correct and intentional behavior. The handshake still aborts on AEAD failure.

The AEAD protection on the ciphertext (`encryptAndHash` before `mixKey`) means that a tampering attack is caught by the AEAD tag before decapsulation is even attempted.

---

## 10. Security Properties

| Property | Source |
|----------|--------|
| Forward secrecy (classical) | DH(ee): ephemeral X25519 on both sides |
| Forward secrecy (quantum-safe) | X-Wing KEM: ML-KEM-768 + X25519 |
| Mutual authentication | DH(es) + DH(se) via signed static keys |
| Identity hiding | Static keys encrypted after ephemeral exchange |
| Hybrid robustness | Secure if either X25519 or ML-KEM-768 is unbroken |
| Payload confidentiality | ChaCha20-Poly1305 AEAD under the final chaining key |

The protocol does NOT provide quantum-safe authentication. The identity layer uses Ed25519 signatures (classical). For full post-quantum authentication, ML-DSA (FIPS 204) identity keys are needed. PR #3432 in js-libp2p tracks that work. When it lands, this implementation will support ML-DSA identity automatically because `privateKey.sign()` is key-type aware and no changes are needed in this layer.

---

## 11. Test Vectors

Deterministic test vectors are in `test/fixtures/pqc-test-vectors.json`. They were generated by `scripts/generate-pqc-vectors.js` using seeded keys. The JSON schema is:

```json
{
  "protocol": "Noise_XXhfs_25519+XWing_ChaChaPoly_SHA256",
  "vectors": [
    {
      "vector_index": 1,
      "static_i_public": "<hex>",
      "static_i_private": "<hex>",
      "static_r_public": "<hex>",
      "static_r_private": "<hex>",
      "ephemeral_dh_i_public": "<hex>",
      "ephemeral_dh_i_private": "<hex>",
      "ephemeral_dh_r_public": "<hex>",
      "ephemeral_dh_r_private": "<hex>",
      "ephemeral_kem_i_public": "<hex>",
      "ephemeral_kem_i_secret": "<hex>",
      "encap_seed_hex": "<hex 64-byte seed>",
      "msg_a": "<hex>",
      "msg_b": "<hex>",
      "msg_c": "<hex>",
      "msg_a_bytes": 1248,
      "msg_b_bytes": 1232,
      "msg_c_bytes": 64,
      "handshake_hash": "<hex>",
      "cs1_k": "<hex 32-byte key>",
      "cs2_k": "<hex 32-byte key>"
    }
  ]
}
```

To regenerate vectors after a code change:

```bash
pnpm build
node scripts/generate-pqc-vectors.js
```

To verify vectors against the current implementation:

```bash
pnpm test:node -- --grep "Noise_XXhfs test vectors"
```

---

## 12. Usage

```ts
import { createLibp2p } from 'libp2p'
import { noiseHFS } from '@chainsafe/libp2p-noise'

const node = await createLibp2p({
  connectionEncrypters: [noiseHFS()],
  // ... other options
})
```

For testing or custom KEM backends:

```ts
import { noiseHFS } from '@chainsafe/libp2p-noise'
import type { IKem } from '@chainsafe/libp2p-noise'

const myKem: IKem = {
  PUBKEY_LEN: 1216,
  CT_LEN: 1120,
  SS_LEN: 32,
  SK_LEN: 32,
  generateKemKeyPair: () => { /* ... */ },
  encapsulate: (pubkey) => { /* ... */ },
  decapsulate: (ct, sk) => { /* ... */ }
}

const node = await createLibp2p({
  connectionEncrypters: [noiseHFS({ kemBackend: myKem })],
})
```

---

## 13. Interoperability

A compatible implementation in another language must:

1. Use the same protocol name exactly: `Noise_XXhfs_25519+XWing_ChaChaPoly_SHA256`
2. Use X-Wing (ML-KEM-768 + X25519 with SHA3-256 combiner) as the KEM
3. Apply `encryptAndHash(cipherText)` BEFORE `mixKey(sharedSecret)` in the ekem1 token
4. Read e1 as 1216 bytes in Message A (no AEAD tag at that stage)
5. Read ekem1 as 1120 + 16 = 1136 bytes in Message B (ciphertext + AEAD tag)
6. Use the test vectors in `test/fixtures/pqc-test-vectors.json` to verify correctness

---

## 14. Performance Reference

Measured on Node.js v22.17.1, Windows 11 x64 (pure JS, no WASM or native bindings):

| Operation | ops/s | ms/op |
|-----------|------:|------:|
| X-Wing keygen | 293 | 3.42 |
| X-Wing encapsulate | 120 | 8.32 |
| X-Wing decapsulate | 136 | 7.33 |
| KEM round-trip | 47 | 21.43 |
| Classical XX handshake | 114 | 8.75 |
| XXhfs handshake | 23 | 44.18 |

The approximately 5x latency increase over classical XX is dominated by the X-Wing KEM (around 21 ms per round-trip). Native WASM or Node.js native ML-KEM support would improve throughput by roughly 3 to 10x.

See `benchmarks/results.md` for the full analysis.

---

## 15. Files

| File | Purpose |
|------|---------|
| `src/kem.ts` | `IKem` interface, `KemKeyPair`, `KemEncapsulateResult` types |
| `src/crypto/pqc.ts` | Default KEM backend (`pqcKem`) using `@noble/post-quantum` |
| `src/crypto/pqc.node.ts` | Node.js backend slot (currently falls back to noble; native TODO) |
| `src/protocol-pqc.ts` | `XXhfsHandshakeState` state machine, `NOISE_HFS_PROTOCOL_NAME` |
| `src/performHandshake-hfs.ts` | Initiator and responder orchestration |
| `src/noise-hfs.ts` | `NoiseHFS` connection encrypter, `noiseHFS()` factory |
| `test/pqc-kem.spec.ts` | IKem unit tests (17 tests) |
| `test/pqc-protocol.spec.ts` | XXhfsHandshakeState unit tests (18 tests) |
| `test/pqc-noise.spec.ts` | Integration tests against libp2p (12 tests) |
| `test/pqc-vectors.spec.ts` | Test vector verification (52 tests) |
| `test/fixtures/pqc-test-vectors.json` | Committed deterministic test vectors (5 vectors) |
| `scripts/generate-pqc-vectors.js` | Vector generator (run after build) |
| `benchmarks/benchmark-pqc.js` | Benchmark runner |
| `benchmarks/results.md` | Benchmark results and analysis |
