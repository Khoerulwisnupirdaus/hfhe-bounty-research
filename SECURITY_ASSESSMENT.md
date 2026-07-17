# HFHE V2 Challenge — Complete Security Assessment

> **Status**: UNSOLVED — All known attack vectors exhausted  
> **Target**: Recover plaintext (wallet private key) from `secret.ct`  
> **Wallet**: `octC5eR9pLGKbpzTbDgHowkFt8HW7LZYb2gzehzxHamxuAZ`  
> **Reward**: 500K OCT (+ 500K from dev = 1M total)  
> **Repo**: https://github.com/octra-labs/pvac_hfhe_cpp  
> **Commit**: `071b0e909c119de815e284b347c4bd979cb59ef3`

---

## Table of Contents
1. [System Architecture](#1-system-architecture)
2. [Encryption Flow](#2-encryption-flow)
3. [Decryption Flow](#3-decryption-flow)
4. [PRF_R Pipeline (LPN-Based)](#4-prf_r-pipeline)
5. [Challenge Data Structure](#5-challenge-data-structure)
6. [Complete Code Audit](#6-complete-code-audit)
7. [Attack Attempts](#7-attack-attempts)
8. [Tools Built](#8-tools-built)
9. [Conclusion](#9-conclusion)

---

## 1. System Architecture

HFHE (Hypergraph-based Fully Homomorphic Encryption) over Fp where P = 2^127 - 1 (Mersenne prime).

### Key Generation (`keygen.hpp`)
```
keygen() → (pk, sk)
├── sk.prf_k[4]       = 4 × 64-bit random from /dev/urandom (AES/PRF master key)
├── sk.lpn_s_bits[]   = 4096-bit random vector (LPN secret)
├── pk.H[]            = 16384 columns × 8192 rows (public binary matrix, full GF2 rank)
├── pk.powg_B[]       = [1, g, g², ..., g^{B-1}] where g = primitive B-th root of unity
├── pk.omega_B        = primitive B-th root of unity in Fp
├── pk.canon_tag      = random 64-bit tag
├── pk.ubk            = deterministic permutation derived from canon_tag
└── pk.H_digest       = SHA256(H matrix)
```

Parameters (from `params.json`):
| Parameter | Value |
|-----------|-------|
| B (basis) | 337 |
| m_bits (H rows) | 8192 |
| n_bits (H columns) | 16384 |
| h_col_wt | 192 |
| x_col_wt | 128 |
| err_wt | 128 |
| noise_entropy_bits | 128 |
| lpn_n | 4096 |
| lpn_t (samples) | 16384 |
| lpn_tau (noise rate) | 1/8 |

---

## 2. Encryption Flow

### enc_text (text.hpp)
```
enc_text(pk, sk, "plaintext ~315 bytes"):
├── CT[0]  = enc_value(pk, sk, msg.size())             ← length as uint64, depth=0
├── CT[1]  = enc_fp_wrapped_depth(block_0, depth=2)    ← 15 bytes packed to Fp
├── CT[2]  = enc_fp_wrapped_depth(block_1, depth=3)
├── ...
└── CT[21] = enc_fp_wrapped_depth(block_20, depth=22)
```

### V2 Wrapping (anti zero-detection fix)
```
enc_fp_wrapped_depth(v, d):
  m = rand_fp_nonzero()           ← random 127-bit mask
  CT_a = enc_fp_depth(v + m, d)   ← one layer encrypting v+m
  CT_b = enc_fp_depth(-m, d)      ← one layer encrypting -m
  return fuse(CT_a, CT_b)         ← combine into 2-layer cipher
```
This wrapping was added in V2 (commit cdc6a52) to prevent the V1 zero-detection oracle that broke bounty 1.

### Core Encryption: synth() (encrypt.hpp)
```
synth(pk, sk, v, depth):
  1. Generate random nonce (128-bit from /dev/urandom)
  2. Compute ztag = SHA256("pvac.dom.ztag" || canon_tag || nonce)
  3. Compute R = prf_R(pk, sk, seed)                ← SECRET Fp scalar
  4. Generate delta noise values via prf_R_noise()
  5. Compute va = v - sum(deltas)                    ← adjusted value
  6. Create 8 signal edges (SigEdge):
     - 7 with random coefs, unique indices from Selector
     - 1 determined: coef = (va - sum_of_7) / g^idx
     - All weights: w = coef * R
  7. Create N2 noise edges (2 per delta):
     - ra = random, rb = (ra*g^a - delta) / g^b
     - w_a = ra * R, w_b = rb * R
  8. Create N3 noise edges (3 per delta, similar)
  9. Merge edges with same (idx, ch): w_merged = sum(w_i), sigma XOR-ed
  10. Random permutation of edge order
  11. Compute PC = pedersen_commit(R_inv, rho)        ← Pedersen commitment
```

Key equation: `T = sum(±w * g^idx) = R * v` for each layer.

---

## 3. Decryption Flow

```
dec_values(pk, sk, CT):
  for each layer lid:
    R[lid] = prf_R(pk, sk, layer.seed)    ← recompute R from seed+sk
  
  acc = c0  (= 0 for BASE layers)
  for each edge e:
    acc += sgn(e.ch) * e.w * g^e.idx * R_inv[e.layer_id]
  
  return acc    ← = plaintext value
```

For wrapped ciphers: `dec(CT) = T0/R0 + T1/R1 = (v+m) + (-m) = v`

---

## 4. PRF_R Pipeline

```
prf_R(pk, sk, seed) = prf_R_core(seed, "pvac.prf.r.1")
                    * prf_R_core(seed, "pvac.prf.r.2")
                    * prf_R_core(seed, "pvac.prf.r.3")

prf_R_core(pk, sk, seed, domain):
  1. AES key = SHA256(prf_k || canon_tag || H_digest || domain || seed)
  2. Initialize AES-CTR PRG with key
  3. For each of 16384 LPN samples:
     a. row = PRG.fill_u64(64 words)         ← 4096-bit row from AES-CTR
     b. dot = popcount(row AND s) mod 2      ← inner product with LPN secret
     c. noise = PRG.bounded(8) < 1           ← noise bit (tau=1/8), SAME stream!
     d. y_bit = dot XOR noise
  4. toep_key = SHA256(prf_k || ... || "pvac.dom.toeplitz")
  5. output = toeplitz_127(AES-CTR(toep_key), y_bits)  ← compress 16384 → 127 bits
  6. R = hash_to_fp_nonzero(output)
```

**Critical observation**: LPN rows and noise bits come from the SAME AES-CTR stream. They are NOT independent. However, AES-CTR is a secure PRG, so this doesn't help without knowing the key.

---

## 5. Challenge Data Structure

### secret.ct (parsed)
- **22 ciphertexts**, each with 2 BASE layers (wrapped), 1 slot
- **CT[0]**: 43 edges (L0=22, L1=21) — encrypts message length
- **CT[1]-CT[21]**: 48-119 edges — encrypts 15-byte plaintext blocks
- **c0 = zeros** for all CTs (unused in BASE layers)
- **R_com = zeros** for all layers (R not hashed — V2 fix)
- **PC values: non-zero** for all 44 layers — 32-byte Ristretto points
- **Edge counts grow linearly** with depth (~2 extra noise edges per depth level)

### pk.bin (parsed)
- B=337, m=8192, n=16384
- H matrix: 16384 columns × 8192 rows, column weight 192-193
- powg_B: 337 precomputed g^i values
- omega_B: B-th root of unity
- ubk: deterministic permutation
- H_digest: SHA256 of H matrix
- **No secret data in pk.bin**

### Structural Properties Verified
| Check | Result |
|-------|--------|
| All 44 nonces unique | ✅ |
| All 44 ztags match prg_layer_ztag | ✅ |
| All 44 PC values unique | ✅ |
| H matrix GF2 rank | 8192/8192 (FULL) |
| H column parity | Mixed (8190 even, 8194 odd) |
| g^B = 1 | ✅ |
| No edges with w=0 | ✅ |
| Edge sigma popcount | ~4096 (m/2), normal random |
| T values (public sums) | All 127-bit random |
| T0/T1 ratios per CT | All random (R0 ≠ R1) |
| Cross-CT T0 ratios | All random (no shared R) |

---

## 6. Complete Code Audit

### Files Audited

#### field.hpp — Fp Arithmetic
- `fp_add`: 128-bit add with mod P reduction ✅
- `fp_neg`: P - x, correct for all inputs ✅
- `fp_sub`: add + neg ✅
- `fp_mul`: 128×128 → 256 with Barrett-like reduction via `fp_reduce256` ✅
- `fp_inv_ct`: Fermat's little theorem a^{P-2} with 5-bit windowed exponentiation ✅
- `fp_from_words`: normalizes 127+ bit values mod P, handles carry ✅
- **Tested**: x*x_inv=1, x+(-x)=0, 0*x=0, P mod P=0 — all correct

#### ristretto255.hpp — Curve Points
- `rist_G()`: standard Ristretto basepoint ✅
- `rist_H()`: hash-to-curve using domain separator, **NOT identity, NOT equal to G** ✅
- `pedersen_commit(v, r)`: v*G + r*H — hiding AND binding verified ✅
- `sc_from_fp_signed`: maps Fp → Scalar with sign bit at position 62 of hi ✅
- **Dead code in rist_H**: variables reassigned but final result correct

#### keygen.hpp — Key Generation
- `keygen()`: uses `csprng_u64()` → /dev/urandom for ALL secret material ✅
- `keygen_from_seed()`: deterministic from wallet private key — **NOT used for bounty** (verified: generate() calls keygen() not keygen_from_seed())
- B=337 correctly divides P-1 ✅

#### matrix.hpp — H Matrix & Sigma
- `gen_H()`: deterministic from (m, n, h_col_wt, column_index, canon_tag) — ALL public ✅
- `sigma_from_H()`: XOR of selected H columns + noise, uses public salt per edge ✅
- H matrix verified: full GF2 rank, no kernel exploit possible

#### lpn.hpp — LPN-Based PRF
- `prf_R_core()`: LPN computation + Toeplitz hash, produces single Fp value ✅
- `hash_to_fp_nonzero()`: maps (lo, hi) to Fp*, returns 1 if input is zero ✅
- `AesCtr256`: standard AES-256-CTR PRG ✅
- LPN row generation: deterministic from AES key derived from sk
- **Noise coupling**: row and noise from same AES-CTR stream (no practical exploit known)

#### encrypt.hpp — Encryption Logic
- `SigEdge::build()`: 8 signal edges, 7 random + 1 determined, unique indices via Selector ✅
- `N2Edge::build()`: index `a` random (NOT from Selector), `b` from Selector.avoid(a) ✅
- `N3Edge::build()`: similar to N2 with 3 edges ✅
- `delta::Gen::scalar()`: tweaks seed with golden ratio constants ✅
- `merge()`: merges edges by (layer_id, idx, ch), keeps w=0 if sigma!=0 ✅
- `permute()`: Fisher-Yates shuffle with CSPRNG ✅
- `compute_R_com_base()`: **R values NOT hashed** (V2 fix confirmed) ✅
- `compute_layer_PC()`: PC = pedersen_commit(R_inv, rho), rho from SHA256(PRF_RHO||prf_k||nonce||slot) ✅
- `enc_fp_wrapped_depth()`: v+m and -m with random mask m ✅

#### decrypt.hpp — Decryption Logic
- `dec_values()`: acc = c0 + sum(±w * g^idx * R_inv) — correctly matches encrypt ✅
- `ru_src()`: checks if layer is "native" via ru_ztag — ALL challenge layers are NOT native ✅
- Native layers rejected by default (DecPolicy::STANDARD) ✅

#### text.hpp — Text Encoding
- `pack_15_bytes_to_fp()`: 15 bytes → Fp (120 bits, MSB 7 bits zero) ✅
- `unpack_fp_to_15_bytes()`: reverse ✅
- `enc_text()`: CT[0]=length, CT[1..N]=15-byte blocks with increasing depth ✅

#### hash.hpp — Commitments
- `compute_R_com_base()`: SHA256("pvac.dom.r_com" || canon_tag || ztag || nonce || slot_count) — **R NOT included** ✅

#### recrypt_src_core.hpp — Native Recrypt
- `ru_ztag()`: SHA256("pvac.native.ru.ztag" || ...) — different domain from prg_layer_ztag ✅
- `ru_affine()`: SHA256("pvac.native.ru.secret" || ... || prf_k) — simpler than LPN-based prf_R ✅
- **Not relevant to challenge** — no layers match ru_ztag format

#### pvac_artifact_serialize.hpp — Serialization
- `serialize_pubkey()`: writes params, canon_tag, H[], ubk, H_digest, omega_B, powg_B — NO sk data ✅
- `serialize_seckey()`: writes prf_k, lpn_s_bits — separate file ✅
- `serialize_cipher()`: writes slots, layers(rule+seed+PC), c0, edges(lid,idx,ch,w,sigma) — NO R values ✅

#### hfhe_bounty_artifact.cpp — Bounty Program
- `generate()`: keygen() + enc_text() + write files — clean, no leaks ✅
- `verify()`: reads sk.bin + plaintext.txt, decrypts, compares — private-side only ✅
- `public_audit()`: public checks only (wrapped, nonzero, H parity, sigma parity, H rank) — no oracle ✅

---

## 7. Attack Attempts

### 7.1 Cryptographic Attacks

| # | Attack | Description | Result |
|---|--------|-------------|--------|
| 1 | LPN brute force | Solve LPN(4096, 1/8) directly | ❌ 2^341 complexity, infeasible |
| 2 | H matrix rank deficiency | Find kernel vectors of H | ❌ Full rank 8192/8192 |
| 3 | Signal/noise edge distinction | Identify signal edges by weight magnitude | ❌ K=8, all coefs random, indistinguishable |
| 4 | PC value extraction | Extract R_inv from Pedersen commitment | ❌ Needs rho (from prf_k, 256-bit) |
| 5 | PC with rho=0 | Assume rho derivation broken | ❌ No match for small R_inv values |
| 6 | T value analysis | T=R*v from public edges | ❌ Random-looking, no structure |
| 7 | T0+T1 analysis | If R0=R1, sum reveals R*v | ❌ R0≠R1, all sums random |
| 8 | Cross-CT correlation | Check if different CTs share R | ❌ All cross-CT ratios random |
| 9 | Multiple-instance LPN | 132 LPN evaluations share same s | ❌ Different AES keys = independent samples |
| 10 | Toeplitz hash invertibility | Recover y-bits from R | ❌ Toeplitz key unknown (from prf_k) |
| 11 | LPN row/noise coupling | Row and noise from same PRG | ❌ No known practical attack |
| 12 | BKW algorithm | Sub-exponential LPN solver | ❌ Still ~2^200+ for n=4096, tau=1/8 |
| 13 | Lattice reduction (LLL/BKZ) | Embed LPN in lattice | ❌ Dimension too large |

### 7.2 Implementation Bug Searches

| # | Bug Type | What We Checked | Result |
|---|----------|-----------------|--------|
| 1 | Field arithmetic errors | fp_add, fp_neg, fp_mul, fp_inv edge cases | ✅ Correct |
| 2 | rist_H = identity | Would make PC non-hiding | ✅ H is valid, independent |
| 3 | rist_H = G | Would make PC non-hiding | ✅ H ≠ G |
| 4 | R_com leaks R | V1 bug: R hashed into R_com | ✅ Fixed in V2 (R not hashed) |
| 5 | Serialization sk leak | sk data in pk.bin or secret.ct | ✅ Clean |
| 6 | Keygen weakness | Weak PRNG or predictable seed | ✅ /dev/urandom, keygen() not from_seed() |
| 7 | Decrypt logic bug | Mismatch between encrypt/decrypt | ✅ Correct match |
| 8 | Nonce reuse | Same nonce for multiple layers | ✅ All 44 unique |
| 9 | Ztag mismatch | Computed vs stored ztag | ✅ All 44 match |
| 10 | Native layer confusion | ru_ztag collision with prg_layer_ztag | ✅ No collision |
| 11 | Integer overflow | In field ops or edge indexing | ✅ No overflow |
| 12 | Wrong variable | Using wrong R, wrong seed, etc. | ✅ All traced correctly |
| 13 | Missing negation | Sign errors in encrypt/decrypt | ✅ Signs correct |
| 14 | Off-by-one | In loops, indices, or reductions | ✅ All correct |
| 15 | Cancelled edges | w=0 after merge leaking info | ✅ No w=0 edges in challenge |

### 7.3 Alternative Decrypt Methods

| # | Method | Description | Result |
|---|--------|-------------|--------|
| 1 | R=1 | Assume PRF always returns 1 | ❌ Random output |
| 2 | R=omega_B | Try root of unity as R | ❌ Random output |
| 3 | R=small | Try R_inv=1..100 with rho=0 | ❌ No PC match |
| 4 | Native path | Check if layers use ru_ztag | ❌ All use prg_layer_ztag |
| 5 | s=0 LPN | Assume all-zero LPN secret | ❌ Not practical to test |

### 7.4 GitHub Issues Investigated

| Issue | Title | Relevance |
|-------|-------|-----------|
| PR #499 | hidden_coeff_stmt_digest leaks alpha | Only affects native-reset, NOT BASE layers in challenge |
| #501 | Addition overflow + R² leak in bounty2 | Our own issue, bounty2 specific |
| #503 | Non-canonical Ristretto encodings | Theoretical, no practical exploit found |

---

## 8. Tools Built

All tools in `~/pvac_work/pvac_hfhe_cpp/`:

| Tool | Purpose |
|------|---------|
| `v2_dump` | Parse secret.ct V3 format, dump full structure |
| `v2_attack` | H rank, edge analysis, sigma parity |
| `v2_weight` | Weight magnitude and GCD analysis |
| `verify_sig2` | Signal/noise verification using bounty2 sk |
| `check_H` | Verify rist_H() correctness |
| `check_fp` | Field arithmetic edge case testing |
| `gen_test` | Generate test bounty with known plaintext |
| `full_audit` | Comprehensive public data analysis |
| `alt_decrypt` | Try all alternative decrypt methods |
| `verify_lpn` | LPN sample binding verifier (from repo) |

Python scripts in scratch/:
| Script | Purpose |
|--------|---------|
| `analyze_bounty2.py` | Bounty2 structure analysis |
| `analyze_lpn_structure.py` | LPN sample structure analysis |
| `catalog_lpn.py` | LPN parameter catalog |
| `bkw_analysis.py` | BKW complexity estimation |
| `check_c0.py` | c0 field analysis |

---

## 9. Conclusion

### Why V2 is Hard

1. **LPN hardness**: n=4096, tau=1/8 gives ~341 bits of security. No known algorithm can solve this in reasonable time.

2. **V2 wrapping**: enc(v+m) + enc(-m) eliminates the V1 zero-detection oracle. Random mask m is 127-bit, making the individual layer ciphertexts information-theoretically independent of the plaintext.

3. **Triple-product PRF**: R = R1 * R2 * R3, each from independent LPN evaluation. Even if one core is weakened, the product remains strong.

4. **Pedersen commitment hiding**: PC = R_inv*G + rho*H where rho depends on prf_k (256-bit secret). Cannot extract R_inv without solving DLOG or knowing rho.

5. **Clean implementation**: Despite some messy code (dead variables in rist_H), the actual security-critical logic is correct. No off-by-one, no wrong variable, no missing negation.

### What Might Still Work (Speculative)

1. **Quantum LPN attack**: Grover's algorithm could reduce LPN to ~2^170. Still infeasible with current hardware.

2. **Algebraic attacks on Toeplitz hash**: If the Toeplitz matrix structure can be exploited in combination with known LPN rows, might reduce the problem.

3. **Side-channel on bounty generation**: If the machine that generated the bounty had a weak PRNG state, nonces could be predictable.

4. **Blockchain/wallet attack**: The wallet address is known (`octC5eR9pLGKbpzTbDgHowkFt8HW7LZYb2gzehzxHamxuAZ`). If the Octra network has vulnerabilities separate from HFHE, the wallet could be accessed directly.

5. **Future mathematical breakthrough**: A new algorithm for LPN with structured matrices or correlated noise.

### Dev's "Fundamentally Broken" Claim

The developer stated HFHE is "fundamentally broken" but "didn't connect to HFHE." This likely means:
- The THEORETICAL security model has flaws (e.g., LPN with structured matrices might be easier than random LPN)
- But the SPECIFIC implementation adds enough practical security that no one has connected the theoretical weakness to a practical attack
- Or the break requires capabilities (compute, mathematical insight) that haven't been applied yet

### Final Status: **UNSOLVED**

After exhaustive code audit, structural analysis, and multiple attack attempts, we were unable to recover the plaintext from `secret.ct`. The V2 implementation appears cryptographically sound against all known attack vectors accessible to us.

---

*Research conducted July 10-18, 2026*
*Assessment by: @Khoerulwisnupirdaus + AI assistant*
