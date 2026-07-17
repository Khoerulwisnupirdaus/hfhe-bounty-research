# HFHE Challenge V2 — Complete Research Knowledge Base
# Last updated: July 17, 2026
# Purpose: Persistent memory for AI agents continuing this research.
# Read this FIRST before doing ANY work on the HFHE bounty.
# Then read Section 12 (CRITICAL DEDUCTION) and Section 19 (LATEST) before starting work.

---

## 1. CHALLENGE OVERVIEW

- **Bounty**: Recover plaintext from `secret.ct` using only public files (`pk.bin`, `secret.ct`, `params.json`)
- **Repo**: https://github.com/octra-labs/pvac_hfhe_cpp @ commit `071b0e9`
- **Dev**: lambda0xe (OCTRA Labs)
- **Status**: ⚠️ Challenge V2 is STILL ACTIVE! Only V1 was cancelled (R_com oracle issue).
- **Reward**: 500K OCT (wallet claim) + 500K OCT (contact dev@octra.org) = **1,000,000 OCT total** (or USDC equivalent)
- **Wallet**: `octC5eR9pLGKbpzTbDgHowkFt8HW7LZYb2gzehzxHamxuAZ`
- **Dev hint**: Lambda said system was "fundamentally broken". V1 was cancelled because "didn't connect to HFHE". Therefore V2 break MUST be through HFHE mechanism (see Section 12 CRITICAL DEDUCTION).

### ADDITIONAL BOUNTIES IN THE SAME REPO (pvac_hfhe_cpp):
| Bounty | Path | Task | Reward | Has sk.bin? |
|--------|------|------|--------|-------------|
| **bounty_data** (=hfhe-challenge) | `bounty_data/` | Recover wallet from secret.ct | 1M OCT | NO |
| **bounty2_data** | `bounty2_data/` | Homomorphic addition → find info leak | Issue label | **YES (560 bytes)** |
| **bounty3_data** | `bounty3_data/` | Break seed.ct → mnemonic+number | 60K OCT + $15K USD | NO (code saves it but not committed) |

### bounty2_data — TRAINING GROUND (has secret key!):
- Files: `a.ct`, `b.ct`, `sum.ct`, `pk.bin`, `sk.bin`, `params.json`
- `sk.bin` format: magic(u32) + ver(u32) + prf_k[0..3](4×u64) + lpn_count(u64) + lpn_s_bits[](n×u64)
- Known sk: `prf_k = [0x0e7cedbf86286e2e, 0xf8adb2a16b2d1e28, 0xdad108b1c99cc831, 0x1d69d98715ec5c29]`
- LPN: 4096 bits, HW=2051 (~50%)
- Same params as main challenge: B=337, lpn_n=4096, lpn_t=16384
- **USE THIS to study how R values, T values, and decryption work with known keys**

### bounty3_data:
- Files: `seed.ct`, `pk.bin`, `params.json` (NO sk.bin in git)
- Wallet: `oct7rAAiRhdRvKChDQrTJEAUqM9M9sfTBGQsacqME18xe1V` (60K OCT)
- Also $15K USD on Ethereum: `0xa0b038b20b4633ffF5cDE2bDEfB63d6E1FD8C2e2`
- Hint in README: "try to extract the parameter R from the equation"
- Same params as main challenge
- **Our repo**: https://github.com/Khoerulwisnupirdaus/hfhe-bounty-research
- **Competitor**: https://github.com/smoke-ui/octra-hfhe-v2-security-assessment (also FAILED to break V2)

---

## 2. CRYPTOGRAPHIC PARAMETERS (VERIFIED)

| Parameter | Value | Notes |
|-----------|-------|-------|
| Field P | 2^127 - 1 (Mersenne prime) | GF(P), 127-bit |
| Generator order B | 337 (prime) | powg_B has 337 entries |
| m_bits | 8192 | Sigma bitvector length, H matrix rows |
| n_bits | 16384 | H matrix columns |
| h_col_wt | 192 | Weight of each H column |
| x_col_wt | 128 | Weight of x in sigma_from_H |
| err_wt | 128 | Noise bits in sigma_from_H |
| lpn_n | 4096 | LPN SECRET dimension (NOT 16384!) |
| lpn_t | 16384 | LPN samples per R derivation |
| lpn_tau | 1/8 | LPN noise rate |
| noise_entropy_bits | 128.0 | Bounty uses 128, default is 120 |
| tuple2_fraction | 0.55 | N2 vs N3 noise ratio |
| depth_slope_bits | 16.0 | Noise increase per depth level |
| edge_budget | 1,200,000 | Max edges before compaction |
| canon_tag | 0x0760802093a19931 | Public key identifier |

---

## 3. SECRET KEY STRUCTURE

- `sk.prf_k`: 4 × u64 = 256 bits (random PRF key)
- `sk.lpn_s_bits`: 4096 bits (FULLY RANDOM, NOT sparse, expected HW ~2048)
- Total secret: 256 + 4096 = 4352 bits
- Even if lpn_s_bits is recovered, prf_k (256 bits) is STILL needed for derive_aes_key

---

## 4. CIPHERTEXT STRUCTURE (FULLY PARSED & VERIFIED)

- Wire format: `OCTRA-HFHE-BTY02` + 22 length-prefixed PVAC v3 ciphers
- All 22 blocks deserialized with remaining=0 (perfect parse)
- CT[0]: encrypts message LENGTH L as uint64 (depth=0)
- CT[1..21]: encrypts 15-byte text chunks as Fp (depth=2..22)
- Message length: L ∈ [301, 315] (21 chunks × 15 bytes)
- Each CT has 2 BASE layers (V2 wrapping), NO PROD layers
- All c0 = [0], slots = 1

### Edge counts per CT:
```
CT[0]:  43 edges (L0:22, L1:21)
CT[1]:  47 edges (L0:24, L1:23)  
CT[2]:  54 edges
...
CT[21]: 119 edges (L0:61, L1:58)
```
Edge count increases with depth (noise scales linearly).

---

## 5. ENCRYPTION FLOW (FULLY UNDERSTOOD)

### enc_text(pk, sk, msg):
1. CT[0] = enc_value(pk, sk, msg.size()) → encrypts length
2. For each 15-byte chunk: CT[i] = enc_fp_wrapped_depth(pk, sk, chunk_as_Fp, depth)

### enc_fp_wrapped_depth (V2 wrapping):
1. Generate random mask m (Fp, nonzero)
2. Layer 0: enc_fp_depth(pk, sk, v+m, depth) → synth()
3. Layer 1: enc_fp_depth(pk, sk, -m, depth) → synth()
4. combine_ciphers(layer0, layer1) → fuse() (just concatenates)

### core::synth (single-layer encryption):
1. Generate nonce, compute ztag = prg_layer_ztag(canon_tag, nonce)
2. Compute R = prf_R(pk, sk, seed) — requires LPN secret!
3. Compute delta noise budget: n2 noise pairs + n3 noise triples
4. va = v - delta_aggregate (subtract noise aggregate from value)
5. Build 8 signal edges: sum = R * va (7 random coefs + 1 deterministic)
6. Build N2/N3 noise edges (cancel in T sum but obscure sigma)
7. Merge edges (same layer/idx/sign → weights add, sigmas XOR)
8. Permute via UBK

### Decryption:
```
v = c0 + Σ(±w_i * g^idx_i * R_inv[layer_i]) for all edges
```
**CRITICAL: sigma (e.s) is NEVER used in decryption!**
Sigma is ONLY for commitment verification.

---

## 6. R DERIVATION (prf_R) — THE SECURITY CORE

```
prf_R(pk, sk, seed) = prf_R_core(dom1) * prf_R_core(dom2) * prf_R_core(dom3)
```

### prf_R_core:
1. derive_aes_key(pk, sk, seed, dom) → AES-256 key + nonce
   - Key = SHA256(sk.prf_k || pk.canon_tag || pk.H_digest || seed || dom)
   - Requires sk.prf_k!
2. lpn_make_ybits: Generate t=16384 LPN samples:
   - For each row: random_row (AES-CTR), dot = <row, sk.lpn_s_bits>, noise with tau=1/8
   - y[r] = dot XOR noise_bit
3. Toeplitz hashing: compress 16384 y-bits → 127-bit Fp value

### Security:
- AES key requires sk.prf_k (256-bit) → can't regenerate LPN matrix without it
- LPN: n=4096, t=16384, tau=1/8, dense secret → BKW ~2^341

---

## 7. sigma_from_H (PUBLIC, but irrelevant to decryption)

```
sigma_from_H(pk, ztag, nonce, idx, ch, salt):
  1. Choose x_col_wt=128 random H columns (via PRG from public data + salt)
  2. XOR those H columns → H*x where |x|=128  
  3. Add err_wt=128 random noise bits
  Result: sigma = H*x + e
```
- salt = csprng_u64() during encryption (random, NOT stored)
- sigma IS stored in edge.s but NEVER used in decryption
- sigma is ONLY for Pedersen commitment verification

---

## 8. PEDERSEN COMMITMENTS

```
PC[j] = sc_from_fp_signed(1/R[j]) * G + rho_j * H
```
- G = Ristretto255 base point, H = hash-derived generator
- rho_j = SHA256(PRF_RHO || sk.prf_k || nonce || j) → requires sk
- sc_from_fp_signed: maps Fp → Scalar (injective, preserves sign)
- DLP on Ristretto255 is hard → can't extract R from PC

---

## 9. HOMOMORPHIC OPERATIONS (ALL PUBLIC-KEY-ONLY)

| Operation | What it does | Layers created |
|-----------|-------------|----------------|
| ct_add | Concatenates layers/edges | A.layers + B.layers |
| ct_sub | ct_add(A, ct_neg(B)) | Same as add |
| ct_neg | Negates all weights | Same layers |
| ct_scale | Multiplies all weights by scalar | Same layers |
| ct_mul | Creates PROD layers | A.layers + B.layers + LA×LB PROD layers |
| ct_square | Creates PROD layers (triangular) | A.layers + LA*(LA+1)/2 PROD layers |
| ct_add_const | Changes c0 only | Same layers |

### Key property of ct_mul/ct_square:
- Original BASE layers LOSE their edges in the product cipher
- Only PROD repack edges remain (8 per PROD layer)
- PROD targets = publicly computable cross-products of original T values
- ct_square(CT[0]): 5 layers, 24 edges, BASE layers have T=0

---

## 10. BUGS FOUND (4)

### BUG-001: R_com without binding
- `R_com = SHA256(domain || canon_tag || ztag || nonce || n_slots)` — R values NEVER hashed
- Removed from V2 serialization

### BUG-002: Keygen root exponent truncation (FIXED before challenge)
- `omega_B = fp_pow_u64(h, (uint64_t)E)` truncated 128-bit E to 64 bits
- Fixed with `fp_pow_u128`

### BUG-003: Edge count asymmetry across layers
- After merge, L0 and L1 have different edge counts

### BUG-004: Sigma merge leaks XOR structure
- merge() XORs sigma vectors when edges collide

---

## 11. APPROACHES TRIED (ALL FAILED)

| # | Approach | Result | Why it failed |
|---|----------|--------|---------------|
| 1 | V1 low-bit leakage | ❌ | Fixed in V2 wrapping |
| 2 | Sigma XOR pair identification | ❌ | HW ≈ 4096 (random) |
| 3 | R_com verification oracle | ❌ | Removed in V2 |
| 4 | LPN statistical attack | ❌ | y-bits random |
| 5 | Direct LPN solving (BKW/ISD) | ❌ | Est. 2^341 complexity |
| 6 | GCD/lattice on weights | ❌ | Prime field → trivial GCD |
| 7 | Cross-CT R sharing | ❌ | All 44 seeds unique |
| 8 | Brute force length CT[0] | ❌ | 1 eq, 2 unknowns per layer |
| 9 | Pedersen DLP | ❌ | Ristretto255 secure |
| 10 | T-value ratio analysis | ❌ | All ratios pseudo-random |
| 11 | Homomorphic ct_mul zero-test | ❌ | Can't distinguish enc(0) from enc(nonzero) with V2 wrapping |
| 12 | Pedersen × T scalar product | ❌ | Fp/Scalar field mismatch (P ≠ L) |
| 13 | sigma_from_H XOR → LPN instance | ⏳ | ~1800 samples, need n²=16M |
| 14 | Native runtime source (ru_src) | ❌ | All 44 layers use standard prg_layer_ztag |
| 15 | Weight ratio analysis | ❌ | R cancels but can't eliminate mask m |
| 16 | Seeded RNG exploitation | ❌ | Bounty uses csprng, not seeded |
| 17 | recrypt_eval.hpp full audit | ✅ DONE | See Section 18 for findings |

---

## 12. KEY INSIGHTS

1. **Sigma is irrelevant for decryption** — only used for commitment verification
2. **All security rests on prf_R** which requires both sk.prf_k AND sk.lpn_s_bits
3. **Even recovering lpn_s_bits alone is insufficient** — prf_k (256-bit) is still needed for AES key derivation
4. **V2 wrapping prevents zero-detection** — enc(0) has random non-zero T values
5. **Homomorphic ops don't leak plaintext** — PROD targets are deterministic functions of already-known T values
6. **Field mismatch** between Fp (mod P=2^127-1) and Scalar (mod L≈2^252) prevents algebraic attacks via Pedersen
7. **OCTRA released 44 LPN files** with 720,896 equations — smoke-ui analyzed them, found no shortcut
8. **Dev (lambda) said "fundamentally broken"** — we haven't found the break yet

### 🔴 CRITICAL DEDUCTION (July 15, 2026):
> **V1 was cancelled because it "didn't connect to HFHE"** (R_com oracle = generic crypto bug, not HFHE-specific).
> **V2 replaced V1** → therefore V2 **MUST be connected to HFHE**.
> **"Fundamentally broken" = the break IS in the HFHE mechanism itself.**
>
> This means: DO NOT look for generic crypto bugs. The vulnerability is specifically
> in how HFHE works — homomorphic evaluation, recryption, NatKey, native runtime,
> or the algebraic structure that enables HFHE.
>
> Even though `ru_cipher()` returns false (recryption disabled in this commit),
> the HFHE DESIGN flaw may still affect the base encryption layer. The question is:
> **what HFHE property leaks information about the plaintext through the public ciphertext?**

---

## 13. FILES & TOOLS CREATED

### C++ attack tools (compile in WSL with `g++ -std=c++17 -O2 -march=native -I./include`):
- `extract_powg.cpp` — Extract powg_B from pk.bin
- `decisive_attack.cpp` — Sigma analysis, T-value computation
- `full_attack.cpp` — Seed collision check, homomorphic ops test
- `check_ru_src.cpp` — Native runtime source check (all negative)
- `attack_tool.cpp` — Earlier attack scaffold

### Python scripts (50+):
- `decompress_pk.py` — PVAC range decoder port
- Various analysis scripts in scratch/

### Build environment:
- WSL Ubuntu 24.04, g++ 13.3
- Use `~/pvac_work/pvac_hfhe_cpp/` for persistent builds (NOT /tmp!)
- Copy .cpp and pvac_artifact_serialize.hpp before building

---

## 14. WHAT TO TRY NEXT (Prioritized)

### 🔴 HIGH PRIORITY (HFHE-connected, per critical deduction):
1. **Use bounty2 known-sk as training ground** — Compute R values, verify decryption, study T/R relationship
2. **Find the correct g (337th root of unity)** — `2^((P-1)/337) = 1` so 2 is NOT a generator! Need to find correct base. The g is stored as `powg_B[1]` in pk.bin — must parse pk.bin correctly or extract from bounty2's pk.
3. **Study the HFHE homomorphic structure for info leaks** — ct_mul, ct_square, ct_add are all public-key ops. The HFHE-specific break must be through these.
4. **Analyze if T-value structure under homomorphic ops reveals plaintext** — e.g. what happens to T values after ct_square? After repeated ct_mul?
5. **Check if V2 wrapping is algebraically breakable under ct_mul** — Products of wrapped CTs create cross-terms with mask interactions

### 🟡 MEDIUM PRIORITY:
6. **Check if delta values have structure** — prf_noise_delta uses sk but maybe predictable
7. **Try algebraic attacks on the ORDER-337 structure** — Characters, DFT on Z/337Z
8. **Investigate the 44 LPN files from OCTRA** — Maybe there's a practical attack with 720K equations
9. **Bounty3 parallel attack** — 60K OCT + $15K USD, same system, potentially easier

### 🟢 LOW PRIORITY:
10. ~~Read recrypt_eval.hpp fully~~ — DONE. See Section 18.
11. ~~Analyze NatKey structure~~ — DONE.
12. Check lambda's lite_node commit — b380d88
13. Analyze compute_layer_coeffs (= fold_edges = T values, already understood)

---

## 15. COMPETITOR ANALYSIS (smoke-ui)

- Also FAILED to break V2
- Tested: v1 oracle regression, wrapper algebra, LPN/PRF stats, RNG analysis, Ristretto, order-337, tensor/hypergraph, BIP39 brute force
- Analyzed OCTRA's 44 LPN files: "No duplicate rows, rank shortcut, anomalous bias found"
- Key quote: "Recovering S would still leave the independent 256-bit prf_k"
- Has Rust parser (independent verification)
- Report docs: EXECUTIVE_SUMMARY.md, REPORT.md, FINDINGS.md, METHODOLOGY.md, etc.

---

## 16. GITHUB REPO (hfhe-bounty-research)

- URL: https://github.com/Khoerulwisnupirdaus/hfhe-bounty-research
- Branch: master
- Contains: README.md with cryptic research log
- Strategy: Show progress without leaking details, redact active approaches
- Last push: July 14, 2026

---

## 17. SOURCE FILES AUDITED (100%)

```
encrypt.hpp        (1106 lines) — FULL: synth, fuse, enc_fp_wrapped_depth, SigEdge, N2Edge, delta
decrypt.hpp        (118 lines)  — FULL: dec_values, layer_R_cached
arithmetic.hpp     (~460 lines) — FULL: ct_add/sub/mul/square/scale/neg, build_product_cipher
recrypt.hpp        (175 lines)  — FULL: enc/dec wrappers, recrypt_compact, make_recrypt_key
recrypt_src_core.hpp (108 lines) — FULL: ru_src, ru_fp, ru_ztag, ru_affine, ru_y
commit.hpp         (104 lines)  — FULL: commit_ct (SHA256 hash only)
lpn.hpp            (419 lines)  — FULL: AesCtr256, derive_aes_key, lpn_make_ybits, prf_R
keygen.hpp         (277 lines)  — FULL: keygen, keygen_from_seed, fp_pow_u128
ristretto255.hpp   (~800 lines) — FULL: sc_from_fp, pedersen_commit, all scalar/point ops
matrix.hpp         (343 lines)  — FULL: sigma_from_H, gen_H, gen_ubk_public, apply_perm_sigma
types.hpp          (~200 lines) — FULL: Params defaults, Cipher/Layer/Edge structs
hash.hpp           (~200 lines) — FULL: SHA256, compute_R_com_base/prod, XofShake
pvac_compress.hpp  (~200 lines) — FULL: is_packed, unpack (range decoder)
seedable_rng.hpp   (~100 lines) — FULL: SeedableRng, make_seeded_rng
text.hpp           (89 lines)   — FULL: pack_15_bytes_to_fp, enc_text, dec_text
pvac_artifact_serialize.hpp (503 lines) — FULL: serialize/deserialize pk/sk/cipher
hfhe_bounty_artifact.cpp (~440 lines) — FULL: generate, verify, public_audit, selftest
```

### Partially audited:
```
(none remaining — all files fully audited as of July 15)
```

---

## 18. RECRYPT SYSTEM FULL AUDIT (July 15, 2026)

### KEY FINDING: `ru_cipher()` ALWAYS RETURNS FALSE!
```cpp
inline bool ru_cipher(const PubKey& pk, const Cipher& ct) {
    (void)pk; (void)ct;
    return false;  // ← HARDCODED! Native runtime is DISABLED!
}
```

### Impact:
- `eval_ru_layers()` always returns false → native eval never works
- `recrypt_hidden()` throws "eval rejected" 
- `decide_ru_eval()` → gate.native=false → gate.admitted=false
- `ru_refresh()` → gate rejected → exception
- **ENTIRE native recryption system is non-functional in this commit**

### NatKey (make_rku) structure:
- `rk.prf = 4` (encrypts prf_k[0..3])
- `rk.lpn = 0` ← **LPN secret NOT included!**
- `rk.sec[i] = enc_value_seeded(pk, sk, sk.prf_k[i], seed)` — each prf_k component encrypted
- No lpn_s_bits components at all

### ru_acc (homomorphic evaluation):
```
acc = constant + Σ(enc(prf_k[i]) * public_ru_fp[i])  
y = acc² + 1
```
This computes `ru_y(sk, seed) = ru_affine(sk, seed)² + 1` homomorphically.
But since ru_cipher() returns false, this path is never actually used.

### recrypt_eval.hpp files fully audited:
```
recrypt_eval.hpp     (315 lines) — FULL
recrypt_src.hpp      (91 lines)  — FULL  
recrypt_fold.hpp     (129 lines) — FULL
recrypt_ru.hpp       (602 lines) — FULL
recrypt_src_core.hpp (108 lines) — FULL (already done)
```

### Conclusion:
The recryption system is a STUB in this commit. But the break MUST
be HFHE-connected (see Section 12 critical deduction). So the vulnerability
must be in the ALGEBRAIC STRUCTURE that enables HFHE (layers, edges,
g^idx, T values, R computation) even though recryption itself is disabled.

---

## 19. HOMOMORPHIC STRUCTURE ANALYSIS (July 17, 2026)

### ct_mul architecture (arithmetic.hpp L314-345):
```
dec(A) = c0_A + Σ(T_i^A / R_i^A)
ct_mul splits: A_g = A with c0=0, then:
Product = c0_A*c0_B + c0_A*B_g + c0_B*A_g + build_product_cipher(A_g, B_g)
```
- `build_product_cipher` (L227): c0 starts at ZERO, creates PROD layers
- PROD target = `field::Op::mul(gA[la], gB[lb])` = T_a * T_b (PUBLIC!)
- `emit_repack_edges` (L71): creates 8 edges summing to target, using csprng randomness
- Cross-term edges: `append_scaled_edges(B_g.E, a0)` scales B's edges by c0_A
- Final c0 = c0_A * c0_B

### ct_square architecture (L347-375):
- Upper-triangular PROD pairs: (la, lb) for la <= lb
- For la != lb: target doubled (= 2 * T_a * T_b)
- For la == lb: target = T_a^2
- Original edges scaled by 2*c0

### Key observation about homomorphic ops:
- ALL repack edges are generated with **fresh randomness** (csprng)
- PROD targets are fully **PUBLIC** (T_a * T_b where T values are computable)
- No new secret material is introduced by ct_mul/ct_square
- ct_add_const ONLY changes c0, does NOT change edges or T values
- Therefore ct_add_const + ct_square changes c0 but T values stay identical

### compute_layer_coeffs (layer_coeffs.hpp, 40 lines):
```cpp
// = fold_edges = T values per layer
for each edge: out[layer_id][slot] += ±(weight * g^idx)
```
This is the SAME as gsum_accumulator in arithmetic.hpp. Returns `vector<vector<Fp>>`.

### Ciphertext format (from bounty3_test.cpp):
```
CT file: magic(u32=0x66699666) + ver(u32=1) + num_cts(u64)
Each CT: nL(u32) + nE(u32) + layers[] + edges[]
Layer BASE: rule(u8=0) + ztag(u64) + nonce_lo(u64) + nonce_hi(u64)
Layer PROD: rule(u8=1) + pa(u32) + pb(u32)
Edge: layer_id(u32) + idx(u16) + ch(u8) + pad(u8) + w(Fp=lo:u64+hi:u64) + sigma(BitVec)
BitVec: nbits(u32) + ceil(nbits/64) words(u64 each)
Fp: lo(u64) + hi(u64) → value = (hi << 64 | lo) % P
SK file: magic(u32=0x66666999) + ver(u32=1) + prf_k[0..3](4×u64) + lpn_count(u64) + lpn_s_bits[](n×u64)
PK file: magic(u32=0x06660666) + ver(u32=1) + params... + H_digest(32B) + H matrix + ubk + omega_B(Fp) + powg_B[](Fp each)
```

### bounty2 a.ct parsed successfully:
- 1 CT, 2 BASE layers, 40 edges (20 per layer)
- sigma_bits = 8192 per edge
- Each edge weight is single Fp (slots=1)

### RESOLVED: g (337th root of unity):
- **g = `0x1ed77a0a38054a3d5e1d5988d34d101f`** extracted from bounty2 pk.bin tail
- `2^((P-1)/337) = 1` (base 2 fails), but `3^((P-1)/337)` works as a different primitive root
- The pk.bin stores the ACTUAL g in `powg_B[1]`. Extracted via HTTP Range header (last 6KB of 16MB file).
- `powg_B[0] = 1`, `g^337 = 1` both confirmed ✅
- T values for bounty2 a.ct, b.ct, sum.ct computed successfully with this g

### RESOLVED: bounty2 parsing ✅
- a.ct: 1 CT, 2 BASE layers, 40 edges (20 per layer, 9-12 positive signs each)
- b.ct: same structure, different seeds
- sum.ct: 4 layers (concat a+b), 80 edges — T_sum[0..1] = T_a[0..1], T_sum[2..3] = T_b[0..1] ✅
- Edge weights: 121-127 bits (near-full Fp), uniform random
- Sigma HW: ~4060-4120 / 8192 (~50%), consistent with random
- No seed collisions between a and b (only expected a==sum, b==sum)

---

## 20. FULL ENCRYPTION/DECRYPTION EQUATIONS (July 17, 2026)

### Encryption pipeline (encrypt.hpp):
```
enc_value(pk, sk, v):
  1. Create layer with random seed (ztag, nonce)
  2. R = prf_R(pk, sk, seed)                    ← SECRET per-layer blinding
  3. delta = prf_noise_delta(pk, sk, seed)       ← small noise
  4. va = v - delta.agg                          ← adjusted value
  5. SigEdge.build(va) → 8 nodes:
     - 7 random: (idx_i, sign_i, coef_i) with random coef
     - 1 forced: coef_last = (va - partial_sum) / g^idx_last
     - Invariant: Σ(±coef_i * g^idx_i) = va
  6. Each node → edge with w = coef * R          ← WEIGHTS ENCODE R!
  7. T = Σ(±w * g^idx) = R * Σ(±coef * g^idx) = R * va

For V2 wrapping (2 layers):
  Layer 0: encrypts (v + mask) → T[0] = R0 * (v + mask - delta0)
  Layer 1: encrypts (-mask)    → T[1] = R1 * (-mask - delta1)
  Sum decrypts to: (v + mask - delta0) + (-mask - delta1) ≈ v (with noise)
```

### Decryption pipeline (decrypt.hpp):
```
dec_value(pk, sk, C):
  For each layer:
    R[lid] = prf_R_slots(pk, sk, layer.seed, slots)
    For PROD: R = R_a * R_b
  
  acc = c0
  For each edge e:
    term = (e.w * g^idx) * (1/R[e.layer_id])    // = coef * R * g^idx / R = coef * g^idx
    acc += ±term
  return acc  // = v (plus delta noise)
```

### R computation pipeline (lpn.hpp):
```
prf_R(pk, sk, seed) = prf_R_core(R1) * prf_R_core(R2) * prf_R_core(R3)

prf_R_core(pk, sk, seed, domain):
  1. aes_key = SHA256(prf_k[0..3] || canon_tag || H_digest || seed || domain)
  2. nonce = fnv1a(domain) ^ seed.nonce.lo
  3. AES-CTR PRG initialized
  4. lpn_make_ybits: for each of 16384 rows:
       row = AES-CTR output (pseudo-random, NOT from pk.H!)
       dot = popcount(row & sk.lpn_s_bits)  ← LPN inner product
       noise = random bernoulli(1/8)
       y[r] = dot ^ noise
  5. Toeplitz hash: random_matrix * y → 127-bit value
  6. hash_to_fp_nonzero → R component
```

### KEY INSIGHT — The LPN matrix is NOT pk.H!
- `lpn_make_ybits` generates rows from AES-CTR, NOT from the stored pk.H matrix
- pk.H is used ONLY for sigma/Pedersen commitment verification
- This means the LPN "matrix" is different per seed (derived from AES key)

### CRITICAL RELATIONSHIP:
```
w = coef * R          (edge weight)
T = Σ(±w * g^idx)     (public T value)
T = R * v_adjusted    (since Σ(±coef * g^idx) = v_adjusted by construction)

Therefore: w_i / R = coef_i  (the random decomposition coefficient)
And: T / R = v_adjusted

If we could find R for ANY layer, we'd get:
  v_adjusted = T / R
  Then: v = v_adjusted + delta ≈ v_adjusted (delta is small noise)
```

### WHERE TO LOOK FOR THE HFHE BREAK:
1. **Can we extract R from the edge structure?** w = coef * R, and coef is "random" but constrained (last coef is deterministic)
2. **Does the 337-root structure create a DFT-based attack?** T = R*v lives in a 337-dimensional space
3. **Cross-layer R correlation?** R0 and R1 use different seeds but same prf_k — is there correlation?
4. **Sigma as an R oracle?** sigma = sigma_from_H(pk, seed, idx, ch, extra_nonce) — does it encode R?
5. **V2 wrapping algebraic attack?** T[0]*T[1] = R0*R1*(v+m)*(-m) = -R0*R1*m*(v+m)

### NEXT STEPS:
1. ~~Build C++ decryption tool for bounty2~~ ✅ DONE (decrypt_b2.cpp, decrypt_b2_v2.cpp)
2. ~~Analyze sigma_from_H~~ ✅ DONE (see Section 20)
3. **Study delta noise** — compute delta_agg, verify v = dec + delta_agg = 1
4. **Try DFT attack** on edge structure (337 roots of unity form a cyclic group)
5. **Cross-CT edge correlation** — do different CTs with same sk share R-derived patterns?

---

## 20. BREAKTHROUGH SESSION — July 17, 2026

### 20.1 PYTHON prf_R = C++ prf_R — VERIFIED EXACT MATCH ✅

Built full Python implementation of prf_R pipeline:
- `derive_aes_key()`: SHA256(prf_k || canon_tag || H_digest || seed || fnv1a(domain)) → key + nonce
- `AesCtr256`: Custom AES-256-ECB(counter) mode matching C++ `_mm_set_epi64x(0, nonce)`, increment low u64
- `lpn_make_ybits()`: generate LPN matrix rows via AES-CTR PRG, dot with lpn_s_bits, add noise
- `toep_127()`: GF(2) polynomial convolution → extract 127 bits
- `prf_R()`: R = R1 * R2 * R3 (three independent prf_R_core calls)

**Both Python and C++ give IDENTICAL R values:**
```
R[0] = 0x00818f19329b59cac130c61be668d523
R[1] = 0x3f3534dcb6b2dba77733334b9bd954bf
```

### 20.2 DECRYPTION RESULTS — HOMOMORPHISM VERIFIED ✅

Bounty2 plaintext: a=1, b=2 (from bounty2_test.cpp line 261-262)

```
dec(a) = 674892774807482974   (60-bit, expected 1)
dec(b) = 478297466189274895   (60-bit, expected 2)
dec(a+b) = 1153190240996757869  (expected 3)

dec(a) + dec(b) = dec(a+b)  ✅  HOMOMORPHISM PERFECT!
```

**The 60-bit residual is DELTA NOISE — not an error in our R computation.**

### 20.3 DECRYPTION IS TRIVIAL — NO DELTA REMOVAL ⚠️

`dec_values()` in decrypt.hpp (lines 86-98) is shockingly simple:
```cpp
acc = c0  // (empty → zeros)
for each edge e:
    term = e.w[j] * g^idx * R_inv[layer]
    acc += ±term
return acc  // = c0 + Σ(T_l / R_l) = v - delta_agg
```

**dec_values does NOT add delta noise back!** It returns:
```
dec = v - Σ(delta_l)   where delta_l = delta::Set::make(gen, budget, S).agg
```

### 20.4 DELTA NOISE — KEY TO CORRECT DECRYPTION

Delta noise uses `prf_R_noise(pk, sk, modified_seed)`:
- `delta::Gen::scalar(i, d)` modifies seed with golden ratio constants then calls `prf_R_noise`
- `delta::Set::make(gen, budget, S)` generates `budget.vol()` delta values and sums them
- `agg = Σ delta_i` is subtracted from plaintext during encryption: `va = v - agg`
- Decryption returns `va = v - agg`, NOT `v`

**CRITICAL QUESTION**: Does bounty2_test.cpp pass its assert? If yes, then either:
1. delta_agg is 0 at depth=0 (budget.vol() = 0?)
2. There's an additional rounding/truncation step we haven't found
3. The test files were generated with a different code version

**TODO**: Run check_delta.cpp to compute actual delta values for bounty2.

### 20.5 sigma_from_H — FULLY UNDERSTOOD ✅

Location: `crypto/matrix.hpp` lines 298-335

```cpp
sigma_from_H(pk, ztag, nonce, idx, ch, salt):
  1. cols = prg_choose_k(x_col_wt=128, n=4096, "X_SEED", [canon_tag, ztag, nonce, idx, ch, salt])
  2. s = XOR of pk.H[cols]   // 128 random columns of H XOR'd together
  3. noise = prg_choose_k(err_wt=128, m=8192, "NOISE", same_words)
  4. flip noise bit positions in s
  5. return s (8192-bit BitVec)
```

**Sigma does NOT depend on sk, R, or plaintext.** It only depends on:
- pk.H (public), ztag/nonce (public), idx/ch (public), salt (random, NOT stored)
- Salt is embedded in sigma but not stored separately
- Sigma is essentially an LPN instance: y = H*x + e

### 20.6 DOMAIN STRINGS — ALL IDENTIFIED ✅

```
Dom::H_GEN      = "pvac.dom.h_gen"
Dom::X_SEED     = "pvac.dom.x_seed"
Dom::NOISE      = "pvac.dom.noise"
Dom::PRF_LPN    = "pvac.dom.prf_lpn"
Dom::TOEP       = "pvac.dom.toeplitz"
Dom::ZTAG       = "pvac.dom.ztag"
Dom::COMMIT     = "pvac.dom.commit"
Dom::PRF_R1     = "pvac.prf.r.1"
Dom::PRF_R2     = "pvac.prf.r.2"
Dom::PRF_R3     = "pvac.prf.r.3"
Dom::PRF_NOISE1 = "pvac.prf.noise.1"
Dom::PRF_NOISE2 = "pvac.prf.noise.2"
Dom::PRF_NOISE3 = "pvac.prf.noise.3"
Dom::R_COM      = "pvac.dom.r_com"
Dom::PRF_RHO    = "pvac.prf.rho"
Dom::PRF_RHO_PROD = "pvac.prf.rho.prod"
```

### 20.7 C0 = 0 ALWAYS FOR enc_value ✅

Tested: `c0.size = 1, c0[0] = 0:0`. Clearing c0 doesn't change decryption result.

### 20.8 C++ TOOLS BUILT IN WSL ✅

All at `~/pvac_work/pvac_hfhe_cpp/`:
- `decrypt_b2` — basic bounty2 decryptor (R + T analysis)
- `decrypt_b2_v2` — exact bounty2_test.cpp format
- `check_c0_v2` — verified c0 = 0
- `check_delta` — delta noise analysis (INTERRUPTED, needs re-run)

### 20.9 GITHUB OPSEC ✅

- KNOWLEDGE_BASE.md removed from git history via `git filter-branch`
- .gitignore updated to exclude KNOWLEDGE_BASE.md
- README.md kept cryptic/mysterious — shows we've audited everything but NOT how
- Force-pushed clean history

### 20.10 ATTACK PRIORITY — UPDATED

```
Priority 1: Compute delta_agg for bounty2, verify v = dec + delta = 1
Priority 2: If delta budget is 0 at depth=0, investigate depth>0 behavior
Priority 3: Study if R can be extracted from edge weight ratios
Priority 4: Cross-layer R correlation (same prf_k, different seeds)  
Priority 5: DFT attack on 337-root structure
Priority 6: Recryption/NatKey pathway analysis
```

**KEY INSIGHT**: The bounty3 README says "try to extract R from the equation."
This is a DIRECT HINT. R extraction is the intended attack vector.

---

## 21. CRITICAL: BOUNTY TESTS DON'T COMPILE! — July 17, 2026

### 21.1 bounty2_test.cpp and bounty3_test.cpp FAIL TO COMPILE ⚠️

Both files use `e.w` (Edge weight) as single `Fp`, but current `types.hpp` defines `Edge.w` as `vector<Fp>`:
```
bounty2_test.cpp:99:  putFp(o, e.w);     // ERROR: e.w is vector<Fp>, putFp expects Fp&
bounty2_test.cpp:108: e.w = getFp(i);     // ERROR: can't assign Fp to vector<Fp>
bounty3_test.cpp:103: putFp(o, e.w);      // SAME ERROR
```

### 21.2 IMPLICATIONS

1. **Bounty data was generated with an OLDER version** of the code where `Edge.w = Fp` (not `vector<Fp>`)
2. **The assert `fa.lo == 1` in bounty2_test.cpp was NEVER tested** with commit 071b0e9
3. **Serialization IS compatible**: single Fp (16 bytes) is read and put into vector<Fp>{fp}
4. **But dec_value behavior may have CHANGED** between versions

### 21.3 DELTA ANALYSIS RESULTS

```
Budget at depth=0: n2=3, n3=2, vol=5 (5 delta noise values per layer)
tuple2_fraction = 0.55

Layer 0 delta_agg = 0x5eafd8d306d252964de8c5248e2ec87f (127-bit)
Layer 1 delta_agg = 0x69e06267b35327810fe160ea40aa99fe8 (127-bit)
Total = 127-bit random

dec(a) + total_delta = 127-bit random ≠ 1
```

**dec(a) + delta_agg ≠ plaintext!** This means either:
1. The delta noise was NOT this value when the data was generated (different code version)
2. There's an additional step (rounding/truncation) we're missing
3. The delta cancellation works differently than we think

### 21.4 WHAT THIS MEANS FOR THE ATTACK

The "fundamentally broken" aspect may be related to this version mismatch:
- Old code: `Edge.w = Fp` (single slot)
- New code: `Edge.w = vector<Fp>` (multi-slot)
- The transition may have introduced a bug or changed the delta/R computation

**TODO**: 
1. Check git history for when Edge.w changed from Fp to vector<Fp>
2. Try compiling with the older version to verify bounty2 decrypts to 1
3. Focus attack on R extraction (the hint!) rather than delta analysis

---

## 22. MAJOR FINDINGS — July 17, 2026 (Session 2)

### 22.1 CONFIRMED: T = R * v EXACTLY (delta cancels!)
```
Fresh encryption: enc_fp_raw(42) → T == R*42? YES ✅
T/R = 42 (exact plaintext recovery with R)
```
Signal edges encode va = v - delta_agg, but noise edges encode +delta_i.
Their total CANCELS: T = R*(v-δ) + R*δ = R*v.

### 22.2 keygen_from_seed — DETERMINISTIC KEY GENERATION
`keygen_from_seed(prm, pk, sk, wallet_privkey[32])` derives ALL keys from wallet private key:
- master = SHA256("OCTRA_PVAC_MASTER_V1" + wallet_privkey)
- canon_tag = from SHA256("OCTRA_PVAC_TAG" + master)
- sk.prf_k = from SHA256("OCTRA_PVAC_SK" + master)
- pk.powg_B = from SHA256("OCTRA_PVAC_GEN" + master)
Circular: mnemonic → wallet_privkey → (pk,sk) → encrypt(mnemonic)

### 22.3 BOUNTY3 WALLET DRAINED — Balance = 125 OCT (was 60K)
- Nonce = 25 (25 transactions already made)
- **Someone likely already claimed the bounty!**
- BUT no GitHub issue filed for bounty3 claim

### 22.4 GitHub Issues — KEY SECURITY FINDINGS
| Issue | Title | By | Date |
|-------|-------|----|----|
| #499 | hidden_coeff_stmt_digest leaks secret coefs | Iamknownasfesal | Jul 7 |
| #500 | SHA256 hidden-trace forgery | Iamknownasfesal | Jul 7 |
| #501 | **R² leak in bounty2 via edge collision** | Anggi272 | Jul 8 |
| #502 | Reproduction of #499/#500 | bitupx00 | Jul 10 |
| #503 | rist_decode non-canonical | bhu1tyagi | Jul 10 |

### 22.5 R² LEAK (Issue #501) — PARTIALLY VERIFIED
Claim: "edges with same idx + opposite ch expose R²"
Our testing:
- bounty2 a.ct: **NO collisions** (no same-idx opposite-ch pairs)
- bounty3 seed.ct: 3 collisions found (CT[0]L1, CT[5], CT[8])
- CT[5] collision is QR but v = T/sqrt(R²) NOT short → **coef product ≠ 1**
- Fresh cipher: 1 collision, coef product ≠ 1
- **CONCLUSION: Issue #501 R² extraction needs additional info to eliminate coef product**

### 22.6 decode_ct.cpp — REQUIRES sk.bin
The official decoder also fails to compile (Edge.w type mismatch). Fixed version works but needs sk.bin which bounty3 doesn't have.

### 22.7 FAILED APPROACHES (session 2)
1. ❌ R² leak doesn't give clean R² (coef product unknown)
2. ❌ NatKey (rku_dom depends on sk)
3. ❌ Cross-CT validation (each R independent per seed)
4. ❌ Brute force mnemonic 2^121 (infeasible)
5. ❌ Reverse prf_R (LPN 2^341)
6. ❌ Sigma for coef identification (sigma independent of coef/R)

### 22.8 REMAINING ATTACK VECTORS (PRIORITY ORDER)
1. **prf_R mathematical shortcut** — the "fundamentally broken" thing
2. **gen_H weakness** — LPN matrix from deterministic canon_tag
3. **Issue #499 hidden_coeff_stmt_digest** — leaks secret coefficients via digest
4. **Edge weight ratio analysis** — statistical distinguisher for signal vs noise
5. **Old code version** — bounty data generated with different (weaker?) code

---

## 23. MAIN BOUNTY V2 (1M OCT) — DEEP ANALYSIS (July 17, 2026 Session 3)

### 23.1 BOUNTY STATUS — ALL MINI-BOUNTIES CLAIMED, MAIN STILL ACTIVE
| Bounty | Reward | Status |
|--------|--------|--------|
| **Main V2 (1M OCT)** | 1M OCT | 🟢 **STILL ACTIVE** (octrascan confirmed) |
| Main V1 mini ($6.6K) | $6,666 USDT | ❌ SOLVED by 0xE42c... |
| Mini-bounty 2 ($3.3K) | $3,333 USDT | ❌ CLAIMED (wallet 0x7d7d... empty) |
| Bounty 3 (60K OCT) | 60K OCT + $15K | ❌ CLAIMED (wallet has 125 OCT) |

### 23.2 MAIN BOUNTY FILES — hfhe-challenge REPO (SEPARATE REPO!)
- **Repo**: https://github.com/octra-labs/hfhe-challenge
- **Cloned to**: `~/pvac_work/pvac_hfhe_cpp/hfhe-challenge/`
- **Files**:
  - `secret.ct` (1,963,107 bytes) — OCTRA-HFHE-BTY02 bundle format
  - `pk.bin` (3,042,901 bytes) — PVAC v3 compressed format
  - `params.json` — m=8192, n=16384, B=337
  - `manifest.json` — commit 071b0e9, reward 500K OCT
  - `lpn_samples/` — 44 JSONL files, ~17MB each
  - `source/hfhe_bounty_artifact.cpp` — generator source code
  - `source/pvac_artifact_serialize.hpp` — V3 serialization
  - `source/tools/verify_lpn_sample_binding.cpp` — LPN↔CT binding verifier

### 23.3 V2 FORMAT DIFFERENCES FROM bounty_data/bounty3
- **Magic**: `OCTRA-HFHE-BTY02` (not `0x66699666`)
- **Bundle**: `[magic 16B][count u64][per-CT: [size u64][cipher_blob]]`
- **Cipher serialization**: `pvac_ser::serialize_cipher()` (V3 format, includes c0, PC, multi-slot)
- **Edge.w**: `vector<Fp>` (multi-slot), NOT single Fp
- **R_com**: REMOVED in V2 (was oracle vulnerability in V1)
- **Encryption**: `enc_text()` with V2 wrapping (2 layers per CT)

### 23.4 LPN SAMPLES — ALREADY ANALYZED (DO NOT REPEAT!)
- 44 files × 16,384 rows = **720,896 LPN equations**
- Parameters: n=4096, t=16384, tau=1/8 (12.5% noise)
- Format: `{"i":N, "y":0|1, "a":"hex_row_4096_bits"}`
- Header: includes seed_ztag, nonce, public_T matching secret.ct layers
- **Binding verified**: LPN samples tied to specific layers via verify_lpn_sample_binding.cpp
- **smoke-ui also analyzed these**: found no shortcut
- **BKW infeasible**: n=4096 requires exponential memory/time for standard BKW
- **Standard LPN solving for these params is computationally infeasible**

### 23.5 KEY OBSERVATIONS FROM hfhe_bounty_artifact.cpp
- `noise_entropy_bits = 128.0` — FULL entropy noise, NOT reduced
- `enc_text(pk, sk, plain)` — standard V2 wrapped encryption
- `public_audit()` checks: wrapped, public_nonzero, zero_regression, H parity, sigma parity, H rank
- plaintext read from `challenge_private/plaintext.txt` (not in repo)

### 23.6 COMPLETED ANALYSIS (Session 3 Deep-Dive)

#### ✅ secret.ct PARSED — FULL STRUCTURE
- **22 CTs**, each with 2 BASE layers, slots=1
- **c0 = zeros** for all CTs (unused in BASE layers)
- **R_com = ZERO** for all layers (removed in V2 as expected)
- **PC values: NON-ZERO** for all 44 layers! Each is 32-byte Ristretto point
- Edge counts: CT[0]=43, CT[21]=119, growing linearly (~2 noise edges/depth)

#### ✅ H MATRIX ANALYSIS
- Dimensions: 16384 columns × 8192 rows
- Column weight: uniform 192-193
- **GF2 rank = 8192 / 8192 = FULL RANK** → no LPN shortcut via kernel
- H parity: mixed (even=8190, odd=8194) → no parity leak

#### ✅ SIGNAL vs NOISE EDGES — CANNOT BE DISTINGUISHED
- **K_signal = 8 FIXED** (hardcoded `static constexpr int K = 8`)
- Signal coefs: 7 random Fp + 1 determined (last edge corrects to target)
- Noise N2 edges: 2 per delta, coefs random
- Noise N3 edges: 3 per delta, coefs random
- **Signal w = coef * R, Noise w = delta * R** — both random magnitudes
- Weight magnitude spread ~4-5 bits is natural variation, NOT signal/noise boundary
- Verified with bounty2 sk.bin: ALL edges show as "noise" (no powg_B match) because coefs are random

#### ✅ SERIALIZATION AUDIT — NO SECRET DATA LEAKED
- `serialize_cipher()`: writes [slots, layers(rule+seed+PC), c0, edges(lid,idx,ch,w,sigma)]
- `serialize_pubkey()`: writes [params, canon_tag, H[], ubk.perm[], ubk.inv[], H_digest, omega_B, powg_B[]]
- R_com intentionally NOT serialized in V3 format (V2 fix)
- **PC values ARE serialized** — 32 bytes per slot per layer
- No extra/padding bytes, no sk data in pk.bin

#### ✅ KEYGEN — CLEAN
- `keygen()` uses `csprng_u64()` → `/dev/urandom` → cryptographically secure
- `keygen_from_seed()` exists for wallet-based keygen but NOT used for bounty
- pk contains only public data, sk separate

#### ✅ DECRYPTION LOGIC — CORRECT
- `dec_values()`: sum of (w * g^idx * R_inv * ±1) + c0 = plaintext
- No obvious logic bug in decrypt flow

#### ✅ PUBLIC_AUDIT FUNCTIONS — ANALYZED
| Function | What it checks | Result |
|----------|---------------|--------|
| `bundle_is_wrapped()` | All CTs have 2 BASE layers | PASS |
| `bundle_base_layers_are_public_nonzero()` | All T values non-zero | PASS |
| `public_zero_regression()` | enc(0) has non-zero T (V2 fix works) | Regression test |
| `mixed_H_parity()` | H columns have both even/odd parity | PASS |
| `mixed_sigma_parity()` | Sigma values have mixed parity | PASS |
| `small_H_rank_regression()` | H has full rank at small dimensions | Regression test |
| `gf2_rank()` | GF2 Gaussian elimination | Full rank confirmed |

### 23.7 DEEP TECHNICAL FINDINGS

#### PC (Pedersen Commitment) Structure
```
PC = sc_from_fp_signed(R_inv) * G + rho * H
```
- `R_inv = fp_inv(R)` — 127-bit field element
- `sc_from_fp_signed()`: maps Fp → Scalar, uses bit 62 of hi to determine sign
- `rho = sc_reduce256(SHA256(PRF_RHO || prf_k[4] || nonce_lo || nonce_hi || slot_j))`
- **rho depends on prf_k (256-bit), NOT lpn_s_bits** → recovering prf_k would break PC
- Pedersen commitment is information-theoretically hiding if rho is random
- **Cannot extract R_inv from PC without knowing rho**

#### PRF_R Pipeline (Complete)
```
prf_R(pk, sk, seed) = prf_R_core(seed, R1) * prf_R_core(seed, R2) * prf_R_core(seed, R3)

prf_R_core:
  1. ybits = lpn_make_ybits(pk, sk, seed, dom)  ← LPN computation
  2. toep_key = derive_aes_key(pk, sk, seed, TOEP)
  3. toep_output = toep_127(AES-CTR(toep_key), ybits)  ← Toeplitz hash
  4. R = hash_to_fp_nonzero(toep_output)
```

#### LPN Row Generation — COUPLED WITH NOISE!
```cpp
// SAME AES-CTR PRG generates BOTH row AND noise:
prg.fill_u64(row_buf, s_words);      // row a_i from PRG
int e = (prg.bounded(den) < num);     // noise e_i from SAME PRG continuation
```
- Rows and noise are NOT independent — they come from same AES-CTR stream
- But AES-CTR is secure PRG → cannot predict noise from rows without key
- AES key = SHA256(prf_k || canon_tag || H_digest || seed_params)

#### Edge Index Distribution
- 4 of 338 indices unused across all CTs
- Max frequency: idx=242 (13 times), roughly uniform
- No obvious clustering that would reveal signal edge positions

#### enc_text Structure
- CT[0] = enc_value(msg.size()) — encrypts LENGTH as uint64
- CT[1..21] = enc_fp_wrapped_depth(block_i, depth_hint) — 15-byte blocks
- depth_hint starts at 2, increments per block
- **Plaintext length: 301-315 bytes** (21 data blocks × 15 bytes)

#### Developer Comment Found
- `// ndt - new fix (3 Jul 2026)` in encrypt.hpp line 979
- This fix is IN the bounty commit (071b0e9) — not a pre-fix vulnerability

### 23.8 DEAD ENDS CONFIRMED THIS SESSION
1. ❌ H rank deficiency → full rank
2. ❌ Signal/noise edge weight distinguisher → both random magnitudes
3. ❌ PC value extraction → needs rho (from prf_k)
4. ❌ Serialization data leak → clean
5. ❌ Keygen weakness → uses /dev/urandom
6. ❌ Decrypt logic bug → correct implementation
7. ❌ c0 leak → always zero for BASE layers

### 23.9 REMAINING UNEXPLORED VECTORS (PRIORITY)
1. **GitHub Issue #499**: `hidden_coeff_stmt_digest` leaks secret coefficients — READ THIS ISSUE BODY
2. **GitHub Issue #503**: `rist_decode` accepts non-canonical encodings — could allow PC forgery
3. **GitHub Issue #501**: "R² leak in bounty2" — what is the R² leak mechanism?
4. **LPN row/noise coupling**: rows and noise from same PRG — any known attack on coupled LPN?
5. **Toeplitz hash invertibility**: if we know output (related to R via T), can we recover ybits?
6. **Multiple-instance attack**: 44 LPN instances share same s, 3 prf_R_core calls per R with DIFFERENT domains → 132 total LPN evaluations on same s
7. **rist_H() dead code**: messy implementation with overwritten variables — is H point computed correctly?
8. **merge edge cancellation**: edges with w=0 but sigma≠0 are kept — any info leak?

### 23.10 TOOLS BUILT THIS SESSION
- `~/pvac_work/pvac_hfhe_cpp/v2_dump` — parses secret.ct, dumps full structure
- `~/pvac_work/pvac_hfhe_cpp/v2_attack` — H rank, edge analysis, sigma parity
- `~/pvac_work/pvac_hfhe_cpp/v2_weight` — weight magnitude and GCD analysis
- `~/pvac_work/pvac_hfhe_cpp/verify_sig2` — signal/noise verification using bounty2 sk
- `~/pvac_work/pvac_hfhe_cpp/verify_lpn` — LPN sample binding verifier (from repo)

