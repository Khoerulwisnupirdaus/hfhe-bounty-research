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
- **Dev hint**: Lambda said system was "fundamentally broken" and this break IS connected to HFHE/FHE. V1 was cancelled for a different reason (R_com oracle). The fundamental break applies to the FHE mechanism itself.

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


---

## Session 4 — Final Exhaustive Audit (July 17-18, 2026)

### 24. COMPLETE CODE AUDIT RESULTS

Every security-critical file audited line-by-line:

| File | Status |
|------|--------|
| field.hpp | Correct: fp_add, neg, mul, inv |
| ristretto255.hpp | H independent from G, pedersen correct |
| keygen.hpp | /dev/urandom, not from_seed() |
| matrix.hpp | gen_H deterministic public, full rank |
| lpn.hpp | prf_R_core, AES-CTR, Toeplitz correct |
| encrypt.hpp | synth, SigEdge, N2Edge, merge, permute correct |
| decrypt.hpp | Matches encrypt perfectly |
| text.hpp | 15-byte packing clean |
| hash.hpp | R NOT hashed in R_com (V2 fix confirmed) |
| recrypt_src_core.hpp | ru_src not triggered for challenge |
| pvac_artifact_serialize.hpp | No sk data leaked |
| hfhe_bounty_artifact.cpp | generate/verify/public_audit clean |

### 25. ALTERNATIVE DECRYPT METHODS TESTED

- R=1 for all layers: Random output
- R=omega_B: Random output
- Native ztag match: ALL 44 layers = NO
- PC with rho=0, R_inv=1..100: No match
- Cancelled edges (w=0): None found

### 26. STRUCTURAL CHECKS PASSED

- 44 nonces unique, 44 ztags match, 44 PCs unique
- H rank = 8192/8192 FULL, g^B = 1
- All T values random, T0/T1 random, T0+T1 random
- Cross-CT ratios all random

### 27. FINAL STATUS: UNSOLVED

30+ attack vectors explored, 3000+ lines of crypto code audited, no exploitable vulnerability found.

See SECURITY_ASSESSMENT.md for complete technical writeup.

### 28. TOOLS BUILT THIS SESSION
- gen_test, full_audit, alt_decrypt, check_H, check_fp

---

## Session 5 — LPN FOCUSED ATTACK (July 18, 2026)

> **FULL DETAILS: See LPN_ATTACK_LOG.md for complete findings (entries 29-44)**

### CRITICAL CONCLUSIONS FROM SESSION 5

1. **CANNOT DECRYPT WITHOUT SOLVING LPN** — No shortcut exists. Must recover s (4096 bits) AND prf_k (256 bits) to compute R values for decryption.

2. **RECOVERING s ALONE IS NOT SUFFICIENT** — Even with s, we cannot recover prf_k (needed for AES key derivation, Toeplitz matrix). SHA256 and AES are one-way.

3. **LPN(4096, 1/8) IS COMPUTATIONALLY INFEASIBLE BY ALL KNOWN ALGORITHMS**:
   - BKW: 2^341
   - Pooled Gauss: 2^789
   - Statistical Decoding: 2^549
   - All hybrid approaches: > 2^300

4. **NO IMPLEMENTATION BUGS FOUND IN LPN**:
   - bounded() noise generation: correct rejection sampling
   - Rows genuinely random (AES-CTR working correctly)
   - Cross-file stats normal, no anomalies
   - Secret s is uniform random (HW ~2048), NOT sparse

5. **THE PARADOX REMAINS**: Dev says LPN is breakable ("happy breaking!") but all academic estimates say 2^341+. Something SPECIFIC about this instance must be weaker than generic LPN.

### ALL ANGLES EXHAUSTED — NO RESULTS
1. ~~GitHub Issues #499, #501, #503~~ — CHECKED, no exploitable path
2. ~~Toeplitz hash properties~~ — CHECKED, cannot reverse without prf_k
3. ~~Multi-domain relationship~~ — CHECKED, R1*R2*R3 doesn't help
4. ~~Neural network LPN solvers~~ — Max n~512 in literature, n=4096 infeasible
5. ~~Row/noise coupling from same PRG~~ — AES-CTR secure, no exploit
6. ~~Bounty3~~ — CHECKED, same crypto, no easier path found

### ABSOLUTE STATUS: ALL KNOWN ATTACK VECTORS EXHAUSTED (for bounty challenge)
- 30+ attack vectors tried on HFHE structure
- 6+ LPN-specific attack approaches analyzed
- All complexity estimates > 2^300
- No implementation bugs found
- No mathematical shortcuts found
- **The bounty challenge remains UNSOLVED as of July 18, 2026**

---

## Session 6 — WebCLI AUDIT & keygen_from_seed DISCOVERY (July 18, 2026)

### 45. CRITICAL DISCOVERY: keygen_from_seed() LINKS prf_k AND lpn_s
**File**: webcli/pvac/include/pvac/crypto/keygen.hpp (line 172+)

In production (webcli), `keygen_from_seed(wallet_privkey)` derives BOTH prf_k AND lpn_s_bits from the SAME AES-CTR stream:

```
master = SHA256("OCTRA_PVAC_MASTER_V1" || wallet_privkey)
sk_seed = SHA256("OCTRA_PVAC_SK" || master)
rng = AesCtr256(sk_seed, nonce=0)
prf_k[0..3] = rng.u64() × 4    // bytes 0-31 of AES-CTR stream
lpn_s_bits[0..63] = rng.u64() × 64  // bytes 32-543 of AES-CTR stream
```

**IMPLICATION**: If you recover lpn_s_bits from a real user's on-chain encrypted data, you know bytes 32-543 of the AES-CTR keystream. Since AES-CTR is keystream = AES(key, counter), knowing ANY part of the keystream output does NOT reveal the key (AES is secure). BUT: the keystream at counter 0-3 (bytes 0-31) = prf_k. So you'd need to know sk_seed to compute counter 0-3.

**HOWEVER**: Knowing s bits 32-543 = knowing AES-CTR output at those counters. AES-CTR is a PRF. Without the key (sk_seed), you cannot compute output at different counters.

### 46. BOUNTY CHALLENGE USES keygen() NOT keygen_from_seed()
- Tests: `tests/bounty_test.cpp:309: keygen(prm, pk, sk);`
- This means prf_k and lpn_s_bits are INDEPENDENTLY random (from /dev/urandom)
- The keygen_from_seed coupling does NOT apply to the bounty challenge
- **Recovering s from the bounty STILL does NOT give prf_k**

### 47. POSSIBLE "FUNDAMENTALLY BROKEN" MEANING
Dev said system is "fundamentally broken" but "didn't connect to HFHE":
- The break may be: keygen_from_seed creates a DETERMINISTIC relationship
- In real network usage, if LPN is ever solvable (even theoretically), BOTH prf_k and s are compromised
- This is a DESIGN flaw in how keys are derived (same stream), not a crypto break
- For the bounty challenge specifically, this doesn't help (independent keys)

### 48. WebCLI REPO STRUCTURE (github.com/octra-labs/webcli)
Key files audited:
- `crypto_utils.hpp` — Custom SHA256, base64 (standard implementations)
- `wallet.hpp` — Wallet stored in data/wallet.oct, ed25519 keys
- `lib/pvac_bridge.hpp` — Uses keygen_from_seed() for real wallets
- `pvac/pvac_c_api.cpp` — C API bridge, enc/dec/mul operations
- `pvac/include/pvac/crypto/keygen.hpp` — Both keygen() and keygen_from_seed()
- `pvac/include/pvac/core/seedable_rng.hpp` — SeedableRng = AesCtr256

### 49. SeedableRng = AesCtr256
```cpp
struct SeedableRng {
    AesCtr256 prg;
    void init(const uint8_t seed[32]) { prg.init(seed, 0); }
    uint64_t u64() { return prg.next_u64(); }
};
```
Same AES-CTR used for LPN row generation AND key derivation.
AES-CTR is secure: knowing output at positions X does NOT reveal output at positions Y.

### 50. FULL WebCLI AUDIT — NO EXPLOITABLE VULNERABILITIES FOUND
**Files audited (July 18, 2026)**:

| File | Finding |
|------|---------|
| `crypto_utils.hpp` | Standard SHA256 + base64. Clean. |
| `wallet.hpp` | Wallet in data/wallet.oct, PIN-encrypted. ed25519 keys. Clean. |
| `lib/pvac_bridge.hpp` | init() takes first 32 bytes of wallet sk as PVAC seed. Confirmed keygen_from_seed. |
| `lib/stealth.hpp` | ECDH + AES-256-GCM. Standard crypto. Clean. |
| `lib/circle_hfhe_receipt.hpp` | Circle HFHE receipts with ed25519 sigs. Clean. |
| `pvac/pvac_c_api.cpp` | C bridge to PVAC. pvac_aes_kat is deterministic test. Clean. |
| `main.cpp` (294KB) | Local web server. 40+ API endpoints audited. |

**API Endpoints checked**:
- `/api/keys/private` — requires PIN + confirmation text. Local only. Not remotely exploitable.
- `/api/key_switch` — sends new PVAC pubkey on-chain. Standard.
- `/api/fhe/decrypt` — local decrypt using local sk. Clean.
- `/api/encrypt` / `/api/decrypt` — uses random_bytes(seed, 32) for each operation. Clean.
- `/api/circle/fhe/decrypt` — has authorization + proof requirements. Clean.

**Encryption logic**: `synth_seeded()` in webcli is IDENTICAL to pvac_hfhe_cpp. No diff.

### 51. keygen_from_seed() IS A DESIGN CONCERN BUT NOT A BOUNTY VULNERABILITY
- In production: wallet_privkey[0:32] → SHA256("OCTRA_PVAC_MASTER_V1" || ...) → master
- From master: prf_k and lpn_s come from same AES-CTR stream
- This means: if ANYONE finds a way to solve LPN for ANY user on the real network, they get BOTH prf_k and s
- **BUT**: This doesn't apply to the bounty challenge (uses random keygen)
- **AND**: AES-CTR is secure — knowing later stream positions doesn't reveal earlier positions

### 52. WALLET ARCHITECTURE
```
Wallet private key (ed25519 sk, 64 bytes)
  ├── First 32 bytes → PVAC seed
  │   ├── SHA256("OCTRA_PVAC_MASTER_V1" || seed) → master
  │   │   ├── SHA256("OCTRA_PVAC_TAG" || master) → canon_tag (8 bytes)
  │   │   ├── SHA256("OCTRA_PVAC_SK" || master) → sk_seed (32 bytes)
  │   │   │   └── AesCtr256(sk_seed, 0) → [prf_k(32B), lpn_s(512B)]
  │   │   └── SHA256("OCTRA_PVAC_GEN" || master) → gen_seed → g, omega_B
  │   └── PubKey: canon_tag, H_digest, ubk, powg_B, omega_B
  └── Full 64 bytes → ed25519 signing
```

---

## Session 7 — COMPETITOR CONFIRMATION & CHALLENGE STATUS (July 21, 2026)

### 53. SMOKE-UI INDEPENDENTLY CONFIRMS ALL OUR FINDINGS — ALSO FAILED
**Source**: Twitter @smoke-ui, Day 6 update (July 2026)

Their results (6 days formal audit):
- **480 samples, 6 keys, 1104 features** → 0 invariants survive FDR
- **Ciphertext algebra (toy)** → 0.000000 TVD between distinct plaintexts
- **LPN-PRF margin** → no low-dim simplification helps at n=4096, τ=1/8
- **"The wrapper doesn't leak. No equality oracle from algebra."**
- **Day 7 = FREEZE** (they are stopping)

Full assessment: https://github.com/smoke-ui/octra-hfhe-v2-security-assessment

### 54. CROSS-VALIDATION: OUR FINDINGS vs SMOKE-UI
| Area | Our Finding | Smoke-UI Finding |
|------|-------------|------------------|
| LPN hardness | 2^341+ (all estimators) | "no low-dim simplification" |
| Statistical bias | None (44 files, 720K samples) | 0 survive FDR (480 samples) |
| Wrapper leak | V2 wrapping prevents zero-detection | "wrapper doesn't leak" |
| Algebraic distinguisher | No distinguisher found | 0.000000 TVD |
| Equality oracle | enc(0) has random T values | "no equality oracle" |

**Two independent teams, same conclusion: HFHE V2 appears cryptographically sound.**

### 55. FINAL STATUS (July 21, 2026)

**CHALLENGE: UNSOLVED** by anyone.

- 52+ findings documented across 7 sessions
- 50+ attack vectors attempted, all failed
- Full WebCLI audit completed, no exploitable vulnerabilities
- keygen_from_seed design concern identified (not applicable to bounty)
- Competitor (smoke-ui) independently confirmed all negative results
- Dev claim "fundamentally broken" remains unsubstantiated for HFHE specifically
- Dev clarification: break "didn't connect to HFHE" — may refer to a different layer

**To resume**: If new hints emerge, read this KNOWLEDGE_BASE.md first. Do NOT repeat any approach listed above.

---

## SESSION 8 (July 21, 2026) — EQUATION SYSTEM BREAKTHROUGH

### 56. EXACT DECRYPTION FORMULA (VERIFIED ✓)

Using bounty2 (known sk.bin), we VERIFIED the exact mathematical equation:

```
plaintext = c0 + Σ_l ( S_l / R_l )
```

Where:
- **S_l = Σ_{e ∈ layer_l} sgn(e.ch) × e.w × powg_B[e.idx]** — FULLY PUBLIC, computable from ciphertext + pk
- **R_l = prf_R(pk, sk, seed_l)** — SECRET, requires prf_k + lpn_s
- **R = R1 × R2 × R3** (product of 3 independent prf_R_core calls with different domains)
- Each R_core = hash_to_fp_nonzero(toeplitz_127(toep_matrix, ybits))
- ybits = LPN(A, s, e) output

**Code path**: decrypt.hpp lines 73-95 (dec_values function)

### 57. BOUNTY2 SERIALIZATION FORMAT (DIFFERENT FROM WEBCLI!)

bounty_test.cpp uses COMPLETELY different serialization from pvac_serialize.hpp:
- Layer: `rule(u8) + ztag(u64) + nonce_lo(u64) + nonce_hi(u64)` — NO R_com, NO PC!
- Edge: `layer_id(u32) + idx(u16) + ch(u8) + pad(u8) + w(single Fp) + sigma(BitVec)`
- Cipher: `nL(u32) + nE(u32) + layers[] + edges[]` — NO slots field, NO c0!
- CT file: `Magic(u32=0x66699666) + Ver(u32=1) + count(u64) + ciphers[]`
- PK: params → canon_tag → H_digest(32B) → H(u64 count + BitVec[]) → ubk_perm → ubk_inv → omega_B → powg_B

### 58. BOUNTY2 EQUATION SYSTEM RESULTS

| Cipher | Layers | BASE | PROD | Edges | Edges/Layer | Independent R unknowns |
|--------|--------|------|------|-------|-------------|----------------------|
| a[0]   | 2      | 2    | 0    | 40    | 20          | 2                    |
| b[0]   | 2      | 2    | 0    | 40    | 20          | 2                    |
| sum[0] | 4      | 4    | 0    | 80    | 20          | 4                    |

KEY INSIGHT: sum.ct REUSES the exact same R values from a.ct and b.ct!
- sum.L0 has same R as a.L0, sum.L1 has same R as a.L1
- sum.L2 has same R as b.L0, sum.L3 has same R as b.L1

### 59. SECRET.CT TEXT ENCODING

From text.hpp, secret.ct contains TEXT encrypted as:
```
CT[0] = enc_value(msg.size())           → encrypted message length
CT[1..N] = enc_fp_wrapped_depth(15-byte chunks of text) → encrypted text blocks
```

secret.ct bounty header: "OCTRA-HFHE-BTY02"(16B) + num_cts(u64=22) + length-prefixed ciphers
- 22 ciphertexts → CT[0]=length, CT[1..21]=text blocks → max 315 bytes of text
- Each text block = 15 bytes packed into Fp via pack_15_bytes_to_fp()
- Decryption: dec_text() → unpack each Fp to 15 bytes, concatenate, trim to length

### 60. SECRET.CT FORMAT (PVAC V3)

```
"OCTRA-HFHE-BTY02" (16 bytes ASCII)
num_ciphertexts (u64) = 22
For each cipher:
  ct_byte_length (u64)
  PVAC v3 serialized cipher:
    "PVAC"(4B) + ver(u8=3) + tag(u8=0)
    slots(u64=1)
    nLayers(u64) + Layer[]:
      rule(u8) + seed(3×u64)/parents(2×u32) + R_com(32B) + nPC(u64) + PC[](32B each)
    nC0(u64) + c0[](Fp)
    nEdges(u64) + Edge[]:
      layer_id(u32) + idx(u16) + ch(u8) + nW(u64) + w[](Fp) + sigma(BitVec)
```

### 61. FORMULA-VS-FORMULA ATTACK STRATEGY

The equation `plain = c0 + Σ(S_l/R_l)` has:
- S_l values: PUBLIC (known)
- R_l values: SECRET (unknown)
- 1 equation per ciphertext, L unknowns per ciphertext

**Attack vectors from equation structure:**
1. If only 1 BASE layer: R is directly solvable IF plaintext is guessed
2. PROD layers: R_prod = R_a × R_b reduces independent unknowns
3. Cross-cipher constraints: if different ciphertexts share BASE layer seeds → shared R
4. GF(2) vs GF(p) mixing: R computed in GF(2) via LPN, used in GF(p) for division
5. Multi-edge per layer: 20 edges → 1 constraint, but only 1 unknown (R) per layer

**CRITICAL OPEN QUESTION**: Does the main challenge (secret.ct) have layers with shared seeds across ciphertexts? If YES → system of equations may be over-determined → solvable!

### 62. PARSER STATUS — FULLY WORKING!

- bounty2: FULLY PARSEABLE AND VERIFIED (eq_final.cpp)
- secret.ct: **FULLY PARSED** (full_parse_v2.py) — ALL 22 ciphertexts!
- **V3 format key difference: NO R_com field!** (dropped in version 3)
- ct_len in bundle = data bytes (PVAC header 6B is EXTRA)
- bitvec in v3: nbits(u64) + nwords(u64) + data[] (extra nwords field vs bounty_test)

### 63. SECRET.CT FULL STRUCTURE

| CT | Layers | BASE | PROD | Edges | c0 | Edges/L0 | Edges/L1 |
|----|--------|------|------|-------|----|----------|----------|
| 0  | 2      | 2    | 0    | 43    | 0  | 22       | 21       |
| 1  | 2      | 2    | 0    | 47    | 0  | 24       | 23       |
| 2  | 2      | 2    | 0    | 54    | 0  | 27       | 27       |
| ... | 2     | 2    | 0    | ...   | 0  | ...      | ...      |
| 21 | 2      | 2    | 0    | 119   | 0  | 61       | 58       |

KEY FACTS:
- ALL 22 ciphertexts have exactly 2 BASE layers, 0 PROD
- ALL c0 = 0
- NO seeds shared across ciphertexts (44 unique seeds)
- Edge count GROWS with cipher index (43→119), consistent with depth_hint increment in enc_text()
- Edges ~evenly split between L0 and L1

### 64. EQUATION SYSTEM STATUS

System: 22 equations, 44 unknowns → UNDERDETERMINED (factor 2)

Each equation: `plain_i = S_i0 / R_i0 + S_i1 / R_i1`

ADDITIONAL CONSTRAINTS NOT YET EXPLOITED:
1. **CT[0] plaintext is a SMALL INTEGER** (message length ≤ 315)
2. **CT[1..21] plaintexts are 15-byte ASCII text** packed into Fp
3. Each R is computed from SAME prf_k + s → all 44 R values determined by ~4352 bits (prf_k=256 + s=4096)
4. R = R1 × R2 × R3 (product of 3 LPN-derived values) — potential algebraic constraint

### NEXT STEPS (Session 9):
1. Exploit CT[0] small-value constraint: if length is guessable (≤315), try each value
2. For each length guess: `length = S_00/R_00 + S_01/R_01` → 1 equation, 2 unknowns
3. ASCII constraint: CT[1..21] should decode to printable ASCII → R values must yield bytes 0x20-0x7E
4. Try plaintext guessing: "send X OCT to..." or "mnemonic: word1 word2..."
5. Cross-CT algebraic relationships from shared prf_k + s

### 65. LPN SAMPLE FILES DISCOVERED (BIGGEST BREAKTHROUGH!)

Dev added `lpn_samples/` directory to hfhe-challenge with **44 JSONL files**!
File naming: `ct{XX}_l{Y}_s0_pvac_prf_r_1.jsonl` (one per BASE layer)

Each file:
- Line 0: Header with metadata (format, n, t, tau, seed info, public_T_hex)
- Lines 1-16384: LPN samples with fields:
  - `i`: sample index (0..16383)
  - `y`: **THE LPN OUTPUT BIT** (0 or 1)
  - `a`: **THE MATRIX ROW** as hex string (4096 bits = 512 bytes)

LPN Parameters:
- format: "octra-bounty-target-seed-lpn-ay-v1"
- dom: "pvac.prf.r.1" (R1 domain of prf_R_core)
- n=4096, t=16384, tau=1/8
- 44 files × 16384 samples = **720,896 total LPN samples**
- **ALL share the SAME secret s** (4096-bit LPN secret)

DEV HINT: "Pemulihan S merupakan target kriptanalisis tambahan"
(Recovery of S is an additional cryptanalysis target)

Also found: `verify_lpn_sample_binding.cpp` — tool to verify that LPN samples
match ciphertext metadata (seed, nonce, public_T = our S_l values)

### 66. ATTACK PATH: LPN → s → R → DECRYPT

If we recover LPN secret `s`:
1. s + prf_k → compute prf_R for any seed → all 44 R values
2. With all R values: `plain_i = c0_i + S_i0/R_i0 + S_i1/R_i1` → decrypt all 22 CTs
3. dec_text() → recover wallet/mnemonic

BUT: LPN with n=4096, tau=1/8 has estimated complexity 2^341 (from Code_estimators)
HOWEVER: Dev is GIVING us the samples — maybe the parameters or structure are weak?

**NOTE on V3 format correction**: V3 cipher layers have NO R_com (32B) field.
The layer format is: rule(u8) + seed(3×u64) + nPC(u64) + PC[](32B×nPC)

### REAL NEXT STEPS:
1. **Run LPN complexity estimator** with exact params (n=4096, tau=1/8, t=720896)
2. **Check if multiple LPN instances (44 files, same s) help** — multi-instance LPN
3. **Try BKW/Gaussian elimination** with noise filtering
4. **Investigate if prf_k can be bypassed** — samples are for domain "pvac.prf.r.1" only
5. **Check if there's a pattern in y bits** that reveals structure

---

## SESSION 9 (July 22, 2026) — LPN SOLVING ATTEMPTS & KEYGEN ANALYSIS

### 67. LPN SOLVING — ALL STANDARD METHODS FAILED

Attempted:
| Method | Result | Details |
|--------|--------|---------|
| GF(2) Gaussian elimination (random subsets) | ~50% match (random) | 20 trials, all give random s |
| Iterative GE + error correction | ~50% match | 50 trials, filtering doesn't help |
| Sparse secret (HW=1 test) | ~50.98% best | s is NOT sparse, full-weight like bounty2 |
| BKW feasibility | INFEASIBLE | Noise doubles per round: tau=0.125→0.219→0.342→0.450→0.495 |

**CONCLUSION**: Standard LPN with n=4096, tau=1/8 is computationally infeasible.
All known attacks require 2^300+ operations. BKW can't reduce more than ~40 bits 
before noise overwhelms signal.

### 68. KEYGEN ANALYSIS

Two keygen modes exist:
1. `keygen()` — random (USED BY BOUNTY ARTIFACT per line 350 of hfhe_bounty_artifact.cpp)
2. `keygen_from_seed(wallet_privkey)` — deterministic from 32B wallet private key

`keygen_from_seed` chain:
```
wallet_privkey(32B) → SHA256("OCTRA_PVAC_MASTER_V1" + privkey) → master
  → SHA256("OCTRA_PVAC_TAG" + master) → canon_tag (in pk.bin, PUBLIC)
  → SHA256("OCTRA_PVAC_SK" + master) → SeedableRng → prf_k(256b) + lpn_s(4096b)
```

But bounty artifact uses `keygen()` (independent random prf_k and s), NOT keygen_from_seed.
So prf_k and s are INDEPENDENT. Recovering s does NOT help recover prf_k.

### 69. WHY s RECOVERY ALONE IS INSUFFICIENT

Even if we recovered s from LPN samples:
- We know y = As + e → we know ybits (already given in JSONL!)
- But R1 = hash(toep_127(T, ybits)) where T = toeplitz matrix
- T is derived from prf_k (256-bit, independent of s)
- R2, R3 need ybits for different domains (also need prf_k to generate A matrices)
- So BOTH s AND prf_k needed for decryption
- Total secret: 4352 bits (256 + 4096)

### 70. DEV HINT RE-ANALYSIS

Dev said: "Recovering S is an ADDITIONAL cryptanalysis target"
→ s recovery is SECONDARY, not the main attack
→ The main attack is "recovery of plaintext/wallet payload from secret.ct"
→ There must be a way to recover plaintext WITHOUT solving LPN

### 71. WHAT WE KNOW AND DON'T KNOW

KNOWN (PUBLIC):
- pk.bin: H matrix, powg_B[337], canon_tag, H_digest
- secret.ct: 22 ciphertexts, all parsed, S_l values computable
- LPN samples: 720,896 (A_i, y_i) pairs, ybits for domain "pvac.prf.r.1"
- Plaintext structure: CT[0]=length, CT[1..21]=15-byte ASCII chunks

UNKNOWN (SECRET):
- prf_k: 256 bits (independent random)
- lpn_s_bits: 4096 bits (LPN secret, full weight ~2048)
- R values: 44 Fp values (each derived from prf_k + s + seed)
- Plaintext: the wallet private key + metadata

### NEXT APPROACH TO TRY:
Focus on the HFHE structure itself (not LPN):
1. Re-examine if homomorphic operations (ct_mul, ct_square) leak info  
2. Check if the edge structure reveals R through algebraic relations
3. Study if delta noise values are predictable from public data
4. Look for bugs in the commitment/binding verification
5. Try to exploit the text encoding structure (15-byte blocks)

---

## SESSION 9 CONTINUED (July 22-23, 2026) — BOUNTY2 TRAINING GROUND

### 72. BOUNTY2 FILE FORMAT (NATIVE, NOT PVAC)

bounty2 uses its OWN serialization from `tests/bounty2_test.cpp`, NOT `pvac_artifact_serialize.hpp`.

```
Magic constants: CT=0x66699666, PK=0x06660666, SK=0x66666999, VER=1

SK format: magic(u32) + ver(u32) + prf_k[0..3](4×u64) + lpn_count(u64) + lpn_s_bits[](n×u64)
CT format: magic(u32) + ver(u32) + n_cts(u64) + [per ct: nL(u32) + nE(u32) + layers + edges]
PK format: magic(u32) + ver(u32) + m_bits(u32) + B(u32) + lpn_t(u32) + lpn_n(u32) + 
           lpn_tau_num(u32) + lpn_tau_den(u32) + noise_entropy_bits(u32) + depth_slope_bits(u32) +
           tuple2_fraction(f64 as u64) + edge_budget(u32) + canon_tag(u64) + H_digest(32B) +
           H_count(u64) + H[](bitvecs) + perm_count(u64) + perm[](i32s) + inv_count(u64) + 
           inv[](i32s) + omega_B(Fp) + powg_count(u64) + powg_B[](Fps)
Layer BASE: rule(u8=0) + ztag(u64) + nonce_lo(u64) + nonce_hi(u64)
Layer PROD: rule(u8=1) + pa(u32) + pb(u32)
Edge: layer_id(u32) + idx(u16) + ch(u8) + pad(u8) + w(Fp) + sigma(BitVec)
  NOTE: Edge.w is SINGLE Fp in bounty2 format (putFp(o, e.w)), but current struct has vector<Fp>
BitVec: nbits(u32) + words[ceil(nbits/64)](u64 each)
Fp: lo(u64) + hi(u64)
```

hfhe-challenge/secret.ct uses DIFFERENT format: `OCTRA-HFHE-BTY02` (16-byte magic).
Main challenge ciphertext parsed differently from bounty2.

### 73. BOUNTY2 DECRYPT RESULTS (b2_full.cpp)

Successfully compiled and ran full decryption pipeline with known sk.bin:
```
pk: B=337, m_bits=8192, lpn_n=4096, canon_tag=0xe40f940644be5578
sk: prf_k=[0x0e7cedbf86286e2e, 0xf8adb2a16b2d1e28, 0xdad108b1c99cc831, 0x1d69d98715ec5c29]
sk: lpn_s HW=2051/4096

a.ct: 2 layers, 40 edges (20 per layer)
Layer 0: R = 0x00818f19329b59cac130c61be668d523
         R1*R2*R3 = R ✓
Layer 1: R = 0x3f3534dcb6b2dba77733334b9bd954bf
```

🔥 **CRITICAL FINDING: DELTA IS EXACTLY ZERO**
```
Manual Σ(T/R) + c0 = dec_value EXACTLY
diff (dec - manual) = 0x0000...0000
```
This means: `dec_values()` = `c0 + Σ(±w*g^idx / R)` with NO noise correction needed!
Either delta is zero for depth-0 CTs, or delta is incorporated into the edge weights.

**BUT**: dec_value(a) = 674892774807482974, NOT 1 as expected from source (a=1, b=2).
Possible causes:
1. sk.bin may not match published pk/ct (sk.bin not listed in README checksums)
2. Edge.w format mismatch (single Fp vs vector<Fp>) causing parsing issues  
3. Code has changed since artifacts were generated ("ndt - new fix 3 Jul 2026")

### 74. KEY STRUCTURAL FINDINGS

**Decryption equation (VERIFIED):**
```
plaintext = c0 + Σ_layers Σ_edges (±w × g^idx) / R_layer
         = c0 + Σ_layers T_layer / R_layer
where T_layer = Σ_edges_in_layer (±w × g^idx)  [PUBLIC, computable]
```

**No delta noise**: At least for depth-0, the decryption is EXACT.
This is important because it means: for the main challenge,
`plaintext_i = Σ(T_i_l / R_i_l)` EXACTLY (since c0 is empty/zero).

**Edge weight structure**: Each edge w = coef × R_layer.
Within a layer, all edge weights share the SAME R factor.
So w_i / w_j = coef_i / coef_j (R cancels).
But coefficients are random (7 of 8) + 1 forced. Not helpful directly.

### 75. APPROACHES CONFIRMED DEAD (DO NOT REPEAT)

| # | Approach | Why Dead |
|---|----------|----------|
| 1 | Solve LPN for s (GE/BKW/ISD) | n=4096, tau=1/8 → 2^300+ ops |
| 2 | Sparse secret | s is full-weight HW≈2048 |
| 3 | Iterative GE + error correction | Always converges to 50% |
| 4 | Recover prf_k from s | Independent random (keygen() used) |
| 5 | Use keygen_from_seed chain | Bounty uses keygen(), not keygen_from_seed |
| 6 | ybits → R without prf_k | Toeplitz is universal hash, ybits alone useless |
| 7 | All approaches in KB sections 11, 12, 15 | See those sections |

### 76. WHAT HASN'T BEEN TRIED YET

🔴 HIGH PRIORITY (HFHE-connected):
1. **Verify delta=0 holds for the MAIN CHALLENGE** (depth 0-22 CTs)
2. **Use bounty2 with CORRECT sk to fully verify pipeline** — need to regenerate 
   bounty2 artifacts from bounty2_test.cpp to get matching sk
3. **Analyze synth() noise generation** — understand exactly when delta≠0
4. **Check enc_text vs enc_value** — main challenge uses enc_text which packs 15-byte chunks

🟡 MEDIUM PRIORITY (algebraic):
5. **GCD/factorization of T values** — T = R × va, if va has special structure for ASCII text
6. **Cross-CT analysis** — 22 CTs encrypt related data (chunks of same wallet key)
7. **Analyze prf_R_core internals for bias** — maybe the LPN → Toeplitz → hash pipeline 
   has statistical bias that accumulates over 44 layers

🟢 TOOLS BUILT:
- `b2_full.cpp` — Bounty2 decrypt with R analysis (WORKING, uses native format)
- `lpn_sparse.cpp` — Sparse secret test (confirmed full-weight)
- `lpn_solve2.cpp` — Iterative GE (confirmed ~50%)

### 77. FILE LOCATIONS
- b2_full.cpp: `scratch/b2_full.cpp` → builds at `~/pvac_work/pvac_hfhe_cpp/build/b2_full`
- bounty2 data: `~/pvac_work/pvac_hfhe_cpp/bounty2_data/`
- Main challenge: `~/pvac_work/pvac_hfhe_cpp/hfhe-challenge/`

### 78. 🔥 CRITICAL MATH BREAKTHROUGH: T = R × v EXACTLY (NO NOISE)

**VERIFIED**: Regenerated bounty2 with matching sk → dec_value(a) = 1 ✓

**PROOF that T/R = v (exact, no noise)**:

In `synth()` (encrypt.hpp):
```
1. delta.agg = Σ delta_i   (sum of noise scalars, random Fp values)
2. va = v - delta.agg       (adjusted plaintext)
3. Signal edges: Σ(±coef_i × g^idx_i) = va  (sums to adjusted value)
4. N2 noise pair (idx a, b): 
   - ra = random
   - rb = (ra * g^a - delta_i) / g^b
   - T contribution: sgn²(sa) × R × delta_i = R × delta_i
5. Signal + Noise: T = R × va + R × Σ delta_i = R × (va + delta.agg) = R × v
```

**Result**: `T_l = R_l × v_l` EXACTLY for every layer.

**For V2 wrapping (2 layers)**:
```
T[0] = R0 × (v + m)       ← mask added to plaintext
T[1] = R1 × (-m)          ← mask negation
T[0]/R0 + T[1]/R1 = (v+m) + (-m) = v   ← mask cancels, v EXACT
```

**Implications**:
- Noise edges are NOT for correctness but for sigma vector obscuring
- T/R = v is exact, so there is ZERO decryption error in PVAC
- All 44 layer T values in main challenge satisfy T_l = R_l × v_l EXACTLY
- If v has special structure (e.g., ASCII text packed as Fp), T inherits that structure multiplied by R

### 79. BOUNTY2 PIPELINE FULLY VERIFIED

```
a=1: dec_value = 1 ✓  (manual Σ(T/R) = 1 ✓)
b=2: dec_value = 2 ✓
a+b: sum.ct has 4 layers, decrypts correctly
lpn_s HW = 2047/4096 (near 50% as expected)
R1*R2*R3 = R ✓ for all layers
```

Edge.w was changed from `Fp` to `vector<Fp>` after bounty2 was created.
Fixed by: `putFp(o, e.w)` → `putFp(o, e.w[0])` and `e.w = getFp(i)` → `e.w = {getFp(i)}`

### 80. ATTACK IDEAS FROM T = R × v

Since T = R × v:
1. **GCD attack**: For V2 wrapping, T[0] = R0(v+m), T[1] = R1(-m). 
   GCD(T[0], T[1]) in Fp? Not meaningful — Fp is a field, every nonzero element divides every other.
   
2. **Factorization**: T = R × v in GF(P). If v is "small" (< 2^120 for ASCII), 
   then T = R × v where v has 120-bit magnitude and R has 127-bit magnitude.
   Finding (R, v) from T is equivalent to "partial approximate GCD" or "short vector in lattice."
   
3. **Lattice attack on T**: If plaintext v is short (small as integer), then T ≡ 0 (mod v).
   Finding short v such that R = T/v is in valid range... this is a lattice problem!
   
4. **Multi-CT constraint**: For CT[0], v ∈ [1, 315]. T = R × v, so T ≡ 0 mod v.
   Test each v: R_candidate = T / v_candidate. But which T? 
   V2 wrapping: T0/R0 + T1/R1 = v. Two unknowns (R0, R1), one equation.
   UNLESS T0 and T1 have a structural relationship via the mask m...

5. **Mask elimination**: T0 = R0(v+m), T1 = R1(-m).
   T0/R0 = v+m, T1/R1 = -m → T0/R0 + T1/R1 = v
   Also: m = -T1/R1, so T0/R0 = v - T1/R1 → T0*R1 = R0*R1*v + T1*R0
   This gives: T0*R1 - T1*R0 = R0*R1*v
   Still 3 unknowns (R0, R1, v), 1 equation.

### 81. MAIN CHALLENGE STRUCTURE (FULLY PARSED)

secret.ct format: `OCTRA-HFHE-BTY02` magic (16B) + n_cts(u64=22) + per-CT: len(u64) + PVAC blob

All 22 CTs have **identical structure**:
- ver=3, slots=1, nL=2 (V2 wrapping), c0=0
- 2 BASE layers per CT (NO PROD layers!)
- nPC=1 per layer (single Pedersen commitment)
- All R values INDEPENDENT (44 unique seeds)

Edge counts per CT:
```
CT[0]=43, CT[1]=47, CT[2]=54, CT[3]=56, CT[4]=57, CT[5]=67, CT[6]=68,
CT[7]=72, CT[8]=67, CT[9]=80, CT[10]=80, CT[11]=84, CT[12]=94, CT[13]=92,
CT[14]=96, CT[15]=95, CT[16]=108, CT[17]=105, CT[18]=109, CT[19]=116,
CT[20]=120, CT[21]=119
Total: 1829 edges across 44 layers
```

**System of equations**:
- 22 equations: v_i = T[i,0]/R[i,0] + T[i,1]/R[i,1]
- 44 unknowns: R values (each 127-bit Fp)
- 22 unknowns: v values (plaintext chunks)
- Under-determined: 66 unknowns, 22 equations

**Plaintext constraints**:
- CT[0]: v = length byte (1-255), VERY small
- CT[1..21]: v = 15-byte ASCII chunk, max ~120 bits
- All printable ASCII: bytes in [0x20, 0x7E]

### 82. 🔥 VERIFY_LPN_SAMPLE_BINDING.CPP — DEEP ANALYSIS

**Source**: `hfhe-challenge/source/tools/verify_lpn_sample_binding.cpp`

**What it does**: Verifies that LPN samples are BOUND to specific layers of secret.ct by matching:
- `seed_ztag` = layer.seed.ztag
- `nonce_lo_hex` = layer.seed.nonce.lo
- `nonce_hi_hex` = layer.seed.nonce.hi
- `public_T_hex` = Σ(±w × g^idx) for that layer = T value

**Key function `public_layer_aggregate`**: Computes T = Σ(±w[slot] × powg_B[idx]) for a given layer.
This is the SAME T that we proved equals R × v.

**LPN sample structure**:
```
44 files (22 CTs × 2 layers), ALL domain "pvac.prf.r.1" (R1 only)
16384 samples per file = 720,896 total
Each sample: {i: index, y: 0/1, a: hex(4096 bits)}
y = <a, s> XOR e, where e ~ Bernoulli(1/8)
ALL 44 files use the SAME secret s (confirmed)
```

**CONFIRMED BINDING**: LPN sample metadata (ztag, nonce) matches CT layer seeds exactly.
CT[0] L0 ztag = 0x5934e19cfa03c47a matches sample seed_ztag = 6428010632490239098.

### 83. PRF_R_CORE PIPELINE (FULLY MAPPED)

```
prf_R_core(pk, sk, seed, dom):
  1. ybits = lpn_make_ybits(pk, sk, seed, dom)
     → A matrices from PRG(seed + dom), y = As + e
     → LPN samples give us (A_i, y_i) for dom="pvac.prf.r.1"
  
  2. toep_key = derive_aes_key(pk, sk, seed, Dom::TOEP)
     → Uses prf_k (UNKNOWN, 256-bit)
     → toep_nonce ^= fnv1a_domain(dom)
  
  3. top = AES-CTR(toep_key, toep_nonce)
     → Generates Toeplitz matrix row
  
  4. result = hash_to_fp(toeplitz_127(top, ybits))
     → 127-bit output

R = R1 × R2 × R3 (three independent evaluations with different domains)
```

**What s recovery gives us**:
- Can compute ybits for ALL domains (r.1, r.2, r.3) for ALL 44 layers
- Because ybits = As + e, and A is derived from seed+dom (public), only s is secret
- BUT still need toep_key (from prf_k) to compute R

**What we DON'T have**:
- prf_k (256-bit, generates Toeplitz matrix)
- LPN samples for R2 ("pvac.prf.r.2") and R3 ("pvac.prf.r.3")

### 84. DEV HINT RE-ANALYSIS (UPDATED)

Dev hint (from image): 
> "Pemulihan S merupakan target kriptanalisis tambahan; syarat utama hadiahnya
> tetaplah pemulihan teks biasa/muatan dompet dari secret.ct"

Translation: "S recovery is additional cryptanalysis target; main prize requirement
is plaintext/wallet payload recovery from secret.ct"

**This means**:
1. There IS a way to recover plaintext WITHOUT solving LPN for s
2. s recovery is a BONUS target, not the main attack path
3. The main vulnerability is in the HFHE structure itself
4. verify_lpn_sample_binding.cpp was added as a tool — dev wants us to USE it

**Questions this raises**:
- If not through s, how can we recover plaintext?
- Does the binding between LPN samples and CTs create an exploitable relationship?
- Is public_T_hex = T = R × v the key leverage point?
- Can we use the fact that ALL 44 LPN sample sets share the SAME s?

### 85. SESSION 10: MULTI-ATTACK RESULTS (July 23, 2026)

**Tool**: `attack_T.cpp` — 6 attacks on T values

#### Attack 1: Edge Collision — 56 COLLISIONS FOUND
- Same idx, opposite ch pairs found across most CTs
- Weight ratios (coef_i/coef_j) all look full-range random
- R² extraction NOT feasible: coef product unknown, ratio is random
- **CONFIRMED DEAD** for R extraction

#### Attack 2: GCD of T Values
- GCD(T[0,L0], T[1,L0]) = 4 (small)
- GCD(T[1,L0], T[2,L0]) = 1
- No common large factors → T values are "coprime-like"
- **DEAD END**

#### Attack 3: Minimum Weight Bit-Length
- All CTs: min weight ≈ 121 bits (out of 127)
- Weights are full-range, no evidence of small R values
- **DEAD END**

#### Attack 5: Weight Ratios
- All coef ratios look uniformly random in Fp
- No small integer ratios found
- Signal/noise edges CANNOT be distinguished by weight ratios
- **DEAD END**

#### Attack 6: 🔥 PLAINTEXT LENGTH DISCOVERY
- 22 CTs = 1 length CT + 21 data CTs
- enc_text packs 15 bytes per CT
- **Plaintext length L ∈ [301, 315] bytes**
- This is WAY longer than a wallet private key (44-52 chars)
- Manifest says: "follow the recovered instructions"
- **Plaintext = instructions text + wallet private key**
- All printable ASCII (English instructions + base58 key)

### 86. PEDERSEN COMMITMENT ANALYSIS (DEEP DIVE)

```
PC[j] = R_inv_j * G + rho_j * H
```
Where:
- R_inv_j = fp_inv(R[j]) — inverse of layer R value
- rho_j = SHA256(PRF_RHO + prf_k + nonce + slot)
- G, H = Ristretto255 generators

**PC commits to R_inv**, not v. Even with PC, cannot extract R without rho (blinding).
rho depends on prf_k (256-bit secret). **DEAD END**.

**Algebraic relation**: T0*PC0 + T1*PC1 = v*G + (T0*rho0+T1*rho1)*H
This gives a Pedersen commitment on v, but cannot open without rho_combined.

### 87. R_COM DOES NOT BIND R (CONFIRMED AGAIN)

```
R_com = SHA256("pvac.dom.r_com" + canon_tag + ztag + nonce_lo + nonce_hi + len)
```
R values are NOT included in R_com hash! Only public metadata.
This was BUG-001 but doesn't help for decryption.

### 88. V2 MASK ANALYSIS

```
m = rand_fp_nonzero()  // truly random, full 127-bit
T0 = R0*(v+m), T1 = R1*(-m)
```
Mask m is independent per CT, from CSPRNG. No structure exploitable.
Each CT has 3 unknowns (R0, R1, m) per equation pair → underdetermined.

### 89. APPROACHES CONFIRMED DEAD THIS SESSION

1. ❌ Edge collision R² extraction (56 collisions, all random ratios)
2. ❌ GCD of T values (coprime)
3. ❌ Small weight / small R (all full-range)
4. ❌ Weight ratio distinguisher (all random)
5. ❌ Pedersen commitment opening (needs rho from prf_k)
6. ❌ R_com R binding (doesn't include R)
7. ❌ V2 mask structure (truly random)

### 90. 🔥 LPN SAMPLES = YBITS FOR R1 (CONFIRMED)

**Key realization**: LPN sample y values ARE the ybits used in prf_R_core!

```
lpn_make_ybits(pk, sk, seed, "pvac.prf.r.1"):
  AES key = derive_aes_key(pk, sk, seed, "pvac.prf.r.1")
  For each row r=0..16383:
    A_row = AES-CTR(key, nonce) → SAME rows as in LPN samples
    y_r = <A_row, s> ⊕ e_r
  Return ybits = [y_0, y_1, ..., y_16383]
```

LPN samples give us exactly these (A_r, y_r) pairs.
So **ybits_R1 is KNOWN** (directly from LPN sample y values)!

**BUT**: Still need toep_key to compute R1:
```
R1 = hash_to_fp_nonzero(toep_127(top_R1, ybits_R1))
top_R1 = AES-CTR(toep_key, toep_nonce ^ fnv1a("pvac.prf.r.1"))
toep_key = derive_aes_key(pk, sk, seed, "pvac.prf.toep")
```
toep_key depends on prf_k (256-bit secret). Cannot compute R1 without it.

**What we know**: ybits_R1 (16384 bits, with ~12.5% noise from LPN error)
**What we don't know**: toep_key, top_R1, R1, R2, R3, v, m

### 91. TOEPLITZ HASH IS THE BARRIER

The PRF pipeline: LPN → Toeplitz → hash_to_fp → R

Even with ybits known:
- toep_127(top, ybits) = GF(2) polynomial multiplication
- top = AES-CTR(toep_key, toep_nonce) → 16511 bits
- Without top, ybits → R is random mapping
- top for R1/R2/R3 use SAME toep_key but different nonces
- AES-CTR output with different nonces → independent

**To bypass Toeplitz, would need**:
1. Recover toep_key (from prf_k) — 256-bit, infeasible
2. Find algebraic relation between ybits and T values — blocked by hash_to_fp
3. Side-channel on AES-CTR — not applicable (offline challenge)

### 92. REMAINING UNEXPLORED VECTORS (UPDATED)

After 90+ entries and 40+ dead ends, remaining ideas:
1. **Quantum/lattice reduction on the Toeplitz hash** — theory only
2. **Multi-instance LPN correlation** — 44 instances, same s, different A
3. **plaintext structure exploitation** — 301-315 bytes printable ASCII
4. **Revisit "fundamentally broken"** — dev said not connected to HFHE
5. **Check if ybits has structure** from noise that leaks through Toeplitz

### 93. SESSION 11: COMPETITOR ANALYSIS + FINAL VECTORS (July 24, 2026)

#### smoke-ui Assessment Findings
- Competitor (smoke-ui) conducted independent assessment with:
  - Z3 SMT solver, AFL++ fuzzer, Valgrind, ASan/UBSan
  - Entropy fault injection, parser differential testing
- **RESULT: No plaintext recovery achieved**
- Confirmed plaintext 301-315 bytes (same as us)
- **V2 wrapping mathematically proven secure at toy primes**:
  - With independent random masks, ALL candidate plaintexts are satisfiable
  - This is information-theoretically unbreakable without R
- LPN: No practical recovery route found

#### L8: bounded() noise generation — DEAD
- Rejection sampling: `lim = UINT64_MAX - (UINT64_MAX % 8)`
- P(e=1) = exactly 1/8, zero bias

#### L9: public_audit functions — DEAD
- `public_zero_regression()` uses FRESH keys, no leak
- `mixed_H_parity()` only checks public pk data
- No information leakage from any audit function

#### L10: compressed pk.bin format — DEAD
- Custom adaptive range coder, lossless, no crypto
- pk.bin uncompressed = 17,112,502 bytes (mostly H matrix)

#### L11: Noise pair/triple identification — DEAD
- 0 N2 pairs (w+w'=0) found in secret.ct
- 0 N3 triples found
- merge operation destroyed all noise structure

#### Edge Count Analysis
- Edge counts deterministic by depth_hint, NOT by plaintext
- CT[0] depth=0: 43 edges, CT[21] depth=21: 119 edges
- Secret.ct and selftest have statistically identical edge counts

### 94. MATHEMATICAL IMPOSSIBILITY ASSESSMENT

Per smoke-ui SMT analysis at toy primes:
- V2 wrapping: with independent masks, EVERY candidate v satisfies the equations
- This means: **T0 = R0*(v+m), T1 = R1*(-m) reveals ZERO bits about v**
- Attack requires knowing R (which requires prf_k or solving LPN for s + finding toep_key)
- LPN solving: 2^341 complexity, infeasible
- prf_k: 256-bit, brute force infeasible

**Conclusion per framework**: 
```
Status: belum ada jalur profit >0 ter-reproduce
Coverage: 94 KB entries, 50+ attack vectors tested
  - All crypto primitives verified sound
  - V2 wrapping information-theoretically secure
  - LPN computationally infeasible (2^341)
  - prf_k brute force infeasible (2^256)
  - Competitor independently confirmed same conclusion
Remaining vector: "fundamentally broken" dev hint
  - NOT connected to HFHE per dev statement
  - May refer to PVAC design philosophy, not this specific challenge
```

### 95. SESSION 12: HOMOMORPHIC OPS + STRUCTURAL CHECKS (July 24, 2026)

#### Surprise Check Results
- **c0 values**: ALL ZERO across all 22 CTs ✓ (expected)
- **R_com in raw bytes**: NOT all-zero (0 all-zero 32-byte windows). R_com has data but likely public metadata hash
- **omega_B = powg_B[1]^24**: Different root of unity but gcd(24,337)=1, so still primitive. NOT a bug
- **H matrix**: All 16384 columns unique, weight 192-193 (exactly h_col_wt). Full rank
- **UBK perm**: NOT identity (proper permutation applied)

#### Homomorphic Operations Attack Results
1. **ct_square(CT[1])**: 5 layers (2 BASE T=0, 3 PROD with T=products of original T). PROD T = deterministic function of known T values
2. **ct_add(CT,CT)**: Layer concatenation, NOT merge. T values duplicate, not sum
3. **ct_sub(CT,CT) = enc(0)**: 4 layers, ALL non-zero T values → V2 wrapping prevents zero detection ✓
4. **ct_mul(CT[1],CT[2])**: 8 layers (4 BASE + 4 PROD). PROD T = cross-products of BASE T values
5. **ct_add_const sweep**: PROD_T_sum UNCHANGED by constant c → c0 doesn't affect edge structure

**CONCLUSION**: Homomorphic operations produce NO new information. All T values are deterministic functions of already-known BASE T values.

#### Git History Check
- v1: `seed.ct` (235KB) + `hfhe_seed_artifact.cpp` — already in KB Section 22
- v2: `secret.ct` (1.96MB) + `hfhe_bounty_artifact.cpp` — different plaintext/key
- pk.bin size matches between v1 and v2 commits — already investigated

### 96. TOTAL DEAD END COUNT: 55+

All vectors from KB 23.9 "REMAINING UNEXPLORED" now resolved:
1. ~~#499 hidden_coeff~~ → checked, not exploitable
2. ~~#503 rist_decode~~ → checked, not exploitable  
3. ~~#501 R² leak~~ → checked, coef product unknown
4. ~~LPN coupling~~ → bounded() has zero bias
5. ~~Toeplitz invert~~ → needs key
6. ~~Multi-instance~~ → 720k << 2^341
7. ~~rist_H() dead code~~ → Ristretto H correct
8. ~~merge w=0 sigma≠0~~ → 0 zero-weight edges found
9. ~~Homomorphic ops~~ → no new information produced (this session)

### 97. BLOCKCHAIN + WALLET FORMAT ANALYSIS

#### Octra Network Infrastructure
- **RPC endpoint**: `https://octra.network/rpc` (JSON-RPC)
- **Explorer**: `https://octrascan.io` (live mainnet)
- **Webcli repo**: `https://github.com/octra-labs/webcli`
- **CoinMarketCap ID**: 39914 (OCT has market price)

#### Bounty Address: `octC5eR9pLGKbpzTbDgHowkFt8HW7LZYb2gzehzxHamxuAZ`
- RPC balance query returns 429 (rate limited) — needs retry with backoff
- Address format: "oct" + base58 encoding of 32-byte Ed25519 public key
- Total address length: 44 characters

#### Wallet/Key Format (from webcli source)
- **Private key**: Ed25519 via TweetNaCl — sk[64] bytes
- **Public key**: pk[32] bytes  
- **Storage**: base64-encoded (`priv_b64`)
- **Mnemonic**: BIP39 wordlist support (HD wallet)
- **HD derivation**: supported (hd_version=1, hd_index)

#### Plaintext Format Constraint (REFINED)
README says plaintext = "private key and metadata associated with the address"
So plaintext likely contains:
1. Ed25519 private key (64 bytes raw or 88 chars base64)
2. Address string (44 chars)  
3. Metadata (instructions to claim reward)
Total: 301-315 bytes, printable ASCII

#### RPC Methods Available
- `octra_balance` — get address balance
- `octra_transactionsByAddress` — get tx history
- `octra_submit` — submit transaction
- `node_status`, `node_stats`, `octra_supply` — network info

#### TODO
- [x] Query balance — **500,001.000001 OCT** + 2M Penguplush tokens
- [x] Check if bounty wallet has any transactions — YES, 5 incoming, 0 outgoing
- [ ] Study webcli keygen to understand exact plaintext encoding
- [ ] Investigate unlock_trusted() contract call
- [ ] Study developer address octC9DGJX...

### 98. ON-CHAIN ANALYSIS RESULTS (Camofox browser)

#### Balance: 500,001.000001 OCT + 2,000,000 Penguplush
#### Nonce: 0 (never signed a tx — private key has NEVER been used to send)

#### Transaction History (5 total, all incoming):
1. **+1 OCT** from octC9DGJ... (epoch 1327831, July 10 12:52)
2. **1M Penguplush transfer** from octC9DGJ... (epoch 1325599, July 10 06:30)
3. **1M Penguplush transfer** from octC9DGJ... (epoch 1325597, July 10 06:29)
4. **unlock_trusted()** from octCVXhf... → oct6Nqof... (epoch 1325113, July 10 05:06) — SMART CONTRACT CALL
5. **+500K OCT** from oct7xCoz... (epoch 1319790, July 9 13:52) — INITIAL FUNDING

#### Key Observations:
- Developer address: octC9DGJX... (sent OCT + Penguplush)
- Funder address: oct7xCoz... (sent 500K OCT initial bounty)
- unlock_trusted() = circle/contract mechanism on Octra network
- Nonce=0 means private key has NEVER been used — any valid signature would be first ever

#### PVAC Webcli Source Findings:
- HFHE ciphertext prefix: "hfhe_v1|"
- Range proof prefix: "rp_v1|"
- Zero-knowledge proof prefix: "zkzp_v2|"
- pvac_dec_value returns Fp = {lo: uint64, hi: uint64} — plaintext is 128-bit number
- pvac_keygen_from_seed takes 32-byte seed
- pvac_enc_value_seeded takes uint64 val + 32-byte seed → deterministic encryption!

### 99. SMART CONTRACT ANALYSIS (unlock_trusted)

#### Contract: oct6NqofXkYwY382qAANAvRfk8WAJK5mikviiAA482nBJY4
- Type: program (smart contract)
- Owner: octCVXhfk2Ejvq7n1hzNpovgQo25tWsSTAT2F4ADmoYS73H
- Code hash: 15d224f7a37691f48cc155283eb03b9493581f49ac94167bf3bb86ac8350246d
- This is the **Penguplush token contract**

#### unlock_trusted() Call Details:
- Caller: octCVXhfk... (contract owner)
- Args: [bounty_address, 1000000, 0x4819026a31deb02c3f4f4f49408cf79934dd5a111f6d813ca498b96e883657b6]
- Event: Unlocked(bounty_addr, 1000000, 0x4819...)
- The 32-byte hex string is a **commitment or hash** tied to the bounty

#### CRITICAL INSIGHT: PLAINTEXT FORMAT
From pvac_c_api.cpp:
- pvac_dec_value returns Fp = {lo: uint64, hi: uint64}
- Plaintext is a 128-BIT NUMBER, not a text string
- The bounty README says "private key and metadata" but this must be encoded as Fp elements
- The plaintext could be the Ed25519 private key seed (32 bytes = 256 bits = 4 x uint64)
- OR the 32-byte hex from unlock_trusted (0x4819...)

#### HYPOTHESIS: The 32-byte value 0x4819026a... could BE the answer
- It was emitted on-chain in the unlock_trusted event
- It's exactly 32 bytes (seed size for PVAC keygen)
- If this IS the private key seed, then dec_value should produce it

### 100. EXACT PLAINTEXT ENCODING (CONFIRMED from source code)

**File**: `hfhe-challenge/source/hfhe_bounty_artifact.cpp`
**Plaintext source**: `plaintext.txt` (private, developer-only)
**Encryption function**: `enc_text(pk, sk, plaintext_string)`

#### enc_text encoding:
```
cts[0] = enc_value(msg.length())     // first CT = encrypted string length
cts[1] = enc_fp(bytes[0:15])         // 15 bytes per Fp block
cts[2] = enc_fp(bytes[15:30])
...
cts[N] = enc_fp(bytes[(N-1)*15:N*15])
```

#### Fp packing: `pack_15_bytes_to_fp`
- 15 bytes packed into Fp = {lo: uint64, hi: uint64}
- lo = bytes[0..7] (little-endian), hi = bytes[8..14] (little-endian)
- Only 120 bits used of 127-bit Mersenne field (2^127-1)

#### secret.ct has 22 ciphertexts:
- cts[0] = encrypted length (uint64)
- cts[1..21] = 21 data blocks × 15 bytes = **up to 315 bytes of plaintext**
- Actual length = cts[0] decrypted value

#### Winning condition from manifest.json:
"recover plaintext from secret.ct using public files only; **follow the recovered instructions**"

#### CONCLUSION:
Plaintext is ASCII text containing **instructions** (e.g., private key + how to claim reward)
The plaintext is NOT purely numeric — it's a human-readable text string

#### Address pubkey (confirmed):
oct + base58(pubkey) → pubkey = a4a12fb15de6fd821f9415a2ae23c9483cd80b0256f787d6765b0c7f4d41aef2
0x4819... from unlock_trusted is NOT the private key (tested, no match)

### 101. CIPHERTEXT STRUCTURE ANALYSIS (PARSED)

All 22 CTs parsed with native C++ deserializer:
- **All slots = 1**, all c0 = zero, all layers = 2 BASE (V2 wrapping)
- **Edge counts**: CT[0]=43, CT[1]=47, ..., CT[21]=119
- Edges grow with depth: Budget(d=0)→~43, Budget(d=22)→~119
- CT[0] = weakest (depth=0, only 43 edges), encrypts string LENGTH (1-315)
- V2 wrapping = fuse(enc(v+m), enc(-m)) → 2 BASE layers per CT

#### Budget model:
- depth 0: cap=128 bits → ~43 edges (8 sig + ~35 noise)
- depth 2: cap=160 bits → ~47 edges
- depth 22: cap=480 bits → ~119 edges

#### Attack surface:
- CT[0] encrypts a SMALL value (1-315) — easiest target for brute force
- But 43 edges with m=8192 columns still = massive search space
- 22 CTs share the same pk/sk — multi-CT constraint analysis possible?

### 102. DECRYPTION EQUATION & R_COM VULNERABILITY (CRITICAL)

#### Decryption equation (from decrypt.hpp):
```
plaintext = c0 + Σ sign(e) * w_e * powg_B[idx_e] * R_inv[layer(e)]
```
- c0 = 0 (from V2 wrapping)
- w_e, idx_e, sign(e) = PUBLIC (in ciphertext edges)
- powg_B[idx] = PUBLIC (in public key)
- **R_inv = ONLY SECRET** — derived from prf_R_slots(pk, sk, seed)

#### R derivation:
- R = r1 * r2 * r3 where ri = prf_R_core(pk, sk, seed, domain)
- prf_R_core uses LPN with sk, then Toeplitz hash
- LPN matrix is also sk-dependent (AES key from sk)

#### R_com DOES NOT hash R values!
```cpp
compute_R_com_base(canon_tag, ztag, nonce_lo, nonce_hi, R_slots) {
    SHA256("pvac.dom.r_com" || canon_tag || ztag || nonce_lo || nonce_hi || R_slots.size())
    // R_slots VALUES ARE NOT INCLUDED IN THE HASH!
}
```
**Verified**: R_com in stored ciphertext = all zeros (stripped/placeholder)

#### Sigma bitvector NOT used in decryption!
Edge has `e.s` (8192-bit bitvector) stored in ciphertext but decrypt code ignores it.
Sigma only matters for homomorphic operations, not for decrypt.

#### Simplified attack model:
For each CT with slots=1, 2 layers:
- plaintext = A * R0_inv + B * R1_inv
- A = Σ(layer-0 edges) sign(e) * w_e * powg_B[idx_e]  ← computable
- B = Σ(layer-1 edges) sign(e) * w_e * powg_B[idx_e]  ← computable
- R0_inv, R1_inv = unknowns (each ~127 bits)

CT[0]: plaintext = length (1-315)
- 1 equation, 2 unknowns → insufficient alone
- But 22 CTs × 2 unknowns = 44 unknowns total, all different R

