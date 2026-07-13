# 🔐 PVAC-HFHE Bounty — Research Log

> *"tell your machine to destroy it"*

---

## Status: `ACTIVE` 🟢

We are actively working on the [Octra HFHE Bounty](https://github.com/octra-labs/pvac_hfhe_cpp) challenge.
Commit target: `071b0e9`

**Days active**: 4 · **Scripts written**: 50+ · **Source files audited**: 25/25

---

## What We Know (Public Summary)

| Property | Value |
|----------|-------|
| Field | GF(2¹²⁷ − 1), Mersenne prime |
| Generator order | B = 337 (prime) |
| LPN parameters | n = 16384, m = 8192, τ = 1/8 |
| LPN noise weight | err_wt = 128, x_col_wt = 128, h_col_wt = 192 |
| Wrapping | V2 dual-layer (July 3 fix) |
| Wire format | `PVAC v3` (custom range-coded compression, tag `0xEC`) |
| CT blocks | 22 (1 length + 21 text chunks × 15 bytes) |
| Layers per CT | 2 (BASE + BASE, wrapped via `combine_ciphers`) |
| Pedersen Commitments | 44 unique, all valid Ristretto255 |
| Edge budget | 1,200,000 |
| Noise entropy | 128.0 bits |
| Depth slope | 16.0 bits/level |

---

## Fully Parsed Ciphertext Structure 📊

Every single CT block has been correctly deserialized and verified (`remaining=0`).

```
CT[ 0]: layers=2  edges= 43  (L0:22, L1:21)   depth=0   ← message length
CT[ 1]: layers=2  edges= 47  (L0:24, L1:23)   depth=1
CT[ 2]: layers=2  edges= 54  (L0:27, L1:27)   depth=2
CT[ 3]: layers=2  edges= 56  (L0:28, L1:28)   depth=3
CT[ 4]: layers=2  edges= 57  (L0:28, L1:29)   depth=4
CT[ 5]: layers=2  edges= 67  (L0:34, L1:33)   depth=5
...
CT[19]: layers=2  edges=116  (L0:56, L1:60)   depth=19
CT[20]: layers=2  edges=120  (L0:59, L1:61)   depth=20
CT[21]: layers=2  edges=119  (L0:61, L1:58)   depth=20
```

All `c0 = [0]`. All layers are `BASE` (no `PROD`). Edge count monotonically increases with depth.

---

## Extracted Public Key Parameters 🔑

Successfully decompressed `pk.bin` (3.0 MB → 17.1 MB) and extracted:

- `canon_tag = 0x760802093a19931`
- All 337 `powg_B` values verified: `powg_B[i] = g^i mod P`, `g^337 = 1 ✓`
- Full H matrix: 16384 columns × 8192-bit bitvecs
- UBK permutation: 8192 entries + inverse
- `omega_B^337 = 1 ✓`

---

## Computed Public Layer Targets (T values) 🎯

For each CT block, we computed:

```
T = c0 + Σ(±w × g^idx)   for each layer
```

All 44 T values (22 blocks × 2 layers) are non-zero, pseudo-random, 127-bit field elements. No obvious patterns in T₀/T₁ ratios or cross-block relationships.

> T values are the **public commitments** to `R × (v + mask ± δ)`.
> Without R, they don't reveal v directly.
> *Unless...?*

---

## Bug Discoveries 🐛

### BUG-001: `compute_R_com_base` — commitment without binding
- `R_com = SHA256(domain ‖ canon_tag ‖ ztag ‖ nonce ‖ n_slots)` — **R values never hashed**
- R_com is fully deterministic from public data, removed from V2 serialization

### BUG-002: `keygen` root exponent truncation (historical)
- `omega_B = fp_pow_u64(h, (uint64_t)E)` truncated 128-bit `E = (P−1)/337` to 64 bits
- Result: `omega_B^B ≠ 1`. Fixed in challenge commit with `// !!!!!!!!!!!` comment.

### BUG-003: Edge count asymmetry across layers
- After merge, L0 and L1 within same CT have different edge counts (e.g., CT[0]: 22 vs 21)
- Merge doesn't guarantee symmetric structure

### BUG-004: Sigma merge leaks XOR structure
- `merge()` XORs sigma vectors when edges collide at same `(layer, idx, sign)`
- Post-merge sigma = XOR of individual sigmas — **noise cancellation possible**

---

## Interesting Findings 🔍

### FINDING-001: Homomorphic operations are public-key-only
All 7 operations (`ct_add`, `ct_sub`, `ct_mul`, `ct_square`, `ct_scale`, `ct_add_const`, `ct_neg`) require **only pk**.
*Implication: redacted.*

### FINDING-002: Edge count encodes depth
CT[0] has **43 edges** (least noise). CT[21] has **119 edges** (most noise). Signal is constant at 8 edges/layer; noise scales linearly with `depth_slope_bits`.

### FINDING-003: Message length is 301–315 bytes
21 text chunks × 15 bytes/chunk → `ceil(length/15) = 21` → length ∈ `[301, 315]`.
This is *not* a standard BIP39 mnemonic (12w≈100B, 24w≈200B). Something larger.

### FINDING-004: Weight ratios cancel R
`w_i / w_j = coef_i / coef_j (mod P)` for edges in the same layer. R cancels.

### FINDING-005: N2 noise pairs have deterministic sign pairing
`sb = sa ⊕ 1` always. One `SGN_P`, one `SGN_M` per N2 pair.

### FINDING-006: Sigma HW analysis
All edge sigmas have HW ≈ 4096 ± 100 (of 8192 bits). Consistent with random.
Parity distribution: roughly 50/50.

### FINDING-007: `sigma_from_H` is publicly computable
`sigma_from_H(pk, seed, idx)` produces the public component of each sigma.
`edge.sigma ⊕ sigma_from_H = y_bits` — this is the **LPN instance**.
We have ~1,800 samples. Still insufficient for n=16384 LPN (need >n²).

### FINDING-008: PVAC uses custom compression
`pk.bin` is compressed with a custom **adaptive range coder** (tag `0xEC`), not LZ4/zstd. We ported the decompressor and also compiled the native C++ extractor.

---

## Approaches Tried

| # | Approach | Result |
|---|----------|--------|
| 1 | V1 low-bit leakage | ❌ Fixed in V2 wrapping |
| 2 | Sigma XOR pair identification | ❌ HW ≈ 4096 (random) |
| 3 | R_com verification oracle | ❌ Removed in V2 |
| 4 | LPN statistical attack | ❌ y-bits random |
| 5 | Direct LPN solving (BKW/ISD) | ❌ Est. 2^341 complexity |
| 6 | GCD/lattice on weights | ❌ Prime field → trivial GCD |
| 7 | Cross-CT R sharing | ❌ All 44 seeds unique |
| 8 | Brute force length CT[0] | ❌ 1 eq, 2 unknowns per layer |
| 9 | Pedersen DLP | ❌ Ristretto255 secure |
| 10 | T-value ratio analysis | ❌ All ratios pseudo-random |
| 11 | Homomorphic ct_mul zero-test | ❌ PROD target ≠ f(guess) |
| 12 | Pedersen × T scalar product | ❌ Fp/Scalar field mismatch |
| 13 | sigma_from_H XOR → LPN instance extraction | ⏳ ~1800 samples, n=16384 |
| 14 | ████████████████████████████ | 🔄 *in progress* |

---

## Infrastructure Built 🛠️

- Custom PVAC range decoder (Python port)
- Native C++ attack toolchain via WSL/g++ 13.3
- Full CT parser with verified `remaining=0` on all 22 blocks
- powg_B extractor → all 337 roots of unity verified
- T-value computation pipeline
- Sigma Hamming weight / parity analyzer

---

## Lines of Code Audited

```
include/pvac/ops/encrypt.hpp        ████████████████████ FULL (1106 lines)
include/pvac/ops/decrypt.hpp        ████████████████████ FULL
include/pvac/ops/arithmetic.hpp     ████████████████████ FULL
include/pvac/ops/recrypt.hpp        ████████████████████ FULL
include/pvac/ops/commit.hpp         ████████████████████ FULL
include/pvac/crypto/lpn.hpp         ████████████████████ FULL
include/pvac/crypto/keygen.hpp      ████████████████████ FULL
include/pvac/crypto/ristretto255.hpp ███████████████████ FULL
include/pvac/crypto/matrix.hpp      ████████████████████ FULL
include/pvac/core/hash.hpp          ████████████████████ FULL
include/pvac/core/types.hpp         ████████████████████ FULL
include/pvac/core/pvac_compress.hpp ████████████████████ FULL
include/pvac/core/seedable_rng.hpp  ████████████████████ FULL
include/pvac/utils/text.hpp         ████████████████████ FULL
source/pvac_artifact_serialize.hpp  ████████████████████ FULL (503 lines)
source/hfhe_bounty_artifact.cpp     ████████████████████ FULL
```

---

## Tools & Resources

- Challenge repo: [pvac_hfhe_cpp](https://github.com/octra-labs/pvac_hfhe_cpp) @ `071b0e9`
- LPN estimators: [Code_estimators](https://github.com/Crypto-TII/LPN_estimator)
- Dev context: [octra-sqlite](https://github.com/tomismeta/octra-sqlite), [billiondollarpdf.com](https://billiondollarpdf.com/)

---

*Last updated: July 14, 2026*  
*50+ attack scripts. 16 source files audited. 14 approaches tried. 4 bugs found.*  
*The machine hasn't stopped thinking.* 🐇🕳️
