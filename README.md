# 🔐 PVAC-HFHE Bounty — Research Log

> *"tell your machine to destroy it"* — dev, circa July 2026

---

## Status: `ACTIVE` 🟢

We are actively working on the [Octra HFHE Bounty](https://github.com/octra-labs/pvac_hfhe_cpp) challenge.
Commit target: `071b0e9`

---

## What We Know (Public Summary)

| Property | Value |
|----------|-------|
| Field | GF(2¹²⁷ − 1), Mersenne prime |
| Generator order | B = 337 (prime) |
| LPN dimension | n = 4096, τ = 1/8 |
| Wrapping | V2 dual-layer (July 3 fix) |
| Wire format | `pvac-v3-length-prefixed-bundle` |
| CT blocks | 22 (1 length + 21 text × 15 bytes) |
| Layers per CT | 2 (BASE + BASE, wrapped) |
| Pedersen Commitments | 44 unique, all valid Ristretto255 |

---

## Bug Discoveries 🐛

### BUG-001: `compute_R_com_base` — commitment without binding
- **File**: `include/pvac/core/hash.hpp`, line 198
- **Severity**: ⚠️ Design flaw
- **Description**: `R_com` is computed as `SHA256(domain ‖ canon_tag ‖ ztag ‖ nonce ‖ n_slots)` — the actual R values are **never hashed**. R_com is fully deterministic from public data and does not bind to any secret.
- **Impact**: R_com cannot serve as a commitment to R. Removed from V2 serialization (possibly for this reason).

### BUG-002: `keygen` root exponent truncation (historical)
- **Commit**: `755025a` ("fix keygen root exponent")
- **Severity**: 🔴 Critical (fixed before challenge)
- **Description**: `omega_B = fp_pow_u64(h, (uint64_t)E)` truncated `E = (P−1)/B` (a 128-bit value) to 64 bits. Result: `omega_B^B ≠ 1` — the root of unity property was **broken**.
- **Verification**: `B × E_trunc mod (P−1) = 2⁶⁴ − 2 ≠ 0`
- **Impact**: Fixed in challenge commit. But the `// !!!!!!!!!!!` comment in the old code tells a story.

### BUG-003: Edge count asymmetry across layers
- **Observation**: Layer 0 and Layer 1 within the same CT block have **different edge counts** after merge (e.g., CT[0]: L0=22, L1=21).
- **Implication**: The merge/permute step does not guarantee symmetric structure. Potentially exploitable for layer identification.

---

## Interesting Findings 🔍

### FINDING-001: All homomorphic operations are public-key-only
- `ct_add`, `ct_sub`, `ct_mul`, `ct_square`, `ct_scale`, `ct_add_const`, `ct_neg` — **none require the secret key**.
- Product (PROD) layer targets are computed as `T_a × T_b` — fully public.
- New edges for PROD layers are generated using only `pk` data.
- *Implication: redacted.*

### FINDING-002: Edge count encodes depth
- CT[0] (depth 0): 43 edges. CT[21] (depth 20): 119 edges.
- Signal edges are constant (8 per layer). Noise scales with depth.
- CT[0] has the **least noise** → most constrained.

### FINDING-003: `omega_B = g^24`
- `omega_B` and `powg_B[1]` are different primitive 337th roots of unity.
- They are related by `omega_B = g^24`, with `gcd(24, 337) = 1`.

### FINDING-004: Signal decomposition structure
- `SigEdge::build` decomposes the value into exactly 8 edges.
- First 7 coefficients are **random**. The 8th is **deterministic**: `coef_8 = (target − Σ₇) / g^{pos₈}`.
- After merge with noise edges, this structure is obscured — but not necessarily destroyed.

### FINDING-005: N2 noise pairs have opposite signs
- `N2Edge::build` always sets `sb = sa ⊕ 1`. Noise pairs consist of one `SGN_P` and one `SGN_M` edge.
- The coefficient relationship: `rb = (ra × g^a − δ) / g^b`.

### FINDING-006: Weight ratios cancel R
- For edges in the same layer: `w_i / w_j = coef_i / coef_j` (mod P).
- R is a common factor and cancels in any same-layer ratio.

---

## Approaches Tried

| # | Approach | Result |
|---|----------|--------|
| 1 | V1 low-bit leakage | ❌ Fixed in V2 wrapping |
| 2 | Sigma XOR pair identification | ❌ HW ≈ 4096 (random) |
| 3 | R_com verification oracle | ❌ Removed in V2 |
| 4 | LPN statistical attack | ❌ y-bits perfectly random |
| 5 | Direct LPN solving (BKW/ISD) | ❌ Est. 2^341 complexity |
| 6 | GCD/lattice on weights | ❌ Prime field → trivial |
| 7 | Cross-CT R sharing | ❌ All 44 seeds unique |
| 8 | Brute force length | ❌ 1 eq, 2 unknowns |
| 9 | Pedersen DLP | ❌ Ristretto255 secure |
| 10 | ████████████████ | 🔄 *in progress* |

---

## Tools & Resources

- Challenge repo: [pvac_hfhe_cpp](https://github.com/octra-labs/pvac_hfhe_cpp) @ `071b0e9`
- LPN estimators: [Code_estimators](https://github.com/Crypto-TII/LPN_estimator)
- Dev context: [octra-sqlite](https://github.com/tomismeta/octra-sqlite), [billiondollarpdf.com](https://billiondollarpdf.com/)

---

## Lines of Code Audited

```
include/pvac/ops/encrypt.hpp       ████████████████████ FULL
include/pvac/ops/decrypt.hpp       ████████████████████ FULL
include/pvac/ops/arithmetic.hpp    ████████████████████ FULL
include/pvac/ops/recrypt.hpp       ████████████████████ FULL
include/pvac/ops/commit.hpp        ████████████████████ FULL
include/pvac/crypto/lpn.hpp        ████████████████████ FULL
include/pvac/crypto/keygen.hpp     ████████████████████ FULL
include/pvac/crypto/ristretto255.hpp ██████████████████ FULL
include/pvac/crypto/matrix.hpp     ████████████████████ FULL
include/pvac/core/hash.hpp         ████████████████████ FULL
include/pvac/core/types.hpp        ████████████████████ FULL
include/pvac/utils/text.hpp        ████████████████████ FULL
pvac_artifact_serialize.hpp        ████████████████████ FULL
recrypt_src_core.hpp               ██████████████░░░░░░ 70%
recrypt_eval.hpp                   ██████████░░░░░░░░░░ 50%
```

---

*Last updated: July 13, 2026*  
*Status: Deep in the rabbit hole. The machine is thinking.* 🐇🕳️
