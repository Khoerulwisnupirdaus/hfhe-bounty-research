# HFHE V2 Bounty Research

> Security research on [Octra Labs HFHE](https://github.com/octra-labs/pvac_hfhe_cpp) homomorphic encryption challenge

## Status: ACTIVE RESEARCH (Session 9+)

Major cryptographic breakthrough achieved — full decryption pipeline verified, T=Rv exactness proven.

## What's Here

- **[SECURITY_ASSESSMENT.md](SECURITY_ASSESSMENT.md)** — Complete technical writeup: architecture, encryption/decryption flow, PRF pipeline, every attack attempted, code audit results
- **[KNOWLEDGE_BASE.md](KNOWLEDGE_BASE.md)** — Running log of all findings (81 entries), dead ends, and session notes
- **[LPN_ATTACK_LOG.md](LPN_ATTACK_LOG.md)** — Detailed LPN attack analysis and complexity estimates

## 🔥 Key Breakthroughs (Session 9)

### 1. T = R × v EXACTLY (Zero Noise)

**Proved mathematically and verified experimentally**: The noise (delta) in PVAC cancels perfectly by construction.

```
Signal edges:  Σ(±coef_i × g^idx_i) = va = v - Σδ_i
N2 noise pair: T_contribution = R × δ_i  (NOT zero!)
Total: T = R×va + R×Σδ_i = R×(v - Σδ + Σδ) = R×v
```

This means **decryption is EXACT** with zero error — the noise edges are purely for sigma vector obscuring, not for correctness.

### 2. Bounty2 Full Pipeline Verified

- Regenerated bounty2 artifacts with matching sk.bin
- `dec_value(enc(1)) = 1` ✓ (exact, delta=0)
- Manual Σ(T/R) matches official `dec_value()` perfectly
- R = R1 × R2 × R3 verified for all layers

### 3. Main Challenge Fully Parsed

```
22 CTs × 2 BASE layers = 44 independent R values
No PROD layers (no algebraic tree)
c0 = 0 for all CTs
1829 total edges
CT[0] = length byte, CT[1..21] = 15-byte ASCII chunks
```

## Quick Summary

| Aspect | Detail |
|--------|--------|
| Target | `secret.ct` → wallet private key for `octC5eR9pLGKbpzTbDgHowkFt8HW7LZYb2gzehzxHamxuAZ` |
| Reward | 500K OCT (+ 500K from dev) |
| Crypto | LPN(4096, 1/8) → ~2^341 security |
| V1→V2 Fix | R_com no longer hashes R; wrapping added (enc(v+m)+enc(-m)) |
| Files Audited | 10+ header files, ~3000 lines of crypto code |
| Attacks Tried | 30+ (see assessment) |
| Key Equation | T = R × v (exact, no noise) |
| Unknowns | 44 R values (127-bit each) + 22 plaintexts |

## Attack Categories Exhausted

**Cryptographic**: LPN brute force, H matrix rank, signal/noise distinction, PC extraction, T-value analysis, cross-CT correlation, BKW, lattice reduction, ISD

**Implementation Bugs**: Field arithmetic, rist_H correctness, serialization leaks, keygen weakness, decrypt logic, nonce reuse, ztag mismatch, integer overflow, sign errors

**Alternative Decrypt**: R=1, R=omega, native path, s=0 secret, small R_inv brute force

## Why It's Hard

1. LPN n=4096 tau=1/8 = ~341 bits security
2. V2 wrapping prevents zero-detection (mask m is random Fp)
3. Triple-product PRF (R = R1 × R2 × R3)
4. 44 independent R values (no algebraic relations)
5. Clean implementation — no exploitable bugs found

## Open Attack Vectors

1. **Lattice attack on short plaintext**: v is "short" (120-bit ASCII vs 127-bit Fp) — hidden number problem variant
2. **Pedersen commitment leakage**: Each layer has 1 PC — analyze if binding/opening is exploitable
3. **Cross-CT constraints**: All 22 CTs encrypt related data (chunks of same wallet key)
4. **prf_R_core bias**: LPN → Toeplitz → hash pipeline may have statistical bias over 44 evaluations

## Competitor

- [smoke-ui assessment](https://github.com/smoke-ui/octra-hfhe-v2-security-assessment) — Also failed to break V2

---

*Research: July 10-23, 2026*
