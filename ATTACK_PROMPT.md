# OCTRA HFHE v2 Cryptanalysis Challenge — Structured Attack Prompt

## PROBLEM STATEMENT

You are attacking the OCTRA Hypergraph-based Fully Homomorphic Encryption (HFHE) scheme, version 2. A secret plaintext (a BIP-39 mnemonic seed phrase, 301–315 bytes) has been encrypted using this scheme. You have:

- `pk.bin`: The full public key (compressed, ~3MB), containing the H matrix (8192×16384 GF(2)), powg_B array (337 elements of Fp where p = 2^127 − 1), and other public parameters.
- `secret.ct`: A bundle of 22 ciphertexts. CT[0] encrypts the plaintext length (an integer in [1, 315]). CT[1]–CT[21] each encrypt a 15-byte block packed into a single Fp element.
- Full source code of the HFHE scheme (C++ headers in `include/pvac/`).

You do NOT have `sk.bin` (the secret key).

The developer has stated that the system is **"fundamentally broken"** and that the break **is connected to the FHE mechanism itself** (not a generic crypto bug).

The bounty3 hint is: **"Try to extract the parameter R from the equation."**

## WHAT CONSTITUTES A COMPLETE SOLUTION

A complete solution must do **exactly one** of the following:

1. **Recover the plaintext**: Output the BIP-39 mnemonic seed phrase (301–315 ASCII bytes).
2. **Recover the secret key**: Output `sk.bin` containing `prf_k` (4×uint64) and `lpn_s_bits` (4096-bit vector).
3. **Recover R values**: For any ciphertext CT[i], recover both R₀ and R₁ (the per-layer blinding factors in Fp), enabling decryption via the known equation `plaintext = agg_L0 * R₀⁻¹ + agg_L1 * R₁⁻¹` where agg values are publicly computable.
4. **Demonstrate a practical attack**: A working algorithm (code) that, given (pk, ct), outputs the plaintext without sk.

## WHAT DOES NOT COUNT AS A SOLUTION

The following are **insufficient** and must not be treated as progress toward the goal:

1. Reproving that the scheme is semantically secure under standard assumptions — the break is implementation/design-specific.
2. Showing that LPN with n=4096, τ=1/8 is hard — estimated 2^341 complexity, already confirmed infeasible.
3. Showing that DLP on Ristretto255 is hard — already confirmed.
4. Analyzing sigma (e.s) bitvectors — they are IRRELEVANT for decryption.
5. Attempting to distinguish enc(0) from enc(nonzero) via T-values — V2 wrapping prevents this.
6. GCD/lattice attacks on weights in the prime field — trivial GCD, no structure.
7. Brute-forcing the CSPRNG, AES keys, or SHA256 preimages.
8. Finding bugs that don't lead to plaintext recovery (e.g., R_com not hashing R, pointer bounds, noncanonical inputs).
9. Reducing the problem to another unproved cryptographic assumption of comparable strength.
10. Any analysis that requires O(2^128) or more operations.

## KNOWN DEAD ENDS (17 APPROACHES ALREADY TRIED AND FAILED)

| # | Approach | Why it failed |
|---|----------|---------------|
| 1 | V1 low-bit leakage | Fixed in V2 wrapping |
| 2 | Sigma XOR pair identification | HW ≈ 4096 (random) |
| 3 | R_com verification oracle | Removed in V2 |
| 4 | LPN statistical attack | y-bits random |
| 5 | Direct LPN solving (BKW/ISD) | 2^341 complexity |
| 6 | GCD/lattice on weights | Prime field → trivial GCD |
| 7 | Cross-CT R sharing | All 44 seeds unique |
| 8 | Brute force length CT[0] | 1 eq, 2 unknowns per layer |
| 9 | Pedersen DLP | Ristretto255 secure |
| 10 | T-value ratio analysis | All ratios pseudo-random |
| 11 | Homomorphic ct_mul zero-test | V2 wrapping prevents it |
| 12 | Pedersen × T scalar product | Fp/Scalar field mismatch (P ≠ L) |
| 13 | sigma_from_H XOR → LPN instance | ~1800 samples, need 16M |
| 14 | Native runtime source (ru_src) | All 44 layers use standard prg_layer_ztag |
| 15 | Weight ratio analysis | R cancels but can't eliminate mask m |
| 16 | Seeded RNG exploitation | Bounty uses csprng, not seeded |
| 17 | recrypt_eval.hpp full audit | No exploitable bugs found |

**DO NOT REPEAT ANY OF THESE.** If you find yourself heading toward one of these approaches, stop immediately and try a different route.

## CRYPTOGRAPHIC STRUCTURE (ESSENTIAL EQUATIONS)

### Field and Group Parameters
- Field: Fp where P = 2^127 − 1 (Mersenne prime)
- Subgroup order: B = 337 (prime), g = generator of order B in Fp*
- powg_B[k] = g^k for k ∈ [0, 336]
- Ristretto255 group (order L ≈ 2^252) for Pedersen commitments

### Encryption (per sub-cipher, depth d)
```
Layer L:
  nonce = random 128-bit
  ztag = PRG(canon_tag, nonce)
  R = prf_R(pk, sk, seed)         ← REQUIRES SK
  delta = prf_R_noise(pk, sk, ...)  ← REQUIRES SK
  m = random Fp (wrapping mask)     ← REQUIRES SK

Signal edges (8 per sub-cipher):
  Positions p[0..7] chosen WITHOUT replacement from [0, B)
  coef[0..6] = random Fp
  coef[7] = (va - Σ coef[i]*powg_B[p[i]]) / powg_B[p[7]]
  where va = plaintext - delta_aggregate
  Edge weight: w = R * coef

Noise edges (N2 pairs + N3 triplets):
  Each N2 pair (a,b): sign_a*w_a*powg_B[pa] + sign_b*w_b*powg_B[pb] = R*delta_t
  w_a = R*ra (random), w_b = R*(ra*powg_B[pa] - delta_t)/powg_B[pb]

After merge: edges with same (layer_id, idx, sign) have weights summed.
After fuse (wrapping): enc(v) = fuse(enc(v+m), enc(-m))
  Layer 0 encrypts (v+m), Layer 1 encrypts (-m)
```

### Decryption Equation
```
plaintext = c0 + Σ_e sign(e) * w_e * powg_B[idx_e] * R_inv[layer(e)]
```
where R_inv = fp_inv(R) and R = prf_R(pk, sk, seed).

Equivalently, defining the public aggregate per layer:
```
agg_L = Σ_e∈layer sign(e) * w_e * powg_B[idx_e]    ← COMPUTABLE FROM PUBLIC DATA
plaintext = agg_L0 * R0_inv + agg_L1 * R1_inv
```

### R Derivation (the target)
```
R[j] = r1 * r2 * r3  where each ri = prf_R_core(pk, sk, seed, domain_i)

prf_R_core:
  1. AES key from SHA256(domain || sk.prf_k || seed)
  2. LPN matrix A from AES-CTR(key, ...)     ← n=4096, t=16384
  3. y_bits = A * sk.lpn_s_bits ⊕ noise      ← LPN problem
  4. Toeplitz hash of y_bits → 127-bit value
  5. hash_to_fp_nonzero → R component
```

### Pedersen Commitment (stored in ciphertext!)
```
PC[j] = sc_from_fp_signed(R_inv[j]) * G + rho_j * H
where rho_j = SHA256("pvac.prf.rho" || sk.prf_k || nonce || j)
```
- G = Ristretto255 base point, H = hash-derived generator
- PC is publicly accessible in the ciphertext (44 points total)
- rho requires sk → can't simply invert

### CT[0] Public Aggregates (computed)
```
Layer0 agg = {3b6032a36dff0198, 54cd7669b430e2e0}
Layer1 agg = {fd64efda13be5723, 62bc7afda3a798e7}
```

## PROBLEM-SPECIFIC TRAPS

1. **R cancels in decryption**: w = R*coef, and decryption multiplies by R_inv, so R cancels. This makes weight analysis seem useless — but the bounty hint says to "extract R from the equation." There must be an equation where R does NOT cancel.

2. **Field mismatch**: Fp has modulus P = 2^127−1, Ristretto255 scalars have modulus L ≈ 2^252. The map sc_from_fp_signed is injective but the algebraic structures are incompatible. Don't try to move between these fields algebraically.

3. **Each CT has independent R values**: Different nonces → different seeds → different R. No correlation between R values across CTs.

4. **Merge obscures edge identity**: After merge, you cannot tell which original edge (signal vs noise) produced a given edge. Don't assume you can identify signal edges.

5. **depth_hint starts at 2**: CT[1..21] use depth_hint = 2, 3, ..., 22. This affects noise budget but NOT the fundamental security.

6. **"Fundamentally broken" ≠ implementation bug**: The dev said the break IS connected to FHE. Look for structural/algebraic weaknesses in the HFHE construction itself, not just code bugs.

## SEARCH MANAGEMENT INSTRUCTIONS

### Strategy
1. **Start with at least 5 independent attack approaches.** Keep them alive simultaneously. Do not converge prematurely on one route.
2. **Aggressively search for counterexamples** to any proposed attack step. If you claim "X leaks information about R," immediately try to disprove it.
3. **Mark a route as BLOCKED** if it only reduces to another problem of comparable hardness (e.g., reducing to DLP, LPN, or AES key recovery).
4. **Prioritize unexplored angles:**
   - How do Pedersen commitments (PC) transform under homomorphic operations (ct_add, ct_mul)?
   - Is there an equation involving R that we haven't identified?
   - Can we use the KNOWN SMALL PLAINTEXT of CT[0] (length ∈ [1,315]) to constrain R?
   - What happens to the R*coef structure when edges are merged?
   - Are there algebraic relations in the order-337 subgroup that break the scheme?

### Tools Available
- C++ build environment in WSL at `~/pvac_work/pvac_hfhe_cpp/`
- Full HFHE source in `include/pvac/`
- Challenge data in `hfhe-challenge/` (pk.bin, secret.ct, params.json)
- bounty2 training ground with known sk: `hfhe-challenge/bounty2_data/` (sk.bin available)
- Working parsers: use `pvac_artifact_serialize.hpp` (do NOT also include `pvac.hpp` — causes crash)
- Parser offset: secret.ct magic is 16 bytes, then u64 count, then length-prefixed CTs

### Build Commands
```bash
cd ~/pvac_work/pvac_hfhe_cpp
g++ -std=c++17 -O2 -maes -msse4.2 -I include -I . -o tool tool.cpp
```

### Verification
Any claimed attack MUST be verified:
1. First test on bounty2 (has known sk for ground truth)
2. Then apply to the main challenge
3. If you recover a plaintext candidate, verify it's valid BIP-39

## ADVERSARIAL AUDIT REQUIREMENT

Before declaring any attack successful, you MUST:
1. State the attack clearly in one paragraph
2. Identify the weakest step in the attack
3. Construct the strongest possible counterargument against that step
4. Either refute the counterargument rigorously or acknowledge the attack is blocked
5. If blocked, move to a different route — do not patch a fundamentally broken approach

## KNOWLEDGE BASE

Read the full knowledge base at: `C:\Users\Hype G12\OneDrive\pribadi\hfhe-bounty-research\KNOWLEDGE_BASE.md`

This contains 111 sections of accumulated research. **DO NOT REPEAT** any approach documented there as failed.

Update the knowledge base after every significant finding or failed approach.
