
# HFHE V2 — LPN Attack Research Log

> **RULE: Read this ENTIRE file before doing ANY LPN work. Do NOT repeat experiments.**

---

## Session 5 — LPN FOCUSED ATTACK (July 18, 2026)

### 29. DEV TWEET CONFIRMATION
Dev tweeted: "The challenge is now easier, but also fairer according even to initial critics. The requested LPN samples are public and the rules are clear. The target is there, happy breaking!"
**LPN IS THE INTENDED ATTACK PATH.**

### 30. LPN SAMPLE FILES STRUCTURE
- Location: hfhe-challenge/lpn_samples/
- 44 files: ct{00-21}_l{0,1}_s0_pvac_prf_r_1.jsonl
- Each about 17MB, 16385 lines (1 header + 16384 samples)
- ALL files use domain pvac.prf.r.1 only (not r.2 or r.3)
- ALL 44 instances share the SAME secret s (lpn_s_bits from sk)

### 31. LPN SAMPLE FORMAT
Header (line 1): JSON with format, cipher_index, layer_id, slot, dom, n=4096, t=16384, tau_num=1, tau_den=8, row_words=64, seed_ztag, nonce_lo_hex, nonce_hi_hex, public_T_hex

Each sample (lines 2-16385): JSON with i (index), y (bit), a (1024 hex chars = 4096 bits)
Where: y = <a, s> XOR e, e is Bernoulli(1/8)

### 32. LPN PARAMETERS
- n = 4096 (secret length in bits)
- t = 16384 (samples per file)
- tau = 1/8 (noise rate = 12.5%)
- Total samples available: 44 x 16384 = 720,896
- All sharing same secret s
- a vectors: 4096-bit, look random (unique per sample, different across files)
- y distribution: about 50/50 (balanced, as expected)

### 33. BINDING VERIFICATION
verify_lpn_sample_binding.cpp checks: seed_ztag, nonce, and public_T_hex match between LPN sample headers and actual ciphertext layer data. Confirms samples are genuinely from the challenge.

### 34. YBITS INSIGHT
LPN samples ARE the ybits for domain "pvac.prf.r.1":
- prf_R_core needs: ybits + toep_matrix
- We HAVE ybits (= y column from samples)
- We DON'T HAVE toep_matrix (requires prf_k via SHA256 -> AES key)
- So even with ybits, we still can't compute R without prf_k

### 35. TOTAL DATA AVAILABLE
- 720,896 LPN samples (44 files x 16384)
- All sharing same s (4096-bit secret)
- Each sample: 4096-bit row a, 1-bit response y
- Noise rate: 1/8 (87.5% of samples are clean)

---

## Session 5b — DEEP VERIFIED ANALYSIS (July 18, 2026)

### 36. SECRET s IS UNIFORMLY RANDOM — VERIFIED
File: include/pvac/crypto/keygen.hpp lines 150-160
sk.lpn_s_bits generated via csprng_u64() = /dev/urandom
**NOT sparse.** Expected Hamming weight ~2048.
bounty2 sk.bin confirms: HW=2051 (50% ones).
Sparse-LPN attacks WILL NOT HELP.

### 37. RECOVERING s ALONE IS NOT SUFFICIENT TO DECRYPT — VERIFIED
Decryption requires BOTH sk.prf_k (256 bits) AND sk.lpn_s_bits (4096 bits).
- prf_k is used by derive_aes_key() for ALL key derivations (LPN rows, Toeplitz matrix, noise)
- Even knowing s + all LPN sample data, we CANNOT recover prf_k:
  - Known AES-CTR plaintext does NOT reveal key (AES is secure)
  - AES key = SHA256(prf_k || public_data), SHA256 is one-way
- README confirms: "Recovering S is an ADDITIONAL target; main bounty = recover plaintext"
- **CONCLUSION: Solving LPN alone does NOT decrypt. There must be a SECOND step or a BYPASS.**

### 38. bounded() IMPLEMENTATION — VERIFIED CORRECT
```cpp
uint64_t bounded(uint64_t M) {
    if (M <= 1) return 0;
    uint64_t lim = UINT64_MAX - (UINT64_MAX % M);
    for (;;) {
        uint64_t x = next_u64();
        if (x < lim) return x % M;
    }
}
```
Standard rejection sampling. Bias = 8/2^64 = negligible. NO BUG HERE.

### 39. ROWS ARE GENUINELY RANDOM — VERIFIED
Tested on ct00_l0_s0_pvac_prf_r_1.jsonl:
- No duplicate rows in first 1000
- Mean Hamming weight: 2048.53 (expected 2048.00, std 32.75)
- Adjacent row XOR weight: 2051.49 (expected 2048.00)
- Cross-file XOR weights: all ~2048
- No all-zero rows
- 64x64 subblock has full rank (64/64)
- **Rows look perfectly pseudorandom (AES-CTR is working correctly)**

### 40. CROSS-FILE STATISTICS — VERIFIED
All 44 files, 720,896 total samples:
- Overall y=1 rate: 0.499689 (expected 0.500000)
- Min y=1 rate per file: 0.493164
- Max y=1 rate per file: 0.511169
- Std dev: 0.003793
- **Perfectly balanced. No anomalies across files.**

### 41. SINGLE-BIT CORRELATION — VERIFIED ABSENT
Tested bits 0,1,2,3,16,32,63 of row a vs y:
- All correlations within [49.4%, 50.7%]
- **No visible single-bit correlation (expected for wt(s)>>1)**

### 42. BKW FEASIBILITY — INFEASIBLE
Noise doubling per round:
| Round | Noise | Bias |
|-------|-------|------|
| 0 | 0.125 | 0.750 |
| 1 | 0.219 | 0.563 |
| 2 | 0.342 | 0.316 |
| 3 | 0.450 | 0.100 |
| 4 | 0.495 | 0.010 |
| 5 | 0.500 | 0.000 (USELESS) |

Max useful rounds: 3-4. With 720K samples, max block size ~14-15.
4 rounds x b=15 = only 60 dimensions eliminated from 4096.
**Standard BKW CANNOT solve this.**

### 43. FULL COMPLEXITY ESTIMATES — ALL INFEASIBLE
| Attack | Complexity | Feasible? |
|--------|-----------|-----------|
| Brute force | 2^4096 | NO |
| BKW | 2^341 | NO |
| Pooled Gauss | 2^789 | NO |
| Statistical Decoding | 2^549 | NO |
| Hybrid (guess 50) | 2^388 | NO |
| Hybrid (guess 100) | 2^434 | NO |

Low-weight dual codewords: ~2^(-4000) expected count for weight 3-10.
**Essentially zero low-weight parity checks exist.**

### 44. UNIQUE DECODING IS POSSIBLE
Code rate: 0.00568, GV capacity at tau=1/8: 0.456
Rate << capacity → solution is UNIQUE. Problem is FINDING it efficiently.

---

## KEY CONCLUSIONS

### CANNOT BREAK WITHOUT SOLVING LPN
There is NO known shortcut to decrypt without either:
1. Recovering s (LPN secret, 4096 bits) — AND THEN somehow getting prf_k
2. Recovering prf_k (256 bits) directly — no known path
3. Finding a mathematical bypass that avoids both

### THE PARADOX
- Dev says LPN = the way ("happy breaking!")
- But LPN(4096, 1/8) = 2^341 security by all known algorithms
- Dev also said system is "fundamentally broken"
- This means either:
  a) There's a SPECIFIC weakness in THIS implementation we haven't found
  b) The LPN parameters are actually weaker than they appear (hidden structure?)
  c) There's a mathematical relationship between LPN and the rest of the system that bypasses standard LPN solving
  d) Dev is wrong about feasibility

### ALL ANGLES EXHAUSTED — NO RESULTS (confirmed by user July 18)
1. ~~GitHub Issues #499, #501, #503~~ — CHECKED, no exploitable path
2. ~~Toeplitz hash properties~~ — CHECKED, cannot reverse without prf_k
3. ~~Multiple-domain relationship~~ — CHECKED, R1*R2*R3 doesn't help
4. ~~Neural network LPN solver~~ — Max n~512, n=4096 infeasible
5. ~~Lattice reduction on LPN~~ — No applicable technique for these params
6. ~~Row/noise coupling from same PRG~~ — AES-CTR secure, no exploit
7. ~~Bounty3~~ — CHECKED, same crypto, no easier path

### FINAL STATUS: STUCK
All known attack vectors exhausted. Need fundamentally new idea or external information to proceed.

