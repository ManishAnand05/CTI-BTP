# PR-RABE_P implementation notes and deviations

Base paper: R. Yang et al., "PR-RABE: Privacy-preserving and Revocable Registered
Attribute-Based Encryption with lightweight encryption", Computer Standards &
Interfaces 98 (2026) 104158. Implemented: prime-order construction (Section 5.2).

## Scope
- Prime-order PR-RABE_P only. Composite-order PR-RABE_C is not implemented.
- Slotted setting with fixed slot count L. Registering a new organisation means
  re-running Aggregate. Full RABE (paper Section 4.3) is Phase II work.
- Pairing group: Charm-Crypto SS512 (PBC Type-A, symmetric). About 80-bit security.
  Prototype grade. A Type-3 (BN254) port would require re-deriving the scheme for
  asymmetric pairings.

## Engineering corrections
| # | Paper | Implementation | Reason |
|---|-------|----------------|--------|
| D1 | Hdr = AGK * T_i^s, AGK in Z_p | Hdr[k][i] = AGK XOR SHA256(T_i^s, k) | A scalar times a group element is not defined; hashed ElGamal keeps the paper's recovery step (T_i^s = C2^{r_i}). |
| D2 | Header per attribute | Header indexed by policy row k | Keying by attribute would expose hidden attribute values. |
| D3 | none | Key-confirmation tag kc = H(m) in ciphertext | With hidden values the decryptor cannot tell a wrong guess; m is a fresh random GT element so the tag leaks nothing useful. |
| D4 | "sums d_i + d_j all distinct" | Not relied on | False for the base-3 {0,1}-digit set (1+12 = 4+9). Correctness holds regardless. |
| D5 | Message space GT | Hybrid: random m in GT -> HKDF-SHA256 -> AES-256-GCM over STIX JSON | ABE cannot encrypt arbitrary bytes. |

## Security notes and known limitations
- Revocation protects records the revoked organisation has not already retrieved,
  and every future record. A copy cached before revocation stays readable (paper scope).
- Revoke re-encrypts with retained m, so the Data Owner role must hold m.
  Who plays that role in the CTI platform is an open design decision.
- AGK leakage: a current group member can leak the AGK to a revoked organisation,
  whose registered attributes are unchanged, enabling decryption. Inherent to
  group-key revocation. Covered by test_known_limitation_agk_leak_after_revocation.
- Header membership: the header shows which slots can use each row, so AGK group
  membership is visible. Registered attribute sets are also public (RABE design).
- CRS generation is a trusted setup: a and b are discarded after Setup.

## Verified by tests (backend/tests/crypto)
Authorized decryption, policy matrix (AND/OR), offline/online split, value hiding,
wrong-attribute decryption fails even with leaked AGK, collusion fails, wrong secret
key fails, revocation blocks revoked org and spares others with no key change,
old AGK unusable after re-encryption, new records after revocation blocked,
STIX hybrid round trip.
