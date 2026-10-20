"""PR-RABE_P core algorithms (Yang et al. 2026, Section 5.2).

Algorithms: KeyGen, IsValid, Aggregate, Encrypt (offline + online), Decrypt.
Revocation (AGK rotation + re-encryption) is in owner.py.

Engineering corrections relative to the paper text (see docs/crypto/DEVIATIONS.md):
  D1. Header encoding. The paper writes Hdr = AGK * T_i^s with AGK in Z_p and
      T_i^s in G, which does not type-check. We use hashed ElGamal:
      Hdr[k][i] = AGK_pi(k) XOR H(T_i^s || k). The decryptor recomputes
      T_i^s = C2^{r_i}, exactly as in the paper's Decrypt step.
  D2. Header indexed by row k, not by attribute value, so the header does not
      reveal hidden attribute values.
  D3. Key-confirmation tag kc = H(m) lets the decryptor detect a wrong
      attribute-value guess under policy hiding (m is a fresh random GT element).
"""

import hashlib
import itertools
from dataclasses import dataclass, field

from charm.toolbox.pairinggroup import ZR, G1, GT, pair

from .policy import parse_policy, reconstruct_rows


# ----------------------------------------------------------------- data types

@dataclass
class PublicKey:
    slot: int
    T: object            # g^{r_i}
    Q: object            # P_i^{r_i}
    V: dict              # j -> A_j^{r_i}   (j != i)


@dataclass
class MasterPublicKey:
    T_hat: object
    U_hat: dict          # attribute -> U_hat_x
    T: list              # registered T_i per slot (needed for headers)
    universe: list


@dataclass
class HelperKey:
    slot: int
    attributes: frozenset
    A: object
    B: object
    V_hat: object
    W_hat: dict          # attribute -> W_hat_{i,x}


@dataclass
class OfflineCiphertext:
    s: object
    h1: object
    h2: object
    C1_tilde: object
    C2: object
    C5_tilde: object
    s_k: list
    C4: list


@dataclass
class Ciphertext:
    labelled_policy: str     # policy structure with ROW<k> labels (public)
    names: list              # public attribute names per row
    matrix: list
    n: int
    C1: object
    C2: object
    C3p: list                # C3'_k = C3_k ^ AGK_pi(k)
    C4: list
    C5: object
    hdr: dict                # k -> {slot: bytes}
    agk_versions: dict       # k -> version of the AGK used for row k
    kc: bytes                # key-confirmation tag


# ----------------------------------------------------------------- helpers

def _h(group, element, k):
    data = b"PRRABE-HDR|" + group.serialize(element) + b"|" + str(k).encode()
    return hashlib.sha256(data).digest()


def zr_to_bytes(group, x):
    return int(x).to_bytes(32, "big")


def bytes_to_zr(group, b):
    return group.init(ZR, int.from_bytes(b, "big"))


def _xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def key_confirmation(group, m):
    return hashlib.sha256(b"PRRABE-KC|" + group.serialize(m)).digest()[:16]


# ----------------------------------------------------------------- KeyGen / IsValid

def keygen(crs, i):
    """KeyGen(crs, i) -> (pk_i, sk_i). Run by the organisation itself."""
    group = crs.group
    r = group.random(ZR)
    pk = PublicKey(
        slot=i,
        T=crs.g ** r,
        Q=crs.P[i] ** r,
        V={j: crs.A[j] ** r for j in range(crs.L) if j != i},
    )
    return pk, r


def is_valid(crs, i, pk):
    """IsValid(crs, i, pk_i): pairing checks from the paper."""
    if pk.slot != i or set(pk.V) != {j for j in range(crs.L) if j != i}:
        return False
    if pair(pk.T, crs.P[i]) != pair(crs.g, pk.Q):
        return False
    return all(pair(crs.g, pk.V[j]) == pair(pk.T, crs.A[j]) for j in pk.V)


# ----------------------------------------------------------------- Aggregate

def aggregate(crs, registrations, universe):
    """Aggregate(crs, (pk_1, S_1), ..., (pk_L, S_L)) -> (mpk, hsk_1..hsk_L).

    registrations: list of length L of (pk, set_of_attribute_strings).
    universe: every attribute string the system may use in a policy.
    Deterministic; run by the (untrusted, transparent) Key Curator.
    """
    group, L = crs.group, crs.L
    if len(registrations) != L:
        raise ValueError("Slotted scheme: exactly L registrations required")
    for i, (pk, _) in enumerate(registrations):
        if not is_valid(crs, i, pk):
            raise ValueError(f"Invalid public key in slot {i}")

    universe = sorted(set(universe))
    pks = [pk for pk, _ in registrations]
    sets = [frozenset(S) for _, S in registrations]

    T_hat = group.init(G1, 1)
    for pk in pks:
        T_hat *= pk.T

    U_hat = {}
    for x in universe:
        acc = group.init(G1, 1)
        for j in range(L):
            if x not in sets[j]:
                acc *= crs.U[j]
        U_hat[x] = acc

    hsks = []
    for i in range(L):
        V_hat = group.init(G1, 1)
        for j in range(L):
            if j != i:
                V_hat *= pks[j].V[i]          # A_i^{r_j}
        W_hat = {}
        for x in universe:
            acc = group.init(G1, 1)
            for j in range(L):
                if j != i and x not in sets[j]:
                    acc *= crs.W[crs.f(i, j)]
            W_hat[x] = acc
        hsks.append(HelperKey(slot=i, attributes=sets[i], A=crs.A[i], B=crs.B[i],
                              V_hat=V_hat, W_hat=W_hat))

    mpk = MasterPublicKey(T_hat=T_hat, U_hat=U_hat, T=[pk.T for pk in pks], universe=universe)
    return mpk, hsks


# ----------------------------------------------------------------- Encrypt

def encrypt_offline(crs, F):
    """Offline phase: message- and policy-independent work, F = max policy rows."""
    group = crs.group
    s = group.random(ZR)
    h1 = group.random(G1)
    h2 = crs.h / h1
    s_k = [group.random(ZR) for _ in range(F)]
    return OfflineCiphertext(
        s=s, h1=h1, h2=h2,
        C1_tilde=crs.Z ** s,
        C2=crs.g ** s,
        C5_tilde=h1 ** s,
        s_k=s_k,
        C4=[crs.g ** sk for sk in s_k],
    )


def encrypt_online(crs, mpk, off, policy_expr, m, groups):
    """Online phase. groups: AttributeGroups (AGK values + member slots)."""
    group = crs.group
    pol = parse_policy(group, policy_expr)
    K = len(pol.rows)
    if K > len(off.s_k):
        raise ValueError(f"Policy has {K} rows; offline phase prepared {len(off.s_k)}")

    v = [off.s] + [group.random(ZR) for _ in range(pol.n - 1)]
    C3p, hdr, versions = [], {}, {}
    for k, (name, value) in enumerate(pol.rows):
        x = f"{name}:{value}"
        if x not in mpk.U_hat:
            raise ValueError(f"Attribute {x} not in registered universe")
        share = group.init(ZR, 0)
        for c in range(pol.n):
            share += group.init(ZR, pol.matrix[k][c]) * v[c]
        C3 = (off.h2 ** share) * (mpk.U_hat[x] ** (-off.s_k[k]))

        agk, version = groups.current(x)
        C3p.append(C3 ** agk)
        versions[k] = version
        agk_bytes = zr_to_bytes(group, agk)
        hdr[k] = {i: _xor(agk_bytes, _h(group, mpk.T[i] ** off.s, k))
                  for i in sorted(groups.members(x))}

    C1 = m * off.C1_tilde
    C5 = off.C5_tilde * (mpk.T_hat ** (-off.s))
    return Ciphertext(
        labelled_policy=pol.labelled, names=pol.names, matrix=pol.matrix, n=pol.n,
        C1=C1, C2=off.C2, C3p=C3p, C4=off.C4[:K], C5=C5,
        hdr=hdr, agk_versions=versions, kc=key_confirmation(group, m),
    )


def encrypt(crs, mpk, policy_expr, m, groups):
    rows = len(parse_policy(crs.group, policy_expr).rows)
    return encrypt_online(crs, mpk, encrypt_offline(crs, rows), policy_expr, m, groups)


# ----------------------------------------------------------------- Decrypt

class DecryptionFailed(Exception):
    pass


def decrypt(crs, hsk, sk, ct):
    """Decrypt(hsk_i, sk_i, Hdr_i, ct) -> m, or raise DecryptionFailed."""
    group, i = crs.group, hsk.slot
    my_values = {}
    for a in hsk.attributes:
        name, value = a.split(":", 1)
        my_values.setdefault(name, []).append(value)

    # Recover AGK for every row where (a) I hold that attribute name and
    # (b) the header contains an entry for my slot (i.e. I am in the AGK group).
    T_i_s = ct.C2 ** sk
    agk = {}
    for k, name in enumerate(ct.names):
        if name in my_values and i in ct.hdr.get(k, {}):
            agk[k] = bytes_to_zr(group, _xor(ct.hdr[k][i], _h(group, T_i_s, k)))
    if not agk:
        raise DecryptionFailed("No usable rows (attribute names absent or not in AGK group)")

    chosen = reconstruct_rows(group, ct.labelled_policy, ct.n, ct.matrix, sorted(agk))
    if chosen is None:
        raise DecryptionFailed("Usable rows do not satisfy the policy")

    base = (ct.C1 / pair(ct.C2, hsk.B)) * pair(ct.C5, hsk.A) * pair(ct.C2, hsk.V_hat)
    C2p = pair(ct.C2, hsk.A)

    # Policy hiding: values are not in the ciphertext, so try my value(s) per row.
    candidates = [my_values[ct.names[k]] for k in chosen]
    for guess in itertools.product(*candidates):
        D_attr = group.init(GT, 1)
        for k, value in zip(chosen, guess):
            x = f"{ct.names[k]}:{value}"
            A_prime = hsk.A ** (1 / agk[k])
            D_attr *= pair(ct.C3p[k], A_prime) * pair(ct.C4[k], hsk.W_hat[x])
        m = base * D_attr * (C2p ** sk)
        if key_confirmation(group, m) == ct.kc:
            return m
    raise DecryptionFailed("Attribute values do not satisfy the hidden policy")
