"""Pairing group, index set and CRS generation for PR-RABE_P.

Follows Yang et al., "PR-RABE", Computer Standards & Interfaces 98 (2026),
Section 5.2 (prime-order construction), Setup algorithm.

Group: Charm-Crypto "SS512" (PBC Type-A, symmetric pairing e: G x G -> GT).
The paper's construction assumes a symmetric pairing, so it maps onto SS512
directly. SS512 gives roughly 80-bit security: prototype grade, not production.
"""

from dataclasses import dataclass, field

from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, pair

GROUP_NAME = "SS512"


def get_group():
    return PairingGroup(GROUP_NAME)


def progression_free_set(L):
    """Return L positive integers that are progression-free and double-free.

    Construction: positive integers whose base-3 digits are only 0 or 1
    (Salem-Spencer set). Adding two such numbers never carries, so
    i + j = 2k forces i = j (progression-free), and 2j has a digit 2 so it is
    never in the set (double-free).

    Note: the paper states that sums d_i + d_j are all distinct. That is not
    true for this set (1 + 12 = 4 + 9), but correctness does not rely on it:
    W_z is simply shared by pairs with equal sums. Recorded in docs.
    """
    out, n = [], 1
    while len(out) < L:
        m, ok = n, True
        while m:
            if m % 3 == 2:
                ok = False
                break
            m //= 3
        if ok:
            out.append(n)
        n += 1
    return out


@dataclass
class CRS:
    """Common reference string. Public. Contains no trapdoor."""

    group: PairingGroup
    L: int
    g: object
    h: object
    Z: object                      # e(g, g)^alpha in GT
    D: list                        # d_1..d_L
    A: list                        # A_i = g^{t_i}
    B: list                        # B_i = g^alpha * h^{t_i}
    P: list                        # P_i = g^{delta_i}
    U: list                        # U_i = g^{b t_i}
    W: dict = field(default_factory=dict)   # z -> g^{b a^z}

    def f(self, i, j):
        return self.D[i] + self.D[j]


def setup(L, group=None):
    """Setup(1^lambda, 1^L) -> crs.

    The secrets a, b, alpha and delta_i are local variables and are discarded
    when this function returns (trusted-setup assumption, documented).
    """
    group = group or get_group()
    D = progression_free_set(L)
    F = {D[i] + D[j] for i in range(L) for j in range(L) if i != j}
    d_max = 3 * max(F)

    g = group.random(G1)
    a = group.random(ZR)
    b = group.random(ZR)
    alpha = -(a ** d_max)

    h = group.init(G1, 1)
    for i in range(L):
        h *= g ** (a ** (d_max - D[i]))

    A, B, P, U = [], [], [], []
    for i in range(L):
        t_i = a ** D[i]
        delta_i = group.random(ZR)
        A.append(g ** t_i)
        B.append((g ** alpha) * (h ** t_i))
        P.append(g ** delta_i)
        U.append(g ** (b * t_i))

    W = {z: g ** (b * (a ** z)) for z in sorted(F)}
    Z = pair(g, g) ** alpha

    return CRS(group=group, L=L, g=g, h=h, Z=Z, D=D, A=A, B=B, P=P, U=U, W=W)
