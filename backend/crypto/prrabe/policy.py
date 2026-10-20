"""Access policy -> LSSS (M, pi) with attribute name/value separation.

Policy syntax (monotone boolean formula):
    "(SECTOR:FINANCE and TRUST:HIGH) or ORGTYPE:CERT"

Each leaf NAME:VALUE becomes one LSSS row k with pi(k) = (name, value).
The ciphertext publishes only the names; values stay with the encryptor
(policy hiding, paper Section 1 and Section 5).

LSSS matrix generation and reconstruction use Charm's Lewko-Waters MSP
implementation. Reconstruction target is (1, 0, ..., 0) and, for the
pruned minimal set, all reconstruction coefficients omega_j are 1.
"""

import re
from dataclasses import dataclass

from charm.toolbox.msp import MSP

ATTR_RE = re.compile(r"\b([A-Z][A-Z0-9]*):([A-Z0-9]+)\b")


def attr(name, value):
    """Canonical attribute string used throughout the module."""
    a = f"{name.upper()}:{value.upper()}"
    if not ATTR_RE.fullmatch(a):
        raise ValueError(f"Invalid attribute {a!r}; use NAME:VALUE, A-Z/0-9 only")
    return a


@dataclass
class LSSSPolicy:
    expression: str     # original policy (secret: contains values)
    labelled: str       # policy with leaves replaced by ROW<k> labels
    rows: list          # rows[k] = (name, value)
    matrix: list        # matrix[k] = list[int], padded to n columns
    n: int

    @property
    def names(self):
        """Public part of pi: attribute names per row."""
        return [name for name, _ in self.rows]


def _label(k):
    # Charm treats '_' as an index separator, so labels are alphanumeric only.
    return f"ROW{k}"


def parse_policy(group, expression):
    rows = []

    def repl(match):
        rows.append((match.group(1), match.group(2)))
        return _label(len(rows) - 1)

    labelled = ATTR_RE.sub(repl, expression.upper().replace(" AND ", " and ").replace(" OR ", " or "))
    if not rows:
        raise ValueError("Policy has no NAME:VALUE attributes")

    msp = MSP(group)
    tree = msp.createPolicy(labelled)
    raw = msp.convert_policy_to_msp(tree)
    n = msp.len_longest_row
    matrix = []
    for k in range(len(rows)):
        r = list(raw[_label(k)])
        matrix.append(r + [0] * (n - len(r)))
    return LSSSPolicy(expression=expression, labelled=labelled, rows=rows, matrix=matrix, n=n)


def reconstruct_rows(group, labelled, n, matrix, usable_rows):
    """Return a minimal satisfying subset of usable_rows, or None.

    usable_rows: row indices the decryptor can use. Coefficients are all 1;
    we assert sum of selected rows == (1, 0, ..., 0) as a sanity check.
    """
    msp = MSP(group)
    tree = msp.createPolicy(labelled)
    pruned = msp.prune(tree, [_label(k) for k in usable_rows])
    if not pruned:
        return None
    chosen = [int(node.getAttributeAndIndex()[3:]) for node in pruned]
    total = [sum(matrix[k][c] for k in chosen) for c in range(n)]
    if total != [1] + [0] * (n - 1):
        raise AssertionError("LSSS reconstruction check failed")
    return chosen
