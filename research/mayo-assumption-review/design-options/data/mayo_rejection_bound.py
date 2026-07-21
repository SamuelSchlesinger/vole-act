#!/usr/bin/env python3
"""Evaluate Lemma 1's MAYO rejection bound for the Round 2 parameter sets.

The specification defines

    B = q^(k-(n-o))/(q-1) + q^(m-ko)/(q-1).

Its EUF-CMA theorem assumes Q_s * B < 1; Section 5.3 uses Q_s * B < 1/2
as the constant-factor regime.
"""

import math


PARAMETERS = {
    "MAYO1": (86, 78, 8, 10),
    "MAYO2": (81, 64, 17, 4),
    "MAYO3": (118, 108, 10, 11),
    "MAYO5": (154, 142, 12, 12),
}
Q = 16


for name, (n, m, o, k) in PARAMETERS.items():
    bound = (Q ** (k - (n - o)) + Q ** (m - k * o)) / (Q - 1)
    half_loss_queries = 1 / (2 * bound)
    print(
        f"{name}: log2(B)={math.log2(bound):.4f}, "
        f"log2(1/(2B))={math.log2(half_loss_queries):.4f}"
    )
