#!/usr/bin/env python3
"""Reproduce the MAYO2 rank-rejection bound used in the reduction notes.

No third-party dependencies are required.  The formula is the bound B from
Lemma 1 / Theorem 1 of the MAYO round-2 specification.
"""

from math import log2


def main() -> None:
    q, n, m, o, k = 16, 81, 64, 17, 4
    first = q ** (k - (n - o)) / (q - 1)
    second = q ** (m - k * o) / (q - 1)
    bound = first + second
    print(f"first_term={first:.18e}")
    print(f"second_term={second:.18e}")
    print(f"B={bound:.18e}")
    print(f"-log2(B)={-log2(bound):.12f}")
    for samples in (2**18, 2**19, 491_520, 900_000):
        product = samples * bound
        factor = float("inf") if product >= 1 else 1 / (1 - product)
        print(
            f"samples={samples} Q_times_B={product:.12f} "
            f"loss_factor={factor:.12f}"
        )


if __name__ == "__main__":
    main()
