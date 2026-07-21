#!/usr/bin/env python3
"""Reproduce representative MAYO2 salted-wrapper loss terms.

The cap bound is intentionally the conservative result justified by the
Round-2 average-over-key Lemma 1.  This script does not report B**256 as a
proved exhaustion bound.
"""

from math import log2


Q = 16
N, M, O, K = 81, 64, 17, 4
SALT_BITS = 256

# Representative, explicit query counts; edit these constants to explore a
# deployment envelope.
Q_S = 2**18
Q_H = 2**32
# Total distinct credential-v2 ideal-XOF inputs, including adversarial offline
# grinding plus honest, reduction-generated, and extracted inputs.
Q_CRED = 2**32
Q_TRY = 2**19
# The winner-only coupling uses Q_S only under response-oblivious winner
# selection. Q_TRY is separate: it controls the conservative bounded-sampler
# failure term and does not repair a first-arrival timing leak.
Q_CPL = Q_S


def log2_probability(value: float) -> str:
    if value == 0:
        return "-inf"
    return f"{log2(value):.6f}"


def main() -> None:
    bound = (Q ** (K - (N - O)) + Q ** (M - K * O)) / (Q - 1)
    sampler_product = Q_CPL * bound
    sampler_factor = 1 / (1 - sampler_product)

    salt_prequery = Q_S * Q_H / 2**SALT_BITS
    salt_repeat = Q_S * (Q_S - 1) / (2 * 2**SALT_BITS)
    credential_collision = Q_CRED * (Q_CRED - 1) / (2 * 2 ** (4 * M))
    unqueried_target = Q ** (-M)

    # Lemma 1 gives E[p_K] <= B. Since 0 <= p_K <= 1,
    # E[p_K**256] <= E[p_K] <= B. A B**256 claim would need a
    # per-key bound which the lemma does not state.
    cap_union_bound = min(1.0, Q_TRY * bound)

    print(f"B={bound:.18e} log2(B)={log2(bound):.6f}")
    print(
        f"Q_cpl={Q_CPL} (response_oblivious_Q_s) "
        f"Q_cpl*B={sampler_product:.12f} "
        f"sampler_factor={sampler_factor:.12f}"
    )
    print(
        f"salt_prequery={salt_prequery:.18e} "
        f"log2={log2_probability(salt_prequery)}"
    )
    print(
        f"salt_repeat={salt_repeat:.18e} "
        f"log2={log2_probability(salt_repeat)}"
    )
    print(
        f"Q_cred={Q_CRED} credential_collision={credential_collision:.18e} "
        f"log2={log2_probability(credential_collision)}"
    )
    print(
        f"unqueried_target={unqueried_target:.18e} "
        f"log2={log2_probability(unqueried_target)}"
    )
    print(
        f"safe_cap_union_bound={cap_union_bound:.12f} "
        f"for_Q_try={Q_TRY} (uses E[p_K^256] <= B, not B^256)"
    )


if __name__ == "__main__":
    main()
