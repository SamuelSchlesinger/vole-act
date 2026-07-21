#!/usr/bin/env python3
"""Validate the displayed snapshot against raw Criterion estimates and sizes.

This does not rerun Criterion. It derives every timing and stored-baseline
summary from the committed raw export, then checks the rounded display cache.
No third-party dependencies are required.
"""

import json
from pathlib import Path


SNAPSHOT = json.loads(
    Path(__file__).with_name("current_wrapper_snapshot.json").read_text(encoding="utf-8")
)
RAW = json.loads(
    Path(__file__).with_name("criterion-2026-07-21.json").read_text(encoding="utf-8")
)
PROFILES = tuple(SNAPSHOT["profiles"])
OLD_DIRECT_PROOF = tuple(SNAPSHOT["old_direct_proof_bytes"])
OLD_DEFERRED_PROOF = tuple(SNAPSHOT["old_deferred_proof_bytes"])
COMMON_PROOF = tuple(SNAPSHOT["common_proof_bytes"])
CURRENT_SPEND_REQUEST = tuple(SNAPSHOT["current_spend_request_bytes"])
BENCHMARKS = RAW["benchmarks"]
BASELINE = RAW["stored_baseline_relative_change"]["benchmarks"]


def rounded_ms(name: str) -> float:
    return float(f"{BENCHMARKS[name]['point_estimate'] / 1_000_000:.2f}")


ISSUE_PROVE_MS = tuple(
    rounded_ms(f"profiles/issue_client-prove/{profile}") for profile in PROFILES
)
DIRECT_PROVE_MS = tuple(
    rounded_ms(f"profiles/direct-input_client-prove/{profile}") for profile in PROFILES
)
DEFERRED_PROVE_MS = tuple(
    rounded_ms(f"profiles/deferred-input_client-prove/{profile}") for profile in PROFILES
)
BALANCED_ISSUER_SPEND_MS = tuple(
    rounded_ms(name)
    for name in (
        "balanced/direct-input_issuer-verify-and-sign",
        "balanced/deferred-input_issuer-verify-and-sign",
        "balanced/deferred-return_issuer-verify-and-sign",
    )
)
BALANCED_END_TO_END_MS = tuple(
    rounded_ms(name)
    for name in (
        "balanced/direct_end-to-end",
        "balanced/deferred-input_direct-end-to-end",
        "balanced/deferred-return_end-to-end",
    )
)

for field, derived in (
    ("issue_prove_ms", ISSUE_PROVE_MS),
    ("direct_prove_ms", DIRECT_PROVE_MS),
    ("deferred_prove_ms", DEFERRED_PROVE_MS),
    ("balanced_issuer_spend_ms", BALANCED_ISSUER_SPEND_MS),
    ("balanced_end_to_end_ms", BALANCED_END_TO_END_MS),
):
    assert tuple(SNAPSHOT[field]) == derived, (field, SNAPSHOT[field], derived)


def percent_increase(new: int, old: int) -> float:
    return 100.0 * (new - old) / old


for index, profile in enumerate(PROFILES):
    direct_delta = percent_increase(COMMON_PROOF[index], OLD_DIRECT_PROOF[index])
    deferred_delta = percent_increase(COMMON_PROOF[index], OLD_DEFERRED_PROOF[index])
    print(
        f"{profile}: common proof={COMMON_PROOF[index]} bytes; "
        f"vs old direct={direct_delta:.2f}%; "
        f"vs old deferred={deferred_delta:.2f}%"
    )

print(
    "current proof range: "
    f"{min(COMMON_PROOF)}..{max(COMMON_PROOF)} bytes"
)
print(
    "current spend-request range: "
    f"{min(CURRENT_SPEND_REQUEST)}..{max(CURRENT_SPEND_REQUEST)} bytes"
)
print(
    "current issue-prove range: "
    f"{min(ISSUE_PROVE_MS):.2f}..{max(ISSUE_PROVE_MS):.2f} ms"
)
all_spend_prove = DIRECT_PROVE_MS + DEFERRED_PROVE_MS
print(
    "current spend-prove range: "
    f"{min(all_spend_prove):.2f}..{max(all_spend_prove):.2f} ms"
)
print(
    "balanced issuer-spend range: "
    f"{min(BALANCED_ISSUER_SPEND_MS):.2f}..{max(BALANCED_ISSUER_SPEND_MS):.2f} ms"
)
print(
    "balanced spend end-to-end range: "
    f"{min(BALANCED_END_TO_END_MS):.2f}..{max(BALANCED_END_TO_END_MS):.2f} ms"
)
print(
    "balanced spend end-to-end means: "
    + ",".join(f"{value:.2f}" for value in BALANCED_END_TO_END_MS)
    + " ms"
)
print(
    "salt wire deltas: "
    f"token={SNAPSHOT['current_token_bytes'] - SNAPSHOT['old_token_bytes']}, "
    f"issue-response={SNAPSHOT['current_issue_response_bytes'] - SNAPSHOT['old_issue_response_bytes']}, "
    f"spend-response={SNAPSHOT['current_spend_response_bytes'] - SNAPSHOT['old_spend_response_bytes']} bytes"
)
direct_regressions = tuple(
    round(BASELINE[f"profiles/direct-input_client-prove/{profile}"]["point_estimate"] * 100)
    for profile in PROFILES
)
regression = tuple(SNAPSHOT["criterion_direct_prover_regression_percent"])
assert regression == (min(direct_regressions), max(direct_regressions))
print(f"Criterion stored-baseline direct-prover regression: {regression[0]}..{regression[1]}%")
print(
    "Criterion stored-baseline Balanced regressions: "
    f"direct issuer={round(BASELINE['balanced/direct-input_issuer-verify-and-sign']['point_estimate'] * 100)}%, "
    f"direct end-to-end={round(BASELINE['balanced/direct_end-to-end']['point_estimate'] * 100)}%"
)
