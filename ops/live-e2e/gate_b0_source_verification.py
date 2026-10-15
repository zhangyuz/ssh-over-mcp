"""Synthetic-only B0a CLI; no real verifier authority is configured yet.

No T5 signature-root policy is authenticated, so even an allowlisted fixture
must refuse. This deliberately has NO success or package-validation path.
"""
from __future__ import annotations

import sys

from gate_b0_evidence import format_refusal

_HELP = (
    "Usage: gate_b0_source_verification.py verify-synthetic "
    "--fixture signed-test-key-1 --format json\n"
    "Synthetic only; T5 policy approval and a real pinned verifier required.\n"
)


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if type(args) is not list or any(type(x) is not str for x in args):
        sys.stdout.buffer.write(format_refusal("CLI_ARGS_REJECTED"))
        return 2
    if args == ["--help"]:
        sys.stdout.write(_HELP)
        return 0
    if (
        len(args) != 5
        or args[0] != "verify-synthetic"
        or args[1] != "--fixture"
        or args[3:] != ["--format", "json"]
    ):
        sys.stdout.buffer.write(format_refusal("CLI_ARGS_REJECTED"))
        return 2
    if args[2] != "signed-test-key-1":
        sys.stdout.buffer.write(format_refusal("FIXTURE_NOT_APPROVED"))
        return 2
    # The test-key fixture, trust roots, signed time, exact verifier closure and
    # handoff mode have NOT been independently approved. Never invent GREEN.
    sys.stdout.buffer.write(format_refusal("T5_POLICY_UNAPPROVED"))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
