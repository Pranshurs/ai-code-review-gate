"""``aicrg`` command line.

Exit codes are part of the contract and never overlap:

    0  PASS
    1  FAIL             the patch failed the gate
    2  usage error      (argparse)
    3  REVIEW_REQUIRED  a human must decide
    4  ERROR            the gate could not complete
    5  receipt verification failed
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from aicrg import __version__
from aicrg.model import Decision

EXIT = {Decision.PASS: 0, Decision.FAIL: 1, Decision.REVIEW_REQUIRED: 3, Decision.ERROR: 4}
EXIT_VERIFY_FAILED = 5


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="aicrg", description="AI Code Review Gate")
    p.add_argument("--version", action="version", version=f"aicrg {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    c = sub.add_parser("check", help="evaluate base..head and write a receipt")
    c.add_argument("--base", required=True, help="target revision (e.g. origin/main)")
    c.add_argument("--head", default="HEAD", help="revision under review (default HEAD)")
    c.add_argument(
        "--policy", help="review contract path (repo-relative unless --policy-from file)"
    )
    c.add_argument(
        "--policy-from",
        choices=("base", "file"),
        default="base",
        help="read the contract from the base commit (default) or the filesystem",
    )
    c.add_argument(
        "--receipt-dir",
        default=".aicrg/receipts",
        help="where to write the receipt (default .aicrg/receipts)",
    )
    c.add_argument("--receipt", help="write the receipt to exactly this path")
    c.add_argument(
        "--no-run",
        action="store_true",
        help="do not execute required checks (decision becomes ERROR if any exist)",
    )
    c.add_argument(
        "--executor",
        choices=("local", "container"),
        help="evidence executor; may upgrade 'local' to 'container', never downgrade",
    )
    c.add_argument(
        "--container-image", help="image for --executor container (if the contract has none)"
    )
    c.add_argument(
        "--bundle",
        action="append",
        default=[],
        metavar="NAME=PATH",
        help="location of a trusted evidence bundle (its digest is pinned by the base contract)",
    )
    c.add_argument(
        "--evidence",
        action="append",
        default=[],
        metavar="NAME=PATH",
        help="report file for an external_evidence entry (e.g. a CodeQL SARIF)",
    )
    c.add_argument(
        "--no-potency",
        action="store_true",
        help="skip test potency (decision becomes ERROR if the contract requires it)",
    )
    c.add_argument("--format", choices=("text", "json", "markdown"), default="text")
    c.add_argument(
        "--summary-file", help="also append a Markdown summary here (e.g. $GITHUB_STEP_SUMMARY)"
    )

    v = sub.add_parser("verify-receipt", help="check a receipt still authorises the current head")
    v.add_argument("receipt")
    v.add_argument("--head", default="HEAD")
    v.add_argument("--base", help="also require the base branch/policy to be unchanged")
    v.add_argument(
        "--allow-non-pass",
        action="store_true",
        help="verify binding only; do not require decision PASS",
    )

    pv = sub.add_parser("policy", help="review-contract utilities")
    pv_sub = pv.add_subparsers(dest="policy_command", required=True)
    val = pv_sub.add_parser("validate", help="parse a contract file and print its digest")
    val.add_argument("path")
    pv_sub.add_parser("show-default", help="print the built-in default contract")

    sub.add_parser("rules", help="list every finding code and how its severity is chosen")

    b = sub.add_parser("bundle", help="trusted evidence bundle utilities")
    b_sub = b.add_subparsers(dest="bundle_command", required=True)
    bd = b_sub.add_parser("digest", help="print the aicrg-tree-v1 digest of a directory or tar")
    bd.add_argument("path")
    return p


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "check":
            return _check(args)
        if args.command == "verify-receipt":
            return _verify(args)
        if args.command == "policy":
            return _policy(args)
        if args.command == "rules":
            return _rules()
        if args.command == "bundle":
            return _bundle(args)
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return EXIT[Decision.ERROR]
    except Exception as exc:  # last line of defence: a crash is ERROR, never PASS
        print(f"aicrg: internal error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return EXIT[Decision.ERROR]
    return 2


def _check(args: argparse.Namespace) -> int:
    from aicrg.gate import GateOptions, run_gate
    from aicrg.receipt.receipt import write_receipt
    from aicrg.render import render_markdown, render_text

    opts = GateOptions(
        base=args.base,
        head=args.head,
        policy=args.policy,
        policy_from=args.policy_from,
        run_checks=not args.no_run,
        executor=args.executor,
        container_image=args.container_image,
        bundles=_pairs(args.bundle, "--bundle"),
        external_evidence=_pairs(args.evidence, "--evidence"),
        run_potency=not args.no_potency,
    )
    result = run_gate(opts)
    try:
        if args.receipt:
            out = Path(args.receipt)
            out.parent.mkdir(parents=True, exist_ok=True)
            tmp = out.with_suffix(out.suffix + ".tmp")
            tmp.write_text(
                json.dumps(result.receipt, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
            tmp.replace(out)
            result.receipt_path = out
        else:
            result.receipt_path = write_receipt(result.receipt, Path(args.receipt_dir))
    except OSError as exc:
        print(f"aicrg: cannot write receipt: {exc}", file=sys.stderr)
        return EXIT[Decision.ERROR]
    if args.format == "json":
        print(json.dumps(result.receipt, indent=2, sort_keys=True, ensure_ascii=False))
    elif args.format == "markdown":
        print(render_markdown(result))
    else:
        print(render_text(result), end="")
    if args.summary_file:
        with open(args.summary_file, "a", encoding="utf-8") as fh:
            fh.write(render_markdown(result))
    return EXIT[result.decision]


def _pairs(values: list[str], flag: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for v in values:
        name, sep, path = v.partition("=")
        if not sep or not name or not path:
            raise SystemExit(f"aicrg: {flag} expects NAME=PATH, got {v!r}")
        out[name] = path
    return out


def _bundle(args: argparse.Namespace) -> int:
    from aicrg.evidence.trusted import TrustedEvidenceError, read_bundle, tree_digest

    try:
        entries = read_bundle(Path(args.path))
    except TrustedEvidenceError as exc:
        print(f"bundle INVALID: {exc}")
        return EXIT[Decision.ERROR]
    print(tree_digest(entries))
    return 0


def _verify(args: argparse.Namespace) -> int:
    from aicrg.receipt.verify import verify_receipt

    v = verify_receipt(
        Path(args.receipt),
        Path.cwd(),
        head=args.head,
        base=args.base,
        require_pass=not args.allow_non_pass,
    )
    if v.ok:
        subj = (v.receipt or {}).get("subject", {})
        print(
            f"receipt OK: {v.receipt.get('decision') if v.receipt else '?'} for head "
            f"{str(subj.get('head'))[:12]} ({(v.receipt or {}).get('receipt_digest')})"
        )
        return 0
    print("receipt REJECTED:")
    for p in v.problems:
        print(f"  - {p}")
    return EXIT_VERIFY_FAILED


def _policy(args: argparse.Namespace) -> int:
    from aicrg.policy.contract import PolicyError, ReviewContract, parse_contract

    if args.policy_command == "show-default":
        print(json.dumps(ReviewContract().canonical(), indent=2, sort_keys=True, default=list))
        return 0
    try:
        contract = parse_contract(Path(args.path).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError) as exc:
        print(f"policy INVALID: {exc}")
        return EXIT[Decision.ERROR]
    except PolicyError as exc:
        print(f"policy INVALID: {exc}")
        return EXIT[Decision.ERROR]
    print(f"policy OK: {contract.digest()}")
    print(json.dumps(contract.canonical(), indent=2, sort_keys=True, default=list))
    return 0


def _rules() -> int:
    from aicrg.rules import RULES

    for code, rule in sorted(RULES.items()):
        if rule.fixed is not None:
            how = rule.fixed.value
        elif rule.change_class is not None:
            how = f"block if forbidden_changes has {rule.change_class}, else review"
        else:
            how = "contract-dependent (see summary)"
        print(
            f"{code:<34} {rule.category:<15} {rule.kind.value:<13} {how}\n{'':<34} {rule.summary}"
        )
    return 0


if __name__ == "__main__":  # pragma: no cover
    if os.environ.get("AICRG_DEBUG"):
        sys.tracebacklimit = 1000
    raise SystemExit(main())
