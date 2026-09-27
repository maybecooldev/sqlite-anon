"""Command line interface.

Exit codes: 0 clean, 1 findings above the threshold, 2 bad usage.
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys

from . import __version__
from .anonymize import anonymize, build_plan
from .detect import CATEGORIES
from .transform import AnonymisationError, load_or_create_key

DEFAULT_SUFFIX = ".anon.db"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sqlite-anon",
        description="Make an anonymised copy of a SQLite database, keeping joins intact.",
    )
    parser.add_argument("database", help="path to the SQLite file to read (never modified)")
    parser.add_argument(
        "-o", "--output", help="where to write the copy (default: alongside the input)"
    )
    parser.add_argument(
        "--key-file",
        help="file holding the 32-byte HMAC key; reuse it to keep two copies consistent",
    )
    parser.add_argument(
        "--create-key", action="store_true", help="generate the key file if it is missing"
    )
    parser.add_argument(
        "--report",
        action="store_true",
        help="print what would change and exit, without writing anything",
    )
    parser.add_argument(
        "--min-confidence",
        type=float,
        default=0.0,
        metavar="N",
        help="only rewrite columns detected with at least this confidence (0-1)",
    )
    parser.add_argument(
        "--only",
        help="comma-separated categories to rewrite, overriding the detector",
    )
    parser.add_argument(
        "--category",
        action="append",
        choices=sorted(CATEGORIES),
        help="only rewrite this category; repeatable",
    )
    parser.add_argument("--sample-rows", type=int, default=200, help="rows to sample per table")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument("--version", action="version", version=f"sqlite-anon {__version__}")
    return parser


def destination_for(source: str, output: str | None) -> str:
    if output:
        return output
    base, extension = os.path.splitext(source)
    return (base if extension else source) + DEFAULT_SUFFIX


def render_report(plan, fmt: str) -> str:
    if fmt == "json":
        return json.dumps(
            {
                "source": plan.source,
                "tables": plan.table_count,
                "rows": plan.row_count,
                "columns": [
                    {
                        "table": item.column.table,
                        "column": item.column.name,
                        "category": item.column.category,
                        "confidence": round(item.column.confidence, 2),
                        "declared_type": item.column.declared_type,
                        "why": [evidence.describe() for evidence in item.column.evidence],
                    }
                    for item in plan.columns
                ],
            },
            indent=2,
        )

    lines = [f"{plan.source}: {plan.table_count} table(s), {plan.row_count} row(s)"]
    if not plan.columns:
        lines.append("")
        lines.append("  no personal data detected")
        return "\n".join(lines)

    lines.append("")
    for item in sorted(plan.columns, key=lambda i: (i.column.table, i.column.name)):
        column = item.column
        lines.append(f"  {column.path:<32} {column.category or '?':<14} {column.confidence:.2f}")
        for evidence in column.evidence:
            lines.append(f"      {evidence.describe()}")
    lines.append("")
    lines.append(f"  {len(plan.columns)} column(s) across {plan.by_category}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if not os.path.isfile(args.database):
        print(f"error: no such file: {args.database}", file=sys.stderr)
        return 2

    if args.create_key and not args.key_file:
        print("error: --create-key needs --key-file to say where to put it", file=sys.stderr)
        return 2

    only: set[str] | None = None
    if args.category:
        only = set(args.category)
    elif args.only:
        only = {part.strip() for part in args.only.split(",") if part.strip()}

    try:
        if args.report:
            plan = build_plan(args.database, args.min_confidence, args.sample_rows)
            if only is not None:
                plan.columns = [item for item in plan.columns if item.column.category in only]
            print(render_report(plan, args.format))
            return 0

        key = load_or_create_key(args.key_file, create=args.create_key)
        target = destination_for(args.database, args.output)
        if os.path.abspath(target) == os.path.abspath(args.database):
            print(
                "error: refusing to write over the input; pass -o with a different path",
                file=sys.stderr,
            )
            return 2

        plan = anonymize(
            args.database,
            target,
            key,
            min_confidence=args.min_confidence,
            sample_rows=args.sample_rows,
            only=only,
        )
    except AnonymisationError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    except sqlite3.Error as error:
        print(f"error: {error}", file=sys.stderr)
        return 1

    if args.format == "json":
        print(
            json.dumps(
                {"output": target, "columns": len(plan.columns), "rows": plan.row_count},
                indent=2,
            )
        )
    else:
        print(f"wrote {target}")
        print(f"  {len(plan.columns)} column(s) rewritten across {plan.row_count} row(s)")
        if not args.key_file:
            print(
                "  note: no --key-file was given, so this mapping cannot be reproduced",
                file=sys.stderr,
            )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
