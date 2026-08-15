"""Command line entry point.

    python -m email_guard message.eml [--pretty]
    python -m email_guard --from-json sample.json
    python -m email_guard --from-json sample.json --dry-run
    python -m email_guard --validate-rules

By default a scan now *writes*: the verdict and the original message land in
``<outbound_dir>/<bucket>/<job>/``, and an unfamiliar sender or an uncatalogued
message shape stages a candidate under ``<daily_brief_dir>/daily-brief-<date>/``.
``--dry-run`` is the old behaviour -- compute, print, touch nothing.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import date
from pathlib import Path
from typing import Any

from . import __version__, config, parse
from .lists import Lists
from .pipeline import scan_and_write
from .route import SourceMessage
from .rulespack import InvalidRulesPack, RulesPack, run_validator

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_INVALID_RULES = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="email_guard",
        description="Scan one email and print a structured verdict as JSON.",
    )
    parser.add_argument("eml", nargs="?", help="path to a raw RFC822 .eml file")
    parser.add_argument(
        "--from-json",
        metavar="PATH",
        help="load a pre-parsed message in the n8n IMAP shape instead of an .eml",
    )
    parser.add_argument("--pretty", action="store_true", help="indent the JSON output")
    parser.add_argument(
        "--validate-rules",
        action="store_true",
        help="validate the rules pack and exit",
    )
    parser.add_argument("--config", metavar="PATH", help="path to config.json")
    parser.add_argument("--lists-dir", metavar="DIR", help="directory holding the live lists")
    parser.add_argument("--rules-dir", metavar="DIR", help="directory holding the rules pack")
    parser.add_argument(
        "--outbound-dir",
        metavar="DIR",
        help="directory for routed output (cleared/ flagged/ rejected/)",
    )
    parser.add_argument(
        "--daily-brief-dir",
        metavar="DIR",
        help="directory for staged daily-brief candidates",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="compute and print the verdict without writing anything",
    )
    parser.add_argument(
        "--now",
        metavar="YYYY-MM-DD",
        help="date for the daily-brief folder (default: today)",
    )
    parser.add_argument(
        "--job-id", metavar="ID", help="fixed job id (default: a fresh uuid per run)"
    )
    parser.add_argument("--version", action="version", version=f"email-guard {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        settings = config.load(
            config_path=args.config,
            lists_dir=args.lists_dir,
            rules_dir=args.rules_dir,
            outbound_dir=args.outbound_dir,
            daily_brief_dir=args.daily_brief_dir,
        )
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    if args.validate_rules:
        return _validate_only(settings.rules_dir)

    try:
        now = date.fromisoformat(args.now) if args.now else None
    except ValueError:
        print(f"error: --now must be a YYYY-MM-DD date, got {args.now!r}", file=sys.stderr)
        return EXIT_ERROR

    if not args.eml and not args.from_json:
        parser.error("give a path to an .eml file, or --from-json PATH")
    if args.eml and args.from_json:
        parser.error("give either an .eml path or --from-json, not both")

    # The engine refuses to run on an invalid pack -- a malformed pack must be
    # rejected before it can affect a verdict (root README, "Engine vs rules pack").
    try:
        pack = RulesPack.load(settings.rules_dir)
    except InvalidRulesPack as exc:
        _report_pack_errors(settings.rules_dir, exc.errors)
        return EXIT_INVALID_RULES

    try:
        parsed, source = _read_message(args.eml, args.from_json)
    except OSError as exc:
        print(f"error: cannot read message: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except ValueError as exc:
        # JSONDecodeError and UnicodeDecodeError are both ValueErrors.
        print(f"error: --from-json file is not valid JSON: {exc}", file=sys.stderr)
        return EXIT_ERROR

    lists = Lists.load(settings.lists_dir)
    try:
        verdict = scan_and_write(
            parsed,
            lists,
            pack,
            source,
            outbound_dir=settings.outbound_dir,
            daily_brief_dir=settings.daily_brief_dir,
            job_id=args.job_id,
            now=now,
            dry_run=args.dry_run,
        )
    except OSError as exc:
        print(f"error: cannot write outputs: {exc}", file=sys.stderr)
        return EXIT_ERROR

    print(dump(verdict, pretty=args.pretty))
    _report_written(verdict)
    return EXIT_OK


def _read_message(eml_path: str | None, json_path: str | None):
    """Read the message once, keeping the raw bytes for the verbatim copy.

    The copy stored beside the report must be what arrived, not a
    re-serialisation of the parsed form, so the bytes are held rather than the
    file re-read at write time.
    """
    if json_path:
        raw = Path(json_path).read_bytes()
        payload = json.loads(raw)
        if not isinstance(payload, dict):
            raise ValueError("expected a JSON object at the top level")
        return parse.parse_json(payload), SourceMessage.from_json(raw)

    raw = Path(eml_path).read_bytes()
    return parse.parse_eml(raw), SourceMessage.from_eml(raw)


def _report_written(verdict: dict[str, Any]) -> None:
    """Human-readable trail on stderr; stdout stays pure JSON for piping."""
    written = verdict.get("written")
    if not written:
        return
    print(f"wrote {written['report']}", file=sys.stderr)
    print(f"wrote {written['message']}", file=sys.stderr)
    if written.get("candidate"):
        print(f"wrote {written['candidate']}", file=sys.stderr)


def dump(verdict: dict[str, Any], pretty: bool = False) -> str:
    return json.dumps(verdict, indent=2 if pretty else None, ensure_ascii=False)


def _validate_only(rules_dir) -> int:
    try:
        errors = run_validator(rules_dir)
    except Exception as exc:  # a validator that cannot run is itself a failure
        print(f"rules pack INVALID ({rules_dir}): validator raised {exc}", file=sys.stderr)
        return EXIT_INVALID_RULES
    if errors:
        _report_pack_errors(rules_dir, errors, scanning=False)
        return EXIT_INVALID_RULES
    print(f"rules pack OK: {rules_dir}")
    return EXIT_OK


def _report_pack_errors(rules_dir, errors: list[str], scanning: bool = True) -> None:
    print(f"rules pack INVALID ({rules_dir}):", file=sys.stderr)
    for error in errors:
        print(f"  - {error}", file=sys.stderr)
    if scanning:
        print("refusing to scan with an invalid rules pack", file=sys.stderr)
