"""Command line entry point.

    python -m email_guard message.eml [--pretty]
    python -m email_guard --from-json sample.json
    python -m email_guard --validate-rules
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from . import __version__, config, parse
from .lists import Lists
from .pipeline import scan_parsed
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
        "--job-id", metavar="ID", help="fixed job id (default: a fresh uuid per run)"
    )
    parser.add_argument("--version", action="version", version=f"email-guard {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        settings = config.load(
            config_path=args.config, lists_dir=args.lists_dir, rules_dir=args.rules_dir
        )
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    if args.validate_rules:
        return _validate_only(settings.rules_dir)

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
        parsed = (
            parse.parse_json_file(args.from_json)
            if args.from_json
            else parse.parse_eml_file(args.eml)
        )
    except OSError as exc:
        print(f"error: cannot read message: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except json.JSONDecodeError as exc:
        print(f"error: --from-json file is not valid JSON: {exc}", file=sys.stderr)
        return EXIT_ERROR

    lists = Lists.load(settings.lists_dir)
    verdict = scan_parsed(parsed, lists, pack, job_id=args.job_id)

    print(dump(verdict, pretty=args.pretty))
    return EXIT_OK


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
