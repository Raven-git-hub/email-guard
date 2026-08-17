"""``python -m email_guard.eval`` -- the pre-push gate, and the corpus importer.

    python -m email_guard.eval tests/eval-corpus
    python -m email_guard.eval data/eval-corpus --json run.json
    python -m email_guard.eval data/eval-corpus --baseline previous.json
    python -m email_guard.eval --import-from-outbound data/outbound data/eval-corpus

Exit codes, and the reasoning behind them:

    0  no dangerous false-clears. Advisory failures may be present and are
       printed in full -- over-blocking is a nuisance to fix, not a reason to
       block a push, and a gate that fires on it is a gate people route around.
    1  at least one DANGEROUS false-clear: mail that should have been held back
       came out `cleared`. This is the gate.
    2  the run could not happen -- unreadable corpus, invalid rules pack, a
       corpus of real mail sitting somewhere git would commit it.

This is a dev/ops tool. It is not in any image, the hardened scan path does not
import it, and it adds no runtime dependency: it reads the corpus with the
stdlib and classifies with the scanner that is already there.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .. import config
from ..rulespack import InvalidRulesPack, RulesPack
from . import report as report_module
from .corpus import Corpus, CorpusError, declares_synthetic_only
from .grade import diff_against, grade_corpus
from .importer import import_from_outbound
from .privacy import NotIgnored, refuse_if_committable

EXIT_OK = 0
EXIT_DANGEROUS = 1
EXIT_ERROR = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m email_guard.eval",
        description=(
            "Score the rules pack against a labelled corpus. Validation proves a "
            "pack loads; this proves it classifies."
        ),
    )
    parser.add_argument("corpus", help="path to the corpus directory")
    parser.add_argument(
        "--import-from-outbound",
        metavar="DIR",
        help=(
            "instead of grading: copy the scanner's stored messages from this "
            "outbound directory into the corpus, marked reviewed:false"
        ),
    )
    parser.add_argument(
        "--rules-dir",
        metavar="DIR",
        help="rules pack to grade (default: the working tree's, via config)",
    )
    parser.add_argument(
        "--lists-dir",
        metavar="DIR",
        help="lists to freeze into a new corpus on import (default: the configured lists)",
    )
    parser.add_argument("--json", metavar="PATH", help="write the scorecard as JSON")
    parser.add_argument(
        "--baseline",
        metavar="PATH",
        help="a previous --json scorecard; report what this run fixed and broke",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="list passing cases too, and print each failure's full forensic log",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv if argv is not None else sys.argv[1:])

    try:
        settings = config.load(rules_dir=args.rules_dir, lists_dir=args.lists_dir)
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    if args.import_from_outbound:
        return _import(args, settings)
    return _grade(args, settings)


def _import(args: argparse.Namespace, settings: config.Config) -> int:
    try:
        result = import_from_outbound(
            args.import_from_outbound, args.corpus, lists_dir=settings.lists_dir
        )
    except CorpusError as exc:
        _report_errors(f"cannot import into {args.corpus}", exc.errors)
        return EXIT_ERROR
    except OSError as exc:
        print(f"error: cannot import: {exc}", file=sys.stderr)
        return EXIT_ERROR

    print(report_module.render_import(result.as_dict()))
    return EXIT_OK


def _grade(args: argparse.Namespace, settings: config.Config) -> int:
    # Before the corpus is opened, not after: a corpus of real mail sitting where
    # git would commit it is a problem with the *location*, and saying so first
    # beats making the operator read a labelling complaint about a directory that
    # should not be there at all. Only the marker is read to decide this.
    try:
        refuse_if_committable(
            Path(args.corpus), synthetic_only=declares_synthetic_only(args.corpus)
        )
    except NotIgnored as exc:
        print(f"refusing to run: {exc}", file=sys.stderr)
        return EXIT_ERROR

    try:
        corpus = Corpus.load(args.corpus)
    except CorpusError as exc:
        _report_errors(f"corpus INVALID ({args.corpus})", exc.errors)
        return EXIT_ERROR

    try:
        pack = RulesPack.load(settings.rules_dir)
    except InvalidRulesPack as exc:
        _report_errors(f"rules pack INVALID ({settings.rules_dir})", exc.errors)
        print("refusing to grade against an invalid rules pack", file=sys.stderr)
        return EXIT_ERROR

    try:
        scorecard = grade_corpus(corpus, settings.rules_dir, pack=pack)
    except CorpusError as exc:
        _report_errors(f"corpus INVALID ({args.corpus})", exc.errors)
        return EXIT_ERROR

    print(report_module.render(scorecard, verbose=args.verbose))

    if args.baseline:
        baseline = _read_baseline(args.baseline)
        if baseline is None:
            return EXIT_ERROR
        print(report_module.render_diff(diff_against(baseline, scorecard), args.baseline))

    if args.json:
        _write_json(Path(args.json), scorecard.as_dict())
        print(f"wrote {args.json}", file=sys.stderr)

    return EXIT_OK if scorecard.clean else EXIT_DANGEROUS


def _read_baseline(path: str) -> dict[str, Any] | None:
    try:
        with Path(path).open(encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        print(f"error: cannot read baseline {path}: {exc}", file=sys.stderr)
        return None
    if not isinstance(data, dict):
        print(f"error: baseline {path} is not a scorecard", file=sys.stderr)
        return None
    return data


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=False)
    path.write_text(text + "\n", encoding="utf-8")


def _report_errors(header: str, errors: list[str]) -> None:
    """The house format, matching `email_guard.cli`: header, then bullets."""
    print(f"{header}:", file=sys.stderr)
    for error in errors:
        print(f"  - {error}", file=sys.stderr)


if __name__ == "__main__":
    sys.exit(main())
