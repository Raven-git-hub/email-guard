"""The rule evaluation harness: does the pack CLASSIFY correctly?

``rules/validate.py`` proves a pack **loads** -- the JSON parses, the regexes
compile, the func modules import and expose their callables. That is what the
auto-updater gates a promote on, and it is necessary, but it says nothing about
whether the pack puts mail in the right bucket. A rule that loads perfectly and
rejects every bank in the country passes validation.

This is the other half: a labelled corpus of messages, and a tool that scores
the working-tree pack against it. Change a rule, run the harness, and see what
you fixed and what you broke before you push.

**It reuses the scanner, it does not re-implement it.** Every case goes through
:func:`email_guard.pipeline.scan_parsed` -- the same call the live scanner makes
-- with the corpus's frozen lists and the current ``rules/``. A harness with its
own idea of how a message is classified would grade a scanner that does not
exist.

Two corpora, for one reason:

* ``tests/eval-corpus/`` is **committed and synthetic-only**. Invented senders on
  reserved ``.example`` domains, no personal content, run by the normal pytest
  suite. It guards specific behaviours for every user of the shared pack.
* ``data/eval-corpus/`` is the **operator's real mail**, under the gitignored
  data tree, never committed, run by hand before a push.

The split is enforced rather than documented: :mod:`.privacy` refuses a real
corpus that git could commit, the harness refuses a synthetic-only corpus with
real cases mixed into it, and ``tests/test_eval_privacy.py`` fails the build if
any ``.eml`` is tracked outside the sanctioned synthetic directories.

Grading is by **bucket**, because the bucket is what happens to the mail. A
failure's *direction* is what decides the exit code:

* **dangerous** -- expected ``flagged``/``rejected``, actually ``cleared``. Bad
  mail reached the inbox. This, and only this, fails the run.
* **advisory** -- everything else, over-blocking included. Quarantining a bank
  notification is a nuisance to be fixed; it is not a breach, and gating on it
  would mean nobody could ever tighten a rule.

Entry point::

    python -m email_guard.eval <corpus_dir> [--json out.json] [--baseline prev.json]
    python -m email_guard.eval --import-from-outbound data/outbound <corpus_dir>
"""

from __future__ import annotations

from .corpus import Case, Corpus, CorpusError
from .grade import ADVISORY, DANGEROUS, CaseResult, Scorecard, diff_against, grade_corpus

__all__ = [
    "ADVISORY",
    "DANGEROUS",
    "Case",
    "CaseResult",
    "Corpus",
    "CorpusError",
    "Scorecard",
    "diff_against",
    "grade_corpus",
]
