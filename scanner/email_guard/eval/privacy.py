"""Keeping real mail out of git, mechanically.

The repository was briefly public. A corpus is, by construction, a pile of whole
messages with real senders in them, so "remember not to commit it" is not a
control -- these are.

Two guards, deliberately different in kind:

* :func:`refuse_if_committable` runs at load time and stops the *harness* from
  treating a real corpus as safe: if the corpus sits inside a git work tree and
  git does not ignore it, the run is refused before a single case is read.
* :func:`tracked_eml_outside` runs in the test suite and inspects the *index*:
  any ``.eml`` git already tracks outside the sanctioned synthetic directories
  fails the build. That catches the mistake the first guard cannot -- a message
  copied in by hand and `git add`-ed.

Both shell out to git rather than re-implementing ``.gitignore`` matching.
Pattern matching that disagrees with git is worse than no check at all: it would
report safe when git would commit the file.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from .corpus import CASES_DIRNAME, MESSAGE_NAME

# Where a committed .eml is allowed to live, and why:
#
#   tests/eval-corpus/  -- the synthetic-only evaluation corpus this module
#                          exists to protect; its manifest declares it, and the
#                          harness refuses real cases inside it.
#   tests/fixtures/eml/ -- the scanner's own hand-made fixtures, which predate
#                          the harness and are held to the same rule (every one
#                          carries a SYNTHETIC note and reserved .example
#                          domains).
#
# Anywhere else is a leak. Add to this tuple only for another *synthetic* set.
SYNTHETIC_EML_ROOTS = ("tests/eval-corpus/", "tests/fixtures/eml/")

EML_SUFFIX = ".eml"


class NotIgnored(Exception):
    """A corpus of real mail is sitting somewhere git would commit it."""


def _git(args: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )


def _work_tree(path: Path) -> Path | None:
    """The root of the git work tree ``path`` is in, or ``None``.

    ``None`` covers both "git is not installed" and "this is not a repository",
    and both mean the same thing for our purposes: nothing here can be
    committed to *this* project by accident.

    Walks up to the first directory that exists, because the paths asked about
    are frequently hypothetical -- :func:`corpus_probe` names a file at the
    depth a message would live at, and neither it nor its parents need exist for
    git to answer whether it would be ignored. Running git in a directory that
    is not there just fails, which would read as "not a repository" and quietly
    disable the guard.
    """
    start = Path(path)
    while not start.is_dir() and start.parent != start:
        start = start.parent
    try:
        completed = _git(["rev-parse", "--show-toplevel"], cwd=start)
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode != 0:
        return None
    root = completed.stdout.strip()
    return Path(root) if root else None


def corpus_probe(corpus_root: Path) -> Path:
    """A path shaped like a message this corpus would hold.

    The question is never "does git ignore this directory" -- the repository's
    own ``data/eval-corpus/**`` ignores a directory's *contents* while leaving
    the directory itself trackable, which is exactly how ``.gitkeep`` survives.
    Asking about the directory would report a perfectly safe corpus as
    committable. So the check asks about a file at the depth real messages live
    at. ``git check-ignore`` answers for paths that do not exist, so nothing is
    created to ask.
    """
    return Path(corpus_root) / CASES_DIRNAME / "_probe" / MESSAGE_NAME


def is_ignored(path: Path) -> bool | None:
    """Does git ignore this exact path? ``None`` if git cannot answer.

    Note this asks about the path as given. For "is this corpus safe", ask about
    :func:`corpus_probe` of it -- see that function for why the directory itself
    is the wrong thing to ask about.
    """
    tree = _work_tree(path)
    if tree is None:
        return None
    try:
        completed = _git(["check-ignore", "--quiet", str(Path(path).resolve())], cwd=tree)
    except (OSError, subprocess.SubprocessError):
        return None
    # 0 = ignored, 1 = not ignored, anything else = git could not tell us.
    if completed.returncode not in (0, 1):
        return None
    return completed.returncode == 0


def refuse_if_committable(corpus_root: Path, *, synthetic_only: bool) -> None:
    """Refuse a corpus of real mail that git is not already ignoring.

    A synthetic-only corpus is exempt: being committed is precisely what it is
    for. Everything else holds whole messages from real people, and the only
    acceptable home for that is a path git will never pick up -- ``data/`` in
    this repository, or anywhere outside it.
    """
    if synthetic_only:
        return

    ignored = is_ignored(corpus_probe(corpus_root))
    if ignored is None or ignored:
        # Outside a repository, or git cannot say, or already ignored. The first
        # two cannot leak into this project's history at all.
        return

    raise NotIgnored(
        f"{corpus_root} holds real mail and git does NOT ignore it. A corpus of "
        "real messages must live under the gitignored data tree (e.g. "
        "data/eval-corpus/), or outside the repository. Move it, or mark the "
        "corpus 'synthetic_only': true in corpus.json if it really is invented mail."
    )


def tracked_eml_outside(
    repo_root: Path, allowed: tuple[str, ...] = SYNTHETIC_EML_ROOTS
) -> list[str]:
    """Every ``.eml`` git tracks outside the allowed synthetic directories.

    Returns repo-relative paths, sorted. An empty list is the healthy state.
    Reads the index rather than the working tree on purpose: an untracked
    message sitting in a working copy is the operator's business, and a tracked
    one is everybody's.
    """
    try:
        completed = _git(["ls-files", "-z", "--", f"*{EML_SUFFIX}"], cwd=repo_root)
    except (OSError, subprocess.SubprocessError):
        return []
    if completed.returncode != 0:
        return []

    tracked = [entry for entry in completed.stdout.split("\0") if entry]
    return sorted(
        path
        for path in tracked
        if not any(path.startswith(prefix) for prefix in allowed)
    )
