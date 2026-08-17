"""The live rules tree: releases, the `current` symlink, and the atomic swap.

Layout under ``live_dir``::

    current -> releases/<id>/rules     RELATIVE symlink; the only thing promoted
    releases/
      seed/rules/                      copy of the committed pack, made on first start
      <sha>/rules/                     one directory per promoted upstream commit
      <sha>/.complete                  written LAST; absence means "crashed mid-stage"
    work/                              the sparse git working copy (has its own .git)
    state.json                         what was promoted, what was rejected, when
    .lock                              the flock target

**Why a symlink swap.** The scanner mounts the rules read-only into a fresh
container per message. ``os.replace`` on a symlink is ``rename(2)``: it either
happened or it did not, and a container starting at any instant resolves either
the old release or the new one. There is no window in which a partial tree is
reachable, because nothing points at ``releases/<sha>`` until the rename lands.

**Why the symlink is RELATIVE.** ``current`` is resolved in at least three
different mount namespaces: the host's (by the docker daemon, when it binds the
scan container's rules mount), the updater's, and the dispatcher's. An absolute
target would name a path that only exists in one of them and dangle in the
others. ``releases/<sha>/rules`` resolves identically in all three.
"""

from __future__ import annotations

import json
import logging
import os
import secrets
import shutil
import time
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

SEED_ID = "seed"
COMPLETE_MARKER = ".complete"
PACK_SUBDIR = "rules"

# A release younger than this is never pruned even if it is over the keep count:
# a scan container that started moments ago may still have it mounted, and the
# daemon resolved the symlink at create time, so the directory must outlive the
# swap that replaced it.
PRUNE_MIN_AGE_SECONDS = 3600.0

# Copied trees never need these, and `.git` in particular must not be copied:
# the working copy is a real clone, and a release is meant to be inert files.
_IGNORE = shutil.ignore_patterns(".git", "__pycache__", "*.pyc", "*.pyo")


def release_dir(live_dir: Path, release_id: str) -> Path:
    return Path(live_dir) / "releases" / release_id


def release_pack(live_dir: Path, release_id: str) -> Path:
    return release_dir(live_dir, release_id) / PACK_SUBDIR


def current_target(live_dir: Path) -> str | None:
    """The raw symlink text, e.g. ``releases/<sha>/rules``. ``None`` if unset."""
    link = Path(live_dir) / "current"
    try:
        return os.readlink(link)
    except OSError:
        return None


def current_release(live_dir: Path) -> str | None:
    """The release id ``current`` points at, or ``None``."""
    target = current_target(live_dir)
    if not target:
        return None
    parts = Path(target).parts
    # releases/<id>/rules
    if len(parts) >= 2 and parts[0] == "releases":
        return parts[1]
    return None


def stage_release(live_dir: Path, release_id: str, source: Path) -> Path:
    """Copy a pack into ``releases/<id>/rules``, replacing any partial attempt.

    Returns the staged pack directory. Nothing points at it yet -- promotion is
    a separate step, which is what makes a half-copied tree unreachable.
    """
    target = release_dir(live_dir, release_id)
    if target.exists():
        shutil.rmtree(target)
    target.mkdir(parents=True)
    shutil.copytree(source, target / PACK_SUBDIR, ignore=_IGNORE, symlinks=False)
    return target / PACK_SUBDIR


def mark_complete(live_dir: Path, release_id: str, detail: dict[str, Any]) -> None:
    """Record that a release is fully staged. Written LAST, before the swap."""
    path = release_dir(live_dir, release_id) / COMPLETE_MARKER
    _write_json(path, detail)


def is_complete(live_dir: Path, release_id: str) -> bool:
    return (release_dir(live_dir, release_id) / COMPLETE_MARKER).is_file()


def promote(live_dir: Path, release_id: str) -> None:
    """Point ``current`` at a release, atomically.

    ``os.replace`` of a symlink onto an existing symlink is a rename within one
    directory: atomic, and visible to any process that has that *directory*
    mounted (which is why the dispatcher binds the live root rather than
    ``current`` itself -- a bind of the symlink resolves once, at container
    start, and would never see a swap).
    """
    live = Path(live_dir)
    link = live / "current"
    target = f"releases/{release_id}/{PACK_SUBDIR}"

    if link.is_symlink() or not link.exists():
        pass
    elif link.is_dir():
        # Someone replaced the symlink with a real directory. Renaming onto it
        # would fail anyway; say so instead of deleting an operator's tree.
        raise IsADirectoryError(
            f"{link} is a real directory, not the managed symlink. Refusing to "
            "replace it -- move it aside if the updater should own this path."
        )

    tmp = live / f".current.{os.getpid()}.{secrets.token_hex(4)}"
    os.symlink(target, tmp)
    try:
        os.replace(tmp, link)
    except OSError:
        tmp.unlink(missing_ok=True)
        raise


def ensure_live_root(live_dir: Path, seed_dir: Path | None = None) -> None:
    """Make the live root usable, and seed it if it has never been promoted.

    Called on every start and before every pull, so a live root that was wiped,
    or never existed, repairs itself rather than failing the first pull.
    """
    live = Path(live_dir)
    (live / "releases").mkdir(parents=True, exist_ok=True)

    prune_incomplete(live)

    if current_target(live) is not None and _current_resolves(live):
        return

    if seed_dir is None:
        return
    seed = Path(seed_dir)
    if not (seed / "scan").is_dir():
        log.warning(
            "cannot seed the live rules tree: %s does not look like a rules pack", seed
        )
        return

    log.info("seeding the live rules tree from the committed pack at %s", seed)
    stage_release(live, SEED_ID, seed)
    mark_complete(live, SEED_ID, {"release": SEED_ID, "source": str(seed)})
    promote(live, SEED_ID)


def _current_resolves(live_dir: Path) -> bool:
    pack = Path(live_dir) / "current"
    try:
        return (pack / "scan").is_dir()
    except OSError:
        return False


def prune_incomplete(live_dir: Path) -> list[str]:
    """Delete staged releases that never reached the `.complete` marker.

    Those are the remains of a crash between copytree and the swap. They are
    unreachable (nothing points at them), but they are also wasted disk and
    confusing to read, and a later pull of the same commit would reuse the id.
    """
    live = Path(live_dir)
    releases = live / "releases"
    if not releases.is_dir():
        return []

    keep = current_release(live)
    removed: list[str] = []
    for entry in sorted(releases.iterdir()):
        if not entry.is_dir() or entry.name == keep:
            continue
        if (entry / COMPLETE_MARKER).is_file():
            continue
        shutil.rmtree(entry, ignore_errors=True)
        removed.append(entry.name)
    if removed:
        log.info("pruned %d incomplete release(s): %s", len(removed), ", ".join(removed))
    return removed


def prune(live_dir: Path, keep: int, now: float | None = None) -> list[str]:
    """Keep the newest ``keep`` releases; never the live one, seed, or a fresh one."""
    live = Path(live_dir)
    releases = live / "releases"
    if not releases.is_dir():
        return []

    stamp = time.time() if now is None else now
    protected = {current_release(live), SEED_ID}

    candidates = [
        entry
        for entry in releases.iterdir()
        if entry.is_dir() and entry.name not in protected
    ]
    candidates.sort(key=lambda path: path.stat().st_mtime, reverse=True)

    removed: list[str] = []
    for entry in candidates[max(keep - 1, 0) :]:
        if stamp - entry.stat().st_mtime < PRUNE_MIN_AGE_SECONDS:
            # An in-flight scan container may still have this mounted.
            continue
        shutil.rmtree(entry, ignore_errors=True)
        removed.append(entry.name)
    if removed:
        log.info("pruned %d old release(s): %s", len(removed), ", ".join(removed))
    return removed


# --- state ------------------------------------------------------------------


def read_state(live_dir: Path) -> dict[str, Any]:
    """The updater's own record. Never raises: a corrupt file is a fresh start."""
    path = Path(live_dir) / "state.json"
    try:
        with path.open(encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def write_state(live_dir: Path, state: dict[str, Any]) -> None:
    _write_json(Path(live_dir) / "state.json", state)


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    """Write via a temp file and rename, so a reader never sees half a document."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.{secrets.token_hex(4)}")
    with tmp.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")
    os.replace(tmp, path)
