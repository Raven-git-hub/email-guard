"""``pull_and_promote()`` -- the whole operation, in one call.

Order matters, and every step is chosen so that the *live* tree is only ever
touched by a single atomic rename at the very end:

1. take the lock, or return ``busy``
2. ask the remote for its branch tip -- one round trip, zero objects
3. if that tip is already promoted, return ``no_change`` and touch nothing
4. if that tip was already rejected, replay the stored errors without refetching
5. fetch and fast-forward the working copy (never the live tree)
6. copy the subtree into ``releases/<sha>/rules`` -- unreachable until promoted
7. validate it; any error and we stop here, live tree untouched  (FAIL CLOSED)
8. check the signature feeds; problems are warnings only            (FAIL OPEN)
9. mark complete, then swap the ``current`` symlink                 (ATOMIC)
10. record state and prune old releases

The function never raises. Every failure -- git, filesystem, timeout -- comes
back as ``status="error"`` with a message, because the caller is either a
scheduled loop that must not die or an HTTP handler that must answer.
"""

from __future__ import annotations

import logging
import shutil
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import git, pack, store
from .config import SyncConfig, load
from .lock import PullBusy, pull_lock

log = logging.getLogger(__name__)

STATUS_UPDATED = "updated"
STATUS_NO_CHANGE = "no_change"
STATUS_REJECTED = "rejected"
STATUS_BUSY = "busy"
STATUS_ERROR = "error"


@dataclass(frozen=True)
class PullResult:
    """The structured outcome of one pull. Serialised straight to JSON."""

    status: str
    old_commit: str | None = None
    new_commit: str | None = None
    validation_errors: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()
    timestamp: str = ""
    message: str = ""

    def as_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["validation_errors"] = list(self.validation_errors)
        data["warnings"] = list(self.warnings)
        return data


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _short(sha: str | None) -> str:
    return (sha or "")[:12] or "none"


def pull_and_promote(config: SyncConfig | None = None) -> PullResult:
    """Fetch, validate and (if valid and changed) promote the rules pack."""
    cfg = config if config is not None else load()
    try:
        with pull_lock(cfg.lock_file):
            return _locked_pull(cfg)
    except PullBusy as exc:
        current = store.current_release(cfg.live_dir)
        log.info("rules pull skipped: %s", exc)
        return PullResult(
            status=STATUS_BUSY,
            old_commit=current,
            new_commit=current,
            timestamp=_now(),
            message=str(exc),
        )
    except Exception as exc:  # the loop must not die, and a handler must answer
        # A root-owned live root is an operator problem with one known fix, so
        # it is reported as that sentence rather than as a stack trace nobody
        # can act on. Everything else keeps the traceback -- it is unrecognised.
        not_writable = store.as_not_writable(cfg.live_dir, exc)
        if not_writable is not None:
            log.error("rules pull failed: %s", not_writable)
            return PullResult(
                status=STATUS_ERROR,
                old_commit=store.current_release(cfg.live_dir),
                timestamp=_now(),
                message=str(not_writable),
            )
        log.exception("rules pull failed")
        return PullResult(
            status=STATUS_ERROR,
            old_commit=store.current_release(cfg.live_dir),
            timestamp=_now(),
            message=f"{type(exc).__name__}: {exc}",
        )


def _locked_pull(cfg: SyncConfig) -> PullResult:
    store.ensure_live_root(cfg.live_dir, cfg.seed_dir)

    state = store.read_state(cfg.live_dir)
    promoted = state.get("promoted_commit")
    old = store.current_release(cfg.live_dir) or promoted
    home = _git_home(cfg)

    # --- what does upstream have? one round trip, no objects -----------------
    try:
        remote_sha = git.ls_remote_sha(
            cfg.repo_url, cfg.branch, timeout=cfg.git_timeout, home=home
        )
    except git.GitError as exc:
        message = git.classify_error(exc.stderr)
        log.error("rules pull: could not reach %s (%s)", cfg.repo_url, message)
        return PullResult(
            status=STATUS_ERROR, old_commit=old, timestamp=_now(), message=message
        )

    if remote_sha == promoted and store.is_complete(cfg.live_dir, remote_sha):
        log.info("rules pull: no change (%s is already live)", _short(remote_sha))
        return PullResult(
            status=STATUS_NO_CHANGE,
            old_commit=old,
            new_commit=old,
            timestamp=_now(),
            message=f"already on {_short(remote_sha)}",
        )

    # A commit we already refused. Replay rather than re-fetch and re-validate
    # it every interval -- and, importantly, do not report it as `no_change`,
    # which would hide a feed that has been stuck for weeks.
    if remote_sha == state.get("last_rejected_commit"):
        errors = tuple(state.get("last_validation_errors") or ())
        log.warning(
            "rules pull: upstream %s is still the rejected commit (%d error(s))",
            _short(remote_sha),
            len(errors),
        )
        return PullResult(
            status=STATUS_REJECTED,
            old_commit=old,
            new_commit=old,
            validation_errors=errors,
            timestamp=_now(),
            message=(
                f"upstream {_short(remote_sha)} was already rejected and has not "
                "changed; the live pack is unchanged"
            ),
        )

    # --- bring the working copy up to that commit ----------------------------
    try:
        _sync_work(cfg, home)
        head = git.head_sha(cfg.work_dir, timeout=cfg.git_timeout, home=home)

        if head != remote_sha:
            if not git.is_ancestor(
                cfg.work_dir, head, remote_sha, timeout=cfg.git_timeout, home=home
            ):
                return _reject(
                    cfg,
                    state,
                    remote_sha,
                    old,
                    [
                        "upstream history was rewritten: the new tip is not a "
                        "descendant of the current one"
                    ],
                    "refusing a non-fast-forward; the live pack is unchanged",
                )
            git.fast_forward(cfg.work_dir, remote_sha, timeout=cfg.git_timeout, home=home)
            head = git.head_sha(cfg.work_dir, timeout=cfg.git_timeout, home=home)
    except git.GitError as exc:
        message = git.classify_error(exc.stderr)
        log.error("rules pull: %s", message)
        return PullResult(
            status=STATUS_ERROR, old_commit=old, timestamp=_now(), message=message
        )

    source = cfg.work_dir / cfg.subpath
    if not (source / "scan").is_dir():
        return _reject(
            cfg,
            state,
            head,
            old,
            [
                f"the repository has no rules pack at {cfg.subpath!r} "
                "(no scan/ directory there)"
            ],
            "nothing that looks like a rules pack at the configured subpath",
        )

    # --- stage, out of reach of any scan container ---------------------------
    staged = store.stage_release(cfg.live_dir, head, source)

    # --- FAIL CLOSED: scan rules --------------------------------------------
    errors = pack.validate_staged(staged, timeout=cfg.validate_timeout)
    if errors:
        shutil.rmtree(store.release_dir(cfg.live_dir, head), ignore_errors=True)
        return _reject(
            cfg,
            state,
            head,
            old,
            errors,
            f"the pulled pack is invalid ({len(errors)} error(s)); "
            "the live pack is unchanged and scanning continues on it",
        )

    # --- FAIL OPEN: the signature feed --------------------------------------
    warnings = pack.check_signature_feed(staged)
    for warning in warnings:
        log.warning("signature feed: %s", warning)

    # --- promote -------------------------------------------------------------
    store.mark_complete(
        cfg.live_dir,
        head,
        {
            "release": head,
            "branch": cfg.branch,
            "repo_url": cfg.repo_url,
            "subpath": cfg.subpath,
            "promoted_at": _now(),
            "warnings": warnings,
        },
    )
    store.promote(cfg.live_dir, head)

    state.update(
        {
            "promoted_commit": head,
            "promoted_at": _now(),
            "last_status": STATUS_UPDATED,
            "last_pull_at": _now(),
            "last_validation_errors": [],
            "last_warnings": warnings,
            "last_rejected_commit": None,
            "branch": cfg.branch,
            "repo_url": cfg.repo_url,
        }
    )
    store.write_state(cfg.live_dir, state)
    store.prune(cfg.live_dir, cfg.keep_releases)

    log.info(
        "rules pull: promoted %s -> %s (%d warning(s))",
        _short(old),
        _short(head),
        len(warnings),
    )
    return PullResult(
        status=STATUS_UPDATED,
        old_commit=old,
        new_commit=head,
        warnings=tuple(warnings),
        timestamp=_now(),
        message=f"promoted {_short(head)} from {cfg.branch}",
    )


def _sync_work(cfg: SyncConfig, home: Path | None) -> None:
    """Make ``work_dir`` a usable clone of the configured branch."""
    work = cfg.work_dir
    if not (work / ".git").is_dir():
        if work.exists():
            shutil.rmtree(work, ignore_errors=True)
        log.info("cloning %s (%s, %s/) into the rules working copy", cfg.repo_url, cfg.branch, cfg.subpath)
        git.clone(
            cfg.repo_url,
            cfg.branch,
            cfg.subpath,
            work,
            timeout=cfg.git_timeout,
            home=home,
        )
        return

    # An existing clone may be on a different branch (the operator changed
    # EMAIL_GUARD_RULES_BRANCH) or have a stale sparse cone (they changed
    # EMAIL_GUARD_RULES_SUBPATH). Reassert both; they are cheap and idempotent.
    git.run(
        ["sparse-checkout", "set", cfg.subpath],
        cwd=work,
        timeout=cfg.git_timeout,
        home=home,
    )
    if git.current_branch(work, timeout=cfg.git_timeout, home=home) != cfg.branch:
        log.info("rules working copy switching to branch %s", cfg.branch)
        git.set_branch(work, cfg.branch, timeout=cfg.git_timeout, home=home)
    else:
        git.fetch(work, cfg.branch, timeout=cfg.git_timeout, home=home)


def _reject(
    cfg: SyncConfig,
    state: dict[str, Any],
    sha: str,
    old: str | None,
    errors: list[str],
    message: str,
) -> PullResult:
    """Record a refusal. The live tree is not touched, by construction."""
    for error in errors:
        log.error("rules pack rejected: %s", error)

    state.update(
        {
            "last_status": STATUS_REJECTED,
            "last_pull_at": _now(),
            "last_rejected_commit": sha,
            "last_validation_errors": errors,
        }
    )
    store.write_state(cfg.live_dir, state)

    return PullResult(
        status=STATUS_REJECTED,
        old_commit=old,
        new_commit=old,
        validation_errors=tuple(errors),
        timestamp=_now(),
        message=message,
    )


def _git_home(cfg: SyncConfig) -> Path | None:
    """A throwaway HOME for git, inside the writable live root.

    The service runs with a read-only rootfs, so git's insistence on a HOME has
    to land somewhere writable. Keeping it beside the working copy means it is
    covered by the same mount, with no extra volume.
    """
    home = cfg.live_dir / ".githome"
    try:
        home.mkdir(parents=True, exist_ok=True)
    except OSError:
        return None
    return home


def status_snapshot(cfg: SyncConfig) -> dict[str, Any]:
    """What the console shows without triggering a pull. No git, no lock."""
    state = store.read_state(cfg.live_dir)
    current = store.current_release(cfg.live_dir)
    return {
        "current_commit": current,
        "current_target": store.current_target(cfg.live_dir),
        "promoted_at": state.get("promoted_at"),
        "last_pull_at": state.get("last_pull_at"),
        "last_status": state.get("last_status"),
        "validation_errors": list(state.get("last_validation_errors") or []),
        "warnings": list(state.get("last_warnings") or []),
        "branch": state.get("branch") or cfg.branch,
        "repo_url": state.get("repo_url") or cfg.repo_url,
        "interval_seconds": cfg.interval_seconds,
    }
