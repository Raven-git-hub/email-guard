"""Git, run with every credential path deliberately shut.

The updater pulls a PUBLIC repository. It must never acquire a credential, and
must never *block* trying to: a git subprocess waiting on a password prompt in a
container with no tty is an updater that has silently stopped updating.

Four independent layers close that off, and they are independent on purpose --
any one of them alone has a hole:

1. ``GIT_TERMINAL_PROMPT=0``     -- no username/password prompt on a terminal.
2. ``GIT_ASKPASS`` / ``SSH_ASKPASS`` -- no external helper is consulted.
3. ``-c credential.helper=``      -- an EMPTY value *clears* the inherited helper
   list rather than adding to it, so a configured `store`/`osxkeychain` cannot
   contribute.
4. ``GIT_CONFIG_GLOBAL``/``GIT_CONFIG_SYSTEM`` pointed at ``/dev/null`` -- so
   neither ``~/.gitconfig`` nor ``/etc/gitconfig`` can reintroduce a helper, and
   ``~/.git-credentials`` is never read.

And the environment is **built, not copied**: whatever credential-shaped
variables exist in the updater's environment are simply not passed on.

Scheme enforcement lives in :mod:`.config`, at load time, so a misconfigured
deployment fails at startup with a sentence an operator can act on rather than
on the first scheduled pull at 3am.
"""

from __future__ import annotations

import logging
import os
import subprocess
from pathlib import Path

log = logging.getLogger(__name__)

# Flags handed to EVERY git invocation. `-c credential.helper=` with an empty
# value is the documented way to reset the helper list; `-c core.askPass=`
# does the same for the askpass hook.
BASE_FLAGS = (
    "-c",
    "credential.helper=",
    "-c",
    "core.askPass=",
)

_FALSE = "/bin/false"


class GitError(RuntimeError):
    """A git command failed. Carries the command, exit code and stderr."""

    def __init__(self, argv: list[str], returncode: int, stderr: str) -> None:
        self.argv = argv
        self.returncode = returncode
        self.stderr = stderr.strip()
        super().__init__(f"git {' '.join(argv[1:3])} failed ({returncode}): {self.stderr}")


def build_env(home: str | Path | None = None) -> dict[str, str]:
    """The environment every git subprocess gets. Built from nothing.

    ``PATH`` is the only thing taken from the ambient environment, because git
    needs to find its own helper binaries.
    """
    git_home = str(home) if home is not None else "/tmp/git-home"
    return {
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        # No prompting, by any route.
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ASKPASS": _FALSE,
        "SSH_ASKPASS": _FALSE,
        # No inherited config can reintroduce a credential helper.
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_SYSTEM": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        # git insists on a HOME; give it a throwaway one rather than the
        # operator's, so `~/.git-credentials` and `~/.ssh` are not even present.
        "HOME": git_home,
        # Stable, parseable stderr for classify_error().
        "LC_ALL": "C",
        "LANG": "C",
        # An ssh transport is refused at config load, but if one ever slipped
        # through, batch mode makes it fail instead of hanging on a passphrase.
        "GIT_SSH_COMMAND": "ssh -o BatchMode=yes -o StrictHostKeyChecking=yes",
    }


def run(
    args: list[str],
    *,
    cwd: Path | None = None,
    timeout: float = 180.0,
    home: Path | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    """Run one git command with the hardened environment."""
    argv = ["git", *BASE_FLAGS, *args]
    log.debug("running: %s", " ".join(argv))
    completed = subprocess.run(
        argv,
        cwd=str(cwd) if cwd else None,
        env=build_env(home),
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if check and completed.returncode != 0:
        raise GitError(argv, completed.returncode, completed.stderr)
    return completed


def ls_remote_sha(url: str, branch: str, *, timeout: float, home: Path | None = None) -> str:
    """The remote branch tip, in one round trip and zero objects transferred.

    This is what makes "nothing changed" cheap: the common case of a daily pull
    against an unchanged branch costs one request and no fetch at all.
    """
    completed = run(
        ["ls-remote", "--exit-code", "--heads", "--", url, f"refs/heads/{branch}"],
        timeout=timeout,
        home=home,
    )
    line = completed.stdout.strip().splitlines()
    if not line:
        raise GitError(["git", "ls-remote", url], 2, f"branch {branch!r} not found on {url}")
    return line[0].split()[0]


def clone(
    url: str,
    branch: str,
    subpath: str,
    target: Path,
    *,
    timeout: float,
    home: Path | None = None,
) -> None:
    """Sparse, blobless, single-branch clone of just the rules subtree.

    ``--filter=blob:none`` rather than ``--depth 1``, and the difference is a
    security property rather than a size one: a shallow clone has no ancestry,
    so ``merge --ff-only`` cannot tell a fast-forward from a rewritten history,
    and the usual workaround (``reset --hard FETCH_HEAD``) would silently accept
    a force-push. A blobless clone keeps the commit graph -- which is cheap --
    so the fast-forward check downstream is a real check.
    """
    target.parent.mkdir(parents=True, exist_ok=True)
    args = [
        "clone",
        "--filter=blob:none",
        "--sparse",
        "--single-branch",
        "--branch",
        branch,
        "--",
        url,
        str(target),
    ]
    try:
        run(args, timeout=timeout, home=home)
    except GitError as exc:
        if not _filtering_unsupported(exc.stderr):
            raise
        # Some servers (and older `file://` remotes) refuse partial clones.
        # A full clone of a rules-sized repo is still cheap.
        log.warning("remote does not support partial clone; retrying without --filter")
        run([arg for arg in args if arg != "--filter=blob:none"], timeout=timeout, home=home)

    run(["sparse-checkout", "set", subpath], cwd=target, timeout=timeout, home=home)


def _filtering_unsupported(stderr: str) -> bool:
    text = stderr.lower()
    return "filter" in text and (
        "not supported" in text or "unsupported" in text or "does not support" in text
    )


def fetch(work: Path, branch: str, *, timeout: float, home: Path | None = None) -> None:
    """Fetch one branch, naming the refspec explicitly.

    The working copy is a ``--single-branch`` clone, so its configured refspec
    covers only the branch it was cloned with. Spelling the destination out
    means this works for any branch, and keeps the remote-tracking ref up to
    date rather than leaving the result only in FETCH_HEAD.
    """
    run(
        ["fetch", "--no-tags", "origin", f"+refs/heads/{branch}:refs/remotes/origin/{branch}"],
        cwd=work,
        timeout=timeout,
        home=home,
    )


def is_ancestor(work: Path, ancestor: str, descendant: str, *, timeout: float,
                home: Path | None = None) -> bool:
    """True if ``descendant`` can be fast-forwarded to from ``ancestor``."""
    completed = run(
        ["merge-base", "--is-ancestor", ancestor, descendant],
        cwd=work,
        timeout=timeout,
        home=home,
        check=False,
    )
    return completed.returncode == 0


def fast_forward(work: Path, ref: str, *, timeout: float, home: Path | None = None) -> None:
    run(["merge", "--ff-only", ref], cwd=work, timeout=timeout, home=home)


def head_sha(work: Path, ref: str = "HEAD", *, timeout: float, home: Path | None = None) -> str:
    return run(["rev-parse", ref], cwd=work, timeout=timeout, home=home).stdout.strip()


def set_branch(work: Path, branch: str, *, timeout: float, home: Path | None = None) -> None:
    """Point the working copy at ``branch``, tracking origin.

    Needed when EMAIL_GUARD_RULES_BRANCH changes under an existing clone: the
    clone was made ``--single-branch``, so the new branch is not in the
    configured refspec and `origin/<branch>` does not exist yet. `set-branches`
    widens the refspec first, so later plain fetches keep working too.
    """
    run(["remote", "set-branches", "origin", branch], cwd=work, timeout=timeout, home=home)
    fetch(work, branch, timeout=timeout, home=home)
    run(
        ["checkout", "-B", branch, "--track", f"origin/{branch}"],
        cwd=work,
        timeout=timeout,
        home=home,
    )


def current_branch(work: Path, *, timeout: float, home: Path | None = None) -> str:
    completed = run(
        ["rev-parse", "--abbrev-ref", "HEAD"], cwd=work, timeout=timeout, home=home, check=False
    )
    return completed.stdout.strip()


def classify_error(stderr: str) -> str:
    """Turn git's stderr into a sentence that names the actual problem.

    The authentication cases matter most: because prompting is disabled, a
    private repository fails with "could not read Username ... terminal prompts
    disabled", which reads like a bug in the updater unless it is translated.
    """
    text = (stderr or "").lower()

    if "terminal prompts disabled" in text or "could not read username" in text:
        return (
            "the repository asked for credentials. The rules updater only pulls "
            "public repositories and never supplies credentials -- check "
            "EMAIL_GUARD_RULES_REPO_URL points at a public repository."
        )
    if "authentication failed" in text or "invalid username or password" in text:
        return (
            "authentication was refused. The rules updater pulls public "
            "repositories only and supplies no credentials."
        )
    if "repository not found" in text or "not found" in text and "remote" in text:
        return (
            "the repository was not found. If it is private, that is expected: "
            "the updater supplies no credentials. Check EMAIL_GUARD_RULES_REPO_URL."
        )
    if "permission denied (publickey)" in text or "host key verification failed" in text:
        return (
            "an SSH transport was attempted. The updater pulls over HTTPS only; "
            "set EMAIL_GUARD_RULES_REPO_URL to an https:// URL."
        )
    if "could not resolve host" in text or "temporary failure in name resolution" in text:
        return (
            "the repository host could not be resolved. The rules-updater "
            "service needs the `egress` network to reach GitHub."
        )
    if "ssl" in text or "certificate" in text:
        return (
            "the TLS connection failed. The updater image needs ca-certificates "
            "installed to fetch over HTTPS."
        )
    if "couldn't find remote ref" in text or "not found on" in text:
        return "the configured branch does not exist upstream (EMAIL_GUARD_RULES_BRANCH)."
    return stderr.strip().splitlines()[-1] if stderr.strip() else "git failed with no output"
