"""One hardened, throwaway container per message.

The other :class:`~.scanner_runner.ScannerRunner`, and the reason the seam
exists. The scanner is the component that parses attacker-controlled input --
and the roadmap has it growing attachment inspection, which is worse. A
subprocess is not a sandbox: it shares this host's filesystem, network and
kernel. So in production each message is scanned by its own container, which is
then destroyed.

**The argv is the security posture.** Everything below is one `docker run`
invocation, and each flag is load-bearing:

===========================  ===================================================
``--rm``                     the container deletes itself; one message, one
                             lifetime, no accumulation
``--network none``           no loopback, no DNS, no egress. A message that
                             achieves code execution has nowhere to call home
``--read-only``              the root filesystem is immutable; the only writable
                             paths are the tmpfs and this message's own output
``--user <uid>:<gid>``       never root, even inside a throwaway
``--cap-drop ALL``           no capabilities at all -- the scanner needs none
``--security-opt
  no-new-privileges``        setuid binaries cannot re-escalate what was dropped
``--tmpfs /tmp``             ``noexec,nosuid,nodev`` and size-capped, so scratch
                             space is not a place to stage a payload
``--memory``/
  ``--memory-swap``          equal on purpose: without the swap cap, a memory
                             limit is evaded by swapping. An archive bomb hits
                             the ceiling and the container is OOM-killed
``--pids-limit``             a fork bomb exhausts its own container's quota and
                             nothing else
``--cpus``                   a CPU-burning regex cannot starve the host
===========================  ===================================================

Every one of those bounds a *crafted message*, and all of them die with the
container. What the dispatcher sees is an ordinary failed
:class:`~.scanner_runner.ScanOutcome`, so an OOM kill and a bad rules pack take
the same retry-then-quarantine path.

**Docker access.** ``DOCKER_HOST`` points at a socket-proxy on the compose
network. The dispatcher never gets ``/var/run/docker.sock`` bind-mounted:
that socket is host-root-equivalent, so mounting it into the process that
handles hostile mail would defeat the entire exercise. A test asserts the
string never appears in any argv this module builds.

**What the scanner container can see.** Only its own message, the rules pack
and the lists (all read-only) -- plus an *empty, per-scan* output directory it
may write. It does not get the shared ``data/outbound``: that is the archive of
every message previously judged hostile, and handing a fresh copy of it to each
new suspect message would be a strange thing for a quarantine to do. The
dispatcher moves the results into place after the container is gone. That move
is a blind directory merge; this module knows the scanner's *paths* because it
must mount them, and nothing about the scanner's *format*.

**The volume-path gotcha**, which is the thing most likely to break silently on
a real host: ``docker run -v src:dst`` resolves ``src`` on the **host**, via the
daemon -- not inside the dispatcher's mount namespace. A dispatcher that passes
its own internal path mounts a *different* directory, or an empty new one, and
the failure is quiet: the container starts, finds no rules, and reports a
rules-pack error that says nothing about mounts. So configuration carries both
paths for each shared tree and :meth:`_host_path` translates, the per-message
spool is deliberately created *under* the data root so it is translatable, and
:meth:`ContainerSettings.validate` refuses at startup anything it can check
without a daemon. Whether the host path is *correct* is only observable on a
real host -- see ``VALIDATION.md``.
"""

from __future__ import annotations

import json
import logging
import os
import secrets
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

from .scanner_runner import ScanOutcome

log = logging.getLogger(__name__)

STDERR_KEEP = 2000

# Where each mount lands *inside* the scanner container. Fixed rather than
# configurable: they are an implementation detail of this pairing, and the
# scanner is told about them through the EMAIL_GUARD_* environment it already
# documents, so nothing here needs to agree with the host's layout.
CONTAINER_MESSAGE = "/message/message.eml"
CONTAINER_RULES = "/rules"
CONTAINER_LISTS = "/data/lists"
CONTAINER_OUTBOUND = "/data/outbound"
CONTAINER_DAILY_BRIEF = "/data/daily-brief"

# The scanner's "safe to publish" sentinel, which `_merge_tree` must move LAST.
# Named here rather than imported: the dispatcher imports nothing from the
# scanner -- the subprocess boundary is the whole interface (see pyproject.toml)
# -- so this is a one-word contract, asserted in tests/test_container_runner.py.
COMPLETE_NAME = ".complete"

DEFAULT_IMAGE = "email-guard-scanner:0.1.0"
DEFAULT_LABEL_NAMESPACE = "email-guard"
DEFAULT_NAME_PREFIX = "email-guard-scan-"

# Per-container ceilings. Deliberately modest: the scanner is a stdlib mail
# parser, so anything approaching these is a crafted message rather than a big
# one. See the README for the aggregate footprint -- these multiply by the
# runner's `concurrency`, because that many scans can be in flight at once.
DEFAULT_MEMORY = "512m"
DEFAULT_PIDS_LIMIT = 128
DEFAULT_CPUS = "1.0"
DEFAULT_TMPFS_SIZE = "64m"

# Housekeeping commands answer fast or not at all; they must never hold up mail.
HOUSEKEEPING_TIMEOUT = 30.0


class ContainerConfigError(ValueError):
    """The container runner is misconfigured. Raised at startup, not per message."""


@dataclass(frozen=True)
class DockerResult:
    exit_code: int
    stdout: bytes = b""
    stderr: bytes = b""
    timed_out: bool = False
    error: str = ""


class DockerCommandClient:
    """Runs ``docker`` argv. The one place a real daemon is contacted.

    Injected into :class:`ContainerRunner` rather than called directly, so the
    whole runner is testable with no daemon -- which matters, because there is
    no daemon in the environment this was built in.
    """

    def __init__(self, binary: str = "docker", env: dict[str, str] | None = None) -> None:
        self._binary = binary
        self._env = env

    def run(
        self, args: Sequence[str], timeout: float | None = None, stdin: bytes | None = None
    ) -> DockerResult:
        argv = [self._binary, *args]
        try:
            completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
                argv,
                capture_output=True,
                timeout=timeout,
                input=stdin,
                env={**os.environ, **(self._env or {})} if self._env else None,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return DockerResult(
                exit_code=-1, timed_out=True, error=f"docker timed out after {timeout}s"
            )
        except OSError as exc:
            # Almost always "docker: not found" -- the dispatcher image is
            # missing the CLI, or the runner was selected on a host without it.
            return DockerResult(exit_code=-1, error=f"cannot run docker: {exc}")
        return DockerResult(
            exit_code=completed.returncode,
            stdout=completed.stdout or b"",
            stderr=completed.stderr or b"",
        )


@dataclass(frozen=True)
class ContainerSettings:
    """Everything the runner needs, with both sides of every path mapping.

    ``host_*`` are paths **on the host**, which is what the daemon resolves.
    The unprefixed ones are where the dispatcher sees those same trees. They
    are equal in the simplest deployments and different under compose, and
    getting them confused is the failure this whole dataclass exists to make
    impossible to ignore.
    """

    image: str = DEFAULT_IMAGE
    host_data_dir: Path = Path("/srv/email-guard/data")
    data_dir: Path = Path("/app/data")
    host_rules_dir: Path = Path("/srv/email-guard/rules")
    rules_dir: Path = Path("/app/rules")
    lists_dir: Path = Path("/app/data/lists")
    outbound_dir: Path = Path("/app/data/outbound")
    daily_brief_dir: Path = Path("/app/data/daily-brief")
    spool_dir: Path = Path("/app/data/dispatcher/scan-spool")
    user: str = ""
    memory: str = DEFAULT_MEMORY
    pids_limit: int = DEFAULT_PIDS_LIMIT
    cpus: str = DEFAULT_CPUS
    tmpfs_size: str = DEFAULT_TMPFS_SIZE
    docker_binary: str = "docker"
    label_namespace: str = DEFAULT_LABEL_NAMESPACE
    name_prefix: str = DEFAULT_NAME_PREFIX

    def validate(self) -> None:
        """Everything checkable without a daemon, checked once at startup."""
        if not self.image:
            raise ContainerConfigError(
                "container.image is empty: name the tag `docker compose build scanner` "
                f"produces (default {DEFAULT_IMAGE})"
            )
        if not self.user:
            raise ContainerConfigError("container.user is empty: expected 'uid:gid'")
        if _is_root(self.user):
            raise ContainerConfigError(
                f"container.user resolves to root ({self.user!r}). The scanner container "
                "must not run as root -- set container.user to a non-zero 'uid:gid', or "
                "run the dispatcher itself as a non-root user so its own uid is inherited."
            )

        # Everything the scanner container touches has to be translatable to a
        # host path, and translation is only defined under the data root.
        for name, path in (
            ("lists_dir", self.lists_dir),
            ("outbound_dir", self.outbound_dir),
            ("daily_brief_dir", self.daily_brief_dir),
            ("spool_dir", self.spool_dir),
        ):
            if not _is_within(path, self.data_dir):
                raise ContainerConfigError(
                    f"{name} ({path}) is outside the data root ({self.data_dir}), so its "
                    "host path cannot be derived and the scanner container would mount "
                    "the wrong directory. Move it under the data root, or point "
                    "container.data_dir at a root that contains it."
                )

        # A missing directory here means a mount the dispatcher itself did not
        # get. Failing now beats failing per-message as an opaque scanner error.
        for name, path in (("data_dir", self.data_dir), ("rules_dir", self.rules_dir)):
            if not path.is_dir():
                raise ContainerConfigError(
                    f"container.{name} ({path}) does not exist inside the dispatcher. "
                    "It is meant to be a mounted volume -- check the compose volumes "
                    "before blaming the host path mapping."
                )


class ContainerRunner:
    """``docker run --rm`` a dedicated hardened scanner image, per message."""

    def __init__(
        self,
        settings: ContainerSettings,
        timeout: float = 120.0,
        docker: Any = None,
        token_factory: Any = None,
    ) -> None:
        settings.validate()
        self._settings = settings
        self._timeout = timeout
        self._docker = docker if docker is not None else DockerCommandClient(settings.docker_binary)
        self._token = token_factory or (lambda: secrets.token_hex(8))
        log.info(
            "container runner: image=%s user=%s caps: memory=%s pids=%s cpus=%s",
            settings.image,
            settings.user,
            settings.memory,
            settings.pids_limit,
            settings.cpus,
        )
        log.info(
            "host path mapping: data %s -> %s, rules %s -> %s "
            "(the left side is what the docker daemon resolves)",
            settings.data_dir,
            settings.host_data_dir,
            settings.rules_dir,
            settings.host_rules_dir,
        )

    # -- the ScannerRunner contract -------------------------------------------

    def scan(self, raw: bytes) -> ScanOutcome:
        """Scan one message in its own container. Never raises."""
        token = self._token()
        spool = self._settings.spool_dir / token
        try:
            self._stage(spool, raw)
        except OSError as exc:
            return ScanOutcome(ok=False, exit_code=-1, error=f"cannot stage message: {exc}")

        try:
            return self._run(token, spool)
        except Exception as exc:  # noqa: BLE001 - a failure is an outcome, not a crash
            log.exception("container scan failed for token=%s", token)
            return ScanOutcome(ok=False, exit_code=-1, error=f"container scan failed: {exc}")
        finally:
            _remove_tree(spool)

    # -- startup housekeeping -------------------------------------------------

    def reap_orphans(self) -> int:
        """Remove leftover scan containers. Never raises.

        A dispatcher killed mid-scan leaves its container running: ``--rm``
        only fires when the container exits on its own. Left alone those
        accumulate across restarts, each still holding its memory and pid
        quota. The label is what makes them identifiable without keeping a
        registry that would itself need to survive the crash.
        """
        found = self._list_orphans()
        if not found:
            return 0

        log.warning("removing %s orphaned scan container(s) from a previous run", len(found))
        result = self._docker.run(["rm", "--force", *found], timeout=HOUSEKEEPING_TIMEOUT)
        if result.exit_code != 0:
            # Not fatal. Draining mail matters more than tidy bookkeeping, and
            # the next startup will try again.
            log.warning("could not remove orphans: %s", _tail(result.stderr) or result.error)
            return 0
        return len(found)

    def _list_orphans(self) -> list[str]:
        result = self._docker.run(
            ["ps", "--all", "--quiet", "--filter", f"label={self._label_role()}"],
            timeout=HOUSEKEEPING_TIMEOUT,
        )
        if result.exit_code != 0:
            log.warning(
                "could not list scan containers to reap: %s",
                _tail(result.stderr) or result.error,
            )
            return []
        return result.stdout.decode("utf-8", errors="replace").split()

    # -- internals ------------------------------------------------------------

    def _stage(self, spool: Path, raw: bytes) -> None:
        """Lay out this scan's private directory: one message in, nothing else."""
        (spool / "outbound").mkdir(parents=True, exist_ok=True)
        (spool / "daily-brief").mkdir(parents=True, exist_ok=True)
        (spool / "message.eml").write_bytes(raw)

    def _run(self, token: str, spool: Path) -> ScanOutcome:
        name = f"{self._settings.name_prefix}{token}"
        argv = self._run_argv(token, name, spool)
        result = self._docker.run(argv, timeout=self._timeout)

        if result.timed_out:
            # `docker run` gave up waiting, but the container is still running
            # and still holding its quotas. --rm will not fire until it exits,
            # so it has to be killed by name.
            self._force_remove(name)
            return ScanOutcome(
                ok=False,
                exit_code=-1,
                error=f"scanner container timed out after {self._timeout}s",
            )
        if result.exit_code != 0:
            return ScanOutcome(
                ok=False,
                exit_code=result.exit_code,
                stderr=_tail(result.stderr),
                error=self._explain(result),
            )

        try:
            verdict = json.loads(result.stdout.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            return ScanOutcome(
                ok=False,
                exit_code=result.exit_code,
                stderr=_tail(result.stderr),
                error=f"scanner stdout is not valid JSON: {exc}",
            )
        if not isinstance(verdict, dict):
            return ScanOutcome(
                ok=False,
                exit_code=result.exit_code,
                stderr=_tail(result.stderr),
                error="scanner stdout is not a JSON object",
            )

        try:
            self._collect(spool)
        except OSError as exc:
            # The scan itself succeeded but its output is not where the rest of
            # the system looks. Reporting success would strand the report, so
            # this is a failure and gets retried like any other.
            return ScanOutcome(
                ok=False,
                exit_code=result.exit_code,
                stderr=_tail(result.stderr),
                error=f"cannot collect scanner output: {exc}",
            )

        return ScanOutcome(
            ok=True,
            exit_code=0,
            verdict=self._rewrite_written(verdict),
            stderr=_tail(result.stderr),
        )

    def _run_argv(self, token: str, name: str, spool: Path) -> list[str]:
        s = self._settings
        return [
            "run",
            "--rm",
            "--name",
            name,
            # Labelled so a dispatcher that died mid-scan can find its orphans
            # on the next startup. The token is random -- never a sender, never
            # a message id: `docker ps` output is not a place for personal data.
            "--label",
            self._label_role(),
            "--label",
            f"{s.label_namespace}.scan={token}",
            "--network",
            "none",
            "--read-only",
            "--user",
            s.user,
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--tmpfs",
            f"/tmp:rw,noexec,nosuid,nodev,size={s.tmpfs_size}",
            "--memory",
            s.memory,
            # Equal to --memory so the limit cannot be evaded by swapping.
            "--memory-swap",
            s.memory,
            "--pids-limit",
            str(s.pids_limit),
            "--cpus",
            s.cpus,
            # The image is built on the host by compose. Never reach for a
            # registry: the socket-proxy does not permit it, and a scanner
            # image silently pulled from the internet is not a scanner image.
            "--pull",
            "never",
            "--volume",
            f"{self._host_data(spool / 'message.eml')}:{CONTAINER_MESSAGE}:ro",
            "--volume",
            f"{self._host_rules()}:{CONTAINER_RULES}:ro",
            "--volume",
            f"{self._host_data(s.lists_dir)}:{CONTAINER_LISTS}:ro",
            # The only writable mounts, and both are private to this scan.
            "--volume",
            f"{self._host_data(spool / 'outbound')}:{CONTAINER_OUTBOUND}",
            "--volume",
            f"{self._host_data(spool / 'daily-brief')}:{CONTAINER_DAILY_BRIEF}",
            # The scanner resolves its own configuration; the dispatcher steers
            # it only through the environment it already documents, exactly as
            # the subprocess runner does.
            "--env",
            f"EMAIL_GUARD_RULES_DIR={CONTAINER_RULES}",
            "--env",
            f"EMAIL_GUARD_LISTS_DIR={CONTAINER_LISTS}",
            "--env",
            f"EMAIL_GUARD_OUTBOUND_DIR={CONTAINER_OUTBOUND}",
            "--env",
            f"EMAIL_GUARD_DAILY_BRIEF_DIR={CONTAINER_DAILY_BRIEF}",
            s.image,
            CONTAINER_MESSAGE,
        ]

    def _force_remove(self, name: str) -> None:
        result = self._docker.run(["rm", "--force", name], timeout=HOUSEKEEPING_TIMEOUT)
        if result.exit_code != 0:
            log.warning(
                "could not remove timed-out container %s: %s",
                name,
                _tail(result.stderr) or result.error,
            )

    def _explain(self, result: DockerResult) -> str:
        """Name the failure mode where docker's exit code makes it knowable."""
        if result.error:
            return result.error
        stderr = _tail(result.stderr)
        if result.exit_code == 125 and _image_missing(stderr):
            return (
                f"scanner image {self._settings.image!r} is not present on the host: "
                "run `docker compose build scanner`"
            )
        if result.exit_code == 125:
            # 125 is docker's own "could not run" code, distinct from anything
            # the scanner exits with, so it always means the invocation.
            return f"docker could not start the scanner container: {stderr or 'exit 125'}"
        if result.exit_code == 137:
            return (
                f"scanner container was killed (exit 137) -- most likely the "
                f"{self._settings.memory} memory cap"
            )
        return f"scanner exited {result.exit_code}"

    # -- host path translation ------------------------------------------------

    def _host_data(self, local: Path) -> str:
        return self._translate(local, self._settings.data_dir, self._settings.host_data_dir)

    def _host_rules(self) -> str:
        return str(self._settings.host_rules_dir)

    @staticmethod
    def _translate(local: Path, local_root: Path, host_root: Path) -> str:
        """A dispatcher-side path, expressed as the host path the daemon needs."""
        try:
            relative = Path(local).relative_to(local_root)
        except ValueError as exc:  # pragma: no cover - validate() rules this out
            raise ContainerConfigError(
                f"{local} is outside {local_root}, so it has no known host path"
            ) from exc
        return str(host_root / relative)

    def _label_role(self) -> str:
        return f"{self._settings.label_namespace}.role=scanner"

    # -- output collection ----------------------------------------------------

    def _collect(self, spool: Path) -> None:
        """Move this scan's private output into the shared stores."""
        _merge_tree(spool / "outbound", self._settings.outbound_dir)
        _merge_tree(spool / "daily-brief", self._settings.daily_brief_dir)

    def _rewrite_written(self, verdict: dict[str, Any]) -> dict[str, Any]:
        """Re-point the verdict's paths at where the output actually ended up.

        The scanner reported paths inside its own container. Those are true but
        useless to a webhook receiver, and the files have since moved. The
        substitution is confined to ``written``, which is the only part of the
        verdict the dispatcher already reads (``sinks.py``), so this adds no
        knowledge of the scanner's format that was not already assumed.
        """
        written = verdict.get("written")
        if not isinstance(written, dict):
            return verdict
        mapping = (
            (CONTAINER_OUTBOUND, str(self._settings.outbound_dir)),
            (CONTAINER_DAILY_BRIEF, str(self._settings.daily_brief_dir)),
        )
        rewritten = {key: _swap_prefix(value, mapping) for key, value in written.items()}
        return {**verdict, "written": rewritten}


# -- helpers ------------------------------------------------------------------


def _swap_prefix(value: Any, mapping: Sequence[tuple[str, str]]) -> Any:
    if not isinstance(value, str):
        return value
    for container_prefix, local_prefix in mapping:
        if value == container_prefix:
            return local_prefix
        if value.startswith(container_prefix + "/"):
            return local_prefix + value[len(container_prefix) :]
    return value


def _merge_tree(source: Path, destination: Path) -> None:
    """Move everything under ``source`` into ``destination``.

    Deliberately blind: it mirrors whatever tree it is given without knowing
    what the scanner writes or how it is laid out, which is what lets the
    scanner stay an opaque unit. Overwriting is correct -- the scanner rewrites
    its own files identically on a rescan, so a collision is the same message
    scanned twice.

    ONE exception to the blindness, and it is not optional. The scanner writes
    `.complete` into a job directory last, and that ordering is what tells the
    host-side publisher a job may be copied to the network partition. This move
    re-creates the tree in the shared store file by file, so it re-creates the
    ordering too -- and plain alphabetical order puts `.complete` FIRST (`.`
    sorts below every letter), which would advertise a job directory holding
    nothing but its sentinel. Sentinels therefore move after everything else.
    See `email_guard.route.COMPLETE_NAME` and `publisher/`.
    """
    if not source.is_dir():
        return
    for entry in _merge_order(source):
        target = destination / entry.relative_to(source)
        if entry.is_dir():
            target.mkdir(parents=True, exist_ok=True)
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.replace(entry, target)
        except OSError:
            # Different filesystems (os.replace cannot cross one). Should not
            # happen -- the spool lives under the data root -- but a copy is
            # always available as a fallback.
            shutil.move(str(entry), str(target))


def _merge_order(source: Path) -> list[Path]:
    """Everything under ``source``, with completion sentinels moved to the end."""
    entries = sorted(source.rglob("*"))
    return [entry for entry in entries if entry.name != COMPLETE_NAME] + [
        entry for entry in entries if entry.name == COMPLETE_NAME
    ]


def _remove_tree(path: Path) -> None:
    try:
        shutil.rmtree(path, ignore_errors=True)
    except Exception:  # noqa: BLE001 - cleanup never fails a scan
        log.warning("could not remove scan spool %s", path)


def _is_within(path: Path, root: Path) -> bool:
    try:
        Path(path).relative_to(root)
    except ValueError:
        return False
    return True


def _image_missing(stderr: str) -> bool:
    """Docker's two ways of saying the image is not on this host.

    With ``--pull never`` the daemon answers "No such image"; without it the
    client says "Unable to find image ... locally" first. Both mean the same
    thing to an operator: the build is stale.
    """
    return "No such image" in stderr or "Unable to find image" in stderr


def _is_root(user: str) -> bool:
    uid = str(user).split(":", 1)[0].strip()
    return uid in ("0", "root")


def _tail(stream: bytes | None) -> str:
    text = (stream or b"").decode("utf-8", errors="replace").strip()
    return text[-STDERR_KEEP:]
