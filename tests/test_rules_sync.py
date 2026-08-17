"""The rules auto-updater, end to end against a real git repository.

Every test here runs offline: the "upstream" is a `git init` in ``tmp_path``
reached over a ``file://`` URL, which exercises the same clone/fetch/ff code
paths a real HTTPS remote would without a network.

The invariants under test are the ones that make an auto-updater safe to point
at production mail:

* a pack the validator rejects is NOT promoted, and the live tree is left byte
  for byte as it was -- scanning continues on the known-good rules;
* a broken *signature feed* still promotes, because that half fails open;
* nothing outside the live root is ever written -- a rules pull and a list edit
  are independent operations, and the lists are personal data that is not in git
  at all;
* re-running with no upstream change promotes nothing.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from email_guard_rules_sync import store
from email_guard_rules_sync.config import SyncConfig
from email_guard_rules_sync.sync import pull_and_promote

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")


# --- fixtures ------------------------------------------------------------------


def git(*args: str, cwd: Path) -> str:
    """Run git in a fixture repo, with an identity that needs no user config."""
    completed = subprocess.run(
        [
            "git",
            "-c",
            "user.email=tests@example.invalid",
            "-c",
            "user.name=Email Guard Tests",
            "-c",
            "commit.gpgsign=false",
            *args,
        ],
        cwd=cwd,
        capture_output=True,
        text=True,
        check=True,
    )
    return completed.stdout.strip()


@pytest.fixture
def upstream(tmp_path: Path, rules_dir: Path) -> Path:
    """A repository shaped like this one: a rules pack plus unrelated code.

    The ``engine/`` directory is a decoy. It exists so the sparse-checkout
    assertions have something that *must not* be pulled.
    """
    repo = tmp_path / "upstream"
    repo.mkdir()
    git("init", "-b", "main", cwd=repo)
    # A `file://` remote refuses partial clones unless it opts in.
    git("config", "uploadpack.allowFilter", "true", cwd=repo)
    git("config", "uploadpack.allowAnySHA1InWant", "true", cwd=repo)

    shutil.copytree(rules_dir, repo / "rules")
    (repo / "engine").mkdir()
    (repo / "engine" / "runner.py").write_text("# not part of the pack\n", encoding="utf-8")

    git("add", "-A", cwd=repo)
    git("commit", "-m", "seed the pack", cwd=repo)
    return repo


@pytest.fixture
def live(tmp_path: Path) -> Path:
    return tmp_path / "rules-live"


@pytest.fixture
def config(upstream: Path, live: Path, rules_dir: Path) -> SyncConfig:
    return SyncConfig(
        repo_url=f"file://{upstream}",
        branch="main",
        subpath="rules",
        live_dir=live,
        seed_dir=rules_dir,
        keep_releases=3,
    )


def commit_upstream(repo: Path, message: str) -> str:
    git("add", "-A", cwd=repo)
    git("commit", "-m", message, cwd=repo)
    return git("rev-parse", "HEAD", cwd=repo)


def tree_digest(root: Path) -> str:
    """A content hash of a whole directory: names, and bytes."""
    digest = hashlib.sha256()
    for path in sorted(Path(root).rglob("*")):
        if path.is_file():
            digest.update(str(path.relative_to(root)).encode())
            digest.update(path.read_bytes())
    return digest.hexdigest()


# --- seeding -------------------------------------------------------------------


def test_a_fresh_live_root_is_seeded_from_the_committed_pack(config: SyncConfig):
    """Before any pull, the live tree already serves the pack that is in git.

    This is what lets the mounts be repointed at the managed tree *before* the
    first successful pull -- and what makes an updater that cannot reach GitHub
    a non-event rather than an outage.
    """
    store.ensure_live_root(config.live_dir, config.seed_dir)

    current = config.live_dir / "current"
    assert current.is_symlink()
    assert (current / "scan" / "level2.json").is_file()
    assert (current / "validate.py").is_file()


def test_the_current_symlink_is_relative(config: SyncConfig):
    """It is resolved in three different mount namespaces.

    The docker daemon resolves it on the host when it binds the scan container's
    rules mount; the dispatcher resolves it inside its own filesystem; the
    updater resolves it inside a third. An absolute target would name a path
    that exists in only one of them.
    """
    store.ensure_live_root(config.live_dir, config.seed_dir)

    target = os.readlink(config.live_dir / "current")
    assert not os.path.isabs(target)
    assert target == "releases/seed/rules"


# --- the happy path ------------------------------------------------------------


def test_the_first_pull_promotes_and_reports_updated(config: SyncConfig, upstream: Path):
    head = git("rev-parse", "HEAD", cwd=upstream)

    result = pull_and_promote(config)

    assert result.status == "updated"
    assert result.new_commit == head
    assert result.validation_errors == ()
    assert os.readlink(config.live_dir / "current") == f"releases/{head}/rules"
    assert (config.live_dir / "current" / "scan" / "level2.json").is_file()


def test_a_second_pull_with_no_upstream_change_promotes_nothing(config: SyncConfig):
    """Deterministic and idempotent: the daily no-op must really be a no-op."""
    pull_and_promote(config)
    before_target = os.readlink(config.live_dir / "current")
    before_releases = sorted(p.name for p in (config.live_dir / "releases").iterdir())
    before_inode = os.lstat(config.live_dir / "current").st_ino

    result = pull_and_promote(config)

    assert result.status == "no_change"
    assert result.old_commit == result.new_commit
    assert os.readlink(config.live_dir / "current") == before_target
    assert sorted(p.name for p in (config.live_dir / "releases").iterdir()) == before_releases
    # Not even a rewritten symlink pointing at the same place.
    assert os.lstat(config.live_dir / "current").st_ino == before_inode


def test_a_new_upstream_commit_is_picked_up(config: SyncConfig, upstream: Path):
    pull_and_promote(config)

    rules = json.loads((upstream / "rules" / "scan" / "level2.json").read_text())
    rules.append(
        {
            "field": "content-newcheck",
            "type": "non_empty",
            "result_if_match": "fail",
            "result_if_no_match": "pass",
        }
    )
    (upstream / "rules" / "scan" / "level2.json").write_text(json.dumps(rules, indent=2))
    head = commit_upstream(upstream, "add a rule")

    result = pull_and_promote(config)

    assert result.status == "updated"
    assert result.new_commit == head
    promoted = json.loads((config.live_dir / "current" / "scan" / "level2.json").read_text())
    assert any(rule["field"] == "content-newcheck" for rule in promoted)


# --- FAIL CLOSED: the scan rules ------------------------------------------------


def test_a_pack_the_validator_rejects_is_not_promoted(config: SyncConfig, upstream: Path):
    pull_and_promote(config)
    good = os.readlink(config.live_dir / "current")

    (upstream / "rules" / "scan" / "level2.json").write_text("{ this is not json")
    commit_upstream(upstream, "break the pack")

    result = pull_and_promote(config)

    assert result.status == "rejected"
    assert result.validation_errors
    assert any("invalid JSON" in error for error in result.validation_errors)
    assert os.readlink(config.live_dir / "current") == good


def test_a_rejected_pull_leaves_the_live_tree_byte_for_byte_identical(
    config: SyncConfig, upstream: Path
):
    """The whole point of failing closed: scanning continues, unchanged."""
    pull_and_promote(config)
    before = tree_digest(config.live_dir / "current")

    (upstream / "rules" / "assess" / "level3.py").write_text("def assess(  # syntax error\n")
    commit_upstream(upstream, "break an assessor")

    result = pull_and_promote(config)

    assert result.status == "rejected"
    assert tree_digest(config.live_dir / "current") == before


def test_a_rejected_commit_is_not_refetched_every_interval(config: SyncConfig, upstream: Path):
    """A stuck upstream must keep saying 'rejected', not decay into 'no_change'.

    Reporting no_change would be actively misleading: it is what an operator
    reads as "we are up to date", when in fact the feed has been frozen since
    the bad commit landed.
    """
    pull_and_promote(config)
    (upstream / "rules" / "scan" / "level3.json").write_text("[")
    commit_upstream(upstream, "break level 3")

    first = pull_and_promote(config)
    second = pull_and_promote(config)

    assert first.status == "rejected"
    assert second.status == "rejected"
    assert second.validation_errors == first.validation_errors


def test_a_rejected_pack_leaves_no_staged_release_behind(config: SyncConfig, upstream: Path):
    pull_and_promote(config)
    (upstream / "rules" / "scan" / "level2.json").write_text("nope")
    bad = commit_upstream(upstream, "break it")

    pull_and_promote(config)

    assert not (config.live_dir / "releases" / bad).exists()


def test_a_missing_pack_at_the_subpath_is_rejected(config: SyncConfig, upstream: Path):
    pull_and_promote(config)
    good = os.readlink(config.live_dir / "current")

    shutil.rmtree(upstream / "rules")
    commit_upstream(upstream, "remove the pack entirely")

    result = pull_and_promote(config)

    assert result.status == "rejected"
    assert os.readlink(config.live_dir / "current") == good


# --- FAIL OPEN: the signature feed ----------------------------------------------


def test_a_malformed_signature_feed_still_promotes(config: SyncConfig, upstream: Path):
    """The opposite half of the split, and the reason it exists.

    A truncated or corrupt feed download must cost sensitivity, not stop the
    mail. Note the pack validator does not look at `reference/` at all, so this
    is checked by the updater itself.
    """
    pull_and_promote(config)

    feed = upstream / "rules" / "reference" / "injection_signatures.json"
    feed.write_text("{ truncated download")
    head = commit_upstream(upstream, "corrupt the injection feed")

    result = pull_and_promote(config)

    assert result.status == "updated"
    assert result.new_commit == head
    assert result.warnings
    assert any("injection_signatures.json" in warning for warning in result.warnings)


def test_a_missing_signature_feed_still_promotes(config: SyncConfig, upstream: Path):
    pull_and_promote(config)

    (upstream / "rules" / "reference" / "injection_signatures.json").unlink()
    commit_upstream(upstream, "drop the injection feed")

    result = pull_and_promote(config)

    assert result.status == "updated"
    assert any(
        "injection_signatures.json" in warning and "missing" in warning
        for warning in result.warnings
    )


def test_a_missing_reference_directory_still_promotes(config: SyncConfig, upstream: Path):
    """git tracks files, not directories, so dropping both feeds drops the dir.

    Worth its own case: the whole-directory branch is the one a fresh pack from
    a repository that never carried a feed would take.
    """
    pull_and_promote(config)

    shutil.rmtree(upstream / "rules" / "reference")
    commit_upstream(upstream, "drop both feeds")

    result = pull_and_promote(config)

    assert result.status == "updated"
    assert result.warnings
    assert any("reference/" in warning for warning in result.warnings)


def test_one_bad_signature_entry_does_not_block_the_promote(
    config: SyncConfig, upstream: Path
):
    pull_and_promote(config)

    feed = upstream / "rules" / "reference" / "injection_signatures.json"
    data = json.loads(feed.read_text())
    data["signatures"].append({"id": "inj-bad", "type": "regex", "pattern": "([unclosed"})
    feed.write_text(json.dumps(data, indent=2))
    commit_upstream(upstream, "add an uncompilable signature")

    result = pull_and_promote(config)

    assert result.status == "updated"
    assert any("does not compile" in warning for warning in result.warnings)


# --- configuration is honoured --------------------------------------------------


def test_only_the_configured_subpath_is_pulled(config: SyncConfig):
    """The decoy `engine/` directory must not reach the live tree.

    A rules pull moves rules. Pulling the whole repository into the mount would
    put engine source where the scanner expects a pack.
    """
    pull_and_promote(config)

    promoted = list((config.live_dir / "releases").rglob("engine"))
    assert promoted == []
    assert not (config.live_dir / "current" / "runner.py").exists()


def test_the_configured_branch_is_honoured(config: SyncConfig, upstream: Path, live: Path):
    git("checkout", "-b", "hardening", cwd=upstream)
    rules = json.loads((upstream / "rules" / "scan" / "level2.json").read_text())
    rules.append(
        {
            "field": "content-hardened",
            "type": "non_empty",
            "result_if_match": "fail",
            "result_if_no_match": "pass",
        }
    )
    (upstream / "rules" / "scan" / "level2.json").write_text(json.dumps(rules, indent=2))
    head = commit_upstream(upstream, "hardening branch only")
    git("checkout", "main", cwd=upstream)

    on_branch = SyncConfig(
        repo_url=config.repo_url,
        branch="hardening",
        subpath=config.subpath,
        live_dir=live,
        seed_dir=config.seed_dir,
    )
    result = pull_and_promote(on_branch)

    assert result.status == "updated"
    assert result.new_commit == head
    promoted = json.loads((live / "current" / "scan" / "level2.json").read_text())
    assert any(rule["field"] == "content-hardened" for rule in promoted)


def test_switching_branch_under_an_existing_clone_works(
    config: SyncConfig, upstream: Path, live: Path
):
    """Changing EMAIL_GUARD_RULES_BRANCH must not need the clone deleted."""
    pull_and_promote(config)

    git("checkout", "-b", "next", cwd=upstream)
    (upstream / "rules" / "reference" / "phishing_signatures.json").write_text(
        json.dumps({"version": 1, "updated": "2026-08-17", "signatures": []}, indent=2)
    )
    head = commit_upstream(upstream, "next branch")
    git("checkout", "main", cwd=upstream)

    switched = SyncConfig(
        repo_url=config.repo_url,
        branch="next",
        subpath=config.subpath,
        live_dir=live,
        seed_dir=config.seed_dir,
    )
    result = pull_and_promote(switched)

    assert result.status == "updated"
    assert result.new_commit == head


# --- history integrity ----------------------------------------------------------


def test_a_force_pushed_history_is_refused(config: SyncConfig, upstream: Path):
    """A rewritten upstream is a supply-chain signal, not an update.

    This is the case a `--depth 1` clone could not detect, which is why the
    working copy is cloned blobless-but-complete instead.
    """
    pull_and_promote(config)
    good = os.readlink(config.live_dir / "current")

    git("checkout", "--orphan", "rewritten", cwd=upstream)
    git("add", "-A", cwd=upstream)
    git("commit", "-m", "unrelated history", cwd=upstream)
    git("branch", "-M", "rewritten", "main", cwd=upstream)

    result = pull_and_promote(config)

    assert result.status == "rejected"
    assert any("rewritten" in error for error in result.validation_errors)
    assert os.readlink(config.live_dir / "current") == good


# --- blast radius ---------------------------------------------------------------


def test_the_pull_writes_only_inside_the_live_root(
    config: SyncConfig, tmp_path: Path, upstream: Path
):
    """A rules update and a list edit are independent operations.

    The live lists are personal data, are never in git, and must be untouched by
    anything the updater does. The repo-wide guard in ``tests/conftest.py``
    covers ``data/``; this covers everything else in the sandbox.
    """
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    (outside / "lists.json").write_text('{"entries": []}', encoding="utf-8")
    before = tree_digest(outside)
    upstream_before = tree_digest(upstream)

    pull_and_promote(config)

    assert tree_digest(outside) == before
    assert tree_digest(upstream) == upstream_before


def test_the_committed_seed_pack_is_never_written(config: SyncConfig, rules_dir: Path):
    """``rules/`` is tracked. The updater reads it and nothing more."""
    before = tree_digest(rules_dir)

    pull_and_promote(config)
    pull_and_promote(config)

    assert tree_digest(rules_dir) == before


# --- housekeeping ---------------------------------------------------------------


def test_a_release_that_never_completed_is_pruned(config: SyncConfig):
    """The remains of a crash between staging and the swap."""
    pull_and_promote(config)
    orphan = config.live_dir / "releases" / "deadbeef" / "rules"
    orphan.mkdir(parents=True)
    (orphan / "stray.json").write_text("{}", encoding="utf-8")

    store.ensure_live_root(config.live_dir, config.seed_dir)

    assert not (config.live_dir / "releases" / "deadbeef").exists()


def test_the_live_release_is_never_pruned(config: SyncConfig):
    pull_and_promote(config)
    current = store.current_release(config.live_dir)

    store.prune(config.live_dir, keep=1, now=1e12)

    assert (config.live_dir / "releases" / current / "rules").is_dir()
    assert (config.live_dir / "current" / "scan").is_dir()


def test_old_releases_are_pruned_to_the_keep_count(config: SyncConfig, upstream: Path):
    pull_and_promote(config)
    for index in range(4):
        (upstream / "rules" / "reference" / "phishing_signatures.json").write_text(
            json.dumps(
                {"version": 1, "updated": f"2026-08-{index + 10}", "signatures": []}, indent=2
            )
        )
        commit_upstream(upstream, f"feed bump {index}")
        pull_and_promote(config)

    # `now` far in the future so the min-age hold-down does not mask the result.
    store.prune(config.live_dir, keep=config.keep_releases, now=1e12)

    releases = [p.name for p in (config.live_dir / "releases").iterdir() if p.is_dir()]
    assert store.current_release(config.live_dir) in releases
    assert len(releases) <= config.keep_releases + 1  # +1 for the protected seed


def test_a_recent_release_is_held_back_from_pruning(config: SyncConfig, upstream: Path):
    """An in-flight scan container may still have it mounted."""
    pull_and_promote(config)
    first = store.current_release(config.live_dir)

    (upstream / "rules" / "reference" / "phishing_signatures.json").write_text(
        json.dumps({"version": 1, "updated": "2026-08-18", "signatures": []}, indent=2)
    )
    commit_upstream(upstream, "bump")
    pull_and_promote(config)

    store.prune(config.live_dir, keep=1)

    assert (config.live_dir / "releases" / first).is_dir()


# --- never raises ---------------------------------------------------------------


def test_an_unreachable_remote_is_an_error_not_an_exception(config: SyncConfig, live: Path):
    broken = SyncConfig(
        repo_url=f"file://{live / 'no-such-repo'}",
        branch="main",
        subpath="rules",
        live_dir=live,
        seed_dir=config.seed_dir,
    )

    result = pull_and_promote(broken)

    assert result.status == "error"
    assert result.message


def test_an_unreachable_remote_leaves_the_seeded_pack_serving(
    config: SyncConfig, live: Path
):
    store.ensure_live_root(live, config.seed_dir)
    broken = SyncConfig(
        repo_url=f"file://{live / 'no-such-repo'}",
        branch="main",
        subpath="rules",
        live_dir=live,
        seed_dir=config.seed_dir,
    )

    pull_and_promote(broken)

    assert (live / "current" / "scan" / "level2.json").is_file()


def test_a_missing_branch_is_an_error(config: SyncConfig, live: Path):
    missing = SyncConfig(
        repo_url=config.repo_url,
        branch="no-such-branch",
        subpath="rules",
        live_dir=live,
        seed_dir=config.seed_dir,
    )

    result = pull_and_promote(missing)

    assert result.status == "error"


def test_the_result_serialises_to_json(config: SyncConfig):
    result = pull_and_promote(config)

    payload = json.dumps(result.as_dict())

    assert json.loads(payload)["status"] == "updated"
    assert set(result.as_dict()) == {
        "status",
        "old_commit",
        "new_commit",
        "validation_errors",
        "warnings",
        "timestamp",
        "message",
    }
