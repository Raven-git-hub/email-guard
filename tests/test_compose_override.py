"""The deployment-specific half of the stack, and the sample that records it.

`docker-compose.override.yml` carries the wiring that is true of ONE host: the
dispatcher's route to the webhook target, over a network another compose stack
created and whose name that stack derived from its own project directory. It
cannot be committed as-is, and it cannot be left implicit either -- the failure
mode is silent. A clone without it brings up a dispatcher on two `internal`
networks, scanning works, and every webhook POST fails to resolve behind a
best-effort delivery that never reports it.

So the live file stays git-ignored and `docker-compose.override.yml.sample`
stands in as the tracked record of what it must contain. These tests hold that
split in place: the sample is tracked, the live file is not, the sample says
what it has to say, and the README says how to turn one into the other.

Parsing the YAML rather than matching substrings, the same call
`tests/test_rules_sync_deploy.py` makes for the base file.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

pytest.importorskip("yaml", reason="compose assertions need PyYAML")

PROJECT_ROOT = Path(__file__).resolve().parent.parent
COMPOSE = PROJECT_ROOT / "docker-compose.yml"
SAMPLE = PROJECT_ROOT / "docker-compose.override.yml.sample"
LIVE = "docker-compose.override.yml"


@pytest.fixture(scope="module")
def sample() -> dict:
    import yaml

    with SAMPLE.open(encoding="utf-8") as handle:
        return yaml.safe_load(handle)


@pytest.fixture(scope="module")
def sample_text() -> str:
    return SAMPLE.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def base() -> dict:
    import yaml

    with COMPOSE.open(encoding="utf-8") as handle:
        return yaml.safe_load(handle)


# --- the tracked/local split ------------------------------------------------------


def test_the_sample_is_tracked_and_the_live_override_is_not():
    """The same shape as `config/secrets.json`: sample in git, filled-in copy out."""
    tracked = subprocess.run(
        ["git", "ls-files"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split()

    assert "docker-compose.override.yml.sample" in tracked
    assert LIVE not in tracked


def test_the_live_override_is_gitignored_and_the_sample_is_not():
    """Asked of git, not matched against `.gitignore` by hand.

    A pattern that also swallowed the sample would leave nothing tracked at
    all -- which is the exact hole this feature closes -- so both directions
    are checked.
    """

    def ignored(name: str) -> bool:
        # `check-ignore` exits 0 when the path IS ignored, 1 when it is not.
        return subprocess.run(
            ["git", "check-ignore", "-q", name],
            cwd=PROJECT_ROOT,
            capture_output=True,
        ).returncode == 0

    assert ignored(LIVE)
    assert not ignored("docker-compose.override.yml.sample")


# --- what the sample has to contain -----------------------------------------------


def test_the_sample_gives_the_dispatcher_a_route_to_the_webhook_target(sample: dict):
    assert sorted(sample["services"]["dispatcher"]["networks"]) == [
        "dockerproxy",
        "mail",
        "n8n",
    ]


def test_the_sample_keeps_the_networks_the_base_file_gave_the_dispatcher(
    sample: dict, base: dict
):
    """Adding `n8n` must not cost the bridge hop or the socket-proxy.

    Compose merges a service's `networks` rather than replacing them, so the
    two would survive being left out -- but the override is also the file an
    operator edits by hand, and an explicit list is what makes a dropped
    network visible there.
    """
    for network in base["services"]["dispatcher"]["networks"]:
        assert network in sample["services"]["dispatcher"]["networks"], (
            f"the sample drops the dispatcher's {network!r} network"
        )


def test_the_n8n_network_is_external_and_names_the_host_network(sample: dict):
    """`external` means "already exists" -- compose must not create its own."""
    n8n = sample["networks"]["n8n"]

    assert n8n["external"] is True
    assert n8n["name"] == "mail-net"


def test_the_sample_says_the_external_name_is_deployment_specific(sample_text: str):
    """The one field that is wrong on every other host has to be flagged as such."""
    assert "DEPLOYMENT-SPECIFIC" in sample_text
    assert "docker network ls" in sample_text


def test_the_base_file_still_declares_no_n8n_network(base: dict):
    """The committed stack stays egress-free; the route is opt-in, per host."""
    assert "n8n" not in base["networks"]
    assert "n8n" not in base["services"]["dispatcher"]["networks"]


# --- the instructions -------------------------------------------------------------


def test_the_readme_documents_the_copy_and_the_adjustment():
    readme = (PROJECT_ROOT / "README.md").read_text(encoding="utf-8")

    assert (
        "cp docker-compose.override.yml.sample docker-compose.override.yml" in readme
    ), "the bring-up steps must include the copy"
    # ...and that compose picks the copy up on its own, which is the reason
    # forgetting it is quiet rather than loud.
    assert "auto-load" in readme.lower()
    assert "mail-net" in readme
