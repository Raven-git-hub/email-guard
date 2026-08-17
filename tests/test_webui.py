"""The review console: the queue it shows, and the writes it is allowed to make.

The web UI is a *consumer* of the scanner, so these tests are about the seam
rather than the engine. Four properties carry the security weight:

* **Plain text only.** A card's ``body`` is the candidate's excerpt and nothing
  else, and an excerpt that looks like markup still arrives as text. The server
  has no raw HTML body to leak, and the test that proves it fabricates a
  candidate whose excerpt is a ``<script>`` tag.
* **The applier is the only writer.** Every write endpoint goes through
  :func:`email_guard.apply.apply_decisions`, so it inherits mutual exclusivity,
  all-or-nothing validation and idempotence. A rejected decision must leave the
  list files byte-for-byte unchanged.
* **A candidate is consumed exactly once.** A decision moves it out of the
  queue; re-posting the same decision changes nothing.
* **The CSP is on every response**, including errors and static assets.

Every test uses ``tmp_path`` lists and daily-brief directories with fabricated
candidates -- never the repo's ``data/`` (guarded by ``repo_data_stays_empty``
in ``conftest.py``) and never the committed fixtures, which the applier would
rewrite.
"""

from __future__ import annotations

import json
import re
from datetime import date
from pathlib import Path

import pytest

fastapi = pytest.importorskip("fastapi", reason="the web UI needs the 'webui' extra")
from fastapi.testclient import TestClient  # noqa: E402

from email_guard.lists import GREYLIST_KNOWN, Lists, classify_greylist, tags_of  # noqa: E402
from email_guard.propose import CANDIDATE_NAME, CANDIDATE_VERSION, brief_dir_name  # noqa: E402
from email_guard_webui.app import create_app  # noqa: E402
from email_guard_webui.config import AUTH_HEADER, WebUIConfig, content_security_policy  # noqa: E402

DAY = date(2026, 5, 15)
UNKNOWN_SENDER = "promo@shopfast.example"
UNKNOWN_DOMAIN = "shopfast.example"


# --- staging -------------------------------------------------------------------


def stage_candidate(
    daily_brief_dir: Path,
    job: str,
    sender: str = UNKNOWN_SENDER,
    *,
    day: date = DAY,
    excerpt: str = "FLASH SALE - 50% off. Tap to shop: hxxps://shopfast[.]example/sale",
    subject: str = "Flash sale this weekend",
    classification: str = "unknown_domain",
    authenticity: dict | None = None,
) -> Path:
    """Write one candidate exactly where ``email_guard.propose`` would.

    Hand-built rather than produced by a scan: these tests are about what the
    console does with a staged candidate, and fabricating one keeps the
    interesting fields (a hostile-looking excerpt, a failing DMARC) under the
    test's control.
    """
    domain = sender.split("@", 1)[1] if "@" in sender else ""
    document = {
        "candidate_version": CANDIDATE_VERSION,
        "job": job,
        "date": day.isoformat(),
        "classification": classification,
        "reason": f"{sender} is on no list",
        "sender": {"email": sender, "domain": domain, "friendly_name": None},
        "outbound": {"bucket": "flagged", "job": job},
        "evidence": {
            "message_id": f"<{job}@example>",
            "subject": subject,
            "excerpt": excerpt,
            "links": ["hxxps://shopfast[.]example/sale"],
            "attachments": [],
            "authenticity": authenticity or {"dkim": "pass", "dmarc": "pass", "spf": "pass"},
        },
        "proposed_structure": {"name": subject, "key_phrases": [f"Subject: {subject}"]},
        "proposed_entries": [],
    }
    path = daily_brief_dir / brief_dir_name(day) / job / CANDIDATE_NAME
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    return path


def write_lists(lists_dir: Path, **lists) -> None:
    for name in ("whitelist", "greylist", "blacklist"):
        (lists_dir / f"{name}.json").write_text(
            json.dumps({name: lists.get(name, [])}, indent=2) + "\n", encoding="utf-8"
        )


# --- fixtures ------------------------------------------------------------------


@pytest.fixture
def lists_dir(tmp_path: Path) -> Path:
    path = tmp_path / "lists"
    path.mkdir()
    write_lists(
        path,
        whitelist=[{"email": "julia@btinternet.example", "tags": ["family"]}],
        greylist=[
            {
                "domain": "hsbc.example",
                "tags": ["bank"],
                "known_structures": [
                    {"name": "payment alert", "key_phrases": ["payment"], "disposition": "allowed"},
                    {"name": "marketing blast", "key_phrases": ["offer"], "disposition": "denied"},
                ],
            }
        ],
        blacklist=[{"email": "scam@fakeemail.example"}],
    )
    return path


@pytest.fixture
def daily_brief_dir(tmp_path: Path) -> Path:
    path = tmp_path / "daily-brief"
    path.mkdir()
    return path


@pytest.fixture
def config(tmp_path: Path, lists_dir: Path, daily_brief_dir: Path) -> WebUIConfig:
    return WebUIConfig(
        lists_dir=lists_dir,
        daily_brief_dir=daily_brief_dir,
        outbound_dir=tmp_path / "outbound",
    )


@pytest.fixture
def client(config: WebUIConfig) -> TestClient:
    return TestClient(create_app(config, today=lambda: DAY))


def entries_of(lists_dir: Path, name: str) -> list[dict]:
    return json.loads((lists_dir / f"{name}.json").read_text(encoding="utf-8"))[name]


def snapshot(lists_dir: Path) -> dict[str, str]:
    return {path.name: path.read_text(encoding="utf-8") for path in sorted(lists_dir.glob("*.json"))}


# --- the queue -----------------------------------------------------------------


def test_candidates_endpoint_reads_the_staged_queue(client, daily_brief_dir):
    stage_candidate(daily_brief_dir, "job-a")
    stage_candidate(daily_brief_dir, "job-b", sender="security@paypa1-alerts.example")

    payload = client.get("/api/candidates").json()

    assert payload["count"] == 2
    assert [card["id"] for card in payload["candidates"]] == [
        f"{brief_dir_name(DAY)}/job-a",
        f"{brief_dir_name(DAY)}/job-b",
    ]
    first = payload["candidates"][0]
    assert first["sender"] == {"email": UNKNOWN_SENDER, "domain": UNKNOWN_DOMAIN}
    assert "unknown_domain" in first["flags"]
    assert first["body"].startswith("FLASH SALE")


def test_a_card_carries_the_excerpt_and_nothing_else(client, daily_brief_dir):
    """The card is the excerpt, the sender, the flags and the membership.

    Not the message id, not the proposed entries, not the links: a review screen
    that only has to answer "which list?" has no business shipping the rest of
    the candidate to a browser.
    """
    stage_candidate(daily_brief_dir, "job-a")

    card = client.get("/api/candidates").json()["candidates"][0]

    assert set(card) == {"id", "sender", "flags", "body", "membership"}
    assert "<" not in json.dumps(card)


def test_an_html_looking_excerpt_is_delivered_inert(client, daily_brief_dir):
    """A hostile excerpt survives as text, and only as text.

    The scanner already strips HTML, so this shape should never arrive -- which
    is exactly why it is worth pinning. The server hands back the characters it
    was given, with no markup and no HTML content type; the client renders them
    with ``textContent``. Nothing on the path turns them into elements.
    """
    hostile = '<script>alert(1)</script><img src=x onerror="alert(2)">'
    stage_candidate(daily_brief_dir, "job-a", excerpt=hostile)

    response = client.get("/api/candidates")
    card = response.json()["candidates"][0]

    # Passed through verbatim -- not sanitised, not stripped, not escaped. The
    # server's job is to never make it markup, and it does that by never
    # serving it as markup.
    assert card["body"] == hostile
    assert response.headers["content-type"].startswith("application/json")
    # The one place the server does serve markup is the shell, and no message
    # text is interpolated into it: it is a static file.
    assert hostile not in client.get("/").text


def test_the_client_has_no_way_to_turn_a_body_into_markup(client):
    """The other half of the same guarantee, checked in the served script.

    ``textContent`` is only a defence while nothing on the page reaches for
    ``innerHTML``. A future edit that adds one would pass every other test in
    this file, so the absence is pinned here rather than left to review.
    """
    script = client.get("/static/app.js").text
    # Comments explain the rule; only the code has to keep it.
    code = re.sub(r"/\*.*?\*/", "", script, flags=re.DOTALL)
    code = "\n".join(line for line in code.splitlines() if not line.lstrip().startswith("//"))

    for sink in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval("):
        assert sink not in code
    assert "textContent" in code


def test_a_candidate_with_no_excerpt_has_an_empty_body(client, daily_brief_dir):
    stage_candidate(daily_brief_dir, "job-a", excerpt="")
    path = daily_brief_dir / brief_dir_name(DAY) / "job-b" / CANDIDATE_NAME
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps({"sender": {"email": "a@b.example", "domain": "b.example"}}), "utf-8")

    bodies = [card["body"] for card in client.get("/api/candidates").json()["candidates"]]

    assert bodies == ["", ""]


def test_flags_come_from_the_candidate(client, daily_brief_dir):
    stage_candidate(
        daily_brief_dir,
        "job-a",
        subject="Urgent: аccount verification",  # Cyrillic 'a' -- a homoglyph
        authenticity={"dkim": "pass", "dmarc": "fail", "spf": "pass"},
    )

    flags = client.get("/api/candidates").json()["candidates"][0]["flags"]

    assert "unknown_domain" in flags
    assert "obfuscation_visual" in flags
    assert "dmarc_fail" in flags


def test_membership_reports_the_list_a_sender_is_already_on(client, daily_brief_dir):
    """Including via a parent domain -- the rule the engine matches on."""
    stage_candidate(daily_brief_dir, "job-a", sender="alerts@notify.hsbc.example")

    card = client.get("/api/candidates").json()["candidates"][0]

    assert card["membership"] == {"list": "greylist", "key": "hsbc.example", "scope": "domain"}


def test_a_sender_on_no_list_has_no_membership(client, daily_brief_dir):
    stage_candidate(daily_brief_dir, "job-a")

    assert client.get("/api/candidates").json()["candidates"][0]["membership"] is None


def test_a_wrong_shaped_candidate_does_not_break_the_queue(client, daily_brief_dir):
    """A candidate is a file a human can open, so a hand-mangled one is possible.

    Wrong-shaped sections read as absent. The card is useless, but the rest of
    the day's review is not lost behind a 500.
    """
    path = daily_brief_dir / brief_dir_name(DAY) / "job-a" / CANDIDATE_NAME
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps({"sender": "promo@shopfast.example", "evidence": []}), "utf-8")

    card = client.get("/api/candidates").json()["candidates"][0]

    assert card["sender"] == {"email": "", "domain": ""}
    assert card["body"] == ""
    assert card["membership"] is None


def test_an_unreadable_candidate_does_not_hide_the_rest(client, daily_brief_dir):
    stage_candidate(daily_brief_dir, "job-a")
    broken = daily_brief_dir / brief_dir_name(DAY) / "job-broken" / CANDIDATE_NAME
    broken.parent.mkdir(parents=True)
    broken.write_text("{not json", encoding="utf-8")

    payload = client.get("/api/candidates").json()

    assert [card["id"] for card in payload["candidates"]] == [f"{brief_dir_name(DAY)}/job-a"]


# --- the queue is live against the current lists --------------------------------
#
# A candidate was staged against the lists as they stood then. These pin that the
# queue re-asks the question against the lists as they stand NOW, using the real
# matching -- `lists.find_entry` and `lists.structure_matches` by way of
# `propose.classify` -- rather than a second implementation of the rule that
# could drift from the scanner's.


HSBC_SENDER = "alerts@hsbc.example"


def test_a_candidate_whose_sender_is_now_whitelisted_drops_out(client, lists_dir, daily_brief_dir):
    stage_candidate(daily_brief_dir, "job-a")
    assert client.get("/api/candidates").json()["count"] == 1

    write_lists(lists_dir, whitelist=[{"email": UNKNOWN_SENDER}])

    payload = client.get("/api/candidates").json()
    assert payload["count"] == 0
    assert payload["suppressed"] == 1


def test_a_candidate_whose_sender_is_now_blacklisted_drops_out(client, lists_dir, daily_brief_dir):
    stage_candidate(daily_brief_dir, "job-a")

    write_lists(lists_dir, blacklist=[{"domain": UNKNOWN_DOMAIN}])

    assert client.get("/api/candidates").json()["count"] == 0


def test_a_candidate_matching_an_allowed_structure_drops_out(client, daily_brief_dir):
    """Its shape is catalogued and it would now clear -- nothing left to decide."""
    stage_candidate(
        daily_brief_dir,
        "job-a",
        sender=HSBC_SENDER,
        subject="Your payment is due",
        excerpt="A payment of 42.10 is scheduled for Friday.",
    )

    assert client.get("/api/candidates").json()["count"] == 0


def test_a_candidate_matching_a_denied_structure_drops_out(client, daily_brief_dir):
    """Catalogued is catalogued: a denied shape is as decided as an allowed one.

    The scanner skips it for the same reason -- the reviewer has already seen
    this shape and rejected it.
    """
    stage_candidate(
        daily_brief_dir,
        "job-a",
        sender=HSBC_SENDER,
        subject="Weekend offer inside",
        excerpt="Our best offer yet on savings accounts.",
    )

    assert client.get("/api/candidates").json()["count"] == 0


def test_the_genuinely_unresolved_still_show(client, daily_brief_dir):
    """The two cards a human still has to answer, and only those.

    An unknown domain, and a greylisted sender whose message matches none of
    that domain's structures. Everything else in this section is suppressed.
    """
    stage_candidate(daily_brief_dir, "job-a")  # unknown domain
    stage_candidate(
        daily_brief_dir,
        "job-b",
        sender=HSBC_SENDER,
        subject="Something entirely new",
        excerpt="Nothing here resembles a catalogued shape.",
    )
    stage_candidate(daily_brief_dir, "job-c", sender="scam@fakeemail.example")  # blacklisted

    payload = client.get("/api/candidates").json()

    assert [card["id"] for card in payload["candidates"]] == [
        f"{brief_dir_name(DAY)}/job-a",
        f"{brief_dir_name(DAY)}/job-b",
    ]
    assert payload["suppressed"] == 1
    # The greylisted one is shown *as* a greylist member: suppression is about
    # whether a decision is still needed, not about whether the sender is listed.
    assert payload["candidates"][1]["membership"]["list"] == "greylist"


def test_a_matching_parent_domain_structure_suppresses_a_subdomain_sender(client, daily_brief_dir):
    """Subdomain-inclusive, because `find_entries` is -- the engine's own rule."""
    stage_candidate(
        daily_brief_dir,
        "job-a",
        sender="noreply@notify.hsbc.example",
        subject="Payment received",
        excerpt="Your payment has been received.",
    )

    assert client.get("/api/candidates").json()["count"] == 0


def test_suppression_is_a_filter_and_never_a_move(client, lists_dir, daily_brief_dir):
    """Non-destructive: the staged file stays put, and the card comes back.

    Only a decision consumes a candidate. A card suppressed because a sender was
    listed returns if that entry is later removed -- which is what makes the
    queue a *view* of the staged tree rather than a second store of its own.
    """
    path = stage_candidate(daily_brief_dir, "job-a")
    write_lists(lists_dir, whitelist=[{"email": UNKNOWN_SENDER}])
    assert client.get("/api/candidates").json()["count"] == 0
    assert path.is_file()

    write_lists(lists_dir)

    assert client.get("/api/candidates").json()["count"] == 1


def test_listing_a_sender_clears_their_whole_backlog(client, daily_brief_dir):
    """The point of the whole filter: one decision answers every pending card.

    Three cards from one subscription sender, staged before anybody listed it.
    Deciding the first suppresses the other two on the next read, without a
    second click and without touching their files.
    """
    for job in ("job-a", "job-b", "job-c"):
        stage_candidate(daily_brief_dir, job, subject=f"Invoice {job}")
    assert client.get("/api/candidates").json()["count"] == 3

    client.post(
        "/api/decisions",
        json={
            "candidate": f"{brief_dir_name(DAY)}/job-a",
            "action": "whitelist",
            "entry": {"email": UNKNOWN_SENDER},
        },
    )

    payload = client.get("/api/candidates").json()
    assert payload["count"] == 0
    assert payload["suppressed"] == 2


# --- trust all mail from this sender --------------------------------------------


def test_trust_all_writes_the_catch_all_and_consumes_the_candidate(
    client, lists_dir, daily_brief_dir
):
    path = stage_candidate(daily_brief_dir, "job-a")

    response = client.post(
        "/api/decisions/trust-all",
        json={
            "candidate": f"{brief_dir_name(DAY)}/job-a",
            "domain": UNKNOWN_DOMAIN,
            "tags": ["invoices"],
        },
    )

    assert response.status_code == 200
    assert response.json()["consumed"] is True
    entry = [e for e in entries_of(lists_dir, "greylist") if e["domain"] == UNKNOWN_DOMAIN][0]
    assert entry["known_structures"] == [
        {"name": "ALL EMAILS", "key_phrases": [], "disposition": "allowed", "tags": ["invoices"]}
    ]
    assert (path.parent / "reviewed" / CANDIDATE_NAME).is_file()


def test_trust_all_clears_the_senders_other_cards(client, daily_brief_dir):
    """Fix 2 and Fix 1 meeting: one click, and the backlog goes with it.

    The invoice sender whose every subject carries a different reference stages
    a card per message. Trusting the domain consumes the card on screen, and the
    rest are suppressed by the queue filter because they now match a structure.
    """
    for job in ("job-a", "job-b", "job-c"):
        stage_candidate(daily_brief_dir, job, subject=f"Invoice INV-{job}", excerpt=f"see {job}")
    assert client.get("/api/candidates").json()["count"] == 3

    client.post(
        "/api/decisions/trust-all",
        json={"candidate": f"{brief_dir_name(DAY)}/job-a", "domain": UNKNOWN_DOMAIN, "tags": []},
    )

    assert client.get("/api/candidates").json()["count"] == 0


def test_trust_all_is_idempotent(client, lists_dir, daily_brief_dir):
    stage_candidate(daily_brief_dir, "job-a")
    body = {
        "candidate": f"{brief_dir_name(DAY)}/job-a",
        "domain": UNKNOWN_DOMAIN,
        "tags": ["invoices"],
    }

    assert client.post("/api/decisions/trust-all", json=body).json()["consumed"] is True
    after_first = snapshot(lists_dir)

    second = client.post("/api/decisions/trust-all", json=body)

    assert second.status_code == 200
    assert second.json()["consumed"] is False
    assert snapshot(lists_dir) == after_first


def test_trust_all_preserves_mutual_exclusivity(client, lists_dir, daily_brief_dir):
    """A trusted domain leaves whichever list it was on, like any decision."""
    stage_candidate(daily_brief_dir, "job-a", sender="payments@hsbc.example")

    response = client.post(
        "/api/decisions/trust-all",
        json={
            "candidate": f"{brief_dir_name(DAY)}/job-a",
            "domain": "hsbc.example",
            "tags": ["bank"],
        },
    )
    assert response.status_code == 200

    client.post(
        "/api/lists/blacklist/add", json={"entry": {"domain": "hsbc.example"}}
    )

    assert not any(e.get("domain") == "hsbc.example" for e in entries_of(lists_dir, "greylist"))
    assert "hsbc.example" in {e.get("domain") for e in entries_of(lists_dir, "blacklist")}
    # And the lists the engine loads are still the ones it will accept.
    assert Lists.load(lists_dir)


def test_a_trusted_sender_is_cleared_by_the_engine(client, lists_dir, daily_brief_dir):
    """What the console wrote, the engine now reads as "trust everything"."""
    stage_candidate(daily_brief_dir, "job-a")

    client.post(
        "/api/decisions/trust-all",
        json={
            "candidate": f"{brief_dir_name(DAY)}/job-a",
            "domain": UNKNOWN_DOMAIN,
            "tags": ["invoices"],
        },
    )

    lists = Lists.load(lists_dir)
    classification, _, matched = classify_greylist(
        lists.greylist, UNKNOWN_SENDER, UNKNOWN_DOMAIN, "Anything at all", "never seen before"
    )
    assert classification == GREYLIST_KNOWN
    assert tags_of(matched) == ["invoices"]


def test_trust_all_cannot_smuggle_a_structure_or_an_action(client, lists_dir, daily_brief_dir):
    """One click means one thing: the body has nowhere to put anything else."""
    stage_candidate(daily_brief_dir, "job-a")
    before = snapshot(lists_dir)
    candidate_id = f"{brief_dir_name(DAY)}/job-a"

    for body in (
        {"candidate": candidate_id, "domain": UNKNOWN_DOMAIN, "action": "blacklist"},
        {
            "candidate": candidate_id,
            "domain": UNKNOWN_DOMAIN,
            "structure": {"name": "S", "key_phrases": ["s"]},
        },
        {"candidate": candidate_id, "email": UNKNOWN_SENDER},
    ):
        assert client.post("/api/decisions/trust-all", json=body).status_code == 422

    assert snapshot(lists_dir) == before
    assert client.get("/api/candidates").json()["count"] == 1


def test_an_invalid_trust_all_is_rejected_and_changes_nothing(client, lists_dir, daily_brief_dir):
    """A card with no domain to trust is the applier's error to report, not ours.

    The console does not pre-validate -- the applier owns the rules, and
    answering them twice is how two answers start disagreeing. So an empty
    domain comes back as its "needs exactly one of 'email' or 'domain'", with
    the candidate still in the queue.
    """
    stage_candidate(daily_brief_dir, "job-a")
    before = snapshot(lists_dir)

    response = client.post(
        "/api/decisions/trust-all",
        json={"candidate": f"{brief_dir_name(DAY)}/job-a", "domain": "  "},
    )

    assert response.status_code == 400
    assert response.json()["errors"]
    assert snapshot(lists_dir) == before
    assert client.get("/api/candidates").json()["count"] == 1


def test_the_trust_all_control_is_wired_the_way_the_csp_requires(client):
    """The new control obeys the two rules the whole console is built on."""
    script = client.get("/static/app.js").text

    assert "buildTrustBox" in script
    assert "/api/decisions/trust-all" in script
    # Built with the el() helper and bound with addEventListener -- no markup
    # string, no inline handler. (`test_the_client_has_no_way_to_turn_a_body_
    # into_markup` pins the absence of every HTML sink for the whole file.)
    assert "el('div', 'trust-box')" in script
    assert "button.addEventListener('click', () => { trustAllSender(); });" in script


def test_the_trust_all_response_carries_the_csp(client, daily_brief_dir):
    stage_candidate(daily_brief_dir, "job-a")

    response = client.post(
        "/api/decisions/trust-all",
        json={"candidate": f"{brief_dir_name(DAY)}/job-a", "domain": UNKNOWN_DOMAIN},
    )

    assert response.status_code == 200
    assert "default-src 'none'" in response.headers["content-security-policy"]
    assert response.headers["cache-control"] == "no-store"


# --- decisions -----------------------------------------------------------------


def test_a_decision_applies_and_consumes_the_candidate(client, lists_dir, daily_brief_dir):
    path = stage_candidate(daily_brief_dir, "job-a")
    candidate_id = f"{brief_dir_name(DAY)}/job-a"

    response = client.post(
        "/api/decisions",
        json={
            "candidate": candidate_id,
            "action": "blacklist",
            "entry": {"email": UNKNOWN_SENDER, "tags": ["phishing"]},
        },
    )

    assert response.status_code == 200
    report = response.json()["report"]
    assert response.json()["consumed"] is True
    assert report["reviewed"] == DAY.isoformat()
    assert [change["operation"] for change in report["changes"]] == ["add_entry"]

    # The list really moved.
    assert [entry["email"] for entry in entries_of(lists_dir, "blacklist")] == [
        "scam@fakeemail.example",
        UNKNOWN_SENDER,
    ]
    # And the candidate is out of the queue, kept as evidence rather than deleted.
    assert not path.is_file()
    assert (path.parent / "reviewed" / CANDIDATE_NAME).is_file()
    assert client.get("/api/candidates").json()["count"] == 0


def test_re_posting_a_decision_is_idempotent(client, lists_dir, daily_brief_dir):
    """A double-clicked Confirm is a non-event.

    The candidate is gone the second time, so nothing is consumed -- and the
    applier, which owns idempotence, leaves the lists byte-for-byte identical.
    """
    stage_candidate(daily_brief_dir, "job-a")
    decision = {
        "candidate": f"{brief_dir_name(DAY)}/job-a",
        "action": "whitelist",
        "entry": {"email": UNKNOWN_SENDER},
    }

    assert client.post("/api/decisions", json=decision).json()["consumed"] is True
    after_first = snapshot(lists_dir)

    second = client.post("/api/decisions", json=decision)

    assert second.status_code == 200
    assert second.json()["consumed"] is False
    assert snapshot(lists_dir) == after_first


def test_a_greylist_decision_catalogues_the_structure(client, lists_dir, daily_brief_dir):
    stage_candidate(daily_brief_dir, "job-a")

    client.post(
        "/api/decisions",
        json={
            "candidate": f"{brief_dir_name(DAY)}/job-a",
            "action": "greylist",
            "entry": {"domain": UNKNOWN_DOMAIN, "tags": ["shopping"]},
            "structure": {
                "name": "FLASH SALE",
                "key_phrases": ["FLASH SALE"],
                "disposition": "denied",
                "tags": ["marketing"],
            },
        },
    )

    entry = [e for e in entries_of(lists_dir, "greylist") if e["domain"] == UNKNOWN_DOMAIN][0]
    assert entry["tags"] == ["shopping"]
    assert entry["known_structures"] == [
        {
            "name": "FLASH SALE",
            "key_phrases": ["FLASH SALE"],
            "disposition": "denied",
            "tags": ["marketing"],
        }
    ]


def test_a_decision_moves_a_sender_off_the_list_it_was_on(client, lists_dir, daily_brief_dir):
    """Mutual exclusivity, inherited from the applier rather than reimplemented."""
    stage_candidate(daily_brief_dir, "job-a", sender="payments@hsbc.example")

    response = client.post(
        "/api/decisions",
        json={
            "candidate": f"{brief_dir_name(DAY)}/job-a",
            "action": "blacklist",
            "entry": {"domain": "hsbc.example"},
        },
    )

    assert response.status_code == 200
    assert entries_of(lists_dir, "greylist") == []
    assert "hsbc.example" in {entry.get("domain") for entry in entries_of(lists_dir, "blacklist")}
    operations = {change["operation"] for change in response.json()["report"]["changes"]}
    assert operations == {"remove_entry", "add_entry"}


def test_a_discard_consumes_the_candidate_and_touches_nothing(client, lists_dir, daily_brief_dir):
    stage_candidate(daily_brief_dir, "job-a")
    before = snapshot(lists_dir)

    response = client.post(
        "/api/decisions",
        json={"candidate": f"{brief_dir_name(DAY)}/job-a", "action": "discard"},
    )

    assert response.status_code == 200
    assert response.json()["consumed"] is True
    assert snapshot(lists_dir) == before
    assert client.get("/api/candidates").json()["count"] == 0


@pytest.mark.parametrize(
    "decision",
    [
        pytest.param({"action": "sideline", "entry": {"email": UNKNOWN_SENDER}}, id="unknown-action"),
        pytest.param({"action": "whitelist", "entry": {}}, id="entry-without-a-subject"),
        pytest.param(
            {"action": "whitelist", "entry": {"email": UNKNOWN_SENDER, "domain": UNKNOWN_DOMAIN}},
            id="entry-claiming-both",
        ),
        pytest.param(
            {"action": "greylist", "entry": {"email": UNKNOWN_SENDER}},
            id="greylist-keyed-on-an-address",
        ),
    ],
)
def test_an_invalid_decision_is_rejected_and_changes_nothing(
    client, lists_dir, daily_brief_dir, decision
):
    """4xx, the applier's own error list, and not a byte written.

    All-or-nothing is the applier's guarantee; what this pins is that the
    console does not quietly repair a bad decision on its way through, and that
    the candidate stays in the queue for another go.
    """
    stage_candidate(daily_brief_dir, "job-a")
    before = snapshot(lists_dir)

    response = client.post(
        "/api/decisions", json={"candidate": f"{brief_dir_name(DAY)}/job-a", **decision}
    )

    assert 400 <= response.status_code < 500
    assert response.json()["errors"]
    assert snapshot(lists_dir) == before
    assert client.get("/api/candidates").json()["count"] == 1


def test_a_decision_for_an_unknown_candidate_still_applies_but_consumes_nothing(
    client, lists_dir
):
    response = client.post(
        "/api/decisions",
        json={
            "candidate": "daily-brief-2026-05-15/job-nobody",
            "action": "whitelist",
            "entry": {"email": "someone@elsewhere.example"},
        },
    )

    assert response.status_code == 200
    assert response.json()["consumed"] is False
    assert "someone@elsewhere.example" in {e.get("email") for e in entries_of(lists_dir, "whitelist")}


@pytest.mark.parametrize(
    "candidate_id",
    ["../../etc/passwd", "daily-brief-2026-05-15/../../../escape", "one-segment", ""],
)
def test_a_candidate_id_cannot_escape_the_daily_brief_directory(
    client, daily_brief_dir, tmp_path, candidate_id
):
    """An id is two path segments, and is rebuilt as such.

    The decision itself still applies -- it is a valid decision about a real
    address -- but nothing outside the daily-brief tree is touched by the
    consume step.
    """
    outside = tmp_path / "outside.json"
    outside.write_text("untouched", encoding="utf-8")

    response = client.post(
        "/api/decisions",
        json={
            "candidate": candidate_id,
            "action": "whitelist",
            "entry": {"email": "someone@elsewhere.example"},
        },
    )

    assert response.status_code in (200, 400, 422)
    if response.status_code == 200:
        assert response.json()["consumed"] is False
    assert outside.read_text(encoding="utf-8") == "untouched"


def test_unknown_keys_in_a_decision_are_refused(client, daily_brief_dir):
    stage_candidate(daily_brief_dir, "job-a")

    response = client.post(
        "/api/decisions",
        json={
            "candidate": f"{brief_dir_name(DAY)}/job-a",
            "action": "whitelist",
            "entry": {"email": UNKNOWN_SENDER, "known_structures": [{"name": "anything"}]},
        },
    )

    assert response.status_code == 422


# --- lists ---------------------------------------------------------------------


def test_list_endpoints_return_the_live_entries(client):
    greylist = client.get("/api/lists/greylist").json()

    assert greylist["count"] == 1
    entry = greylist["entries"][0]
    assert entry["key"] == "hsbc.example"
    assert entry["scope"] == "domain"
    assert entry["tags"] == ["bank"]
    assert [(s["name"], s["disposition"]) for s in entry["structures"]] == [
        ("payment alert", "allowed"),
        ("marketing blast", "denied"),
    ]

    whitelist = client.get("/api/lists/whitelist").json()
    assert [entry["key"] for entry in whitelist["entries"]] == ["julia@btinternet.example"]
    assert whitelist["entries"][0]["scope"] == "address"


def test_a_structure_with_no_disposition_reads_as_allowed(client, lists_dir):
    """The documented default, resolved server-side.

    Lists written before dispositions existed mean "catalogued, therefore
    fine"; the panel must show what the engine will do, not what the file
    happens to spell.
    """
    write_lists(
        lists_dir,
        greylist=[{"domain": "old.example", "known_structures": [{"name": "receipt"}]}],
    )

    entries = client.get("/api/lists/greylist").json()["entries"]

    assert entries[0]["structures"][0]["disposition"] == "allowed"


def test_an_unknown_list_is_a_404(client):
    assert client.get("/api/lists/pinklist").status_code == 404
    assert client.post("/api/lists/pinklist/add", json={"entry": {"domain": "x.example"}}).status_code == 404


def test_the_add_endpoint_applies_through_the_applier(client, lists_dir):
    response = client.post(
        "/api/lists/whitelist/add",
        json={"entry": {"email": "newsletter@daily.example", "tags": ["news"]}},
    )

    assert response.status_code == 200
    assert response.json()["report"]["reviewed"] == DAY.isoformat()
    added = [e for e in entries_of(lists_dir, "whitelist") if e["email"] == "newsletter@daily.example"]
    assert added[0]["tags"] == ["news"]
    # The applier's own shape, so a manual add is indistinguishable from a
    # reviewed one -- including the match-all structure.
    assert added[0]["known_structures"] == [{"name": "ALL EMAILS", "key_phrases": []}]


def test_a_manual_add_moves_a_domain_off_its_previous_list(client, lists_dir):
    response = client.post(
        "/api/lists/blacklist/add", json={"entry": {"domain": "hsbc.example"}}
    )

    assert response.status_code == 200
    assert entries_of(lists_dir, "greylist") == []
    assert "hsbc.example" in {entry.get("domain") for entry in entries_of(lists_dir, "blacklist")}


def test_an_invalid_manual_add_is_rejected_and_changes_nothing(client, lists_dir):
    before = snapshot(lists_dir)

    response = client.post("/api/lists/greylist/add", json={"entry": {"email": UNKNOWN_SENDER}})

    assert response.status_code == 400
    assert response.json()["errors"]
    assert snapshot(lists_dir) == before


def test_the_lists_the_engine_refuses_are_refused_here_too(client, lists_dir):
    """One domain on two lists: the scanner will not load it, so neither will this.

    Written past the applier on purpose -- it maintains the invariant, so the
    only way into this state is a hand-edit, which is exactly the case a
    reviewer needs told about rather than shown a half-true screen.
    """
    write_lists(
        lists_dir,
        greylist=[{"domain": "both.example"}],
        blacklist=[{"domain": "both.example"}],
    )

    response = client.get("/api/lists/greylist")

    assert response.status_code == 503
    assert response.json()["errors"]


def test_a_reviewed_decision_is_visible_to_the_scanner(client, lists_dir, daily_brief_dir):
    """The loop actually closes: what the console wrote, the engine now loads."""
    stage_candidate(daily_brief_dir, "job-a")

    client.post(
        "/api/decisions",
        json={
            "candidate": f"{brief_dir_name(DAY)}/job-a",
            "action": "greylist",
            "entry": {"domain": UNKNOWN_DOMAIN},
            "structure": {"name": "flash sale", "key_phrases": ["FLASH SALE"], "disposition": "denied"},
        },
    )

    lists = Lists.load(lists_dir)
    entry = lists.find("greylist", UNKNOWN_SENDER, UNKNOWN_DOMAIN)
    assert entry is not None
    assert entry["known_structures"][0]["disposition"] == "denied"


# --- serving -------------------------------------------------------------------


@pytest.mark.parametrize("path", ["/", "/api/candidates", "/static/app.js", "/api/lists/pinklist"])
def test_the_csp_is_on_every_response(client, path):
    """Including the 404 -- a middleware, so no handler can forget it."""
    response = client.get(path)

    policy = response.headers["content-security-policy"]
    assert "default-src 'none'" in policy
    assert "script-src 'self'" in policy
    assert "frame-ancestors 'none'" in policy
    assert response.headers["x-content-type-options"] == "nosniff"


def test_frame_ancestors_is_the_one_knob(tmp_path, lists_dir, daily_brief_dir):
    """The side-panel host gets embedded later by widening exactly one directive."""
    config = WebUIConfig(
        lists_dir=lists_dir,
        daily_brief_dir=daily_brief_dir,
        outbound_dir=tmp_path / "outbound",
        frame_ancestors="https://panel.local",
    )

    policy = TestClient(create_app(config)).get("/").headers["content-security-policy"]

    assert "frame-ancestors https://panel.local" in policy
    assert policy.replace("https://panel.local", "'none'") == content_security_policy()


def test_the_console_and_its_assets_are_served(client):
    page = client.get("/")
    assert page.status_code == 200
    assert page.headers["content-type"].startswith("text/html")

    # The CSP forbids inline script, so the page must contain none: no <script>
    # without a src, and no `on*=` handler attribute, which is inline script
    # wearing a different hat. Comments are stripped first -- the file explains
    # the rule in prose, and prose is not a handler.
    markup = re.sub(r"<!--.*?-->", "", page.text, flags=re.DOTALL)
    assert "<script src=" in markup
    assert re.search(r"<script(?![^>]*\ssrc=)", markup) is None
    assert re.search(r"\son[a-z]+\s*=", markup) is None

    script = client.get("/static/app.js")
    assert script.status_code == 200
    assert "addEventListener" in script.text
    assert client.get("/static/app.css").status_code == 200


def test_api_responses_are_never_cached(client):
    assert client.get("/api/candidates").headers["cache-control"] == "no-store"


# --- authentication ------------------------------------------------------------


def test_auth_is_off_by_default(client):
    assert client.get("/api/candidates").status_code == 200


def test_a_configured_token_guards_every_api_route(tmp_path, lists_dir, daily_brief_dir):
    config = WebUIConfig(
        lists_dir=lists_dir,
        daily_brief_dir=daily_brief_dir,
        outbound_dir=tmp_path / "outbound",
        auth_token="s3cret",
    )
    guarded = TestClient(create_app(config, today=lambda: DAY))

    assert guarded.get("/api/candidates").status_code == 401
    assert guarded.get("/api/lists/greylist").status_code == 401
    assert guarded.get("/api/candidates", headers={AUTH_HEADER: "wrong"}).status_code == 401
    assert guarded.post(
        "/api/lists/whitelist/add", json={"entry": {"email": "a@b.example"}}
    ).status_code == 401
    assert entries_of(lists_dir, "whitelist") == [
        {"email": "julia@btinternet.example", "tags": ["family"]}
    ]

    assert guarded.get("/api/candidates", headers={AUTH_HEADER: "s3cret"}).status_code == 200
    # The shell carries no data, and a browser cannot put a header on a
    # navigation -- so it stays reachable while every data route does not.
    assert guarded.get("/").status_code == 200


def test_a_rejected_request_still_carries_the_csp(tmp_path, lists_dir, daily_brief_dir):
    config = WebUIConfig(
        lists_dir=lists_dir,
        daily_brief_dir=daily_brief_dir,
        outbound_dir=tmp_path / "outbound",
        auth_token="s3cret",
    )
    response = TestClient(create_app(config)).get("/api/candidates")

    assert response.status_code == 401
    assert "default-src 'none'" in response.headers["content-security-policy"]
