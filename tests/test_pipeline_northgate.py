"""End-to-end pipeline runs against the synthetic Northgate Bank fixtures.

Every fixture here is invented -- reserved ``.example`` domains, ``example.com``
recipients, TEST-NET IPs. They are shaped like forwarded bank notifications so
they exercise the same paths a real deployment hits: Outlook pipe detection,
DKIM alignment, greylist subdomain matching, and link analysis.

Expected levels are re-derived from the FIXED behaviour of both false-positive
bugs (visual obfuscation on typography, link rules blinded by de-fanging), not
carried over from the pre-fix expectations.
"""

from __future__ import annotations

VERDICT_KEYS = {
    "message_id",
    "source_pipe",
    "sender",
    "friendly_name",
    "initial_level",
    "final_level",
    "bucket",
    "list_hits",
    "greylist_classification",
    "forensic_log",
    "links",
    "attachments",
    "canary",
    "proposed_action",
    "proposal",
}


def test_subdomain_sender_is_recognised_but_structurally_new(scan):
    """Domain recognised (greylist hit via subdomain), message shape not.

    Level reasoning: triage lands on 3 (greylisted domain, no matching
    structure). The level-3 deep dive now scores a perfect profile -- the links
    are on ``www.northgate-bank.example`` and ALIGN with the
    ``notify.northgate-bank.example`` sender, so ``content-links`` passes
    instead of returning ``fail_critical``. That promotes to level 4, where the
    sender rule fails (Northgate is not one of the three major consumer
    providers) and the corrected level-4 assessment downgrades to 3 for review.
    """
    verdict = scan("json/northgate_1.json")

    assert verdict["sender"] == "notifications@notify.northgate-bank.example"
    assert verdict["list_hits"]["greylist"] is True
    assert verdict["greylist_classification"] == "new_structure"
    assert verdict["proposal"]["classification"] == "new_structure"
    assert verdict["source_pipe"] == "OUTLOOK"

    assert verdict["initial_level"] == 3
    assert verdict["final_level"] == 3
    assert verdict["bucket"] == "flagged"

    # The link fix at work: no critical link marker, so no escalation to 2.
    log = " | ".join(verdict["forensic_log"])
    assert "Critical markers found" not in log
    assert "Downgrading to Level 4" in log

    # Links still reach the verdict de-fanged and unclickable.
    assert verdict["links"]
    assert all("h_ttp" in link and "[.]" in link for link in verdict["links"])
    assert not any(link.startswith("http") for link in verdict["links"])


def test_curly_apostrophe_subject_is_no_longer_obfuscation(scan):
    """Regression for fix 1: ordinary typography must not trigger level 1.

    This subject carries U+2019. The ported character set omitted General
    Punctuation, so the apostrophe read as homoglyph obfuscation, triage
    returned level 1, and a routine bank notification was rejected outright.
    With punctuation allowed it triages normally as a greylisted domain with an
    uncatalogued structure, and settles at 3 like its sibling fixture.
    """
    verdict = scan("json/northgate_2.json")

    assert "’" in "We’ve added a payee"

    assert verdict["sender"] == "payments@pay.northgate-bank.example"
    assert verdict["list_hits"]["greylist"] is True
    assert verdict["greylist_classification"] == "new_structure"

    assert verdict["initial_level"] != 1
    assert verdict["final_level"] != 1
    assert verdict["bucket"] != "rejected"

    assert verdict["initial_level"] == 3
    assert verdict["final_level"] == 3
    assert verdict["bucket"] == "flagged"

    # No deep scan runs for a terminal level, so reaching level 4 proves triage
    # let the message through.
    assert any("level4" in line for line in verdict["forensic_log"])


def test_exact_domain_and_subdomain_senders_both_match_the_greylist(scan):
    """northgate_1 hits via subdomain, northgate_2 via the exact domain."""
    subdomain = scan("json/northgate_1.json")
    exact = scan("json/northgate_2.json")

    assert subdomain["sender"].endswith("@notify.northgate-bank.example")
    assert exact["sender"].endswith("@pay.northgate-bank.example")
    assert subdomain["list_hits"]["greylist"] is True
    assert exact["list_hits"]["greylist"] is True


def test_off_domain_links_escalate_the_message(scan):
    """Regression for fix 2: link misalignment is real signal again.

    Same sender domain and headers as northgate_1, but every link points at an
    unrelated host. Before the fix both fixtures looked identical to the rules
    (all links failed alignment because they were compared as de-fanged
    strings). Now the level-3 assessment sees a critical marker on this one and
    only this one, and escalates to level 2.
    """
    verdict = scan("json/northgate_spoof.json")

    assert verdict["links"] == ["h_ttps://northgate-verify[.]example/account/"]
    assert verdict["initial_level"] == 3
    assert verdict["final_level"] == 2
    assert verdict["bucket"] == "flagged"
    assert any("Critical markers found" in line for line in verdict["forensic_log"])


def test_legitimate_and_spoofed_messages_now_diverge(scan):
    """The two fixtures differ only in link host, and now reach different levels."""
    legitimate = scan("json/northgate_1.json")
    spoofed = scan("json/northgate_spoof.json")

    assert legitimate["sender"] == spoofed["sender"]
    assert legitimate["final_level"] != spoofed["final_level"]


def test_verdict_shape_is_complete(scan):
    verdict = scan("json/northgate_1.json")
    assert set(verdict) == VERDICT_KEYS
    assert set(verdict["list_hits"]) == {"whitelist", "greylist", "blacklist"}
    assert verdict["proposed_action"] is None


def test_canary_is_stubbed_and_gated_to_high_threat_levels(scan):
    """The Canary runs for levels 1-2 only, and reports itself unavailable."""
    high = scan("json/northgate_spoof.json")
    assert high["final_level"] == 2
    assert high["canary"] == {
        "injection": None,
        "phishing": None,
        "reason": "not evaluated",
        "available": False,
    }

    lower = scan("json/northgate_1.json")
    assert lower["final_level"] == 3
    assert lower["canary"]["available"] is False
    assert lower["canary"]["reason"] == "not applicable at this level"


def test_scan_is_deterministic(scan):
    assert scan("json/northgate_1.json") == scan("json/northgate_1.json")
