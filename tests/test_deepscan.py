"""The declarative rule engine, scan-point decomposition, and the ported funcs."""

from __future__ import annotations

import pytest

from email_guard import parse
from email_guard.clean import clean
from email_guard.deepscan import GROUPS, STATUSES, apply_rule, decompose, scan
from email_guard.rulespack import RulesPack


@pytest.fixture
def message(lists):
    raw = (
        b"From: sender@example.com\r\n"
        b"Subject: Notes\r\n"
        b"Content-Type: text/plain\r\n"
        b"\r\n"
        b"body\r\n"
    )
    return clean(parse.parse_eml(raw), lists)


# --- decomposition -------------------------------------------------------------


def test_decomposition_covers_every_part_of_the_normalised_message(message):
    points = {point for point, _group, _key, _value in decompose(message)}

    assert "core-original_sender" in points
    assert "core-title" in points
    assert "core-clean_text" in points
    assert "core-attachments" in points
    assert "core-links" in points

    for section in ("authenticity", "origin", "path", "technical", "behavioural"):
        assert any(point.startswith(f"metadata-{section}-") for point in points)

    assert "metadata-authenticity-dkim" in points
    assert "integrity-dkim_verified" in points
    assert "integrity-source_pipe" in points
    assert "content-links" in points
    assert "content-text" in points


def test_every_scan_point_has_a_rule_at_every_level(message, pack: RulesPack):
    """Rules pack and normalised shape must not drift apart."""
    points = {point for point, _g, _k, _v in decompose(message)}

    for level in (2, 3, 4):
        covered = {rule["field"] for rule in pack.rules_for(level)}
        missing = points - covered
        assert not missing, f"level{level}.json has no rule for: {sorted(missing)}"


def test_no_rule_targets_a_scan_point_that_does_not_exist(message, pack: RulesPack):
    points = {point for point, _g, _k, _v in decompose(message)}

    for level in (2, 3, 4):
        declared = {rule["field"] for rule in pack.rules_for(level)}
        assert not declared - points, f"level{level}.json targets unknown points"


def test_scan_groups_results_the_way_the_assessors_read_them(message, pack: RulesPack):
    block = scan(message, 2, pack, {"report": {}})

    assert set(block) == set(GROUPS)
    # The assessors index metadata by "<section>-<key>", core by bare field name.
    assert "authenticity-dkim" in block["metadata"]
    assert "title" in block["core"]
    assert "dkim_verified" in block["integrity"]
    assert "links" in block["content"]
    for group in GROUPS:
        assert all(status in STATUSES for status in block[group].values())


def test_unmatched_scan_point_is_unknown(message):
    class BarePack:
        def rules_for(self, level):
            return []

    block = scan(message, 2, BarePack(), {})
    assert block["core"]["title"] == "unknown"


# --- declarative rule types ----------------------------------------------------


def apply(rule, value, message=None, context=None):
    return apply_rule(rule, value, message or {}, context if context is not None else {}, None)


def test_ignore_type():
    assert apply({"field": "core-title", "type": "ignore"}, "anything") == "ignore"


@pytest.mark.parametrize(
    "value,expected",
    [("please verify now", "fail_pass"), ("nothing to see", "pass")],
)
def test_regex_any(value, expected):
    rule = {
        "field": "core-clean_text",
        "type": "regex_any",
        "patterns": ["verify", "login"],
        "result_if_match": "fail_pass",
        "result_if_no_match": "pass",
    }
    assert apply(rule, value) == expected


def test_regex_is_case_insensitive_by_default():
    rule = {
        "field": "core-title",
        "type": "regex_any",
        "patterns": ["urgent"],
        "result_if_match": "fail_pass",
        "result_if_no_match": "pass",
    }
    assert apply(rule, "URGENT action") == "fail_pass"


def test_regex_case_sensitivity_can_be_demanded():
    rule = {
        "field": "metadata-behavioural-mailer",
        "type": "regex_any",
        "patterns": ["^SER-[a-f0-9]+"],
        "ignore_case": False,
        "result_if_match": "pass_service",
        "result_if_no_match": "fail_spam",
    }
    assert apply(rule, "SER-3b2d5ad1") == "pass_service"
    assert apply(rule, "ser-3b2d5ad1") == "fail_spam"


def test_regex_all_requires_every_pattern():
    rule = {
        "field": "core-clean_text",
        "type": "regex_all",
        "patterns": ["alpha", "beta"],
        "result_if_match": "pass_service",
        "result_if_no_match": "pass",
    }
    assert apply(rule, "alpha and beta") == "pass_service"
    assert apply(rule, "alpha only") == "pass"


def test_regex_matches_across_a_list_value():
    rule = {
        "field": "content-links",
        "type": "regex_any",
        "patterns": ["bit\\.ly"],
        "result_if_match": "fail",
        "result_if_no_match": "pass",
    }
    assert apply(rule, ["https://ok.example.com", "https://bit.ly/x"]) == "fail"
    assert apply(rule, ["https://ok.example.com"]) == "pass"


def test_equals_on_strings_and_booleans():
    string_rule = {
        "field": "metadata-authenticity-dkim",
        "type": "equals",
        "value": "pass",
        "result_if_match": "pass_downgrade",
        "result_if_no_match": "fail_pass",
    }
    assert apply(string_rule, "pass") == "pass_downgrade"
    assert apply(string_rule, "none") == "fail_pass"

    bool_rule = {
        "field": "integrity-dkim_verified",
        "type": "equals",
        "value": True,
        "result_if_match": "pass",
        "result_if_no_match": "fail_pass",
    }
    assert apply(bool_rule, True) == "pass"
    assert apply(bool_rule, False) == "fail_pass"
    # 1 must not be mistaken for True.
    assert apply(bool_rule, 1) == "fail_pass"


def test_equals_can_ignore_case():
    rule = {
        "field": "metadata-origin-sid_result",
        "type": "equals",
        "value": "pass",
        "ignore_case": True,
        "result_if_match": "pass_downgrade",
        "result_if_no_match": "fail_pass",
    }
    assert apply(rule, "PASS") == "pass_downgrade"


def test_in_type():
    rule = {
        "field": "metadata-technical-encoding",
        "type": "in",
        "values": ["7bit", "8bit"],
        "result_if_match": "pass",
        "result_if_no_match": "fail_spam",
    }
    assert apply(rule, "7bit") == "pass"
    assert apply(rule, "base64") == "fail_spam"


def test_is_false_type():
    rule = {
        "field": "metadata-technical-is_multipart",
        "type": "is_false",
        "result_if_match": "fail_pass",
        "result_if_no_match": "pass",
    }
    assert apply(rule, False) == "fail_pass"
    assert apply(rule, True) == "pass"


def test_non_empty_type():
    rule = {
        "field": "core-attachments",
        "type": "non_empty",
        "result_if_match": "fail_critical",
        "result_if_no_match": "pass",
    }
    assert apply(rule, [{"filename": "x.pdf"}]) == "fail_critical"
    assert apply(rule, []) == "pass"


def test_unknown_rule_type_raises():
    with pytest.raises(ValueError):
        apply({"field": "core-title", "type": "nonsense"}, "x")


# --- ported rule functions -----------------------------------------------------


def test_level2_return_path_alignment(pack):
    func = pack.resolve_func("level2_funcs.return_path_alignment")
    context = {"senderDomain": "northgate-bank.example"}

    assert func("<owner+SRS=y=DM=northgate-bank.example=z@example.net>", {}, context) == "pass"
    # Misalignment is a weak, supporting signal -- never grounds to reject on
    # its own, since every message here is forwarded and the envelope belongs
    # to the forwarder.
    assert func("<attacker@evil.example>", {}, context) == "fail_pass"
    # No sender domain to compare against -- the prototype passes.
    assert func("<anything>", {}, {"senderDomain": ""}) == "pass"


def test_level2_header_count_band(pack):
    func = pack.resolve_func("level2_funcs.header_count_band")
    assert func(10, {}, {}) == "fail_pass"
    assert func(20, {}, {}) == "pass"
    assert func(40, {}, {}) == "pass_downgrade"


def test_level3_dkim_domain_alignment(pack):
    func = pack.resolve_func("level3_funcs.dkim_domain_alignment")
    context = {
        "report": {
            "messageContent": {
                "metadata": {"path": {"return_path": "<owner+SRS=b=DM=northgate-bank.example=c@example.net>"}}
            }
        }
    }
    auth = "dkim=pass (Good signature) header.d=northgate-bank.example header.a=rsa-sha256"
    assert func(auth, {}, context) == "pass_service"

    misaligned = "dkim=pass header.d=evil.example"
    assert func(misaligned, {}, context) == "fail_critical"


def test_level3_hop_count_with_srs(pack):
    func = pack.resolve_func("level3_funcs.hop_count_with_srs")
    plain = {"report": {"messageContent": {"metadata": {"path": {"return_path": "<a@plain.example>"}}}}}
    forwarded = {
        "report": {
            "messageContent": {"metadata": {"path": {"return_path": "<owner+SRS=x=DM=orig.example=c@example.net>"}}}
        }
    }
    assert func(9, {}, plain) == "fail_critical"
    assert func(9, {}, forwarded) == "pass"
    assert func(2, {}, plain) == "pass"


def test_level4_sender_on_trusted_list(pack):
    """Fix A: level 4 confirms list membership, not a hardcoded provider list."""
    func = pack.resolve_func("level4_funcs.sender_on_trusted_list")
    sender = "payments@pay.northgate-bank.example"

    # Greylist-recognised (triage rule 4) and whitelisted (rule 7) both pass...
    assert func(sender, {"greylist_hit": True, "whitelist_hit": False}, {}) == "pass"
    assert func(sender, {"greylist_hit": False, "whitelist_hit": True}, {}) == "pass"
    assert func(sender, {"greylist_hit": True, "whitelist_hit": True}, {}) == "pass"

    # ...and an off-list sender that somehow reached level 4 does not.
    assert func(sender, {"greylist_hit": False, "whitelist_hit": False}, {}) == "fail"
    assert func(sender, {}, {}) == "fail"

    # The sender string itself is no longer what decides the outcome: a major
    # consumer provider with no list hit still fails.
    assert func("someone@gmail.com", {}, {}) == "fail"


def test_level4_major_provider_rule_is_gone(pack):
    """The replaced rule must not linger in the pack."""
    import pytest as _pytest

    from email_guard.rulespack import InvalidRulesPack

    with _pytest.raises(InvalidRulesPack):
        pack.resolve_func("level4_funcs.major_provider_sender")


# --- fix B: SRS-aware return-path alignment ------------------------------------


def test_level2_return_path_is_srs_aware(pack):
    """Fix B: a forwarded return path embeds the original domain -- accept it.

    All inbound mail is SRS-forwarded, so the envelope return path belongs to
    the forwarder. The old plain substring test failed for every forwarded
    message and returned ``fail_critical``.
    """
    func = pack.resolve_func("level2_funcs.return_path_alignment")
    context = {"senderDomain": "pay.northgate-bank.example"}

    # SRS embeds the parent domain while the sender is a subdomain.
    srs = "<owner+SRS=7AqCh=DM=northgate-bank.example=payments@example.net>"
    assert func(srs, {}, dict(context)) == "pass"

    # SRS naming a different organisation entirely is still a signal -- but a
    # contributing one, not a verdict.
    wrong = "<owner+SRS=x=DM=evil.example=a@example.net>"
    assert func(wrong, {}, dict(context)) == "fail_pass"


def test_level2_return_path_non_srs_behaviour_is_unchanged(pack):
    """Without an SRS token nothing was rewritten, so the direct check stands."""
    func = pack.resolve_func("level2_funcs.return_path_alignment")
    context = {"senderDomain": "pay.northgate-bank.example"}

    assert func("<payments@pay.northgate-bank.example>", {}, dict(context)) == "pass"
    assert func("<attacker@evil.example>", {}, dict(context)) == "fail_pass"
    # No sender domain to compare against -- the prototype passes.
    assert func("<anything>", {}, {"senderDomain": ""}) == "pass"


def test_link_rules_see_real_hosts_through_the_defanging(pack):
    """Regression for fix 2: de-fanged links no longer blind the link rules.

    Links reach the rules as ``h_ttps://www[.]example[.]test/x``. The rules
    re-fang internally, so alignment and shortener checks compare real hosts,
    while the de-fanged form remains the only thing ever emitted.
    """
    level2 = pack.resolve_func("level2_funcs.links_aligned_with_sender")
    level3 = pack.resolve_func("level3_funcs.links_aligned_with_sender")
    level4 = pack.resolve_func("level4_funcs.shortener_links")

    on_domain = ["h_ttps://www[.]northgate-bank[.]example/privacy"]
    context = {"senderDomain": "notify.northgate-bank.example"}

    # Subdomain-aware in both directions: www.<bank> aligns with notify.<bank>.
    assert level2(on_domain, {}, dict(context)) == "pass_downgrade"
    assert level3(on_domain, {}, dict(context)) == "pass_service"
    assert level4(on_domain, {}, {}) == "pass"

    # The same links un-defanged behave identically -- refang is idempotent here.
    plain = ["https://www.northgate-bank.example/privacy"]
    assert level2(plain, {}, dict(context)) == "pass_downgrade"
    assert level3(plain, {}, dict(context)) == "pass_service"


def test_off_domain_link_fails_alignment(pack):
    level2 = pack.resolve_func("level2_funcs.links_aligned_with_sender")
    level3 = pack.resolve_func("level3_funcs.links_aligned_with_sender")
    context = {"senderDomain": "notify.northgate-bank.example"}

    mixed = [
        "h_ttps://www[.]northgate-bank[.]example/ok",
        "h_ttps://northgate-verify[.]example/account",
    ]
    assert level2(mixed, {}, dict(context)) == "fail_pass"
    assert level3(mixed, {}, dict(context)) == "fail_critical"

    # A lookalike that merely contains the name must not align either.
    lookalike = ["h_ttps://northgate-bank[.]example[.]evil[.]example/x"]
    assert level2(lookalike, {}, dict(context)) == "fail_pass"
    assert level3(lookalike, {}, dict(context)) == "fail_critical"


def test_no_links_passes_every_link_rule(pack):
    context = {"senderDomain": "notify.northgate-bank.example"}
    assert pack.resolve_func("level2_funcs.links_aligned_with_sender")([], {}, dict(context)) == "pass"
    assert pack.resolve_func("level3_funcs.links_aligned_with_sender")([], {}, dict(context)) == "pass"
    assert pack.resolve_func("level4_funcs.shortener_links")([], {}, {}) == "pass"


@pytest.mark.parametrize(
    "link",
    [
        "h_ttps://bit[.]ly/abc123",
        "h_ttps://t[.]co/abc123",
        "h_ttps://tinyurl[.]com/abc123",
        "h_ttp://myhost[.]duckdns[.]org/x",
    ],
)
def test_level4_flags_shortened_links(pack, link):
    """Regression for fix 2: the shortener check can actually fire now."""
    assert pack.resolve_func("level4_funcs.shortener_links")([link], {}, {}) == "fail"


def test_level4_does_not_flag_ordinary_links(pack):
    func = pack.resolve_func("level4_funcs.shortener_links")
    assert func(["h_ttps://www[.]northgate-bank[.]example/x"], {}, {}) == "pass"
    assert func(["h_ttps://bitly-lookalike[.]example/x"], {}, {}) == "pass"


# --- link helpers --------------------------------------------------------------


@pytest.mark.parametrize(
    "url,host",
    [
        ("h_ttps://www[.]northgate-bank[.]example/a/b", "www.northgate-bank.example"),
        ("https://www.northgate-bank.example/a/b", "www.northgate-bank.example"),
        ("h_ttps://user:pw@host[.]example:8443/x", "host.example"),
        ("not a url at all", ""),
    ],
)
def test_link_host_extraction(url, host):
    from email_guard.links import link_host

    assert link_host(url) == host


@pytest.mark.parametrize(
    "host,registrable",
    [
        ("www.northgate-bank.example", "northgate-bank.example"),
        ("northgate-bank.example", "northgate-bank.example"),
        ("a.b.c.example", "c.example"),
        ("mail.example.com.hk", "example.com.hk"),
        ("shop.example.co.uk", "example.co.uk"),
        ("", ""),
    ],
)
def test_registrable_domain(host, registrable):
    from email_guard.links import registrable_domain

    assert registrable_domain(host) == registrable


def test_defang_refang_round_trip():
    from email_guard.links import defang, refang

    url = "https://www.northgate-bank.example/a.b?x=1"
    assert refang(defang(url)) == url
    assert "http" not in defang(url)
