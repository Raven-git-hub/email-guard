"""List matching: greylist classification, match-all, whitelist/blacklist, dedupe.

Covers the two list-related entries in the root README's "Known issues":
greylist schema drift (match against ``known_structures``, not the old
``pass``/``block`` shape) and ``"ALL EMAILS"`` / empty ``key_phrases`` being
treated as match-all.
"""

from __future__ import annotations

import json

import pytest

from email_guard.lists import (
    GREYLIST_DENIED,
    GREYLIST_KNOWN,
    GREYLIST_NEW_STRUCTURE,
    GREYLIST_NONE,
    InvalidLists,
    Lists,
    classify_greylist,
    dedupe,
    disposition,
    entry_matches,
    matched_structure,
    structure_matches,
    tags_of,
    validate_lists,
)
from tests.conftest import CONFLICT_LIST_FIXTURES


# --- match-all -----------------------------------------------------------------


def test_empty_key_phrases_matches_everything():
    structure = {"name": "Anything At All", "key_phrases": []}
    assert structure_matches(structure, "any subject", "any body") is True


def test_all_emails_name_matches_everything_even_with_phrases():
    structure = {"name": "ALL EMAILS", "key_phrases": ["a phrase that is absent"]}
    assert structure_matches(structure, "unrelated", "unrelated") is True


def test_missing_key_phrases_key_matches_everything():
    assert structure_matches({"name": "No Phrases Key"}, "s", "b") is True


@pytest.mark.parametrize("domain", ["shopfast.example", "mailings.example"])
def test_match_all_domains_classify_as_known(lists: Lists, domain: str):
    classification, _entry, structure = classify_greylist(
        lists.greylist, f"anyone@{domain}", domain, "any subject", "any body"
    )
    assert classification == GREYLIST_KNOWN
    assert structure is not None


# --- phrase matching -----------------------------------------------------------


def test_subject_phrase_checked_against_subject_only():
    structure = {"name": "S", "key_phrases": ["Subject: Your statement is ready"]}
    assert structure_matches(structure, "Your statement is ready", "unrelated body") is True
    assert structure_matches(structure, "unrelated subject", "Your statement is ready") is False


def test_body_phrase_checked_against_body_only():
    structure = {"name": "B", "key_phrases": ["your monthly statement is now available"]}
    assert structure_matches(structure, "s", "Your Monthly Statement Is Now Available.") is True
    assert structure_matches(structure, "your monthly statement is now available", "b") is False


def test_matching_is_case_insensitive():
    structure = {"name": "S", "key_phrases": ["Subject: Your Statement Is Ready"]}
    assert structure_matches(structure, "YOUR STATEMENT IS READY", "") is True


def test_any_single_phrase_is_enough():
    structure = {"name": "S", "key_phrases": ["absent one", "present one", "absent two"]}
    assert structure_matches(structure, "s", "contains the present one here") is True


# --- classification outcomes ---------------------------------------------------


def test_known_when_a_structure_matches(lists: Lists):
    classification, entry, structure = classify_greylist(
        lists.greylist,
        "alerts@northgate-bank.example",
        "northgate-bank.example",
        "Your statement is ready",
        "body text",
    )
    assert classification == GREYLIST_KNOWN
    assert entry["domain"] == "northgate-bank.example"
    assert structure["name"] == "Northgate Statement Ready"


def test_new_structure_when_domain_listed_but_nothing_matches(lists: Lists):
    classification, entry, structure = classify_greylist(
        lists.greylist,
        "alerts@northgate-bank.example",
        "northgate-bank.example",
        "Something else entirely",
        "unrelated body",
    )
    assert classification == GREYLIST_NEW_STRUCTURE
    assert entry is not None
    assert structure is None


def test_new_structure_when_domain_has_no_structures_at_all(lists: Lists):
    """An empty ``known_structures`` list is not the same as a match-all structure."""
    classification, _entry, _structure = classify_greylist(
        lists.greylist,
        "hello@oldforum.example",
        "oldforum.example",
        "anything",
        "anything",
    )
    assert classification == GREYLIST_NEW_STRUCTURE


def test_none_when_domain_absent(lists: Lists):
    classification, entry, structure = classify_greylist(
        lists.greylist, "someone@nowhere.example", "nowhere.example", "s", "b"
    )
    assert classification == GREYLIST_NONE
    assert entry is None
    assert structure is None


# --- subdomain matching --------------------------------------------------------


def test_subdomain_matches_parent_domain_entry(lists: Lists):
    classification, entry, _structure = classify_greylist(
        lists.greylist, "notifications@notify.northgate-bank.example", "notify.northgate-bank.example", "s", "b"
    )
    assert classification == GREYLIST_NEW_STRUCTURE
    assert entry["domain"] == "northgate-bank.example"


def test_lookalike_domain_does_not_match():
    """``notnorthgate-bank.example`` must not match ``northgate-bank.example`` -- only a dotted boundary counts."""
    entry = {"domain": "northgate-bank.example"}
    assert entry_matches(entry, "a@notify.northgate-bank.example", "notify.northgate-bank.example") is True
    assert entry_matches(entry, "a@northgate-bank.example", "northgate-bank.example") is True
    assert entry_matches(entry, "a@notnorthgate-bank.example", "notnorthgate-bank.example") is False
    assert entry_matches(entry, "a@northgate-bank.example.evil.example", "northgate-bank.example.evil.example") is False


# --- whitelist / blacklist -----------------------------------------------------


def test_whitelist_hit_by_email(lists: Lists):
    assert lists.find("whitelist", "friend@example.org", "example.com") is not None
    assert lists.find("whitelist", "stranger@example.org", "example.com") is None


def test_blacklist_hit_by_email(lists: Lists):
    entry = lists.find("blacklist", "scam@phisher.example", "phisher.example")
    assert entry is not None
    assert entry["friendly_name"] == "Bad Actor"


# --- data hygiene --------------------------------------------------------------


def test_duplicate_entries_are_deduped_on_load(lists: Lists):
    """The live blacklist ships a vendor address twice; dedupe on load."""
    emails = [entry["email"] for entry in lists.blacklist]
    assert emails.count("noreply@spammy.example") == 1
    assert len(emails) == len(set(emails))


def test_dedupe_keeps_first_occurrence():
    entries = [
        {"email": "a@example.com", "friendly_name": "first"},
        {"email": "a@example.com", "friendly_name": "second"},
        {"email": "b@example.com"},
    ]
    result = dedupe(entries)
    assert len(result) == 2
    assert result[0]["friendly_name"] == "first"


# --- loading -------------------------------------------------------------------


def test_missing_list_files_yield_empty_lists(tmp_path):
    """A clean clone with no live lists must still run."""
    loaded = Lists.load(tmp_path)
    assert loaded.whitelist == [] and loaded.greylist == [] and loaded.blacklist == []


def test_shipped_sample_lists_are_schema_valid(tmp_path):
    """The committed *.sample.json templates load through the real loader."""
    from tests.conftest import PROJECT_ROOT

    for name in ("whitelist", "greylist", "blacklist"):
        source = PROJECT_ROOT / "data" / "lists" / f"{name}.sample.json"
        (tmp_path / f"{name}.json").write_text(
            source.read_text(encoding="utf-8"), encoding="utf-8"
        )

    loaded = Lists.load(tmp_path)
    assert loaded.whitelist and loaded.greylist and loaded.blacklist
    for entry in loaded.whitelist + loaded.blacklist:
        assert "email" in entry
    for entry in loaded.greylist:
        assert "domain" in entry
        assert isinstance(entry.get("known_structures"), list)


def test_list_file_may_be_a_bare_array(tmp_path):
    (tmp_path / "greylist.json").write_text(
        json.dumps([{"domain": "x.example", "known_structures": []}]), encoding="utf-8"
    )
    assert Lists.load(tmp_path).greylist[0]["domain"] == "x.example"


# --- disposition ---------------------------------------------------------------


def test_a_structure_with_no_disposition_is_allowed():
    """Dispositions arrived after the schema shipped; older lists still mean pass."""
    assert disposition({"name": "S", "key_phrases": []}) == "allowed"
    assert disposition({"name": "S", "disposition": "allowed"}) == "allowed"
    assert disposition({"name": "S", "disposition": " DENIED "}) == "denied"


def test_an_unreadable_disposition_fails_closed():
    """A typo must not buy trust. ``validate_lists`` surfaces it separately."""
    assert disposition({"name": "S", "disposition": "denyed"}) == "denied"
    assert validate_lists(
        [], [{"domain": "x.example", "known_structures": [{"name": "S", "disposition": "denyed"}]}], []
    ) != []


def test_a_denied_structure_classifies_as_denied(lists: Lists):
    classification, entry, structure = classify_greylist(
        lists.greylist,
        "noreply@mixedsignals.example",
        "mixedsignals.example",
        "Reset your password",
        "body",
    )
    assert classification == GREYLIST_DENIED
    assert entry["domain"] == "mixedsignals.example"
    assert structure["name"] == "Password Reset Bait"


def test_denied_wins_over_an_allowed_match_on_the_same_entry(lists: Lists):
    """``mixedsignals.example`` carries a match-all AND a denied structure.

    The match-all is listed first, so a first-match-wins scan would clear the
    very shape the reviewer catalogued in order to reject it.
    """
    classification, _entry, structure = classify_greylist(
        lists.greylist,
        "noreply@mixedsignals.example",
        "mixedsignals.example",
        "Reset your password",
        "body",
    )
    assert classification == GREYLIST_DENIED
    assert structure["disposition"] == "denied"


def test_an_unmatched_shape_on_that_domain_is_still_allowed(lists: Lists):
    """Denied is per shape, not per domain: the match-all still clears the rest."""
    classification, _entry, structure = classify_greylist(
        lists.greylist, "noreply@mixedsignals.example", "mixedsignals.example", "Weekly digest", "body"
    )
    assert classification == GREYLIST_KNOWN
    assert structure["name"] == "ALL EMAILS"


def test_denied_wins_across_two_entries_covering_one_sender():
    """A parent entry and a subdomain entry can both cover a sender.

    Stopping at the first covering entry would let a denied shape hide behind
    whichever entry happens to be listed first.
    """
    greylist = [
        {"domain": "bank.example", "known_structures": [{"name": "ALL EMAILS", "key_phrases": []}]},
        {
            "domain": "notify.bank.example",
            "known_structures": [
                {"name": "Bait", "key_phrases": ["Subject: reset"], "disposition": "denied"}
            ],
        },
    ]
    classification, _entry, structure = classify_greylist(
        greylist, "a@notify.bank.example", "notify.bank.example", "Please reset now", "body"
    )
    assert classification == GREYLIST_DENIED
    assert structure["name"] == "Bait"


def test_matched_structure_still_returns_the_first_match():
    """The original helper keeps its contract for callers that only want one."""
    entry = {"known_structures": [{"name": "A", "key_phrases": []}, {"name": "B", "key_phrases": []}]}
    assert matched_structure(entry, "s", "b")["name"] == "A"


# --- tags ----------------------------------------------------------------------


def test_tags_are_carried_on_the_matched_structure(lists: Lists):
    _classification, _entry, structure = classify_greylist(
        lists.greylist, "receipts@quietservice.example", "quietservice.example", "Your receipt", "b"
    )
    assert tags_of(structure) == ["receipt"]


def test_tags_normalise_to_clean_unique_strings():
    assert tags_of({"tags": [" work ", "work", "", 7, "notes"]}) == ["work", "notes"]
    assert tags_of({}) == []
    assert tags_of(None) == []


# --- the one-list invariant ----------------------------------------------------


def test_an_address_on_two_lists_fails_the_load():
    """A hand-edit that breaks exclusivity surfaces at load, not as a verdict."""
    with pytest.raises(InvalidLists) as caught:
        Lists.load(CONFLICT_LIST_FIXTURES)

    assert any("both@conflict.example" in error for error in caught.value.errors)


def test_the_conflict_fixture_still_loads_with_validation_off():
    """Precedence stays testable in the state a validated load cannot produce."""
    loaded = Lists.load(CONFLICT_LIST_FIXTURES, validate=False)
    assert loaded.whitelist and loaded.blacklist


def test_an_address_whose_domain_is_listed_elsewhere_is_a_conflict():
    """Exclusivity is a domain rule: an address claims its domain."""
    errors = validate_lists(
        [{"email": "a@shopfast.example", "known_structures": []}],
        [{"domain": "shopfast.example", "known_structures": []}],
        [],
    )
    assert any("shopfast.example" in error for error in errors)


def test_a_subdomain_on_another_list_is_not_a_conflict():
    """Matching is subdomain-inclusive; the invariant is exact, and deliberately so.

    Blacklisting one abusive subdomain while greylisting the parent is a
    refinement the precedence ladder already resolves, not a contradiction.
    """
    assert validate_lists(
        [],
        [{"domain": "bank.example", "known_structures": []}],
        [{"domain": "phish.bank.example", "known_structures": []}],
    ) == []


def test_the_fixture_lists_satisfy_the_invariant(lists: Lists):
    assert validate_lists(lists.whitelist, lists.greylist, lists.blacklist) == []


def test_a_repeat_within_one_list_is_not_a_cross_list_conflict():
    """Exclusivity is about *different* lists.

    The live blacklist ships an address twice; ``dedupe`` collapses it on load,
    before validation, and even unrepaired it is a hygiene problem rather than
    a contradiction.
    """
    twice = [{"email": "a@x.example", "known_structures": []}] * 2
    assert validate_lists([], [], twice) == []


@pytest.mark.parametrize(
    "entry, fragment",
    [
        ({"known_structures": []}, "needs an 'email' or a 'domain'"),
        ({"email": "a@x.example", "known_structures": "nope"}, "must be a list"),
        ({"email": "a@x.example", "tags": "work"}, "'tags' must be a list"),
        ({"email": "a@x.example", "known_structures": [{"key_phrases": []}]}, "non-empty 'name'"),
    ],
    ids=["keyless", "structures-not-a-list", "tags-not-a-list", "structure-without-a-name"],
)
def test_a_malformed_entry_is_reported(entry, fragment):
    errors = validate_lists([entry], [], [])
    assert any(fragment in error for error in errors)


def test_a_greylist_entry_keyed_on_an_email_is_reported():
    errors = validate_lists([], [{"email": "a@x.example", "known_structures": []}], [])
    assert any("key on 'domain'" in error for error in errors)
