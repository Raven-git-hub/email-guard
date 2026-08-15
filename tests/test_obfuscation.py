"""Visual obfuscation: typography must pass, homoglyphs must still flag.

Fix 1. The ported character set omitted General Punctuation, so a curly
apostrophe, an em dash or an ellipsis in a subject read as "obfuscation" and
triage rejected the message at level 1. The set now allows ordinary typography
while still catching what the heuristic is actually for -- letters from other
scripts standing in for Latin ones -- and the invisible characters that are not
typography at all.
"""

from __future__ import annotations

import pytest

from email_guard.clean.common import obfuscation_flags


def visual(subject: str) -> bool:
    return obfuscation_flags(subject)["visual"]


# --- ordinary typography must NOT flag -----------------------------------------


@pytest.mark.parametrize(
    "subject,what",
    [
        ("We’ve added a payee", "curly apostrophe U+2019"),
        ("“Your receipt” is ready", "curly double quotes"),
        ("Statement – May 2026", "en dash U+2013"),
        ("Statement — final notice", "em dash U+2014"),
        ("Loading your statement…", "ellipsis U+2026"),
        ("Amount:\u00a042.00", "non-breaking space"),
        ("Amount:\u202f42.00", "narrow no-break space U+202F"),
        ("Fee † applies", "dagger"),
        ("Item • two", "bullet"),
        ("Half a \u2044 slash", "fraction slash U+2044"),
        ("Plain ASCII subject Ref:[NB1]", "plain ASCII"),
        ("付款轉賬成功", "CJK"),
        ("メールの件", "kana"),
        ("Payment received \U0001f389", "emoji"),
    ],
)
def test_typography_is_not_obfuscation(subject: str, what: str):
    assert visual(subject) is False, f"{what} should not flag as visual obfuscation"


# --- genuine lookalike attacks must STILL flag ---------------------------------


@pytest.mark.parametrize(
    "subject,what",
    [
        ("\u0410pple account suspended", "Cyrillic capital A homoglyph"),
        ("R\u0435set your p\u0430ssword", "Cyrillic e and a homoglyphs"),
        ("\u039fmega Bank alert", "Greek capital Omicron homoglyph"),
        ("\U0001d400ank of somewhere", "Mathematical Alphanumeric capital A"),
        ("\uff21ccount notice", "fullwidth Latin A"),
    ],
)
def test_homoglyphs_still_flag(subject: str, what: str):
    assert visual(subject) is True, f"{what} must still flag as visual obfuscation"


# --- invisible characters are not typography -----------------------------------


@pytest.mark.parametrize(
    "subject,what",
    [
        ("Bank\u200balert", "zero-width space U+200B"),
        ("Bank\u200dalert", "zero-width joiner U+200D"),
        ("Bank\ufeffalert", "BOM / zero-width no-break space"),
        ("invoice\u202edoc.exe", "right-to-left override U+202E"),
        ("Bank\u2060alert", "word joiner U+2060"),
        ("Bank\u206aalert", "deprecated format character U+206A"),
    ],
)
def test_invisible_and_bidi_characters_still_flag(subject: str, what: str):
    """These live inside General Punctuation but are carved out deliberately."""
    assert visual(subject) is True, f"{what} must still flag as visual obfuscation"


# --- the tactical flag is untouched by this fix --------------------------------


def test_tactical_flag_still_works():
    assert obfuscation_flags("URGENT: verify immediately")["tactical"] is True
    assert obfuscation_flags("Your monthly statement")["tactical"] is False


def test_empty_subject_is_clean():
    assert obfuscation_flags("") == {"visual": False, "tactical": False}
