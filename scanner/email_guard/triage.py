"""Triage: a lenient, content-only guess at the initial threat level.

Three concerns are kept strictly apart, and this module owns exactly one of
them:

* **Triage reads message content only** -- the title and the cleaned body text.
  Nothing else.
* **The deep scan owns technical forensics** -- headers, DKIM, return path,
  multipart structure, mailer fingerprints, header counts. Triage must never
  read ``metadata.technical``, ``integrity.dkim_verified`` or the return path.
* **The lists own identity** -- who the sender is, and which domains are
  recognised.

Triage is a face-value guess, **not a line of defence**. Everything it assigns
above level 1 is revisited by the deep-scan loop, which can move a message
either way. So it is deliberately lenient and only rejects outright on signals
that are unambiguous: a blacklisted sender, or injection phrasing that no
legitimate correspondent would send.

An earlier version had a "weak infrastructure" branch here that pushed a
message to level 2 for being single-part, or unverified by DKIM, or having a
misaligned return path. Those are technical signals, they are wrong far more
often than they are right (all mail here is forwarded through the bridge, which
rewrites exactly those fields), and the deep scan already weighs them with
proper context. They have been removed entirely: an ordinary plain-text receipt
from an unknown domain is a level 3 to be looked at, not a level 2 suspect.

Priority ladder, first match wins:

    1. blacklist hit                                        -> 1
    1b. greylist "denied" -- a catalogued shape the reviewer
       marked unwanted. A blacklist entry scoped to one
       message shape rather than a whole sender             -> 1
    2. injection detected -- the hard-baked floor below, or
       the level-1 injection signature feed. Fires even for
       a whitelisted sender: no legitimate sender embeds
       injection, so one that does is spoofed or compromised -> 1
    3. NOT whitelisted, and either the phishing signature
       feed matches, or the subject carries standalone
       obvious obfuscation (homoglyphs) with no injection
       payload beneath it -- rule 2 already ruled that out   -> 2
    4. greylist "known"                                      -> 4
       greylist "new_structure"                              -> 3
       greylist "none" AND not whitelisted                   -> 3
    5. whitelist hit                                         -> 4 with
                                                                attachments,
                                                                else 5

Note the ordering of 4 before 5, which is what the ``and not whitelisted``
qualifier in rule 4 implies: a whitelisted address on a greylisted domain is
judged by the domain's catalogued shape, so an uncatalogued message from it
still lands at 3 for review rather than being waved through at 5.

Rule 1b does not breach "triage reads message content only". The content ->
disposition decision belongs to :func:`email_guard.lists.classify_greylist`,
which reads the subject and body against the catalogued shapes; triage receives
only the resulting classification string, exactly as it always has.
"""

from __future__ import annotations

import re
from typing import Any

from .lists import (
    GREYLIST_DENIED,
    GREYLIST_KNOWN,
    GREYLIST_NEW_STRUCTURE,
    GREYLIST_NONE,
)
from .signatures import SignatureFeed

# ---------------------------------------------------------------------------
# The hard-baked injection floor.
#
# This is the permanent baseline, not a default that the feed replaces. It is
# what triage still catches when the signature feed is missing, empty or
# unreadable -- see email_guard.signatures on why that feed fails open. The
# feed adds to these markers; it never removes them.
#
# So the floor has to be able to stand alone. Anything that MUST be caught in
# the fail-open state belongs here, not only in the feed -- rule 2 is what
# stops a whitelisted sender being trusted with a payload, and a rule that
# evaporates when a file goes missing is not a floor.
# ---------------------------------------------------------------------------

# Roleplay / instruction framing, e.g. "system:", "### Instruction:", "[INST]:".
_ROLEPLAY_RE = re.compile(r"(system|user|assistant|instruction|###|\[INST\])\s*:", re.IGNORECASE)
_FENCE_RE = re.compile(r"```")
# The canonical prose override, mirroring feed seeds inj-0001 and inj-0002.
#
# The other markers are all *structural* -- framing tokens, invisible
# characters, fenced blocks. Without this one the single most common phrasing
# of the attack ("ignore all previous instructions") lived only in the feed,
# so losing the feed reopened exactly the hole rule 2 exists to close: a
# whitelisted sender carrying that sentence fell through to level 5, cleared.
#
# One alternation rather than two near-identical patterns: "ignore" and
# "disregard" are the same shape with the same object, and the floor is meant
# to stay a small permanent failsafe. The feed keeps the long tail (persona
# reassignment, concealment, "new system instructions:"), and the overlap
# between floor and feed is intended -- floor is a subset that cannot go
# missing, feed is the updatable superset.
#
# Held to the same precision bar as the feed: the instruction-shaped OBJECT is
# required, because a level-1 hit rejects even a whitelisted sender. "Please
# disregard the previous email" is a routine correction notice; "disregard the
# previous instructions" is not.
_OVERRIDE_RE = re.compile(
    r"(?:ignore|disregard)\s+(?:all\s+)?(?:the\s+)?"
    r"(?:previous|prior|earlier|above|foregoing)\s+"
    r"(?:instructions|prompts|directions|rules|commands)",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# hidden_unicode: concealment, not merely invisibility.
#
# This marker used to be `re.search("[\u200B-\u200D\uFEFF]")` -- ANY zero-width
# character anywhere in the title or body was a level-1 reject. That is not a
# detector, it is a census of a character class, and it was the single largest
# source of over-rejection in the engine: a 300-message rescan cleared ~12%,
# with this marker a primary driver. Marketing, banking and receipt templates
# emit zero-width padding as a matter of course -- Standard Chartered, HSBC,
# store-news@amazon, Glassdoor, Suno, Telekom were all being thrown out for it.
#
# The floor still runs BEFORE the lists, and that ordering is not what was
# wrong: a trusted sender's account can be compromised, so injection detection
# must never be bypassable by list membership. The fix is precision, not
# precedence -- the marker now has to show that the characters are *concealing*
# something rather than merely being invisible.
#
# Two shapes are concealment, and nothing else is:
#
#   * a zero-width run INSIDE a word -- "ig<zw>nore pre<zw>vious". Splitting a
#     word breaks every keyword and phrase matcher downstream while leaving the
#     text identical to a human, which is the whole attack.
#   * a zero-width run that HIDES phrasing: stripping the characters makes a
#     floor marker appear that the text as it stands does not match. "ignore
#     all<zw> previous instructions" defeats the override pattern's `\s+`
#     without splitting a single word.
#
# Everything else is padding, and padding raises the level not at all: a run
# next to whitespace, punctuation or a string boundary; scattered spacers; a
# U+200D joining two emoji into one glyph.
#
# "Inside a word" is deliberately scoped to the scripts the phrase matching
# reads -- Latin, Greek, Cyrillic and digits. Two consequences, both wanted:
# ZWNJ/ZWJ carrying their ordinary orthographic job in Arabic or Indic text
# never trips the marker, and neither does the U+200B that Thai and Khmer use
# as a word separator. A split there evades no matcher we run, and injection
# phrasing hidden in any script is still caught by the reveal rule above.
#
# The residual cost, accepted knowingly: a line-break hint inside one long
# word (German compound nouns are the usual source) is indistinguishable from a
# one-word split and still fires. That shape is rare next to the padding this
# fix admits, and softening it would mean not catching "ig<zw>nore".
# ---------------------------------------------------------------------------

# Escape form deliberately -- these are invisible when pasted literally.
_ZERO_WIDTH_CHARS = "\u200B\u200C\u200D\uFEFF"
_ZERO_WIDTH_RE = re.compile(f"[{_ZERO_WIDTH_CHARS}]")
# Runs, not single characters: "ig<zw><zw>nore" is one split, not two.
_ZERO_WIDTH_RUN_RE = re.compile(f"[{_ZERO_WIDTH_CHARS}]+")
# Latin (incl. accented), Greek, Cyrillic, digits -- see the note above on why
# the joining scripts are left out rather than special-cased.
_WORD_CHAR_RE = re.compile("[0-9A-Za-z\u00C0-\u024F\u0370-\u03FF\u0400-\u04FF]")


def content_text(message: dict[str, Any]) -> str:
    """The only thing triage is allowed to look at: title + body text."""
    parts = [message.get("title") or "", message.get("clean_text") or ""]
    return "\n".join(part for part in parts if part)


def _visible_markers(text: str) -> list[str]:
    """The floor markers that read the text as it stands."""
    found: list[str] = []
    if _ROLEPLAY_RE.search(text):
        found.append("roleplay_tag")
    if len(_FENCE_RE.findall(text)) >= 2:
        found.append("code_fences")
    if _OVERRIDE_RE.search(text):
        found.append("instruction_override")
    return found


def _splits_a_word(text: str) -> bool:
    """True when a zero-width run sits between two word characters."""
    for run in _ZERO_WIDTH_RUN_RE.finditer(text):
        before = text[run.start() - 1 : run.start()] if run.start() else ""
        after = text[run.end() : run.end() + 1]
        if _WORD_CHAR_RE.fullmatch(before) and _WORD_CHAR_RE.fullmatch(after):
            return True
    return False


def zero_width_markers(text: str) -> list[str]:
    """The markers the text's zero-width characters justify, if any.

    ``[]`` for padding -- which is what zero-width characters almost always
    are. ``["hidden_unicode", ...]`` when they are concealing: splitting a word
    run, or hiding phrasing that the floor catches once they are stripped. Any
    marker the stripping revealed is named alongside, so the reason reads as
    "smuggled, and here is what was smuggled" rather than just "invisible
    characters present".
    """
    if not _ZERO_WIDTH_RE.search(text):
        return []

    visible = _visible_markers(text)
    revealed = [
        marker
        for marker in _visible_markers(_ZERO_WIDTH_RE.sub("", text))
        if marker not in visible
    ]
    if not revealed and not _splits_a_word(text):
        return []
    return ["hidden_unicode", *revealed]


def injection_markers(clean_text: str) -> list[str]:
    """Which hard-baked prompt-injection markers appear in the text."""
    text = clean_text or ""
    found = _visible_markers(text)
    found.extend(marker for marker in zero_width_markers(text) if marker not in found)
    return found


def initial_level(
    message: dict[str, Any],
    greylist_classification: str,
    feed: SignatureFeed | None = None,
) -> tuple[int, list[str]]:
    """Return ``(level, reasons)`` for a normalised message.

    ``feed`` is optional and an absent one is not an error: triage then runs on
    the hard-baked floor alone. That is the whole point of the feed failing
    open, so callers without a pack (and the tests) need do nothing special.
    """
    feed = feed or SignatureFeed()
    reasons: list[str] = []

    whitelisted = bool(message.get("whitelist_hit"))
    obfuscation = message.get("obfuscation_flags") or {}
    content = content_text(message)

    # Rule 1 -- identity, decided by the lists.
    if message.get("blacklist_hit"):
        return 1, ["blacklist_hit"]

    # Rule 1b -- a denied structure rejects exactly like a blacklist entry, and
    # for the same reason: the reviewer has already judged this shape. A
    # greylisted domain is never whitelisted (lists are mutually exclusive --
    # see `lists.validate_lists`), so there is no override to reconcile here.
    if greylist_classification == GREYLIST_DENIED:
        return 1, ["greylist_denied_structure"]

    # Rule 2 -- injection. Checked before the whitelist on purpose.
    markers = injection_markers(content)
    injection_signatures = feed.injection_hits(content)
    if markers or injection_signatures:
        reasons.extend(f"injection_marker:{marker}" for marker in markers)
        reasons.extend(f"injection_signature:{name}" for name in injection_signatures)
        return 1, reasons

    # Rule 3 -- content-level suspicion, for senders we do not vouch for.
    if not whitelisted:
        phishing_signatures = feed.phishing_hits(content)
        visual = bool(obfuscation.get("visual"))
        if phishing_signatures or visual:
            reasons.extend(f"phishing_signature:{name}" for name in phishing_signatures)
            if visual:
                # Standalone: rule 2 has already established there is no
                # injection payload underneath it.
                reasons.append("obfuscation_visual")
            return 2, reasons

    # Rule 4 -- the greylist's view of the domain's catalogued shapes.
    if greylist_classification == GREYLIST_KNOWN:
        return 4, ["greylist_known_structure"]
    if greylist_classification == GREYLIST_NEW_STRUCTURE:
        return 3, ["greylist_new_structure"]
    if greylist_classification == GREYLIST_NONE and not whitelisted:
        return 3, ["unknown_domain"]

    # Rule 5 -- whitelisted, on no greylisted domain, and nothing above tripped.
    if message.get("attachments"):
        return 4, ["whitelist_hit", "attachments_present"]
    return 5, ["whitelist_hit"]
