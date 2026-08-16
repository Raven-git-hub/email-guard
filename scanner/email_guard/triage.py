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
"""

from __future__ import annotations

import re
from typing import Any

from .lists import GREYLIST_KNOWN, GREYLIST_NEW_STRUCTURE, GREYLIST_NONE
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
# Zero-width and BOM characters used to smuggle text past a human reader.
# Escape form deliberately -- these are invisible when pasted literally.
_HIDDEN_UNICODE_RE = re.compile(r"[\u200B-\u200D\uFEFF]")
_FENCE_RE = re.compile(r"```")
# The canonical prose override, mirroring feed seeds inj-0001 and inj-0002.
#
# The three markers above are all *structural* -- framing tokens, invisible
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


def content_text(message: dict[str, Any]) -> str:
    """The only thing triage is allowed to look at: title + body text."""
    parts = [message.get("title") or "", message.get("clean_text") or ""]
    return "\n".join(part for part in parts if part)


def injection_markers(clean_text: str) -> list[str]:
    """Which hard-baked prompt-injection markers appear in the text."""
    text = clean_text or ""
    found: list[str] = []
    if _ROLEPLAY_RE.search(text):
        found.append("roleplay_tag")
    if _HIDDEN_UNICODE_RE.search(text):
        found.append("hidden_unicode")
    if len(_FENCE_RE.findall(text)) >= 2:
        found.append("code_fences")
    if _OVERRIDE_RE.search(text):
        found.append("instruction_override")
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
