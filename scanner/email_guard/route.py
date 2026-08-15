"""Routing: final level -> bucket.

    1     -> rejected   (quarantine)
    2, 3  -> flagged    (quarantine)
    4, 5  -> cleared    (consolidated inbox, tagged with an action)

Root README, "Threat level model".
"""

from __future__ import annotations

REJECTED = "rejected"
FLAGGED = "flagged"
CLEARED = "cleared"


def bucket_for(level: int) -> str:
    if level <= 1:
        return REJECTED
    if level in (2, 3):
        return FLAGGED
    return CLEARED


# TODO(delivery): `cleared` mail is later tagged with an action (finance,
# personal_assistant, work, calendar, summarise) taken from the greylist entry,
# and handed to the dispatcher for webhook delivery + consolidated-inbox
# delivery. The action field is not yet in the greylist schema; the verdict
# carries `proposed_action: null` as the placeholder.
