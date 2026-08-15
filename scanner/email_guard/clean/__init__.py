"""Source cleaners: raw parsed message -> the normalised message shape.

Header fingerprints pick the pipe, matching the prototype's "Mailbox Filter"
node: ``x-ms-*`` means the message came through Outlook, ``x-google-dkim`` /
``x-gm-*`` through Gmail, anything else is treated as native Proton.
"""

from __future__ import annotations

from typing import Any

from ..lists import Lists
from . import gmail, outlook, proton
from .common import normalise

__all__ = ["clean", "pick_source", "normalise", "outlook", "gmail", "proton"]

SOURCES = {
    outlook.SOURCE_PIPE: outlook,
    gmail.SOURCE_PIPE: gmail,
    proton.SOURCE_PIPE: proton,
}


def pick_source(parsed: dict[str, Any]):
    """Choose the cleaner for this message by header fingerprint."""
    metadata = parsed.get("metadata") or {}
    keys = list(metadata.keys())

    if any(key.startswith("x-ms-") for key in keys):
        return outlook
    if any(key.startswith("x-gm-") or key == "x-google-dkim-signature" for key in keys):
        return gmail
    return proton


def clean(parsed: dict[str, Any], lists: Lists, job_id: str | None = None) -> dict[str, Any]:
    """Normalise a parsed message using the cleaner its headers point at."""
    source = pick_source(parsed)
    return normalise(parsed, source, lists, job_id=job_id)
