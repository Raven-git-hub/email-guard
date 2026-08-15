"""Proton source cleaner -- ``metadata`` pillars + ``integrity`` only.

Ported from the pillar section of ``reference/n8n/proton_cleaner.js``. The rest
of that file (sender identity, list hits, obfuscation, links, clean_text,
attachments) now lives in :mod:`email_guard.clean.common`, shared with the other
two sources -- see the root README, "Known issues" -> "Cleaner contract
mismatch".

Proton is the default/fallback pipe: mail arrives already decrypted through the
Bridge, so authenticity is asserted internally rather than read off headers.
"""

from __future__ import annotations

from typing import Any

from ..parse import header_text

SOURCE_PIPE = "ProtonMail"
FRIENDLY_PREFIX = "proton"


def pillars(parsed: dict[str, Any]) -> dict[str, Any]:
    metadata = parsed.get("metadata") or {}
    subject = parsed.get("subject") or ""

    return {
        "metadata": {
            "authenticity": {
                # The prototype's Proton cleaner emitted no dmarc/spf keys at
                # all. They are present here (as "none") so all three sources
                # expose the identical pillar shape for the rules pack.
                "dmarc": "none",
                "dkim": "internal-pass",
                "spf": "none",
                "auth_string": "internal-proton-encryption",
            },
            "origin": {
                "ip": "proton-internal",
                "sid_result": "pass",
            },
            "path": {
                "return_path": header_text(metadata.get("return-path") or "") or "internal",
                "is_forwarded": "fw:" in subject.lower(),
                "hop_count": 1,
            },
            "technical": {
                "content_type": header_text(metadata.get("content-type") or "")
                or "multipart/mixed",
                "is_multipart": True,
                "encoding": "end-to-end-encrypted",
                "mime_version": header_text(metadata.get("mime-version") or "") or "1.0",
            },
            "behavioural": {
                "header_count": len(metadata),
                "mailer": "ProtonMail-Web-Interface",
                "traffic_type": "Internal-Encrypted",
            },
        },
        "integrity": {
            "dkim_verified": True,
            "source_pipe": SOURCE_PIPE,
        },
    }
