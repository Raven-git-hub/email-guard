"""Gmail source cleaner -- ``metadata`` pillars + ``integrity`` only.

Ported from ``reference/n8n/gmail_cleaner.js``.
"""

from __future__ import annotations

from typing import Any

from ..parse import header_text, hop_count
from .common import auth_results, sender_ip

SOURCE_PIPE = "GMAIL"
FRIENDLY_PREFIX = "gmail"


def pillars(parsed: dict[str, Any]) -> dict[str, Any]:
    metadata = parsed.get("metadata") or {}
    auth_string, dkim, dmarc, spf = auth_results(metadata)

    return_path = header_text(metadata.get("return-path") or "") or "unknown"
    is_forwarded = bool(
        metadata.get("x-forwarded-for")
        or metadata.get("x-forwarded-to")
        or metadata.get("resent-from")
    )
    content_type = header_text(metadata.get("content-type") or "") or "unknown"

    return {
        "metadata": {
            "authenticity": {
                "dmarc": dmarc,
                "dkim": dkim,
                "spf": spf,
                "auth_string": auth_string,
            },
            "origin": {
                "ip": sender_ip(metadata),
                # The Gmail pipe never exposed a Microsoft SID result.
                "sid_result": "unknown",
            },
            "path": {
                "return_path": return_path,
                "is_forwarded": is_forwarded,
                "hop_count": hop_count(metadata.get("received")),
            },
            "technical": {
                "content_type": content_type,
                "is_multipart": "multipart" in content_type.lower(),
                "encoding": header_text(metadata.get("content-transfer-encoding") or "")
                or "quoted-printable",
                "mime_version": header_text(metadata.get("mime-version") or "") or "1.0",
            },
            "behavioural": {
                "header_count": len(metadata),
                "mailer": header_text(metadata.get("x-mailer") or "") or "hidden",
                "traffic_type": "Email",
            },
        },
        "integrity": {
            "dkim_verified": dkim == "pass",
            "source_pipe": SOURCE_PIPE,
        },
    }
