"""Outlook source cleaner -- ``metadata`` pillars + ``integrity`` only.

Ported from ``reference/n8n/outlook_cleaner.js``. Everything else the message
needs is built by :mod:`email_guard.clean.common`.
"""

from __future__ import annotations

from typing import Any

from ..parse import header_text, hop_count
from .common import auth_results, sender_ip

SOURCE_PIPE = "OUTLOOK"
FRIENDLY_PREFIX = "outlook"


def pillars(parsed: dict[str, Any]) -> dict[str, Any]:
    metadata = parsed.get("metadata") or {}
    auth_string, dkim, dmarc, spf = auth_results(metadata)

    return_path = header_text(metadata.get("return-path") or "") or "unknown"
    is_forwarded = "SRS" in return_path or bool(metadata.get("resent-from"))
    content_type = header_text(metadata.get("content-type") or "") or "unknown"

    try:
        header_count = int(header_text(metadata.get("x-incomingheadercount") or ""))
    except (TypeError, ValueError):
        header_count = 0
    if not header_count:
        header_count = len(metadata)

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
                "sid_result": (header_text(metadata.get("x-sid-result") or "unknown")).lower(),
            },
            "path": {
                "return_path": return_path,
                "is_forwarded": is_forwarded,
                "hop_count": hop_count(metadata.get("received")),
            },
            "technical": {
                "content_type": content_type,
                "is_multipart": "multipart" in content_type.lower(),
                "encoding": header_text(metadata.get("content-transfer-encoding") or "") or "7bit",
                "mime_version": header_text(metadata.get("mime-version") or "") or "1.0",
            },
            "behavioural": {
                "header_count": header_count,
                "mailer": header_text(
                    metadata.get("user-agent") or metadata.get("x-mailer") or ""
                )
                or "hidden",
                "traffic_type": header_text(metadata.get("x-ms-publictraffictype") or "")
                or "unknown",
            },
        },
        "integrity": {
            "dkim_verified": dkim == "pass",
            "source_pipe": SOURCE_PIPE,
        },
    }
