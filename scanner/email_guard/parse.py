"""Raw message -> the intermediate "parsed message".

Two front doors, one output shape:

* :func:`parse_eml`  -- a raw RFC822 ``.eml`` via the stdlib ``email`` package.
* :func:`parse_json` -- a pre-parsed message in the n8n IMAP node's shape, so the
  prototype's pinData samples work as fixtures (``--from-json``).

The shape deliberately mirrors the n8n IMAP item, because that is what the
prototype's cleaners were written against::

    {
      "metadata":  {lower-cased header name -> str, or list[str] when repeated},
      "textHtml":  str,
      "textPlain": str,
      "from": str, "to": str, "subject": str, "date": str,
      "uid": int | None,
      "attachments": [ {"filename": str, "contentType": str} ],
    }
"""

from __future__ import annotations

import json
from email import policy
from email.header import decode_header, make_header
from email.parser import BytesParser
from pathlib import Path
from typing import Any

__all__ = ["parse_eml", "parse_eml_file", "parse_json", "parse_json_file", "header_text", "hop_count"]


def parse_eml(raw: bytes) -> dict[str, Any]:
    """Parse raw RFC822 bytes into the intermediate parsed-message shape."""
    message = BytesParser(policy=policy.default).parsebytes(raw)

    metadata: dict[str, Any] = {}
    for name, value in message.items():
        key = name.lower()
        decoded = _decode(value)
        if key in metadata:
            existing = metadata[key]
            if isinstance(existing, list):
                existing.append(decoded)
            else:
                metadata[key] = [existing, decoded]
        else:
            metadata[key] = decoded

    text_html, text_plain, attachments = _walk_parts(message)

    return {
        "metadata": metadata,
        "textHtml": text_html,
        "textPlain": text_plain,
        "from": _decode(message.get("from", "")),
        "to": _decode(message.get("to", "")),
        "subject": _decode(message.get("subject", "")),
        "date": _decode(message.get("date", "")),
        "uid": None,
        "attachments": attachments,
    }


def parse_eml_file(path: str | Path) -> dict[str, Any]:
    return parse_eml(Path(path).read_bytes())


def parse_json(payload: dict[str, Any]) -> dict[str, Any]:
    """Normalise a pre-parsed n8n IMAP item into the parsed-message shape."""
    metadata = {str(k).lower(): v for k, v in (payload.get("metadata") or {}).items()}

    uid = payload.get("uid")
    if uid is None:
        uid = (payload.get("attributes") or {}).get("uid")

    attachments = list(payload.get("attachments") or [])
    # The IMAP node exposes attachments under `binary`; the prototype's Proton
    # cleaner read both that and the `x-attached` header.
    for key, blob in (payload.get("binary") or {}).items():
        attachments.append(
            {
                "filename": blob.get("fileName") or blob.get("filename") or key,
                "contentType": blob.get("mimeType") or "unknown",
            }
        )

    return {
        "metadata": metadata,
        "textHtml": payload.get("textHtml") or "",
        "textPlain": payload.get("textPlain") or "",
        "from": payload.get("from") or metadata.get("from") or "",
        "to": payload.get("to") or metadata.get("to") or "",
        "subject": payload.get("subject") or "",
        "date": payload.get("date") or "",
        "uid": uid,
        "attachments": attachments,
        "messageID": payload.get("messageID"),
    }


def parse_json_file(path: str | Path) -> dict[str, Any]:
    with Path(path).open(encoding="utf-8") as handle:
        return parse_json(json.load(handle))


def header_text(value: Any) -> str:
    """Flatten a header to a single string for regex work.

    Repeated headers arrive as a list. The prototype called ``.match()`` straight
    on the value, which throws for an array -- joining keeps every occurrence
    searchable instead of crashing on the second ``Received:``.
    """
    if value is None:
        return ""
    if isinstance(value, list):
        return "\n".join(str(v) for v in value)
    return str(value)


def hop_count(value: Any) -> int:
    """``Received`` header count -- 1 unless the header repeats (as in the prototype)."""
    if isinstance(value, list):
        return len(value)
    return 1


def _decode(value: Any) -> str:
    """Decode RFC2047 encoded-words, tolerating malformed input."""
    if value is None:
        return ""
    if isinstance(value, list):
        return "\n".join(_decode(v) for v in value)
    try:
        return str(make_header(decode_header(str(value))))
    except Exception:
        return str(value)


def _walk_parts(message) -> tuple[str, str, list[dict[str, str]]]:
    text_html = ""
    text_plain = ""
    attachments: list[dict[str, str]] = []

    for part in message.walk():
        if part.is_multipart():
            continue
        content_type = part.get_content_type()
        filename = part.get_filename()
        disposition = (part.get_content_disposition() or "").lower()

        if disposition == "attachment" or filename:
            attachments.append(
                {"filename": _decode(filename) or "unnamed", "contentType": content_type}
            )
            continue

        body = _part_text(part)
        if content_type == "text/html" and not text_html:
            text_html = body
        elif content_type == "text/plain" and not text_plain:
            text_plain = body

    return text_html, text_plain, attachments


def _part_text(part) -> str:
    try:
        payload = part.get_content()
    except Exception:
        payload = part.get_payload(decode=True)
        if isinstance(payload, bytes):
            charset = part.get_content_charset() or "utf-8"
            payload = payload.decode(charset, errors="replace")
    return payload if isinstance(payload, str) else ""
