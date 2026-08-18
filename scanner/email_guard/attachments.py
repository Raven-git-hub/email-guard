"""Cleared attachments, from the message's own bytes onto disk.

The scanner never *inspects* an attachment. This module lifts the raw bytes of
each attachment part out of the message and writes them into the job directory
beside ``report.json`` and ``message.eml``, so a downstream consumer (the
"Smiley" machine -- see README, "Publishing to acheron") receives a
self-describing package and does the inspection itself, off this host.

Two rules govern everything here, and both are load-bearing:

* **Bytes only.** An attachment is never opened, sniffed, decoded as text,
  unpacked, or executed by this process. The one transformation applied is the
  MIME *transfer* decoding -- base64 or quoted-printable back to the octets the
  sender attached -- which is the difference between storing an attachment and
  storing its envelope. Nothing reads those octets afterwards: they are hashed,
  sized and written. The verdict is computed before any of this runs and cannot
  be influenced by it (``tests/test_attachments.py`` pins that).
* **Cleared mail only.** Materialising a file from `flagged` or `rejected` mail
  would put attacker-supplied executables on disk in the quarantine tree for
  the sake of a package nothing is allowed to consume. The caller
  (:mod:`email_guard.route`) enforces it; the quarantined ``message.eml`` still
  holds the whole message, attachments included, for a human reviewer.

The filename is the hostile part. It arrives from the sender verbatim and is
about to become a path, so :func:`sanitise_name` treats it the way
:func:`email_guard.route.job_slug` treats a message id: strip the directory
components, transliterate, restrict to a known-safe character set, cap the
length, and refuse the handful of names that would collide with the package's
own files or with the publisher's markers.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass
from email import policy
from email.parser import BytesParser
from typing import Any

# Same alphabet as the job slug: everything else collapses to a single "-".
_UNSAFE_CHARS = re.compile(r"[^A-Za-z0-9._-]+")
_TRIM_CHARS = "-._"
# Well inside the 255-byte limit of every common filesystem, with room for the
# "-1", "-2" collision suffixes and the publisher's temp-directory prefix.
_NAME_MAX = 100
_EXT_MAX = 16
_FALLBACK_NAME = "attachment"

# Names the package already owns, plus the publisher's two markers. An
# attachment called `report.json` would otherwise overwrite the verdict, and one
# called `.complete` would announce a half-written job to the publisher.
RESERVED_NAMES = frozenset(
    {"report.json", "message.eml", "message.json", ".complete", ".published"}
)


@dataclass(frozen=True)
class Attachment:
    """One attachment part: its sender-supplied name, its type, its octets."""

    filename: str
    content_type: str
    data: bytes


def extract(kind: str, raw: bytes) -> list[Attachment]:
    """Every attachment part of one message, in the order the message lists them.

    ``kind`` is :attr:`email_guard.route.SourceMessage.kind` -- ``"eml"`` for raw
    RFC822, ``"json"`` for the n8n IMAP item shape. Duplicated filenames are
    *kept*: two parts genuinely called ``invoice.pdf`` are two attachments, and
    :func:`sanitise_name` gives them separate names on disk. (The verdict's own
    ``attachments`` list de-dupes by filename -- it describes what the message
    claims; this describes what is on disk.)

    Never raises on malformed input: an unparseable part yields no attachment
    rather than failing the scan. Quarantine still holds the whole message.
    """
    if kind == "json":
        return _from_json(raw)
    return _from_eml(raw)


def _from_eml(raw: bytes) -> list[Attachment]:
    try:
        message = BytesParser(policy=policy.default).parsebytes(raw)
    except Exception:  # noqa: BLE001 - a message we cannot walk has no attachments
        return []

    found: list[Attachment] = []
    for part in message.walk():
        if part.is_multipart():
            continue
        filename = part.get_filename()
        disposition = (part.get_content_disposition() or "").lower()
        # Exactly the test `email_guard.parse._walk_parts` uses to decide what
        # counts as an attachment, so the bytes on disk and the verdict's
        # attachment list describe the same parts.
        if disposition != "attachment" and not filename:
            continue

        data = _part_bytes(part)
        if data is None:
            continue
        found.append(
            Attachment(
                filename=_decoded_filename(filename),
                content_type=part.get_content_type(),
                data=data,
            )
        )
    return found


def _part_bytes(part) -> bytes | None:
    """The part's payload with its transfer encoding undone -- and nothing else."""
    try:
        payload = part.get_payload(decode=True)
    except Exception:  # noqa: BLE001
        payload = None
    if isinstance(payload, bytes):
        return payload

    # `message/rfc822` and friends carry a sub-message rather than an encoded
    # payload, and `decode=True` answers None for them. The attached message's
    # own bytes are the attachment, so serialise the part back out verbatim.
    try:
        rendered = part.as_bytes()
    except Exception:  # noqa: BLE001
        return None
    return rendered if isinstance(rendered, bytes) else None


def _decoded_filename(filename: Any) -> str:
    """The sender's filename as a string, RFC2047 words already handled upstream.

    ``get_filename()`` returns the decoded value under ``policy.default``; this
    only guards the type, because the value is attacker-controlled and about to
    be sanitised, not trusted.
    """
    if not filename:
        return ""
    return str(filename)


def _from_json(raw: bytes) -> list[Attachment]:
    """Attachments from an n8n IMAP item: base64 blobs under ``binary``.

    The JSON front door is the prototype's pinData path (``--from-json``). Items
    whose ``binary`` entry carries no ``data`` are metadata-only -- the verdict
    still lists them, and there are no bytes to write.
    """
    try:
        payload = json.loads(raw.decode("utf-8"))
    except Exception:  # noqa: BLE001
        return []
    if not isinstance(payload, dict):
        return []

    found: list[Attachment] = []
    for key, blob in (payload.get("binary") or {}).items():
        if not isinstance(blob, dict):
            continue
        encoded = blob.get("data")
        if not isinstance(encoded, str) or not encoded:
            continue
        try:
            data = base64.b64decode(encoded, validate=False)
        except (binascii.Error, ValueError):
            continue
        found.append(
            Attachment(
                filename=str(
                    blob.get("fileName") or blob.get("filename") or key or ""
                ),
                content_type=str(blob.get("mimeType") or "unknown"),
                data=data,
            )
        )
    return found


def sanitise_name(raw: Any, taken: set[str] | None = None) -> str:
    """A safe, unique, on-disk name for an attacker-supplied filename.

    In order: take the last path component (so ``../../etc/passwd`` and
    ``C:\\Windows\\evil.exe`` and ``/etc/passwd`` all reduce to their basename),
    transliterate unicode to ASCII, collapse everything outside
    ``[A-Za-z0-9._-]`` to ``-``, refuse leading dots (no hidden files, and no
    forging the publisher's markers), cap the length keeping the extension, and
    finally disambiguate against ``taken`` -- which the caller carries across
    one job's attachments, so two ``invoice.pdf`` parts become ``invoice.pdf``
    and ``invoice-1.pdf``.

    The result is never empty, never absolute, never contains a separator, and
    never escapes the job directory.
    """
    taken = taken if taken is not None else set()

    text = str(raw or "")
    # Both separators, whatever the sending platform: a Windows client's
    # `..\..\evil.exe` must not survive on a POSIX host.
    basename = re.split(r"[\\/]", text)[-1]
    stem, extension = _split_extension(_ascii_fold(basename))

    stem = _UNSAFE_CHARS.sub("-", stem).strip(_TRIM_CHARS)
    extension = _UNSAFE_CHARS.sub("-", extension).strip(_TRIM_CHARS)[:_EXT_MAX]

    if not stem:
        stem = _FALLBACK_NAME
    stem = stem[: _NAME_MAX - (len(extension) + 1 if extension else 0)].rstrip(_TRIM_CHARS)
    if not stem:
        stem = _FALLBACK_NAME

    candidate = f"{stem}.{extension}" if extension else stem
    if candidate.lower() in RESERVED_NAMES:
        stem = f"{_FALLBACK_NAME}-{stem}"
        candidate = f"{stem}.{extension}" if extension else stem

    return _disambiguate(stem, extension, candidate, taken)


def _disambiguate(stem: str, extension: str, candidate: str, taken: set[str]) -> str:
    if candidate not in taken:
        return candidate
    index = 1
    while True:
        suffixed = f"{stem}-{index}"
        candidate = f"{suffixed}.{extension}" if extension else suffixed
        if candidate not in taken:
            return candidate
        index += 1


def _ascii_fold(text: str) -> str:
    """``café.pdf`` -> ``cafe.pdf``: decompose, drop the combining marks.

    Folding before the character filter keeps accented names readable instead of
    punching a ``-`` through every letter that carries a diacritic. Anything
    with no single-character ASCII form -- ``ß``, ``发`` -- still collapses to
    ``-`` in the filter that follows. Readability is the only goal here; safety
    is the filter's job, not this one's.
    """
    decomposed = unicodedata.normalize("NFKD", text)
    return "".join(char for char in decomposed if not unicodedata.combining(char))


def _split_extension(name: str) -> tuple[str, str]:
    """``report.tar.gz`` -> ``("report.tar", "gz")``; a leading dot is not one."""
    trimmed = name.strip().strip(_TRIM_CHARS)
    stem, dot, extension = trimmed.rpartition(".")
    if not dot or not stem:
        return trimmed, ""
    return stem, extension


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
