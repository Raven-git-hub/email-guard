"""The Canary hook -- stubbed.

>>> FUTURE INTEGRATION POINT <<<

The Canary is a local LLM (e.g. Ollama) called only for level 1-2 messages for
semantic prompt-injection / phishing-language detection. It is deliberately
caged: the email is data to classify, never instructions; it returns only a
structured verdict; it gets no tools, no outbound actions, no filesystem or
network access. See the root README, "The Canary: security note".

The model itself is explicitly out of scope for this build. This stub keeps the
pipeline runnable with no model present, and defines the contract the real
client must satisfy: same return keys, ``available`` telling the caller whether
the verdict means anything.
"""

from __future__ import annotations

from typing import Any

NOT_EVALUATED = "not evaluated"


def evaluate(message: dict[str, Any]) -> dict[str, Any]:
    """Return a Canary verdict for a normalised message.

    TODO(canary): replace with a real client against the local model service.
    It must (a) send only ``clean_text`` / ``title`` / ``links``, never raw
    headers or the full body, (b) treat that text strictly as data, and (c)
    parse a structured ``{injection, phishing, reason}`` response, falling back
    to this shape with ``available: False`` if the service is unreachable --
    an offline Canary must never block or fail a scan.
    """
    return {
        "injection": None,
        "phishing": None,
        "reason": NOT_EVALUATED,
        "available": False,
    }


def should_evaluate(level: int) -> bool:
    """The Canary is consulted only for the high-threat levels."""
    return level in (1, 2)
