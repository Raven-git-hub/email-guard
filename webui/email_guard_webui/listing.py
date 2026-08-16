"""The List Data panel's view of the live lists.

A projection, not a copy: the panel needs the key, the label, the tags and --
for the greylist -- the catalogued shapes with their dispositions. Reading it
through :class:`email_guard.lists.Lists` means the console shows the same
entries the engine matches on, deduped the same way, and fails on the same
invalid state instead of rendering something the scanner would refuse.

A hand-edited list can carry keys nothing in the schema mentions (the fixtures'
``_note``). Those stay on disk -- only the applier rewrites a list -- and are
simply not projected here.
"""

from __future__ import annotations

from typing import Any

from email_guard.lists import Lists, disposition, entry_key, tags_of


def entries(lists: Lists, list_name: str) -> list[dict[str, Any]]:
    """Every entry on one list, in file order."""
    return [view(entry) for entry in getattr(lists, list_name)]


def view(entry: dict[str, Any]) -> dict[str, Any]:
    key = entry_key(entry)
    friendly_name = entry.get("friendly_name")
    return {
        "key": key,
        # What the entry is keyed on, so the panel can say "this address" or
        # "this domain and its subdomains" without re-deriving it.
        "scope": "address" if "@" in key else "domain",
        "friendly_name": friendly_name if isinstance(friendly_name, str) else None,
        "tags": tags_of(entry),
        "structures": [
            structure_view(structure)
            for structure in entry.get("known_structures") or []
            if isinstance(structure, dict)
        ],
    }


def structure_view(structure: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": str(structure.get("name") or ""),
        "key_phrases": [
            phrase for phrase in structure.get("key_phrases") or [] if isinstance(phrase, str)
        ],
        # Resolved, not raw: `allowed` is the documented default for shapes
        # catalogued before dispositions existed, and an unreadable value reads
        # as `denied`. The panel must show the disposition the engine will act
        # on, not the one the file happens to spell.
        "disposition": disposition(structure),
        "tags": tags_of(structure),
    }
