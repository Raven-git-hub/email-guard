"""Docker HEALTHCHECK for the rules updater.

"Healthy" is deliberately not "the last pull succeeded". An upstream that is
unreachable, or a pack that was correctly rejected, are both states in which
this service is doing its job perfectly well -- the live pack is intact and
scanning continues. Restarting the container would fix neither and would only
lose the backoff.

So health is the one thing whose failure a restart could plausibly help, and the
one thing the rest of the stack depends on: **a scan container starting right
now would find a usable rules pack at the promote target.**
"""

from __future__ import annotations

import sys

from .config import ConfigError, load


def main() -> int:
    try:
        config = load()
    except ConfigError as exc:
        print(f"rules updater config is unusable: {exc}", file=sys.stderr)
        return 1

    pack = config.current_link
    if not (pack / "scan" / "level2.json").is_file():
        print(
            f"no rules pack at {pack}: the live tree has never been seeded or "
            "the current symlink is dangling",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
