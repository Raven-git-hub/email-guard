"""Run the review console.

    python -m email_guard_webui [--host H] [--port P] [--lists-dir DIR] ...

The bind address is the security-relevant argument, so it is the one this
module argues with. The console reads mail content and edits the lists that
decide whether mail is delivered; there is no authentication by default and no
transport security at all, because "it is on loopback" is doing that work. A
non-loopback bind therefore has to be asked for twice -- the host *and*
``--allow-non-loopback`` -- rather than being a typo away.

The one legitimate use of that flag is inside a container, where the process
must bind ``0.0.0.0`` for a published port to reach it and the host side of the
publication is pinned to ``127.0.0.1`` (see ``docker-compose.yml``).
"""

from __future__ import annotations

import argparse
import sys

import uvicorn

from . import config as webui_config
from .app import create_app

EXIT_OK = 0
EXIT_USAGE = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m email_guard_webui",
        description="Email Guard review console (localhost only).",
    )
    parser.add_argument("--config", help="path to config.json")
    parser.add_argument("--lists-dir", help="directory holding the live lists")
    parser.add_argument("--daily-brief-dir", help="directory holding staged candidates")
    parser.add_argument("--outbound-dir", help="directory holding routed messages")
    parser.add_argument("--host", help=f"bind address (default {webui_config.DEFAULT_HOST})")
    parser.add_argument("--port", type=int, help=f"bind port (default {webui_config.DEFAULT_PORT})")
    parser.add_argument(
        "--allow-non-loopback",
        action="store_true",
        help="permit a bind address that is not loopback (containers only)",
    )
    parser.add_argument("--log-level", default="info", help="uvicorn log level")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    config = webui_config.load(
        config_path=args.config,
        lists_dir=args.lists_dir,
        daily_brief_dir=args.daily_brief_dir,
        outbound_dir=args.outbound_dir,
        host=args.host,
        port=args.port,
    )

    allowed = args.allow_non_loopback or webui_config.allow_non_loopback()
    if not config.is_loopback and not allowed:
        print(
            f"refusing to bind {config.host}: the console reads mail and edits the "
            "lists, and is unauthenticated by default. Bind 127.0.0.1, or pass "
            "--allow-non-loopback (set "
            f"{webui_config.ENV_ALLOW_NON_LOOPBACK}=1) if a container is publishing "
            "the port to loopback on the host.",
            file=sys.stderr,
        )
        return EXIT_USAGE

    print(
        f"lists       {config.lists_dir}\n"
        f"daily brief {config.daily_brief_dir}\n"
        f"auth        {'shared token' if config.auth_enabled else 'disabled'}\n"
        f"serving     http://{config.host}:{config.port}/",
        file=sys.stderr,
    )
    if not config.auth_enabled and not config.is_loopback:
        print(
            "warning: bound off loopback with no token -- anything that can reach "
            f"this port can read mail and edit the lists. Set "
            f"{webui_config.ENV_TOKEN}.",
            file=sys.stderr,
        )

    uvicorn.run(
        create_app(config),
        host=config.host,
        port=config.port,
        log_level=args.log_level,
        # The console has no proxy in front of it, so there is no forwarded
        # header to trust. Left off deliberately.
        proxy_headers=False,
    )
    return EXIT_OK


if __name__ == "__main__":  # pragma: no cover - process entry point
    raise SystemExit(main())
