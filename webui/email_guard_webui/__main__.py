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
publication decides who can actually connect (see ``docker-compose.yml``).

There are two refusals here and they guard different things:

1. **A non-loopback bind, unasked for.** A typo in ``--host`` must not be all
   that stands between this process and the network, so the bind has to be
   asked for twice.
2. **Reachable off this host with no token.** Once the console *is* reachable
   from elsewhere, "it is on loopback" has stopped standing in for
   authentication and nothing has replaced it. That combination is refused
   rather than warned about: a warning scrolls past in a container log and the
   console serves mail to the LAN anyway.

Both run before anything binds. The second is fail-closed -- see
:func:`email_guard_webui.config.reachable_beyond_this_host`, which assumes
reachable whenever it cannot prove otherwise.
"""

from __future__ import annotations

import argparse
import sys

import uvicorn

from . import config as webui_config
from .app import create_app

EXIT_OK = 0
EXIT_USAGE = 2
# Distinct from EXIT_USAGE so an operator (or `docker compose ps`) can tell
# "you asked for something impossible" from "you asked for something unsafe".
EXIT_INSECURE = 3


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

    # Fail-closed, and before anything binds: a console anything but this host
    # can reach, with no token, is an unauthenticated reader of mail and editor
    # of delivery rules. `reachable_beyond_this_host` assumes reachable unless
    # it can show otherwise, so an unknown deployment refuses rather than
    # guesses -- see its docstring for the three cases.
    exposed = webui_config.reachable_beyond_this_host(config)
    if exposed and not config.auth_enabled:
        print(
            "refusing to start: the console accepts non-loopback connections but "
            f"{webui_config.ENV_TOKEN} is empty; set a token or run loopback-only.\n"
            "  set a token   export "
            f"{webui_config.ENV_TOKEN}=$(openssl rand -hex 32)   (or put it in "
            f"{webui_config.DEFAULT_SECRETS_FILE} under 'webui'.'token')\n"
            "  loopback only bind 127.0.0.1 and drop "
            f"{webui_config.ENV_ALLOW_NON_LOOPBACK}\n"
            "  under compose leave EMAIL_GUARD_WEBUI_BIND at 127.0.0.1, or set "
            f"{webui_config.ENV_TOKEN} in .env alongside it",
            file=sys.stderr,
        )
        return EXIT_INSECURE

    print(
        f"lists       {config.lists_dir}\n"
        f"daily brief {config.daily_brief_dir}\n"
        f"auth        {'shared token' if config.auth_enabled else 'disabled'}\n"
        f"reachable   {'beyond this host' if exposed else 'this host only'}\n"
        f"serving     http://{config.host}:{config.port}/",
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
