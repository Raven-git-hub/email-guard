# Email Guard rules updater -- the only component that runs git.
#
# It pulls the rules pack from a public repository, validates it, and swaps a
# symlink so the NEXT scanner container mounts the new tree. Nothing restarts:
# each message is scanned by a fresh `docker run --rm`, so there is no
# long-lived process holding the old rules.
#
# What this image deliberately does NOT have:
#
#   * the docker CLI, and no DOCKER_HOST. Unlike the dispatcher, this service
#     never creates a container, so it has no business being able to. The
#     socket-proxy's allow-list is not widened for it and /var/run/docker.sock
#     is not mounted anywhere near it.
#   * any access to the data volume. The live lists, the daily brief and the
#     dispatcher's state are personal data; a rules update and a list edit are
#     independent operations and this service touches only the former.
#
# Two apt packages, and both earn their place:
#
#   * `git`, obviously -- and note `.dockerignore` excludes `.git/` from every
#     build context, so history cannot be baked in. The clone happens at
#     runtime, into the mounted working copy.
#   * `ca-certificates`, less obviously. Without it an HTTPS fetch fails with
#     an opaque "SSL certificate problem" that reads like a network fault, and
#     python:slim does not carry the bundle git needs.
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# The updater imports nothing from the scanner, the dispatcher or the console --
# it reaches the pack only by running the pack's own `validate.py` as a
# subprocess. But all four package roots are declared in pyproject's
# `packages.find`, so the other three must exist for `pip install .` to resolve.
COPY pyproject.toml ./
COPY rules_sync/ ./rules_sync/
RUN mkdir -p scanner dispatcher webui

RUN pip install --no-cache-dir . \
 && rm -rf /root/.cache

# The mount points, created at build time so a missing volume is a clean error
# rather than a confusing one. /app/rules is the committed seed (read-only);
# /app/rules-live is the promote target and the only writable rules path in the
# whole stack.
RUN mkdir -p /rules /app/rules /app/rules-live

# Non-root, with the same fixed uid as every other service, so the tree this
# writes stays editable on the host. Compose overrides it with the operator's.
RUN useradd --system --uid 1000 --user-group --no-create-home emailguard
USER 1000

EXPOSE 8090

# Health is "a scan container starting now would find a usable pack" -- NOT
# "the last pull succeeded". An unreachable upstream, or a correctly rejected
# pack, are both states in which this service is working exactly as intended.
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
  CMD ["python", "-m", "email_guard_rules_sync.healthcheck"]

CMD ["python", "-m", "email_guard_rules_sync"]
