# Email Guard scanner -- the per-message unit.
#
# Unlike the review console, nothing built from this image is long-lived: the
# dispatcher runs one container per message with `docker run --rm`, it scans,
# it exits, it is deleted. So this image is built to be a *pure function in
# container form*, and everything variable is mounted rather than baked:
#
#   * the rules pack     -> /rules            (read-only)
#   * the live lists     -> /data/lists       (read-only)
#   * one message        -> /message/message.eml (read-only)
#   * this scan's output -> /data/outbound, /data/daily-brief
#
# Nothing personal is in the image. `data/` is excluded by .dockerignore, and
# no config file is copied either -- the dispatcher steers the scanner entirely
# through the EMAIL_GUARD_* environment the scanner already documents, so a
# baked config would only be a stale second opinion.
#
# The container this produces is run with `--read-only`, `--network none`,
# `--cap-drop ALL`, `--security-opt no-new-privileges`, a non-root user, and
# memory/pid/cpu caps. Two things here exist to keep that working:
#
#   * PYTHONDONTWRITEBYTECODE, because a read-only root filesystem cannot take
#     a __pycache__ and the interpreter would otherwise try on every import.
#   * a non-editable install, because an editable one leaves the import path
#     pointing at a source tree that then also has to be present and readable.
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Only the scanner. The dispatcher and web UI package roots are declared in
# pyproject's `packages.find`, so they are created empty rather than copied --
# the scanner image has no business containing the process that runs it.
COPY pyproject.toml ./
COPY scanner/ ./scanner/
RUN mkdir -p dispatcher webui rules_sync

# Zero runtime dependencies by design (pyproject.toml): the scanner parses mail
# with the stdlib `email` package, which is what lets this image stay small and
# run with no network at all.
RUN pip install --no-cache-dir . \
 && rm -rf /root/.cache

# The mount points, created at build time so they exist even if a mount is
# missing -- which turns "the dispatcher forgot a volume" into a clean "no
# rules pack" error rather than a confusing failure inside Docker.
RUN mkdir -p /rules /data/lists /data/outbound /data/daily-brief /message

# Non-root, with a fixed uid. The dispatcher overrides it with `--user` to its
# own uid so the report it has to collect afterwards is readable; this default
# is what a bare `docker run` of this image gets.
RUN useradd --system --uid 1000 --user-group --no-create-home emailguard
USER 1000

# ENTRYPOINT rather than CMD: the only argument this image ever takes is the
# path of the one message to scan, so `docker run <image> /message/message.eml`
# is the whole interface. stdout is the verdict JSON and nothing else.
ENTRYPOINT ["python", "-m", "email_guard"]
