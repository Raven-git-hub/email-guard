# Email Guard review console.
#
# Unlike the scanner -- a throwaway `docker run --rm` per message -- this is a
# long-lived service, so the image is built for one: a fixed dependency set, no
# build toolchain left behind, and an unprivileged user.
#
# The bind address is deliberately NOT overridden here. The image's default is
# still `127.0.0.1`, so a bare `docker run` serves only the inside of its own
# container and cannot be published anywhere by accident. Reaching it from the
# host needs two decisions taken together -- bind the container's interface,
# publish only to the host's loopback -- and `docker-compose.yml` takes them
# three lines apart, where a reviewer can check both at once.
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# The three package roots plus the packaging metadata. `data/` is never copied
# in: the live lists and the daily brief are personal data that belongs to the
# host, mounted at runtime (root README, "Storage & privacy").
COPY pyproject.toml ./
COPY scanner/ ./scanner/
COPY dispatcher/ ./dispatcher/
COPY webui/ ./webui/
COPY config/config.json ./config/config.json

# Editable, because the served assets (`webui/static/`) live beside the package
# rather than inside it -- an editable install keeps the source layout the
# resolver in `email_guard_webui.config` expects.
RUN pip install --no-cache-dir -e ".[webui]"

# Non-root, with a fixed uid so a host bind-mount's ownership is predictable.
# Compose overrides it with the operator's own uid/gid, which is what keeps the
# lists this container writes readable on the host afterwards.
RUN useradd --system --uid 1000 --user-group --no-create-home emailguard
USER 1000

EXPOSE 8080

# The shell is unauthenticated by design, so the health check works whether or
# not a shared token is configured -- and reaches for stdlib urllib rather than
# putting curl in a service image.
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD python -c "import os,urllib.request; urllib.request.urlopen('http://127.0.0.1:' + os.environ.get('EMAIL_GUARD_WEBUI_PORT','8080') + '/').read(1)"

CMD ["python", "-m", "email_guard_webui"]
