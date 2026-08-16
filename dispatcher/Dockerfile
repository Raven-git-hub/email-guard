# Email Guard dispatcher -- the always-on process that feeds the scanner.
#
# Long-lived, unlike the scanner: it holds one IMAP connection to the Proton
# bridge, sits in IDLE waiting for mail, and launches one throwaway scanner
# container per message.
#
# The only unusual thing in here is the `docker` CLI, and it is worth being
# precise about what that does and does not mean:
#
#   * It is the *client* binary only, copied from the official docker image in
#     a build stage. No daemon, no containerd, no package-manager churn.
#   * It talks to DOCKER_HOST, which compose points at a socket-proxy on an
#     internal network. This image never gets /var/run/docker.sock bind-mounted
#     into it -- that socket is host-root-equivalent, and handing it to the
#     process that touches hostile mail would defeat the entire design.
#
# See docker-compose.yml for the proxy's allow-list and the README's "Container
# runtime" section for what that reduction does and does not buy.
FROM docker:27-cli AS dockercli

FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# EMAIL_GUARD_CONFIG is load-bearing, and its absence was a real bring-up
# failure rather than a theoretical one.
#
# Both config loaders fall back to `project_root()`, defined as
# `Path(__file__).parents[2]`. That is the repo root when running from a
# checkout -- but `/usr/local/lib/python3.11` once the package is pip-installed
# into site-packages. No config file exists there, so every *relative* path in
# config.json resolves against that prefix instead of /app, and the dispatcher
# goes looking for `/usr/local/lib/python3.11/data/lists`.
#
# ContainerRunner's startup self-check catches it loudly ("lists_dir ... is
# outside the data root"), but naming the file is the actual fix -- and it
# belongs in the image, so it holds however the image is run, not only under
# the compose file that happens to set it.
ENV EMAIL_GUARD_CONFIG=/app/config/config.json

COPY --from=dockercli /usr/local/bin/docker /usr/local/bin/docker

WORKDIR /app

# The dispatcher imports nothing from the scanner -- the runner abstraction is
# the whole interface -- but both package roots are declared in pyproject's
# `packages.find`, and a single install keeps the console scripts consistent.
# The scanner source rides along unused here; the *scanner image* is what
# actually runs it.
COPY pyproject.toml ./
COPY dispatcher/ ./dispatcher/
COPY scanner/ ./scanner/
COPY config/config.json ./config/config.json
RUN mkdir -p webui

RUN pip install --no-cache-dir . \
 && rm -rf /root/.cache

# Non-root, and load-bearing rather than hygiene: the dispatcher's own uid is
# what it hands to `docker run --user`, so a root dispatcher would produce root
# scanner containers. ContainerRunner refuses to start if that is the case.
RUN useradd --system --uid 1000 --user-group --no-create-home emailguard
USER 1000

# No HEALTHCHECK: the dispatcher serves nothing and binds no port, so there is
# nothing to probe that would not just be "the process is running", which the
# container runtime already knows. `restart: unless-stopped` covers the rest.
CMD ["python", "-m", "email_guard_dispatcher"]
