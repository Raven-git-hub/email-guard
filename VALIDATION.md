# First bring-up: validating the container runtime on a real host

**Read this first: the container path has never been executed.** It was built
in an environment with a Docker *client* but no daemon (`docker version`
reports the client, then fails on `/var/run/docker.sock`). Everything reachable
without a daemon is covered by the test suite — the argv the dispatcher builds,
its hardening flags, the host-path translation, orphan reaping, output
collection, and the whole IDLE control flow. What no test here has done is
start a container, so the first run on the host is a real validation step, not
a formality.

This is the ordered sequence for that run, and the diagnosis for the two things
most likely to be wrong.

---

## 0. What this assumes

- A working Docker daemon, and a user who can reach it.
- **An existing, already-logged-in Proton Bridge.** This stack deliberately
  reuses it. Nothing below logs a bridge in, and pointing
  `EMAIL_GUARD_BRIDGE_CONFIG_DIR` at an empty directory will force the entire
  account-login and keychain dance again.
- The repository checked out on that host, since the scanner and dispatcher
  images are built from it locally.

---

## 1. Configure

```sh
cp .env.sample .env
$EDITOR .env
```

Three values have no usable default:

| Variable | What it must be |
|---|---|
| `EMAIL_GUARD_HOST_ROOT` | This repo's **absolute path on the host** — `pwd` here, on this machine |
| `EMAIL_GUARD_BRIDGE_CONFIG_DIR` | The **existing** bridge config directory |
| `EMAIL_GUARD_IMAP_USERNAME` / `_PASSWORD` | The **bridge-generated** credentials, not the Proton account password |

Find the current bridge config directory from the running bridge container:

```sh
docker inspect -f '{{range .Mounts}}{{.Source}} -> {{.Destination}}{{"\n"}}{{end}}' <bridge-container>
```

Set `EMAIL_GUARD_UID` / `EMAIL_GUARD_GID` to your own (`id -u`, `id -g`) so the
lists and reports stay hand-editable afterwards. **They must not be 0** — the
dispatcher's uid becomes the scanner container's uid, and `ContainerRunner`
refuses to start as root rather than quietly producing root sandboxes.

If host port 8080 is already taken, set `EMAIL_GUARD_WEBUI_HOST_PORT` — only
the host side moves, and the publication stays loopback-only either way.

**No override file, no edits to tracked files.** A filled-in `.env` is the
whole of the configuration; everything else is committed.

### The bridge connection — leave the defaults alone

Two values are already correct in the committed compose and are the two most
likely to be "fixed" into being wrong:

**Port 143, not 1143.** Both are real. 1143 is what the bridge listens on
inside its own container and publishes to the host when run standalone, which
is why the Proton Bridge documentation quotes it everywhere. The shenxn image
runs socat in front, exposing **143** on the container network. The dispatcher
reaches the bridge over that network, so 143 is the one that works; 1143 gets a
flat connection refusal.

**`tls=none` on that hop, deliberately.** The `mail` network is
`internal: true` — no gateway, no route off the host, nothing attached but
those two containers — which is the same reasoning that lets the dispatcher
accept the bridge's self-signed certificate over loopback.

It is not a shortcut past a better option, because there isn't one yet. The
bridge's certificate is issued for `localhost` / `127.0.0.1`, so verifying it
against the service name `bridge` fails on hostname mismatch whatever CA file
you supply — and the dispatcher deliberately has no verify-off switch, because
it refuses to silently downgrade verification for a non-loopback host. Closing
that gap needs a TLS mode meaning "encrypt, trust this specific certificate,
skip the hostname check"; it is tracked as `TODO(bridge-tls)` in
`docker-compose.yml` and in `ImapSettings.build_ssl_context`.

---

## 2. Build the images

```sh
docker compose build bridge dispatcher webui
docker compose --profile build build scanner
```

**`bridge` is built here, not pulled, and that is a fix rather than a
preference.** `shenxn/protonmail-bridge` updates the bridge binary *inside the
running container*, and the build Proton now ships needs `libfido2.so.1`, which
that image does not carry. The next restart after the self-update then fails
with `error while loading shared libraries: libfido2.so.1`, the IMAP listener
never opens, and the failure surfaces at the far end as a dispatcher stuck on
`EOF` against `bridge:143` — see the diagnosis section, which is where you will
actually meet this. `bridge/Dockerfile` installs `libfido2-1` on top of the
upstream image so a clean build-and-up survives the next auto-update too.

The scanner is under a `build` profile because it is never *run* as a service —
the dispatcher creates its containers directly. Confirm the tag the dispatcher
will ask for actually exists:

```sh
docker image inspect email-guard-scanner:0.1.0 --format '{{.Id}}'
```

If that tag and `EMAIL_GUARD_SCANNER_IMAGE` ever drift apart, every scan fails
with `No such image` — the runner reports exactly that, and names
`docker compose build scanner` as the fix.

---

## 3. Start the stack

```sh
docker compose up -d
docker compose ps
docker compose logs -f dispatcher
```

Four services should be up: `bridge`, `dispatcher`, `docker-socket-proxy`,
`webui`.

**Expect the dispatcher to log connection failures for the first few seconds.**
It starts alongside the bridge and will usually beat it to readiness, so
`could not connect (...); retrying in 2s` is normal startup, not a fault — it
backs off and waits the bridge out rather than exiting. What is *not* normal is
that message continuing indefinitely; see the diagnosis section.

In the dispatcher's log, look for these three lines before any mail moves:

```
container runner: image=email-guard-scanner:0.1.0 user=1000:1000 caps: memory=512m pids=128 cpus=1.0
host path mapping: data /app/data -> /srv/.../data, rules /app/rules -> /srv/.../rules
selected INBOX (uidvalidity=..., idle=on)
```

Check the middle line by eye. **The right-hand side of each mapping must be a
path that exists on the host** — that is the single assertion no test in this
repo can make for you.

`idle=on` confirms the bridge advertised IDLE and the connection took it.
`idle=off` is not a failure — it means polling every `poll_interval_seconds`,
which is the correctness backstop doing its job — but on Proton Bridge it is
unexpected and worth investigating.

---

## 4. Confirm the bridge is logged in

```sh
docker compose logs bridge | tail -30
```

The dispatcher's own log is the real test: a successful `selected <mailbox>`
line means it authenticated and opened the mailbox. `IMAP credentials missing`
means `.env` was not read; an authentication failure means the credentials are
the Proton account's rather than the bridge's, or the bridge lost its login.

---

## 5. Send one test message

Point the first run at a **test intake mailbox**, not a real inbox — the first
drain scans every unread message it finds.

```sh
# with EMAIL_GUARD_IMAP_MAILBOX=Intake in .env
docker compose restart dispatcher
```

Then send a message to the account from an address on **no** list, so it also
exercises the daily-brief candidate path. Watch:

```sh
docker compose logs -f dispatcher
```

### Catch the container while it runs

In a second terminal, immediately after sending:

```sh
watch -n0.5 'docker ps --filter label=email-guard.role=scanner --format "{{.Names}} {{.Status}}"'
```

A container named `email-guard-scan-<token>` should appear and vanish within a
few seconds. Seeing it appear is the proof that the whole path works; seeing it
*vanish* is the proof `--rm` is doing its job.

---

## 6. The checks that prove it actually worked

**A scanner container really ran, and really was hardened.** Catch one
mid-flight and inspect it:

```sh
docker inspect $(docker ps -q --filter label=email-guard.role=scanner) \
  --format '{{.HostConfig.NetworkMode}} {{.HostConfig.ReadonlyRootfs}} {{.Config.User}} {{.HostConfig.Memory}} {{.HostConfig.PidsLimit}} {{.HostConfig.CapDrop}}'
```

Expect `none true 1000:1000 536870912 128 [ALL]`.

**It removed itself.** After the scan settles, this must be empty:

```sh
docker ps -a --filter label=email-guard.role=scanner
```

Anything left here means containers are leaking. They would be reaped on the
next dispatcher start, but a *steady* accumulation while running is a bug.

**A report was filed.** On the host:

```sh
find data/outbound -newermt '-5 minutes' -name report.json
```

One `data/outbound/<bucket>/<job>/report.json` plus a `message.eml` beside it.
This is also the proof that the private per-scan output directory was collected
correctly — the scanner wrote into its own spool, and the dispatcher moved it
here.

**A candidate was staged** (unknown sender only):

```sh
find data/daily-brief -newermt '-5 minutes' -name candidate.json
```

**The state file recorded it, and survives a recreate.** This is the
at-least-once guarantee's anchor:

```sh
cat data/dispatcher/state.json
docker compose up -d --force-recreate dispatcher
cat data/dispatcher/state.json     # unchanged: the named volume held
```

A state file that empties on recreate means the volume is misconfigured, and
the next drain would rescan the whole mailbox and re-fire every webhook.

**The console sees it:**

```sh
open "http://127.0.0.1:${EMAIL_GUARD_WEBUI_HOST_PORT:-8080}/"
```

**On-arrival latency.** Send a second message and watch the timestamps. The
drain should begin within a second or two, not at the next 30-second poll. If
it consistently waits the full `poll_interval_seconds`, IDLE is not firing —
which costs latency only, and is worth chasing but is not urgent.

---

## 7. Optional: onboard the existing mailbox with `--rescan`

Everything above validates the *live* path, which only ever sees unread mail.
`--rescan` is the one-shot that sorts what is already there — the whole
mailbox, `\Seen` or not, watermark or not.

**Stop the dispatcher first.** It is a one-shot, not a second worker; two
processes scanning one mailbox fire each other's webhooks and race on the
scanner's output directories.

```sh
docker compose stop dispatcher

# a trial subset, no webhooks, one container per message
docker compose run --rm dispatcher python -m email_guard_dispatcher \
  --rescan --limit 20 --verbose
```

Watch the progress lines (`rescan 7/20: uid=... level=3 bucket=flagged`) and
read the summary at the end:

```
rescan: mailbox=2841 scanned=20 failed=0 cleared=14 flagged=5 rejected=1 candidates=3 (limit=20)
```

Then confirm on the host that it re-filed and re-staged exactly as a drain
does, and — the part worth checking deliberately — that it disturbed **nothing**:

```sh
find data/outbound -newermt '-10 minutes' -name report.json | wc -l   # ~20
find data/daily-brief -newermt '-10 minutes' -name candidate.json | wc -l
sha256sum data/dispatcher/state.json    # unchanged by the re-scan
```

The state file must be byte-identical afterwards. A re-scan records nothing in
the done-list, marks nothing `\Seen` and quarantines nothing — so when the
dispatcher is started again it resumes with the semantics it had before, and
mail that was unread is still unread and still waiting for it.

Drop `--limit` for the full pass, and expect it to take a long time: one
hardened container per message, sequential. Add `--emit-webhooks` to also POST
each verdict, which is how the recognised, tagged backlog gets injected into a
downstream as onboarding — read the next section before doing that, because the
URL that works is usually not the obvious one.

```sh
docker compose start dispatcher      # back to the live loop
```

---

## 8. Optional: webhook delivery

`EMAIL_GUARD_WEBHOOK_URL` in `.env` is passed through to the dispatcher
(`"${EMAIL_GUARD_WEBHOOK_URL:-}"`). Unset, no webhook sink is built at all and
the dispatcher stays egress-free — which is the committed default and the right
one for a process that handles hostile mail.

**(a) The target runs on this host** (n8n, typically). Reach it over *that
service's* docker network, by service name, on its *internal* port —
`http://n8n:5678/webhook/...` — and attach the dispatcher to that network with
an override:

```yaml
# docker-compose.override.yml
services:
  dispatcher:
    networks: [mail, dockerproxy, n8n]
networks:
  n8n:
    external: true
    name: n8n_default        # `docker network ls` for the real name
```

Verify the hop before trusting it:

```sh
docker compose exec dispatcher python -c \
  "import socket;socket.create_connection(('n8n',5678),5);print('reachable')"
```

Pointing at the *public* hostname instead sends the POST out of the host and
back in through the edge, for a service two containers away — and puts the
delivery in front of whatever bot filter the edge runs. **Cloudflare answers a
bare container-issued POST with `error 1010`**, which the sink logs as an HTTP
failure that says nothing about why, and the event is dropped after its
retries. If webhook attempts fail with a 403 and the target works fine from a
browser, this is what happened.

**(b) The target is off-host.** Then it needs a public URL *and* egress, which
the dispatcher does not have:

```yaml
# docker-compose.override.yml
services:
  dispatcher:
    networks: [mail, dockerproxy, egress]
```

Without it the dispatcher is on two `internal: true` networks only, so an
off-host URL fails DNS rather than failing to authenticate.

Both are override patterns and neither is committed: giving the dispatcher a
route off the host is a deliberate decision, made in a file that is not tracked.

---

## Diagnosis

### The socket-proxy allow-list is too short

**Symptom.** The dispatcher logs a docker failure mentioning `403`, or
`request returned Forbidden for API route`, on every scan.

**This is a configuration fix, not a code fix.** The allow-list in
`docker-compose.yml` starts as tight as it can plausibly be: `CONTAINERS=1` and
`POST=1` and nothing else. `docker run` may also inspect the local image before
creating a container, which that pair does not cover.

The first thing to try, and usually the only one needed:

```yaml
# docker-compose.yml, service docker-socket-proxy
IMAGES: 1
```

then `docker compose up -d docker-socket-proxy`. Confirm what was actually
refused before widening anything further:

```sh
docker compose logs docker-socket-proxy | grep -i 403
```

Add only what a refused call names. Do not enable `EXEC`, `VOLUMES`,
`NETWORKS` or `SYSTEM` speculatively — each is a genuine widening of what a
compromised dispatcher could reach, and none of them is needed to run a scan.

### The host-path mapping is wrong

**Symptom — and this is the one to recognise, because it does not look like a
mount problem at all.** Scans fail with a rules-pack or lists error: exit 2, or
`no rules pack at /rules`. The container started fine. It simply found empty
directories, because the daemon resolved the mount source on the host and there
was nothing there.

**Confirm it:**

```sh
docker compose exec dispatcher printenv | grep EMAIL_GUARD_HOST
ls "$EMAIL_GUARD_HOST_ROOT/rules"      # on the HOST, not in a container
ls "$EMAIL_GUARD_HOST_ROOT/data/lists"
```

If those `ls` commands fail, `EMAIL_GUARD_HOST_ROOT` is wrong. It must be the
repository's absolute path **on the machine running the daemon** — not a path
inside any container, and not relative.

Then verify what a scan actually asks for. Run the scanner image by hand with
the same mounts:

```sh
docker run --rm --network none --read-only \
  --user "$(id -u):$(id -g)" --cap-drop ALL --security-opt no-new-privileges \
  -v "$EMAIL_GUARD_HOST_ROOT/rules:/rules:ro" \
  -v "$EMAIL_GUARD_HOST_ROOT/data/lists:/data/lists:ro" \
  -v "$PWD/tests/fixtures/eml/simple.eml:/message/message.eml:ro" \
  -e EMAIL_GUARD_RULES_DIR=/rules -e EMAIL_GUARD_LISTS_DIR=/data/lists \
  email-guard-scanner:0.1.0 /message/message.eml
```

A verdict on stdout means the image and the mount model are both sound and the
problem is in what the dispatcher is passing. An error means the paths
themselves are wrong.

**Rootless Docker and Docker Desktop** are the known-unverified cases. Under
rootless Docker the daemon's filesystem view is not the host's, and under
Docker Desktop (macOS/Windows) bind sources are resolved inside the VM. Neither
was available to test against; if either is in play, treat the manual
`docker run` above as the authoritative check before trusting the stack.

### The dispatcher never connects: `EOF`, or connection refused, forever

Two different causes, and the logs distinguish them.

**`EOF` / `abort: socket error: EOF`** almost always means the bridge is up but
has never authenticated, so its IMAP listener is not accepting sessions. Check
the bridge, not the dispatcher:

```sh
docker compose logs bridge | grep -i "proton\|lookup\|login\|listen"
```

`error while loading shared libraries: libfido2.so.1` means the bridge
auto-updated itself into a binary the base image cannot run. This is the one
failure here that appears without anything changing on your side, and it will
recur — the update happens inside the container. The fix is the committed
`bridge/Dockerfile`; if the bridge service is still running the upstream image
directly, rebuild it:

```sh
docker compose build bridge && docker compose up -d bridge
docker compose exec bridge ldconfig -p | grep -c libfido2   # expect 1 or more
```

`lookup mail-api.proton.me ... server misbehaving` means the bridge has no
egress. It must be on the non-internal `egress` network as well as `mail` —
that is committed, so if it is missing, something overrode it:

```sh
docker inspect email-guard-bridge -f '{{range $n, $_ := .NetworkSettings.Networks}}{{$n}} {{end}}'
```

Expect both `..._mail` and `..._egress`.

**`ConnectionRefused`** with a healthy, authenticated bridge is usually the
port. It must be **143** over the container network, not 1143 — see "The bridge
connection" above. Confirm what the dispatcher is actually using and that the
port answers:

```sh
docker compose exec dispatcher printenv EMAIL_GUARD_IMAP_PORT
docker compose exec dispatcher python -c \
  "import socket;s=socket.create_connection(('bridge',143),5);print(s.recv(100))"
```

A `* OK` greeting means the hop is fine.

### The socket-proxy restarts in a loop

```sh
docker compose logs docker-socket-proxy | tail -20
```

`can't create /tmp/haproxy.cfg: Read-only file system` means the `tmpfs` entries
are missing. The proxy renders its haproxy config at startup, so it needs
writable `/tmp` and `/run` even though — and this is the point — its root
filesystem stays read-only. Both are committed.

### The web UI shows nothing, or the dispatcher reports a path under `/usr/local`

The signature is a path like `/usr/local/lib/python3.11/data/lists`. Both config
loaders fall back to `Path(__file__).parents[2]`, which is the repo root from a
checkout but the *install prefix* inside an image — so with no config file
found, every relative path in `config.json` resolves under that prefix.

The dispatcher fails loudly on it (`lists_dir ... is outside the data root`);
the console would just quietly show an empty queue. Both images set
`EMAIL_GUARD_CONFIG=/app/config/config.json` to prevent it. Verify:

```sh
docker compose exec dispatcher printenv EMAIL_GUARD_CONFIG
docker compose exec webui printenv EMAIL_GUARD_CONFIG
docker compose exec webui ls /app/config/config.json
```

If the variable is set but the file is missing, the bind mount of
`./config/config.json` did not land.

### The scanner writes nothing, and the report never appears

Check the spool is being created and cleaned:

```sh
ls -la data/dispatcher/scan-spool/
```

Directories accumulating here mean collection is failing — usually a
permissions mismatch, where the scanner container's uid cannot write into a
spool directory the dispatcher created. Both should be
`EMAIL_GUARD_UID:EMAIL_GUARD_GID`; confirm with `docker compose exec dispatcher id`.

### Orphaned containers after a hard kill

By design: `--rm` only fires on a clean exit, so a dispatcher killed mid-scan
leaves its container running. Restarting the dispatcher reaps them before it
drains, and logs `reaped N orphaned scan container(s)`. To verify deliberately,
`docker kill` the dispatcher mid-scan, restart it, and look for that line.

---

## What is still unproven after all of the above

Even a clean run of this runbook leaves these untested by anything in the repo:

- Behaviour under **concurrency** — `concurrency: 4` means up to four scanner
  containers alive at once, and therefore ~4× the per-container caps. The
  aggregate is documented in the README, but only a real backlog exercises it.
- **Long-running IDLE**: whether the connection survives hours of re-issued
  IDLE against the real bridge, and whether the bridge drops it in ways the
  reconnect path handles gracefully.
- **A large first drain**: one container per message, in sequence — materially
  slower than the subprocess path. Expected, not a fault. The same applies to
  `--rescan` over a real inbox, at a much larger multiple.
- **The bridge's `libfido2` fix under an actual auto-update.** The library is
  installed and the image builds, but the sequence that matters — bridge
  self-updates, container restarts, IMAP comes back — only plays out over days
  on a live host.
- **Webhook delivery over a real network**, in either pattern. The
  `error 1010` case above is a live-run finding, not something the suite can
  reproduce.
- Rootless Docker, Docker Desktop, and SELinux-enforcing hosts (which may
  require `:z` / `:Z` on the bind mounts).
