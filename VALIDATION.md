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

### TLS to the bridge

Under compose the bridge is reached at the service name `bridge`, not
`127.0.0.1`, so the loopback exemption that lets its self-signed certificate
through no longer applies and verification is enforced. Copy the bridge's
certificate into the repo and name it:

```sh
cp "$EMAIL_GUARD_BRIDGE_CONFIG_DIR"/cert.pem config/bridge-cert.pem   # path varies
# in .env:
EMAIL_GUARD_IMAP_CA_FILE=/app/config/bridge-cert.pem
```

The exact filename inside the bridge config directory is one of the things this
runbook cannot state with certainty — look for a `cert.pem` / `*.crt`. If you
cannot locate it, `EMAIL_GUARD_IMAP_TLS=none` is the documented fallback: that
hop is an `internal: true` network with no route off the host, but it *is* a
downgrade and the bridge password crosses it. Prefer the CA file.

---

## 2. Build both images

```sh
docker compose build dispatcher webui
docker compose --profile build build scanner
```

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
`webui`. In the dispatcher's log, look for these three lines before any mail
moves:

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
open http://127.0.0.1:8080/
```

**On-arrival latency.** Send a second message and watch the timestamps. The
drain should begin within a second or two, not at the next 30-second poll. If
it consistently waits the full `poll_interval_seconds`, IDLE is not firing —
which costs latency only, and is worth chasing but is not urgent.

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
  slower than the subprocess path. Expected, not a fault.
- Rootless Docker, Docker Desktop, and SELinux-enforcing hosts (which may
  require `:z` / `:Z` on the bind mounts).
