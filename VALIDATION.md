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

**The job is marked finished, and marked finished LAST.** Every job directory,
in every bucket, ends with an empty `.complete` sentinel:

```sh
ls -la data/outbound/*/*/
```

`.complete` is the "safe to publish" signal — nothing acts on a job directory
without it. If it is ever present while `report.json` is not, something is
writing out of order, and the host publisher (§11) must not be enabled until
that is understood.

**A cleared message's attachments are on disk, intact.** Send yourself a
message from a greylisted sender with two attachments, then verify every file
against the manifest the report carries:

```sh
ls data/outbound/cleared/*/          # report.json, message.eml, the files, .complete

python3 -c '
import glob, hashlib, json, pathlib
for report in glob.glob("data/outbound/cleared/*/report.json"):
    job = pathlib.Path(report).parent
    for item in json.loads(pathlib.Path(report).read_text())["extracted_attachments"]:
        blob = (job / item["stored_name"]).read_bytes()
        ok = hashlib.sha256(blob).hexdigest() == item["sha256"] and len(blob) == item["size"]
        print("OK " if ok else "BAD", job.name, item["original_name"], "->", item["stored_name"])
'
```

Every line must say `OK`. The `->` is worth reading: the left side is the name
the *sender* chose and the right side is the sanitised name on disk. They differ
whenever the sender's name contained a path, unicode, or one of the package's
own filenames — that is the sanitiser working, not a fault.

**Quarantined mail materialises nothing.** A `flagged` or `rejected` job has the
report, the verbatim message and the sentinel, and no extracted files:

```sh
ls data/outbound/flagged/*/ data/outbound/rejected/*/
```

The whole message is still there inside `message.eml` for a human reviewer. What
is not there is an attacker's file sitting on disk under a name of its choosing.

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

## 9. The rules auto-updater, and cutting over to it

The `rules-updater` service pulls the rules pack from GitHub, validates it, and
promotes it by swapping a symlink. Nothing restarts when it does: each message is
scanned by a fresh `docker run --rm` that mounts the rules directory at scan
time, so the next message picks up the new pack on its own.

It comes up with the stack and starts working immediately, but **it changes
nothing that scans until you cut the mounts over** — that is step 9.4, and it is
a deploy-time change, not something the code does for you.

### 9.0 Before the first `up`: own the live tree

`rules-live/` is the updater's only writable path, and it is a bind mount. **If
the directory is missing when the stack starts, docker creates it root-owned** —
and the updater runs as `EMAIL_GUARD_UID:EMAIL_GUARD_GID`, so it cannot write a
single byte into it. The repository ships `rules-live/.gitkeep` so a fresh clone
already owns the directory; a deploy that copied the tree without dotfiles, or
created the path by hand as root, will not:

```sh
ls -ld rules-live
mkdir -p rules-live
sudo chown -R "${EMAIL_GUARD_UID:-1000}:${EMAIL_GUARD_GID:-1000}" rules-live
```

The symptom if you skip it is one line in `docker compose logs rules-updater`,
and the service exiting rather than looping on it:

```
rules updater cannot start: /app/rules-live is not writable by uid 1000:1000
(Permission denied). Docker creates a missing bind source root-owned; chown it
on the host to EMAIL_GUARD_UID:EMAIL_GUARD_GID — sudo chown -R …
```

### 9.1 Confirm it seeded itself

**The live tree serves the committed pack before any pull has succeeded.** On
first start the updater copies `./rules` into `rules-live/` and points `current`
at it, so the promote target is never empty:

```sh
docker compose up -d rules-updater
docker compose logs rules-updater | tail -20
readlink rules-live/current
```

Expect a log line `seeding the live rules tree from the committed pack`, and a
readlink of `releases/seed/rules` — or `releases/<sha>/rules` if a pull has
already landed.

**The symlink must be relative.** If `readlink` prints something starting with
`/`, stop: an absolute target resolves only in whichever filesystem wrote it and
will dangle inside the dispatcher and inside every scan container.

**The promoted tree is a valid pack**, checked with the same validator the engine
runs on load:

```sh
python rules/validate.py rules-live/current
```

Expect `rules pack OK`.

### 9.2 Trigger a manual pull and read the result

From the console: open the **Config** panel and click **Refresh rules**. The
panel shows the live commit, the last-pull time, and the outcome of the click.

The equivalent from the host, which is also the way to see the whole structured
result:

```sh
curl -sS -X POST http://127.0.0.1:${EMAIL_GUARD_WEBUI_HOST_PORT:-8080}/api/rules/refresh \
     -H "X-Email-Guard-Token: $EMAIL_GUARD_WEBUI_TOKEN" | python -m json.tool
```

(Drop the `-H` if no console token is configured.)

`status` is the field that matters, and every value below is an HTTP 200 — a
refused pack is the updater working, not a broken button:

| `status` | What happened |
|---|---|
| `updated` | A new commit was validated and promoted. `new_commit` is now live. |
| `no_change` | Upstream is already the promoted commit. Nothing was staged or swapped. |
| `rejected` | The pulled pack failed validation. **The live pack is unchanged** and `validation_errors` says why. |
| `busy` | Another pull held the lock. Nothing was changed. |
| `error` | The pull could not run — unreachable host, missing branch. `message` says which. |

Running it a second time immediately must return `no_change`. If it returns
`updated` twice for the same upstream commit, the promote is not idempotent and
something is wrong.

> **A `rejected` commit is remembered, and the next pull does not re-check it.**
> The refusal is recorded in `rules-live/state.json` as `last_rejected_commit`,
> and a later pull that finds upstream still on that commit replays the stored
> errors without refetching or re-validating — deliberately, so a stuck feed
> keeps saying so instead of quietly costing a fetch every interval.
>
> The consequence is that **fixing the problem is not enough to clear it** if the
> problem was in the updater rather than in the pack — a rebuilt image still
> short-circuits on the remembered verdict, and the upstream commit has not
> changed to dislodge it. Forget the verdict, then pull again:
>
> ```sh
> docker compose stop rules-updater
> sudo rm -rf rules-live/state.json rules-live/releases rules-live/current
> docker compose up -d rules-updater      # re-seeds, then re-evaluates the commit
> ```
>
> Removing `state.json` alone is enough to force a re-evaluation; the rest is
> only there to leave a clean tree. `rules-live/work/` may be kept — it is just
> a git working copy and re-cloning it costs a fetch.

### 9.3 Prove a bad pack cannot go live

**A rejected pull leaves the live pack exactly as it was.** This is the drill
worth doing once on a real host, because it is the guarantee the whole design
rests on. On a scratch branch of the rules repo, commit a deliberately broken
rule — `echo 'not json' > rules/scan/level2.json` — then point the updater at it:

```sh
# docker-compose.override.yml, or just in .env
#   EMAIL_GUARD_RULES_BRANCH=broken-on-purpose
docker compose up -d rules-updater
readlink rules-live/current          # note this value
docker compose run --rm rules-updater python -m email_guard_rules_sync --once
readlink rules-live/current          # must be UNCHANGED
```

Expect exit code 2, `"status": "rejected"`, the validator's own error text in
`validation_errors`, and an identical `readlink` before and after. Scanning
continues on the known-good pack throughout.

The opposite half is worth confirming too: corrupt
`rules/reference/injection_signatures.json` instead and the pull **succeeds**,
with a warning. The signature feed fails open on purpose — a truncated download
must cost sensitivity, not stop the mail.

### 9.4 Cut over to the managed rules tree

Until this step, the scanner still reads the committed `./rules` and pulls change
nothing that scans. Repoint both mounts by setting two variables in `.env`:

```sh
EMAIL_GUARD_RULES_LIVE_NAME=rules-live
EMAIL_GUARD_RULES_LIVE_POINTER=/current
```

**Order matters.** `rules-live/current` must exist first, or the dispatcher
refuses to start on a rules directory that is not there:

```sh
docker compose run --rm rules-updater python -m email_guard_rules_sync --once
readlink rules-live/current          # must print releases/<something>/rules
docker compose up -d dispatcher
```

Confirm the dispatcher took the new mount:

```sh
docker compose exec dispatcher printenv EMAIL_GUARD_HOST_RULES_DIR
docker compose exec dispatcher ls /app/rules/current/scan
```

Expect a path ending `/rules-live/current`, and the three `levelN.json` files.

> **Why the bind is `rules-live/`, not `rules-live/current`.** A bind mount of a
> symlink is resolved once, by the daemon, when the container starts — the
> container gets the release the link pointed at *then*, and a later swap is
> invisible to it forever. Binding the directory mounts the directory itself, so
> `current` is an entry inside it and the next path walk sees the new target.
> That is why `EMAIL_GUARD_RULES_LIVE_POINTER` moves the `/current` onto the
> container path instead of into the bind.
>
> Scan containers are the opposite case and are already handled: each is created
> fresh per message, so the daemon resolving `.../current` at create time gives
> that container one immutable release for its whole life. A promote landing
> mid-scan cannot affect a scan already running.

### 9.5 Confirm the next scan actually used the new rules

This is the check that closes the loop — everything above proves the *files*
moved, not that a scan read them.

```sh
# 1. what is live right now
readlink rules-live/current

# 2. send a test message, then catch its container mid-flight
docker inspect $(docker ps -q --filter label=email-guard.role=scanner) \
  --format '{{range .Mounts}}{{.Source}} -> {{.Destination}} (rw={{.RW}}){{"\n"}}{{end}}'
```

Expect a line whose source resolves to the release from step 1, destination
`/rules`, and **`rw=false`**. The scanner only ever reads the rules; the updater
is the only component in the stack with a writable rules mount.

If the source still ends in a plain `/rules`, the cutover in 9.4 has not taken
effect — the dispatcher was not recreated after the `.env` edit.

### 9.6 Confirm the blast radius

**A rules pull touches the rules and nothing else.** The live lists are personal
data, are never in git, and no part of this feature can reach them:

```sh
docker inspect email-guard-rules-updater \
  --format '{{range .Mounts}}{{.Source}} -> {{.Destination}} (rw={{.RW}}){{"\n"}}{{end}}'
```

Expect exactly two mounts — `rules-live` read-write and `rules` read-only — and
**no** `data` volume and **no** `/var/run/docker.sock`. The updater creates no
containers, so it has no docker access at all.

---

## 10. The rule-tuning loop

§9 proves a pulled pack **loads**. Nothing in it proves the pack **classifies**
correctly — a rule that parses perfectly and quarantines every bank in the
country passes validation with no complaint. This section is the other half:
label a corpus of your own mail, score the pack against it, and only push when
nothing dangerous gets through.

```
   import ──▶ review ──▶ run ──▶ read ──▶ push ──▶ (§9 promotes it)
              ▲                    │
              └────── fix a rule ──┘
```

The harness is a dev/ops tool. It is not in any image, the scanner does not
import it, and it adds no dependency — it classifies by calling the same
`scan_parsed` the live scanner calls.

> **Privacy first.** A corpus is a directory of whole messages from real people.
> The operator's corpus lives at `data/eval-corpus/`, which is gitignored, and
> the harness *refuses to run* a corpus of real mail that git is not ignoring.
> The committed corpus at `tests/eval-corpus/` is synthetic-only — invented
> senders on reserved `.example` domains — and the harness refuses to import
> real mail into it. `tests/test_eval_privacy.py` fails the build if any `.eml`
> is tracked outside those synthetic directories.

### 10.1 Import what the scanner has already stored

Every scan writes `data/outbound/<bucket>/<job>/message.eml`, so the raw
material has been accumulating since the first message. Copy it into corpus
shape:

```sh
python -m email_guard.eval --import-from-outbound data/outbound data/eval-corpus
```

This copies each message verbatim, pre-fills `expected_bucket` with the bucket
it landed in, marks every case `"reviewed": false`, and freezes a copy of your
current lists into `data/eval-corpus/lists/` (once — the frozen context is half
of what a label means, so a later import never re-points old cases at edited
lists).

Re-running it is safe: cases already in the corpus are left untouched, so a week
of reviewing is not reset by the next import.

### 10.2 Review and label — the step that does the work

**The imported bucket is a guess, not an answer.** The reason you are building
this is that the scanner mis-scores real mail; grading it against its own past
output would score it as perfect and freeze today's mistakes in as the answer
key. Unreviewed cases are *not graded*, and the harness says how many are
waiting.

For each case, open `data/eval-corpus/cases/<id>/` and read `message.eml`, then
edit `expected.json`:

```json
{
  "expected_bucket": "cleared",
  "expected_level": 4,
  "reviewed": true,
  "synthetic": false,
  "note": "routine statement notice from my bank; must not be quarantined"
}
```

* `expected_bucket` — `cleared`, `flagged` or `rejected`. **What should have
  happened**, which is often not what did.
* `expected_level` — optional. Worth setting when the bucket is too coarse:
  levels 4 and 5 both mean `cleared`.
* `note` — why. In six months this is the only record of the judgement.
* `reviewed: true` — the assertion that a human decided. Until it is set, the
  case is skipped.

Start with the mail that annoyed you. A dozen well-chosen cases beat two hundred
unreviewed ones.

### 10.3 Run the harness

```sh
python -m email_guard.eval data/eval-corpus
python -m email_guard.eval data/eval-corpus --json before.json    # keep a baseline
```

### 10.4 Read the scorecard

```
graded 42  |  passed 38  failed 4  (dangerous 1, advisory 3)

confusion matrix
  expected \ actual      cleared   flagged  rejected
  cleared                     21         2         1
  flagged                      1        11         0
  rejected                     0         0         6

FAILURES

  [DANGEROUS] rejected-a1b2-phisher.example
      expected rejected, got cleared
      levels:   initial 3 -> final 4
      decided:  deep-scan (level 3 -> 4), greylist (known)
      because:  triage: initial level 3 (greylist_new_structure) || pass1-level3: ...
```

Read it in this order:

1. **Dangerous count.** Anything above zero means mail the corpus says should
   have been held back reached `cleared`. Fix it before pushing.
2. **The confusion matrix.** The shape of the mistakes. Weight down the
   `cleared` column is over-blocking; weight in the `cleared` column on a
   `flagged`/`rejected` row is the dangerous kind.
3. **Each failure.** The `decided:` line says which half of the pipeline settled
   it and which list was involved, and `because:` is the engine's own forensic
   log — usually enough to name the rule without opening the message.

**Exit codes**, which is what makes this usable from a hook or CI:

| Code | Meaning |
|---|---|
| `0` | No dangerous false-clears. Advisory failures may be present, printed in full. |
| `1` | At least one **dangerous** false-clear. Do not push. |
| `2` | The run could not happen — bad corpus, invalid pack, real corpus in a committable location. |

Over-blocking does not fail the run, deliberately. Tightening a rule nearly
always costs a few over-blocks before it is tuned, and a gate that fires on that
is a gate people learn to bypass. Letting bad mail into `cleared` is the failure
worth blocking a push over.

### 10.5 Change a rule, and see exactly what moved

```sh
# edit rules/scan/level3.json, rules/assess/level3.py, ...
python -m email_guard.eval data/eval-corpus --baseline before.json
```

```
FIXED (2):
  + cleared-c3d4-mybank.example
  + cleared-e5f6-invoices.example
NEWLY BROKEN (1):
  - rejected-g7h8-phisher.example

  !! 1 case(s) became DANGEROUS false-clears: rejected-g7h8-phisher.example
```

That is the question the harness exists to answer, in one command. A deleted
case is reported as `removed`, never as `fixed` — deleting the failing case and
fixing it must not look the same.

### 10.6 Only then push

```sh
python -m email_guard.eval data/eval-corpus && \
python -m pytest tests/test_eval_corpus.py && \
git push
```

The first command is your mail; the second is the committed synthetic corpus,
which guards the shared behaviours for everyone. Once pushed, §9 takes over: the
updater pulls the commit, validates that it loads, and promotes it.

Two gates, and they check different things. Neither replaces the other.

### 10.7 Engine changes do **not** ride the auto-updater

§9 promotes the **rules pack** — `rules/`, and the lists. Everything under
`scanner/` is the engine, it is baked into the scanner image, and a `git push`
moves it not at all. A change there is live only after a rebuild on the host:

```sh
# on cerberus
git pull
docker compose --profile build build scanner   # or: docker compose build
```

Nothing needs restarting afterwards — every scan is a fresh container, so the
next message picks up the new image. See "Updating the scanner" in the README
for why restarting the dispatcher does nothing.

The trap is that the two look identical from a laptop: tests pass, the push
succeeds, the updater reports a clean pull — and the behaviour on the host is
unchanged, because what changed was never in the pack. If a fix does not appear
live and the tests say it should have, check which side of that line it is on
before reaching for anything else.

**Known engine changes awaiting a rebuild:**

| Change | Lands in | Needs |
|--------|----------|-------|
| `hidden_unicode` precision — zero-width padding no longer rejects, word-internal splits and hidden phrasing still do (`scanner/email_guard/triage.py`) | scanner image | `docker compose build` on cerberus |
| Attachment extraction for cleared mail + the `.complete` sentinel (`scanner/email_guard/attachments.py`, `route.py`) | scanner image | `docker compose build` on cerberus. Until it is rebuilt, jobs carry no sentinel and the publisher (§11) correctly publishes nothing. |
| Sentinel ordering when a scan container's output is merged into the shared tree (`dispatcher/email_guard_dispatcher/container_runner.py`) | dispatcher image | `docker compose build dispatcher && docker compose up -d dispatcher` |

The host publisher and the retention sweep (§11) are the opposite case: they are
**not** in any image, so they need no rebuild at all — `install` the units and
`systemctl enable` them.

---

## 11. Publishing to the acheron partition

Everything above stops at local disk. This section installs the two **host**
units that carry a finished job across to `/mnt/network/acheron`, where the
downstream machine ("Smiley") consumes it — and proves each guarantee that
matters, including the ones that only show up when the network is down.

Read the boundary first, because it is the thing not to undo: **the containers
never mount acheron.** There is no volume for it in `docker-compose.yml`, no
environment variable naming it, and the publisher's code is not installed into
any image. The scanner handles hostile mail; the host publisher touches the
share; those are different processes with different privileges, and that
separation is the whole design. If you ever find yourself adding
`/mnt/network/acheron` to a compose service to "make it simpler", stop — that is
the failure this feature exists to prevent.

### 11.0 Before you start

```sh
# the partition is mounted, and uid 1000 can write it
mountpoint /mnt/network/acheron
sudo -u '#1000' test -w /mnt/network/acheron && echo writable

# the destination root exists and is owned by the same uid the containers use
sudo install -d -o 1000 -g 1000 -m 0755 /mnt/network/acheron/email-guard
```

If the mount is absent, everything below still installs cleanly and simply does
nothing: jobs accumulate locally, unpublished, until it comes back. That is the
designed behaviour, not a degraded mode.

### 11.1 Configure

One `EnvironmentFile`, read by both units, so the paths and the retention window
cannot skew between them:

```sh
cd /opt/email-guard          # wherever EMAIL_GUARD_HOST_ROOT points
sudo install -d -m 0755 /etc/email-guard
sudo install -m 0644 publisher/systemd/publisher.env.sample /etc/email-guard/publisher.env
sudoedit /etc/email-guard/publisher.env
```

Set the two paths. The first is the one people get wrong:

| Variable | Set it to | Note |
|----------|-----------|------|
| `EMAIL_GUARD_OUTBOUND_DIR` | `${EMAIL_GUARD_HOST_ROOT}/data/outbound` | The **host** path — the bind source of the `email-guard-data` volume. **Not** `/app/data/outbound`, which is what a container sees. |
| `EMAIL_GUARD_PUBLISH_DEST` | `/mnt/network/acheron/email-guard` | Must be on the mounted partition: the copy is staged inside it so the last step can be an atomic rename, and a rename cannot cross a filesystem. |
| `EMAIL_GUARD_PUBLISH_BUCKETS` | *(optional)* | All three by default. `cleared` alone keeps quarantined mail on this host. |
| `EMAIL_GUARD_OUTBOUND_RETENTION_DAYS` | *(optional)* | Default 14. |

Check it before installing anything — this reads the configuration, lists the
backlog, and changes nothing:

```sh
sudo -u '#1000' env $(grep -v '^#' /etc/email-guard/publisher.env | xargs) \
     PYTHONPATH=/opt/email-guard/publisher \
     python3 -m email_guard_publisher status
```

Expect the two paths you set, the bucket list, the retention window, and a count
of pending jobs (every job scanned so far, since none has been published yet).
A `configuration error:` line here means the file is wrong; fix it before going
on. The one it refuses outright is a destination that overlaps the source tree
— publishing a tree into itself would let the retention sweep delete the
published copy.

### 11.2 Install the units

```sh
sudo cp publisher/systemd/email-guard-publisher.path    /etc/systemd/system/
sudo cp publisher/systemd/email-guard-publisher.service /etc/systemd/system/
sudo cp publisher/systemd/email-guard-publisher.timer   /etc/systemd/system/
sudo cp publisher/systemd/email-guard-cleanup.service   /etc/systemd/system/
sudo cp publisher/systemd/email-guard-cleanup.timer     /etc/systemd/system/
```

**Then edit the absolute paths inside them.** systemd cannot expand the
`EnvironmentFile` into unit *directives*, so three of them are literal and must
match this host:

- `PathModified=` in `email-guard-publisher.path` — three lines, one per bucket,
  under your real `data/outbound`;
- `ReadWritePaths=` in `email-guard-publisher.service` — the outbound tree and
  the partition;
- `ReadWritePaths=` in `email-guard-cleanup.service` — the outbound tree, and
  deliberately **not** the partition.

Also check `User=` / `Group=` (1000 by default, matching `EMAIL_GUARD_UID`) and
`WorkingDirectory=` / `PYTHONPATH=` (`/opt/email-guard` and its `publisher/`
subdirectory). Then:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now email-guard-publisher.path
sudo systemctl enable --now email-guard-publisher.timer
sudo systemctl enable --now email-guard-cleanup.timer

systemctl list-timers 'email-guard-*'
systemctl status email-guard-publisher.path
```

Nothing is pip-installed and no image is rebuilt: the publisher is stdlib-only
and runs straight from the checkout.

### 11.3 Prove one job crosses

```sh
# drain whatever is already pending
sudo systemctl start email-guard-publisher.service
journalctl -u email-guard-publisher.service -n 30 --no-pager
```

Expect a line per job (`published cleared/<job> -> /mnt/network/acheron/...`)
and a summary. Then check both sides:

```sh
# the package landed, at the deterministic path
ls /mnt/network/acheron/email-guard/cleared/<job>/

# the local job is marked, and unchanged otherwise
ls -a data/outbound/cleared/<job>/
cat  data/outbound/cleared/<job>/.published
```

Three things to confirm, and each is a promise to the consumer:

1. **The package is clean.** The destination has `report.json`, `message.eml`
   and the attachments — and **no** `.complete` or `.published`. Those markers
   are ours and stay on this host.
2. **The path is deterministic.** `<bucket>/<job>`, the same slug as locally.
   Smiley can construct it from the bucket and the job id.
3. **Nothing local was removed.** The job directory still has everything it had,
   plus `.published` naming where the copy went.

### 11.4 Prove the latency, then prove it does not depend on the event

Send a test message and watch:

```sh
journalctl -u email-guard-publisher.service -f
```

The job should publish within a second or two of the scan finishing — that is
the `.path` unit firing on the new job directory.

Now the honest part. systemd path units do not recurse, so the unit watches the
three **bucket** directories; creating a job directory is the event, and that
happens a fraction of a second *before* the `.complete` sentinel inside it. So a
fire can arrive too early, find nothing publishable, and exit — which is why
`email-guard-publisher.timer` exists. Prove the backstop works on its own:

```sh
sudo systemctl stop email-guard-publisher.path     # no events at all
# ... send a message, wait for the scan ...
sleep 330                                          # the timer runs every 5 minutes
ls /mnt/network/acheron/email-guard/cleared/ | tail -3
sudo systemctl start email-guard-publisher.path
```

The job must still have crossed. Latency comes from the path unit; the guarantee
comes from the timer. Run both.

### 11.5 Prove an outage loses nothing

This is the check worth doing properly, because it is the one that costs mail if
it is wrong.

```sh
# simulate the share going away
sudo umount /mnt/network/acheron        # or: pull the network, stop the NAS

# ... send two or three messages, let them scan ...
sudo systemctl start email-guard-publisher.service
journalctl -u email-guard-publisher.service -n 5 --no-pager
```

Expect a **warning**, not a failure: `destination ... is not reachable -- N
job(s) stay local and will be retried on the next fire`. Confirm the unit did
not go into a failed state (`systemctl status` shows the last run as successful)
— a NAS reboot is an expected state of the world, not an incident to page for.

Then confirm nothing was lost or half-done:

```sh
ls -a data/outbound/cleared/*/ | grep -c '\.published'    # no new markers
sudo systemctl start email-guard-cleanup.service          # retention, mid-outage
ls data/outbound/cleared/ | wc -l                         # unchanged
```

The retention sweep must delete **nothing**: an unpublished job is never
expired, however old it is. That rule is what turns a week-long outage into a
week of disk usage instead of a week of lost mail.

Bring the mount back and watch the backlog drain by itself:

```sh
sudo mount /mnt/network/acheron
sudo systemctl start email-guard-publisher.service
ls /mnt/network/acheron/email-guard/cleared/ | wc -l
```

### 11.6 Prove a consumer never sees half a job

The copy is assembled in a staging directory *inside the destination bucket*,
and the final step is a single `rename` — atomic within one filesystem. To see
it, watch the bucket while a large attachment crosses:

```sh
# in one shell
while :; do ls /mnt/network/acheron/email-guard/cleared/; sleep 0.1; done
```

Job directories appear complete, in one step, under their real name. A
`publishing-<job>.<pid>` entry may flash by while a copy is in flight — that is
the staging directory, and it is **visible on purpose**: this share is CIFS/SMB
and its server refuses to create any name beginning with a dot, so it cannot be
hidden (a `.publishing-` prefix made the first `mkdir` fail with ENOENT and
nothing published at all). The guarantee never depended on hiding it; it depends
on the rename. A consumer that lists the bucket instead of resolving the job
path should skip `publishing-*`.

If the destination turns out **not** to be the same filesystem as the staging
directory (it always is — staging is inside it), the rename would fail rather
than silently degrade to a copy, and the job would stay pending.

### 11.7 Prove retention, without waiting fourteen days

Back-date a published job's marker and run the sweep:

```sh
job=data/outbound/cleared/<some-published-job>
sudo -u '#1000' touch -d '30 days ago' $job/.published
sudo systemctl start email-guard-cleanup.service
journalctl -u email-guard-cleanup.service -n 5 --no-pager
ls $job                                    # gone
ls /mnt/network/acheron/email-guard/cleared/<some-published-job>/   # still there
```

Both halves matter: the local copy expires, and **the published copy does not**.
The cleanup unit is not even given the partition in its `ReadWritePaths`, so
that second line is enforced by systemd, not only by the code.

### 11.8 The Smiley side

Nothing to install here — Smiley is triggered by the **existing n8n webhook**,
unchanged. Two things to tell whoever maintains it:

- **The file may land a beat after the webhook.** The dispatcher POSTs as soon as
  the scan returns; the publisher fires on the job directory appearing. The gap
  is normally well under a second, but it is a race. Treat the webhook as "a job
  is coming" and retry the path briefly rather than treating a missing directory
  as an error.
- **The path is `/mnt/network/acheron/email-guard/<bucket>/<job>/`**, built from
  the `bucket` and `written.job` fields the webhook payload already carries.
  Resolving that path directly — rather than scanning the bucket — is the
  intended access pattern, and it needs no filtering at all: the directory
  appears atomically under that exact name. Verify attachments against
  `extracted_attachments` in `report.json`, which carries the SHA-256 and size
  of every file beside it. A consumer that *does* list a bucket should skip
  entries starting with `publishing-` — those are copies in flight.

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

### The rules never update, and the updater looks fine

**Symptom.** `docker compose logs rules-updater` shows `rules updated: … -> …`,
`readlink rules-live/current` moves — and scans behave exactly as before.

Almost always the cutover in §9.4 has not been done, or was done without
recreating the dispatcher. The updater writes `rules-live/`; the scanner reads
whatever `EMAIL_GUARD_HOST_RULES_DIR` names, and that still says `.../rules`:

```sh
docker compose exec dispatcher printenv EMAIL_GUARD_HOST_RULES_DIR
```

If it does not end in `/rules-live/current`, set both variables in `.env` and
`docker compose up -d dispatcher`.

The subtler version of this is a dispatcher that was started when the bind was
`rules-live/current` rather than `rules-live/`. It will serve the release that
was live at its start, forever, and look entirely healthy doing so. Check:

```sh
docker inspect email-guard-dispatcher \
  --format '{{range .Mounts}}{{.Source}} -> {{.Destination}}{{"\n"}}{{end}}' | grep rules
```

The source must be the directory, not the symlink.

### The updater logs `could not read Username` or `Authentication failed`

**Symptom.** Every pull returns `status: error` with a message about
credentials, against a repository you can clone by hand.

The updater pulls **public** repositories only. It supplies no credentials and
cannot be made to: prompting is disabled, `GIT_ASKPASS` is `/bin/false`, the
credential helper list is cleared on every invocation, and `~/.gitconfig` and
`/etc/gitconfig` are both pointed at `/dev/null`. A private repository therefore
fails, and this is that failure surfacing.

If `EMAIL_GUARD_RULES_REPO_URL` really is public, check the URL for a typo — a
nonexistent public repository and a private one are indistinguishable to an
unauthenticated client, and GitHub returns "not found" for both.

An `ssh://` or `git@host:path` URL is refused at startup rather than attempted,
with a message saying so on stderr.

### Every pull is `rejected`, and the pack is fine

**Symptom.** Every pull — scheduled or from the console's **Refresh rules** —
comes back `rejected`, with `validation_errors` that all look like this:

```
scan/level2.json[content-links]: scan/level2_funcs.py failed to import
  (No module named 'email_guard')
```

The live pack never moves off `releases/seed/rules`, and
`python rules/validate.py rules/` on the host says `rules pack OK`.

**That disagreement is the diagnosis.** The pack is valid; the *environment the
updater validates it in* is not. `rules/scan/level*_funcs.py` call into the
engine (`from email_guard.links import …`), and `validate.py` proves a pack will
run by importing exactly those modules — so validation needs `email_guard`
importable, and the updater image has to install `scanner/` for that. Confirm
what the running image actually has:

```sh
docker compose exec rules-updater python -c "import email_guard; print(email_guard.__file__)"
```

A `ModuleNotFoundError` here is the fault. Rebuild the updater **from the same
checkout as the scanner** — the engine it validates against must be the engine
the scanner will run the pack on:

```sh
docker compose build rules-updater scanner
docker compose up -d rules-updater
```

Then clear the remembered verdict, or the rebuilt image will short-circuit on it
and report the same errors without re-validating anything — see the note under
§9.2:

```sh
docker compose stop rules-updater
sudo rm -rf rules-live/state.json rules-live/releases rules-live/current
docker compose up -d rules-updater
```

### The updater cannot write, or the dispatcher will not start on the rules mount

**Symptom.** The updater logs a single line and exits:

```
rules updater cannot start: /app/rules-live is not writable by uid 1000:1000
(Permission denied). Docker creates a missing bind source root-owned; chown it
on the host to EMAIL_GUARD_UID:EMAIL_GUARD_GID — sudo chown -R …
```

Or the dispatcher exits with `container.rules_dir (…) does not exist inside the
dispatcher`.

The usual cause is an absent `rules-live/` on the host: docker creates a missing
bind source as a **root-owned** directory, which the uid-1000 updater then cannot
write into. The repository ships `rules-live/.gitkeep` so a fresh clone owns the
directory; if it went missing:

```sh
ls -ld rules-live
mkdir -p rules-live && touch rules-live/.gitkeep
sudo chown -R "${EMAIL_GUARD_UID:-1000}:${EMAIL_GUARD_GID:-1000}" rules-live
docker compose up -d rules-updater
```

The service exits rather than retrying on purpose: nothing inside the container
can fix an ownership problem on the host, and a loop would only bury the line
that names the fix.

### Nothing is published, and the publisher unit looks fine

**Symptom.** `data/outbound` fills up, `/mnt/network/acheron/email-guard` stays
empty, and `systemctl status email-guard-publisher.service` shows a clean run.

Work down this list; each step distinguishes a different cause.

```sh
# 1. WHAT does it think it is doing? Wrong paths are the usual answer.
sudo -u '#1000' env $(grep -v '^#' /etc/email-guard/publisher.env | xargs) \
     PYTHONPATH=/opt/email-guard/publisher \
     python3 -m email_guard_publisher status
```

- **`pending 0 job(s)` while jobs exist.** It is looking at the wrong tree, or
  the jobs have no `.complete`. Check `EMAIL_GUARD_OUTBOUND_DIR` is the **host**
  path (`${EMAIL_GUARD_HOST_ROOT}/data/outbound`) and not `/app/data/outbound`;
  then `ls -a data/outbound/*/*/ | grep complete`. A missing sentinel on a job
  that otherwise looks finished means the scanner image predates this feature —
  rebuild it (§10.7).
- **`pending N` but nothing crosses.** Read the journal: `destination ... is not
  reachable` means the mount is gone or uid 1000 cannot write it
  (`sudo -u '#1000' test -w /mnt/network/acheron/email-guard`). A per-job
  exception means a real copy error, and the job stays pending by design.
- **The status command works but the unit does nothing.** The unit is not
  reading the same environment: check `systemctl show -p Environment -p
  EnvironmentFiles email-guard-publisher.service`, and that
  `/etc/email-guard/publisher.env` is readable by the unit's user.

**The events never arrive, but a manual start works.** That is the path unit,
not the publisher. `systemctl status email-guard-publisher.path` and confirm the
`PathModified=` lines name directories that **exist** — a path unit watching a
missing directory sits there quietly. The bucket directories are created by the
first message routed to them, so on a fresh host `data/outbound/rejected` may
not exist yet; create the three by hand. Until then, the backstop timer is what
is publishing, five minutes at a time.

### Jobs are published but never expire

**Symptom.** `.published` markers everywhere, `data/outbound` growing without
bound, and the cleanup timer showing as active.

```sh
systemctl list-timers 'email-guard-*'
journalctl -u email-guard-cleanup.service -n 20 --no-pager
```

The log line names all three counts. `kept N unpublished` means those jobs never
crossed — that is the publisher's problem, above, and retention is correctly
refusing to delete them. `kept N within the window` with a retention you thought
was smaller means the unit is reading a different `EMAIL_GUARD_OUTBOUND_RETENTION_DAYS`
than you edited; `systemctl show -p EnvironmentFiles email-guard-cleanup.service`.
Remember the age is counted from the `.published` marker's mtime — the moment the
job was *published*, not scanned — so a backlog that drained yesterday gets its
full window from yesterday.

### Smiley sees a job directory before its files

**Symptom.** The consumer reports a job with a missing `report.json` or a
missing attachment.

This should be impossible for a published job: the package is assembled in a
staging directory and renamed into place in one atomic step. Two things to check
before looking anywhere else:

- **Is the consumer reading the staging directory?** It is named
  `publishing-<job>.<pid>` and is **not** hidden — the SMB server backing this
  share rejects leading-dot names, so it cannot be. A consumer that globs `*`
  will occasionally catch one mid-copy. Resolve the job path from the webhook
  instead, or skip `publishing-*`.
- **Is something else writing into the destination?** The publisher is the only
  thing that should. A second copy of it — an old cron job, a manual `rsync` —
  breaks the guarantee by writing files directly.

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
- **A promote landing while a scan is in flight.** The reasoning is sound —
  the daemon resolves the symlink at container-create time, so a running scan
  holds its own release — and the release-pruning hold-down keeps that
  directory alive for an hour afterwards. But the race has never actually been
  run: it needs a promote timed against a live scan on a busy mailbox.
- **A real upstream force-push.** The non-fast-forward refusal is covered by a
  test against a local repository; whether GitHub's transport surfaces it the
  same way on a genuine rewritten branch is unproven.
- **Whether 24h is the right interval.** It is a guess. The feed is the part
  that wants updating often, and nothing here yet measures how quickly a new
  signature ought to reach a running deployment.
- **The publisher against a real network filesystem.** Every test runs against
  two tmp directories, which model a local filesystem exactly and a CIFS/SMB
  share only approximately. One difference has already bitten: **this share
  refuses to create any name beginning with a dot** (`mkdir with.dots` works,
  `mkdir .anything` returns ENOENT), which meant the original
  `.publishing-<job>.<pid>` staging directory failed on its first `mkdir` and
  nothing published at all. The prefix is now `publishing-`, and
  `tests/test_publisher.py` asserts both that it stays dot-free and that nothing
  else the publisher copies to the share is dot-prefixed. The internal markers
  keep their dots — they are only ever written to the local ext4 tree.

  Still unproven on the real share: a *stale* mount, which can pass the
  reachability check and fail mid-copy (handled — the job stays pending), and
  whether the server honours `fsync` on a directory. Watch the journal.
- **A rename onto a destination another writer is touching.** The publisher
  assumes it is the only thing writing under `${DEST}`. Two hosts publishing
  into one share, or a manual `rsync` into it, is untested and outside the
  design.
- **The path-unit race, quantified.** The window between a job directory
  appearing and its sentinel being written is small enough that the early fire
  is expected to be rare, but nothing measures how often it actually happens on
  a busy mailbox. It costs latency only — the backstop timer publishes anything
  the event missed — but if the journal shows the backstop doing most of the
  work, the event path is worth revisiting.
- **Smiley's side of the contract.** That a job directory appears whole is
  tested here; that the consumer *retries* when the file lands a beat after the
  webhook is a property of that machine, and can only be confirmed there.
