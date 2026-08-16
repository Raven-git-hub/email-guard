# Email Guard

A self-hosted, containerised email scanning service. It ingests mail from multiple
mailboxes through a Proton Mail Bridge, scans each message for prompt injection,
phishing, and spam, assigns a threat level, and consolidates the trustworthy mail into a
single clean inbox while quarantining everything else. It also learns: unfamiliar senders
and message shapes are proposed as database entries for you to approve, and trusted mail
is tagged with an **action** that a downstream workflow acts on.

This repository is the **Docker-native rebuild** of an earlier prototype that ran on
[n8n](https://n8n.io/). The scanning philosophy is carried over; the orchestration is
rewritten so each email is scanned in its own disposable container, with a local LLM
("the Canary") for semantic checks, a versioned **rules pack** for the detection logic,
and structured webhook outputs for downstream processing.

**Engine runtime: Python.** Detection logic lives in a separate, git-versioned rules pack.

---

## Guiding philosophy

You can learn most of what you need about an email from its text, headers, and sender
authentication. If those don't check out, the links and attachments almost certainly
don't either. So Email Guard reads the envelope and body **first**, and treats attachments
as the last and least-trusted signal — not the primary gate.

---

## Engine vs rules pack

Two things are deliberately kept apart:

- **The engine** — message parsing, orchestration, the Canary client, outputs, the
  dispatcher, the UI. Written in Python. Changes rarely; shipped as container images.
- **The rules pack** — all detection logic, versioned (in this repo for now, possibly its
  own repo later), mounted into the scanner and loaded at runtime. This is the part you
  iterate on and **push to Git as security updates** without rebuilding the engine.

The rules pack contains:

- **Declarative scan rules** for the many simple, per-field pattern checks (the bulk of the
  old `level2/3/4.json`): entries like `{ field, test, → status }`. Clean git diffs, no
  code execution, and they cannot crash the engine.
- **Python rule functions** for the minority of checks that need real logic — cross-field
  comparisons, and the level assessment scripts with their scoring and overturn rules.
- **A validator** run in CI (on push) and by the engine on load. A malformed pack is
  rejected before it goes live, and the engine falls back to the last known-good pack.

> Replaces the prototype's pattern of storing logic as JavaScript strings run through
> `new Function()`, where a stray syntax error broke a scan at runtime with no warning.

---

## Status

| Area | State |
|------|-------|
| Detection logic (levels 2–4) | Exists in prototype (JS strings), to re-express as a rules pack |
| Source cleaners (Outlook / Gmail / Proton) | Provided; contracts to be standardised |
| Triage / initial level assignment | Exists; greylist matching to be updated to current schema |
| Signature reference DB (`rules/reference/`) | **Scaffolded** — injection feed seeded, phishing feed empty by design; static loader that fails open. Interval-pulling from git not built |
| Dispatcher (bridge IMAP → scanner) | **Built** — poll-based; runs the scanner as a subprocess, IDLE and per-email containers still to come |
| Canary (local LLM) semantic checks | **To be built** |
| Routing / outbound store | **Built** — every scan lands in `outbound/<bucket>/<job>/` (report + original) |
| Candidate generation + daily review | Scanner **stages candidates** to `daily-brief-{date}/`; review UI + applier to be built |
| Webhook / output sinks + actions | Partially proven; actions not yet in the greylist schema |
| Admin UI (lists, stats, quarantine, review, approvals) | **To be built** |
| Unified configuration | **To be built** (replaces conflicting path files + index refs) |
| Consolidated inbox delivery | **To be built** |

---

## Why the rebuild

Much of the prototype's complexity existed only to work around n8n's execution model — one
workflow run at a time, no clean isolation between messages — producing a lock file, a
shared job queue, and a queue-drainer workflow.

Running **one container per email** removes the reason those pieces exist: each message is
scanned in its own process, memory, and filesystem, so the lock file and job queue go away;
a hostile message's blast radius is a single throwaway container; and concurrency becomes a
dispatcher setting.

---

## Architecture

```
                        ┌───────────────────────┐
   Outlook ─┐           │   Proton Mail Bridge   │
   Gmail  ──┼─ forward ─▶   (bridge-inbound)     │  IMAP :1143 / SMTP :1025
   Proton ──┘           └───────────┬───────────┘
                                    │ IMAP IDLE (new message)
                                    ▼
                        ┌───────────────────────┐        ┌──────────────────┐
                        │      Dispatcher        │        │    Admin UI      │
                        │  watches the bridge,   │        │  lists · stats · │
                        │  spawns one scanner    │        │  quarantine ·    │
                        │  per message; owns      │        │  daily review ·  │
                        │  webhook delivery       │        │  approvals       │
                        └───────────┬───────────┘        └────────┬─────────┘
                                    │ docker run --rm          reads/writes
                       rules pack ─▶│  (raw .eml in)               │
                                    ▼                              ▼
                        ┌───────────────────────┐        ┌──────────────────┐
                        │       Scanner          │──L1/L2─▶│  Canary (LLM)   │
                        │  clean → triage →      │ verdict │  local model,   │
                        │  deep scan → [canary] →│◀────────│  caged/read-only│
                        │  assess → route →      │        └──────────────────┘
                        │  propose → emit        │
                        └───────────┬───────────┘
              ┌─────────────────────┼───────────────────┐        │ event + action
              ▼                     ▼                    ▼        ▼
           cleared              flagged              rejected   webhook ──▶ downstream
        (→ consolidated       (quarantine)         (quarantine)            email-processing
         inbox, tagged                                                      (other machine)
         with an action)
                              candidates ──▶ daily-brief queue ──▶ UI review ──▶ instructions ──▶ applier ──▶ live lists
```

### Components

**Proton Mail Bridge** — the existing `shenxn/protonmail-bridge` container; Outlook, Gmail
and Proton mail forwarded into Proton and exposed over local IMAP/SMTP. Unchanged.

**Dispatcher** — small, always-on. Holds one IMAP `IDLE` connection and launches an
ephemeral **Scanner** (`docker run --rm`) per message with the rules pack mounted. Enforces
concurrency and **owns webhook delivery + retries** so an offline downstream never loses an
event. Deliberately dumb, so it can later be swapped for a worker pool without touching the
scanner.

**Scanner** — the core engine, a **pure function in container form**: one raw RFC822 message
+ a rules pack in, a verdict + routing decision + database candidates + output event out,
then it exits. Testable offline by piping in a saved `.eml`.

**Canary (local LLM)** — a persistent, warm container (e.g. Ollama) called **only for level
1–2 messages** for semantic prompt-injection / phishing-language detection. Deliberately
caged (see below).

**Admin UI** — LAN-only, authenticated console: edits lists, shows stats, browses quarantine
with forensic logs, and hosts the **daily review** that replaces the old Discord forms.

---

## Normalised message shape

Every cleaner emits one standard object; the rules pack scans its fields. This is the
contract between the engine and the rules pack:

```
{
  messageID, timestamp, job_id, uid, mailbox,
  original_sender, friendly_name,
  whitelist_hit, greylist_hit, blacklist_hit,
  obfuscation_flags: { visual, tactical },
  title,                       # subject, forwarding prefixes stripped
  clean_text,                  # HTML stripped, first ~2000 chars
  attachments: [ { filename, contentType } ],
  links: [ defanged_url, ... ],
  metadata: {
    authenticity: { dmarc, dkim, spf, auth_string },
    origin:       { ip, sid_result },
    path:         { return_path, is_forwarded, hop_count },
    technical:    { content_type, is_multipart, encoding, mime_version },
    behavioural:  { header_count, mailer, traffic_type }
  },
  integrity: { dkim_verified, source_pipe },   # source_pipe: OUTLOOK | GMAIL | ProtonMail
  content:   { links, attachments, text, timestamp }
}
```

Each source cleaner (Outlook / Gmail / Proton) is responsible for producing this from its
own header dialect. In the rebuild all three share **one contract** (the prototype's Proton
cleaner returns a different shape from the Outlook/Gmail cleaners — to be reconciled).

---

## The scanning pipeline

1. **Clean.** Header fingerprints pick Outlook / Gmail / Proton; the matching cleaner
   normalises the message into the shape above.
2. **Triage — initial level** from list hits and message *content* only (title + body text).
   A lenient face-value guess; technical signals are not consulted here. See "Threat level
   model" below.
3. **Deep scan.** The rules pack for the triage level runs point-by-point over every field,
   each rule returning a status (`pass`, `pass_service`, `fail_pass`, `fail_critical`).
4. **Canary (conditional).** For level 1–2, cleaned text → local LLM → semantic verdict fed
   back as a signal.
5. **Assessment & routing.** The level's assessment logic takes a holistic view (incl. the
   Canary verdict) and upgrades/downgrades under fixed rules, iterating with the deep scan
   until the level settles. Allowed moves: **L2 → {1,2,3}**, **L3 → {2,3,4}**, **L4 →
   {4,5}**; the loop stops when the level stabilises or oscillates between two.
6. **Propose.** Unfamiliar senders / uncatalogued structures are written as candidates to
   the `daily-brief` store — never straight to the live lists.
7. **Output.** A structured event (message id, final level, bucket, sender, forensic log,
   de-fanged links, **and the action** for cleared/greylisted mail) is handed to the
   dispatcher for webhook delivery + notifications.

Levels **1** and **5** are terminal — no deep-scan library. Level 1 (injection) goes to the
high-threat path and the Canary; level 5 (trusted whitelist, no attachments) goes straight
to cleared.

---

## Threat level model

| Level | Meaning | Bucket |
|-------|---------|--------|
| **1** | Clear, obvious prompt-injection attempt | `rejected` |
| **2** | Targeted / sophisticated phishing | `flagged` |
| **3** | Low-level phishing or spam | `flagged` |
| **4** | Greylist domain, or whitelist **with** attachments | `cleared` |
| **5** | Trusted whitelist (no attachments) | `cleared` |

`cleared` → consolidated inbox (tagged with an action); `flagged`/`rejected` → quarantine.

### Three kinds of signal, three owners

The stages do not share evidence, and that separation is deliberate:

| Signal | Examples | Owner |
|--------|----------|-------|
| **Content** | subject text, cleaned body text, injection phrasing, homoglyphs | **Triage** |
| **Technical** | DKIM, return path, multipart structure, header counts, mailer strings | **Deep scan** |
| **Identity** | who the sender is, which domains are recognised | **The lists** |

**Triage reads message content only** — the title and the cleaned body. It must never read
`metadata.technical`, `integrity.dkim_verified` or the return path.

Triage is a **lenient face-value guess, not a line of defence**. Everything it assigns above
level 1 is revisited by the deep-scan loop, which can move a message in either direction, so
triage only rejects outright on signals that are unambiguous.

An earlier ladder had a "weak infrastructure" rule here that pushed a message to level 2 for
being single-part, or unverified by DKIM, or having a misaligned return path. Those are
technical signals; they are wrong far more often than they are right — all mail here is
forwarded through the bridge, which rewrites exactly those fields — and the deep scan already
weighs them with proper context. An ordinary plain-text receipt from an unknown domain is a
level 3 to be looked at, not a level 2 suspect. That branch is gone.

For the same reason the level-2 `return_path_alignment` check was demoted from `fail_critical`
to `fail_pass`: envelope misalignment is defense-in-depth, contributing to a picture built
from several signals, never grounds to reject by itself.

### The triage ladder

First match wins:

| # | Condition | Level |
|---|-----------|-------|
| 1 | Blacklist hit | **1** |
| 2 | Injection detected — the hard-baked floor **or** the level-1 injection signature feed | **1** |
| 3 | **Not** whitelisted, and either the phishing signature feed matches **or** the subject carries standalone obvious obfuscation (homoglyphs) with no injection payload beneath it | **2** |
| 4 | Greylist `known` → **4** · `new_structure` → **3** · `none` and not whitelisted → **3** | 4/3/3 |
| 5 | Whitelist hit | **4** with attachments, else **5** |

Two things worth spelling out:

- **Rule 2 fires regardless of whitelist status.** No legitimate sender embeds instructions
  aimed at a downstream model, so a whitelisted address that does has been spoofed or
  compromised — precisely when trusting the list would be worst.
- **Rule 4 runs before rule 5.** Only its `none` arm carries the "and not whitelisted"
  qualifier, so a whitelisted address on a *greylisted* domain is judged by whether the
  message shape is catalogued: an uncatalogued one lands at 3 for review rather than being
  waved through at 5.

---

## Signature reference database

Detection *phrasing* changes far more often than detection *logic*, so it lives apart from
both the engine and the scan rules, as plain reference data under `rules/reference/`:

```
rules/reference/
├── injection_signatures.json    # level 1 — prompt-injection phrasing
└── phishing_signatures.json     # level 2 — phishing language
```

### Schema

```json
{
  "version": 1,
  "updated": "2026-08-16",
  "description": "what this feed is for",
  "signatures": [
    {
      "id": "inj-0001",
      "type": "regex",
      "pattern": "ignore\\s+(all\\s+)?(the\\s+)?(previous|prior)\\s+(instructions|prompts)",
      "description": "why this entry exists"
    }
  ]
}
```

`type` is `literal` (case-insensitive substring) or `regex` (case-insensitive search).

**Injection entries must be high precision.** A hit is level 1, which rejects the message even
from a whitelisted sender, with no list to appeal to. Every seeded pattern therefore requires
an instruction-shaped *object* rather than the bare verb: `disregard the previous email` and
`forget everything you know about insurance` are ordinary business and marketing phrasing,
while `disregard the previous instructions` is not. Prefer missing an attack to flagging a
receipt — the deep scan and the Canary both get a look afterwards.

**The phishing feed ships empty**, on purpose. Level 2 is a suspicion rather than a rejection,
but a noisy entry there flags real mail for *every* non-whitelisted sender, and unknown
senders are the common case. Grow it from observed traffic (Canary-assisted), not from generic
spam phrasing.

### The feed fails OPEN — the scan rules fail CLOSED

The two halves of the pack behave in opposite ways, and this is the design:

| | On a malformed file |
|---|---|
| **Scan rules** (`rules/scan/`, `rules/assess/`) | **Fail closed.** `rules/validate.py` rejects the pack, `InvalidRulesPack` is raised, the scanner refuses to score anything. A broken rule could silently mis-score every message, so not running is safer. |
| **Signature feeds** (`rules/reference/`) | **Fail open.** A file that is missing, empty, unparseable or malformed logs a warning, is skipped, and triage carries on against its hard-baked floor. |

The feeds are the part most likely to be half-written by a future auto-update, and a bad fetch
must cost sensitivity, not stop the mail. Making the feeds fail closed would let a truncated
download halt every scan; making the scan rules fail open would let a typo quietly disable
detection. **Do not unify them.**

One bad *entry* costs that entry, not the whole feed — a signature with an invalid regex, an
unknown `type` or a duplicate `id` is skipped with a warning and the rest still load.

Resolution order, highest first:

1. the validated file under `rules/reference/`
2. *TODO(cache):* a last-known-good copy of the last feed that loaded cleanly, so a bad update
   degrades to yesterday's signatures rather than all the way to the baseline. Not implemented
   — there is nowhere to cache to until the interval pull exists.
3. nothing — triage falls back to the hard-baked markers in `scanner/email_guard/triage.py`
   (`_ROLEPLAY_RE`, `_HIDDEN_UNICODE_RE`, `_FENCE_RE`). These are a permanent floor, not a
   default the feed replaces: the feed only ever adds to them.

> **TODO(feed-pull):** pulling this repository on an interval so signature updates land without
> a redeploy is the intended operating mode, and is what the fail-open behaviour above exists
> to protect. **Not built.** Today the loader is static — the feeds are read once when the
> rules pack loads, from whatever is on disk.

---

## Scanner outputs

A scan **writes**. Printing the verdict is the `--dry-run` behaviour; by default the
scanner persists three things.

```
data/outbound/<bucket>/<job>/report.json    # the full verdict
data/outbound/<bucket>/<job>/message.eml    # the original, byte for byte
                        ... /message.json   # ... or the --from-json input
data/daily-brief/daily-brief-<YYYY-MM-DD>/<job>/candidate.json
```

- `<bucket>` is `cleared` / `flagged` / `rejected`, from the level (see above).
- `<job>` is a filesystem-safe slug of the message id — angle brackets stripped, unsafe
  characters replaced, over-long ids truncated with a hash suffix. A message with no usable
  id falls back to a short hash **of its own bytes**, so it still gets a stable directory of
  its own.
- The stored message is a **verbatim copy**, never a re-serialisation of the parsed form:
  quarantine is forensic storage, so what the scanner saw is what a reviewer reads.
- The verdict gains a `written` section naming every path created; it is `null` under
  `--dry-run`.
- Re-scanning the same message with the same date **overwrites its own files identically** —
  no timestamps, no run ids, fixed JSON formatting.

A `candidate.json` is staged only for `unknown_domain` (sender on no list) and
`new_structure` (greylisted domain, uncatalogued shape). `skip` writes nothing, and
**nothing here ever edits the live lists** — a candidate carries `proposed_entries`, each a
complete schema-shaped list entry plus the `list` it would join and the `operation` needed.
They are alternatives: the reviewer picks at most one, and only the applier writes lists.
A proposed structure is deliberately over-specific (it is drafted from one sample); the
review UI is where a human generalises it.

The daily-brief date is **injected, never read from the clock** inside the logic — `--now
YYYY-MM-DD` pins it, defaulting to today — so a run is reproducible and testable.

### CLI

```
python -m email_guard message.eml
python -m email_guard --from-json sample.json --pretty
python -m email_guard --from-json sample.json --dry-run       # compute, print, write nothing
python -m email_guard --validate-rules
```

Paths resolve by **flag > environment > `config/config.json` > built-in default**:

| Setting | Flag | Environment | Default |
|---------|------|-------------|---------|
| Live lists | `--lists-dir` | `EMAIL_GUARD_LISTS_DIR` | `data/lists` |
| Rules pack | `--rules-dir` | `EMAIL_GUARD_RULES_DIR` | `rules` |
| Routed output | `--outbound-dir` | `EMAIL_GUARD_OUTBOUND_DIR` | `data/outbound` |
| Staged candidates | `--daily-brief-dir` | `EMAIL_GUARD_DAILY_BRIEF_DIR` | `data/daily-brief` |
| Config file | `--config` | `EMAIL_GUARD_CONFIG` | `config/config.json` |

Both output stores hold personal data (whole messages, real senders) and are git-ignored;
the repo ships only the empty directories.

---

## Running the dispatcher against the Proton bridge

The scanner handles one message. The **dispatcher** is the always-on process that feeds it:
it holds an IMAP connection to the Proton Mail Bridge, pulls each new message, and runs
`python -m email_guard` on it as a subprocess.

The dispatcher deliberately knows nothing about how a message is scored. It hands over raw
bytes and reads the verdict back off stdout, and it passes **no** `--lists-dir` /
`--outbound-dir` flags — the scanner resolves its own configuration exactly as it does when
you run it by hand. That keeps the scanner a pure function in container form and the
dispatcher dumb enough to swap for a worker pool later.

### 1. Configure the connection

The non-secret settings live in the `imap` section of `config/config.json`:

```json
"imap": {
  "host": "127.0.0.1",
  "port": 1143,
  "mailbox": "INBOX",
  "tls": "starttls",
  "ca_file": null,
  "poll_interval_seconds": 30,
  "max_attempts": 3,
  "concurrency": 4,
  "scan_timeout_seconds": 120
}
```

| Key | Meaning |
|-----|---------|
| `host` / `port` | Where the bridge listens. `127.0.0.1:1143` is the bridge's default local IMAP. |
| `mailbox` | Which mailbox to watch. |
| `tls` | `starttls` (the bridge's default), `ssl`, or `none`. |
| `ca_file` | A CA bundle to verify the bridge certificate against. Usually unnecessary — see below. |
| `poll_interval_seconds` | How often to check for new mail. |
| `max_attempts` | Scans per message before it is quarantined. |
| `concurrency` | Simultaneous scanner subprocesses. |

**About the certificate.** The bridge generates its own self-signed certificate at install
time, so there is nothing to verify it against. On a **loopback** host (`127.0.0.1`, `::1`,
`localhost`) the dispatcher accepts it — the connection never leaves the machine, so there is
no network attacker to defend against. On **any other host** the certificate is verified
normally and a self-signed one will be rejected; point `ca_file` at the bridge's certificate
if you genuinely run it on another machine. Verification is never silently disabled for a
remote host.

### 2. Provide the bridge credentials

These are the credentials **Proton Mail Bridge generates for the account** — not your Proton
account password. Find them in the Bridge app: select the account → *Mailbox details* (or
*Configure*), which shows the IMAP username and a generated password.

They must never enter git. Either put them in the environment:

```sh
export EMAIL_GUARD_IMAP_USERNAME='you@proton.me'
export EMAIL_GUARD_IMAP_PASSWORD='the-bridge-generated-password'
```

…or copy `config/secrets.sample.json` to `config/secrets.json` (git-ignored) and fill it in.
The environment wins if both are present.

### 3. First run

Install once, then drain what is currently unread and stop:

```sh
pip install -e ".[dev]"
python -m email_guard_dispatcher --once --verbose
```

`--once` scans the currently-UNSEEN messages and exits — the right shape for a first live
test and for cron. `--verbose` prints one line per message: uid, sender, final level, bucket.
Drop `--once` to run the poll loop until stopped:

```sh
python -m email_guard_dispatcher            # polls every poll_interval_seconds
```

> **The first live run processes your entire unread backlog.** The dispatcher finds work with
> `SEARCH UNSEEN`, so every unread message in the mailbox is scanned on that first pass. Point
> the first `--once` run at a small or test intake mailbox (`--mailbox Intake`) before turning
> it loose on a real inbox.
>
> The converse also matters: **a message already marked `\Seen` by another client is never
> scanned.** That is fine for the intended setup — a dedicated intake mailbox that no human
> reads — but it means the dispatcher is not safe to point at a mailbox you browse yourself,
> because anything you open first will be skipped.

### What it does with each message

1. `FETCH` the raw RFC822 bytes by UID (with `BODY.PEEK[]`, so reading does not mark the
   message seen before it has actually been scanned).
2. Write them to a temp `.eml`, run `python -m email_guard <tmpfile>`, capture the verdict
   JSON from stdout and the exit code, delete the temp file. The scanner files the message
   into `outbound/<bucket>/<job>/` itself.
3. On success: record the message as processed, mark it `\Seen`, and hand the verdict to the
   configured sinks.
4. On failure: retry up to `max_attempts`. After that, write a line to the quarantine log and
   mark it processed anyway, so one bad message cannot block everything behind it.

Processed messages are recorded by `(UIDVALIDITY, UID)` in `data/dispatcher/state.json`, so a
restart does not rescan them. That file — not the `\Seen` flag — is the authority: any client
can clear a flag, and quarantined messages are recorded there too so a cleared flag cannot
replay a known-bad message. Both it and `data/dispatcher/quarantine.log` name real
correspondents, so both are git-ignored.

### Optional webhook

Set `dispatcher.webhook_url` in `config/config.json` or `EMAIL_GUARD_WEBHOOK_URL` in the
environment and each verdict is POSTed as JSON, with a short retry and backoff. With no URL
set, the default sink just logs the verdict. Delivery is currently best-effort — a durable
retry queue is still to come.

---

## Databases & the daily review

### List schemas (from the live samples)

```
whitelist: [ { email, friendly_name, known_structures: [ { name, key_phrases: [] } ] } ]
blacklist: [ { email, friendly_name?, known_structures: [ ... ] } ]
greylist:  [ { domain,               known_structures: [ { name, key_phrases: [ "Subject: …", … ] } ] } ]
```

- Whitelist / blacklist key on **email**; greylist keys on **domain**.
- A structure with empty `key_phrases`, or one named `"ALL EMAILS"`, means **match every
  message from this sender** (the matcher must handle empty phrase sets explicitly).
- `"Subject: …"` phrases match the subject; other phrases match the body.
- **Domain matching includes subdomains**: a list entry matches when
  `sender_domain == domain` or `sender_domain` ends with `"." + domain` (so
  `notify.example-bank.test` matches an `example-bank.test` entry).

### Storage & privacy

Live lists are personal data (real correspondents, bank relationships) and are **never
committed** to the repo — which may be published later.

- The scanner reads live lists from a configurable directory, default `data/lists/*.json`,
  resolved via `config.json` (`lists_dir`); host-provided and bind-mounted at runtime.
- `data/lists/*.json` is git-ignored. The repo ships only schema-valid
  `data/lists/*.sample.json` templates plus a `.gitkeep`, so the shape is documented and a
  clean clone can start.
- Tests run on **synthetic fixtures** in `tests/fixtures/lists/` (fake data), never the real
  lists — keeping the repo safe to publish. Fixtures use reserved names only
  (`.example` domains, `example.com`/`.net`/`.org` addresses, TEST-NET IPs) and carry no
  real senders, recipients or correspondents.

### Greylist match outcomes

- Message matches a known structure → **known / pass**.
- Domain present but no structure matches → **new_structure** (surface for review).
- Domain absent → **unknown** (surface for review).

### The learning loop (currently over Discord, moving into the UI)

1. **Propose** — the scanner generates candidate entries for unfamiliar senders / new
   structures into `daily-brief-{date}/`.
2. **Classify** — each candidate is `unknown_domain`, `new_structure`, or `skip`.
3. **Review** — once a day the UI shows the batch; each card presents the proposal (the
   Canary can pre-annotate a suggested classification + reason) and lets you choose the
   list, whether to catalogue a new structure, and the action group.
4. **Apply** — decisions compile into `instructions-{date}.json`, handed to the applier that
   writes the live lists. Nothing edits the lists without approval.

### Actions

Greylisted / cleared mail carries an **action** the downstream workflow dispatches on:
`finance`, `personal_assistant`, `work`, `calendar`, `summarise`, or none. This is the
payload the outbound webhook hands to the other machine. *(Not yet present in the greylist
schema — to be added per domain during the rebuild.)*

---

## The Canary: security note

The Canary reads text that may itself be an injection, so it is deliberately caged:

- Treats the email strictly as **data to classify, never as instructions.**
- Returns only a **structured verdict** (e.g. `{ injection, phishing, reason }`).
- Has **no tools, no outbound actions, no filesystem/network access** beyond returning that
  verdict.

Its database suggestions are **proposals only**, applied to the lists only after approval in
the UI.

---

## Proposed repository layout

```
email-guard/
├── README.md
├── .gitignore                   # ignores data/lists/*.json (keeps *.sample.json)
├── docker-compose.yml          # bridge + dispatcher + canary + ui + volumes
├── dispatcher/
│   └── email_guard_dispatcher/ # Python package: bridge IMAP in, scanner subprocesses out
│       ├── __main__.py         # --once / poll loop
│       ├── config.py           # imap section + secrets (env or git-ignored file)
│       ├── mailsource.py       # MailSource protocol, ImapMailSource, FakeMailSource
│       ├── scanner_client.py   # runs `python -m email_guard`, reads the verdict
│       ├── state.py            # processed (UIDVALIDITY, UID) + quarantine log
│       ├── sinks.py            # verdict output: logging, optional webhook
│       └── runner.py           # fetch -> scan (pooled) -> commit (serial)
├── scanner/
│   ├── Dockerfile
│   └── email_guard/            # Python package: .eml + rules pack in → verdict out
│       ├── __main__.py
│       ├── clean/              # outlook.py, gmail.py, proton.py  (one shared contract)
│       ├── triage.py
│       ├── deepscan.py         # runs the rules pack
│       ├── assess.py
│       ├── canary.py
│       ├── route.py
│       ├── propose.py          # writes daily-brief candidates
│       └── outputs.py
├── rules/                       # THE RULES PACK — its own version history
│   ├── scan/                   # level2.json … declarative pattern rules   (fail CLOSED)
│   ├── assess/                 # level2.py …    procedural assessment logic (fail CLOSED)
│   ├── reference/              # signature feeds read by triage            (fail OPEN)
│   │   ├── injection_signatures.json   # level 1 — seeded, high precision
│   │   └── phishing_signatures.json    # level 2 — deliberately empty
│   ├── signatures/             # prompt-injection.json  (starts empty)
│   └── validate.py             # load-time + CI validator (scan rules only)
├── applier/                     # consumes instructions-{date}.json → writes live lists
├── canary/                      # local model service config (e.g. Ollama)
├── ui/                          # LAN-only console
├── config/
│   ├── config.json             # single unified config (replaces path files + index refs)
│   └── secrets.sample.json     # template for config/secrets.json (git-ignored)
├── tests/
│   └── fixtures/
│       └── lists/              # SYNTHETIC list fixtures (committed, safe to publish)
└── data/                        # runtime data — git-ignored except *.sample.json
    ├── lists/                  # live lists (host-provided / bind-mounted); ships *.sample.json + .gitkeep
    ├── daily-brief/            # staged candidates awaiting review
    ├── outbound/               # cleared/  flagged/  rejected/
    └── dispatcher/             # state.json (processed UIDs) + quarantine.log
```

---

## Known issues carried over from the prototype

- **Greylist schema drift.** Triage still matches an old greylist schema
  (`greyEntry.pass.subject` / `block.keywords`) that the current data no longer has — the
  live greylist uses `known_structures` / `key_phrases`. Reconcile to one schema.
- **`"ALL EMAILS"` / empty `key_phrases` not handled.** The structure matcher's `.some()`
  over an empty phrase list returns false, so "trust everything" entries don't match. Handle
  empty phrase sets as match-all.
- **Cleaner contract mismatch.** The Proton cleaner returns the full normalised object; the
  Outlook/Gmail cleaners return only `{ metadata, integrity }`. Standardise on one contract.
- **Conflicting / index-based config paths.** Workflows read different config files and
  reference paths by array index (`paths[13]`), which breaks if the order changes. Use one
  named config.
- **Level-5 inversion.** `level4assess` escalates a *suspicious* message to `revisedLevel =
  5`, but level 5 is *most trusted* and routing treats `≥ 4` as `cleared`. Fix so a
  suspicious L4 escalates toward threat, not trust.
- **Dynamic code execution.** Logic stored as strings + `new Function()`; removed by the
  rules pack.
- **Data hygiene.** The live blacklist contains a duplicated entry; dedupe on load.

---

## Roadmap

1. Extract the scanner (clean, triage, deep scan, assessment, routing) into a standalone
   Python package that runs on one `.eml` + a rules pack.
2. Standardise the three cleaner contracts to the normalised message shape.
3. Build the rules pack: declarative scan rules, Python assessment modules, validator.
4. Reconcile the greylist matching to the `known_structures` schema (incl. match-all).
5. Unify configuration into one named config; drop index-based path references.
6. Add the Canary client and stand up the local LLM service; gate on level 1–2.
7. Containerise the scanner (`--rm`); test offline against saved messages.
8. ~~Build the dispatcher (IMAP → spawn) with concurrency + webhook delivery.~~ **Done**,
   poll-based. Still to do: IMAP `IDLE` for latency, and a durable webhook retry queue.
9. Formalise output sinks and the **action** payload; add `action` to the greylist schema.
10. Build the review → applier half of the learning loop, and the Admin UI (the scanner
    already stages candidates into `daily-brief-{date}/`).
11. Wire up consolidated-inbox delivery for `cleared` mail.
12. Seed the prompt-injection signature DB (Canary-assisted) as real traffic is seen.
13. Fix the known issues; add a regression corpus of real sample messages.
14. *(Optional, later)* Attachment content inspection as defense-in-depth.
```
