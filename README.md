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

**Validation proves a pack loads. The harness proves it classifies.** Those are
different questions, and the validator above only answers the first: a rule that parses
perfectly, compiles its regexes and quarantines every bank in the country is a valid
pack. So there is a second gate, `python -m email_guard.eval <corpus>` — a labelled
corpus of messages and a scorer that runs each one through the *real* classification
entry point and compares the bucket it lands in to the bucket a human said it should.

Grading is by bucket, and the direction of a failure decides the exit code: mail that
should have been held back but reached `cleared` is **dangerous** and fails the run;
over-blocking is **advisory** and does not, because tightening a rule always costs a few
over-blocks before it is tuned and a gate that fires on that is one people route around.
`--baseline` diffs against a previous run, so "what did my change fix, and what did it
break" is one command.

Two corpora, because a corpus is a pile of whole messages: `tests/eval-corpus/` is
committed and **synthetic-only** (invented senders, reserved `.example` domains) and runs
in the normal test suite; the operator's real mail lives in a gitignored corpus under
`data/`, imported from the scanner's own outbound store and reviewed by hand. The split
is enforced, not documented — the harness refuses a real corpus git would commit, refuses
real cases inside the synthetic one, and the test suite fails the build if any `.eml` is
tracked outside the sanctioned synthetic directories. The rule-tuning loop is
`VALIDATION.md` §10.

### Auto-updating the pack

The `rules-updater` service pulls the pack from git on an interval (24h by default),
validates it, and promotes it — so a security update lands by pushing to the rules repo,
with no redeploy and **no restart of anything**. There is a **Refresh rules** button in
the review console's Config panel for when you would rather not wait.

Nothing restarts because nothing is holding the old rules: each message is scanned by a
fresh `docker run --rm` that mounts the rules directory at scan time, so updating the
files the *next* container will mount is the entire job.

Two properties make that safe to point at live mail:

- **Promotion is atomic.** A pulled pack is staged into `rules-live/releases/<sha>/`,
  which nothing points at, and goes live by swapping a symlink. A scan container starting
  at any instant resolves either the old release or the new one — never a half-written
  tree — and a scan already running keeps the release it started with.
- **The pack's own failure split is preserved exactly.** Scan rules **fail closed**: any
  validator error and the pull is *rejected*, the live pack is untouched, and scanning
  continues on the known-good rules. The signature feed **fails open**: a malformed or
  missing `reference/*_signatures.json` is a warning that still promotes. This is the
  same asymmetry the runtime enforces, for the same reason — a truncated download must
  cost sensitivity, not stop the mail.

The updater is deliberately the narrowest component in the stack: it has **no docker
access** (it creates no containers), **no access to the data volume** (a rules update and
a list edit are independent, and the lists are personal data that is not in git at all),
and it is the **only** component with a writable rules mount. The console has neither git
nor write access; it asks the updater over an internal network, so exactly one process
owns the write path and a scheduled pull cannot race a manual one.

It runs whether or not the scanner has been pointed at the managed tree. Cutting over is
a **deploy-time change** — two variables in `.env` — documented in `.env.sample` and in
VALIDATION.md, "The rules auto-updater, and cutting over to it".

> The validator imports the pulled pack's Python in order to check it, so the updater runs
> it as a subprocess. That is isolation and repeatability, **not a sandbox** — the real
> controls are the container's: non-root, read-only rootfs, all capabilities dropped, no
> docker, no lists. It does have egress, which is the honest residual risk.
>
> Because it imports the pack, **the updater image carries the engine too**. The pack's
> rule functions call into `email_guard` (link alignment, registrable domains), so
> validating a pack means importing it in an environment where the engine is present —
> the *scanner's* environment, not the updater's. Without it the validator reports every
> function rule as "failed to import" and the updater rejects packs that scan mail
> perfectly well. It costs nothing: the engine has zero runtime dependencies. The
> updater's own code still imports nothing from it, so the pack and its updater stay
> independently movable to another repository — and the two images must be built from the
> same checkout, so the engine a pack is validated against is the one that will run it.

---

## Status

| Area | State |
|------|-------|
| Detection logic (levels 2–4) | Exists in prototype (JS strings), to re-express as a rules pack |
| Source cleaners (Outlook / Gmail / Proton) | Provided; contracts to be standardised |
| Triage / initial level assignment | Exists; greylist matching to be updated to current schema |
| Signature reference DB (`rules/reference/`) | **Scaffolded** — injection feed seeded, phishing feed empty by design; static loader that fails open |
| Rules pack auto-updater (`rules_sync/`) | **Built, unvalidated on a host** — scheduled `git pull` plus a manual refresh from the console, validated and promoted atomically by symlink swap. Repointing the scanner's mounts at the managed tree is a deploy-time change — see `VALIDATION.md` §9 |
| Rule evaluation harness (`email_guard.eval`) | **Built** — labelled corpus + scorer over the real classification path; gates on dangerous false-clears, `--baseline` diffs a change. Committed synthetic corpus runs in the test suite; the operator's real corpus is local and gitignored — see `VALIDATION.md` §10. Only as good as the labels a human has reviewed |
| Dispatcher (bridge IMAP → scanner) | **Built** — on-arrival via IMAP `IDLE`, with the poll loop kept as the correctness backstop. Two scanner runners behind one interface: subprocess (dev) and one hardened container per message (deployed). Plus `--rescan`, the one-shot onboarding pass over an entire existing mailbox |
| Per-message scanner container | **Built, unvalidated on a host** — `scanner/Dockerfile` plus `ContainerRunner`: `docker run --rm`, no network, read-only root, non-root, caps dropped, memory/pid/cpu bounded, Docker reached via a socket-proxy. Built where no Docker daemon exists, so the container path has never actually run — see `VALIDATION.md` |
| Canary (local LLM) semantic checks | **To be built** |
| Routing / outbound store | **Built** — every scan lands in `outbound/<bucket>/<job>/` (report + original) |
| Candidate generation + daily review | Scanner **stages candidates** to `daily-brief-{date}/`; the **applier is built** (`email_guard apply`); the **review console is built** — each Confirm applies one decision immediately |
| Webhook / output sinks + actions | Partially proven; actions not yet in the greylist schema |
| Admin UI (lists, stats, quarantine, review, approvals) | **Phase 1 built** (`webui/`) — review queue and list view/add, localhost-bound. Event log, stats, quarantine browsing and config editing are Phase 2 |
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

IDLE is a **trigger only**. Every wake runs the same full drain — enumerate all
unprocessed UIDs — and a drain also happens every `poll_interval_seconds` regardless of
what the server announces. So a missed push or a silently-dropped IDLE connection costs
latency and cannot strand a message: the durable queue is still the mailbox, and the
done-list is still the state file.

How the scanner is invoked is chosen by config (`dispatcher.scanner_runner`) behind a
one-method interface — `scan(raw) -> verdict`. `subprocess` needs no daemon and is the
code default for development and tests; `container` is what compose deploys. The dispatch
logic is identical either way, which is the point: the isolation strategy can change
without the loop changing with it.

**Scanner** — the core engine, a **pure function in container form**: one raw RFC822 message
+ a rules pack in, a verdict + routing decision + database candidates + output event out,
then it exits. Testable offline by piping in a saved `.eml`.

**Canary (local LLM)** — a persistent, warm container (e.g. Ollama) called **only for level
1–2 messages** for semantic prompt-injection / phishing-language detection. Deliberately
caged (see below).

**Admin UI** — the review console. **Phase 1 is built** (`webui/`): a localhost-bound FastAPI
service that hosts the **daily review** replacing the old Discord forms, and shows and edits
the live lists. It is the only component that imports the scanner as a library — it calls
`email_guard.apply` to write lists, `email_guard.lists` to read them and `email_guard.config`
to find them. Stats, quarantine browsing and the event log are Phase 2. See "Running the
review console".

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
| 1b | Greylist `denied` — a catalogued shape the reviewer marked unwanted | **1** |
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
- **Rule 1b sits with rule 1, not rule 4.** A denied structure is a blacklist entry scoped
  to one message shape rather than a whole sender, so it rejects for the same reason and at
  the same point. It does not breach "triage reads content only": the content → disposition
  decision belongs to the greylist matcher, and triage still receives only a classification
  string.

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
   degrades to yesterday's signatures rather than all the way to the baseline. Still not
   implemented **in the loader**. The auto-updater now covers the case this was written for —
   a bad *pull* is rejected whole and the previous pack stays live, so a corrupt feed never
   reaches this resolution order — but a feed corrupted in place, after promotion, still
   falls straight through to 3.
3. nothing — triage falls back to the hard-baked floor in `scanner/email_guard/triage.py`.
   This is a permanent baseline, not a default the feed replaces: the feed only ever adds
   to it.

### The hard-baked floor

| Marker | Catches |
|--------|---------|
| `roleplay_tag` | instruction framing — `system:`, `### Instruction:`, `[INST]:` |
| `hidden_unicode` | zero-width and BOM characters **concealing** something — see below |
| `code_fences` | two or more ` ``` ` fences |
| `instruction_override` | the canonical prose override — `ignore`/`disregard` + `(all)? (the)? previous/prior/earlier/above/foregoing` + `instructions/prompts/directions/rules/commands` |

The first three are *structural*. `instruction_override` is prose, and it is here because the
most common phrasing of the attack once lived only in the feed — so losing the feed reopened
exactly the hole rule 2 exists to close: a whitelisted sender carrying "ignore all previous
instructions" fell through to level 5, cleared. **A rule that evaporates when a file goes
missing is not a floor.**

**Floor and feed overlap on purpose**: the floor is the permanent subset that cannot go
missing, the feed is the updatable superset carrying the long tail (persona reassignment,
concealment, `new system instructions:`). The floor stays deliberately small — anything that
*must* survive the fail-open state belongs in it, everything else belongs in the feed.

Both halves are held to the same precision bar, against one shared false-positive corpus in
`tests/conftest.py`. `instruction_override` requires the instruction-shaped object for the
same reason the feed seeds do: "please disregard the previous **email**" is a routine
correction notice, "disregard the previous **instructions**" is not.

#### `hidden_unicode`: concealment, not merely invisibility

The marker used to be a character census — *any* U+200B/200C/200D/FEFF anywhere in the title
or body was a level-1 reject. Because the floor runs ahead of the lists, that rejected
greylisted and whitelisted senders alike, and mail templates emit zero-width padding as a
matter of course: it was the engine's largest single source of over-rejection (a 300-message
rescan cleared ~12%, with this marker a primary driver — Standard Chartered, HSBC,
`store-news@amazon`, Glassdoor, Suno and Telekom among the victims).

The ordering was never the bug — a trusted sender's account can be compromised, so injection
detection must not be bypassable by list membership. The **detection** is what became
precise. Two shapes now fire, and nothing else does:

| Shape | Example | Why |
|-------|---------|-----|
| a zero-width run **inside a word** | `ig<zw>nore pre<zw>vious` | splits the word for every keyword and phrase matcher downstream while reading identically to a human |
| a run that **hides phrasing** | `ignore all<zw> previous instructions` | stripping the characters makes a floor marker appear that the text as it stands does not match — here the override pattern's `\s+` |

When stripping reveals a marker, that marker is named alongside `hidden_unicode`, so the
reason reads *smuggled, and here is what was smuggled*.

Everything else is padding and raises the level not at all: a run next to whitespace,
punctuation or a string boundary; scattered spacers; a U+200D joining two emoji into one
glyph. "Inside a word" is scoped to the scripts the phrase matching actually reads (Latin,
Greek, Cyrillic, digits), so ZWNJ/ZWJ doing their ordinary orthographic job in Arabic or
Indic text, and the U+200B that Thai and Khmer use as a word separator, never trip it — a
split there evades no matcher this engine runs, and injection phrasing hidden in any script
is still caught by the reveal rule. One residual cost is accepted knowingly: a line-break
hint inside a single long word (German compound nouns are the usual source) is
indistinguishable from a one-word split and still fires.

Both directions are pinned in the committed corpus, and neither case means much alone:
`greylist-zero-width-padding` (a padded receipt that must clear — formerly a `strict` xfail)
and `injection-zero-width-split-rejected` (an override cut mid-word that must still be
rejected).

> **This is engine code, not pack data.** `triage.py` ships inside the scanner image, so it
> does not ride the rules auto-updater: it is live only after `docker compose build scanner`
> on the host. `VALIDATION.md` §10.7.

> **Interval pulling: built.** Pulling this repository on an interval so signature updates
> land without a redeploy is the intended operating mode, and is what the fail-open behaviour
> above exists to protect — see "Auto-updating the pack". The loader itself is unchanged and
> still static: it reads the feeds once, when the rules pack loads, from whatever is on disk.
> That stays correct because a scan container is created per message, so "once per load" is
> once per message.

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
- The verdict carries `tags`: the routing labels of the allowed greylist structure the
  message matched, empty otherwise. This is what the outbound webhook dispatches on.
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
python -m email_guard apply decisions-2026-05-15.json         # the learning loop's other half
```

`apply` is the one subcommand, dispatched on the first argument rather than through argparse
subparsers — subparsers would demand a verb on *every* invocation, turning the documented
`python -m email_guard message.eml` (which the dispatcher runs) into `… scan message.eml`.
An `.eml` file actually named `apply` can be scanned as `./apply`.

| Exit code | Meaning |
|-----------|---------|
| `0` | success |
| `1` | unreadable input, or an output that could not be written |
| `2` | invalid rules pack — refused to scan |
| `3` | contradictory lists — refused to scan |
| `4` | invalid decisions document — no list was written |

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
  "scan_timeout_seconds": 120,
  "idle": true,
  "idle_timeout_seconds": 1500
}
```

| Key | Meaning |
|-----|---------|
| `host` / `port` | Where the bridge listens. `127.0.0.1:1143` is the bridge's default local IMAP — **but under compose it is `bridge:143`**, see below. |
| `mailbox` | Which mailbox to watch. |
| `tls` | `starttls` (the bridge's default), `ssl`, or `none`. |
| `ca_file` | A CA bundle to verify the bridge certificate against. Usually unnecessary — see below. |
| `poll_interval_seconds` | The **guaranteed** drain interval. With IDLE on, mail normally arrives long before this; it is what makes a missed notification harmless rather than a lost message. |
| `max_attempts` | Scans per message before it is quarantined. |
| `concurrency` | Simultaneous scans. Under the container runner this is also how many hardened containers can be alive at once — see "Aggregate resource footprint". |
| `idle` | Use IMAP `IDLE` for on-arrival processing. Set `false` (or `EMAIL_GUARD_IMAP_IDLE=0`) to fall back to pure polling. |
| `idle_timeout_seconds` | How long one `IDLE` stretch may last before being re-issued. Default 1500s, comfortably inside the ~29 minutes RFC 2177 warns a server may allow. |

**About IDLE.** It is hand-rolled over the standard-library `imaplib` connection
(`dispatcher/email_guard_dispatcher/idle.py`) rather than pulled from a library, to keep the
dispatcher's zero-runtime-dependency property. That is only defensible because IDLE here is
a *latency* optimisation and never a correctness one — the poll interval above still bounds
the drain, so a best-effort IDLE that occasionally gives up is exactly good enough. If a
future change makes latency load-bearing, `imapclient` is the obvious swap and `idle.py` is
the only file that would go. Reaching into `imaplib` internals is confined to that one file
for the same reason.

The connection self-demotes when it has to: a server that does not advertise `IDLE`, or
answers `BAD`, drops to polling with one log line; repeated failures give up on IDLE until
the next reconnect. Nothing in that path can lose mail.

**Selecting the scanner runner** — `dispatcher.scanner_runner`, `"subprocess"` (default) or
`"container"`, overridable with `EMAIL_GUARD_SCANNER_RUNNER`. See "Container runtime".

**About the certificate.** The bridge generates its own self-signed certificate at install
time, so there is nothing to verify it against. On a **loopback** host (`127.0.0.1`, `::1`,
`localhost`) the dispatcher accepts it — the connection never leaves the machine, so there is
no network attacker to defend against. On **any other host** the certificate is verified
normally and a self-signed one will be rejected; point `ca_file` at the bridge's certificate
if you genuinely run it on another machine. Verification is never silently disabled for a
remote host.

**Under compose, both of those change** — and the committed defaults are already right:

- **The port is `143`, not `1143`.** 1143 is what the bridge listens on inside its own
  container, and what it publishes to the host when run standalone; the `shenxn` image fronts
  it with socat and exposes **143** on the container network. The dispatcher reaches it over
  that network. Using 1143 there gets a flat connection refusal.
- **That hop runs as `tls=none`.** It sits on a compose network declared `internal: true` —
  no gateway, no route off the host, nothing else attached — which is the same reasoning that
  makes the loopback exemption safe.

  It is not a shortcut past a better option, because there is not one yet. The bridge's
  certificate is issued for `localhost`/`127.0.0.1`, so it fails hostname verification against
  the service name `bridge` whatever `ca_file` is supplied, and there is deliberately no
  verify-off switch. Closing that needs a fourth TLS mode — *encrypt, trust this specific
  certificate, skip the hostname check* — tracked as `TODO(bridge-tls)`. Plaintext on a
  network with no route out is the honest answer meanwhile; a downgrade that pretended to
  verify would be worse.

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
Drop `--once` to run until stopped — mail is then processed **on arrival**, with the poll
interval as the backstop rather than the schedule:

```sh
python -m email_guard_dispatcher            # IDLE, and a full drain at least every
                                            # poll_interval_seconds regardless
```

> **The first live run processes your entire unread backlog.** The dispatcher finds work with
> `SEARCH UNSEEN`, so every unread message in the mailbox is scanned on that first pass. Point
> the first `--once` run at a small or test intake mailbox (`--mailbox Intake`) before turning
> it loose on a real inbox. Under the container runner that first pass is also **slow** — one
> container created and destroyed per message — which is expected, not a fault.
>
> The converse also matters: **a message already marked `\Seen` by another client is never
> scanned.** That is fine for the intended setup — a dedicated intake mailbox that no human
> reads — but it means the dispatcher is not safe to point at a mailbox you browse yourself,
> because anything you open first will be skipped. `--rescan` is the way to reach that mail,
> and the way to onboard an existing inbox — see "Re-scanning the whole mailbox" below.

### What it does with each message

1. `FETCH` the raw RFC822 bytes by UID (with `BODY.PEEK[]`, so reading does not mark the
   message seen before it has actually been scanned).
2. Stage them as an `.eml` and hand them to the configured **scanner runner**, which returns
   the verdict JSON from stdout and an exit code, then cleans up after itself. Under
   `subprocess` that is `python -m email_guard <tmpfile>` on this host; under `container` it
   is `docker run --rm` of the hardened scanner image, and the dispatcher moves that scan's
   private output into `outbound/<bucket>/<job>/` afterwards. Everything downstream of this
   step is identical either way.
3. On success: record the message as processed, mark it `\Seen`, and hand the verdict to the
   configured sinks.
4. On failure: retry up to `max_attempts`. After that, write a line to the quarantine log and
   mark it processed anyway, so one bad message cannot block everything behind it.

Processed messages are recorded by `(UIDVALIDITY, UID)` in `data/dispatcher/state.json`, so a
restart does not rescan them. That file — not the `\Seen` flag — is the authority: any client
can clear a flag, and quarantined messages are recorded there too so a cleared flag cannot
replay a known-bad message. Both it and `data/dispatcher/quarantine.log` name real
correspondents, so both are git-ignored.

### Re-scanning the whole mailbox (onboarding)

The live loop only ever sees what is unread. `--rescan` is the one-shot that sees everything:

```sh
python -m email_guard_dispatcher --rescan --limit 20 --verbose   # trial subset first
python -m email_guard_dispatcher --rescan                        # the whole mailbox
python -m email_guard_dispatcher --rescan --emit-webhooks        # ...and notify downstream
```

It finds work with `SEARCH ALL` rather than `SEARCH UNSEEN`, by UID, so **both** of the
filters the live loop depends on are bypassed: the `\Seen` flag is irrelevant, and so is the
processed-state watermark in `data/dispatcher/state.json`. Every message goes through the
configured scanner runner — the hardened container in production, same as any other scan —
and each report is re-filed into `outbound/<bucket>/<job>/` and each review candidate
re-staged, exactly as a normal drain does. There is no special re-filing path; the scanner
writes those keyed by message id on every run, so re-scanning *is* re-sorting.

> **Run it with the live dispatcher stopped.** It is a one-shot, not a second worker. Two
> processes scanning the same mailbox would fire each other's webhooks and race on the
> scanner's output directories.

What it deliberately does **not** do is touch the live loop's state semantics. It records
nothing in the state file, marks nothing `\Seen`, and quarantines nothing — a scan failure is
logged, counted, and reflected in the exit code, and the message is left exactly where it was
for the live loop to handle properly. Stop the dispatcher, re-scan, start it again, and the
done-list means precisely what it meant before.

| flag | effect |
| --- | --- |
| `--rescan` | scan every message; re-file and re-stage locally; **fire no webhooks** |
| `--emit-webhooks` | also POST each verdict to the configured sink — the onboarding injection |
| `--limit N` | stop after N messages, for a trial run |
| `--verbose` | one line per message at the end, on top of the running progress log |

Webhook emission is off by default because a plain re-sort must not, by itself, replay months
of mail into someone's automation. Turning it on is how the **recognised, tagged backlog**
gets injected into a downstream (n8n) as onboarding — the whole inbox arrives already scored,
bucketed and tagged, rather than the downstream starting from empty.

Expect it to be slow: one hardened container per message over a full inbox is a long job, and
the pass is sequential on purpose so the progress count only goes up and deliveries reach the
downstream in mailbox order. Progress is logged per message, and the run ends with a summary:

```
rescan: mailbox=2841 scanned=2839 failed=2 cleared=2103 flagged=684 rejected=52 candidates=97
```

`--rescan` and `--once` are mutually exclusive, and neither enters the IDLE loop.
`--emit-webhooks` and `--limit` are refused outside `--rescan` rather than quietly ignored.

### Optional webhook

Set `dispatcher.webhook_url` in `config/config.json` or `EMAIL_GUARD_WEBHOOK_URL` in the
environment and each verdict is POSTed as JSON, with a short retry and backoff. With no URL
set, the default sink just logs the verdict. Delivery is currently best-effort — a durable
retry queue is still to come.

Under compose the variable is passed through to the dispatcher (`"${EMAIL_GUARD_WEBHOOK_URL:-}"`),
so it is set in `.env` and nothing tracked changes. **Which URL works depends on where the
downstream runs, and the answer is usually not the address you would type into a browser.**

**(a) The target runs on this host** — n8n in its own compose stack, say. Reach it over *that
service's* docker network, by service name, on its *internal* port:

```sh
# .env
EMAIL_GUARD_WEBHOOK_URL=http://n8n:5678/webhook/email-guard
```

```yaml
# docker-compose.override.yml -- attach the dispatcher to n8n's network
services:
  dispatcher:
    networks: [mail, dockerproxy, n8n]
networks:
  n8n:
    external: true
    name: n8n_default        # `docker network ls` for the real name
```

Using the public hostname instead sends the POST out of the host and back in through the
edge, for a service that is two containers away. That round-trip is pure cost, and it puts
the delivery in front of whatever bot filter the edge runs: **Cloudflare answers a bare
container-issued POST with `error 1010`**, and the event is lost behind a 403-shaped log line
that says nothing about why. The internal URL avoids both.

**(b) The target runs somewhere else** — then it does need a public URL, *and* the dispatcher
needs egress, which it does not have:

```yaml
# docker-compose.override.yml
services:
  dispatcher:
    networks: [mail, dockerproxy, egress]
```

Without that the dispatcher is on `mail` and `dockerproxy` only, both `internal: true`, so an
off-host URL fails to resolve rather than failing to authenticate.

Both are **override patterns, not defaults**. The committed dispatcher reaches the bridge and
the socket-proxy and nothing else; giving the process that handles hostile mail a route off
the host is a decision to make deliberately, in a file that is not tracked.

---

## Container runtime

> **Not yet validated on a real host.** This was built in an environment with a Docker
> client but no daemon, so no container described here has ever actually started. Everything
> reachable without a daemon is tested — the command construction, the hardening flags, the
> host-path translation, orphan reaping, output collection. Starting a container is not.
> **`VALIDATION.md` is the first bring-up runbook**, and it is a real step.

The scanner is the component that parses attacker-controlled input, and the roadmap has it
growing attachment inspection. A subprocess shares this host's filesystem, network and
kernel; that is not a sandbox. In production each message gets its own container, which is
then destroyed.

### One `docker run` per message

```
docker run --rm --name email-guard-scan-<token>
  --label email-guard.role=scanner --label email-guard.scan=<token>
  --network none --read-only --user <uid>:<gid>
  --cap-drop ALL --security-opt no-new-privileges
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m
  --memory 512m --memory-swap 512m --pids-limit 128 --cpus 1.0
  --pull never
  -v <host>/…/<token>/message.eml:/message/message.eml:ro
  -v <host>/rules:/rules:ro
  -v <host>/data/lists:/data/lists:ro
  -v <host>/…/<token>/outbound:/data/outbound
  -v <host>/…/<token>/daily-brief:/data/daily-brief
  email-guard-scanner:0.1.0 /message/message.eml
```

| Flag | What it bounds |
|------|----------------|
| `--rm` | One message, one lifetime. Nothing accumulates. |
| `--network none` | No loopback, no DNS, no egress. A message that achieves execution has nowhere to call. |
| `--read-only` | Immutable root filesystem; the only writable paths are the tmpfs and this scan's own output. |
| `--user <uid>:<gid>` | Never root, even inside a throwaway. Inherited from the dispatcher's own uid; a root dispatcher is refused at startup. |
| `--cap-drop ALL` | The scanner needs no capabilities. |
| `--security-opt no-new-privileges` | A setuid binary cannot re-escalate what was dropped. |
| `--tmpfs /tmp` | `noexec,nosuid,nodev` and size-capped — scratch space, not a staging area. |
| `--memory` + `--memory-swap` | Equal on purpose: without the swap cap a memory limit is evaded by swapping. An archive bomb is OOM-killed. |
| `--pids-limit` | A fork bomb exhausts its own quota and nothing else. |
| `--cpus` | A catastrophic-backtracking regex cannot starve the host. |

All of it dies with the container. What the dispatcher sees is an ordinary failed scan, so
an OOM kill takes the same retry-then-quarantine path as a bad rules pack.

### What a scan container can see

Its own message, the rules pack and the lists — all read-only — plus an **empty, per-scan**
output directory it may write. It does **not** get the shared `data/outbound`: that is the
archive of every message previously judged hostile, and handing a fresh copy to each new
suspect message would be a strange thing for a quarantine to do. The dispatcher moves the
results into place after the container is gone, as a blind directory merge — it knows the
scanner's *paths* because it has to mount them, and nothing about its *format*.

One consequence worth knowing: the scanner reports paths as it saw them, so the verdict's
`written` section is rewritten to point at where the files actually ended up before any sink
sees it.

### Docker access: a socket-proxy, never the socket

The dispatcher must create containers. The obvious way — bind-mounting
`/var/run/docker.sock` into it — is host-root-equivalent: anyone reaching that socket can
start a privileged container mounting `/`. Giving it to the process that handles hostile
mail would defeat the entire exercise, so the socket goes to a `tecnativa/docker-socket-proxy`
instead, on an `internal: true` network, with an allow-list.

**Be clear-eyed about what that buys.** `CONTAINERS=1` + `POST=1` still permits container
creation, which is inherently powerful. What it removes is everything else — images,
volumes, networks, exec, swarm, system and info — and it keeps the socket out of the
dispatcher's mount namespace entirely. A large reduction, not an elimination. Claiming
otherwise would be false comfort.

The allow-list starts as tight as it plausibly goes. **If the first real `docker run`
returns a 403 from the proxy, the fix is the allow-list, not the code** — most likely
`IMAGES: 1`, since `docker run` may inspect the local image before creating a container.
Add only what a refused call actually names; `VALIDATION.md` has the diagnosis steps.

### The volume-path model, and the way it fails

Bind-mount **sources are resolved by the host daemon**, not inside the dispatcher's mount
namespace. A containerised dispatcher that passes its own internal path mounts a different
directory — or an empty new one — and *the failure is quiet*: the container starts, finds no
rules pack, and reports a rules-pack error that says nothing about mounts.

So configuration carries **both** paths for every shared tree, and the runner translates:

| Key | Meaning |
|-----|---------|
| `container.host_data_dir` / `container.data_dir` | where `data/` is **on the host**, and where the dispatcher sees it |
| `container.host_rules_dir` / `container.rules_dir` | the same pair for the rules pack |

Host paths default to the dispatcher's own, which is correct whenever it is not itself
containerised. Under compose they come from a single `EMAIL_GUARD_HOST_ROOT` in `.env`, and
compose refuses to start if it is unset. The per-message spool is deliberately created
*under* the data root so it is translatable; anything outside is a startup error.

Startup checks everything checkable without a daemon and logs the full mapping at INFO.
Whether the host path is *correct* is only observable on a host — check that log line by eye
on first bring-up.

### Orphan reaping

`--rm` only fires when a container exits on its own, so a dispatcher killed mid-scan leaves
one running, still holding its memory and pid quota. Every scan container is labelled
`email-guard.role=scanner`; on startup, **before draining**, the dispatcher removes any it
finds. The label is what makes them identifiable without a registry that would itself have
to survive the crash. Reaping failures log and continue — draining mail matters more.

Labels carry a random token, never a sender or a message id: `docker ps` output is not a
place for personal data.

### Aggregate resource footprint

The caps above are **per container**, and scans run in the existing thread pool, so up to
`concurrency` of them are live at once. Set the two as a matched pair:

| `concurrency` | Peak memory | Peak pids | Peak CPU |
|---|---|---|---|
| 4 (default) | **2 GB** | 512 | 4 cores |
| 2 | 1 GB | 256 | 2 cores |
| 1 | 512 MB | 128 | 1 core |

Lower `imap.concurrency`, or lower `dispatcher.container.memory`, if that ceiling does not
fit the host. Both are configurable; the defaults assume a machine with a few GB to spare.

**Expect the first drain of a large backlog to be slow.** One container is created, run and
destroyed per message, and container startup dominates a scan that otherwise takes
milliseconds — so it is materially slower than the subprocess path. That is correct
behaviour, not a fault. Point the first live run at a small intake mailbox.

### Updating the scanner

The scanner now runs from an **image**, not from the working tree. Changing scanner code and
restarting the dispatcher does nothing — the dispatcher is not what runs it:

```sh
docker compose --profile build build scanner   # rebuild the image
docker compose restart dispatcher              # only needed for dispatcher changes
```

The next message picks up the new image automatically; there is nothing to restart for the
scanner itself, because every scan is a fresh container. `EMAIL_GUARD_SCANNER_IMAGE` and the
tag compose builds must agree — if they drift, every scan fails with `No such image`, which
the runner reports as exactly that and names the rebuild as the fix.

Changing the **rules pack or the lists** needs no rebuild at all: both are mounted read-only
at scan time, so an edit takes effect on the next message.

---

## Running the review console

The reviewer's half of the learning loop, served as a single page. The scanner stages
candidates; this is where a human answers them, and each answer goes straight through
`email_guard.apply` to the live lists. It writes nothing any other way.

```
pip install -e ".[webui]"
python -m email_guard_webui            # http://127.0.0.1:8080/
```

Flags mirror the scanner's — `--config`, `--lists-dir`, `--daily-brief-dir`,
`--outbound-dir` — plus `--host` and `--port`. Everything else comes from the `webui`
section of `config/config.json` or the environment (`EMAIL_GUARD_WEBUI_HOST`,
`EMAIL_GUARD_WEBUI_PORT`, `EMAIL_GUARD_WEBUI_TOKEN`,
`EMAIL_GUARD_WEBUI_FRAME_ANCESTORS`).

### What Phase 1 does

- **Review** — the queue read from `data/daily-brief/*/candidate.json`, one card per
  candidate *that still needs an answer*: the sender, the flags, the message excerpt, and
  which list (if any) already covers that sender. Choose a list, catalogue a structure if it
  is a greylist decision, and Confirm — which applies **one** decision immediately, as its
  own single-item decisions document, and moves the candidate into a `reviewed/` sibling so
  it does not come back on reload. **Skip** is client-side only: it re-queues the card and
  tells the server nothing, because "not yet" is not a decision.

  **The queue is live against the current lists.** A candidate was staged against the lists
  as they stood *then*, so every read of the queue re-asks the scanner's own question —
  `propose.classify` over `lists.classify_greylist`, from the subject and excerpt the
  candidate already carries — against the lists as they stand *now*, and suppresses whatever
  is already answered: the sender is now white/blacklisted, or the message now matches a
  known greylist structure, allowed **or** denied. What is left is only the genuinely
  unresolved — unknown senders, and greylisted senders whose message matches no structure
  they have. So listing a sender clears their pending cards without a second click, and a
  greylisted subscription stops producing a card per message. The filter is
  non-destructive: nothing moves on disk, and a card returns if the entry that covered it is
  later removed. The response carries a `suppressed` count so a queue that shrank is
  legible.

- **Trust all mail from this sender** — the one-click answer to a sender whose *every*
  message is wanted, sitting on the review card beside the list choice with an optional tags
  field. It greylists the sender's domain with an `"ALL EMAILS"` catch-all — empty
  `key_phrases`, disposition `allowed`, carrying those tags — which the matcher reads as
  "every message from this sender". A subscription that puts a per-message reference in
  every subject line is otherwise unanswerable by structure: each message is a new shape, so
  it generates a card forever. With the catch-all written, future mail clears and carries the
  tags, and the sender's other pending cards drop out of the queue by the rule above. A shape
  already catalogued as `denied` on that domain **stays denied** — trusting a sender
  wholesale does not un-block the one thing from them a reviewer rejected.
- **List Data** — the live entries per list, greylist structures with their resolved
  dispositions, and a manual **Add** that builds a decision and applies it down the same
  path. There is no second way into `data/lists/`.
- **Event Log** is present but inert — the event store is Phase 2. **Config** is inert with
  one exception: **Refresh rules** is live, and pulls the rules pack through the
  rules-updater service (see "Auto-updating the pack"). Everything else on that panel is
  still a placeholder — SAVE is disabled rather than silent, and the recognitions chart is
  empty rather than invented.

### Why it binds loopback

The console reads mail content and edits the lists that decide whether mail is delivered,
over plain HTTP, with no password unless you configure one. The default bind is `127.0.0.1`
and a non-loopback address is refused unless asked for twice — the host *and*
`--allow-non-loopback` (or `EMAIL_GUARD_WEBUI_ALLOW_NON_LOOPBACK=1`). That flag exists for
the container case, where the process must bind `0.0.0.0` for a published port to reach it
and `docker-compose.yml` pins the publication to `127.0.0.1`. The host *port* is configurable
(`EMAIL_GUARD_WEBUI_HOST_PORT`, default 8080) so the console can move out of the way of
whatever else already has 8080; the loopback interface is not.

Optional shared-token auth guards every `/api/` route: set `EMAIL_GUARD_WEBUI_TOKEN`, or put
it in `config/secrets.json` under `webui.token` (git-ignored, like the bridge credentials —
never in `config.json`, which is committed). Clients present it as `X-Email-Guard-Token`; a
browser picks it up once from `?token=…`, keeps it in `sessionStorage` and strips it from
the address bar. The static shell stays reachable without it, because it carries no data and
a browser cannot put a header on a top-level navigation.

### The rendering rules

Reviewing hostile mail in a browser is the one genuinely dangerous thing this project does,
so two rules are structural rather than conventional:

- **Every response carries a CSP**, from a middleware so no handler can forget it:

  ```
  default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline';
  connect-src 'self'; img-src 'none'; base-uri 'none'; form-action 'none';
  frame-ancestors 'none'
  ```

  `frame-ancestors` is the single knob (`webui.frame_ancestors`) so the side-panel host can
  be allowed to embed the console later without touching the rest of the policy. `script-src
  'self'` is why the UI's JavaScript lives in `webui/static/app.js` and binds every handler
  with `addEventListener` — an inline `onclick=` is inline script.

- **The server never sends an HTML body.** The only message text it will serve is the
  candidate's `excerpt` — the scanner's `clean_text`, HTML already stripped and links already
  de-fanged — and the client writes it with `textContent`. There is no `innerHTML` in
  `app.js`, and a test asserts there never is.

### Docker

The console is one service in the full stack:

```
cp .env.sample .env && $EDITOR .env       # required paths and credentials
docker compose --profile build build scanner
docker compose build bridge dispatcher webui
docker compose up -d                       # bridge + dispatcher + socket-proxy + webui
```

`docker compose up -d webui` still brings up the console alone.

**Deploying a console change.** The console's code — `webui/`, and the parts of the scanner
package it imports in-process (`apply`, `lists`, `propose`, `config`) — is baked into the
`webui` image, so a change to any of it needs that image rebuilt and the container
recreated:

```
docker compose build webui
docker compose up -d --force-recreate webui
```

The **scanner** image needs no rebuild for a console-only change, even one that touches
`scanner/email_guard/apply.py`: the scanner never applies decisions — proposing and applying
are separate halves of the loop on purpose — so its copy of the applier is inert. Rebuild
the scanner (`docker compose --profile build build scanner`) when the *scanning* path
changes, `propose.py` included, since that is the half the scanner does run.

The console publishes to loopback only — `127.0.0.1:${EMAIL_GUARD_WEBUI_HOST_PORT:-8080}`
— and shares the same data volume the dispatcher and scanner use, so it reads the candidates
they stage and writes the lists they read back. Run it as your own uid (`EMAIL_GUARD_UID` /
`EMAIL_GUARD_GID`) to keep the lists hand-editable afterwards.

**The state file and the data directories live on a named volume**, so a container recreate
cannot take the done-list with it — losing `data/dispatcher/state.json` would rescan the
whole mailbox and re-fire every webhook. The volume is bound to a known host directory
because the dispatcher has to name that host path when mounting into scanner containers.

A filled-in `.env` is the whole of the configuration — there is no override file to write
and nothing tracked to edit. Two things to know before the first `up`:

- **`EMAIL_GUARD_HOST_ROOT` must be this repo's absolute path on the host.** Compose fails
  loudly if it is unset; if it is set but *wrong*, scans fail with a confusing rules-pack
  error. See "The volume-path model" above.
- **The bridge service reuses your existing, already-logged-in Proton Bridge** via
  `EMAIL_GUARD_BRIDGE_CONFIG_DIR`. It does not initialise a new one, and pointing it at an
  empty directory forces the whole account-login and keychain dance again.

#### The bridge is built here, not pulled

`bridge/Dockerfile` is three lines on top of `shenxn/protonmail-bridge:latest`, and it exists
because that image **updates the bridge binary inside the running container**. The build
Proton now ships links against `libfido2.so.1`, which the image does not carry, so the next
restart after that self-update dies at launch with:

```
error while loading shared libraries: libfido2.so.1: cannot open shared object file
```

Nothing in this repository changes; the stack simply stops working one day. And the symptom
lands somewhere else entirely — the bridge restart-loops, never opens its IMAP listener, and
the *dispatcher* logs `EOF` or connection-refused against `bridge:143` forever, which reads
as a dispatcher fault. The Dockerfile installs `libfido2-1`, so `docker compose build bridge`
and `up` give a bridge that survives its own auto-updates. Pinning an older base tag would
only trade this for a bridge that eventually cannot authenticate against Proton.

The bridge sits on two networks: the `internal: true` `mail` network it shares with the
dispatcher, and a second `egress` network it needs to reach Proton at all — without egress it
never authenticates, never opens IMAP, and the dispatcher just sees EOF. The dispatcher stays
off `egress`.

Expect the dispatcher to log a few `could not connect ...; retrying` lines at startup: it
comes up alongside the bridge and waits it out with backoff rather than exiting.

Scanner containers are created by the dispatcher, not by compose, so they never appear in
`docker compose ps`. Find them with `docker ps --filter label=email-guard.role=scanner`.

Full first-run procedure and diagnosis: **`VALIDATION.md`**.

---

## Databases & the daily review

### List schemas (from the live samples)

```
whitelist: [ { email|domain, friendly_name, tags: [], known_structures: [ { name, key_phrases: [] } ] } ]
blacklist: [ { email|domain, friendly_name?,          known_structures: [ ... ] } ]
greylist:  [ { domain,       tags: [],
               known_structures: [ { name, key_phrases: [ "Subject: …", … ],
                                     disposition: "allowed"|"denied", tags: [] } ] } ]
```

- Whitelist / blacklist normally key on **email**; greylist always keys on **domain**. A
  whole-domain white/blacklist entry is legal too — the wizard writes one when the reviewer
  decides about a domain rather than a correspondent.
- A structure with empty `key_phrases`, or one named `"ALL EMAILS"`, means **match every
  message from this sender** (the matcher must handle empty phrase sets explicitly).
- `"Subject: …"` phrases match the subject; other phrases match the body.
- **Domain matching includes subdomains**: a list entry matches when
  `sender_domain == domain` or `sender_domain` ends with `"." + domain` (so
  `notify.example-bank.test` matches an `example-bank.test` entry).

**`disposition`** — a greylist structure either clears its shape or rejects it.

- `"allowed"` (the **default when the key is absent**, so every list written before
  dispositions existed keeps its meaning) → the shape is catalogued and fine.
- `"denied"` → the shape is catalogued and unwanted; it rejects at level 1, exactly like a
  blacklist entry scoped to one message shape rather than a whole sender.
- A value that is neither **fails closed to `denied`** and is rejected by the validator, so
  a typo can never buy trust.

**`tags`** — free-form routing labels on entries and on structures. The matched *allowed*
structure's tags are carried onto the verdict as `tags`, for the outbound webhook to
dispatch on. **Tags never affect the threat level**; they say what a message *is*, not how
dangerous it is.

**One domain, one list.** An address or domain is represented on exactly one of the three
lists. The lists answer a single question — who is this sender? — and the matcher consults
them in a fixed order, so a sender on two lists would get a verdict decided by precedence
rather than by the reviewer. `Lists.load` **fails closed** on a violation, the same way the
rules pack does; the applier maintains the invariant when it writes.

The invariant is about *keys*, not coverage, and removal is deliberately narrower than
matching: `phish.bank.example` on the blacklist while `bank.example` is greylisted is a
refinement the precedence ladder resolves correctly, not a contradiction. Matching broadly
is defence in depth; deleting broadly is data loss.

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
- A reviewed candidate is **moved, not deleted**: the review console puts it in a `reviewed/`
  sibling under the same `daily-brief-{date}/{job}/` folder, so the proposal behind a list
  change stays alongside it. That tree is already git-ignored personal data, so keeping it
  costs nothing and losing it would cost the audit trail.
- The review console serves mail content to a browser on loopback and adds no new store: it
  reads the same `data/daily-brief/` and writes the same `data/lists/`. Nothing it renders is
  cached (`Cache-Control: no-store` on every API response).

### Greylist match outcomes

- Message matches an **allowed** structure → **known / pass** (level 4), carrying that
  structure's `tags`.
- Message matches a **denied** structure → **denied / reject** (level 1).
- Domain present but no structure matches → **new_structure** (surface for review).
- Domain absent → **unknown** (surface for review).

**Denied wins.** A message matching both an allowed and a denied structure is denied — the
reviewer catalogued the denied shape precisely to reject it, and a broad `"ALL EMAILS"`
entry must not override that. Neither the scan over structures nor the scan over covering
entries short-circuits, because a sender at `notify.bank.example` can be covered by a
`bank.example` entry and a `notify.bank.example` entry at once.

### The learning loop (now in the review console — see "Running the review console")

1. **Propose** — the scanner generates candidate entries for unfamiliar senders / new
   structures into `daily-brief-{date}/`.
2. **Classify** — each candidate is `unknown_domain`, `new_structure`, or `skip`.
3. **Review** — once a day the UI shows the batch; each card presents the proposal (the
   Canary can pre-annotate a suggested classification + reason) and lets you choose the
   list, whether to catalogue a new structure, and the action group.
4. **Apply** — decisions compile into a **decisions document** handed to the applier that
   writes the live lists. Nothing edits the lists without approval. Two producers, one
   contract: the CLI takes a whole `decisions-{date}.json` by hand, and the review console
   emits a single-decision document per Confirm — the applier is all-or-nothing, so batching
   a day's answers would let one bad card block every other decision.

#### The decisions document

The contract between the review UI and the applier. Emitting one of these is the *only* way
a live list changes.

```json
{ "decisions_version": 1, "reviewed": "2026-05-15",
  "decisions": [
    { "candidate": "<job-or-domain>",
      "action": "whitelist" | "greylist" | "trust_all" | "blacklist" | "discard",
      "entry":     { "email"|"domain", "friendly_name"?, "tags": [] },
      "structure": { "name", "key_phrases": [], "disposition": "allowed"|"denied", "tags": [] } }
  ] }
```

- `entry` names the **subject** of the decision and is required for all four list actions
  — a greylist decision needs a target domain like any other. Exactly one of `email` or
  `domain`; a greylist `entry` must use `domain`.
- `structure` is **greylist-only** and says what to catalogue, with its disposition. A
  greylist decision without one just creates the entry, whose shapes then all come back
  `new_structure` for review.
- `trust_all` is the greylist action for a sender whose every message is wanted: it writes
  the domain's entry with the `"ALL EMAILS"` catch-all structure — empty `key_phrases`,
  disposition `allowed`, carrying the `entry`'s `tags` — and therefore carries **no
  `structure` of its own**, which is refused rather than half-honoured. It keys on `domain`
  like any greylist decision, and a `greylist` and a `trust_all` for one domain are not a
  conflict: both name the greylist, and both apply to the one entry.
- `discard` drops the candidate and touches nothing.

This mirrors the wizard. A new domain: `action` picks the list; white/black writes a
match-all entry (plus `tags` for the whitelist); greylist writes or appends the structure.
A domain already on the greylist is just a greylist decision that appends another structure
to the existing entry — and `trust_all` is that same append with the shape already decided,
which is why re-trusting a domain replaces its catch-all in place rather than duplicating it.

#### The applier

```
python -m email_guard apply decisions-2026-05-15.json [--lists-dir DIR] [--dry-run]
```

It prints a JSON report of every change to stdout and `wrote <path>` lines to stderr, and it
owes four guarantees:

- **Mutual exclusivity.** Applying a decision first removes every entry claiming that domain
  from the other two lists — including address-keyed ones, since an address claims its
  domain — and logs each removal. The new decision wins; that is what approving it meant.
- **All-or-nothing.** The whole document is validated before anything is applied, naming the
  candidate that failed, and the resulting lists are validated in memory before anything is
  written. One bad decision leaves every file exactly as it was.
- **Idempotent.** Re-applying a document changes nothing: a structure is appended only when
  its name is not already on the entry. A structure of the same name whose *content* differs
  is replaced in place rather than silently dropped — flipping a shape from `allowed` to
  `denied` is the operation a reviewer most needs once a domain starts sending something
  nasty.
- **Atomic.** Each file is written to a temp sibling and renamed, so a crash mid-write cannot
  truncate a live list. Atomicity is per file; files that only *lost* entries are written
  first, so a crash between renames leaves a domain on zero lists — re-reviewed at level 3 —
  rather than on two, which the loader would now refuse.

Hand-edited files round-trip: the `{"greylist": […]}` wrapper, a bare top-level array, and
sibling keys such as `_note` all survive a rewrite untouched.

### Actions

Greylisted / cleared mail carries an **action** the downstream workflow dispatches on:
`finance`, `personal_assistant`, `work`, `calendar`, `summarise`, or none. This is the
payload the outbound webhook hands to the other machine. *(Still not in the greylist schema.
The general routing hook now exists — `tags` on entries and structures, surfaced on the
verdict — and the single `action` enum is to be layered on top of it.)*

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
├── VALIDATION.md                # first bring-up runbook for the container runtime
├── .gitignore                   # ignores data/lists/*.json (keeps *.sample.json)
├── .env.sample                  # host paths + bridge credentials for compose
├── docker-compose.yml          # bridge + dispatcher + socket-proxy + webui (+ canary to follow)
├── dispatcher/
│   ├── Dockerfile              # long-lived service; carries the docker CLI, never the socket
│   └── email_guard_dispatcher/ # Python package: bridge IMAP in, scanner containers out
│       ├── __main__.py         # --once / IDLE+poll loop; reaps orphans before draining
│       ├── config.py           # imap section + secrets (env or git-ignored file)
│       ├── mailsource.py       # MailSource protocol, ImapMailSource, FakeMailSource
│       ├── idle.py             # hand-rolled IMAP IDLE over imaplib (the only file that
│       │                       #   touches imaplib internals)
│       ├── scanner_runner.py   # the seam: ScanOutcome, ScannerRunner, runner selection
│       ├── scanner_client.py   # SubprocessRunner -- `python -m email_guard`
│       ├── container_runner.py # ContainerRunner -- `docker run --rm`, one per message
│       ├── state.py            # processed (UIDVALIDITY, UID) + quarantine log
│       ├── sinks.py            # verdict output: logging, optional webhook
│       └── runner.py           # fetch -> scan (pooled) -> commit (serial)
├── scanner/
│   ├── Dockerfile              # the per-message unit: pure function in container form
│   └── email_guard/            # Python package: .eml + rules pack in → verdict out
│       ├── __main__.py
│       ├── clean/              # outlook.py, gmail.py, proton.py  (one shared contract)
│       ├── triage.py
│       ├── deepscan.py         # runs the rules pack
│       ├── assess.py
│       ├── canary.py
│       ├── route.py
│       ├── propose.py          # writes daily-brief candidates
│       ├── apply.py            # decisions document in → live lists out
│       └── outputs.py
├── rules/                       # THE RULES PACK — its own version history
│   ├── scan/                   # level2.json … declarative pattern rules   (fail CLOSED)
│   ├── assess/                 # level2.py …    procedural assessment logic (fail CLOSED)
│   ├── reference/              # signature feeds read by triage            (fail OPEN)
│   │   ├── injection_signatures.json   # level 1 — seeded, high precision
│   │   └── phishing_signatures.json    # level 2 — deliberately empty
│   ├── signatures/             # prompt-injection.json  (starts empty)
│   └── validate.py             # load-time + CI validator (scan rules only)
├── canary/                      # local model service config (e.g. Ollama)
├── webui/                       # the review console — localhost-bound FastAPI + one page
│   ├── Dockerfile
│   ├── email_guard_webui/      # Python package: the only consumer of the scanner library
│   │   ├── __main__.py         # argparse + uvicorn; refuses a non-loopback bind
│   │   ├── config.py           # host/port/token/frame-ancestors + the scanner's data dirs
│   │   ├── app.py              # the FastAPI app: CSP middleware, token guard, endpoints
│   │   ├── candidates.py       # the daily-brief queue: read, project, consume
│   │   ├── decisions.py        # a card's answer → a one-item decisions document
│   │   └── listing.py          # the live lists, projected for the List Data panel
│   └── static/                 # index.html + app.css + app.js (no inline script — CSP)
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
7. ~~Containerise the scanner (`--rm`); test offline against saved messages.~~ **Done** —
   `scanner/Dockerfile` and `ContainerRunner` run one hardened throwaway container per
   message. Still to do: validate it on a host with a real Docker daemon (`VALIDATION.md`).
8. ~~Build the dispatcher (IMAP → spawn) with concurrency + webhook delivery.~~ **Done**.
   ~~Still to do: IMAP `IDLE` for latency~~ **Done** — IDLE triggers the drain, polling
   still guarantees it. Still to do: a durable webhook retry queue.
9. Formalise output sinks and the **action** payload; add `action` to the greylist schema.
10. ~~Build the applier half of the learning loop~~ **Done** — `email_guard apply` consumes a
    decisions document and writes the live lists, with greylist dispositions and tags behind
    it. ~~The review UI that emits the decisions document~~ **Done (Phase 1)** — `webui/`
    serves the review queue and the list panel over loopback. The queue is live against the
    current lists, and **Trust all mail from this sender** answers the subscription case in
    one click. Still to do: the event store behind the Event Log and the recognitions chart,
    the dispatcher config panel, and the daily digest that presents the batch.

    Also still to do, and deliberately not folded into the trust-all change: **generalising
    structure *capture*.** Both halves of the capture path are over-specific — the scanner's
    proposed structure is the whole subject line, and the console catalogues the phrase the
    reviewer pastes — so a subject carrying a per-message reference produces a structure that
    matches exactly one message. The catch-all covers the sender you want trusted wholesale;
    it does nothing for the sender you want *structure-sorted*, where the fix is capturing
    short stable phrases rather than paragraph-length ones. That is a fuzzier change (what
    makes a phrase stable is a judgement about a corpus, not a rule) and belongs on its own.
11. Wire up consolidated-inbox delivery for `cleared` mail.
12. Seed the prompt-injection signature DB (Canary-assisted) as real traffic is seen.
13. Fix the known issues; add a regression corpus of real sample messages.
14. *(Optional, later)* Attachment content inspection as defense-in-depth.
```
