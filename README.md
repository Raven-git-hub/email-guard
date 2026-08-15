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
| Prompt-injection signature DB | **Does not exist yet** — starts empty, grows over time |
| Docker dispatcher + scanner | **To be built** |
| Canary (local LLM) semantic checks | **To be built** |
| Candidate generation + daily review | Exists over Discord (clunky); to move into the UI |
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
2. **Triage — initial level** from list hits and obvious signals.
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
│   ├── Dockerfile
│   └── src/                     # IMAP IDLE watcher, scanner spawner, webhook delivery
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
│   ├── scan/                   # level2.json … declarative pattern rules
│   ├── assess/                 # level2.py …    procedural assessment logic
│   ├── signatures/             # prompt-injection.json  (starts empty)
│   └── validate.py             # load-time + CI validator
├── applier/                     # consumes instructions-{date}.json → writes live lists
├── canary/                      # local model service config (e.g. Ollama)
├── ui/                          # LAN-only console
├── config/
│   └── config.json             # single unified config (replaces path files + index refs)
├── tests/
│   └── fixtures/
│       └── lists/              # SYNTHETIC list fixtures (committed, safe to publish)
└── data/                        # runtime data — git-ignored except *.sample.json
    ├── lists/                  # live lists (host-provided / bind-mounted); ships *.sample.json + .gitkeep
    ├── daily-brief/            # staged candidates awaiting review
    └── outbound/               # cleared/  flagged/  rejected/
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
8. Build the dispatcher (IMAP `IDLE` → spawn) with concurrency + webhook delivery.
9. Formalise output sinks and the **action** payload; add `action` to the greylist schema.
10. Build the candidate → daily-brief → review → applier loop, and the Admin UI.
11. Wire up consolidated-inbox delivery for `cleared` mail.
12. Seed the prompt-injection signature DB (Canary-assisted) as real traffic is seen.
13. Fix the known issues; add a regression corpus of real sample messages.
14. *(Optional, later)* Attachment content inspection as defense-in-depth.
```
