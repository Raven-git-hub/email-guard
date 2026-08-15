# reference/n8n — prototype source (for porting only)

These are verbatim exports of the working n8n prototype, provided as the **source of truth
for the Python port**. They are NOT part of the deployed system and should not be run — port
their logic into `scanner/` and `rules/` per the root `README.md`, then this folder can be
kept for reference or removed.

## Contents

| File | What it is |
|------|------------|
| `outlook_cleaner.js`, `gmail_cleaner.js`, `proton_cleaner.js` | Source-specific cleaners. Outlook/Gmail return only `{ metadata, integrity }`; Proton returns the full normalised object. **Standardise all three to one contract during the port.** |
| `level2.json`, `level3.json`, `level4.json` | Deep-scan rule libraries. Each rule's `logic` is a JS string that receives `content` + `context` and returns `{ status }`. Port to the declarative rules pack (+ Python funcs for cross-field rules). |
| `level2assess.js`, `level3assess.js`, `level4assess.js` | Per-level assessment logic (scoring, overturns, verdict, loop control). Port to `rules/assess/levelN.py`. |

> **Removed:** the list samples and the two captured sample messages that once sat here
> carried real personal data (correspondents, bank relationships, recipient addresses) and
> have been deleted. The authoritative list schemas now live in `data/lists/*.sample.json`
> and in `scanner/email_guard/lists.py`; the pipeline's regression fixtures are fully
> synthetic and live in `tests/fixtures/`.

## Porting notes / gotchas

- **Domain matching includes subdomains.** The prototype matches a list entry when
  `senderDomain === entry.domain` **or** `senderDomain.endsWith('.' + entry.domain)`, so a
  sender at `notify.example-bank.test` matches an `example-bank.test` entry. Preserve this
  subdomain matching.
- **Greylist schema is the current one** (`known_structures` / `key_phrases`). The prototype's
  Triage node still references an older `pass`/`block` greylist shape — ignore that; match
  against `known_structures` as described in the root README.
- **"ALL EMAILS" / empty `key_phrases`** means match every message from that sender.
- **Level-5 inversion** in `level4assess.js` is a known bug — see the root README "Known
  issues". Fix during the port (suspicious ⇒ escalate to a threat level, not to trusted 5).
- **Mailbox routing.** Messages forwarded in from an Outlook mailbox carry `x-ms-*` headers and
  route to the **Outlook** cleaner; `x-google-dkim` / `x-gm-*` route to **Gmail**; anything
  else falls back to **Proton**.
- **De-fanged links.** The cleaner rewrites URLs (`http` → `h_ttp`, `.` → `[.]`) before the
  rules pack sees them. The prototype's link rules compared against those de-fanged strings
  and so could never match a real host; the port re-fangs internally for comparison while
  still emitting the de-fanged form.
