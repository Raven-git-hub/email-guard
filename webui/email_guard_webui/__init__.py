"""Email Guard review console: the daily review, served over localhost.

The reviewer half of the learning loop (root README, "The learning loop"). The
scanner proposes candidates into ``data/daily-brief/`` and never writes a list;
this component shows that queue to a human and turns each answer into a
decisions document handed to :mod:`email_guard.apply`, which is still the only
code in the repo that writes ``data/lists/*.json``.

It is a *consumer* of the scanner package, not an extension of it: it imports
``email_guard.apply``, ``email_guard.lists``, ``email_guard.propose`` and
``email_guard.config``, and it owns no verdict logic of its own. Nothing here
re-implements a rule the scanner already owns.

Two properties are load-bearing rather than incidental, because this process
reads mail content and edits security lists:

* **Localhost only.** The server binds ``127.0.0.1`` and refuses any other
  interface unless explicitly allowed (:mod:`email_guard_webui.__main__`).
* **No HTML from the server.** The only message text that reaches the browser
  is the candidate's ``excerpt`` -- already de-fanged plain text -- and the
  client renders it via ``textContent``. The CSP forbids inline script so a
  string that looks like markup has nowhere to become markup.
"""

__version__ = "0.1.0"
