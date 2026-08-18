"""The two filenames that make up the contract with the scanner.

``.complete`` is written by the scanner as the LAST file of a job directory. It
means every other file of that job -- ``report.json``, the verbatim message
copy, and any extracted attachments -- is already on disk. Its absence means the
directory may be half written, so nothing acts on a job without it.

``.published`` is written by this package, locally, after a job has been copied
to the partition in full. It means "this job is on acheron"; it is what makes
publishing idempotent, and it is what the retention sweep requires before it
will delete anything.

Both are **internal markers** and neither is copied to the partition: the
downstream consumer receives the clean package (report, message, attachments)
and nothing about our bookkeeping. A job directory on acheron is whole by
construction -- it is renamed into place complete -- so a sentinel there would
say nothing a consumer needs.

These names are duplicated from :mod:`email_guard.route` on purpose. This
package runs on the host with no scanner installed, so importing it is not an
option; ``tests/test_publisher.py`` asserts the two definitions agree, which
turns a silent "the publisher just never fires" into a failing test.
"""

from __future__ import annotations

COMPLETE = ".complete"
PUBLISHED = ".published"

#: Never copied to the destination.
INTERNAL_MARKERS = frozenset({COMPLETE, PUBLISHED})

#: Prefix of the staging directory a copy is assembled in, inside the
#: destination bucket. Dot-prefixed so a consumer listing the bucket skips it
#: the same way it skips any hidden entry -- see README, "The Smiley contract".
STAGING_PREFIX = ".publishing-"
