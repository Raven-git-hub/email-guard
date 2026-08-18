"""The filenames this package treats as structural: the markers, and the staging prefix.

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

Note the asymmetry between the markers and :data:`STAGING_PREFIX`, because it is
not decoration. The markers are written to the LOCAL outbound tree only, which is
ext4, where a leading dot is ordinary. The staging directory is created on the
DESTINATION, which is a CIFS/SMB share, and that server refuses to create any
name beginning with a dot -- so the staging prefix must not have one. Both facts
are load-bearing and neither generalises to the other.
"""

from __future__ import annotations

COMPLETE = ".complete"
PUBLISHED = ".published"

#: Never copied to the destination.
INTERNAL_MARKERS = frozenset({COMPLETE, PUBLISHED})

#: Prefix of the staging directory a copy is assembled in, inside the destination
#: bucket.
#:
#: It MUST NOT begin with a dot. Acheron is a CIFS/SMB share
#: (``//192.168.1.71/acheron``) whose server refuses to create any file or
#: directory whose name starts with one: ``mkdir with.dots`` succeeds, ``mkdir
#: .anything`` fails with ENOENT. The first version of this prefix was
#: ``.publishing-``, and the result was that the very first ``mkdir`` on the
#: share raised ``FileNotFoundError`` and not one job ever published. A dot here
#: does not degrade the design -- it breaks it outright, on this destination.
#:
#: Nothing about safety rests on this directory being hidden. A consumer never
#: sees a partial package under the real ``<job>`` name because the last step is
#: an atomic ``os.rename`` into that name, and the primary consumer (Smiley) is
#: webhook-triggered with the exact job name rather than scanning the bucket. A
#: consumer that DOES scan should skip entries starting with this prefix -- see
#: README, "The Smiley contract".
#:
#: ``tests/test_publisher.py`` asserts the leading dot cannot come back.
STAGING_PREFIX = "publishing-"
