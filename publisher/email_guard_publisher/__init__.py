"""The host-side bridge: local job directories -> the network partition.

This package is deliberately NOT part of the container stack. Email Guard's
scanner and dispatcher run in hardened containers that can see local disk and
nothing else; the wider network drive is reachable only from the HOST, through
the mounted partition ``/mnt/network/acheron``. Something has to carry a
finished job across that line, and this is it -- a small, stdlib-only program
run by two systemd units on the host, under an ordinary user account.

The shape of the boundary, and why it is drawn here:

    scanner container ──writes──▶ data/outbound/<bucket>/<job>/   (local disk)
                                              │
                        HOST, systemd path unit + this package
                                              │
                                              ▼
                                  ${DEST}/<bucket>/<job>/         (acheron)
                                              │
                                        ──consumed by──▶ "Smiley"

The containers never mount acheron. Not "should not": they have no mount for it
and no network route to the drive, so a compromised scanner cannot reach the
share whatever it does -- the blast radius of hostile mail stops at the local
job directory. This program is the only crossing, it runs outside the sandbox,
and it copies bytes without interpreting them.

Two entry points, one for each unit (see ``publisher/systemd/``):

* :mod:`~email_guard_publisher.publish` -- fired by a **path unit** when a new
  ``.complete`` sentinel appears under the outbound tree. Copies each finished,
  unpublished job to the partition and marks it ``.published`` locally.
* :mod:`~email_guard_publisher.cleanup` -- fired by a daily **timer**. Deletes
  local job directories that are published AND older than the retention window.

Nothing here imports the scanner, and nothing here is installed into any image:
it is stdlib-only so the host can run it straight from the checkout with no
virtualenv, no ``pip install``, and no dependency that could drift from the
containers'. The two filenames it shares with the scanner (``.complete``,
``.published``) are restated in :mod:`~email_guard_publisher.markers` rather
than imported -- a four-word wire contract, pinned by a test on both sides.
"""

from __future__ import annotations

__all__ = ["cleanup", "config", "markers", "publish"]
