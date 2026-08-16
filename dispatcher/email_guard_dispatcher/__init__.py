"""Email Guard dispatcher: bridge IMAP in, scanner subprocesses out.

The dispatcher owns the mail connection and the orchestration around it. It
knows nothing about how a message is scored -- it hands raw bytes to
``python -m email_guard`` and reads the verdict back off stdout. That split is
deliberate (root README, "Components"): the scanner stays a pure function in
container form, and the dispatcher stays dumb enough to be swapped for a
worker pool later without touching it.
"""

__version__ = "0.1.0"
