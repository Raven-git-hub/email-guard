"""Email Guard scanner engine.

One raw message + a rules pack in, a structured verdict out. No network, no
services, no state: the package is a pure function in library form so it can be
driven from the CLI today and from a throwaway container later.

Engine (this package) and rules pack (``rules/``) are deliberately separate --
see the root README, "Engine vs rules pack".
"""

__version__ = "0.1.0"
