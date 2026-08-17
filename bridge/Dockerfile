# The Proton Bridge, plus the one shared library its own auto-update needs.
#
# `shenxn/protonmail-bridge` updates the bridge binary inside the running
# container. A build shipped from Proton now links against libfido2 (the U2F /
# passkey path), and the image does not carry it -- so the bridge that comes
# back after the next restart dies at launch with:
#
#     error while loading shared libraries: libfido2.so.1:
#     cannot open shared object file: No such file or directory
#
# From the outside this looks like the stack breaking on its own: the bridge
# container restart-loops, its IMAP listener never opens, and the dispatcher
# reports EOF or connection-refused against `bridge:143` forever. Nothing in
# this repo changed; the base image updated itself out of a working state.
#
# Pinning the base image to an older tag would trade this for a bridge that
# stops being able to authenticate against Proton. Installing the library is
# the fix that survives the next auto-update as well as this one.
FROM shenxn/protonmail-bridge:latest
USER root
RUN apt-get update && apt-get install -y --no-install-recommends libfido2-1 \
    && rm -rf /var/lib/apt/lists/*
