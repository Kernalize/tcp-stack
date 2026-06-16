#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# dev.sh — start the DOCKER development container (the *isolated* workflow).
#
# This is the ALTERNATIVE to our default "run directly in WSL2" workflow. Use it
# only if you want full filesystem isolation (see docs/setup-windows.md).
# Note: it mounts ~/tcp-stack (a copy inside WSL home), NOT /mnt/c — so if you use
# Docker, keep your source in ~/tcp-stack, not the Windows folder.
#
# Flags explained:
#   --cap-add=NET_ADMIN    grant CAP_NET_ADMIN so the process can create tun0
#   --device=/dev/net/tun  pass the TUN char device into the container
#   --name tcp-stack-dev   fixed name so new_terminal.sh can attach to it
#   -v ...:/workspace      mount the source at /workspace inside the container
#   --rm                   delete the container on exit (state is in the mount)
#   tcp-stack-env          the image built from ./Dockerfile
# Inside the container, setcap works because /workspace is on the container's
# native overlay fs (the /mnt/c xattr problem only applies to the WSL-direct path).
# ─────────────────────────────────────────────────────────────────────────────
docker run -it \
  --cap-add=NET_ADMIN \
  --device=/dev/net/tun \
  --name tcp-stack-dev \
  -v "$HOME/tcp-stack:/workspace" \
  --rm \
  tcp-stack-env
