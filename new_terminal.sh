#!/bin/bash
# new_terminal.sh — open a SECOND shell inside the already-running dev container
# (started by dev.sh). Use it for Terminal 2/3 work (ip addr / ping / tcpdump)
# while the stack runs in the first terminal. Docker workflow only; on the
# WSL-direct workflow just open another WSL tab instead.
docker exec -it tcp-stack-dev bash