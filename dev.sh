#!/bin/bash
docker run -it \
  --cap-add=NET_ADMIN \
  --device=/dev/net/tun \
  --name tcp-stack-dev \
  -v "$HOME/tcp-stack:/workspace" \
  --rm \
  tcp-stack-env
