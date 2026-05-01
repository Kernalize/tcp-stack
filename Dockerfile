# ── Base image ───────────────────────────────────────────────────────────────
# We use debian:bookworm-slim (small ~30MB base) instead of ubuntu.
# Kali is Debian-based, so the same apt commands work. Slim = fewer pre-installed
# packages = smaller attack surface = faster builds.
FROM debian:bookworm-slim

# ── System dependencies ───────────────────────────────────────────────────────
# Explanation of each package:
#   build-essential  → gcc, make, linker — Rust's proc-macro crates need a C linker
#   pkg-config       → helps Rust find system libraries
#   iproute2         → the 'ip' command (ip link, ip addr, ip route)
#   tcpdump          → CLI packet capture — you'll use this constantly to debug
#   netcat-openbsd   → 'nc' for raw TCP/UDP testing
#   curl             → to send HTTP requests to your stack
#   iperf3           → bandwidth benchmarking (Week 12)
#   git              → clone packetdrill and other tools
#   wget ca-certificates → fetch rustup installer securely
#   iputils-ping     → ping command
RUN apt-get update && apt-get install -y \
    build-essential \
    pkg-config \
    iproute2 \
    tcpdump \
    netcat-openbsd \
    curl \
    iperf3 \
    git \
    wget \
    ca-certificates \
    iputils-ping \
    wireshark-common \
    tshark \
    strace \
    linux-perf \
    bison \
    flex \
    && rm -rf /var/lib/apt/lists/*

# ── Install Rust via rustup ───────────────────────────────────────────────────
# We install Rust INSIDE the container so it's completely isolated from
# whatever Rust version is on your Kali host (if any).
# -y = non-interactive, --no-modify-path = don't touch shell configs
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --no-modify-path

# Add cargo/rustup to PATH for all subsequent RUN commands and at runtime
ENV PATH="/root/.cargo/bin:${PATH}"

# ── Verify Rust installed correctly ──────────────────────────────────────────
RUN rustc --version && cargo --version

# ── Install packetdrill (Google's TCP test tool) ──────────────────────────────
# packetdrill lets you write scripted packet-level TCP tests (used in Week 11).
# It needs to be built from source.
RUN git clone --depth=1 https://github.com/google/packetdrill /tmp/packetdrill \
    && cd /tmp/packetdrill/gtests/net/packetdrill \
    && ./configure \
    && make -j$(nproc) \
    && mv packetdrill /usr/local/bin/ \
    && rm -rf /tmp/packetdrill

# ── Working directory ─────────────────────────────────────────────────────────
# /workspace is where we'll mount your project from the host
WORKDIR /workspace

# ── Default command ───────────────────────────────────────────────────────────
# Drop into bash when you 'docker run' without a command
CMD ["/bin/bash"]