# Use the official Rust image as a base
FROM rust:1.78-bookworm

# Install the networking tools required by the project
RUN apt-get update && apt-get install -y \
    iproute2 \
    tcpdump \
    netcat-openbsd \
    curl \
    iperf3 \
    git \
    build-essential \
    cmake

# Install packetdrill (as specified in the curriculum)
RUN git clone https://github.com/google/packetdrill /opt/packetdrill && \
    cd /opt/packetdrill/gtests/net/packetdrill && \
    ./configure && make

WORKDIR /usr/src/tcp-stack
COPY . .

# Keep the container alive for testing
CMD ["sleep", "infinity"]