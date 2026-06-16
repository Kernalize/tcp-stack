# Validation

How this stack is verified — two layers: an **automated, offline** layer that runs in CI on every
push, and a **live** layer you run by hand against the real Linux kernel.

## 1. Automated (offline, no network, no privileges)

Everything here runs with `cargo test` — deterministically, on a simulated millisecond clock, with no
TUN device and no `sudo`. This is the bar the project holds itself to: if a behaviour can't be proven
offline, it's called out as such.

```bash
cargo test                                  # 153 unit + integration tests
cargo clippy --all-targets -- -D warnings   # lint-clean (matches CI)
```

What the suite covers:

- **Parsers vs. known packets** — IPv4 / ICMP / UDP / TCP headers and options decoded and re-encoded,
  cross-checked against `etherparse`.
- **The state machine** — passive/active open, data transfer, half-close, the full four-way teardown,
  TIME_WAIT, RST, and the RFC 5961 / 1337 robustness rules.
- **Reliability & congestion math** — adaptive RTO (RFC 6298), retransmission, NewReno, RFC 6675
  SACK recovery, RACK-TLP, CUBIC, and BBR (BtlBw/RTprop filters, the four-state machine, pacing).
- **End-to-end loss resilience** — `socket::bulk_transfer_survives_packet_loss_end_to_end` drives two
  real stacks back-to-back through a **lossy loopback** (~12% of datagrams dropped each way) and
  asserts a 16 KB transfer arrives **intact and in order**. This exercises SYN/data retransmission,
  fast-retransmit / RACK / NewReno recovery, and out-of-order reassembly together — the offline,
  CI-gated equivalent of an `iperf3`-under-`tc netem` run.
- **The socket façade** — single-connection `TcpListener`/`TcpStream` and the multi-connection
  `TcpServer`, over an in-memory `PacketIo` loopback.

## 2. Live (real kernel, needs Linux + `/dev/net/tun` + `sudo`)

These can't be unit-tested — they need a privileged TUN device and a real peer (the Linux network
stack). Run them in WSL2 (or any Linux). On Windows, prefix a command with `!` in Claude Code to run
it in your own terminal so `sudo` can prompt.

```bash
# Terminal 1 — build and run the stack (native-fs target so setcap works; see .cargo/config.toml)
cargo build
BIN=~/.tcp-stack-target/debug/tcp-stack
sudo setcap cap_net_admin=eip "$BIN" && "$BIN"

# Terminal 2 — bring up the interface, then interoperate with stock tools
sudo ip addr add 192.168.0.1/24 dev tun0 && sudo ip link set tun0 up
ping 192.168.0.2                 # ICMP echo reply — 0% loss
nc 192.168.0.2 8080              # TCP echo: type a line, get it back
curl http://192.168.0.2:8080/    # HTTP/1.1 200 OK, then a clean close

# Reliability under adverse conditions (loss + reordering)
sudo tc qdisc add dev tun0 root netem loss 5% reorder 25% 50%
#   …retransmission + reassembly keep the transfer intact…
sudo tc qdisc del dev tun0 root  # remove the impairment

# Throughput
sudo apt install -y iperf3       # then drive iperf3 across tun0 against the stack

# Conformance against the RFCs
sudo apt install -y packetdrill  # replay packetdrill scripts to assert per-segment behaviour
```

### Interop checklist

- [ ] `ping 192.168.0.2` — replies, 0% loss
- [ ] `nc 192.168.0.2 8080` — line echoed back
- [ ] `curl http://192.168.0.2:8080/` — `200 OK`, connection closes cleanly
- [ ] under `tc netem loss/reorder` — transfers still complete intact
- [ ] `iperf3` — sustained throughput without stalls
- [ ] `packetdrill` — scripted handshake / teardown / recovery sequences pass

> The automated layer (1) proves correctness on every push. The live layer (2) is the final
> real-world confirmation; it depends on a privileged TUN device, so it's run by hand rather than in
> CI.
