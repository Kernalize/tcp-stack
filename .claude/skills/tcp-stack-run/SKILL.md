---
name: tcp-stack-run
description: "Build, test, setcap and run the tcp-stack project correctly inside WSL2 from this Windows machine. Use whenever the user wants to build, test, run, or see packets from the TCP stack, or check that it still compiles. Handles the Windows→WSL + native-fs + CAP_NET_ADMIN details so commands just work."
trigger: /tcp-run
---

# tcp-stack-run

This project is **Linux-only** (needs `/dev/net/tun` + `CAP_NET_ADMIN`) and is developed
from Windows via **WSL2 Ubuntu**. Source lives on Windows at
`C:\Users\daasa\Projects\tcp-stack` = `/mnt/c/Users/daasa/Projects/tcp-stack` in WSL.

## Key facts (do not relearn these)
- Build artifacts go to `/home/daasa/.tcp-stack-target` (set in `.cargo/config.toml`),
  NOT `./target`. Reason: `setcap` fails on `/mnt/c` (DrvFs has no Linux xattrs) and 9p
  builds are slow. So plain `cargo build` already does the right thing.
- Binary path after build: `/home/daasa/.tcp-stack-target/debug/tcp-stack`.
- The TUN device uses `Iface::without_packet_info` (no 4-byte PI header). If you ever
  switch to `Iface::new`, every offset shifts by 4 and `version` parses as 0.

## To VERIFY correctness (no sudo, no TUN, no network) — prefer this
```bash
wsl -d Ubuntu -- bash -lc 'cd /mnt/c/Users/daasa/Projects/tcp-stack && cargo test 2>&1 | tail -40'
```
Run this after any code change. It compiles and runs the unit tests (parser vs known
packets, rejection paths, etherparse differential check). This is the fast feedback loop.

## To BUILD only
```bash
wsl -d Ubuntu -- bash -lc 'cd /mnt/c/Users/daasa/Projects/tcp-stack && cargo build 2>&1 | tail -20'
```

## To RUN live (sees real packets) — this part is interactive, hand to the user
`setcap` + the multi-terminal run need a real WSL terminal (sudo password, blocking recv).
Do not try to drive it through the Bash tool. Give the user these exact steps:

Terminal 1 (run the stack):
```bash
cd /mnt/c/Users/daasa/Projects/tcp-stack
cargo build
sudo setcap cap_net_admin=eip /home/daasa/.tcp-stack-target/debug/tcp-stack
/home/daasa/.tcp-stack-target/debug/tcp-stack
```
Terminal 2 (wire up + ping):
```bash
sudo ip addr add 192.168.0.1/24 dev tun0 && sudo ip link set tun0 up
ping -c3 192.168.0.2          # echo reply implemented → expect 0% loss
```
Optional Terminal 3: `sudo apt install -y tcpdump` then `sudo tcpdump -i tun0 -n -v`.

## Troubleshooting (symptom → cause)
- `version=0` / every packet skipped → using `Iface::new`; must be `without_packet_info`.
- `setcap: Operation not supported` → binary is on `/mnt/c`; ensure `.cargo/config.toml`
  target-dir points to native fs and rebuild.
- `PermissionDenied` on run → forgot `setcap` (re-run it after EVERY `cargo build`) or run with `sudo`.
- `ResourceBusy` creating tun0 → `sudo ip link delete tun0` then retry.
- 100% ping loss → expected until Day 2 (we receive but don't reply yet).

## Hygiene
Never use unquoted brace expansion (`{...}`) with a redirect — it writes a literal junk
file like `{,+`. Always quote globs/paths in shell commands.
