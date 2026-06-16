# Doc 1 — From Zero to Reading Real Packets

> A from-scratch teaching text for `src/main.rs`. The goal: after reading this with the
> file closed, you can re-type the whole thing and explain every line, every byte, and
> every design choice — including the ones I rejected and why.
>
> Scope of Doc 1: open a TUN device, receive raw packets, and **decode** the IPv4 header
> (plus peek at ICMP and TCP). We do not *reply* yet — that is Doc 2 (and it needs
> checksums, which get their own chapter). 100% ping loss today is the correct result.

**Contents**
1. The mental model — what are we even building
2. TUN/TAP — a virtual wire into the kernel
3. The 4-byte gotcha that breaks the manual (`IFF_NO_PI`)
4. The receive loop and blocking I/O
5. The IPv4 header, field by field
6. Bit manipulation: nibbles, shifts, masks
7. Endianness — the #1 beginner bug
8. IHL: why the payload is not always at byte 20
9. Parsing in Rust — slices, bounds, `Result` vs panic
10. ICMP — what ping actually is
11. Verification — proving the parser correct
12. The code, walked end to end
13. Design choices and alternatives (the "why this, not that" table)
14. Rebuild it yourself — blank-file checklist + exercises
15. What Doc 2 adds
- Appendix A — Troubleshooting (symptom → cause)
- Appendix B — Glossary

---

## 1. The mental model — what are we even building

A "TCP/IP stack" is the layer of software that turns a raw stream of bytes arriving on a
wire into the abstractions you use every day: an IP address, a port, a reliable ordered
byte stream (`TcpStream`). Normally this code lives **inside the kernel**. When you call
`connect()` in any language, you are calling into the kernel's TCP stack.

We are going to write our **own** stack, in userspace, in Rust. The trick that makes this
possible without rebooting into our own OS is a **TUN device**: a virtual network
interface where, instead of bytes going out a physical NIC, they get handed to *our
process* as plain reads and writes on a file descriptor.

```
   Normal path                          Our path (Doc 1)
   ───────────                          ────────────────
   ping ──► kernel TCP/IP ──► NIC       ping ──► kernel routing ──► tun0 ──► OUR process
                                                                            (we read bytes)
```

So the entire project is: *a program that reads byte buffers, interprets them as network
protocols, and writes byte buffers back.* Doc 1 is only the **read + interpret** half.

Layers, bottom to top, and where we sit:

| Layer | Example | Who handles it in this project |
|---|---|---|
| L2 Link | Ethernet, MAC, ARP | **Skipped** — TUN is L3, so no Ethernet header exists |
| L3 Network | **IPv4**, ICMP | **Us, Doc 1** (parse) → Doc 2 (reply) |
| L4 Transport | **TCP**, UDP | Us, Weeks 5–10 |
| L7 Application | HTTP, DNS | The test tools (`ping`, `nc`, `curl`) |

Because we chose TUN (L3), we *never* deal with MAC addresses or ARP. The first byte we
receive is the first byte of the **IP header**. That is a deliberate simplification: it
lets us learn IP and TCP without first writing Ethernet framing. (TAP, the L2 sibling,
would hand us Ethernet frames — see §2.)

---

## 2. TUN/TAP — a virtual wire into the kernel

`/dev/net/tun` is a **character device**: a file you `open()` and then `read()`/`write()`,
where each read returns one packet and each write injects one packet. When you create a
TUN interface, the kernel makes a new network interface (`tun0`) appear in `ip addr`. Any
packet the kernel routes *to* `tun0` is delivered to whoever holds the file descriptor —
us. Any packet we *write* to the fd appears to the kernel as if it arrived *from* `tun0`.

That is the whole magic. We are a fake computer sitting on a virtual cable.

**TUN vs TAP** — one flag's difference, a whole layer's difference:

| | TUN | TAP |
|---|---|---|
| Operates at | L3 (IP) | L2 (Ethernet) |
| First byte you read is | start of the **IP** header | start of the **Ethernet** header (dest MAC) |
| You must implement | IP, ICMP, TCP | Ethernet framing + **ARP** + all of the above |
| Used by | most VPNs (WireGuard, OpenVPN tun mode) | VM bridges, L2 VPNs |

We use **TUN**. The empty `src/ethernet.rs` and `src/arp.rs` in this repo are there for an
optional later detour into TAP; on the main TUN path they stay empty.

**CAP_NET_ADMIN.** Creating a network interface is privileged. Linux splits root's power
into ~40 *capabilities* instead of all-or-nothing; `CAP_NET_ADMIN` is the one that covers
"create interfaces, set addresses, manage routes." Two ways to grant it:

```bash
sudo ./tcp-stack                              # blunt: run the whole program as root
sudo setcap cap_net_admin=eip ./tcp-stack     # surgical: grant just this one cap to the binary
```

`setcap` is better practice (least privilege), but it has a hard requirement: **the binary
must live on a filesystem that supports Linux extended attributes.** `/mnt/c` (the Windows
drive, mounted as DrvFs/9p) does **not**. That is the entire reason this repo ships a
`.cargo/config.toml` redirecting build output to `/home/daasa/.tcp-stack-target` on native
ext4. Build on `/mnt/c` and `setcap` fails silently-ish with "Operation not supported."

> `=eip` means grant the cap in all three sets: **e**ffective, **i**nheritable,
> **p**ermitted. And you must re-run `setcap` after **every** `cargo build`, because a new
> binary file is a new inode with no xattrs.

**Under the hood (optional but worth it).** `Iface::new` does three things: `open("/dev/net/tun")`
to get a file descriptor, then an `ioctl(fd, TUNSETIFF, ...)` naming the interface (`tun0`)
and its mode (`IFF_TUN`, optionally `IFF_NO_PI`), and the kernel wires that fd to a fresh
interface. After that, `iface.recv()` is literally `read(fd, buf)` and `iface.send()` is
`write(fd, buf)` — a TUN device is "a network interface you talk to as a file." That is why
the whole project reduces to *read a byte buffer, interpret it, write a byte buffer back*.
The `tun-tap` crate just wraps those syscalls so you don't write the `ioctl` by hand.

---

## 3. The 4-byte gotcha that breaks the manual (`IFF_NO_PI`)

This is the single most important thing in Doc 1, and the project's own `doc1.md` gets it
wrong, so internalize it.

The `tun-tap` crate has two constructors:

```rust
Iface::new("tun0", Mode::Tun)                 // kernel PREPENDS 4 bytes to every packet
Iface::without_packet_info("tun0", Mode::Tun) // sets IFF_NO_PI: no prepended bytes
```

With `new`, every `recv` gives you a 4-byte **packet information** header *in front of* the
IP packet:

```
 byte:  0   1   2   3   4   5   6 ...
       [ flags ][ proto ][ 45  00  00 ... ]   <- with Iface::new  (proto 0x0800 = IPv4)
        \_____ TUN PI ____/ \__ real IP packet __/

       [ 45  00  00  54 ... ]                  <- with without_packet_info
        \__ real IP packet __/
```

So with `Iface::new`, `buf[0]` is `0x00` (a flags byte), **not** `0x45`. The manual's code
reads `version = buf[0] >> 4` → `0`, concludes "not IPv4," and skips *every packet
forever*. The symptom: your stack prints nothing while `tcpdump` clearly shows the pings
arriving. Hours lost.

Two correct fixes:

- **What we do:** `Iface::without_packet_info(...)`. The buffer is the raw IP packet,
  offsets match every diagram and RFC, and there is one less concept in the way. Best
  choice for a learning stack.
- **The alternative (handle the PI):** keep `Iface::new`, then on each read do
  `if u16::from_be_bytes([buf[2], buf[3]]) != 0x0800 { continue; }` and parse from
  `&buf[4..]`. You'd do this if you needed the EtherType to distinguish IPv4 vs IPv6
  cheaply, or were porting code that assumes PI. We don't, so we drop it.

The docs.rs page for `recv` even tells you: *"the buffer … MTU (usually 1500) **+ 4 for the
header in case that packet info is prepended**."* That "+4" is this header.

> Debugging rule of thumb you can keep forever: **if `version` parses as 0, you forgot
> `IFF_NO_PI`.**

---

## 4. The receive loop and blocking I/O

```rust
let mut buf = [0u8; 1504];
loop {
    let n = iface.recv(&mut buf)?;   // BLOCKS until exactly one packet arrives
    let packet = &buf[..n];          // only the first n bytes are valid this iteration
    ...
}
```

Three things worth understanding:

- **Why 1504 and not 1500.** 1500 is the standard Ethernet **MTU** — the largest IP packet
  that fits without fragmentation. We add a few bytes of slack (the manual uses 1504; it's
  the MTU + the 4-byte PI header we *could* receive). A buffer too small would truncate
  packets. A stack array (`[0u8; 1504]`) avoids a heap allocation on every read — it lives
  on the stack, reused each loop iteration.
- **`recv` blocks.** The thread parks in the kernel until a packet is ready; it consumes no
  CPU while waiting. The program "hanging" after startup is correct — it's waiting. (Later,
  for handling many connections, you'd switch to non-blocking + `epoll`; the crate exposes
  `set_non_blocking()`. Doc 1 doesn't need it.)
- **`n` is the real length.** `buf` is always 1504 bytes; only `buf[..n]` is this packet.
  Slicing to `&buf[..n]` once and parsing the slice prevents the classic bug of reading
  stale bytes from a previous, longer packet.

---

## 5. The IPv4 header, field by field

Defined in **RFC 791**. Minimum 20 bytes. Bit layout (each row is 32 bits / 4 bytes):

```
 0               1               2               3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-------+-------+---------------+-------------------------------+
|Version|  IHL  |    DSCP/ECN   |          Total Length         |   bytes 0–3
+-------+-------+---------------+-----+-------------------------+
|         Identification        |Flags|     Fragment Offset     |   bytes 4–7
+---------------+---------------+-----+-------------------------+
|      TTL      |   Protocol    |        Header Checksum        |   bytes 8–11
+---------------+---------------+-------------------------------+
|                       Source Address                          |   bytes 12–15
+--------------------------------------------------------------+
|                    Destination Address                        |   bytes 16–19
+--------------------------------------------------------------+
|                  Options (only if IHL > 5)                    |   bytes 20+
+--------------------------------------------------------------+
```

Byte-offset table — this is what `parse_ipv4` walks:

| Bytes | Field | Meaning / how to read |
|---|---|---|
| `[0]` hi nibble | **Version** | `>> 4`. Always 4 here. |
| `[0]` lo nibble | **IHL** | `& 0x0f`. Header length in 32-bit words; ×4 = bytes. |
| `[1]` | DSCP + ECN | QoS / congestion marking. Ignored Doc 1. |
| `[2..4]` | **Total Length** | `u16` BE. Whole datagram (header+payload) in bytes. |
| `[4..6]` | Identification | Fragment group id (reassembly, later). |
| `[6..8]` | Flags + Frag Offset | top 3 bits flags (DF/MF), low 13 bits offset. |
| `[8]` | **TTL** | Hops remaining; each router decrements; 0 ⇒ dropped. |
| `[9]` | **Protocol** | 1=ICMP, 6=TCP, 17=UDP. Tells us how to read the payload. |
| `[10..12]` | Header Checksum | One's-complement over the header (see Doc 2). |
| `[12..16]` | **Source IP** | 4 octets. |
| `[16..20]` | **Destination IP** | 4 octets. |

The four fields that matter today are bold: version, protocol, src, dst (and IHL to find
the payload).

**Worked decode** of a real ping — the bytes `45 00 00 54 ab cd 40 00 40 01 e2 3f c0 a8 00
01 c0 a8 00 02`:

```
45 → version 4, IHL 5  (5×4 = 20-byte header, no options)
00 → DSCP/ECN 0
00 54 → total length = 0x0054 = 84 bytes
ab cd → identification
40 00 → flags=0b010 (DF set), fragment offset 0
40 → TTL = 64  (Linux default)
01 → protocol = 1 = ICMP   ← it's a ping
e2 3f → header checksum
c0 a8 00 01 → 192.168.0.1   (source: the host)
c0 a8 00 02 → 192.168.0.2   (dest: our stack)
```

`c0 a8 00 01` → `192.168.0.1` because `0xc0=192`, `0xa8=168`, `0x00=0`, `0x01=1`. Memorize
`0xc0a8` = `192.168` — you will read it in hex dumps for the rest of your life.

A few fields are worth real understanding even though we don't act on them yet:

- **TTL** is how `traceroute` works: send packets with TTL=1,2,3…; each router that
  decrements TTL to 0 sends back an ICMP *Time Exceeded* revealing its address.
- **Flags/Fragment Offset** are IP fragmentation. DF = "Don't Fragment." Path MTU Discovery
  relies on routers replying ICMP *Fragmentation Needed* when a too-big DF packet can't pass.
- **Total Length** is your authority for where the datagram ends — never trust the buffer
  size alone once real payloads arrive.

---

## 6. Bit manipulation: nibbles, shifts, masks

Byte 0 packs two 4-bit numbers (nibbles) into 8 bits. Extracting them is pure bit math:

```rust
let version = packet[0] >> 4;       // keep the HIGH nibble
let ihl     = packet[0] & 0x0f;     // keep the LOW nibble
```

`0x45 = 0100 0101`:

```
>> 4 :  0100 0101  ->  0000 0100  = 4      (shift right 4, high nibble falls into place)
& 0x0f: 0100 0101
        0000 1111  (mask)
        ---------
        0000 0101  = 5                      (AND zeroes the high nibble, keeps the low)
```

- **`>> n`** shifts bits right by `n`, discarding the low `n` bits and zero-filling the top.
- **`& mask`** keeps only the bits set in `mask`. `0x0f = 0000 1111` keeps the low 4.

Same toolkit reads TCP flags later: `flags & 0x02 != 0` tests the SYN bit. There is no
magic here — every protocol "field smaller than a byte" is a shift and/or a mask.

Why not C-style bitfields or a `#[repr(C)]` struct overlaid on the bytes? Because bitfield
layout is compiler/ABI-defined and endianness-dependent — it is *not portable* and not how
you write a wire parser. Explicit shifts and masks are unambiguous and match the RFC
diagrams one-to-one. (Crates like `bitflags` are nice for *sets of named flags*; we'll use
hand math to stay close to the metal.)

---

## 7. Endianness — the #1 beginner bug

A `u16` like Total Length spans two bytes. Which byte is "first"?

- **Big-endian (network byte order):** most-significant byte first. `1500 = 0x05DC` →
  `[0x05, 0xDC]`. **All internet protocols use this.**
- **Little-endian:** least-significant first → `[0xDC, 0x05]`. **Your x86/ARM CPU uses
  this internally.**

So the bytes on the wire are big-endian, but your CPU is little-endian. Convert explicitly:

```rust
let total_len = u16::from_be_bytes([packet[2], packet[3]]); // RIGHT: from_BE_bytes
// let bad    = u16::from_ne_bytes([packet[2], packet[3]]); // WRONG on x86/ARM: 0x5400 = 21504
```

`from_be_bytes` says "these bytes are big-endian, give me the native integer." It compiles
to a byte-swap on little-endian machines and a no-op on big-endian ones — correct
everywhere. The historic C equivalents are `ntohs`/`ntohl` ("network to host short/long").

**Rule:** every multi-byte field read from a packet uses `from_be_bytes`. Every multi-byte
field you *write* into a packet uses `to_be_bytes`. Never `ne`/`le` for wire data. This one
rule prevents a category of bugs that look like random garbage values.

---

## 8. IHL: why the payload is not always at byte 20

IHL (Internet Header Length) is the header size in 32-bit words:

```rust
let header_len = (packet[0] & 0x0f) as usize * 4;
```

- IHL 5 → 20 bytes → no options (≈99% of traffic).
- IHL 6–15 → 24–60 bytes → IP **options** present (timestamps, record-route, etc.).

The transport payload (ICMP/TCP/UDP) starts at `packet[header_len]`, **not** a hardcoded
`packet[20]`. If you hardcode 20 and a packet ever carries options, you'll parse 4+ bytes
of IP options as if they were TCP, and everything downstream is garbage. So:

```rust
let l4 = &packet[hdr.header_len..];   // correct for options and no-options alike
```

This is a "costs nothing now, saves you later" correctness habit. Defensive parsing at the
boundary is the whole game in a network stack: the bytes come from an adversary.

---

## 9. Parsing in Rust — slices, bounds, `Result` vs panic

**Slices (`&[u8]`).** A slice is a borrowed view — a `(pointer, length)` pair — into bytes
we already have. `parse_ipv4(&[u8])` copies nothing; it reads in place. This is "zero-copy"
parsing, the same idea `etherparse`'s `...Slice` types use. We copy only the few small
fields we extract into an `Ipv4Header` struct for convenience.

**Bounds and panics.** `packet[19]` on a 2-byte slice **panics** (Rust checks every index).
A panic in a server = crash = denial of service. So we bounds-check *once, up front*:

```rust
if packet.len() < 20 { return Err(ParseError::TooShort { have: packet.len(), need: 20 }); }
```

After that single guard, indices `[0..20]` are provably safe. Then we check `header_len`
before slicing the payload. Two checks total; everything after is panic-free by
construction.

**Why `Result`, not `Option` or panic.** Three choices for "this might fail":

| Approach | When it's right | Why not here |
|---|---|---|
| `panic!` / unchecked index | truly impossible / programmer error | input is hostile; crashing is the bug |
| `Option<T>` | failure has exactly one, obvious reason | hides *why* it failed |
| **`Result<T, ParseError>`** | failure has several distinct, useful causes | ✅ tells us short vs not-IPv4 vs bad-IHL |

The typed `ParseError` enum pays off the moment something misbehaves: the log says
`NotIpv4 { version: 0 }` and you instantly know it's the §3 PI-header bug, not a length
problem. (For ICMP, the only failure is "too short," so `Option` is the right, lighter tool
— matching the failure shape to the type is the lesson.)

**The big alternatives to hand-parsing**, and why we still hand-roll:

- `etherparse` — excellent, we *depend on it* — but only as the **oracle** that checks our
  work (§11). Using it for everything would mean learning the crate, not the protocol.
- `nom` — parser-combinator library; great for complex grammars, overkill for fixed
  offsets.
- `byteorder` — older crate for `read_u16::<BigEndian>()`; the std `from_be_bytes` made it
  largely unnecessary.
- **`unsafe { transmute }` a struct over the bytes — never do this.** It ignores
  endianness, assumes a memory layout the compiler doesn't guarantee, and breaks on
  unaligned reads. It is *the* wrong way and a classic source of UB.

---

## 10. ICMP — what ping actually is

ICMP (RFC 792) is IP's control/diagnostic protocol. `ping` sends an **Echo Request** (type
8); a host is supposed to answer with an **Echo Reply** (type 0) carrying the same payload.
Round-trip time of that exchange is what ping prints.

The fixed 8-byte head (sits right after the IP header):

```
[0] Type        (8 = Echo Request, 0 = Echo Reply, 3 = Dest Unreachable, 11 = Time Exceeded)
[1] Code        (sub-type; 0 for echo)
[2..4] Checksum (u16 BE, one's complement over the ICMP message)
[4..6] Identifier (u16 BE — usually the pinging process's id; lets it match replies)
[6..8] Sequence  (u16 BE — increments per ping: seq 1, 2, 3…)
[8..]  Data       (echoed back verbatim; Linux puts a timestamp + filler here)
```

Why today's ping reports **100% loss**: we *receive* the Echo Requests but never send Echo
Replies. `ping` waits, hears nothing, reports loss. That's success for Doc 1 — it proves
packets reach our code. Doc 2 is: read the request, build a reply (swap src/dst, set type
0, **recompute the checksum**), and `iface.send()` it. The checksum is the new concept and
why reply waits a day.

> ICMP's Identifier/Sequence are unrelated to TCP's sequence numbers — same word, totally
> different mechanism. Don't conflate them.

---

## 11. Verification — proving the parser correct

You wrote bit math by hand. How do you *know* it's right? Two layers, both in this repo.

**1. Differential testing against an oracle (runtime).** In the loop we parse every packet
a second time with `etherparse` and compare. If a field disagrees we shout `⚠ MISMATCH`.
Agreement is silent. This is *differential testing*: two independent implementations of the
same spec should produce the same answer; divergence localizes a bug to one of them
(usually yours). It runs against real, live traffic.

**2. Unit tests against a known packet (offline).** `cargo test` feeds the parser the exact
ping bytes from §5 and asserts every field, plus the "too short" and "not IPv4" rejection
paths, plus an `agrees_with_etherparse` test. These need **no TUN, no sudo, no network** —
they run anywhere in <1ms, so you get instant feedback while editing and a regression net
forever after. (All 5 pass on this code.)

**3. `tcpdump` as ground truth (manual).** `sudo tcpdump -i tun0 -n -v` decodes the same
packets independently; cross-reading its output against your hex/printout teaches you to
trust your eyes. This is the debugging skill you'll use every single day of the project.

The principle: **never trust a parser you only eyeballed.** An oracle + unit tests + a
sniffer is the standard three-legged stool.

---

## 12. The code, walked end to end

Open `src/main.rs` alongside this. The structure, top to bottom:

1. **`struct Ipv4Header` + `enum ParseError`** — the typed result of parsing. Deriving
   `PartialEq, Eq` is *only* so the unit tests can `assert_eq!` on them; it costs nothing.
2. **`fn parse_ipv4`** — the one guarded, panic-free walk of §5–§8. Returns `Result`.
3. **`fn protocol_name`** — `u8` → label; `&'static str` because the strings are baked into
   the binary, no allocation.
4. **`struct IcmpHeader` + `fn parse_icmp`** — `Option` because the only failure is "too
   short" (§9). 
5. **`fn icmp_name`** — `(type, code)` → label via tuple match.
6. **`fn print_tcp`** — peek only: ports, seq/ack, flags via masks (§6). Lets you *see*
   `nc` handshakes; real TCP is Week 5.
7. **`fn main`** — `without_packet_info` (§3) → print setup → `loop { recv; parse; print;
   dispatch on protocol; cross-check }`.
8. **`mod tests`** — §11's offline proof.

Read each function and say out loud what every line does. If you can't, that line is your
next thing to learn — that's the point of having written it small and explicit.

---

## 13. Design choices and alternatives (the "why this, not that" table)

| Decision | What we chose | The alternative | Why ours wins *here* |
|---|---|---|---|
| TUN packet info | `without_packet_info` (IFF_NO_PI) | `Iface::new` + strip 4 bytes | offsets match RFCs; one less concept; avoids the silent skip-everything bug |
| Layer | TUN (L3) | TAP (L2) | skips Ethernet+ARP; learn IP/TCP first |
| Privilege | `setcap` on native-fs binary | `sudo ./binary` | least privilege; but **needs** ext4, hence `.cargo/config.toml` |
| Parser return | `Result<_, ParseError>` | panic / `Option` | hostile input must not crash; *why* it failed aids debugging |
| ICMP return | `Option` | `Result` | single failure mode → match the type to the shape |
| Field storage | small owned `struct` | borrow slices everywhere | simpler today; revisit for zero-copy if it ever matters |
| Addresses | `std::net::Ipv4Addr` | raw `[u8;4]` | free `Display` (`192.168.0.1`), `==`, well-known type |
| Endianness | `from_be_bytes` | `from_ne_bytes` | wire is big-endian; `ne` is the classic garbage-value bug |
| Verification | etherparse oracle + unit tests | eyeball it | proof, not hope; regression net |
| Code location | one `main.rs` today | split into `ip.rs`/`icmp.rs` now | premature modularization; split when there are 2+ users of a function (≈ Week 3) |

What a **production** stack does differently, for honesty: non-blocking I/O + `epoll`/io_uring
for many connections; pools/ring buffers instead of a stack array per read; validates the IP
header checksum and `total_len` against the buffer; handles IP options and fragmentation;
and is split into modules with property-based + fuzz tests. We'll grow into most of these.

---

## 14. Rebuild it yourself — blank-file checklist + exercises

Close this book. From an empty `main.rs`, you should be able to:

1. `use std::net::Ipv4Addr; use etherparse::Ipv4HeaderSlice; use tun_tap::{Iface, Mode};`
2. Open `Iface::without_packet_info("tun0", Mode::Tun)?` — and explain why not `new`.
3. `loop { let n = iface.recv(&mut buf)?; let packet = &buf[..n]; ... }`.
4. Guard `packet.len() < 20`, read `version = packet[0] >> 4`, reject `!= 4`.
5. `header_len = (packet[0] & 0x0f) * 4`; guard `packet.len() < header_len`.
6. `total_len`/`protocol`/`src`/`dst` with the right offsets and `from_be_bytes`.
7. Slice `&packet[header_len..]` and dispatch on `protocol` (1 ICMP, 6 TCP).
8. Cross-check against `etherparse` and write the 5 unit tests from memory.

If any step needs a peek, that step is your weak spot — drill it (and make an Anki card from
it, per your Learning OS).

**Exercises (do at least 1–2 before Doc 2):**
- **E1.** Print the IP header **checksum** field and the **identification** field. (You read
  the bytes; you don't validate yet.)
- **E2.** Add UDP (protocol 17): print source/dest ports (first 4 bytes of its payload).
  Test with `nc -u 192.168.0.2 53` or a DNS query.
- **E3.** Make `parse_ipv4` also reject packets where `total_len < header_len` (a malformed
  header). Add a `ParseError` variant and a unit test.
- **E4.** Decode the ICMP **data** length (`total_len - header_len - 8`) and print it. For a
  standard Linux ping it's 56 — explain why (hint: 84 − 20 − 8).
- **E5.** Temporarily switch to `Iface::new`, observe `version=0` skips, then fix it by
  stripping `buf[..4]`. Now you've *felt* §3 instead of just reading it.

---

## 15. What Doc 2 adds

- **ICMP Echo Reply** so `ping` finally succeeds (0% loss). Build the reply: copy the
  request, swap source/dest IPs, set ICMP type 0, **recompute both checksums**, `send()`.
- **The Internet Checksum** (RFC 1071) — one's-complement sum — its own chapter: what it is,
  why one's-complement (end-around carry), how to compute it over IP and ICMP, and the
  beautiful trick that to *verify* a checksum you just sum everything including the checksum
  field and expect `0xFFFF`.
- That is the first time we **write** to the wire — the second half of "a program that reads
  and writes byte buffers." After that, `tcpdump` shows request *and* reply, and you've
  built a host that answers pings using a network stack you wrote from scratch.

> Reminder from your own rules: now **re-type `main.rs` from this book with the book closed.**
> Reading proved you can follow it; typing it cold proves you own it.

---

## Appendix A — Troubleshooting (symptom → cause)

| What you see | Most likely cause | Fix |
|---|---|---|
| `version=0`, every packet skipped, yet `tcpdump` shows pings | Using `Iface::new` → 4-byte PI header shifts all offsets (§3) | use `Iface::without_packet_info` (or parse from `buf[4..]`) |
| `setcap: Operation not supported` | binary is on `/mnt/c` (DrvFs has no Linux xattrs) | build to native fs — that's what `.cargo/config.toml` does; rebuild |
| `Error: ... PermissionDenied` on run | no `CAP_NET_ADMIN` | re-run `setcap` (needed after *every* build) or run with `sudo` |
| `Error: ... ResourceBusy` creating tun0 | a `tun0` already exists | `sudo ip link delete tun0`, retry |
| `Error: ... NotFound` opening tun | `/dev/net/tun` missing | `sudo modprobe tun` |
| program prints nothing and "hangs" | normal — `recv` is blocking, waiting for a packet | ping it from terminal 2 |
| `ping` says 100% packet loss | we receive but don't reply yet | expected until Doc 2 (ICMP echo reply) |
| multi-byte field is a wild/huge number | used `from_ne_bytes` instead of `from_be_bytes` (§7) | always `from_be_bytes` for wire data |
| L4 fields look shifted/garbage | hardcoded payload start at byte 20 instead of `ihl*4` (§8) | slice `&packet[header_len..]` |
| `⚠ MISMATCH vs etherparse` printed | your hand parser disagrees with the oracle | a real bug — check byte indices / endianness |
| index-out-of-bounds panic | parsed before the length guard | bounds-check once up front, then index freely (§9) |

## Appendix B — Glossary

- **TUN device** — a virtual L3 network interface delivered to a userspace fd; you read/write
  raw IP packets. **TAP** is its L2 sibling (Ethernet frames).
- **MTU** — Maximum Transmission Unit; largest IP packet that fits without fragmentation
  (1500 on Ethernet).
- **CAP_NET_ADMIN** — the Linux capability permitting interface/route/address management;
  a slice of root, not all of it.
- **IFF_NO_PI** — the TUN flag that disables the 4-byte "packet information" header; set by
  `without_packet_info`.
- **octet** — an 8-bit byte; networking prefers "octet" because historically a byte wasn't
  always 8 bits.
- **nibble** — 4 bits = half a byte; IPv4 byte 0 holds two nibbles (version, IHL).
- **IHL** — Internet Header Length, in 32-bit words; ×4 = header bytes; 5 = 20-byte header.
- **big-endian / network byte order** — most-significant byte first; all internet protocols
  use it. Your x86/ARM CPU is little-endian internally — hence `from_be_bytes`.
- **TTL** — Time To Live; per-hop counter; 0 ⇒ drop + ICMP Time Exceeded (how traceroute works).
- **ICMP** — IP's control/diagnostic protocol (RFC 792); ping = Echo Request/Reply.
- **Internet checksum** — the one's-complement 16-bit sum (RFC 1071) used by IP/ICMP/TCP/UDP;
  built on Doc 2.
- **differential testing** — running two independent implementations on the same input and
  comparing; divergence localizes a bug. Here: our parser vs `etherparse`.
- **zero-copy / slice** — a `&[u8]` is a borrowed `(pointer, length)` view; parsing in place
  without copying the packet.
- **DrvFs / 9p** — the filesystem WSL uses to expose `/mnt/c`; it lacks Linux extended
  attributes, so `setcap` can't work there.
- **setcap** — sets file capabilities on a binary (e.g. `cap_net_admin=eip`).
- **etherparse** — the reference packet-parsing crate we use only as a correctness oracle.

---
---

# VOLUME II — The Exhaustive Reference

> Volume I above is the *narrative* that gets you to working code. Volume II is the *reference*
> that makes you not need the narrative again: every bit, every field value, every Rust
> mechanism, every debugging technique, exhaustively, so you can re-derive the whole of Doc 1
> from first principles. Read it once slowly; return to it as a lookup.

## Contents of Volume II
- A. Number systems — binary, hexadecimal, and why networking lives in them
- B. Two's complement, one's complement, and signedness
- C. Bit operations from the ground up
- D. Endianness, completely
- E. The IPv4 header — every field, every value, exhaustively
- F. (continues in later installments: TUN/kernel datapath, Rust-for-parsers, ICMP, tooling)

---

## A. Number systems — binary, hexadecimal, and why networking lives in them

### A.1 — Why you cannot avoid this

A packet is *just bytes*. Every abstraction you will build — addresses, ports, sequence
numbers, flags — is a particular interpretation of a group of bytes. If you are not fluent in
binary and hexadecimal, every packet is an opaque wall of numbers; if you are, a hex dump
reads like prose. This section makes you fluent. It is not optional background — it is the
literacy the entire project assumes.

### A.2 — Positional number systems

Every number system we use is *positional*: a digit's value is the digit times the base
raised to the digit's position (counting from 0 on the right).

In **decimal** (base 10), the number 4521 means:

```
4 × 10³ + 5 × 10² + 2 × 10¹ + 1 × 10⁰
= 4000 + 500 + 20 + 1
= 4521
```

In **binary** (base 2), digits are only 0 and 1, and the place values are powers of two. The
binary number `1011` means:

```
1 × 2³ + 0 × 2² + 1 × 2¹ + 1 × 2⁰
= 8 + 0 + 2 + 1
= 11  (decimal)
```

In **hexadecimal** (base 16), digits run 0–9 then A–F (A=10, B=11, C=12, D=13, E=14, F=15),
and the place values are powers of sixteen. The hex number `0x2F` means:

```
2 × 16¹ + 15 × 16⁰
= 32 + 15
= 47  (decimal)
```

The `0x` prefix is a convention (used by C, Rust, Python, and this book) meaning "what
follows is hexadecimal." Binary is sometimes written with a `0b` prefix (`0b1011`).

### A.3 — Why binary: the hardware reason

A computer stores and moves information as electrical signals that are reliably
distinguishable in only two states: roughly "high voltage" and "low voltage," which we label
1 and 0. Everything — every integer, character, pixel, and packet — is ultimately a pattern
of these two-state cells called **bits** (binary digits). A group of 8 bits is a **byte** (in
networking, an **octet**, because historically some machines had bytes that were not 8 bits;
on the internet a byte is always 8 bits). One byte holds 2⁸ = 256 distinct values, 0 through
255.

### A.4 — Why hexadecimal: the human reason

Binary is correct but unreadable: the byte `11000000` is hard to scan and easy to miscount.
Hexadecimal is the perfect compression for humans because **one hex digit encodes exactly
four bits** (a *nibble*), since 2⁴ = 16. So a byte is always exactly two hex digits:

```
binary    11000000
nibbles   1100 0000
hex       C    0       →  0xC0  →  192 decimal
```

This 4-bits-per-hex-digit alignment is why every protocol diagram, hex dump, and debugger
speaks hex. You should memorize the nibble table cold:

| Binary | Hex | Dec |   | Binary | Hex | Dec |
|--------|-----|-----|---|--------|-----|-----|
| 0000   | 0   | 0   |   | 1000   | 8   | 8   |
| 0001   | 1   | 1   |   | 1001   | 9   | 9   |
| 0010   | 2   | 2   |   | 1010   | A   | 10  |
| 0011   | 3   | 3   |   | 1011   | B   | 11  |
| 0100   | 4   | 4   |   | 1100   | C   | 12  |
| 0101   | 5   | 5   |   | 1101   | D   | 13  |
| 0110   | 6   | 6   |   | 1110   | E   | 14  |
| 0111   | 7   | 7   |   | 1111   | F   | 15  |

With this table you can convert any byte by hand instantly: split the 8 bits into two
nibbles, look up each. `0100 0101` → `4` and `5` → `0x45` → 69 decimal. That `0x45` is the
first byte of every standard IPv4 packet — you will see it thousands of times.

### A.5 — Converting between bases by hand

**Binary → decimal:** add the place values where a 1 appears.
`0b10101100` = 128 + 32 + 8 + 4 = 172.

**Decimal → binary (subtraction method):** subtract the largest power of two that fits, repeat.
172: 128 fits (rem 44), 64 no, 32 fits (rem 12), 16 no, 8 fits (rem 4), 4 fits (rem 0).
Powers used: 128,32,8,4 → `10101100`. ✓

**Decimal → binary (division method):** divide by 2 repeatedly; the remainders, read bottom to
top, are the bits.
```
172 ÷ 2 = 86 r 0
 86 ÷ 2 = 43 r 0
 43 ÷ 2 = 21 r 1
 21 ÷ 2 = 10 r 1
 10 ÷ 2 =  5 r 0
  5 ÷ 2 =  2 r 1
  2 ÷ 2 =  1 r 0
  1 ÷ 2 =  0 r 1
read up: 1010 1100 = 0xAC = 172  ✓
```

**Hex → binary:** expand each hex digit to its 4-bit nibble. `0xB8` → `1011 1000`.

**Binary → hex:** group bits into nibbles from the right, look up each. `1011 1000` → `0xB8`.

**Hex ↔ decimal:** go through binary, or use place values directly.
`0xB8` = 11×16 + 8 = 176 + 8 = 184.

### A.6 — The power-of-two table you should know

These recur constantly (buffer sizes, windows, address ranges):

| 2ⁿ | value |   | 2ⁿ | value |
|----|-------|---|----|-------|
| 2⁰ | 1     |   | 2⁸ | 256   |
| 2¹ | 2     |   | 2¹⁰| 1024 (1 KiB) |
| 2² | 4     |   | 2¹⁶| 65536 |
| 2³ | 8     |   | 2²⁰| 1048576 (1 MiB) |
| 2⁴ | 16    |   | 2²⁴| 16777216 |
| 2⁷ | 128   |   | 2³²| 4294967296 (~4.29 billion) |

2⁸ = 256 is the number of values in one byte (so a byte holds 0–255). 2¹⁶ = 65536 is the
number of TCP/UDP ports and the range of a 16-bit field (total length, window, checksum,
ports). 2³² is the size of the IPv4 address space and the TCP sequence-number space — note
the same number underlies both, and both wrap around at it.

### A.7 — Units: bits vs bytes, and the KiB/KB trap

- 8 bits = 1 byte. Network *speeds* are quoted in **bits** per second (a "100 Mbps" link is
  100 million *bits*/s ≈ 12.5 MB/s). Storage is quoted in **bytes**. Mixing them up is a
  factor-of-8 error.
- 1 KiB = 1024 bytes (binary, kibibyte); 1 KB = 1000 bytes (decimal). Memory/buffers are
  usually powers of two (1024); marketing often uses 1000. We use 1024-based sizes for
  buffers.

---

## B. Two's complement, one's complement, and signedness

You will meet two different "complements" in this project, and confusing them causes real
bugs. This section pins them down.

### B.1 — Unsigned vs signed

A raw byte pattern like `1111 1111` has no inherent sign — *interpretation* gives it meaning.
As an **unsigned** 8-bit integer it is 255. As a **signed** 8-bit integer (two's complement)
it is −1. The bits are identical; the type decides. In Rust, `u8` vs `i8`, `u16` vs `i16`,
`u32` vs `i32` choose the interpretation. Packet fields are essentially always **unsigned**
(`u8`/`u16`/`u32`), which is why our parser uses `u16::from_be_bytes`, never `i16`.

### B.2 — Two's complement (how computers represent negatives)

Two's complement is the near-universal way CPUs store signed integers. For an n-bit number:

- The top bit is the **sign bit** (1 = negative).
- To negate a value: **invert all bits, then add 1.**

Example, 8-bit, negate 5:
```
 5  = 0000 0101
~5  = 1111 1010   (invert)
+1  = 1111 1011   = −5
```
Check: −5 as unsigned bits `1111 1011` = 251, and 251 = 256 − 5. That is the defining trick:
a negative value −x is stored as 2ⁿ − x. Two's complement makes addition/subtraction work
with the *same* circuitry for signed and unsigned, which is why hardware uses it. **We rarely
need it directly** (packet fields are unsigned), but you must recognize it because Rust's
bitwise NOT (`!`) and any signed arithmetic obey it.

### B.3 — One's complement (how the Internet checksum works)

One's complement is an *older* representation where negation is **just invert all bits** (no
"+1"). Its key arithmetic feature is **end-around carry**: when an addition overflows the top
bit, the carry is added back at the bottom. The Internet checksum (Doc 2) is defined in terms
of one's-complement *addition* precisely because end-around carry gives it the endianness-
independence property. So:

- **Two's complement** → how signed integers are stored (invert + 1).
- **One's complement** → the arithmetic of the Internet checksum (invert; carries wrap around).

Rust's `!x` operator computes the bitwise NOT, which *is* the one's complement of the bit
pattern — that is exactly the final step of `utils::checksum` on Doc 2.

### B.4 — Why packet fields are unsigned

A TTL of 64, a port of 443, a window of 65535, a sequence number — none of these are ever
negative. Representing them as unsigned (a) doubles the positive range for the same bits
(0–255 instead of −128–127 for a byte), and (b) makes wrap-around well-defined and meaningful
(TCP sequence numbers *rely* on `u32` wrap-around — Doc 3). Using a signed type for a packet
field is a latent bug: a "large" value would read as negative.

---

## C. Bit operations from the ground up

Parsing sub-byte fields is entirely bit operations. Here is every one you need, with truth
tables and packet-world uses.

### C.1 — AND ( `&` ) — masking (keeping bits)

AND yields 1 only where *both* inputs are 1:

```
a b | a&b
0 0 |  0
0 1 |  0
1 0 |  0
1 1 |  1
```

Use: **mask** — keep selected bits, zero the rest. To extract the low nibble of byte 0:

```
  0100 0101   (0x45)
& 0000 1111   (0x0f mask: keep low 4)
  ---------
  0000 0101   (0x05 = IHL 5)
```

A mask has 1s where you want to keep, 0s where you want to discard. `& 0x0f` keeps the low
nibble; `& 0xf0` keeps the high nibble; `& 0x01` tests the lowest bit.

### C.2 — OR ( `|` ) — setting bits / combining flags

OR yields 1 where *either* input is 1:

```
a b | a|b
0 0 |  0
0 1 |  1
1 0 |  1
1 1 |  1
```

Use: **set** bits / **combine** flags. TCP flags are individual bits; `SYN | ACK` =
`0x02 | 0x10` = `0x12` builds the combined flag byte for a SYN-ACK (Doc 3). Building a value
out of named bits is OR; that is why our flag constants are powers of two.

### C.3 — XOR ( `^` ) — toggling / difference

XOR yields 1 where the inputs *differ*:

```
a b | a^b
0 0 |  0
0 1 |  1
1 0 |  1
1 1 |  0
```

Use: toggle a bit, detect change, and (relevant later) incremental checksum updates. `x ^ x`
is always 0; `x ^ 0` is `x`.

### C.4 — NOT ( `!` ) — invert all bits (one's complement)

NOT flips every bit: `!0b0000_0101` (as u8) = `0b1111_1010`. On a `u16`, `!0x479E = 0xB861` —
this is the final step of the Internet checksum. Beware the width: `!` inverts *all* bits of
the type, so `!5u8 = 250` but `!5u16 = 65530`. Always know your integer width.

### C.5 — Left shift ( `<<` ) — multiply by powers of two, move fields up

`x << n` moves bits left by n, filling the low end with zeros; each shift doubles the value:

```
0000 0101  (5)
<< 1  →  0000 1010  (10)
<< 4  →  0101 0000  (80)
```

Use: position a field. The IPv4/TCP data-offset is the *high* nibble of a byte, so to *write*
"IHL = 5" we do `5 << 4` = `0x50`. The odd-byte case of the checksum uses `(b as u32) << 8`
to put a byte in the high half of a 16-bit word.

### C.6 — Right shift ( `>>` ) — divide by powers of two, move fields down

`x >> n` moves bits right by n; for unsigned types the high end fills with zeros (a *logical*
shift). Each shift halves the value:

```
0100 0101  (0x45)
>> 4  →  0000 0100  (4)   ← the version nibble
```

Use: extract a high field. `packet[0] >> 4` gives the version; `(byte >> 4)` gives any high
nibble. (For *signed* types Rust does an *arithmetic* right shift that copies the sign bit —
another reason packet fields are unsigned, so `>>` behaves as a plain divide-by-two.)

### C.7 — The extract-a-field recipe

To pull a field of `width` bits starting `shift` bits from the bottom of a byte/word:

```
(value >> shift) & ((1 << width) - 1)
```

`(1 << width) - 1` builds a mask of `width` ones. Example: extract bits 3..0 of a byte =
`(b >> 0) & 0x0f`. Extract the 3 IP flag bits (top 3 of byte 6) = `(packet[6] >> 5) & 0x07`.
The 13-bit fragment offset spanning bytes 6–7 = `u16::from_be_bytes([p[6],p[7]]) & 0x1FFF`.
Memorize this recipe; it parses every sub-field in every protocol.

### C.8 — Worked: decode IPv4 byte 0 with bit ops

`packet[0] = 0x45 = 0100 0101`:
```
version = 0x45 >> 4          = 0000 0100 = 4
ihl     = 0x45 & 0x0f        = 0000 0101 = 5    → header_len = 5 * 4 = 20 bytes
```
And to *build* it for an outgoing packet: `version(4) << 4 | ihl(5)` = `0x40 | 0x05` = `0x45`.
Reading is shift+mask; writing is shift+OR. They are inverses.

---

## D. Endianness, completely

Endianness caused the silent bug that would have broken Doc 1 if we'd used the wrong
conversion. Here is the whole topic.

### D.1 — The problem statement

A single byte has no ordering question. But a value wider than a byte — a 16-bit total
length, a 32-bit sequence number — must be stored as *several* bytes, and the two ends of a
connection (and the CPU and the wire) must agree on **which byte comes first**. That ordering
convention is *endianness*.

### D.2 — Big-endian vs little-endian

Take the 16-bit value `0x05DC` (decimal 1500, the Ethernet MTU). Its two bytes are the
most-significant `0x05` and the least-significant `0xDC`.

- **Big-endian:** most-significant byte at the lowest address (first). Bytes: `05 DC`.
- **Little-endian:** least-significant byte first. Bytes: `DC 05`.

The names come from *Gulliver's Travels* (which end of a boiled egg to crack) — a joke by
Danny Cohen in his 1980 paper "On Holy Wars and a Plea for Peace," which framed exactly this
dispute.

For a 32-bit value `0x0A0B0C0D`:
- Big-endian bytes: `0A 0B 0C 0D`
- Little-endian bytes: `0D 0C 0B 0A`

### D.3 — Who is which

- **Network byte order = big-endian.** Every internet protocol header field (IP, ICMP, TCP,
  UDP) is big-endian on the wire. This is fixed by the RFCs.
- **Your CPU (x86, x86-64, and ARM in normal config) is little-endian** internally.
- Some older/other architectures (SPARC, classic MIPS, m68k, PowerPC big-endian mode) are
  big-endian. "Network order" was chosen so a convention exists regardless of host.

So there is an impedance mismatch: the wire is big-endian, your CPU is little-endian. Every
multi-byte field must be converted at the boundary.

### D.4 — The conversion in Rust

Rust gives explicit, unambiguous conversions on every integer type:

| Method | Meaning |
|---|---|
| `u16::from_be_bytes([a,b])` | interpret bytes as **big-endian** → native integer (USE THIS for wire) |
| `u16::from_le_bytes([a,b])` | interpret bytes as little-endian |
| `u16::from_ne_bytes([a,b])` | interpret bytes as *native* endianness (NON-portable) |
| `n.to_be_bytes()` | native integer → **big-endian** bytes (USE THIS when writing wire) |
| `n.to_le_bytes()` / `to_ne_bytes()` | little / native |

The rule is absolute: **reading wire fields uses `from_be_bytes`; writing wire fields uses
`to_be_bytes`.** `from_ne_bytes` is the trap — it happens to be little-endian on your machine,
so it produces the byte-swapped wrong value and your code is silently incorrect *and*
non-portable.

### D.5 — Worked: the silent bug

Total Length bytes on the wire are `00 54` (big-endian for 84).
```
u16::from_be_bytes([0x00, 0x54]) = 0x0054 = 84      ✓ correct
u16::from_ne_bytes([0x00, 0x54]) = 0x5400 = 21504   ✗ on little-endian x86/ARM
```
A length field reading 21504 would make every downstream offset nonsense. The bug is
invisible until you check the value — which is why §11 (verification) exists.

### D.6 — The historical C equivalents

In C you used `htons`/`htonl` ("host to network short/long") and `ntohs`/`ntohl` ("network to
host"). On a little-endian host these byte-swap; on a big-endian host they are no-ops. Rust's
`to_be_bytes`/`from_be_bytes` are the modern, type-safe equivalents — they don't depend on a
platform macro and they make the direction explicit in the name.

### D.7 — A test you can run in your head

If you ever doubt your machine's endianness:
```rust
let n: u16 = 1;            // 0x0001
let bytes = n.to_ne_bytes();
// little-endian → [1, 0]   (least-significant byte first)
// big-endian    → [0, 1]
```
On your x86/ARM box this is `[1, 0]`. Now you can *feel* why wire data needs explicit
big-endian handling.

---

## E. The IPv4 header — every field, every value, exhaustively

Volume I §5 gave you the working subset. Here is the complete RFC 791 header, every field,
every defined value, and what we do (or defer) with each.

### E.1 — The complete layout (with bit numbers)

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Version|  IHL  |Type of Service|          Total Length         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Identification        |Flags|      Fragment Offset    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Time to Live |    Protocol   |         Header Checksum       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Source Address                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Destination Address                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Options                    |    Padding     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### E.2 — Field 1: Version (4 bits, byte 0 high nibble)

The IP version. `4` for IPv4 (`0x4`), `6` for IPv6 (`0x6`). It is the very first nibble so a
receiver can decide how to parse the rest before assuming anything. Our parser rejects
anything but 4 (`ParseError::NotIpv4`). Because IPv6 has a *completely different* header, the
version nibble is the fork in the road. On a TUN interface configured for IPv4 you'll only see
4, but a dual-stack interface can deliver 6 too — hence the check is not paranoia.

### E.3 — Field 2: IHL — Internet Header Length (4 bits, byte 0 low nibble)

Header length in **32-bit words**. Minimum 5 (5×4 = 20 bytes, no options); maximum 15 (15×4 =
60 bytes, up to 40 bytes of options). It exists because the header is *variable length* (due
to options), so the receiver needs to know where the header ends and the payload begins:
`payload_start = IHL × 4`. A value below 5 is malformed (the fixed header alone is 20 bytes);
our `HeaderLongerThanPacket` guard and the `< 20` guard together bound it safely. Hardcoding
"payload at byte 20" is the classic bug this field prevents (Volume I §8).

### E.4 — Field 3: Type of Service / DSCP+ECN (8 bits, byte 1)

Originally "Type of Service" (RFC 791): bits for precedence, delay, throughput, reliability.
Redefined by RFC 2474/3168 into:
- **DSCP** (Differentiated Services Code Point), the top 6 bits — QoS class. Values like
  `EF` (Expedited Forwarding, 0b101110) for low-latency voice, `AF` classes for assured
  forwarding, `CS0..CS7` class selectors, `0` = best effort.
- **ECN** (Explicit Congestion Notification), the low 2 bits — lets routers mark congestion
  *without dropping* a packet: `00` not-ECT, `01`/`10` ECT(1)/ECT(0) (endpoints support ECN),
  `11` CE (congestion experienced). TCP then echoes this back to slow down.

We ignore byte 1 on Doc 1 (it doesn't affect parsing), but you should know it is *not*
reserved — it carries QoS and congestion signaling that real networks act on.

### E.5 — Field 4: Total Length (16 bits, bytes 2–3, big-endian)

The length of the **entire** datagram — header *plus* payload — in bytes. 16 bits ⇒ max
65,535 bytes. The minimum is 20 (header only). This is the authority for where the datagram
ends; once real payloads arrive you trust `total_len`, not the buffer size, to bound the data
(a buffer may hold trailing garbage or be larger than the packet). Note the interplay with
MTU: links cap the *physical* frame (1500 on Ethernet), so a 65,535-byte IP datagram must be
*fragmented* to cross them — which is what the next three fields manage.

### E.6 — Field 5: Identification (16 bits, bytes 4–5, big-endian)

A unique-ish id the sender stamps on a datagram so that, if it is fragmented, the receiver can
group the fragments that belong together (all fragments of one datagram share the
Identification). We don't reassemble on Doc 1, but you'll need this field when you implement
fragmentation. Historically also (ab)used for other purposes; modern stacks often set it to 0
for DF packets.

### E.7 — Field 6: Flags (3 bits, byte 6 top 3 bits)

```
bit 0: Reserved, must be 0  (famously "evil bit" in the April-fools RFC 3514)
bit 1: DF (Don't Fragment) — routers must not fragment; if too big, drop + ICMP "Frag Needed"
bit 2: MF (More Fragments)  — 0 on the last fragment, 1 on all earlier ones
```
DF is the engine of **Path MTU Discovery**: send big DF packets, and if one is too large for
some link, that router replies ICMP Type 3 Code 4 telling you the MTU, so you shrink. Extract
with `(packet[6] >> 5) & 0x07`.

### E.8 — Field 7: Fragment Offset (13 bits, low of byte 6 + byte 7)

Where this fragment's payload sits within the original datagram, measured in **8-byte units**
(because 13 bits can't index 65,535 bytes directly; ×8 gives the needed range). The first
fragment has offset 0. Reassembly places each fragment at `offset × 8`. Extract with
`u16::from_be_bytes([packet[6], packet[7]]) & 0x1FFF`. Fragmentation is a rich source of
historical attacks (overlapping fragments, teardrop) — a reason modern stacks prefer PMTUD +
DF over fragmentation.

### E.9 — Field 8: Time To Live (8 bits, byte 8)

A hop budget. Each router that forwards the packet **decrements TTL by 1**; when it reaches 0
the router discards the packet and sends back ICMP Type 11 (Time Exceeded). This prevents
packets from looping forever in a routing loop. Common initial values: 64 (Linux/macOS), 128
(Windows), 255 (some routers). Two consequences you can observe: (1) the TTL in a reply hints
at the sender's OS and distance; (2) **traceroute** sends packets with TTL = 1, 2, 3, … and
collects the Time-Exceeded replies to map every router on the path. We set TTL = 64 on packets
we generate (Doc 2+).

### E.10 — Field 9: Protocol (8 bits, byte 9)

Which transport/next-layer protocol is in the payload, so the receiver knows how to parse it.
The full set is the IANA protocol-numbers registry; the ones that matter here:

| Number | Protocol | Number | Protocol |
|--------|----------|--------|----------|
| 1      | ICMP     | 47     | GRE      |
| 2      | IGMP     | 50     | ESP (IPsec) |
| 6      | **TCP**  | 51     | AH (IPsec)  |
| 17     | **UDP**  | 58     | ICMPv6   |
| 4      | IPv4 (encapsulation) | 89 | OSPF |
| 41     | IPv6 (6in4) | 132 | SCTP   |

Our `match` handles 1/6/17; everything else is "unknown" and ignored for now. This single byte
is the demultiplexing key from L3 to L4.

### E.11 — Field 10: Header Checksum (16 bits, bytes 10–11, big-endian)

The Internet checksum (RFC 1071) computed over **the header only** (not the payload — TCP/UDP
checksum their own data). A router that decrements TTL must recompute (or incrementally update)
this. We *parse* it on Doc 1 and *compute/validate* it on Doc 2. Note IPv6 dropped the header
checksum entirely (relying on L2 and L4 checks) to save router work — a deliberate design
reversal worth knowing.

### E.12 — Fields 11 & 12: Source and Destination Address (32 bits each, bytes 12–15, 16–19)

The IPv4 addresses, four octets each, in order. `c0 a8 00 01` = 192.168.0.1. Notable ranges:
- **Private (RFC 1918):** 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 — not routed on the
  public internet; our 192.168.0.x lab lives here.
- **Loopback:** 127.0.0.0/8 (127.0.0.1 = localhost).
- **Link-local:** 169.254.0.0/16 (APIPA).
- **Multicast:** 224.0.0.0/4. **Broadcast:** 255.255.255.255.
- **0.0.0.0** = "this host"/unspecified.
A `/24` (as in `192.168.0.1/24`) means the top 24 bits are the network, the low 8 the host —
256 addresses, 192.168.0.0–192.168.0.255. This CIDR notation is how routing decides "is this
destination on my local link or do I send it to a gateway?"

### E.13 — Field 13: Options + Padding (0–40 bytes, only if IHL > 5)

Optional, rarely used: Record Route, Timestamp, Strict/Loose Source Routing, Router Alert.
Each option is type-length-value; the header is padded with zeros to a 32-bit boundary so IHL
stays an integer number of words. Source-routing options are a security hazard and usually
dropped by routers. We don't parse options, but because IHL accounts for them, our payload
offset (`IHL × 4`) stays correct even when they're present — the payoff of using IHL instead
of a hardcoded 20.

### E.14 — A full second worked decode

Bytes: `45 00 05 dc 1c 46 40 00 40 06 a1 2b c0 a8 00 0a 5d b8 d8 22`
```
45      → version 4, IHL 5 (20-byte header)
00      → DSCP 0, ECN 0
05 dc   → total length 0x05DC = 1500 (a full-MTU packet)
1c 46   → identification 0x1C46
40 00   → flags: 010 → DF set, MF clear; fragment offset 0
40      → TTL 64
06      → protocol 6 = TCP
a1 2b   → header checksum 0xA12B
c0 a8 00 0a → source 192.168.0.10
5d b8 d8 22 → destination 93.184.216.34
```
Read it back: a 1500-byte, don't-fragment TCP packet from your LAN host to a public server,
64 hops of budget left. You can now read any IPv4 header on sight.

## F. The TUN device and the Linux kernel datapath, in full

Volume I §2 told you *what* a TUN device is. This section tells you *how* it works inside the
kernel, how a packet normally travels, exactly where we intercept it, and how TUN compares to
every other packet-access mechanism. This is the "systems" half of the project.

### F.1 — How a packet normally travels (no TUN)

When a real application sends data over a real NIC, the bytes pass through a stack of layers,
each a piece of kernel code:

```
   application:   write() / send() on a socket
        │
   socket layer:  copies user bytes into a kernel buffer (an sk_buff)
        │
   TCP/UDP:       adds the L4 header, sequence numbers, checksum (the work WE are reimplementing)
        │
   IP:            adds the IP header, picks a route, sets TTL, checksum
        │
   netfilter:     iptables/nftables hooks (firewall, NAT) run here
        │
   device queue:  qdisc (traffic shaping), then the driver
        │
   NIC:           DMA the frame onto the wire
```

Receiving is the mirror image: NIC interrupt → driver → IP → netfilter → TCP → socket → the
app's `read()`. The central data structure carried through all of this is the **`sk_buff`**
("socket buffer," often `skb`), a struct holding the packet bytes plus metadata, with clever
pointers that let each layer prepend/strip its header without copying the payload.

### F.2 — Where a TUN device sits

A TUN device is a **virtual** network interface with no hardware behind it. To the kernel's IP
layer it looks exactly like a real NIC: it has a name (`tun0`), an MTU, an IP/route, and it can
be `UP`. But instead of a driver that DMAs frames to silicon, its "driver" is the
`/dev/net/tun` character device. So:

```
   our process  ── write(fd) ──►  TUN driver  ──►  kernel IP layer  (looks like "received from tun0")
   our process  ◄── read(fd) ───  TUN driver  ◄──  kernel IP layer  (kernel "transmitted to tun0")
```

When you run `ip addr add 192.168.0.1/24 dev tun0`, you create a route: "192.168.0.0/24 is
reachable via tun0." So when `ping 192.168.0.2` runs, the kernel's routing table says "192.168.0.2
is on tun0," builds the ICMP+IP packet, and "transmits" it on tun0 — which means it hands the
bytes to whoever holds the `/dev/net/tun` fd: **us**, via `read()`. We are the wire and the
machine at the other end, simultaneously.

### F.3 — TUN vs TAP at the driver level

The same driver (`drivers/net/tun.c`) implements both:
- **TUN (`IFF_TUN`)** — a *point-to-point* L3 device. Reads/writes are **IP packets**. No
  Ethernet header, no MAC, no ARP, no broadcast. This is us.
- **TAP (`IFF_TAP`)** — an L2 *Ethernet* device. Reads/writes are **Ethernet frames** (14-byte
  header: dst MAC, src MAC, EtherType). You'd implement Ethernet + ARP before any IP.

You choose at creation via the `ioctl` flags. TUN is simpler for learning IP/TCP; TAP is for
bridging VMs/containers at L2.

### F.4 — The creation ioctl, step by step

`Iface::new`/`without_packet_info` ultimately do this (in C terms):

```c
int fd = open("/dev/net/tun", O_RDWR);     // 1. get a handle to the TUN driver
struct ifreq ifr = {0};
ifr.ifr_flags = IFF_TUN | IFF_NO_PI;       // 2. choose TUN (L3) and no packet-info header
strncpy(ifr.ifr_name, "tun0", IFNAMSIZ);   // 3. ask for the name "tun0"
ioctl(fd, TUNSETIFF, &ifr);                // 4. create/attach the interface to this fd
// from here: read(fd, buf, len) returns one packet; write(fd, buf, len) injects one
```

- **`open`** returns a file descriptor — an integer the kernel maps to this TUN instance.
- **`ioctl`** ("I/O control") is the generic "do something device-specific" syscall;
  `TUNSETIFF` is the TUN-specific command meaning "make this fd a TUN interface with these
  flags/name."
- The `tun-tap` crate wraps all of this and hands you an `Iface` whose `recv`/`send` are
  `read`/`write` on that fd. When the `Iface` is dropped, the fd is closed and (for a
  non-persistent device) the interface disappears.

### F.5 — The IFF flags (the full set worth knowing)

| Flag | Meaning |
|------|---------|
| `IFF_TUN` | L3 mode — read/write IP packets |
| `IFF_TAP` | L2 mode — read/write Ethernet frames |
| `IFF_NO_PI` | **no** 4-byte packet-information prefix (we set this) |
| `IFF_MULTI_QUEUE` | allow multiple fds/queues for parallelism on multicore |
| `IFF_VNET_HDR` | prepend a virtio-net header (offload metadata for VMs) |
| `IFF_PERSIST` | (via `TUNSETPERSIST`) keep the interface after the fd closes |

We use `IFF_TUN | IFF_NO_PI`. The others matter for VMs (vhost/virtio) and high-performance
multi-queue setups — context for when you read production code.

### F.6 — The 4-byte packet-information header, in full

When `IFF_NO_PI` is *not* set (i.e. `Iface::new`), every `read` is prefixed with a 4-byte
`struct tun_pi`:

```
 byte 0   byte 1   byte 2   byte 3   byte 4 ...
+--------+--------+--------+--------+----------
|     flags       |    proto (EtherType)     |   IP packet ...
+--------+--------+--------+--------+----------
```

- **flags** (2 bytes): TUN flags for this packet; usually 0 on read.
- **proto** (2 bytes, big-endian): the EtherType — `0x0800` for IPv4, `0x86DD` for IPv6,
  `0x0806` for ARP. This lets a reader demultiplex IPv4 vs IPv6 without parsing the version
  nibble.

Two ways to live with it: set `IFF_NO_PI` (our choice — the prefix vanishes, `buf[0]` is the IP
version), or keep it and parse from `buf[4..]` after checking the EtherType. The whole
Doc-1-breaking bug (version reads as 0) is this prefix shifting every offset by 4 — see Volume
I §3. The docs literally tell you to size your buffer "MTU + 4" because of these bytes.

### F.7 — Capabilities and isolation, deeper

Creating an interface needs `CAP_NET_ADMIN`. Linux capabilities (see `capabilities(7)`) split
root's monolithic power into ~40 independently-grantable units; `CAP_NET_ADMIN` covers
interface configuration, routing, and `TUNSETIFF`. Granting just that one to a binary
(`setcap cap_net_admin=eip`) follows **least privilege**: a bug in our stack can't, say, load
kernel modules or read arbitrary files the way full root could. The `=eip` sets the capability
in the *effective*, *inheritable*, and *permitted* sets. Caveat already burned into us: file
capabilities are stored in filesystem extended attributes, which DrvFs (`/mnt/c`) doesn't
support — hence the native-fs build directory.

### F.8 — How `recv` blocks (and how it wouldn't)

`read(fd, buf, len)` on a TUN fd **blocks**: the calling thread is put to sleep by the kernel
and consumes no CPU until a packet is available to deliver, at which point the kernel copies it
into your buffer and wakes you. This is fine for a single-connection toy. A real stack handling
many connections plus timers can't block on one fd, so it switches to **non-blocking** mode
(`set_non_blocking`, which sets `O_NONBLOCK`): now `read` returns `EWOULDBLOCK` immediately if
nothing is ready, and you use `epoll`/`poll` to wait on the fd *and* timers simultaneously.
That event-loop change is exactly the prerequisite for retransmission (see doc5-book.md §10).

### F.9 — TUN vs the other ways to touch packets

| Mechanism | Layer | What you get | Typical use |
|---|---|---|---|
| **TUN** | L3 | IP packets to/from a userspace fd | VPNs, this project |
| **TAP** | L2 | Ethernet frames | VM/container bridges, L2 VPNs |
| **AF_PACKET (raw socket)** | L2/L3 | copies of frames on a *real* interface | sniffers, custom L2 tools |
| **libpcap / `tcpdump`** | L2 | capture (and limited inject) on real ifaces | packet capture/analysis |
| **AF_XDP / XDP / eBPF** | driver | very high-speed packet processing in/near the driver | DDoS scrubbing, LB |
| **DPDK** | userspace poll-mode driver | bypass the kernel entirely for max throughput | NFV, trading |

TUN is the sweet spot for *building a stack*: you get clean L3 packets, full control of the
responses, and isolation from the host's real networking — without writing a driver. The
others either tap an existing interface (you can't easily be the *endpoint*) or chase raw
performance we don't need.

### F.10 — Persistence and lifecycle

By default our TUN interface is **non-persistent**: it exists only while our process holds the
fd, and disappears on exit (handy — no cleanup). With `TUNSETPERSIST` (and an owner uid) it can
outlive the process, which is how VPN daemons pre-create `tun0` at boot. If you ever get
`ResourceBusy` creating `tun0`, a stale persistent interface is the usual cause — `sudo ip link
delete tun0` clears it.

---

## G. Rust for parsers — ownership, borrowing, slices, and error handling

The code is small but it leans on the parts of Rust that make systems code safe. This section
explains every language mechanism the parser uses, why it exists, and what the alternatives
cost — enough that you could write the parser in Rust having never seen it, and explain why it
won't segfault.

### G.1 — Why Rust for a network stack

A packet parser is the textbook place to get **memory-safety** bugs: you index into buffers of
attacker-controlled length. In C, a missing bounds check is a buffer over-read (Heartbleed was
exactly this — reading past a length in a TLS heartbeat). Rust makes the same code safe by
construction: every slice index is bounds-checked at runtime (panic instead of silent
over-read), and the **borrow checker** prevents use-after-free and data races at *compile*
time, with no garbage collector and no runtime cost. You get C's control and speed with
guardrails. That is why new stacks, parsers, and kernels increasingly choose Rust.

### G.2 — Ownership

Every value in Rust has exactly one **owner** (a variable). When the owner goes out of scope,
the value is dropped (freed) — deterministically, no GC. Assigning or passing a non-`Copy`
value *moves* ownership:

```rust
let v = vec![1u8, 2, 3];   // v owns the heap buffer
let w = v;                  // ownership MOVED to w; v is now invalid
// println!("{:?}", v);     // compile error: borrow of moved value
```

This single-owner rule is what makes "when is this freed?" always answerable, and it's the
foundation the borrow checker builds on. Small `Copy` types (`u8`, `u16`, `u32`, `Ipv4Addr`,
our `TcpHeader`-less plain fields) are *copied* instead of moved, because copying a few bytes
is trivial — that's why passing a `u16` around "just works."

### G.3 — Borrowing and references (`&`)

You often want to *use* a value without *taking ownership*. That's a **borrow**, written `&`:

```rust
fn parse(packet: &[u8]) -> ... { /* reads packet, does not own it */ }
let buf = [0u8; 1504];
let h = parse(&buf);        // lend buf to parse; buf still owned by us afterward
```

`&T` is a shared/immutable reference (read-only, many allowed at once). `&mut T` is an
exclusive/mutable reference (read-write, only one at a time). Our `parse(&[u8])` borrows the
packet immutably — it promises not to modify it and copies out only the fields it returns. This
is why, in the main loop, we can `let packet = &buf[..n];` parse it, and next iteration still
`iface.recv(&mut buf)` — the immutable borrow ends when we're done with `packet`.

### G.4 — The borrowing rules (the borrow checker)

At any moment, for a given value, you may have **either**:
- any number of immutable references (`&T`), **or**
- exactly one mutable reference (`&mut T`),

never both. This "shared XOR mutable" rule, enforced at compile time, is what statically
eliminates data races and iterator-invalidation bugs. It's why you sometimes restructure code
to satisfy it (e.g. compute `state = conn.state()` *before* `connections.remove(&quad)` in
Doc 5 — the `&mut conn` borrow must end before we touch the map again). The checker is not
being difficult; it's proving the absence of a class of bugs.

### G.5 — Slices (`&[u8]`) — the parser's core type

A slice is a **borrowed view** into a contiguous run of elements: internally a `(pointer,
length)` pair (a "fat pointer"). `&buf[..n]` is a slice of the first `n` bytes; it copies
nothing — it points into `buf`. `&packet[header_len..]` is the payload, again zero-copy. Slices
are the reason packet parsing in Rust is fast *and* safe: you pass around windows into the one
buffer, and every access is bounds-checked.

```rust
let l4 = &packet[hdr.header_len..];     // payload view, no allocation
let port = u16::from_be_bytes([l4[0], l4[1]]);  // bounds-checked reads
```

### G.6 — Indexing, panics, and bounds checks

`slice[i]` panics if `i` is out of range. A panic unwinds and (in `main`) aborts the program —
catastrophic for a server (a crafted short packet would be a denial of service). Two
defenses, both used:
1. **Guard once, then index freely.** `parse` checks `packet.len() < 20` *first*; after that,
   `packet[0..20]` cannot panic. We reason about safety in one place.
2. **Fallible indexing where appropriate.** `slice.get(i)` returns `Option<&T>` (None instead
   of panic) — useful when a length is uncertain. We prefer the up-front guard because it makes
   the happy path clean and the error explicit.

### G.7 — `Option<T>` — "a value or nothing"

`Option<T>` is `Some(T)` or `None`. It's how Rust expresses "might be absent" without null
pointers (no "billion-dollar mistake"). We use it where failure has a single obvious meaning:
`parse_icmp` returns `Option<IcmpHeader>` — `None` means "too short," nothing more to say. You
consume it with `match`, `if let Some(x) = ...`, or combinators (`map`, `unwrap_or`).

```rust
if let Some(i) = icmp::parse(l4) { /* use i */ }
```

### G.8 — `Result<T, E>` — "success or a described failure"

`Result<T, E>` is `Ok(T)` or `Err(E)`. Use it when failure has *causes worth distinguishing*.
`ip::parse` returns `Result<Ipv4Header, ParseError>`; the `ParseError` enum names *why*
(`TooShort`, `NotIpv4`, `HeaderLongerThanPacket`). Choosing `Result` over `Option` here pays
off the instant something misbehaves — the log says exactly which check failed. Matching the
return type to the *shape of failure* (one cause → `Option`, several → `Result`) is a real
design skill, not a formality.

### G.9 — Enums and pattern matching

Rust enums are **sum types** — a value is exactly one of several variants, optionally carrying
data:

```rust
enum ParseError {
    TooShort { have: usize, need: usize },
    NotIpv4 { version: u8 },
    HeaderLongerThanPacket { header_len: usize, have: usize },
}
```

`match` forces you to handle every variant (or use `_`), so adding a variant later produces
compile errors at every place that must consider it — the compiler maintains your TODO list.
The TCP `State` enum (SynRcvd/Established/LastAck/Closed) is the same idea applied to a state
machine. Tuple/struct matching also destructures: `match (typ, code) { (8, 0) => ..., ... }`.

### G.10 — The `?` operator and error propagation

`main() -> std::io::Result<()>` lets us write `let n = iface.recv(&mut buf)?;`. The `?` means
"if this is `Err`, return it from the function now; otherwise unwrap the `Ok`." It's concise
propagation without nested matches. It works for both `Result` and `Option` and requires the
function's return type to be compatible — which is why `main` returns `io::Result<()>`.

### G.11 — `&'static str` and string types

`protocol_name` returns `&'static str` — a reference to a string baked into the binary, valid
for the whole program (`'static` lifetime), so no allocation. Contrast `String` (heap-owned,
growable), which `tcp::flags_str` builds because it concatenates at runtime. Rule of thumb: a
fixed label is `&'static str`; a runtime-assembled string is `String`. We avoid `String` in the
hot path precisely to avoid per-packet allocation.

### G.12 — Lifetimes (the one-paragraph version)

A lifetime is the compiler's name for "how long a reference is valid." Most are inferred;
you'd write one explicitly if a struct *borrowed* packet bytes (e.g. a zero-copy
`Ipv4HeaderSlice<'a>` that lives no longer than the buffer it points into). We sidestep
explicit lifetimes by **copying** the few fields we need into an owned `Ipv4Header` struct — a
deliberate simplicity-over-zero-copy trade (Volume I §9). When performance demands it, you'd
introduce a borrowed header type with a lifetime tying it to the packet.

### G.13 — Arrays, `Vec`, and `copy_from_slice`

- `[0u8; 1504]` is a fixed-size **array** on the stack — no allocation, reused each loop
  iteration (our receive buffer).
- `Vec<u8>` is a growable **heap** buffer — what `to_vec()` and `build_packet` produce for
  outgoing packets, because their size varies.
- `dst.copy_from_slice(src)` bulk-copies bytes (memcpy) and panics if lengths differ — used to
  lay header fields into an outgoing `Vec` and to swap addresses in the echo reply.

### G.14 — Iterators (`chunks_exact`) and why they're zero-cost

The checksum (Doc 2) uses `data.chunks_exact(2)` to walk 16-bit words, plus `.remainder()` for
a trailing odd byte. Rust iterators are **zero-cost abstractions**: they compile to the same
machine code as a hand-written loop, but read declaratively and avoid off-by-one bugs.
`for w in chunks.by_ref()` consumes the even pairs; `chunks.remainder()` then yields the leftover.

### G.15 — `#[derive(...)]` and traits

`#[derive(Debug, PartialEq, Eq)]` auto-generates trait implementations:
- `Debug` → `{:?}` formatting (our logs and test failure messages).
- `PartialEq, Eq` → `==` (so tests can `assert_eq!` on a parsed header).
- `Hash` (on `Quad`) → usable as a `HashMap` key.
- `Clone, Copy` → value semantics for small types.
Traits are Rust's interfaces; deriving them is the compiler writing the boilerplate. We derive
only what we use; `PartialEq` on `Ipv4Header` exists purely for tests and costs nothing at
runtime.

### G.16 — `#[cfg(test)]` and the test harness

`#[cfg(test)] mod tests { ... }` compiles only under `cargo test`, so test code and fixtures add
nothing to the release binary. Tests live in the same file as the code they exercise (Rust
convention), can call private items (they're a child module), and run in parallel. This is why
our parsers are verifiable with zero network setup — the offline safety net.

### G.17 — The alternatives we rejected, and why

| Approach | What it is | Why not here |
|---|---|---|
| `unsafe { std::mem::transmute }` a `#[repr(C)]` struct over bytes | reinterpret raw memory as a header struct | ignores endianness; assumes field layout/alignment the compiler doesn't guarantee; **undefined behavior** on unaligned/garbage input — the canonical wrong way |
| `nom` | parser-combinator library | excellent for complex/recursive grammars; overkill for fixed byte offsets |
| `byteorder` crate | `read_u16::<BigEndian>()` etc. | predates std `from_be_bytes`; std now covers it |
| `bytes` crate | cursor over buffers with advancing reads | nice ergonomics; an unnecessary dependency for this size |
| `etherparse` for everything | full parse/build library | we *use* it — but as an oracle; doing the parsing ourselves is the entire point |
| `packed_struct`/`deku`/`binrw` | derive-based binary (de)serialization | great for big formats; hides the bit-level learning we're here for |

The throughline: hand-rolled shift/mask/`from_be_bytes` parsing keeps us at the byte level
(the learning), while bounds checks + `Result`/`Option` keep it safe (the Rust). We borrow a
library only to *check* ourselves.

---

## H. ICMP, exhaustively

Volume I §10 gave you the echo subset. ICMP (RFC 792, with extensions in 1191, 4884, 6633, and
ICMPv6 in 4443) is the internet's control and diagnostic plane — the layer that *reports* about
IP rather than carrying user data. This section covers the whole protocol surface you'll meet.

### H.1 — What ICMP is for

IP is "best effort": packets can be dropped, delayed, or undeliverable, and plain IP has no way
to tell anyone. ICMP fills that gap. It carries *error reports* ("your packet couldn't be
delivered," "TTL expired," "fragmentation needed") and *diagnostics* (echo request/reply for
`ping`, timestamp). It rides **inside** IP (protocol number 1) but is considered part of the
network layer, not a transport like TCP/UDP — it has no ports. An ICMP error message includes
the **IP header + first 8 bytes** of the packet that triggered it, so the original sender can
match the error to the offending flow (those 8 bytes contain the TCP/UDP ports or the ICMP
id/seq).

### H.2 — The ICMP message format

Every ICMP message begins with the same 4 bytes, then a type-specific body:

```
 0               1               2               3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Type      |     Code      |          Checksum             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                  rest of header (type-specific)               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                  data (type-specific)                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- **Type** (1 byte) — the category of message (8 = echo request, etc.).
- **Code** (1 byte) — a sub-type within the type (for Unreachable, *why* it was unreachable).
- **Checksum** (2 bytes) — the Internet checksum over the *entire* ICMP message (header + body).
  Unlike TCP/UDP, ICMP's checksum has **no pseudo-header** (it doesn't depend on IP addresses).
- **Rest of header** (4 bytes) — meaning depends on type. For echo it's Identifier + Sequence.
- **Data** — for echo, the payload to be echoed back; for errors, the offending IP header + 8 bytes.

### H.3 — Echo Request / Echo Reply (types 8 and 0) — what `ping` is

The diagnostic everyone knows. Layout of the 8-byte echo header + data:

```
 type(8 or 0) | code(0) | checksum(2) | identifier(2) | sequence(2) | data...
```

- **Echo Request = type 8, code 0.** Sent by `ping`.
- **Echo Reply = type 0, code 0.** The required answer (what we build on Doc 2).
- **Identifier** — lets the sending process match replies to itself (often the PID on Linux, or
  a fixed value). Multiple pings on one host are told apart by id.
- **Sequence** — increments each request (1, 2, 3…), so `ping` can compute per-packet loss and
  RTT and print `icmp_seq=N`.
- **Data** — arbitrary payload echoed back verbatim. Linux ping puts a timestamp at the front
  (to compute RTT) plus filler to a default 56 bytes → 64-byte ICMP → 84-byte IP packet (the
  famous "64 bytes from…"). The reply must copy this data unchanged; that's why our echo-reply
  builder keeps the payload and only flips the type and fixes checksums.

`ping` mechanics end to end: send Echo Request (id=mine, seq=n, data=timestamp), start a timer;
on the matching Echo Reply, RTT = now − timestamp; track which seq numbers came back for loss %.

### H.4 — Destination Unreachable (type 3) — the codes

A router or host couldn't deliver the packet. The **code** says why (the ones that matter):

| Code | Meaning | Who sends it |
|------|---------|--------------|
| 0 | Net Unreachable | a router with no route to the network |
| 1 | Host Unreachable | last-hop router; host is down/absent |
| 2 | Protocol Unreachable | host doesn't run that L4 protocol |
| 3 | **Port Unreachable** | host has nothing listening on that UDP port |
| 4 | **Fragmentation Needed and DF set** | a router whose link MTU is too small (drives PMTUD) |
| 5 | Source Route Failed | source-routing option couldn't be honored |
| 6/7 | Dest Network/Host Unknown | — |
| 9/10 | Net/Host Administratively Prohibited | a firewall dropping you |
| 13 | Communication Administratively Prohibited | firewall/ACL |

Two are especially important: **Code 3 (Port Unreachable)** is how UDP signals "nobody's home"
on a port (and is the basis of one form of traceroute), and **Code 4 (Fragmentation Needed)**
carries the next-hop MTU and is the engine of **Path MTU Discovery** — without it, DF packets
that are too big would vanish silently ("PMTUD black hole").

### H.5 — Time Exceeded (type 11) — how traceroute works

- **Code 0: TTL exceeded in transit.** A router decremented TTL to 0 and dropped the packet,
  reporting back with this message (whose source address is *that router*).
- **Code 1: Fragment reassembly time exceeded.**

**Traceroute** exploits Code 0 deliberately: send packets toward the destination with TTL = 1,
then 2, then 3, … The router at hop *k* decrements TTL to 0 and sends Time Exceeded, revealing
its IP. By increasing TTL you walk out the path hop by hop until packets finally reach the
destination (which replies with Echo Reply, or — for UDP traceroute — Port Unreachable). Each
hop is probed a few times to show per-hop RTT. This is a beautiful example of using an error
mechanism as a measurement tool.

### H.6 — Redirect (type 5), Source Quench (type 4, deprecated), and others

- **Type 5 Redirect** — a router telling a host "use a better gateway for this destination."
  Largely disabled today (a spoofing risk).
- **Type 4 Source Quench** — an obsolete, deprecated congestion signal (RFC 6633 formally
  deprecated it); congestion is handled by TCP + ECN now.
- **Type 13/14 Timestamp Request/Reply** — clock-based diagnostic, rarely used (info leak).
- **Type 17/18 Address Mask Request/Reply** — obsolete.

### H.7 — The full type table (IPv4 ICMP)

| Type | Name | Notes |
|------|------|-------|
| 0 | Echo Reply | ping answer |
| 3 | Destination Unreachable | see code table; carries offending header+8B |
| 4 | Source Quench | deprecated |
| 5 | Redirect | usually disabled |
| 8 | Echo Request | ping |
| 9/10 | Router Advertisement/Solicitation | rarely used |
| 11 | Time Exceeded | traceroute |
| 12 | Parameter Problem | malformed header field |
| 13/14 | Timestamp Request/Reply | rare |
| 17/18 | Address Mask Request/Reply | obsolete |

### H.8 — ICMPv6 — the same idea, more responsibility (context)

ICMP for IPv6 (RFC 4443, protocol number 58) is not optional plumbing — it's load-bearing. It
absorbed ARP's job via **Neighbor Discovery** (Neighbor Solicitation/Advertisement replace ARP;
Router Solicitation/Advertisement do autoconfiguration). So on IPv6 you cannot "just block all
ICMP" the way some misguided IPv4 firewalls do, or the network stops working. Echo is types 128
(request)/129 (reply) there. We're IPv4-only, but knowing this explains why "block ICMP" is bad
advice in general and catastrophic on v6.

### H.9 — Security and operational notes

- **Don't blanket-block ICMP.** Blocking Echo is debatable; blocking *Fragmentation Needed*
  (type 3 code 4) breaks PMTUD and creates hangs ("works for small pages, stalls on big
  downloads") — the classic PMTUD black hole.
- **ICMP as a covert channel / tunnel.** Because Echo data is arbitrary and often allowed out,
  tools tunnel data inside ping payloads (`icmptunnel`). Relevant to your security track.
- **Smurf / ping flood / ping of death** — historical attacks (amplification via broadcast
  echo; oversized/overlapping fragments). Modern stacks rate-limit ICMP and reject malformed
  fragments; a hardened version of *our* stack would rate-limit echo replies.
- **Error messages quote 8 bytes of the original** — enough to leak/confirm the ports and
  sequence of a flow, which is why some setups limit ICMP error generation.

### H.10 — Mapping it back to our code

`icmp::parse` reads type/code/checksum/id/seq. `icmp::name` labels the (type, code) pairs from
the tables above. `icmp::build_echo_reply` handles exactly type 8 → type 0, recomputing the
checksum that §H.2 says covers the whole message with no pseudo-header. Everything else in the
type table we currently *recognize but don't act on*; exercises add Port Unreachable (type 3
code 3) generation, which is your first *originated* (not mutated) ICMP error.

---

## I. tcpdump and Wireshark, field by field

You cannot debug a network stack you cannot see. `tcpdump` and Wireshark are the ground truth
you check your code against — when your parser and the sniffer disagree, the sniffer is right.
This section makes you fluent in both, focused on `tun0`.

### I.1 — Why an external sniffer is non-negotiable

Your stack's `println!` shows *what your code thinks happened*. A sniffer shows *what was
actually on the wire*, decoded by a mature, correct implementation. The gap between the two is
exactly your bug. The Doc-1 `IFF_NO_PI` trap is the perfect example: your code prints nothing
(it skipped everything), but `tcpdump -i tun0` clearly shows the ICMP requests arriving — so the
problem is in your parse, not the network. That triangulation is the core debugging loop.

### I.2 — tcpdump essentials

```bash
sudo tcpdump -i tun0 -n -v
```
- `-i tun0` — capture on our interface.
- `-n` — don't resolve IPs to names (faster, and you want to see the raw addresses).
- `-v` / `-vv` — verbose: show TTL, id, flags, options, checksum validation.
- `-e` — also show link-layer header (irrelevant on TUN — there isn't one).
- `-X` — print a **hex + ASCII dump** of each packet (priceless for byte-level work).
- `-XX` — like `-X` with link header.
- `-c N` — stop after N packets.
- `-w cap.pcap` — write raw packets to a file (open later in Wireshark).
- `-r cap.pcap` — read back a saved capture.
- `-s 0` — capture full packet length (old default truncated; modern tcpdump is full by default).

Example you'll use constantly while building:
```bash
sudo tcpdump -i tun0 -n -vv -X
```

### I.3 — Reading a tcpdump ICMP line

```
12:01:02.345678 IP 192.168.0.1 > 192.168.0.2: ICMP echo request, id 4660, seq 1, length 64
```
- `12:01:02.345678` — timestamp (microseconds).
- `IP 192.168.0.1 > 192.168.0.2` — source > destination (the `>` is direction).
- `ICMP echo request` — type/code decoded for you (your `icmp::name` should agree).
- `id 4660` — the Identifier (0x1234 = 4660; cross-check your parser's `id`).
- `seq 1` — Sequence number.
- `length 64` — ICMP payload length (64 = 8-byte header is *not* counted here; tcpdump shows the
  ICMP data length differently per version — verify against your `total_len`).
After Doc 2 you should see a *second* line, `ICMP echo reply`, from .2 > .1 — proof your reply
went out.

### I.4 — Reading a tcpdump TCP line

```
12:05:00.100 IP 192.168.0.1.43210 > 192.168.0.2.8080: Flags [S], seq 100, win 65535, length 0
12:05:00.101 IP 192.168.0.2.8080 > 192.168.0.1.43210: Flags [S.], seq 0, ack 101, win 1024, length 0
12:05:00.102 IP 192.168.0.1.43210 > 192.168.0.2.8080: Flags [.], ack 1, win 65535, length 0
```
- `.43210` / `.8080` — the ports appended to the IP (source port . dest port).
- `Flags [S]` — SYN. `[S.]` — SYN+ACK (the `.` is ACK). `[.]` — bare ACK. `[P.]` — PSH+ACK
  (data). `[F.]` — FIN+ACK. `[R]` — RST. **Memorize these letters**; they're how you'll read
  every handshake/teardown at a glance. (S=SYN, .=ACK, P=PSH, F=FIN, R=RST, U=URG.)
- `seq`, `ack`, `win`, `length` — exactly the fields your `tcp::parse` extracts. tcpdump by
  default shows *relative* seq/ack (starting from 0) after it sees the handshake; pass
  `-S` (`--absolute-tcp-sequence-numbers`) to see the raw 32-bit values your code actually puts
  on the wire.

This is your Doc-3/4/5 verification: the three handshake lines, then `[P.]` data + your echo,
then the `[F.]` exchanges, with seq/ack numbers matching your TCB math.

### I.5 — BPF capture filters

tcpdump (and Wireshark capture) use **BPF** expressions to capture only what you want:
```bash
sudo tcpdump -i tun0 -n 'icmp'                 # only ICMP
sudo tcpdump -i tun0 -n 'tcp port 8080'        # only TCP on port 8080
sudo tcpdump -i tun0 -n 'host 192.168.0.2'     # only to/from our stack
sudo tcpdump -i tun0 -n 'tcp[tcpflags] & tcp-syn != 0'   # only segments with SYN set
```
Filters keep the noise down when you only care about one flow. They compile to bytecode the
kernel runs per packet — the same BPF that powers a lot of modern observability.

### I.6 — Wireshark: when you want the GUI

Wireshark reads the same `.pcap` files and decodes far more, with a clickable tree:
1. Capture to a file with tcpdump: `sudo tcpdump -i tun0 -w cap.pcap`, reproduce the traffic,
   Ctrl-C, then open `cap.pcap` in Wireshark (or run Wireshark with sudo on `tun0` directly).
2. **The three panes:** packet list (one row per packet), packet details (the decoded header
   tree — expand IP → see every field you parse), packet bytes (hex, with the selected field
   highlighted).
3. **Display filters** (different syntax from capture/BPF filters): `ip.addr == 192.168.0.2`,
   `tcp.flags.syn == 1`, `icmp.type == 8`, `tcp.port == 8080`, `ip.ttl < 5`.
4. **Follow TCP Stream** — reassembles a connection's bytes into the conversation, so you can
   see "hi" go out and come back in your echo test.
5. **Checksum validation** — Wireshark can flag bad IP/TCP checksums (enable in preferences);
   invaluable when your generated packets are being silently dropped — a red checksum tells you
   instantly that's why.

### I.7 — Cross-referencing: the discipline

The habit that makes you fast: for each packet, line up three views — your stack's `println!`,
tcpdump's decoded line, and the `-X` hex dump — and confirm they agree byte for byte. When the
`agrees_with_etherparse` test passes but the live link misbehaves, it's almost always a
*generated* packet (checksum, length, or a field you set wrong); Wireshark's field tree + bad-
checksum flag finds it in seconds. Reading your own packets is a skill; by Doc 5 it should be
reflexive.

### I.8 — A field-mapping cheat sheet (your code ↔ the tools)

| Your code | tcpdump shows | Wireshark filter |
|---|---|---|
| `ip::Ipv4Header.src/dst` | `A > B` | `ip.src`, `ip.dst` |
| `hdr.ttl` | `ttl 64` (with `-v`) | `ip.ttl` |
| `hdr.protocol` | `ICMP` / `tcp` / `UDP` | `ip.proto` |
| `icmp.typ/code` | `echo request`/`unreachable` | `icmp.type`, `icmp.code` |
| `icmp.id/seq` | `id`, `seq` | `icmp.ident`, `icmp.seq` |
| `tcp.src_port/dst_port` | `.PORT > .PORT` | `tcp.srcport`, `tcp.dstport` |
| `tcp.seq/ack` | `seq`, `ack` (use `-S` for absolute) | `tcp.seq`, `tcp.ack` |
| `tcp.flags` | `[S]/[S.]/[.]/[P.]/[F.]/[R]` | `tcp.flags.syn` etc. |
| `tcp.window` | `win` | `tcp.window_size` |

---

## J. Extended exercises with full worked solutions

Work each one on paper or in code *before* reading the solution. These are graded from
warm-up to genuinely tricky; together they re-derive all of Doc 1.

### J.1 — Decode a header cold

**Q.** Decode `45 00 00 3c 1a 2b 40 00 80 06 b1 e6 c0 a8 01 64 5d b8 d8 22`.

**Solution.**
```
45        version 4, IHL 5 → 20-byte header
00        DSCP/ECN 0
00 3c     total length 0x003C = 60 bytes
1a 2b     identification 0x1A2B
40 00     flags 010 (DF set), fragment offset 0
80        TTL 128  → a Windows sender (128 is the Windows default)
06        protocol 6 = TCP
b1 e6     header checksum 0xB1E6
c0 a8 01 64  source 192.168.1.100
5d b8 d8 22  destination 93.184.216.34
```
Read-back: a 60-byte, don't-fragment TCP packet from a Windows host (TTL 128) on 192.168.1.0/24
to a public server. (60 − 20 IP = 40 bytes of TCP → a 20-byte TCP header + 20 bytes of options:
this is almost certainly a SYN with MSS/SACK/window-scale options.)

### J.2 — Version nibble

**Q.** Without running code, what does `parse_ipv4` return for a buffer beginning `0x60...`?

**Solution.** `0x60 >> 4 = 6`. Version 6 ≠ 4, so `Err(ParseError::NotIpv4 { version: 6 })`. It's
an IPv6 packet; our IPv4 parser correctly refuses it rather than misreading it.

### J.3 — The IFF_NO_PI symptom

**Q.** You switch to `Iface::new` and now every packet logs `NotIpv4 { version: 0 }`, yet
`tcpdump -i tun0` shows pings arriving. Explain precisely and give two fixes.

**Solution.** `Iface::new` prepends the 4-byte `tun_pi` header `[flags(2) | proto(2)]`. So
`buf[0]` is a flags byte `0x00`, and `0x00 >> 4 = 0` → version 0 → `NotIpv4`. The packets are
fine; the offsets are shifted by 4. Fixes: (1) use `Iface::without_packet_info` (drops the
prefix); or (2) keep `new`, verify `u16::from_be_bytes([buf[2],buf[3]]) == 0x0800`, and parse
from `&buf[4..]`.

### J.4 — Endianness

**Q.** A Total Length field on the wire is `01 2c`. What value, and what's the wrong value if you
used `from_ne_bytes` on little-endian x86?

**Solution.** Correct: `u16::from_be_bytes([0x01, 0x2c]) = 0x012C = 300`. Wrong (ne on LE):
`0x2C01 = 11265`. The byte-swap silently corrupts the length.

### J.5 — IHL and payload offset

**Q.** A packet has `buf[0] = 0x46`. Where does the L4 payload start, and why does it matter?

**Solution.** IHL = `0x46 & 0x0f = 6` → header_len = 6×4 = 24 bytes (20 fixed + 4 bytes of IP
options). The payload starts at byte 24, not 20. If you hardcoded 20, you'd parse 4 bytes of IP
options as the first 4 bytes of the TCP/ICMP header — garbage. Hence `&packet[header_len..]`.

### J.6 — Bit extraction

**Q.** Given IP byte 6 = `0x60`, extract the 3 flag bits and state DF/MF.

**Solution.** Flags are the top 3 bits: `(0x60 >> 5) & 0x07`. `0x60 = 0110 0000`; `>>5 = 011`;
`& 0x07 = 0b011 = 3`. Bit layout reserved/DF/MF (high→low) = `0 1 1`? Careful: the 3 bits are
[reserved, DF, MF] = `0,1,1`? `0b011` means reserved=0, DF=1, MF=1. Wait — `0x60=0110 0000`, top
3 bits are `011`, i.e. reserved=0, DF=1, MF=1. Hmm: actually `0x40` is DF-only (`010`). `0x60`
(`011`) means **DF=1 and MF=1** — unusual (don't-fragment yet more-fragments) and would be
malformed in practice; `0x40` is the normal "DF set, last fragment." (Lesson: compute, don't
guess — and notice when a combination is nonsensical.)

### J.7 — Write byte 0

**Q.** Build IPv4 byte 0 for a standard no-options header.

**Solution.** version 4, IHL 5: `(4 << 4) | 5 = 0x40 | 0x05 = 0x45`. Writing is shift+OR;
reading was shift+mask. Inverse operations.

### J.8 — Decode an ICMP echo

**Q.** After the 20-byte IP header, the next bytes are `08 00 4d 5a 00 07 00 02`. What is it?

**Solution.** type 8 = Echo Request; code 0; checksum 0x4D5A; identifier 0x0007; sequence 0x0002.
A ping, id 7, second packet (seq 2).

### J.9 — Reject a short packet (code)

**Q.** Write the guard so a 12-byte buffer can't panic the parser, and the test.

**Solution.**
```rust
if packet.len() < 20 {
    return Err(ParseError::TooShort { have: packet.len(), need: 20 });
}
// test:
assert_eq!(parse(&[0u8; 12]), Err(ParseError::TooShort { have: 12, need: 20 }));
```
After this guard, `packet[0..20]` is provably in-bounds.

### J.10 — Add UDP decoding (code)

**Q.** Extend the dispatch to print UDP source/dest ports (protocol 17).

**Solution.**
```rust
17 => {
    if l4.len() >= 8 {
        let sport = u16::from_be_bytes([l4[0], l4[1]]);
        let dport = u16::from_be_bytes([l4[2], l4[3]]);
        let len   = u16::from_be_bytes([l4[4], l4[5]]);
        println!("         └── UDP {sport} → {dport}  len={len}");
    }
}
```
The UDP header is only 8 bytes: src port, dst port, length, checksum. Test with
`nc -u 192.168.0.2 53` or a DNS query through the interface.

### J.11 — Validate the incoming IP checksum (code)

**Q.** Make `parse` (or the loop) reject a packet whose IP header checksum is wrong.

**Solution.** After confirming `header_len`, run the checksum over the header and require 0:
```rust
if utils::checksum(&packet[..header_len]) != 0 {
    return Err(ParseError::BadChecksum);
}
```
(add `BadChecksum` to the enum). Recall the verify-trick: a valid header *including* its
checksum field sums to 0. Test: take a known-good header → expect Ok; flip one byte → expect
`BadChecksum`. (Needs the Doc-2 `utils::checksum`.)

### J.12 — Count protocols seen (code, design)

**Q.** Track how many ICMP/TCP/UDP packets you've seen and print a running tally.

**Solution.** A `HashMap<u8, u64>` or three counters incremented in the dispatch; print every N
packets. The point: per-connection/aggregate *state* is what turns a parser into a stack — a
warm-up for the TCP connection table (Doc 3).

### J.13 — Why does ping show 100% loss on Doc 1 but 0% on Doc 2?

**Solution.** Doc 1 only *parses*; it never calls `iface.send`, so no Echo Reply is produced —
`ping` waits and times out → 100% loss. Doc 2 builds an Echo Reply (type 0, swapped addresses,
recomputed checksums) and sends it → `ping` matches it by id/seq → 0% loss. The visible behavior
is identical to "a reply with a bad checksum," which is why Doc 2 tests the checksum offline.

### J.14 — The hardest one: hand-compute an IP header checksum

**Q.** For header `45 00 00 28 00 00 40 00 40 06 00 00 0a 00 00 01 0a 00 00 02` (checksum field
zeroed), compute the checksum.

**Solution.** Sum the ten 16-bit words:
```
4500 + 0028 + 0000 + 4000 + 4006 + 0000 + 0a00 + 0001 + 0a00 + 0002
```
Add step by step (hex): 4500+0028=4528; +4000=8528; +4006=C52E; +0A00=CF2E; +0001=CF2F;
+0A00=D92F; +0002=D931. (The 0000 words add nothing.) Sum = 0xD931, no carry above 16 bits, so
no fold needed. Checksum = `~0xD931 = 0x26CE`. Verify by re-summing with `26CE` in place:
`0xD931 + 0x26CE = 0xFFFF` → `~0xFFFF = 0`. ✓ (This is the Doc-2 algorithm done by hand.)

---

## K. Extended glossary and the RFC reading list

### K.1 — Extended glossary (Doc 1 scope, exhaustive)

- **ARPANET** — the 1969 packet-switched research network that evolved into the internet; origin
  of TCP/IP.
- **ACK (acknowledgement)** — confirmation that data was received; a TCP flag and a 32-bit field
  (Doc 3+).
- **bit** — a binary digit, 0 or 1; the atom of all data.
- **big-endian** — most-significant byte first; **network byte order**; all IP/TCP/UDP fields.
- **BPF (Berkeley Packet Filter)** — kernel bytecode for matching packets; powers tcpdump
  capture filters and modern eBPF.
- **byte / octet** — 8 bits; "octet" in networking because byte size was once machine-dependent.
- **CAP_NET_ADMIN** — Linux capability for network-interface/route administration; needed to
  create `tun0`.
- **CIDR** — Classless Inter-Domain Routing; the `a.b.c.d/n` notation; `n` = network-prefix bits.
- **checksum (Internet)** — RFC 1071 one's-complement 16-bit sum for error detection (Doc 2).
- **character device** — a file you read/write as a byte stream; `/dev/net/tun` is one.
- **datagram** — a self-contained packet (IP datagram, UDP datagram); routed independently.
- **DF (Don't Fragment)** — IP flag forbidding fragmentation; drives Path MTU Discovery.
- **DSCP / ECN** — the two halves of IPv4 byte 1: QoS class and congestion notification.
- **endianness** — byte-ordering convention for multi-byte values.
- **EtherType** — 2-byte protocol selector in Ethernet/TUN-PI; 0x0800 IPv4, 0x86DD IPv6, 0x0806 ARP.
- **fat pointer** — a pointer carrying extra data; a Rust slice is a (ptr, len) fat pointer.
- **fragmentation** — splitting an IP datagram to fit a link MTU; reassembled by the receiver.
- **fd (file descriptor)** — an integer handle the kernel maps to an open resource (our TUN fd).
- **header** — protocol metadata prefixed to a payload; we parse IP/ICMP/TCP headers.
- **hexadecimal** — base-16; one digit = one nibble = 4 bits; the lingua franca of packet dumps.
- **IHL** — Internet Header Length, in 32-bit words; ×4 = header bytes.
- **ICMP** — Internet Control Message Protocol (RFC 792); ping, traceroute, error reports.
- **Identifier (ICMP)** — field matching echo replies to the sending process.
- **IFF_NO_PI** — TUN flag disabling the 4-byte packet-information prefix.
- **ioctl** — the "I/O control" syscall for device-specific operations; `TUNSETIFF` creates a TUN.
- **ISN/ISS/IRS** — Initial Sequence Number (and send/recv variants); TCP (Doc 3).
- **little-endian** — least-significant byte first; x86/ARM internal order.
- **loopback** — 127.0.0.0/8; traffic to oneself.
- **MTU** — Maximum Transmission Unit; largest L3 packet a link carries unfragmented (1500 Ethernet).
- **mask (bit)** — an AND operand selecting which bits to keep.
- **nibble** — 4 bits; one hex digit; half a byte.
- **netfilter** — the Linux kernel hook framework behind iptables/nftables (firewall/NAT).
- **network byte order** — synonym for big-endian.
- **one's complement** — bit-inversion arithmetic with end-around carry; basis of the checksum.
- **Option (Rust)** — `Some(T)`/`None`; "value or nothing," replacing null.
- **panic** — Rust's unrecoverable error; out-of-bounds index panics (we guard against it).
- **payload** — the data a header wraps; the next layer up.
- **PMTUD (Path MTU Discovery)** — finding the smallest MTU on a path via DF + ICMP type 3 code 4.
- **port** — 16-bit transport endpoint identifier (TCP/UDP); not present in IP/ICMP.
- **protocol number** — IP byte 9; selects the L4 parser (1 ICMP, 6 TCP, 17 UDP).
- **pseudo-header** — IP fields fed into the TCP/UDP checksum (not ICMP); ties checksum to addresses.
- **Result (Rust)** — `Ok(T)`/`Err(E)`; success or described failure.
- **RFC** — Request For Comments; the internet's standards documents (IETF).
- **sk_buff** — the kernel's packet buffer struct carried through the network stack.
- **slice (`&[u8]`)** — a borrowed (ptr, len) view into bytes; zero-copy parsing.
- **setcap** — sets file capabilities on a binary; needs an xattr-capable filesystem.
- **TTL** — Time To Live; per-hop counter preventing routing loops; basis of traceroute.
- **two's complement** — signed-integer representation (invert + 1); CPU arithmetic.
- **TUN / TAP** — virtual L3 (IP) / L2 (Ethernet) interfaces backed by a userspace fd.
- **wrapping arithmetic** — modular `wrapping_add` etc.; defined overflow (TCP seq numbers wrap at 2³²).
- **zero-copy** — processing data in place via borrows instead of copying.

### K.2 — The RFC reading list (Doc 1 relevant, in reading order)

RFCs are the primary sources. Read the *introduction* and the *header-format* sections first;
the prose is dense but precise, and learning to read it is a skill in itself (look for the
ASCII header diagrams and the MUST/SHOULD/MAY keywords from RFC 2119).

| RFC | Title | Why for Doc 1 |
|-----|-------|---------------|
| 791 | Internet Protocol | the IPv4 header you parse — read §3.1 (header format) |
| 792 | Internet Control Message Protocol | ICMP echo + errors |
| 1071 | Computing the Internet Checksum | the Doc-2 algorithm, with worked examples |
| 1122 | Requirements for Internet Hosts — Communication Layers | what a host MUST do; the "host rules" |
| 2474 | Definition of the DiffServ Field (DSCP) | what IP byte 1 became |
| 3168 | The Addition of ECN to IP | the low 2 bits of byte 1 |
| 1191 | Path MTU Discovery | DF + ICMP frag-needed |
| 8200 | Internet Protocol, Version 6 (IPv6) | the contrast: no header checksum, no IHL, fixed 40-byte header |
| 2119 | Key words (MUST/SHOULD/MAY) | how to *read* every other RFC |
| 1180 | A TCP/IP Tutorial | a gentle narrative overview of the whole stack |

Supplementary (deeper): Stevens, *TCP/IP Illustrated, Vol. 1* (the canonical book; ch. 1–6 cover
links, IP, ICMP); Kurose & Ross, *Computer Networking: A Top-Down Approach* (ch. 4 network layer);
Beej's *Guide to Network Programming* (the sockets side you're reimplementing).

---

## L. Complete annotated hex dumps of every Doc-1 packet type

Memorizing these three dumps means you can read any Doc-1 packet instantly. Offsets are decimal
byte indices from the start of the IP packet (TUN, no PI prefix).

### L.1 — ICMP Echo Request (a ping), 98 bytes shown as 84 (IP) — the canonical Linux ping

```
off  bytes        field                     value / meaning
---  -----------  ------------------------  --------------------------------
IP HEADER (20 bytes)
 0   45           version|IHL               v4, 5 words = 20-byte header
 1   00           DSCP|ECN                  best effort
 2   00 54        total length              84 bytes (20 IP + 64 ICMP)
 4   ab cd        identification            0xABCD (fragment group id)
 6   40 00        flags|frag offset         DF set, offset 0
 8   40           TTL                       64 (Linux default)
 9   01           protocol                  1 = ICMP
10   e2 3f        header checksum           0xE23F
12   c0 a8 00 01  source IP                 192.168.0.1 (the pinger)
16   c0 a8 00 02  destination IP            192.168.0.2 (our stack)
ICMP MESSAGE (64 bytes)
20   08           type                      8 = Echo Request
21   00           code                      0
22   xx xx        checksum                  over the whole ICMP message
24   12 34        identifier                0x1234 (matches the process)
26   00 01        sequence                  1 (first ping)
28   .. (56 bytes)  data                    timestamp + filler, echoed back verbatim
```
Read it: "DF TCP-less ICMP echo, id 0x1234 seq 1, 192.168.0.1→.2, 64 hops left." Our parser
takes bytes 0/9/12-19 (IP) and 20-27 (ICMP); the reply flips byte 20 to 0x00 and fixes the two
checksums.

### L.2 — ICMP Echo Reply (our Doc-2 output) — what changed from L.1

```
 same 84 bytes as L.1, with these edits:
12   c0 a8 00 02  source IP                 192.168.0.2 (us)        ← swapped
16   c0 a8 00 01  destination IP            192.168.0.1 (pinger)    ← swapped
 8   40           TTL                       64                      ← reset by us
10   xx xx        IP header checksum        recomputed              ← changed (header changed)
20   00           ICMP type                 0 = Echo Reply          ← flipped from 8
22   xx xx        ICMP checksum             recomputed              ← changed (type changed)
24.. 12 34 00 01 + data                     id/seq/data unchanged   ← echoed verbatim
```
Four edits, two checksums — exactly `icmp::build_echo_reply`. The unchanged id/seq/data is what
lets the pinger match this reply to its request.

### L.3 — TCP SYN (what `nc` sends first), 60 bytes (20 IP + 40 TCP with options)

```
off  bytes        field                     value / meaning
---  -----------  ------------------------  --------------------------------
IP HEADER (20 bytes)
 0   45           version|IHL               v4, 20-byte IP header
 2   00 3c        total length              60 bytes
 6   40 00        flags                     DF
 8   40           TTL                       64
 9   06           protocol                  6 = TCP
12   c0 a8 00 01  source                    192.168.0.1
16   c0 a8 00 02  destination               192.168.0.2
TCP HEADER (40 bytes: 20 fixed + 20 options)
20   d4 31        source port               54321
22   1f 90        destination port          8080
24   00 00 00 64  sequence number           100 (client ISN)
28   00 00 00 00  acknowledgement           0 (none yet; ACK flag clear)
32   a0           data offset|reserved      0xA0 → 10 words = 40-byte TCP header
33   02           flags                     0x02 = SYN
34   ff ff        window                    65535
36   xx xx        checksum                  TCP checksum (pseudo-header + segment)
38   00 00        urgent pointer            0
40   02 04 05 b4 …  options                 MSS=1460, then SACK-permitted, window scale, …
```
Read it: "SYN from :54321 to :8080, ISN 100, advertising a 65535 window and a 1460 MSS." Our
`tcp::parse` reads the fixed 20 bytes (ports, seq, ack, data-offset→40, flags=SYN, window) and
uses `data_offset` to skip the 20 option bytes when locating any payload. The handshake response
(`accept`) builds a 40-byte (20+20, no options) SYN-ACK: seq=ISS(0), ack=101, flags 0x12.

### L.4 — The three dumps side by side (what to look for)

- **First byte** is always `0x45` (IPv4, no options) for *our generated* packets; inbound ones
  may differ (e.g. `0x45` for ping, IHL>5 only with IP options).
- **Byte 9** (protocol) is your first fork: `01` ICMP, `06` TCP, `11`(hex) = 17 UDP.
- **Bytes 12–19** are always the address pair; swapping them is the essence of a reply.
- For TCP, **byte 33** (the flag byte) is the at-a-glance state: `02`=SYN, `12`=SYN-ACK,
  `10`=ACK, `18`=PSH-ACK (data), `11`=FIN-ACK, `04`=RST.

---

## M. A short history of IP and the layered model

Knowing where these designs came from makes the field choices feel inevitable rather than
arbitrary. This is the context that turns "the RFC says so" into "of course it does."

### M.1 — From circuits to packets

Before the internet, networks were **circuit-switched** like the telephone system: a dedicated
end-to-end path was reserved for a conversation. This wastes capacity (the path sits idle during
pauses) and is fragile (one cut link kills the call). In the 1960s, Paul Baran (RAND) and Donald
Davies (NPL) independently proposed **packet switching**: chop data into small, independently-
addressed packets that each find their own way through a mesh, to be reassembled at the
destination. It is robust (route around failures) and efficient (links are shared statistically).
The U.S. **ARPANET** (1969) was the first large packet-switched network; its early host protocol
(NCP) handled both addressing and reliability in one layer.

### M.2 — The birth of TCP/IP

NCP couldn't connect *different* networks. In 1974 Vint Cerf and Bob Kahn published "A Protocol
for Packet Network Intercommunication," introducing TCP — and crucially the idea of a network of
networks (an *inter*net) glued by gateways. Originally TCP did everything. The pivotal design
move (c. 1978) was the **split**: pull the simple, connectionless delivery job into **IP** (just
get a packet from A to B, best effort), and leave reliability, ordering, and flow control to
**TCP** on top. This separation — dumb network, smart endpoints — is the **end-to-end principle**
(Saltzer, Reed, Clark, 1984) and is *the* reason the internet scaled: the core stays simple and
fast; intelligence lives at the edges where it can evolve. On **1 January 1983** ("flag day")
ARPANET switched from NCP to TCP/IP — the protocol you are reimplementing.

### M.3 — Why layering

A protocol *stack* is layered so each layer solves one problem and offers a clean service to the
layer above, hiding the layer below:

- **Link (L2)** — move a frame across one physical hop (Ethernet, Wi-Fi). Local addressing (MAC).
- **Network (L3, IP)** — move a packet across *many* hops, globally addressed, best effort.
- **Transport (L4, TCP/UDP)** — endpoint-to-endpoint service: ports (which app), and for TCP
  reliability/ordering/flow/congestion.
- **Application (L7)** — HTTP, DNS, SSH: what the bytes *mean*.

Each layer **encapsulates** the one above: your HTTP bytes get a TCP header, then an IP header,
then an Ethernet header, like nested envelopes; each hop peels and re-wraps as needed. We operate
at L3/L4 on a TUN device, so we skip L2 entirely — which is exactly why our first byte is the IP
header, not a MAC address.

### M.4 — OSI vs TCP/IP

You'll hear about the **OSI 7-layer model** (Physical, Data Link, Network, Transport, Session,
Presentation, Application). It was a committee-designed *reference* model (ISO, early 1980s) and
is useful vocabulary, but the internet runs the leaner **TCP/IP model** (Link, Internet,
Transport, Application — 4 layers) that shipped working code first. The famous quip: "OSI was the
model everyone studied; TCP/IP was the one everyone deployed." The OSI session/presentation layers
have no clean TCP/IP equivalent — their concerns live inside applications (e.g. TLS sits awkwardly
"between" L4 and L7). When someone says "layer 3" they mean IP; "layer 4," TCP/UDP; "layer 7," the
app — that numbering is OSI's, applied loosely to the TCP/IP stack.

### M.5 — How an RFC becomes a standard

The internet has no king; it has **rough consensus and running code** (David Clark's phrase). The
**IETF** (Internet Engineering Task Force) develops protocols in open working groups; proposals
circulate as **Internet-Drafts**, and when mature are published as **RFCs** by the RFC Editor.
Not all RFCs are standards: they range over Standards Track (Proposed Standard → Internet
Standard), Informational, Experimental, Best Current Practice, and Historic. RFC 791 (IP) and 793
(TCP, now obsoleted by **RFC 9293**) are core standards. RFC 2119 defines the capitalized
**MUST/SHOULD/MAY** keywords that give RFC prose its precise force. Reading RFCs is a skill: start
with the abstract and the header-format section, watch for the keywords, and note which RFCs
**obsolete** or **update** which (793 → 9293 is why we cite 9293).

### M.6 — Why IPv6 exists (and what it changed)

IPv4's 32-bit addresses give ~4.3 billion addresses — exhausted in the 2010s, papered over by NAT.
**IPv6** (RFC 8200) uses **128-bit** addresses (3.4×10³⁸) and *simplified the header*: it dropped
the IPv4 header checksum (L2 and L4 already check integrity — saves every router work), removed
in-router fragmentation (endpoints do PMTUD), and uses a fixed 40-byte header with extension
headers instead of variable options/IHL. So the very fields you're learning in IPv4 — checksum,
IHL, fragmentation — are precisely the ones IPv6 *removed* as design mistakes or router burdens.
Learning IPv4 first makes those reversals legible.

---

## N. Comparison to real stacks — Linux, BSD, lwIP, smoltcp

Our stack is a teaching toy. Seeing how it differs from production code tells you what "the rest
of the iceberg" is, and which real codebases to read next.

### N.1 — The Linux kernel stack (`net/ipv4/`, `net/core/`)

The reference production stack. Differences from ours, in kind:
- **In-kernel, zero-copy, interrupt-driven.** Packets live in `sk_buff`s; NAPI batches receive
  interrupts; offloads (checksum, segmentation: GRO/GSO/TSO) push work to the NIC.
- **A real socket API** (`socket/bind/listen/accept/connect/read/write`) with per-socket buffers,
  backlog queues, and `epoll` readiness.
- **Full TCP**: every state, retransmission with RTO estimation (RFC 6298), SACK, fast
  retransmit/recovery, multiple congestion controllers (CUBIC default, BBR), window scaling,
  timestamps, PAWS, SYN cookies, TIME_WAIT recycling.
- **Routing, netfilter, namespaces, qdiscs.** An entire control plane we don't have.
It's enormous (hundreds of thousands of lines) and battle-hardened against decades of adversarial
traffic. We implement maybe the 1% that teaches the concepts.

### N.2 — The BSD stack (the ancestor)

The 4.2/4.4BSD TCP/IP stack (early–mid 1980s) is the *original* widely-deployed implementation;
macOS, iOS, and much networking gear descend from it, and the **sockets API** itself is "BSD
sockets." Stevens' *TCP/IP Illustrated Vol. 2* annotates this code line by line — the canonical
text if you want to read a real, complete, yet comprehensible stack. Many algorithm names
(Nagle, Karn, Van Jacobson's congestion control) entered the world here.

### N.3 — lwIP (lightweight IP)

A small, complete TCP/IP stack for **embedded** systems (kilobytes of RAM), widely used in
microcontrollers and bootloaders. It's the sweet spot between "toy" and "Linux": full TCP, but
written to be read and to run without an OS. If you want to see how a *complete but minimal* stack
is structured (memory pools, a raw/callback API plus a sockets shim), lwIP's source is approachable
and directly comparable to where this project is heading.

### N.4 — smoltcp (the Rust one)

`smoltcp` is a standalone, `no_std`, heapless TCP/IP stack **in Rust** — essentially the
production-grade version of what we're building, used in Redox OS and embedded Rust. Reading it is
the natural "graduation" from this project: same language, same TUN-style device abstraction
(`phy::Device`), but with real TCP (congestion control, retransmission, windowing), IPv6, DHCP,
and a polished socket API — all without a heap. It will show you idiomatic Rust answers to every
"later step" in our roadmap, and how to do them without `Vec`/allocation.

### N.5 — What we deliberately don't do (the honest gap)

| Capability | Us | Real stacks |
|---|---|---|
| I/O model | one blocking `recv` loop | non-blocking + epoll/io_uring, multi-queue |
| Buffers | a stack array / per-packet `Vec` | pools, ring buffers, zero-copy `sk_buff` |
| TCP reliability | none yet | retransmission, RTO, SACK, fast recovery |
| Congestion control | none | CUBIC/BBR/Reno |
| Flow control | fixed window | dynamic, buffer-driven windows + scaling |
| Reassembly | in-order only | full out-of-order reassembly |
| Security | minimal | SYN cookies, ISN randomization, RST/seq validation, rate limits |
| API | a `match` in `main` | `listen/accept/read/write` sockets |
| Offload | none | NIC checksum/segmentation offload |
| Address families | IPv4 only | IPv4 + IPv6 + dual stack |

This table is also a study plan: each row is a thing you can add to *this* stack (the roadmap in
doc5-book.md §10) and then go read how `smoltcp`/lwIP/Linux do it properly.

### N.6 — Why build a toy at all

Because reading Linux's stack cold teaches you almost nothing — there's too much. Building the
1% yourself, byte by byte, gives you the mental model that makes the other 99% *readable*. After
this project, `smoltcp` and the relevant Linux files stop being walls of code and become "oh, this
is the retransmission queue I didn't build, and here's the seq-validation I simplified." That
transfer — from your toy to real systems — is the entire point.

---

## O. Line-by-line walkthrough — `utils.rs` and `ip.rs`

This section reads the foundational files one construct at a time, so you can account for every
character. (`icmp.rs`, `main.rs`, and `tcp.rs` get the same treatment in their doc-books.)

### O.1 — `utils.rs`, line by line

```rust
pub fn checksum(data: &[u8]) -> u16 {
```
- `pub` — visible to other modules (`ip`, `icmp`, `tcp` all call it). Without `pub` it'd be
  private to `utils`.
- `fn checksum` — a free function (not a method; no `self`).
- `data: &[u8]` — borrows a byte slice; reads it, doesn't own or modify it. Works on any
  contiguous bytes (an IP header, an ICMP message, a TCP pseudo-header+segment).
- `-> u16` — returns the 16-bit checksum. Unsigned, because a checksum is a bit pattern, not a
  signed quantity.

```rust
    let mut sum: u32 = 0;
```
- `let mut` — a mutable binding (we add into it in the loop). Default bindings are immutable in
  Rust; `mut` is required to reassign.
- `: u32` — **32 bits on purpose.** We add many 16-bit words; the running total must hold the
  overflow (carries) above bit 15 until we fold them. A `u16` here would silently drop carries.

```rust
    let mut chunks = data.chunks_exact(2);
    for w in chunks.by_ref() {
        sum += u16::from_be_bytes([w[0], w[1]]) as u32;
    }
```
- `chunks_exact(2)` — an iterator over non-overlapping 2-byte windows; it yields only *full*
  pairs and stashes any leftover odd byte in `.remainder()`.
- `chunks.by_ref()` — iterate **without consuming** `chunks`, so we can call `.remainder()`
  afterward. (A plain `for w in chunks` would move it and we couldn't ask for the remainder.)
- `w` is a `&[u8]` of length exactly 2. `from_be_bytes([w[0], w[1]])` reads it big-endian into a
  `u16`; `as u32` widens it so the `+=` accumulates without overflow.

```rust
    if let [last] = chunks.remainder() {
        sum += (*last as u32) << 8;
    }
```
- `chunks.remainder()` is a slice of length 0 or 1. `if let [last] = ...` is a **slice pattern**
  that matches *only* the length-1 case, binding `last: &u8`.
- `*last` dereferences to the `u8`; `as u32` widens; `<< 8` puts it in the **high** byte of a
  16-bit word (the odd byte is the most-significant half, padded with a zero low byte) — exactly
  RFC 1071's rule.

```rust
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
```
- The **end-around carry** fold. `sum >> 16` is everything above the low 16 bits (the
  accumulated carries); `sum & 0xffff` is the low 16. Adding them folds carries back in.
- It's a `while`, not an `if`, because the fold itself can produce a new carry (rare but
  possible), so we repeat until the high half is zero.

```rust
    !(sum as u16)
}
```
- `sum as u16` truncates to the folded low 16 bits (now guaranteed to fit).
- `!` is bitwise NOT — the **one's complement**, the final step. No trailing semicolon, so this
  expression is the function's return value (Rust's implicit return).

The test module then asserts it against the known `0xB861` vector, the verify-to-zero property,
and the odd-length path — see §J.14 for the hand computation that mirrors this code.

### O.2 — `ip.rs`, line by line

```rust
use std::net::Ipv4Addr;
use crate::utils;
```
- `Ipv4Addr` — the standard library's IPv4 address type; gives us `Display` ("192.168.0.1"),
  equality, and `.octets()`.
- `crate::utils` — reach the sibling module; `crate::` is the crate root path. This is how `ip`
  calls `utils::checksum`.

```rust
#[derive(Debug, PartialEq, Eq)]
pub struct Ipv4Header {
    pub version: u8,
    pub header_len: usize,
    ...
}
```
- `#[derive(...)]` auto-generates `Debug` (for `{:?}` and test output) and `PartialEq/Eq` (so
  tests `assert_eq!` whole headers). Pure convenience; zero runtime cost.
- All fields `pub` so `main`/`icmp` can read them. `header_len: usize` is in **bytes** (already
  multiplied by 4) — a deliberate API choice so callers never re-multiply. `usize` because it's
  used as an index/length.

```rust
#[derive(Debug, PartialEq, Eq)]
pub enum ParseError {
    TooShort { have: usize, need: usize },
    NotIpv4 { version: u8 },
    HeaderLongerThanPacket { header_len: usize, have: usize },
}
```
- A **sum type**: a parse failure is exactly one of these, each carrying the data you'd want in a
  log/test. Naming the cause (vs a bare `None`) is what makes a misbehaving packet diagnosable.

```rust
pub fn parse(packet: &[u8]) -> Result<Ipv4Header, ParseError> {
    if packet.len() < 20 {
        return Err(ParseError::TooShort { have: packet.len(), need: 20 });
    }
```
- Guard 1. After this `return`, every index in `0..20` is provably valid, so no later panic.
  `return Err(...)` is an early exit; `?` isn't used because we're *constructing* the error here.

```rust
    let version = packet[0] >> 4;
    if version != 4 {
        return Err(ParseError::NotIpv4 { version });
    }
```
- High nibble of byte 0. The check both enforces correctness and is the canary for the
  `IFF_NO_PI` bug (version reads 0). `ParseError::NotIpv4 { version }` uses field-init shorthand
  (the field is named `version` and so is the local).

```rust
    let ihl = (packet[0] & 0x0f) as usize;
    let header_len = ihl * 4;
    if packet.len() < header_len {
        return Err(ParseError::HeaderLongerThanPacket { header_len, have: packet.len() });
    }
```
- Low nibble × 4 = header bytes. Guard 2 ensures the declared header actually fits the data we
  hold, so slicing `&packet[header_len..]` later is safe even with IP options.

```rust
    let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    let ttl = packet[8];
    let protocol = packet[9];
    let src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    Ok(Ipv4Header { version, header_len, total_len, ttl, protocol, src, dst })
}
```
- `from_be_bytes` for the 16-bit total length (big-endian wire order). Single bytes (`ttl`,
  `protocol`) need no endianness. `Ipv4Addr::new` takes the four octets in order. The final
  `Ok(Ipv4Header { ... })` uses field shorthand throughout and is the success return.

```rust
pub fn write_header_checksum(header: &mut [u8]) {
    header[10] = 0;
    header[11] = 0;
    let c = utils::checksum(header);
    let [hi, lo] = c.to_be_bytes();
    header[10] = hi;
    header[11] = lo;
}
```
- `&mut [u8]` — an **exclusive** borrow, because we write into it. Caller passes exactly the
  header slice (`&mut pkt[..20]`).
- Zero the checksum field *first* (the algorithm requires the field be 0 during computation),
  compute over the whole header, then write the result back **big-endian** via `to_be_bytes()`
  destructured into `[hi, lo]`. This is the build-side mirror of the verify in `checksum`.

The `#[cfg(test)]` block exercises `parse` (fields, both rejections, the etherparse oracle) and
`write_header_checksum` (round-trips to a verifying-zero header).

---

## P. Debugging war stories — the ten bugs you will hit, and how to find each

Each entry: the **symptom** you actually observe, the **cause**, the **diagnosis** technique,
and the **fix**. These are the failures this project produces in practice.

### P.1 — Stack prints nothing; tcpdump shows the pings

- **Symptom:** you ping, `tcpdump -i tun0` clearly shows ICMP echo requests, but your program
  logs nothing (or `NotIpv4 { version: 0 }`).
- **Cause:** `Iface::new` instead of `without_packet_info` → the 4-byte PI header shifts every
  offset; version reads 0.
- **Diagnosis:** print the first 8 raw bytes of `buf`. If you see `00 00 08 00 45 00 ...`, the PI
  header is present (`08 00` is the EtherType). The IP packet starts at byte 4, not 0.
- **Fix:** `Iface::without_packet_info(...)`, or parse from `&buf[4..]` after checking EtherType.

### P.2 — `setcap: Operation not supported`

- **Symptom:** `sudo setcap cap_net_admin=eip target/debug/tcp-stack` fails.
- **Cause:** the binary lives on `/mnt/c` (DrvFs), which has no Linux extended attributes.
- **Diagnosis:** `df -T` the binary's path; if the type is `9p`/`drvfs`, that's it. `getcap` shows
  nothing was set.
- **Fix:** build to native fs (`CARGO_TARGET_DIR=$HOME/...` or the project's `.cargo/config.toml`)
  and `setcap` the native-fs binary. Or run with `sudo`.

### P.3 — `Error: PermissionDenied` on every run

- **Symptom:** the program errors immediately at `Iface::without_packet_info`.
- **Cause:** missing `CAP_NET_ADMIN` — you forgot `setcap`, or rebuilt (which makes a new inode
  with no caps).
- **Diagnosis:** `getcap <binary>` — empty means no caps. Remember: **every** `cargo build`
  wipes the cap.
- **Fix:** re-run `setcap` after each build (or wrap build+setcap in one shell line), or `sudo`.

### P.4 — `ResourceBusy` creating tun0

- **Symptom:** `Error: Os { code: 16, ... ResourceBusy }`.
- **Cause:** a `tun0` already exists (a previous run that was persistent, or a crashed instance).
- **Diagnosis:** `ip link show tun0` shows it lingering.
- **Fix:** `sudo ip link delete tun0`, then rerun.

### P.5 — Multi-byte fields are wildly wrong

- **Symptom:** total length reads 21504 instead of 84; ports/seq look byte-swapped.
- **Cause:** `from_ne_bytes` (or manual `a | b<<8` in the wrong order) instead of `from_be_bytes`.
- **Diagnosis:** byte-swap the wrong value in your head — `0x5400` vs `0x0054` — and it matches.
- **Fix:** `from_be_bytes` for every multi-byte wire read; `to_be_bytes` for every write.

### P.6 — L4 fields garbage only on some packets

- **Symptom:** TCP/ICMP parse fine usually, but occasionally the ports/type are nonsense.
- **Cause:** hardcoded payload offset 20 instead of `ihl * 4`; the bad packets carry IP options
  (IHL > 5).
- **Diagnosis:** print `header_len`; the broken ones show 24/28/… not 20.
- **Fix:** slice the payload at `&packet[header_len..]`.

### P.7 — Index-out-of-bounds panic (crash) on a short packet

- **Symptom:** thread panics: `index out of bounds: the len is 12 but the index is 19`.
- **Cause:** you indexed before checking length; a runt/crafted packet is shorter than the header.
- **Diagnosis:** the panic message gives the exact index and length.
- **Fix:** the up-front length guards (`< 20`, `< header_len`); after them, indices are safe.

### P.8 — ping stays at 100% loss after you "added" the reply (Doc 2)

- **Symptom:** you build and send an Echo Reply, but `ping` still reports loss; tcpdump shows the
  reply going out.
- **Cause:** a **bad checksum** — IP header or ICMP — so the kernel/peer drops your reply. Usual
  culprits: forgot to zero the checksum field before computing; checksummed the wrong byte range
  (IP = header only; ICMP = whole message); wrote the result little-endian.
- **Diagnosis:** Wireshark flags the bad checksum in red; or compute `checksum(reply_header)` and
  `checksum(reply_icmp)` — a valid one is 0.
- **Fix:** zero the field, checksum the correct range, write `to_be_bytes`. (Our
  `reply_is_well_formed` test asserts both regions verify to 0.)

### P.9 — handshake never completes (Doc 3)

- **Symptom:** SYN-ACK goes out, but the connection never reaches ESTABLISHED; client retransmits
  SYN or RSTs.
- **Cause:** wrong ack number in the SYN-ACK (must be `client_seq + 1`), or bad TCP checksum
  (forgot the pseudo-header), or wrong data-offset nibble.
- **Diagnosis:** tcpdump with `-S` (absolute seq); compare your SYN-ACK's seq/ack to the spec.
  Wireshark checksum flag for the pseudo-header mistake.
- **Fix:** `ack = recv.nxt = client_seq + 1`; checksum over pseudo-header + segment; data offset
  `5 << 4`.

### P.10 — echo works once, then stalls (Doc 4)

- **Symptom:** the first data segment echoes, later ones are ignored.
- **Cause:** sequence-number bookkeeping drift — not advancing `RCV.NXT`/`SND.NXT` by the payload
  length, so the next in-order check (`seg.seq == RCV.NXT`) fails.
- **Diagnosis:** log `RCV.NXT`, `SND.NXT`, and each segment's seq/ack; the mismatch is visible.
- **Fix:** `RCV.NXT += payload.len()` on accept; `SND.NXT += payload.len()` after sending.

### P.11 — bonus: a junk file named `{,+` appears

- **Symptom:** a zero-byte file with a brace/comma name shows up in the repo.
- **Cause:** an unquoted brace expansion hit a shell redirect (e.g. `> something{,+`).
- **Fix/diagnosis:** `rm './{,+'` (quote it!); always quote globs/paths in shell commands.

### P.12 — the meta-lesson

Every bug above is found the same way: **compare three views** — your `println!`, tcpdump's
decode, and (for generated packets) Wireshark's checksum flag — and the divergence localizes it.
A network bug is almost never mysterious once you look at the actual bytes. Build the habit of
looking before theorizing.

---

## Q. From-absolute-scratch reconstruction — build Doc 1 from an empty directory

If you can do this from a blank folder without copying, you own Doc 1. Commands assume WSL Ubuntu.

### Q.1 — Toolchain

```bash
# Rust (if not present in WSL)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
rustc --version            # confirm

# Network tools for testing
sudo apt update && sudo apt install -y iproute2 tcpdump netcat-openbsd iputils-ping
ls -l /dev/net/tun         # must exist; else: sudo modprobe tun
```

### Q.2 — Project skeleton

```bash
mkdir tcp-stack && cd tcp-stack
cargo init --name tcp-stack          # creates Cargo.toml + src/main.rs + git
```

Edit `Cargo.toml` to add the dependencies:
```toml
[dependencies]
tun-tap = "0.1"
etherparse = "0.14"
```

Create `.cargo/config.toml` so builds land on native fs (only matters when source is on /mnt/c):
```toml
[build]
target-dir = "/home/<you>/.tcp-stack-target"
```

### Q.3 — Write the code

From memory (the blank-file checklist in Volume I §14 and O.1/O.2):
1. `src/main.rs`: open `Iface::without_packet_info("tun0", Mode::Tun)?`; loop `recv` → parse →
   print → dispatch.
2. Factor the parser into `parse(&[u8]) -> Result<Ipv4Header, ParseError>` with the two guards,
   the version/IHL nibbles, `from_be_bytes` fields, and `Ipv4Addr` addresses.
3. Add the `#[cfg(test)]` module with the ping-packet fixture and the field/rejection/etherparse
   tests.

### Q.4 — Verify offline first

```bash
cargo test           # parser proven without any network setup
cargo build
```

### Q.5 — Run it live

```bash
sudo setcap cap_net_admin=eip "$(echo $HOME)/.tcp-stack-target/debug/tcp-stack"  # or use sudo
"$HOME/.tcp-stack-target/debug/tcp-stack"     # terminal 1 — blocks, waiting
```
```bash
# terminal 2
sudo ip addr add 192.168.0.1/24 dev tun0 && sudo ip link set tun0 up
ping -c3 192.168.0.2          # Doc 1: 100% loss is correct
sudo tcpdump -i tun0 -n -v    # terminal 3: see the requests
```

### Q.6 — Self-check

You succeeded if: `cargo test` is green; running prints decoded `IPv4 ... proto=1 (ICMP)` lines on
ping; and you can explain, without notes, why ping shows 100% loss and what each printed field
means. If any step needed a peek, that step is your weak spot — drill it and make an Anki card.

---

## R. The mathematics of the Internet checksum

This is the "why it works" behind Doc 2's code. None of it is needed to *use* the checksum, but
understanding it is the difference between memorizing an algorithm and owning it.

### R.1 — One's-complement integers as a number system

Work in 16-bit one's-complement. The representable values are the bit patterns `0x0000`…`0xFFFF`,
but the *interpretation* is: `0x0000`…`0x7FFF` are 0…32767, and `0x8000`…`0xFFFF` are
−32767…−0. Note there are **two zeros**: `0x0000` (+0) and `0xFFFF` (−0). This twin-zero is the
quirk that makes the checksum's verify-trick land on `0xFFFF` and complement to `0x0000`.

### R.2 — End-around carry = addition modulo (2¹⁶ − 1)

Ordinary 16-bit addition is modulo 2¹⁶ (carries off the top are lost). One's-complement addition
*adds the carry back in* (end-around carry). The effect: one's-complement addition is arithmetic
**modulo 2¹⁶ − 1 = 65535**. Why: a carry out of bit 15 has weight 2¹⁶; adding it back at bit 0
(weight 2⁰ = 1) changes its contribution from 2¹⁶ to 1, i.e. subtracts (2¹⁶ − 1). Subtracting the
modulus is exactly what "mod 65535" does. So:

```
ones_complement_sum(a, b) = (a + b) mod 65535     (with 0 represented as 65535/0xFFFF, not 0)
```

### R.3 — Why that makes it associative and commutative

Addition modulo a fixed number is associative and commutative (it inherits these from ordinary
integer addition, which the modulus preserves). Therefore the order in which you sum the 16-bit
words **does not matter**, and you may sum in any grouping. This is what licenses optimizations:
summing 32 or 64 bits at a time and folding at the end gives the same result as the naive
word-by-word loop. Our code sums word-by-word for clarity; high-performance stacks sum wide and
fold once — provably identical because of associativity.

### R.4 — Why it is endianness-independent (the elegant part)

Claim: computing the checksum with the bytes swapped (little-endian view) yields the byte-swapped
checksum — so two machines of opposite endianness agree on the *stored* value after the natural
byte order is applied. Sketch: swapping the two bytes of every 16-bit word is a fixed permutation
that commutes with the mod-(2¹⁶−1) sum (because 2⁸ ≡ a fixed factor and the carry wraps), so the
sum of swapped words equals the swap of the sum of words. Practical upshot (RFC 1071 §2 states it
plainly): you can run the checksum loop in host byte order without per-word swapping and only fix
the byte order of the final 16-bit result — a real speedup that's *correct* only because of this
property. We keep it simple and read big-endian throughout, but now you know why the fast path is
legitimate.

### R.5 — The verify-to-zero theorem

Let S be the one's-complement sum of all data words *excluding* the checksum field, and let the
stored checksum be C = ~S (one's complement). The sum over *all* words including C is
S + C = S + ~S. In one's complement, x + ~x = `0xFFFF` (all ones, i.e. −0). The checksum function
returns ~(that) = ~`0xFFFF` = `0x0000`. Hence **a valid message checksums to 0** — the basis of
`valid_header_verifies_to_zero` and of incoming-packet validation (exercise J.11). Conversely, if
any bit flipped in transit, S changes, S + C ≠ `0xFFFF`, and the result is nonzero → detected.

### R.6 — What it can and cannot catch

- **Catches:** any single-bit error; most burst errors; any error that changes the mod-65535 sum.
- **Misses:** errors that cancel — e.g. add 1 to one word and subtract 1 from another, or swap two
  whole 16-bit words (reordering words doesn't change the sum, by commutativity!). This is why it's
  a *weak* checksum: ~1 in 65536 random corruptions slips through, and **word reordering is
  invisible** to it. Link-layer CRCs (stronger, catch all burst errors up to their length) and L4
  checks layer on top. The Internet checksum is chosen for *speed and simplicity*, not strength —
  a deliberate end-to-end-principle trade (cheap end-to-end sanity check; let stronger checks live
  where they're worth it).

### R.7 — Incremental update (why routers don't re-sum)

A router that only decrements TTL changes one field. Re-summing the whole header would be wasteful,
so RFC 1624 gives an **incremental update**: `new_checksum = ~(~old_checksum + ~old_field +
new_field)` (in one's-complement arithmetic). Because the sum is associative and the change is
local, you can patch the checksum in O(1) instead of O(header). We don't need this (we rebuild
whole packets), but it's why high-traffic routers can forward at line rate, and it's a neat
corollary of §R.3.

---

## S. Performance notes — what this loop costs, and where real stacks spend time

We optimize for clarity, not speed, but knowing the costs tells you what you'd change for
throughput and why production stacks look the way they do.

### S.1 — The cost of our receive loop, per packet

1. **One syscall** (`read`) — a user↔kernel transition, the dominant fixed cost (hundreds of ns).
2. **One copy** — the kernel copies the packet into our `buf`. (Real high-speed paths avoid this
   with zero-copy/mmap rings.)
3. **Parsing** — a handful of byte reads and `from_be_bytes`; effectively free next to the syscall.
4. **For replies:** a `Vec` allocation in `build_*` (heap), field writes, a checksum pass
   (O(packet length)), and a second syscall (`write`) + copy.

So our per-packet cost is dominated by **two syscalls and two copies** for a reply. That's fine for
a ping or an `nc` session (thousands/sec trivially); it's nowhere near what a NIC at 10–100 Gbps
needs.

### S.2 — Where the time goes at scale (and the fixes real stacks use)

- **Syscall overhead** → batching (`recvmmsg`/`sendmmsg`, io_uring) amortizes transitions over
  many packets; `epoll` avoids blocking per fd.
- **Copies** → zero-copy via `mmap`'d ring buffers (AF_PACKET v3, AF_XDP) or kernel-bypass (DPDK).
- **Per-packet allocation** → never allocate in the hot path; use pre-allocated pools/ring buffers
  (our per-reply `Vec` is exactly what you'd eliminate first).
- **Checksums** → offload to the NIC entirely (the OS sets "checksum offload" flags and the
  hardware fills them in); when in software, sum 32/64 bits at a time (legit per §R.3).
- **Segmentation** → GSO/TSO let the stack hand the NIC one big buffer and have hardware chop it
  into MTU-sized segments, cutting per-packet work.
- **Interrupts** → NAPI switches from one-interrupt-per-packet to polling under load.
- **Cores** → multi-queue NICs + RSS spread flows across CPUs; our single blocking loop uses one
  core.

### S.3 — Our deliberate non-optimizations (and when they'd matter)

| We do | Cheap alternative we skipped | When it matters |
|---|---|---|
| stack `[u8; 1504]` reused | (already optimal) | — |
| `Vec` per outgoing packet | a reusable scratch buffer | high reply rates |
| blocking `read` | non-blocking + `epoll` | many connections + timers (required for retransmission) |
| word-by-word checksum | 32/64-bit summation | multi-Gbps software checksumming |
| copy on recv | mmap ring | line-rate capture |

None of these change correctness; all trade simplicity for throughput. The single change that's
not just performance but *capability* is blocking→event-loop, because retransmission timers need
it — which is why it heads the doc5-book.md §10 roadmap.

### S.4 — Big-O of the data structures

- IPv4/ICMP/TCP parse: **O(1)** (fixed offsets).
- Checksum: **O(n)** in packet length (unavoidable; one pass).
- Connection lookup (Doc 3+): **O(1)** average via `HashMap<Quad, _>`.
- Echo/reply build: **O(payload)** for the copy + checksum.
Nothing in the design is worse than linear in the packet size, which is the floor — you must at
least look at each byte you checksum.

---

## T. Extended FAQ — forty questions a careful reader asks

**1. Why a TUN device instead of a real NIC?** A TUN gives us real L3 packets to/from userspace
with zero hardware and full isolation from the host's networking — perfect for *being* an endpoint
without a driver.

**2. Why L3 (TUN) and not L2 (TAP)?** TAP would force us to implement Ethernet framing and ARP
before any IP. TUN lets us start at IP, which is the layer we're here to learn.

**3. Why does `buf[0]` start at `0x45` and not the Ethernet header?** Because TUN is L3 — there is
no Ethernet header. The first byte is the IP version/IHL.

**4. What exactly are the 4 bytes `Iface::new` prepends?** A `tun_pi` struct: 2 bytes of flags +
2 bytes EtherType (0x0800 = IPv4). `without_packet_info` (IFF_NO_PI) suppresses it.

**5. Why 1504 and not 1500 for the buffer?** MTU 1500 + slack (the 4 PI bytes you might receive).
Bigger-than-needed is harmless; too small truncates.

**6. Why does `recv` block?** `read()` on the fd sleeps the thread until a packet arrives — 0% CPU
while waiting. The apparent "hang" at startup is correct.

**7. Why is ping 100% loss on Doc 1?** We receive but never send an Echo Reply. Doc 2 fixes it.

**8. Why must I re-run `setcap` after every build?** A new binary is a new inode; file
capabilities live in the inode's xattrs and don't carry over.

**9. Why does `setcap` fail on /mnt/c?** DrvFs has no Linux extended attributes to store the
capability. Build to native ext4.

**10. What does `cap_net_admin=eip` mean?** Grant CAP_NET_ADMIN in the effective, inheritable, and
permitted capability sets.

**11. Why `from_be_bytes` and not `from_ne_bytes`?** Wire data is big-endian; `ne` is native
(little-endian on x86/ARM) and silently byte-swaps your values.

**12. Does endianness matter for single bytes (TTL, protocol)?** No — a single byte has no
ordering. Only multi-byte fields need conversion.

**13. Why is the payload not always at byte 20?** IP options make the header longer (IHL > 5).
Use `ihl * 4`.

**14. What's the difference between IHL and Total Length?** IHL = header length (in 4-byte words);
Total Length = whole datagram (header + payload) in bytes.

**15. Why does indexing a slice panic instead of returning an error?** Rust chooses safety: an
out-of-range index is a bug, and panicking is safer than a silent over-read. We guard lengths
up front so it never triggers.

**16. Why `Result` for IP parse but `Option` for ICMP parse?** IP parse fails for several
distinct reasons worth naming; ICMP parse fails for exactly one ("too short"). Match the type to
the failure shape.

**17. What is a slice, really?** A borrowed `(pointer, length)` view into bytes you already have —
no copy, bounds-checked on access.

**18. Why copy fields into a struct instead of zero-copy?** Simplicity for now. A zero-copy
borrowed header needs a lifetime; we trade a few bytes of copy for less complexity (Volume I §9).

**19. What's the `?` operator?** Propagate errors: on `Err`, return it from the function; on `Ok`,
unwrap. Requires a compatible return type (`io::Result` in `main`).

**20. Why `&'static str` for `protocol_name`?** The labels are compile-time constants baked in the
binary — no allocation, valid forever.

**21. Why is `etherparse` a dependency if we parse by hand?** It's our oracle — we cross-check our
hand parser against it to catch bugs (differential testing).

**22. What is the Internet checksum protecting?** Accidental bit corruption in transit. It is not
cryptographic — it stops errors, not attackers.

**23. Why one's complement and not a CRC?** Speed and simplicity, and endian-independence; CRCs
(stronger) live at the link layer. An end-to-end-principle trade.

**24. Why does the checksum field get zeroed before computing?** So the field doesn't contribute to
the sum of itself; you compute, then store. Verifying re-includes it and expects 0.

**25. Why does a valid header checksum to 0?** Because the stored value is the complement of the
rest; sum-of-all = all-ones, complemented = 0 (§R.5).

**26. Can the checksum miss errors?** Yes — canceling errors and whole-word reorderings are
invisible (§R.6). It's intentionally weak/fast.

**27. What's the difference between ICMP and TCP/UDP?** ICMP is a network-layer control/diagnostic
protocol (no ports); TCP/UDP are transports (ports, and for TCP reliability).

**28. Why does ICMP have no pseudo-header in its checksum, but TCP does?** TCP's checksum binds to
the IP addresses (to detect misdelivery); ICMP's covers just the ICMP message.

**29. What are ICMP id and seq for?** id matches replies to the sending process; seq increments per
ping for loss/RTT accounting.

**30. How does traceroute work?** Send packets with TTL 1,2,3…; each hop's router replies ICMP
Time Exceeded, revealing its address.

**31. Why is TTL 64 common?** It's the Linux/macOS default initial value; Windows uses 128. Enough
to cross the internet (rarely > ~30 hops).

**32. What's the relationship to IPv6?** IPv6 removed the header checksum, IHL, and in-router
fragmentation — the exact IPv4 features you're learning, as design corrections.

**33. Why learn IPv4 first if IPv6 is "better"?** IPv4's "mistakes" are pedagogically rich, it's
still dominant in practice, and the concepts transfer.

**34. Can I run two pings at once and tell them apart?** Yes — the ICMP id differs per process;
that's its job.

**35. Why does `cargo test` not need sudo or a TUN device?** Tests call the pure parsing/checksum
functions on byte fixtures; they never open the interface.

**36. Where do the build artifacts go and why?** To `~/.tcp-stack-target` (native fs) so `setcap`
works and builds are fast — set in `.cargo/config.toml`.

**37. What happens if two packets arrive while I'm processing one?** The kernel queues them on the
TUN device; the next `recv` returns the next packet. We can fall behind under load (no batching).

**38. Why is there a `.gitignore` ignoring `target/` and `Cargo.lock`?** Build output and (for this
binary, the author's choice) the lockfile aren't tracked. The native target dir is outside the repo
anyway.

**39. Could a malicious packet crash my stack?** Only if you index without guarding — which is the
whole reason for the up-front length checks. A short/garbage packet must be rejected, not panic.

**40. What's the single most important habit from Doc 1?** Compare three views (your output,
tcpdump, the hex) before theorizing. The bytes never lie.

---

## U. This project and the security track — every parser is an attack surface

You're building toward offensive/defensive security research; a packet parser is exactly where
those worlds meet. This section maps Doc-1 concepts to the security mindset.

### U.1 — A parser is a trust boundary

Every byte you parse came from someone else, possibly hostile. The discipline of *guard the
length, then index* is not pedantry — it's the difference between a robust stack and a remotely
crashable one. **Heartbleed** (CVE-2014-0160) was precisely a missing length check in a TLS
heartbeat parser: it echoed back `length` bytes without verifying `length` against the actual
payload, leaking adjacent memory (private keys included). Our `ParseError::TooShort` guard is the
same class of check that would have prevented it. Internalize: *the parser is the front line.*

### U.2 — Classic IP/ICMP-layer attacks (and how our choices relate)

- **Ping of Death** — an oversized/overlapping fragmented ICMP that overflowed reassembly buffers.
  Defense: validate lengths and fragment offsets (we don't reassemble yet, but the length
  discipline is the seed).
- **Smurf attack** — spoof the victim's address as the source of broadcast ICMP echo; every host
  replies to the victim (amplification). Defense: don't reply to broadcast echo; rate-limit replies
  (a hardened `build_echo_reply` would).
- **ICMP tunneling / covert channels** — arbitrary data in echo payloads to exfiltrate past
  firewalls. Relevant to both red (build it) and blue (detect anomalous echo sizes/rates).
- **IP spoofing** — forging the source address. IP has no authentication; this is why TCP's
  random ISN (Doc 3) and sequence checks matter, and why ingress filtering (BCP 38) exists.
- **TTL games** — low TTL to map networks (traceroute), or to evade IDS that reassemble differently
  than the target (insertion/evasion attacks, Ptacek & Newsham 1998). Parsing TTL is step one.

### U.3 — The fuzzing connection

Your tests feed *known* packets; a **fuzzer** feeds *random/mutated* packets to find inputs that
panic, hang, or misbehave. A parser like ours is the ideal fuzz target: `cargo fuzz` (libFuzzer)
or AFL can throw millions of malformed packets at `ip::parse`/`tcp::parse` and flag any panic. A
production-quality version of this project would have a fuzz harness; the up-front guards are what
make it *pass* the fuzzer. This is a direct bridge to your security track — exercise: write a
`cargo fuzz` target for `ip::parse` and confirm it never panics.

### U.4 — Defensive parsing principles (a checklist you'll reuse everywhere)

1. **Never trust a length field** — validate it against the actual buffer before using it.
2. **Bounds-check before indexing** — once, up front; then reason about safety.
3. **Reject, don't assume** — unknown version/protocol/short buffer → error, not best-effort guess.
4. **No panics on input** — a panic on attacker data is a denial of service.
5. **Validate cross-field invariants** — e.g. `total_len ≥ header_len`; checksum verifies.
6. **Fail closed** — when unsure, drop the packet; don't forward/act on ambiguous data.
These six are how a parser earns the right to be on a network.

### U.5 — Red vs blue, both rooted here

- **Red (offense):** crafting packets (exactly what `build_echo_reply`/`build_packet` do) is how
  you build scanners, spoofers, and exploit PoCs. Knowing the header bit-by-bit is the prerequisite.
- **Blue (defense):** an IDS/IPS *parses* the same headers to detect anomalies (Snort/Suricata are,
  at heart, very fast packet parsers + rule engines). Your parsing skill is their core skill.
The TCP stack you're building is the substrate both sides operate on; this project is the
foundation of the whole security curriculum, not a detour from it.

---

## V. The annotated project — `Cargo.toml`, `.gitignore`, and layout

A stack is more than `main.rs`; the surrounding files encode real decisions.

### V.1 — `Cargo.toml`, line by line

```toml
[package]
name = "tcp-stack"
version = "0.1.0"
edition = "2021"
```
- `[package]` — crate metadata. `edition = "2021"` selects the language edition (affects closure
  captures, the prelude, etc.); editions let Rust evolve without breaking old code.

```toml
[dependencies]
tun-tap = "0.1"
etherparse = "0.14"
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
rand = "0.8"
```
- `tun-tap = "0.1"` — the TUN wrapper. `"0.1"` is a caret requirement meaning `>=0.1.0, <0.2.0`
  (SemVer-compatible updates allowed).
- `etherparse = "0.14"` — our parsing oracle.
- `tracing` / `tracing-subscriber` — structured logging (better than `println!` for real use);
  `features = ["env-filter"]` enables `RUST_LOG`-style filtering. We mostly use `println!` for
  teaching clarity, but the deps are present for when you switch.
- `rand = "0.8"` — for ISN randomization (the secure version of Doc 3's ISS); use `OsRng`, not
  `thread_rng`, for anything security-relevant.

```toml
[profile.release]
opt-level = 3
debug = true
```
- Release builds at max optimization (`opt-level = 3`) but **keep debug symbols** (`debug = true`)
  so you can profile/gdb an optimized binary — useful for a stack you'll benchmark later.

### V.2 — `.cargo/config.toml`

```toml
[build]
target-dir = "/home/<you>/.tcp-stack-target"
```
Redirects build output to native ext4 so (1) `setcap` works (xattrs) and (2) builds are fast (not
on the 9p `/mnt/c` mount). Machine-specific absolute path; fine because this project only ever
builds inside this one WSL instance. Without it, plain `cargo build` would litter `/mnt/c/.../target`
and `setcap` would fail.

### V.3 — `.gitignore` highlights

- `/target/` and `Cargo.lock` — build output and (author's choice for this binary) the lockfile.
- `*.pcap`, `*.log`, `*.cast` — capture/log artifacts you'll generate while testing.
- `flamegraph.svg`, `perf.data*` — profiling output (for the performance work in §S).
- `.env`, `*.key`, `*.pem` — never commit secrets (a habit, even in a toy).
A junk file like `{,+` is *not* matched by these patterns — which is why the real fix is shell
hygiene (quote globs), not a gitignore rule.

### V.4 — The source layout and the module graph

```
src/
  main.rs    — the recv/dispatch/send loop; declares `mod utils; mod ip; mod icmp; mod tcp;`
  utils.rs   — checksum (used by ip, icmp, tcp)
  ip.rs      — IPv4 parse + header checksum
  icmp.rs    — ICMP parse + echo reply       (uses ip, utils)
  tcp.rs     — TCP parse + connection state   (uses ip, utils)
  ethernet.rs, arp.rs — placeholders (TAP-only path; not `mod`-declared)
docs/
  doc1.md                 — the original doc-1 walkthrough
  doc1-book.md … doc29-book.md — these teaching books (compiled into BOOK.md)
  setup-windows.md, setup-kali.md — environment setup guides
```
Dependency direction is strictly upward: `utils` depends on nothing; `ip` on `utils`; `icmp`/`tcp`
on `ip`+`utils`; `main` on all. No cycles — a clean layering that mirrors the protocol stack
itself.

---

## W. Anki starter deck — Doc 1 (drawn from this chapter)

Per your Learning OS, make cards from *your own* slips first; this deck seeds the rest. Format is
Q → A. Keep cards atomic.

```
Q: First byte of an IPv4 packet, 0x45 — decode both nibbles.
A: version 4 (high nibble), IHL 5 → 20-byte header (low nibble × 4).

Q: Which Rust call reads a big-endian u16 from packet bytes?
A: u16::from_be_bytes([a, b]). (Never from_ne_bytes for wire data.)

Q: Where does the L4 payload start in an IP packet?
A: At byte (IHL × 4) = header_len — NOT always 20 (options make it longer).

Q: What are the 4 extra bytes from Iface::new, and how do you remove them?
A: A tun_pi header (2B flags + 2B EtherType). Remove via without_packet_info (IFF_NO_PI).

Q: Why does setcap fail on /mnt/c?
A: DrvFs/9p has no Linux extended attributes to store the capability. Build to native ext4.

Q: IP protocol numbers for ICMP / TCP / UDP?
A: 1 / 6 / 17.

Q: How do you extract a width-w field at bit offset s from a byte?
A: (value >> s) & ((1 << w) - 1).

Q: Internet checksum — the three steps.
A: Sum 16-bit BE words into a u32; fold carries (end-around); bitwise NOT the low 16.

Q: How do you VERIFY an Internet checksum?
A: Run the same sum over the data INCLUDING the checksum field; a valid message → 0.

Q: Why does SYN (and FIN) consume a sequence number?
A: By spec each occupies one position in the sequence space, so it's acknowledged with seq+1.

Q: What does a cumulative TCP ACK number mean?
A: "I have everything up to but not including N; send N next." (ack = receiver's RCV.NXT)

Q: ICMP echo: which type is request, which is reply?
A: 8 = Echo Request (ping), 0 = Echo Reply (pong).

Q: TTL reaching 0 — what happens, and what tool exploits it?
A: Router drops the packet and sends ICMP Time Exceeded (type 11); traceroute exploits it.

Q: Big-endian vs little-endian for 0x05DC?
A: Big-endian (network): 05 DC. Little-endian (x86/ARM): DC 05.

Q: Why Result for ip::parse but Option for icmp::parse?
A: IP parse has several distinct failure causes worth naming; ICMP parse has one ("too short").

Q: One security reason to bounds-check before indexing a packet?
A: Avoid a panic/over-read on hostile input (the Heartbleed class of bug).

Q: TCP checksum covers what beyond the segment?
A: A 12-byte pseudo-header (src/dst IP, proto=6, TCP length) — ties it to the addresses.

Q: Why is ping 100% loss on Doc 1 but 0% on Doc 2?
A: Doc 1 only parses (no reply sent); Doc 2 builds+sends the Echo Reply.

Q: Data offset nibble for a 20-byte TCP header, as a byte value?
A: 5 words → 5 << 4 = 0x50.

Q: The one architectural change that unblocks retransmission?
A: Move from a blocking recv loop to non-blocking I/O + an epoll event loop (for timers).
```

Add ~10 more from whatever *you* got wrong while reading — those stick best.

---

## X. Closing synthesis — the one-page mental model of Doc 1

If you forget everything else, keep this:

> A network stack is **a program that reads a byte buffer, interprets it as nested protocol
> headers, and writes a byte buffer back.** A **TUN** device makes that possible from userspace:
> the kernel routes IP packets to `tun0`, and `read(fd)` hands them to us; `write(fd)` injects our
> replies. Doc 1 is the *read + interpret* half.

The interpret step, in one breath: the first byte's nibbles give **version** and **IHL**; multi-
byte fields are **big-endian** (`from_be_bytes`); the **protocol** byte says how to read the
payload, which starts at **IHL × 4**; you **guard lengths before indexing** so hostile input can't
crash you. **ICMP** is the control plane (ping = type 8 → 0). The **Internet checksum**
(one's-complement sum, Doc 2) is how integrity is checked, and a valid header sums to 0.

The discipline, in one line: **guard, then parse; convert endianness explicitly; verify against an
oracle and tcpdump; never panic on input.**

Everything in docs 2–5 (checksums, the handshake, data, teardown) is the *write* half and the
addition of *state* — but it all rests on this: bytes in, bytes out, with the headers understood.

You now have the complete Doc-1 picture, narrative (Volume I) and reference (Volume II). Re-type
the code with the books closed; you own it when you can.

---

## Y. Extended packet gallery — ten real packets, fully decoded

Cover the right column, decode from the hex, then check. By packet ten this is automatic.

### Y.1 — ICMP echo request (ping)
`45 00 00 54 00 00 40 00 40 01 b8 6a c0 a8 00 01 c0 a8 00 02 | 08 00 ...`
→ v4 IHL5; len 84; DF; TTL 64; **proto 1 ICMP**; 192.168.0.1→192.168.0.2; ICMP **type 8** (request).

### Y.2 — ICMP echo reply (pong)
`45 00 00 54 00 00 40 00 40 01 b8 6a c0 a8 00 02 c0 a8 00 01 | 00 00 ...`
→ same but addresses **swapped** and ICMP **type 0** (reply). This is what our Doc-2 code emits.

### Y.3 — ICMP destination port unreachable
`45 00 00 38 ... 40 01 .. .. <router> <you> | 03 03 ...`
→ proto 1 ICMP; **type 3 code 3** = Port Unreachable; the body carries the offending IP header + 8
bytes (so you can see which UDP port had nothing listening).

### Y.4 — ICMP time exceeded (a traceroute hop)
`45 00 00 38 ... 40 01 .. .. <hop-router-IP> <you> | 0b 00 ...`
→ proto 1 ICMP; **type 11 code 0** = TTL exceeded; source = the router that dropped your TTL-limited
probe. Traceroute prints that source as a hop.

### Y.5 — TCP SYN
`45 00 00 3c ... 40 06 .. .. <client> <server> | <sp> <dp> <seq> 00000000 a0 02 ffff ...`
→ proto **6 TCP**; TCP flags byte `0x02` = **SYN**; ack 0; data offset `0xA0`→40-byte header (options:
MSS/SACK/wscale). Connection start.

### Y.6 — TCP SYN-ACK (our Doc-3 reply)
`45 00 00 28 ... 40 06 .. .. <server> <client> | <dp> <sp> <ISS=0> <ack=clientseq+1> 50 12 0400 ...`
→ flags `0x12` = **SYN+ACK**; data offset `0x50`→20-byte header (no options); window 0x0400=1024.

### Y.7 — TCP ACK (handshake completion)
`... 40 06 ... | ... 50 10 ...` → flags `0x10` = **ACK** only; len 0; completes the three-way
handshake → ESTABLISHED.

### Y.8 — TCP data segment (PSH-ACK)
`... 40 06 ... | ... 50 18 ... "hi"` → flags `0x18` = **PSH+ACK**; payload `68 69` = "hi". Our echo
server sends the same flags back.

### Y.9 — TCP FIN-ACK (teardown)
`... 40 06 ... | ... 50 11 ...` → flags `0x11` = **FIN+ACK**; begins connection close. FIN consumes
a sequence number.

### Y.10 — TCP RST
`... 40 06 ... | ... 50 04 ...` → flags `0x04` = **RST**; an abrupt abort (e.g. connecting to a
closed port on a host that *does* run TCP). We don't emit these yet (a roadmap item).

### Y.11 — The flag-byte cheat (memorize)
`02`=SYN · `12`=SYN-ACK · `10`=ACK · `18`=PSH-ACK(data) · `11`=FIN-ACK · `04`=RST · `14`=RST-ACK.
The byte is `URG ACK PSH RST SYN FIN` from bit 5→0; read any handshake at a glance from this byte.

### Y.12 — A UDP datagram (for contrast)
`45 00 00 27 ... 40 11 .. .. <client> <server> | <sp> <dp> 0013 <csum> ...`
→ proto `0x11`=**17 UDP**; the 8-byte UDP header is just sport/dport/length(0x0013=19)/checksum —
no seq, no ack, no state. The simplicity contrast that makes TCP's machinery legible.

---

## Z. Cross-reference index — concept → RFC, code, and doc-book

A lookup table tying every Doc-1 concept to its authoritative source, where it lives in the code,
and the chapter that develops it.

| Concept | RFC / source | Code location | Developed in |
|---|---|---|---|
| IPv4 header format | RFC 791 §3.1 | `ip::parse` | doc1 V1 §5, V2 §E |
| Version / IHL nibbles | RFC 791 | `ip::parse` (byte 0) | doc1 §5.5, §C.8, §O.2 |
| Total length | RFC 791 | `ip::Ipv4Header.total_len` | doc1 §E.5 |
| Fragmentation (flags/offset) | RFC 791, 1191 | (parsed, not used) | doc1 §E.7–E.8 |
| TTL | RFC 791, 1122 | `ip::Ipv4Header.ttl` | doc1 §E.9, §H.5 |
| Protocol numbers | IANA registry | dispatch `match` | doc1 §E.10 |
| IP header checksum | RFC 791, 1071 | `ip::write_header_checksum`, `utils::checksum` | doc1 §E.11, doc2, doc1 §R |
| Addresses / CIDR | RFC 791, 4632 | `Ipv4Addr` fields | doc1 §E.12 |
| Endianness | RFC 1700 (assigned numbers), Cohen 1980 | `from_be_bytes` everywhere | doc1 §D, §7 |
| Internet checksum algorithm | RFC 1071, 1624 | `utils::checksum` | doc2, doc1 §R |
| ICMP message format | RFC 792 | `icmp::parse` | doc1 §10, §H.2 |
| Echo request/reply | RFC 792 | `icmp::build_echo_reply` | doc2, doc1 §H.3 |
| Dest Unreachable / Time Exceeded | RFC 792 | (recognized) | doc1 §H.4–H.5 |
| TUN device | Linux `tuntap.txt` | `Iface::without_packet_info` | doc1 §2, §F |
| IFF_NO_PI / PI header | Linux tun driver | `without_packet_info` | doc1 §3, §F.6 |
| CAP_NET_ADMIN / setcap | `capabilities(7)` | run instructions | doc1 §2, §F.7 |
| Bounds-checking / safety | (Rust) | length guards in `parse` | doc1 §9, §G.6, §U |
| Result/Option/enums | (Rust) | `ParseError`, `parse` | doc1 §9, §G.7–G.9 |
| Slices / zero-copy | (Rust) | `&packet[..]` | doc1 §9, §G.5 |
| Differential testing | (testing practice) | `agrees_with_etherparse` | doc1 §11, §I |
| TCP header / handshake | RFC 9293 | `tcp::parse`, `Connection::accept` | doc3 |
| TCP checksum + pseudo-header | RFC 9293 §3.1 | `tcp::tcp_checksum` | doc3 §8 |
| Sequence numbers | RFC 9293 §3.3 | `SendSequence`/`RecvSequence` | doc3 §3–4 |
| Data transfer / ACK | RFC 9293 | `Connection::on_packet` | doc4 |
| Teardown / FIN / states | RFC 9293 §3.5–3.6 | `State`, `on_packet` | doc5 |
| Retransmission / RTO | RFC 6298 | (roadmap) | doc5 §10 |
| Congestion control | RFC 5681, 8312, 9438 | (roadmap) | doc5 §10 |

---

## AA. Addressing and routing — how a packet ends up at `tun0`

You typed `ip addr add 192.168.0.1/24 dev tun0` and pings started arriving. This section explains
every part of that, so the "magic" of packets reaching your code becomes mechanism.

### AA.1 — What an IPv4 address is

A 32-bit number, written as four dotted octets for humans: `192.168.0.1` = `0xC0A80001` =
`11000000 10101000 00000000 00000001`. The dots are purely notation; on the wire it's four bytes.
An address identifies an *interface*, not a host (a host with three NICs has three addresses).

### AA.2 — Subnets and the prefix (`/24`)

An address splits into a **network part** and a **host part**. The split point is the **prefix
length**: `/24` means the top 24 bits are the network, the low 8 are the host. So `192.168.0.1/24`
says "I'm host `.1` on the network `192.168.0.0/24`," which spans `192.168.0.0`–`192.168.0.255`
(2⁸ = 256 addresses; `.0` is the network address, `.255` the broadcast, leaving 254 usable). The
**netmask** form of `/24` is `255.255.255.0` (24 ones then 8 zeros). To test "are A and B on the
same subnet?" you AND each with the mask and compare the network parts — pure bit-masking, the §C
skill applied to addresses.

### AA.3 — CIDR, the modern notation

**CIDR** (Classless Inter-Domain Routing, RFC 4632) replaced the old rigid Class A/B/C scheme with
arbitrary prefix lengths. `/8`, `/16`, `/24`, `/30` are just different split points. A `/30` has 4
addresses (2 usable) — common for point-to-point links. CIDR lets routing aggregate many networks
under one prefix (a `/16` covers 256 `/24`s), which is what keeps the global routing table from
exploding. Worth memorizing: `/24` = 256 addrs, `/16` = 65536, `/8` = 16.7M, `/30` = 4, `/32` = a
single host.

### AA.4 — The routing table

The kernel decides where to send each outbound packet by consulting the **routing table** — a list
of (destination prefix → next hop / interface) rules. `ip route` shows it. When you added the
address, the kernel auto-created a **connected route**:

```
192.168.0.0/24 dev tun0 proto kernel scope link src 192.168.0.1
```

Read it: "any destination in 192.168.0.0/24 is directly reachable on `tun0`; use source
192.168.0.1." The kernel matches a destination against all routes and picks the **longest prefix
match** (most specific wins): a `/32` host route beats a `/24` beats the `/0` default route.

### AA.5 — How `ping 192.168.0.2` finds `tun0`

Step by step:
1. `ping` asks the kernel to send an ICMP Echo to `192.168.0.2`.
2. The kernel looks up `192.168.0.2` in the routing table → longest match is the connected route
   `192.168.0.0/24 dev tun0`.
3. So the packet's outgoing interface is `tun0`, source `192.168.0.1`.
4. "Transmitting on tun0" means: hand the bytes to whoever holds the `/dev/net/tun` fd — **us**.
5. We `recv` it. (No ARP step, because TUN is L3 point-to-point — there's no MAC to resolve.)

That is the entire path from a `ping` command to your `iface.recv()`. The address+route you
configured is what makes `192.168.0.2` "belong" to your program.

### AA.6 — The default route and gateways (context)

For destinations *not* on a local subnet, the routing table has a **default route** (`0.0.0.0/0
via <gateway>`): "anything I don't have a specific route for, send to the gateway (router)." The
gateway repeats the process with its own table. This hop-by-hop, longest-prefix forwarding is how a
packet crosses the internet — each router only needs to know "the next hop toward that prefix," not
the whole path (the end-to-end principle again: dumb-ish core, no per-flow state in routers).

### AA.7 — NAT (why your `192.168.x` can reach the internet)

`192.168.0.0/16`, `10.0.0.0/8`, `172.16.0.0/12` are **private** (RFC 1918) — not routable on the
public internet. **NAT** (Network Address Translation) lets many private hosts share one public
address: the home router rewrites the source address (and port — that's **PAT/NAPT**) of outgoing
packets to its public IP, remembers the mapping, and rewrites replies back. It's the reason IPv4
survived address exhaustion, and the reason "every device needs a unique public IP" became false.
Our lab is pure private/point-to-point, so no NAT — but knowing it explains why home addresses look
like ours and why inbound connections need port forwarding.

### AA.8 — ARP's absence (and where it would appear)

On a normal Ethernet LAN, before sending to `192.168.0.2` the kernel must learn its **MAC address**
via **ARP** ("who has 192.168.0.2? tell me your MAC"). On our **TUN** (L3) link there are no MACs,
so ARP never happens — another simplification TUN buys us. If you switched to **TAP** (L2), your
very first task would be answering ARP requests for `192.168.0.2` with a fake MAC, *before* any IP
traffic could flow. That's why `arp.rs`/`ethernet.rs` exist as placeholders.

---

## AB. The BSD sockets API — what we're reimplementing, call by call

When an app uses the network, it calls the **sockets API** — the interface to the kernel's TCP/IP
stack. We are building the *other side* of that interface. Knowing the calls shows you exactly which
of our pieces corresponds to which app-visible operation, and what a "real" API on top of our stack
would expose.

### AB.1 — `socket()`

`socket(AF_INET, SOCK_STREAM, 0)` creates an endpoint: address family `AF_INET` (IPv4),
`SOCK_STREAM` (TCP) or `SOCK_DGRAM` (UDP). Returns a file descriptor. In our world, "a socket" maps
to an entry we'd keep in a table; for TCP it's the per-connection TCB (`Connection`). We don't have
the call yet — `main` is the implicit socket layer.

### AB.2 — `bind()`

`bind(fd, addr, port)` claims a local address/port. A server binds to e.g. `0.0.0.0:8080`. In our
stack, "bound port 8080" is the `local` port we accept SYNs for. We currently accept on *any* port
(no real `bind`); a listening-socket abstraction (doc3 exercise E3) is where `bind` would live.

### AB.3 — `listen()`

`listen(fd, backlog)` marks a TCP socket **passive** — willing to accept incoming connections —
and sizes the queue of completed-but-not-yet-`accept`ed connections (the backlog). This maps to our
implicit LISTEN state: a SYN to a "listening" quad triggers `Connection::accept`. The backlog is
where SYN-flood defenses (SYN cookies) live.

### AB.4 — `accept()`

`accept(fd)` blocks until a connection completes the handshake, then returns a *new* fd for that
connection (the listening fd keeps listening). In our terms, `accept` would pop a connection that
reached ESTABLISHED from a ready queue. Our `Connection::accept` is named for this but currently
does the SYN-ACK directly; a real `accept()` is the app *retrieving* an established connection.

### AB.5 — `connect()` (active open)

`connect(fd, addr, port)` initiates an outgoing connection: the client side of the handshake (send
SYN, await SYN-ACK, send ACK). We implement only the **passive** (server) side so far; `connect`
would be the active-open path (send the first SYN, drive SYN_SENT → ESTABLISHED). It's a roadmap
item.

### AB.6 — `read()` / `recv()`

`read(fd, buf, len)` returns received, in-order, acknowledged bytes from the connection's receive
buffer (blocking until some arrive). This is the app consuming what our `on_packet` accepted and
advanced `RCV.NXT` over. A real API would buffer received data and hand it out here; our echo server
short-circuits by sending data straight back instead of delivering it to an "app."

### AB.7 — `write()` / `send()`

`write(fd, buf, len)` queues bytes to send; the stack segments them, assigns sequence numbers,
transmits, and retransmits until acknowledged. Our `build_packet` + `SND.NXT` bookkeeping is the
core of this; the missing parts (a send buffer, retransmission) are exactly the reliability roadmap.

### AB.8 — `close()` / `shutdown()`

`close(fd)` initiates teardown (send FIN, walk the closing states) and releases the socket;
`shutdown(fd, how)` can half-close one direction. Our Doc-5 FIN handling is the *passive* close
(responding to the peer's `close()`); an app-initiated `close()` (active close, with TIME_WAIT) is
the counterpart we noted as future work.

### AB.9 — `setsockopt()` / `getsockopt()`

Tune a socket: `TCP_NODELAY` (disable Nagle), `SO_REUSEADDR`, buffer sizes, etc. These map to the
knobs a mature version of our stack would expose (Nagle, window sizes). We hardcode the equivalents.

### AB.10 — The mapping, summarized

| Sockets call | App meaning | Our stack |
|---|---|---|
| `socket` | make an endpoint | (implicit; TCB is per-connection) |
| `bind` | claim local addr/port | the `local` side of a `Quad` |
| `listen` | be passive | implicit LISTEN (accept SYNs) |
| `accept` | get an established conn | retrieve a SYN_RCVD→ESTABLISHED `Connection` |
| `connect` | active open | roadmap (SYN_SENT path) |
| `read` | consume rx bytes | data accepted in `on_packet` |
| `write` | queue tx bytes | `build_packet` + `SND.NXT` |
| `close` | teardown | Doc-5 FIN handling (passive) |

Building a real `listen/accept/read/write` layer on top of our packet engine is the capstone that
turns this from "a stack that echoes" into "a stack apps can use." It's the final roadmap item.

---

## AC. Bibliography and where to go next

The curated sources behind this book, grouped by purpose. Start with the bold ones.

### AC.1 — Books
- **W. Richard Stevens, *TCP/IP Illustrated, Volume 1: The Protocols*** — the canonical reference;
  read ch. 1 (intro/layering), 3 (IP), 6 (ICMP) for Doc 1. Vol. 2 annotates the BSD source line by
  line (the "real stack" reading).
- **Kurose & Ross, *Computer Networking: A Top-Down Approach*** — the best textbook; ch. 4
  (network layer) maps onto everything here. Top-down (apps→wire) complements our bottom-up build.
- Tanenbaum & Wetherall, *Computer Networks* — broad, systems-flavored.
- Beej's *Guide to Network Programming* (free online) — the sockets side (§AB) you're reimplementing.
- Comer, *Internetworking with TCP/IP* — classic, protocol-focused.

### AC.2 — Primary standards (the RFCs from §K.2)
RFC 791 (IP), 792 (ICMP), 1071 (checksum, with worked examples), 1122 (host requirements), 9293
(TCP, current), 2119 (MUST/SHOULD/MAY), 1180 (TCP/IP tutorial), 8200 (IPv6 contrast). Read header-
format sections first; learn to skim for the keywords.

### AC.3 — Rust
- *The Rust Programming Language* ("the book," free) — ch. 4 (ownership), 8 (collections), 9 (error
  handling), 10 (traits/lifetimes) cover everything in §G.
- *Rust for Rustaceans* (Gjengset) — intermediate; the same author's "Implementing TCP in Rust"
  video series builds essentially this project live (great companion).
- `smoltcp` source — the production Rust TCP/IP stack; your graduation reading (§N.4).

### AC.4 — Tools
- `tcpdump` man page; `man 7 pcap-filter` for BPF syntax.
- Wireshark User's Guide; the display-filter reference.
- `man 7 capabilities`, `man 8 setcap`, Linux `Documentation/networking/tuntap.rst`.

### AC.5 — Going deeper on the security track (§U)
- Ptacek & Newsham, "Insertion, Evasion, and Denial of Service" (1998) — IDS evasion via TTL/frag.
- The Heartbleed write-ups (CVE-2014-0160) — the canonical parser-length-bug case study.
- `cargo fuzz` / libFuzzer docs — to fuzz your parsers.
- Snort/Suricata docs — production packet parsers + rule engines (the blue-team mirror of this).

### AC.6 — The natural next projects (from MASTER_PLAN)
After finishing this stack: `smoltcp` source-read; then the curriculum's `Distributed_Raft_KV`
(consensus over a network you now understand) or the security track's `ML_Network_IDS` (parse +
classify the very packets you can now build). Each reuses this foundation.

---

## AD. Self-test exam — fifty questions (no answers)

If you can answer all fifty cold, you own Doc 1 (and previews of 2–5). No peeking; check yourself
against the code, the RFCs, and earlier sections.

1. Decode `0x45` into its two fields.
2. Why is the first byte `0x45` and not a MAC address on our interface?
3. What are the 4 bytes `Iface::new` adds, and which constructor removes them?
4. Convert `0xC0A80002` to dotted decimal.
5. Convert `172.16.5.4` to hex.
6. What is `1011_0110` in decimal and hex?
7. Extract the version from byte 0 with a bit expression.
8. Extract IHL and convert it to a byte count.
9. Why multiply IHL by 4?
10. Where does the L4 payload start, in general?
11. Why is `from_ne_bytes` wrong for wire data?
12. Big-endian bytes for the value 1500?
13. What does Total Length include that IHL doesn't?
14. Which IP byte selects the L4 protocol, and the values for ICMP/TCP/UDP?
15. What does TTL do, and what sends a message when it hits 0?
16. How does traceroute use TTL?
17. State the three steps of the Internet checksum.
18. How do you verify a checksum without recomputing the expected value?
19. Why is `sum` a `u32` in the checksum, not `u16`?
20. What is end-around carry, and why does it make the sum mod 65535?
21. Two error types the Internet checksum cannot detect.
22. Why does ICMP's checksum have no pseudo-header but TCP's does?
23. ICMP types for echo request and reply.
24. What are the ICMP id and sequence fields for?
25. Which ICMP type/code drives Path MTU Discovery?
26. Why does Doc-1 ping show 100% loss?
27. List the four edits that turn an Echo Request into an Echo Reply.
28. Why does the data payload echo back "for free"?
29. Why must `setcap` target a binary on native fs, not /mnt/c?
30. What does `cap_net_admin=eip` grant?
31. Why must you re-run `setcap` after every build?
32. Why does `recv` block, and is that a bug?
33. What is a slice, in terms of its representation?
34. Why guard length before indexing, in security terms?
35. When do you choose `Result` over `Option`?
36. What does the `?` operator do?
37. What does `mod ip;` actually cause the compiler to do?
38. Why is `etherparse` a dependency if we parse by hand?
39. What does the connected route `192.168.0.0/24 dev tun0` mean?
40. How does `ping 192.168.0.2` end up at our `recv`?
41. Why is there no ARP on our TUN link?
42. What is longest-prefix match?
43. Why do private addresses need NAT to reach the internet?
44. Which sockets call corresponds to our `Connection::accept`?
45. Which sockets call would the active-open (client) path implement?
46. Why does SYN consume a sequence number?
47. What does a cumulative ACK number mean?
48. What is the TCP pseudo-header, and why include the IP addresses?
49. Why does FIN, like SYN, consume a sequence number?
50. Name the single architectural change that unblocks retransmission, and why.

---

## AE. Errata and assumptions — every simplification, collected

Honesty about what this book/stack glosses, so you know the edges of your knowledge.

### AE.1 — Networking simplifications
- **IPv4 only** — no IPv6 (different header; §M.6).
- **No IP options parsing** — we account for them via IHL but don't interpret them.
- **No fragmentation/reassembly** — we read the flags/offset fields but don't reassemble.
- **No incoming-checksum validation by default** — we parse first; validating is exercise J.11.
- **TUN/L3 only** — no Ethernet/ARP (TAP path unimplemented).
- **Static addressing** — no DHCP; you assign `192.168.0.1/24` by hand.

### AE.2 — TCP simplifications (developed in docs 3–5)
- **ISN fixed at 0** — real stacks randomize (RFC 6528); ours is debuggable, not secure.
- **In-order data only** — no out-of-order buffering/reassembly.
- **`SND.UNA = seg.ack` unconditionally** — no modular validation of the ack window.
- **No retransmission/RTO, congestion control, or flow control** — the reliability roadmap.
- **Passive close only** — no active open/close, no TIME_WAIT.
- **No RST generation** — stray segments are ignored, not reset.
- **Fixed 1024 window**, no window scaling.

### AE.3 — Engineering simplifications
- **Blocking single-threaded loop** — one connection's worth of attention at a time; the change to
  non-blocking + epoll is the prerequisite for timers (retransmission).
- **`println!` logging** — `tracing` is a dependency but unused for clarity.
- **Per-reply `Vec` allocation** — fine for teaching, first thing to pool for performance.
- **No fuzzing/property tests** — only example-based unit tests (the fuzz harness is a §U exercise).

### AE.4 — Pedagogical assumptions
- You're on **Windows + WSL2 Ubuntu** (the build/run instructions assume it).
- You'll **re-type the code** from the books (the retention step), not just read.
- Numbers in worked examples use the project's lab addressing (`192.168.0.1`↔`.2`).

None of these are hidden bugs — they're the deliberate scope line between "a stack that teaches the
concepts" and "a stack you'd ship." Every item is a known door to walk through next, and most are
exercises or roadmap entries already named.

---

## AF. One HTTP request, fully encapsulated — every layer at once

To see how the layers compose, follow a single `GET / HTTP/1.1` from a browser to a server,
through every header. (On our TUN link there's no Ethernet layer; it's shown to complete the
picture of a real LAN.) This is the whole stack in one packet.

### AF.1 — The nesting

```
+-----------------------------------------------------------------------+
| Ethernet header (14 B)  dst MAC | src MAC | EtherType=0x0800          |  L2 (absent on TUN)
| +-------------------------------------------------------------------+ |
| | IPv4 header (20 B)  ver/IHL | ... | proto=6 | src IP | dst IP      | |  L3  ← we parse this
| | +---------------------------------------------------------------+ | |
| | | TCP header (20 B)  src port | dst port=80 | seq | ack | flags  | | |  L4  ← we parse this
| | | +-----------------------------------------------------------+ | | |
| | | | HTTP (application data)                                    | | | |  L7  ← the app's bytes
| | | |   GET / HTTP/1.1\r\nHost: example.com\r\n\r\n              | | | |
| | | +-----------------------------------------------------------+ | | |
| | +---------------------------------------------------------------+ | |
| +-------------------------------------------------------------------+ |
+-----------------------------------------------------------------------+
```

Each layer **wraps** the one inside it with its own header — like nested envelopes. Sending pushes
headers on (encapsulation); receiving pops them off (decapsulation). Our stack lives at the IP and
TCP envelopes: we read the IP header to learn "this is TCP for me," read the TCP header to find the
connection and the data offset, and hand the inner bytes (HTTP) to the application.

### AF.2 — What each layer contributes

- **Ethernet (L2):** gets the frame across *one* physical link, addressed by 48-bit MAC. EtherType
  `0x0800` says "IPv4 inside." Stripped/replaced at every router hop. (None on TUN.)
- **IPv4 (L3):** gets the packet across *many* links to the right host, addressed by 32-bit IP.
  `protocol=6` says "TCP inside." Survives end to end (addresses unchanged, barring NAT).
- **TCP (L4):** gets the bytes to the right *application* (port 80) on that host, reliably and in
  order. Ports demultiplex; seq/ack provide reliability. End to end.
- **HTTP (L7):** what the bytes *mean* — a request for a resource. The stack doesn't care; it's
  just TCP payload.

### AF.3 — The journey of the request

1. Browser writes `GET / HTTP/1.1\r\nHost: example.com\r\n\r\n` to a connected socket (`write`).
2. TCP wraps it: assigns a sequence number, sets dst port 80, computes the checksum (pseudo-header
   + segment), pushes the 20-byte TCP header.
3. IP wraps that: sets protocol 6, src/dst addresses, TTL 64, header checksum, pushes the 20-byte
   IP header.
4. (On Ethernet) the link layer wraps that with MACs and ships the frame; each router strips the
   Ethernet header, consults its routing table, decrements TTL, recomputes the IP checksum, re-wraps
   in a new Ethernet header for the next hop. The IP/TCP/HTTP layers ride untouched.
5. At the server, decapsulation reverses it: IP (right host? protocol TCP) → TCP (right port?
   right connection? in order? ACK it) → HTTP handed to the web server.
6. The response retraces the path in reverse.

### AF.4 — Where our project sits in this

We are the **server's L3+L4** for a TUN-delivered packet: steps 5's IP and TCP handling. We parse
the IP header (`ip::parse`), confirm it's TCP (`protocol == 6`), parse the TCP header
(`tcp::parse`), match the connection (`Quad`), and — once we implement `read()` — would hand the
HTTP bytes to an application. Everything in docs 1–5 is building exactly the L3/L4 envelope
handling this picture requires. The HTTP layer is out of scope (it's "just data" to us), which is
the whole point of layering: we made TCP work without knowing or caring it carried HTTP.

---

## AG. A timeline of internet protocol history

Context turns arbitrary-seeming details into the residue of real decisions.

- **1961–64** — Kleinrock (queueing theory), Baran (RAND), Davies (NPL) independently develop
  packet-switching ideas; Baran's motivation is a communications network that survives partial
  destruction.
- **1969** — ARPANET's first nodes (UCLA, SRI, UCSB, Utah); the first host-to-host message ("LO",
  a crashed "LOGIN").
- **1971** — Ray Tomlinson sends the first network email; chooses `@`.
- **1973–74** — Cerf & Kahn design TCP; the term "internet" (internetworking) emerges; the goal is
  connecting *different* networks via gateways.
- **1978** — TCP is split into **TCP + IP** (the end-to-end principle in action): IP for simple
  delivery, TCP for reliability. This is the architecture you're building.
- **1981** — **RFC 791 (IP)** and **RFC 793 (TCP)** published — the headers in this book.
- **1 Jan 1983** — ARPANET "flag day": NCP → TCP/IP. The internet's protocol is now yours.
- **1983** — DNS designed (RFC 882/883; later 1034/1035) — names instead of memorized addresses.
- **1984** — Saltzer, Reed, Clark formalize the **end-to-end argument**.
- **1986** — Congestion collapse on the early internet; **1988** Van Jacobson's congestion control
  (slow start, AIMD) saves it — the algorithms in our doc-5 roadmap.
- **1989–91** — Tim Berners-Lee invents the Web (HTTP/HTML/URLs) on top of TCP/IP.
- **1990s** — Classful → **CIDR** (RFC 1519/4632, 1993) to slow routing-table growth and address
  exhaustion; **NAT** (RFC 1631, 1994) papers over IPv4 scarcity.
- **1998** — **IPv6** (RFC 2460; current RFC 8200, 2017) standardized for the 128-bit future.
- **2000s–** — TLS everywhere; congestion control evolves (CUBIC 2008, **BBR** 2016); **RFC 9293**
  (2022) consolidates TCP, obsoleting 793.
- **2010s–** — **QUIC** (RFC 9000) reimplements reliability/ordering/congestion *over UDP* in
  userspace to escape TCP's ossification — a spiritual cousin of *this* project (a transport built
  outside the kernel).

The throughline: a 1970s design, deliberately simple at the core, proved extensible enough to carry
the Web, streaming, and mobile — because the intelligence lives at the endpoints (where you're
working), not the network.

---

## AH. Comprehensive glossary — all five books

(Builds on §K.1; adds terms from the TCP days and the deep dives. Alphabetical.)

- **ACK** — acknowledgement; TCP flag + 32-bit cumulative field ("next byte I expect").
- **AIMD** — Additive-Increase/Multiplicative-Decrease; TCP congestion-control dynamics.
- **ARP** — Address Resolution Protocol; IP→MAC on a LAN (absent on TUN).
- **backlog** — queue of completed-but-not-`accept`ed connections on a listening socket.
- **BBR / CUBIC / Reno** — TCP congestion-control algorithms.
- **BPF / eBPF** — in-kernel packet-matching/programmability bytecode.
- **CIDR** — classless prefix routing (`a.b.c.d/n`); longest-prefix match.
- **congestion control** — limiting send rate to avoid overloading the network (vs flow control).
- **connection (TCP)** — state shared by two endpoints, keyed by the 4-tuple; held in a TCB.
- **datagram** — a self-contained, independently-routed packet (IP, UDP).
- **decapsulation / encapsulation** — popping / pushing layer headers.
- **DF / MF** — Don't-Fragment / More-Fragments IP flags.
- **DSCP / ECN** — QoS class / congestion notification (IP byte 1).
- **end-to-end principle** — keep the network simple; put function at the endpoints.
- **ESTABLISHED** — TCP state where data flows.
- **FIN** — TCP flag beginning a half-close; consumes a sequence number.
- **flow control** — receiver limiting the sender via the advertised window (vs congestion control).
- **four-tuple (Quad)** — (src ip, src port, dst ip, dst port); identifies a connection.
- **handshake (three-way)** — SYN / SYN-ACK / ACK to open a TCP connection.
- **IHL** — IP header length in 32-bit words.
- **IRS / ISS / ISN** — initial receive/send sequence numbers.
- **longest-prefix match** — routing rule: the most specific matching prefix wins.
- **MSS** — Maximum Segment Size; largest TCP payload, advertised in a SYN option.
- **MTU** — Maximum Transmission Unit; largest L3 packet a link carries.
- **NAT / PAT** — address (and port) translation; many private hosts behind one public IP.
- **Nagle's algorithm** — coalesce small TCP writes to reduce tiny packets.
- **netmask** — the mask form of a prefix length (`/24` = 255.255.255.0).
- **pseudo-header** — IP fields fed into the TCP/UDP checksum.
- **PSH** — TCP flag asking prompt delivery to the app.
- **QUIC** — a reliable transport over UDP, in userspace (a modern cousin of this project).
- **RST** — TCP flag aborting a connection.
- **RTO / RTT** — retransmission timeout / round-trip time.
- **SACK** — Selective Acknowledgement; ACK non-contiguous ranges (TCP option).
- **SND.UNA / SND.NXT / RCV.NXT** — TCB sequence pointers.
- **SYN** — TCP flag opening a connection; consumes a sequence number.
- **SYN cookies** — stateless SYN-flood defense.
- **TCB** — Transmission Control Block; a connection's state.
- **TIME_WAIT** — post-close wait (2·MSL) on the active closer.
- **window (TCP)** — advertised receive capacity; basis of flow control; scaled via an option.
- **window scaling** — TCP option extending the 16-bit window beyond 65535.

(For Doc-1-specific terms — bit, byte, endianness, nibble, checksum, TTL, TUN, etc. — see §K.1.)

---

## AI. Designing the event loop — the change that unblocks retransmission

The single most important future change (named in doc5 §10) is moving from a blocking `recv` loop
to a non-blocking, event-driven one. This section is a concrete design so it's not just a TODO.

### AI.1 — Why the blocking loop can't do retransmission

Retransmission means: "if an ACK for sent data hasn't arrived within RTO, resend." That requires
*acting when nothing arrives* — a timer firing. Our `iface.recv(&mut buf)?` blocks the only thread
until a packet comes; while parked there, no timer can run. You cannot both "wait for a packet" and
"wait for a timeout" on one blocking call. The fix is to wait on *both at once*.

### AI.2 — Non-blocking I/O + readiness notification

Two pieces:
1. **Non-blocking fd:** `iface.set_non_blocking()` (sets `O_NONBLOCK`). Now `recv` returns
   immediately — either a packet, or `WouldBlock` if none is ready.
2. **A readiness API:** `epoll` (Linux) tells you *which* fds are ready, with a **timeout**. You
   block in `epoll_wait(timeout)` instead of in `read`. When it returns, either the TUN fd is
   readable (drain packets) or the timeout elapsed (run due timers) — or both.

```text
loop {
    let timeout = next_timer_deadline() - now();   // when does the soonest RTO fire?
    let events = epoll_wait(&[tun_fd], timeout);    // wait for a packet OR the timeout
    if tun_fd is readable {
        while let Ok(n) = iface.recv(&mut buf) {     // drain all queued packets
            handle_packet(&buf[..n]);                // parse/dispatch as today
        }
    }
    run_due_timers(now());                            // retransmit anything past its RTO
}
```

This single structural change is what every real stack has and ours doesn't. In Rust you'd use the
`mio` crate (a thin epoll/kqueue wrapper) or `tokio` (a full async runtime); `mio` is closer to the
metal and better for learning.

### AI.3 — The timer wheel / retransmission queue

Each connection keeps a queue of **unacknowledged segments** with a send timestamp. The structures:
- A per-connection retransmission buffer: `Vec<(seq, bytes, sent_at)>` (or a ring) for data in
  `SND.UNA..SND.NXT`.
- A way to find "the soonest deadline" across all connections — a min-heap by deadline, or a
  hashed **timer wheel** (O(1) insert/expire) for many connections.
On each loop iteration, `run_due_timers` pops everything past its deadline and resends it, doubling
the RTO (exponential backoff, Karn's algorithm: don't sample RTT from a retransmitted segment).

### AI.4 — RTO estimation (RFC 6298)

The timeout isn't fixed; it tracks the measured **RTT**:
```
SRTT  = (1 - α)·SRTT + α·RTT_sample          (α = 1/8)   smoothed RTT
RTTVAR = (1 - β)·RTTVAR + β·|SRTT - RTT|      (β = 1/4)   variation
RTO   = SRTT + max(G, 4·RTTVAR)              clamped to [1s, 60s]
```
You sample `RTT` when an ACK acknowledges new data (timestamp of send vs now), never from a
retransmitted segment (Karn). This adapts to a fast LAN or a slow satellite link automatically.

### AI.5 — What stays the same

`ip::parse`, `icmp::*`, `tcp::parse`, the checksum, `build_packet`, and the per-packet state
transitions are **unchanged** — they're already pure functions of (packet, state). Only the *driver*
(`main`'s loop) changes shape: from "block on one read" to "wait on fd-readiness-or-timeout, then
drain packets and run timers." That clean separation (pure protocol logic vs the I/O driver) is why
the refactor is contained — and a good argument for having factored the modules the way we did.

### AI.6 — Migration order

1. `set_non_blocking`; wrap the loop in `mio`'s `Poll`/`epoll`, draining on readiness (behavior
   identical to today — a safe first step, fully testable).
2. Add the retransmission buffer + a single timer; resend on RTO with fixed backoff.
3. Add proper RTO estimation (§AI.4).
4. Then flow/congestion control can hang off the same timer + window machinery.
Each step is independently testable; step 1 changes structure with no behavior change, which is the
safe way to do a scary refactor.

---

## AJ. Glossary of Rust terms used in this project

For quick reference while reading the code (complements §G).

- **borrow (`&`, `&mut`)** — use a value without owning it; shared (`&`) or exclusive (`&mut`).
- **borrow checker** — the compiler pass enforcing shared-XOR-mutable, statically preventing data
  races and use-after-free.
- **`Copy`** — types duplicated on assignment (integers, `Ipv4Addr`); no move.
- **`derive`** — auto-generate trait impls (`Debug`, `PartialEq`, `Hash`, …).
- **enum** — a sum type; a value is exactly one variant, possibly with data.
- **fat pointer** — a pointer plus metadata; a slice is `(ptr, len)`.
- **lifetime (`'a`)** — the compiler's name for how long a reference is valid.
- **`match`** — exhaustive pattern matching over variants/values.
- **module (`mod`)** — a namespace; `mod x;` compiles `x.rs` into the crate.
- **move** — transfer of ownership on assignment/passing (for non-`Copy` types).
- **`Option<T>`** — `Some(T)` | `None`; presence/absence without null.
- **ownership** — each value has one owner; dropped when the owner leaves scope.
- **panic** — unrecoverable error; out-of-bounds index panics (we guard against it).
- **`Result<T, E>`** — `Ok(T)` | `Err(E)`; success or described failure.
- **slice (`&[T]`)** — a borrowed view into a contiguous run of elements.
- **`String` vs `&str`** — owned growable heap string vs borrowed string slice; `&'static str` is
  a compile-time-baked string.
- **trait** — an interface; behavior types can implement (`Debug`, `Hash`, …).
- **`Vec<T>`** — a growable heap array (outgoing packet buffers).
- **`wrapping_add`** — modular addition with defined overflow (TCP sequence numbers).
- **`?` operator** — propagate `Err`/`None` early; unwrap `Ok`/`Some`.
- **`#[cfg(test)]`** — compile only under `cargo test`.
- **`pub`** — make an item visible outside its module.
- **zero-cost abstraction** — high-level constructs (iterators) compiling to hand-written-quality code.

---

## AK. Final index and a reader's roadmap through all five books

### AK.1 — How the five books fit together

- **doc1-book.md** (this one) — the foundation: packets, TUN, IPv4, ICMP, endianness, Rust
  parsing, the toolchain, plus this Volume-II reference. Read first, in full.
- **doc2-book.md** — the Internet checksum (with §R here as the deep math) and the first write
  (ICMP echo reply). Read after Doc-1 Volume I.
- **doc3-book.md** — TCP, part 1: the handshake, TCB, sequence numbers, the pseudo-header checksum.
- **doc4-book.md** — TCP, part 2: data transfer, cumulative ACK, the echo server.
- **doc5-book.md** — TCP, part 3: teardown, the full lifecycle, and the production roadmap (§10),
  expanded by §AI here (the event-loop design).

### AK.2 — Suggested reading paths

- **First pass (build intuition):** doc1 Volume I → doc2 §1–6 → doc3 §1–6 → doc4 → doc5 §1–7. Skip
  the deep dives; get the working mental model and run the code.
- **Mastery pass (own it):** doc1 Volume II A–S → re-type each file closed-book → doc2 §R math →
  doc3–5 in full → the §AD exam → fix every miss with an Anki card.
- **Security-track pass:** doc1 §U → §AI/§AE (the gaps are attack surface) → write the `cargo fuzz`
  target → read Snort/Suricata as the blue-team mirror.
- **Systems pass:** doc1 §F (kernel datapath) → §S (performance) → §AI (event loop) → read
  `smoltcp` as the production comparison.

### AK.3 — The concept index (where to look)

- **Bits/hex/endianness:** doc1 §A–§D.
- **IPv4 every field:** doc1 §E. **ICMP every type:** doc1 §H. **TCP:** doc3–5.
- **Checksum (code → math):** doc2 → doc1 §R.
- **Rust mechanisms:** doc1 §G, §AJ. **Code line-by-line:** doc1 §O (foundational files).
- **Tooling (tcpdump/Wireshark):** doc1 §I.
- **Debugging:** doc1 §P. **Exercises+solutions:** doc1 §J. **Self-test:** doc1 §AD.
- **Roadmap/event loop:** doc5 §10 + doc1 §AI. **Sockets API:** doc1 §AB.
- **Security:** doc1 §U. **Performance:** doc1 §S. **History:** doc1 §M, §AG.

### AK.4 — The finish line, restated

You have finished Doc 1 when you can, book closed: re-type `utils.rs`/`ip.rs`/`icmp.rs`, explain
every byte of an IPv4+ICMP packet, compute a checksum by hand, and answer the §AD fifty. You have
finished the *project* when `ping` and `nc` work live, all tests are green, and you can teach the
whole lifecycle (open→data→close) at a whiteboard. The books are the answer key; the keyboard and
the whiteboard are the exam.

---

## AL. Worked subnetting problems (with solutions)

Subnetting is pure §C bit-work applied to §AA addresses. Cover the solutions; compute first.

### AL.1 — Network and broadcast of `192.168.0.1/24`
**Solution.** `/24` mask = `255.255.255.0`. Network = address AND mask = `192.168.0.0`. Broadcast =
network OR (inverted mask) = `192.168.0.255`. Usable hosts: `.1`–`.254` (254). This is our lab net.

### AL.2 — Is `10.1.2.130` on the same `/25` as `10.1.2.5`?
**Solution.** `/25` mask = `255.255.255.128`; the split is in the last octet's top bit. `.5` AND
`.128`-mask → host bits with network `10.1.2.0`; `.130` → `10.1.2.128`. Different network parts →
**no**, different `/25` subnets (`.0–.127` vs `.128–.255`).

### AL.3 — How many hosts in a `/30`?
**Solution.** 32 − 30 = 2 host bits → 2² = 4 addresses; minus network + broadcast = **2 usable**.
That's why `/30` is the classic point-to-point link subnet.

### AL.4 — Split `192.168.1.0/24` into four equal subnets
**Solution.** Four subnets need 2 more prefix bits → `/26` (mask `255.255.255.192`), each with
2⁶ = 64 addresses (62 usable):
`192.168.1.0/26` (.0–.63), `192.168.1.64/26` (.64–.127), `192.168.1.128/26` (.128–.191),
`192.168.1.192/26` (.192–.255).

### AL.5 — What prefix gives at least 1000 hosts?
**Solution.** Need ≥ 1000 usable → ≥ 1002 addresses → smallest power of two ≥ 1002 is 1024 = 2¹⁰ →
10 host bits → prefix `/22` (32 − 10). A `/22` has 1024 addresses, 1022 usable.

### AL.6 — Aggregate `192.168.0.0/24` and `192.168.1.0/24` into one prefix
**Solution.** They differ only in the 24th bit; a `/23` covers both: `192.168.0.0/23` (spans
`192.168.0.0`–`192.168.1.255`). This is **route aggregation** — the reason CIDR keeps routing tables
small.

### AL.7 — Which subnet does `172.16.20.200/21` belong to?
**Solution.** `/21` → the third octet's top 5 bits are network; block size in the third octet is
2^(24−21) = 8. `200`/... actually the boundary is in octet 3: 20 falls in the block `16–23` (since
blocks step by 8: 0–7, 8–15, 16–23). Network = `172.16.16.0/21`, broadcast `172.16.23.255`.

### AL.8 — The shortcut (memorize the block sizes)
For a prefix, the "magic number" = 256 − (mask octet). `/26` → 256−192 = 64 (subnets step by 64).
`/28` → 256−240 = 16. `/30` → 256−252 = 4. The address's octet divided by the block size (floored,
times block size) gives the network. This turns subnetting into one division.

---

## AM. Flow control vs congestion control — preparing for the roadmap

Two TCP mechanisms students constantly conflate. Both limit the sender, for *different reasons*.
You'll implement these in the post-doc-5 roadmap; here's the conceptual groundwork.

### AM.1 — Flow control: don't overrun the *receiver*

The receiver advertises a **window** (`RCV.WND`, the TCP header's 16-bit window field) = "I have
this much free buffer; don't send more than this beyond what you've already sent." The sender must
keep `SND.NXT − SND.UNA ≤ SND.WND`. If the receiver's app is slow to `read`, its buffer fills, it
advertises a smaller window, eventually **window = 0** ("stop"); later it sends a window update to
resume. This protects a *slow receiver* from a *fast sender*. Our stack hardcodes window 1024 and
ignores the peer's — fine for `nc`, wrong for bulk transfer. **Window scaling** (a SYN option)
multiplies the 16-bit window so it can exceed 65535 on fast/long links.

### AM.2 — Congestion control: don't overrun the *network*

The window above protects the receiver; nothing yet protects the *routers in between*. Congestion
control adds a second, sender-side limit — the **congestion window** (`cwnd`) — and the sender may
send only `min(RCV.WND, cwnd)`. `cwnd` is grown and shrunk by feedback:
- **Slow start:** begin small, double `cwnd` each RTT (exponential) until loss or a threshold.
- **Congestion avoidance:** past the threshold, grow linearly (+1 MSS/RTT) — additive increase.
- **On loss (the congestion signal):** multiplicatively decrease (halve) — this is **AIMD**, and
  it's what keeps the shared internet stable (Van Jacobson, 1988, after the 1986 congestion
  collapse).
- **Fast retransmit/recovery:** 3 duplicate ACKs ⇒ a segment was lost ⇒ resend it immediately
  without waiting for the RTO, and don't drop all the way back to slow start.
Modern algorithms: **CUBIC** (default; window grows as a cubic function of time since last loss),
**BBR** (models bottleneck bandwidth and RTT instead of treating loss as the only signal).

### AM.3 — The clean mental split

| | Flow control | Congestion control |
|---|---|---|
| Protects | the receiver's buffer | the network's routers/links |
| Signal | advertised window (`RCV.WND`) | loss / delay (inferred) |
| Sender limit | `SND.WND` | `cwnd` |
| Sender sends ≤ | `SND.WND` | `min(SND.WND, cwnd)` |
| In our stack | hardcoded, ignored | absent |
Both are in the doc-5 roadmap; both need the event loop (§AI) because they're driven by ACK arrival
and timers. Knowing the distinction now means the roadmap reads as "add these two limiters," not as
mystery.

---

## AN. TCP options — the bytes after the 20-byte header

A SYN's 40-byte TCP header (data offset 10 words) carries 20 bytes of **options** beyond the fixed
header. We skip them (using `data_offset` to find the payload), but they're where much of modern
TCP's capability is negotiated, so know what's there.

### AN.1 — The TLV format
Most options are **Type-Length-Value**: 1 byte kind, 1 byte total length, then value. Two are
single-byte specials: **End of Option List** (kind 0) and **No-Operation** (kind 1, used as padding
to align options to 4-byte boundaries).

### AN.2 — The options you'll see in a real SYN
- **MSS (kind 2, len 4):** Maximum Segment Size — the largest TCP payload this side will accept,
  typically 1460 (1500 MTU − 20 IP − 20 TCP). Each side announces it in its SYN; only in SYNs.
- **Window Scale (kind 3, len 3):** a shift count (0–14) multiplying the 16-bit window, allowing
  windows up to ~1 GB — essential for high bandwidth-delay-product links. SYN-only; both sides must
  send it to enable.
- **SACK-Permitted (kind 4, len 2):** "I support Selective ACK." SYN-only.
- **SACK (kind 5):** in data segments, ACK non-contiguous received ranges so the sender retransmits
  only the actual gaps, not everything after a loss.
- **Timestamps (kind 8, len 10):** two 4-byte timestamps for accurate RTT measurement and PAWS
  (Protection Against Wrapped Sequence numbers on fast links).

### AN.3 — Why we skip them (and what it costs)
Our handshake sends a bare 20-byte TCP header (no options): no MSS announcement (peer assumes a
default), no window scaling (capped at 65535), no SACK (loss recovery would be coarse), no
timestamps (RTT estimation coarser). For a local `nc` over a lossless TUN link none of this matters.
On a real network they significantly affect throughput and loss recovery — adding them is a natural
extension once the core works. The key implementation point: because we honor `data_offset`, we
*tolerate* a peer's options (we skip them correctly); we just don't *send* or *act on* any.

---

## AO. UDP in full — the simplest transport, and the contrast that makes TCP legible

UDP (RFC 768) is the other transport over IP (protocol 17). It is *deliberately* minimal, and
understanding it sharpens your understanding of everything TCP adds.

### AO.1 — The entire UDP header (8 bytes)

```
 0               1               2               3
+-------------------------------+-------------------------------+
|          Source Port          |       Destination Port        |
+-------------------------------+-------------------------------+
|            Length             |           Checksum            |
+-------------------------------+-------------------------------+
|                          data ...                              |
```
That's it. Four 16-bit fields:
- **Source / Destination Port** — demultiplexing, same as TCP.
- **Length** — UDP header + data, in bytes (minimum 8).
- **Checksum** — Internet checksum over a pseudo-header (same shape as TCP's, protocol 17) + the
  UDP header + data. Optional in IPv4 (0 = "not computed"); mandatory in IPv6.

### AO.2 — What UDP does NOT have (and TCP does)

No connection, no handshake, no sequence numbers, no acknowledgements, no retransmission, no
ordering, no flow control, no congestion control, no teardown. A UDP "datagram" is fire-and-forget:
it may be lost, duplicated, or reordered, and UDP won't tell you. **All** the machinery of docs 3–5
is precisely what TCP adds on top of this. Seeing UDP's 8 bytes next to TCP's 20+ bytes and stateful
machine is the clearest way to grasp "what reliability costs."

### AO.3 — Why UDP exists / when it's right

- **Low latency, loss-tolerant:** DNS (one request/reply — a handshake would double the latency),
  VoIP/video (a late packet is worse than a lost one), games.
- **You want to build your own reliability:** QUIC runs *its own* TCP-like logic over UDP in
  userspace — exactly the spirit of this project, but shipped (HTTP/3 uses it). DNS-over-QUIC,
  WebRTC, etc.
- **Broadcast/multicast:** UDP can; TCP (connection-oriented) cannot.

### AO.4 — Adding UDP to our stack (it's easy — that's the point)

Protocol 17 → parse the 8-byte header, read ports/length. There's no state to keep (no TCB), so no
connection table — you'd just deliver the datagram (or, for our echo theme, send it straight back
with ports swapped and a fresh checksum). It's the doc-1 exercise J.10 plus a checksum. The ease of
UDP versus the difficulty of TCP *is* the lesson about what transport reliability requires.

---

## AP. A complete annotated TCP connection trace

The whole lifecycle (docs 3–5) as one packet-by-packet trace with the TCB after each step. Numbers:
client ISN 100, our ISS 0, client sends "hi" (2 bytes).

```
# = packet   dir: C=client→us, U=us→client     [flags] seq/ack/len      TCB after (our side)
─────────────────────────────────────────────────────────────────────────────────────────────
1  C→U  [SYN]        seq=100 ack=-   len=0    → accept(): RCV.IRS=100 RCV.NXT=101
                                                ISS=0 SND.UNA=0 SND.NXT=1  state=SYN_RCVD
2  U→C  [SYN,ACK]    seq=0   ack=101 len=0    → (our SYN sent; SND.NXT already 1)
3  C→U  [ACK]        seq=101 ack=1   len=0    → ack==SND.NXT(1) ⇒ SND.UNA=1 state=ESTABLISHED
4  C→U  [PSH,ACK]    seq=101 ack=1   len=2 "hi" → seg.seq==RCV.NXT(101): accept 2B
                                                RCV.NXT=103
5  U→C  [PSH,ACK]    seq=1   ack=103 len=2 "hi" → echo; SND.NXT=3 (consumed 2)
6  C→U  [ACK]        seq=103 ack=3   len=0    → SND.UNA=3 (our 2 data bytes acknowledged)
7  C→U  [FIN,ACK]    seq=103 ack=3   len=0    → FIN at RCV.NXT(103): RCV.NXT=104
8  U→C  [FIN,ACK]    seq=3   ack=104 len=0    → our FIN; SND.NXT=4  state=LAST_ACK
9  C→U  [ACK]        seq=104 ack=4   len=0    → ack==SND.NXT(4) ⇒ state=CLOSED (TCB removed)
```

Things to notice, each a concept from the doc-books:
- **The two `+1`s** (packets 1→2 ack, 7→8 ack) are SYN and FIN each consuming a sequence number.
- **Cumulative ACK:** packet 6's `ack=3` says "I have your bytes up to seq 2, send 3 next."
- **Piggybacking:** packet 5 is one segment doing two jobs (send "hi" *and* ack the client's "hi").
- **Every U→C packet** is built by `build_packet` with a valid IP header checksum and a valid TCP
  checksum (pseudo-header + segment) — our tests assert exactly these.
- **State transitions** match `tcp::Connection`'s `State` enum: SYN_RCVD → ESTABLISHED → LAST_ACK →
  CLOSED. This trace is literally what `passive_close_via_fin` + `established_echoes_data` verify.

If you can produce this table from a blank page — every seq, ack, flag, and state — you understand
TCP's core. It is the single most important diagram in docs 3–5.

---

## AQ. The applications riding underneath — DNS and DHCP (context)

Two protocols you use constantly, both built on the transports you now understand; they close the
loop from "raw packets" to "how the internet actually starts a connection."

### AQ.1 — DNS (name → address)

When you type a hostname, **DNS** (RFC 1034/1035) translates it to an IP before any IP packet can be
addressed. It runs (classically) over **UDP port 53**: one small request ("A record for
example.com?"), one small reply ("93.184.216.34") — a perfect fit for UDP's low-latency, no-
handshake model. Large replies or zone transfers fall back to **TCP/53**. DNS is why §AA's "the
kernel needs the destination IP" is usually preceded by a DNS lookup. (Modern variants: DNS-over-TLS,
DNS-over-HTTPS, DNS-over-QUIC — encrypting the lookup.)

### AQ.2 — DHCP (how a host gets its address)

We *assigned* `192.168.0.1/24` by hand. On a real network a host gets its address automatically via
**DHCP** (RFC 2131) over **UDP ports 67/68**, in a four-message dance (**DORA**): Discover (broadcast
"any DHCP servers?"), Offer (server proposes an address), Request (client accepts), Acknowledge
(server confirms). It hands out the address, netmask, default gateway, and DNS servers — everything
§AA needs. It must use UDP broadcast precisely because the client has *no IP yet* (can't do TCP, can't
be unicast-addressed). Our static `ip addr add` is the manual stand-in for DORA.

### AQ.3 — The full "open a web page" sequence (synthesis)

Putting §AA, §AF, §AO, and this together — what happens when you load `http://example.com`:
1. **DHCP** (if not already): get our IP, gateway, DNS server (UDP 67/68).
2. **DNS**: resolve `example.com` → `93.184.216.34` (UDP 53).
3. **Routing** (§AA): `93.184.216.34` isn't on our subnet → send to the default gateway; (ARP to
   find the gateway's MAC on a real LAN).
4. **TCP handshake** (docs 3): SYN/SYN-ACK/ACK to `93.184.216.34:80`.
5. **HTTP** (§AF): `GET / HTTP/1.1` as TCP payload; server replies with the page.
6. **TCP teardown** (doc 5): FINs close the connection.
Every single step is something this project either implements (3–6, the IP/TCP parts) or explains
(1–2). You now hold the complete chain from "typed a URL" to "bytes on the wire" — which is the real
goal of building a stack from scratch.

---

## AR. Exercise set II — fifteen more, with full solutions

Harder and more code-oriented than §J. Attempt before reading the solution.

### AR.1 — Build an IPv4 header from scratch
**Q.** Write bytes 0, 6, 8, 9 of an outgoing 40-byte (IP+TCP) packet with DF set, TTL 64, TCP.
**A.** byte0 `(4<<4)|5 = 0x45`; bytes 2–3 total length `0x0028` (40); bytes 6–7 `0x4000` (DF, no
frag); byte8 TTL `0x40`; byte9 proto `0x06`. (This is what `build_packet` does.)

### AR.2 — Compute total length for a TCP segment with 100 payload bytes, no options
**A.** IP(20) + TCP(20) + 100 = 140 = `0x008C`.

### AR.3 — Why does the checksum use `chunks_exact(2)` not `chunks(2)`?
**A.** `chunks_exact` yields only full 2-byte words and exposes the leftover via `.remainder()`,
letting us handle the odd byte explicitly (`<<8`). `chunks(2)` would yield a final 1-byte slice
mid-iteration, complicating the `from_be_bytes([a,b])` read.

### AR.4 — Given `data_offset` byte = `0x60`, how many TCP option bytes?
**A.** `0x60 >> 4 = 6` words = 24-byte TCP header; minus 20 fixed = **4 option bytes**.

### AR.5 — Write `is_between_wrapping(start, x, end)` for modular seq comparison
**A.**
```rust
// true if x is in (start, end] on the wrapping u32 number circle
fn is_between_wrapping(start: u32, x: u32, end: u32) -> bool {
    start < x && x <= end            // simple case
    || end < start && (start < x || x <= end)  // wrapped case
}
```
(The RFC 9293 / Gjengset formulation; needed to validate acks across the 2³² wrap.)

### AR.6 — Why is `recv` given `&mut buf` but `send` given `&reply`?
**A.** `recv` *writes into* the buffer (mutable borrow); `send` only *reads* the bytes to transmit
(shared borrow). The borrow kind matches the data direction.

### AR.7 — Decode TCP flags `0x14`
**A.** `0x14 = 0001 0100` → RST(0x04) + ACK(0x10) = **RST-ACK** (an abort that also acknowledges).

### AR.8 — Hand-build the pseudo-header for a 20-byte TCP segment, ME→PEER
**A.** `c0 a8 00 02` (src) `c0 a8 00 01` (dst) `00` (zero) `06` (proto) `00 14` (TCP length 20).
Twelve bytes, prepended to the segment before `utils::checksum`.

### AR.9 — Why must the checksum field be zero during computation but the addresses present?
**A.** The field can't checksum itself (you'd need the answer to compute the answer). The addresses
must be present because the pseudo-header *binds* the checksum to them (misdelivery detection).

### AR.10 — What does `Ipv4Addr::new(192,168,0,1).octets()` return, and why use it?
**A.** `[192, 168, 0, 1]` (`[u8;4]`). Used to compare our parsed address to etherparse's `source()`
without depending on a particular accessor.

### AR.11 — Add a `ParseError::BadChecksum` and validate incoming headers
**A.** After the length guards: `if utils::checksum(&packet[..header_len]) != 0 { return
Err(ParseError::BadChecksum); }`. Test: good header → Ok; flip a byte → BadChecksum.

### AR.12 — Why does our echo `build_echo_reply` swap addresses by copying into temporaries?
**A.** Because `reply[12..16].copy_from_slice(&reply[16..20])` would be an overlapping
borrow-of-self conflict; copying src/dst into `[u8;4]` temporaries first avoids aliasing the same
`Vec` mutably and immutably at once.

### AR.13 — A SYN arrives for an existing ESTABLISHED quad. What should happen (real TCP)?
**A.** Per RFC 9293, a SYN in ESTABLISHED is suspicious; a compliant stack sends a challenge ACK
(RFC 5961) rather than blindly resetting — anti-spoofing. We currently route it to `on_packet`,
which ignores it; hardening is a roadmap item.

### AR.14 — Why is `count: u64` and not `u32`?
**A.** A long-running stack could exceed 4.29 billion packets (u32 max); `u64` won't realistically
wrap. Cheap insurance against a counter overflow.

### AR.15 — Convert the whole §AP trace's packet 5 to bytes (IP+TCP, no options, "hi")
**A.** IP: `45 00 00 2c 00 00 40 00 40 06 <csum> c0a80002 c0a80001` (len 44 = 20+20+2+... wait: 20
IP + 20 TCP + 2 data = 42 = 0x2A). Correct total length `0x002A`. TCP: `<sp> <dp> 00000001
00000067 50 18 0400 <csum> 0000 68 69`. (seq=1, ack=103=0x67, flags 0x18=PSH-ACK, win 1024, "hi"=
68 69.) Build it and `tcp_checksum` it → verifies to 0. *(Note: total length is 42=0x2A, not 44 —
catching that is the exercise.)*

---

## AS. A Rust ownership case study — reading the borrow checker through our code

The borrow checker is the part of Rust that most surprises newcomers. Here it is, concretely, in
*our* code, so the rules stop being abstract.

### AS.1 — The receive buffer across loop iterations

```rust
let mut buf = [0u8; 1504];
loop {
    let n = iface.recv(&mut buf)?;   // (1) exclusive borrow of buf
    let packet = &buf[..n];          // (2) shared borrow of buf
    let hdr = ip::parse(packet)?;    // uses the shared borrow
    // ... packet used here ...
}                                     // (3) borrows end at loop bottom
```
Why this compiles: the exclusive borrow at (1) ends the instant `recv` returns (its result `n` is a
plain `usize`, owning nothing). Then the shared borrow at (2) begins and lasts only as long as
`packet` is used. By the next iteration both are gone, so the next `&mut buf` is fine. The rule
"exclusive XOR shared" holds *at every instant* — they never overlap in time. If you tried to keep
`packet` alive *and* call `recv(&mut buf)` again, the checker would reject it (you'd be reading and
writing `buf` at once) — which is exactly the bug it's preventing (parsing stale/overwritten bytes).

### AS.2 — Why the Doc-5 close needs a specific order

```rust
Some(conn) => {                       // conn: &mut Connection (exclusive borrow of the map entry)
    if let Some(out) = conn.on_packet(&th, payload) { iface.send(&out)?; }
    let state = conn.state();         // last use of conn → borrow ends here
    if state == tcp::State::Closed {
        connections.remove(&quad);    // now allowed: no live borrow of `connections`
    }
}
```
`conn` is a mutable borrow *into* `connections`. You cannot call `connections.remove(...)` while
`conn` is alive — that would be two simultaneous mutable accesses to the same map. Copying `state`
out (a `Copy` enum) lets `conn`'s borrow end, after which `remove` is legal. The compiler *forces*
the safe ordering; in C this exact pattern (free a node while iterating a container) is a classic
use-after-free.

### AS.3 — Why we copy fields instead of borrowing the packet into the header

`ip::parse` returns an **owned** `Ipv4Header` (copies out version, addrs, etc.) rather than a struct
holding `&packet` slices. If it borrowed, the returned header would carry a lifetime tied to
`packet`, and you couldn't, say, store headers past the buffer's reuse without fighting lifetimes.
Owning a few small `Copy` fields sidesteps all of that for a negligible cost. This is the
explicit simplicity-vs-zero-copy trade from §G.12 — and the borrow checker is *why* the zero-copy
version would be more complex (correctly so: it would stop you from holding a header that outlives
its bytes).

### AS.4 — The mental model

The borrow checker is not a style linter; it is a proof engine. Every time it rejects your code, it
has found a way two accesses could conflict, or a reference could outlive its data. The fixes
(end a borrow sooner by copying a small value; restructure the order; own instead of borrow) are
the *same* fixes that make C code memory-safe — except here they're mandatory and checked. Reading
its errors as "what conflict did I create?" turns frustration into a fast feedback loop.

---

## AT. Cross-topic synthesis — how every piece connects

Doc 1 looks like many small topics; they are one system. This section draws the lines.

### AT.1 — From a `ping` keystroke to a printed line (the whole chain)

`ping 192.168.0.2` → kernel routing (§AA) picks `tun0` because of the connected route → kernel
builds an ICMP echo (§H) inside an IP packet (§E) and "transmits" it on `tun0`, i.e. `write`s it to
the TUN fd (§F) → our `iface.recv` (§4) returns those bytes → `ip::parse` reads the header using
bit ops (§C) and big-endian conversion (§D), guarding lengths first (§G.6) → protocol byte says
ICMP → `icmp::parse` reads it → we print, and (Doc 2) build a reply, recomputing the checksum (§R)
and `write`ing it back. Eleven sections, one packet. Every concept earns its place in this path.

### AT.2 — The recurring shape: read header → decide → maybe write

Every layer we touch follows the same three-beat rhythm: **parse** a fixed-offset header (shift/
mask/`from_be_bytes`), **decide** based on a key field (version, protocol, ICMP type, TCP flags/
state), and **optionally build** a response (lay out bytes, fix checksums, `send`). IP, ICMP, and
TCP are the same pattern at different layers. Once you see the rhythm, a new protocol is just "what
are its offsets, what's its key field, what response does it need?"

### AT.3 — The two invariants that keep it safe and correct

1. **Guard then index** (§G.6, §U): never touch a byte you haven't proven exists. This is the
   safety invariant — it's why hostile input can't crash us.
2. **Big-endian at the boundary** (§D): convert every multi-byte field with `from_be_bytes`/
   `to_be_bytes`. This is the correctness invariant — it's why our values match the wire.
Almost every Doc-1 bug violates one of these two.

### AT.4 — State is what separates a parser from a stack

Docs 1–2 are stateless (parse, reply, forget). Doc 3 introduces the **TCB** and the connection
table — *memory across packets* — and that single addition is what turns "a program that decodes
packets" into "a TCP stack." Everything hard about TCP (handshake, reliability, ordering, teardown)
is the management of that state over time. The progression of the five books *is* the progression
from stateless to stateful.

### AT.5 — Why the layering paid off in our own code

We split `utils`/`ip`/`icmp`/`tcp` along protocol-layer lines (§V.4). The payoff showed up
concretely: the checksum (`utils`) is reused unchanged by IP, ICMP, and TCP; `ip`'s header builder
serves both the ICMP reply and TCP segments; and the event-loop refactor (§AI) touches only the
*driver*, not the layered protocol logic. Good module boundaries mirror the problem's structure —
here, the protocol stack itself.

---

## AU. Expert insights — fifteen things that take people years to internalize

Shortcuts to the intuitions experienced network programmers carry.

1. **The bytes never lie.** When code and mental model disagree, dump the bytes and decode by hand.
   Theorizing without looking wastes hours; a hex dump ends the debate.
2. **Endianness bugs are invisible until you print the value.** Build the `from_be_bytes` reflex so
   they never start.
3. **A length field is an adversary's lever.** Validate every length against reality before using it;
   this one habit prevents a whole CVE class.
4. **Checksums fail silently.** A bad checksum doesn't error — the packet just vanishes. When "I sent
   it but nothing happened," suspect the checksum first.
5. **ACK means "next expected," not "last received."** Off-by-one here breaks everything; say it as
   "send me N next."
6. **SYN and FIN cost a sequence number.** The `+1`s in the handshake/teardown are not arbitrary.
7. **In-order is the easy 80%.** Out-of-order + retransmission is the hard 20% that makes TCP
   *reliable* — and where the real complexity lives.
8. **Most of TCP is timers.** Retransmission, delayed ACK, TIME_WAIT, keepalive — which is why a
   blocking loop can't be a real TCP and the event loop is non-negotiable.
9. **The receiver's window protects the receiver; the congestion window protects the network.** Two
   different limits for two different victims.
10. **NAT broke the end-to-end principle in practice.** It's why inbound connections are hard and
    why QUIC/STUN/ICE exist. Know it's there.
11. **`tcpdump`/Wireshark are not optional.** The engineers who are fast are the ones fluent in
    reading captures; it's a learnable skill, so learn it early.
12. **Test the pure functions offline.** Parsers and checksums need no network; a fixture-driven
    test suite is faster feedback than any live run and a permanent regression net.
13. **Differential testing finds parser bugs cheaply.** Cross-check against a known-good library; a
    mismatch localizes the bug to one implementation.
14. **Modular sequence arithmetic is mandatory, not optional.** Plain `<` on sequence numbers is a
    latent bug that detonates at the 2³² wrap; use windowed/wrapping comparisons.
15. **Simplicity at the core is why the internet scaled.** IP is dumb on purpose; intelligence lives
    at the endpoints (where you're working). When in doubt, push complexity to the edges.

---

## AV. Testing strategy — how to know your stack is correct

A stack that "seems to work" with `ping` can be deeply broken. Here's the layered testing approach
this project uses and how you'd extend it.

### AV.1 — Level 1: example-based unit tests (what we have)

Feed a known packet, assert the parsed fields / built bytes. Fast (<1ms), no network, run on every
save. Our 17 tests cover: IP/ICMP/TCP parse fields, rejection paths, checksum vectors, echo-reply
well-formedness, handshake numbers, data echo, teardown. **These are your first line** — if they're
red, nothing else matters. Cover the *boundaries*: minimum-length packets, the version check, the
wrap of sequence numbers.

### AV.2 — Level 2: differential testing (what we have, partially)

Run a second, independent implementation on the same input and compare (`agrees_with_etherparse`).
Divergence localizes a bug. Extend it: parse a corpus of captured packets with both your parser and
etherparse and assert agreement on every field.

### AV.3 — Level 3: property-based testing (the next step)

Instead of fixed inputs, assert *properties* over many generated inputs (the `proptest`/`quickcheck`
crates). Examples for our stack:
- *Round-trip:* `parse(build(header)) == header` for any valid header.
- *Checksum:* for any bytes, `checksum(data_with_field_set)` verifies to 0.
- *No panic:* `parse` never panics on any `Vec<u8>` (the gateway to fuzzing).
Properties catch classes of bugs examples miss because the generator explores inputs you wouldn't
think to write.

### AV.4 — Level 4: fuzzing (the security step, §U.3)

`cargo fuzz` throws millions of mutated byte strings at `ip::parse`/`tcp::parse`, hunting for any
panic, hang, or sanitizer trip. A parser that survives a long fuzz run with the up-front guards is
genuinely hardened against malformed input — the difference between "passes my tests" and "survives
the internet." Writing one fuzz target is the single highest-leverage robustness exercise here.

### AV.5 — Level 5: integration / conformance (the live step)

The real network is the final judge: `ping` (ICMP), `nc` (TCP echo), `tcpdump`/Wireshark to confirm
the wire bytes, and `packetdrill` (Google's tool, in the Manual) to script exact packet sequences
and assert your stack's responses — true conformance testing against the RFC behavior. This is where
"my tests pass but the live link misbehaves" bugs (usually generated-packet checksums) surface.

### AV.6 — The pyramid

Many fast unit tests (the base), fewer property/differential tests, a fuzz target, a handful of live
integration checks (the tip). Most of your confidence comes from the base (instant, deterministic);
the tip catches what models miss. Build the base first — which is exactly why every day in this
project ships `#[cfg(test)]` tests before touching the live interface.

---

## AW. Complete tooling and command reference

Every command you need to build, run, observe, and stress this stack, in one place.

### AW.1 — Interface setup (`ip`, from iproute2)
```bash
sudo ip addr add 192.168.0.1/24 dev tun0   # give the host side an address + connected route
sudo ip link set tun0 up                    # bring the interface up
ip addr show tun0                           # verify: UP, inet 192.168.0.1/24
ip route show | grep 192.168                # verify the connected route
sudo ip link delete tun0                    # clean up a stale interface (fixes ResourceBusy)
sudo modprobe tun                           # load the TUN module if /dev/net/tun is missing
```

### AW.2 — Generating traffic (`ping`, `nc`)
```bash
ping -c 3 192.168.0.2                        # 3 ICMP echo requests
ping -c 1 -s 1000 192.168.0.2                # a 1000-byte payload (test larger packets)
nc 192.168.0.2 8080                          # open a TCP connection, type to send
printf 'hi\n' | nc -q1 192.168.0.2 8080      # send "hi", close after 1s (echo test)
nc -u 192.168.0.2 53                         # UDP (for the UDP exercise)
```

### AW.3 — Observing (`tcpdump`, Wireshark) — see §I for full detail
```bash
sudo tcpdump -i tun0 -n -vv                  # decoded, verbose
sudo tcpdump -i tun0 -n -X                   # + hex/ASCII dump
sudo tcpdump -i tun0 -n -S 'tcp'             # absolute TCP seq numbers, TCP only
sudo tcpdump -i tun0 -w cap.pcap             # capture to file → open in Wireshark
```

### AW.4 — Crafting/attacking (advanced; security track)
- **`hping3`** — craft arbitrary TCP/UDP/ICMP packets (set any flag/seq/port): e.g.
  `sudo hping3 -S 192.168.0.2 -p 8080` sends a raw SYN — a way to poke your handshake without `nc`.
- **`scapy`** (Python) — programmatic packet construction/parsing; ideal for writing test cases and
  PoCs against your own stack: `IP(dst="192.168.0.2")/TCP(dport=8080, flags="S")`.
- **`nmap`** — port scanning; runs the handshakes/RSTs your stack must handle.

### AW.5 — Conformance (`packetdrill`)
Google's **packetdrill** scripts an exact packet timeline and asserts the stack's responses — true
RFC conformance testing. A snippet (conceptual):
```
0   `your stack listening on 8080`
+0  > S  0:0(0) win 65535 <mss 1460>          # inject a SYN
+0  < S. 0:0(0) ack 1 win 1024                # EXPECT a SYN-ACK with ack=1
+0  > .  1:1(0) ack 1                          # inject the final ACK
```
If your stack's reply doesn't match the `<` line, packetdrill fails the test. This is how you'd
verify the handshake against the spec, deterministically, without a flaky live peer.

### AW.6 — Build/test (`cargo`)
```bash
cargo test                                   # offline correctness (no sudo/TUN)
cargo build                                  # → ~/.tcp-stack-target/debug/tcp-stack
cargo fuzz run parse_ip                      # (with cargo-fuzz set up) hammer the parser
sudo setcap cap_net_admin=eip <binary>       # grant TUN privilege (after every build)
```

---

## AX. Packet-crafting walkthrough — build an ICMP echo *request* by hand

We've built replies (mutate-in-place) and TCP segments (from scratch). For completeness, here's how
you'd originate an ICMP Echo Request — the thing `ping` sends — which is the basis of writing your
own ping (a great exercise) and of the active side of any protocol.

### AX.1 — The plan
A 28-byte packet: 20-byte IP header + 8-byte ICMP header (no data, minimal). Steps mirror
`build_packet`: zero a buffer, write IP fields, IP checksum, write ICMP fields, ICMP checksum.

### AX.2 — The IP header
```
buf[0]      = 0x45                      # v4, IHL 5
buf[2..4]   = (28u16).to_be_bytes()     # total length 28
buf[6..8]   = (0x4000u16).to_be_bytes() # DF
buf[8]      = 64                        # TTL
buf[9]      = 1                         # protocol ICMP
buf[12..16] = src.octets()             # us
buf[16..20] = dst.octets()             # target
ip::write_header_checksum(&mut buf[..20])
```

### AX.3 — The ICMP header
```
buf[20] = 8            # type 8 = echo request
buf[21] = 0            # code 0
# buf[22..24] checksum = 0 for now
buf[24..26] = id.to_be_bytes()    # any identifier
buf[26..28] = seq.to_be_bytes()   # sequence number
let c = utils::checksum(&buf[20..28]);   # ICMP checksum over the ICMP message
buf[22..24] = c.to_be_bytes();
```

### AX.4 — Why this matters
Originating a packet (vs replying) is the active half of every protocol: it's how you'd write a
ping client, a port scanner, or the client side of TCP (`connect`). The discipline is identical —
lay out bytes big-endian, checksum last with the field zeroed. Once you can craft an echo request
*and* parse the reply, you've built a working `ping` from scratch — a satisfying capstone exercise
that uses every Doc-1/Doc-2 skill.

### AX.5 — Verifying a crafted packet
Send it (`iface.send`), watch `tcpdump -i tun0` show your echo request, and — if the target is a
real host on a real interface — watch the echo reply come back. Offline, assert
`utils::checksum(&buf[..20]) == 0` and `utils::checksum(&buf[20..28]) == 0`; both zero means both
headers are valid and the kernel/peer won't silently drop it.

---

## AY. Miscellaneous deep-dives (reader questions that didn't fit elsewhere)

### AY.1 — Why is the MTU 1500, specifically?
Historical: original Ethernet chose a 1500-byte payload as a balance between efficiency (bigger =
less per-packet overhead) and fairness/latency (smaller = no one frame hogs the wire too long) and
buffer cost in 1980s hardware. It stuck, and now the whole internet is effectively tuned around it
(MSS 1460 = 1500 − 40). Jumbo frames (9000) exist in data centers but don't survive the public path.

### AY.2 — What actually happens to a packet at a router?
Strip L2 header → look up the destination IP (longest-prefix match) → decrement TTL → recompute the
IP header checksum (incrementally, §R.7) → wrap in a new L2 header for the next hop → forward. It
does *not* touch L4 (TCP/UDP) — that's end-to-end. NAT routers are the exception (they rewrite
addresses/ports and fix checksums).

### AY.3 — Why doesn't IP guarantee delivery?
By design (end-to-end principle, §M.2): a simple, stateless core scales and survives failures;
reliability is expensive and only some apps want it, so it lives at the endpoints (TCP) where it can
be added or skipped (UDP). Pushing reliability into every router would make the core complex,
stateful, and slow.

### AY.4 — How does the OS know which app gets a received packet?
Demultiplexing by the 4-tuple (TCP/UDP) or protocol (ICMP). The kernel maps `(proto, src ip, src
port, dst ip, dst port)` to a socket. Our `Quad` + connection table is exactly this demultiplexing
for TCP, done by hand.

### AY.5 — What's the difference between a "packet," "segment," "datagram," "frame"?
Loose but conventional: **frame** = L2 (Ethernet) unit; **packet** = L3 (IP) unit; **segment** =
L4 TCP unit; **datagram** = L4 UDP unit (and "IP datagram" for L3). People say "packet" for
everything informally; precise speech uses the layer-specific term.

### AY.6 — Could I run two instances of this stack?
Not on the same `tun0` (ResourceBusy). You'd create `tun1` with a different subnet, or use network
namespaces (`ip netns`) to give each its own isolated stack — which is, incidentally, how containers
get separate networking.

---

## AZ. Closing note — the one habit to carry forward

You have, in Doc 1, gone from "a packet is an opaque wall of numbers" to "I can read any IPv4/ICMP
header on sight, decode it by hand, write the parser that does it safely, compute its checksum, and
explain where every field came from and why." Volume I gave you the working narrative; Volume II
made you not need it.

If you keep one thing, keep this: **look at the bytes.** Every concept in this book — endianness,
the header layout, the checksum, the handshake, the state machine — is ultimately a claim about a
specific sequence of bytes on the wire, and every one of those claims is checkable in seconds with
`tcpdump -X`, a hex dump, and the field tables you now know. The engineers who are fast at networks
are not the ones who memorized the most; they are the ones who, when confused, *immediately look at
the actual bytes* instead of theorizing. That single reflex — paired with "guard then parse" and
"big-endian at the boundary" — is the whole craft in miniature.

Now do the thing that converts reading into knowing: **re-type `utils.rs`, `ip.rs`, and `icmp.rs`
from memory with this book closed, run `cargo test`, and make an Anki card from every line you had
to peek at.** Then turn to doc2-book.md, where the bytes start flowing the other way — and you write
your first packet onto the wire.

— End of Doc 1 (Volume I + Volume II). On to Doc 2.

---
---

# VOLUME III — Reference Tables (Appendix)

> Lookup material to keep beside you while reading hex dumps. These are the tables you'll consult
> for the rest of the project; memorize the bold rows.

## RT.1 — Powers of two

| n | 2ⁿ | n | 2ⁿ |
|---|-----|---|-----|
| 0 | 1 | 16 | 65,536 |
| 1 | 2 | 17 | 131,072 |
| 2 | 4 | 18 | 262,144 |
| 3 | 8 | 19 | 524,288 |
| 4 | 16 | 20 | 1,048,576 |
| 5 | 32 | 21 | 2,097,152 |
| 6 | 64 | 22 | 4,194,304 |
| 7 | 128 | 23 | 8,388,608 |
| **8** | **256** | 24 | 16,777,216 |
| 9 | 512 | 25 | 33,554,432 |
| **10** | **1,024** | 26 | 67,108,864 |
| 11 | 2,048 | 27 | 134,217,728 |
| 12 | 4,096 | 28 | 268,435,456 |
| 13 | 8,192 | 29 | 536,870,912 |
| 14 | 16,384 | 30 | 1,073,741,824 |
| 15 | 32,768 | **32** | **4,294,967,296** |

Key rows: 2⁸ = 256 (values in a byte), 2¹⁶ = 65,536 (a 16-bit field; ports; window), 2³² ≈ 4.29
billion (IPv4 address space; TCP sequence space — both wrap here).

## RT.2 — Subnet / prefix reference (IPv4)

| Prefix | Netmask | Addresses | Usable hosts |
|--------|---------|-----------|--------------|
| /8 | 255.0.0.0 | 16,777,216 | 16,777,214 |
| /16 | 255.255.0.0 | 65,536 | 65,534 |
| /20 | 255.255.240.0 | 4,096 | 4,094 |
| /21 | 255.255.248.0 | 2,048 | 2,046 |
| /22 | 255.255.252.0 | 1,024 | 1,022 |
| /23 | 255.255.254.0 | 512 | 510 |
| **/24** | **255.255.255.0** | **256** | **254** |
| /25 | 255.255.255.128 | 128 | 126 |
| /26 | 255.255.255.192 | 64 | 62 |
| /27 | 255.255.255.224 | 32 | 30 |
| /28 | 255.255.255.240 | 16 | 14 |
| /29 | 255.255.255.248 | 8 | 6 |
| **/30** | **255.255.255.252** | **4** | **2** |
| /31 | 255.255.255.254 | 2 | 2 (RFC 3021 p2p) |
| /32 | 255.255.255.255 | 1 | 1 (single host) |

"Magic number" = 256 − last mask octet = the subnet block size in that octet (§AL.8). Usable =
addresses − 2 (network + broadcast), except /31 and /32.

## RT.3 — IP protocol numbers (the ones you'll meet)

| # | Protocol | # | Protocol |
|---|----------|---|----------|
| 0 | HOPOPT (IPv6 hop-by-hop) | 50 | ESP (IPsec) |
| **1** | **ICMP** | 51 | AH (IPsec) |
| 2 | IGMP | 58 | ICMPv6 |
| 4 | IPv4 (encapsulation) | 59 | IPv6-NoNxt |
| **6** | **TCP** | 60 | IPv6 destination options |
| 8 | EGP | 88 | EIGRP |
| 9 | IGP | 89 | OSPF |
| 17 | **UDP** | 103 | PIM (multicast) |
| 41 | IPv6 (6in4) | 112 | VRRP |
| 43 | IPv6-Route | 115 | L2TP |
| 44 | IPv6-Frag | 132 | SCTP |
| 47 | GRE | 137 | MPLS-in-IP |

Byte 9 of the IPv4 header. We dispatch 1/6/17; the rest are "unknown" to us.

## RT.4 — ICMP types and codes (IPv4)

| Type | Code | Meaning |
|------|------|---------|
| **0** | 0 | **Echo Reply (pong)** |
| 3 | 0 | Net Unreachable |
| 3 | 1 | Host Unreachable |
| 3 | 2 | Protocol Unreachable |
| **3** | **3** | **Port Unreachable** |
| 3 | 4 | Fragmentation Needed, DF set (PMTUD) |
| 3 | 5 | Source Route Failed |
| 3 | 9/10 | Net/Host Administratively Prohibited |
| 3 | 13 | Communication Administratively Prohibited |
| 4 | 0 | Source Quench (deprecated) |
| 5 | 0/1 | Redirect (network/host) |
| **8** | 0 | **Echo Request (ping)** |
| 9/10 | 0 | Router Advertisement / Solicitation |
| **11** | **0** | **Time Exceeded in transit (traceroute)** |
| 11 | 1 | Fragment reassembly time exceeded |
| 12 | 0 | Parameter Problem (bad header) |
| 13/14 | 0 | Timestamp Request / Reply |

First two bytes of the ICMP message. Errors (3, 11, 12) also carry the offending IP header + 8 bytes.

## RT.5 — Well-known ports (TCP/UDP)

| Port | Service | Port | Service |
|------|---------|------|---------|
| 7 | echo | 161/162 | SNMP |
| 20/21 | FTP data/control | 179 | BGP |
| 22 | SSH | 389 | LDAP |
| 23 | Telnet | 443 | **HTTPS** |
| 25 | SMTP | 445 | SMB |
| **53** | **DNS** | 514 | syslog |
| 67/68 | **DHCP** (server/client) | 587 | SMTP submission |
| 69 | TFTP | 853 | DNS-over-TLS |
| **80** | **HTTP** | 993 | IMAPS |
| 110 | POP3 | 995 | POP3S |
| 123 | NTP | 3306 | MySQL |
| 137-139 | NetBIOS | 5432 | PostgreSQL |
| 143 | IMAP | 6379 | Redis |
| 161 | SNMP | 8080 | HTTP-alt (our lab) |

Ports 0–1023 are "well-known" (privileged); 1024–49151 registered; 49152–65535 ephemeral (the
range clients pick source ports from).

## RT.6 — Protocol field maximums (know your widths)

| Field | Bits | Max value | Notes |
|-------|------|-----------|-------|
| IP version / IHL | 4 / 4 | 15 / 15 | IHL max = 60-byte header |
| IP Total Length | 16 | 65,535 | whole datagram |
| IP TTL | 8 | 255 | hop budget |
| IP fragment offset | 13 | 8,191 | ×8 = 65,528 byte range |
| Port (TCP/UDP) | 16 | 65,535 | source/dest |
| TCP seq / ack | 32 | 4,294,967,295 | wraps (mod 2³²) |
| TCP data offset | 4 | 15 | ×4 = 60-byte header |
| TCP window (unscaled) | 16 | 65,535 | scale option extends it |
| Checksum (all) | 16 | 65,535 | one's-complement |

When a value can exceed a field's max, there's an option or a different mechanism (window scaling,
fragmentation) — the max tells you where those exist.

## RT.7 — ASCII (the printable range, 32–126)

Useful for reading payloads in hex dumps (`-X`). Dec / Hex / Char:

```
32 20 (space)  48 30 0   64 40 @   80 50 P   96 60 `   112 70 p
33 21 !        49 31 1   65 41 A   81 51 Q   97 61 a   113 71 q
34 22 "        50 32 2   66 42 B   82 52 R   98 62 b   114 72 r
35 23 #        51 33 3   67 43 C   83 53 S   99 63 c   115 73 s
36 24 $        52 34 4   68 44 D   84 54 T  100 64 d   116 74 t
37 25 %        53 35 5   69 45 E   85 55 U  101 65 e   117 75 u
38 26 &        54 36 6   70 46 F   86 56 V  102 66 f   118 76 v
39 27 '        55 37 7   71 47 G   87 57 W  103 67 g   119 77 w
40 28 (        56 38 8   72 48 H   88 58 X  104 68 h   120 78 x
41 29 )        57 39 9   73 49 I   89 59 Y  105 69 i   121 79 y
42 2a *        58 3a :   74 4a J   90 5a Z  106 6a j   122 7a z
43 2b +        59 3b ;   75 4b K   91 5b [  107 6b k   123 7b {
44 2c ,        60 3c <   76 4c L   92 5c \  108 6c l   124 7c |
45 2d -        61 3d =   77 4d M   93 5d ]  109 6d m   125 7d }
46 2e .        62 3e >   78 4e N   94 5e ^  110 6e n   126 7e ~
47 2f /        63 3f ?   79 4f O   95 5f _  111 6f o
```
Control chars (0–31) and DEL (127) are non-printing; tcpdump shows them as `.` in the ASCII column.
Key ones: 0x0D = CR (`\r`), 0x0A = LF (`\n`) — HTTP lines end in `\r\n` = `0d 0a`. "hi" = `68 69`.

## RT.8 — Common hex bytes you'll recognize in packets

| Byte | Meaning in context |
|------|--------------------|
| `45` | IPv4, 20-byte header (first byte of most IP packets) |
| `00` | DSCP/ECN 0; also padding |
| `40` | IP flags = DF (in byte 6); also TTL 64 (byte 8) |
| `01` `06` `11` | protocol ICMP / TCP / UDP (byte 9) |
| `c0 a8` | `192.168` (private address prefix) |
| `0a` | `10.` (private); also LF |
| `ac 1?` | `172.16–31` (private) |
| `08 00` | ICMP echo request (type/code); also EtherType IPv4 |
| `00 00` | ICMP echo reply (type/code) |
| `02` `12` `10` `18` `11` `04` | TCP flags SYN / SYN-ACK / ACK / PSH-ACK / FIN-ACK / RST |
| `50` | TCP data offset 5 words (20-byte header), in byte 12 |
| `1f 90` | port 8080; `00 50` = 80; `00 35` = 53 |

These are the at-a-glance anchors that let you skim a hex dump and know what you're looking at
without decoding every field.

---

## RT.9 — Binary / hex / decimal for byte values 0–63

The conversion drill made into a lookup. (Values 64–255 follow the same pattern with the top two
bits set; the low 6 bits repeat this table.)

```
dec hex binary       dec hex binary       dec hex binary       dec hex binary
 0  00  00000000     16  10  00010000     32  20  00100000     48  30  00110000
 1  01  00000001     17  11  00010001     33  21  00100001     49  31  00110001
 2  02  00000010     18  12  00010010     34  22  00100010     50  32  00110010
 3  03  00000011     19  13  00010011     35  23  00100011     51  33  00110011
 4  04  00000100     20  14  00010100     36  24  00100100     52  34  00110100
 5  05  00000101     21  15  00010101     37  25  00100101     53  35  00110101
 6  06  00000110     22  16  00010110     38  26  00100110     54  36  00110110
 7  07  00000111     23  17  00010111     39  27  00100111     55  37  00110111
 8  08  00001000     24  18  00011000     40  28  00101000     56  38  00111000
 9  09  00001001     25  19  00011001     41  29  00101001     57  39  00111001
10  0a  00001010     26  1a  00011010     42  2a  00101010     58  3a  00111010
11  0b  00001011     27  1b  00011011     43  2b  00101011     59  3b  00111011
12  0c  00001100     28  1c  00011100     44  2c  00101100     60  3c  00111100
13  0d  00001101     29  1d  00011101     45  2d  00101101     61  3d  00111101
14  0e  00001110     30  1e  00011110     46  2e  00101110     62  3e  00111110
15  0f  00001111     31  1f  00011111     47  2f  00101111     63  3f  00111111
```

To extend past 63: bit 6 (value 64) and bit 7 (value 128) are the top two; e.g. 0x45 = 69 =
64 + 5 = `01000101`, and 0xC0 = 192 = 128 + 64 = `11000000`. Every byte is one of these 64 low
patterns plus the two high bits.

## RT.10 — Acronyms, expanded

- **ACK** Acknowledgement · **AIMD** Additive-Increase Multiplicative-Decrease · **ARP** Address
  Resolution Protocol · **ARPANET** Advanced Research Projects Agency Network
- **BGP** Border Gateway Protocol · **BPF** Berkeley Packet Filter · **BSD** Berkeley Software
  Distribution
- **CIDR** Classless Inter-Domain Routing · **CRC** Cyclic Redundancy Check · **CWND** Congestion
  Window
- **DF** Don't Fragment · **DHCP** Dynamic Host Configuration Protocol · **DNS** Domain Name System
  · **DSCP** Differentiated Services Code Point
- **ECN** Explicit Congestion Notification · **EOL** End Of Option List
- **FIN** Finish · **FQDN** Fully Qualified Domain Name
- **GRO/GSO/TSO** Generic Receive / Generic Segmentation / TCP Segmentation Offload
- **ICMP** Internet Control Message Protocol · **IETF** Internet Engineering Task Force · **IHL**
  Internet Header Length · **IP** Internet Protocol · **IRS/ISS/ISN** Initial Receive/Send Sequence
  Number
- **MAC** Media Access Control · **MF** More Fragments · **MSS** Maximum Segment Size · **MTU**
  Maximum Transmission Unit
- **NAT/NAPT** Network Address (and Port) Translation · **NIC** Network Interface Card · **NAPI**
  New API (Linux polling)
- **OSI** Open Systems Interconnection
- **PAT** Port Address Translation · **PMTUD** Path MTU Discovery · **PSH** Push
- **QoS** Quality of Service · **QUIC** (a name, not an acronym — a UDP-based transport)
- **RFC** Request For Comments · **RST** Reset · **RTO** Retransmission TimeOut · **RTT** Round-Trip
  Time · **RCV.NXT/WND** Receive Next/Window
- **SACK** Selective Acknowledgement · **SND.UNA/NXT/WND** Send Unacknowledged/Next/Window · **SYN**
  Synchronize
- **TCB** Transmission Control Block · **TCP** Transmission Control Protocol · **TLV**
  Type-Length-Value · **TTL** Time To Live · **TUN/TAP** network TUNnel / network TAP
- **UDP** User Datagram Protocol · **URG** Urgent
- **WSL** Windows Subsystem for Linux

## RT.11 — RFC index (every RFC referenced in this book)

| RFC | Title | Where cited |
|-----|-------|-------------|
| 768 | User Datagram Protocol | §AO |
| 791 | Internet Protocol (IPv4) | §E, §5 |
| 792 | Internet Control Message Protocol | §H, §10 |
| 793 | Transmission Control Protocol (obsoleted by 9293) | §M.5, doc3 |
| 826 | Address Resolution Protocol | arp.rs note |
| 1034/1035 | Domain Names (DNS) | §AQ.1 |
| 1071 | Computing the Internet Checksum | §R, doc2 |
| 1122 | Requirements for Internet Hosts | §K.2 |
| 1191 | Path MTU Discovery | §E.7, §AC |
| 1518/1519 | CIDR (obsoleted by 4632) | §AG |
| 1624 | Incremental checksum update | §R.7 |
| 1631 | The IP Network Address Translator | §AG |
| 1700 | Assigned Numbers (endianness/"network order") | §D |
| 1918 | Address Allocation for Private Internets | §E.12, §AA.7 |
| 2119 | Key words: MUST/SHOULD/MAY | §K.2, §M.5 |
| 2131 | Dynamic Host Configuration Protocol | §AQ.2 |
| 2474 | Definition of the DiffServ Field (DSCP) | §E.4 |
| 3021 | Using /31 prefixes on point-to-point links | RT.2 |
| 3168 | The Addition of ECN to IP | §E.4 |
| 3514 | The Security Flag ("evil bit", April 1) | §E.7 |
| 4443 | ICMPv6 | §H.8 |
| 4632 | CIDR (current) | §AA.3 |
| 5681 | TCP Congestion Control | §AM.2 |
| 5961 | Improving TCP's Robustness to Blind Attacks | §AR.13 |
| 6298 | Computing TCP's Retransmission Timer | §AI.4 |
| 6528 | Defending against Sequence Number Attacks (ISN) | §11, doc3 |
| 6633 | Deprecation of ICMP Source Quench | §H.6 |
| 8200 | Internet Protocol, Version 6 | §M.6 |
| 8312 | CUBIC | §AM.2 |
| 9000 | QUIC | §AG |
| 9293 | Transmission Control Protocol (current) | doc3–5 |
| 9438 | CUBIC (updated) | §Z |

---

## RT.12 — Linux networking command cheat-sheet

```bash
# interface
ip addr / ip a                      # list interfaces + addresses
ip addr add 192.168.0.1/24 dev tun0 # assign address (creates connected route)
ip link set tun0 up|down            # bring interface up/down
ip link delete tun0                 # remove (fixes ResourceBusy)
ip -s link show tun0                # interface stats (rx/tx counts, errors)
# routing
ip route / ip r                     # routing table
ip route get 192.168.0.2            # which route/interface a destination uses
# neighbors (L2; not on TUN, but on real links)
ip neigh                            # ARP/NDP cache
# diagnostics
ping -c N host ; ping -s SIZE host  # ICMP echo, N packets / SIZE payload
traceroute host ; tracepath host    # path discovery (TTL trick)
ss -tunlp                           # sockets: tcp/udp, listening, with PIDs
nc [-u] host port ; nc -l port      # connect / listen (TCP or -u UDP)
# capture
tcpdump -i tun0 -n -vv -X [filter]  # capture+decode+hex (filter e.g. 'tcp port 8080')
tcpdump -i tun0 -w f.pcap ; -r f.pcap
# kernel
modprobe tun                        # load the TUN module
sysctl net.ipv4.ip_forward          # is forwarding on?
cat /proc/net/dev                   # per-interface counters
```

## RT.13 — Doc 1 in 100 facts (rapid review)

1. A packet is just bytes; a stack reads bytes, interprets headers, writes bytes.
2. TUN is an L3 virtual interface delivering IP packets to a userspace fd.
3. `read(tun_fd)` = receive a packet; `write(tun_fd)` = inject one.
4. TAP is the L2 sibling (Ethernet frames); we use TUN.
5. On TUN, byte 0 of the buffer is the IP header (no Ethernet).
6. `Iface::new` prepends a 4-byte packet-info header; `without_packet_info` doesn't.
7. The PI header is 2 bytes flags + 2 bytes EtherType (0x0800=IPv4).
8. If version parses as 0, you forgot IFF_NO_PI.
9. Creating tun0 needs CAP_NET_ADMIN.
10. `setcap cap_net_admin=eip` grants it to a binary (least privilege).
11. setcap needs native-fs xattrs; it fails on /mnt/c (DrvFs).
12. Rebuilding wipes the capability; re-run setcap each time.
13. `recv` blocks until a packet arrives (0% CPU while waiting).
14. The receive buffer is MTU(1500)+slack; reused each loop (no per-packet alloc).
15. IPv4 header is min 20 bytes (RFC 791).
16. Byte 0 = version (high nibble) + IHL (low nibble).
17. Version 4 = IPv4; reject anything else.
18. IHL counts 32-bit words; ×4 = header bytes; 5 = 20 bytes.
19. Payload starts at IHL×4, not always 20 (IP options).
20. Byte 1 = DSCP (QoS) + ECN (congestion), ignored by us.
21. Bytes 2–3 = Total Length (whole datagram), big-endian, max 65535.
22. Bytes 4–5 = Identification (fragment group id).
23. Byte 6 top 3 bits = flags: reserved, DF, MF.
24. DF + ICMP "frag needed" drive Path MTU Discovery.
25. Bytes 6–7 low 13 bits = fragment offset (×8 bytes).
26. Byte 8 = TTL; each router decrements; 0 ⇒ drop + ICMP Time Exceeded.
27. TTL 64 = Linux/macOS default; 128 = Windows.
28. Traceroute sends TTL 1,2,3… to map hops via Time Exceeded.
29. Byte 9 = protocol: 1 ICMP, 6 TCP, 17 UDP.
30. Bytes 10–11 = IP header checksum (header only).
31. Bytes 12–15 = source IP; 16–19 = destination IP.
32. `0xc0a8` = 192.168 (private prefix).
33. Multi-byte fields are big-endian (network byte order).
34. Read with `from_be_bytes`; write with `to_be_bytes`.
35. `from_ne_bytes` is the silent byte-swap bug on x86/ARM.
36. Endianness names come from Gulliver's Travels (Cohen 1980).
37. Single bytes have no endianness.
38. One hex digit = one nibble = 4 bits; a byte = 2 hex digits.
39. 0x45 = version 4, IHL 5 — the first byte of most IP packets.
40. Extract a field: `(value >> shift) & mask`.
41. `>> 4` gets the high nibble; `& 0x0f` gets the low.
42. Build a byte: `(hi << 4) | lo` — reading is mask, writing is OR.
43. A slice `&[u8]` is a borrowed (ptr, len) view; zero-copy.
44. Indexing past the end panics; guard length first.
45. Guard then index: one check up front makes the rest panic-free.
46. A panic on hostile input is a denial of service (Heartbleed class).
47. `Result` for multiple failure causes; `Option` for one.
48. Enums are sum types; `match` is exhaustive.
49. `?` propagates errors; `main` returns `io::Result<()>`.
50. `&'static str` for fixed labels (no allocation).
51. ICMP (RFC 792) is the control/diagnostic plane; protocol 1; no ports.
52. ICMP message = type, code, checksum, then type-specific body.
53. Echo Request = type 8; Echo Reply = type 0.
54. ICMP id matches replies to the sending process; seq increments.
55. ICMP checksum covers the whole message; no pseudo-header.
56. Ping = send Echo Request, time the matching Echo Reply.
57. Doc 1 ping = 100% loss (we parse, don't reply).
58. Dest Unreachable = type 3; Port Unreachable = code 3.
59. Time Exceeded = type 11 (traceroute).
60. ICMP errors carry the offending IP header + 8 bytes.
61. Internet checksum (RFC 1071) = one's-complement 16-bit sum.
62. Sum 16-bit BE words in a u32; fold carries; bitwise NOT.
63. End-around carry makes it addition mod 65535.
64. Zero the checksum field before computing.
65. A valid header checksums (incl. the field) to 0.
66. It's weak: misses canceling errors and word reorderings.
67. One's complement = invert bits (checksum); two's complement = invert+1 (signed ints).
68. Packet fields are unsigned (u8/u16/u32).
69. TCP seq numbers are 32-bit and wrap (use wrapping_add).
70. SYN and FIN each consume one sequence number.
71. TCP ACK is cumulative: "next byte I expect."
72. The 4-tuple (src ip/port, dst ip/port) identifies a connection.
73. The TCB holds SND.UNA/NXT/WND and RCV.NXT/WND.
74. Three-way handshake: SYN / SYN-ACK / ACK.
75. TCP checksum covers a pseudo-header (IPs, proto, length) + segment.
76. TCP data offset = header length in 32-bit words (byte 12 high nibble).
77. Flag byte: URG ACK PSH RST SYN FIN (bits 5..0).
78. 0x02=SYN, 0x12=SYN-ACK, 0x10=ACK, 0x18=PSH-ACK, 0x11=FIN-ACK, 0x04=RST.
79. ESTABLISHED is where data flows; teardown is FIN→…→CLOSED.
80. TIME_WAIT (2·MSL) is on the active closer.
81. Our stack: passive open/close, in-order data, fixed window, ISS=0.
82. Retransmission needs timers → needs a non-blocking event loop.
83. Flow control protects the receiver (advertised window).
84. Congestion control protects the network (cwnd, AIMD).
85. UDP (RFC 768) = 8-byte header, no state; the contrast to TCP.
86. DNS resolves names→IPs (usually UDP 53) before any IP packet.
87. DHCP (UDP 67/68, DORA) hands out address/gateway/DNS.
88. A connected route (192.168.0.0/24 dev tun0) makes .2 "ours".
89. Routing uses longest-prefix match.
90. Private addresses (RFC 1918) need NAT to reach the internet.
91. No ARP on TUN (L3); ARP is L2 (TAP only).
92. CIDR /n: top n bits network; block size = 256 − mask octet.
93. /24 = 256 addrs (254 hosts); /30 = 4 (2); /32 = one host.
94. tcpdump/Wireshark are the ground truth; compare three views.
95. Test pure functions offline (cargo test, no sudo/TUN).
96. Differential test against etherparse; silence = agreement.
97. Fuzz the parser; the guards are what make it pass.
98. Modules mirror layers: utils→ip→icmp/tcp→main.
99. The rhythm: parse header → decide on a key field → maybe build a reply.
100. The habit: when confused, look at the actual bytes.

## RT.14 — Mastery checklist (can you do each, book closed?)

- [ ] Decode any IPv4 header from hex, every field.
- [ ] Explain version/IHL nibble extraction with bit ops.
- [ ] State why payload starts at IHL×4.
- [ ] Convert any byte between binary/hex/decimal.
- [ ] Explain big-endian and use from_be_bytes correctly.
- [ ] Re-type `ip::parse` with both length guards.
- [ ] Re-type `utils::checksum` and explain end-around carry.
- [ ] Compute an IP header checksum by hand and verify to 0.
- [ ] Decode any ICMP type/code; explain ping and traceroute.
- [ ] Re-type `icmp::build_echo_reply` (the four edits + two checksums).
- [ ] Explain why Doc-1 ping is 100% loss and Doc-2 is 0%.
- [ ] Walk the three-way handshake's seq/ack numbers (the two +1s).
- [ ] Explain the TCP pseudo-header and why it includes the IPs.
- [ ] Produce the full §AP connection trace from a blank page.
- [ ] Name the architectural change that unblocks retransmission, and why.
- [ ] Read a live capture in tcpdump and identify every packet.
- [ ] State the two invariants: guard-then-parse; big-endian at the boundary.

When every box is checked, Doc 1 is yours — not read, *owned*.

---

## RT.15 — Bridge to Doc 2

Doc 1 was the **read + interpret** half of "bytes in, bytes out": you can now receive a packet and
understand every field. Doc 2 begins the **write** half and introduces the one piece of arithmetic
shared by every layer.

What carries forward directly:
- **The checksum** (here previewed in §R as math, and in `utils` as code) becomes the centerpiece of
  Doc 2 — first computed, then used to make a *valid* reply the kernel won't drop.
- **`build_echo_reply`'s four edits** (§5, §L.2) are your first packet construction; the technique
  (lay out bytes, fix checksums last with the field zeroed, big-endian throughout) is reused for
  every packet in docs 3–5.
- **The two invariants** (guard-then-parse; big-endian at the boundary) apply unchanged.
- **The toolchain and habits** (cargo test offline, tcpdump for truth, re-type to retain) are the
  same every day.

What's new in Doc 2:
- The **Internet checksum** algorithm in full, with its own worked proofs (you have a head start
  from §R here).
- Your **first `iface.send`** — writing to the wire — and the satisfaction of `ping` finally
  replying with **0% loss**.
- The **modular refactor** (utils/ip/icmp) that the growing code now justifies.

Open `doc2-book.md` and continue. The bytes start flowing both ways.

---

*That completes Doc 1 in full — Volume I (narrative), Volume II (exhaustive reference, §A–§AZ),
Volume III (reference tables + rapid review, §RT). The deepest of the five books by design: it
carries the foundations the others build on. Docs 2–5 now receive the same Volume II/III expansion.
— Doc 1 complete (5,000+ lines).*
