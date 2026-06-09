# Day 3 — TCP, Part 1: The Three-Way Handshake

> Goal: when a client runs `nc 192.168.0.2 8080`, our stack answers its `SYN` with a `SYN-ACK`,
> accepts the client's `ACK`, and reaches **ESTABLISHED** — a real, open TCP connection. This is
> where the project gets hard, because unlike ICMP, **TCP has memory**: per-connection state (the
> TCB), sequence numbers, and a state machine. After this you can explain every number in a handshake
> and why three packets — not two, not four — are required.

This is the hinge of the whole project. Days 1–2 were *stateless*: parse a packet, maybe reply, forget
it. From here on TCP forces us to *remember* — and almost every later day (data transfer,
retransmission, flow/congestion control, options, SACK) is a refinement of the bookkeeping we set up
today. Read this one slowly.

**Contents**

Volume I — the chapter
1. Why TCP is a different kind of problem
2. The 4-tuple and the connection table
3. Sequence numbers — the central idea
4. The TCB — send and receive sequence spaces
5. The three-way handshake, number by number
6. The state machine (our subset)
7. Building a TCP segment from scratch
8. The TCP checksum and the pseudo-header
9. The Rust: types, ownership, error handling
10. The code, walked end to end
11. Verification
12. Why this, not that
13. Honesty: what production does that we don't
14. Rebuild it yourself — checklist + exercises
15. What the next step adds

Volume II — the exhaustive reference
- A. The TCP header, every field, exhaustively
- B. Sequence numbers and modular arithmetic, completely
- C. The full 11-state TCP state machine
- D. ISN selection and thirty years of attacks (RFC 6528)
- E. SYN floods and SYN cookies
- F. The pseudo-header checksum, worked byte by byte
- G. Active open, simultaneous open, and self-connect
- H. A complete annotated handshake trace (hex + TCB evolution)
- I. Comparison to real stacks — LISTEN, the accept queue, the backlog
- J. Security — the handshake as attack surface
- K. Performance notes
- L. Extended FAQ — thirty questions a careful reader asks
- M. Anki starter deck
- N. Glossary
- O. Reference tables

---

# Volume I — the chapter

## 1. Why TCP is a different kind of problem

ICMP (Day 2) was **stateless**: each packet was handled in isolation — see an echo request, send an
echo reply, forget everything. There was nothing to remember between packets. TCP is **stateful**. It
turns IP's unreliable, unordered, duplicating, best-effort packet delivery into a **reliable, ordered,
de-duplicated byte stream**, and the only way to do that is for both ends to *remember things across
packets*:

- what we've sent and what's been acknowledged,
- what we've received and what we expect next,
- which phase of its life the connection is in.

That memory is the **Transmission Control Block (TCB)** — one per connection. So our stack now needs
two things it never needed before: a **table** of TCBs (because many connections coexist) and a
**state machine** that advances each TCB as packets arrive. The handshake is the first, smallest, and
most carefully-numbered instance of all of this. Everything else is built on it.

A useful way to hold it: TCP is a *distributed agreement protocol*. Two machines that share no clock,
no memory, and an unreliable channel must nonetheless agree on a starting point for a conversation —
specifically, on each side's initial sequence number — before a single byte of data is trusted. The
three-way handshake is the minimal protocol that reaches that agreement and survives lost, duplicated,
and delayed packets.

## 2. The 4-tuple and the connection table

Many connections can exist at once: two browser tabs to the same server, a download and an SSH session
to the same host, ten clients to our one port 8080. TCP tells them apart by the **4-tuple**:

```text
   (source IP, source port, destination IP, destination port)
```

That 4-tuple uniquely identifies one connection. Two tabs from the same client differ in *source
port* (the OS picks a fresh ephemeral port per connection); two clients differ in *source IP*. We
model the tuple as:

```text
   Quad { remote: (IP, port),   // the packet's source = the client
          local:  (IP, port) }  // the packet's destination = us
```

and use it as the key of a `HashMap<Quad, Connection>`. Every incoming TCP segment is looked up:

- **found** → hand it to that connection's state machine (`on_segment`),
- **not found** → if it's a `SYN`, open a new connection (`accept`); otherwise it's a stray segment to
  a closed port, and the correct reply is a `RST` (we add that on Day 5; Day 3 simply ignores it).

`Quad` derives `Hash, Eq, Copy` so it can be a map key and passed by value freely; `Ipv4Addr` already
supports those. The direction convention (remote = source = client, local = destination = us) is worth
fixing in your head now, because *every* segment we build later swaps them — we send *from* `local`
*to* `remote`.

## 3. Sequence numbers — the central idea

Every byte in a TCP connection has a **32-bit sequence number**. This single idea is the engine of
reliability and ordering: numbering bytes lets the receiver detect what's **missing** (a gap in
numbers), what's a **duplicate** (a number already seen), and what's **reordered** (a number out of
order), and lets it acknowledge *exactly* how far it has received.

Four facts you must internalize:

1. **They are 32-bit and wrap around** (mod 2³²). After `0xFFFF_FFFF` comes `0`. All arithmetic uses
   `wrapping_add` so overflow is *defined*, not a panic, and comparisons use *modular* "is A before B"
   logic (RFC 1982 serial numbers — Day 3's `src/seq.rs`, expanded in §B). A connection that runs
   long enough genuinely wraps; the math must keep working across the seam.

2. **They do not start at 0 on the wire.** Each side picks a random **Initial Sequence Number (ISN)**
   and counts from there. Our deterministic tests use ISS = 0 for legibility; production randomizes
   (RFC 6528 — §D explains why a predictable ISN is a serious vulnerability).

3. **The ACK number is "the next sequence number I expect from you"** — a *cumulative* acknowledgement.
   `ACK = 101` means "I have everything up to and including byte 100; send me 101 next." One number
   summarizes everything received so far. (Day 18's SACK adds a *second* channel for the gaps this one
   can't express — but that's far ahead.)

4. **`SYN` and `FIN` each consume one sequence number**, even though they carry no data. This is why
   the handshake math has `+1` everywhere: a SYN with `seq = 100` is acknowledged with `ack = 101`,
   as if it were one byte. Think of SYN as the phantom byte "connection opens here" and FIN as
   "connection closes here" — both occupy a slot in the stream so their delivery is itself reliable.

## 4. The TCB — send and receive sequence spaces

RFC 9293 §3.3.1 splits the TCB's sequence bookkeeping into two halves — the bytes *we send* and the
bytes *we receive*. We mirror it exactly, because matching the RFC's names makes every later rule
read directly off the spec.

**Send Sequence Space** — about the bytes *we* send (`SendSequence`):

```text
        SND.UNA        SND.NXT
          │              │
   …──────┼──────────────┼────────►  sequence numbers
   acked  │  sent, not   │  usable (within SND.WND)
          │  yet acked   │
   ISS = our initial send sequence number
```

- `iss` — our initial send sequence number (the ISN we chose).
- `una` — **S**e**nd** **Una**cknowledged: the oldest sequence number we've sent that the peer hasn't
  acked yet. Everything below it is safely delivered.
- `nxt` — **S**e**nd** **N**e**xt**: the next sequence number we'll put on the wire.
- `wnd` — the peer's advertised receive window: how much it will let us have in flight (flow control,
  Day 8). It's a `u32` in our code because window scaling (Day 17) can stretch it past 64 KB.

The region `[UNA, NXT)` is "sent but not yet acknowledged" — the data we may have to **retransmit**
(Day 6). The region from `NXT` up to `UNA + WND` is what we may still send.

**Receive Sequence Space** — about the bytes *we* receive (`RecvSequence`):

```text
        RCV.NXT
          │
   …──────┼───────────────►  what we expect next; we'll accept up to RCV.WND beyond it
   IRS = peer's initial sequence number (learned from their SYN)
```

- `irs` — **I**nitial **R**eceive **S**equence number: the peer's ISN, learned from its SYN.
- `nxt` — **R**e**c**ei**v**e **N**e**xt**: the next sequence number we expect from the peer. This is
  exactly the ACK number we put in every segment we send.
- `wnd` — our receive window: how much we're willing to accept (a fixed 1024 for now; it's a `u16`
  because it's the raw value we advertise on the wire).

On a passive open, all of these are initialized from the incoming SYN (next section).

## 5. The three-way handshake, number by number

Using our test's numbers — **client ISN = 100, our ISS = 0**:

```text
   client (192.168.0.1)                         us (192.168.0.2)
        │                                            │
        │  ① SYN  seq=100                            │   we receive SYN:
        │ ─────────────────────────────────────────►│     RCV.IRS=100, RCV.NXT=101
        │                                            │     ISS=0, SND.UNA=0, SND.NXT=1
        │  ② SYN,ACK  seq=0  ack=101                 │   we send SYN-ACK, state=SYN_RCVD
        │ ◄─────────────────────────────────────────│     (our SYN consumes seq 0 → NXT=1)
        │                                            │
        │  ③ ACK  seq=101  ack=1                      │   we receive ACK of our SYN:
        │ ─────────────────────────────────────────►│     ack==SND.NXT(1) ⇒ ESTABLISHED
        │                                            │     SND.UNA=1
```

Why each number is what it is:

- **① The client's SYN carries `seq = 100`** (its ISN). The SYN consumes seq 100, so the next byte
  the client sends will be 101 — hence we set `RCV.NXT = 101`. We also record `RCV.IRS = 100` (the
  starting point of the peer's stream) and initialize *our* send space: `ISS = 0`, `SND.UNA = 0`,
  `SND.NXT = 1` (our SYN, which we're about to send, will consume seq 0).
- **② Our SYN-ACK carries our `seq = 0`** (our ISS) and **`ack = 101`** ("I received your SYN;
  I expect 101 next"). The SYN flag on this segment consumes our seq 0, so `SND.NXT = 1`. We move to
  **SYN_RCVD** (we've received their SYN and replied; we await the final ACK).
- **③ The client ACKs with `ack = 1`** ("I received your SYN; I expect 1 next"). Since `ack == SND.NXT`
  (1 == 1), our SYN is acknowledged → the connection is **ESTABLISHED**, and `SND.UNA = 1`.

**Why three packets, not two?** Each side must do two things: *announce* its own ISN and *learn and
confirm* the other's. Packet ① announces the client's ISN. Packet ② confirms ① and announces ours.
Packet ③ confirms ②. Two packets could confirm only one direction's ISN; three confirms both. This is
the minimum for two parties to agree on two numbers over an unreliable channel. (A subtle fourth case,
*simultaneous open*, where both send SYN at once, needs no extra packet type — §G.)

**Why bother agreeing on ISNs at all?** Because the network can deliver an *old* duplicate segment
from a previous connection on the same 4-tuple. Random, per-connection ISNs make it astronomically
unlikely that a stale segment's sequence number falls in the new connection's window, so the new
connection isn't poisoned by ghosts of the old one. (This is the same reason TIME_WAIT exists — Day 7.)

## 6. The state machine (our subset)

Full TCP has **eleven** states (the complete map is in §C). The passive-open path we implement *today*
is the smallest meaningful slice:

```text
   (no entry)  ──SYN arrives, send SYN-ACK──►  SYN_RCVD  ──valid ACK──►  ESTABLISHED
```

- **(no entry in the table)** is effectively LISTEN/CLOSED — every port is implicitly "listening,"
  because we open a TCB on any incoming SYN.
- **SYN_RCVD** — we've sent our SYN-ACK and await the client's ACK.
- **ESTABLISHED** — open; ready for data (Day 4).

`Connection::accept` creates the TCB and the SYN-ACK; `Connection::on_segment` drives
SYN_RCVD → ESTABLISHED. Later days add the teardown states (FIN_WAIT_1/2, CLOSING, CLOSE_WAIT,
LAST_ACK, TIME_WAIT) and the active-open state (SYN_SENT, via `connect`). The `State` enum in the code
already lists them all; today only two are reachable.

## 7. Building a TCP segment from scratch

For ICMP we *mutated* a received packet (flip the type, fix the checksum, send it back). TCP responses
are genuinely new packets, so `build_packet` **synthesizes** a full IPv4 + TCP packet from nothing — the
mirror image of parsing:

- **IPv4 header (20 B):** version/IHL `0x45`, total length, flags `0x4000` (Don't Fragment), TTL 64,
  protocol **6** (TCP), our source IP, the peer's destination IP, then `ip::write_header_checksum`.
- **TCP header (20 B + options):** source/dest ports, the 32-bit seq and ack, the **data offset**
  (header length in 32-bit words, in the high nibble of byte 12 — the TCP analogue of IHL), the flag
  byte, the window, then the checksum, then the urgent pointer (0).
- **payload** — none for a SYN-ACK; data arrives in Day 4.

The whole thing is `vec![0u8; total_len]` followed by field-by-field `copy_from_slice` of big-endian
bytes. Every multi-byte field goes out **most-significant byte first** (network byte order) — the
discipline drilled in Day 1 §7. (Every field of the TCP header is dissected in §A.)

## 8. The TCP checksum and the pseudo-header

The TCP checksum uses the same one's-complement `utils::checksum` (Day 2), but over more than the
segment: it covers a **pseudo-header** *plus* the TCP segment. The IPv4 pseudo-header is 12 bytes:

```text
   +--------------------+--------------------+
   |            Source IPv4 Address          |
   +--------------------+--------------------+
   |         Destination IPv4 Address        |
   +--------+-----------+--------------------+
   |  zero  | proto = 6 |     TCP length     |   (TCP length = TCP header + data)
   +--------+-----------+--------------------+
```

**Why include IP fields the TCP header doesn't even contain?** So that a segment delivered to the
wrong host or under the wrong protocol is detected: the checksum is *bound* to the addresses it was
meant for. It is a deliberate cross-layer integrity tie. The pseudo-header is **only an input to the
checksum** — it is never transmitted. As always, the checksum field must be zero while computing, and
a valid segment re-checksums (pseudo-header + segment) to 0 — which is exactly what our tests assert.
(§F works a full checksum out byte by byte.)

## 9. The Rust: types, ownership, error handling

The handshake introduces our first genuinely *stateful* types, so the ownership story matters:

- **`Quad` is `Copy`** — a tiny value type (two IP+port pairs) used as a map key and passed by value.
  Making it `Copy` means we never fight the borrow checker over "who owns the key."
- **`Connection` is owned by the `HashMap`.** `on_segment(&mut self, …)` borrows it mutably for the
  duration of handling one packet; the borrow ends when the function returns. This is why the event
  loop looks up the quad, mutates the connection, and gets back a `Vec<u8>` to send — the borrow
  doesn't escape.
- **Parsing returns `Option`/validated structs, never panics.** `tcp::parse` checks the data offset
  is in range before slicing; `accept` returns `Option<(Connection, Vec<u8>)>` — `None` when the
  segment isn't a SYN — so "can't open a connection from this" is a *value*, not a crash. Hostile or
  truncated input is handled, not trusted.
- **The two sequence-space structs are plain data** (`SendSequence`, `RecvSequence`). Splitting them
  out (rather than a flat pile of `u32`s on `Connection`) makes the code read like the RFC and keeps
  related fields together.

A note on `#[allow(dead_code)]`: `RecvSequence.irs` is stored but not yet *read* (we'll need it for
relative-sequence reporting later), so the struct carries the allow to keep the build warning-clean —
an honest "this exists for a reason that arrives later" marker rather than deleting and re-adding it.

## 10. The code, walked end to end

`src/tcp.rs`:

- **Flag constants** `SYN/ACK/FIN/RST/PSH/URG` — bit masks for byte 13 of the TCP header.
- **`Quad`** — the 4-tuple map key (§2).
- **`State`** — the connection state enum (today only `SynRcvd | Established` are reached).
- **`TcpHeader` + `parse`** — the 20-byte fixed header; `data_offset` is computed in *bytes* so the
  data start is simply `&segment[data_offset..]`. `parse` rejects a data offset below 20 or past the
  segment end.
- **`SendSequence` / `RecvSequence`** — the two halves of the TCB (§4).
- **`Connection`** — state + both sequence spaces + the two endpoints (plus, in later days, the retx
  queue, RTT estimator, reassembler, congestion controller, buffers).
  - **`accept` / `accept_with_iss[_at]`** — passive open: validate it's a SYN, initialize the TCB
    (ISS, `SND.NXT = ISS + 1`, `RCV.IRS = peer.seq`, `RCV.NXT = peer.seq + 1`), build and return the
    SYN-ACK. `accept` randomizes the ISN (RFC 6528); `accept_with_iss` takes a fixed one for tests.
  - **`on_segment`** — in SYN_RCVD, accept the ACK whose `ack == SND.NXT` → ESTABLISHED.
  - **`segment` / `segment_opts`** — build a packet from this connection's perspective (src = us,
    dst = peer), advertising *our* receive window.
- **`build_packet`** — synthesize IPv4 + TCP (§7).
- **`tcp_checksum`** — pseudo-header + segment one's-complement sum (§8).

`src/main.rs` keeps the `HashMap<Quad, Connection>` and dispatches: look up the quad → an existing
connection advances via `on_segment`; absent → a SYN opens one via `accept` and we send the SYN-ACK.

## 11. Verification

`cargo test` proves the handshake offline — no TUN, no sudo, no network. The TCP tests for this day:

- **`parses_syn`** — the 20-byte header decodes correctly (ports, seq, flags, `data_offset == 20`).
- **`accept_produces_valid_synack`** — the SYN-ACK has swapped addresses, flags `SYN|ACK`, `seq = ISS`
  (0), `ack = client_seq + 1` (101), and **both checksums verify to 0** (the IPv4 header checksum and
  the TCP+pseudo-header checksum). This single test exercises building, byte order, and both
  checksums at once.
- **`final_ack_reaches_established`** — feeding the client's ACK (`ack == SND.NXT`) moves the TCB to
  ESTABLISHED.
- **`ignores_non_syn_open`** — a stray ACK to a closed port does **not** open a connection (`accept`
  returns `None`).

Live (your hands): run the stack, then `nc 192.168.0.2 8080` from a second terminal. The log shows the
inbound `SYN`, "→ sent SYN-ACK (state SynRcvd)", then the client's `ACK` and "state now Established."
`nc` appears to connect (and stays open, since we don't close yet). With `sudo tcpdump -i tun0 -n` you
see all three packets and can read the seq/ack numbers exactly as drawn in §5.

## 12. Why this, not that

| Decision | We chose | Alternative | Why / caveat |
|---|---|---|---|
| ISN | fixed 0 in tests, random in `accept` | always random | 0 is debuggable; **production must randomize** (RFC 6528) — a predictable ISN enables off-path spoofing/injection (§D). |
| No-connection non-SYN | ignore (Day 3) | send RST | RST is the correct behavior; we add it on Day 5. |
| Connection key | `Quad{remote,local}` | a listener-socket abstraction | a real API has explicit listening sockets + an accept queue (§I); we go straight to per-flow TCBs. |
| SYN-flood defense | none | SYN cookies | a real server must resist half-open floods (§E); out of scope but essential to know. |
| Simultaneous open | not handled at Day 3 | full state machine | both-sides-SYN is rare; the code grows to handle it later (§G). |
| Receive window | fixed 1024 | dynamic, from buffer space | real flow control arrives on Day 8. |
| TCB layout | two RFC-named structs | flat fields | matching RFC 9293 §3.3.1 names makes later rules read off the spec. |

## 13. Honesty: what production does that we don't

- **LISTEN is implicit.** We open a TCB on *any* incoming SYN to *any* port. A real stack only accepts
  on ports an application has explicitly `listen()`ed, and RSTs the rest. (Exercise E3.)
- **No accept queue / backlog.** Real kernels keep a *SYN queue* (half-open) and an *accept queue*
  (established, waiting for `accept()`), each bounded (the `backlog`). We have neither. (§I.)
- **Fixed window, no buffers yet.** We advertise 1024 unconditionally; the real window tracks free
  receive-buffer space.
- **No options yet.** A real SYN carries MSS, window scale, SACK-permitted, timestamps — all added
  Days 15–18. Today's SYN-ACK is bare.
- **No RST, no PAWS, no challenge-ACK.** The defensive validations (RFC 5961) come much later.
- **ISN is a counter/0 in tests**, not the RFC 6528 keyed hash (§D).

None of these are bugs in the handshake *logic*; they're the breadth that turns a correct core into a
hardened server.

## 14. Rebuild it yourself — checklist + exercises

**Blank-file checklist** (write from memory, then check against the chapter):

- [ ] Define `Quad` and explain why it keys the connection table.
- [ ] State what `SND.UNA`, `SND.NXT`, and `RCV.NXT` mean, and how `accept` initializes them from a
      SYN.
- [ ] Walk the three-way handshake's seq/ack numbers and explain the two `+1`s (SYN consumes a seq).
- [ ] Build a TCP segment: ports, seq, ack, `data_offset = 5 << 4`, flags, window, then the
      pseudo-header checksum.
- [ ] Explain why the pseudo-header includes the IP addresses.
- [ ] Explain why three packets, not two.

**Exercises:**

- **E1.** Randomize the ISN (`rand::random::<u32>()`), confirm the handshake still works, and explain
  what attack this defends against (§D).
- **E2.** Send a **RST** when a non-SYN segment arrives for an unknown quad (build a segment with the
  RST flag and the correct seq/ack per RFC 9293 §3.5).
- **E3.** Add a `State::Listen` and only `accept` on specific local ports (e.g. 8080), RST-ing others —
  a step toward real listening sockets.
- **E4.** Write a test for sequence-number **wraparound**: ISS `0xFFFF_FFFF`; confirm `SND.NXT`
  becomes 0 via `wrapping_add`.
- **E5.** Implement **simultaneous open**: handle a SYN (no ACK) arriving while in SYN_SENT (§G), and
  test the SYN_RCVD path on both sides.
- **E6.** Add a **SYN-cookie** mode (§E): on SYN, don't allocate a TCB; encode the state in the ISN;
  reconstruct it from the final ACK. Discuss what you lose (options).

## 15. What the next step adds

Day 4 is **data transfer**: in ESTABLISHED, accept incoming data, advance `RCV.NXT`, send an **ACK**
for it, and — to prove it end to end — build a tiny **echo server** that sends the data back, verifiable
with `nc`. That brings *acceptance tests* on sequence numbers (in-window vs out-of-window), the `PSH`
flag, and sending data with correct seq/ack. After that: teardown (FIN/TIME_WAIT, Days 5 & 7) and
reliability (retransmission, Day 6).

---

# Volume II — the exhaustive reference

## A. The TCP header, every field, exhaustively

The fixed TCP header is 20 bytes; options extend it to at most 60. Every field, with its byte offset
within the TCP header:

```text
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |          Source Port          |       Destination Port        |   bytes 0–3
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        Sequence Number                         |   bytes 4–7
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Acknowledgment Number                       |   bytes 8–11
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Data |           |U|A|P|R|S|F|                               |
   | Offset| Reserved  |R|C|S|S|Y|I|            Window             |   bytes 12–15
   |       |           |G|K|H|T|N|N|                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Checksum            |         Urgent Pointer        |   bytes 16–19
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Options (0–40 bytes)        |   Padding     |   bytes 20…
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

```text
   field            bytes  bits  meaning / our handling
   ──────────────   ─────  ────  ──────────────────────────────────────────────
   Source Port      0–1    16    sender's port; for us-as-replier = our 8080
   Dest Port        2–3    16    receiver's port; for a client SYN = 8080
   Sequence Number  4–7    32    seq of the first data byte (or the SYN/FIN slot)
   Ack Number       8–11   32    next seq expected; valid only if ACK flag set
   Data Offset      12 hi  4     header length in 32-bit words (5–15 → 20–60 bytes)
   Reserved         12 lo  4     must be 0 (later: parts reused by ECN/NS)
   Flags            13     8     URG ACK PSH RST SYN FIN (low 6 bits)
   Window           14–15  16    receive window advertised by the sender
   Checksum         16–17  16    one's-complement over pseudo-header + segment
   Urgent Pointer   18–19  16    offset of urgent data; valid only if URG set
   Options          20…    0–40  MSS, window scale, SACK-perm, timestamps (Days 15–18)
```

The six flags (byte 13, low bits), most to least significant of the low six:

```text
   URG  0x20  urgent pointer is valid (almost never used today)
   ACK  0x10  acknowledgment number is valid (set on everything after the first SYN)
   PSH  0x08  "push" buffered data to the app promptly
   RST  0x04  reset — abort the connection
   SYN  0x02  synchronize sequence numbers — opens a connection
   FIN  0x01  no more data from the sender — half-close
```

Our `parse` reads byte 13 as the flag byte and tests bits with masks (`th.flags & SYN`). The **data
offset** is the high nibble of byte 12; we multiply by 4 to get a byte count, and reject anything below
20 (a header can't be shorter than its fixed part) or past the segment (a lie that would make us read
out of bounds).

## B. Sequence numbers and modular arithmetic, completely

Sequence numbers live on a circle of 2³² points. "Before" and "after" must be *modular*, because a
plain `<` mis-orders numbers across the wrap (is `0xFFFF_FFFF` before `0x0000_0001`? Yes — they're two
apart on the circle, but `<` says no). RFC 1982 ("Serial Number Arithmetic") defines the fix, which
`src/seq.rs` implements:

```text
   before(a, b)  ≜  (a − b) mod 2³²  has its top bit set   (a is in the "behind" half of b)
   after(a, b)   ≜  before(b, a)
   between(s,x,e) ≜  after(x, s) && !after(x, e)            (s < x ≤ e, the ACK-acceptability shape)
```

Worked: `before(0xFFFF_FFFF, 1)` → `(0xFFFF_FFFF − 1) = 0xFFFF_FFFE`, top bit set → **true** (the
big number is "before" the small one across the wrap). `before(1, 0xFFFF_FFFF)` → `(1 − 0xFFFF_FFFF)
= 2`, top bit clear → **false**. Exactly the wrap-aware ordering we need.

This is *why* `accept` uses `wrapping_add(1)` for `SND.NXT` and `RCV.NXT`: if the ISN is near the top
of the space, `+1` must wrap to 0, not panic on overflow. And it's why ACK acceptability later is
`between(SND.UNA, ack, SND.NXT)` rather than `SND.UNA < ack && ack <= SND.NXT`.

The two windows on the circle, drawn together:

```text
        SND.UNA       SND.NXT                 RCV.NXT
          │             │                        │
   ───────┼──ourstream──┼──►              ───────┼──peerstream──►
   acked  unacked   usable                 received   expected
```

A 32-bit space wraps after 4 GiB of one-directional data — reachable on a fast link, which is exactly
why timestamps + PAWS (Day 16) exist to disambiguate a wrapped sequence from an ancient duplicate.

## C. The full 11-state TCP state machine

Today we touch only CLOSED→(SYN_RCVD)→ESTABLISHED. The complete machine (RFC 9293 §3.3.2), so you see
where the handshake sits:

```text
                              +---------+
                              | CLOSED  |
                              +---------+
                   passive open │   │ active open (send SYN)
                                ▼   ▼
                           +--------+    +-----------+
                           | LISTEN |    | SYN_SENT  |
                           +--------+    +-----------+
                  recv SYN /    │              │  recv SYN,ACK / send ACK
                  send SYN,ACK  ▼              ▼
                           +-----------+   +-------------+
                           | SYN_RCVD  |──►| ESTABLISHED |
                           +-----------+   +-------------+
                                            │         │
                          (we close) send FIN│         │recv FIN / send ACK
                                            ▼         ▼
                                   +-----------+   +------------+
                                   | FIN_WAIT_1|   | CLOSE_WAIT |
                                   +-----------+   +------------+
                                   │      │              │ (app closes) send FIN
                            recv ACK│      │recv FIN      ▼
                                   ▼      ▼          +-----------+
                            +---------+ +--------+   | LAST_ACK  |
                            |FIN_WAIT2| |CLOSING |   +-----------+
                            +---------+ +--------+         │ recv ACK
                            recv FIN│     │recv ACK        ▼
                                   ▼     ▼            +---------+
                                +-----------+         | CLOSED  |
                                | TIME_WAIT |────────►+---------+
                                +-----------+  2·MSL timeout
```

- **The handshake** is the top half: CLOSED → (LISTEN | SYN_SENT) → SYN_RCVD → ESTABLISHED.
- **The teardown** is the bottom half (Days 5 & 7): four-way close with FIN_WAIT/CLOSE_WAIT/CLOSING,
  ending in TIME_WAIT's 2·MSL linger.
- Our code's `State` enum names all of these; only the handshake half is reachable at Day 3.

## D. ISN selection and thirty years of attacks (RFC 6528)

Why does the ISN have to be *random*? Because if an off-path attacker can **predict** your ISN, they
can forge a complete connection or inject data into an existing one *without ever seeing your packets*:

- **Predictable-ISN spoofing (the Morris/Mitnick lineage).** Early BSD incremented the ISN by a fixed
  amount on a timer. An attacker probes your ISN, predicts the next, and sends a SYN *spoofed* from a
  trusted host's IP, then the matching ACK with the predicted ISN+1 — completing a handshake they
  can't see the replies to, and issuing commands as the trusted host. This is essentially how Kevin
  Mitnick attacked Tsutomu Shimomura's machines in 1994.
- **Blind data injection.** Even into an established connection, a guessed sequence number lets an
  attacker inject bytes (or a RST to tear it down).

The fix, **RFC 6528**, makes the ISN a *keyed hash*:

```text
   ISN = M + F(localIP, localPort, remoteIP, remotePort, secret_key)
```

where `M` is a 4-µs timer (so a re-used 4-tuple still gets a fresh, monotonically-rising ISN, which
TIME_WAIT relies on) and `F` is a cryptographic hash keyed by a per-boot secret. The 4-tuple
dependence means each connection's ISN is independent and *unpredictable* to anyone who doesn't know
the secret, while the timer term preserves the "ISNs rise over time" property the protocol needs.

Our `accept` uses `rand::random::<u32>()` — unpredictable, which is the security property that matters;
it omits the timer term (so we don't get the monotonic-per-4-tuple guarantee, but our tests and peers
don't need it). `accept_with_iss` pins the ISN for deterministic tests. Never ship a counter.

## E. SYN floods and SYN cookies

The handshake has a built-in asymmetry an attacker exploits: when a SYN arrives, the server allocates
a TCB and replies with a SYN-ACK, then waits in SYN_RCVD for the final ACK. A **SYN flood** sends many
SYNs (often from spoofed source IPs) and never completes them, filling the server's *half-open* table
until it can accept no new connections — a classic DoS.

**SYN cookies** defend against this by making the server **stateless until the handshake completes**.
Instead of allocating a TCB on SYN, the server encodes the essential state *into its own ISN*:

```text
   ISN (cookie) = hash(4-tuple, secret, time-counter) || coarse MSS index
```

The server sends the SYN-ACK with this cookie as its seq and **forgets everything**. When the final
ACK comes back, its `ack = cookie + 1` carries the cookie; the server re-hashes the 4-tuple and
validates it, reconstructing just enough state to build the TCB *then*. No half-open memory is held, so
a flood costs the server nothing.

The cost: the cookie has only a few bits for state, so options negotiated in the SYN (window scale,
SACK, full MSS) are mostly lost — which is why cookies are typically a *fallback*, enabled only when
the SYN queue overflows. We implement neither the half-open table nor cookies (§13); exercise E6
sketches a cookie mode.

## F. The pseudo-header checksum, worked byte by byte

Take our SYN-ACK: src `192.168.0.2`, dst `192.168.0.1`, a 20-byte TCP header (no payload), seq 0, ack
101, flags `SYN|ACK` (0x12), window 1024 (0x0400), data offset 5 (`0x50`). The pseudo-header:

```text
   c0 a8 00 02     src 192.168.0.2
   c0 a8 00 01     dst 192.168.0.1
   00 06           zero, protocol 6 (TCP)
   00 14           TCP length = 20
```

The TCP header (checksum field zeroed for the computation):

```text
   00 50           src port 80
   1f 90           dst port 8080  (0x1f90 = 8080)
   00 00 00 00     seq = 0
   00 00 00 65     ack = 101  (0x65)
   50 12           data offset 5 (0x5_), flags 0x12 = SYN|ACK
   04 00           window = 1024
   00 00           checksum = 0  (while computing)
   00 00           urgent pointer = 0
```

Sum all the 16-bit words (pseudo-header + header) with end-around carry, then take the one's
complement; that 16-bit result goes into the checksum field. The receiver sums the *same* words *with*
the checksum in place and gets `0xFFFF` → `0` after complement — the property our
`accept_produces_valid_synack` test checks with `tcp_checksum(...) == 0`. (The full one's-complement
mechanics — folding carries, why `0` is sent as `0xFFFF` — are in day2-book.md §R; here the point is
*which bytes* go in: pseudo-header first, then the segment.)

## G. Active open, simultaneous open, and self-connect

**Active open (`connect`).** The client side of the handshake, the mirror of `accept`: pick an ISS,
send a bare `SYN` (seq = ISS, no ACK — we don't know the peer's seq yet), enter **SYN_SENT**. When the
peer's `SYN,ACK` arrives (`ack == SND.NXT`), learn its ISN (`RCV.IRS`, `RCV.NXT = peer.seq + 1`), set
`SND.UNA = ack`, send the final `ACK`, and reach ESTABLISHED. Our `connect`/`connect_with_iss` do
exactly this; the binary runs as a passive server, so this path is exercised by tests.

**Simultaneous open.** Both ends `connect` at once, so both are in SYN_SENT when the *other's* SYN
arrives (a SYN with no ACK). Each replies with SYN-ACK and moves SYN_SENT → SYN_RCVD → ESTABLISHED.
No new packet type — the same SYN/SYN-ACK/ACK, just crossing on the wire. It's rare (it needs both
sides to initiate to each other's exact ports simultaneously) but the state machine handles it for
free once SYN_SENT can accept a bare SYN.

**Self-connect.** A pathological case: a host connects to itself on the same 4-tuple (source == dest).
The "two" SYNs are the same packet, producing a simultaneous open with a single TCB. Real stacks have
had bugs here; it's a good fuzz target.

## H. A complete annotated handshake trace (hex + TCB evolution)

The full passive-open handshake from §5, with our TCB after each step. `C` = client, `U` = us.

```text
   ① C→U  SYN  seq=100 win=65535
      wire (TCP hdr): 12 34 00 50 | 00 00 00 64 | 00 00 00 00 | 50 02 ff ff | csum | 00 00
                      sport 4660  | seq 100     | ack 0       | off5 SYN win | ...
      U TCB after:  state=SYN_RCVD  IRS=100 RCV.NXT=101  ISS=0 SND.UNA=0 SND.NXT=1

   ② U→C  SYN,ACK  seq=0 ack=101 win=1024
      wire (TCP hdr): 00 50 12 34 | 00 00 00 00 | 00 00 00 65 | 50 12 04 00 | csum | 00 00
                      sport 80    | seq 0       | ack 101     | off5 SYNACK  | ...
      (queued for retransmission until the final ACK — Day 12)

   ③ C→U  ACK  seq=101 ack=1 win=65535
      wire (TCP hdr): 12 34 00 50 | 00 00 00 65 | 00 00 00 01 | 50 10 ff ff | csum | 00 00
                      sport 4660  | seq 101     | ack 1       | off5 ACK win | ...
      U TCB after:  state=ESTABLISHED  SND.UNA=1  (our SYN is acknowledged)
```

Read step ③'s flag byte `0x10` = ACK only; step ① and ② carry SYN (`0x02`) and SYN|ACK (`0x12`). The
`+1`s are visible: ②'s `ack=101` = ①'s `seq + 1`; ③'s `ack=1` = ②'s `seq + 1`.

## I. Comparison to real stacks — LISTEN, the accept queue, the backlog

```text
   concept           real kernel (Linux/BSD)                 this stack
   ───────────────   ─────────────────────────────────────  ───────────────────────────
   LISTEN            explicit: bind()+listen() on a port     implicit: any SYN opens a TCB
   half-open store   SYN queue (bounded; cookies on overflow) none (no flood defense)
   established store accept queue, drained by accept()        the HashMap directly
   backlog           tunable limit on both queues             unbounded (the map grows)
   per-conn TCB      struct tcp_sock / struct tcpcb           Connection
   demux             hash of the 4-tuple                      HashMap<Quad, Connection>
```

The big missing abstraction is the **listening socket**: in a real stack, `accept()` returns a *new*
socket per connection while the listener keeps listening, and two bounded queues sit between the wire
and the application. We collapse all of that into "a SYN to any port makes a TCB in the map" — fine for
a single-purpose server, wrong for a general OS. (Exercise E3 takes the first step toward LISTEN.)

## J. Security — the handshake as attack surface

Every byte we parse from a SYN is attacker-controlled, and the handshake itself is a resource the
attacker can consume:

- **Parser safety.** `parse` validates the data offset before slicing; a malformed offset can't make
  us read out of bounds or panic. This is the same discipline as the Day 1/2 parsers — every length is
  checked against the actual buffer.
- **Resource exhaustion.** With no half-open limit, a SYN flood grows our map without bound (§E). A
  real server caps it and uses cookies.
- **Spoofing/injection.** A predictable ISN enables off-path connection forgery and data/RST injection
  (§D) — defended only by ISN randomness, which `accept` has and `accept_with_iss` deliberately omits
  for tests.
- **Amplification.** A SYN-ACK is larger than a SYN; an attacker spoofing a victim's IP as the SYN
  source turns our server into a (small) reflector. Real mitigations rate-limit and use cookies.

The takeaway from the security track: *the handshake is both a parser (validate everything) and a
resource allocator (bound everything)*, and Day 3 implements the parser-safety half but not the
resource-bounding half.

## K. Performance notes

- **One hash lookup per segment.** Demuxing is `HashMap<Quad, Connection>` — O(1) average. Real
  stacks use a hash table too (Linux's `ehash`/`bhash`), so the shape is right; the constant factors
  (SipHash vs a faster keyed hash, cache layout) differ.
- **Allocation per reply.** `build_packet` allocates a `Vec<u8>` per segment. Fine for our scale; a
  high-performance stack reuses buffers / does zero-copy from a ring.
- **Checksum cost.** The TCP checksum is a linear pass over the pseudo-header + segment. Real NICs
  offload it (TX/RX checksum offload); we compute it in software, which is the honest baseline.
- **TCB size.** Our `Connection` grows over the days (retx queue, RTT, reassembler, congestion, buffers).
  A real `tcp_sock` is hundreds of bytes; per-connection memory is the dominant cost of a server with
  millions of connections (the "C10M" problem).

## L. Extended FAQ — thirty questions a careful reader asks

1. **Why three packets, not two or four?** Two parties must each announce and confirm an ISN; three is
   the minimum that confirms both directions (§5). Four would be redundant.
2. **Why does SYN consume a sequence number?** So its delivery is itself reliable — the SYN occupies a
   slot the ACK can acknowledge; that's the `+1`.
3. **Does FIN also consume one?** Yes — same reason, at close (Day 5).
4. **What is the ACK number, exactly?** The next sequence number expected = cumulative "I have
   everything below this."
5. **Why random ISNs?** To defeat off-path spoofing/injection and to fence off stale duplicates from a
   prior connection (§D).
6. **What if two connections share a 4-tuple over time?** TIME_WAIT (Day 7) plus rising ISNs keep the
   old incarnation's segments from poisoning the new one.
7. **What's `RCV.NXT` used for in our segments?** It's the ACK number we send — "send me this next."
8. **What's `SND.NXT` vs `SND.UNA`?** NXT = next to send; UNA = oldest unacked. `[UNA, NXT)` is the
   retransmittable window.
9. **Why is the window 1024 and fixed?** Placeholder until Day 8 wires it to real buffer space.
10. **Why is `SND.WND` a `u32` but `RCV.WND` a `u16`?** The peer's window can be window-scaled past
    64 KB (Day 17); the raw value we advertise is the 16-bit field.
11. **What's the pseudo-header for?** To bind the checksum to the IP addresses/protocol so a
    misdelivered segment is caught (§8, §F).
12. **Is the pseudo-header sent on the wire?** No — it's only an input to the checksum.
13. **What's the data offset?** TCP header length in 32-bit words (5 = 20 bytes, up to 15 = 60).
14. **Why reject a data offset < 5?** A header can't be shorter than its fixed 20 bytes; a smaller
    value is malformed.
15. **What happens to a non-SYN to a closed port?** Day 3 ignores it; the correct reply is a RST
    (Day 5).
16. **What's `Quad`'s direction convention?** `remote` = source = peer; `local` = dest = us. Replies
    swap them.
17. **Can we open from any port?** We do (implicit LISTEN); a real stack only on `listen()`ed ports
    (§I).
18. **What's a half-open connection?** SYN received, SYN-ACK sent, final ACK not yet arrived
    (SYN_RCVD).
19. **What's a SYN flood?** Many never-completed SYNs exhausting the half-open store (§E).
20. **What are SYN cookies?** Stateless handshake: encode state in the ISN, allocate only on the final
    ACK (§E).
21. **What's simultaneous open?** Both sides `connect` at once; both go SYN_SENT → SYN_RCVD →
    ESTABLISHED (§G).
22. **Do we handle simultaneous open at Day 3?** Not yet; the code grows to (exercise E5 / later days).
23. **Why split the TCB into two structs?** To mirror RFC 9293 §3.3.1 so later rules read off the spec.
24. **Why `Option` from `accept`?** "Not a SYN → can't open" is a value, not a panic.
25. **Why `wrapping_add`?** Sequence numbers wrap at 2³²; `+1` near the top must become 0, not overflow
    (§B).
26. **Does a SYN carry data?** It may (TCP Fast Open), but classically no; ours doesn't.
27. **What options does a real SYN carry?** MSS, window scale, SACK-permitted, timestamps (Days
    15–18). Ours is bare at Day 3.
28. **How is this tested without a network?** Construct headers, call `accept`/`on_segment`, assert
    states and checksums — all offline (§11).
29. **What's the biggest simplification today?** No LISTEN/accept-queue/backlog and no RST — implicit
    open, unbounded store (§13, §I).
30. **What's the single most important takeaway?** The TCB + sequence numbers: numbering bytes and
    remembering the two windows is what makes everything afterward possible.

## M. Anki starter deck

```text
Q: What uniquely identifies a TCP connection?  A: the 4-tuple (src IP, src port, dst IP, dst port).
Q: How many sequence numbers does a SYN consume?  A: one (so its delivery is acknowledgeable).
Q: SYN-ACK ack number, given client SYN seq=100?  A: 101 (client seq + 1).
Q: What does ACK=101 mean?  A: "I have everything through byte 100; send 101 next" (cumulative).
Q: SND.UNA vs SND.NXT?  A: oldest unacked vs next to send; [UNA,NXT) is retransmittable.
Q: RCV.NXT is?  A: the next seq we expect = the ACK number we put in our segments.
Q: Why three-way (not two)?  A: each side must announce AND confirm an ISN; 3 confirms both directions.
Q: Why random ISNs?  A: defeat off-path spoofing/injection; fence off stale duplicates (RFC 6528).
Q: What does the TCP pseudo-header contain?  A: src IP, dst IP, 0, protocol 6, TCP length.
Q: Is the pseudo-header transmitted?  A: no — only an input to the checksum.
Q: Data offset value for a 20-byte header?  A: 5 (words); byte 12 high nibble = 0x5.
Q: Flag byte for SYN|ACK?  A: 0x12.
Q: A non-SYN to a closed port should get?  A: a RST (Day 3 ignores; Day 5 adds it).
Q: What is a SYN flood, and the defense?  A: never-completed SYNs exhausting half-open store; SYN cookies.
Q: Why wrapping_add for SND.NXT/RCV.NXT?  A: 32-bit seq space wraps; +1 near top must become 0.
```

## N. Glossary

- **TCB (Transmission Control Block)** — the per-connection state: sequence spaces, state, endpoints,
  and (later) buffers/timers. Our `Connection`.
- **4-tuple / Quad** — (src IP, src port, dst IP, dst port); the connection identity / map key.
- **ISN / ISS / IRS** — Initial Sequence Number; the *send* one we chose (ISS) and the *receive* one
  we learned from the peer (IRS).
- **SND.UNA / SND.NXT / SND.WND** — send-side: oldest unacked, next to send, peer's window.
- **RCV.NXT / RCV.WND / RCV.IRS** — receive-side: next expected, our window, peer's initial seq.
- **Cumulative ACK** — the ACK number; "everything below this is received."
- **SYN / SYN-ACK / ACK** — the three handshake segments.
- **Passive open** — answering an incoming SYN (`accept`). **Active open** — initiating (`connect`).
- **Simultaneous open** — both sides actively open at once.
- **Half-open** — handshake started, not completed (SYN_RCVD).
- **Pseudo-header** — the synthetic IP-fields block included in the TCP checksum.
- **Data offset** — TCP header length in 32-bit words.
- **SYN cookie** — stateless handshake technique encoding TCB state in the ISN.
- **PSH / URG / RST / FIN** — push, urgent, reset, finish flags.

## O. Reference tables

**O.1 — TCP flags (byte 13)**

```text
   flag  mask  meaning
   ────  ────  ─────────────────────────────────
   FIN   0x01  no more data (half-close)
   SYN   0x02  synchronize sequence numbers (open)
   RST   0x04  reset / abort
   PSH   0x08  push buffered data to the app
   ACK   0x10  acknowledgment number is valid
   URG   0x20  urgent pointer is valid
```

**O.2 — Handshake seq/ack arithmetic (client ISN = X, our ISS = Y)**

```text
   packet     seq    ack    flags    consumes   our TCB after
   ────────   ────   ────   ──────   ────────   ─────────────────────────────
   ① SYN      X      —      SYN      seq X      IRS=X RCV.NXT=X+1 ISS=Y UNA=Y NXT=Y+1
   ② SYN,ACK  Y      X+1    SYN|ACK  seq Y      state SYN_RCVD
   ③ ACK      X+1    Y+1    ACK      —          ESTABLISHED, SND.UNA=Y+1
```

**O.3 — TCB fields → RFC 9293 names → our code**

```text
   concept              RFC name   our field
   ──────────────────   ────────   ───────────────────────
   our initial seq      ISS        send.iss
   oldest unacked       SND.UNA    send.una
   next to send         SND.NXT    send.nxt
   peer's window        SND.WND    send.wnd (u32)
   peer's initial seq   IRS        recv.irs
   next expected        RCV.NXT    recv.nxt
   our window           RCV.WND    recv.wnd (u16)
```

> Re-type `tcp.rs`'s `accept` and the SYN_RCVD→ESTABLISHED transition from this chapter with it
> closed, then `cargo test`. Make Anki cards from your own slips — especially "what the ACK number
> means" and "why SYN consumes a seq." When you can draw the three-packet trace with every number and
> explain each `+1`, you own the handshake.
