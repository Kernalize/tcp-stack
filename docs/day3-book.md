# Day 3 — TCP, Part 1: The Three-Way Handshake

> Goal: when a client runs `nc 192.168.0.2 8080`, our stack answers its `SYN` with a
> `SYN-ACK`, accepts the client's `ACK`, and reaches **ESTABLISHED** — a real, open TCP
> connection. This is where the project gets hard, because unlike ICMP, **TCP has memory**:
> per-connection state (the TCB), sequence numbers, and a state machine. After this you can
> explain every number in a handshake and why three packets are required.

**Contents**
1. Why TCP is a different kind of problem
2. The 4-tuple and the connection table
3. Sequence numbers — the central idea
4. The TCB — send and receive sequence spaces
5. The three-way handshake, number by number
6. The state machine (our subset)
7. Building a TCP segment from scratch
8. The TCP checksum and the pseudo-header
9. The code, walked
10. Verification
11. Design choices and alternatives
12. Rebuild it yourself — checklist + exercises
13. What the next step adds

---

## 1. Why TCP is a different kind of problem

ICMP was *stateless*: each packet was handled in isolation (see a request → send a reply,
forget it). TCP is *stateful*. It turns IP's unreliable, unordered packet delivery into a
**reliable, ordered byte stream**, and to do that both ends must remember things across
packets: what's been sent, what's been acknowledged, what's expected next, which state the
connection is in. That memory is the **Transmission Control Block (TCB)**, one per
connection. Our stack therefore needs a *table* of TCBs and a *state machine* that advances
on each packet. The handshake is the first, smallest instance of all of this.

---

## 2. The 4-tuple and the connection table

Many connections can exist at once (two browser tabs to the same server, say). TCP tells
them apart by the **4-tuple**: `(source IP, source port, destination IP, destination port)`.
That tuple uniquely identifies a connection. We model it as `Quad { remote, local }`
(remote = the packet's source = the client; local = the destination = us) and use it as the
key of a `HashMap<Quad, Connection>`. Every incoming TCP segment is looked up in this table:

- **found** → hand it to that connection's state machine (`on_packet`).
- **not found** → if it's a `SYN`, open a new connection (`accept`); otherwise ignore (a
  real stack would send a `RST` — Step 5).

`Quad` derives `Hash, Eq, Copy` so it can be a map key; `Ipv4Addr` already supports those.

---

## 3. Sequence numbers — the central idea

Every byte in a TCP connection has a **32-bit sequence number**. This is the mechanism
behind reliability and ordering: the receiver can detect missing bytes (gap in seq numbers),
duplicates (already-seen seq), and reordering (out-of-order seq), and acknowledge exactly how
far it has received.

Key facts:
- Sequence numbers are **32-bit and wrap around** (mod 2³²). After `0xFFFFFFFF` comes `0`.
  All arithmetic uses `wrapping_add` so overflow is defined, not a panic. Comparisons use
  *modular* "is A before B" logic (we'll need that fully in Step 4).
- They do **not** start at 0 on the wire. Each side picks a random **Initial Sequence
  Number (ISN)** and counts from there (we use 0 for now — see §11).
- The **ACK number** a side sends is "the next sequence number I expect from you" =
  cumulative acknowledgement. ACK=101 means "I have everything up to and including seq 100;
  send me 101 next."
- `SYN` and `FIN` flags **each consume one sequence number**, even though they carry no data.
  This is why the handshake math has `+1` everywhere: a SYN with seq=100 is acknowledged
  with ack=101.

---

## 4. The TCB — send and receive sequence spaces

RFC 9293 §3.3.1 splits the TCB's sequence bookkeeping into two halves. We mirror it exactly:

**Send Sequence Space** — about the bytes *we* send (`SendSequence`):
```
        SND.UNA        SND.NXT
          │              │
   …──────┼──────────────┼────────►  sequence numbers
   acked  │  sent, not   │  usable (within SND.WND)
          │  yet acked   │
   ISS = our initial send sequence number
```
- `iss` initial send seq · `una` oldest unacked · `nxt` next to send · `wnd` peer's window.

**Receive Sequence Space** — about the bytes *we* receive (`RecvSequence`):
```
        RCV.NXT
          │
   …──────┼───────────────►  what we expect next; we'll accept up to RCV.WND beyond it
   IRS = peer's initial sequence number (learned from their SYN)
```
- `irs` initial recv seq (peer's ISN) · `nxt` next expected · `wnd` how much we'll accept.

On a passive open these are initialized from the incoming SYN (next section).

---

## 5. The three-way handshake, number by number

Using our test's numbers — client ISN = 100, our ISS = 0:

```
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

Why each number:
- ① The client's SYN carries `seq=100` (its ISN). It consumes seq 100, so the next byte the
  client sends will be 101 — hence we set `RCV.NXT = 101`.
- ② Our SYN-ACK carries **our** `seq=0` (our ISS) and `ack=101` ("I got your SYN, expecting
  101 next"). Our SYN consumes seq 0, so `SND.NXT = 1`.
- ③ The client ACKs with `ack=1` ("I got your SYN, expecting 1 next"). Since `ack == SND.NXT`,
  our SYN is acknowledged → connection is ESTABLISHED.

**Why three packets and not two?** Each side must both *announce* its ISN and *learn+confirm*
the other's. ① announces the client's ISN. ② confirms ① and announces ours. ③ confirms ②.
Two packets could confirm only one direction; three confirms both. (TCP also allows a rare
*simultaneous open* where both send SYN at once — §11.)

---

## 6. The state machine (our subset)

Full TCP has 11 states; the passive-open path we implement so far is:

```
   (no entry)  ──SYN arrives, send SYN-ACK──►  SYN_RCVD  ──valid ACK──►  ESTABLISHED
```

- **(no entry in table)** is effectively LISTEN/CLOSED — any port is "listening."
- **SYN_RCVD** — we've sent our SYN-ACK and await the client's ACK.
- **ESTABLISHED** — open; ready for data (Step 4).

`Connection::accept` creates the TCB and the SYN-ACK; `Connection::on_packet` drives
SYN_RCVD → ESTABLISHED. Later steps add FIN_WAIT/CLOSE_WAIT/TIME_WAIT for teardown.

---

## 7. Building a TCP segment from scratch

For ICMP we *mutated* a received packet. TCP responses are new, so `build_packet`
synthesizes a full IPv4 + TCP packet:

- **IPv4 header (20 B):** version/IHL `0x45`, total length, DF flag, TTL 64, protocol **6**
  (TCP), our src and the peer's dst, then `ip::write_header_checksum`.
- **TCP header (20 B):** src/dst ports, 32-bit seq and ack, **data offset** = 5 words (the
  TCP analogue of IHL — header length in 32-bit words; `5<<4` in byte 12), the flag byte,
  the window, then the checksum, then the urgent pointer (0).
- **payload** (none for a SYN-ACK; data arrives in Step 4).

The whole thing is `vec![0u8; total_len]` then field-by-field `copy_from_slice` of
big-endian bytes — the mirror image of parsing.

---

## 8. The TCP checksum and the pseudo-header

The TCP checksum uses the same one's-complement `utils::checksum` (Day 2), but over more than
the segment: it is computed over a **pseudo-header** *plus* the TCP segment. The IPv4
pseudo-header is 12 bytes:

```
+--------------------+--------------------+
|            Source IPv4 Address          |
+--------------------+--------------------+
|         Destination IPv4 Address        |
+--------+-----------+--------------------+
|  zero  | proto = 6 |     TCP length     |   (TCP length = TCP header + data)
+--------+-----------+--------------------+
```

**Why include IP fields the TCP header doesn't even contain?** So a segment delivered to the
wrong host/protocol is detected: the checksum is bound to the addresses it was meant for. It
is a cross-layer integrity tie. The pseudo-header is *only* an input to the checksum — it is
never transmitted. As always, the checksum field must be zero while computing, and a valid
segment re-checksums (pseudo-header + segment) to 0 — which is exactly what our test asserts.

---

## 9. The code, walked

`src/tcp.rs`:
- **Flag constants** `SYN/ACK/FIN/RST/PSH/URG` — bit masks for byte 13.
- **`Quad`** — the 4-tuple map key.
- **`State`** — `SynRcvd | Established` (our subset).
- **`TcpHeader` + `parse`** — the 20-byte fixed header; `data_offset` in bytes so the data
  start is `&segment[data_offset..]`.
- **`SendSequence` / `RecvSequence`** — the two halves of the TCB (§4).
- **`Connection`** — holds state + both sequence spaces + the two endpoints.
  - **`accept`** — passive open: validate it's a SYN, init the TCB (ISS, SND.NXT=ISS+1,
    RCV.NXT=peer.seq+1), build and return the SYN-ACK.
  - **`on_packet`** — in SYN_RCVD, accept the ACK that matches `SND.NXT` → ESTABLISHED.
  - **`segment`** — build a packet from this connection's perspective (src=us, dst=peer).
- **`build_packet`** — synthesize IPv4 + TCP (§7).
- **`tcp_checksum`** — pseudo-header + segment one's-complement sum (§8).

`src/main.rs` keeps `HashMap<Quad, Connection>` and dispatches: look up the quad → existing
connection advances; absent → a SYN opens one and we send the SYN-ACK.

---

## 10. Verification

`cargo test` (15 green, no TUN/sudo). The TCP ones:
- `parses_syn` — header fields decode correctly.
- `accept_produces_valid_synack` — the SYN-ACK has swapped addresses, flags `SYN|ACK`,
  `seq=ISS(0)`, `ack=client_seq+1(101)`, and **both checksums verify to 0** (IP header and
  TCP+pseudo-header).
- `final_ack_reaches_established` — feeding the client's ACK moves the TCB to ESTABLISHED.
- `ignores_non_syn_open` — a stray ACK to a closed port does not open a connection.

Live (your hands): run the stack, then `nc 192.168.0.2 8080` from terminal 2. The stack log
should show the inbound `SYN`, "→ sent SYN-ACK (state SynRcvd)", then the client's `ACK` and
"state now Established". `nc` will appear to connect (it stays open because we don't close).
With `tcpdump -i tun0` you'll see all three packets of the handshake.

---

## 11. Design choices and alternatives

| Decision | We chose | Alternative | Why / caveat |
|---|---|---|---|
| ISN | fixed 0 | random (RFC 6528) | 0 is debuggable; **must randomize in reality** — predictable ISNs enable connection spoofing/injection. Step-7 hardening. |
| No-connection non-SYN | ignore | send RST | RST is correct TCP behavior; we add it during teardown (Step 5). |
| Connection key | `Quad{remote,local}` | a listener socket abstraction | a real API has listening sockets + accept queues; we go straight to per-flow TCBs. |
| SYN flood defense | none | SYN cookies | a real server must resist half-open floods; out of scope but worth knowing. |
| Simultaneous open | not handled | full state machine | both-sides-SYN is rare; we handle passive open only for now. |
| Window | fixed 1024 | dynamic, from buffer space | flow control comes in Step 4. |

---

## 12. Rebuild it yourself — checklist + exercises

From memory:
1. Define `Quad` and explain why it keys the table.
2. State what SND.UNA/NXT and RCV.NXT mean and how `accept` initializes them from a SYN.
3. Walk the three-way handshake's seq/ack numbers and the two `+1`s (SYN consumes a seq).
4. Build a TCP segment: ports, seq, ack, `data_offset=5<<4`, flags, window, then the
   pseudo-header checksum.
5. Explain why the pseudo-header includes the IP addresses.

**Exercises:**
- **E1.** Randomize the ISN (`rand::random::<u32>()`) and confirm the handshake still works;
  explain what attack this defends against.
- **E2.** Send a **RST** when a non-SYN segment arrives for an unknown quad. (Build a segment
  with the RST flag, correct seq/ack per RFC 9293 §3.5.)
- **E3.** Add a `State::Listen` and only `accept` on specific local ports (e.g. 8080), RST-ing
  others — a step toward real listening sockets.
- **E4.** Write a test for sequence-number **wraparound**: ISN `0xFFFFFFFF`, confirm
  `SND.NXT` becomes 0 via `wrapping_add`.

---

## 13. What the next step adds

Step 4 is **data transfer**: in ESTABLISHED, accept incoming data, advance `RCV.NXT`, send an
**ACK** for it, and (to prove it end-to-end) build a tiny **echo server** that sends the data
back — verifiable with `nc`. That brings in *acceptance tests* on sequence numbers
(in-window vs out-of-window), the `PSH` flag, and sending data with correct seq/ack. After
that: teardown (FIN/TIME_WAIT) and retransmission.

> Re-type `tcp.rs` from this chapter with it closed, then `cargo test`. Anki cards from your
> own slips — especially "what does the ACK number mean" and "why does SYN consume a seq."
