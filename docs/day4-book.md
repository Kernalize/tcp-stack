# Day 4 — TCP, Part 2: Data Transfer (an Echo Server)

> Goal: once a connection is ESTABLISHED, accept the bytes the client sends, acknowledge them, and
> send them back. `printf 'hi' | nc 192.168.0.2 8080` should print `hi`. This is the payoff — a working
> TCP application running on a stack you wrote, end to end: handshake, data in, ACK, data out.

Day 3 reached ESTABLISHED but the connection was mute. Today it *talks*. The mechanism is small — a
receiver advances one cumulative pointer and a sender stamps bytes with sequence numbers — but it is
the heart of "a reliable, ordered byte stream," and every later day (reassembly, retransmission, flow
and congestion control, the socket API) refines exactly this loop.

**Contents**

Volume I — the chapter
1. What "data transfer" requires
2. Accepting in-order data (and why only in-order, for now)
3. Acknowledgements: cumulative ACK and piggybacking
4. Sending data: consuming sequence numbers
5. The echo logic, walked
6. Modular sequence arithmetic and the acceptance window
7. The PSH flag
8. The Rust: borrowing, slices, building the echo
9. The code, walked end to end
10. Verification
11. Why this, not that
12. Honesty: what production does, and how later days refactored this
13. Rebuild it yourself — checklist + exercises
14. What the next step adds

Volume II — the exhaustive reference
- A. The anatomy of a data segment (where the payload starts)
- B. Cumulative ACK, delayed ACK, and the ack-every-other rule
- C. The four-case acceptance test (RFC 9293 §3.10.7.4), exhaustively
- D. Sequence-space accounting, worked numerically
- E. PSH and URG in depth
- F. How this day was later refactored (reassembler + socket API)
- G. A complete annotated echo trace (hex + TCB evolution)
- H. Comparison to real stacks — sockets, recv buffers, delayed ACK
- I. Security — data injection and why the acceptance window matters
- J. Performance — copies and per-segment ACK overhead
- K. Extended FAQ
- L. Anki starter deck
- M. Glossary
- N. Reference tables

---

# Volume I — the chapter

## 1. What "data transfer" requires

In ESTABLISHED, each segment may carry payload bytes starting at sequence number `seg.seq`. To turn
unreliable packets into an ordered byte stream, the receiver must, *per segment*:

1. decide whether the data is the next expected bytes (acceptability),
2. accept it if so, and move its "next expected" pointer forward,
3. tell the peer how far it has now received (an **ACK**).

And to *prove* the stream works end to end, we also **send** data — here, the same bytes back (echo).
Sending introduces the send side's bookkeeping: stamp bytes with `SND.NXT`, advance it, and remember
that those sequence numbers are now "in flight" until the peer acknowledges them.

That is the whole of data transfer: one pointer advancing on each side, and an ACK number carrying the
receiver's pointer back to the sender. Reliability (what to do when a segment is *lost*) is a separate
concern we add on Day 6; today we assume the cooperative, lossless TUN link and keep the core idea
clean.

## 2. Accepting in-order data (and why only in-order, for now)

We accept a segment's data only when it is *exactly* the next byte we expect:

```text
   seg.seq == RCV.NXT      ⇒  in order: accept
   seg.seq >  RCV.NXT      ⇒  a gap (future data): drop for now (Day 9 buffers it)
   seg.seq <  RCV.NXT      ⇒  a duplicate (old data): drop
```

When in order, we advance the cumulative pointer by the payload length:

```rust
self.recv.nxt = self.recv.nxt.wrapping_add(payload.len() as u32);
```

`RCV.NXT` now points just past the bytes we hold. **In-order-only is a real simplification** — a full
stack buffers out-of-order segments and reassembles them when the gap fills (Day 9), and detects
acceptability with a *window* test rather than strict equality (§C). But the simplification keeps the
day-4 idea pure: **the receiver advances a single cumulative pointer.** Everything else is refinement.

Why is in-order-only *correct* (if inefficient) on our link? Because the peer (`nc` over a lossless
TUN) sends in order and nothing is dropped, so `seg.seq` always equals `RCV.NXT`. The moment we
introduce loss or reordering (Days 6 & 9), this assumption breaks and we need the buffer and the
window — which is exactly why those days exist.

## 3. Acknowledgements: cumulative ACK and piggybacking

TCP's ACK is **cumulative**: `ACK = N` means "I have received everything up to but *not* including N;
send N next." It is a single high-water mark (the same number we called `RCV.NXT`). After taking 2
bytes at seq 101, we advance `RCV.NXT` to 103, and every segment we send carries `ack = 103`.

**Piggybacking.** An ACK is just a field (bytes 8–11) plus a flag (the ACK bit) on a segment — so it
can *ride along* on a data segment. Our echo segment is `PSH|ACK` with `ack = RCV.NXT`: it
simultaneously **sends data back** and **acknowledges the data we received**. One packet, two jobs.
(If we had data to acknowledge but nothing to send, we'd emit a bare `ACK` segment; a real stack also
*delays* ACKs to batch them — §B.)

The elegance is that the same 20-byte header expresses "here is my data (seq), and here is how far I've
received yours (ack)" at once. A bidirectional TCP connection is two sequence streams sharing one
header on every segment.

## 4. Sending data: consuming sequence numbers

When we send `k` payload bytes, we stamp them with `seq = SND.NXT`, then advance:

```rust
self.send.nxt = self.send.nxt.wrapping_add(k as u32);
```

Those `k` sequence numbers are now **in flight**. `SND.UNA` (oldest unacknowledged) stays put until the
peer ACKs them; the region `[SND.UNA, SND.NXT)` is the unacknowledged data a real stack keeps buffered
for **retransmission** (Day 6). We learn the peer acknowledged our data by reading the `ack` field of
incoming segments and advancing `SND.UNA`.

This is the send-side mirror of §2: where the receiver advances `RCV.NXT` on data *in*, the sender
advances `SND.NXT` on data *out*, and `SND.UNA` trails behind, marking how much the peer has confirmed.

## 5. The echo logic, walked

The day-4 ESTABLISHED handler, in pseudocode:

```text
   if segment has an ACK:                       SND.UNA = seg.ack        // peer acked our data
   if payload non-empty AND seg.seq == RCV.NXT:                          // in-order data
       RCV.NXT += payload.len()                                          // accept it
       out = segment(seq=SND.NXT, ack=RCV.NXT, PSH|ACK, payload)         // echo + acknowledge
       SND.NXT += payload.len()                                          // our data consumes seq space
       return out                                                        // main.rs sends it
```

A nice consequence of the state machine's structure: the handshake's final ACK can itself carry data
(a client may start sending immediately, e.g. TCP Fast Open or just a fast `nc`), so the handler first
completes SYN_RCVD → ESTABLISHED and then **falls through** into this same data path — no special case
for "data on the final ACK." The states share one linear handler.

(Note: the *current* code splits this — `on_segment` delivers data to a buffer and returns a bare ACK,
while the application echoes via `write`/`poll_transmit`. The day-4 inline echo above is the milestone;
§F explains the refactor and why it happened.)

## 6. Modular sequence arithmetic and the acceptance window

Sequence numbers are 32-bit and wrap, so "is A before B?" is **modular**, not plain `<` (RFC 1982; see
day3-book.md §B). A correct stack decides acceptability with a *window* test, not strict equality. The
RFC 9293 §3.10.7.4 acceptance rule asks: does any part of the segment fall in the receive window
`[RCV.NXT, RCV.NXT + RCV.WND)`? The four cases (length × window) are tabulated exhaustively in §C.

We sidestepped the full test with two honest simplifications, both flagged in the code:

- **In-order only** (`seg.seq == RCV.NXT` exactly) — no acceptance *window*, just the next-byte check.
- **`SND.UNA = seg.ack` unconditionally** — a real stack only *advances* UNA, and only if the ack is
  in `(SND.UNA, SND.NXT]` mod 2³² (`seq::between`); otherwise the ack is stale or forged and must be
  ignored.

These are fine for a cooperative `nc` over a lossless TUN link; they are the first things hardened for
the open internet. (Day 6 replaces the unconditional UNA update with the `between` check; Day 9 replaces
in-order-only with the reassembler.)

## 7. The PSH flag

`PSH` ("push") asks the receiver to deliver buffered data to the application *promptly* rather than
waiting for more to accumulate. Historically, a receiver might hold bytes in its buffer to hand the
application a larger chunk; PSH says "don't wait — this is a complete message." For our echo it's
mostly cosmetic (we act on every segment immediately, and there's no held buffer to flush), but we set
it on outgoing data because that's what a sender of a small, complete message does, and it's what
`nc` / `tcpdump` expect to see (`tcpdump` prints `P.` for `PSH|ACK`). On modern stacks PSH is set by
the sending TCP whenever it empties the send buffer, and most receivers deliver promptly regardless, so
it rarely changes behavior — but it's part of speaking TCP correctly.

## 8. The Rust: borrowing, slices, building the echo

- **The payload is a borrowed slice.** `on_segment(&mut self, th: &TcpHeader, payload: &[u8], …)`
  takes the data as `&[u8]` — a view into the received buffer, no copy. We read its `.len()` to advance
  `RCV.NXT` and pass it straight to the segment builder. Borrowing (not owning) the payload keeps the
  hot path allocation-free until we actually build a reply.
- **The reply is an owned `Vec<u8>`.** `segment(...)` returns a freshly built packet; ownership
  transfers to the caller (the event loop), which writes it to the TUN and drops it. Clear ownership:
  the input is borrowed, the output is owned.
- **`&mut self` for the duration of one segment.** The connection is mutated in place (pointers
  advance); the borrow ends when the handler returns, so the `HashMap` that owns the connection is free
  again. No long-lived borrows, no `Rc`/`RefCell` gymnastics.
- **Wrapping arithmetic, always.** `wrapping_add` for `RCV.NXT`/`SND.NXT` so a pointer near 2³² rolls
  to 0 rather than panicking in debug builds.

## 9. The code, walked end to end

`src/tcp.rs`, ESTABLISHED branch of the segment handler:

- Read the ACK field → advance `SND.UNA` (day-4: unconditionally; later: `seq::between`-validated).
- If there's payload and it's in order (`seg.seq == RCV.NXT`): advance `RCV.NXT`, build the echo
  (`PSH|ACK`, `seq = SND.NXT`, `ack = RCV.NXT`, the payload), advance `SND.NXT`, return the packet.
- `segment(seq, ack, flags, payload)` builds the IP+TCP packet from this connection's perspective
  (src = us, dst = peer), advertising our receive window, and checksums both layers (Day 3 §7–8).

`src/main.rs` dispatches: look up the `Quad`, call the handler, and write any returned bytes to the
TUN. The handshake and data paths are the same call — `on_segment` — so `main` doesn't distinguish
"this segment opened a connection" from "this segment carried data."

## 10. Verification

`cargo test` proves the echo offline (no TUN/sudo). The day-4 test, `established_echoes_data` (and its
descendants like `established_delivers_data_then_app_echoes`):

- establish a connection, then feed an in-order 2-byte segment (`"hi"` at seq 101);
- assert `RCV.NXT` 101 → 103 and `SND.NXT` 1 → 3;
- assert the echo is a valid IP+TCP packet (`utils::checksum(ip) == 0`, `tcp_checksum(...) == 0`),
  flags `PSH|ACK`, `seq = 1`, `ack = 103`, payload `"hi"`.

That one test exercises acceptance, both pointer advances, segment construction, byte order, and both
checksums — the whole day in a single assertion block.

Live (your hands): run the stack, then

```bash
printf 'hello\n' | nc -q1 192.168.0.2 8080
```

`nc` prints `hello` back — the bytes made a full round trip through your TCP. `sudo tcpdump -i tun0 -n`
shows SYN, SYN-ACK, ACK, then the data segment and your echo (`P.` flags) with matching seq/ack
numbers.

## 11. Why this, not that

| Decision | We chose | Alternative | Why / caveat |
|---|---|---|---|
| Out-of-order data | drop | buffer + reassemble | reassembly needs a receive queue — the Day 9 reliability work. |
| ACK strategy | piggyback on the echo | delayed / standalone ACKs | fine for request/response; delayed ACK batches for efficiency (§B). |
| Send window | ignore the peer's window | obey `SND.WND` (flow control) | we never flood `nc`; flow control matters for bulk transfer (Day 8). |
| Nagle's algorithm | off (send immediately) | coalesce small writes | Nagle reduces tiny-packet overhead; irrelevant for echo (Day 13 adds it). |
| UNA update | trust `seg.ack` (day-4) | validate in `(UNA, NXT]` | required against stale/forged acks on a real network (Day 6 hardens it). |
| Acceptance | strict `seq == RCV.NXT` | window test (§C) | strict is correct in-order; the window test handles partial overlaps and reordering. |

## 12. Honesty: what production does, and how later days refactored this

The day-4 inline echo is the clearest *teaching* shape, but it conflates three jobs that a real stack —
and our *current* code — keep separate:

- **Receiving** ≠ **delivering** ≠ **echoing.** The current `on_segment` hands the payload to the
  **reassembler** (`reasm.recv`, Day 9), which returns the now-contiguous bytes; those go into a
  **receive buffer** (`recv_buf`); the handler returns a *bare* ACK. The **application** then reads the
  bytes (`take_received`), decides to echo, calls `write`, and `poll_transmit` drains the send buffer
  onto the wire as the window allows (Days 8, 10, 11). So "accept → echo" became "accept → reassemble →
  buffer → ACK" plus "app: read → write → transmit." The day-4 milestone is the same connection from
  the client's point of view; the internals grew a clean receive/send split.
- **Acceptance is a window, not equality.** Production uses the four-case test (§C) so it can accept the
  *new* tail of a partially-overlapping segment and tolerate reordering.
- **ACKs are delayed.** Real receivers ack roughly every *other* full-sized segment, or after ~40–200
  ms, halving ACK traffic (§B). We ack every segment.
- **Flow and congestion control gate sending.** We send the whole echo immediately; a real sender is
  bounded by `min(SND.WND, cwnd)` (Days 8, 10).
- **Zero-copy and buffering.** Real stacks avoid copying payloads (page flipping, `sendfile`); we copy
  into a `Vec`.

None of these change the day-4 *contract* (bytes go in, the same bytes come back, acknowledged); they
are the breadth the later days add.

## 13. Rebuild it yourself — checklist + exercises

**Blank-file checklist:**

- [ ] The in-order test `seg.seq == RCV.NXT` and the `RCV.NXT += len` advance.
- [ ] Why an ACK is cumulative, and how the echo piggybacks it on a `PSH|ACK`.
- [ ] `seq = SND.NXT` on send, then `SND.NXT += len`; what `[SND.UNA, SND.NXT)` means.
- [ ] Why sequence comparisons must be modular, and what the acceptance window is.
- [ ] What PSH asks for, and why we set it on the echo.

**Exercises:**

- **E1.** Send a **bare ACK** for received data when you have nothing to echo: build an `ACK` segment
  with `seq = SND.NXT, ack = RCV.NXT`, no payload. (This is what the current code does.)
- **E2.** Buffer **one** out-of-order segment and deliver it once the gap fills; add a test. (The seed
  of Day 9.)
- **E3.** Implement the modular `between(start, x, end)` helper and use it to validate incoming acks;
  test the wraparound boundary. (The seed of Day 6's UNA check.)
- **E4.** Respect `SND.WND`: don't send more unacknowledged data than the peer's advertised window.
  (The seed of Day 8.)
- **E5.** Implement a **delayed ACK** (§B): when in-order data arrives, hold the ACK briefly and ack
  every other segment or on a timer; measure the drop in ACK packets under a bulk transfer.

## 14. What the next step adds

Day 5 is **teardown**: handle the client's `FIN` (it consumes a sequence number, like SYN), ACK it,
send our own `FIN`, and walk the closing states (CLOSE_WAIT → LAST_ACK on the passive side). After that
the connection lifecycle is complete: **open → transfer → close**. Reliability (retransmission/RTO,
Day 6), reassembly (Day 9), and congestion control (Day 10) are the hardening that makes it survive a
real, lossy network.

---

# Volume II — the exhaustive reference

## A. The anatomy of a data segment (where the payload starts)

A data segment is the same TCP header as a SYN, with a non-empty payload after the options. The crucial
parse detail is the **data offset**: the payload does not always start at byte 20.

```text
   IP header (20)            TCP header (20 + options)              payload
   ├──────────────┤         ├───────────────────────────┤        ├─────────┤
   0             20         20      20+opt = data_offset           …       end
                                    ▲
                                    payload starts at: 20 (IP) + data_offset (TCP)
```

In our parser, `data_offset` is the TCP header length in bytes (the high nibble of TCP byte 12, ×4).
The payload is `&segment[data_offset..]` within the TCP portion, i.e. `&packet[20 + data_offset..]` in
the full IP packet. The helper `payload_of(pkt)` in the tests does exactly this. Getting this wrong —
assuming payload at byte 40 always — breaks the instant options appear (Days 15–18), which is why every
test extracts the payload via the parsed `data_offset`, never a hard-coded offset.

The payload length is implicit: `IP.total_length − IP.IHL×4 − TCP.data_offset`. TCP has no payload-length
field; it's derived from the IP length, which is why a wrong IP length corrupts the byte stream (and why
we validate it on receive).

## B. Cumulative ACK, delayed ACK, and the ack-every-other rule

The cumulative ACK is robust precisely because it is *idempotent and self-correcting*: if an ACK is
lost, the next one (carrying a higher or equal number) supersedes it; the sender never needs the lost
ACK. This is why TCP can ack-batch.

**Delayed ACK (RFC 1122 §4.2.3.2).** A receiver need not ACK every segment immediately. It MAY delay an
ACK, but:

- it MUST ACK at least every *second* full-sized segment, and
- it MUST NOT delay an ACK by more than 500 ms (typically ~40–200 ms).

The win is roughly halving the ACK packet count on a bulk transfer (and enabling piggybacking on
reverse-direction data). The risk is interacting badly with **Nagle's algorithm** (Day 13): a small
write held by Nagle, waiting for an ACK that the receiver is delaying, causes a visible latency stall —
the classic "Nagle + delayed-ACK" 40 ms hiccup. We ack every segment (no delay), so we don't hit this,
but it's a famous interaction worth knowing.

```text
   receiver policy      ACKs per 10 data segments     latency           our choice
   ─────────────────    ─────────────────────────     ───────────       ──────────
   ACK every segment    10                            lowest            ✓ (day 4)
   delayed (every 2nd)  5                             +up to ~200 ms    real stacks
```

## C. The four-case acceptance test (RFC 9293 §3.10.7.4), exhaustively

A real receiver accepts a segment if it overlaps the receive window `[RCV.NXT, RCV.NXT + RCV.WND)` at
all. The spec enumerates four cases by **segment length** and **window size**:

```text
   SEG.LEN   RCV.WND   acceptable if …
   ───────   ───────   ───────────────────────────────────────────────────
   0         0         SEG.SEQ == RCV.NXT
   0         > 0       RCV.NXT ≤ SEG.SEQ < RCV.NXT + RCV.WND
   > 0       0         not acceptable (window closed) — but still ACK it
   > 0       > 0       RCV.NXT ≤ SEG.SEQ < RCV.NXT+RCV.WND
                       OR  RCV.NXT ≤ SEG.SEQ+SEG.LEN−1 < RCV.NXT+RCV.WND
```

The two-clause last case is what lets a receiver accept a segment that *starts* below the window but
*ends* inside it (a partial overlap with already-received data, e.g. a retransmission of `[100,200)`
when we already have `[100,150)`): the receiver trims the duplicate prefix and keeps the new tail. Our
Day-9 reassembler implements exactly this trimming (`trims_partial_overlap_with_delivered`); our day-4
strict `seq == RCV.NXT` is the special case "starts exactly at the window's left edge." A segment wholly
outside the window is dropped — but TCP still sends an ACK (to re-sync a confused peer), which is the
seed of the duplicate-ACK mechanism (Day 10).

## D. Sequence-space accounting, worked numerically

A three-segment echo, client ISN = 100 (so first data at 101), our ISS = 0 (so our data at 1):

```text
   step  recv (from client)          our TCB             we send (echo)              our TCB after
   ────  ──────────────────────      ───────────────     ──────────────────────     ──────────────
   est.  (handshake done)            RCV.NXT=101         —                          SND.UNA=1 SND.NXT=1
   1     "AB"  seq=101 (2 bytes)     accept → 103        PSH,ACK seq=1 ack=103 "AB"  SND.NXT=3
   2     ACK   ack=3                 SND.UNA=3           —                          (our echo acked)
   3     "CDE" seq=103 (3 bytes)     accept → 106        PSH,ACK seq=3 ack=106 "CDE" SND.NXT=6
   4     ACK   ack=6                 SND.UNA=6           —                          (echo acked)
```

Watch the invariants: `RCV.NXT` only ever advances by exactly the in-order bytes received; `SND.NXT`
advances by exactly the bytes we send; `SND.UNA` chases `SND.NXT` as the peer acks. At rest,
`SND.UNA == SND.NXT` (nothing in flight) and `RCV.NXT` equals the total bytes received + 101. Each
echo's `ack` is the receiver pointer; each echo's `seq` is the sender pointer at send time.

## E. PSH and URG in depth

- **PSH** — a one-bit hint, "deliver promptly." It does *not* affect sequence numbers or reliability; a
  receiver that ignores it is still correct. Senders set it when flushing the send buffer (the last
  segment of a write). Useful mental model: PSH marks message boundaries the *application* cares about,
  even though TCP itself is a boundary-less stream.
- **URG + Urgent Pointer** — a largely-deprecated mechanism for "out-of-band" data: when URG is set,
  the 16-bit Urgent Pointer (bytes 18–19) gives the offset (from `seq`) of the last urgent byte, and the
  receiver is told to deliver up to there immediately (e.g. a Ctrl-C in telnet). It is widely considered
  a misfeature (ambiguous spec, security pitfalls) and RFC 6093 advises new applications not to use it.
  We never set URG; our Urgent Pointer is always 0. Knowing it exists explains the otherwise-mysterious
  bytes 18–19 of the header.

## F. How this day was later refactored (reassembler + socket API)

The clean separation the current code uses, and the day that introduced each piece:

```text
   wire → on_segment ─┬─ reasm.recv(seq, data, RCV.NXT)  → contiguous bytes   [Day 9]
                      │     (buffers out-of-order, trims duplicates)
                      ├─ recv_buf.extend(contiguous)      → app-visible bytes  [Day 11]
                      └─ return bare ACK (ack_options)     → acknowledge        [Day 4 idea, hardened]

   app loop (main) ─┬─ take_received()   → bytes for the application           [Day 11]
                    ├─ write(echo)       → queue into send_buf                  [Day 11]
                    └─ poll_transmit()   → drain send_buf to the wire,         [Days 8/10]
                                            bounded by min(SND.WND, cwnd), MSS
```

Why split it? Three reasons: (1) **reassembly** needs to hold out-of-order data and deliver it later,
which a fire-and-forget inline echo can't; (2) **flow/congestion control** must gate *sending*
independently of *receiving*, so send and receive became separate buffers with their own pacing; (3) a
real **application interface** is read/write, not "echo inside the protocol handler." The day-4 inline
echo is the right first lesson; the refactor is the right architecture. Both are in the git history, and
this book teaches the lesson while pointing at the architecture.

## G. A complete annotated echo trace (hex + TCB evolution)

One round trip of `"hi"`, client ISN 100, our ISS 0, established. `C` = client, `U` = us. TCP headers
only (IP omitted); checksum/urgent shown as `··`.

```text
   ① C→U  data  seq=101 ack=1  PSH,ACK  "hi"
      12 34 00 50 | 00 00 00 65 | 00 00 00 01 | 50 18 ff ff | ·· ·· 00 00 | 68 69
      sport 4660  | seq 101     | ack 1       | off5 P|A win | csum urg    | "hi"
      U TCB: RCV.NXT 101→103 (accepted "hi")

   ② U→C  echo  seq=1 ack=103  PSH,ACK  "hi"
      00 50 12 34 | 00 00 00 01 | 00 00 00 67 | 50 18 04 00 | ·· ·· 00 00 | 68 69
      sport 80    | seq 1       | ack 103     | off5 P|A win | csum urg    | "hi"
      U TCB: SND.NXT 1→3 (our echo in flight)

   ③ C→U  ack   seq=103 ack=3  ACK
      12 34 00 50 | 00 00 00 67 | 00 00 00 03 | 50 10 ff ff | ·· ·· 00 00
      sport 4660  | seq 103     | ack 3       | off5 ACK win | csum urg
      U TCB: SND.UNA 1→3 (echo acknowledged; nothing in flight)
```

Flag byte `0x18` = PSH|ACK on the data segments, `0x10` = ACK on the bare ack. The `+len`s are visible:
①'s "hi" (2 bytes) takes `RCV.NXT` 101→103; ②'s ack=103 echoes that pointer; ②'s "hi" takes `SND.NXT`
1→3; ③'s ack=3 confirms it.

## H. Comparison to real stacks — sockets, recv buffers, delayed ACK

```text
   concept              real kernel (Linux/BSD)                  this stack
   ──────────────────   ──────────────────────────────────────  ──────────────────────────
   receive path         segment → recv buffer (sk_rcvbuf)        reasm → recv_buf (Day 9/11)
   app read             recv()/read() drains the buffer          take_received()
   app write            send()/write() into send buffer          write() → send_buf
   send pacing          min(cwnd, rwnd), TSO/GSO offload         poll_transmit, min(SND.WND,cwnd)
   ACK policy           delayed (every 2nd / timer)              every segment (day 4)
   PSH                  set on buffer flush; mostly advisory     set on echo
   buffer sizing        autotuned SO_RCVBUF/SO_SNDBUF            fixed ~1 KB window
   copy                 zero-copy paths (sendfile, MSG_ZEROCOPY) copy into Vec
```

The shape matches — segment in, buffer, app reads, app writes, paced send — which is the point of the
refactor in §F: even a teaching stack benefits from the kernel's receive/app/send separation once
reliability and flow control enter.

## I. Security — data injection and why the acceptance window matters

The day-4 simplifications are exactly the ones an attacker abuses, which is why hardening them is the
security track:

- **Unconditional `SND.UNA = seg.ack`.** A forged segment with a bogus ack could *advance* `SND.UNA`
  past data the peer never acknowledged, making us discard unacknowledged data. The fix (`seq::between`,
  Day 6) only advances UNA for an ack in `(SND.UNA, SND.NXT]`, ignoring stale/forged values.
- **Blind data injection.** An off-path attacker who guesses the 4-tuple and a sequence number *in the
  window* can inject bytes into the stream. The acceptance window (§C) bounds *which* sequence numbers
  are accepted; a small window and random ISNs (Day 3 §D) shrink the attacker's target. RFC 5961 adds
  further checks (challenge ACKs).
- **RST injection.** The same logic applies to a forged RST — accepted only if in-window, which is why
  RFC 5961 tightened RST acceptance to the *exact* next sequence number.

The lesson: every "trust the field" simplification is an injection vector; the acceptance window and
ack validation are not just for correctness under loss, they're the connection's immune system.

## J. Performance — copies and per-segment ACK overhead

- **Copies.** We copy the payload into the echo `Vec`. For an echo that's unavoidable (the data turns
  around), but a real receiver hands the app a buffer slice without copying, and high-performance senders
  use zero-copy (`sendfile`, page flipping).
- **ACK overhead.** Acking every segment doubles small-packet count versus delayed ACK (§B). On a bulk
  transfer that's real overhead; for request/response echo it's negligible.
- **Per-segment cost.** Each segment is one hash lookup (demux), one acceptance check, two pointer
  advances, and (if echoing) one allocation + two checksums. All O(payload). NIC checksum offload would
  remove the checksum cost in a real stack; we pay it in software.
- **Syscall/packet ratio.** Real stacks amortize with TSO/GSO (hand the NIC a 64 KB "super-segment" it
  splits) and GRO (coalesce received segments). We process one segment per packet — simplest, slowest.

## K. Extended FAQ

1. **What makes a segment "in order"?** `seg.seq == RCV.NXT` — it starts exactly at the next expected
   byte.
2. **What happens to out-of-order data at day 4?** Dropped; Day 9's reassembler buffers it.
3. **What does `ack = 103` mean?** "I have everything below 103; send 103 next" (cumulative).
4. **What is piggybacking?** Carrying the ACK on a data segment — one packet does data + ack.
5. **Why `PSH|ACK` on the echo?** ACK acknowledges received data; PSH says "deliver promptly"; together
   they're a complete small message.
6. **Does PSH affect reliability?** No — it's an advisory delivery hint only.
7. **What are bytes 18–19 (Urgent Pointer)?** The URG mechanism; deprecated, always 0 for us (§E).
8. **Why advance `SND.NXT` by the payload length?** Those sequence numbers are now used by our data and
   must be acknowledged.
9. **What's `[SND.UNA, SND.NXT)`?** Data we've sent but the peer hasn't acked — the retransmit window
   (Day 6).
10. **Why is unconditional `SND.UNA = seg.ack` unsafe?** A forged/stale ack could move UNA wrongly; Day 6
    validates with `between`.
11. **Why only in-order at day 4?** Simplicity; correct on a lossless link. Loss/reorder needs the
    reassembler (Day 9).
12. **Does the final handshake ACK carry data?** It can; the handler completes ESTABLISHED then falls
    through to the data path.
13. **Where does the payload start in the packet?** `20 (IP) + data_offset (TCP)`; never assume 40.
14. **How is payload length known?** Derived from IP total length; TCP has no length field.
15. **What is a delayed ACK?** Acking every other segment / on a timer to cut ACK traffic (§B).
16. **What's the Nagle + delayed-ACK stall?** A held small write waiting on a delayed ACK → ~40 ms
    latency (Day 13).
17. **Does the current code echo inside `on_segment`?** No — it buffers and ACKs; the app echoes via
    `take_received`/`write`/`poll_transmit` (§F).
18. **Why was it refactored?** Reassembly, flow/congestion control, and a real read/write app interface
    (§F).
19. **What window do we advertise?** A fixed ~1 KB (`RCV.WND`); real stacks autotune it.
20. **Can a single segment carry data in both directions?** Each segment is one direction's data + the
    other direction's ack (piggyback); "both data" needs two segments.
21. **What's the acceptance window?** `[RCV.NXT, RCV.NXT + RCV.WND)`; a segment overlapping it is
    acceptable (§C).
22. **What if the window is 0?** Data is unacceptable but still ACKed; the sender probes (Day 14).
23. **Why ACK an out-of-window segment?** To re-sync a confused peer; repeated such ACKs become
    duplicate ACKs (Day 10).
24. **Is the echo's checksum recomputed?** Yes — `build_packet` zeroes then computes both IP and TCP
    checksums.
25. **How is this tested offline?** Feed a header+payload to `on_segment`, assert pointers and the echo
    bytes/checksums (§10).

## L. Anki starter deck

```text
Q: When is data "in order"?  A: seg.seq == RCV.NXT (starts at the next expected byte).
Q: How far does RCV.NXT advance on in-order data?  A: by the payload length (wrapping).
Q: Meaning of ACK = N?  A: "I have everything below N; send N next" (cumulative).
Q: What is piggybacking?  A: carrying the ACK on a data segment (one packet, two jobs).
Q: Flags on the echo segment?  A: PSH|ACK (0x18).
Q: Does PSH affect sequence numbers or reliability?  A: no — advisory "deliver promptly" only.
Q: How far does SND.NXT advance when we send k bytes?  A: by k (those seq numbers are in flight).
Q: What is [SND.UNA, SND.NXT)?  A: sent-but-unacked data (the retransmit window).
Q: Why is unconditional SND.UNA = seg.ack unsafe?  A: a forged/stale ack could move UNA wrongly.
Q: Day-4 acceptance vs real acceptance?  A: strict seq==RCV.NXT vs the 4-case window test (§C).
Q: Where does the payload start in a packet?  A: 20 (IP) + data_offset (TCP); never hard-code 40.
Q: What is a delayed ACK?  A: ack every other segment / on a timer to cut ACK traffic.
Q: How did the code later split this day?  A: reassembler + recv_buf + app write/poll_transmit.
Q: Bytes 18–19 of the TCP header?  A: the (deprecated) Urgent Pointer; 0 for us.
```

## M. Glossary

- **Data transfer** — moving payload bytes over an ESTABLISHED connection, acknowledged and ordered.
- **Cumulative ACK** — the ACK number; "everything below this is received."
- **Piggyback** — carry an ACK on a data segment.
- **PSH** — push flag; "deliver buffered data promptly."
- **URG / Urgent Pointer** — deprecated out-of-band data mechanism (bytes 18–19).
- **In-order** — `seg.seq == RCV.NXT`; the next expected bytes.
- **Acceptance window** — `[RCV.NXT, RCV.NXT + RCV.WND)`; the seq range a receiver will accept.
- **In flight** — sent but not yet acknowledged: `[SND.UNA, SND.NXT)`.
- **Delayed ACK** — acking every other segment / on a timer to reduce ACK packets.
- **Echo server** — sends received bytes back; our day-4 end-to-end proof.
- **`take_received` / `write` / `poll_transmit`** — the current code's app read / app write / paced
  send (the refactor of the inline echo).

## N. Reference tables

**N.1 — Pointer updates per event**

```text
   event                         pointer change
   ───────────────────────────   ──────────────────────────────
   in-order data of len L in     RCV.NXT += L
   we send L payload bytes       SND.NXT += L
   peer acks (ack A acceptable)  SND.UNA  = A   (day-4: unconditional; later: if between(UNA,A,NXT))
```

**N.2 — Flag bytes seen in data transfer**

```text
   byte 13   flags      typical use
   ───────   ────────   ─────────────────────────────
   0x10      ACK        bare acknowledgement
   0x18      PSH|ACK    data segment (push + ack)
   0x11      FIN|ACK    last data / close (Day 5)
```

**N.3 — Day-4 simplifications → where each is hardened**

```text
   simplification                      hardened on   by
   ────────────────────────────────    ───────────   ─────────────────────────────
   in-order only (drop OOO)            Day 9         reassembler (buffer + deliver)
   SND.UNA = seg.ack unconditionally   Day 6         seq::between(UNA, ack, NXT) check
   ack every segment                   (exercise)    delayed ACK
   ignore SND.WND                      Day 8         flow control
   send immediately (no Nagle)         Day 13        Nagle + TCP_NODELAY
```

> Re-type the ESTABLISHED data branch — accept in order, advance `RCV.NXT`, echo `PSH|ACK`, advance
> `SND.NXT` — with the book closed, then `cargo test`. When `printf 'hi' | nc 192.168.0.2 8080` prints
> `hi`, you have run an application over a TCP stack you built from raw packets.
