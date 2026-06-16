# Doc 8 — TCP, Part 6: Flow Control (the Sliding Window)

> Goal: stop a fast sender from drowning a slow receiver. Every TCP segment carries a **window**: the
> receiver's standing offer of "I have room for this many more bytes." The sender must keep its
> unacknowledged data within that offer. This chapter wires up *both* directions of that contract —
> honoring the peer's advertised window (`SND.WND`) and advertising our own (`RCV.WND`) honestly — and is
> careful about which window is which, because mixing them up is a classic, silent bug (one we had, and
> fix here).

Reliability (Doc 6) makes bytes *arrive*; flow control makes them arrive *at a survivable rate*. The
mechanism — the sliding window — is one of the most elegant ideas in networking: a single 16-bit field,
updated on every segment, that lets a receiver continuously throttle a sender end-to-end with no separate
control channel. The subtlety, and the bug this chapter fixes, is that there are *two* windows sharing
one field's name, and confusing them silently breaks the contract.

**Contents**

Volume I — the chapter
1. The mental model: the receiver sets the pace
2. The window field, and the *two* windows
3. Tracking the peer's window — `SND.WND`
4. `usable_window()` — how much we may send right now
5. Advertising *our* window — `RCV.WND` (and the bug we fixed)
6. Worked numbers
7. The Rust: two `u16`s that mean opposite things, and safe arithmetic
8. The code, walked end to end
9. Verification
10. Why this, not that
11. Honesty: what production does, and what later days added
12. Rebuild it yourself — checklist + exercises
13. What the next step adds

Volume II — the exhaustive reference
- A. The sliding window, completely (edges, pointers, motion)
- B. The two windows and `SND.WL1`/`SND.WL2` (stale-update protection)
- C. Silly Window Syndrome — Clark's receiver fix and Nagle's sender fix
- D. The zero window and the persist timer (preview of Doc 14)
- E. The bandwidth-delay product and the 64 KB ceiling (preview of Doc 17)
- F. Flow control vs congestion control — the two limits
- G. A worked sliding-window animation
- H. The bug, deep — the `u16` type confusion and how a newtype prevents it
- I. Comparison to real stacks — receive-window autotuning
- J. Security — window-manipulation and zero-window attacks
- K. Performance — BDP, throughput caps, bufferbloat
- L. Extended FAQ
- M. Anki starter deck
- N. Glossary
- O. Reference tables

---

# Volume I — the chapter

## 1. The mental model: the receiver sets the pace

Reliability (Doc 6) guarantees bytes *arrive*; it says nothing about whether the receiver can *keep up*.
A receiver has a finite buffer between "bytes off the wire" and "bytes the application has read." If the
sender blasts data faster than the app drains that buffer, the buffer overflows and bytes are dropped —
which then have to be retransmitted, wasting the very bandwidth that caused the overflow. **Flow control**
is the receiver throttling the sender to its own pace.

The mechanism is the **sliding window**, and it is gloriously simple: in every segment, the receiver
advertises a `window` = the number of bytes it can currently accept *beyond what it has already
acknowledged*. The sender treats that as a hard ceiling on **in-flight (unacknowledged) data**. As ACKs
come back, the window "slides" forward and more may be sent. When the window reaches zero, the sender
must stop and wait for it to reopen.

Two properties make this beautiful: it needs **no separate channel** (the window rides on the ACKs that
are already flowing), and it is **self-clocking** — each ACK both frees window *and* paces the next send,
so the sender naturally transmits at the rate the receiver drains. This is **end-to-end** and
receiver-driven, and it is distinct from *congestion* control (Doc 10), which is *network*-driven. The
real send limit is `min(receiver's window, congestion window)`. This chapter is the receiver-driven half.

## 2. The window field, and the *two* windows

The `window` lives in the TCP header — bytes 14–15, the 16-bit field we've parsed since Doc 1:

```text
   byte 14        byte 15
  ┌────────────┬────────────┐
  │   window (16 bits, big-endian)  │   →  0..65535 bytes the SENDER of this segment can accept
  └────────────┴────────────┘
```

The trap that snares everyone: **there are two windows, and each segment's `window` field means
different things depending on who sent it.** From *our* point of view:

| Name | RFC | Meaning | Where it comes from |
|---|---|---|---|
| `SND.WND` (`send.wnd`) | §3.3.1 | how much **the peer** can accept → bounds how much **we** may send | read from *incoming* segments' window field |
| `RCV.WND` (`recv.wnd`) | §3.3.1 | how much **we** can accept | written into *outgoing* segments' window field |

So the window field is **inbound → updates `SND.WND`**, and **outbound → carries `RCV.WND`**. Reading the
wrong one into the wrong place is undetectable by a casual test (both are just `u16`s) and quietly
corrupts the contract. §5 is exactly that story; §H dissects why the type system didn't catch it and how
it could.

## 3. Tracking the peer's window — `SND.WND`

Before this feature, `send.wnd` was set once at connection setup (to our init constant) and never updated
— so we had no idea how much the peer could actually take. The fix is one line in the `ESTABLISHED`
branch: every acceptable segment from the peer refreshes our view of its window.

```rust
// Flow control: track the peer's advertised receive window so we never send more
// unacknowledged data than it can hold (RFC 9293 §3.4).
self.send.wnd = th.window;   // (Doc 17 widens this: (th.window as u32) << snd_wscale)
```

`SND.WND` is now live — it rises and falls as the peer's buffer drains and fills. (A fuller stack also
guards against an *old* segment moving the window backwards, using `SND.WL1`/`SND.WL2` sequence checks
(§B); we take the simpler "latest acceptable wins," which is correct on our in-order link. Doc 14 adds a
"window unchanged" check so a pure window update isn't mistaken for a duplicate ACK.)

## 4. `usable_window()` — how much we may send right now

The window bounds **in-flight** data, not total data. In-flight = everything sent but not yet
acknowledged = `SND.NXT − SND.UNA` (the "FlightSize" of RFC 5681). So the bytes we may still send without
overrunning the peer:

```rust
pub fn usable_window(&self) -> u32 {
    let in_flight = self.send.nxt.wrapping_sub(self.send.una);   // SND.NXT − SND.UNA
    (self.send.wnd as u32).saturating_sub(in_flight)             // SND.WND − in_flight
}
```

Two deliberate uses of wrapping/saturating arithmetic:

- `wrapping_sub` for `in_flight` — `SND.NXT` and `SND.UNA` are 32-bit sequence numbers that wrap (Doc 3);
  their *difference* is the true count even across the 2³² boundary.
- `saturating_sub` for the result — if in-flight somehow exceeds the window (it shrank under us), we
  report `0` ("send nothing"), never a giant number from unsigned underflow.

A bulk sender gates every transmission on `usable_window()`. The echo path sends tiny 2-byte echoes that
never approach even a small window, so doc 8 *computes* the limit without yet *enforcing* it; Doc 11's
`poll_transmit` enforces it for the HTTP/bulk path. (Doc 10 also folds in the congestion window:
`usable = min(SND.WND, cwnd) − FlightSize`.)

## 5. Advertising *our* window — `RCV.WND` (and the bug we fixed)

Here is §2's trap, made concrete. Our segment builder must advertise `recv.wnd` (our receive capacity):

```rust
fn segment(&self, seq, ack, flags, payload) -> Vec<u8> {
    build_packet(self.local, self.remote, seq, ack, flags, self.recv.wnd, payload)
}                                                          // ↑ OUR window — RCV.WND
```

It used to read `send.wnd` — and that "worked" only by accident: while `send.wnd` was a frozen constant
equal to `recv.wnd` (both `1024`), the two were indistinguishable. The moment §3 made `send.wnd` track
the *peer's* window, `segment()` began **parroting the peer's window back** as if it were ours: tell us
you have 64 KB free and our next segment would falsely claim *we* have 64 KB free — advertising buffer we
don't have, inviting exactly the overflow flow control is meant to prevent. The fix is `send.wnd →
recv.wnd`, now pinned by the test `advertises_our_receive_window_not_the_peers`.

We advertise a **constant `1024`** because our receiver never backs up: an echo server consumes each
segment the instant it arrives, so its free buffer is always the full 1024. A real receiver shrinks
`RCV.WND` as unread bytes pile up and grows it as the application reads — that dynamic window is the
sliding window's other edge (exercise E2; §C covers the silly-window pitfall of doing it naively).

## 6. Worked numbers

The peer advertises a 500-byte window; we trace `usable_window()` as data and ACKs flow
(`tracks_peer_window` asserts the first line):

```text
   SND.WND=500, SND.UNA=1, SND.NXT=1   in_flight = 0     usable = 500 − 0   = 500
   send 200 bytes → SND.NXT=201        in_flight = 200   usable = 500 − 200 = 300
   send 300 more  → SND.NXT=501        in_flight = 500   usable = 500 − 500 = 0   → STOP
   peer ACKs 100  → SND.UNA=101        in_flight = 400   usable = 500 − 400 = 100 → may send 100
```

The window **slides**: an ACK that advances `SND.UNA` frees an equal amount of send budget. And the
zero-window case (`usable = 0`) is where a sender must park — see §D / Doc 14.

And the advertisement side (`advertises_our_receive_window_not_the_peers`):

```text
   peer's segment carries window = 0xffff (65535)   → SND.WND = 65535
   our echo's window field                          = RCV.WND = 1024   (NOT 65535)
```

## 7. The Rust: two `u16`s that mean opposite things, and safe arithmetic

- **The bug was a type-system gap.** `send.wnd` and `recv.wnd` are both `u16` (well, `recv.wnd` is `u16`;
  Doc 17 widens `send.wnd` to `u32`), so the compiler happily let `segment()` read the wrong one. Nothing
  in `u16` says "this is *the peer's* capacity" vs "this is *our* capacity." A **newtype** (`struct
  SndWnd(u16); struct RcvWnd(u16);`) would have made the mistake a compile error (§H). We instead pin it
  with a test and clear field names — the pragmatic fix — but the lesson is real: when two values have
  the same representation and opposite meaning, the type system is your friend.
- **Wrapping vs saturating, chosen deliberately.** `wrapping_sub` for a *difference of sequence numbers*
  (correct across the 2³² wrap); `saturating_sub` for a *count that must not underflow* (a shrunk window
  yields 0, not a 4-billion-byte "usable window"). Picking the right overflow discipline per operation is
  a recurring theme in this stack.
- **`u16` field, wider internal math.** The wire window is 16 bits, but `usable_window` returns `u32` and
  the internal `SND.WND` becomes `u32` (Doc 17) so window scaling can exceed 64 KB. The *advertised* field
  stays 16 bits by definition; only the *interpreted* value widens.

## 8. The code, walked end to end

Everything is in `src/tcp.rs`; `main` is unchanged (flow control is internal accounting):

| Piece | Role |
|---|---|
| `send.wnd` (`SND.WND`) | the peer's advertised window; refreshed from each incoming segment |
| `recv.wnd` (`RCV.WND`) | our advertised window (constant 1024); written by `segment()` |
| `self.send.wnd = th.window` | the one-line tracker in the `ESTABLISHED` branch |
| `usable_window()` | `SND.WND − (SND.NXT − SND.UNA)`, saturating at 0 |
| `segment()` | stamps every outgoing header with `recv.wnd` |

Data path: a peer segment arrives → `send.wnd` updates to its window → if we reply, `segment()` advertises
*our* `recv.wnd` back → `usable_window()` reflects the peer's window minus our in-flight bytes, ready for
a sender to consult.

## 9. Verification

`cargo test` proves the accounting offline. Flow-control coverage:

- `tracks_peer_window` — peer advertises 500; with nothing in flight, `usable_window()` is 500.
- `advertises_our_receive_window_not_the_peers` — even when the peer advertises `0xffff`, our echo's
  window field is `1024` (our `RCV.WND`), proving §5's fix and guarding against its return.
- (Later) `peer_window_is_left_shifted_by_negotiated_scale` (Doc 17) — the window-scaling widening of
  `SND.WND`; `window_updates_and_zero_windows_are_not_duplicate_acks` (Doc 14) — a window change isn't a
  dup ACK.

Live (your hands): `nc 192.168.0.2 8080`, then `sudo tcpdump -i tun0 -n -v` and read the `win` field —
outbound segments from us show `win 1024`; the client's segments show *its* window. To see the window
genuinely *slide* you need a bulk transfer that fills the pipe, since the echo path keeps in-flight data
near zero.

## 10. Why this, not that

| Decision | We chose | Real TCP |
|---|---|---|
| Our advertised window | constant 1024 | dynamic: shrinks with unread data, grows as the app reads |
| Enforce `usable_window` | computed at doc 8; enforced in `poll_transmit` (Doc 11) | sender blocks/segments to fit the window |
| Window-update ordering | latest acceptable wins | `SND.WL1`/`SND.WL2` guard against stale updates (§B) |
| Zero-window handling | none at doc 8; persist timer added Doc 14 | persist timer + zero-window probes (§D) |
| Silly-window syndrome | not addressed | Nagle (sender, Doc 13) + receiver SWS avoidance (Clark, §C) |
| Window scaling | none at doc 8; added Doc 17 | `WScale` option shifts the window up to ~1 GB |
| flow vs congestion | flow control only | effective window = `min(SND.WND, cwnd)` (Doc 10) |

## 11. Honesty: what production does, and what later days added

- **`SND.WND` widened to `u32` on Doc 17.** Window scaling (RFC 7323) multiplies the 16-bit field by a
  negotiated shift, so the *interpreted* send window can reach ~1 GB; `send.wnd` became `u32` and the
  tracker became `(th.window as u32) << snd_wscale` (§E).
- **The congestion window joined the limit on Doc 10.** `usable_window` became
  `min(SND.WND, cwnd) − FlightSize` — flow control caps you at the receiver, congestion control at the
  network, and you obey the smaller.
- **Enforcement arrived with the send buffer (Doc 11).** `poll_transmit` drains an application send buffer
  into segments bounded by `usable_window()` and the MSS — the doc-8 accounting finally *gating* real
  transmission.
- **Zero-window probes arrived Doc 14.** When the peer advertises 0, a naive sender parks forever if the
  window-reopen ACK is lost; the persist timer pokes a 1-byte probe to break the deadlock (§D).
- **`SND.WL1`/`SND.WL2` not implemented.** We take "latest acceptable wins" rather than the RFC's
  sequence-checked window update; correct on our in-order link, not against a reordering network (§B).
- **Static receive window / no SWS avoidance.** A real receiver autotunes `RCV.WND` and avoids
  advertising tiny windows (Clark's algorithm, §C). We advertise a flat 1024.

None of these change the doc-8 contract (we honor the peer's window and advertise our own honestly); they
are the breadth the later days add.

## 12. Rebuild it yourself — checklist + exercises

**Blank-file checklist:**

- [ ] The two windows and the rule: *inbound* window field → `SND.WND`; *outbound* → `RCV.WND`.
- [ ] Why `usable_window = SND.WND − (SND.NXT − SND.UNA)`, and why both arithmetic guards
      (`wrapping_sub`, `saturating_sub`) are there.
- [ ] The §5 bug in one sentence — advertising `send.wnd` parrots the peer's window — and the one-token
      fix.
- [ ] Why the window bounds *in-flight* data, not total data.

**Exercises:**

- **E1.** ✅ *Done* (Doc 11): a real sender that *enforces* `usable_window()` — queue application data and
  emit only up to the window, deferring the rest until ACKs slide it open.
- **E2.** Make `RCV.WND` dynamic: track a receive buffer, shrink the advertised window as unread bytes
  accumulate, grow it (with a window-update ACK) as the app reads — and avoid silly-window syndrome (§C).
- **E3.** ✅ *Done* (Doc 14): handle a **zero window** with a persist timer and a 1-byte probe so a lost
  window-update can't deadlock the connection.
- **E4.** ✅ *Done* (Doc 17): add **window scaling** (RFC 7323) — negotiate `WScale` in the SYN and shift
  the window, lifting the 64 KB ceiling.
- **E5.** Implement `SND.WL1`/`SND.WL2` so a stale (reordered) segment can't move `SND.WND` backwards
  (§B).

## 13. What the next step adds

Doc 9 adds **out-of-order reassembly** — a receive buffer that holds gaps until they fill, so a reordered
or retransmitted segment is delivered in order rather than dropped (the receiver-side complement to Doc 6
and the foundation for SACK, Doc 18). Then Doc 10 adds **congestion control** — capping the sender at what
the *network* can carry (slow start, AIMD, fast retransmit/recovery), making the real send limit
`min(SND.WND, cwnd)`. Flow control is the receiver's half of pacing; congestion control is the network's.

---

# Volume II — the exhaustive reference

## A. The sliding window, completely (edges, pointers, motion)

The send window, drawn against the sequence space, with the four regions every byte falls into:

```text
            SND.UNA            SND.NXT          SND.UNA+SND.WND
              │                  │                    │
   ───────────┼──────────────────┼────────────────────┼───────────────►  sequence
    (1) acked │ (2) sent, unacked│ (3) sendable now   │ (4) not yet allowed
              │   = in-flight    │   = usable window  │   (beyond the window)
              │◄──── SND.WND (the receiver's offer) ──►│
```

- **(1)** below `SND.UNA`: acknowledged, done, forgotten (dropped from the retx queue).
- **(2)** `[SND.UNA, SND.NXT)`: in flight — sent, awaiting ACK, retained for retransmission.
- **(3)** `[SND.NXT, SND.UNA + SND.WND)`: the **usable window** — bytes we may send *right now*.
- **(4)** at/after `SND.UNA + SND.WND`: beyond the receiver's offer — forbidden until the window slides.

**Motion.** Two events move the edges:

```text
   we send k bytes:   SND.NXT += k         (region 2 grows, region 3 shrinks)
   peer ACKs k bytes: SND.UNA += k         (region 1 grows; the WHOLE window slides right by k,
                                            re-opening region 3 by k — "self-clocking")
   peer changes wnd:  SND.WND = new        (the right edge moves; region 3 grows or shrinks)
```

The receiver's `RCV.WND` is the symmetric picture on the other side: `[RCV.NXT, RCV.NXT + RCV.WND)` is
what it will accept. The two windows are independent — a connection can have a huge send window and a tiny
receive window, or vice versa.

## B. The two windows and `SND.WL1`/`SND.WL2` (stale-update protection)

A reordering network can deliver an *old* segment after a newer one. If we blindly take "latest segment
wins," an old segment carrying a *smaller* window could shrink `SND.WND` after a newer one grew it —
corrupting the offer. RFC 9293 §3.10.7.4 guards against this with two extra variables:

- **`SND.WL1`** — the sequence number of the segment that last updated `SND.WND`.
- **`SND.WL2`** — the acknowledgment number of that segment.

The rule: update `SND.WND` from an incoming segment only if it is *newer* —
`SND.WL1 < SEG.SEQ`, or (`SND.WL1 == SEG.SEQ` and `SND.WL2 ≤ SEG.ACK`). This accepts a window update only
from a segment at least as recent as the one that set the current window, so a delayed old segment can't
move it backward. We omit this (correct on our in-order TUN link); exercise E5 adds it. The practical
symptom of omitting it on a reordering path is occasional spurious window shrink/grow.

## C. Silly Window Syndrome — Clark's receiver fix and Nagle's sender fix

**Silly Window Syndrome (SWS)** is a degenerate equilibrium where the window advances in tiny increments,
so the connection sends many small, inefficient segments (huge header-to-data overhead). It can be caused
by *either* end:

- **Receiver-caused.** A slow application reads one byte at a time; a naive receiver advertises a 1-byte
  window each time, the sender sends a 1-byte segment, repeat — a stream of 41-byte packets carrying 1
  byte each. **Clark's algorithm (RFC 813 / RFC 1122):** the receiver does *not* advertise a window
  increase until it can offer a "useful" amount — at least one MSS or half the buffer. It keeps the
  window closed (or unchanged) and only re-opens it in worthwhile chunks.
- **Sender-caused.** An application writes one byte at a time; a naive sender ships each as its own
  segment. **Nagle's algorithm (RFC 896, Doc 13):** while there's unacknowledged data outstanding, hold a
  small (sub-MSS) write and coalesce it with later writes, sending only when a full segment accumulates or
  the outstanding data is acked. `TCP_NODELAY` opts out for latency-sensitive traffic.

Together, Clark (receiver) and Nagle (sender) keep the window moving in efficient chunks. We implement
Nagle (Doc 13) but not Clark (our window is a flat 1024, never tiny). The famous gotcha is the
Nagle + delayed-ACK interaction (Doc 4 §B): a Nagle-held write waiting on a delayed ACK → a ~40 ms stall.

## D. The zero window and the persist timer (preview of Doc 14)

When the receiver's buffer fills, it advertises `window = 0` — "stop sending." The sender parks. The
hazard: the window reopens via an ACK ("I have room now"), but **a pure ACK is not retransmitted**, so if
that window-update ACK is lost, the sender waits forever for a signal that will never come, and the
receiver waits forever for data — a **deadlock**.

The fix is the **persist timer**: when the window is zero and we have data to send, the sender
periodically sends a **zero-window probe** — a 1-byte segment into the closed window. The receiver
responds with its current window (an ACK), so even if the original window-update was lost, the probe
elicits a fresh one and breaks the deadlock. The probe interval backs off exponentially (like the RTO).
We add this on Doc 14 (`persist_ms`); doc 8 simply computes `usable = 0` and would stall without it. This
is the one place flow control *requires* the sender to keep poking, because silence is ambiguous between
"no room" and "lost the reopen."

## E. The bandwidth-delay product and the 64 KB ceiling (preview of Doc 17)

The window must be at least one **bandwidth-delay product (BDP)** to keep a pipe full: to have data
arriving continuously, a sender must have `bandwidth × RTT` bytes in flight before the first ACK returns.

```text
   BDP = bandwidth × RTT
   e.g. 1 Gbit/s × 80 ms = 1e9/8 × 0.080 ≈ 10 MB
```

But the window *field* is 16 bits → max 65,535 bytes. On that 1 Gbit/s × 80 ms path, a 64 KB window caps
throughput at `64 KB / 80 ms ≈ 6.5 Mbit/s` — **0.6 %** of the link. The field, sized in 1981, is the
bottleneck on any modern "long fat network."

**Window scaling (RFC 7323, Doc 17)** fixes it without changing the field: both ends negotiate a shift
`S` (0–14) in the SYN, and thereafter a window value `W` means `W << S`. With `S = 14`, a full field of
65,535 means ~1 GB — plenty for any BDP. This is why `SND.WND` becomes `u32` (Doc 17): the *interpreted*
window exceeds 16 bits even though the wire field doesn't. Flow control (doc 8) sets up the machinery;
window scaling lifts its ceiling.

## F. Flow control vs congestion control — the two limits

Two independent limits bound how fast a sender may transmit, and the sender obeys the **smaller**:

```text
   limit                bounds against        set by             our field
   ──────────────────   ───────────────────   ────────────────   ──────────────
   flow control         receiver overflow      the receiver       SND.WND  (Doc 8)
   congestion control   network overflow       the sender (infer) cwnd     (Doc 10)

   effective window = min(SND.WND, cwnd) − FlightSize
```

They answer different questions: flow control asks "can the *receiver* hold more?"; congestion control
asks "can the *network* carry more?" A connection can be flow-limited (slow receiver, fast network) or
congestion-limited (fast receiver, congested network). Conflating them is a classic confusion: a large
receive window does *not* mean you may blast — `cwnd` may be tiny after a loss. Doc 8 builds the first
limit; Doc 10 builds the second and the `min`.

## G. A worked sliding-window animation

A sender with `SND.WND = 400`, MSS 100, starting `SND.UNA = SND.NXT = 1000`. Watch all four regions move.
`|` marks `SND.UNA`, `^` marks `SND.NXT`, `]` marks the window's right edge `SND.UNA + SND.WND`.

```text
   t0  send nothing:           |^                                ]   usable = 400
       1000                    1000                            1400
   t1  send 4×100 (fill win):  |          ^                     ]   usable = 0   (in-flight 400)
       1000                    1000      1400                 1400
   t2  ACK 1200 (2 segs):              |        ^               ]   window slid +200
       1200                          1200      1400         1600   usable = 200 (in-flight 200)
   t3  send 2×100 (refill):           |                  ^      ]   usable = 0   (in-flight 400)
       1200                          1200              1600   1600
   t4  peer shrinks wnd to 100,    |        ^                ]      right edge MOVED LEFT
       ACK 1300:                 1300     1600           1400      usable = saturating(100−300)=0
```

t4 shows the saturating guard earning its keep: the receiver shrank its window while data was in flight,
so `SND.WND − in_flight = 100 − 300` underflows — `saturating_sub` reports `0` ("send nothing"), the safe
answer, instead of a 4-billion-byte usable window from `u32` wraparound. The window will reopen as ACKs
advance `SND.UNA`.

## H. The bug, deep — the `u16` type confusion and how a newtype prevents it

The §5 bug: `segment()` advertised `send.wnd` (the peer's window) instead of `recv.wnd` (ours). It was
invisible while both were the constant 1024, and became wrong the instant `send.wnd` started tracking the
peer. Root cause: **two values with the same type and opposite meaning.** The compiler can't object to
`build_packet(..., self.send.wnd, ...)` vs `self.recv.wnd` — both are `u16`.

Rust's fix would be **newtypes**:

```rust
struct SndWnd(u32);   // the peer's capacity — bounds what WE send
struct RcvWnd(u16);   // our capacity — what WE advertise
// build_packet(window: RcvWnd, ...)  ← only RcvWnd accepted
```

Now passing `SndWnd` where `RcvWnd` is expected is a *compile error*; the mistake becomes impossible
rather than merely testable. This is the "make illegal states unrepresentable" principle. We chose the
pragmatic path — clear field names (`send.wnd`/`recv.wnd`) plus a regression test
(`advertises_our_receive_window_not_the_peers`) — because retrofitting newtypes through the whole header
builder is churn. But the bug is a textbook case for newtypes, and worth remembering whenever two
same-typed values mean opposite things (sequence-space "ours vs theirs," port "local vs remote", etc.).

## I. Comparison to real stacks — receive-window autotuning

```text
   aspect              real kernel (Linux)                       this stack
   ─────────────────   ───────────────────────────────────────  ─────────────────────
   receive window      autotuned (tcp_rmem), grows to BDP         flat 1024
   send buffer         autotuned (tcp_wmem)                       Doc 11 send_buf
   SWS avoidance       Clark (receiver) + Nagle (sender)          Nagle only (Doc 13)
   stale updates       SND.WL1/WL2 checks                         "latest wins" (no WL)
   zero window         persist timer + probes                     Doc 14
   window scaling      on by default (RFC 7323)                   Doc 17
   effective limit     min(rwnd, cwnd)                            min(SND.WND, cwnd) (Doc 10)
```

The big real-world feature we lack is **receive-window autotuning**: Linux starts with a modest window
and grows it toward the measured BDP as the connection proves it can drain fast, balancing memory against
throughput. A flat window either caps throughput (too small) or wastes memory (too big); autotuning
finds the sweet spot per connection. Our flat 1024 is fine for an echo server, wrong for bulk transfer.

## J. Security — window-manipulation and zero-window attacks

- **Zero-window DoS.** A malicious *receiver* can advertise a zero (or tiny) window and then read slowly
  or never, pinning the sender's resources (buffers, a parked connection) for a long time — the
  "slow-read" attack (e.g. Slowloris-style against servers). Defenses: cap how long a connection may sit
  flow-blocked, and bound per-connection memory.
- **Shrinking-window mischief.** A receiver shrinking its window after advertising a larger one (RFC
  forbids shrinking the *right edge*, but it happens) can confuse a naive sender; the saturating-subtract
  guard (§G) keeps *us* safe as a sender (we never compute a bogus huge usable window).
- **Window-update injection.** An off-path attacker who guesses the 4-tuple and an in-window sequence
  number could inject a segment that moves `SND.WND` (e.g. shrink it to stall, or grow it to provoke an
  overrun). The `SND.WL1/WL2` checks (§B) and small windows + random ISNs reduce the target; RFC 5961
  adds further validation.
- **Optimistic ACK / window manipulation for congestion (Doc 10).** A lying receiver can ACK data early
  or advertise a huge window to make a sender transmit faster than safe — more a congestion-control
  attack, but it rides the same fields.

The theme: the window is an attacker-influenced control input in *both* directions (a malicious receiver
stalls a sender; an injected segment moves our window), so a hardened stack validates window updates and
bounds the resources a flow-blocked connection can hold.

## K. Performance — BDP, throughput caps, bufferbloat

- **Throughput is `window / RTT`** (when window-limited). Too small a window caps a fast/long path far
  below the link rate (§E); this is *the* reason window scaling exists.
- **Too large a window** wastes receiver memory and, combined with over-buffered routers, causes
  **bufferbloat**: data piles up in network queues, inflating RTT and harming latency for everyone. The
  modern answer is *not* "bigger windows" but smarter congestion control (BBR) and AQM (CoDel) — flow
  control alone can't see queue buildup.
- **Self-clocking** makes the steady state efficient: each ACK paces the next send, so a well-tuned
  window transmits smoothly at the receiver's drain rate with no bursts. Bursts come from window *jumps*
  (a big ACK freeing a lot at once), which pacing (a real-stack feature) smooths.
- **Our cost** is one field update per segment and one subtraction in `usable_window` — negligible. The
  performance *limitation* is the flat 1024 window, which caps bulk throughput; that's by design for an
  echo server and lifted conceptually by Docs 10/11/17.

## L. Extended FAQ

1. **What does the window field advertise?** Bytes the *sender of that segment* can currently accept
   beyond what it has acked.
2. **What are the two windows?** `SND.WND` (peer's capacity, bounds our sending) and `RCV.WND` (our
   capacity, what we advertise).
3. **Which window does an *incoming* segment's field update?** `SND.WND`.
4. **Which window does an *outgoing* segment's field carry?** `RCV.WND`.
5. **What was the doc-8 bug?** `segment()` advertised `send.wnd` (the peer's window) instead of
   `recv.wnd` (ours).
6. **Why did the bug hide for so long?** Both windows were the constant 1024 until `send.wnd` started
   tracking the peer.
7. **What does `usable_window` compute?** `SND.WND − (SND.NXT − SND.UNA)` — the window minus in-flight
   data.
8. **Why `wrapping_sub` for in-flight?** Sequence numbers wrap; their difference is the true count across
   2³².
9. **Why `saturating_sub` for the result?** A shrunk window must yield 0, not an underflowed huge number.
10. **Does the window bound total or in-flight data?** In-flight (`SND.NXT − SND.UNA`).
11. **What makes the window "slide"?** An ACK advancing `SND.UNA` frees an equal amount of send budget.
12. **What is a zero window?** `window = 0` — "stop sending"; handled with a persist timer (Doc 14).
13. **What deadlock does the persist timer prevent?** A lost window-reopen ACK leaving both sides waiting
    forever.
14. **What is Silly Window Syndrome?** Tiny window increments causing many small segments; fixed by Clark
    (receiver) + Nagle (sender).
15. **Why is our advertised window constant?** An echo server drains instantly, so its free buffer is
    always 1024.
16. **What are `SND.WL1`/`SND.WL2`?** Sequence/ack of the last window update, to reject stale ones (§B).
17. **Flow vs congestion control?** Receiver-imposed (`SND.WND`) vs network-imposed (`cwnd`); obey the
    `min`.
18. **What's the BDP?** Bandwidth × RTT — the window needed to keep a pipe full (§E).
19. **Why is 64 KB sometimes too small?** On a long fat network the BDP exceeds the 16-bit field; window
    scaling (Doc 17) fixes it.
20. **When did we *enforce* the window?** Doc 11's `poll_transmit` (doc 8 only computes it).
21. **When did `SND.WND` become `u32`?** Doc 17 (window scaling).
22. **Can the peer shrink its window?** It can (the RFC discourages moving the right edge left); our
    saturating math stays safe.
23. **What's bufferbloat?** Over-large network buffers inflating latency; flow control alone can't see it
    (§K).
24. **Is a big receive window always good?** No — it wastes memory and can worsen bufferbloat; autotuning
    balances it.
25. **How would the type system prevent the §5 bug?** Newtypes (`SndWnd`/`RcvWnd`) make the mix a compile
    error (§H).

## M. Anki starter deck

```text
Q: What does the TCP window field advertise?  A: bytes the segment's sender can accept beyond its ACK.
Q: Two windows from our view?  A: SND.WND (peer's capacity → bounds our sending), RCV.WND (ours → advertised).
Q: Incoming segment's window updates which?  A: SND.WND.
Q: Outgoing segment's window carries which?  A: RCV.WND.
Q: usable_window formula?  A: SND.WND − (SND.NXT − SND.UNA), saturating at 0.
Q: Why wrapping_sub for in-flight?  A: sequence numbers wrap; the difference is the true count.
Q: Why saturating_sub for usable?  A: a shrunk window must give 0, not an underflowed huge value.
Q: Does the window bound total or in-flight data?  A: in-flight.
Q: What makes the window slide?  A: an ACK advancing SND.UNA frees equal send budget.
Q: The doc-8 bug?  A: advertising send.wnd (peer's) instead of recv.wnd (ours).
Q: Zero-window deadlock fix?  A: persist timer + 1-byte probe (Doc 14).
Q: Silly Window Syndrome fixes?  A: Clark (receiver) + Nagle (sender).
Q: Flow vs congestion control?  A: receiver-imposed SND.WND vs network-imposed cwnd; obey the min.
Q: BDP?  A: bandwidth × RTT — the window needed to keep the pipe full.
Q: Why 64KB caps a fast/long path?  A: 16-bit window < BDP; window scaling (Doc 17) lifts it.
```

## N. Glossary

- **Flow control** — receiver-driven throttling of the sender to its buffer's drain rate.
- **Sliding window** — the advancing range of sendable sequence numbers bounded by the receiver's offer.
- **`SND.WND` / `RCV.WND`** — the peer's advertised window (bounds our sending) / our advertised window.
- **In-flight / FlightSize** — sent-but-unacked data, `SND.NXT − SND.UNA`.
- **Usable window** — `SND.WND − FlightSize`; bytes we may send now.
- **Self-clocking** — each ACK paces the next send and frees window.
- **Zero window** — `window = 0`; handled with the persist timer (Doc 14).
- **Silly Window Syndrome** — tiny window increments → many small segments; Clark + Nagle avoid it.
- **`SND.WL1` / `SND.WL2`** — last-window-update seq/ack, for rejecting stale updates.
- **BDP (bandwidth-delay product)** — bandwidth × RTT; the window needed to fill a pipe.
- **Bufferbloat** — excess network buffering that inflates latency.

## O. Reference tables

**O.1 — Which window is which**

```text
   direction   field reads/writes   variable    meaning
   ─────────   ──────────────────   ─────────   ─────────────────────────────────
   inbound     read                 SND.WND     how much the peer can accept (bounds our send)
   outbound    write                RCV.WND     how much we can accept (our advertisement)
```

**O.2 — Window arithmetic guards**

```text
   quantity            operation        why
   ─────────────────   ──────────────   ────────────────────────────────────
   in-flight count     wrapping_sub     SND.NXT − SND.UNA across the 32-bit wrap
   usable window       saturating_sub   SND.WND − in_flight, never underflow → 0
```

**O.3 — The two send limits**

```text
   limit         variable   set by       day    bounds against
   ───────────   ────────   ──────────   ────   ──────────────────
   flow          SND.WND    receiver     8      receiver overflow
   congestion    cwnd       sender       10     network overflow
   effective     min(both) − FlightSize  10     both
```

> Re-type the window accounting from this chapter with the book closed, then `cargo test`. You now hold
> the receiver's half of pacing: open (Doc 3), data (Doc 4), close (Doc 5), reliability (Doc 6), active
> close (Doc 7), and flow control (Doc 8). When you can say which window each segment's field means
> *without thinking*, the §5 bug will never be yours.
