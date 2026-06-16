# Doc 14 — TCP, Part 12: Zero-Window Probes (the Persist Timer)

> Goal: fix the one deadlock that flow control quietly created. Doc 8 taught the sender to obey the
> receiver's advertised window: when the peer says "my window is 0," we stop. Correct — but incomplete. The
> signal that the window has *re-opened* travels in a pure ACK, and pure ACKs are not retransmitted. Lose
> that one ACK and both sides wait forever: the receiver thinks it told us to resume, the sender is still
> holding. TCP's escape is the **persist timer** (RFC 9293 §3.8.6.1): when the window is shut and we have
> data to send, periodically poke a single byte into the closed window, forcing the peer to re-announce its
> current window. This chapter implements it — and, on the way, tightens the duplicate-ACK rule so a window
> update can never be mistaken for packet loss.

This is a *correctness* day, not an efficiency one: it closes the last way our connection could silently
hang. The lesson is deep — **TCP's liveness must never depend on an unacknowledged segment** — and the fix
is a small jewel: don't build a new retransmission loop, just fire one probe and let the existing RTO machine
repeat it.

**Contents**

Volume I — the chapter
1. The mental model: a silence that kills
2. Why this can't be fixed by retransmitting data
3. The persist timer: probe the closed window
4. What the probe is, exactly
5. Letting the retransmission queue do the repeats
6. The companion fix: a window update is not a duplicate ACK
7. The Rust: one field, one branch in `on_tick`
8. Worked example: shut, probe, reopen
9. The code, walked end to end
10. Verification
11. Why this, not that
12. Honesty: what production does, and what we don't
13. Rebuild it yourself — checklist + exercises
14. What the next step adds

Volume II — the exhaustive reference
- A. The deadlock in full — why pure ACKs aren't reliable
- B. The persist timer vs the retransmission timer
- C. Silly Window Syndrome avoidance (receiver side)
- D. The four duplicate-ACK conditions, exhaustively
- E. A worked stall-and-recover trace (hex)
- F. Comparison to real stacks — persist limits
- G. Security — zero-window slow-read and sockstress
- H. Performance — the cost of a stalled connection
- I. Extended FAQ
- J. Anki starter deck
- K. Glossary
- L. Reference tables

---

# Volume I — the chapter

## 1. The mental model: a silence that kills

Flow control is a promise: "I, the receiver, will accept up to `RCV.WND` more bytes." When the receiver's
buffer fills, it advertises `window = 0`, and a well-behaved sender (ours, since Doc 8) stops dead —
`usable_window()` is 0, so `poll_transmit` emits nothing. Later the application drains the buffer and the
receiver sends a fresh ACK: "window = 4000, you may resume." That update is the *only* thing that unblocks
the sender.

Now notice what kind of segment that update is: a **pure ACK** — no data, no SYN, no FIN. It consumes no
sequence number, so the receiver never queues it for retransmission. If the network drops it:

```text
   sender (blocked)                 receiver
     |  window=0 received → STOP      buffer fills
     |                                ...app drains buffer...
     |        (ACK "window=4000" is LOST)
     |   ...sender waits for a window update...
     |                                ...receiver waits for data it already invited...
    DEADLOCK forever — neither side will speak first.
```

This is not a rare corner: any connection that ever hits a full receiver (a slow consumer, a paused
download) is one dropped ACK away from a permanent hang. The principle to engrave: **TCP must not depend on
an unacknowledged segment for liveness.** Anything load-bearing must be retransmittable, and a pure ACK
isn't — so the responsibility to break the silence falls on the *sender*, which is counterintuitive (the
*receiver* opened the window) but necessary (only the sender has retransmittable state to lean on).

## 2. Why this can't be fixed by retransmitting data

Your first instinct (mine too) is "just let the retransmission timer resend something." But there is
*nothing in the retransmission queue*: the sender stopped before putting any of the blocked bytes on the
wire, precisely because the window was 0. `FlightSize == 0`. The retransmission machinery from Doc 6/12 only
resends what was already sent; here, by construction, nothing was. So liveness needs a *new* action:
deliberately send something into a window we've been told is closed. That deliberate, slightly-rude poke is
the zero-window probe.

## 3. The persist timer: probe the closed window

The rule (RFC 9293 §3.8.6.1):

> When the send window is zero and the sending TCP has data to send, it sends a small **probe** segment
> periodically (the *persist timer*) so that the receiver is forced to re-advertise its window. The probe
> carries one byte of new data; the timer backs off exponentially.

The probe's job is not to deliver data — it is to *provoke a reply*. The receiver, on getting a byte it
cannot accept (its window is 0), must still send an ACK, and that ACK carries its **current** window. If the
window is still 0, we learn nothing new and probe again later. If it has re-opened, the ACK tells us and the
stall is broken. Either way the connection cannot silently die: we keep asking until we get an answer. The
persist timer is, in effect, "I refuse to accept silence as a final answer about your window."

## 4. What the probe is, exactly

A zero-window probe is **one byte of real, sequence-consuming data**, sent at `SND.NXT`:

- We take the first byte of the blocked send buffer and send it in a 1-byte segment.
- It advances `SND.NXT` by 1 and goes into the retransmission queue like any other data — so it is not lost
  from our bookkeeping even if the receiver discards it.
- The receiver either accepts it (window had quietly re-opened) and ACKs *past* it, or rejects it (window
  genuinely 0) and re-ACKs `RCV.NXT` *without* advancing — but it ACKs, which is the point.

We only probe when **`FlightSize == 0`** (nothing already in flight). If data *were* in flight, the ordinary
retransmission timer would already be poking the peer; the persist timer exists exactly for the case where
the queue is empty and there is no other source of liveness.

## 5. Letting the retransmission queue do the repeats

A subtle, satisfying simplification: the persist timer only needs to fire **once**. After the first probe is
sent, `FlightSize` becomes 1 — there is now an unacknowledged segment in the queue. From that moment, the
**ordinary RTO retransmission** (Doc 6) resends that same one-byte segment on its own timer, with the usual
exponential backoff. That *is* the persist repeat. So:

- persist timer → sends the **first** probe (because the queue was empty);
- RTO retransmission → sends every **subsequent** probe (because now the queue is not).

We disarm the persist timer the instant a probe is outstanding (`FlightSize > 0`), and re-arm only if we
somehow return to "window 0, data pending, nothing in flight." This reuses machinery instead of duplicating
a backoff loop, and it keeps the probe spacing consistent with the connection's RTO. It's the same
design-economy as Doc 12 (control segments ride the existing queue): build the *trigger*, reuse the *engine*.

## 6. The companion fix: a window update is not a duplicate ACK

Adding zero-window handling exposes a latent bug in the Doc 10 duplicate-ACK logic. RFC 5681 §2 defines a
duplicate ACK by **four** conditions, all of which must hold:

1. the ACK number equals `SND.UNA` (acknowledges no new data),
2. the segment carries no data,
3. `SND.UNA < SND.NXT` (data is outstanding),
4. **the advertised window is the same as in the previous ACK.**

We had been checking only the first three. Condition 4 matters now because two perfectly normal events
produce an ACK with `ack == SND.UNA` and no data:

- a **window update** (receiver re-advertises a *different* window), and
- a **zero-window probe response** (receiver re-ACKs with window 0).

Without condition 4, three of these in a row would trip *fast retransmit* and needlessly halve the
congestion window — treating a flow-control event as packet loss. So we now record the previous window and
require `th.window == prev_wnd` **and** `th.window != 0` before counting a duplicate ACK. A changed window is
an update; a zero window is the receiver being full; neither is congestion. (With window scaling, Doc 17,
the comparison is on the *scaled* values — §D.)

## 7. The Rust: one field, one branch in `on_tick`

- A `persist_ms: u64` field on `Connection` — the absolute time the next probe is due, `0` when disarmed.
  Initialized `0` in both constructors.
- A branch at the end of `on_tick`:

```rust
if self.state == State::Established
    && self.send.wnd == 0
    && !self.send_buf.is_empty()
    && self.flight_size() == 0
{
    if self.persist_ms == 0 {
        self.persist_ms = now_ms.saturating_add(self.rtt.rto()); // arm one RTO out
    } else if now_ms >= self.persist_ms {
        if let Some(byte) = self.send_buf.pop_front() {
            let probe = self.segment(self.send.nxt, self.recv.nxt, ACK, &[byte]);
            self.send.nxt = self.send.nxt.wrapping_add(1);
            self.retx.record(self.send.nxt.wrapping_sub(1), self.send.nxt, probe.clone(), now_ms);
            out.push(probe);
        }
        self.persist_ms = 0; // disarm; the retx queue now repeats the probe
    }
} else {
    self.persist_ms = 0; // window open, nothing to send, or a probe already in flight
}
```

The four-part `&&` is the exact "we are stalled and only a probe can save us" condition. The `else` disarms
the moment any clause stops holding (window opened, buffer drained, or a probe is already outstanding) — so
the timer is self-resetting, no explicit teardown. The dup-ACK fix is two extra `&&` clauses in `on_segment`.
That is the whole feature. (`record`'s `start_seq` argument is Doc 18's; doc 14 used the four-arg form.)

## 8. Worked example: shut, probe, reopen

ESTABLISHED, `SND.NXT = 1`, default RTO 200 ms. App wants to send "hello".

```text
   t=0    peer ACK ack=1 window=0      → SND.WND = 0; sender blocked
          app write "hello"            → buffered; poll_transmit sends nothing (usable=0)
   t=100  on_tick: wnd=0, data pending, FlightSize=0, persist disarmed
                                        → ARM persist_ms = 100 + 200 = 300
   t=350  on_tick: now ≥ 300           → FIRE probe: 1 byte 'h' at seq=1; SND.NXT=2; FlightSize=1
                                        → disarm persist; 'h' now lives in the retx queue
   ...if still 0, RTO resends 'h' at t≈550, 950, … (backoff) — these are the repeat probes...
   t=400  peer ACK ack=2 window=1000   → accepts 'h', SND.UNA=2, SND.WND=1000, FlightSize=0
          poll_transmit                → sends "ello" (seq 2, 4 bytes). Deadlock broken.
```

Had we *not* probed, the lost `window=1000` ACK at some later point would have left both ends mute. The
probe guarantees we ask again.

## 9. The code, walked end to end

All in `src/tcp.rs`:

- **Struct / constructors**: `persist_ms: u64`, initialized `0`.
- **`on_segment`** (ESTABLISHED): capture `prev_wnd` before overwriting `send.wnd`; add
  `th.window == prev_wnd && th.window != 0` (scaled, Doc 17) to the duplicate-ACK condition.
- **`on_tick`**: the persist branch above. It appends the probe to the same `Vec` the RTO retransmissions go
  into, so the event loop sends it with no special casing.

`main.rs` is unchanged — it already calls `on_tick` every loop and sends whatever it returns.

## 10. Verification

`cargo test` adds three tests:

- `zero_window_arms_then_fires_persist_probe` — a shut window with pending data arms the timer on the first
  tick and emits exactly one 1-byte probe at `SND.NXT` after the RTO.
- `persist_probe_recovers_when_window_reopens` — the peer's reopening ACK acknowledges the probe and the
  rest of the data flows: the deadlock is broken end to end.
- `window_updates_and_zero_windows_are_not_duplicate_acks` — three window-update ACKs and three zero-window
  ACKs all return `None` (no fast retransmit), proving condition 4 of the dup-ACK rule.

## 11. Why this, not that

| Decision | Alternative | Why |
|---|---|---|
| Probe with 1 byte of real data | Send a zero-length "window probe" segment | A data byte is unambiguously sequence-consuming and forces an ACK; a real next byte is simplest and never wasted. |
| Persist fires once; RTO does the repeats | A separate persist backoff loop | Reuses the existing retransmission timer/backoff; one fewer timer to get wrong; probe spacing tracks the RTO. |
| Probe only when `FlightSize == 0` | Probe whenever the window is 0 | If data is in flight, the RTO already pokes the peer — a persist probe would be redundant. |
| Exclude window-updates *and* zero windows from dup-ACK | Only add RFC 5681 condition 4 | Condition 4 alone still miscounts steady zero-window re-acks (window unchanged at 0) as dups; excluding `window == 0` too keeps a flow-control stall from ever looking like loss. |

## 12. Honesty: what production does, and what we don't

- **No persist cap / abort.** RFC 9293 §3.8.6.1 lets a stack give up after the user timeout if probes go
  unanswered indefinitely; we probe forever (exercise E1). A peer that advertises 0 and never reopens pins
  our connection.
- **No receiver-side Silly Window Syndrome avoidance.** A correct *receiver* shouldn't reopen its window in
  tiny increments (or our probe would chase a 1-byte window, sending runts) — RFC 9293 §3.8.6.2 / Clark's
  algorithm says only advertise a re-opened window once it grows by ≥ 1 MSS or ½ the buffer. Our receiver
  has a flat window and never shrinks it, so this doesn't arise here, but a real receive buffer needs it
  (Doc 8 §C, exercise E2).
- **`record` gained `start_seq` (Doc 18).** The probe is recorded with the SACK-aware `record(start_seq,
  end_seq, …)` now; doc 14 used the four-arg form.
- **Window-update comparison is scaled (Doc 17).** The dup-ACK condition compares *scaled* windows once
  window scaling is negotiated, so a scaled-window change still isn't mistaken for a dup.
- **Probe data choice.** We send the next *real* buffered byte; some stacks send a byte *below* `SND.UNA`
  (guaranteed-old, definitely rejected) to avoid advancing the stream if the window is genuinely shut. Both
  force an ACK; the real-byte approach is simpler and the byte is never wasted (it's data we wanted to send
  anyway).

None of these change the doc-14 contract (a stalled connection always recovers when the window reopens, and
a window event is never mistaken for loss); they are hardening and the receiver-side complement.

## 13. Rebuild it yourself — checklist + exercises

**Blank-file checklist:**

- [ ] Why does a lost window-update ACK deadlock the connection? Why can't the RTO save it?
- [ ] What is a zero-window probe, and what response does it force from the receiver?
- [ ] Why does the persist timer only need to fire once?
- [ ] State all four RFC 5681 duplicate-ACK conditions. Which two did we add, and why?
- [ ] Why probe only when `FlightSize == 0`?

**Exercises:**

- **E1.** Add an explicit persist backoff cap and a connection-abort after ~R2 unanswered probes (RFC 9293
  §3.8.6.1 / the user timeout). Test it.
- **E2.** Implement Silly Window Syndrome avoidance on the *receiver*: don't advertise a re-opened window
  until it grows by at least one MSS (or ½ the buffer), so probes don't chase 1-byte windows (§C).
- **E3.** Make the probe re-send the *same* byte explicitly via a dedicated persist path rather than leaning
  on the RTO queue, and compare the two designs' complexity.
- **E4.** Write a test where the window reopens but the probe byte is *not* accepted (peer ACKs `SND.UNA`
  with a non-zero window); confirm `poll_transmit` then sends from the buffer correctly.
- **E5.** Reproduce a **sockstress**-style zero-window attack in a test (§G) and add a per-connection limit
  on how long it may sit flow-blocked.

## 14. What the next step adds

Doc 15 begins the **TCP options** era. So far every segment we build has a bare 20-byte header; we have
ignored the options field on the way in and never written one on the way out. Doc 15 adds the machinery to
*parse* and *emit* options, and uses it for the most fundamental one: **MSS negotiation** (RFC 9293
§3.7.1) — read the peer's Maximum Segment Size from its SYN, advertise our own, and segment outgoing data to
the negotiated value instead of a hardcoded 1460. That option framework is the foundation the next several
days (timestamps, window scaling, SACK) all build on.

---

# Volume II — the exhaustive reference

## A. The deadlock in full — why pure ACKs aren't reliable

The zero-window deadlock is a small instance of a fundamental asymmetry in TCP's reliability:

```text
   reliable (retransmitted):   data, SYN, FIN, zero-window probes  — they consume sequence space
   NOT reliable (not retx'd):  pure ACKs, window updates           — they consume no sequence space
```

A pure ACK is *idempotent and self-superseding* — if one is lost, the *next* ACK (carrying a higher-or-equal
cumulative number) replaces it, so TCP can safely not retransmit ACKs. This works perfectly **as long as
there will be a next ACK**. The zero-window case breaks that assumption: after advertising window 0, the
receiver has nothing to ACK (no data is arriving — it told the sender to stop), so the "window reopened" ACK
might be the *only* ACK for a long time, with no successor to supersede it if lost. The general rule — *don't
depend on an unacknowledged segment for liveness* — is violated, and the persist probe restores it by
manufacturing a reason for the receiver to ACK (a byte it must respond to), turning "no next ACK" into "an
ACK on demand." It's the same flavor as the Two Generals' Problem (Doc 7 §F): you can't be *sure* your
message arrived, so you keep asking until you get a reply.

## B. The persist timer vs the retransmission timer

TCP runs (conceptually) several timers; the persist and retransmission timers are easy to confuse but do
opposite jobs:

```text
   timer            armed when                          fires to                      backoff
   ──────────────   ─────────────────────────────────  ───────────────────────────  ────────
   retransmission   data is in flight, unacked          resend lost data              exponential
   persist          window is 0, data pending, none      probe the closed window       exponential
                    in flight
   keepalive        connection idle (optional)           detect a dead peer            —
   TIME_WAIT (2MSL) after active close                   reap the connection           —
```

The crucial relationship (§5): the persist timer and the retransmission timer are **mutually exclusive by
construction**. Persist fires only when `FlightSize == 0` (retransmission has nothing to do); the instant it
sends a probe, `FlightSize == 1` (retransmission takes over, persist disarms). So a connection is *either*
retransmitting outstanding data *or* persisting into a closed window, never both — which is why we can let
one fire the first probe and the other fire the repeats with no coordination. They're two faces of one idea:
keep poking the peer until it answers, whether the silence is "lost my data" (retransmit) or "closed your
window" (persist).

## C. Silly Window Syndrome avoidance (receiver side)

The persist probe has a failure mode if the *receiver* is naive: if the receiver reopens its window one byte
at a time (because its app reads one byte at a time), each probe elicits "window = 1," the sender sends one
byte, the receiver advertises "window = 1" again — a stream of 1-byte segments, the **Silly Window Syndrome**
(SWS, Doc 8 §C). The fix is **receiver-side SWS avoidance** (RFC 9293 §3.8.6.2 / Clark's algorithm): the
receiver must *not* advertise a re-opened window until it can offer a "useful" amount — at least one MSS or
half the receive buffer, whichever is smaller. Until then it keeps advertising 0 (and keeps absorbing
probes), then jumps the window open in a worthwhile chunk.

So SWS avoidance and the persist timer are partners: persist guarantees the sender keeps *asking*; SWS
avoidance guarantees the receiver only *answers* with a window worth filling. Together they recover from a
full buffer efficiently (one big window update, a burst of full segments) rather than pathologically (a
trickle of 1-byte probes and replies). Our receiver has a flat 1024 window and never shrinks it, so SWS
never arises in our stack — but a real receive buffer (exercise E2) must implement Clark's rule or the
persist mechanism degrades into tinygram chasing.

## D. The four duplicate-ACK conditions, exhaustively

RFC 5681 §2's definition of a duplicate ACK, with *why* each condition is necessary (a violation that would
otherwise misfire as fast retransmit):

```text
   # condition                          excludes the false positive of…
   ─ ─────────────────────────────────  ──────────────────────────────────────────────────
   1 SEG.ACK == SND.UNA                  an ACK that advances UNA (real progress, not a dup)
   2 segment carries no data             a data segment that happens to re-ack (it's new data)
   3 SND.UNA < SND.NXT                   an ack when nothing is outstanding (nothing to retransmit)
   4 advertised window unchanged         a WINDOW UPDATE (same ack, no data, but new window)
   + (ours) window != 0                  a ZERO-WINDOW re-ack (same ack, no data, window steady at 0)
```

Conditions 1–3 say "this ACK reports no forward progress on outstanding data." Condition 4 adds "and it
isn't carrying news about the *window*." Our extra `window != 0` clause handles the steady-zero-window case
that condition 4 alone misses: while the window sits at 0, successive re-acks have an *unchanged* window
(0 == 0, satisfying condition 4) and no data and ack == UNA — so without the extra clause, three zero-window
re-acks would be counted as duplicates and trip fast retransmit, halving `cwnd` over a *flow-control* stall
that has nothing to do with congestion. Excluding `window == 0` keeps a full-receiver event from ever looking
like loss. (Under window scaling, Doc 17, conditions compare the *scaled* window so the same logic holds for
windows > 64 KB.)

## E. A worked stall-and-recover trace (hex)

A bulk send hitting a full receiver, the reopening ACK lost once, recovered by a probe. TCP flags shown;
`window` is the key field. `U` = us (sender), `C` = client (receiver).

```text
   ① C→U  ACK ack=1 win=0        U: SND.WND=0 → poll_transmit blocked; app has "hello" buffered
   ── on_tick arms persist (rto out) ──
   ② U→C  ACK seq=1 ack=X win=Y  "h"   (persist probe — 1 byte, after the RTO)   FlightSize→1
      C: window still 0 → discards 'h', re-acks
   ③ C→U  ACK ack=1 win=0        (probe rejected; NOT a dup-ACK — window==0 clause)
   ── app drains; C would send win=4000, but that ACK is LOST ──
   ── RTO resends the probe (FlightSize>0) ──
   ④ U→C  ACK seq=1 ack=X "h"    (RTO retransmit of the probe)
      C: window now open → accepts 'h'
   ⑤ C→U  ACK ack=2 win=4000     U: SND.UNA=2, SND.WND=4000 → unblocked
   ⑥ U→C  PSH,ACK seq=2 "ello"   poll_transmit flushes the rest. Recovered.
```

The lost win=4000 ACK (between ③ and ④) would have deadlocked a probe-less stack forever. The persist probe
(then its RTO repeat) forces ⑤, the fresh window advertisement that breaks the stall. Note ③ correctly does
*not* count as a duplicate ACK (window == 0), so the stall never masquerades as congestion.

## F. Comparison to real stacks — persist limits

```text
   aspect              real stacks (Linux)                       this stack
   ─────────────────   ────────────────────────────────────────  ──────────────────────
   persist trigger     window 0, data pending, nothing in flight  same
   first probe         after the persist timer (≈ RTO)             after the RTO
   probe repeats       persist timer, exponential backoff          RTO queue does the repeats
   probe limit         tcp_retries2 / TCP_USER_TIMEOUT abort       none (probe forever)
   probe content       1 byte (often the next data byte)           the next buffered byte
   receiver SWS        Clark's avoidance (no tiny windows)         flat window (n/a)
   zero-window guard   in dup-ACK detection                        window==prev && window!=0
```

The one structural difference is the **repeat engine**: Linux runs a dedicated persist timer with its own
backoff; we lean on the retransmission queue (§5). Both reach the same behavior (a probe roughly every RTO,
backing off). The one *missing* safety is the **abort limit**: a real stack stops probing after the user
timeout / `tcp_retries2` and errors the connection, so a peer stuck at window 0 forever doesn't pin a socket
indefinitely. We probe forever (exercise E1) — which is the door §G's attacks walk through.

## G. Security — zero-window slow-read and sockstress

The persist mechanism keeps a connection *alive* through a closed window — which a malicious receiver turns
into a resource-exhaustion attack:

- **Slow-read / zero-window DoS.** A client connects, requests a large response, then advertises `window = 0`
  and *never reopens it*. The server's connection is pinned indefinitely: it holds the response in its send
  buffer, dutifully probes forever (with our uncapped persist), and consumes a socket/TCB/memory the whole
  time. Open thousands of such connections and a server runs out of sockets/memory while sending almost no
  data — the receiver-side analogue of Slowloris.
- **Sockstress (Outpost24, 2008).** A family of attacks that includes the zero-window variant: complete the
  handshake cheaply (often statelessly, via the attacker's own minimal stack), then advertise a tiny or zero
  window so the server must hold connection state and buffered data essentially forever. It targets the
  *memory and connection-table* cost of held connections, not bandwidth — devastating precisely because each
  attacking connection costs the attacker almost nothing but pins real server resources.
- **The defense is the limit we lack.** Bound how long a connection may sit flow-blocked (the user timeout /
  `tcp_retries2` abort, §F), cap the number of zero-windowed connections, and bound per-connection send-buffer
  memory. Our uncapped "probe forever" is exactly the vulnerable choice; exercise E1/E5 adds the bound.

The theme: liveness mechanisms (keep-alive, persist) are double-edged — they keep good connections alive *and*
let a hostile peer keep bad connections alive at the server's expense. Every "never give up" must be paired
with a "but eventually give up" bound, which our teaching version omits and a production stack must not.

## H. Performance — the cost of a stalled connection

- **A stalled connection is mostly free to *probe* but expensive to *hold*.** One probe per RTO is negligible
  bandwidth; the cost is the *held state* — the send buffer full of undelivered data, the TCB, the socket —
  for as long as the window stays shut. On a server with many slow consumers, that held memory dominates
  (§G).
- **The probe's own overhead** is one 41-byte segment per RTO (then per backed-off RTO), trivial. The
  exponential backoff means even a long stall costs only `log` probes, not one-per-RTO forever.
- **SWS avoidance is a throughput feature** (§C): without it, recovery from a full buffer is a trickle of
  1-byte segments (terrible goodput); with it, recovery is a burst of full segments after one big window
  update. Our flat window sidesteps it but a real receive buffer needs it for post-stall throughput.
- **Our cost** is one comparison per `on_tick` (the four-clause guard) and the dup-ACK extra conditions —
  free. The *risk* is the unbounded hold (§G), a correctness/security gap, not a throughput one.

## I. Extended FAQ

1. **What deadlock does doc 14 fix?** A lost window-reopen ACK leaving sender and receiver both waiting
   forever.
2. **Why can't the RTO fix it?** The blocked bytes were never sent (window was 0), so the retransmission
   queue is empty.
3. **What is the persist timer?** A timer that fires a zero-window probe when the window is shut and data is
   pending.
4. **What is a zero-window probe?** One byte of real data sent into a closed window to force the receiver to
   re-ack its current window.
5. **Why one byte of real data?** It's sequence-consuming (forces an ACK) and never wasted (it's data we
   wanted to send).
6. **What response does the probe force?** An ACK carrying the receiver's *current* window (0 or reopened).
7. **Why probe only when `FlightSize == 0`?** If data is in flight, the RTO already pokes the peer.
8. **Why does persist only need to fire once?** After the first probe, `FlightSize > 0`, so the RTO queue
   repeats it.
9. **When is the persist timer disarmed?** The moment the window opens, the buffer drains, or a probe is
   outstanding.
10. **What are the four duplicate-ACK conditions?** ack==UNA, no data, UNA<NXT, window unchanged (+ our
    window!=0).
11. **Why did adding zero-window expose a dup-ACK bug?** Window updates and zero-window re-acks look like dup
    ACKs without condition 4.
12. **What would the bug have done?** Three such ACKs → fast retransmit → needless `cwnd` halving on a
    flow-control event.
13. **Why also exclude `window == 0`?** Steady zero-window re-acks have an unchanged window (0==0) and would
    still miscount.
14. **What is Silly Window Syndrome here?** Probes chasing a 1-byte-at-a-time reopened window (§C).
15. **What is receiver SWS avoidance?** Don't reopen the window until it grows ≥ 1 MSS / ½ buffer (Clark).
16. **Does our receiver need SWS avoidance?** Not with a flat window; a real receive buffer does.
17. **Do we cap probes?** No (probe forever); real stacks abort after the user timeout (§F).
18. **What attack does uncapped persist enable?** Zero-window slow-read / sockstress resource exhaustion
    (§G).
19. **What's the sockstress zero-window variant?** Cheap handshake + tiny/zero window pinning server state
    forever.
20. **What's the defense?** Bound flow-blocked time, cap zero-windowed connections, bound send-buffer memory.
21. **Is the persist timer the same as the retransmission timer?** No — mutually exclusive; persist when
    nothing's in flight, retransmit when something is (§B).
22. **What does `main.rs` change?** Nothing — it already sends whatever `on_tick` returns.
23. **What general rule does this enforce?** Never depend on an unacknowledged (pure-ACK) segment for
    liveness (§A).
24. **Does the probe advance the data stream?** Yes (it's the next real byte); some stacks send an old byte
    to avoid that.
25. **Why is this a "correctness," not "efficiency," day?** It removes a deadlock, not a slowdown — Nagle was
    efficiency.

## J. Anki starter deck

```text
Q: What deadlock does the persist timer fix?  A: a lost window-reopen ACK leaving both sides waiting forever.
Q: Why can't the RTO fix the zero-window deadlock?  A: the blocked bytes were never sent → retx queue empty.
Q: What is a zero-window probe?  A: 1 byte of real data sent into a closed window to force a window re-ack.
Q: Why one byte of real data?  A: sequence-consuming (forces an ACK) and never wasted.
Q: Why probe only when FlightSize == 0?  A: if data is in flight, the RTO already pokes the peer.
Q: Why does persist only fire once?  A: after the probe, FlightSize>0, so the RTO queue repeats it.
Q: Four duplicate-ACK conditions?  A: ack==UNA, no data, UNA<NXT, window unchanged (+ our window!=0).
Q: Why must a window update not count as a dup ACK?  A: 3 would trip fast retransmit, halving cwnd over a flow event.
Q: Why also exclude window==0 from dup-ACK?  A: steady zero-window re-acks have unchanged window (0==0).
Q: Persist vs retransmission timer?  A: mutually exclusive — persist when nothing's in flight, retransmit when something is.
Q: What is receiver SWS avoidance?  A: don't reopen the window until it grows ≥1 MSS / ½ buffer (Clark).
Q: Do we cap zero-window probes?  A: no (probe forever); real stacks abort after the user timeout.
Q: What attack does uncapped persist enable?  A: zero-window slow-read / sockstress resource exhaustion.
Q: General rule this enforces?  A: never depend on an unacknowledged (pure-ACK) segment for liveness.
Q: Efficiency or correctness day?  A: correctness — it removes a deadlock (Nagle was efficiency).
```

## K. Glossary

- **Persist timer** — the timer that fires zero-window probes when the window is shut and data is pending.
- **Zero-window probe** — a 1-byte segment sent into a closed window to force a window re-advertisement.
- **Window update** — a pure ACK re-advertising a changed (usually reopened) window.
- **Duplicate ACK** — an ACK reporting no forward progress (4 conditions, RFC 5681 §2).
- **Silly Window Syndrome (SWS)** — pathological tiny-window/tiny-segment exchange.
- **Receiver SWS avoidance (Clark)** — only reopen the window in useful (≥ MSS / ½ buffer) increments.
- **Sockstress** — a family of resource-exhaustion attacks including the zero-window pin.
- **Slow-read DoS** — a malicious receiver advertising window 0 to pin server resources.
- **FlightSize** — unacked data outstanding (`SND.NXT − SND.UNA`); 0 is the persist trigger.
- **Liveness** — the guarantee a connection won't silently hang; the persist timer protects it.

## L. Reference tables

**L.1 — The persist trigger (all must hold)**

```text
   condition                 meaning
   ───────────────────────   ─────────────────────────────────────
   state == ESTABLISHED       only probe an open connection
   SND.WND == 0               the window is shut
   !send_buf.is_empty()       we have data we want to send
   FlightSize == 0            nothing else is poking the peer
```

**L.2 — The two probe phases**

```text
   phase           who sends it      spacing
   ─────────────   ───────────────   ─────────────────────────
   first probe     persist timer      one RTO after arming
   repeat probes   RTO retransmit     RTO, exponential backoff
```

**L.3 — Duplicate-ACK conditions (ours)**

```text
   #   condition                what it rejects
   ─   ──────────────────────   ──────────────────────────────────
   1   ack == SND.UNA            an ACK that advances (real progress)
   2   no data                   a data segment that re-acks
   3   SND.UNA < SND.NXT         nothing outstanding to retransmit
   4   window == prev_wnd        a window UPDATE
   5   window != 0               a steady zero-window re-ack
```

> Re-type the persist branch and the dup-ACK condition with the book closed, then `cargo test`. Your stack
> can no longer be killed by a single dropped ACK — the last silent deadlock is gone. (Now go bound the
> probe, or a malicious receiver will pin you forever — §G.)
