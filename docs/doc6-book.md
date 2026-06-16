# Doc 6 — TCP, Part 4: Reliability (Retransmission, the Event Loop & the Adaptive RTO)

> Goal: make the connection **reliable**. Until now every byte we sent was assumed to arrive. A real
> network drops packets. So we keep a copy of every segment we send, start a clock, and if its
> acknowledgement doesn't come back in time we **resend** it. The "in time" part is the subtle one — too
> eager and we flood the link with needless copies; too patient and a lost segment stalls the connection
> for a second. So we *measure* the round-trip time and let the timeout track the path. This is the
> chapter Doc 5 §10 promised as "the right Step 6," and it required a structural change: moving off
> blocking I/O to an event loop.

This is the day TCP earns the word "reliable." It is also the day the *architecture* changes — a
blocking `recv()` loop physically cannot run a timer, so the whole I/O model is rebuilt. Three pieces
arrive together and interlock: the **event loop** (somewhere for time to pass), the **retransmission
queue** (a memory of what's unacknowledged), and the **adaptive RTO** (a deadline that tracks the
path).

**Contents**

Volume I — the chapter
1. The mental model: what "reliable" actually costs
2. Why the blocking loop could not do this (the design change)
3. The non-blocking event loop
4. The retransmission queue
5. Karn's algorithm — why a retransmitted segment's timing lies
6. The RTT estimator: SRTT, RTTVAR, and the RTO (RFC 6298)
7. Worked numbers (the exact ones the tests assert)
8. The Rust: monotonic time, owned packets, time-passed-in
9. The code, walked end to end
10. Verification
11. Why this, not that
12. Honesty: what production does, and what later days added
13. Rebuild it yourself — checklist + exercises
14. What the next step adds

Volume II — the exhaustive reference
- A. RFC 6298 in full: every equation and constant
- B. A short history: RFC 793's broken RTO and Jacobson/Karels (1988)
- C. Karn's algorithm in depth (the two halves)
- D. The fixed-point arithmetic — why right-shifts, no floats
- E. The event loop in depth — blocking, non-blocking, epoll, io_uring, timer wheels
- F. Timer-driven vs ACK-driven loss detection (RTO vs fast retransmit)
- G. A full retransmission episode with backoff, worked numerically
- H. A complete annotated lossy trace (hex + timers)
- I. Comparison to real stacks — RTO, timer wheels, RACK-TLP
- J. Security — low-rate "shrew" DoS and RTT manipulation
- K. Performance — timer overhead, goodput, the cost of a wrong MIN_RTO
- L. Extended FAQ
- M. Anki starter deck
- N. Glossary
- O. Reference tables

---

# Volume I — the chapter

## 1. The mental model: what "reliable" actually costs

TCP promises the application a **reliable, ordered byte stream** over an **unreliable** packet network.
The network may drop, duplicate, reorder, or corrupt any packet. Corruption we already catch (the
checksum, Doc 2). Reordering and gaps are a later chapter (Doc 9). *Loss* is this one.

The only tool TCP has against loss is **redundancy in time**: send a segment, and if you don't hear
that it arrived, send it again. Two pieces of machinery fall out of that one sentence:

- **A memory of what's unacknowledged.** You cannot resend what you've thrown away, so every segment
  carrying sequence space (data, SYN, FIN) must be *retained* until its ACK arrives. That is the
  **retransmission queue**.
- **A clock and a deadline.** "If you don't hear back *in time*" needs a definition of time and of *in
  time*. That is the **retransmission timeout (RTO)**, and computing a good one is the job of the RTT
  estimator.

ACKs are cumulative: `SND.UNA` (the oldest unacknowledged byte) only moves forward, and when it passes
a segment's last byte, that whole segment is safe to forget. So the queue is drained from the *front*
by advancing `SND.UNA`, and topped up at the *back* as we send. The retransmission queue is, in effect,
a window onto `[SND.UNA, SND.NXT)` — the sent-but-unacked bytes — with each segment remembering when it
was sent.

The deep idea: reliability is a *closed control loop*. We send, we observe (ACK or silence), and we act
(forget, or resend). The RTT estimator is the loop's sense of time; getting it wrong in either
direction (too fast → spurious resends that *cause* congestion; too slow → stalls) is why this day is
more about *measurement* than about *resending*.

## 2. Why the blocking loop could not do this (the design change)

Through Doc 5 the main loop was, in essence:

```text
   loop { let n = iface.recv(&mut buf)?;  // BLOCKS until a packet arrives
          handle(packet); }
```

`recv()` parks the thread until the kernel hands it a packet. That is fine for a pure request/response
echo — but a retransmission timer has to fire **when nothing is arriving** (the whole point is that the
expected ACK *didn't* come). In a blocking loop there is no moment to check a clock: the thread is
asleep inside `recv()`, possibly forever. This is exactly the "blocker" Doc 5 §10 named.

The fix is structural, not a patch: switch the interface to **non-blocking** I/O. Now `recv()` returns
immediately — either a packet, or a `WouldBlock` error meaning "nothing right now." That frees the loop
to do two jobs on every pass: service timers, then read a packet if one is ready.

```rust
iface.set_non_blocking()?;
let clock = std::time::Instant::now();   // monotonic; never goes backwards
```

`Instant` is monotonic — immune to wall-clock adjustments (NTP, DST) that could make a duration
negative. We never need calendar time, only *elapsed* milliseconds, so `clock.elapsed()` is the right
primitive. This is the single most important design lesson of the day: **timers and blocking reads are
incompatible; reliability forces an event loop.** Every real stack lives inside one.

## 3. The non-blocking event loop

Each iteration now has a fixed shape:

```text
   now_ms = clock.elapsed()
   for each connection:                 # ── timers first ──
       for pkt in conn.on_tick(now_ms): # any segment past its RTO, plus TIME_WAIT expiry
           iface.send(pkt)              # resend it
       if conn.state == CLOSED: mark for removal
   remove the closed connections        # reap freed TCBs

   match iface.recv(buf):               # ── then input ──
       Ok(n)            => handle the packet
       Err(WouldBlock)  => sleep 5 ms, continue   # nothing ready; don't busy-spin
       Err(e)           => bail
```

The 5 ms nap matters. Without it, a quiet link would spin the CPU at 100% calling `recv()` in a tight
loop. With it, the loop wakes ~200×/second — fine-grained enough that a 200 ms RTO fires within ~5 ms
of its true deadline, cheap enough to be invisible. This is a poor-man's `epoll`: a production stack
would block in `poll()`/`epoll_wait()` with a timeout equal to the *nearest* timer, waking *exactly* on
a packet or a deadline rather than polling (§E). Same idea, less wasted wakeups.

Reaping closed connections is now the loop's job too: `on_tick` may move a `TIME_WAIT` connection to
`CLOSED` after 2·MSL purely on the clock (no packet involved), so the loop checks state after ticking
and drops dead TCBs from the table. Time itself can now drive a state transition — a thing the blocking
loop literally could not express.

## 4. The retransmission queue

`RetxQueue` is a list of segments we've sent but not yet seen acknowledged. The doc-6 entry (it grows
two fields later — §12):

```rust
struct Unacked {
    end_seq:    u32,      // one past this segment's last seq number; acked when SND.UNA reaches it
    packet:     Vec<u8>,  // the complete IP+TCP bytes, ready to resend verbatim
    sent_at_ms: u64,      // when it was (last) sent — the start of its RTT timer
    retries:    u32,      // how many times we've resent it (Karn's flag + future backoff)
}
```

Three operations, and the discipline of **passing time in** rather than reading a clock inside — so the
whole thing is unit-testable without sleeping:

- **`record(end_seq, packet, now_ms)`** — called right after we transmit data: store a clone and stamp
  it with the send time.
- **`ack(una, now_ms) -> Option<u64>`** — drop every segment the cumulative ACK now covers, and return
  an RTT sample for one of them (see §5). "Covered" is the wraparound-safe test
  `!seq::before(una, end_seq)` — `una` has reached or passed `end_seq` on the 32-bit circle (that
  `seq::before` is the modular comparison from Doc 3).
- **`due(now_ms, rto_ms) -> Vec<packet>`** — return clones of every segment whose timer has elapsed
  (`now_ms − sent_at_ms ≥ rto_ms`), and for each, **reset its timer and bump `retries`**. Resetting is
  what makes the next resend wait another full RTO instead of firing every tick.

Note what we store: the *whole packet bytes*, not just the payload. Resending is then a literal
`iface.send(&bytes)` — the seq/ack/checksum were correct when built and are still correct (a pure
retransmission re-sends identical bytes). Simple and impossible to get subtly wrong. (A production stack
stores the *data* and rebuilds the header, so it can re-segment or update the ACK/window on
retransmission — §10's table.)

The connection wires these in: on sending data it `retx.record(SND.NXT, segment, now)`; on an
acceptable ACK it advances `SND.UNA` and calls `retx.ack(SND.UNA, now)`; and `on_tick` returns
`retx.due(now, self.rtt.rto())`.

## 5. Karn's algorithm — why a retransmitted segment's timing lies

Here is the trap. Suppose we send segment X at t=0, hear nothing, resend it at t=250, and an ACK arrives
at t=300. What was the RTT — 300 ms (from the first send) or 50 ms (from the second)? **We cannot
tell**, because both copies are byte-identical and the ACK names a sequence number, not a transmission.
Picking either can be badly wrong: if the ACK was actually for the *first* copy and we credit it to the
second, we'd compute a wildly short RTT and shrink the RTO toward spurious retransmissions — a feedback
loop that makes loss *worse*.

**Karn's algorithm (RFC 6298 §3):** never take an RTT sample from a segment that was retransmitted. In
code that is exactly the `retries == 0` guard inside `ack`:

```rust
if !still_unacked && s.retries == 0 && sample.is_none() {
    sample = Some(now_ms.saturating_sub(s.sent_at_ms));  // a trustworthy round trip
}
```

A segment that `due` ever resent has `retries > 0`, so it contributes no sample — its ack clears it
from the queue but leaves SRTT untouched. We sample at most one segment per ACK (the oldest
freshly-cleared, never-retransmitted one), which is all RFC 6298 asks for ("at least one measurement
per RTT"). `saturating_sub` guards the degenerate `now < sent_at` (impossible with a monotonic clock,
but free insurance against a 0-stamped test segment).

Karn's *other* half — exponentially backing off the RTO on each retransmit and holding it until a clean
sample arrives — is the second half of the algorithm, added later as `RttEstimator::back_off` (Doc 12 /
§C). Without it, a path that suddenly slows would retransmit at the old (too-short) RTO repeatedly;
with it, each timeout doubles the RTO, so the sender stops hammering a congested or stalled path.

## 6. The RTT estimator: SRTT, RTTVAR, and the RTO (RFC 6298)

A single RTT sample is noisy, so we keep two smoothed statistics and update them on each sample `R`.
`α = 1/8` and `β = 1/4` are the standard gains; the divisions are exact right-shifts because the gains
are powers of two and everything is integer milliseconds (deterministic, no floats):

```text
   first sample R:   SRTT   = R
                     RTTVAR = R / 2

   later sample R:   RTTVAR = (1 − β)·RTTVAR + β·|SRTT − R|     # >> 2 for ·(1/4)
                     SRTT   = (1 − α)·SRTT   + α·R              # >> 3 for ·(1/8)
                     (RTTVAR updated FIRST — it uses the OLD SRTT, RFC 6298 §2.3)

   RTO = clamp( SRTT + max(K·RTTVAR, G),  MIN_RTO,  MAX_RTO )
```

with `K = 4`, `G = 1 ms` (clock granularity, the floor on the variance term), `MIN_RTO = 200 ms`,
`MAX_RTO = 60 000 ms`. The RTO is `SRTT` plus a **safety margin proportional to the jitter**: a steady
path has small `RTTVAR` and a tight RTO; a jittery path widens it automatically. This mean-plus-variance
design is the Jacobson/Karels insight (§B) that fixed TCP's congestion-collapse problem in 1988.

Two deliberate departures from the letter of the RFC, both documented in `rtt.rs`:

- RFC 6298 §2.4 SHOULDs `MIN_RTO = 1000 ms`. We use **200 ms** — over a local TUN link the real RTT is
  sub-millisecond, and a 1-second floor would make a teaching demo feel broken. On the open internet you
  would restore 1000.
- Before the first sample, `rto()` returns `MIN_RTO` (200 ms) — a conservative default so the very
  first unacked segment still has a sane deadline. (RFC 6298 §2.1 uses 1 s as the initial value.)

The estimator is pure arithmetic over two `u64`s with no I/O, so its unit tests pin every branch.

## 7. Worked numbers (the exact ones the tests assert)

Steady path — RTT genuinely 100 ms (`rtt::tests::converges_on_steady_rtt`):

```text
   sample R=100 (first):  SRTT=100,  RTTVAR=100/2=50
                          RTO = 100 + max(4·50, 1) = 100 + 200 = 300

   sample R=100 (second): |SRTT−R| = |100−100| = 0
                          RTTVAR = 50 − (50>>2) + (0>>2) = 50 − 12 + 0 = 38
                          SRTT   = 100 − (100>>3) + (100>>3) = 100 − 12 + 12 = 100
                          RTO = 100 + max(4·38, 1) = 100 + 152 = 252
```

The margin shrank from 200→152 as the estimator gained confidence — exactly the point.

Clamp on a fast link (`clamps_low_rtt_to_minimum`):

```text
   sample R=10:  SRTT=10, RTTVAR=5,  raw RTO = 10 + max(20,1) = 30  →  clamped UP to 200
```

End-to-end through the connection (`tcp::tests::ack_of_new_data_samples_rtt_and_adapts_rto`):

```text
   echo "hi" sent at t=0, queued (retries=0).  rto() = 200  (no sample yet, the default)
   peer ACKs the 2 bytes at t=120, no retransmit  →  sample R=120
                          SRTT=120, RTTVAR=60,  RTO = 120 + 4·60 = 360
```

And Karn in action (`connection_retransmits_then_clears_on_ack`): the echo is resent at t=250 (past the
200 ms default RTO), so when its ACK lands `retries=1` → no sample → `rto()` stays 200.

## 8. The Rust: monotonic time, owned packets, time-passed-in

- **`Instant`, not `SystemTime`.** Retransmission cares about *elapsed* time, never the calendar.
  `Instant` is monotonic; `clock.elapsed().as_millis()` can't go backwards under an NTP step. Using
  wall-clock time here is a classic bug (a negative duration → a panic or a retransmit storm).
- **The queue owns the bytes it stores.** `record` takes `packet: Vec<u8>` by value (the caller hands
  over a clone of what it sent). `due`/`ack` return clones for resending. Ownership is unambiguous: the
  queue holds the canonical copy until the ACK frees it.
- **Time is a parameter, not a side effect.** Every method takes `now_ms: u64`. The estimator and queue
  do *no* I/O and read *no* clock — so the tests drive them with synthetic times and assert exact RTOs
  (§7) with zero sleeping and zero flakiness. This "inject the clock" discipline is what makes
  time-dependent logic testable; it's worth copying into any timer code you write.
- **Integer math, deterministic.** SRTT/RTTVAR are `u64` ms; the `α/β` gains are right-shifts. No
  floats means bit-identical results across platforms and in tests.

## 9. The code, walked end to end

The pieces and where they live:

| File | What it gained |
|---|---|
| `src/rtt.rs` | `RttEstimator` — `sample(R)` folds in a measurement, `rto()` reads the timeout, (later) `back_off()` |
| `src/tcp.rs` | `RetxQueue` (record/ack/due); `Connection` holds a `RttEstimator`; `on_tick` |
| `src/main.rs` | non-blocking interface, the timer-then-input loop, connection reaping |

The data path for one echoed segment, tracing the bytes:

```text
   1. data arrives in-order → we build the echo, SND.NXT += len
   2. retx.record(SND.NXT, echo_bytes, now)        # remember it, stamp the time
   3. ...time passes, no ACK...
   4. on_tick(now): retx.due(now, rtt.rto())        # now − sent_at ≥ rto? resend, retries++
   5. peer's ACK arrives, SND.UNA < ACK ≤ SND.NXT   # acceptable (Doc 3's seq::between)
   6. SND.UNA = ACK; if let Some(r) = retx.ack(SND.UNA, now) { rtt.sample(r) }
           # segment cleared from the queue; if retries==0, r adapts the RTO
```

The crucial ordering in `Connection::on_tick`: expire `TIME_WAIT` first (a clock-only state change),
*then* `retx.due(now, self.rtt.rto())`. The RTO is no longer a constant passed in by `main` — the
connection owns its own adaptive estimate, which is why `on_tick` dropped its `rto_ms` parameter. `main`
just calls `conn.on_tick(now_ms)`.

## 10. Verification

`cargo test` proves reliability offline (no TUN, no sudo). The reliability-specific tests:

- `rtt::*` — default RTO with no sample, first sample, convergence on a steady RTT, and both clamps.
  These pin the arithmetic of §6/§7.
- `retx_records_acks_and_clears`, `retx_partial_ack_keeps_unacked`, `retx_ack_wraparound` — the queue
  drops exactly the fully-acked segments, keeps partials, and is wraparound-safe.
- `retx_fires_after_rto` — `due` returns nothing before the RTO, the segment after it, then resets.
- `connection_retransmits_then_clears_on_ack` — the full path: echo → resend after RTO → ACK clears the
  queue, with Karn suppressing the sample (RTO stays 200).
- `ack_of_new_data_samples_rtt_and_adapts_rto` — a clean (un-retransmitted) ACK drives RTO 200→360.

Live (your hands): run the stack, `nc 192.168.0.2 8080`, type a line. Then add loss with
`sudo tc qdisc add dev tun0 root netem loss 30%` and watch the stack log print `↻ retransmit (N bytes)`
— the connection survives drops that would have silently hung it before. Remove it with
`sudo tc qdisc del dev tun0 root`.

## 11. Why this, not that

| Decision | We chose | Real TCP / alternative |
|---|---|---|
| I/O model | non-blocking `recv` + 5 ms sleep | `epoll`/`io_uring` waking on packet *or* the nearest timer |
| Store for resend | whole packet bytes per segment | a byte buffer + rebuild header (lets you re-segment / refresh ACK & window) |
| RTO before first sample | fixed 200 ms default | RFC 6298 initial RTO = 1 s until first measurement |
| `MIN_RTO` | 200 ms (local link) | 1 s (RFC SHOULD), to survive internet jitter |
| Karn's backoff | sample-suppression at doc 6; backoff added Doc 12 | suppress **and** double RTO per retransmit, hold until a clean sample |
| Retransmit unit | each segment on its own timer | one timer per connection for the oldest unacked (RFC 6298 §5) |
| Float vs integer SRTT | integer ms + right-shifts | same in practice — kernels use fixed-point too |

## 12. Honesty: what production does, and what later days added

- **One timer per segment vs one per connection.** RFC 6298 §5 runs a *single* retransmission timer for
  the oldest unacked segment, restarted as ACKs arrive. We give each segment its own deadline — simpler
  to reason about, slightly more timers. Same observable behavior for the common case.
- **Backoff (Karn's second half) arrived Doc 12.** `RttEstimator::back_off` doubles the RTO per
  consecutive timeout (capped) and holds it until a clean sample clears it (RFC 6298 §5.5). Doc 6
  suppresses samples; Doc 12 adds the doubling — needed so we stop hammering a stalled path.
- **Control segments became reliable on Doc 12.** Doc 6 queues *data*; a lost SYN-ACK or FIN could
  still hang the handshake/teardown. Doc 12 queues those too.
- **The `Unacked` struct grew.** Doc 18 (SACK) added `start_seq` and a `sacked` flag so loss recovery
  can skip selectively-acked ranges; Doc 6's struct is the four-field original shown in §4.
- **Fast retransmit (Doc 10) beats the RTO.** Waiting a whole RTO is slow; three duplicate ACKs let a
  sender resend *immediately* without a timeout (RFC 5681). Doc 6 is timer-driven only; Doc 10 adds the
  ACK-driven path (§F).
- **No giving up.** We retransmit forever; a real stack caps retries and resets (exercise E1).
- **Real timers are O(1) wheels.** We scan all connections each tick; kernels use a timer wheel /
  hashed timers to fire in O(1) (§E, §I).

None of these change the doc-6 contract (lost data is resent on an adaptive timeout); they are the
hardening the later days add.

## 13. Rebuild it yourself — checklist + exercises

**Blank-file checklist:**

- [ ] Why a *blocking* `recv` can't host a timer, and the exact shape of the non-blocking loop
      (timers → input → `WouldBlock`-nap).
- [ ] The three `RetxQueue` operations and the wraparound-safe "fully acked" test.
- [ ] Karn's algorithm in one sentence, and the `retries == 0` line that implements it.
- [ ] The RFC 6298 update equations — including *why RTTVAR is updated before SRTT* — and the
      `RTO = SRTT + max(K·RTTVAR, G)` clamp.
- [ ] Why `Instant` (monotonic) and not `SystemTime`.

**Exercises:**

- **E1.** Cap `retries`: after N (say 5) resends of the same segment, give up and `RST` the connection.
  Today an unanswered segment retransmits forever.
- **E2.** ✅ *Done* (`RttEstimator::back_off`, Doc 12): the RTO doubles on each retransmit (capped ×64)
  and the backed-off value holds until a fresh, non-retransmitted RTT sample clears it — the second half
  of Karn's algorithm (RFC 6298 §5.5).
- **E3.** ✅ *Done* (Doc 12): retransmit the **SYN-ACK** and **FIN** too — they consume sequence space
  and can be lost. Queue them in `accept`/`close` and watch the handshake/teardown survive loss.
- **E4.** Replace the 5 ms sleep with a real `poll()` whose timeout is the nearest segment's deadline,
  so the loop wakes exactly on a packet or a timer (§E).
- **E5.** Implement a single per-connection timer (RFC 6298 §5) instead of per-segment, and convince
  yourself the behavior matches on the common path.

## 14. What the next step adds

Doc 7 adds the **active close** (our side initiating the FIN) with FIN_WAIT_1/2, CLOSING, and TIME_WAIT
— now that the event loop exists to drive the 2·MSL timer. Doc 8 adds **flow control** (gating
transmission on the peer's advertised window). Doc 9 adds **out-of-order reassembly**. Doc 10 adds
**congestion control** — slow start, AIMD, and *fast retransmit* (the ACK-driven loss detection that
beats the RTO). Retransmission tells you *that* to resend; congestion control governs *how fast* you may
send into a shared network — the next big conceptual leap.

---

# Volume II — the exhaustive reference

## A. RFC 6298 in full: every equation and constant

RFC 6298 ("Computing TCP's Retransmission Timer", 2011, obsoleting RFC 2988) is short and prescriptive.
The full algorithm:

**Before the first RTT measurement:** `RTO = 1 second` (we use 200 ms — §6 deviation).

**On the first measurement `R`:**

```text
   SRTT   = R
   RTTVAR = R / 2
   RTO    = SRTT + max(G, K·RTTVAR)        with K = 4
```

**On a subsequent measurement `R'`:**

```text
   RTTVAR = (1 − β)·RTTVAR + β·|SRTT − R'|   with β = 1/4   ← uses the OLD SRTT
   SRTT   = (1 − α)·SRTT   + α·R'            with α = 1/8
   RTO    = SRTT + max(G, K·RTTVAR)
```

**Clamps:** `RTO = max(RTO, 1 s)` per the RFC (we use 200 ms); a maximum MAY be imposed if ≥ 60 s (we
use 60 s).

**On retransmission timeout (§5.5):** `RTO = RTO × 2` (the backoff), capped at the maximum; restart the
timer. **Karn (§3):** ignore RTT samples from retransmitted segments, and keep the backed-off RTO until
a new, unambiguous sample is taken.

**Why update RTTVAR before SRTT?** RTTVAR's formula uses `|SRTT − R'|` — the deviation of the new sample
from the *current* (old) smoothed estimate. If you updated SRTT first, RTTVAR would measure deviation
from an already-corrected mean and systematically under-estimate jitter. The order is load-bearing.

```text
   constant   value      meaning
   ────────   ────────   ──────────────────────────────────
   α          1/8        SRTT gain (smoothing of the mean)
   β          1/4        RTTVAR gain (smoothing of the deviation)
   K          4          how many deviations of safety margin
   G          1 ms       clock granularity (floor on the margin)
   MIN_RTO    1000 ms*   floor (*we use 200 ms on a LAN)
   MAX_RTO    60000 ms   ceiling
```

## B. A short history: RFC 793's broken RTO and Jacobson/Karels (1988)

The original RFC 793 RTO used only a smoothed *mean* RTT with a fixed multiplier: `RTO = β·SRTT`
(β ≈ 2). This has a fatal flaw on a loaded network: as load rises, RTT both *increases* and *varies
more*, but a fixed multiplier of the mean can't track the rising *variance*. The RTO ends up too low,
triggering retransmissions, which add load, which raises RTT further — the positive feedback that caused
the **congestion collapses** of October 1986 (throughput between LBL and UC Berkeley, 400 yards apart,
dropped from 32 kbit/s to 40 bit/s — a factor of 1000).

Van Jacobson and Michael Karels's 1988 paper "Congestion Avoidance and Control" fixed the RTO by adding
the **mean deviation** term (RTTVAR) — cheap to compute (no multiply/divide, just shifts and an absolute
value) and a good proxy for standard deviation. `RTO = SRTT + 4·RTTVAR` tracks both the mean *and* the
variance, so a jittery path automatically gets a looser timeout. The same paper introduced slow start
and congestion avoidance (Doc 10). This day's estimator is, almost verbatim, the Jacobson/Karels
algorithm that saved the Internet.

## C. Karn's algorithm in depth (the two halves)

Phil Karn and Craig Partridge's 1987 algorithm has **two** rules, and both matter:

1. **Don't sample retransmitted segments.** The ACK is ambiguous (which copy?), so any sample is
   untrustworthy (§5). We implement this via `retries == 0`.
2. **Back off the RTO on each timeout, and freeze it.** When a retransmission times out, double the RTO
   (`RTO ← 2·RTO`, capped) and *keep* the doubled value until a fresh, unambiguous sample (from a
   non-retransmitted segment) is available — only then resume normal estimation. This prevents a
   too-short RTO from causing repeated retransmissions on a path that has genuinely slowed.

Why the freeze (rule 2's second clause)? Because rule 1 means you *can't* get a new sample while you're
retransmitting — every segment in flight is a retransmission. Without the freeze, you'd revert to the
old (too-short) RTO the instant a cumulative ACK cleared a never-retransmitted segment behind the loss,
re-triggering the storm. Backoff + freeze together give the path time to recover. Doc 6 implements rule
1; Doc 12's `back_off` implements rule 2. The exponential backoff (1×, 2×, 4×, …) is the same shape as
Ethernet's collision backoff — a general principle for probing a contended resource without piling on.

## D. The fixed-point arithmetic — why right-shifts, no floats

The RFC's `α = 1/8`, `β = 1/4` are deliberately powers of two so the smoothing is implementable with
**shifts**, no floating point:

```text
   SRTT   = SRTT − (SRTT >> 3) + (R >> 3)            # (1 − 1/8)·SRTT + (1/8)·R
   RTTVAR = RTTVAR − (RTTVAR >> 2) + (|SRTT−R| >> 2) # (1 − 1/4)·RTTVAR + (1/4)·|SRTT−R|
```

Working `SRTT = 100`, `R = 100`: `100 − (100>>3) + (100>>3) = 100 − 12 + 12 = 100` (stable, as it should
be). With `R = 200`: `100 − 12 + 25 = 113` — moved 1/8 of the way from 100 toward 200, as `α = 1/8`
dictates.

Why avoid floats? Three reasons: (1) **determinism** — integer shifts give bit-identical results on
every platform, so the unit tests can assert exact RTOs; (2) **speed** — this runs per-ACK in the
kernel; shifts are free; (3) **no rounding drift** — repeated float multiply-accumulate accumulates
error. Real kernels (Linux `tcp_rtt_estimator`) use the same fixed-point trick, often scaling SRTT by 8
and RTTVAR by 4 internally to keep precision. Our `>>3`/`>>2` on plain millisecond `u64`s is the
teaching-clear version.

## E. The event loop in depth — blocking, non-blocking, epoll, io_uring, timer wheels

The progression of I/O models, and where we sit:

```text
   model              wakeups                         our analogue
   ────────────────   ─────────────────────────────   ─────────────────────────
   blocking recv      one thread parked per socket     Doc 1–5 (no timers possible)
   non-blocking+poll  spin or sleep, check readiness    Doc 6 (recv + 5 ms nap)
   select/poll        wake on any of N fds, w/ timeout  exercise E4
   epoll/kqueue       O(1) readiness, scalable to 10⁵   real servers
   io_uring           batched async submission/complete  modern Linux high-perf
```

Our 5 ms-sleep loop is the simplest thing past blocking: it *polls* readiness and *polls* timers. The
next rung, `poll()` with a computed timeout, eliminates the fixed nap: compute the nearest deadline
across all connections, pass it as the `poll` timeout, and wake *exactly* on a packet or that deadline.

**Timer management** is the other half. We scan *every* connection each tick to find due segments —
O(connections) per tick. Kernels can't afford that with millions of connections, so they use a **timer
wheel** (a.k.a. hashed/hierarchical timing wheels): timers are bucketed by expiry into a circular array,
and each tick advances a hand and fires only the current bucket — O(1) amortized insertion and
expiry. Our linear scan is correct and clear at our scale; the timer wheel is the production data
structure (§I).

## F. Timer-driven vs ACK-driven loss detection (RTO vs fast retransmit)

There are two ways to learn a segment was lost:

- **Timer-driven (RTO) — this day.** Wait for the deadline; if no ACK, resend. Robust (works even if
  *all* later segments are also lost) but *slow* — you pay a whole RTO (≥ 200 ms here, ≥ 1 s on the
  internet), during which the pipe is idle.
- **ACK-driven (fast retransmit) — Doc 10.** When the receiver gets out-of-order data it sends a
  *duplicate ACK* (the same cumulative number again). Three duplicate ACKs strongly imply the next
  segment was lost (not merely reordered), so the sender resends it *immediately* — no timeout. This
  recovers a single loss in ~1 RTT instead of ~1 RTO.

A modern stack uses both, plus newer time-based detection (RACK-TLP, §I) that largely replaces the
3-dup-ACK heuristic. Doc 6 builds the RTO floor (always correct, sometimes slow); Doc 10 adds the fast
path (usually faster, needs enough ACKs to trigger). The RTO is the safety net the fast path falls back
to.

## G. A full retransmission episode with backoff, worked numerically

A segment is sent at t=0 with `SRTT=100, RTTVAR=50 → RTO=300`, and the path has gone dark (no ACKs).
With Karn backoff (Doc 12 behavior):

```text
   t=0      send X (retries=0), RTO=300
   t=300    due! resend X (retries=1), back_off → RTO=600
   t=900    due! resend X (retries=2), back_off → RTO=1200
   t=2100   due! resend X (retries=3), back_off → RTO=2400
   t=4500   ACK finally arrives for X
            retries>0 → Karn: NO sample taken; RTO stays backed-off (frozen)
   ...next NEW segment Y acked cleanly (retries=0) → sample taken → RTO re-estimated
```

The deadlines are 300, then +600, +1200, +2400 — exponential backoff, so four retransmits span 4.5 s
rather than hammering every 300 ms (which would be 15 retransmits). When the ACK for the retransmitted X
arrives, Karn forbids a sample (we can't tell which copy it answers), and the frozen RTO persists until
a *new*, never-retransmitted segment gives a clean measurement. This is exactly the §C two-halves
working together.

## H. A complete annotated lossy trace (hex + timers)

An echo of `"hi"` (seq 1, 2 bytes) over a link that drops the first copy. `U` = us, `C` = client. TCP
flags shown; the key is the *timer*, not new header bytes.

```text
   t=0     U→C  PSH,ACK seq=1 ack=103 "hi"      retx.record(end=3, t=0); rto()=200
                ✗ dropped by the network
   t=200   on_tick: now−sent = 200 ≥ 200 → due  retx.due resends the SAME bytes, retries=1, sent_at=200
           U→C  PSH,ACK seq=1 ack=103 "hi"      (identical packet — pure retransmission)
   t=260   C→U  ACK ack=3                        SND.UNA→3; retx.ack(3): clears X
                                                 retries=1 → Karn: NO RTT sample; rto() stays 200
```

Contrast a *clean* (no-loss) echo: the ACK at, say, t=120 clears a `retries=0` segment → sample
R=120 → `SRTT=120, RTTVAR=60, RTO=360`. The only wire difference between the two traces is *which* copy
the ACK answers; the timer and Karn's guard are what make the stack do the right thing in each case.

## I. Comparison to real stacks — RTO, timer wheels, RACK-TLP

```text
   aspect              Linux / modern TCP                         this stack
   ─────────────────   ────────────────────────────────────────  ──────────────────────────
   RTT estimator       Jacobson/Karels fixed-point (same math)    same (integer SRTT/RTTVAR)
   MIN_RTO             ~200 ms (TCP_RTO_MIN), tunable              200 ms
   initial RTO         1 s (RFC 6298)                             200 ms default
   timers              hashed timer wheel, O(1)                   linear scan per tick
   retransmit timer    one per socket (oldest unacked)            one per segment
   loss detection      RACK-TLP (time-based) + dupACK + RTO       RTO (Doc 6) + 3-dupACK (Doc 10)
   tail loss           Tail Loss Probe (TLP) before RTO           RTO only
   resend granularity  repacketize on retransmit                  resend identical bytes
```

The headline modern change is **RACK-TLP** (RFC 8985): instead of the 3-duplicate-ACK heuristic, mark a
segment lost if a segment sent *later* has been ACKed and enough time has passed (using per-segment send
timestamps) — more robust to reordering and small flights. We implement the classical RTO + dupACK
path; RACK is the natural advanced exercise once timestamps (Doc 16) are in place.

## J. Security — low-rate "shrew" DoS and RTT manipulation

- **The "shrew" / low-rate TCP-targeted DoS.** An attacker who knows TCP's minimum RTO (~1 s, or our
  200 ms) can send a short, high-rate burst *exactly* every RTO, causing repeated timeouts in victim
  flows and forcing them to near-zero throughput — while the attacker's *average* rate is low enough to
  evade rate-based detection. The defense is RTO randomization and not having a too-predictable MIN_RTO.
  Our fixed 200 ms is, in principle, shrew-targetable; a hardened stack jitters it.
- **RTT manipulation via forged ACKs.** An on-path attacker (or a lying receiver) can ACK data
  *early* — before it's actually received — to shrink the sender's RTT estimate and RTO, or "ACK
  division"/"optimistic ACKing" to make the sender transmit faster than safe (a congestion-control
  attack, more relevant on Doc 10). Timestamps (Doc 16) make the RTT sample harder to forge because the
  echoed TSecr must match.
- **Retransmission amplification.** A too-low RTO that retransmits aggressively wastes the sender's own
  bandwidth and can be induced; capping retries (E1) and backoff (§C) bound the damage.

The theme: the RTO is a *control parameter an adversary would love to move*, so real stacks randomize
it, validate samples (Karn + timestamps), and bound retransmission.

## K. Performance — timer overhead, goodput, the cost of a wrong MIN_RTO

- **Goodput vs throughput.** Every retransmission is bandwidth spent on bytes the receiver may already
  have or will get anyway; *goodput* (useful bytes/sec) falls as loss rises. A well-tuned RTO minimizes
  *spurious* retransmissions (resending data that wasn't actually lost), which is why the variance term
  matters.
- **MIN_RTO too low** → spurious timeouts on a jittery path → retransmission storms and (with Doc 10)
  needless `cwnd` collapse. **MIN_RTO too high** → a real loss stalls the connection for the whole
  floor (1 s on the internet) before recovery — which is why fast retransmit (Doc 10) exists to avoid
  paying the RTO at all for common single losses.
- **Timer cost.** Our per-tick linear scan is O(connections); at thousands of connections that's real
  CPU. A timer wheel makes expiry O(1). The 5 ms nap also bounds timer *resolution* to ±5 ms, fine for
  a 200 ms RTO, too coarse for sub-ms LAN RTTs (we'd never want a sub-5ms RTO anyway, hence MIN_RTO).
- **Memory.** The retransmission queue holds whole-packet copies of all unacked data — up to a window's
  worth. With window scaling (Doc 17) that can be megabytes; a real stack stores the data once and
  rebuilds headers to halve the footprint.

## L. Extended FAQ

1. **Why can't a blocking `recv` run a timer?** The thread is asleep inside `recv` with no chance to
   check a clock; a timer must fire when nothing is arriving.
2. **What does the 5 ms sleep prevent?** A 100%-CPU busy-spin on a quiet link.
3. **Why `Instant`, not `SystemTime`?** Monotonic — immune to NTP/DST steps that could make a duration
   negative.
4. **What does the retransmission queue store?** Whole packet bytes, send time, end_seq, retries.
5. **Why store whole packets, not payloads?** Resend is a literal `send(bytes)`; can't get the
   seq/checksum wrong. (Real stacks store data + rebuild — §10.)
6. **When is a queued segment dropped?** When `SND.UNA` reaches/passes its `end_seq` (cumulative ACK).
7. **What is Karn's algorithm?** Don't sample RTT from a retransmitted segment (ambiguous), and back
   off + freeze the RTO while retransmitting.
8. **Why is a retransmitted segment's RTT ambiguous?** The ACK names a sequence number, not which copy
   it answers.
9. **Which line implements Karn part 1?** The `s.retries == 0` guard in `ack`.
10. **What are SRTT and RTTVAR?** Smoothed mean RTT and smoothed mean deviation (jitter).
11. **Why update RTTVAR before SRTT?** RTTVAR uses the deviation from the *old* SRTT (RFC 6298 §2.3).
12. **Why `RTO = SRTT + 4·RTTVAR`?** Mean plus a jitter-proportional margin; tight on steady paths,
    loose on jittery ones.
13. **Why integer shifts, not floats?** Determinism (testable), speed, no rounding drift.
14. **What is MIN_RTO and why 200 ms here?** The RTO floor; 200 ms suits a LAN (RFC SHOULDs 1 s for the
    internet).
15. **What's the RTO before the first sample?** 200 ms (our default; RFC uses 1 s).
16. **What's RTO backoff?** Doubling the RTO on each consecutive timeout (Karn part 2, Doc 12).
17. **Why freeze the backed-off RTO?** You can't get a clean sample while retransmitting; freezing
    avoids reverting to a too-short RTO.
18. **Does Doc 6 retransmit SYN-ACK/FIN?** No — only data; control-segment retransmission is Doc 12.
19. **What is fast retransmit and how does it differ?** ACK-driven (3 dup ACKs) immediate resend; beats
    the RTO (Doc 10).
20. **Why does `on_tick` expire TIME_WAIT before checking `due`?** TIME_WAIT is a clock-only transition;
    do state first, then timers.
21. **How is the RTO tested without sleeping?** Time is passed in as `now_ms`; tests use synthetic
    times.
22. **What clamps the RTO?** `[MIN_RTO, MAX_RTO]` = `[200 ms, 60 s]`.
23. **What's the "congestion collapse" this fixed?** The 1986 throughput collapse from RFC 793's
    variance-blind RTO (§B).
24. **Do we ever give up retransmitting?** No (exercise E1); a real stack caps retries and RSTs.
25. **What's a timer wheel?** An O(1) data structure kernels use to fire timers without scanning all
    connections (§E).

## M. Anki starter deck

```text
Q: TCP's only tool against loss?  A: redundancy in time — resend if no ACK in time.
Q: Two pieces of machinery for reliability?  A: the retransmission queue + the RTO timer.
Q: Why can't a blocking recv() host a timer?  A: the thread sleeps in recv; no moment to check a clock.
Q: Instant vs SystemTime for the RTO clock?  A: Instant — monotonic, can't go backwards.
Q: When is a queued segment forgotten?  A: when SND.UNA reaches/passes its end_seq (cumulative ACK).
Q: Karn's algorithm, part 1?  A: don't sample RTT from a retransmitted segment (ambiguous ACK).
Q: Karn's algorithm, part 2?  A: back off (double) the RTO per timeout and freeze it until a clean sample.
Q: SRTT and RTTVAR?  A: smoothed mean RTT and smoothed mean deviation (jitter).
Q: RTO formula?  A: SRTT + max(K·RTTVAR, G), K=4, clamped to [MIN_RTO, MAX_RTO].
Q: Why update RTTVAR before SRTT?  A: RTTVAR uses |old SRTT − R|; updating SRTT first under-estimates jitter.
Q: α and β gains?  A: 1/8 (SRTT) and 1/4 (RTTVAR) — powers of two → right-shifts, no floats.
Q: Our MIN_RTO and why?  A: 200 ms for a LAN (RFC SHOULDs 1 s for the internet).
Q: Whose 1988 algorithm is the RTO?  A: Jacobson/Karels (mean + variance), which fixed congestion collapse.
Q: RTO vs fast retransmit?  A: timer-driven (slow, robust) vs 3-dupACK-driven (fast, Doc 10).
```

## N. Glossary

- **Reliability** — guaranteed delivery of every byte, achieved by retransmitting unacknowledged data.
- **Retransmission queue (`RetxQueue`)** — the store of sent-but-unacked segments.
- **RTO (Retransmission TimeOut)** — the deadline after which an unacked segment is resent.
- **RTT** — round-trip time; the sample the estimator smooths.
- **SRTT / RTTVAR** — smoothed RTT (mean) and smoothed RTT variation (deviation/jitter).
- **Karn's algorithm** — don't sample retransmitted segments; back off + freeze the RTO while
  retransmitting.
- **Backoff** — doubling the RTO on each consecutive timeout.
- **Event loop** — the timers-then-input loop that replaced blocking `recv`.
- **Non-blocking I/O / `WouldBlock`** — `recv` returns immediately; "nothing ready" is an error value.
- **`Instant`** — Rust's monotonic clock; the right RTO time source.
- **Timer wheel** — an O(1) kernel data structure for firing many timers.
- **Fast retransmit** — ACK-driven (3 dup ACKs) resend that beats the RTO (Doc 10).

## O. Reference tables

**O.1 — RFC 6298 constants (and our values)**

```text
   symbol     RFC value     ours        role
   ────────   ──────────    ─────────   ──────────────────────────
   α          1/8           1/8         SRTT smoothing gain
   β          1/4           1/4         RTTVAR smoothing gain
   K          4             4           variance multiplier in the RTO
   G          (clock gran.) 1 ms        floor on the variance term
   initial    1 s           200 ms      RTO before the first sample
   MIN_RTO    1 s (SHOULD)  200 ms      RTO floor (LAN tuning)
   MAX_RTO    ≥ 60 s        60 s        RTO ceiling
```

**O.2 — `RetxQueue` operations**

```text
   op                      when called              effect
   ─────────────────────   ──────────────────────   ─────────────────────────────────────
   record(end, pkt, now)   right after sending      append, stamp send time, retries=0
   ack(una, now)           on an acceptable ACK      drop end_seq ≤ una; sample if retries==0
   due(now, rto)           every on_tick             resend elapsed ≥ rto; reset timer, retries++
```

**O.3 — Loss detection paths**

```text
   path             trigger                    latency to resend     day
   ──────────────   ────────────────────────   ───────────────────   ─────
   RTO              timer ≥ RTO, no ACK         ~RTO (≥ 200 ms)       6
   fast retransmit  3 duplicate ACKs            ~1 RTT                10
   (RACK-TLP)       time-based, per-segment ts  ~1 RTT, reorder-safe  (future, RFC 8985)
```

> Re-type `RetxQueue` and `RttEstimator` from this chapter with the book closed, then `cargo test`. You
> now hold reliability end to end: parsing (Doc 1), checksums (Doc 2), handshake (Doc 3), data (Doc 4),
> close (Doc 5), and now retransmission + the adaptive RTO (Doc 6). When the connection survives
> `netem loss 30%`, you've built the control loop that makes TCP *reliable*.
