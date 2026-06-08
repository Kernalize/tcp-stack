# Day 6 — TCP, Part 4: Reliability (Retransmission, the Event Loop & the Adaptive RTO)

> Goal: make the connection **reliable**. Until now every byte we sent was assumed to arrive.
> A real network drops packets. So we keep a copy of every segment we send, start a clock, and
> if its acknowledgement doesn't come back in time we **resend** it. The "in time" part is the
> subtle one — too eager and we flood the link with needless copies; too patient and a lost
> segment stalls the connection for a second. So we *measure* the round-trip time and let the
> timeout track the path. This is the chapter Day 5 §10 promised as "the right Step 6."

**Contents**
1. The mental model: what "reliable" actually costs
2. Why the blocking loop could not do this (the design change)
3. The non-blocking event loop
4. The retransmission queue
5. Karn's algorithm — why a retransmitted segment's timing lies
6. The RTT estimator: SRTT, RTTVAR, and the RTO (RFC 6298)
7. Worked numbers (the exact ones the tests assert)
8. The code, walked end-to-end
9. Verification
10. Why this, not that
11. Rebuild it yourself — checklist + exercises
12. What's still missing (the honest roadmap)

---

## 1. The mental model: what "reliable" actually costs

TCP promises the application a **reliable, ordered byte stream** over an **unreliable** packet
network. The network may drop, duplicate, reorder, or corrupt any packet. Corruption we already
catch (the checksum, Day 2). Reordering and gaps are a later chapter. *Loss* is this one.

The only tool TCP has against loss is **redundancy in time**: send a segment, and if you don't
hear that it arrived, send it again. Two pieces of machinery fall out of that sentence:

- **A memory of what's unacknowledged.** You cannot resend what you've thrown away, so every
  segment carrying sequence space (data, SYN, FIN) must be *retained* until its ACK arrives.
  That is the **retransmission queue**.
- **A clock and a deadline.** "If you don't hear back *in time*" needs a definition of time and
  of *in time*. That is the **retransmission timeout (RTO)**, and computing a good one is the
  RTT estimator.

ACKs are cumulative: `SND.UNA` (the oldest unacknowledged byte) only moves forward, and when it
passes a segment's last byte, that whole segment is safe to forget. So the queue is drained from
the front by advancing `SND.UNA`, and topped up at the back as we send.

---

## 2. Why the blocking loop could not do this (the design change)

Through Day 5 the main loop was, in essence:

```text
loop { let n = iface.recv(&mut buf)?;  // BLOCKS until a packet arrives
       handle(packet); }
```

`recv()` parks the thread until the kernel hands it a packet. That is fine for a pure
request/response echo — but a retransmission timer has to fire **when nothing is arriving**
(the whole point is that the expected ACK *didn't* come). In a blocking loop there is no moment
to check a clock: the thread is asleep inside `recv()`, possibly forever. This is exactly the
"blocker" Day 5 §10 named.

The fix is structural, not a patch: switch the interface to **non-blocking** I/O. Now `recv()`
returns immediately — either a packet, or a `WouldBlock` error meaning "nothing right now." That
frees the loop to do two jobs on every pass: service timers, then read a packet if one is ready.

```rust
iface.set_non_blocking()?;
let clock = std::time::Instant::now();   // monotonic; never goes backwards
```

`Instant` is monotonic — immune to wall-clock adjustments (NTP, DST) that could make a duration
negative. We never need calendar time, only *elapsed* milliseconds, so `clock.elapsed()` is the
right primitive.

---

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

The 5 ms nap matters. Without it, a quiet link would spin the CPU at 100% calling `recv()` in a
tight loop. With it, the loop wakes ~200×/second — fine-grained enough that a 200 ms RTO fires
within ~5 ms of its true deadline, cheap enough to be invisible. This is a poor-man's `epoll`:
a production stack would block in `poll()` with a timeout equal to the nearest timer, waking
*exactly* on a packet or a deadline. Same idea, less polling.

Reaping closed connections is now the loop's job too: `on_tick` may move a `TIME_WAIT`
connection to `CLOSED` after 2·MSL purely on the clock (no packet involved), so the loop checks
state after ticking and drops dead TCBs from the table.

---

## 4. The retransmission queue

`RetxQueue` is a list of segments we've sent but not yet seen acknowledged. Each entry:

```rust
struct Unacked {
    end_seq:    u32,      // one past this segment's last seq number; acked when SND.UNA reaches it
    packet:     Vec<u8>,  // the complete IP+TCP bytes, ready to resend verbatim
    sent_at_ms: u64,      // when it was (last) sent — the start of its RTT timer
    retries:    u32,      // how many times we've resent it (Karn's flag + future backoff)
}
```

Three operations, and the discipline of **passing time in** rather than reading a clock inside —
so the whole thing is unit-testable without sleeping:

- **`record(end_seq, packet, now_ms)`** — called right after we transmit data: store a clone and
  stamp it with the send time.
- **`ack(una, now_ms) -> Option<u64>`** — drop every segment the cumulative ACK now covers, and
  return an RTT sample for one of them (see §5). "Covered" is the wraparound-safe test
  `!seq::before(una, end_seq)` — `una` has reached or passed `end_seq` on the 32-bit circle
  (that `seq::before` is the modular comparison from Day 3).
- **`due(now_ms, rto_ms) -> Vec<packet>`** — return clones of every segment whose timer has
  elapsed (`now_ms − sent_at_ms ≥ rto_ms`), and for each, **reset its timer and bump `retries`**.
  Resetting is what makes the next resend wait another full RTO instead of firing every tick.

Note what we store: the *whole packet bytes*, not just the payload. Resending is then a literal
`iface.send(&bytes)` — the seq/ack/checksum were correct when built and are still correct (a pure
retransmission re-sends identical bytes). Simple and impossible to get subtly wrong.

The connection wires these in. On accepting in-order data it echoes, then
`retx.record(SND.NXT, echo, now)`. On an acceptable ACK it advances `SND.UNA` and calls
`retx.ack(SND.UNA, now)`. And `on_tick` returns `retx.due(now, self.rtt.rto())`.

---

## 5. Karn's algorithm — why a retransmitted segment's timing lies

Here is the trap. Suppose we send segment X at t=0, hear nothing, resend it at t=250, and an ACK
arrives at t=300. What was the RTT — 300 ms (from the first send) or 50 ms (from the second)?
**We cannot tell**, because both copies are byte-identical and the ACK names a sequence number,
not a transmission. Picking either can be badly wrong: if the ACK was actually for the *first*
copy and we credit it to the second, we'd compute a wildly short RTT and shrink the RTO toward
spurious retransmissions — a feedback loop that makes loss *worse*.

**Karn's algorithm (RFC 6298 §3):** never take an RTT sample from a segment that was
retransmitted. In code that is exactly the `retries == 0` guard inside `ack`:

```rust
if !still_unacked && s.retries == 0 && sample.is_none() {
    sample = Some(now_ms.saturating_sub(s.sent_at_ms));  // a trustworthy round trip
}
```

A segment that `due` ever resent has `retries > 0`, so it contributes no sample — its ack clears
it from the queue but leaves SRTT untouched. We sample at most one segment per ACK (the oldest
freshly-cleared, never-retransmitted one), which is all RFC 6298 asks for ("at least one
measurement per RTT"). Karn's *other* half — exponentially backing off the RTO on each
retransmit and holding it until a clean sample arrives — is left as exercise E2.

`saturating_sub` guards the degenerate `now < sent_at` (can't happen with a monotonic clock, but
free insurance against a 0-stamped test segment).

---

## 6. The RTT estimator: SRTT, RTTVAR, and the RTO (RFC 6298)

A single RTT sample is noisy, so we keep two smoothed statistics and update them on each sample
`R`. `α = 1/8` and `β = 1/4` are the standard gains; the divisions are exact right-shifts because
the gains are powers of two and everything is integer milliseconds (deterministic, no floats):

```text
first sample R:   SRTT   = R
                  RTTVAR = R / 2

later sample R:   RTTVAR = (1 − β)·RTTVAR + β·|SRTT − R|     # >> 2 for ·(1/4)
                  SRTT   = (1 − α)·SRTT   + α·R              # >> 3 for ·(1/8)
                  (RTTVAR updated FIRST — it uses the OLD SRTT, RFC 6298 §2.3)

RTO = clamp( SRTT + max(K·RTTVAR, G),  MIN_RTO,  MAX_RTO )
```

with `K = 4`, `G = 1 ms` (clock granularity, the floor on the variance term), `MIN_RTO = 200 ms`,
`MAX_RTO = 60 000 ms`. The RTO is `SRTT` plus a **safety margin proportional to the jitter**: a
steady path has small `RTTVAR` and a tight RTO; a jittery path widens it automatically.

Two deliberate departures from the letter of the RFC, both documented in `rtt.rs`:
- RFC 6298 §2.4 SHOULDs `MIN_RTO = 1000 ms`. We use **200 ms** — over a local TUN link the real
  RTT is sub-millisecond, and a 1-second floor would make a teaching demo feel broken. On the
  open internet you would restore 1000.
- Before the first sample, `rto()` returns `MIN_RTO` (200 ms) — a conservative default so the
  very first unacked segment still has a sane deadline.

The estimator is pure arithmetic over two `u64`s with no I/O, so its five unit tests pin every
branch.

---

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

And Karn in action (`connection_retransmits_then_clears_on_ack`): the echo is resent at t=250
(past the 200 ms default RTO), so when its ACK lands `retries=1` → no sample → `rto()` stays 200.

---

## 8. The code, walked end-to-end

The pieces and where they live:

| File | What it gained |
|---|---|
| `src/rtt.rs` | `RttEstimator` — `sample(R)` folds in a measurement, `rto()` reads the timeout |
| `src/tcp.rs` | `RetxQueue` (record/ack/due); `Connection` holds a `RttEstimator`; `on_tick` |
| `src/main.rs` | non-blocking interface, the timer-then-input loop, connection reaping |

The data path for one echoed segment, tracing the bytes:

```text
1. data arrives in-order → we build the echo, SND.NXT += len
2. retx.record(SND.NXT, echo_bytes, now)        # remember it, stamp the time
3. ...time passes, no ACK...
4. on_tick(now): retx.due(now, rtt.rto())        # now − sent_at ≥ rto? resend, retries++
5. peer's ACK arrives, SND.UNA < ACK ≤ SND.NXT   # acceptable (Day 3's `seq::between`)
6. SND.UNA = ACK; if let Some(r) = retx.ack(SND.UNA, now) { rtt.sample(r) }
        # segment cleared from the queue; if retries==0, r adapts the RTO
```

The crucial ordering in `Connection::on_tick`: expire `TIME_WAIT` first (a clock-only state
change), *then* `retx.due(now, self.rtt.rto())`. The RTO is no longer a constant passed in by
`main` — the connection owns its own adaptive estimate, which is why `on_tick` dropped its
`rto_ms` parameter. `main` just calls `conn.on_tick(now_ms)`.

---

## 9. Verification

`cargo test` → **44 green**, all offline (no TUN, no sudo). The reliability-specific ones:

- `rtt::*` (5) — default RTO with no sample, first sample, convergence on a steady RTT, and both
  clamps. These pin the arithmetic of §6/§7.
- `retx_records_acks_and_clears`, `retx_partial_ack_keeps_unacked`, `retx_ack_wraparound` — the
  queue drops exactly the fully-acked segments, keeps partials, and is wraparound-safe.
- `retx_fires_after_rto` — `due` returns nothing before the RTO, the segment after it, then resets.
- `connection_retransmits_then_clears_on_ack` — the full path: echo → resend after RTO → ACK
  clears the queue, with Karn suppressing the sample (RTO stays 200).
- `ack_of_new_data_samples_rtt_and_adapts_rto` — a clean (un-retransmitted) ACK drives RTO 200→360.

Live (your hands), via the `tcp-stack-run` skill: run the stack, `nc 192.168.0.2 8080`, type a
line. Then add loss with `sudo tc qdisc add dev tun0 root netem loss 30%` and watch the stack log
print `↻ retransmit (N bytes)` — the connection survives drops that would have silently hung it
before. Remove it with `sudo tc qdisc del dev tun0 root`.

---

## 10. Why this, not that

| Decision | We chose | Real TCP / alternative |
|---|---|---|
| I/O model | non-blocking `recv` + 5 ms sleep | `epoll`/`io_uring` waking on packet *or* nearest timer |
| Store for resend | whole packet bytes per segment | a byte buffer + rebuild header (lets you re-segment/coalesce) |
| RTO before first sample | fixed 200 ms default | RFC 6298 initial RTO = 1 s until first measurement |
| `MIN_RTO` | 200 ms (local link) | 1 s (RFC SHOULD), to survive internet jitter |
| Karn's backoff | sample-suppression only (E2 left open) | suppress **and** double RTO per retransmit, hold until clean sample |
| Retransmit unit | one segment at a time on its own timer | one timer per connection for the oldest unacked (RFC 6298 §5) |
| Float vs integer SRTT | integer ms + right-shifts | same in practice — kernels use fixed-point too |

---

## 11. Rebuild it yourself — checklist + exercises

From a blank file, reconstruct:
1. Why a *blocking* `recv` can't host a timer, and the exact shape of the non-blocking loop
   (timers → input → `WouldBlock`-nap).
2. The three `RetxQueue` operations and the wraparound-safe "fully acked" test.
3. Karn's algorithm in one sentence, and the `retries == 0` line that implements it.
4. The RFC 6298 update equations — including *why RTTVAR is updated before SRTT* — and the
   `RTO = SRTT + max(K·RTTVAR, G)` clamp.

**Exercises:**
- **E1.** Cap `retries`: after N (say 5) resends of the same segment, give up and `RST` the
  connection. Today an unanswered segment retransmits forever.
- **E2.** Implement the second half of Karn: double the RTO on each retransmit (exponential
  backoff) and hold the backed-off value until the next clean sample resets it.
- **E3.** Retransmit the **SYN-ACK** and **FIN** too (not just data) — they consume sequence
  space and can be lost. Queue them in `accept`/`close` and watch the handshake survive loss.
- **E4.** Replace the 5 ms sleep with a real `poll()` whose timeout is the nearest segment's
  deadline, so the loop wakes exactly on a packet or a timer.

---

## 12. What's still missing (the honest roadmap)

The connection is now reliable over a lossy link, but the climb continues (Manual Phases 3–5):

1. **Flow control** — we already track the peer's advertised window (`SND.WND`) and expose
   `usable_window()`; a bulk sender must actually *gate* transmission on it and we must advertise
   our own window from real buffer space. (Documented next: Day 8.)
2. **Active close + TIME_WAIT** — initiating the FIN ourselves and lingering 2·MSL. Already coded;
   its chapter is Day 7.
3. **Out-of-order reassembly** — a receive buffer that holds gaps until they fill. We still accept
   only exactly-in-order data and drop the rest.
4. **Congestion control** — slow start, congestion avoidance, fast retransmit/recovery
   (Reno/CUBIC). Retransmission tells you *that* to resend; congestion control governs *how fast*
   you may send into a shared network. This is the next big conceptual leap.
5. **A socket-style API** — `listen`/`accept`/`read`/`write` so an application, not a hard-coded
   echo, drives the bytes.

The honest status: **a TCP that opens, transfers, retransmits lost data with an adaptive timeout,
and closes — built from scratch and fully unit-tested.** That is a genuinely reliable stack over a
cooperative link. Congestion control is what separates it from one you'd dare put on the open
internet.

> Re-type `RetxQueue` and `RttEstimator` from this chapter with the book closed, then `cargo
> test`. You now hold reliability end to end: parsing (Day 1), checksums (Day 2), handshake
> (Day 3), data (Day 4), close (Day 5), and now retransmission + RTO (Day 6).
