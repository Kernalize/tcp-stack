# Day 12 — TCP, Part 10: Retransmitting the Control Segments (SYN, SYN-ACK, FIN)

> Goal: close the first robustness gap left open at the end of Day 11. Through Day 11 the
> retransmission queue protected only **data**. The three control segments that open and close a
> connection — `SYN`, `SYN-ACK`, and `FIN` — were sent exactly once. If any of them is dropped, the
> connection wedges: a lost SYN-ACK leaves the server stuck in `SYN_RCVD` forever; a lost FIN leaves
> a half-finished teardown. This chapter makes those segments first-class citizens of the same
> retransmission machinery you already built, so the *whole* lifecycle is reliable, not just the
> middle of it.

**Contents**
1. The mental model: control segments live in sequence space too
2. Why a lost SYN-ACK (or FIN) hangs the connection
3. The mechanism: record on send, clear on ack
4. The sequence-number bookkeeping, exactly
5. Karn's algorithm and why the handshake yields no RTT sample
6. The Rust: an `_at` wrapper so time enters without a test rewrite
7. Worked example: a SYN-ACK lost once, then recovered
8. The code, walked
9. Verification
10. Why this, not that
11. Rebuild it yourself — checklist + exercises
12. What the next day adds

---

## 1. The mental model: control segments live in sequence space too

A TCP sequence number counts **octets of the byte stream**, but two of the control flags also
"occupy" one number each, as if they were a phantom byte:

- **SYN** occupies the sequence number it is sent with. That is why, after sending a SYN at `ISS`,
  the next thing you send is at `ISS + 1`.
- **FIN** occupies one number too: it is the marker that says "no byte will ever follow this
  position."

(`RST` does *not* consume a sequence number, and pure `ACK`s carry no new sequence — they only
report `RCV.NXT`. So neither is ever retransmitted: there is nothing to be acknowledged.)

Because SYN and FIN sit *in* the sequence space, the receiver acknowledges them exactly the way it
acknowledges data: by advancing its ACK number past them. And the moment a segment can be
acknowledged, it can also be **lost and resent** — the sender just keeps a copy until the ACK
covers it. That is the entire idea of Day 12: the retransmission queue from Day 6 already does this
for data; we simply put the SYN, SYN-ACK, and FIN into the same queue.

```text
        consumes a seq number?     can be ACKed?     must be retransmittable?
  SYN          yes                     yes                  yes   ← new today
  FIN          yes                     yes                  yes   ← new today
  data         yes (len bytes)         yes                  yes   (Day 6)
  pure ACK     no                      no                   no
  RST          no                      no                   no
```

## 2. Why a lost SYN-ACK (or FIN) hangs the connection

Walk the passive open. A client SYN arrives; we create the TCB in `SYN_RCVD` and send a SYN-ACK.
Now picture the SYN-ACK being dropped by the network:

```text
  client                         us (SYN_RCVD)
    | --- SYN seq=100 ---------->  |   create TCB, send SYN-ACK
    |        (SYN-ACK seq=0 ack=101 is LOST)
    |                              |   ...we wait for the final ACK...
    |   ...client waits for the SYN-ACK that never came...
    |                              |
   DEADLOCK: each side is waiting for the other.
```

The client *will* retransmit its SYN (its own stack queues it), so in practice a real peer rescues
us — but only because *its* side is reliable. If **we** are the one that must resend (e.g. we did
the active open, or the client's stack is minimal), nothing happens. The same is true at close: a
dropped FIN means the peer never learns we are done, never sends the final ACK, and the connection
lingers in `LAST_ACK`/`FIN_WAIT` indefinitely.

The fix is symmetry: every segment that consumes a sequence number must be resent until it is
acknowledged. We already do that for data. Today we extend it to the three control segments.

## 3. The mechanism: record on send, clear on ack

The retransmission queue (`RetxQueue`, Day 6) stores `Unacked { end_seq, packet, sent_at_ms,
retries }`. Two operations matter:

- **`record(end_seq, packet, now)`** — remember a segment we just put on the wire. `end_seq` is the
  sequence number *one past* the last number it consumes; the segment is fully acknowledged once
  `SND.UNA` reaches `end_seq`.
- **`ack(una, now)`** — drop every queued segment that `una` now covers (`end_seq` is at or before
  `una`, modulo 2³²).

Day 12 adds exactly four `record` calls and a handful of `ack` calls:

| Segment | Recorded in | `end_seq` | Cleared when |
|---|---|---|---|
| SYN-ACK | `accept` (passive open) | `ISS + 1` | the final ACK arrives (`SYN_RCVD → ESTABLISHED`) |
| SYN | `connect` (active open) | `ISS + 1` | the SYN-ACK arrives (`SYN_SENT → ESTABLISHED`) |
| FIN (passive close) | the FIN-handling path in `ESTABLISHED` | `SND.NXT` after its `+1` | the final ACK (`LAST_ACK → CLOSED`) |
| FIN (active close) | `close()` | `SND.NXT` after its `+1` | the peer's ACK of our FIN (`FIN_WAIT_1 → …`) |

Resending is *free*: `on_tick` already walks the queue and resends anything whose RTO has elapsed,
regardless of what kind of segment it is. We changed nothing there. The only new work is putting
the control segments **in** the queue and taking them **out** at the right transitions.

## 4. The sequence-number bookkeeping, exactly

The single most error-prone part is getting `end_seq` right, because SYN and FIN each consume one
number. Track `SND.NXT` through a passive open + passive close, ISS = 0:

```text
  event                         SND.NXT   record end_seq   note
  ------------------------------------------------------------------------
  accept(): build SYN-ACK         0        —              SYN-ACK carries seq=ISS=0
  SYN consumes one → nxt += 1      1        1             record(end_seq = SND.NXT = 1)
  final ACK (ack=1) arrives        1        (clear 1)     SND.UNA = 1 ≥ 1 → drop SYN-ACK
  ...data flows...
  peer FIN arrives, we reply FIN   1        —             FIN carries seq=SND.NXT=1
  our FIN consumes one → nxt += 1  2        2             record(end_seq = SND.NXT = 2)
  final ACK (ack=2) arrives        2        (clear 2)     SND.UNA = 2 ≥ 2 → drop FIN
```

The rule each time: **build the segment, advance `SND.NXT` by the one number the flag consumes,
then `record(SND.NXT, …)`** — so `end_seq` is the post-increment value. That is identical to how
data is recorded (`record(self.send.nxt, …)` after `self.send.nxt += n`), which is exactly the
point: control and data use one rule.

Clearing uses `ack(una, now)` with the wrapping comparison `seq::before(una, end_seq)`: a segment is
"still unacked" while `una` is strictly before its `end_seq`. When `una == end_seq` (the ack lands
exactly on the boundary) the segment is dropped. This is the same modular arithmetic from Day 3, so
it is correct across the 2³² wrap.

## 5. Karn's algorithm and why the handshake yields no RTT sample

`ack()` returns an RTT sample (`now − sent_at`) for the oldest freshly-acked, *never-retransmitted*
segment, which the data path feeds to the RTT estimator. For the **control** clears we deliberately
throw that sample away:

```rust
let _ = self.retx.ack(self.send.una, now_ms);   // discard the sample
```

Two reasons:

1. **Karn's algorithm** (Day 6): a retransmitted segment must not be timed, because you cannot tell
   which copy the ACK answers. `ack()` already suppresses the sample for retransmitted segments —
   but we go further and suppress it for *all* handshake/teardown clears, because…
2. **It would corrupt the estimator's first sample.** Our deterministic tests establish a connection
   at logical time `t = 0` and record the SYN-ACK at `t = 0`; the handshake ACK also arrives at
   `t = 0`, so the "sample" would be `0 ms` — a meaningless measurement that would wrongly become
   `SRTT`. Keeping the first *real* sample for the first *data* exchange is both simpler and closer
   to what the estimator is for. (RFC 6298 permits measuring RTT from the SYN/SYN-ACK exchange; we
   choose not to, and document it.)

So control retransmission reuses the queue's *resend* and *clear* logic but opts out of its
*timing* logic.

## 6. The Rust: an `_at` wrapper so time enters without a test rewrite

To timestamp a control segment we need the current time at the moment it is built. `accept` and
`connect` previously took no clock. Threading `now_ms` into them naively would force a `now_ms`
argument onto ~15 existing test call sites. Instead we use a thin-wrapper pattern that keeps the
deterministic test constructors unchanged:

```rust
// Production entry: real clock, random ISN.
pub fn accept(src, dst, th, now_ms) -> ... {
    Self::accept_with_iss_at(src, dst, th, rand::random(), now_ms)
}

// Test-only: fixed ISN, records the SYN-ACK as if sent at t = 0 (when tests drive the clock from).
#[cfg(test)]
pub fn accept_with_iss(src, dst, th, iss) -> ... {
    Self::accept_with_iss_at(src, dst, th, iss, 0)
}

// The real body: fixed ISN + send time.
pub fn accept_with_iss_at(src, dst, th, iss, now_ms) -> ... { /* build + record */ }
```

`#[cfg(test)]` on `accept_with_iss` means it is compiled only under `cargo test`, so it never
becomes an unused-function warning in `cargo build` — and `accept_with_iss_at` stays reachable from
production through `accept`, so it does not warn either. The thirteen existing tests that call
`accept_with_iss(…, iss)` keep working verbatim. This is a small lesson in evolving an API: add the
more-capable function, express the old one in terms of it, and gate the test-only convenience
behind `cfg(test)`.

## 7. Worked example: a SYN-ACK lost once, then recovered

ISS = 0, client SYN at seq 100, default RTO 200 ms (no RTT sample yet).

```text
  t=0     client SYN seq=100  →  accept(): TCB in SYN_RCVD; send SYN-ACK seq=0 ack=101;
                                  record(end_seq=1, sent_at=0)
          (the SYN-ACK is dropped by the network)
  t=150   on_tick(150): 150 − 0 = 150 < 200 → nothing due
  t=250   on_tick(250): 250 − 0 = 250 ≥ 200 → RESEND the exact SYN-ACK bytes;
                                  reset its timer to 250, back off RTO 200 → 400
  t=300   client final ACK ack=1 → SND.UNA = 1; ack(1) drops the SYN-ACK (1 ≥ 1);
                                  SYN_RCVD → ESTABLISHED
  t=1000  on_tick(1000): queue empty → nothing resent, forever
```

The connection that would have deadlocked now self-heals after one RTO. The retransmitted bytes are
**byte-for-byte identical** to the original (we stored the whole packet), so the client cannot tell
a resend from the first transmission — which is the whole contract of a retransmission.

## 8. The code, walked

All changes are in `src/tcp.rs` (plus two call-site updates in `src/main.rs`).

- **`accept_with_iss_at`** builds the SYN-ACK, then `conn.retx.record(conn.send.nxt, synack.clone(),
  now_ms)`. `conn.send.nxt` is already `ISS + 1`, so `end_seq` is right.
- **`connect_with_iss`** does the same for the SYN, now taking `now_ms`.
- **`close`** records the FIN after advancing `SND.NXT`, and now takes `now_ms`.
- **The `ESTABLISHED` FIN path** (passive close) records our FIN after its `+1`.
- **Clears**: `SYN_SENT → ESTABLISHED`, `SYN_RCVD → ESTABLISHED`, `LAST_ACK → CLOSED`, `FIN_WAIT_1`
  (when our FIN is acked, before choosing `FIN_WAIT_2` / `CLOSING` / `TIME_WAIT`), and `CLOSING →
  TIME_WAIT` each call `let _ = self.retx.ack(th.ack /or self.send.una/, now_ms)`.
- **`main.rs`** passes `now_ms` into `accept(…)` and `close(…)`.

Nothing in `on_tick` or `RetxQueue` changed — that is the payoff of the Day 6 design: time is an
argument, resending is type-agnostic, so extending coverage is purely additive.

## 9. Verification

`cargo test` adds four tests that drive the clock explicitly:

- `synack_retransmits_until_final_ack` — the SYN-ACK is silent before the RTO, resent after it, and
  never resent once the final ACK clears it.
- `syn_retransmits_until_synack` — the active-open SYN, same shape.
- `passive_fin_retransmits_until_acked` — our FIN-ACK (in `LAST_ACK`) is resent until the peer's
  final ACK, which also drives `→ CLOSED`.
- `active_fin_retransmits_until_acked` — our FIN (in `FIN_WAIT_1`) is resent until the peer ACKs it.

Each asserts the resent bytes equal the originally-sent bytes, and that the queue is empty after the
acknowledgement. The existing 62 tests still pass unchanged — the regression guarantee that the new
clears do not over-fire.

## 10. Why this, not that

| Decision | Alternative | Why we chose it |
|---|---|---|
| Put control segments in the existing `RetxQueue` | A separate "control retransmit" timer | One queue, one timer path, one set of bugs. SYN/FIN are sequence-consuming just like data — the queue already models exactly that. |
| Suppress the RTT sample on handshake clears | Sample the SYN/SYN-ACK RTT (RFC 6298 allows it) | Avoids a meaningless `0 ms` first sample in tests and keeps the estimator fed by data exchanges; documented, reversible. |
| `_at` wrapper + `#[cfg(test)]` convenience | Thread `now_ms` through all 15 call sites | Keeps the diff focused on the feature, not on mechanical test churn, and teaches a clean API-evolution move. |
| Resend forever (no give-up cap) | Abort after N control retransmits (RFC 9293 §3.8.3) | Consistent with the *data* path, which also does not yet cap. A real stack RSTs after `R2`; we note it as the next robustness step rather than special-casing control. |

## 11. Rebuild it yourself — checklist + exercises

**Blank-file checklist** (re-derive without looking):
- [ ] Which flags consume a sequence number? (SYN, FIN — not RST, not a pure ACK.)
- [ ] For each control segment, what is `end_seq`? (The post-`+1` `SND.NXT`.)
- [ ] Where is each control segment recorded, and at which state transition is it cleared?
- [ ] Why is the RTT sample discarded on those clears?
- [ ] Why does `on_tick` need no change at all?

**Exercises:**
- **E1.** Add a retransmission cap: after `R2` resends of a control segment with no progress, abort
  the connection (send a RST, go to `CLOSED`). Mirror it for data. (RFC 9293 §3.8.3.)
- **E2.** Make the active-open SYN carry an MSS option (foreshadowing Day 15) and confirm the resent
  copy still includes it byte-for-byte.
- **E3.** Write a test where the *final ACK* of the handshake is itself lost, the client's data
  arrives, and confirm our SYN-ACK is no longer in flight by the time the data is processed.
- **E4.** Measure: how many times does a SYN-ACK get resent before a peer that is artificially silent
  for 1 s gives up, given the 200 ms → 400 → 800 backoff? Reconcile with `RttEstimator::back_off`.

## 12. What the next day adds

Day 13 turns to **efficiency rather than reliability**: **Nagle's algorithm** (RFC 896). A chatty
application that writes one byte at a time would otherwise flood the link with 41-byte packets (40
bytes of header for 1 byte of data). Nagle coalesces those small writes — *hold a sub-MSS segment
while earlier data is still unacknowledged* — and we add a `TCP_NODELAY` switch to turn it off for
latency-sensitive traffic. It is a three-line change to `poll_transmit` with a surprisingly large
effect, and the first time our sender chooses *not* to send something it technically could.

> Re-type the four `record` calls and the clears with the book closed, then `cargo test`. The
> lifecycle is now reliable end to end: not one sequence-consuming segment can be lost without being
> resent.
