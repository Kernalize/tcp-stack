# Day 12 — TCP, Part 10: Retransmitting the Control Segments (SYN, SYN-ACK, FIN)

> Goal: close the first robustness gap left open at the end of Day 11. Through Day 11 the retransmission
> queue protected only **data**. The three control segments that open and close a connection — `SYN`,
> `SYN-ACK`, and `FIN` — were sent exactly once. If any is dropped, the connection wedges: a lost SYN-ACK
> leaves the server stuck in `SYN_RCVD` forever; a lost FIN leaves a half-finished teardown. This chapter
> makes those segments first-class citizens of the same retransmission machinery, so the *whole* lifecycle
> is reliable, not just the middle of it — and adds the exponential RTO **backoff** (Karn's second half)
> so a stalled path is probed ever more patiently instead of hammered.

The insight is small and beautiful: SYN and FIN occupy sequence numbers exactly like data bytes, so they
can be acknowledged exactly like data — and anything that can be acknowledged can be lost and resent by the
*same* queue. Day 6 built that queue for data; today we drop the control segments into it and reuse every
line. The only genuinely new mechanism is RTO backoff.

**Contents**

Volume I — the chapter
1. The mental model: control segments live in sequence space too
2. Why a lost SYN-ACK (or FIN) hangs the connection
3. The mechanism: record on send, clear on ack
4. The sequence-number bookkeeping, exactly
5. RTO backoff — Karn's second half
6. Why the handshake yields no RTT sample
7. The Rust: an `_at` wrapper so time enters without a test rewrite
8. Worked example: a SYN-ACK lost once, then recovered
9. The code, walked end to end
10. Verification
11. Why this, not that
12. Honesty: what production does, and what later days added
13. Rebuild it yourself — checklist + exercises
14. What the next step adds

Volume II — the exhaustive reference
- A. Which flags consume sequence space, exhaustively
- B. RTO exponential backoff in full
- C. The connection-establishment timeout (R1/R2) — when to give up
- D. SYN retransmission and the SYN-flood interaction
- E. A worked lost-FIN recovery trace
- F. The `_at` wrapper and API evolution
- G. Comparison to real stacks — retry knobs
- H. Security — SYN-ACK amplification and the retry-cap DoS
- I. Performance — handshake latency and TCP Fast Open
- J. Extended FAQ
- K. Anki starter deck
- L. Glossary
- M. Reference tables

---

# Volume I — the chapter

## 1. The mental model: control segments live in sequence space too

A TCP sequence number counts **octets of the byte stream**, but two of the control flags also "occupy" one
number each, as if they were a phantom byte:

- **SYN** occupies the sequence number it is sent with. That is why, after sending a SYN at `ISS`, the next
  thing you send is at `ISS + 1`.
- **FIN** occupies one number too: the marker that says "no byte will ever follow this position."

(`RST` does *not* consume a sequence number, and pure `ACK`s carry no new sequence — they only report
`RCV.NXT`. So neither is ever retransmitted: there is nothing to be acknowledged.)

Because SYN and FIN sit *in* the sequence space, the receiver acknowledges them exactly the way it
acknowledges data: by advancing its ACK number past them. And the moment a segment can be acknowledged, it
can also be **lost and resent** — the sender just keeps a copy until the ACK covers it. That is the entire
idea of Day 12: the retransmission queue from Day 6 already does this for data; we simply put the SYN,
SYN-ACK, and FIN into the same queue.

```text
              consumes a seq number?     can be ACKed?     must be retransmittable?
   SYN              yes                     yes                  yes   ← new today
   FIN              yes                     yes                  yes   ← new today
   data             yes (len bytes)         yes                  yes   (Day 6)
   pure ACK         no                      no                   no
   RST              no                      no                   no
```

## 2. Why a lost SYN-ACK (or FIN) hangs the connection

Walk the passive open. A client SYN arrives; we create the TCB in `SYN_RCVD` and send a SYN-ACK. Now
picture the SYN-ACK being dropped by the network:

```text
   client                         us (SYN_RCVD)
     | --- SYN seq=100 ---------->  |   create TCB, send SYN-ACK
     |        (SYN-ACK seq=0 ack=101 is LOST)
     |                              |   ...we wait for the final ACK...
     |   ...client waits for the SYN-ACK that never came...
     |                              |
    DEADLOCK: each side is waiting for the other.
```

The client *will* retransmit its SYN (its own stack queues it), so in practice a real peer rescues us — but
only because *its* side is reliable. If **we** are the one that must resend (e.g. we did the active open, or
the client's stack is minimal), nothing happens. The same is true at close: a dropped FIN means the peer
never learns we are done, never sends the final ACK, and the connection lingers in `LAST_ACK`/`FIN_WAIT`
indefinitely. The fix is symmetry: every segment that consumes a sequence number must be resent until it is
acknowledged. We already do that for data; today we extend it to the three control segments.

## 3. The mechanism: record on send, clear on ack

The retransmission queue (`RetxQueue`, Day 6) stores `Unacked { start_seq, end_seq, packet, sent_at_ms,
retries, sacked }` (the `start_seq`/`sacked` fields were added by Day 18's SACK; day 12 used the original
four). Two operations matter:

- **`record(start_seq, end_seq, packet, now)`** — remember a segment we just put on the wire. `end_seq` is
  the sequence number *one past* the last number it consumes; the segment is fully acknowledged once
  `SND.UNA` reaches `end_seq`.
- **`ack(una, now)`** — drop every queued segment that `una` now covers (`end_seq` at or before `una`,
  modulo 2³²).

Day 12 adds exactly four `record` calls and a handful of `ack` calls:

| Segment | Recorded in | `end_seq` | Cleared when |
|---|---|---|---|
| SYN-ACK | `accept` (passive open) | `ISS + 1` | the final ACK arrives (`SYN_RCVD → ESTABLISHED`) |
| SYN | `connect` (active open) | `ISS + 1` | the SYN-ACK arrives (`SYN_SENT → ESTABLISHED`) |
| FIN (passive close) | the FIN path in `ESTABLISHED` | `SND.NXT` after its `+1` | the final ACK (`LAST_ACK → CLOSED`) |
| FIN (active close) | `close()` | `SND.NXT` after its `+1` | the peer's ACK of our FIN (`FIN_WAIT_1 → …`) |

Resending is *free*: `on_tick` already walks the queue and resends anything whose RTO has elapsed,
regardless of what kind of segment it is. We changed nothing there. The only new work is putting the control
segments **in** the queue and taking them **out** at the right transitions.

## 4. The sequence-number bookkeeping, exactly

The single most error-prone part is getting `end_seq` right, because SYN and FIN each consume one number.
Track `SND.NXT` through a passive open + passive close, ISS = 0:

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

The rule each time: **build the segment, advance `SND.NXT` by the one number the flag consumes, then
`record(start_seq, SND.NXT, …)`** — so `end_seq` is the post-increment value and `start_seq` is one less.
That is identical to how data is recorded, which is exactly the point: control and data use one rule.

Clearing uses `ack(una, now)` with the wrapping comparison `seq::before(una, end_seq)`: a segment is "still
unacked" while `una` is strictly before its `end_seq`. When `una == end_seq` (the ack lands exactly on the
boundary) the segment is dropped. Same modular arithmetic as Day 3, so it is correct across the 2³² wrap.

## 5. RTO backoff — Karn's second half

Day 6 implemented the first half of Karn's algorithm (don't sample a retransmitted segment). Day 12 adds the
**second half**: when a retransmission timeout fires, **double the RTO** and hold the doubled value until a
clean sample arrives. `RttEstimator::back_off`:

```rust
pub fn back_off(&mut self) {
    self.rto = (self.rto * 2).min(MAX_RTO);   // exponential, capped at 60 s
}
```

It's called from `on_tick` whenever `retx.due()` actually resends something (the RTO fired). The progression
is `200 → 400 → 800 → 1600 …`, capped at 60 s. Why double, and why freeze?

- **Doubling** is the universal "probe a contended/silent resource patiently" pattern (Ethernet collision
  backoff, the persist timer). If a path has gone dark, resending every 200 ms forever just wastes
  bandwidth; backing off geometrically tries a few times quickly, then ever more slowly.
- **Freezing** (holding the backed-off value) is necessary because Karn part 1 forbids a sample while
  retransmitting — *every* in-flight segment is a retransmission, so there's no clean RTT to recompute from.
  Without the freeze you'd snap back to the old (too-short) RTO the instant a cumulative ACK cleared an
  un-retransmitted segment behind the loss, restarting the storm. The backed-off RTO holds until the first
  *new*, never-retransmitted segment gives a clean sample, which resets the estimator.

Together with Day 6's sample-suppression, this completes RFC 6298 §5.5 / Karn & Partridge 1987 (§B has the
full treatment).

## 6. Why the handshake yields no RTT sample

`ack()` returns an RTT sample (`now − sent_at`) for the oldest freshly-acked, *never-retransmitted* segment,
which the data path feeds to the estimator. For the **control** clears we deliberately throw that sample
away:

```rust
let _ = self.retx.ack(self.send.una, now_ms);   // discard the sample
```

Two reasons: (1) **Karn part 1** — a retransmitted SYN-ACK/FIN can't be timed; and (2) it would corrupt the
estimator's first sample. Our deterministic tests establish a connection at logical `t = 0` and record the
SYN-ACK at `t = 0`; the handshake ACK also arrives at `t = 0`, so the "sample" would be `0 ms` — a
meaningless measurement that would wrongly become `SRTT`. Keeping the first *real* sample for the first
*data* exchange is simpler and closer to the estimator's purpose. (RFC 6298 *permits* measuring RTT from the
SYN/SYN-ACK exchange; we choose not to, and document it.) So control retransmission reuses the queue's
*resend* and *clear* logic but opts out of its *timing* logic.

## 7. The Rust: an `_at` wrapper so time enters without a test rewrite

To timestamp a control segment we need the current time at the moment it is built. `accept` and `connect`
previously took no clock. Threading `now_ms` into them naively would force a `now_ms` argument onto ~15
existing test call sites. Instead we use a thin-wrapper pattern that keeps the deterministic test
constructors unchanged:

```rust
// Production entry: real clock, random ISN.
pub fn accept(src, dst, th, opts, now_ms) -> ... {
    Self::accept_with_iss_at(src, dst, th, opts, rand::random(), now_ms)
}
// Test-only: fixed ISN, records the SYN-ACK as if sent at t = 0.
#[cfg(test)]
pub fn accept_with_iss(src, dst, th, iss) -> ... {
    Self::accept_with_iss_at(src, dst, th, &TcpOptions::default(), iss, 0)
}
// The real body: fixed ISN + send time.
pub fn accept_with_iss_at(src, dst, th, opts, iss, now_ms) -> ... { /* build + record */ }
```

`#[cfg(test)]` on `accept_with_iss` means it compiles only under `cargo test`, so it never becomes an
unused-function warning in `cargo build` — and `accept_with_iss_at` stays reachable from production through
`accept`, so it doesn't warn either. The existing tests that call `accept_with_iss(…, iss)` keep working
verbatim. A small lesson in evolving an API: add the more-capable function, express the old one in terms of
it, and gate the test-only convenience behind `cfg(test)`. (§F.)

## 8. Worked example: a SYN-ACK lost once, then recovered

ISS = 0, client SYN at seq 100, default RTO 200 ms (no RTT sample yet).

```text
   t=0     client SYN seq=100  →  accept(): TCB in SYN_RCVD; send SYN-ACK seq=0 ack=101;
                                   record(start=0, end_seq=1, sent_at=0)
           (the SYN-ACK is dropped by the network)
   t=150   on_tick(150): 150 − 0 = 150 < 200 → nothing due
   t=250   on_tick(250): 250 − 0 = 250 ≥ 200 → RESEND the exact SYN-ACK bytes;
                                   reset its timer to 250, back off RTO 200 → 400
   t=300   client final ACK ack=1 → SND.UNA = 1; ack(1) drops the SYN-ACK (1 ≥ 1);
                                   SYN_RCVD → ESTABLISHED
   t=1000  on_tick(1000): queue empty → nothing resent, forever
```

The connection that would have deadlocked now self-heals after one RTO. The retransmitted bytes are
**byte-for-byte identical** to the original (we stored the whole packet), so the client cannot tell a resend
from the first transmission — which is the whole contract of a retransmission.

## 9. The code, walked end to end

All changes are in `src/tcp.rs` (plus two call-site updates in `src/main.rs`).

- **`accept_with_iss_at`** builds the SYN-ACK, then `conn.retx.record(conn.send.iss, conn.send.nxt,
  synack.clone(), now_ms)`. `conn.send.nxt` is already `ISS + 1`, so `end_seq` is right.
- **`connect_with_iss`** does the same for the SYN, now taking `now_ms`.
- **`close`** records the FIN after advancing `SND.NXT`, and now takes `now_ms`.
- **The `ESTABLISHED` FIN path** (passive close) records our FIN after its `+1`.
- **Clears**: `SYN_SENT → ESTABLISHED`, `SYN_RCVD → ESTABLISHED`, `LAST_ACK → CLOSED`, `FIN_WAIT_1` (when
  our FIN is acked), and `CLOSING → TIME_WAIT` each call `let _ = self.retx.ack(…, now_ms)`.
- **`on_tick`** calls `self.rtt.back_off()` when `retx.due()` resent something (§5).
- **`main.rs`** passes `now_ms` into `accept(…)` and `close(…)`.

Nothing in `RetxQueue`'s resend logic changed — the payoff of the Day 6 design: time is an argument,
resending is type-agnostic, so extending coverage is purely additive.

## 10. Verification

`cargo test` adds four tests that drive the clock explicitly:

- `synack_retransmits_until_final_ack` — the SYN-ACK is silent before the RTO, resent after it, and never
  resent once the final ACK clears it.
- `syn_retransmits_until_synack` — the active-open SYN, same shape.
- `passive_fin_retransmits_until_acked` — our FIN-ACK (in `LAST_ACK`) is resent until the peer's final ACK,
  which also drives `→ CLOSED`.
- `active_fin_retransmits_until_acked` — our FIN (in `FIN_WAIT_1`) is resent until the peer ACKs it.

Each asserts the resent bytes equal the originally-sent bytes, and that the queue is empty after the
acknowledgement. The existing tests still pass unchanged — the regression guarantee that the new clears do
not over-fire.

## 11. Why this, not that

| Decision | Alternative | Why we chose it |
|---|---|---|
| Put control segments in the existing `RetxQueue` | A separate "control retransmit" timer | One queue, one timer path, one set of bugs. SYN/FIN are sequence-consuming just like data. |
| Suppress the RTT sample on handshake clears | Sample the SYN/SYN-ACK RTT (RFC 6298 allows it) | Avoids a meaningless `0 ms` first sample in tests; keeps the estimator fed by data; documented, reversible. |
| `_at` wrapper + `#[cfg(test)]` convenience | Thread `now_ms` through all 15 call sites | Keeps the diff focused on the feature, not on mechanical test churn (§F). |
| Resend forever (no give-up cap) | Abort after N control retransmits (RFC 9293 §3.8.3) | Consistent with the data path, which also doesn't yet cap. A real stack RSTs after `R2` (§C); noted as the next step. |
| RTO doubles per timeout, capped 60 s | Linear or fixed RTO | Exponential backoff is the proven patient-probe rule; the cap bounds the wait (§B). |

## 12. Honesty: what production does, and what later days added

- **No retransmission cap.** We resend SYN/SYN-ACK/FIN/data *forever*. RFC 9293 §3.8.3 says give up after
  `R2` retransmissions (Linux `tcp_retries2` ≈ 15, ~15 minutes) and RST the connection, with an earlier
  `R1` (~3) that triggers a routing-recheck. We never abort (exercise E1, §C). A hung connection therefore
  lingers in our stack until the process dies.
- **`Unacked` grew on Day 18.** Day 12's record stored four fields; Day 18 (SACK) added `start_seq` (to
  match SACK blocks) and `sacked`, so the §3 struct shows six. The control-segment recording adapted to the
  new `record(start_seq, end_seq, …)` signature.
- **SYN-ACK retry limits matter for SYN floods.** A real server caps SYN-ACK retransmissions tightly (or
  uses SYN cookies, Day 3 §E) precisely so a flood of never-completed handshakes can't make it retransmit
  forever. Our uncapped resend would amplify a flood (§H).
- **We don't sample the handshake RTT.** RFC 6298 permits it (it would give an RTT estimate one round trip
  earlier); we forgo it for test determinism (§6).
- **No TCP Fast Open.** A real modern stack can carry data *in* the SYN (TFO, RFC 7413) to save a round
  trip; ours doesn't (§I).

None of these change the day-12 contract (every sequence-consuming segment is now resent until acked); they
are the breadth a production stack adds.

## 13. Rebuild it yourself — checklist + exercises

**Blank-file checklist:**

- [ ] Which flags consume a sequence number? (SYN, FIN — not RST, not a pure ACK.)
- [ ] For each control segment, what is `end_seq`? (The post-`+1` `SND.NXT`.)
- [ ] Where is each control segment recorded, and at which state transition is it cleared?
- [ ] Why is the RTT sample discarded on those clears?
- [ ] What does RTO backoff do, and why must it *freeze* until a clean sample (Karn part 2)?

**Exercises:**

- **E1.** Add a retransmission cap: after `R2` resends of a segment with no progress, abort the connection
  (send a RST, go to `CLOSED`). Mirror it for data (RFC 9293 §3.8.3; §C).
- **E2.** Make the active-open SYN carry an MSS option (Day 15) and confirm the resent copy still includes
  it byte-for-byte.
- **E3.** Write a test where the *final ACK* of the handshake is itself lost, the client's data arrives, and
  confirm our SYN-ACK is no longer in flight by the time the data is processed.
- **E4.** Measure: how many resends before a peer artificially silent for 1 s, given 200 → 400 → 800
  backoff? Reconcile with `RttEstimator::back_off`.
- **E5.** Implement the `R1` routing-recheck hint and the `R2` abort separately (§C).

## 14. What the next step adds

Day 13 turns from **reliability** to **efficiency**: **Nagle's algorithm** (RFC 896). A chatty application
that writes one byte at a time would flood the link with 41-byte packets (40 bytes of header for 1 byte of
data). Nagle coalesces those small writes — *hold a sub-MSS segment while earlier data is still
unacknowledged* — and a `TCP_NODELAY` switch turns it off for latency-sensitive traffic. It's a three-line
change to `poll_transmit` with a surprisingly large effect, and the first time our sender chooses *not* to
send something it technically could.

---

# Volume II — the exhaustive reference

## A. Which flags consume sequence space, exhaustively

The rule that drives everything in this chapter: a segment is retransmittable iff it consumes sequence
space (so it can be acknowledged). The full accounting:

```text
   carries                consumes seq?   "length" in seq space   retransmit?
   ────────────────────   ─────────────   ─────────────────────   ───────────
   data (len bytes)       yes             len                     yes (Day 6)
   SYN                    yes             1                       yes (Day 12)
   FIN                    yes             1                       yes (Day 12)
   SYN + data (TFO)       yes             1 + len                 yes
   FIN + data             yes             len + 1                 yes
   pure ACK               no              0                       no (nothing to ack)
   RST                    no              0                       no (abortive, not reliable)
   window update (bare)   no              0                       no
   zero-window probe      yes             1 (one byte)            yes (Day 14)
```

The "length in sequence space" (RFC 9293 calls it `SEG.LEN` including the SYN/FIN) is what the receiver's
ACK advances past, and what `end_seq` records. A pure ACK has `SEG.LEN = 0` — it changes no sequence
number, carries only `RCV.NXT` feedback, and is therefore never retained (if it's lost, the next ACK
supersedes it). This is why the retransmission queue holds exactly "things that advance `SND.NXT`."

## B. RTO exponential backoff in full

Karn & Partridge's 1987 algorithm has two rules; Day 6 did rule 1, Day 12 does rule 2:

```text
   rule 1 (Day 6):  ignore RTT samples from retransmitted segments (ambiguous ACK).
   rule 2 (Day 12): on each retransmission timeout, RTO ← min(2·RTO, MAX_RTO),
                    and HOLD that value until a fresh, unambiguous sample is taken.
```

The backoff sequence from a 200 ms base: `200, 400, 800, 1600, 3200, 6400, 12800, 25600, 51200, 60000,
60000…` (capped at 60 s). Each doubling buys patience: the first few resends probe quickly (the loss was
probably transient), later ones space out (the path may be down). The **freeze** is the subtle half: while
backed off, you're retransmitting, so rule 1 forbids any sample — there's nothing to recompute from. Only
when a *new* segment (sent after the loss cleared) is acked cleanly does the estimator get a fresh sample
and reset. Our `RttEstimator` implements this by leaving `rto` at its backed-off value until `sample()` is
next called with a real measurement, which recomputes `RTO = SRTT + 4·RTTVAR` from scratch.

A subtle correctness point: backoff operates on the *RTO*, not on `SRTT`/`RTTVAR` — it's a temporary
inflation, not a re-estimate. When the clean sample arrives, the estimator recomputes from the smoothed
statistics (which the backoff never touched), so one bad patch of loss doesn't permanently distort the RTT
estimate.

## C. The connection-establishment timeout (R1/R2) — when to give up

A real stack cannot resend forever; RFC 9293 §3.8.3 defines two thresholds:

- **R1** — after this many retransmissions of a segment with no progress, the stack should *notify IP to
  recheck the route* (maybe the path changed) but keep trying. Linux `tcp_retries1` ≈ 3.
- **R2** — after this many, *abort* the connection (deliver an error to the application, send a RST). Linux
  `tcp_retries2` ≈ 15, which with exponential backoff is ~13–30 minutes.

For the **handshake** specifically there are tighter, separate limits: `tcp_syn_retries` (active-open SYN,
≈ 6, ~127 s of total wait) and `tcp_synack_retries` (passive SYN-ACK, ≈ 5). These are smaller than the data
limits because a connection that can't even *open* in a couple of minutes is almost certainly dead, and —
for SYN-ACK — because a server under SYN flood must not retransmit half-open handshakes for long (§H).

We implement *none* of these caps (exercise E1, E5): our SYN/SYN-ACK/FIN/data resend forever. The practical
consequence is that a connection to a vanished peer never errors out on our side; it just retransmits with
ever-longer backoff until the process exits. Adding `R2` is the single most important robustness step after
this chapter.

## D. SYN retransmission and the SYN-flood interaction

SYN-ACK retransmission and SYN-flood defense pull in opposite directions, which is why real stacks treat
SYN-ACK retries specially:

- **Why retransmit a SYN-ACK at all?** A lost SYN-ACK on an active-open-from-a-minimal-peer would deadlock
  (§2); resending rescues it.
- **Why limit it tightly?** Each half-open connection (in `SYN_RCVD`, awaiting the final ACK) holds a TCB.
  A **SYN flood** (Day 3 §E) creates many half-opens that never complete; if the server retransmits each
  SYN-ACK several times with backoff, it spends bandwidth and holds TCBs *longer*, amplifying the attack.

The production resolution is **SYN cookies** (Day 3 §E): under flood, don't allocate a TCB or queue a
SYN-ACK retransmission at all — encode the state in the ISN and reconstruct it from the final ACK. So a real
stack retransmits SYN-ACKs normally when the SYN queue is healthy, and switches to stateless cookies (no
retransmission) when it overflows. Our uncapped, always-stateful SYN-ACK retransmission is the wrong choice
*under attack* (§H) and the right choice for a cooperative LAN — the usual teaching-vs-hardening gap.

## E. A worked lost-FIN recovery trace

Active close (we send the first FIN), our FIN lost once. ISS context: `SND.NXT = 1` at close, default RTO
200.

```text
   t=0     close(): send FIN seq=1 ack=RCV.NXT; SND.NXT → 2; record(start=1, end=2, sent_at=0); → FIN_WAIT_1
           (the FIN is dropped)
   t=200   on_tick: 200 ≥ 200 → resend the exact FIN bytes; timer → 200; back_off RTO 200 → 400
   t=260   peer ACK ack=2 → SND.UNA = 2; ack(2) drops the FIN (2 ≥ 2); our FIN is acknowledged
           (FIN_WAIT_1 → FIN_WAIT_2, awaiting the peer's FIN)
   t=...   peer FIN → we ACK → TIME_WAIT → (2·MSL) → CLOSED
```

Without Day 12, the FIN dropped at t=0 would never be resent: we'd sit in FIN_WAIT_1 forever, the peer never
learning we'd closed. With it, the teardown self-heals in one RTO — and the backoff means if the path is
genuinely down, we probe at 200, 400, 800… rather than flooding it. The same shape protects the *passive*
FIN (in LAST_ACK) and the SYN/SYN-ACK at open.

## F. The `_at` wrapper and API evolution

The pattern used to add a `now_ms` parameter without churning every caller generalizes to any "this function
now needs a new input that most callers can default":

```text
   public  fn foo(args)          → delegates to foo_with_x(args, default_x)   [keeps old callers working]
   public  fn foo_with_x(args, x) → the real body                            [new capability]
   #[cfg(test)] fn foo_test(args) → foo_with_x(args, fixed_x)                [test-only convenience]
```

The key moves: (1) the *most capable* function holds the real logic; (2) the *old signature* is re-expressed
as a thin wrapper that supplies a sensible default, so existing callers compile unchanged; (3) any
*test-only* convenience constructor is gated behind `#[cfg(test)]` so it doesn't trip `dead_code` in release
builds. This keeps a feature diff focused on the feature rather than a mechanical sweep of call sites, and it
keeps `cargo clippy -D warnings` (the CI gate) green — an unused non-test function or an un-cfg'd test helper
would both warn. We used it for `accept`/`connect`/`close` gaining `now_ms`; the same shape recurs as later
days add `opts` to these constructors.

## G. Comparison to real stacks — retry knobs

```text
   knob (Linux)         default   governs                              our equivalent
   ──────────────────   ───────   ──────────────────────────────────  ──────────────────
   tcp_syn_retries      6         active-open SYN resends (~127 s)     uncapped resend
   tcp_synack_retries   5         passive SYN-ACK resends              uncapped resend
   tcp_retries1         3         data: when to recheck the route (R1) (not implemented)
   tcp_retries2         15        data: when to abort (R2, ~15 min)    (not implemented)
   TCP_USER_TIMEOUT     —         app-set abort deadline               (not implemented)
   RTO_MIN / RTO_MAX    ~200ms/120s  the RTO clamp                     200 ms / 60 s
```

The structural difference is that real stacks **bound** every retransmission category with a count and/or a
deadline, surfaced as tunables, while we resend unconditionally. The defaults encode hard-won operational
wisdom: SYN retries are short (a dead path should fail fast at connect), data retries are long (a transient
outage mid-transfer should be ridden out), and `TCP_USER_TIMEOUT` lets latency-sensitive apps demand an even
tighter bound. Implementing `R2` (E1) is the first step toward this.

## H. Security — SYN-ACK amplification and the retry-cap DoS

- **SYN-ACK retransmission amplification.** An attacker spoofing a victim's IP as the SYN source makes us
  send SYN-ACKs *to the victim* — and, with uncapped retransmission, *several* SYN-ACKs per spoofed SYN, each
  larger than the SYN. That turns our server into a (small) reflection/amplification source aimed at the
  victim, and ties up our TCBs. Real stacks cap SYN-ACK retries (§G) and use cookies under load (§D); ours
  doesn't, so it's a worse reflector than it should be.
- **The retry-cap DoS (the other direction).** A *too-aggressive* cap can be abused too: if an attacker can
  induce a few losses on a victim's connection right at the cap, the connection aborts. `TCP_USER_TIMEOUT`
  and the `R1`/`R2` split balance "don't hang forever" against "don't abort a recoverable connection." The
  tuning is genuinely adversarial.
- **Resource exhaustion via never-completing handshakes.** Without a cap, every half-open from a SYN flood
  retransmits SYN-ACKs indefinitely, holding bandwidth and TCBs — the amplified SYN flood. Bounded retries +
  cookies are the defense (Day 3 §E).

The theme: control-segment retransmission is necessary for reliability but is an *attacker-exploitable
resource* (each resend costs the server bandwidth and a held TCB), so production stacks cap it tightly for
the handshake and fall back to stateless cookies under flood — exactly the hardening our cooperative-LAN
version omits.

## I. Performance — handshake latency and TCP Fast Open

- **The cost of a lost SYN is brutal for latency.** Because there's no RTT estimate yet, a lost SYN/SYN-ACK
  waits the *initial* RTO (1 s in RFC 6298, 200 ms for us) before resending — so a single early loss adds a
  full second to connection setup on the real internet. This is why short flows (a small HTTP request) are so
  sensitive to handshake loss: the *setup* dominates, and one dropped SYN can triple the user-visible
  latency.
- **TCP Fast Open (TFO, RFC 7413)** attacks the *handshake round trip itself*: it lets a client send data
  *in* the SYN (validated by a server-issued cookie from a prior connection), so the request is delivered in
  the first packet and the response can come back in the SYN-ACK — saving one full RTT on repeat
  connections. With our uncapped retransmission, TFO data in the SYN would simply be part of the recorded
  segment (`SYN + data` consumes `1 + len`, §A). We don't implement TFO, but the sequence-space accounting
  here is exactly what it would build on.
- **Backoff and goodput.** The exponential backoff (§B) trades latency for politeness: it won't recover a
  transient loss as fast as a fixed short RTO, but it won't melt a congested path either. For setup
  specifically, that's why real stacks keep the *initial* RTO modest and the SYN retry count low — fast
  recovery matters most exactly when there's no data to amortize it over.
- **Our cost** is one extra `record`/`ack` per control segment and one `back_off` per timeout — negligible;
  the *limitation* is the uncapped resend (a dead connection never errors).

## J. Extended FAQ

1. **Which flags consume a sequence number?** SYN and FIN (one each); data (len bytes). Not RST, not pure
   ACK.
2. **Why does that matter for retransmission?** Only sequence-consuming segments can be acked, hence lost
   and resent.
3. **What hangs if a SYN-ACK is lost (pre-Day-12)?** The server sits in SYN_RCVD; the client waits — a
   deadlock unless the client resends its SYN.
4. **What hangs if a FIN is lost?** The teardown stalls in LAST_ACK/FIN_WAIT; the peer never sends the final
   ACK.
5. **How are control segments made reliable?** Recorded in the same `RetxQueue` as data; resent by `on_tick`;
   cleared on the acking transition.
6. **What is a control segment's `end_seq`?** `SND.NXT` *after* the SYN/FIN's `+1` — the post-increment
   value.
7. **Where is the SYN-ACK recorded / cleared?** Recorded in `accept`; cleared at SYN_RCVD → ESTABLISHED.
8. **Where is the active-open SYN recorded / cleared?** Recorded in `connect`; cleared at SYN_SENT →
   ESTABLISHED.
9. **Why discard the RTT sample on handshake clears?** Karn (retransmitted/ambiguous) + it'd be a bogus
   `0 ms` first sample in tests.
10. **What is RTO backoff?** Doubling the RTO on each timeout (capped 60 s) — Karn's second half.
11. **Why freeze the backed-off RTO?** No clean sample is possible while retransmitting; freezing avoids
    snapping back to a too-short RTO.
12. **When does the frozen RTO reset?** When a *new*, never-retransmitted segment is acked cleanly.
13. **What changed in `on_tick`?** It calls `rtt.back_off()` when `retx.due()` resent something.
14. **Did the resend logic change?** No — it's type-agnostic; only `record`/`ack`/`back_off` calls were
    added.
15. **What is the `_at` wrapper pattern?** Add `foo_with_x`, re-express `foo` via it with a default, gate
    test helpers behind `cfg(test)` (§F).
16. **Why `#[cfg(test)]` on `accept_with_iss`?** So a test-only convenience doesn't warn in release builds.
17. **Do we cap retransmissions?** No — we resend forever; real stacks use R1/R2 / SYN-retry limits (§C).
18. **What's R1 vs R2?** Recheck-route threshold vs abort threshold (RFC 9293 §3.8.3).
19. **Why are SYN-ACK retries limited tightly in real stacks?** SYN-flood amplification — uncapped retries
    worsen it (§D/§H).
20. **How does this interact with SYN cookies?** Cookies are stateless (no TCB, no SYN-ACK retransmission)
    under flood (Day 3 §E).
21. **What is the latency cost of a lost SYN?** A full initial RTO (1 s real / 200 ms us) before resend —
    setup-dominating for short flows (§I).
22. **What is TCP Fast Open?** Data in the SYN (cookie-validated) saving a round trip; `SYN+data` consumes
    `1+len` (§A/§I).
23. **Does the resent segment differ from the original?** No — byte-for-byte identical (we store the whole
    packet).
24. **Did `Unacked` change later?** Yes — Day 18 added `start_seq` and `sacked` (SACK), so `record` gained
    a `start_seq` arg.
25. **What's the most important next robustness step?** Implement `R2` to abort a hung connection (E1).

## K. Anki starter deck

```text
Q: Which TCP flags consume a sequence number?  A: SYN and FIN (one each); data (len). Not RST/pure ACK.
Q: Why can SYN/FIN be retransmitted but a pure ACK can't?  A: they consume seq space → can be acked → can be lost/resent.
Q: What hangs if a SYN-ACK is lost (no control retx)?  A: server stuck in SYN_RCVD; deadlock unless client resends.
Q: A control segment's end_seq?  A: SND.NXT after the SYN/FIN +1 (post-increment).
Q: Where is the SYN-ACK cleared?  A: at SYN_RCVD → ESTABLISHED (the final ACK).
Q: Why discard the handshake RTT sample?  A: Karn (ambiguous) + it'd be a bogus 0 ms first sample.
Q: What is RTO backoff (Karn part 2)?  A: double the RTO per timeout (cap 60 s) and freeze until a clean sample.
Q: Why freeze the backed-off RTO?  A: no clean sample exists while retransmitting; avoids snapping back too short.
Q: When does the frozen RTO reset?  A: when a new, never-retransmitted segment is acked cleanly.
Q: Did on_tick/resend logic change much?  A: no — type-agnostic; only record/ack/back_off calls added.
Q: The _at wrapper pattern?  A: foo_with_x holds logic; foo defaults to it; test helper gated by cfg(test).
Q: Do we cap retransmissions?  A: no (resend forever); real stacks use R1/R2 and SYN-retry limits.
Q: R1 vs R2?  A: recheck-route threshold vs abort-the-connection threshold (RFC 9293 §3.8.3).
Q: Why limit SYN-ACK retries tightly?  A: SYN-flood amplification — uncapped retries worsen it.
Q: TCP Fast Open?  A: data in the SYN (cookie-validated), saving a round trip; SYN+data consumes 1+len.
```

## L. Glossary

- **Control segment** — a SYN, SYN-ACK, or FIN; sequence-consuming but data-less.
- **Sequence-consuming** — occupies sequence space (SYN/FIN: 1; data: len), hence acknowledgeable.
- **`record` / `ack`** — the `RetxQueue` operations: remember a sent segment / drop acked ones.
- **`end_seq`** — one past the last sequence number a segment consumes; acked when `SND.UNA` reaches it.
- **RTO backoff** — doubling the RTO per consecutive timeout (Karn's second half).
- **Karn's algorithm** — don't sample retransmitted segments (part 1) + back off and freeze the RTO (part 2).
- **R1 / R2** — RFC 9293 thresholds: recheck-route / abort.
- **`tcp_syn_retries` / `tcp_synack_retries`** — Linux handshake retransmission limits.
- **SYN cookies** — stateless handshake under flood; no SYN-ACK retransmission.
- **TCP Fast Open (TFO)** — carrying data in the SYN to save a round trip.
- **`_at` wrapper** — the API-evolution pattern for adding a `now_ms` (or `opts`) input.

## M. Reference tables

**M.1 — Control segments in the retransmission queue**

```text
   segment    recorded in   end_seq         cleared at
   ────────   ───────────   ─────────────   ───────────────────────────
   SYN-ACK    accept        ISS+1           SYN_RCVD → ESTABLISHED
   SYN        connect       ISS+1           SYN_SENT → ESTABLISHED
   FIN (pass) ESTABLISHED   SND.NXT (post)  LAST_ACK → CLOSED
   FIN (act)  close()       SND.NXT (post)  FIN_WAIT_1 (FIN acked) / CLOSING → TIME_WAIT
```

**M.2 — RTO backoff sequence (200 ms base, cap 60 s)**

```text
   timeout #   1     2     3     4     5      6      7      8       9      10+
   RTO (ms)    200   400   800   1600  3200   6400   12800  25600   51200  60000
```

**M.3 — Sequence-space length by segment type**

```text
   segment            SEG.LEN (seq consumed)   retransmittable?
   ────────────────   ──────────────────────   ────────────────
   data (len)         len                       yes
   SYN / FIN          1                         yes
   SYN+data           1 + len                   yes (TFO)
   zero-window probe  1                         yes (Day 14)
   pure ACK / RST     0                         no
```

> Re-type the four `record` calls, the clears, and `back_off` with the book closed, then `cargo test`. The
> lifecycle is now reliable end to end: not one sequence-consuming segment can be lost without being resent,
> and a stalled path is probed with ever-increasing patience instead of being hammered.
