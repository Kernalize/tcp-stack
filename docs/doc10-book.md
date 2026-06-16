# Doc 10 — TCP, Part 8: Congestion Control (Slow Start, AIMD, Fast Recovery)

> Goal: keep the sender from overwhelming the **network**. Flow control (Doc 8) bounds the sender by the
> receiver's buffer; congestion control bounds it by the *path* — the routers and links in between, which
> the receiver's window knows nothing about. The sender carries a second window, `cwnd`, that grows while
> ACKs flow and collapses on loss. That feedback loop — AIMD — is one of the most consequential control
> systems ever deployed: it is the reason the internet, a network with no central traffic cop, doesn't
> melt down under its own load.

This is the deepest idea in TCP and arguably in the whole internet. There is no central allocator deciding
how fast each of a billion flows may send; instead every sender runs a tiny distributed control loop that
*infers* the network's capacity from the timing of ACKs and loss, and the aggregate of those loops
self-organizes into a fair, stable sharing of every link. We implement the classic RFC 5681 (Reno) version
— the algorithm Van Jacobson designed in 1988 to end the congestion collapses that were killing the early
internet.

**Contents**

Volume I — the chapter
1. The mental model: two ceilings, take the lower
2. `cwnd` and `ssthresh`
3. Slow start — find the ceiling fast
4. Congestion avoidance — probe it gently (AIMD)
5. Two faces of loss: duplicate ACKs vs a timeout
6. Fast retransmit & fast recovery
7. Worked numbers (what the tests assert)
8. The Rust: the state machine and saturating math
9. The code, walked — module + wiring
10. The honest caveat: an echo server can't stress this
11. Verification
12. Why this, not that
13. Honesty: what production does (NewReno, CUBIC, BBR, ECN)
14. Rebuild it yourself — checklist + exercises
15. What the next step adds

Volume II — the exhaustive reference
- A. The 1986 congestion collapse and Jacobson's 1988 fix
- B. AIMD — why it is provably stable and fair (the control theory)
- C. Slow start, exhaustively (the ACK clock)
- D. Congestion avoidance and the sawtooth, exhaustively
- E. Loss responses — Reno, NewReno, and SACK-based recovery
- F. ECN — congestion signaling without loss
- G. The modern algorithms — CUBIC and BBR
- H. A worked sawtooth trace
- I. Comparison to real stacks
- J. Security — ACK division, optimistic ACKing, congestion attacks
- K. Performance — BDP, fairness, bufferbloat, incast
- L. Extended FAQ
- M. Anki starter deck
- N. Glossary
- O. Reference tables

---

# Volume I — the chapter

## 1. The mental model: two ceilings, take the lower

The receiver's window (`SND.WND`) says "my buffer can hold this much." But between us and the receiver sit
queues in routers with finite capacity. If everyone sends as fast as their receiver allows, those queues
overflow, packets drop, everyone retransmits, queues overflow harder — a **congestion collapse**. The
internet actually suffered this in 1986 (§A); Van Jacobson's 1988 fix is what we implement here.

The sender keeps a private estimate of the network's capacity, the **congestion window** `cwnd`, and never
lets in-flight data exceed:

```text
   effective window = min(SND.WND, cwnd) − FlightSize
```

`SND.WND` protects the receiver; `cwnd` protects the network. Whichever is smaller wins. In our stack
that's `Connection::usable_window()`: `min(self.send.wnd, self.cong.window()) − flight`.

The profound part: `cwnd` is **inferred, not told.** No router ever announces "you may send 100 KB." The
sender learns the capacity by *probing* — increasing `cwnd` until loss happens, treating loss as the
network's only feedback signal, then backing off. Congestion control is the art of estimating a hidden,
shared, changing quantity from one bit of feedback (loss/no-loss), in a way that stays stable and fair when
a billion senders do it at once.

## 2. `cwnd` and `ssthresh`

Two variables drive everything (`src/congestion.rs`):

- **`cwnd`** — the congestion window in bytes. Starts at 1 MSS (so slow start's ramp is visible in the
  teaching demo; modern stacks per RFC 6928 start at 10 MSS).
- **`ssthresh`** — the slow-start threshold. It's the boundary between two growth regimes:
  `cwnd < ssthresh` → **slow start** (exponential); `cwnd ≥ ssthresh` → **congestion avoidance** (linear).
  It starts "infinite" (we use 65535) and is pulled down to roughly half the in-flight data every time loss
  is detected — that's the "multiplicative decrease" half of AIMD.

`MSS` (maximum segment size) is the unit of growth. At doc 10 we use a fixed 1460 (typical Ethernet
payload); Doc 15 negotiates it from the peer's SYN. Measuring `cwnd` in *bytes* but growing it in *MSS
units* keeps the algorithm packet-oriented (the network congests on packets/queues, roughly per-segment),
which is what RFC 5681 specifies.

## 3. Slow start — find the ceiling fast

At connection start (or after a timeout) we have *no idea* how much the network will bear, so we probe
**exponentially**: every ACK bumps `cwnd` by one MSS.

```rust
if self.cwnd < self.ssthresh {
    self.cwnd = self.cwnd.saturating_add(MSS);   // +1 MSS per ACK
}
```

Why is "+1 MSS per ACK" exponential? Because in one RTT you receive roughly `cwnd / MSS` ACKs (one per
segment in flight), so `cwnd` *doubles* each round trip: 1 → 2 → 4 → 8 MSS… It's "slow" only relative to
the original "blast everything at once" — it actually ramps very quickly, until it hits `ssthresh` or loss.
The doubling-per-RTT is the fastest *safe* probe: it finds the right order of magnitude of the path's
capacity in `log₂(capacity)` round trips.

## 4. Congestion avoidance — probe it gently (AIMD)

Once `cwnd` reaches `ssthresh`, we're near the estimated capacity, so we switch to **linear** growth —
roughly +1 MSS per *RTT* instead of per ACK:

```rust
else {
    self.cwnd = self.cwnd.saturating_add((MSS * MSS / self.cwnd).max(1));  // +MSS²/cwnd per ACK
}
```

Summed over the `cwnd / MSS` ACKs in one RTT, `MSS²/cwnd × (cwnd/MSS) = MSS` — about one MSS per RTT. This
is the **additive increase** of AIMD. Paired with halving on loss (multiplicative decrease), it produces
the famous TCP **sawtooth**: climb gently, halve on loss, climb again. The `.max(1)` guards against the
integer division rounding to 0 for a large `cwnd` (we always grow by at least 1 byte per ACK). AIMD is not
an arbitrary choice — it is the *unique* increase/decrease rule that converges to fair, efficient sharing
(§B).

## 5. Two faces of loss: duplicate ACKs vs a timeout

TCP infers loss two ways, and they mean different things:

- **Three duplicate ACKs** — the receiver got segments *after* a gap (it keeps re-acking the byte it's
  missing; those dup-ACKs are exactly what Doc 9 made us emit). Data is still flowing, so the network isn't
  badly congested → a *mild* signal. Response: **fast retransmit + fast recovery** (halve, keep going).
- **Retransmission timeout (RTO)** — silence; not even dup-ACKs came back. The pipe may be severely
  congested or broken → a *strong* signal. Response: collapse `cwnd` to 1 MSS and restart slow start.

```rust
pub fn on_timeout(&mut self, flight_size: u32) {
    self.ssthresh = (flight_size / 2).max(2 * MSS);   // remember ~half as the new threshold
    self.cwnd = MSS;                                  // back to square one
    ...
}
```

We wire this where the RTO actually fires — in `Connection::on_tick`, when `retx.due()` returns something
to resend. The asymmetry (mild vs strong response) is the key insight: not all loss is equal, and reacting
to a single reordering as if the network collapsed would needlessly halve throughput.

## 6. Fast retransmit & fast recovery

On the **third** duplicate ACK we don't wait for the RTO — we resend the missing segment at once (fast
retransmit) and halve our window rather than crashing it to 1 (fast recovery):

```rust
pub fn on_dup_ack(&mut self, flight_size: u32) -> bool {
    self.dup_acks += 1;
    if self.dup_acks == 3 {
        self.ssthresh = (flight_size / 2).max(2 * MSS);   // multiplicative decrease
        self.cwnd = self.ssthresh + 3 * MSS;              // inflate by the 3 segments that left
        self.in_recovery = true;
        return true;                                      // ⇒ caller fast-retransmits
    }
    if self.in_recovery { self.cwnd += MSS; }             // each extra dup-ACK inflates
    false
}
```

The `+3·MSS` and per-dup inflation model the fact that each dup-ACK proves a segment *left* the network
(the receiver got it), so we may send a little more — keeping the ACK clock ticking during recovery. When a
*new* ACK finally arrives, we exit recovery and **deflate** `cwnd` back to `ssthresh`:

```rust
pub fn on_ack(&mut self, acked: u32) {
    self.dup_acks = 0;
    if self.in_recovery { self.in_recovery = false; self.cwnd = self.ssthresh; return; }
    ...
}
```

On our side, `Connection` detects a duplicate ACK (acks no new data, `th.ack == SND.UNA`, data still
outstanding, empty payload, window unchanged — the four-part test hardened on Doc 14) and, when
`on_dup_ack` returns `true`, resends the oldest unacked segment via `RetxQueue::fast_retransmit` — which
also bumps that segment's retry count so Karn's algorithm (Doc 6) correctly refuses to time it. (Doc 18's
SACK makes fast_retransmit resend the first *un-SACKed* hole rather than blindly the oldest.)

## 7. Worked numbers (what the tests assert)

MSS = 1460. Slow start (`slow_start_adds_one_mss_per_ack`):

```text
   cwnd 1·MSS → on_ack → 2·MSS → on_ack → 3·MSS …   (each ACK adds a full MSS)
```

Three dup-ACKs with 10·MSS in flight (`three_dup_acks_trigger_fast_retransmit`):

```text
   FlightSize = 14600
   ssthresh = 14600/2 = 7300  (= 5·MSS)
   cwnd     = ssthresh + 3·MSS = 7300 + 4380 = 11680  (= 8·MSS)   → return true (fast retransmit)
```

New ACK ends recovery (`new_ack_deflates_out_of_recovery`): `cwnd → ssthresh = 5·MSS`. Then with
`cwnd == ssthresh` we're in congestion avoidance, and one ACK adds only `MSS²/cwnd ≈ 1460²/7300 ≈ 292`
bytes — far less than a full MSS (`congestion_avoidance_grows_sub_linearly`). A timeout
(`timeout_collapses_to_one_mss_and_slow_start`): `cwnd → 1·MSS`, and the next ACK adds a full MSS again
(slow start resumed). These exact numbers are why the §7 tests assert `8·MSS`, `5·MSS`, `292`, and `1·MSS`.

## 8. The Rust: the state machine and saturating math

- **A four-field state machine.** `CongestionControl { cwnd, ssthresh, dup_acks, in_recovery }` — the whole
  RFC 5681 controller is four numbers and three methods (`on_ack`, `on_dup_ack`, `on_timeout`). No floats,
  no allocation; it's a tiny, pure state machine, which is why all seven of its tests drive it directly
  with synthetic ACK counts and assert exact `cwnd` values.
- **Saturating arithmetic everywhere.** `cwnd.saturating_add(MSS)` can't overflow past `u32::MAX`;
  `(flight_size/2).max(2*MSS)` floors `ssthresh` at 2 segments (RFC 5681 §3.1 requires
  `ssthresh ≥ 2·SMSS`). The `.max(1)` in congestion avoidance guards the integer division. Each guard
  encodes an RFC invariant directly in the type-correct arithmetic.
- **`flight_size` passed in, not stored.** The controller doesn't know about sequence numbers; the
  connection computes `FlightSize = SND.NXT − SND.UNA` and hands it in. Clean separation: the controller is
  pure congestion logic, the connection owns the sequence space.
- **`window()` is the single read.** The connection calls `self.cong.window()` (returns `cwnd`) inside
  `usable_window`'s `min`. One method bridges the controller to the send path.

## 9. The code, walked — module + wiring

| Piece | Role |
|---|---|
| `src/congestion.rs` | `CongestionControl`: `on_ack` / `on_dup_ack` / `on_timeout` / `window()` — the RFC 5681 machine |
| `Connection.cong` | one per connection; default = 1 MSS cwnd, 65535 ssthresh |
| `usable_window()` | now `min(SND.WND, cwnd) − FlightSize` |
| `on_segment` ACK branch | new-data ACK → `on_ack` (grow); duplicate ACK → `on_dup_ack` → maybe fast-retransmit |
| `on_tick` | RTO fired (`retx.due` non-empty) → `on_timeout` (collapse + slow start) |
| `RetxQueue::fast_retransmit` | resend the oldest unacked (un-SACKed, Doc 18) segment, reset timer, count retry |

The connection now distinguishes three kinds of ACK in ESTABLISHED: one that **advances** `SND.UNA` (grow
cwnd), a **duplicate** (no new data, data outstanding → count toward fast retransmit), and everything else
(ignored). That three-way split is the sender side of congestion control.

## 10. The honest caveat: an echo server can't stress this

Congestion control governs a sender with a *backlog* — data queued faster than it can be sent. Our stack is
an echo server: it sends only a tiny response to each received segment and then has nothing queued, so
`FlightSize` stays near zero and `min(SND.WND, cwnd)` never actually clamps it. `cwnd` sits there growing
harmlessly.

So why build it now? Because the **algorithm** is the lesson, and it's fully exercised by unit tests that
drive the state machine directly. The piece that makes it *bind* in practice is a real **send buffer** and
an application that writes in bulk — precisely the socket API of Doc 11, whose `poll_transmit` gates every
send on `usable_window()`. Building the controller first means Doc 11's sender has a correct window to obey
on day one. (Same pattern as the RTT estimator in Doc 6: a clean, tested module wired in ahead of the load
that will exercise it.)

## 11. Verification

`cargo test` proves the controller offline. Coverage:

- `congestion::*` — slow-start increment, the 3-dup-ACK fast-retransmit trigger and its `cwnd`/`ssthresh`
  math, per-dup inflation, deflation on a new ACK, sub-linear congestion avoidance, and timeout collapse +
  slow-start resumption.
- `tcp::three_dup_acks_fast_retransmit_the_oldest_segment` — end-to-end: we echo "hi", then three duplicate
  ACKs arrive; the first two do nothing, the third returns the echo bytes for immediate resend.
- `tcp::bulk_send_is_gated_by_the_congestion_window` (Doc 11) — a real backlog clamped by `cwnd`.

Live, you can't easily *see* `cwnd` bind on the echo path (§10). The honest demonstration is the unit tests
plus, with Doc 11's bulk sender, an `iperf3`-style transfer under `tc netem loss 5%` showing the sawtooth —
the Manual's Week 8 milestone.

## 12. Why this, not that

| Decision | We chose | Real TCP |
|---|---|---|
| Algorithm | RFC 5681 Reno (AIMD + fast recovery) | CUBIC (Linux default), BBR (model-based), etc. (§G) |
| Initial cwnd | 1 MSS (visible ramp) | 10 MSS (RFC 6928) |
| MSS | fixed 1460 at doc 10 | negotiated via the MSS option in the SYN (Doc 15) |
| Loss signal | 3 dup-ACKs + RTO | + ECN (§F), RACK-TLP (time-based) |
| Recovery | basic fast recovery | NewReno / SACK-based per-segment recovery (§E) |
| Where it binds | nowhere at doc 10 (echo server) | gates every send from a real send buffer (Doc 11) |

## 13. Honesty: what production does (NewReno, CUBIC, BBR, ECN)

- **Reno → NewReno → SACK recovery.** Our fast recovery is basic Reno. **NewReno** (RFC 6582) stays in
  recovery until *all* data outstanding at the time of loss is acked, retransmitting on each *partial* ACK
  — fixing Reno's poor handling of multiple losses in one window. **SACK-based recovery** (RFC 6675, our
  Doc 18 building blocks) uses the scoreboard to retransmit exactly the holes while keeping the pipe full.
  We implement classic Reno; the upgrades are exercises E2/E5.
- **CUBIC is the Linux default (§G).** Reno's linear additive-increase is too slow to fill modern long-fat
  pipes; CUBIC grows as a cubic function of time-since-loss, ramping fast far from the last loss and gently
  near it. BBR abandons loss-as-signal entirely, modeling bandwidth and RTT directly.
- **ECN avoids loss as the signal (§F).** Explicit Congestion Notification lets routers *mark* packets
  instead of dropping them; the sender reacts to a mark as a (gentler, lossless) congestion signal. We
  don't implement ECN.
- **MSS is fixed at doc 10.** The controller uses a 1460 constant; Doc 15 negotiates the real MSS, and the
  congestion module derives its `MSS` from the same source so the two agree.
- **No pacing.** Real stacks *pace* `cwnd` worth of data smoothly across the RTT rather than bursting it on
  each ACK; we'd burst (if we had a backlog). Pacing reduces queue spikes.
- **Appropriate Byte Counting, hystart, etc.** Many refinements (RFC 3465 ABC, HyStart slow-start exit) are
  out of scope.

None of these change the doc-10 contract (the sender obeys `min(SND.WND, cwnd)` and runs AIMD); they are
the decades of refinement layered on Jacobson's core.

## 14. Rebuild it yourself — checklist + exercises

**Blank-file checklist:**

- [ ] The two ceilings and why the sender takes `min(SND.WND, cwnd) − FlightSize`.
- [ ] Why "+1 MSS per ACK" is exponential but "+MSS²/cwnd per ACK" is linear (count the ACKs per RTT).
- [ ] The two loss signals and their very different responses (halve vs collapse-to-1).
- [ ] The fast-retransmit/fast-recovery sequence: 3 dup-ACKs → halve `ssthresh`, inflate `cwnd`, retransmit
      → deflate on the next new ACK.
- [ ] Why AIMD (not AIAD or MIMD) converges to fairness (§B).

**Exercises:**

- **E1.** ✅ *Done* (Doc 11): a real send buffer + bulk write so `usable_window()` actually clamps
  transmission; watch `cwnd` sawtooth under `tc netem loss`.
- **E2.** Implement **NewReno**: stay in recovery until *all* data outstanding at the time of loss is acked,
  retransmitting on each partial ACK (§E).
- **E3.** Add **ECN**: react to a congestion mark in the IP/TCP headers as a gentler loss signal, halving
  without a retransmit (§F).
- **E4.** Swap Reno for **CUBIC**'s cubic growth and compare ramp-up on a high-BDP path (§G).
- **E5.** Wire Doc 18's SACK scoreboard into recovery (RFC 6675 `pipe`/`IsLost`) so recovery retransmits
  holes while keeping the pipe full.

## 15. What the next step adds

We now have every internal mechanism of TCP: handshake, reliable in-order transfer, retransmission with an
adaptive RTO, teardown, flow control, reassembly, and congestion control. What's missing is the
**interface**: a socket-style API (`write`/`take_received`/`poll_transmit`) with a send buffer, so a real
application — a tiny HTTP server — can drive the stack instead of a hard-coded echo. That API (Doc 11) is
also what finally gives congestion control something to push against.

---

# Volume II — the exhaustive reference

## A. The 1986 congestion collapse and Jacobson's 1988 fix

In October 1986, the throughput between Lawrence Berkeley Lab and UC Berkeley — 400 yards apart, connected
through a few IMPs — dropped from 32 kbit/s to **40 bit/s**, a factor of 1000. The cause: under load, RTTs
rose, RFC 793's variance-blind RTO (Doc 6 §B) fired too early, senders retransmitted, the extra traffic
raised load further, and the network entered **congestion collapse** — a stable state where the link is
busy but almost no *useful* data gets through (it's nearly all retransmissions of data already delivered or
about to be).

Van Jacobson's 1988 paper "Congestion Avoidance and Control" diagnosed it and added three mechanisms, all
in this curriculum: the **variance-based RTO** (Doc 6), **slow start**, and **congestion avoidance** (this
day). The unifying principle he articulated is **conservation of packets**: a connection "in equilibrium"
should put a new packet into the network only when an old one leaves (an ACK arrives) — the **ACK clock**.
Slow start *reaches* equilibrium; congestion avoidance *maintains* it; the RTO and dup-ACKs detect when
it's lost. This paper is why the internet scaled from thousands to billions of hosts without a central
traffic authority.

## B. AIMD — why it is provably stable and fair (the control theory)

Why **A**dditive **I**ncrease, **M**ultiplicative **D**ecrease, and not some other rule? Consider two flows
sharing a link, plotted with flow 1's rate on the x-axis and flow 2's on the y-axis. The "fairness line" is
`x = y` (equal shares); the "efficiency line" is `x + y = capacity` (link full). We want to converge to
their intersection (fair *and* full).

```text
   y (flow 2)
    │   \   efficiency line: x+y=C
    │    \      ↗ additive increase moves at 45° (parallel to fairness line)
    │  ·  \   ╱
    │ fair ·\ ╱  multiplicative decrease moves toward the origin (toward the fairness line)
    │ line  ·X
    └──────────── x (flow 1)
```

- **Additive increase** moves both flows up-right at 45° (each adds the same amount), *parallel* to the
  fairness line — it doesn't change the *ratio*, only pushes toward efficiency.
- **Multiplicative decrease** scales both flows toward the origin along a line through it — this *does*
  move toward the fairness line (halving a big flow and a small flow narrows their ratio).

Iterating "increase additively until the link fills (loss), then decrease multiplicatively" zig-zags
*toward* the intersection and stays near it — Chiu & Jain (1989) proved AIMD is the rule that converges to
both fairness and efficiency. AIAD (additive decrease) wouldn't reduce the ratio (no fairness convergence);
MIMD (multiplicative increase) overshoots and oscillates. AIMD is the sweet spot, which is why every
loss-based TCP uses it. The "sawtooth" you see in a single flow's `cwnd` is this convergence in action.

## C. Slow start, exhaustively (the ACK clock)

Slow start exists because a new connection has *no* RTT/capacity estimate and starting at the full window
would dump a huge burst into queues of unknown depth. Instead it **self-clocks**: send 1 MSS, and for each
ACK that returns, send 2 (the one ACKed plus one new). The number in flight doubles every RTT:

```text
   RTT 0:  send 1 seg                          cwnd = 1·MSS
   RTT 1:  1 ACK back → send 2                 cwnd = 2·MSS
   RTT 2:  2 ACKs back → send 4                cwnd = 4·MSS
   RTT 3:  4 ACKs back → send 8                cwnd = 8·MSS
   ...     doubling until cwnd ≥ ssthresh OR loss
```

The exponential ramp reaches a path's capacity `C` in `log₂(C/MSS)` RTTs — e.g. a 10 MB window in ~13 RTTs.
The genius is that it's *driven by ACKs*, so it automatically paces to the path's RTT: a slow path ramps
slowly (ACKs come slowly), a fast path ramps fast. Slow start ends one of three ways: `cwnd` hits
`ssthresh` (switch to congestion avoidance), a loss occurs (the path's capacity found the hard way), or the
receiver's window caps it. Modern stacks add **HyStart** to exit slow start *before* a loss by watching RTT
inflation (a sign queues are filling), avoiding the burst-loss that ends naive slow start.

## D. Congestion avoidance and the sawtooth, exhaustively

In congestion avoidance the sender believes it's *near* capacity, so it probes gently: +1 MSS per RTT. Over
the `W = cwnd/MSS` ACKs in one RTT, adding `MSS²/cwnd = MSS/W` per ACK sums to one MSS. This linear growth,
punctuated by multiplicative decrease on loss, is the **sawtooth**:

```text
   cwnd
    │        /|        /|        /|
    │       / |       / |       / |     each tooth: +1 MSS/RTT (additive increase)
    │      /  |      /  |      /  |      each cliff: cwnd ← cwnd/2 (multiplicative decrease on loss)
    │     /   |____ /   |____ /   |____
    │    /         /         /
    └────────────────────────────────── time
```

The **average** throughput of a single Reno flow is the famous "TCP-friendly" formula:

```text
   throughput ≈ MSS / (RTT · √p) · constant       (p = loss probability)
```

Two consequences fall out of the `1/√p` and `1/RTT`: a flow's rate is **inversely proportional to its
RTT** (short-RTT flows beat long-RTT flows on a shared link — the "RTT unfairness" that newer algorithms
try to fix), and it falls only as `1/√p` with loss (so Reno tolerates modest loss but its `1/RTT` term
caps it badly on long-fat networks — the reason CUBIC exists, §G). The sawtooth's average utilization is
~75% of the peak (the area under the teeth), which is why a single Reno flow can't perfectly fill a link.

## E. Loss responses — Reno, NewReno, and SACK-based recovery

The evolution of fast recovery, each fixing the last's weakness with multiple losses in one window:

- **Reno (RFC 5681, ours).** 3 dup-ACKs → halve `ssthresh`, set `cwnd = ssthresh + 3·MSS`, retransmit the
  one segment at `SND.UNA`, inflate per further dup-ACK, deflate to `ssthresh` on a new ACK. *Weakness:* if
  *two* segments were lost in one window, the new ACK after the first retransmit is only a *partial* ACK;
  Reno exits recovery, then needs another 3 dup-ACKs (or an RTO) for the second loss — slow.
- **NewReno (RFC 6582).** Remembers the highest sequence sent when recovery began (`recover`). A *partial*
  ACK (acks some but not all of it) means another loss; NewReno immediately retransmits the next hole and
  *stays* in recovery until all of `recover` is acked. Handles multiple losses in `~1 RTT each` without an
  RTO.
- **SACK-based recovery (RFC 6675).** With SACK (Doc 18) the receiver *names* the holes, so the sender
  retransmits exactly them while a `pipe` estimator keeps the network as full as `cwnd` allows — the best
  loss recovery, retransmitting only genuine holes and never stalling. Our Doc 18 builds the SACK
  scoreboard; wiring 6675's `pipe`/`IsLost` is exercise E5.

```text
   algorithm   multiple losses / window      retransmits        keeps pipe full during recovery?
   ─────────   ───────────────────────────   ────────────────   ────────────────────────────────
   Reno        ~1 RTO per extra loss (slow)   the SND.UNA hole   no
   NewReno     ~1 RTT per loss               holes, one/RTT     partially
   SACK/6675   ~1 RTT for all                exactly the holes  yes (pipe-driven)
```

## F. ECN — congestion signaling without loss

**Explicit Congestion Notification** (RFC 3168) lets the network signal congestion *without dropping a
packet*. Two bits in the IP header (the ECN field) and two TCP flags (ECE, CWR) coordinate it:

- A router experiencing congestion, instead of dropping an ECN-capable packet, *marks* it (sets
  `CE = Congestion Experienced` in the IP ECN bits).
- The receiver echoes the mark to the sender via the **ECE** (ECN-Echo) TCP flag.
- The sender reacts as if it were a loss — **halves `cwnd`** — and signals it has done so via **CWR**
  (Congestion Window Reduced).

The win: congestion is signaled *before* a queue overflows, so the sender backs off without anyone losing
(and retransmitting) a packet — lower latency and no wasted bandwidth. ECN underpins modern low-latency
designs (DCTCP in datacenters uses fine-grained ECN marking). We don't implement it; exercise E3 adds the
ECE reaction. The point to carry: loss is TCP's *default* congestion signal only because the early internet
had no other; ECN (and BBR's RTT-based model) are attempts to congestion-control without needing to drop
packets at all.

## G. The modern algorithms — CUBIC and BBR

```text
   algorithm   signal            growth                      strength                weakness
   ─────────   ───────────────   ─────────────────────────   ─────────────────────   ──────────────────
   Reno        loss              linear (+1 MSS/RTT)         simple, fair, proven    slow on long-fat nets
   CUBIC       loss              cubic in time-since-loss    fills high-BDP fast     still loss-based
   BBR         bandwidth + RTT   paces to estimated BtlBw    loss-tolerant, low queue can be unfair to Reno
```

- **CUBIC** (Linux default since 2.6.19). `cwnd` grows as a **cubic** function of the time since the last
  loss: it shoots up quickly when far below the previous loss point, flattens (the "plateau") as it nears
  it, then probes gently past it. This is *RTT-independent* (growth keyed to wall-clock time, not ACKs), so
  it fixes Reno's `1/RTT` unfairness and fills high-BDP links far faster.
- **BBR** (Google, 2016). Abandons loss as the signal entirely. It actively probes to *measure* the
  bottleneck bandwidth (BtlBw) and the minimum RTT (RTprop), then **paces** at the bandwidth and caps
  in-flight data at the BDP — keeping the bottleneck link full but queues nearly empty (low latency, no
  bufferbloat). It can be aggressive toward loss-based flows sharing a queue. BBR is a different philosophy:
  *model the pipe* rather than *react to drops*.

Reno (ours) is the conceptual foundation all of these build on or react against — you can't understand
CUBIC's "fix the linear ramp" or BBR's "stop using loss" without first owning AIMD.

## H. A worked sawtooth trace

A bulk flow, MSS 1460, `ssthresh` starts ∞, RTT steady. Slow start then a loss, in `cwnd`/MSS units:

```text
   phase                 event                         cwnd (MSS)   ssthresh (MSS)
   ───────────────────   ───────────────────────────   ──────────   ──────────────
   slow start            1 RTT of ACKs                  1→2→4→8       ∞
   slow start            8 segs in flight, 1 lost       —             —
   fast retransmit       3rd dup-ACK (FlightSize 8MSS)  8/2+3 = 7     4   (= 8/2)
   fast recovery         each extra dup-ACK             7→8→9 …       4
   recovery exit         new ACK arrives                cwnd ← 4      4
   congestion avoidance  +1 MSS per RTT                 4→5→6→7 …     4
   ...                   next loss at, say, 8           8/2+3 = 7     4
   congestion avoidance  +1/RTT from cwnd=4 again       4→5→6 …       4
```

The signature: an exponential ramp once (slow start), then forever the linear-climb / halve-on-loss
sawtooth, with `ssthresh` tracking "half of where loss last happened" as the level the linear phase starts
from. The first loss permanently exits slow start (sets a finite `ssthresh`); after that the flow lives in
the congestion-avoidance sawtooth unless an RTO collapses it back to `cwnd = 1` and re-enters slow start.

## I. Comparison to real stacks

```text
   aspect            Linux                                this stack
   ───────────────   ──────────────────────────────────  ──────────────────────
   default algo      CUBIC (BBR optional)                 Reno (RFC 5681)
   initial cwnd      10 MSS (RFC 6928)                    1 MSS
   slow-start exit   HyStart (RTT-based, pre-loss)        on loss or ssthresh
   recovery          SACK + RACK-TLP + PRR                Reno fast recovery
   ECN               supported (DCTCP for datacenters)     none
   pacing            fq/pacing qdisc, BBR paces            none (would burst)
   MSS               negotiated + PMTU discovery           negotiated (Doc 15)
```

The instructive gap is **PRR** (Proportional Rate Reduction, RFC 6937), Linux's modern replacement for the
inflate/deflate dance of classic fast recovery: instead of inflating `cwnd` by dup-ACKs and snapping to
`ssthresh`, PRR reduces the sending rate *smoothly* and proportionally during recovery, ending exactly at
`ssthresh` with far less burstiness. Our inflate-then-deflate (§6) is the RFC 5681 classic; PRR is the
production refinement.

## J. Security — ACK division, optimistic ACKing, congestion attacks

Congestion control trusts ACKs, and a lying or forged ACK stream can manipulate `cwnd`:

- **ACK division (Savage et al., 1999).** A malicious *receiver* sends *many* ACKs each acking a *fraction*
  of a segment. A naive sender grows `cwnd` per-ACK, so the receiver tricks it into growing `cwnd` much
  faster than one MSS/RTT — stealing bandwidth and potentially congesting the network. Defense:
  **Appropriate Byte Counting** (RFC 3465) — grow `cwnd` by *bytes acknowledged*, not by number of ACKs.
- **Optimistic ACKing.** A receiver ACKs data it *hasn't received yet*, fooling the sender into inflating
  `cwnd` and sending faster than safe (and breaking reliability). Hard to fully defend; mitigations include
  skipping random sequence ranges the receiver must echo, or cumulative-ACK plausibility checks.
- **Forged dup-ACKs / RST.** An off-path attacker who guesses the connection can inject dup-ACKs to trigger
  spurious fast retransmits and `cwnd` halving (a throughput DoS), or an in-window RST to kill the flow.
  RFC 5961 validation + random ISNs raise the bar.
- **Low-rate "shrew" DoS (Doc 6 §J).** Bursts timed to the RTO force repeated timeouts → `cwnd` collapse,
  starving a victim flow with low average attacker rate.

The theme: `cwnd` is a quantity an adversary on either end (lying receiver) or off-path (injected ACKs)
would love to move, so production stacks count bytes (not ACKs), validate ACK plausibility, and rate-limit
reactions.

## K. Performance — BDP, fairness, bufferbloat, incast

- **The BDP target.** To fill a path, `cwnd` must reach the bandwidth-delay product (Doc 8 §E). Reno's
  linear growth takes `~BDP/MSS` RTTs to recover after each loss — on a 10 Gbit/s × 100 ms path (BDP
  ≈ 83k segments) that's *minutes* per recovery, which is why Reno can't fill long-fat networks and CUBIC/BBR
  exist (§G).
- **RTT fairness.** Reno's `1/RTT` throughput means short-RTT flows dominate a shared link — a 10 ms flow
  gets ~10× a 100 ms flow's share. CUBIC's time-based growth largely fixes this.
- **Bufferbloat.** Loss-based control *needs* a queue to fill (it probes until drop), so over-large router
  buffers let the queue grow huge before dropping — inflating RTT for everyone. The fix isn't TCP alone:
  AQM (CoDel, RED) drops/marks early, and BBR keeps queues short by design.
- **TCP incast.** In datacenters, many senders to one receiver (e.g. a sharded query) can synchronize
  losses and all time out together, collapsing throughput for ~RTO — a known datacenter pathology fixed
  with smaller RTOs, ECN/DCTCP, and reduced fan-in.
- **Our cost** is trivial (four integers, three branches per ACK); the *limitation* is that Reno + a flat
  small window + no pacing wouldn't fill a fast path — by design for a teaching echo server.

## L. Extended FAQ

1. **What does congestion control protect?** The *network* (router queues), vs flow control protecting the
   *receiver*.
2. **What is the effective send limit?** `min(SND.WND, cwnd) − FlightSize`.
3. **What is `cwnd`?** The sender's inferred estimate of how much the network can hold.
4. **What is `ssthresh`?** The boundary between slow start (below) and congestion avoidance (above).
5. **Why is slow start exponential?** +1 MSS per ACK, and ~cwnd/MSS ACKs per RTT → doubling per RTT.
6. **Why is congestion avoidance linear?** +MSS²/cwnd per ACK sums to ~+1 MSS per RTT.
7. **What is AIMD?** Additive Increase, Multiplicative Decrease — the rule that converges to fair, full
   sharing (§B).
8. **The two loss signals?** 3 dup-ACKs (mild → fast recovery, halve) vs RTO (strong → collapse to 1 MSS).
9. **Why react differently to them?** Dup-ACKs mean data still flows; silence means the pipe may be
   broken/badly congested.
10. **What is fast retransmit?** Resend on the 3rd dup-ACK without waiting for the RTO.
11. **What is fast recovery?** Halve `cwnd` (to `ssthresh`+3·MSS) instead of collapsing to 1, inflate per
    dup-ACK, deflate on a new ACK.
12. **Why `+3·MSS` on entering recovery?** Three dup-ACKs prove three segments left the network.
13. **Why does `on_timeout` set `cwnd = 1 MSS`?** A timeout is the strong signal; restart slow start.
14. **Where does the RTO get wired?** `on_tick` when `retx.due` is non-empty → `on_timeout`.
15. **Does congestion control bind on the echo server?** No — no backlog; it binds with Doc 11's send
    buffer (§10).
16. **What is the TCP sawtooth?** Linear climb + halve-on-loss in congestion avoidance (§D).
17. **What's the throughput formula?** ≈ `MSS/(RTT·√p)` — inverse RTT, inverse √(loss) (§D).
18. **Why does Reno struggle on long-fat networks?** Linear growth is too slow to refill a huge BDP after
    loss (§K); CUBIC fixes it.
19. **What is NewReno?** Stays in recovery handling multiple losses via partial ACKs (§E).
20. **What is SACK-based recovery?** Retransmit exactly the SACK-named holes, pipe-driven (RFC 6675;
    Doc 18).
21. **What is ECN?** Routers *mark* congestion instead of dropping; sender halves without a loss (§F).
22. **What is CUBIC?** Cubic, RTT-independent growth — Linux's default (§G).
23. **What is BBR?** Models bandwidth + RTT, paces to the BDP, ignores loss as the signal (§G).
24. **What is ACK division?** A receiver fragmenting ACKs to over-grow `cwnd`; fixed by counting bytes (§J).
25. **What was the 1986 collapse?** Throughput fell 1000× from retransmission feedback; Jacobson's 1988
    paper fixed it (§A).

## M. Anki starter deck

```text
Q: Congestion control protects what (vs flow control)?  A: the network's queues (vs the receiver's buffer).
Q: Effective send limit?  A: min(SND.WND, cwnd) − FlightSize.
Q: cwnd vs ssthresh?  A: the network estimate; the slow-start/congestion-avoidance boundary.
Q: Why is "+1 MSS per ACK" exponential?  A: ~cwnd/MSS ACKs per RTT → cwnd doubles per RTT.
Q: Why is "+MSS²/cwnd per ACK" linear?  A: it sums to ~+1 MSS per RTT.
Q: What does AIMD stand for / converge to?  A: Additive Increase Multiplicative Decrease → fair + full.
Q: Two loss signals and responses?  A: 3 dup-ACKs → halve (fast recovery); RTO → cwnd=1 (slow start).
Q: Fast retransmit?  A: resend on the 3rd dup-ACK without waiting for the RTO.
Q: On entering fast recovery, cwnd = ?  A: ssthresh + 3·MSS (3 segments left the net).
Q: On a new ACK after recovery, cwnd = ?  A: ssthresh (deflate).
Q: On RTO, cwnd = ?  A: 1·MSS, ssthresh = FlightSize/2; restart slow start.
Q: The TCP sawtooth is?  A: linear climb + halve-on-loss in congestion avoidance.
Q: Reno throughput formula?  A: ≈ MSS/(RTT·√p) — inverse RTT, inverse √loss.
Q: Why does Reno underfill long-fat networks?  A: linear growth too slow to refill a big BDP (CUBIC fixes).
Q: What is ECN?  A: routers mark (not drop) congestion; sender halves losslessly.
Q: What did Jacobson 1988 add?  A: variance RTO, slow start, congestion avoidance — ending 1986 collapse.
```

## N. Glossary

- **Congestion control** — sender-side limiting to what the *network* can carry.
- **`cwnd` (congestion window)** — the sender's inferred network-capacity estimate, in bytes.
- **`ssthresh` (slow-start threshold)** — the cwnd boundary between slow start and congestion avoidance.
- **Slow start** — exponential `cwnd` growth (+1 MSS/ACK) to find capacity fast.
- **Congestion avoidance** — linear `cwnd` growth (+1 MSS/RTT) near capacity.
- **AIMD** — Additive Increase, Multiplicative Decrease; the fair/efficient control rule.
- **Fast retransmit** — resend on the 3rd duplicate ACK without an RTO.
- **Fast recovery** — halve `cwnd` (not collapse) and keep sending during recovery.
- **The sawtooth** — the cwnd-vs-time shape of AIMD.
- **NewReno / SACK recovery** — improved multi-loss recovery (RFC 6582 / 6675).
- **ECN** — Explicit Congestion Notification: mark instead of drop (RFC 3168).
- **CUBIC / BBR** — modern congestion-control algorithms (loss-cubic / bandwidth-model).
- **Congestion collapse** — the 1986 pathology of throughput destroyed by retransmission feedback.

## O. Reference tables

**O.1 — The two windows / two ceilings**

```text
   window     protects     grows on        shrinks on       day
   ────────   ──────────   ─────────────   ──────────────   ───
   SND.WND    receiver     receiver reads  receiver fills    8
   cwnd       network      ACKs (AIMD)     loss (÷2 or →1)   10
   effective = min(SND.WND, cwnd) − FlightSize
```

**O.2 — Growth and loss responses (RFC 5681)**

```text
   event             cwnd change                      ssthresh change
   ───────────────   ──────────────────────────────   ────────────────────────
   ACK, slow start   += MSS                            —
   ACK, cong. avoid  += MSS²/cwnd (≈ +1 MSS/RTT)       —
   3 dup-ACKs        = ssthresh + 3·MSS                = max(FlightSize/2, 2·MSS)
   extra dup-ACK     += MSS                            —
   new ACK (recover) = ssthresh                        —
   RTO timeout       = 1·MSS                           = max(FlightSize/2, 2·MSS)
```

**O.3 — Algorithm lineage**

```text
   algorithm   signal           growth            our status
   ─────────   ──────────────   ───────────────   ──────────────────
   Reno        loss             linear            implemented (RFC 5681)
   NewReno     loss             linear + partial  exercise E2
   SACK/6675   loss + SACK      pipe-driven       Doc 18 blocks; E5
   CUBIC       loss             cubic(time)       exercise E4
   BBR         bandwidth+RTT    paced to BDP      —
```

> Re-type the `CongestionControl` state machine from this chapter with the book closed, then `cargo test`.
> You now hold TCP's three control loops: reliability (Doc 6), flow control (Doc 8), and congestion control
> (Doc 10) — the trio that turns IP's best-effort packets into a stream you can trust on a shared network,
> and the algorithm that keeps the internet from melting.
