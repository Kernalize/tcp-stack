# Day 10 — TCP, Part 8: Congestion Control (Slow Start, AIMD, Fast Recovery)

> Goal: keep the sender from overwhelming the **network**. Flow control (Day 8) bounds the sender
> by the receiver's buffer; congestion control bounds it by the *path* — the routers and links in
> between, which the receiver's window knows nothing about. The sender carries a second window,
> `cwnd`, that grows while ACKs flow and collapses on loss. That feedback loop — AIMD — is one of
> the most consequential control systems ever deployed: it's why the internet doesn't melt down.

**Contents**
1. The mental model: two ceilings, take the lower
2. `cwnd` and `ssthresh`
3. Slow start — find the ceiling fast
4. Congestion avoidance — probe it gently (AIMD)
5. Two faces of loss: duplicate ACKs vs a timeout
6. Fast retransmit & fast recovery
7. Worked numbers (what the tests assert)
8. The code, walked — module + wiring
9. The honest caveat: an echo server can't stress this
10. Verification
11. Why this, not that
12. Rebuild it yourself — checklist + exercises
13. What's next

---

## 1. The mental model: two ceilings, take the lower

The receiver's window (`SND.WND`) says "my buffer can hold this much." But between us and the
receiver sit queues in routers with finite capacity. If everyone sends as fast as their receiver
allows, those queues overflow, packets drop, everyone retransmits, queues overflow harder — a
**congestion collapse**. The internet actually suffered this in 1986; Van Jacobson's 1988 fix is
what we implement here.

The sender keeps a private estimate of the network's capacity, the **congestion window** `cwnd`,
and never lets in-flight data exceed:

```text
effective window = min(SND.WND, cwnd) − FlightSize
```

`SND.WND` protects the receiver; `cwnd` protects the network. Whichever is smaller wins. In our
stack that's `Connection::usable_window()`: `min(self.send.wnd, self.cong.window()) − flight`.

---

## 2. `cwnd` and `ssthresh`

Two variables drive everything (`src/congestion.rs`):

- **`cwnd`** — the congestion window in bytes. Starts at 1 MSS (so slow start's ramp is visible;
  modern stacks per RFC 6928 start at 10 MSS).
- **`ssthresh`** — the slow-start threshold. It's the boundary between two growth regimes:
  `cwnd < ssthresh` → **slow start** (exponential); `cwnd ≥ ssthresh` → **congestion avoidance**
  (linear). It starts "infinite" (65535) and is pulled down to roughly half the in-flight data
  every time loss is detected — that's the "multiplicative decrease" half of AIMD.

`MSS` (maximum segment size) is the unit of growth. We don't negotiate the MSS option, so we
assume a typical 1460-byte Ethernet payload; a real stack learns it from the peer's SYN.

---

## 3. Slow start — find the ceiling fast

At connection start (or after a timeout) we have *no idea* how much the network will bear, so we
probe **exponentially**: every ACK bumps `cwnd` by one MSS.

```rust
if self.cwnd < self.ssthresh {
    self.cwnd = self.cwnd.saturating_add(MSS);   // +1 MSS per ACK
}
```

Why is "+1 MSS per ACK" exponential? Because in one RTT you receive roughly `cwnd / MSS` ACKs
(one per segment in flight), so `cwnd` *doubles* each round trip: 1 → 2 → 4 → 8 MSS… It's
"slow" only relative to the original "blast everything" — it actually ramps up very quickly,
until it hits `ssthresh` or loss.

---

## 4. Congestion avoidance — probe it gently (AIMD)

Once `cwnd` reaches `ssthresh`, we're near the estimated capacity, so we switch to **linear**
growth — roughly +1 MSS per *RTT* instead of per ACK:

```rust
else {
    self.cwnd = self.cwnd.saturating_add((MSS * MSS / self.cwnd).max(1));  // +MSS²/cwnd per ACK
}
```

Summed over the `cwnd / MSS` ACKs in one RTT, `MSS²/cwnd` adds up to about one MSS. This is the
**additive increase** of AIMD. Paired with halving on loss (multiplicative decrease), it produces
the famous TCP "sawtooth": climb gently, halve on loss, climb again — provably stable and fair
when many flows share a link.

---

## 5. Two faces of loss: duplicate ACKs vs a timeout

TCP infers loss two ways, and they mean different things:

- **Three duplicate ACKs** — the receiver got segments *after* a gap (it keeps re-acking the byte
  it's missing; those dup-ACKs are exactly what Day 9 made us emit). Data is still flowing, so the
  network isn't badly congested → a *mild* signal. Response: **fast retransmit + fast recovery**.
- **Retransmission timeout (RTO)** — silence; not even dup-ACKs came back. The pipe may be
  severely congested or broken → a *strong* signal. Response: collapse to 1 MSS and restart slow
  start.

```rust
pub fn on_timeout(&mut self, flight_size: u32) {
    self.ssthresh = (flight_size / 2).max(2 * MSS);   // remember ~half as the new threshold
    self.cwnd = MSS;                                  // back to square one
    ...
}
```

We wire this where the RTO actually fires — in `Connection::on_tick`, when `retx.due()` returns
something to resend.

---

## 6. Fast retransmit & fast recovery

On the **third** duplicate ACK we don't wait for the RTO — we resend the missing segment at once
(fast retransmit) and halve our window rather than crashing it to 1 (fast recovery):

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

The `+3·MSS` and per-dup inflation model the fact that each dup-ACK proves a segment *left* the
network (the receiver got it), so we may send a little more. When a *new* ACK finally arrives, we
exit recovery and **deflate** `cwnd` back to `ssthresh`:

```rust
pub fn on_ack(&mut self, acked: u32) {
    self.dup_acks = 0;
    if self.in_recovery { self.in_recovery = false; self.cwnd = self.ssthresh; return; }
    ...
}
```

On our side, `Connection` detects a duplicate ACK (acks no new data, `th.ack == SND.UNA`, data
still outstanding, empty payload) and, when `on_dup_ack` returns `true`, resends the oldest
unacked segment via `RetxQueue::fast_retransmit` — which also bumps that segment's retry count so
Karn's algorithm (Day 6) correctly refuses to time it.

---

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
`cwnd == ssthresh` we're in congestion avoidance, and one ACK adds only `MSS²/cwnd ≈ 292` bytes —
far less than a full MSS (`congestion_avoidance_grows_sub_linearly`). A timeout
(`timeout_collapses_to_one_mss_and_slow_start`): `cwnd → 1·MSS`, and the next ACK adds a full MSS
again (slow start resumed).

---

## 8. The code, walked — module + wiring

| Piece | Role |
|---|---|
| `src/congestion.rs` | `CongestionControl`: `on_ack` / `on_dup_ack` / `on_timeout` / `window()` — the RFC 5681 state machine |
| `Connection.cong` | one per connection; default = 1 MSS cwnd, ∞ ssthresh |
| `usable_window()` | now `min(SND.WND, cwnd) − FlightSize` |
| `on_packet_at` ACK branch | new-data ACK → `on_ack(grow)`; duplicate ACK → `on_dup_ack` → maybe fast-retransmit |
| `on_tick` | RTO fired (`retx.due` non-empty) → `on_timeout` |
| `RetxQueue::fast_retransmit` | resend the oldest unacked segment, reset its timer, count the retry |

The connection now distinguishes three kinds of ACK in ESTABLISHED: one that **advances**
`SND.UNA` (grow cwnd), a **duplicate** (no new data, data outstanding → count toward fast
retransmit), and everything else (ignored). That three-way split is the sender side of congestion
control.

---

## 9. The honest caveat: an echo server can't stress this

Congestion control governs a sender with a *backlog* — data queued faster than it can be sent. Our
stack is an echo server: it sends only a tiny response to each received segment and then has
nothing queued, so `FlightSize` stays near zero and `min(SND.WND, cwnd)` never actually clamps it.
`cwnd` will sit there growing harmlessly.

So why build it now? Because the **algorithm** is the lesson, and it's fully exercised by unit
tests that drive the state machine directly. The piece that would make it *bind* in practice is a
real **send buffer** and an application that writes in bulk — which is precisely the socket API of
Day 11. Building the controller first means Day 11's sender has a correct window to obey on day
one. (This is the same pattern as the RTT estimator in Day 6: a clean, tested module wired into
the connection ahead of the load that will exercise it.)

---

## 10. Verification

`cargo test` → **60 green**. Congestion coverage:

- `congestion::*` (7) — slow-start increment, the 3-dup-ACK fast-retransmit trigger and its
  `cwnd`/`ssthresh` math, per-dup inflation, deflation on a new ACK, sub-linear congestion
  avoidance, and timeout collapse + slow-start resumption.
- `tcp::three_dup_acks_fast_retransmit_the_oldest_segment` — end-to-end: we echo "hi", then three
  duplicate ACKs arrive; the first two do nothing, the third returns the echo bytes for immediate
  resend.

Live, you can't easily *see* `cwnd` bind on the echo path (§9). The honest demonstration is the
unit tests plus, once Day 11's bulk sender exists, an `iperf3`-style transfer under
`tc netem loss 5%` showing the sawtooth — the Manual's Week 8 milestone.

---

## 11. Why this, not that

| Decision | We chose | Real TCP |
|---|---|---|
| Algorithm | RFC 5681 Reno (AIMD + fast recovery) | CUBIC (Linux default), BBR (model-based), etc. |
| Initial cwnd | 1 MSS (visible ramp) | 10 MSS (RFC 6928) |
| MSS | fixed 1460 | negotiated via the MSS option in the SYN |
| Loss signal | 3 dup-ACKs + RTO | + ECN (explicit congestion notification), RACK-TLP |
| Recovery | basic fast recovery | NewReno / SACK-based recovery (per-segment) |
| Where it binds | nowhere yet (echo server) | gates every send from a real send buffer |

---

## 12. Rebuild it yourself — checklist + exercises

From a blank file:
1. The two ceilings and why the sender takes `min(SND.WND, cwnd)`.
2. Why "+1 MSS per ACK" is exponential but "+MSS²/cwnd per ACK" is linear (count the ACKs per RTT).
3. The two loss signals and their very different responses (halve vs collapse-to-1).
4. The fast-retransmit/fast-recovery sequence: 3 dup-ACKs → halve ssthresh, inflate cwnd,
   retransmit → deflate on the next new ACK.

**Exercises:**
- **E1.** Add a real send buffer + bulk write so `usable_window()` actually clamps transmission,
  then watch `cwnd` sawtooth under `tc netem loss`. (Pairs with Day 11.)
- **E2.** Implement **NewReno**: stay in recovery until *all* data outstanding at the time of loss
  is acked, retransmitting on each partial ACK.
- **E3.** Add **ECN**: react to a congestion mark in the IP/TCP headers as a (gentler) loss signal,
  halving without a retransmit.
- **E4.** Swap Reno for **CUBIC**'s cubic growth function and compare ramp-up on a high-bandwidth,
  high-latency path.

---

## 13. What's next

We now have every internal mechanism of TCP: handshake, reliable in-order transfer, retransmission
with an adaptive RTO, teardown, flow control, reassembly, and congestion control. What's missing is
the **interface**: a socket-style API (`TcpListener` / `TcpStream`) with a send buffer and a
multi-connection event loop, so a real application — a tiny HTTP server — can drive the stack
instead of a hard-coded echo. That API is also what finally gives congestion control something to
push against. That's Day 11, the last build day.

> Re-type the `CongestionControl` state machine from this chapter with the book closed, then
> `cargo test`. You now hold TCP's three control loops: reliability (Day 6), flow control (Day 8),
> and congestion control (Day 10) — the trio that turns IP's best-effort packets into a stream you
> can trust on a shared network.
