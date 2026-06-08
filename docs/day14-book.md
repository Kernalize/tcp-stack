# Day 14 — TCP, Part 12: Zero-Window Probes (the Persist Timer)

> Goal: fix the one deadlock that flow control quietly created. Day 8 taught the sender to obey the
> receiver's advertised window: when the peer says "my window is 0," we stop. Correct — but
> incomplete. The signal that the window has *re-opened* travels in a pure ACK, and pure ACKs are
> not retransmitted. Lose that one ACK and both sides wait forever: the receiver thinks it told us
> to resume, the sender is still holding. TCP's escape is the **persist timer** (RFC 9293 §3.8.6.1):
> when the window is shut and we have data to send, periodically poke a single byte into the closed
> window, forcing the peer to re-announce its current window. This chapter implements it — and, on
> the way, tightens the duplicate-ACK rule so a window update can never be mistaken for packet loss.

**Contents**
1. The mental model: a silence that kills
2. Why this can't be fixed by retransmitting data
3. The persist timer: probe the closed window
4. What the probe is, exactly
5. Letting the retransmission queue do the repeats
6. The companion fix: a window update is not a duplicate ACK
7. The Rust: one field, one branch in `on_tick`
8. Worked example: shut, probe, reopen
9. The code, walked
10. Verification
11. Why this, not that
12. Rebuild it yourself — checklist + exercises
13. What the next day adds

---

## 1. The mental model: a silence that kills

Flow control is a promise: "I, the receiver, will accept up to `RCV.WND` more bytes." When the
receiver's buffer fills, it advertises `window = 0`, and a well-behaved sender (ours, since Day 8)
stops dead — `usable_window()` is 0, so `poll_transmit` emits nothing. Later the application drains
the buffer and the receiver sends a fresh ACK: "window = 4000, you may resume." That update is the
*only* thing that unblocks the sender.

Now notice what kind of segment that update is: a **pure ACK** — no data, no SYN, no FIN. It consumes
no sequence number, so the receiver never queues it for retransmission. If the network drops it:

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
download) is one dropped ACK away from a permanent hang. TCP must not depend on an unacknowledged
segment for liveness.

## 2. Why this can't be fixed by retransmitting data

Your first instinct (mine too) is "just let the retransmission timer resend something." But there is
*nothing in the retransmission queue*: the sender stopped before putting any of the blocked bytes on
the wire, precisely because the window was 0. `FlightSize == 0`. The retransmission machinery from
Day 6/12 only resends what was already sent; here, by construction, nothing was. So liveness needs a
*new* action: deliberately send something into a window we've been told is closed.

## 3. The persist timer: probe the closed window

The rule (RFC 9293 §3.8.6.1):

> When the send window is zero and the sending TCP has data to send, it sends a small **probe**
> segment periodically (the *persist timer*) so that the receiver is forced to re-advertise its
> window. The probe carries one byte of new data; the timer backs off exponentially.

The probe's job is not to deliver data — it is to *provoke a reply*. The receiver, on getting a byte
it cannot accept (its window is 0), must still send an ACK, and that ACK carries its **current**
window. If the window is still 0, we learn nothing new and probe again later. If it has re-opened,
the ACK tells us and the stall is broken. Either way the connection cannot silently die: we keep
asking until we get an answer.

## 4. What the probe is, exactly

A zero-window probe is **one byte of real, sequence-consuming data**, sent at `SND.NXT`:

- We take the first byte of the blocked send buffer and send it in a 1-byte segment.
- It advances `SND.NXT` by 1 and goes into the retransmission queue like any other data — so it is
  not lost from our bookkeeping even if the receiver discards it.
- The receiver either accepts it (window had quietly re-opened) and ACKs *past* it, or rejects it
  (window genuinely 0) and re-ACKs `RCV.NXT` *without* advancing — but it ACKs, which is the point.

We only probe when **`FlightSize == 0`** (nothing already in flight). If data *were* in flight, the
ordinary retransmission timer would already be poking the peer; the persist timer exists exactly for
the case where the queue is empty and there is no other source of liveness.

## 5. Letting the retransmission queue do the repeats

A subtle, satisfying simplification: the persist timer only needs to fire **once**. After the first
probe is sent, `FlightSize` becomes 1 — there is now an unacknowledged segment in the queue. From
that moment, the **ordinary RTO retransmission** (Day 6) resends that same one-byte segment on its
own timer, with the usual exponential backoff. That *is* the persist repeat. So:

- persist timer → sends the **first** probe (because the queue was empty);
- RTO retransmission → sends every **subsequent** probe (because now the queue is not).

We disarm the persist timer the instant a probe is outstanding (`FlightSize > 0`), and re-arm only
if we somehow return to "window 0, data pending, nothing in flight." This reuses machinery instead
of duplicating a backoff loop, and it keeps the probe spacing consistent with the connection's RTO.

## 6. The companion fix: a window update is not a duplicate ACK

Adding zero-window handling exposes a latent bug in the Day 10 duplicate-ACK logic. RFC 5681 §2
defines a duplicate ACK by **four** conditions, all of which must hold:

1. the ACK number equals `SND.UNA` (acknowledges no new data),
2. the segment carries no data,
3. `SND.UNA < SND.NXT` (data is outstanding),
4. **the advertised window is the same as in the previous ACK.**

We had been checking only the first three. Condition 4 matters now because two perfectly normal
events produce an ACK with `ack == SND.UNA` and no data:

- a **window update** (receiver re-advertises a *different* window), and
- a **zero-window probe response** (receiver re-ACKs with window 0).

Without condition 4, three of these in a row would trip *fast retransmit* and needlessly halve the
congestion window — treating a flow-control event as packet loss. So we now record the previous
window and require `th.window == prev_wnd` **and** `th.window != 0` before counting a duplicate ACK.
A changed window is an update; a zero window is the receiver being full; neither is congestion.

## 7. The Rust: one field, one branch in `on_tick`

- A `persist_ms: u64` field on `Connection` — the absolute time the next probe is due, `0` when
  disarmed. Initialized `0` in both constructors.
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
            self.retx.record(self.send.nxt, probe.clone(), now_ms);
            out.push(probe);
        }
        self.persist_ms = 0; // disarm; the retx queue now repeats the probe
    }
} else {
    self.persist_ms = 0; // window open, nothing to send, or a probe already in flight
}
```

The dup-ACK fix is the two extra `&&` clauses in `on_packet_at`. That is the whole feature.

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

Had we *not* probed, the lost `window=1000` ACK at some later point would have left both ends mute.
The probe guarantees we ask again.

## 9. The code, walked

All in `src/tcp.rs`:

- **Struct / constructors**: `persist_ms: u64`, initialized `0`.
- **`on_packet_at`** (ESTABLISHED): capture `prev_wnd` before overwriting `send.wnd`; add
  `th.window == prev_wnd && th.window != 0` to the duplicate-ACK condition.
- **`on_tick`**: the persist branch above. It appends the probe to the same `Vec` the RTO
  retransmissions go into, so the event loop sends it with no special casing.

`main.rs` is unchanged — it already calls `on_tick` every loop and sends whatever it returns.

## 10. Verification

`cargo test` adds three tests (72 total):

- `zero_window_arms_then_fires_persist_probe` — a shut window with pending data arms the timer on
  the first tick and emits exactly one 1-byte probe at `SND.NXT` after the RTO.
- `persist_probe_recovers_when_window_reopens` — the peer's reopening ACK acknowledges the probe and
  the rest of the data flows: the deadlock is broken end to end.
- `window_updates_and_zero_windows_are_not_duplicate_acks` — three window-update ACKs and three
  zero-window ACKs all return `None` (no fast retransmit), proving condition 4 of the dup-ACK rule.

## 11. Why this, not that

| Decision | Alternative | Why |
|---|---|---|
| Probe with 1 byte of real data | Send a zero-length "window probe" segment | A data byte is unambiguously sequence-consuming and forces an ACK; some stacks send a garbage byte below `SND.UNA`, but a real next byte is simplest and never wasted. |
| Persist fires once; RTO does the repeats | A separate persist backoff loop | Reuses the existing retransmission timer/backoff; one fewer timer to get wrong, and probe spacing tracks the RTO automatically. |
| Probe only when `FlightSize == 0` | Probe whenever the window is 0 | If data is already in flight, the RTO is already poking the peer — a persist probe would be redundant and could blast the closed window byte-by-byte. |
| Exclude window-updates *and* zero windows from dup-ACK | Only add RFC 5681 condition 4 (`window unchanged`) | Condition 4 alone still miscounts steady zero-window re-acks (window unchanged at 0) as dups; excluding `window == 0` too keeps a flow-control stall from ever looking like loss. |

## 12. Rebuild it yourself — checklist + exercises

**Blank-file checklist:**
- [ ] Why does a lost window-update ACK deadlock the connection? Why can't the RTO save it?
- [ ] What is a zero-window probe, and what response does it force from the receiver?
- [ ] Why does the persist timer only need to fire once?
- [ ] State all four RFC 5681 duplicate-ACK conditions. Which two did we add, and why?
- [ ] Why probe only when `FlightSize == 0`?

**Exercises:**
- **E1.** Add an explicit persist backoff cap and a connection-abort after ~R2 unanswered probes
  (RFC 9293 §3.8.6.1 references the user timeout). Test it.
- **E2.** Implement Silly Window Syndrome avoidance on the *receiver*: don't advertise a re-opened
  window until it grows by at least one MSS (or ½ the buffer), so probes don't chase 1-byte windows.
  (RFC 9293 §3.8.6.2.)
- **E3.** Make the probe re-send the *same* byte explicitly via a dedicated persist path rather than
  leaning on the RTO queue, and compare the two designs' complexity.
- **E4.** Write a test where the window reopens but the probe byte is *not* accepted (peer ACKs
  `SND.UNA` with a non-zero window); confirm `poll_transmit` then sends from the buffer correctly.

## 13. What the next day adds

Day 15 begins the **TCP options** era. So far every segment we build has a bare 20-byte header; we
have ignored the options field on the way in and never written one on the way out. Day 15 adds the
machinery to *parse* and *emit* options, and uses it for the most fundamental one: **MSS
negotiation** (RFC 9293 §3.7.1). We will read the peer's Maximum Segment Size from its SYN, advertise
our own, and segment outgoing data to the negotiated value instead of the hardcoded 1460. That option
framework is the foundation the next several days (timestamps, window scaling, SACK) all build on.

> Re-type the persist branch and the dup-ACK condition with the book closed, then `cargo test`. Your
> stack can no longer be killed by a single dropped ACK — the last silent deadlock is gone.
