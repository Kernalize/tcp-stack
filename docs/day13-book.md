# Day 13 — TCP, Part 11: Nagle's Algorithm (and the `TCP_NODELAY` Escape Hatch)

> Goal: stop a chatty application from flooding the link with runt packets. If a program writes one
> byte at a time — a classic telnet session, a game sending keystrokes — a naive stack puts each
> byte in its own segment: 40 bytes of IP+TCP header to carry 1 byte of data, a 4000% overhead.
> Nagle's algorithm (RFC 896, 1984) fixes this with a single rule that needs no new packet type and
> no negotiation: *don't send a small segment while you're still waiting to hear about the last one.*
> This chapter implements it in three lines of `poll_transmit`, adds the `TCP_NODELAY` switch that
> turns it off, and explains the infamous Nagle-vs-delayed-ACK interaction.

**Contents**
1. The mental model: the small-packet (tinygram) problem
2. The rule, in one sentence
3. The exact condition — four cases
4. `TCP_NODELAY`: when coalescing is wrong
5. The famous bad interaction: Nagle + delayed ACK
6. The Rust: one field, one setter, a three-line guard
7. Worked example: five bytes, then three
8. The code, walked
9. Verification
10. Why this, not that
11. Rebuild it yourself — checklist + exercises
12. What the next day adds

---

## 1. The mental model: the small-packet (tinygram) problem

A TCP segment costs 40 bytes of header before it carries any payload (20 IP + 20 TCP). Send one
data byte per segment and you are paying 40:1 overhead — and worse, you are putting 41-byte packets
on the wire as fast as the application can call `write`, which on a congested 1984 ARPANET (and on a
congested 2026 Wi-Fi link) is exactly the wrong thing to do. John Nagle's insight: a sender that has
**unacknowledged data already in flight** has *time to wait*. It can accumulate the application's
next few small writes into one larger segment, because it has to wait for an ACK anyway. The result
is self-clocking: on a fast link the ACK comes back quickly and you send small often; on a slow or
loaded link the ACK is delayed and you naturally coalesce more. The algorithm needs no timer, no
threshold tuning, and no new wire format — just a decision in the send path.

```text
  Without Nagle (app writes "h","e","l","l","o"):
    seg[seq=1 "h"]  seg[seq=2 "e"]  seg[seq=3 "l"] ...   five 41-byte packets

  With Nagle (one segment in flight at a time):
    seg[seq=1 "h"]  →  (wait for ACK; buffer "ello")  →  seg[seq=2 "ello"]   two packets
```

## 2. The rule, in one sentence

> **While any sent data is still unacknowledged, hold a *small* (sub-MSS) segment in the buffer
> until either that data is acknowledged or a full-sized segment can be sent.**

"Small" means smaller than the Maximum Segment Size (a full segment is always worth sending — it is
maximally efficient already). "Unacknowledged data in flight" is exactly our `FlightSize =
SND.NXT − SND.UNA > 0`. Put together: a runt is only held when sending it now would add a *second*
small packet to a network that has not yet confirmed the first.

## 3. The exact condition — four cases

`poll_transmit` already computes `n`, the number of bytes it would put in the next segment
(`min(usable_window, MSS, send_buf.len())`). Nagle adds one guard before sending that segment:

| `n == MSS`? | data in flight (`FlightSize > 0`)? | `TCP_NODELAY`? | Send now? |
|:---:|:---:|:---:|:---:|
| full segment | — | — | **yes** — full segments are never held |
| small | no (`FlightSize == 0`) | — | **yes** — first packet, nothing to wait for |
| small | yes | off (Nagle on) | **no** — hold until ack or a full segment |
| small | yes | on | **yes** — `TCP_NODELAY` overrides |

Only the third row holds. In code that is a single early `break` out of the drain loop:

```rust
if self.nagle && n < mss && self.flight_size() > 0 {
    break; // hold the sub-MSS tail; a later ACK re-drives poll_transmit and it flushes
}
```

The held bytes are not lost — they stay in `send_buf`. The event loop calls `poll_transmit` again on
the very next received packet, and when the ACK that clears the in-flight data arrives, `FlightSize`
drops to 0 and the same bytes sail through.

## 4. `TCP_NODELAY`: when coalescing is wrong

Nagle optimizes *throughput efficiency* at the cost of *latency*. For bulk transfer that is a pure
win. For request/response and interactive traffic it can hurt: an SSH keystroke, a game input, or a
small RPC wants to leave **now**, not wait for the previous segment's ACK. So TCP exposes a per-
socket switch, `TCP_NODELAY`, that disables Nagle. We model it as a single boolean — `self.nagle`,
default `true` — flipped by `set_nodelay(true)`:

```rust
pub fn set_nodelay(&mut self, nodelay: bool) {
    self.nagle = !nodelay;
}
```

Our echo/HTTP server leaves Nagle on (its responses are either a single sub-MSS write sent with
nothing in flight, or bulk data in full segments — neither is held). A latency-sensitive app built
on this stack would call `set_nodelay(true)`.

## 5. The famous bad interaction: Nagle + delayed ACK

This is the one thing every networking engineer eventually gets burned by, so it is worth knowing
even though our receiver does not (yet) delay ACKs. **Delayed ACK** (RFC 1122) lets a receiver wait
up to ~200 ms before acknowledging, hoping to piggyback the ACK on reply data or to ack two segments
at once. Now compose it with Nagle on the sender:

```text
  sender (Nagle on)                 receiver (delayed ACK)
    write small "req-part-1"  →     got it… I'll delay the ACK (waiting for more / for reply data)
    write small "req-part-2"        Nagle: data in flight, holds it  →  nothing on the wire
       ...both sides wait...
    receiver's 200 ms delayed-ACK timer finally fires  →  ACK
    sender: FlightSize=0 now → sends "req-part-2"
```

A ~200 ms stall on every request that the application split into two small writes — for *no reason
but the two heuristics colliding*. The fixes: send the whole request in one `write` (so it is not
two tinygrams), or set `TCP_NODELAY`. This is why so much advice says "buffer your request fully,
then write once" and why latency-sensitive protocols disable Nagle. We document it here; if you add
delayed ACK later (an exercise), come back and re-read this.

## 6. The Rust: one field, one setter, a three-line guard

The whole feature is:

- a `nagle: bool` field on `Connection`, initialized `true` in both constructors;
- `set_nodelay(&mut self, nodelay)` (with `#[allow(dead_code)]` — the server never calls it, tests
  do);
- the three-line guard in `poll_transmit`.

No new packet type, no header change, no extra state machine. That economy is the point of Nagle: it
is a *scheduling* decision layered on top of machinery you already have (`flight_size`, the send
buffer, the MSS chop). It is also the first time our sender deliberately declines to send something
the window would allow — a small but real shift from "send whatever fits" to "send what is wise."

## 7. Worked example: five bytes, then three

ESTABLISHED, ISS 0 so `SND.NXT = 1`, peer window 0xffff, `cwnd = 1·MSS`, Nagle on.

```text
  app write "hello" (5B)
  poll_transmit:
    n = min(usable=1460, MSS=1460, 5) = 5
    FlightSize = 0  → guard false → SEND seg[seq=1, 5B "hello"]; SND.NXT=6, FlightSize=5

  app write "abc" (3B)
  poll_transmit:
    n = min(usable=1455, 1460, 3) = 3
    Nagle on, n(3) < MSS, FlightSize(5) > 0 → guard TRUE → HOLD; nothing sent

  peer ACK ack=6  → SND.UNA=6, FlightSize=0
  poll_transmit (re-driven by the ACK):
    n = 3, FlightSize = 0 → guard false → SEND seg[seq=6, 3B "abc"]
```

With `TCP_NODELAY` set, the second `poll_transmit` skips the guard and sends "abc" immediately at
`seq=6` while "hello" is still unacknowledged — two packets instead of the coalesced one, by the
application's explicit choice.

## 8. The code, walked

All in `src/tcp.rs`:

- **Struct**: `nagle: bool` joins `Connection`.
- **Constructors**: `accept_with_iss_at` and `connect_with_iss` set `nagle: true`.
- **`set_nodelay`**: flips it (`self.nagle = !nodelay`).
- **`poll_transmit`**: the `if self.nagle && n < mss && self.flight_size() > 0 { break; }` guard,
  placed after the `n == 0` window check so window-blocking and Nagle-holding stay distinct reasons
  to stop draining.

Nothing else changes — not `main.rs`'s loop, not the retransmission path. A held segment is just one
that has not been recorded yet; when it finally goes out it is recorded for retransmission exactly
like any other.

## 9. Verification

`cargo test` adds three tests:

- `nagle_holds_small_write_until_prior_data_acked` — the canonical sequence from §7: small write
  with nothing in flight goes; a second small write is held; the ACK flushes it.
- `nodelay_sends_small_write_immediately` — same setup with `set_nodelay(true)`; the second write is
  not held.
- `nagle_never_holds_a_full_segment` — with `cwnd` grown to 2·MSS, two full segments go out
  back-to-back even though the second leaves while the first is in flight (Nagle only holds *runts*).

All previous tests still pass (69 total) — the guard never fires for full segments or for the
first-in-flight segment, so existing send behavior is unchanged.

## 10. Why this, not that

| Decision | Alternative | Why |
|---|---|---|
| Hold only sub-MSS segments | A fixed byte threshold or a coalescing timer | Nagle's MSS rule is self-clocking and tuning-free; a timer reintroduces the latency we are trying to bound. |
| Condition on `FlightSize > 0` | Condition on "buffer < MSS" alone | The whole point is "wait *because* something is unacked." With nothing in flight there is nothing to wait for, so the first runt must go. |
| Single `nagle` bool + `set_nodelay` | A full socket-option table | One switch covers the only option that matters here; `TCP_NODELAY` is exactly a boolean. |
| Leave Nagle on in the server | Force `TCP_NODELAY` | The echo/HTTP paths are never hurt by it (single small writes with an empty flight, or bulk full segments), so the default that helps chatty apps is the right default. |

## 11. Rebuild it yourself — checklist + exercises

**Blank-file checklist:**
- [ ] State Nagle's rule in one sentence. What counts as "small"? What counts as "in flight"?
- [ ] Which of the four cases in §3 is the only one that holds?
- [ ] Why are the held bytes guaranteed to be sent eventually without any new timer?
- [ ] What does `TCP_NODELAY` change, and name one protocol that needs it.
- [ ] Describe the Nagle + delayed-ACK stall and two ways to avoid it.

**Exercises:**
- **E1.** Add delayed ACK to the *receiver* (ack at most every other segment, or after ~40 ms), then
  reproduce the §5 stall in a test and confirm `set_nodelay(true)` removes it.
- **E2.** Implement the "minimum of (MSS, ½·SND.WND)" small-segment rule variant and compare.
- **E3.** Add a `PSH`-driven override: if the application marks a write as "push", flush it even under
  Nagle (some stacks do). Decide whether that is wise and justify it.
- **E4.** Instrument `poll_transmit` to count how many segments Nagle saved over a simulated 1000
  single-byte writes interleaved with ACKs.

## 12. What the next day adds

Day 14 closes a *correctness* hole that flow control left open: **zero-window probes** (the persist
timer, RFC 9293 §3.8.6.1). When the peer advertises a window of 0, our sender correctly stops — but
if the later "window re-opened" ACK is lost, both sides wait forever: a deadlock. The persist timer
breaks it by periodically sending a 1-byte probe into the closed window, forcing the peer to re-ack
its current window. It is the mirror image of today's lesson: Nagle decides *not* to send a small
segment; the persist timer insists on sending one *anyway*, because silence would be fatal.

> Re-type the three-line guard and the `nagle` field with the book closed, then `cargo test`. You
> have taught your sender its first bit of restraint — and learned the most over-discussed three
> lines in all of TCP.
