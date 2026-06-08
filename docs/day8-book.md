# Day 8 — TCP, Part 6: Flow Control (the Sliding Window)

> Goal: stop a fast sender from drowning a slow receiver. Every TCP segment carries a **window**:
> the receiver's standing offer of "I have room for this many more bytes." The sender must keep
> its unacknowledged data within that offer. This chapter wires up *both* directions of that
> contract — honoring the peer's advertised window (`SND.WND`), and advertising our own
> (`RCV.WND`) honestly — and is careful about which window is which, because mixing them up is a
> classic and silent bug (one we had, and fix here).

**Contents**
1. The mental model: the receiver sets the pace
2. The window field, and the *two* windows
3. Tracking the peer's window — `SND.WND`
4. `usable_window()` — how much we may send right now
5. Advertising *our* window — `RCV.WND` (and the bug we fixed)
6. Worked numbers
7. The code, walked
8. Verification
9. Why this, not that
10. Rebuild it yourself — checklist + exercises
11. What's next

---

## 1. The mental model: the receiver sets the pace

Reliability (Day 6) guarantees bytes *arrive*; it says nothing about whether the receiver can
*keep up*. A receiver has a finite buffer between "bytes off the wire" and "bytes the application
has read." If the sender blasts data faster than the app drains that buffer, the buffer overflows
and bytes are dropped — which then have to be retransmitted, wasting the very bandwidth that
caused the overflow. **Flow control** is the receiver throttling the sender to its own pace.

The mechanism is the **sliding window**, and it is gloriously simple: in every segment, the
receiver advertises a `window` = the number of bytes it can currently accept beyond what it has
already acknowledged. The sender treats that as a hard ceiling on **in-flight (unacknowledged)
data**. As ACKs come back, the window "slides" forward and more may be sent. When the window
reaches zero, the sender must stop and wait.

Crucially this is **end-to-end** and receiver-driven — distinct from *congestion* control
(Day 9+), which is *network*-driven. The real send limit is `min(receiver's window, congestion
window)`. This chapter is the first half only.

---

## 2. The window field, and the *two* windows

The `window` lives in the TCP header — bytes 14–15, the 16-bit field we've parsed since Day 1:

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

So the window field is **inbound → updates `SND.WND`**, and **outbound → carries `RCV.WND`**.
Reading the wrong one into the wrong place is undetectable by a casual test (both are just
`u16`s) and quietly corrupts the contract. §5 is exactly that story.

---

## 3. Tracking the peer's window — `SND.WND`

Before this feature, `send.wnd` was set once at connection setup (to our init constant) and never
updated — so we had no idea how much the peer could actually take. The fix is one line in the
`ESTABLISHED` branch of `on_packet_at`: every acceptable segment from the peer refreshes our view
of its window.

```rust
if self.state == State::Established {
    // Flow control: track the peer's advertised receive window so we never send more
    // unacknowledged data than it can hold (RFC 9293 §3.4).
    self.send.wnd = th.window;
    ...
}
```

`SND.WND` is now live — it rises and falls as the peer's buffer drains and fills. (A fuller stack
also guards against an *old* segment moving the window backwards, using `SND.WL1`/`SND.WL2`
sequence checks; we take the simpler "latest wins," which is correct on our in-order link.)

---

## 4. `usable_window()` — how much we may send right now

The window bounds **in-flight** data, not total data. In-flight = everything sent but not yet
acknowledged = `SND.NXT − SND.UNA`. So the bytes we may still send without overrunning the peer:

```rust
pub fn usable_window(&self) -> u32 {
    let in_flight = self.send.nxt.wrapping_sub(self.send.una);     // SND.NXT − SND.UNA
    (self.send.wnd as u32).saturating_sub(in_flight)               // SND.WND − in_flight
}
```

Two deliberate uses of wrapping/saturating arithmetic:
- `wrapping_sub` for `in_flight` — `SND.NXT` and `SND.UNA` are 32-bit sequence numbers that wrap
  (Day 3); their *difference* is the true count even across the 2³² boundary.
- `saturating_sub` for the result — if in-flight somehow exceeds the window (it shrank under us),
  we report `0` ("send nothing"), never a giant number from underflow.

A bulk sender would gate every transmission on `usable_window()`. Our echo server sends tiny
2-byte echoes that never approach even a small window, so it doesn't yet *enforce* the limit — but
the accounting is correct and ready for a sender that does (exercise E1).

---

## 5. Advertising *our* window — `RCV.WND` (and the bug we fixed)

Here is §2's trap, made concrete. Our segment builder is:

```rust
fn segment(&self, seq, ack, flags, payload) -> Vec<u8> {
    build_packet(self.local, self.remote, seq, ack, flags, self.recv.wnd, payload)
}                                                          // ↑ OUR window — RCV.WND
```

It **must** advertise `recv.wnd` (our receive capacity). It used to read `send.wnd` — and that
"worked" only by accident: while `send.wnd` was a frozen constant equal to `recv.wnd` (both
`1024`), the two were indistinguishable. The moment §3 made `send.wnd` track the *peer's* window,
`segment()` began **parroting the peer's window back** as if it were ours: tell us you have 64 KB
free and our next segment would falsely claim *we* have 64 KB free — advertising buffer we don't
have, inviting exactly the overflow flow control is meant to prevent. The fix is `send.wnd →
recv.wnd`, now pinned by the test `advertises_our_receive_window_not_the_peers`.

We advertise a **constant `1024`** because our receiver never backs up: an echo server consumes
each segment the instant it arrives, so its free buffer is always the full 1024. A real receiver
shrinks `RCV.WND` as unread bytes pile up and grows it as the application reads — that dynamic
window is the sliding window's other edge (exercise E2).

---

## 6. Worked numbers

The peer advertises a 500-byte window; we trace `usable_window()` as data and ACKs flow
(`tracks_peer_window` asserts the first line):

```text
SND.WND=500, SND.UNA=1, SND.NXT=1   in_flight = 0     usable = 500 − 0   = 500
send 200 bytes → SND.NXT=201        in_flight = 200   usable = 500 − 200 = 300
send 300 more  → SND.NXT=501        in_flight = 500   usable = 500 − 500 = 0   → STOP
peer ACKs 100  → SND.UNA=101        in_flight = 400   usable = 500 − 400 = 100 → may send 100
```

The window **slides**: an ACK that advances `SND.UNA` frees an equal amount of send budget. And
the zero-window case (`usable = 0`) is where a sender must park — see E3.

And the advertisement side (`advertises_our_receive_window_not_the_peers`):

```text
peer's segment carries window = 0xffff (65535)   → SND.WND = 65535
our echo's window field                          = RCV.WND = 1024   (NOT 65535)
```

---

## 7. The code, walked

Everything is in `src/tcp.rs`; nothing in `main` changed (flow control is internal accounting):

| Piece | Role |
|---|---|
| `send.wnd` (`SND.WND`) | the peer's advertised window; refreshed from each incoming segment |
| `recv.wnd` (`RCV.WND`) | our advertised window (constant 1024); written by `segment()` |
| `self.send.wnd = th.window` | the one-line tracker in the `ESTABLISHED` branch |
| `usable_window()` | `SND.WND − (SND.NXT − SND.UNA)`, saturating at 0 |
| `segment()` | stamps every outgoing header with `recv.wnd` |

Data path: a peer segment arrives → `send.wnd` updates to its window → if we echo, `segment()`
advertises *our* `recv.wnd` back → `usable_window()` reflects the peer's window minus our
in-flight bytes, ready for a sender to consult.

---

## 8. Verification

`cargo test` → **45 green**. Flow-control coverage:

- `tracks_peer_window` — peer advertises 500; with nothing in flight, `usable_window()` is 500.
- `advertises_our_receive_window_not_the_peers` — even when the peer advertises `0xffff`, our
  echo's window field is `1024` (our `RCV.WND`), proving §5's fix and guarding against its return.

Live (your hands), via `tcp-stack-run`: `nc 192.168.0.2 8080`, then `sudo tcpdump -i tun0 -n -v`
and read the `win` field — outbound segments from us show `win 1024`; the client's segments show
*its* window. To see the window genuinely *slide* you need a bulk transfer that fills the pipe
(exercise E1), since the echo path keeps in-flight data near zero.

---

## 9. Why this, not that

| Decision | We chose | Real TCP |
|---|---|---|
| Our advertised window | constant 1024 | dynamic: shrinks with unread data, grows as the app reads |
| Enforce `usable_window` | computed, not yet enforced (tiny echoes) | sender blocks/segments to fit the window |
| Window-update ordering | latest segment wins | `SND.WL1`/`SND.WL2` guard against stale updates |
| Zero-window handling | none (would just stall) | persist timer + zero-window probes to avoid deadlock |
| Silly-window syndrome | not addressed | Nagle (sender) + receiver SWS avoidance (Clark) |
| Window scaling | none — capped at 65535 | `WScale` option shifts the window up to 1 GB (RFC 7323) |
| flow vs congestion | flow control only | effective window = `min(SND.WND, cwnd)` |

---

## 10. Rebuild it yourself — checklist + exercises

From a blank file:
1. The two windows and the rule: *inbound* window field → `SND.WND`; *outbound* → `RCV.WND`.
2. Why `usable_window = SND.WND − (SND.NXT − SND.UNA)`, and why both arithmetic guards
   (`wrapping_sub`, `saturating_sub`) are there.
3. The §5 bug in one sentence — advertising `send.wnd` parrots the peer's window — and the
   one-token fix.

**Exercises:**
- **E1.** Make a real sender that *enforces* `usable_window()`: queue application data and emit
  only up to the window, deferring the rest until ACKs slide it open.
- **E2.** Make `RCV.WND` dynamic: track a receive buffer, shrink the advertised window as unread
  bytes accumulate, and grow it (sending a window-update ACK) as the app reads.
- **E3.** Handle a **zero window**: when the peer advertises 0, start a persist timer and send a
  1-byte zero-window probe so a lost window-update can't deadlock the connection forever.
- **E4.** Add **window scaling** (RFC 7323): negotiate the `WScale` option in the SYN and shift
  both windows, lifting the 64 KB ceiling.

---

## 11. What's next

Flow control caps the sender at what the *receiver* can hold. The missing twin is **congestion
control**: capping the sender at what the *network* can carry — slow start, congestion avoidance,
and fast retransmit/recovery (Reno/CUBIC), with the real send limit becoming
`min(SND.WND, cwnd)`. That, plus **out-of-order reassembly** (a receive buffer that holds gaps
until they fill) and a **socket-style API**, is the remaining curriculum (Manual Phases 4–5).

> Re-type the window accounting from this chapter with the book closed, then `cargo test`. You now
> hold the receiver's half of pacing: open (Day 3), data (Day 4), close (Day 5), reliability
> (Day 6), active close (Day 7), and flow control (Day 8). Congestion control is the next summit.
