# Day 5 — TCP, Part 3: Connection Teardown

> Goal: close the connection cleanly. When the client sends `FIN`, we acknowledge it, send
> our own `FIN`, and on the client's final `ACK` we destroy the TCB. After this the whole
> lifecycle — **open → transfer → close** — works end to end. This chapter ends with an
> honest map of what a *production* TCP still needs.

**Contents**
1. Closing, conceptually
2. FIN consumes a sequence number
3. The closing states (full picture vs ours)
4. TIME_WAIT — why it exists, why we skip it
5. The code, walked
6. Verification
7. The full lifecycle, one diagram
8. Simplifications and alternatives
9. Rebuild it yourself — checklist + exercises
10. What "complete" really requires (the honest roadmap)

---

## 1. Closing, conceptually

TCP connections are **full-duplex**: two independent byte streams (client→server and
server→client). Closing is therefore two half-closes: each side sends a `FIN` to say "I have
no more data," and each `FIN` is acknowledged. A clean close is four control exchanges, but
when one side has nothing more to send it can combine its ACK-of-their-FIN with its own FIN —
which is exactly what our echo server does (three packets instead of four).

---

## 2. FIN consumes a sequence number

Like `SYN`, a `FIN` occupies one position in the sequence space even though it carries no
data. So when the client's FIN arrives with `seq == RCV.NXT`, we advance `RCV.NXT` by **1**
to "cover" the FIN, and our acknowledgement of it carries `ack = RCV.NXT` (one past the FIN).
Our own FIN likewise consumes one of *our* sequence numbers, so after sending it we do
`SND.NXT += 1`, and the peer's final ACK must equal that new `SND.NXT`. This is the same
"+1 for a flag" rule you met in the handshake.

---

## 3. The closing states (full picture vs ours)

The RFC's two closing paths:

```
   active close (initiator)            passive close (responder — us)
   ESTABLISHED                          ESTABLISHED
     │ send FIN                           │ recv FIN, send ACK
     ▼                                    ▼
   FIN_WAIT_1  ─recv ACK→ FIN_WAIT_2     CLOSE_WAIT
     │ recv FIN, send ACK                 │ app done, send FIN
     ▼                                    ▼
   TIME_WAIT ──(2·MSL)──► CLOSED         LAST_ACK ─recv ACK→ CLOSED
```

We implement the **passive** side, collapsed: because an echo server has no more data the
moment the client closes, we go `ESTABLISHED → LAST_ACK` directly, sending `FIN|ACK` in one
segment (the ACK of their FIN + our FIN together), and then `LAST_ACK → CLOSED` on their
final ACK. We skip `CLOSE_WAIT` as a *distinct* state because there is no gap during which a
local application is still writing.

---

## 4. TIME_WAIT — why it exists, why we skip it

The side that sends the *last* ACK (the active closer) lingers in **TIME_WAIT** for `2·MSL`
(twice the Maximum Segment Lifetime, ~minutes) before truly closing. Two reasons:
1. **Reliability of the final ACK** — if it's lost, the peer retransmits its FIN; TIME_WAIT
   keeps the TCB around to re-ACK it. Without it, the retransmitted FIN would get a confusing
   RST.
2. **Old-duplicate protection** — it lets stray, delayed segments from this connection die
   out before the same 4-tuple can be reused, so they can't be mistaken for the new connection.

As the *passive* closer we end in CLOSED via LAST_ACK and don't need TIME_WAIT. (If we later
implement *active* close — our app initiating the FIN — we'd add it. It's the classic reason
a busy server accumulates thousands of TIME_WAIT sockets.)

---

## 5. The code, walked

In `Connection::on_packet`, the ESTABLISHED branch gained a FIN case:

```text
if FIN set and seg.seq == RCV.NXT:
    RCV.NXT += 1                                  # consume their FIN
    out = segment(seq=SND.NXT, ack=RCV.NXT, FIN|ACK)   # ack theirs + send ours
    SND.NXT += 1                                  # consume our FIN
    state = LAST_ACK
    return out
```

and a new LAST_ACK branch:

```text
if state == LAST_ACK and ACK set and seg.ack == SND.NXT:
    state = CLOSED
```

`main.rs` checks `conn.state()` after each packet and, when it's `CLOSED`, removes the TCB
from the `HashMap` — the connection is forgotten, freeing its slot.

---

## 6. Verification

`cargo test` → 17 green. `passive_close_via_fin`:
- establishes, then sends the client's `FIN` (seq 101);
- asserts our reply is `FIN|ACK`, `seq=1`, `ack=102` (their FIN at 101, +1), valid TCP
  checksum, and state `LastAck`;
- sends the client's final `ACK` (ack 2) and asserts state `Closed`.

Live (your hands): `printf 'hi\n' | nc -q1 192.168.0.2 8080` — `nc` prints `hi` and then
exits cleanly (its close triggers the FIN exchange). The stack log shows the FIN, "state now
LastAck", the final ACK, "state now Closed", "removed from table". `tcpdump` shows the FINs
and ACKs with matching seq/ack.

---

## 7. The full lifecycle, one diagram

```
   client                                   us (echo server)
     │  SYN seq=100                          │
     │ ────────────────────────────────────►│  SYN_RCVD
     │  SYN,ACK seq=0 ack=101                 │
     │ ◄────────────────────────────────────│
     │  ACK seq=101 ack=1                     │
     │ ────────────────────────────────────►│  ESTABLISHED
     │  PSH,ACK seq=101 ack=1  "hi"           │
     │ ────────────────────────────────────►│  RCV.NXT=103
     │  PSH,ACK seq=1 ack=103  "hi"  (echo)   │
     │ ◄────────────────────────────────────│  SND.NXT=3
     │  FIN,ACK seq=103 ack=3                  │
     │ ────────────────────────────────────►│  send FIN,ACK → LAST_ACK
     │  FIN,ACK seq=3 ack=104                  │
     │ ◄────────────────────────────────────│
     │  ACK seq=104 ack=4                      │
     │ ────────────────────────────────────►│  CLOSED (TCB removed)
```

Every number here is produced and checked by the test suite. You built a TCP that a standard
`nc` can connect to, exchange data with, and close.

---

## 8. Simplifications and alternatives

| Decision | We chose | Real TCP |
|---|---|---|
| Close path | passive only, collapsed to LAST_ACK | active + passive, full state set |
| TIME_WAIT | none (passive closer) | 2·MSL wait on the active closer |
| FIN with data | data branch handles data; FIN branch handles a bare FIN | a segment can carry final data + FIN together |
| RST | not sent | RST on bad/closed-port segments |
| Half-close | not supported (we close both ways at once) | app can close one direction, keep reading |

---

## 9. Rebuild it yourself — checklist + exercises

From memory:
1. Why FIN consumes a sequence number and where the `+1`s go.
2. The passive-close path: ESTABLISHED → LAST_ACK → CLOSED, and which segment carries what.
3. Why TIME_WAIT exists and which side waits.

**Exercises:**
- **E1.** Add `CLOSE_WAIT` as a real intermediate state: ACK the FIN immediately, and only
  send our FIN on a later tick. (Sets up half-close.)
- **E2.** Send a `RST` for a segment to an unknown/closed connection (ties together with
  day3 E2).
- **E3.** Implement `TIME_WAIT` for an *active* close path and explain the 2·MSL timer.

---

## 10. What "complete" really requires (the honest roadmap)

The lifecycle works over a **lossless, cooperative** TUN link. A TCP for the real internet
needs more, and each item needs an architectural change this build deliberately deferred:

1. **Retransmission + RTO (the big one).** Keep unacknowledged data in a buffer; start a
   timer; if the ACK doesn't arrive by the retransmission timeout, resend. This is what makes
   TCP *reliable*. **Blocker:** our `recv()` loop is purely blocking — there is no place for a
   timer to fire. Real fix: switch to **non-blocking I/O + a poll/epoll event loop** (the
   crate exposes `set_non_blocking`) or a timer thread, then drive retransmits on timeouts.
2. **Modular sequence validation** — accept/reject seq and ack by RFC 9293's windowed,
   wraparound comparisons (we do exact-match only).
3. **Out-of-order reassembly** — a receive buffer that holds gaps until they fill.
4. **Flow control** — honor the peer's advertised window (`SND.WND`); advertise our own
   based on free buffer space.
5. **Congestion control** — slow start, congestion avoidance, fast retransmit/recovery
   (Reno/CUBIC). Determines how fast you may send on a shared network.
6. **RST handling**, **active open** (connect out), **TIME_WAIT**, **ISN randomization**,
   and a real **socket-style API** (`listen`/`accept`/`read`/`write`).

That ordered list *is* the rest of the curriculum (Manual Phases 3–5). The honest status:
**a complete TCP connection lifecycle is built, tested, and demoable today**; turning it into
a robust, internet-grade stack is the retransmission-and-beyond work above, gated on the
move from blocking I/O to an event loop. Doing that next is the right Step 6 — and it's a
design change worth its own chapter rather than bolting timers onto a blocking loop.

> **Update:** Step 6 is now built — the non-blocking event loop, the retransmission queue, and
> the adaptive RTO (RFC 6298) are in `docs/day6-book.md`. Items 1 (retransmission/RTO) and the
> event-loop blocker above are done; the connection now survives a lossy link.

---

> Re-type the FIN/LAST_ACK logic from this chapter, then `cargo test`. You now hold the whole
> picture: parsing (Day 1), checksums + write (Day 2), handshake (Day 3), data (Day 4),
> close (Day 5).
