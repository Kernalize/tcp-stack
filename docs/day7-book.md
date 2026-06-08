# Day 7 — TCP, Part 5: Active Close & TIME_WAIT

> Goal: close the connection from **our** side. Day 5 did the *passive* close — the peer sends
> `FIN`, we react. But a real endpoint also has to *initiate* a close: stop sending, emit our own
> `FIN`, and walk the active-closer's branch of the state machine — `FIN_WAIT_1 → FIN_WAIT_2 →
> TIME_WAIT → CLOSED`, with a detour for a simultaneous close. This chapter implements Day 5's
> exercise **E3** and finally gives us the full RFC 9293 teardown.

**Contents**
1. The mental model: who says goodbye first
2. The four states the active closer walks
3. `close()` — sending our FIN
4. FIN_WAIT_1 — the three-way branch point
5. FIN_WAIT_2 and the simultaneous close (CLOSING)
6. TIME_WAIT — why 2·MSL, and how the clock reaps it
7. The full active close, with worked seq/ack numbers
8. The code, walked end-to-end
9. Verification
10. Why this, not that
11. Rebuild it yourself — checklist + exercises
12. What's next

---

## 1. The mental model: who says goodbye first

A TCP connection is two independent byte streams, so closing is two **half-closes**, one per
direction. Whoever sends `FIN` first is the **active closer**; the other is the **passive closer**.
Day 5 built the passive side (the path through `LAST_ACK`). The roles are not symmetric, and the
asymmetry is the whole lesson of this chapter:

- The **passive** closer's last act is to send a `FIN`; it can forget the connection as soon as
  that FIN is acknowledged (`LAST_ACK → CLOSED`).
- The **active** closer's last act is to send an **ACK** (acknowledging the peer's FIN). An ACK is
  never itself acknowledged — so the active closer can't *know* its final ACK arrived. If it was
  lost, the peer will retransmit its FIN, expecting another ACK. So the active closer must linger,
  ready to re-ACK, in **TIME_WAIT**.

That single fact — *you can't get an ACK for your ACK* — is why TIME_WAIT exists and why only the
active closer pays for it.

A subtlety worth stating up front: our binary is a passive echo server, so it never *calls*
`close()` in `main`. The active-close machinery is therefore `#[allow(dead_code)]` in the binary
and exercised entirely by unit tests — which is fine, because the state machine is the same
whether a real app or a test drives it. Wiring a socket API that lets an app close is a later step.

---

## 2. The four states the active closer walks

Day 5's `State` enum gained four variants for the initiator's path (the passive `LAST_ACK` from
Day 5 stays):

```text
FinWait1   we sent our FIN; waiting for its ACK and/or the peer's FIN
FinWait2   our FIN was ACKed; now waiting only for the peer's FIN
Closing    simultaneous close — both sent FIN before either was ACKed; await our FIN's ACK
TimeWait   both FINs sent & acked; linger 2·MSL absorbing retransmitted FINs, then CLOSED
```

The RFC's two paths, side by side (we now implement *both* columns):

```text
   active close (initiator — new)        passive close (responder — Day 5)
   ESTABLISHED                            ESTABLISHED
     │ send FIN                             │ recv FIN, send FIN|ACK
     ▼                                      ▼
   FIN_WAIT_1 ─recv ACK→ FIN_WAIT_2        LAST_ACK ─recv ACK→ CLOSED
     │ recv FIN          │ recv FIN
     │ send ACK          │ send ACK
     ▼                   ▼
   CLOSING ─recv ACK→  TIME_WAIT ──(2·MSL)──► CLOSED
```

---

## 3. `close()` — sending our FIN

`close()` is the application's "I'm done sending." It is valid only from `ESTABLISHED` (you can't
close what isn't open), emits a `FIN|ACK`, and advances into `FIN_WAIT_1`:

```rust
pub fn close(&mut self) -> Option<Vec<u8>> {
    if self.state != State::Established { return None; }
    let out = self.segment(self.send.nxt, self.recv.nxt, FIN | ACK, &[]);
    self.send.nxt = self.send.nxt.wrapping_add(1); // our FIN consumes one sequence number
    self.state = State::FinWait1;
    Some(out)
}
```

Two familiar rules: the FIN carries `ACK` (we acknowledge everything received so far, `RCV.NXT`),
and the FIN **consumes one sequence number** — so `SND.NXT += 1`, and the peer's ACK of our FIN
will carry `ack == SND.NXT` (the new value). This is the same "+1 for a flag" from the SYN and the
passive FIN.

---

## 4. FIN_WAIT_1 — the three-way branch point

`FIN_WAIT_1` is the most interesting state in the machine because **three** different things can
arrive, and one segment can do two of them at once:

```rust
if self.state == State::FinWait1 {
    let acked_our_fin = th.flags & ACK != 0 && th.ack == self.send.nxt;
    // (a) the peer also sent its FIN (in order) → acknowledge it
    if th.flags & FIN != 0 && th.seq == self.recv.nxt {
        self.recv.nxt = self.recv.nxt.wrapping_add(1);
        let out = self.segment(self.send.nxt, self.recv.nxt, ACK, &[]);
        if acked_our_fin {
            self.state = State::TimeWait;  // their FIN + our FIN's ACK in one segment
            self.time_wait_ms = now_ms;
        } else {
            self.state = State::Closing;   // their FIN arrived, our FIN not yet ACKed
        }
        return Some(out);
    }
    // (b) a bare ACK of our FIN, no FIN of theirs yet → half-closed
    if acked_our_fin {
        self.state = State::FinWait2;
    }
    return None;
}
```

The three outcomes:

1. **ACK of our FIN only** → `FIN_WAIT_2` (the peer got our FIN but still has data/own-FIN to send).
2. **Peer's FIN that *also* ACKs ours** (the common case against a cooperative peer) → straight to
   `TIME_WAIT`, sending one ACK that covers their FIN.
3. **Peer's FIN that does *not* ACK ours** (simultaneous close — both FINs crossed on the wire) →
   `CLOSING`; we've ACKed their FIN but still await the ACK of ours.

`acked_our_fin` is computed once, up front, because both the FIN branch and the bare-ACK branch
need it. Note the acceptance guards: the peer's FIN is only honored when `th.seq == RCV.NXT`
(in order), and an ACK only counts when `th.ack == SND.NXT` (it acknowledges *exactly* our FIN).

---

## 5. FIN_WAIT_2 and the simultaneous close (CLOSING)

From `FIN_WAIT_2` we wait solely for the peer's FIN, ACK it, and enter `TIME_WAIT`:

```rust
if self.state == State::FinWait2 {
    if th.flags & FIN != 0 && th.seq == self.recv.nxt {
        self.recv.nxt = self.recv.nxt.wrapping_add(1);
        let out = self.segment(self.send.nxt, self.recv.nxt, ACK, &[]);
        self.state = State::TimeWait;
        self.time_wait_ms = now_ms;
        return Some(out);
    }
    return None;
}
```

`CLOSING` is the rare simultaneous-close meeting point: we already ACKed their FIN (in
`FIN_WAIT_1` branch (a) above), so all that's left is the ACK of *our* FIN:

```rust
if self.state == State::Closing {
    if th.flags & ACK != 0 && th.ack == self.send.nxt {
        self.state = State::TimeWait;
        self.time_wait_ms = now_ms;
    }
    return None;
}
```

Every road leads to `TIME_WAIT`, and each stamps `time_wait_ms = now_ms` so the clock can later
expire it.

---

## 6. TIME_WAIT — why 2·MSL, and how the clock reaps it

The active closer lingers in `TIME_WAIT` for **2·MSL** (twice the Maximum Segment Lifetime) for two
reasons, both consequences of "you can't ACK an ACK":

1. **Re-ACK a retransmitted FIN.** If our final ACK is lost, the peer's FIN times out and is
   resent; TIME_WAIT keeps the TCB alive to answer it. A connection that vanished the instant it
   sent the last ACK would reply to that resent FIN with a confusing `RST`.
2. **Let old duplicates die.** Stray, delayed segments from this 4-tuple must expire before the
   same 4-tuple can host a *new* connection, or they'd be mistaken for fresh data. 2·MSL is one
   round of "out and back" worth of lifetime.

This is the first state change driven purely by **time, not a packet** — which is exactly why
Day 6's event loop had to exist. `on_tick` checks it every pass:

```rust
const TIME_WAIT_MS: u64 = 2 * 120_000; // 2·MSL, with MSL = 2 minutes  → 240 s
if self.state == State::TimeWait
    && now_ms.saturating_sub(self.time_wait_ms) >= TIME_WAIT_MS {
    self.state = State::Closed;
}
```

`main`'s loop then drops any `CLOSED` connection from the table (Day 6 §3), freeing the slot. This
is the classic reason a busy server accumulates thousands of TIME_WAIT sockets: it's the active
closer for every short-lived client connection, and each one holds a TCB for minutes after the
last byte.

---

## 7. The full active close, with worked seq/ack numbers

Tracing `tcp::tests::active_close_to_timewait_then_closed` (our ISS = 0, peer ISN = 100):

```text
   us (active closer)                     peer
   ESTABLISHED  SND.NXT=1 RCV.NXT=101
     │  FIN,ACK seq=1 ack=101              │   close(): SND.NXT → 2
     │ ───────────────────────────────────►   FIN_WAIT_1
     │  ACK seq=101 ack=2                   │   acks our FIN (ack==SND.NXT=2)
     │ ◄───────────────────────────────────   FIN_WAIT_2
     │  FIN,ACK seq=101 ack=2               │   peer's FIN, in order (seq==RCV.NXT)
     │ ◄───────────────────────────────────   RCV.NXT → 102
     │  ACK seq=2 ack=102                   │   we ACK their FIN
     │ ───────────────────────────────────►   TIME_WAIT  (time_wait_ms = 1000)
     │            ...2·MSL passes...        │
     │  on_tick(1000 + 240_000)             │   TIME_WAIT → CLOSED, TCB reaped
```

Every number is asserted by the test: our FIN at `seq=1`, the ACK of it at `ack=2`, our ACK of
their FIN at `ack=102` (their FIN at 101, +1), and the two `on_tick` calls bracketing the 2·MSL
deadline (`on_tick(1000)` still TIME_WAIT; `on_tick(241_000)` → CLOSED).

---

## 8. The code, walked end-to-end

The whole feature lives in `src/tcp.rs` (state machine) and rides Day 6's loop in `src/main.rs`:

| Piece | Role |
|---|---|
| `State::{FinWait1,FinWait2,Closing,TimeWait}` | the active-closer's four states |
| `Connection::close()` | app-initiated close: emit FIN\|ACK, `SND.NXT += 1`, → FIN_WAIT_1 |
| `on_packet_at` branches | the per-state transitions of §4–§5 |
| `time_wait_ms` field | timestamp of entry into TIME_WAIT |
| `on_tick` | expires TIME_WAIT after 2·MSL (clock-driven, no packet) |
| `main`'s reaper | removes `CLOSED` connections from the table |

The flow of control for a clean active close: app calls `close()` → we send FIN, go `FIN_WAIT_1`
→ peer ACKs → `FIN_WAIT_2` → peer FINs → we ACK, go `TIME_WAIT`, stamp the clock → 2·MSL later an
`on_tick` flips us to `CLOSED` → the loop reaps the TCB. The passive `LAST_ACK` path from Day 5 is
untouched and still handles the case where the *peer* closes first.

---

## 9. Verification

`cargo test` → 44 green. The active-close coverage:

- `active_close_to_timewait_then_closed` — the full §7 trace: `close()` → FIN_WAIT_1, peer ACK →
  FIN_WAIT_2, peer FIN → TIME_WAIT (asserting the ACK's `seq`/`ack` and a valid TCP checksum),
  then the two `on_tick`s proving the 2·MSL expiry to CLOSED.
- `passive_close_via_fin` (Day 5) still passes — the responder path is unchanged.

Live (your hands), via the `tcp-stack-run` skill: because the binary is a passive server it won't
initiate a close, so this is best seen at the *peer*. Connect with `nc`, exchange a line, and let
`nc` close — `tcpdump -i tun0 -n` shows our `FIN,ACK`, the peer's ACK, its FIN, and our final ACK,
with the seq/ack numbers above. To exercise *our* active close live you'd need exercise E1 (a
socket API or a timed auto-close).

---

## 10. Why this, not that

| Decision | We chose | Real TCP / alternative |
|---|---|---|
| Who closes | passive in `main`, active in tests | app decides per socket via a close() API |
| FIN with data | bare FIN only (echo has nothing left) | a segment may carry final data + FIN together |
| TIME_WAIT length | 2·MSL with MSL = 2 min (240 s) | OS-tunable; Linux ~60 s; `SO_REUSEADDR` to bypass |
| Retransmit our FIN | not queued (loss of our FIN hangs the close) | FIN is queued in the retx buffer like data (E2) |
| CLOSE_WAIT | collapsed (echo has no app-write gap) | distinct state while the local app finishes sending |
| half-close | unsupported (we close both ways at once) | `shutdown(SHUT_WR)` closes one direction, keeps reading |

---

## 11. Rebuild it yourself — checklist + exercises

From a blank file:
1. The four active-closer states and the one-line trigger for each transition.
2. Why `FIN_WAIT_1` has three outcomes, and how one segment reaches TIME_WAIT directly.
3. The two reasons TIME_WAIT exists, and why **only the active closer** waits.
4. Why TIME_WAIT expiry needs the event loop (no packet triggers it).

**Exercises:**
- **E1.** Add a minimal trigger for `close()` in `main` (e.g. close a connection that's been idle
  N seconds) so the active path runs live, then watch TIME_WAIT in `tcpdump`.
- **E2.** Queue our FIN in the `RetxQueue` (Day 6) so a lost FIN is retransmitted — today losing
  our FIN stalls the close forever.
- **E3.** Implement a real `CLOSE_WAIT`: as the passive closer, ACK the peer's FIN immediately but
  send our FIN only on a later tick, modelling an app that's still draining its send buffer.
- **E4.** Honor `SO_REUSEADDR` semantics: allow a new connection on a 4-tuple still in TIME_WAIT
  when the new ISN is provably beyond the old sequence space.

---

## 12. What's next

The teardown is now complete in both directions. The remaining reliability work is **flow
control** — we already record the peer's advertised window (`SND.WND`) and expose
`usable_window()`, but a sender must actually *gate* its transmission on it so it never overruns a
slow receiver. That's Day 8. After that: out-of-order reassembly and congestion control (the rest
of Manual Phases 3–5).

> Re-type the `FIN_WAIT_1/2`, `CLOSING`, and `TIME_WAIT` transitions from this chapter with the
> book closed, then `cargo test`. You now hold the entire lifecycle from both sides: open
> (Day 3), data (Day 4), passive close (Day 5), reliability (Day 6), and active close (Day 7).
