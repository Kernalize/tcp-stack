# Day 7 — TCP, Part 5: Active Close & TIME_WAIT

> Goal: close the connection from **our** side. Day 5 did the *passive* close — the peer sends `FIN`,
> we react. But a real endpoint also has to *initiate* a close: stop sending, emit our own `FIN`, and
> walk the active-closer's branch of the state machine — `FIN_WAIT_1 → FIN_WAIT_2 → TIME_WAIT → CLOSED`,
> with a detour for a simultaneous close. This chapter completes the RFC 9293 teardown and confronts the
> most over-discussed state in TCP: TIME_WAIT.

The teardown is asymmetric, and the asymmetry is the entire lesson. The passive closer (Day 5) gets off
easy — it forgets the connection the moment its FIN is acked. The active closer pays: it must linger for
minutes in TIME_WAIT. Understanding *why* — the "you can't ACK an ACK" theorem — explains a huge amount
of real-world server behavior (why busy servers drown in TIME_WAIT, why you push the close onto the
client, why HTTP keep-alive exists).

**Contents**

Volume I — the chapter
1. The mental model: who says goodbye first
2. The four states the active closer walks
3. `close()` — sending our FIN
4. FIN_WAIT_1 — the three-way branch point
5. FIN_WAIT_2 and the simultaneous close (CLOSING)
6. TIME_WAIT — why 2·MSL, and how the clock reaps it
7. The full active close, with worked seq/ack numbers
8. The Rust: dead_code-by-design, compute-once, clock-driven transitions
9. The code, walked end to end
10. Verification
11. Why this, not that
12. Honesty: what production does, and what later days added
13. Rebuild it yourself — checklist + exercises
14. What the next step adds

Volume II — the exhaustive reference
- A. The complete teardown state machine, every transition
- B. TIME_WAIT, deep — the 2·MSL math and the two jobs
- C. TIME_WAIT mitigations — `SO_REUSEADDR`, `tcp_tw_reuse`, and the `tcp_tw_recycle` cautionary tale
- D. Simultaneous close and CLOSING, exhaustively
- E. Half-close and CLOSE_WAIT — the app-write gap we collapse
- F. The "you can't ACK an ACK" theorem
- G. A complete annotated active-close trace (hex + TCB)
- H. Comparison to real stacks — who closes, and HTTP keep-alive
- I. Security — TIME_WAIT assassination (RFC 1337) and RST in TIME_WAIT
- J. Performance — the close storm, port exhaustion, memory
- K. Extended FAQ
- L. Anki starter deck
- M. Glossary
- N. Reference tables

---

# Volume I — the chapter

## 1. The mental model: who says goodbye first

A TCP connection is two independent byte streams, so closing is two **half-closes**, one per direction.
Whoever sends `FIN` first is the **active closer**; the other is the **passive closer**. Day 5 built the
passive side (the path through `LAST_ACK`). The roles are not symmetric, and the asymmetry is the whole
lesson of this chapter:

- The **passive** closer's last act is to send a `FIN`; it can forget the connection as soon as that FIN
  is acknowledged (`LAST_ACK → CLOSED`).
- The **active** closer's last act is to send an **ACK** (acknowledging the peer's FIN). An ACK is never
  itself acknowledged — so the active closer can't *know* its final ACK arrived. If it was lost, the peer
  will retransmit its FIN, expecting another ACK. So the active closer must linger, ready to re-ACK, in
  **TIME_WAIT**.

That single fact — *you can't get an ACK for your ACK* (§F) — is why TIME_WAIT exists and why only the
active closer pays for it.

A subtlety worth stating up front: our binary is a passive echo server, so it never *calls* `close()` in
`main`. The active-close machinery is therefore `#[allow(dead_code)]` in the binary and exercised
entirely by unit tests — which is fine, because the state machine is the same whether a real app or a
test drives it (§8). Wiring a socket API that lets an app close arrives on Day 11.

## 2. The four states the active closer walks

Day 5's `State` enum gained four variants for the initiator's path (the passive `LAST_ACK` from Day 5
stays):

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

## 3. `close()` — sending our FIN

`close()` is the application's "I'm done sending." It is valid only from `ESTABLISHED` (you can't close
what isn't open), emits a `FIN|ACK`, and advances into `FIN_WAIT_1`:

```rust
pub fn close(&mut self, now_ms: u64) -> Option<Vec<u8>> {
    if self.state != State::Established { return None; }
    let out = self.segment(self.send.nxt, self.recv.nxt, FIN | ACK, &[]);
    self.send.nxt = self.send.nxt.wrapping_add(1); // our FIN consumes one sequence number
    self.retx.record(self.send.nxt.wrapping_sub(1), self.send.nxt, out.clone(), now_ms); // (Day 12)
    self.state = State::FinWait1;
    Some(out)
}
```

Two familiar rules: the FIN carries `ACK` (we acknowledge everything received so far, `RCV.NXT`), and the
FIN **consumes one sequence number** — so `SND.NXT += 1`, and the peer's ACK of our FIN will carry
`ack == SND.NXT` (the new value). This is the same "+1 for a flag" from the SYN and the passive FIN. (The
`retx.record` line is Day 12's addition: our FIN is queued for retransmission so a lost FIN doesn't hang
the close — §12. The original day-7 `close()` took no `now_ms` and didn't queue.)

## 4. FIN_WAIT_1 — the three-way branch point

`FIN_WAIT_1` is the most interesting state in the machine because **three** different things can arrive,
and one segment can do two of them at once:

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

`acked_our_fin` is computed once, up front, because both the FIN branch and the bare-ACK branch need it.
Note the acceptance guards: the peer's FIN is only honored when `th.seq == RCV.NXT` (in order), and an
ACK only counts when `th.ack == SND.NXT` (it acknowledges *exactly* our FIN).

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

`CLOSING` is the rare simultaneous-close meeting point: we already ACKed their FIN (in `FIN_WAIT_1`
branch (a) above), so all that's left is the ACK of *our* FIN:

```rust
if self.state == State::Closing {
    if th.flags & ACK != 0 && th.ack == self.send.nxt {
        self.state = State::TimeWait;
        self.time_wait_ms = now_ms;
    }
    return None;
}
```

Every road leads to `TIME_WAIT`, and each stamps `time_wait_ms = now_ms` so the clock can later expire
it.

## 6. TIME_WAIT — why 2·MSL, and how the clock reaps it

The active closer lingers in `TIME_WAIT` for **2·MSL** (twice the Maximum Segment Lifetime) for two
reasons, both consequences of "you can't ACK an ACK":

1. **Re-ACK a retransmitted FIN.** If our final ACK is lost, the peer's FIN times out and is resent;
   TIME_WAIT keeps the TCB alive to answer it. A connection that vanished the instant it sent the last
   ACK would reply to that resent FIN with a confusing `RST`.
2. **Let old duplicates die.** Stray, delayed segments from this 4-tuple must expire before the same
   4-tuple can host a *new* connection, or they'd be mistaken for fresh data. 2·MSL is one round of "out
   and back" worth of lifetime (§B).

This is the first state change driven purely by **time, not a packet** — which is exactly why Day 6's
event loop had to exist. `on_tick` checks it every pass:

```rust
const TIME_WAIT_MS: u64 = 2 * 120_000; // 2·MSL, with MSL = 2 minutes  → 240 s
if self.state == State::TimeWait
    && now_ms.saturating_sub(self.time_wait_ms) >= TIME_WAIT_MS {
    self.state = State::Closed;
}
```

`main`'s loop then drops any `CLOSED` connection from the table (Day 6 §3), freeing the slot. This is the
classic reason a busy server accumulates thousands of TIME_WAIT sockets: it's the active closer for every
short-lived client connection, and each one holds a TCB for minutes after the last byte (§J).

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

Every number is asserted by the test: our FIN at `seq=1`, the ACK of it at `ack=2`, our ACK of their FIN
at `ack=102` (their FIN at 101, +1), and the two `on_tick` calls bracketing the 2·MSL deadline
(`on_tick(1000)` still TIME_WAIT; `on_tick(241_000)` → CLOSED).

## 8. The Rust: dead_code-by-design, compute-once, clock-driven transitions

- **`#[allow(dead_code)]` is a design statement, not laziness.** `close()` and the active-open `connect`
  are unused *by the binary* (a passive echo server never initiates), but they're real, tested
  capabilities. The attribute says "this is intentionally not wired into `main` yet" and keeps the build
  warning-clean. Removing and re-adding the code each time an app needs it would be churn; the allow
  documents intent.
- **Compute the predicate once.** `acked_our_fin` is computed at the top of the FIN_WAIT_1 branch and
  used twice. This avoids re-deriving it (and re-reading `th.ack`/`self.send.nxt`) in two places, and
  makes the three-way branch read as a small decision table.
- **A state machine is just a field + matches.** Each state is an `if self.state == State::X` block that
  reads the segment, maybe emits a reply, and assigns the next state. No framework, no trait objects —
  the clarity comes from mirroring the RFC's prose one block per state.
- **Time drives a transition with no packet.** TIME_WAIT → CLOSED happens in `on_tick`, purely from the
  clock. This is only expressible because Day 6 made time a first-class input (`now_ms` threaded through
  every entry point). `saturating_sub` keeps the comparison safe if `now_ms < time_wait_ms`.

## 9. The code, walked end to end

The whole feature lives in `src/tcp.rs` (state machine) and rides Day 6's loop in `src/main.rs`:

| Piece | Role |
|---|---|
| `State::{FinWait1,FinWait2,Closing,TimeWait}` | the active-closer's four states |
| `Connection::close(now_ms)` | app-initiated close: emit FIN\|ACK, `SND.NXT += 1`, queue it, → FIN_WAIT_1 |
| `on_segment` branches | the per-state transitions of §4–§5 |
| `time_wait_ms` field | timestamp of entry into TIME_WAIT |
| `on_tick` | expires TIME_WAIT after 2·MSL (clock-driven, no packet) |
| `main`'s reaper | removes `CLOSED` connections from the table |

The flow of control for a clean active close: app calls `close()` → we send FIN, go `FIN_WAIT_1` → peer
ACKs → `FIN_WAIT_2` → peer FINs → we ACK, go `TIME_WAIT`, stamp the clock → 2·MSL later an `on_tick`
flips us to `CLOSED` → the loop reaps the TCB. The passive `LAST_ACK` path from Day 5 is untouched and
still handles the case where the *peer* closes first.

## 10. Verification

`cargo test` proves the active close offline. The coverage:

- `active_close_to_timewait_then_closed` — the full §7 trace: `close()` → FIN_WAIT_1, peer ACK →
  FIN_WAIT_2, peer FIN → TIME_WAIT (asserting the ACK's `seq`/`ack` and a valid TCP checksum), then the
  two `on_tick`s proving the 2·MSL expiry to CLOSED.
- `active_fin_retransmits_until_acked` (Day 12) — our FIN is resent on RTO until the peer ACKs it.
- `passive_close_via_fin` (Day 5) still passes — the responder path is unchanged.

Live (your hands): because the binary is a passive server it won't initiate a close, so this is best seen
at the *peer*. Connect with `nc`, exchange a line, and let `nc` close — `sudo tcpdump -i tun0 -n` shows
our `FIN,ACK`, the peer's ACK, its FIN, and our final ACK, with the seq/ack numbers above. To exercise
*our* active close live you'd need exercise E1 (a socket API or a timed auto-close) — which Day 11's HTTP
server provides (it active-closes after the response).

## 11. Why this, not that

| Decision | We chose | Real TCP / alternative |
|---|---|---|
| Who closes | passive in `main`, active in tests (and HTTP, Day 11) | app decides per socket via a close() API |
| FIN with data | bare FIN only (echo has nothing left) | a segment may carry final data + FIN together |
| TIME_WAIT length | 2·MSL with MSL = 2 min (240 s) | OS-tunable; Linux ~60 s; `SO_REUSEADDR` to rebind |
| Retransmit our FIN | queued (Day 12) | FIN is queued in the retx buffer like data |
| CLOSE_WAIT | collapsed (echo has no app-write gap) | distinct state while the local app finishes sending |
| half-close | unsupported (we close both ways at once) | `shutdown(SHUT_WR)` closes one direction, keeps reading |
| One timer per FIN | per-segment (Day 6 model) | one connection retransmit timer (RFC 6298 §5) |

## 12. Honesty: what production does, and what later days added

- **FIN retransmission arrived Day 12.** The original day-7 `close()` didn't queue the FIN, so a lost FIN
  hung the close forever (day-7 exercise E2). Day 12 added `now_ms` to `close()` and queues the FIN in
  the `RetxQueue`, making teardown reliable — reflected in the §3 code.
- **No distinct CLOSE_WAIT / half-close.** We collapse CLOSE_WAIT into the FIN|ACK on the passive path
  and don't support `shutdown(SHUT_WR)`. A server that streams a response after the client half-closes
  its request needs the distinct state (§E).
- **No FIN-with-data.** A real final segment may carry the last bytes *and* the FIN; we separate them.
- **TIME_WAIT length is fixed at 240 s.** Real stacks tune it (Linux ~60 s) and offer `SO_REUSEADDR` /
  `tcp_tw_reuse` to manage the close storm (§C). We always wait the full 2·MSL.
- **No TIME_WAIT-assassination defense beyond the basics.** RFC 1337 / PAWS (Day 16) harden TIME_WAIT
  against injected RSTs; our day-7 TIME_WAIT is minimal (§I).
- **The binary never actively closes (until HTTP).** Day 11's HTTP/1.0 server is the first code path that
  calls `close()` for real (it closes after sending the response), finally exercising this machinery in
  the running binary.

None of these change the day-7 contract (we can initiate a clean close and walk to CLOSED through
TIME_WAIT); they are the breadth later days add.

## 13. Rebuild it yourself — checklist + exercises

**Blank-file checklist:**

- [ ] The four active-closer states and the one-line trigger for each transition.
- [ ] Why `FIN_WAIT_1` has three outcomes, and how one segment reaches TIME_WAIT directly.
- [ ] The two reasons TIME_WAIT exists, and why **only the active closer** waits.
- [ ] Why TIME_WAIT expiry needs the event loop (no packet triggers it).
- [ ] The "you can't ACK an ACK" theorem (§F) in one sentence.

**Exercises:**

- **E1.** ✅ *Done* (Day 11): the HTTP server calls `close()` after the response, running the active path
  live — watch TIME_WAIT in `tcpdump`.
- **E2.** ✅ *Done* (Day 12): queue our FIN in the `RetxQueue` so a lost FIN is retransmitted.
- **E3.** Implement a real `CLOSE_WAIT`: as the passive closer, ACK the peer's FIN immediately but send
  our FIN only on a later tick, modelling an app that's still draining its send buffer (§E).
- **E4.** Honor `SO_REUSEADDR`/`tcp_tw_reuse` semantics: allow a new connection on a 4-tuple still in
  TIME_WAIT when the new ISN/timestamp is provably beyond the old (§C).
- **E5.** Add FIN-with-data: accept final bytes and the FIN in one segment on the active path.

## 14. What the next step adds

The teardown is now complete in both directions. Day 8 adds **flow control** — we already record the
peer's advertised window (`SND.WND`) and expose `usable_window()`, but a sender must actually *gate* its
transmission on it so it never overruns a slow receiver. After that: out-of-order reassembly (Day 9) and
congestion control (Day 10) — the rest of Manual Phases 3–5.

---

# Volume II — the exhaustive reference

## A. The complete teardown state machine, every transition

Each teardown state, the events it accepts, and where it goes:

```text
   state         event                              action                  next state
   ───────────   ────────────────────────────────   ─────────────────────   ───────────
   ESTABLISHED   app close()                         send FIN                FIN_WAIT_1   (active)
   ESTABLISHED   recv peer FIN                       send FIN|ACK            LAST_ACK     (passive)
   FIN_WAIT_1    recv ACK of our FIN (only)          —                       FIN_WAIT_2
   FIN_WAIT_1    recv peer FIN + ACK of ours         send ACK                TIME_WAIT
   FIN_WAIT_1    recv peer FIN (ours not acked)      send ACK                CLOSING
   FIN_WAIT_2    recv peer FIN                       send ACK                TIME_WAIT
   CLOSING       recv ACK of our FIN                 —                       TIME_WAIT
   LAST_ACK      recv ACK of our FIN                 —                       CLOSED
   TIME_WAIT     2·MSL elapses (clock)              —                       CLOSED
   TIME_WAIT     recv retransmitted peer FIN         re-send ACK            TIME_WAIT (restart timer)
```

The last row is the *job* of TIME_WAIT: it stays able to re-ACK a retransmitted FIN. (Our minimal
implementation expires purely on the timer and would not currently restart it on a retransmitted FIN —
exercise / §I.) Note every active path converges on TIME_WAIT, and only the passive path skips it.

## B. TIME_WAIT, deep — the 2·MSL math and the two jobs

**MSL (Maximum Segment Lifetime)** is the assumed upper bound on how long a segment can exist in the
network before being discarded (it's bounded by the IP TTL, decremented at each hop). RFC 793 picks
MSL = 2 minutes; implementations vary (Linux effectively ~30–60 s).

**Why exactly 2·MSL?** Consider the worst case after we send our final ACK:

```text
   our last ACK travels to the peer:        up to MSL
   IF lost, peer's FIN retransmission back:  up to MSL
   ─────────────────────────────────────────────────
   total worst-case round:                  2·MSL
```

Waiting 2·MSL guarantees that by the time we leave TIME_WAIT, either our final ACK was delivered, or the
peer's retransmitted FIN has already arrived (and we re-ACKed it). Simultaneously, any *data* segment
from this connection still in the network has a lifetime ≤ MSL ≤ 2·MSL, so it has expired before the
4-tuple is reusable. One wait, both guarantees.

**The two jobs, restated:**

1. *Reliable connection termination* — absorb a retransmitted FIN with a fresh ACK rather than a RST.
2. *Sequence-number quarantine* — prevent a stray old segment from being accepted by a new incarnation of
   the same 4-tuple.

## C. TIME_WAIT mitigations — `SO_REUSEADDR`, `tcp_tw_reuse`, and `tcp_tw_recycle`

The cost of TIME_WAIT (held by the active closer) leads to several knobs, with very different safety:

- **`SO_REUSEADDR`** — lets a socket `bind()` to a local address/port that's in TIME_WAIT. Essential for
  server *restarts* (otherwise you'd wait minutes to re-bind your listening port). Safe: it only affects
  binding, not the sequence-number quarantine, because a new *listening* socket gets fresh connections
  with new 4-tuples.
- **`tcp_tw_reuse` (Linux)** — lets a new *outbound* connection reuse a 4-tuple still in TIME_WAIT, *when
  TCP timestamps prove* the new connection's segments can't be confused with the old ones (the timestamp
  is strictly increasing). Safe *with timestamps* (Day 16). Helps clients making many short connections.
- **`tcp_tw_recycle` (Linux, removed in 4.12)** — a more aggressive recycling that keyed off per-host
  timestamps. It **broke** clients behind NAT (multiple hosts sharing one IP have unrelated timestamp
  clocks, so the kernel rejected legitimate connections) and was a notorious source of "random connection
  failures." It was removed entirely. The cautionary tale: TIME_WAIT exists for correctness; "optimizing"
  it away without the timestamp guarantee silently corrupts connections.

The robust real-world answer is usually architectural (§H): make the *client* the active closer, or avoid
closing at all with keep-alive.

## D. Simultaneous close and CLOSING, exhaustively

If both apps `close()` at nearly the same time, both send FIN from ESTABLISHED and enter FIN_WAIT_1. Then
each receives the *other's* FIN before its own FIN is acked:

```text
   A: FIN_WAIT_1, recv peer FIN (no ACK of ours yet) → send ACK → CLOSING
   B: FIN_WAIT_1, recv peer FIN (no ACK of ours yet) → send ACK → CLOSING
   each: later recv ACK of our FIN → TIME_WAIT → (2·MSL) → CLOSED
```

So **both** ends go through CLOSING and **both** end in TIME_WAIT (in the normal asymmetric close, only
one side does). CLOSING means precisely "I have acknowledged your FIN, but mine has not yet been
acknowledged." It needs no new packet types — just the FIN/ACK in a crossed interleaving. Our FIN_WAIT_1
branch (a) detects it via `!acked_our_fin` and routes to CLOSING; the CLOSING block then waits for the ACK
of our FIN. Rare in practice (needs both apps to close within a round trip), but the machine handles it.

## E. Half-close and CLOSE_WAIT — the app-write gap we collapse

**Half-close** (`shutdown(fd, SHUT_WR)`) closes the *sending* direction while keeping the *receiving*
direction open. On the wire it's a FIN one way; the reverse stream keeps flowing. The canonical use: a
client sends a request, half-closes to signal "request complete," then reads a response the server
streams *after* receiving that FIN.

For the **passive** side this is why **CLOSE_WAIT** must be a distinct state: the peer's FIN arrives, you
ACK it and enter CLOSE_WAIT, but your *application* may still be writing the response; only when the app
finishes and closes do you send *your* FIN (CLOSE_WAIT → LAST_ACK). The gap between "peer closed" and "I
close" is where the application keeps sending.

Our echo server has no such gap — it has nothing to send once the client closes — so we **collapse**
CLOSE_WAIT into the FIN|ACK (Day 5) and never model it. The practical consequence: we can't serve a
protocol that streams a response *after* a request half-close. (HTTP/1.0 without keep-alive works because
the client doesn't half-close mid-request; a strict request-then-half-close-then-stream protocol would
need real CLOSE_WAIT — exercise E3.) Seeing many CLOSE_WAIT sockets in `netstat` on a real server almost
always means an application bug: it received a FIN but forgot to `close()`.

## F. The "you can't ACK an ACK" theorem

Why is the teardown fundamentally asymmetric? Because **pure ACKs are not acknowledged.** TCP
acknowledges *sequence-consuming* things (data, SYN, FIN), not bare ACKs. So:

- The **passive** closer's final transmission is a *FIN* — sequence-consuming, hence acknowledged. When
  it sees the ACK, it *knows* the peer received its FIN, and can safely CLOSE.
- The **active** closer's final transmission is a *bare ACK* (of the peer's FIN) — not acknowledged.
  There is no signal that confirms the peer received it. If it was lost, the only evidence is the peer
  *retransmitting its FIN*. So the active closer cannot safely forget the connection; it must wait long
  enough to catch a retransmitted FIN and re-ACK it.

This is a small instance of the **Two Generals' Problem**: no finite exchange of messages over a lossy
channel lets both parties be *certain* the other has stopped. TCP doesn't solve the impossible; it bounds
the uncertainty with time (2·MSL). TIME_WAIT is the protocol admitting "I can't be sure my last ACK
arrived, so I'll wait long enough to handle the case where it didn't." Everything about TIME_WAIT follows
from this one theorem.

## G. A complete annotated active-close trace (hex + TCB)

Our active close, TCP headers only, checksum/urgent `··`. Our ISS 0, peer ISN 100, state ESTABLISHED with
`SND.NXT=1, RCV.NXT=101`.

```text
   ① U→C  FIN,ACK  seq=1 ack=101         close()
      00 50 12 34 | 00 00 00 01 | 00 00 00 65 | 50 11 04 00 | ·· ·· 00 00
      sport 80    | seq 1       | ack 101     | off5 F|A win | csum urg
      U TCB: SND.NXT 1→2, state ESTABLISHED→FIN_WAIT_1 (FIN queued for retransmit)

   ② C→U  ACK  seq=101 ack=2
      12 34 00 50 | 00 00 00 65 | 00 00 00 02 | 50 10 ff ff | ·· ·· 00 00
      U TCB: our FIN acked (ack==SND.NXT 2) → FIN_WAIT_2; retx queue drained

   ③ C→U  FIN,ACK  seq=101 ack=2
      12 34 00 50 | 00 00 00 65 | 00 00 00 02 | 50 11 ff ff | ·· ·· 00 00
      U TCB: peer FIN in order (seq==RCV.NXT 101) → RCV.NXT 101→102

   ④ U→C  ACK  seq=2 ack=102
      00 50 12 34 | 00 00 00 02 | 00 00 00 66 | 50 10 04 00 | ·· ·· 00 00
      U TCB: state FIN_WAIT_2→TIME_WAIT, time_wait_ms = now

   ⑤ (no packet)  on_tick(now + 240_000)
      U TCB: 2·MSL elapsed → TIME_WAIT→CLOSED → main reaps the TCB
```

Flag bytes: `0x11` FIN|ACK, `0x10` ACK. The `+1`s: ①'s FIN at seq 1 → ②'s ack 2; ③'s FIN at 101 → ④'s
ack 102. Step ⑤ is the packet-less, clock-driven transition unique to TIME_WAIT.

## H. Comparison to real stacks — who closes, and HTTP keep-alive

```text
   concept             real systems                                this stack
   ─────────────────   ─────────────────────────────────────────  ──────────────────────────
   who actively closes  often the CLIENT (to push TIME_WAIT off    HTTP server closes (Day 11);
                        the busy server)                            echo is passive
   TIME_WAIT length     tunable (~60 s Linux); SO_REUSEADDR/reuse   fixed 240 s, no reuse
   avoiding close       HTTP keep-alive: many requests / one conn   single request then close
   CLOSE_WAIT           distinct (app-write gap); leaks = bug       collapsed
   half-close           shutdown(SHUT_WR) supported                 unsupported
   reaping              after 2·MSL                                 main.remove on CLOSED
```

The headline real-world technique is **HTTP keep-alive** (and HTTP/2 multiplexing): the cheapest close is
the one you never do. A persistent connection serves many requests, amortizing both the handshake (Day 3)
and the teardown (this day, including TIME_WAIT). Where a close is unavoidable, well-designed systems
arrange for the *client* to be the active closer so the *server* doesn't accumulate TIME_WAIT TCBs. Our
HTTP server (Day 11) actively closes — a deliberate simplification (one request per connection), and thus
the first place our binary pays the TIME_WAIT cost.

## I. Security — TIME_WAIT assassination (RFC 1337) and RST in TIME_WAIT

- **TIME_WAIT assassination (RFC 1337).** An attacker (or a confused peer) can inject an *old* segment
  that elicits a RST while we're in TIME_WAIT; a naive stack accepts the RST, kills the TIME_WAIT early,
  and reopens the old-duplicate window the wait was meant to close. The defenses: ignore RSTs in
  TIME_WAIT for already-acknowledged sequence space, and use **PAWS** (Day 16 timestamps) to reject
  segments older than the most recent — a timestamp that predates `TS.Recent` is a stale duplicate and is
  dropped regardless of its sequence number.
- **RST injection generally.** A forged in-window RST tears down a live connection. RFC 5961 tightens RST
  acceptance to the *exact* `RCV.NXT` (a near-miss earns a rate-limited "challenge ACK" instead of a
  teardown). Our stack doesn't yet validate RSTs this tightly.
- **Port stealing / 4-tuple reuse.** Without TIME_WAIT (or with an unsafe `tcp_tw_recycle`, §C), an
  attacker who can reuse a 4-tuple might inject data that a new incarnation accepts. TIME_WAIT + random
  ISNs (Day 3) + PAWS (Day 16) together close this.
- **Resource exhaustion.** An attacker who induces many active closes can balloon a server's TIME_WAIT
  table; bounded tables and (safe) reuse mitigate.

The theme echoes Day 5's: every control transition is attacker-forgeable, and TIME_WAIT in particular is
a *time-bounded* defense that injected RSTs try to cut short — which is why PAWS exists.

## J. Performance — the close storm, port exhaustion, memory

- **The close storm.** A server that actively closes N short connections per second holds ~`N × 240`
  TIME_WAIT TCBs simultaneously (with our 240 s wait). At 1000 closes/s that's 240,000 TCBs — hundreds of
  MB and real CPU to manage. This is *the* reason "let the client close" and "use keep-alive" are
  performance gospel.
- **Ephemeral port exhaustion (clients).** A client repeatedly connecting to one `(server IP, port)` uses
  a fresh ephemeral source port each time; ports stuck in TIME_WAIT cap concurrency at the ephemeral
  range (~28k–64k) divided by the TIME_WAIT duration. `tcp_tw_reuse` + timestamps reclaim them safely.
- **Memory per TCB.** A TIME_WAIT TCB is lighter than a full one (no buffers needed), and real kernels
  use a compact "TIME_WAIT bucket" struct rather than the full socket — an optimization we don't make
  (we keep the whole `Connection`).
- **Our cost** is the linear `on_tick` scan to find expired TIME_WAITs plus a `HashMap::remove`. At our
  scale it's nothing; at server scale you'd want the timer wheel (Day 6 §E) and a TIME_WAIT-specific
  lightweight bucket.

## K. Extended FAQ

1. **Who is the active closer?** Whoever sends the first FIN.
2. **Why does only the active closer wait in TIME_WAIT?** Its last act is a bare ACK, which is never
   acknowledged (§F).
3. **What are the four active-closer states?** FIN_WAIT_1, FIN_WAIT_2, CLOSING, TIME_WAIT.
4. **What makes FIN_WAIT_1 special?** Three outcomes: ACK-only → FIN_WAIT_2; peer FIN+ACK → TIME_WAIT;
   peer FIN only → CLOSING.
5. **What is CLOSING?** Simultaneous close: we acked their FIN, ours isn't acked yet.
6. **Why 2·MSL?** Covers a worst-case round (our ACK out + peer's FIN retransmission back) and quarantines
   old duplicates (§B).
7. **What's MSL?** Maximum Segment Lifetime (~2 min); TTL-bounded.
8. **Which side accumulates TIME_WAIT sockets?** The active closer — typically a server that closes each
   connection.
9. **How do we avoid the close storm?** Keep-alive (don't close), or make the client close (§H).
10. **What is `SO_REUSEADDR`?** Allows rebinding a local port in TIME_WAIT (server restart); safe.
11. **What is `tcp_tw_reuse`?** Safe reuse of a TIME_WAIT 4-tuple for a new outbound conn, guarded by
    timestamps.
12. **Why was `tcp_tw_recycle` removed?** It broke NATed clients (shared IP, unrelated timestamp clocks).
13. **What is half-close?** `shutdown(SHUT_WR)`: done sending, still receiving (§E).
14. **Why do we collapse CLOSE_WAIT?** An echo server has nothing to send after the peer closes.
15. **What's a CLOSE_WAIT leak?** An app that got a FIN but never `close()`d; sockets pile up in
    CLOSE_WAIT.
16. **What triggers TIME_WAIT → CLOSED?** The clock (2·MSL) in `on_tick`, not a packet.
17. **Why did TIME_WAIT expiry need Day 6's event loop?** It's a packet-less, time-driven transition.
18. **Is our FIN retransmitted if lost?** Yes, since Day 12 (queued in the RetxQueue).
19. **Does our binary ever actively close?** Not the echo path; the HTTP server (Day 11) does.
20. **What's TIME_WAIT assassination?** An injected RST cutting TIME_WAIT short (RFC 1337); PAWS defends.
21. **Can a FIN carry data?** Yes; we send bare FINs, real stacks may combine.
22. **What ack does our FIN carry?** `RCV.NXT` (we acknowledge all received data).
23. **What ack must the peer's ACK of our FIN carry?** `SND.NXT` (one past our FIN).
24. **Why compute `acked_our_fin` once?** Both the FIN and bare-ACK branches use it.
25. **What's the Two Generals connection?** TIME_WAIT bounds the impossibility of being certain your last
    message arrived (§F).

## L. Anki starter deck

```text
Q: Active vs passive closer?  A: active sends the first FIN; passive responds.
Q: Why only the active closer waits in TIME_WAIT?  A: its last act is a bare ACK, never acknowledged.
Q: Four active-closer states?  A: FIN_WAIT_1, FIN_WAIT_2, CLOSING, TIME_WAIT.
Q: Three outcomes from FIN_WAIT_1?  A: ACK-only→FIN_WAIT_2; peerFIN+ACK→TIME_WAIT; peerFIN only→CLOSING.
Q: What is CLOSING?  A: simultaneous close — we acked their FIN, ours not yet acked.
Q: Why 2·MSL?  A: worst-case our-ACK-out + peer-FIN-retransmit-back, and old-duplicate quarantine.
Q: What triggers TIME_WAIT → CLOSED?  A: the 2·MSL timer in on_tick (no packet).
Q: Why did that need an event loop?  A: it's a time-driven transition with no triggering packet.
Q: SO_REUSEADDR does what?  A: lets you rebind a local port still in TIME_WAIT (safe).
Q: tcp_tw_reuse safety condition?  A: TCP timestamps prove the new connection can't be confused.
Q: Why was tcp_tw_recycle removed?  A: it broke NATed clients (shared IP, different timestamp clocks).
Q: The close-storm fix?  A: keep-alive (don't close) or make the client the active closer.
Q: "You can't ACK an ACK" implies?  A: the active closer can't confirm its last ACK → must linger.
Q: CLOSE_WAIT pile-up means?  A: an app that received a FIN but never close()d (a leak).
```

## M. Glossary

- **Active close** — initiating teardown by sending the first FIN.
- **Passive close** — responding to the peer's FIN (Day 5).
- **FIN_WAIT_1 / FIN_WAIT_2** — active closer: FIN sent / FIN acked, awaiting peer FIN.
- **CLOSING** — simultaneous close; peer's FIN received before ours was acked.
- **TIME_WAIT** — the active closer's 2·MSL linger before CLOSED.
- **MSL** — Maximum Segment Lifetime (~2 min); TIME_WAIT is 2·MSL.
- **Half-close** — `shutdown(SHUT_WR)`: done sending, still receiving.
- **CLOSE_WAIT** — passive closer's state while the local app still has data to send.
- **`SO_REUSEADDR` / `tcp_tw_reuse` / `tcp_tw_recycle`** — TIME_WAIT-management knobs (last one removed).
- **TIME_WAIT assassination (RFC 1337)** — cutting TIME_WAIT short via an injected RST.
- **Two Generals' Problem** — the impossibility TIME_WAIT bounds with time.

## N. Reference tables

**N.1 — Who pays for what**

```text
   role       last segment sent   knows peer got it?   waits TIME_WAIT?
   ────────   ─────────────────   ──────────────────   ────────────────
   passive    FIN (acked)         yes (sees the ACK)   no
   active     ACK (not acked)     no                   yes (2·MSL)
```

**N.2 — Active-close sequence accounting (our FIN at seq S, peer FIN at seq F)**

```text
   packet           seq   ack    flags     effect
   ──────────────   ────  ─────  ───────   ───────────────────────────
   our FIN          S     RCV    FIN|ACK   SND.NXT = S+1; → FIN_WAIT_1
   peer ACK of FIN  F     S+1    ACK       → FIN_WAIT_2
   peer FIN         F     S+1    FIN|ACK   RCV.NXT = F+1
   our ACK          S+1   F+1    ACK       → TIME_WAIT
   (2·MSL timer)    —     —      —         → CLOSED
```

**N.3 — TIME_WAIT knobs**

```text
   knob              effect                                       safe?
   ───────────────   ──────────────────────────────────────────  ─────────────────────
   SO_REUSEADDR      rebind a local port in TIME_WAIT             yes (binding only)
   tcp_tw_reuse      reuse 4-tuple for new outbound conn          yes WITH timestamps
   tcp_tw_recycle    aggressive per-host recycle                  NO — removed (NAT breakage)
   shorter MSL       less waiting                                 risky (reopens duplicate window)
```

> Re-type the `FIN_WAIT_1/2`, `CLOSING`, and `TIME_WAIT` transitions from this chapter with the book
> closed, then `cargo test`. You now hold the entire lifecycle from both sides: open (Day 3), data
> (Day 4), passive close (Day 5), reliability (Day 6), and active close (Day 7) — and you can explain,
> from the "you can't ACK an ACK" theorem, exactly why TIME_WAIT must exist.
