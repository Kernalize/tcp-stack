# Doc 5 — TCP, Part 3: Connection Teardown (the Passive Close)

> Goal: close the connection cleanly. When the client sends `FIN`, we acknowledge it, send our own
> `FIN`, and on the client's final `ACK` we destroy the TCB. After this the whole lifecycle —
> **open → transfer → close** — works end to end with a stock `nc`. This chapter teaches the *passive*
> close (the responder's side) in full, and maps the rest of the teardown machine that Doc 7 completes.

Opening a connection took three packets and a careful dance of sequence numbers (Doc 3). Closing is
the mirror image, and it is subtler than it looks, because TCP connections are **full-duplex**: closing
is really *two* independent half-closes, and the rules for who waits, who can still send, and how stray
old packets are kept from poisoning a reused address are where decades of TCP folklore (TIME_WAIT,
half-close, RST) live.

**Contents**

Volume I — the chapter
1. Closing, conceptually: full-duplex and the half-close
2. FIN consumes a sequence number
3. The closing states (full picture vs ours)
4. The passive close, number by number
5. TIME_WAIT — why it exists, why the passive closer skips it
6. The Rust: state transitions and reaping the TCB
7. The code, walked end to end
8. The full lifecycle, one diagram
9. Verification
10. Why this, not that
11. Honesty: what production does that we don't
12. Rebuild it yourself — checklist + exercises
13. What the next step adds

Volume II — the exhaustive reference
- A. The four-way close, exhaustively (active and passive)
- B. The teardown half of the 11-state machine
- C. TIME_WAIT in depth (2·MSL, the two reasons, the hazards)
- D. Simultaneous close and the CLOSING state
- E. Half-close, `shutdown`, and CLOSE_WAIT as a distinct state
- F. Graceful FIN vs abortive RST (and `SO_LINGER`)
- G. FIN consuming a sequence number, worked numerically
- H. A complete annotated teardown trace (hex + TCB)
- I. Comparison to real stacks — the TIME_WAIT problem
- J. Security — RST injection, FIN scans, off-path resets
- K. Performance — TIME_WAIT memory and port exhaustion
- L. Extended FAQ
- M. Anki starter deck
- N. Glossary
- O. Reference tables

---

# Volume I — the chapter

## 1. Closing, conceptually: full-duplex and the half-close

A TCP connection is **full-duplex**: two independent byte streams flow at once — client→server and
server→client. Each direction is closed *separately*. To close its sending direction, a side sends a
**`FIN`** ("I have no more data to send"), and that FIN is acknowledged like a byte. The other
direction stays open until *it* sends its own FIN. So a fully clean close is **four** control
exchanges:

```text
   A → B   FIN          "A is done sending"
   A ← B   ACK          "B heard A's FIN"
   A ← B   FIN          "B is also done sending"
   A → B   ACK          "A heard B's FIN"
```

But when the side responding to a FIN has *nothing more to send*, it can combine its ACK-of-their-FIN
with its own FIN into one segment — **three** packets instead of four. That is exactly our echo server:
the moment the client closes, the server has no pending data, so it bundles `ACK + FIN` and the close
collapses by one packet. (A side that *does* still have data to send must keep its half open and send
its FIN later — that's the distinct **CLOSE_WAIT** state and **half-close**, §E.)

The mental model to carry: **closing is not one event, it's two half-closes**, and almost every close
subtlety (who waits in TIME_WAIT, who may still send, graceful vs abortive) follows from which half
closes when.

## 2. FIN consumes a sequence number

Like `SYN`, a `FIN` occupies **one** position in the sequence space even though it carries no data —
the phantom byte "stream ends here." This makes its delivery reliable: the FIN can be acknowledged, lost
and retransmitted, and ordered relative to the data before it.

So when the client's FIN arrives with `seg.seq == RCV.NXT`, we advance `RCV.NXT` by **1** to "cover" the
FIN, and our acknowledgement carries `ack = RCV.NXT` (one past the FIN). Our *own* FIN likewise consumes
one of *our* sequence numbers, so after sending it we do `SND.NXT += 1`, and the peer's final ACK must
equal that new `SND.NXT`. Same "+1 for a flag" rule as the handshake's SYN.

A consequence worth noting: because the FIN is ordered in the sequence space *after* the last data byte,
all data sent before the FIN is delivered before the close takes effect — TCP guarantees you never lose
the tail of a stream to a close. The FIN can't "overtake" data.

## 3. The closing states (full picture vs ours)

The RFC's two closing paths, side by side:

```text
   active close (initiator)            passive close (responder — us, doc 5)
   ESTABLISHED                          ESTABLISHED
     │ send FIN                           │ recv FIN, send ACK
     ▼                                    ▼
   FIN_WAIT_1  ─recv ACK→ FIN_WAIT_2     CLOSE_WAIT
     │ recv FIN, send ACK                 │ (app finishes sending) send FIN
     ▼                                    ▼
   TIME_WAIT ──(2·MSL)──► CLOSED         LAST_ACK ─recv ACK→ CLOSED
```

Today we implement the **passive** side, *collapsed*: because an echo server has no more data the
instant the client closes, we go `ESTABLISHED → LAST_ACK` directly, sending `FIN|ACK` in one segment
(the ACK of their FIN + our FIN together), then `LAST_ACK → CLOSED` on their final ACK. We skip
**CLOSE_WAIT** as a *distinct* state because there is no interval during which a local application is
still writing — there is no local application, just the echo. (Doc 7 adds the *active* close —
our side initiating — with FIN_WAIT_1/2, CLOSING, and TIME_WAIT. The full state enum already exists in
the code; doc 5 reaches the passive subset.)

## 4. The passive close, number by number

Continuing the data-transfer example (client ISN 100, our ISS 0), after the client has sent `"hi"` and
we echoed it (so `RCV.NXT = 103`, `SND.NXT = 3`, `SND.UNA = 3`), the client closes:

```text
   client                                  us
     │  FIN,ACK  seq=103 ack=3              │  recv FIN (seq==RCV.NXT 103):
     │ ───────────────────────────────────►│    RCV.NXT = 104  (cover their FIN)
     │  FIN,ACK  seq=3  ack=104             │  send FIN|ACK (ack theirs + our FIN):
     │ ◄───────────────────────────────────│    SND.NXT = 4    (our FIN consumes seq 3)
     │                                      │    state = LAST_ACK
     │  ACK  seq=104 ack=4                  │  recv ACK (ack==SND.NXT 4):
     │ ───────────────────────────────────►│    state = CLOSED  (TCB reaped)
```

Why each number:

- The client's FIN carries `seq = 103` (the next sequence number after its last data byte). It's in
  order (`== RCV.NXT`), so we cover it: `RCV.NXT = 104`.
- Our `FIN|ACK` carries `ack = 104` ("I received your FIN, expecting 104 next" — there will be nothing,
  but the number is correct) and `seq = 3` (our next sequence number). Our FIN consumes seq 3, so
  `SND.NXT = 4`. We move to **LAST_ACK**.
- The client's final `ACK` carries `ack = 4` (== our `SND.NXT`), acknowledging our FIN. We move to
  **CLOSED**, and the TCB is removed from the table.

Three packets, the close mirror of the three-packet open.

## 5. TIME_WAIT — why it exists, why the passive closer skips it

The side that sends the **last ACK** — the *active* closer — does not go straight to CLOSED. It lingers
in **TIME_WAIT** for `2·MSL` (twice the Maximum Segment Lifetime; MSL is conventionally 2 minutes, so
the wait is ~4 minutes) before truly closing. Two reasons, both essential:

1. **Reliability of the final ACK.** If that last ACK is lost, the peer's FIN retransmits; TIME_WAIT
   keeps the TCB around to *re-ACK* it. Without the lingering TCB, the retransmitted FIN would hit a
   closed connection and earn a confusing **RST**, making the peer think the close failed.
2. **Old-duplicate protection.** It lets stray, delayed segments from *this* connection drain out of
   the network before the same 4-tuple can be reused, so a ghost segment from the old connection can't
   be mistaken for data on a new one. (This is the same hazard random ISNs guard against at open —
   Doc 3 §D.)

As the **passive** closer, we send the last *FIN* and receive the last *ACK*, so we end in CLOSED via
LAST_ACK and don't need TIME_WAIT — the *peer* (the active closer) is the one that waits. (When we
implement active close ourselves on Doc 7, we add TIME_WAIT and its 2·MSL timer. It is the classic
reason a busy server accumulates thousands of TIME_WAIT sockets — §C, §I.)

## 6. The Rust: state transitions and reaping the TCB

- **`State` is a small `Copy` enum.** Transitions are plain assignments (`self.state = State::LastAck`).
  No allocation, no indirection — the state machine is just a field.
- **The TCB's lifetime ends at CLOSED.** `on_segment` doesn't free anything; it sets `state = Closed`.
  The *owner* of the connection — the `HashMap<Quad, Connection>` in `main.rs` — checks
  `conn.state()` after each packet and `remove`s the entry when it's CLOSED. Ownership lives in the
  map; the connection is dropped (and its buffers/queues freed) when removed. This is the Rust way: the
  protocol logic decides *when* the connection is dead; the container decides *how* it's freed, via the
  `Drop` that running off the end of `remove` triggers.
- **The FIN is queued for retransmission.** The current code records our FIN in the retransmission
  queue (Doc 12) so a lost FIN is resent until acknowledged, rather than hanging the teardown. At doc 5
  the link is lossless so this isn't exercised, but the hook is there.

## 7. The code, walked end to end

`Connection::on_segment`, the ESTABLISHED branch gained a FIN case:

```text
   if FIN set and seg.seq == RCV.NXT:
       RCV.NXT += 1                                      # consume their FIN
       out = segment(seq=SND.NXT, ack=RCV.NXT, FIN|ACK)  # ack theirs + send ours
       SND.NXT += 1                                      # consume our FIN
       (queue our FIN for retransmission — Doc 12)
       state = LAST_ACK
       return out
```

and a new LAST_ACK branch:

```text
   if state == LAST_ACK and ACK set and seg.ack == SND.NXT:
       (drop our FIN from the retransmission queue)
       state = CLOSED
```

`main.rs` checks `conn.state()` after each packet and, when it's `CLOSED`, removes the TCB from the
`HashMap` — the connection is forgotten and its slot freed. The dispatch is unchanged: the same
`on_segment` handles open, data, and close; only the *return* (a packet to send) and the *side effect*
(a state change `main` observes) differ.

## 8. The full lifecycle, one diagram

```text
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
     │ ────────────────────────────────────►│  send FIN,ACK → LAST_ACK, RCV.NXT=104
     │  FIN,ACK seq=3 ack=104                  │
     │ ◄────────────────────────────────────│  SND.NXT=4
     │  ACK seq=104 ack=4                      │
     │ ────────────────────────────────────►│  CLOSED (TCB removed)
```

Every number here is produced and checked by the test suite. You built a TCP that a standard `nc` can
connect to, exchange data with, and close — the complete lifecycle.

## 9. Verification

`cargo test` proves the close offline. `passive_close_via_fin`:

- establishes, then sends the client's `FIN` (seq 101 in the minimal test);
- asserts our reply is `FIN|ACK`, `seq = 1`, `ack = 102` (their FIN at 101, +1), a valid TCP checksum,
  and state `LastAck`;
- sends the client's final `ACK` (ack 2) and asserts state `Closed`.

Live (your hands): `printf 'hi\n' | nc -q1 192.168.0.2 8080` — `nc` prints `hi` and then exits cleanly
(its close triggers the FIN exchange). The stack log shows the FIN, "state now LastAck", the final ACK,
"state now Closed", "removed from table". `sudo tcpdump -i tun0 -n` shows the FINs and ACKs with
matching seq/ack numbers.

## 10. Why this, not that

| Decision | We chose | Real TCP | Why / caveat |
|---|---|---|---|
| Close path | passive only, collapsed to LAST_ACK | active + passive, full state set | an echo server only ever *responds* to a close (Doc 7 adds active). |
| CLOSE_WAIT | fused with the FIN-ACK | a distinct state | there's no local app still writing, so no gap to model (§E). |
| TIME_WAIT | none (we're the passive closer) | 2·MSL on the active closer | the *peer* waits; we add it when we close actively (Doc 7, §C). |
| FIN with data | data branch + a separate bare-FIN branch | a segment can carry final data + FIN together | our echo never co-sends data and FIN; a real stack handles both at once. |
| RST | not sent at doc 5 | RST on bad/closed-port segments | added later (Doc 7 path); abortive close is §F. |
| Half-close | not supported (we close both ways at once) | app can close one direction, keep reading | needs CLOSE_WAIT as a real state (§E). |

## 11. Honesty: what production does that we don't

- **No distinct CLOSE_WAIT / half-close.** We fuse the ACK-of-FIN with our own FIN. A real stack
  enters CLOSE_WAIT, signals the app "peer closed" (a 0-byte `read`), and lets the app keep *sending*
  until it closes — the *half-close* (§E). A server that streams a large response *after* the client
  closes its request direction relies on this.
- **No graceful-vs-abortive choice.** We always close gracefully (FIN). Applications can force an
  *abortive* close (RST) to discard buffered data and skip TIME_WAIT (`SO_LINGER` with timeout 0, §F).
- **Simultaneous close not exercised at doc 5.** If both sides FIN at once you reach CLOSING (§D);
  the code grows to handle it (Doc 7).
- **No FIN-with-data.** A real final segment may carry the last bytes *and* the FIN; we separate them.
- **TIME_WAIT tuning.** Real stacks have `tcp_tw_reuse`, `SO_REUSEADDR`, and TIME_WAIT-assassination
  defenses (§C, §I) to manage the close storm of a busy server. We have none (we're the passive side).
- **Lingering reliability.** The current code *does* queue the FIN for retransmission (Doc 12), so a
  lost FIN is resent — a genuine reliability improvement over the original doc-5 fire-and-forget.

None of these change the doc-5 contract (a client can close and we tear down cleanly); they are the
breadth Doc 7 and beyond add.

## 12. Rebuild it yourself — checklist + exercises

**Blank-file checklist:**

- [ ] Why a connection close is *two* half-closes (full-duplex).
- [ ] Why FIN consumes a sequence number, and where the `+1`s go (theirs and ours).
- [ ] The passive path: ESTABLISHED → LAST_ACK → CLOSED, and which segment carries the ACK+FIN.
- [ ] Why TIME_WAIT exists and which side (active closer) waits.
- [ ] How `main` reaps a CLOSED TCB from the table.

**Exercises:**

- **E1.** Add `CLOSE_WAIT` as a real intermediate state: ACK the FIN immediately, and only send our
  FIN on a later `on_tick`. This sets up half-close (§E).
- **E2.** Send a `RST` for a segment to an unknown/closed connection (ties together with doc3 E2; §F).
- **E3.** Implement `TIME_WAIT` for an *active* close and explain the 2·MSL timer (preview of Doc 7;
  §C).
- **E4.** Handle a **FIN that carries data**: accept the trailing bytes, *then* process the FIN, in one
  segment.
- **E5.** Handle **simultaneous close**: from a state where we've sent our FIN, receive the peer's FIN
  and reach CLOSING → TIME_WAIT (§D).

## 13. What the next step adds

Doc 6 is **reliability**: keep unacknowledged data in a retransmission queue, drive a timer from a
non-blocking event loop, and resend on a retransmission timeout (RTO) computed adaptively (RFC 6298).
That is the change that lets the connection survive a *lossy* link — including a lost FIN, so the
teardown itself becomes reliable. Doc 7 then adds the **active close** (our side initiating) with
FIN_WAIT_1/2, CLOSING, and TIME_WAIT — completing the state machine sketched in §3.

---

# Volume II — the exhaustive reference

## A. The four-way close, exhaustively (active and passive)

The canonical close, with both sides' states, when neither side fuses (the general four-packet case).
`A` actively closes; `B` passively closes:

```text
   A (active closer)          packets                 B (passive closer)
   ───────────────────        ─────────────────       ───────────────────
   ESTABLISHED
     send FIN  ───────────────►  FIN, seq=u           ESTABLISHED
   FIN_WAIT_1                                            recv FIN: RCV.NXT=u+1
                              ◄───────────────  ACK      send ACK
   FIN_WAIT_2                    ACK, ack=u+1          CLOSE_WAIT
                                                         (app finishes sending)
                              ◄───────────────  FIN      send FIN, seq=v
     recv FIN: RCV.NXT=v+1       FIN, seq=v           LAST_ACK
     send ACK  ───────────────►  ACK, ack=v+1
   TIME_WAIT                                            recv ACK: CLOSED
     (wait 2·MSL)
   CLOSED
```

The **three-packet** collapse (our echo) happens when B has nothing to send when A's FIN arrives, so B
fuses its ACK and FIN: `FIN_WAIT_1 → (recv FIN|ACK) → TIME_WAIT` on A, and `ESTABLISHED → LAST_ACK →
CLOSED` on B (us). The four-packet form is what you see when the passive side streams a response after
the request half-closes.

## B. The teardown half of the 11-state machine

Zooming into the bottom of the full diagram (doc3-book.md §C):

```text
                         ESTABLISHED
                         /          \
            (we close)  /            \  (peer closes: recv FIN/send ACK)
                       ▼              ▼
                 FIN_WAIT_1       CLOSE_WAIT
                  /      \              \  (app close: send FIN)
       recv ACK /        \ recv FIN     ▼
               ▼          ▼            LAST_ACK
        FIN_WAIT_2     CLOSING            \  recv ACK
               \          \                ▼
       recv FIN \          \ recv ACK    CLOSED
                 ▼          ▼
              TIME_WAIT ◄───┘
                 │ 2·MSL
                 ▼
              CLOSED
```

- **FIN_WAIT_1** — we sent FIN, awaiting its ACK and/or the peer's FIN.
- **FIN_WAIT_2** — our FIN is acked; awaiting the peer's FIN.
- **CLOSING** — *simultaneous close*: we got the peer's FIN before our FIN was acked (§D).
- **CLOSE_WAIT** — peer closed; we acked; our app may still send (§E).
- **LAST_ACK** — we sent our FIN (from CLOSE_WAIT); awaiting its ACK.
- **TIME_WAIT** — the active closer's 2·MSL linger (§C).

Doc 5 reaches only ESTABLISHED → LAST_ACK → CLOSED (the fused passive path). Doc 7 reaches the rest.

## C. TIME_WAIT in depth (2·MSL, the two reasons, the hazards)

**Why 2·MSL?** The Maximum Segment Lifetime is the assumed maximum time a segment can survive in the
network (TTL-bounded; conventionally 2 minutes). Waiting *twice* MSL covers a full round trip of the
worst case: our last ACK could take up to MSL to arrive, and if it's lost, the peer's retransmitted FIN
could take up to MSL to come back — so 2·MSL guarantees that by the time we leave TIME_WAIT, both our
final ACK has been delivered (or re-sent) and any straggling segment from this connection has expired.

**The two jobs again, precisely:**

1. *Absorb the peer's FIN retransmission.* While in TIME_WAIT we still respond to a retransmitted FIN
   with another ACK. A CLOSED connection would instead send a RST, which the peer interprets as "the
   connection broke," not "the close completed."
2. *Quarantine old duplicates.* Any segment from this 4-tuple still wandering the network dies within
   MSL; 2·MSL ensures none can be alive when the 4-tuple is reused.

**The hazards (why TIME_WAIT is infamous):**

- **Accumulation.** The *active closer* holds the TIME_WAIT. A server that closes connections (e.g.
  HTTP/1.0 `Connection: close`) accumulates thousands of TIME_WAIT TCBs, consuming memory and ephemeral
  ports. Designs push the active close onto the *client* for this reason.
- **Port exhaustion.** A client making many short connections to one server can run out of ephemeral
  source ports, all stuck in TIME_WAIT. Mitigations: `tcp_tw_reuse` (reuse a TIME_WAIT for a new
  *outgoing* connection when safe via timestamps), `SO_REUSEADDR`, longer ephemeral ranges.
- **TIME_WAIT assassination (RFC 1337).** An injected RST can prematurely kill a TIME_WAIT, reopening
  the old-duplicate window. PAWS (Doc 16 timestamps) defends against the duplicate hazard.

We, as passive closer, never hold TIME_WAIT — which is precisely why a passive-only server is cheap to
close. Doc 7's active close is where we take on the cost.

## D. Simultaneous close and the CLOSING state

If both sides decide to close at the same time, both send FIN from ESTABLISHED and enter FIN_WAIT_1.
Each then receives the *other's* FIN before its own FIN is acked:

```text
   A: FIN_WAIT_1, recv peer FIN (not yet getting our ACK) → send ACK → CLOSING
   B: FIN_WAIT_1, recv peer FIN                            → send ACK → CLOSING
   each: recv ACK of our FIN → TIME_WAIT → (2·MSL) → CLOSED
```

**CLOSING** is the state "I've acked your FIN, but mine isn't acked yet." It's rare (needs both apps to
close within a round trip of each other) but the state machine handles it with no new packet types —
just the same FIN/ACK in a different interleaving. Our code adds CLOSING on Doc 7's active-close path.

## E. Half-close, `shutdown`, and CLOSE_WAIT as a distinct state

**Half-close** is closing *one* direction while keeping the other open. The API is
`shutdown(fd, SHUT_WR)`: "I'm done *sending*, but I'll keep *reading*." On the wire it's a FIN in one
direction only; the other stream keeps flowing.

The classic use is a request/response where the client sends a request, half-closes to signal "request
complete," and then reads a (possibly large) response the server streams *after* receiving the FIN. For
the server, this is exactly why **CLOSE_WAIT** must be a distinct state: the peer's FIN arrives, the
server ACKs it and enters CLOSE_WAIT, but the server's *application* keeps writing the response; only
when the app finishes and closes does the server send *its* FIN (CLOSE_WAIT → LAST_ACK).

Our echo server has no such gap — it has nothing to send once the client closes — so we *fuse*
CLOSE_WAIT into the FIN|ACK and never model it separately. A common real-world bug is an application
that forgets to close, leaving connections stuck in CLOSE_WAIT forever (the FIN is acked, but the app
never sends its FIN); seeing many CLOSE_WAIT sockets in `netstat` almost always means an app-level
close leak. Exercise E1 makes CLOSE_WAIT real in our stack.

## F. Graceful FIN vs abortive RST (and `SO_LINGER`)

There are two ways to end a connection:

- **Graceful close (FIN).** The four-way (or three-way fused) handshake above. Guarantees all data sent
  before the FIN is delivered and acknowledged. This is the default and what doc 5 implements.
- **Abortive close (RST).** Send a `RST` to immediately discard the connection — any unsent/unacked
  data is dropped, the peer gets "connection reset by peer," and there is **no TIME_WAIT**. Triggered
  by `SO_LINGER` with a zero timeout, by closing a socket with unread data, or by the stack when it
  receives a segment for a connection it has no record of (a closed port).

`SO_LINGER` controls the behavior of `close()`: by default `close()` returns immediately and the stack
delivers remaining data in the background; with `SO_LINGER` on and a non-zero timeout, `close()` blocks
until data is delivered or the timer expires; with a *zero* timeout it sends a RST (abortive). RST is
the right tool when the application knows the data is worthless (e.g. a protocol error) and wants to
skip both delivery and TIME_WAIT.

We send neither RST in the doc-5 path; the broader stack sends RST for segments to unknown/closed
connections (`build_rst`, used on the dispatch path). Exercise E2 wires RST into the close logic.

## G. FIN consuming a sequence number, worked numerically

Why the `+1`s land where they do, traced as sequence-space bookkeeping. Suppose before the close
`RCV.NXT = 103` (we've received the client's data through 102) and `SND.NXT = SND.UNA = 3` (our echo is
acked):

```text
   event                         seq/ack on the wire        our TCB after
   ───────────────────────────   ────────────────────────   ──────────────────────────
   client FIN (its phantom byte  seq=103 (==RCV.NXT)         RCV.NXT = 104  (FIN covered)
     occupies seq 103)           ack=3
   our FIN|ACK                   seq=3   ack=104             SND.NXT = 4    (our FIN at seq 3)
   client final ACK              seq=104 ack=4 (==SND.NXT)   state = CLOSED
```

The client's FIN sits at seq 103 — the next number after its last data byte (102) — so covering it
makes `RCV.NXT = 104`. Our FIN sits at *our* next number, seq 3, so after it `SND.NXT = 4`, and the
client's final ack must be exactly 4. Every `+1` is "the FIN occupies one sequence number," nothing
more.

## H. A complete annotated teardown trace (hex + TCB)

The three-packet passive close, TCP headers only, checksum/urgent as `··`. Client ISN 100, our ISS 0,
state at start: `RCV.NXT=103, SND.NXT=3, SND.UNA=3`.

```text
   ① C→U  FIN,ACK  seq=103 ack=3
      12 34 00 50 | 00 00 00 67 | 00 00 00 03 | 50 11 ff ff | ·· ·· 00 00
      sport 4660  | seq 103     | ack 3       | off5 F|A win | csum urg
      U TCB: RCV.NXT 103→104, state ESTABLISHED→LAST_ACK

   ② U→C  FIN,ACK  seq=3 ack=104
      00 50 12 34 | 00 00 00 03 | 00 00 00 68 | 50 11 04 00 | ·· ·· 00 00
      sport 80    | seq 3       | ack 104     | off5 F|A win | csum urg
      U TCB: SND.NXT 3→4 (our FIN in flight, queued for retransmit)

   ③ C→U  ACK  seq=104 ack=4
      12 34 00 50 | 00 00 00 68 | 00 00 00 04 | 50 10 ff ff | ·· ·· 00 00
      sport 4660  | seq 104     | ack 4       | off5 ACK win | csum urg
      U TCB: SND.UNA→4, state LAST_ACK→CLOSED (TCB reaped by main)
```

Flag byte `0x11` = FIN|ACK; `0x10` = ACK. The two `+1`s are visible: ①'s FIN at 103 → ②'s ack 104;
②'s FIN at 3 → ③'s ack 4.

## I. Comparison to real stacks — the TIME_WAIT problem

```text
   concept            real kernel (Linux/BSD)                    this stack (doc 5)
   ────────────────   ────────────────────────────────────────  ──────────────────────
   passive close      CLOSE_WAIT (distinct), app then closes      fused → LAST_ACK
   active close        FIN_WAIT_1/2 → TIME_WAIT (2·MSL)            Doc 7 adds it
   TIME_WAIT cost      per-TCB memory; ephemeral-port pressure     n/a (we're passive)
   mitigations         tcp_tw_reuse, SO_REUSEADDR, tw recycling    none
   half-close          shutdown(SHUT_WR); stream after peer FIN    not supported
   abortive close      RST via SO_LINGER 0 / unread data           RST only for unknown conns
   reap                TCB freed after TIME_WAIT/CLOSED            map.remove on CLOSED
```

The famous "TIME_WAIT problem" — a server drowning in TIME_WAIT TCBs — is a *server-actively-closes*
problem. The standard fixes are architectural (let the client close, use keep-alive to avoid closing at
all) plus the kernel knobs above. Our passive-only close sidesteps it entirely, which is a legitimate
design point for a request/response server, not a gap.

## J. Security — RST injection, FIN scans, off-path resets

- **RST injection.** A forged in-window RST tears down a live connection (a DoS, or censorship — some
  middleboxes inject RSTs to block traffic). The defense (RFC 5961) is to accept a RST only at the
  *exact* `RCV.NXT`, and to rate-limit "challenge ACKs" for near-misses. Our doc-5 stack doesn't
  validate incoming RSTs tightly; that's a later hardening.
- **FIN/NULL/Xmas scans.** Sending a FIN (or no-flags, or FIN+URG+PSH) to a *closed* port elicits a RST
  on many stacks, while an *open* port stays silent — a port-scanning technique (nmap `-sF`). Whether
  your stack replies reveals its state; correct behavior per RFC is to RST a non-SYN to a closed port.
- **TIME_WAIT assassination (§C).** An injected RST during TIME_WAIT can cut it short, reopening the
  old-duplicate window; PAWS (Doc 16) mitigates.
- **Resource exhaustion via half-open closes.** An attacker can open many connections and FIN them to
  drive CLOSE_WAIT/LAST_ACK churn; bounded TCB tables and timeouts defend.

The recurring lesson: every control segment (SYN, FIN, RST) is both a state transition and an
attacker-forgeable trigger, so each needs in-window validation — the immune system the later RFC 5961
work adds.

## K. Performance — TIME_WAIT memory and port exhaustion

- **TIME_WAIT memory** is the dominant teardown cost on a busy *active-closing* server: each lingering
  TCB is hundreds of bytes held for ~4 minutes. At thousands of closes per second that's millions of
  TCBs. We avoid it (passive close).
- **Ephemeral-port exhaustion** caps a client to ~28k–64k concurrent short connections per
  (dst IP, dst port) before ports stuck in TIME_WAIT run out; `tcp_tw_reuse` + timestamps reclaim them.
- **Close batching / keep-alive.** The cheapest close is the one you don't do: HTTP keep-alive
  (Doc 11) reuses one connection for many requests, amortizing handshake *and* teardown.
- **Our cost** is one state assignment and one `HashMap::remove` per close — O(1), no lingering. The
  honest trade is that we don't *do* the expensive part (TIME_WAIT) because we don't actively close.

## L. Extended FAQ

1. **Why is closing two half-closes?** TCP is full-duplex; each direction closes independently with its
   own FIN.
2. **Does FIN consume a sequence number?** Yes — one, like SYN; that's the `+1`.
3. **Why can a FIN not overtake data?** It's ordered after the last data byte in the sequence space.
4. **Why three packets, not four, for our close?** We fuse our ACK-of-their-FIN with our own FIN (no
   pending data).
5. **What is CLOSE_WAIT?** Peer closed, we acked, our app may still send; distinct when there's pending
   data (§E).
6. **Why do we skip a distinct CLOSE_WAIT?** An echo server has nothing to send after the client
   closes.
7. **Which side waits in TIME_WAIT?** The active closer (sends the last ACK). We're passive, so we
   don't.
8. **Why 2·MSL?** Covers a worst-case round trip so the final ACK is delivered and old duplicates
   expire (§C).
9. **What goes wrong without TIME_WAIT?** A retransmitted FIN hits a closed conn → RST; and old
   duplicates can poison a reused 4-tuple.
10. **What is half-close?** Closing one direction (`shutdown(SHUT_WR)`) while still reading (§E).
11. **What is an abortive close?** A RST that drops data and skips TIME_WAIT (`SO_LINGER` 0; §F).
12. **What is simultaneous close?** Both sides FIN at once → CLOSING → TIME_WAIT (§D).
13. **Can a segment carry data and FIN together?** Yes; we separate them, real stacks combine.
14. **How does the TCB get freed?** `main` removes it from the map when state is CLOSED; Rust drops it.
15. **Is our FIN retransmitted if lost?** Yes — it's queued in the retransmission queue (Doc 12).
16. **What ack does our FIN|ACK carry?** `RCV.NXT` = one past the client's FIN.
17. **What ack must the client's final ACK carry?** Our `SND.NXT` (one past our FIN).
18. **Why many CLOSE_WAIT sockets in netstat?** An app that received a FIN but never closed (a leak).
19. **Why many TIME_WAIT sockets?** A process actively closing many short connections.
20. **What is `SO_REUSEADDR`?** Allows binding a port still in TIME_WAIT (server restart).
21. **What is `tcp_tw_reuse`?** Reuse a TIME_WAIT for a new outgoing connection when timestamps make it
    safe.
22. **Does a closed port send RST?** Per RFC, yes, for a non-SYN; our broader stack does via
    `build_rst`.
23. **What is a FIN scan?** Probing with a FIN to infer open/closed ports from RST-or-silence (§J).
24. **Does PSH matter at close?** No; the FIN flag drives the close, PSH is just a delivery hint.
25. **What's the minimal close in our code?** ESTABLISHED → (FIN) → LAST_ACK → (ACK) → CLOSED.

## M. Anki starter deck

```text
Q: How many half-closes in a TCP close?  A: two (full-duplex; each direction FINs separately).
Q: How many sequence numbers does a FIN consume?  A: one (like SYN).
Q: Our FIN|ACK ack value, given client FIN seq=103?  A: 104 (their FIN +1).
Q: Passive-close state path (echo server)?  A: ESTABLISHED → LAST_ACK → CLOSED.
Q: Which side enters TIME_WAIT?  A: the active closer (sends the last ACK).
Q: How long is TIME_WAIT?  A: 2·MSL (~4 minutes).
Q: Two reasons for TIME_WAIT?  A: re-ACK a retransmitted FIN; quarantine old duplicates.
Q: What is CLOSE_WAIT?  A: peer closed, we acked, our app may still send.
Q: Why do we fuse CLOSE_WAIT into FIN|ACK?  A: an echo server has no more data to send.
Q: What is half-close?  A: shutdown(SHUT_WR): done sending, still reading.
Q: Graceful vs abortive close?  A: FIN (delivers data, TIME_WAIT) vs RST (drops data, no TIME_WAIT).
Q: What is simultaneous close's state?  A: CLOSING (acked their FIN, ours not yet acked).
Q: How is a CLOSED TCB freed?  A: main removes it from the HashMap; Rust drops it.
Q: Many CLOSE_WAIT sockets usually mean?  A: an app that received a FIN but never close()d.
```

## N. Glossary

- **FIN** — the flag/phantom-byte that closes one direction of the stream.
- **Half-close** — closing one direction (`shutdown(SHUT_WR)`) while keeping the other open.
- **Passive close** — responding to the peer's FIN (our role at doc 5).
- **Active close** — initiating the close by sending the first FIN (Doc 7).
- **CLOSE_WAIT** — peer closed; we acked; local app may still send.
- **LAST_ACK** — we sent our FIN (from CLOSE_WAIT); awaiting its ACK.
- **FIN_WAIT_1 / FIN_WAIT_2** — active closer: FIN sent / FIN acked, awaiting peer FIN.
- **CLOSING** — simultaneous close: peer's FIN received before ours was acked.
- **TIME_WAIT** — active closer's 2·MSL linger before CLOSED.
- **MSL** — Maximum Segment Lifetime (~2 min); TIME_WAIT is 2·MSL.
- **Graceful vs abortive close** — FIN (orderly) vs RST (immediate, drops data).
- **`SO_LINGER` / `SO_REUSEADDR` / `tcp_tw_reuse`** — close-behavior and TIME_WAIT-management knobs.

## O. Reference tables

**O.1 — Close states by role**

```text
   role            state path                                   waits TIME_WAIT?
   ─────────────   ──────────────────────────────────────────  ────────────────
   passive (us)    ESTABLISHED → [CLOSE_WAIT] → LAST_ACK → CLOSED   no
   active          ESTABLISHED → FIN_WAIT_1 → FIN_WAIT_2 → TIME_WAIT → CLOSED   yes
   simultaneous    ESTABLISHED → FIN_WAIT_1 → CLOSING → TIME_WAIT → CLOSED   yes
```

**O.2 — Sequence accounting at close (client FIN seq=F, our next seq=S)**

```text
   packet        seq   ack    flags    effect
   ───────────   ────  ─────  ──────   ───────────────────────────
   client FIN    F     —      FIN|ACK  RCV.NXT = F+1 (cover their FIN)
   our FIN|ACK   S     F+1    FIN|ACK  SND.NXT = S+1 (our FIN)
   client ACK    F+1   S+1    ACK      state = CLOSED
```

**O.3 — FIN vs RST**

```text
                graceful (FIN)              abortive (RST)
   ─────────    ────────────────────────   ─────────────────────────
   data         all prior data delivered    unsent/unacked data dropped
   handshake    3–4 way FIN/ACK exchange    single RST, no exchange
   TIME_WAIT    yes (active closer)          none
   trigger      close()                      SO_LINGER 0, unread data, closed port
   peer sees    orderly EOF                  "connection reset by peer"
```

> Re-type the FIN/LAST_ACK logic from this chapter, then `cargo test`. You now hold the whole picture:
> parsing (Doc 1), checksums + write (Doc 2), handshake (Doc 3), data (Doc 4), close (Doc 5) — a TCP
> connection a real `nc` opens, uses, and closes.
