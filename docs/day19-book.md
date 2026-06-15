# Day 19 — TCP, Part 17: Finishing the State Machine — Half-Close (CLOSE_WAIT) + RFC 5961

> Goal: make the teardown *correct*, and make the connection *hard to kill*. Two jobs that sound
> unrelated but are the same job — closing the gap between "passes our happy-path tests" and "is a
> real TCP endpoint."
>
> **Half-close.** Until today an incoming FIN was answered by a *fused* `FIN|ACK`: the instant the
> peer said "I'm done sending," we said "then so am I," and jumped straight to LAST_ACK. That is a
> shortcut, not the protocol. TCP is **two independent simplex pipes**; one side can stop sending
> while the other keeps going (`curl`'s upload finishing while the download continues; a shell
> pipeline draining after EOF). The correct path is **CLOSE_WAIT**: ACK the FIN, deliver EOF to the
> local application, and keep *our* send side open until the app itself decides to close.
>
> **RFC 5961.** A TCP connection is identified by a 4-tuple and a 32-bit sequence window. An off-path
> attacker who can *guess* those — and on a long-lived connection (BGP, a database link) they often
> can — could, under the original RFC 793 rules, tear the connection down with a single forged RST
> landing *anywhere* in the window, or force a reset with a forged SYN. RFC 5961 tightens both:
> honor only a RST whose sequence is *exactly* `RCV.NXT`, answer the merely-in-window ones with a
> **challenge ACK**, and never reset on a SYN — challenge it instead. We also add **RFC 1337**:
> ignore RSTs in TIME_WAIT, so a late duplicate can't assassinate it.
>
> This is the day the lifecycle stops being a demo and becomes a *state machine*: every arrival in
> every state has a defined, defensible answer.

**Contents**

Volume I — the chapter
1. The mental model: a connection is two one-way pipes
2. The four-way close, and the two roles
3. Where CLOSE_WAIT lives — and why we skipped it
4. The state machine, with CLOSE_WAIT drawn in
5. The FIN is a sequence-consuming control bit (the +1, again)
6. Piggybacked and out-of-order FINs — the bug we just fixed
7. The application's view: EOF, and who calls `close()`
8. Blind in-window attacks: the threat model
9. The RST acceptability rule, in three cases
10. The challenge ACK — why an *acknowledgement* defends against a *reset*
11. The in-window SYN rule
12. RFC 1337: TIME-WAIT assassination
13. The Rust: `match` on state, `Option<u32>`, `&self` vs `&mut self`
14. A fully worked half-close trace (`nc`), byte by byte
15. An annotated RST-attack trace — the challenge ACK in action
16. The code, walked end to end
17. Verification — the ten new tests, and why each exists
18. Why this, not that
19. Honesty: what production does that we don't
20. Rebuild it yourself — checklist + exercises
21. What the next day adds

Volume II — the exhaustive reference
- A. RFC 9293 §3.5–3.6: the close sequence, every transition
- B. The complete 11-state TCP diagram, and our subset
- C. RFC 5961 in full: the three blind attacks (RST, SYN, data)
- D. The challenge-ACK throttle, and CVE-2016-5696
- E. RFC 1337 TIME-WAIT assassination, worked
- F. Half-close in the sockets API: `shutdown()` vs `close()`
- G. Comparison to real stacks — Linux, FreeBSD, lwIP, smoltcp
- H. Security — our posture, and what we still don't defend
- I. Extended FAQ — thirty questions a careful reader asks
- J. Anki starter deck
- K. Glossary
- L. Reference tables

---

# Volume I — the chapter

## 1. The mental model: a connection is two one-way pipes

A TCP connection looks like one bidirectional channel, but the protocol models it as **two
independent simplex (one-way) byte streams** stacked back to back:

```text
        our send stream  ───────────────────────────────▶   peer's receive stream
   us  ◀───────────────────────────────  peer's send stream                       peer
```

Each direction has its own sequence space, its own window, its own FIN. The two directions are
*coupled only by convenience* — we piggyback the ACK for the inbound stream onto segments of the
outbound stream, because both share the same header. But they **close independently**. "I have no
more bytes to send you" (a FIN on our send stream) says nothing about whether we are still willing to
*receive* your bytes.

This is the whole idea behind **half-close**. When the peer sends its FIN, exactly one of the two
pipes is being shut: *the peer's send stream → our receive stream*. Our send stream is untouched. A
correct stack must therefore:

1. Acknowledge the FIN (the inbound pipe is now drained and closed).
2. Tell the local application it has reached **EOF** on reads.
3. **Keep our send side open** — the app may have a whole reply still to write.
4. Close our send side (send our own FIN) only when the application says so.

Yesterday's code collapsed steps 2–4 into "send our FIN immediately." For an echo server that
happens to be harmless, because an echo server genuinely has nothing left to say once the input
stops. But it is the wrong *shape*, and the wrong shape breaks the moment the application is anything
richer than an echo — an HTTP server still streaming a response body, a proxy draining a backend, a
shell still flushing output after the user hits Ctrl-D.

> The one-line version: **a FIN closes a direction, not a connection.** Today we stop treating the
> two directions as one.

## 2. The four-way close, and the two roles

Opening a connection is a *three*-way handshake (SYN, SYN-ACK, ACK) because the middle segment fuses
two messages. Closing is a *four*-way handshake, because each direction's FIN and its ACK are
genuinely separate events:

```text
   active closer (calls close first)                 passive closer
   ─────────────────────────────────                ──────────────────────────
   ESTABLISHED                                        ESTABLISHED
        │  ── FIN ──────────────────────────────▶
   FIN_WAIT_1                                              (app still reading)
        │  ◀──────────────────────────── ACK ──         CLOSE_WAIT
   FIN_WAIT_2                                         (app finishes, calls close)
        │  ◀──────────────────────────── FIN ──         LAST_ACK
        │  ── ACK ──────────────────────────────▶
   TIME_WAIT                                              CLOSED
        │  (2·MSL)
   CLOSED
```

Two roles, and which you play depends only on **who sends the first FIN**:

- The **active closer** sends FIN first. It traverses `FIN_WAIT_1 → FIN_WAIT_2 → TIME_WAIT → CLOSED`
  and is the one that pays the 2·MSL TIME_WAIT cost (Day 7). In our stack, the HTTP path is the
  active closer: after writing `200 OK` it calls `close()` itself.
- The **passive closer** receives the first FIN. It traverses `CLOSE_WAIT → LAST_ACK → CLOSED` and
  **never enters TIME_WAIT**. In our stack, the echo path is the passive closer: the user closes
  `nc`, we get the FIN.

The fourth case is **simultaneous close** (both sides send FIN before receiving the other's):
`FIN_WAIT_1 → CLOSING → TIME_WAIT`. We've supported that since Day 7; it is untouched today.

The crucial asymmetry: the active closer's middle states (`FIN_WAIT_1/2`) are driven by the
*network* — it's waiting for the peer's ACK and FIN to arrive. The passive closer's middle state
(`CLOSE_WAIT`) is driven by the **local application** — it's waiting for *its own* program to call
`close()`. That difference is why CLOSE_WAIT is the single most famous "leak" state in all of
networking (§3).

## 3. Where CLOSE_WAIT lives — and why we skipped it

Re-read yesterday's FIN handling (the code we just replaced):

```rust
// OLD — the fused passive close
if th.flags & FIN != 0 && th.seq == self.recv.nxt {
    self.recv.nxt = self.recv.nxt.wrapping_add(1);          // consume the FIN
    let out = self.segment(self.send.nxt, self.recv.nxt, FIN | ACK, &[]);  // FIN *and* ACK
    self.send.nxt = self.send.nxt.wrapping_add(1);          // consume our FIN
    self.retx.record(/* … */);
    self.state = State::LastAck;                            // skip CLOSE_WAIT entirely
    return Some(out);
}
```

It does three things in one breath: ACKs the peer's FIN, sends *our* FIN, and jumps to LAST_ACK. It
fuses the passive closer's entire `CLOSE_WAIT → LAST_ACK` into a single segment. The honest comment
in the old code admitted it: *"A full stack would pass through CLOSE_WAIT while the local app
finishes sending."*

Why is the real thing important?

- **It's where the application's `close()` belongs.** CLOSE_WAIT means "the kernel has received the
  peer's FIN and ACKed it; it is now waiting for *you*, the application, to call `close()`." If your
  program forgets — a missing `defer conn.Close()`, an exception that skips cleanup — the connection
  sits in CLOSE_WAIT *forever*. The peer is gone, but you still hold the socket, the file
  descriptor, and the kernel memory. A server with a `close()` bug accumulates CLOSE_WAIT sockets
  until it runs out of file descriptors and falls over. Every backend engineer eventually learns to
  read `ss -tan | grep CLOSE-WAIT` as "find the resource leak."

- **It's the only place half-close can happen.** Sending data *after* the peer's FIN — the defining
  feature of a real connection — is only possible if there is a state that means "peer done,
  we're not." That state is CLOSE_WAIT.

So today we split the fusion back into its two real steps:

```rust
// NEW — honor the FIN: pure ACK, enter CLOSE_WAIT, signal EOF; our send side stays open
if self.state == State::Established && self.pending_fin == Some(self.recv.nxt) {
    self.recv.nxt = self.recv.nxt.wrapping_add(1);   // consume the FIN
    self.pending_fin = None;
    self.peer_fin = true;                            // application now sees EOF
    self.state = State::CloseWait;
    return Some(self.segment(self.send.nxt, self.recv.nxt, ACK, &[]));  // *pure* ACK
}
```

and let `close()` do the second step, now legal from CLOSE_WAIT as well as ESTABLISHED:

```rust
let next = match self.state {
    State::Established => State::FinWait1,   // active close
    State::CloseWait  => State::LastAck,     // passive close, second half
    _ => return None,
};
```

The echo application closes the moment its send buffer drains (`main.rs`):

```rust
if conn.state() == tcp::State::CloseWait && conn.send_buffer_empty() {
    if let Some(fin) = conn.close(now_ms) { iface.send(&fin)?; }
}
```

For an echo server the two steps still happen within microseconds of each other — but now they are
*two steps*, each correct on its own, and an application that wanted to keep sending could.

## 4. The state machine, with CLOSE_WAIT drawn in

Here is our complete connection lifecycle as of today. Boxes are `State` variants; edges are labeled
`trigger / action`.

```text
                              passive open (recv SYN)
                  ┌───────────────────────────────────────────┐
                  │                                            ▼
              ( start )                                   ┌──────────┐
                  │  active open: send SYN                 │ SYN_RCVD │
                  ▼                                        └────┬─────┘
            ┌──────────┐   recv SYN-ACK / send ACK              │ recv ACK
            │ SYN_SENT │──────────────────────────────┐        │
            └────┬─────┘                               ▼        ▼
                 │ recv RST(acks SYN)            ┌──────────────────┐
                 ▼                               │   ESTABLISHED    │
              CLOSED                             └───┬──────────┬───┘
                                        recv FIN /   │          │  app close() /
                                        send ACK     │          │  send FIN
                                                     ▼          ▼
                                              ┌────────────┐  ┌────────────┐
                                              │ CLOSE_WAIT │  │ FIN_WAIT_1 │
                                              └─────┬──────┘  └──┬──────┬──┘
                                  app close() /     │            │      │ recv FIN /
                                  send FIN          │   recv ACK │      │ send ACK
                                                    ▼            ▼      ▼
                                              ┌──────────┐  ┌──────────┐ ┌─────────┐
                                              │ LAST_ACK │  │FIN_WAIT_2│ │ CLOSING │
                                              └────┬─────┘  └────┬─────┘ └────┬────┘
                                       recv ACK /  │   recv FIN /│            │ recv ACK
                                       (done)      │   send ACK  │            │
                                                   ▼             ▼            ▼
                                                CLOSED      ┌──────────┐   (TIME_WAIT)
                                                            │TIME_WAIT │◀──────┘
                                                            └────┬─────┘
                                                       2·MSL /   │
                                                                 ▼
                                                              CLOSED
```

The two new edges Day 19 adds are the split of the old single arrow `ESTABLISHED ──FIN──▶ LAST_ACK`
into `ESTABLISHED ──recv FIN──▶ CLOSE_WAIT ──app close()──▶ LAST_ACK`. Everything else was already
there. (And every *synchronized* box — ESTABLISHED through TIME_WAIT — now also has the invisible
self-edges "recv bad RST / challenge or drop" and "recv SYN / challenge," from RFC 5961.)

## 5. The FIN is a sequence-consuming control bit (the +1, again)

We met this with SYN on Day 3: a control flag that carries no data nonetheless **occupies one
sequence number**, so that its delivery is reliable in exactly the same way data is. FIN is the
other such bit.

Concretely, if the peer's last data byte was sequence `N−1`, the FIN sits at sequence `N`. To
acknowledge "I have received everything including your FIN," we send `ACK = N + 1`. That is why every
FIN-ack in our traces is `peer.seq + payload_len + 1`.

This produces a subtle but important fact: **the FIN's sequence number is not the segment's `seq`
field — it's `seq + payload_len`.** A pure FIN has `payload_len = 0`, so the FIN sits at `seq`
(yesterday's `th.seq == self.recv.nxt` check worked for that case). But a segment that carries data
*and* a FIN puts the data at `[seq, seq+len)` and the FIN at `seq+len`. Get this wrong and you either
drop FINs or acknowledge them one byte early. Our code computes it explicitly:

```rust
let fin_seq = th.seq.wrapping_add(payload.len() as u32);  // where the FIN actually sits
```

and only honors the FIN when `fin_seq == self.recv.nxt` *after* the segment's data has been
delivered — i.e. when everything up to the FIN is in order. That single line is the seam between the
"pure FIN" world we handled before and the "data+FIN, possibly reordered" world we handle now (§6).

## 6. Piggybacked and out-of-order FINs — the bug we just fixed

Yesterday's data path returned early:

```rust
// OLD
if !payload.is_empty() {
    /* deliver via reassembler */
    return Some(/* ACK */);     // ← returns here…
}
if th.flags & FIN != 0 && th.seq == self.recv.nxt {   // ← …so this never runs for a data+FIN segment
    /* close */
}
```

A TCP sender is *allowed*, and Linux routinely chooses, to set the FIN bit on its **last data
segment** rather than send a separate empty FIN. (Run `printf 'hi' | nc -q0 …` and watch
Wireshark: one segment, flags `PSH, ACK, FIN`.) Against yesterday's code that segment delivered its
data, returned an ACK from the data branch, and **silently dropped the FIN**. The connection would
never close on our side; the peer would retransmit its data+FIN forever (the data now a duplicate,
re-ACKed, the FIN still ignored) until it gave up. A latent, real-traffic deadlock.

Today the data branch no longer returns. It delivers, then *falls through* to the FIN handling:

```rust
let had_data = !payload.is_empty();
if had_data { /* deliver via reassembler, advance RCV.NXT */ }

if th.flags & FIN != 0 {
    let fin_seq = th.seq.wrapping_add(payload.len() as u32);
    /* CLOSE_WAIT retransmit re-ACK, or record where the FIN sits */
}
if self.state == State::Established && self.pending_fin == Some(self.recv.nxt) {
    /* honor it: consume, EOF, CLOSE_WAIT, pure ACK */
}
if had_data { return Some(/* data ACK + SACK */); }
```

The second subtlety is **reordering**. What if the data+FIN segment arrives *before* the bytes that
precede it? Say `RCV.NXT = 101` and a segment `seq=103, "XY", FIN` arrives — the FIN is at 105, but
we don't have `[101,103)` yet. We must **not** honor the FIN: there's a hole below it. Our
reassembler buffers "XY"; `RCV.NXT` stays 101; the FIN's position (105) is recorded but not yet
reached. We remember it in a one-slot field:

```rust
/// the sequence number the peer's FIN sits at, when it arrived out of order
pending_fin: Option<u32>,
```

When the gap-filler `seq=101, "AB"` finally arrives, the reassembler delivers "ABXY" in one shot,
`RCV.NXT` jumps to 105, and the honor check `self.pending_fin == Some(self.recv.nxt)` now fires —
in the *same* call, no retransmission needed. The connection closes correctly even though the FIN
overtook its own data on the wire.

Why a single `Option<u32>` and not a set? Because one peer can have **at most one FIN outstanding** —
a FIN is the last thing it will ever send; there is nothing after it to reorder past. (A real stack
folds this into the reassembler's bookkeeping; we keep it as a sibling field, which is simpler to
read and exactly as correct for a single sender. §19.)

## 7. The application's view: EOF, and who calls `close()`

From the application's side, half-close is the difference between these two POSIX idioms:

```c
shutdown(fd, SHUT_WR);   // send a FIN now: "I'm done sending." Still readable.
close(fd);               // drop the descriptor: FIN happens when the last reference goes away.
```

`shutdown(SHUT_WR)` is the half-close primitive — it sends our FIN while leaving the read side open.
`close()` tears down the descriptor. A clean client does `shutdown(SHUT_WR)` to signal end-of-input,
keeps reading until it sees EOF, *then* `close()`s. (See §F for the full sockets story.)

On the *receive* side, "the peer sent its FIN" is delivered to the application as **EOF**: `read()`
returns `0`. Our stack exposes that with one accessor:

```rust
pub fn peer_closed(&self) -> bool { self.peer_fin }
```

A future blocking `TcpStream::read` (the day11-book §11 exercise) returns `Ok(0)` exactly when
`peer_closed()` is true and the receive buffer is drained — the canonical Rust EOF. Our `main`
doesn't need the accessor because its "application" is hard-coded: the echo policy is *"once the peer
closes and my send buffer is empty, I have nothing more to say, so close."* That's
`state() == CloseWait && send_buffer_empty()`. A real application would instead be *told* about EOF
(via `peer_closed()`) and decide for itself — which is the whole point of separating the layers.

## 8. Blind in-window attacks: the threat model

Switch hats now, from correctness to security. The second half of today is **RFC 5961**, "Improving
TCP's Robustness to Blind In-Window Attacks."

The threat is an **off-path attacker**: someone who can *send* packets with a forged source address
but *cannot see* the packets flowing on the connection. (An on-path attacker who can read the traffic
already knows the sequence numbers and needs none of this; defending against them is TLS's job, not
TCP's.) The off-path attacker wants to inject a segment the receiver will accept. To be accepted, a
segment needs:

1. the right **4-tuple** (src IP, src port, dst IP, dst port), and
2. a sequence number inside the receiver's **window**.

For a long-lived, well-known connection — two BGP routers peering on port 179, a replication link, a
database connection pool — the 4-tuple is often guessable or even public. That leaves the window.
Here is the arithmetic that makes the attack practical:

```text
   sequence space:      2^32 = 4,294,967,296 values
   a generous window:   W = 65,535 (or far larger with window scaling, Day 17)
   guesses to land one packet in window:   2^32 / W ≈ 65,536
```

65,536 packets is *nothing* — milliseconds on a fast link. So an attacker who knows the 4-tuple can,
under the loose RFC 793 rules, reliably land a forged segment in the window. What can they do with
it?

- A forged **RST** in window → **tears the connection down** (RFC 793: any in-window RST resets).
  Drop a BGP session and you've caused a routing flap.
- A forged **SYN** in window → **forces a reset** (RFC 793 said an in-window SYN in a synchronized
  state is an error → reset).
- A forged **data segment** in window → **injects bytes** into the stream (the blind data injection
  attack; RFC 5961 §5).

RFC 5961 closes the first two cheaply (today's work) and tightens the third (we note our partial
stance in §19/§H). The trick in every case is the same: **demand more than "in window" before taking
a destructive action.**

## 9. The RST acceptability rule, in three cases

The RFC 793 rule was binary: an in-window RST resets the connection. RFC 5961 §3.2 replaces it with
three cases, distinguished by *how precisely* the RST's sequence number matches what we expect:

```text
   incoming RST, sequence = SEG.SEQ
   ────────────────────────────────────────────────────────────────────────
   SEG.SEQ  == RCV.NXT                  → exact: a legitimate RST → RESET (→ CLOSED)
   RCV.NXT  <  SEG.SEQ < RCV.NXT+RCV.WND → in window, not exact → send CHALLENGE ACK, do not reset
   otherwise                            → out of window → DROP silently
```

The logic: a *legitimate* RST from the real peer will always carry the exact next-expected sequence
number, because the real peer knows precisely where the conversation is. A *blind* attacker can only
land somewhere in the (e.g. 65,535-wide) window; hitting the single exact value `RCV.NXT` is
2^32-to-1 against per packet, not 65,536-to-1. So:

- **Exact** → almost certainly real → honor it.
- **In window but inexact** → suspicious → don't act, but don't ignore either: bounce a *challenge
  ACK* back (§10) and let the real peer, if there is one, prove itself.
- **Out of window** → can't be current → drop.

Our implementation is `on_rst`:

```rust
fn on_rst(&mut self, th: &TcpHeader) -> Option<Vec<u8>> {
    if self.state == State::SynSent {
        // RFC 9293 §3.10.7.3: in SYN_SENT a RST counts only if it acks our SYN.
        if th.flags & ACK != 0 && th.ack == self.send.nxt { self.state = State::Closed; }
        return None;
    }
    if self.state == State::TimeWait { return None; }  // RFC 1337 (§12)
    if th.seq == self.recv.nxt {
        self.state = State::Closed;                    // exact → reset
        None
    } else if self.in_window(th.seq) {
        Some(self.challenge_ack())                     // in window → challenge
    } else {
        None                                           // out of window → drop
    }
}
```

with the window test the standard acceptability interval on the wrapping circle:

```rust
fn in_window(&self, seq: u32) -> bool {
    let end = self.recv.nxt.wrapping_add(self.recv.wnd as u32);
    !seq::before(seq, self.recv.nxt) && seq::before(seq, end)   // RCV.NXT ≤ seq < RCV.NXT+RCV.WND
}
```

Two special states get special handling. **SYN_SENT** isn't synchronized yet — we have no `RCV.NXT`
to compare against — so RFC 9293 says a RST there is acceptable only if it acknowledges the SYN we
just sent (`ack == SND.NXT`); that's "connection refused" (no listener on the port). **TIME_WAIT**
gets RFC 1337 treatment (§12).

## 10. The challenge ACK — why an *acknowledgement* defends against a *reset*

The challenge ACK is the clever bit, and it's worth slowing down on, because at first it sounds
backwards: we received something that *might* be an attack, and our response is to send the sender a
helpful ACK telling it our exact state?

A **challenge ACK** is a bare ACK of our current position:

```text
   <SEQ = SND.NXT>  <ACK = RCV.NXT>  <CTL = ACK>
```

```rust
fn challenge_ack(&self) -> Vec<u8> {
    self.segment(self.send.nxt, self.recv.nxt, ACK, &[])
}
```

The defense works because of **who can hear the answer**:

- If the RST was **legitimate** (the real peer really did reset — say it crashed and rebooted, and
  no longer recognizes this connection), then the real peer *receives* our challenge ACK. To the
  real peer, that ACK refers to a connection it no longer has, which is itself an unacceptable
  segment — so it replies with a *fresh* RST. And that fresh RST is generated from the real peer's
  own state, so it carries the **exact** `RCV.NXT` we expect → it passes the exact-match test → we
  reset. The connection still dies, just one round-trip later, *correctly*.

- If the RST was **forged** by an off-path attacker, the challenge ACK flies to the *real* host at
  the spoofed address (which has no idea what's going on and ignores it), **not** to the attacker.
  The attacker, being off-path, never sees it. They cannot learn our exact `RCV.NXT`, and they
  cannot produce the exact-match RST that the exact-match test demands. The attack fails.

So the challenge ACK turns "land anywhere in the window" (≈65k guesses) back into "name the exact
sequence number" (≈4 billion guesses). It's a *liveness probe* that only the genuine endpoint can
answer. The same mechanism handles the in-window SYN (§11).

There is a sting in the tail — the challenge ACK is itself a signal, and emitting one per suspicious
segment without limit created a side-channel (CVE-2016-5696, §D). The modern fix is to rate-limit
challenge ACKs with a *randomized* budget. We don't (we're a teaching stack with one connection),
but we flag it loudly.

## 11. The in-window SYN rule

RFC 793's handling of a SYN arriving on an already-synchronized connection was: treat it as an error
and reset. That hands an attacker the same blind kill primitive as the RST — forge an in-window SYN,
the connection resets. RFC 5961 §4 replaces it with: **send a challenge ACK and drop the SYN.** Never
reset on a SYN. Notably, this is *irrespective of the SYN's sequence number* — any SYN to a
synchronized connection is anomalous and gets the same liveness probe.

```rust
if th.flags & SYN != 0 && self.is_synchronized() {
    return Some(self.challenge_ack());
}
```

`is_synchronized()` is "ESTABLISHED and every close state" — the states where both ISNs are fixed:

```rust
fn is_synchronized(&self) -> bool {
    matches!(self.state,
        State::Established | State::FinWait1 | State::FinWait2 |
        State::CloseWait | State::Closing | State::LastAck | State::TimeWait)
}
```

There's a delightful bonus: this exact rule *also* fixes a legitimate edge case. Suppose our SYN-ACK
reached the peer, the peer's final ACK reached us (we're ESTABLISHED), but then the peer
**retransmits its SYN-ACK** because *our* SYN-ACK's ACK to it was lost and it's still in SYN_RCVD.
That retransmitted SYN-ACK is a SYN arriving at our synchronized connection → we emit a challenge
ACK → which is precisely the ACK the peer needed to complete *its* handshake. The robustness rule and
the recovery behavior are the same code. (We place the check *after* the SYN_SENT branch, so a normal
SYN-ACK during our own active open is still handled as a handshake, not challenged.)

## 12. RFC 1337: TIME-WAIT assassination

One more, because it falls out naturally and the Manual calls for it. TIME_WAIT exists so that
delayed duplicate segments from the just-closed connection die out (2·MSL) before the same 4-tuple
can be reused — otherwise an ancient segment could be mistaken for data on a *new* connection.

But what if a delayed RST from the old connection arrives during TIME_WAIT? Under RFC 5961's exact
rule it could match `RCV.NXT` and reset us out of TIME_WAIT early — "assassinating" it. Now the
4-tuple is free immediately, a new connection can form on it, and the *other* delayed duplicates
TIME_WAIT was supposed to absorb can corrupt that new connection. RFC 1337's fix is blunt and
correct: **ignore all RSTs in TIME_WAIT.** A RST there can only be a ghost of the dead connection,
never a legitimate reset of anything live.

```rust
if self.state == State::TimeWait { return None; }   // before the exact/in-window checks
```

## 13. The Rust: `match` on state, `Option<u32>`, `&self` vs `&mut self`

A few Rust-specific notes on how today's logic is expressed.

**`match` for state transitions that share a tail.** `close()` needs different *next* states for
ESTABLISHED vs CLOSE_WAIT but identical FIN-building afterward. Rather than duplicate the body or
nest `if`s, we compute the next state first and fall through to shared code:

```rust
let next = match self.state {
    State::Established => State::FinWait1,
    State::CloseWait  => State::LastAck,
    _ => return None,            // early-return for "no FIN to send"
};
// … build & queue the FIN, identical for both …
self.state = next;
```

The `_ => return None` arm is doing real work: it's the type-checked guarantee that `close()` from,
say, TIME_WAIT is a no-op rather than an illegal FIN. The compiler forces us to handle every state
because `match` on an enum is exhaustive (we opt the rest out with `_`).

**`Option<u32>` for "maybe a deferred FIN."** `pending_fin: Option<u32>` encodes "there might be a
FIN waiting at some sequence number" in the type system — `None` is "no FIN outstanding," `Some(s)`
is "FIN at `s`." The honor check is a single, total comparison:

```rust
if self.state == State::Established && self.pending_fin == Some(self.recv.nxt) { … }
```

No sentinel value (we don't reserve a "magic" sequence number to mean "none"), no separate boolean
to keep in sync. `Option` *is* the boolean-plus-value, fused so they can't disagree. `Option<u32>`
derives `PartialEq`, so `== Some(x)` just works.

**`&self` vs `&mut self` — what each helper is allowed to touch.** `challenge_ack`, `in_window`, and
`is_synchronized` take `&self`: they *read* state and (for the challenge ACK) build bytes, but change
nothing. `on_rst` takes `&mut self` because it may transition to `Closed`. The borrow checker turns
this design intent into a compile-time fact: a `&self` method *cannot* accidentally mutate the TCB,
so when reading `challenge_ack` you know with certainty it has no side effects on the connection.
That's the same discipline that let `segment()` stay `&self` since Day 3 — building a packet reads
the connection but must never alter it.

**`matches!` for a set membership test.** `is_synchronized` could be a chain of `||`, but
`matches!(self.state, A | B | C)` reads as exactly what it is — "is the state one of these?" — and
the `|` patterns are checked against the enum so a typo'd variant won't compile.

## 14. A fully worked half-close trace (`nc`), byte by byte

Let `nc 192.168.0.2 8080` connect, the user type `hi` + Enter (3 bytes: `h`, `i`, `\n`), then
Ctrl-D / Ctrl-C to close. Our ISS is 0; the peer's ISN is 100. After the handshake:
`SND.UNA = SND.NXT = 1`, `RCV.NXT = 101`. We advertise `RCV.WND = 1024`.

```text
   #  dir  segment (flags seq/ack len)           our state      SND.UNA SND.NXT RCV.NXT  note
   ── ───  ─────────────────────────────────────  ────────────  ─────── ─────── ───────  ────────────────────────
   1  ▶us  PSH,ACK seq=101 ack=1 len=3 "hi\n"      ESTABLISHED    1       1       101      in-order data
   2  us▶  ACK     seq=1   ack=104 len=0           ESTABLISHED    1       1       104      RCV.NXT += 3
                                                    (app reads "hi\n", echoes it)
   3  us▶  PSH,ACK seq=1   ack=104 len=3 "hi\n"    ESTABLISHED    1       4       104      poll_transmit
   4  ▶us  ACK     seq=104 ack=4   len=0           ESTABLISHED    4       4       104      our echo acked
   5  ▶us  FIN,ACK seq=104 ack=4   len=0           ESTABLISHED →  4       4       105      peer half-closes
                                                    CLOSE_WAIT                              fin_seq=104==RCV.NXT
   6  us▶  ACK     seq=4   ack=105 len=0           CLOSE_WAIT     4       4       105      *pure* ACK, peer_fin=true
                                                    (app: send buffer empty → close())
   7  us▶  FIN,ACK seq=4   ack=105 len=0           LAST_ACK       4       5       105      our FIN, consumes seq 4
   8  ▶us  ACK     seq=105 ack=5   len=0           CLOSED         5       5       105      our FIN acked → done
```

Trace the FIN arithmetic at step 5: the peer's FIN segment has `seq = 104`, `len = 0`, so
`fin_seq = 104 + 0 = 104`, which equals `RCV.NXT`. We honor it: `RCV.NXT` becomes 105 (acknowledging
the FIN's sequence number), `peer_fin = true`, state → CLOSE_WAIT, and we emit a **pure ACK** at
step 6 — note flags `ACK`, *not* `FIN|ACK`. That's the visible difference from yesterday: there used
to be no step 6 and step 7 was fused into it.

Steps 6→7 are where the application lives. Between them, `main` notices `CLOSE_WAIT` with an empty
send buffer and calls `close()`, producing the FIN at step 7 (`seq = 4`, the value `SND.NXT` reached
after the echo). Had the application wanted to send more, steps 6→7 could have been separated by an
arbitrary number of data segments — that's half-close.

Compare the **data+FIN** variant, where the peer sets FIN on its last data segment (one fewer
packet):

```text
   #  dir  segment                                 our state                note
   ── ───  ─────────────────────────────────────  ───────────────────────  ────────────────────────────
   1  ▶us  PSH,ACK,FIN seq=101 ack=1 len=3 "hi\n"  ESTABLISHED→CLOSE_WAIT   data delivered, THEN FIN honored
   2  us▶  ACK seq=1 ack=105 len=0                 CLOSE_WAIT               one ACK covers data (104) + FIN (105)
```

At step 1: `had_data` delivers "hi\n" (`RCV.NXT` 101→104), then `fin_seq = 101 + 3 = 104 = RCV.NXT`
→ FIN honored (`RCV.NXT` 104→105), one ACK of 105. Yesterday this segment would have delivered the
data, ACKed 104, and **lost the FIN.**

## 15. An annotated RST-attack trace — the challenge ACK in action

Connection ESTABLISHED, `SND.NXT = 1`, `RCV.NXT = 101`, `RCV.WND = 1024` → window `[101, 1125)`.

```text
   event                                            on_rst decision           our state    reply
   ──────────────────────────────────────────────  ────────────────────────  ───────────  ───────────────────
   attacker forges RST seq=500 (in window, guessed) 500 ≠ 101, in [101,1125)  ESTABLISHED  CHALLENGE ACK
                                                                              (unchanged)  seq=1 ack=101
   ── the real peer (at 192.168.0.1) receives the challenge ACK ──
     · if it HAD reset: replies RST seq=101 (exact) 101 == RCV.NXT            → CLOSED      (none)
     · if it's healthy: the ACK is for live data    (normal processing)       ESTABLISHED  (no spurious RST)
   ── the off-path attacker never sees the challenge ACK, cannot send seq=101 ──
   attacker forges RST seq=5000 (out of window)     5000 ∉ [101,1125)         ESTABLISHED  (dropped silently)
   attacker forges SYN seq=anything                 synchronized → §4         ESTABLISHED  CHALLENGE ACK
```

The attacker's in-window RST achieves nothing but a challenge ACK sent to *someone else*. To actually
reset us they'd need `seq = 101` exactly — and the only way to know it is to be on-path, at which
point they didn't need the attack. That is the entire value RFC 5961 buys, for the price of one ACK.

## 16. The code, walked end to end

Everything lives in `src/tcp.rs`, with three lines of wiring in `src/main.rs`. Read it top to bottom
in the order a segment flows.

**The new state and fields.**

```rust
pub enum State { /* … */ Established, CloseWait, LastAck, /* … */ }

struct Connection {
    /* … */
    peer_fin: bool,            // peer sent FIN → application at EOF
    pending_fin: Option<u32>,  // sequence of an out-of-order FIN, honored when RCV.NXT reaches it
}
```

**Entry: `on_segment` now screens for attacks first.** After refreshing the timestamp clock, before
any state-specific logic, we run the two RFC 5961 gates. RST is checked before everything (it can
arrive in any state):

```rust
if th.flags & RST != 0 { return self.on_rst(th); }
```

then, *after* the SYN_SENT branch (so our own active-open SYN-ACK still works), the SYN gate:

```rust
if th.flags & SYN != 0 && self.is_synchronized() {
    return Some(self.challenge_ack());
}
```

**The synchronized data path now spans ESTABLISHED *and* CLOSE_WAIT**, because our send side is alive
in both — ACK processing, congestion control, and (importantly) the ability to *receive* ACKs for
data we send after the peer's half-close:

```rust
if self.state == State::Established || self.state == State::CloseWait {
    // PAWS, window tracking, ACK acceptance, dup-ACK / fast retransmit … (unchanged)
    // then the rewritten data + FIN handling (§6)
}
```

**`poll_transmit` and the persist timer** likewise gained `|| CloseWait`, so a half-closed
connection can still drain its send buffer and still probe a zero window:

```rust
if self.state != State::Established && self.state != State::CloseWait { return out; }   // poll_transmit
```

**`close()`** became dual-purpose (active from ESTABLISHED, passive-second-half from CLOSE_WAIT) via
the `match` of §13.

**The helpers**: `is_synchronized`, `in_window`, `challenge_ack`, `on_rst` — small, single-purpose,
`&self` where they only read.

**`main.rs`** adds the application's close policy after the existing HTTP-close block:

```rust
if conn.state() == tcp::State::CloseWait && conn.send_buffer_empty() {
    if let Some(fin) = conn.close(now_ms) { iface.send(&fin)?; /* → LAST_ACK */ }
}
```

That's the entire feature: ~70 lines of logic, every line on a path some real peer or attacker
exercises.

## 17. Verification — the ten new tests, and why each exists

`cargo test` proves all of this offline — no TUN, no sudo, no network — by constructing headers and
calling `on_segment` / `close` directly and asserting on the bytes and states. We updated two old
tests to the corrected close, and added ten. (Total: **111 passing**.)

Updated:

- **`passive_close_via_fin`** — now asserts the *two-step* close: FIN → pure `ACK` + `CloseWait`
  (with `peer_closed()` true), then `close()` → `FIN|ACK` + `LastAck`, then peer ACK → `Closed`. It
  used to assert the fused `FIN|ACK` straight to `LastAck`.
- **`passive_fin_retransmits_until_acked`** — the FIN that retransmits is now *our* FIN sent by
  `close()` from CLOSE_WAIT, not a fused one.

New — half-close:

- **`data_and_fin_in_one_segment_delivers_data_and_enters_close_wait`** — the bug fix: a
  `PSH,ACK,FIN` segment must deliver its data *and* honor the FIN, ACKing through `data+FIN`.
- **`half_close_lets_local_side_keep_sending`** — after the peer's FIN we `write()` and
  `poll_transmit()` more data *in CLOSE_WAIT*, the peer ACKs it, and only then do we `close()`. This
  is the feature, asserted end to end.
- **`close_wait_reacks_a_retransmitted_fin`** — a duplicate FIN (our ACK was lost) is re-ACKed, not
  ignored, so the peer can finish.
- **`out_of_order_data_with_fin_defers_then_completes_the_close`** — a reordered data+FIN is
  *deferred* (stay ESTABLISHED, dup-ACK), then honored the instant the gap fills, delivering all
  bytes and reaching CLOSE_WAIT.

New — RFC 5961 / 1337:

- **`rst_at_rcv_nxt_resets_the_connection`** — exact-match RST → `Closed`, no reply.
- **`in_window_rst_is_challenged_not_honored`** — in-window inexact RST → challenge ACK
  (`seq=SND.NXT, ack=RCV.NXT`), state unchanged.
- **`out_of_window_rst_is_ignored`** — out-of-window RST → dropped, untouched.
- **`rst_in_time_wait_is_ignored`** — RFC 1337: drive a real active close to TIME_WAIT, then an
  exact-match RST is ignored.
- **`in_window_syn_gets_a_challenge_ack`** — SYN into ESTABLISHED → challenge ACK, no reset.
- **`syn_sent_rst_that_acks_our_syn_refuses_the_connection`** — SYN_SENT RST handling: refuse when
  it acks our SYN, ignore otherwise.

Each maps to one rule in §§6–12; together they pin every branch of the new logic.

## 18. Why this, not that

**Why a distinct CLOSE_WAIT instead of keeping the fused close?** Because the fusion is only correct
for applications that have nothing to send after EOF. The state machine should be correct for *all*
applications; the echo server's "close immediately" is then a one-line *policy* on top of a correct
mechanism, not a shortcut baked into the mechanism. (See §3.)

**Why honor only `seq == RCV.NXT` for RST, not the whole window?** Because "in window" is ~65k
guesses for an attacker and "exact" is ~4 billion. The exact rule is the entire security delta of
RFC 5961 §3.2. The cost is one extra round trip for a *legitimate* mid-window RST (rare), via the
challenge ACK. (See §9.)

**Why answer a suspicious RST with an ACK rather than just dropping it?** Dropping a *legitimate*
in-window RST would leave us hung on a connection the peer has abandoned. The challenge ACK is the
liveness probe that lets a real peer prove the reset and lets a forged one fail. (See §10.)

**Why never reset on a SYN?** Because resetting on an in-window SYN is itself the attack primitive.
Challenge instead; the real peer (if it restarted) answers with a proper RST. As a bonus the same
rule recovers a lost handshake ACK. (See §11.)

**Why `pending_fin: Option<u32>` and not tracking the FIN in the reassembler?** A single pending FIN
is all one sender can have outstanding, and a sibling field keeps the reassembler focused on *data*.
A production stack integrates it (so a FIN can ride a fragment that itself fills a deeper hole), but
the externally observable behavior is identical for a single sender. (See §6, §19.)

**Why a one-slot pending FIN and not a flag "saw a FIN somewhere"?** Because we must honor it *at the
right sequence number*. A flag would lose *where* the FIN is, and we'd risk honoring it before its
preceding bytes arrived — exactly the reordering bug. Storing the sequence makes "is it time yet?" a
total comparison.

## 19. Honesty: what production does that we don't

In the spirit of every chapter — here is the gap between our correct *core* and a hardened stack.

- **RFC 5961 §5 (blind data injection) is only partial.** We tightened *RST* and *SYN*; we did **not**
  tighten *data/ACK* acceptance to RFC 5961 §5's stricter ACK window
  (`SND.UNA − MAX.SND.WND ≤ SEG.ACK ≤ SND.NXT`) with a challenge ACK on violation. We still use the
  Day 8 `between(SND.UNA, ACK, SND.NXT)` acceptance, which is RFC 793-grade. An attacker who can also
  guess the ACK number could still attempt blind data injection. (Exercise E4.)
- **No challenge-ACK rate limiting.** RFC 5961 §3 recommends throttling challenge ACKs; doing it with
  a *shared, non-random* counter created CVE-2016-5696 (§D). We emit one per trigger, unlimited.
  Fine for one teaching connection; unacceptable at scale.
- **CLOSE_WAIT has no timeout.** A real stack (and the OS) will eventually reap a connection stuck in
  CLOSE_WAIT, and applications get `SO_KEEPALIVE`. Ours waits forever for the app to `close()` — our
  app always does, but a buggy one would leak. (FIN_WAIT_2 has the same issue, with the famous
  `tcp_fin_timeout`.)
- **Half-close is mechanism-only.** We *support* sending after the peer's FIN, but our `main`'s
  application is a hard-coded echo that never wants to. There's no `shutdown(SHUT_WR)` API yet, no way
  for a program to half-close on purpose. That's the `TcpStream` veneer (day11-book §11).
- **No `LISTEN` state.** A passively-opened connection that receives a RST in SYN_RCVD goes straight
  to `Closed` (we delete the TCB); a stack with a real listener returns to `LISTEN` to accept the
  next SYN.
- **RST generation is still minimal.** We send a polite RST for segments to *unknown* connections
  (Day 4's `build_rst`), but we don't, e.g., RST a connection whose app aborted; we only ever close
  gracefully with FIN.
- **No simultaneous-open, no data on SYN (TFO).** Out of scope, as before.

None of these are bugs in what we built; they are the next layers. The state machine is now
*correct* for the paths it claims — which it was not, yesterday, for a piggybacked FIN.

## 20. Rebuild it yourself — checklist + exercises

Close the book and rebuild today's delta from a blank diff. You should be able to:

**Checklist**

- [ ] Add `State::CloseWait` between `Established` and `LastAck`.
- [ ] Add `peer_fin: bool` and `pending_fin: Option<u32>` to the TCB; initialize both in `accept`
      and `connect`.
- [ ] Split the FIN handler: deliver data first (no early return), compute `fin_seq = seq + len`,
      record it in `pending_fin` when `≥ RCV.NXT`, and honor it (consume, `peer_fin = true`,
      → CLOSE_WAIT, **pure ACK**) when `pending_fin == RCV.NXT`.
- [ ] Re-ACK a retransmitted FIN in CLOSE_WAIT.
- [ ] Make `close()` legal from CLOSE_WAIT (→ LAST_ACK) as well as ESTABLISHED (→ FIN_WAIT_1).
- [ ] Let `poll_transmit` and the persist timer run in CLOSE_WAIT.
- [ ] Add `on_rst`: SYN_SENT (ack-our-SYN → Closed), TIME_WAIT (ignore, RFC 1337), else
      exact→reset / in-window→challenge / out→drop.
- [ ] Add the in-window SYN → challenge ACK gate, *after* the SYN_SENT branch.
- [ ] Wire `main`: in CLOSE_WAIT with an empty send buffer, `close()`.
- [ ] `cargo test` green (111), `cargo clippy -- -D warnings` clean.

**Exercises**

1. **E1 — half-close for real.** Add `Connection::shutdown_write()` that sends our FIN from
   ESTABLISHED → FIN_WAIT_1 *without* closing the read side, and a test that we still deliver inbound
   data afterward (active half-close, the mirror of today's passive one).
2. **E2 — CLOSE_WAIT timeout.** Give CLOSE_WAIT (and FIN_WAIT_2) a timer in `on_tick` that RSTs and
   reaps the connection after N seconds. Test that a connection abandoned in CLOSE_WAIT is eventually
   collected.
3. **E3 — challenge-ACK throttle.** Add a per-connection challenge-ACK budget (say 1 per 500 ms) and
   a test that the second challenge within the window is suppressed. Then read §D and explain why the
   budget must be *randomized* in a real stack.
4. **E4 — RFC 5961 §5 (data).** Tighten ACK acceptance to the §5 window and emit a challenge ACK on a
   violation; test that an ACK far below `SND.UNA` is challenged, not silently accepted.
5. **E5 — the data+FIN on the wire.** With the live stack running, `printf 'hi' | nc -q0
   192.168.0.2 8080` and capture with `tcpdump -i tun0 -X`. Find the single segment with flags
   `[P.F]` and confirm our one ACK covers both the data and the FIN.

Make Anki cards from whatever you got wrong rebuilding — especially the `fin_seq = seq + len`
arithmetic and the three RST cases; those are the two things people misremember.

## 21. What the next day adds

The state machine is correct; the obvious next reach is **modern congestion control** — upgrading our
RFC 5681 Reno (Day 10) to **NewReno** (RFC 6582), so a *single* fast-recovery episode survives
*multiple* losses in one window via partial-ACK handling, instead of collapsing. After that, the
**RFC 6675 SACK scoreboard** (the `pipe` estimator that keeps a fast link full *during* recovery) is
the natural partner to Day 18's selective ACKs — together they're how a real connection sustains
throughput across loss. Alternatively, the **`TcpListener`/`TcpStream` blocking veneer** (day11-book
§11) turns everything we've built into an API a program can actually call — and is where the
half-close *mechanism* from today finally gets an application that uses it on purpose.

---

# Volume II — the exhaustive reference

## A. RFC 9293 §3.5–3.6: the close sequence, every transition

RFC 9293 (which obsoletes RFC 793) specifies "closing a connection" in §3.5 and the state changes in
the per-state event tables of §3.10. The relevant transitions, as event/action pairs:

```text
   state         event                              action                              → state
   ───────────   ────────────────────────────────  ──────────────────────────────────  ──────────
   ESTABLISHED   app close                          send FIN                            FIN_WAIT_1
   ESTABLISHED   recv FIN                            send ACK                            CLOSE_WAIT
   FIN_WAIT_1    recv ACK of FIN                     —                                   FIN_WAIT_2
   FIN_WAIT_1    recv FIN (not yet our ACK)          send ACK                            CLOSING
   FIN_WAIT_1    recv FIN + ACK of our FIN           send ACK                            TIME_WAIT
   FIN_WAIT_2    recv FIN                            send ACK                            TIME_WAIT
   CLOSING       recv ACK of FIN                     —                                   TIME_WAIT
   CLOSE_WAIT    app close                           send FIN                            LAST_ACK
   LAST_ACK      recv ACK of FIN                     —                                   CLOSED
   TIME_WAIT     2·MSL timeout                       delete TCB                          CLOSED
```

Note the structural symmetry: FIN_WAIT_1 is the active mirror of CLOSE_WAIT+LAST_ACK fused (the
active side can receive the peer's FIN at any sub-step, hence the three FIN_WAIT_1 exits). The
passive side is simpler because it has already received the peer's FIN by the time it's in
CLOSE_WAIT.

**What each side counts.** A FIN consumes one sequence number on the *sender's* stream. So the active
closer's `SND.NXT` advances by 1 when it sends FIN; the passive closer's `RCV.NXT` advances by 1 when
it receives one; and each side's ACK of the other's FIN is `that FIN's seq + 1`.

## B. The complete 11-state TCP diagram, and our subset

The canonical RFC 793 diagram has eleven states. Ours implements nine of them (all but `LISTEN` and
the brief `SYN_RCVD`-from-`LISTEN` nuance, since our passive open creates the TCB directly on the
SYN):

```text
   state          we have it?   role
   ────────────   ───────────   ──────────────────────────────────────────────
   CLOSED         implicit      no TCB in the table = closed
   LISTEN         ✗             we create a TCB per SYN instead of a listener
   SYN_SENT       ✓             active open, awaiting SYN-ACK
   SYN_RCVD       ✓             passive open, awaiting final ACK
   ESTABLISHED    ✓             data transfer
   FIN_WAIT_1     ✓             active close, FIN sent, awaiting ACK/FIN
   FIN_WAIT_2     ✓             active close, our FIN acked, awaiting peer FIN
   CLOSE_WAIT     ✓ (Day 19)    passive close, peer FIN acked, app to close
   CLOSING        ✓             simultaneous close
   LAST_ACK       ✓             passive close, our FIN sent, awaiting ACK
   TIME_WAIT      ✓             active close complete, 2·MSL linger
```

The classic ASCII rendering, for reference (active-close path on the left, passive on the right):

```text
                                  +---------+
                                  | CLOSED  |
                                  +---------+
                          passive   |    |   active: send SYN
                          (recv SYN)|    |
                              +-----+    +-----+
                              v                v
                        +----------+      +----------+
                        | SYN_RCVD |      | SYN_SENT |
                        +----------+      +----------+
                              | recv ACK     | recv SYN-ACK / send ACK
                              +-----+  +-----+
                                    v  v
                                +-------------+
                                | ESTABLISHED |
                                +-------------+
                   recv FIN /      |       | app close /
                   send ACK        |       | send FIN
                        +----------+       +----------+
                        v                             v
                  +------------+                +------------+
                  | CLOSE_WAIT |                | FIN_WAIT_1 |
                  +------------+                +------------+
                   app close /|                  |  |   |
                   send FIN   |       recv ACK   |  |   | recv FIN / send ACK
                        v     |          +-------+  |   +-------+
                  +----------+|          v          |           v
                  | LAST_ACK ||    +------------+    |     +---------+
                  +----------+|    | FIN_WAIT_2 |    |     | CLOSING |
                   recv ACK / |    +------------+    |     +---------+
                   (done)     |     recv FIN /|      |   recv ACK |
                        v     |     send ACK  |      |            |
                    +--------+|               +------+------------+
                    | CLOSED |◀──┐                   v
                    +--------+   │             +-----------+
                                 │   2·MSL     | TIME_WAIT |
                                 └─────────────+-----------+
```

## C. RFC 5961 in full: the three blind attacks

RFC 5961 (Aug 2010) addresses three blind in-window attacks. The unifying principle: *raise the bar
from "in window" to "exact" for any state-destroying action, and use a challenge ACK to let the
genuine peer re-prove itself.*

**§3 — Blind RST attack.** Covered in §9. Rule: exact `RCV.NXT` → reset; in-window inexact →
challenge ACK; out-of-window → drop.

**§4 — Blind SYN attack.** Covered in §11. Rule: any SYN in a synchronized state → challenge ACK and
drop, irrespective of sequence number. (The peer responds with a real RST if it genuinely restarted.)

**§5 — Blind data injection.** The hardest. An attacker who guesses the 4-tuple *and* lands an ACK in
the acceptable ACK window could inject data. RFC 5961 §5 tightens the *ACK* acceptance test:

```text
   RFC 793 (loose):    SND.UNA  <  SEG.ACK  ≤ SND.NXT
   RFC 5961 §5 (tight): SND.UNA − MAX.SND.WND ≤ SEG.ACK ≤ SND.NXT
                        ── anything outside this → send a challenge ACK, drop the segment
```

The §5 window is deliberately *wider on the low side* (it tolerates old duplicate ACKs) but bounded,
and crucially it pairs with a challenge ACK so an out-of-bounds ACK can't be used as a probe. We
implement §3 and §4; §5 is exercise E4 (we currently use the RFC 793 acceptance from Day 8).

A summary table:

```text
   attack (RFC 5961 §)   forged bit   old (793) effect       new (5961) defense
   ───────────────────   ──────────   ────────────────────   ──────────────────────────────────
   §3 blind reset        RST          in-window RST → reset   exact→reset; in-window→challenge
   §4 blind SYN          SYN          in-window SYN → reset   any SYN → challenge, never reset
   §5 blind data inject  ACK+data     in-window ACK → accept  tighten ACK window + challenge   (partial here)
```

## D. The challenge-ACK throttle, and CVE-2016-5696

RFC 5961 §3 says implementations SHOULD rate-limit challenge ACKs to avoid being turned into a
reflection/amplification tool. Linux implemented this with a **global** counter (`sysctl_tcp_
challenge_ack_limit`, default 100/sec) shared across *all* connections.

That shared, deterministic counter was itself a side channel. **CVE-2016-5696** (2016, "Off-Path TCP
Exploits") showed that an off-path attacker could *deliberately exhaust* the global challenge-ACK
budget with traffic to a connection it controlled, then observe — by whether a challenge ACK still
came back — whether a *different*, targeted connection existed and even infer its sequence numbers,
one bit of information at a time. A defense against blind attacks had introduced a new blind
inference channel.

The fix: make the limit **per-connection** and **randomized** (Linux now perturbs the budget so the
count can't be inferred). The lesson worth internalizing: *a security mechanism that emits an
observable, deterministic signal can become an oracle.* Our stack emits one challenge ACK per
trigger with no limit at all — wrong for production (it's a reflection vector), but it has no shared
state to leak. Exercise E3 adds a (randomized) throttle.

## E. RFC 1337 TIME-WAIT assassination, worked

TIME_WAIT lasts 2·MSL so that every segment from the old connection has died before the 4-tuple is
reused. RFC 1337 (1992) describes how a stray RST can defeat this ("TIME-WAIT Assassination
Hazards"):

```text
   t0   connection A on (IP:port)×2 closes; active closer enters TIME_WAIT
   t1   a DELAYED duplicate from A — a RST, reordered/retransmitted long ago — arrives
   t2   under RFC 5961 exact-match, if its seq == RCV.NXT, it would reset TIME_WAIT → CLOSED
   t3   the 4-tuple is now free; a NEW connection B forms on it
   t4   OTHER delayed duplicates from A (the ones TIME_WAIT existed to absorb) arrive
   t5   they fall in B's window → B is corrupted with A's ancient data
```

The fix is to refuse step t2: **a RST received in TIME_WAIT is ignored.** A RST there cannot be a
legitimate reset of anything live (nothing live exists on that 4-tuple yet), so it can only be a
ghost. Our `on_rst` returns `None` immediately for `State::TimeWait`, before the exact-match check.
(Linux implements the same, plus the related "TIME-WAIT recycling" heuristics we don't.)

## F. Half-close in the sockets API: `shutdown()` vs `close()`

The mechanism we built maps onto the BSD sockets API that every networked program uses:

```text
   call                       wire effect                    our analogue
   ────────────────────────   ───────────────────────────    ─────────────────────────────────
   shutdown(fd, SHUT_WR)      send FIN now, keep read open   close() from ESTABLISHED (active)
   shutdown(fd, SHUT_RD)      stop reading (local only)      (no wire effect; not modeled)
   close(fd)                  drop ref; FIN at last ref      close() + reap
   recv() returns 0           peer's FIN reached us (EOF)    peer_closed() == true
```

The canonical clean shutdown of a request/response protocol:

```c
write(fd, request, n);     // send the request
shutdown(fd, SHUT_WR);     // "that's all I'm sending" → our FIN; we go FIN_WAIT_1
while ((k = read(fd, buf, sizeof buf)) > 0) { /* consume response */ }   // drain until EOF
// k == 0: peer's FIN → we ACK it; if we were FIN_WAIT_2, → TIME_WAIT
close(fd);
```

This is *active* half-close (we FIN first, keep reading). Today we implemented *passive* half-close
(peer FINs first, we keep sending) — the mirror image; exercise E1 adds the active side. The two
together are the full half-close picture: either end can be the first to stop sending.

A subtlety the sockets API exposes and we don't yet: with `dup()`/`fork()`, `close()` only sends a
FIN when the *last* descriptor referencing the socket is closed. That reference counting is an OS
concern; our `Connection` is the single owner.

## G. Comparison to real stacks — Linux, FreeBSD, lwIP, smoltcp

```text
   aspect                 Linux               FreeBSD            lwIP              smoltcp        ours (Day 19)
   ────────────────────   ─────────────────   ────────────────   ───────────────   ────────────   ─────────────────
   CLOSE_WAIT             full, leak-prone    full               full              full           full (Day 19)
   CLOSE_WAIT timeout     app/keepalive       app/keepalive      poll interval     configurable   none (E2)
   half-close API         shutdown()          shutdown()         tcp_shutdown()    .close()/abort no API yet (E1)
   RFC 5961 RST           yes (exact)         yes                yes (recent)      yes            yes
   RFC 5961 SYN           yes                 yes                yes               yes            yes
   RFC 5961 §5 data       yes                 yes                partial           partial        partial (E4)
   challenge-ACK limit    per-conn random*    rate-limited       limited           limited        none (E3)
   RFC 1337 (RST in TW)   yes                 yes                yes               yes            yes
   *post-CVE-2016-5696
```

The shape is the same everywhere; the gaps in our column are all *hardening* (timeouts, throttles,
the §5 ACK window) rather than missing protocol. That's the recurring story of this project: the core
is real, the production hardening is the next mile.

## H. Security — our posture, and what we still don't defend

What today's work *does* defend:

- Blind RST connection teardown (RFC 5961 §3) — an off-path attacker can no longer reset us by
  landing an in-window RST; they'd need the exact `RCV.NXT`.
- Blind SYN-forced reset (RFC 5961 §4) — an in-window SYN no longer kills the connection.
- TIME-WAIT assassination (RFC 1337) — a stray RST can't shorten TIME_WAIT and expose a new
  incarnation.

What it does **not** defend (and why that's acceptable for a teaching stack, but not production):

- **Blind data injection (RFC 5961 §5)** — partial; our ACK acceptance is still RFC 793-grade
  (E4).
- **Challenge-ACK reflection / inference** — we emit unlimited challenge ACKs; no randomized throttle
  (E3, §D).
- **On-path attackers** — entirely out of scope; that's TLS's job. TCP's robustness work only ever
  targets the *blind* attacker.
- **SYN-flood / state exhaustion** — we create a TCB per SYN with no SYN-cookie/backlog defense (a
  Phase-5 hardening item; the Manual flags a `syn_received_timeout`).
- **Resource exhaustion via CLOSE_WAIT/FIN_WAIT_2** — no state timeouts (E2).

The honest one-line posture: *we now resist the cheap, classic blind reset/SYN attacks that the
original RFC 793 left open, and nothing more.*

## I. Extended FAQ — thirty questions a careful reader asks

1. **Why is closing four-way but opening three-way?** Opening fuses the middle (SYN-ACK is one
   segment carrying both the peer's SYN and the ACK of ours). Closing's two FINs are independent
   events on independent streams, so they don't fuse — except in simultaneous close.
2. **Does the passive closer ever enter TIME_WAIT?** No. Only the active closer (the one who sent FIN
   first) does. The passive closer goes CLOSE_WAIT → LAST_ACK → CLOSED.
3. **So who pays the 2·MSL cost?** Whoever closes first. For HTTP/1.0 `Connection: close`, the server
   closes first and pays it — which is why busy servers tune `tcp_tw_reuse`.
4. **What exactly is "CLOSE_WAIT leak"?** The kernel ACKed the peer's FIN and is waiting for the
   *application* to call `close()`. If the app never does, the connection sits in CLOSE_WAIT forever,
   holding an fd. Thousands of these = fd exhaustion = outage.
5. **How would I see it in production?** `ss -tan state close-wait` (or `netstat`). A growing count
   pinned to one process is a missing-`close()` bug.
6. **Why does a FIN consume a sequence number?** So its delivery is reliable exactly like data: the
   peer ACKs `FIN.seq + 1`, the FIN is retransmitted until that ACK arrives. A control bit that
   didn't consume a sequence number couldn't be reliably retransmitted.
7. **Where does the FIN sit on a data+FIN segment?** At `seq + payload_len`. The data is
   `[seq, seq+len)`; the FIN is the next sequence number after it.
8. **Why did the old code drop a piggybacked FIN?** The data branch `return`ed before the FIN check.
   Today data delivery falls through to FIN handling.
9. **What if the data+FIN arrives out of order?** We buffer the data (reassembler), record the FIN's
   position in `pending_fin`, and honor it only when `RCV.NXT` reaches it — possibly several segments
   later, in the call that fills the gap.
10. **Why one `pending_fin`, not a list?** A sender has at most one FIN outstanding (it's the last
    thing it sends). Nothing follows it to reorder past.
11. **What does `peer_closed()` tell the application?** That the peer sent its FIN → the application
    is at EOF on reads (a `read()` veneer returns `Ok(0)`).
12. **Can we still send after `peer_closed()` is true?** Yes — that's half-close. Our send side stays
    open in CLOSE_WAIT until *we* call `close()`.
13. **Why did `poll_transmit` need changing?** It early-returned unless ESTABLISHED, which would
    block all sending in CLOSE_WAIT — defeating half-close. Now it also runs in CLOSE_WAIT.
14. **And the persist timer?** Same reason: a half-closed connection can still hit a zero window and
    needs to probe it.
15. **Why is the RST check first in `on_segment`?** A RST can arrive in any state and should be
    evaluated before state-specific logic; placing it first keeps each state's branch free of RST
    special cases.
16. **Why is the SYN check *after* the SYN_SENT branch?** Because during our own active open a
    SYN-ACK legitimately carries the SYN bit; we must process it as a handshake, not challenge it.
    Only *synchronized* states challenge a SYN.
17. **What's a challenge ACK, in one line?** A bare ACK of our current state
    (`seq=SND.NXT, ack=RCV.NXT`) that only the genuine peer can usefully answer.
18. **Why does answering with an ACK defend against a RST?** It forces the sender to prove it knows
    the exact sequence number: a real peer answers with a correctly-sequenced RST; an off-path
    attacker never sees the challenge and can't.
19. **Could the challenge ACK itself be abused?** Yes — unlimited challenge ACKs are a reflection
    vector, and a shared deterministic limit became CVE-2016-5696. Production randomizes a
    per-connection limit (§D).
20. **Why ignore RSTs in TIME_WAIT?** RFC 1337: a RST there can only be a ghost of the dead
    connection; honoring it would free the 4-tuple early and let old duplicates corrupt a new
    connection.
21. **What about a RST in SYN_SENT?** Accept it only if it acknowledges our SYN (`ack == SND.NXT`);
    that's "connection refused." Otherwise ignore.
22. **Does our exact-match RST break anything legitimate?** Only the rare case of a real peer sending
    an in-window-but-inexact RST — which then gets a challenge ACK and re-sends an exact one. One
    extra round trip, no lost correctness.
23. **Is the window test wrap-safe?** Yes — `in_window` uses the `seq::before` modular comparison, so
    `[RCV.NXT, RCV.NXT+RCV.WND)` is correct across the 32-bit wrap.
24. **What's `is_synchronized()` for?** It gates the SYN-challenge rule to the states where both ISNs
    are fixed (ESTABLISHED through TIME_WAIT), excluding the handshake states.
25. **Why is `close()` a `match` returning `next`?** To share the FIN-building tail between the
    ESTABLISHED (→FIN_WAIT_1) and CLOSE_WAIT (→LAST_ACK) cases, with `_ => return None` for illegal
    states.
26. **How is all this tested without a network?** By constructing `TcpHeader`s and calling
    `on_segment`/`close` directly, asserting on returned bytes and `state()`. Ten new offline tests.
27. **Does any of this touch congestion control?** No — but extending the ACK-processing block to
    CLOSE_WAIT means data sent after half-close is still congestion-controlled and SACK-aware, for
    free.
28. **What happens to `pending_fin` if a RST arrives mid-defer?** The RST path resets to `Closed`;
    `pending_fin` is irrelevant (the TCB is about to be removed).
29. **Why not just keep the fused close for the echo server?** Because the *state machine* must be
    correct for all apps; the echo "close immediately" is then a one-line policy, not a baked-in
    shortcut. Correctness first, policy on top.
30. **What's the single biggest thing still missing here?** RFC 5961 §5 (blind data injection
    hardening) and a randomized challenge-ACK throttle — both noted in §H, both exercises.

## J. Anki starter deck

```text
Q: A FIN closes what?  A: one direction (a simplex stream), not the whole connection.
Q: Passive-close state path?  A: ESTABLISHED → CLOSE_WAIT → LAST_ACK → CLOSED.
Q: Active-close state path?  A: ESTABLISHED → FIN_WAIT_1 → FIN_WAIT_2 → TIME_WAIT → CLOSED.
Q: Who enters TIME_WAIT?  A: only the active closer (sent FIN first).
Q: What is CLOSE_WAIT waiting for?  A: the local application to call close().
Q: The "CLOSE_WAIT leak" is?  A: app never calls close() → connection (and fd) held forever.
Q: A FIN consumes how many sequence numbers?  A: one (like SYN).
Q: On a data+FIN segment, the FIN sits at seq = ?  A: seq + payload_len.
Q: Why store pending_fin as a sequence number?  A: to honor the FIN only when RCV.NXT reaches it.
Q: RFC 5961 RST rule — exact RCV.NXT?  A: reset the connection.
Q: RFC 5961 RST rule — in window, inexact?  A: send a challenge ACK, do not reset.
Q: RFC 5961 RST rule — out of window?  A: drop silently.
Q: A challenge ACK is?  A: <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK> — a bare ACK of current state.
Q: Why does a challenge ACK defend against a forged RST?  A: only the on-path peer sees it and can reply with an exact-seq RST.
Q: RFC 5961 SYN rule (synchronized state)?  A: challenge ACK and drop, never reset (any seq).
Q: Bonus effect of the SYN-challenge rule?  A: recovers a lost final handshake ACK.
Q: RFC 1337 says do what with a RST in TIME_WAIT?  A: ignore it (anti-assassination).
Q: RST in SYN_SENT is accepted only if?  A: it acknowledges our SYN (ack == SND.NXT) → refused.
Q: Attacker guesses to land in a 64KB window?  A: ~65,536 (2^32 / W).
Q: Attacker guesses to hit exact RCV.NXT?  A: ~2^32 (4 billion).
Q: CVE-2016-5696 was?  A: a shared, deterministic challenge-ACK counter used as an off-path oracle.
Q: shutdown(SHUT_WR) does?  A: sends our FIN now, leaves the read side open (half-close).
Q: recv()==0 means?  A: the peer sent its FIN — EOF.
```

## K. Glossary

- **Half-close** — shutting one direction of the connection while the other stays open.
- **Active closer** — the endpoint that sends the first FIN; traverses FIN_WAIT_1/2 → TIME_WAIT.
- **Passive closer** — the endpoint that receives the first FIN; traverses CLOSE_WAIT → LAST_ACK.
- **CLOSE_WAIT** — passive-close state: peer's FIN ACKed, awaiting the local app's `close()`.
- **LAST_ACK** — passive-close state: our FIN sent, awaiting its ACK, then CLOSED.
- **EOF** — end of input; the receive side's view of the peer's FIN (`read()` returns 0).
- **FIN** — the control bit meaning "no more data from me"; consumes one sequence number.
- **Off-path attacker** — can send forged packets but not observe the connection's traffic.
- **Blind in-window attack** — an off-path attack that lands a forged segment anywhere in the window.
- **Challenge ACK** — a bare ACK of current state, sent to make a suspicious sender prove liveness.
- **Exact-match (RST)** — `SEG.SEQ == RCV.NXT`; the only RST RFC 5961 honors outright.
- **TIME-WAIT assassination** — using a stray RST to end TIME_WAIT early (RFC 1337 hazard).
- **`pending_fin`** — our one-slot record of an out-of-order FIN's sequence, honored when reached.
- **`peer_fin` / `peer_closed()`** — flag/accessor: the peer has sent its FIN (we're at EOF).
- **`is_synchronized()`** — predicate: both ISNs fixed (ESTABLISHED … TIME_WAIT); RFC 5961 applies.

## L. Reference tables

**L.1 — Close states and what each waits for**

```text
   state         role       waiting for                       next on event           enters TIME_WAIT?
   ───────────   ────────   ───────────────────────────────   ─────────────────────   ────────────────
   FIN_WAIT_1    active     ACK of our FIN (and/or peer FIN)   FIN_WAIT_2/CLOSING/TW   yes (eventually)
   FIN_WAIT_2    active     peer's FIN                         TIME_WAIT               yes
   CLOSING       both       ACK of our FIN                     TIME_WAIT               yes
   CLOSE_WAIT    passive    the local app to close()           LAST_ACK                no
   LAST_ACK      passive    ACK of our FIN                     CLOSED                  no
   TIME_WAIT     active     2·MSL to elapse                    CLOSED                  (is TIME_WAIT)
```

**L.2 — Incoming segment → action, by what's set (synchronized states)**

```text
   bit / condition                         action
   ─────────────────────────────────────   ────────────────────────────────────────────
   RST, seq == RCV.NXT                      reset → CLOSED          (RFC 5961 §3, exact)
   RST, in window, seq != RCV.NXT           challenge ACK           (RFC 5961 §3)
   RST, out of window                       drop                    (RFC 5961 §3)
   RST, state == TIME_WAIT                  drop                    (RFC 1337)
   SYN (any seq)                            challenge ACK, drop     (RFC 5961 §4)
   FIN, fin_seq == RCV.NXT (in order)       ACK, → CLOSE_WAIT       (RFC 9293 §3.5)
   FIN, fin_seq > RCV.NXT (reordered)       buffer data, defer FIN  (pending_fin)
   FIN retransmit in CLOSE_WAIT             re-ACK current state
```

**L.3 — FIN sequence arithmetic**

```text
   segment                       data range       FIN sits at     we ACK
   ───────────────────────────   ──────────────   ─────────────   ──────────────
   pure FIN, seq=S               (none)           S               S + 1
   data+FIN, seq=S, len=L        [S, S+L)         S + L           S + L + 1
   our FIN, SND.NXT=N            (none)           N               (peer acks N+1)
```

**L.4 — Attacker work factor (off-path, known 4-tuple)**

```text
   action                    RFC 793            RFC 5961               improvement
   ───────────────────────   ────────────────   ────────────────────   ────────────
   reset via RST             ~2^32 / W guesses  ~2^32 guesses (exact)  × W
   reset via SYN             ~2^32 / W guesses  impossible (challenge) total
   inject data              ~2^32 / W × ack    tighter + challenge    partial (ours: E4)
```

> Re-type `on_rst`, `challenge_ack`, the split FIN handler (deliver → record `pending_fin` → honor →
> CLOSE_WAIT, pure ACK), and the dual-mode `close()` with the book closed, then `cargo test`. When
> your stack lets a client half-close while you keep talking — and shrugs off a forged in-window RST
> with a single challenge ACK — you own RFC 9293's teardown and RFC 5961's robustness.
