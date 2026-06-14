# Day 26 — TCP, Part 24: Keepalive — Detecting a Peer That Vanished (`SO_KEEPALIVE`, RFC 9293 §3.8.4)

> Goal: notice when the other end is simply *gone*. Everything so far detects an *active* failure —
> a RST aborts, a FIN closes, lost data triggers retransmission. But what about a connection that is
> ESTABLISHED, idle (no data flowing), and whose peer silently **disappears** — a crashed process, a
> yanked Ethernet cable, a NAT box that dropped the mapping, a laptop that slept? No FIN, no RST, no
> data to retransmit: nothing happens. The connection sits ESTABLISHED *forever*, a zombie holding a
> TCB (and, on a real OS, a file descriptor) for a peer that will never speak again. Our Day 23
> reaper bounds the *half-closed* states, but an idle ESTABLISHED connection has no timer at all.
>
> **TCP keepalive** (`SO_KEEPALIVE`) fills the gap. After a connection sits idle for a while, the
> sender pokes it with a **keepalive probe** — a segment carrying sequence number `SND.NXT − 1`, one
> byte *below* what comes next, i.e. a byte the peer has already acknowledged. A live peer is obliged
> to answer with a plain ACK (re-acking the old data), which proves it's still there and resets the
> timer. A dead peer answers nothing; after a few unanswered probes the connection is declared dead
> and torn down. It's a deliberately tiny, low-rate heartbeat — off by default (it costs packets on
> otherwise-silent connections), opt-in via the socket option, exactly as on every real stack.

**Contents**

Volume I — the chapter
1. The mental model: silence is ambiguous
2. The gap keepalive fills (vs RST, FIN, retransmission, the reaper)
3. The probe: a segment at `SND.NXT − 1`
4. The three timers: idle, interval, count
5. Reset on any activity
6. Why it's off by default
7. Where it lives: `on_tick`, beside the other timers
8. The Rust: opt-in flag, the probe schedule, no retransmission record
9. A fully worked trace — a dead peer, detected
10. The code, walked end to end
11. Verification — the two new tests
12. Why this, not that
13. Honesty: what production does that we don't
14. Rebuild it yourself — checklist + exercises
15. What comes after

Volume II — the exhaustive reference
- A. RFC 9293 §3.8.4: the keepalive rules
- B. The probe segment, byte by byte
- C. The default timers, and why two hours
- D. Keepalive vs application-layer heartbeats
- E. Comparison to real stacks — the sysctls and socket options
- F. Extended FAQ — twenty questions a careful reader asks
- G. Anki starter deck
- H. Glossary
- I. Reference tables

---

# Volume I — the chapter

## 1. The mental model: silence is ambiguous

On an idle TCP connection, **no packets flow**. That's by design — TCP sends nothing when there's
nothing to send; it doesn't poll. But it creates an ambiguity the protocol otherwise can't resolve:

```text
   the connection is silent. is the peer…
     • just idle (alive, nothing to say)?          ← keep waiting
     • crashed / unreachable (gone forever)?        ← tear down, free the resources
   from the silence alone, you cannot tell.
```

Every other failure announces itself: a RST (abort), a FIN (graceful close), or an unacked segment
(loss → retransmit → eventually RTO). But a peer that vanishes *while idle* announces nothing. The
only way to disambiguate silence is to **make noise and see if anyone answers** — to send a probe and
require a response. That's keepalive: a periodic "are you still there?" with a required "yes."

## 2. The gap keepalive fills

Line up everything that can end a connection and what detects it:

```text
   failure mode                         detected by                         state it acts in
   ──────────────────────────────────   ─────────────────────────────────   ────────────────────
   peer aborts                          incoming RST (Day 19)               any synchronized
   peer closes gracefully               incoming FIN (Days 5, 19)           ESTABLISHED → CLOSE_WAIT
   in-flight data lost                  RTO / RACK / dup-ACK (Days 6,10,24) data outstanding
   peer FIN'd then vanished             reaper timeout (Day 23)             CLOSE_WAIT / FIN_WAIT_2
   peer vanished while IDLE+ESTABLISHED  ── nothing, until today ──          ESTABLISHED, idle
```

The last row is the hole. An ESTABLISHED connection with **nothing in flight** (`FlightSize == 0`)
and an empty send buffer has no RTO armed (nothing to retransmit), isn't half-closed (the reaper
doesn't apply), and receives nothing (the peer is gone). It would live forever. Keepalive is the
*only* mechanism that probes a healthy-looking but idle connection, so it's the only thing that can
catch this failure.

## 3. The probe: a segment at `SND.NXT − 1`

The keepalive probe is a small, clever trick. It's a segment whose **sequence number is one below**
the next byte we'd send:

```rust
out.push(self.segment(self.send.nxt.wrapping_sub(1), self.recv.nxt, ACK, &[]));
//                     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^  SND.NXT − 1
```

Why `SND.NXT − 1`? Because that's a byte the peer **already received and acknowledged**. The segment
carries no new data (zero-length, or in some stacks one garbage byte). To the peer it looks like a
stale retransmission of an old byte, and TCP's rules require it to respond with an **ACK of its
current state** (`ack = its RCV.NXT = our SND.NXT`) — "I already have everything up to here." That
forced ACK is the proof of life. We send a sequence number the peer must reject-with-an-ACK precisely
*so that* it must answer.

It must be `SND.NXT − 1`, not `SND.NXT`: a segment at `SND.NXT` would be *new* in-window data the peer
would happily accept and deliver (corrupting the stream with a probe), and it would advance sequence
numbers. `SND.NXT − 1` is provably old, so it's inert except for the ACK it compels.

## 4. The three timers: idle, interval, count

Keepalive is governed by three parameters (the classic `tcp_keepalive_*` knobs):

```text
   KEEPALIVE_IDLE_MS    how long the connection must be idle before the FIRST probe
   KEEPALIVE_INTVL_MS   the gap between probes once they start
   KEEPALIVE_PROBES     how many unanswered probes before declaring the peer dead
```

Real defaults are deliberately *huge* — Linux: idle 7200 s (2 hours), interval 75 s, 9 probes — so
keepalive is a slow background safety net, not a chatty poll. We shorten them for a teaching demo
(idle 60 s, interval 5 s, 3 probes) so the behavior is observable in seconds. The schedule:

```text
   t = last_activity + IDLE                 → probe #1
   t = last_activity + IDLE + 1·INTVL       → probe #2
   t = last_activity + IDLE + 2·INTVL       → probe #3
   t = last_activity + IDLE + 3·INTVL       → no response after PROBES probes → CLOSED
```

Our `on_tick` computes the next probe's due time directly from `keepalive_probes_sent`:

```rust
let next_probe_at = self.last_active_ms
    .saturating_add(KEEPALIVE_IDLE_MS)
    .saturating_add(self.keepalive_probes_sent as u64 * KEEPALIVE_INTVL_MS);
if now_ms >= next_probe_at {
    if self.keepalive_probes_sent >= KEEPALIVE_PROBES { self.state = State::Closed; }
    else { self.keepalive_probes_sent += 1; out.push(/* probe */); }
}
```

So the total time to detect a dead peer is `IDLE + PROBES · INTVL` (here 60 + 3·5 = 75 s; on Linux,
~2h 11m). The idle period dominates — keepalive is patient by design.

## 5. Reset on any activity

The keepalive timer measures *idleness*, so **any** segment from the peer resets it. We already track
`last_active_ms` (Day 23, for the reaper); the keepalive schedule is anchored to it, and we reset the
probe counter on every arriving segment:

```rust
// top of on_segment:
self.last_active_ms = now_ms;       // Day 23
self.keepalive_probes_sent = 0;     // Day 26 — the peer spoke, so it's alive; restart probing
```

This is what makes keepalive safe: a connection that's actually exchanging data (or whose peer
answered a probe) never gets torn down, because each segment pushes the idle deadline forward. Only a
connection that is *genuinely* silent for `IDLE` *and then* fails to answer `PROBES` probes is
reaped. The probe's own response — the peer's forced ACK from §3 — arrives at `on_segment`, resets
the counter, and the cycle restarts. A live peer is immortal; a dead one has `IDLE + PROBES·INTVL`.

## 6. Why it's off by default

Keepalive costs packets on connections that would otherwise be silent — and on a server with a
million idle connections, a low-rate heartbeat on each adds up. It can also, with aggressive timers,
tear down a connection across a transient outage that would have recovered. So TCP makes it
**opt-in**: the application sets `SO_KEEPALIVE` when it *wants* dead-peer detection (long-lived idle
connections — SSH sessions, database pools, push notifications), and leaves it off otherwise (let the
application layer or the user notice). Our `set_keepalive(on)` mirrors the socket option; it defaults
off, and the demo server leaves it off (like `set_nodelay`, it's exercised by tests). A real
deployment turns it on per-connection where idle-peer detection matters.

## 7. Where it lives: `on_tick`, beside the other timers

Keepalive is a pure timer, so it belongs in `on_tick` alongside the RTO, the persist timer, the
TIME_WAIT/reaper expiries, and RACK/TLP. The ordering doesn't matter much — keepalive only acts when
the connection is ESTABLISHED, idle (`FlightSize == 0`, empty send buffer), and `keepalive_enabled` —
conditions under which none of the other timers fire (there's nothing in flight to retransmit, no
zero-window to probe, no close in progress). It reads the same `now_ms` and pushes any probe onto the
same `out` vector the event loop sends. One connection's `on_tick` is now its complete timer service:
retransmission, fast/RACK recovery, zero-window persistence, lifecycle reaping, *and* liveness.

## 8. The Rust: opt-in flag, the probe schedule, no retransmission record

**An opt-in `bool`, defaulted off.** `keepalive_enabled: bool` starts `false`; `set_keepalive(true)`
turns it on. The `on_tick` block is gated on it, so a connection that didn't ask pays nothing. This
mirrors `set_nodelay` (Day 13) — a per-connection option the protocol exposes but doesn't impose.

**The schedule from a counter, not a stored deadline.** Rather than store and rearm a "next probe
time," we *derive* it each tick from `last_active_ms + IDLE + probes_sent · INTVL`. That's stateless
(one `u32` counter), self-correcting (a reset of `last_active_ms`/`probes_sent` instantly reschedules
everything), and impossible to leave stale. `saturating_add` keeps the arithmetic safe at the `u64`
ceiling.

**No retransmission record.** Unlike a data segment or a FIN, the probe is **not** put in the
retransmission queue (`retx.record`) — it carries no sequence space (it's an old byte), so there's
nothing to reliably deliver. We just emit it; if it's lost, the *next* interval's probe covers us.
The probe is fire-and-forget; the *count* of unanswered probes, not per-probe reliability, is what
declares the peer dead.

## 9. A fully worked trace — a dead peer, detected

Idle ESTABLISHED connection, `SND.NXT = 1`, `RCV.NXT = 101`, last activity at `t = 0`, keepalive on
(IDLE = 60 s, INTVL = 5 s, PROBES = 3). The peer has crashed and will never respond.

```text
   t (s)   on_tick action                                          probes_sent   state
   ─────   ─────────────────────────────────────────────────────   ───────────   ───────────
   0–59    next_probe_at = 60 s; now < it → nothing                 0             ESTABLISHED
   60      probe #1: segment seq=0 (SND.NXT−1) ack=101              1             ESTABLISHED
   61–64   next = 60 + 1·5 = 65 s; now < it → nothing               1             ESTABLISHED
   65      probe #2: seq=0 ack=101                                  2             ESTABLISHED
   70      probe #3: seq=0 ack=101                                  3             ESTABLISHED
   75      next = 60 + 3·5 = 75 s; probes_sent(3) ≥ PROBES(3)       3             CLOSED  ← dead
```

The connection is collected 75 s after it went idle — and `main` removes any CLOSED connection from
its table, freeing the TCB. Had the peer been *alive*, its forced ACK to probe #1 (at, say, t = 60)
would have hit `on_segment`, reset `last_active_ms = 60` and `probes_sent = 0`, and the whole schedule
would restart from 60 s — the connection living on indefinitely. (The unit tests check both: the dead
path to CLOSED, and a peer response resetting the timer.)

## 10. The code, walked end to end

All in `src/tcp.rs`.

**State**: `keepalive_enabled: bool` (the opt-in) and `keepalive_probes_sent: u32` (the counter),
both initialised off/zero in `accept` and `connect`.

**`set_keepalive(on)`**: the `SO_KEEPALIVE` analogue; `#[allow(dead_code)]` (test-only, like
`set_nodelay`) — the demo server leaves it off.

**`on_segment`**: resets `keepalive_probes_sent = 0` beside the existing `last_active_ms = now_ms`, so
any arriving segment (data *or* a probe response) proves liveness and restarts the schedule.

**`on_tick`**: the probe logic of §4 — when enabled, ESTABLISHED, and idle (nothing in flight, empty
send buffer), emit a probe at each scheduled time, and declare the peer dead after `KEEPALIVE_PROBES`.

`main` doesn't enable it (keeping the demo's behavior unchanged); a real application calls
`set_keepalive(true)` on the connections where idle-peer detection matters.

## 11. Verification — the two new tests

`cargo test` — **133 passing** (131 + 2).

- **`keepalive_probes_idle_connection_then_declares_it_dead`** — enable keepalive, then drive
  `on_tick` across the schedule: nothing before `IDLE`; a probe at `SND.NXT − 1` at `IDLE`; further
  probes at each interval (connection still ESTABLISHED while they go unanswered); and CLOSED after
  `KEEPALIVE_PROBES`. The §9 trace as an assertion.
- **`keepalive_is_reset_by_a_peer_response`** — a probe goes out, then a peer ACK arrives; the next
  probe is delayed by a full idle period *measured from the response*, and the connection stays
  ESTABLISHED. Pins the "any activity resets it" safety property — a live peer is never reaped.

Every prior test still passes: keepalive is off by default, so no existing connection's `on_tick`
behavior changes.

## 12. Why this, not that

**Why probe at `SND.NXT − 1` instead of `SND.NXT`?** `SND.NXT − 1` is a byte the peer already acked,
so the probe is inert except for the forced ACK it compels. A probe at `SND.NXT` would be *new* data
the peer accepts and delivers — corrupting the stream and advancing sequence numbers. (§3.)

**Why count unanswered probes instead of retransmitting one reliably?** The probe carries no sequence
space, so there's nothing to reliably deliver; spacing several probes over `PROBES · INTVL` and
declaring death after the last is both simpler and more robust to a single lost probe. (§8.)

**Why off by default?** Keepalive spends packets on idle connections and can sever a connection
across a transient outage; the application opts in only where idle-peer detection is worth it. (§6.)

**Why not just shorten the reaper to cover ESTABLISHED?** The reaper reaps *half-closed* states after
inactivity unconditionally; an idle ESTABLISHED connection is *legitimately* idle (both ends fine,
nothing to say) and must NOT be reaped blindly — it must be *probed* and given a chance to prove it's
alive. Keepalive's required-response is exactly that proof; a blind timeout would kill healthy idle
connections. (§§1–2.)

**Why derive the schedule from a counter, not store a deadline?** Stateless, self-correcting, and
impossible to leave stale across a reset. (§8.)

## 13. Honesty: what production does that we don't

- **Not wired into the demo.** Like `set_nodelay`, `set_keepalive` is API + tested, but `main` leaves
  it off, so the live server doesn't probe idle `nc` sessions. A real app enables it per-connection.
- **Shortened timers.** Our 60 s / 5 s / 3 are for a watchable demo; real defaults (7200 s / 75 s / 9)
  make keepalive a slow background net. The mechanism is identical; only the constants differ.
- **No per-connection timer configuration.** Real sockets expose `TCP_KEEPIDLE`, `TCP_KEEPINTVL`,
  `TCP_KEEPCNT` to tune the three values per connection; ours are global constants.
- **No "one garbage byte" variant.** Some legacy peers only answer a probe carrying *one* byte of old
  data; we send a zero-length probe at `SND.NXT − 1`, which conformant peers answer. (Both are
  RFC-acceptable.)
- **Reaping, not RST.** On death we transition to CLOSED and let `main` drop the TCB; a production
  stack also typically sends a RST to the (possibly returned) peer and surfaces `ETIMEDOUT` to the
  application. We don't send the RST.
- **No interaction with the application.** Real keepalive death wakes a blocked `read`/`write` with an
  error; our socket façade (Day 22) would need to surface it (a small follow-on).

The mechanism — idle detection, the `SND.NXT − 1` probe, the count-to-death, the reset-on-activity —
is real RFC 9293 keepalive; the gaps are configuration surface and integration polish.

## 14. Rebuild it yourself — checklist + exercises

**Checklist**

- [ ] Add `keepalive_enabled: bool` and `keepalive_probes_sent: u32`; init off/0 in both constructors.
- [ ] `set_keepalive(on)` (the `SO_KEEPALIVE` analogue).
- [ ] In `on_segment`, reset `keepalive_probes_sent = 0` beside `last_active_ms`.
- [ ] In `on_tick`, when enabled + ESTABLISHED + idle (FlightSize 0, empty send buffer): probe at
      `last_active + IDLE + probes_sent·INTVL`; segment at `SND.NXT − 1`; CLOSED after `PROBES`.
- [ ] `cargo test` green (133), `cargo clippy -- -D warnings` clean.

**Exercises**

1. **E1 — per-connection timers.** Add `set_keepalive_params(idle, intvl, probes)` (the
   `TCP_KEEPIDLE`/`INTVL`/`CNT` analogues) and test a connection with custom values.
2. **E2 — surface the death.** Wire keepalive into the Day 22 socket façade so a `read` on a
   keepalive-dead connection returns an error (the `ETIMEDOUT` analogue).
3. **E3 — RST on death.** Send a RST to the peer when keepalive declares it dead (in case it returns),
   and test the RST is well-formed.
4. **E4 — enable in `main`.** Turn keepalive on for accepted connections with a short idle, and watch
   (live) an abandoned `nc` session get probed and dropped in `tcpdump`.
5. **E5 — the one-byte variant.** Add a probe carrying one byte of old data (`SND.NXT − 1`'s byte) for
   legacy peers, and confirm a conformant peer still answers the zero-length form.

Make Anki cards from the `SND.NXT − 1` probe trick and the `IDLE + PROBES·INTVL` death time.

## 15. What comes after

Keepalive closes the idle-ESTABLISHED gap, the last *liveness* corner. The remaining robustness item
is **SYN cookies** — defending the *accept* path against a SYN flood by not allocating a TCB until the
final ACK proves the client (encoding the connection state in the SYN-ACK's sequence number instead).
After that, the frontiers are **BBR** (model-based congestion control), a **multi-connection socket
façade**, and the live `packetdrill`/`iperf3` validation that needs a network. The protocol engine —
every connection state, modern recovery and congestion control, and now full liveness detection — is
complete.

---

# Volume II — the exhaustive reference

## A. RFC 9293 §3.8.4: the keepalive rules

RFC 9293 (and 1122 §4.2.3.6 before it) specify keepalive precisely:

```text
   1. Keepalive is OFF by default; it MUST be enabled per-connection by the application.
   2. A keepalive probe MAY be sent only after the connection has been idle for ≥ the keepalive time
      (RFC: ≥ 2 hours by default).
   3. The probe is a segment with no data (or one garbage byte) and sequence number = SND.NXT − 1, so
      a conformant peer responds with an ACK of its current state.
   4. An implementation MUST NOT interpret the *absence* of a response to a single probe as a dead
      connection — it MUST send multiple probes, spaced out, before concluding the peer is gone.
   5. Any segment received resets the keepalive timer.
```

We honor all five: off by default (rule 1, `keepalive_enabled`), an idle threshold (rule 2,
`KEEPALIVE_IDLE_MS`), the `SND.NXT − 1` probe (rule 3), multiple spaced probes before death (rule 4,
`KEEPALIVE_PROBES`/`INTVL`), and reset on any segment (rule 5, in `on_segment`).

## B. The probe segment, byte by byte

A keepalive probe on our connection (`SND.NXT = 1`, `RCV.NXT = 101`, our window 1024):

```text
   IPv4: src = us, dst = peer, proto = 6 (TCP), standard header
   TCP:
     seq    = 0       (SND.NXT − 1 = 1 − 1 = 0 — a byte the peer already acked)
     ack    = 101     (RCV.NXT — our current acknowledgement)
     flags  = ACK
     window = 1024    (our receive window, as always)
     data   = (none)
```

The peer receives `seq = 0`, which is below its `RCV.NXT` (it already has byte 0), so per the
acceptability rules it discards the (empty) payload and returns an ACK of *its* current state:
`ack = its RCV.NXT = our SND.NXT = 1`. That returning ACK is the heartbeat. (If timestamps are
negotiated, the probe and its response also carry them — harmless, and they refresh PAWS.)

## C. The default timers, and why two hours

```text
   parameter            our value   Linux default      sysctl
   ──────────────────   ─────────   ────────────────   ──────────────────────────
   idle before probe    60 s        7200 s (2 hours)   net.ipv4.tcp_keepalive_time
   interval between      5 s        75 s               net.ipv4.tcp_keepalive_intvl
   probe count           3          9                  net.ipv4.tcp_keepalive_probes
   ⇒ time to declare dead  75 s     ~2 h 11 m
```

Why two hours, not two minutes? Because keepalive is a *safety net for resource cleanup*, not a
liveness SLA. A two-hour idle threshold means keepalive never interferes with normal operation (real
idle gaps are seconds to minutes) and only reclaims connections genuinely abandoned for a long time.
Applications that need faster dead-peer detection (a chat server, a trading feed) either tune the
timers down (`TCP_KEEPIDLE`) or — better — use an *application-layer* heartbeat (§D). We shorten ours
only to make the behavior observable in a unit test and a short demo.

## D. Keepalive vs application-layer heartbeats

```text
   property                  TCP keepalive               application heartbeat (e.g. PING/PONG)
   ───────────────────────   ─────────────────────────   ───────────────────────────────────────
   layer                     transport (kernel)          application
   detects                   dead peer / dead path       dead peer / dead path / hung application
   default timers            hours (coarse)              seconds (tuned to the app)
   sees a hung (live) app?   no (the kernel ACKs)        yes (the app must reply)
   portability of timers     OS-dependent sysctls        fully in the app's control
```

The crucial difference: TCP keepalive is answered by the *kernel*, so it proves the *host and path*
are alive but **not** that the *application* is making progress — a hung server whose kernel still
ACKs looks alive to keepalive. Application heartbeats (the app must actively reply) catch a hung app
too, and the app controls the timing. So keepalive is the cheap, coarse, transport-level net;
latency-sensitive systems layer an application heartbeat on top. Both have their place; keepalive is
the one TCP itself provides.

## E. Comparison to real stacks — the sysctls and socket options

```text
   aspect                Linux                          ours (Day 26)
   ───────────────────   ────────────────────────────   ──────────────────────────
   enable                setsockopt SO_KEEPALIVE        set_keepalive(true)
   idle / intvl / count  TCP_KEEPIDLE/INTVL/CNT          global constants (E1)
   defaults              7200 s / 75 s / 9              60 s / 5 s / 3 (shortened)
   probe                 seq = SND.NXT−1, no data        same
   on death              RST + ETIMEDOUT to the app      transition to CLOSED (E2/E3)
   reset on activity     yes                            yes
```

Our column is "real RFC keepalive, shortened timers, with per-connection tuning and app integration
as exercises." The probe and the reset-on-activity semantics match exactly.

## F. Extended FAQ — twenty questions a careful reader asks

1. **What does keepalive detect?** A peer (or path) that vanished while the connection was idle and
   ESTABLISHED — no FIN, no RST, no data.
2. **Why can't the other mechanisms catch it?** RST/FIN require the peer to *send* something; loss
   recovery requires data in flight; the reaper only covers half-closed states. An idle ESTABLISHED
   connection has none of these.
3. **What is the probe?** A zero-length segment at `seq = SND.NXT − 1` (a byte the peer already acked).
4. **Why `SND.NXT − 1`?** It's provably old, so it's inert except that the peer must answer with an
   ACK — the proof of life.
5. **What if it were `SND.NXT`?** The peer would accept it as new data, corrupting the stream and
   advancing sequence numbers.
6. **How does a live peer respond?** With a bare ACK of its current state (`ack = our SND.NXT`).
7. **How does that reset keepalive?** The ACK arrives at `on_segment`, which resets `last_active_ms`
   and `keepalive_probes_sent`.
8. **What declares the peer dead?** `KEEPALIVE_PROBES` consecutive unanswered probes.
9. **How long until death?** `IDLE + PROBES · INTVL` (75 s for us; ~2 h 11 m on Linux defaults).
10. **Why so long by default?** Keepalive is a resource-cleanup net, not a liveness SLA; long timers
    avoid interfering with normal idle gaps.
11. **Why off by default?** It costs packets on idle connections and can sever across a transient
    outage; the app opts in where it's worth it.
12. **Is the probe retransmitted reliably?** No — it carries no sequence space; spacing several probes
    and counting is the reliability.
13. **Where does the probe logic run?** `on_tick`, beside the RTO/persist/reaper timers.
14. **Does an active connection get probed?** No — any data resets the idle timer; only a genuinely
    idle connection is probed.
15. **Does keepalive change sequence numbers?** No — `SND.NXT − 1` is old; nothing advances.
16. **Does it interact with the reaper (Day 23)?** No — the reaper handles half-closed states;
    keepalive handles idle ESTABLISHED. Disjoint.
17. **Is it enabled in our demo?** No — API + tested, off in `main` (like `set_nodelay`).
18. **Does keepalive detect a *hung application*?** No — the kernel answers the probe; the app could
    be stuck. An application heartbeat catches that (§D).
19. **What happens on death in our stack?** State → CLOSED; `main` removes the TCB. (A real stack also
    RSTs and signals the app — E3/E2.)
20. **Biggest thing still missing?** Per-connection timer tuning, a RST on death, and surfacing the
    death to the socket API — all exercises.

## G. Anki starter deck

```text
Q: What failure does TCP keepalive detect?  A: a peer that vanished while idle + ESTABLISHED (no FIN/RST).
Q: Why can't FIN/RST/retransmission catch it?  A: they need the peer to send / data in flight; idle has neither.
Q: The keepalive probe is?  A: a zero-length segment at seq = SND.NXT − 1.
Q: Why SND.NXT − 1?  A: an already-acked byte → inert, but forces the peer to ACK (proof of life).
Q: A live peer answers a probe with?  A: a bare ACK of its current state.
Q: What declares the peer dead?  A: KEEPALIVE_PROBES consecutive unanswered probes.
Q: Time to detect death?  A: IDLE + PROBES·INTVL.
Q: Linux default idle time?  A: 7200 s (2 hours).
Q: Is keepalive on by default?  A: no — opt-in via SO_KEEPALIVE.
Q: What resets the keepalive timer?  A: any segment received (data or a probe response).
Q: Does keepalive probe an active connection?  A: no — activity keeps resetting the idle timer.
Q: Does keepalive detect a hung (but kernel-alive) application?  A: no — only an app heartbeat does.
Q: Where does the probe logic live?  A: on_tick, beside the other timers.
Q: Is the probe retransmitted reliably?  A: no — spacing several probes + counting is the reliability.
```

## H. Glossary

- **Keepalive** — a periodic probe on an idle connection to detect a vanished peer (`SO_KEEPALIVE`).
- **Keepalive probe** — a zero-length segment at `SND.NXT − 1` that forces the peer to ACK.
- **Keepalive time (idle)** — how long the connection must be idle before the first probe.
- **Keepalive interval** — the gap between probes once they start.
- **Keepalive probe count** — unanswered probes before the peer is declared dead.
- **Idle connection** — ESTABLISHED with nothing in flight and an empty send buffer.
- **Proof of life** — the peer's forced ACK in response to a probe.
- **`SO_KEEPALIVE`** — the socket option that enables keepalive per connection.

## I. Reference tables

**I.1 — keepalive parameters**

```text
   constant             our value   role
   ──────────────────   ─────────   ───────────────────────────────────────────
   KEEPALIVE_IDLE_MS    60 000      idle time before the first probe
   KEEPALIVE_INTVL_MS    5 000      gap between probes
   KEEPALIVE_PROBES         3       unanswered probes before declaring death
   ⇒ death at  last_active + IDLE + PROBES·INTVL = +75 s of continuous silence
```

**I.2 — the probe vs other zero-ish segments we send**

```text
   segment              seq            purpose                         retransmitted?
   ──────────────────   ────────────   ─────────────────────────────   ──────────────
   keepalive probe      SND.NXT − 1    force an ACK (liveness)         no (Day 26)
   zero-window probe    SND.NXT        poke a closed window (1 byte)   yes (Day 14)
   challenge ACK        SND.NXT        prove our state (RFC 5961)      no (Days 19/23)
   ordinary ACK         SND.NXT        acknowledge received data       no
```

**I.3 — what detects each end-of-connection**

```text
   event                            mechanism            chapter
   ──────────────────────────────   ──────────────────   ───────
   abort                            incoming RST          19
   graceful close                   incoming FIN          5 / 19
   lost in-flight data              RTO / RACK / dup-ACK  6 / 10 / 24
   peer FIN'd then vanished         reaper                23
   peer vanished while idle         keepalive             26
```

> Re-type the `SND.NXT − 1` probe, the `last_active + IDLE + probes·INTVL` schedule, and the
> reset-on-activity with the book closed, then `cargo test`. When your stack quietly reclaims a
> connection whose peer pulled the plug — but never bothers a healthy idle one — you've closed the
> last liveness gap.
