# Doc 13 — TCP, Part 11: Nagle's Algorithm (and the `TCP_NODELAY` Escape Hatch)

> Goal: stop a chatty application from flooding the link with runt packets. If a program writes one byte at
> a time — a classic telnet session, a game sending keystrokes — a naive stack puts each byte in its own
> segment: 40 bytes of IP+TCP header to carry 1 byte of data, a 4000% overhead. Nagle's algorithm (RFC 896,
> 1984) fixes this with a single rule that needs no new packet type and no negotiation: *don't send a small
> segment while you're still waiting to hear about the last one.* This chapter implements it in three lines
> of `poll_transmit`, adds the `TCP_NODELAY` switch that turns it off, and dissects the infamous
> Nagle-vs-delayed-ACK interaction that has burned every networking engineer at least once.

This is the most over-discussed three lines in all of TCP, and worth every word, because Nagle sits at the
exact intersection of throughput and latency — and its interaction with delayed ACK is the canonical
example of two locally-sensible heuristics combining into a globally-terrible outcome. Knowing it cold is a
networking rite of passage.

**Contents**

Volume I — the chapter
1. The mental model: the small-packet (tinygram) problem
2. The rule, in one sentence
3. The exact condition — four cases
4. `TCP_NODELAY`: when coalescing is wrong
5. The famous bad interaction: Nagle + delayed ACK
6. The Rust: one field, one setter, a three-line guard
7. Worked example: five bytes, then three
8. The code, walked end to end
9. Verification
10. Why this, not that
11. Honesty: what production does, and what we don't
12. Rebuild it yourself — checklist + exercises
13. What the next step adds

Volume II — the exhaustive reference
- A. The history: John Nagle, RFC 896, and the 1984 congestion
- B. Nagle + delayed ACK, the full pathology
- C. `TCP_NODELAY`, `TCP_CORK`, and the option zoo
- D. The self-clocking property, in depth
- E. Where Nagle hurts — the write-write-read anti-pattern
- F. A worked tinygram-savings calculation
- G. Comparison to real stacks — autocorking and `MSG_MORE`
- H. Security — small-packet floods and amplification
- I. Performance — the overhead math
- J. Extended FAQ
- K. Anki starter deck
- L. Glossary
- M. Reference tables

---

# Volume I — the chapter

## 1. The mental model: the small-packet (tinygram) problem

A TCP segment costs 40 bytes of header before it carries any payload (20 IP + 20 TCP). Send one data byte
per segment and you are paying 40:1 overhead — and worse, you are putting 41-byte packets on the wire as
fast as the application can call `write`, which on a congested 1984 ARPANET (and on a congested 2026 Wi-Fi
link) is exactly the wrong thing to do. John Nagle's insight: a sender that has **unacknowledged data
already in flight** has *time to wait*. It can accumulate the application's next few small writes into one
larger segment, because it has to wait for an ACK anyway. The result is **self-clocking**: on a fast link
the ACK comes back quickly and you send small often; on a slow or loaded link the ACK is delayed and you
naturally coalesce more. The algorithm needs no timer, no threshold tuning, and no new wire format — just a
decision in the send path.

```text
   Without Nagle (app writes "h","e","l","l","o"):
     seg[seq=1 "h"]  seg[seq=2 "e"]  seg[seq=3 "l"] ...   five 41-byte packets

   With Nagle (one segment in flight at a time):
     seg[seq=1 "h"]  →  (wait for ACK; buffer "ello")  →  seg[seq=2 "ello"]   two packets
```

The "tinygram" (Nagle's word) is the enemy: a 41-byte packet carrying 1 useful byte. On a network where
*packets*, not bytes, are the scarce resource (router queue slots, per-packet processing), tinygrams cause
congestion out of all proportion to their data. Nagle bounds a connection to **at most one small,
unacknowledged segment outstanding** — a remarkably effective rule from a remarkably small change.

## 2. The rule, in one sentence

> **While any sent data is still unacknowledged, hold a *small* (sub-MSS) segment in the buffer until either
> that data is acknowledged or a full-sized segment can be sent.**

"Small" means smaller than the Maximum Segment Size (a full segment is always worth sending — it is
maximally efficient already). "Unacknowledged data in flight" is exactly our `FlightSize =
SND.NXT − SND.UNA > 0`. Put together: a runt is only held when sending it now would add a *second* small
packet to a network that has not yet confirmed the first.

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

The held bytes are not lost — they stay in `send_buf`. The event loop calls `poll_transmit` again on the
very next received packet, and when the ACK that clears the in-flight data arrives, `FlightSize` drops to 0
and the same bytes sail through. No timer, no separate state — the existing ACK flow re-drives it.

## 4. `TCP_NODELAY`: when coalescing is wrong

Nagle optimizes *throughput efficiency* at the cost of *latency*. For bulk transfer that is a pure win. For
request/response and interactive traffic it can hurt: an SSH keystroke, a game input, or a small RPC wants
to leave **now**, not wait for the previous segment's ACK. So TCP exposes a per-socket switch,
`TCP_NODELAY`, that disables Nagle. We model it as a single boolean — `self.nagle`, default `true` — flipped
by `set_nodelay(true)`:

```rust
pub fn set_nodelay(&mut self, nodelay: bool) { self.nagle = !nodelay; }
```

Our echo/HTTP server leaves Nagle on (its responses are either a single sub-MSS write sent with nothing in
flight, or bulk data in full segments — neither is held). A latency-sensitive app built on this stack would
call `set_nodelay(true)`. The naming is a small trap: `TCP_NODELAY = true` means "no Nagle delay" = Nagle
*off*, so `self.nagle = !nodelay`.

## 5. The famous bad interaction: Nagle + delayed ACK

This is the one thing every networking engineer eventually gets burned by, so it is worth knowing even
though our receiver does not (yet) delay ACKs. **Delayed ACK** (RFC 1122) lets a receiver wait up to
~200 ms before acknowledging, hoping to piggyback the ACK on reply data or to ack two segments at once. Now
compose it with Nagle on the sender:

```text
   sender (Nagle on)                 receiver (delayed ACK)
     write small "req-part-1"  →     got it… I'll delay the ACK (waiting for more / for reply data)
     write small "req-part-2"        Nagle: data in flight, holds it  →  nothing on the wire
        ...both sides wait...
     receiver's ~200 ms delayed-ACK timer finally fires  →  ACK
     sender: FlightSize=0 now → sends "req-part-2"
```

A ~40–200 ms stall on every request that the application split into two small writes — for *no reason but
the two heuristics colliding*. Each is locally correct (Nagle: "don't add a tinygram"; delayed ACK: "don't
ack every segment"), but composed they deadlock until a timer breaks it. The fixes: send the whole request
in one `write` (so it is not two tinygrams), or set `TCP_NODELAY`. This is why so much advice says "buffer
your request fully, then write once," and why latency-sensitive protocols disable Nagle. We document it
here; if you add delayed ACK later (exercise E1), come back and re-read this. (§B has the full pathology and
real incidents.)

## 6. The Rust: one field, one setter, a three-line guard

The whole feature is:

- a `nagle: bool` field on `Connection`, initialized `true` in both constructors;
- `set_nodelay(&mut self, nodelay)` (with `#[allow(dead_code)]` — the server never calls it, tests do);
- the three-line guard in `poll_transmit`.

No new packet type, no header change, no extra state machine. That economy is the point of Nagle: it is a
*scheduling* decision layered on machinery you already have (`flight_size`, the send buffer, the MSS chop).
It is also the first time our sender deliberately declines to send something the window would allow — a
small but real shift from "send whatever fits" to "send what is wise." The `#[allow(dead_code)]` on
`set_nodelay` is the same honest marker as elsewhere: a real, tested capability the *binary* doesn't
exercise.

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

With `TCP_NODELAY` set, the second `poll_transmit` skips the guard and sends "abc" immediately at `seq=6`
while "hello" is still unacknowledged — two packets instead of the coalesced one, by the application's
explicit choice. This is exactly what `nagle_holds_small_write_until_prior_data_acked` and
`nodelay_sends_small_write_immediately` assert.

## 8. The code, walked end to end

All in `src/tcp.rs`:

- **Struct**: `nagle: bool` joins `Connection`.
- **Constructors**: `accept_with_iss_at` and `connect_with_iss` set `nagle: true`.
- **`set_nodelay`**: flips it (`self.nagle = !nodelay`).
- **`poll_transmit`**: the `if self.nagle && n < mss && self.flight_size() > 0 { break; }` guard, placed
  *after* the `n == 0` window check so window-blocking and Nagle-holding stay distinct reasons to stop
  draining.

Nothing else changes — not `main.rs`'s loop, not the retransmission path. A held segment is just one that
has not been recorded yet; when it finally goes out it is recorded for retransmission exactly like any
other.

## 9. Verification

`cargo test` adds three tests:

- `nagle_holds_small_write_until_prior_data_acked` — the canonical sequence from §7: small write with
  nothing in flight goes; a second small write is held; the ACK flushes it.
- `nodelay_sends_small_write_immediately` — same setup with `set_nodelay(true)`; the second write is not
  held.
- `nagle_never_holds_a_full_segment` — with `cwnd` grown to 2·MSS, two full segments go out back-to-back
  even though the second leaves while the first is in flight (Nagle only holds *runts*).

All previous tests still pass — the guard never fires for full segments or for the first-in-flight segment,
so existing send behavior is unchanged.

## 10. Why this, not that

| Decision | Alternative | Why |
|---|---|---|
| Hold only sub-MSS segments | A fixed byte threshold or a coalescing timer | Nagle's MSS rule is self-clocking and tuning-free; a timer reintroduces the latency we're bounding. |
| Condition on `FlightSize > 0` | Condition on "buffer < MSS" alone | The point is "wait *because* something is unacked." Nothing in flight → nothing to wait for → the first runt must go. |
| Single `nagle` bool + `set_nodelay` | A full socket-option table | One switch covers the only option that matters here; `TCP_NODELAY` is exactly a boolean. |
| Leave Nagle on in the server | Force `TCP_NODELAY` | The echo/HTTP paths are never hurt by it, so the default that helps chatty apps is the right default. |

## 11. Honesty: what production does, and what we don't

- **The modern Nagle rule is slightly richer.** RFC 1122 / RFC 9293 §3.7.4 state it as: send if a full
  segment can go *or* (no unacked small segment is outstanding) *or* `TCP_NODELAY`. The "outstanding *small*
  segment" framing (not just "any data in flight") lets a stack send a small segment if the only thing in
  flight is itself small-and-acked-soon; the difference is subtle and our `FlightSize > 0` version is the
  classic RFC 896 statement, which is correct and what most descriptions teach.
- **Delayed ACK is not implemented (receiver side).** We ack every segment, so we *can't* trigger the §5
  stall against ourselves — but a peer that delays ACKs could still stall *our* Nagle-held writes. Exercise
  E1 adds delayed ACK so the interaction is reproducible.
- **No `TCP_CORK` / `MSG_MORE`.** Real stacks offer `TCP_CORK` ("hold everything until I uncork or a full
  segment forms") for explicit batching — the opposite knob from `TCP_NODELAY` (§C, §G). We have only the
  Nagle on/off boolean.
- **No autocorking.** Linux *autocorks* small writes briefly to coalesce them even without `TCP_CORK` (§G).
  We don't.
- **Interaction with the send buffer.** Our `poll_transmit` is called per received packet; a real stack also
  has a short Nagle/cork timer so held data isn't stuck if no ACK or packet arrives. On our cooperative link
  an ACK always comes; on a one-way bulk push you'd want a small flush timer.

None of these change the doc-13 contract (sub-MSS writes coalesce while data is unacked, `TCP_NODELAY`
overrides); they are refinements and the missing receiver-side half.

## 12. Rebuild it yourself — checklist + exercises

**Blank-file checklist:**

- [ ] State Nagle's rule in one sentence. What counts as "small"? What counts as "in flight"?
- [ ] Which of the four cases in §3 is the only one that holds?
- [ ] Why are the held bytes guaranteed to be sent eventually without any new timer?
- [ ] What does `TCP_NODELAY` change, and name one protocol that needs it.
- [ ] Describe the Nagle + delayed-ACK stall and two ways to avoid it.

**Exercises:**

- **E1.** Add delayed ACK to the *receiver* (ack at most every other segment, or after ~40 ms), then
  reproduce the §5 stall in a test and confirm `set_nodelay(true)` removes it.
- **E2.** Implement the RFC's "minimum of (MSS, ½·SND.WND)" small-segment rule variant and compare.
- **E3.** Add `TCP_CORK` semantics: hold *all* output (even full segments queued behind a runt) until
  uncorked or a full segment forms; contrast with `TCP_NODELAY` (§C).
- **E4.** Instrument `poll_transmit` to count how many segments Nagle saved over a simulated 1000 single-byte
  writes interleaved with ACKs (§F).

## 13. What the next step adds

Doc 14 closes a *correctness* hole that flow control left open: **zero-window probes** (the persist timer,
RFC 9293 §3.8.6.1). When the peer advertises a window of 0, our sender correctly stops — but if the later
"window re-opened" ACK is lost, both sides wait forever: a deadlock. The persist timer breaks it by
periodically sending a 1-byte probe into the closed window, forcing the peer to re-ack its current window.
It is the mirror image of today's lesson: Nagle decides *not* to send a small segment; the persist timer
insists on sending one *anyway*, because silence would be fatal.

---

# Volume II — the exhaustive reference

## A. The history: John Nagle, RFC 896, and the 1984 congestion

John Nagle wrote RFC 896 ("Congestion Control in IP/TCP Internetworks", January 1984) while at Ford
Aerospace, which ran an internal internet connected to the ARPANET. He observed two distinct pathologies:
the **small-packet problem** (tinygrams from interactive traffic swamping the network with header overhead)
and **congestion collapse** (which Jacobson later solved more fully, Doc 10 §A). His fix for the first — the
algorithm now bearing his name — was elegantly minimal: a connection may have *at most one* small,
unacknowledged segment outstanding. Everything else waits to be coalesced or sent full-sized.

The historical context matters: in 1984, links were slow and per-packet processing was expensive, so a
flood of tinygrams genuinely melted gateways. The algorithm has been default-on in essentially every TCP
since. Nagle himself has, for decades, patiently explained on forums (Hacker News, especially) that the
*real* bug people hit is not Nagle but its **interaction with delayed ACK** (§B) — a feature added *after*
his algorithm, by different people, without considering the composition. His repeated point: "turn off
delayed ACKs, not Nagle" — though in practice applications turn off Nagle because they can't control the
peer's delayed-ACK behavior.

## B. Nagle + delayed ACK, the full pathology

The deadlock arises because **each heuristic waits for the other**:

```text
   Nagle (sender):        "I won't send this small segment until my outstanding data is ACKed."
   Delayed ACK (receiver): "I won't ACK until I have reply data to piggyback on, or ~200 ms passes."
```

If the sender's protocol is "write a small header, then write the body, then read the reply"
(write-write-read, §E), the sequence is:

```text
   sender writes header (small) → on the wire (nothing in flight before it)
   receiver gets header → delays ACK (waiting for the body or for reply data it can't produce yet,
                                      because it needs the body to know what to reply)
   sender writes body (small) → Nagle holds it (header still unacked)
   ── stall ── neither side has a reason to act ──
   receiver's delayed-ACK timer fires (~40–200 ms) → ACK the header
   sender: FlightSize→0 → sends the body
   receiver gets the body → produces the reply
```

Result: ~200 ms added to *every* request, purely from the composition. Real incidents are legion: slow
database drivers (the classic "every query takes 40 ms" bug), Nagle-induced lag in early multiplayer games,
sluggish RPC frameworks, and the reason `curl`, `redis-cli`, Nagle-unaware HTTP clients, and most RPC
libraries set `TCP_NODELAY` by default. The three real fixes, in order of preference: **(1)** send the whole
message in *one* `write` (no tinygrams → Nagle never holds anything → best, fixes the root cause); **(2)**
set `TCP_NODELAY` (Nagle off → small writes go immediately); **(3)** disable delayed ACK on the receiver
(rarely controllable). The deep lesson — two correct local optimizations can compose into a global
pessimization — is why "understand the whole path" beats "tune one knob."

## C. `TCP_NODELAY`, `TCP_CORK`, and the option zoo

The send-batching knobs form a small spectrum from "send immediately" to "batch maximally":

```text
   option           effect                                          use when
   ──────────────   ─────────────────────────────────────────────  ──────────────────────────
   TCP_NODELAY      Nagle OFF: send every write immediately          interactive / RPC / latency-critical
   (default)        Nagle ON: coalesce sub-MSS while unacked         general / chatty apps
   TCP_CORK (Linux) hold ALL output until uncork or a full segment   explicit batching (sendfile + header)
   MSG_MORE         per-write "more coming" hint (like a 1-shot cork) streaming a response in pieces
```

`TCP_CORK` is the *opposite* extreme from `TCP_NODELAY`: where NODELAY says "never wait," CORK says "always
wait until I say go or a full segment forms," letting an app assemble a header + body + file into MTU-sized
segments before any leave. The classic use is a web server writing response headers then `sendfile`-ing the
body: cork, write headers, sendfile, uncork — so the headers and the file's first bytes share a segment.
`MSG_MORE` is a per-`send` version of the same hint. We implement only the Nagle boolean; CORK is exercise
E3.

## D. The self-clocking property, in depth

Nagle's elegance is that it needs *no timer and no tuning* — it paces itself to the network automatically:

- **On a fast/idle link:** the ACK for the outstanding small segment returns in ~1 RTT (tiny), so the held
  data is released almost immediately. Coalescing is minimal — which is correct, because a fast link can
  afford the small segments.
- **On a slow/loaded link:** the ACK is delayed (queueing, congestion), so more writes accumulate before
  release. Coalescing is aggressive — which is correct, because a loaded link must not be fed tinygrams.

The "clock" is the ACK stream itself (the same self-clocking idea as congestion control, Doc 10 §A): the
rate at which held data is released equals the rate at which ACKs return, which equals the rate the network
can sustain. No threshold to tune, no timer to misconfigure — the network's own feedback sets the coalescing
level. This is why a fixed-byte-threshold or timer-based small-packet rule (§10's alternatives) is *worse*:
it imposes a constant where Nagle adapts. The one weakness of pure self-clocking is exactly the delayed-ACK
interaction (§B): if the clock (the ACK) is *artificially* delayed, the release stalls — which is why the
two compose badly.

## E. Where Nagle hurts — the write-write-read anti-pattern

The pattern that triggers the stall is **write-write-read**: the application does two (or more) small writes
and then blocks reading the reply. The first write goes; the second is Nagle-held; the read can't complete
until the reply comes, which can't come until the second write arrives, which is held until the first is
ACKed (delayed). The cure is **write-read** with the request sent in *one* write:

```text
   anti-pattern (stalls):     write(header); write(body); read(reply);
   fixed (no stall):          buf = header + body; write(buf); read(reply);
```

This is why "coalesce your application-level message before calling `write`" is gospel for protocol
implementers — it's not about saving a syscall, it's about not creating two tinygrams that Nagle will
serialize behind a delayed ACK. Frameworks that can't guarantee single writes (because the message is built
incrementally) instead set `TCP_NODELAY` and accept the tinygram overhead in exchange for predictable
latency. The decision tree: *can you write your whole message at once?* → keep Nagle on (best). *No?* → set
`TCP_NODELAY` (good). *Streaming a large response in pieces but want MTU packing?* → `TCP_CORK`/`MSG_MORE`.

## F. A worked tinygram-savings calculation

An app makes 1000 single-byte writes over a connection with RTT 50 ms, link otherwise idle. Compare:

```text
   TCP_NODELAY (Nagle off):
     1000 writes → 1000 segments → 1000 × 41 bytes = 41,000 bytes on the wire (1000 useful)
     overhead = 40,000 / 41,000 = 97.6%

   Nagle on (one small segment outstanding at a time):
     write 1 → send (nothing in flight)
     writes 2..N during that RTT → buffered
     ACK (after ~50 ms) → flush the buffered run as ONE segment
     so per RTT: ~1 segment carrying however many bytes accumulated
     at, say, 20 writes per 50 ms RTT → ~50 segments total instead of 1000
     ≈ 50 × (40 + 20) = 3,000 bytes for 1000 useful → overhead ≈ 33%, and 20× fewer packets
```

The exact numbers depend on write rate vs RTT, but the shape is universal: Nagle turns "one packet per
write" into "one packet per RTT" for a chatty sender, cutting *packet count* (the scarce resource) by the
number of writes that fit in an RTT. The cost is up to one RTT of latency on the held data — a great trade
for bulk/chatty throughput, a bad one for a latency-critical single keystroke (hence `TCP_NODELAY`).

## G. Comparison to real stacks — autocorking and `MSG_MORE`

```text
   feature            Linux                                    this stack
   ────────────────   ──────────────────────────────────────  ──────────────────────
   Nagle              on by default; per-socket TCP_NODELAY     on by default; set_nodelay
   rule               RFC 9293 "no unacked SMALL segment"       FlightSize > 0 (RFC 896 classic)
   autocorking        tcp_autocorking: briefly hold small writes  none
   TCP_CORK / MSG_MORE explicit batching knobs                   none (exercise E3)
   delayed ACK        on (quickack togger)                       none (ack every segment)
   flush timer        small timer so held data isn't stuck       relies on next packet/ACK
```

**Autocorking** (Linux ≥ 3.14) is the interesting modern addition: even *without* `TCP_CORK`, if the
application is writing small chunks faster than they can be sent, the kernel briefly holds them to coalesce —
getting Nagle-like packing for apps that do many small writes but didn't set any option. It's a heuristic
("the app is mid-burst, wait a moment for more") that captures Nagle's benefit more aggressively while still
flushing promptly. Our stack relies entirely on the next ACK/packet to re-drive `poll_transmit`, so a held
runt on a silent link could wait indefinitely — a real stack's small flush timer (or autocork timer)
prevents that.

## H. Security — small-packet floods and amplification

- **Tinygram floods.** The pathology Nagle *prevents* is also an attack: an adversary (or a buggy app)
  emitting maximal tinygrams maximizes *packet* rate for minimal *byte* rate, stressing per-packet
  resources (router queues, NIC interrupt rate, firewall state) disproportionately. Nagle on the *sender*
  bounds a cooperative sender to one small outstanding segment; it does nothing against a *malicious* sender
  (who'd disable it), so packet-rate limiting at the network is the real defense.
- **Nagle as a (weak) side channel.** Because Nagle's coalescing depends on RTT and ACK timing, an observer
  can sometimes infer application write patterns or RTT from the *sizes and timing* of segments — a minor
  traffic-analysis signal. `TCP_NODELAY` (every write its own packet) actually *leaks more* about
  application message boundaries. Neither is a serious channel, but message-boundary preservation is why
  privacy-sensitive protocols pad and pace.
- **Delayed-ACK-induced DoS amplification of latency.** An attacker who can induce the §B stall (e.g. a
  middlebox that delays ACKs) inflates every request's latency by ~200 ms — a subtle performance attack on a
  victim using write-write-read. Defense: `TCP_NODELAY` + single-write messages.

The theme is modest: Nagle is a *cooperative* efficiency measure, not a security control; it bounds a
well-behaved sender and is irrelevant against a hostile one, while its *interaction* with delayed ACK is a
latency-attack surface for middleboxes.

## I. Performance — the overhead math

- **The 40:1 ratio.** A 1-byte payload in a 41-byte packet is 2.4% efficiency; even a 100-byte payload is
  71% (140/... no: 100/140 = 71%). Full MSS (1460 in 1500) is 97%. The header is fixed, so efficiency rises
  with payload — which is *why* Nagle coalesces toward full segments.
- **Packets vs bytes.** Nagle optimizes *packets*, which matters because many network costs are per-packet
  (router lookups, NIC interrupts, ACK generation, firewall state), not per-byte. Cutting packet count 20×
  (§F) saves far more than the byte reduction suggests.
- **The latency cost is bounded by one RTT.** Held data waits at most until the outstanding segment's ACK —
  one RTT. For bulk transfer that's invisible; for an interactive keystroke it's the whole user-perceived
  lag, hence `TCP_NODELAY`.
- **Our cost** is one comparison per `poll_transmit` iteration — free. The performance *risk* in our
  implementation is the missing flush timer (§G): a held runt on a one-way push with no return ACKs could
  stall, which a real stack's autocork/Nagle timer prevents.

## J. Extended FAQ

1. **What problem does Nagle solve?** Tinygrams — many small segments with 40:1 header overhead flooding the
   network.
2. **The rule in one sentence?** Hold a sub-MSS segment while data is unacked, until it's acked or a full
   segment forms.
3. **What counts as "small"?** Smaller than the MSS (a full segment is always sent).
4. **What counts as "in flight"?** `FlightSize = SND.NXT − SND.UNA > 0` (unacked data outstanding).
5. **Which of the four cases holds the segment?** Small + data in flight + Nagle on (`TCP_NODELAY` off).
6. **Why must the first runt go even though it's small?** Nothing is in flight, so there's nothing to wait
   for.
7. **Why must a full segment never be held?** It's already maximally efficient; coalescing buys nothing.
8. **How are held bytes eventually sent without a timer?** The next ACK clears the flight; `poll_transmit`
   re-runs and flushes.
9. **What does `TCP_NODELAY` do?** Disables Nagle — every write goes immediately.
10. **Why `self.nagle = !nodelay`?** `TCP_NODELAY = true` means "no delay" = Nagle off.
11. **Name a protocol that wants `TCP_NODELAY`.** SSH, interactive games, low-latency RPC.
12. **What is delayed ACK?** Receiver waits ~40–200 ms to ack, hoping to piggyback/batch (RFC 1122).
13. **What's the Nagle + delayed-ACK stall?** Each waits for the other → ~200 ms hang on write-write-read
    (§B).
14. **Two fixes for the stall?** Send the whole message in one write; or set `TCP_NODELAY`.
15. **What is the write-write-read anti-pattern?** Two small writes then a read → triggers the stall (§E).
16. **What is `TCP_CORK`?** The opposite of NODELAY: batch all output until uncork/full segment (§C).
17. **What is autocorking?** Linux briefly holding small writes to coalesce, even without `TCP_CORK` (§G).
18. **Why is Nagle "self-clocking"?** Held data releases at the ACK rate, which tracks the network's rate
    (§D).
19. **Does our receiver delay ACKs?** No (we ack every segment), so we can't stall ourselves — but a peer
    could.
20. **Is the doc-13 change big?** No — one field, one setter, a three-line guard; no new wire format.
21. **Does Nagle break full-segment bulk transfer?** No — full segments are never held; bulk runs at line
    rate.
22. **What's the overhead of a tinygram?** 40 header bytes per packet; 1-byte payload = 2.4% efficiency.
23. **Does Nagle defend against a malicious sender?** No — it's cooperative; a hostile sender disables it.
24. **What's missing vs Linux?** TCP_CORK, autocorking, delayed ACK, a flush timer (§11/§G).
25. **First time the sender declines to send?** Yes — Nagle is the first "restraint" in our send path.

## K. Anki starter deck

```text
Q: What problem does Nagle's algorithm solve?  A: tinygrams — small segments with huge header overhead.
Q: Nagle's rule in one sentence?  A: hold a sub-MSS segment while data is unacked, until acked or a full segment forms.
Q: What counts as "in flight" for Nagle?  A: FlightSize = SND.NXT − SND.UNA > 0.
Q: Which case holds the segment?  A: small + data in flight + Nagle on.
Q: Why must the first small write go?  A: nothing is in flight → nothing to wait for.
Q: Why are full segments never held?  A: they're already maximally efficient.
Q: How are held bytes flushed without a timer?  A: the next ACK clears the flight; poll_transmit re-runs.
Q: What does TCP_NODELAY do?  A: disables Nagle — send every write immediately.
Q: Why self.nagle = !nodelay?  A: TCP_NODELAY=true means "no delay" = Nagle off.
Q: What is delayed ACK?  A: receiver waits ~40–200 ms to ack (piggyback/batch).
Q: The Nagle + delayed-ACK stall?  A: each waits for the other → ~200 ms hang on write-write-read.
Q: Two fixes for the stall?  A: one write for the whole message; or TCP_NODELAY.
Q: write-write-read anti-pattern?  A: two small writes then a read → triggers the stall.
Q: TCP_CORK vs TCP_NODELAY?  A: cork batches everything; nodelay sends everything immediately.
Q: Why is Nagle "self-clocking"?  A: held data releases at the ACK rate, which tracks the network's rate.
```

## L. Glossary

- **Nagle's algorithm** — hold a sub-MSS segment while unacked data is outstanding (RFC 896).
- **Tinygram** — a small packet with disproportionate header overhead (Nagle's target).
- **`TCP_NODELAY`** — the per-socket switch that disables Nagle.
- **`TCP_CORK` / `MSG_MORE`** — explicit batching knobs (the opposite of NODELAY).
- **Delayed ACK** — receiver waiting ~40–200 ms before acknowledging (RFC 1122).
- **The Nagle + delayed-ACK stall** — the ~200 ms deadlock when both heuristics wait on each other.
- **Write-write-read** — the application pattern that triggers the stall.
- **Self-clocking** — releasing held data at the rate ACKs return (the network's rate).
- **Autocorking** — Linux's heuristic coalescing of small writes without `TCP_CORK`.
- **FlightSize** — unacked data outstanding, `SND.NXT − SND.UNA`.

## M. Reference tables

**M.1 — The Nagle send decision**

```text
   segment size   FlightSize   TCP_NODELAY   action
   ────────────   ──────────   ───────────   ───────
   = MSS (full)   any          any           send
   < MSS (small)  0            any           send (first runt)
   < MSS          > 0          off           HOLD
   < MSS          > 0          on            send
```

**M.2 — The batching spectrum**

```text
   knob          latency        packing        use case
   ───────────   ────────────   ────────────   ─────────────────────────
   TCP_NODELAY   lowest          none           interactive, RPC, games
   Nagle (def.)  +≤1 RTT (runt)  good (chatty)  general
   TCP_CORK      highest         maximal        sendfile + headers, streaming
```

**M.3 — Header-overhead efficiency**

```text
   payload bytes   packet bytes (≈+40)   efficiency
   ─────────────   ──────────────────    ──────────
   1               41                     2.4%
   100             140                    71%
   536 (min MSS)   576                    93%
   1460 (Eth MSS)  1500                   97%
```

> Re-type the three-line guard and the `nagle` field with the book closed, then `cargo test`. You have
> taught your sender its first bit of restraint — and learned the most over-discussed three lines in all of
> TCP, including the delayed-ACK interaction that has cost the industry untold debugging hours.
