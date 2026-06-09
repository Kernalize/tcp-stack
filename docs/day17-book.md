# Day 17 — TCP, Part 15: Window Scaling (the Other Half of RFC 7323)

> Goal: lift the 64 KB ceiling on the window. TCP's window field is only 16 bits, so without help a receiver
> can advertise at most 65 535 bytes — and on a "long fat" path (high bandwidth × high latency) that caps
> throughput far below the link's capacity. **Window scaling** (RFC 7323 §2) negotiates a left-shift, applied
> to the window field, that stretches the effective window up to ~1 GB. It is negotiated once in the SYN
> exchange, like timestamps, and it forces the last 16-bit window in our code — `SND.WND` — to widen to 32
> bits.

The window field was sized in 1981, when 64 KB was a generous amount of in-flight data. On a modern long-fat
network it's a throttle that wastes 99% of the link. Window scaling fixes a 1981 decision without changing
the wire field — a masterclass in backward-compatible protocol evolution — by negotiating, once, a shared
multiplier. It's the feature that makes TCP usable on a transcontinental gigabit path, and the day our last
16-bit window finally becomes 32-bit.

**Contents**

Volume I — the chapter
1. The mental model: the bandwidth-delay product and a 16-bit field
2. The Window Scale option and how it is negotiated
3. The asymmetry: each side scales its own window
4. Widening `SND.WND` to `u32`
5. Why our own advertised scale is 0
6. The Rust: the widening, the clamp, the shift
7. Worked example: a 128 000-byte window from a 1000-byte field
8. The code, walked end to end
9. Verification
10. Why this, not that
11. Honesty: what production does, and what we don't
12. Rebuild it yourself — checklist + exercises
13. What the next step adds

Volume II — the exhaustive reference
- A. The bandwidth-delay product, exhaustively
- B. The Window Scale option in full
- C. Why the handshake windows are unscaled
- D. The shift cap of 14 and why
- E. PAWS is mandatory with scaling
- F. A worked long-fat-network throughput calculation
- G. Comparison to real stacks — autotuning and middleboxes
- H. Security — window-scale stripping and silent degradation
- I. Performance — the BDP, autotuning, and bufferbloat
- J. Extended FAQ
- K. Anki starter deck
- L. Glossary
- M. Reference tables

---

# Volume I — the chapter

## 1. The mental model: the bandwidth-delay product and a 16-bit field

To keep a pipe full, a sender must have at least one **bandwidth × round-trip-time** worth of data in flight
before the first ACK returns. On a 1 Gbit/s link with 80 ms RTT that is `1e9/8 × 0.080 ≈ 10 MB`. But the
receiver can only *advertise* what fits in the 16-bit window field: 65 535 bytes. The sender, obeying flow
control, stops after 64 KB and waits — using `64 KB / 10 MB ≈ 0.6 %` of the link. The window field, sized in
1981, is the bottleneck.

Window scaling fixes it without changing the field: both ends agree, at connection setup, on a **shift count**
`S` (0–14). Thereafter a window field value `W` is interpreted as `W << S`. With `S = 14`, a full field of
65 535 means `65 535 × 16 384 ≈ 1 GB` — plenty for any path. The elegance: the 16-bit field on the wire never
changes (every middlebox and old stack still parses it), but its *interpretation* is multiplied by a factor
negotiated once. It's a pure semantic overlay on an unchanged syntax — the only way to fix a header field
that a billion deployed stacks already read (§H on what happens when a middlebox *doesn't* get the memo).

## 2. The Window Scale option and how it is negotiated

The option is 3 bytes, padded to 4 with a leading NOP:

```text
   [ NOP | kind=3 | len=3 | shift ]
```

Negotiation mirrors timestamps (RFC 7323 §2.2):

- A host offers scaling by putting the option in its **SYN** (and, for a passive open, in its **SYN-ACK**
  *only if the SYN offered it*).
- Scaling is used only if **both** SYNs carried the option.
- The shift in a host's option applies to *that host's* future window fields — it tells the peer "multiply my
  advertised window by `2^shift`."
- The SYN/SYN-ACK windows themselves are **never** scaled; the shift takes effect only on subsequent segments
  (§C). (We never need to special-case this, because we apply the shift in ESTABLISHED, after the handshake.)

## 3. The asymmetry: each side scales its own window

The subtle part: window scaling is **per-direction**. There are two independent shifts:

- `snd_wscale` — the shift the *peer* advertised. We apply it to the peer's window field to get the true
  `SND.WND` (how much *we* may send).
- `rcv_wscale` — the shift *we* advertised. The peer applies it to our window field to get how much *it* may
  send us.

They need not be equal. A big-buffer server and a tiny embedded client can each pick the shift that suits
their own receive buffer. So "enabling window scaling" is really "I learn the peer's shift for the data I
send, and the peer learns my shift for the data it sends." This is the same per-direction asymmetry as the
window itself (Day 8) and MSS (Day 15): each side advertises a property of *its own* receive path, and the
peer applies it when *sending*.

## 4. Widening `SND.WND` to `u32`

`SND.WND` is the peer's advertised window — and with scaling it can exceed 65 535. So the `SendSequence.wnd`
field changes from `u16` to `u32`, and the flow-control math follows:

```rust
let new_wnd = (th.window as u32) << self.snd_wscale;   // recover the true window
self.send.wnd = new_wnd;
// usable window = min(SND.WND, cwnd) − FlightSize   — now entirely in u32
```

This is the last place a window lived in 16 bits. The receive window we *advertise* stays a `u16` field (it's
16 bits on the wire by definition), and the duplicate-ACK "window unchanged" test (Day 14) now compares the
*scaled* values, so a pure window update is still distinguished from a real duplicate even when the window
exceeds 64 KB. The widening is the day's one real type change, and it ripples exactly as far as the
flow-control arithmetic — `usable_window` drops an old `as u32` cast because everything is `u32` now.

## 5. Why our own advertised scale is 0

We negotiate scaling — we send the Window Scale option — but with a shift of **0**. Our receive buffer is only
~1 KB, so we have no large window to advertise; scaling our own field would gain nothing and only risk
rounding a tiny window down (a shift of `S` means the smallest representable window step is `2^S` bytes, so
advertising a 1 KB buffer with `S=7` could only express multiples of 128). Sending shift 0 still *enables*
the feature, which is what lets us honor the peer's (possibly huge) window in the other direction. That is the
honest choice for this stack: implement the mechanism fully, advertise truthfully. Bumping our receive buffer
and advertising a real shift is a one-line exercise once the buffer grows (E1).

## 6. The Rust: the widening, the clamp, the shift

- **`u16 → u32` for `SND.WND`.** The wire field is 16 bits; the *interpreted* window is up to 30 bits
  (`65535 << 14`), so it must be `u32`. We change `SendSequence.wnd` to `u32` and let the flow-control math
  follow — `(th.window as u32) << snd_wscale` produces a value that can't overflow `u32` (max
  `65535 × 16384 ≈ 1.07e9 < 2^32`). Crucially, only the *send* window widens; the advertised field stays
  `u16` (it's literally a 16-bit wire field).
- **The clamp.** `parse_options` clamps the peer's shift to `MAX_WSCALE = 14` (`data[0].min(MAX_WSCALE)`). A
  shift > 14 is illegal (RFC 7323 §2.3, §D) — a bug or attack — and clamping it (rather than rejecting the
  segment) is the defensive choice: we still negotiate, just at the legal maximum. This is the same
  "validate/clamp values from the wire" discipline as the option-length checks (Day 15 §D).
- **The shift is a no-op when not negotiated.** `snd_wscale` defaults to 0, so `W << 0 == W` — a
  non-scaling connection takes the exact pre-Day-17 path, and every prior test passes untouched. Backward
  compatibility falls out of the identity `x << 0 = x`, with no conditional.
- **`Option<u8>` for the parsed scale** distinguishes "no WS option" (`None` → don't enable) from "WS option
  with shift 0" (`Some(0)` → enable at shift 0), which matters for the both-sides negotiation.

## 7. Worked example: a 128 000-byte window from a 1000-byte field

Peer's SYN offers window scale 7 (×128); both sides enable scaling.

```text
   handshake:  peer SYN  WS=7   →  snd_wscale = 7
   later ACK:  window field = 1000
               SND.WND = 1000 << 7 = 128 000 bytes
```

The sender may now keep 128 000 unacknowledged bytes in flight (subject to cwnd), versus the 1000 a naive
reading of the field would allow — a 128× difference, all from one shift negotiated at setup. Note the
*granularity* cost: with `S=7`, the window moves in steps of 128 bytes (field 1000 → 128 000, field 1001 →
128 128), so the receiver can't express a window to byte precision — a fine trade for 128× the range.

## 8. The code, walked end to end

- `parse_options` yields `window_scale` (clamped to 14).
- The SYN/SYN-ACK builders concatenate `MSS [+ WS] [+ TS] [+ SACK-Perm]` — each sub-blob already 4-byte
  aligned, so the concatenation is too.
- `accept` sets `snd_wscale` from the peer's SYN; `on_segment`'s SYN_SENT branch sets it from the SYN-ACK
  (active open).
- ESTABLISHED left-shifts the incoming window into the now-`u32` `SND.WND`; the dup-ACK comparison (Day 14)
  uses the scaled values.
- `usable_window` drops its old `as u32` cast — the math is `u32` throughout.

`main.rs` already parses options and routes through `on_segment`, so it needs only the progress note.

## 9. Verification

`cargo test` adds:
- `parse_options_reads_and_clamps_window_scale` — reads a shift, clamps `> 14` to 14, rejects a wrong-length
  option.
- `synack_offers_window_scale_when_peer_does` / `synack_omits_window_scale_when_peer_silent`.
- `peer_window_is_left_shifted_by_negotiated_scale` — a 1000-byte field with shift 7 becomes `SND.WND =
  128 000`.
- `active_open_adopts_peer_window_scale`.

## 10. Why this, not that

| Decision | Alternative | Why |
|---|---|---|
| Advertise our own scale = 0 | Pick a non-zero shift | Our receive buffer is ~1 KB; a shift would only round it down. Shift 0 still enables scaling so we can honor the peer's window. |
| Apply the shift in ESTABLISHED | Also scale the SYN/SYN-ACK window | RFC 7323 §2.2: handshake windows are unscaled; applying the shift only after the handshake matches the spec without a special case (§C). |
| Widen only `SND.WND` to `u32` | Widen the advertised field too | The wire field stays 16 bits by definition; only the *interpreted* send window can exceed 64 KB. |
| Clamp the peer's shift to 14 | Trust it | RFC 7323 §2.3 caps the shift at 14; a larger value is a bug or attack and must be clamped (§D). |

## 11. Honesty: what production does, and what we don't

- **No dynamic receive window / `rcv_wscale`.** We advertise shift 0 and a flat ~1 KB window, so we never
  *use* scaling in our receive direction — we only *honor* the peer's in our send direction. A real stack
  picks `rcv_wscale` from its (autotuned, large) receive buffer and emits `field = real_window >> rcv_wscale`
  (Day 8 §I, exercise E1).
- **PAWS is the silent prerequisite (Day 16).** A bigger window means more in-flight data means the 32-bit
  sequence space wraps faster — so window scaling on a fast path is only *safe* because timestamps + PAWS
  reject wrapped old duplicates (§E). We implemented PAWS first (Day 16) for exactly this reason.
- **No window-scale-loss recovery.** If the SYN carrying the WS option is lost and retransmitted *without*
  it (some buggy stacks), scaling silently fails to negotiate. We always include it on retransmits (the whole
  SYN is stored byte-for-byte, Day 12), which is correct; the hazard is a peer or middlebox that strips it
  (§H).
- **No middlebox-stripping detection.** If a middlebox strips our WS option from the SYN but not the
  SYN-ACK (or vice versa), the two ends disagree on whether scaling is active — a famous cause of *silent
  throughput collapse or data corruption* (§H). Real stacks have heuristics; we trust the negotiation.
- **The cap and granularity.** We clamp to 14 and accept the resulting granularity (window steps of `2^S`);
  a real stack picks the *smallest* shift that covers its buffer to minimize granularity loss.

None of these change the day-17 contract (we negotiate scaling and honor the peer's scaled window); they are
the receive-side dynamism and middlebox-robustness a production stack adds.

## 12. Rebuild it yourself — checklist + exercises

**Blank-file checklist:**

- [ ] Why does a 16-bit window throttle a long-fat-network path? Compute a BDP example.
- [ ] Draw the Window Scale option bytes. What does the shift apply to?
- [ ] Explain the per-direction asymmetry: what are `snd_wscale` and `rcv_wscale`?
- [ ] Why must `SND.WND` become `u32` but the advertised field stay 16 bits?
- [ ] Why do we advertise shift 0, and what does that still buy us?

**Exercises:**

- **E1.** Grow the receive buffer to, say, 256 KB and advertise a real `rcv_wscale`; scale the window we emit
  (`field = real_window >> rcv_wscale`) and add a test.
- **E2.** Enforce RFC 7323 §2.2: ignore a Window Scale option that arrives on a non-SYN segment.
- **E3.** Combine with Day 16: confirm a SYN-ACK carrying MSS + WS + TS parses correctly and the data offset
  / checksum are right.
- **E4.** Capture a real Linux SYN with `tcpdump -v` and verify `parse_options` reads its window scale
  alongside MSS, SACK-permitted, and timestamps.
- **E5.** Implement receive-window autotuning (§I): grow the advertised window toward the measured BDP as the
  connection proves it can drain fast, picking the smallest `rcv_wscale` that covers it.

## 13. What the next step adds

Day 18 is the big one: **Selective Acknowledgment** (SACK, RFC 2018). Today a single lost segment forces the
sender to retransmit *everything* after it on a timeout, because a cumulative ACK can only say "I have through
byte N." SACK lets the receiver also say "…and I separately have bytes N+1000 to N+2000," so the sender
retransmits only the genuine hole. It uses the option framework (a SACK-Permitted option in the SYN, SACK
blocks in ACKs), the reassembler's buffered ranges (to *generate* blocks), and the retransmission queue (to
*act* on them) — the culmination of the last several days. And it matters *most* on exactly the long-fat
paths window scaling just unlocked, where a window's worth of needless retransmission is megabytes.

---

# Volume II — the exhaustive reference

## A. The bandwidth-delay product, exhaustively

The **bandwidth-delay product (BDP)** is the amount of data "in the pipe" when it's full — the minimum window
needed to keep a sender transmitting continuously:

```text
   BDP = bandwidth × RTT

   link                RTT      BDP                window needed   16-bit field enough?
   ─────────────────   ──────   ────────────────   ─────────────   ───────────────────
   10 Mbit/s LAN       1 ms     1.25 KB             1.25 KB         yes (≪ 64 KB)
   100 Mbit/s          10 ms    125 KB              125 KB          NO (> 64 KB)
   1 Gbit/s            80 ms    10 MB               10 MB           NO (155× too small)
   10 Gbit/s           100 ms   125 MB              125 MB          NO (2000× too small)
   satellite (10 Mb)   600 ms   750 KB              750 KB          NO
```

A path with a large BDP — high bandwidth, high latency, or both — is a **"long fat network" (LFN**, pronounced
"elephan(t)"). The 64 KB window caps throughput at `64 KB / RTT`: on the 1 Gbit/s × 80 ms path that's
`65535 / 0.080 ≈ 819 KB/s ≈ 6.5 Mbit/s` — **0.6%** of the link. Window scaling lifts the cap so the window
can reach the BDP, letting the sender keep the pipe full. The throughput a window-limited connection achieves
is exactly `window / RTT`, so the window *must* be ≥ BDP for line-rate — which is why every modern stack
enables scaling by default. The satellite row is instructive: even modest bandwidth needs scaling when RTT is
huge (geostationary orbit is ~600 ms round trip).

## B. The Window Scale option in full

RFC 7323 §2 specifies the option and its negotiation precisely:

```text
   +--------+--------+--------+
   |Kind=3  |Len=3   | shift  |    shift ∈ [0, 14]
   +--------+--------+--------+      (we NOP-pad to 4 bytes: [NOP, 3, 3, shift])
```

Rules:
- The option MAY appear **only in a SYN** (and SYN-ACK). It MUST be ignored on a non-SYN segment.
- Sending it means "I will scale *my* advertised windows by `2^shift`; apply this shift when reading my window
  field." So the shift describes the *sender's* receive window scaling.
- Window scaling is enabled (in *both* directions) only if **both** SYNs carried the option. If either side
  omits it, neither side scales — it's all-or-nothing and bilateral.
- The shift applies to all windows *after* the SYN; the SYN/SYN-ACK windows are unscaled (§C).
- `shift` is capped at 14 (§D); a larger value MUST be treated as 14 (we clamp).

Our `ws_option(shift)` emits `[NOP, 3, 3, shift]`; `parse_options` reads and clamps it; `snd_wscale` stores
the peer's shift, `OUR_RCV_WSCALE = 0` is ours. The both-sides rule is implemented exactly as for timestamps:
offer always, enable only when the peer also offered.

## C. Why the handshake windows are unscaled

The SYN and SYN-ACK carry a window field, but it is **never** scaled — read it literally. Why? A
bootstrapping problem: the scale factor is being *negotiated by* the SYN exchange, so at the moment the SYN's
window is read, the receiver doesn't yet *know* the shift (the negotiation isn't complete until both SYNs are
seen). Scaling the SYN's window would be a chicken-and-egg paradox. So RFC 7323 §2.2 mandates: the window in
the SYN/SYN-ACK is the literal, unscaled value; the agreed shift takes effect only on segments *after* the
handshake.

We get this for free: we apply the shift in the ESTABLISHED handler, which only runs *after* the handshake
completes. The SYN-handling code reads the window literally (and in practice ignores it — we don't act on the
peer's window until ESTABLISHED anyway). No special case needed; the architecture (shift applied in
ESTABLISHED) makes the rule automatic. A stack that applied the shift everywhere would have to special-case
the handshake; ours doesn't because the shift lives in the right place.

## D. The shift cap of 14 and why

The shift is capped at **14**, giving a maximum window of `65535 << 14 = 65535 × 16384 ≈ 1.07 GB`. Why 14 and
not 15 or 16? The constraint is the **sequence-number arithmetic**. TCP's "is A before B?" comparison (RFC
1982, Day 3) works by checking whether the wrapping difference lands in the *lower half* of the 32-bit space —
i.e. it assumes the window is less than `2^31`. If the window could approach or exceed `2^31`, the modular
comparisons that decide acceptability would become ambiguous (you couldn't tell "far ahead" from "far
behind"). RFC 7323 §2.3 caps the maximum window at `2^30` (a full field `2^16 − 1` shifted by 14 is just under
`2^30`), comfortably below the `2^31` limit, leaving headroom so sequence comparisons stay unambiguous even
with a maximally-scaled window in flight.

So the cap isn't arbitrary — it's the largest shift that keeps the window safely under half the sequence
space, preserving the wrap-aware comparisons everything else relies on. A peer advertising shift 15+ is either
buggy or hostile (trying to break our sequence math), which is exactly why we *clamp* to 14 rather than
honor it.

## E. PAWS is mandatory with scaling

Window scaling and timestamps were specified *together* (RFC 1323, now RFC 7323) for a reason that's easy to
miss: **scaling makes PAWS necessary.** The chain:

```text
   bigger window  →  more data in flight  →  the 32-bit sequence space wraps faster
                  →  more chances for a delayed old segment to reappear with an in-window
                     (wrapped) sequence number  →  silent corruption  →  PAWS required
```

Day 16 §E quantified it: at 10 Gbit/s the sequence space wraps in ~3.4 s, well under the MSL, so a delayed
duplicate can alias current data. A *large* window (which scaling enables) is exactly what pushes a connection
into the high-throughput regime where this happens. So you cannot safely deploy window scaling on a fast path
*without* PAWS to reject wrapped duplicates by timestamp. This is why the curriculum did timestamps (Day 16)
*before* window scaling (Day 17): PAWS is the safety net that scaling's larger windows require. The two halves
of RFC 7323 are not independent features bundled by accident — scaling unlocks the speed, PAWS makes that
speed safe, and together they make TCP work on the modern internet.

## F. A worked long-fat-network throughput calculation

A 1 Gbit/s link, 80 ms RTT, no loss. Compare throughput without and with window scaling.

```text
   without window scaling (16-bit window, max 65535 bytes):
     throughput = window / RTT = 65535 / 0.080 = 819,187 bytes/s ≈ 6.55 Mbit/s
     link utilization = 6.55 / 1000 = 0.66%

   with window scaling (shift 7 → window 128 KB; shift 10 → 64 MB):
     to fill the BDP (10 MB) need a window ≥ 10 MB → shift such that 65535 << S ≥ 10e6
       65535 << 8 = 16.8 MB  → shift 8 suffices
     throughput (window-limited) = 10 MB / 0.080 = 125 MB/s = 1 Gbit/s  → 100% utilization
```

The difference is **150×** — from 0.66% to 100% of a gigabit link, purely from a shift negotiated at setup.
This is not a micro-optimization; it's the difference between a transcontinental link being usable or not. The
same calculation explains why a large file transfer over a high-latency path was painfully slow before window
scaling was universally deployed, and why "tune your TCP window" was once standard advice for scientific
data movers (before autotuning, §I, made it automatic).

## G. Comparison to real stacks — autotuning and middleboxes

```text
   aspect             Linux                                    this stack
   ────────────────   ────────────────────────────────────────  ──────────────────────
   on by default      yes (net.ipv4.tcp_window_scaling=1)        offered always
   rcv_wscale         derived from autotuned receive buffer       0 (flat ~1 KB window)
   snd_wscale         learned from peer's SYN/SYN-ACK             learned ✓
   receive autotuning grows the window toward the BDP             none (flat window)
   shift cap          14                                          14 (clamped)
   middlebox handling  heuristics for stripped options            trust the negotiation
```

The big real-world feature we lack is **receive-window autotuning** (Day 8 §I): Linux starts with a modest
window and grows it toward the measured BDP as the connection proves it can drain fast, choosing
`rcv_wscale` to cover the target. This balances memory (don't allocate huge buffers for slow connections)
against throughput (do allocate them for fast ones), per-connection, automatically — which is why "tuning the
window" is no longer manual advice. Our flat shift-0 window means we *honor* a peer's big window (our send
direction works on an LFN) but never *advertise* one (our receive direction is capped) — fine for an echo
server, wrong for a bulk receiver.

## H. Security — window-scale stripping and silent degradation

- **Middlebox option stripping → silent corruption/degradation.** The infamous window-scaling hazard: a
  middlebox (firewall, old NAT) that **strips the WS option from one SYN but not the other** leaves the two
  ends *disagreeing* on whether scaling is active. If the server thinks scaling is off (shift 0) but the
  client thinks it's on (shift 7), the client reads the server's window field shifted when it shouldn't be —
  interpreting a 1000-byte window as 128 000, sending 128× too much data, overrunning the receiver. Historically
  this caused mysterious stalls and corruption, and it's a major reason new TCP options are so hard to deploy
  (the "ossification" that pushed HTTP/3 to QUIC over UDP). Real stacks added heuristics (e.g. disable scaling
  if the negotiation looks inconsistent); we trust the negotiation, so a stripping middlebox could fool us
  (the SYN we store and retransmit always includes WS, which is correct on our end, but we can't detect the
  *peer's* option being stripped).
- **Oversized-window resource pressure.** Honoring a huge scaled window means a sender may keep a huge amount
  of data in flight / buffered for retransmission (Day 6's retx queue holds a window's worth) — a memory cost
  a malicious peer advertising a maximal window could try to inflate. Bounded send buffers defend; our small
  buffers make it moot.
- **The shift-cap clamp as defense.** A peer advertising shift > 14 is trying to push the window toward `2^31`
  where sequence comparisons break (§D); clamping to 14 is a security measure, not just spec compliance —
  it keeps the modular arithmetic unambiguous regardless of what the peer claims.
- **Fingerprinting.** The advertised window scale (and whether it's offered at all) is part of the OS
  fingerprint (Day 15 §H) — our fixed shift-0 offer is identifiable.

The theme: window scaling's semantic-overlay design (unchanged field, negotiated multiplier) is robust to
*old* stacks (they ignore the option and don't scale) but fragile to *middleboxes that partially strip it* —
the canonical example of protocol ossification — and the shift cap is a real security boundary against
sequence-math attacks.

## I. Performance — the BDP, autotuning, and bufferbloat

- **Window must reach the BDP for line rate** (§A, §F). Below it, throughput is `window / RTT`; scaling is
  what lets the window get there. This is the single biggest throughput lever on a high-latency path.
- **Autotuning finds the sweet spot.** A *static* large window wastes memory on slow connections and (with
  over-buffered routers) worsens bufferbloat; a *static* small window throttles fast ones. Receive-window
  autotuning grows the window per-connection toward the measured BDP, getting throughput without blanket
  memory cost — the production answer scaling makes possible (a window can only autotune *up* if it can
  exceed 64 KB).
- **Bufferbloat interaction.** A large window lets a sender put a lot in flight; if routers have deep buffers
  and congestion control is loss-based (Day 10), that data piles up in queues, inflating RTT for everyone.
  Window scaling alone doesn't cause bufferbloat (congestion control governs *how much* you actually send),
  but it removes the 64 KB cap that used to *accidentally* limit it. The real fixes are AQM (CoDel) and
  better congestion control (BBR), not a smaller window.
- **Granularity cost.** A shift `S` means the window is expressible only in multiples of `2^S` bytes (§7), so
  a large shift coarsens flow control slightly — a negligible cost for the range it buys, and why a real
  stack picks the *smallest* shift covering its buffer.
- **Our cost** is one shift per incoming segment (`<<`) and the `u16→u32` widening — free. The performance
  *limitation* is our flat shift-0 receive window (we can't receive fast over an LFN), by design for an echo
  server; our *send* direction correctly fills an LFN by honoring the peer's scaled window.

## J. Extended FAQ

1. **What does window scaling fix?** The 16-bit window field capping throughput on a high-BDP (long-fat)
   path.
2. **What is the BDP?** Bandwidth × RTT — the in-flight data needed to keep a pipe full.
3. **Why is 64 KB too small?** On a 1 Gbit/s × 80 ms path the BDP is 10 MB; 64 KB fills 0.6% of the link.
4. **How does scaling work?** Both ends negotiate a shift `S`; a window field `W` means `W << S`.
5. **What's the max window?** `65535 << 14 ≈ 1 GB`.
6. **Where is the WS option valid?** SYN / SYN-ACK only (ignored on other segments).
7. **How is it negotiated?** Both SYNs must carry it (bilateral, all-or-nothing).
8. **What does a host's shift describe?** *Its own* receive window scaling — the peer applies it when reading
   that host's window.
9. **Is window scaling per-direction?** Yes — `snd_wscale` (peer's, for our sends) and `rcv_wscale` (ours,
   for the peer's sends) are independent.
10. **Are the SYN/SYN-ACK windows scaled?** No — they're literal; the shift applies only after the handshake
    (§C).
11. **Why are the handshake windows unscaled?** The shift is still being negotiated when they're read
    (bootstrap).
12. **Why does `SND.WND` become `u32`?** A scaled window can exceed 65535; the *interpreted* value needs 32
    bits.
13. **Does the advertised window field widen?** No — it stays 16 bits on the wire; only the interpretation
    grows.
14. **Why advertise our own scale = 0?** Our receive buffer is ~1 KB; a shift would only coarsen it. Shift 0
    still enables the feature.
15. **What does shift 0 still buy us?** It enables scaling so we can honor the peer's (possibly huge) window
    when sending.
16. **Why clamp the shift to 14?** RFC 7323 §2.3; a larger shift pushes the window toward 2^31 where sequence
    math breaks (§D).
17. **What's the granularity cost of shift S?** The window is expressible only in multiples of `2^S` bytes.
18. **Why does scaling need PAWS?** Bigger windows wrap the sequence space faster → wrapped duplicates → PAWS
    required (§E).
19. **Why were timestamps done before scaling?** PAWS (timestamps) is the safety net scaling's large windows
    require.
20. **What's the middlebox-stripping hazard?** A middlebox removing WS from one SYN → ends disagree on scaling
    → corruption (§H).
21. **What is receive-window autotuning?** Growing the advertised window toward the BDP per connection (real
    stacks; we don't).
22. **Does a non-scaling connection change?** No — `snd_wscale = 0`, `W << 0 = W`, byte-identical to before.
23. **What's the throughput on an LFN with vs without scaling?** Up to ~150× (0.66% → 100% of a gigabit link)
    (§F).
24. **What does the dup-ACK check compare now?** The *scaled* window values (Day 14), so updates aren't
    miscounted.
25. **Why is it the "last 16-bit window"?** `SND.WND` was the final window still pinned to `u16`; it's now
    `u32`.

## K. Anki starter deck

```text
Q: What does window scaling fix?  A: the 16-bit window field capping throughput on a long-fat (high-BDP) path.
Q: What is the BDP?  A: bandwidth × RTT — in-flight data needed to keep the pipe full.
Q: Max window with scaling?  A: 65535 << 14 ≈ 1 GB.
Q: How is window scaling negotiated?  A: both SYNs carry the WS option (bilateral, SYN-only).
Q: What does a host's shift describe?  A: its own receive window scaling (peer applies it reading that window).
Q: Is scaling per-direction?  A: yes — snd_wscale (peer's) and rcv_wscale (ours) are independent.
Q: Are SYN/SYN-ACK windows scaled?  A: no — literal; the shift applies only after the handshake.
Q: Why must SND.WND become u32?  A: a scaled window exceeds 65535; the interpreted value needs 32 bits.
Q: Does the wire window field widen?  A: no — still 16 bits; only the interpretation grows.
Q: Why advertise our own scale = 0?  A: our ~1 KB buffer needs no scaling; shift 0 still enables it for the peer's window.
Q: Why clamp the shift to 14?  A: a larger shift pushes the window toward 2^31 where sequence math breaks.
Q: Why does scaling need PAWS?  A: bigger windows wrap the sequence space faster → wrapped duplicates.
Q: Middlebox-stripping hazard?  A: removing WS from one SYN → ends disagree on scaling → corruption.
Q: LFN throughput with vs without scaling?  A: up to ~150× (0.66% → 100% of a gigabit link).
Q: Why "the last 16-bit window"?  A: SND.WND was the final window pinned to u16; now u32.
```

## L. Glossary

- **Window scaling** — negotiating a left-shift applied to the 16-bit window field (RFC 7323 §2).
- **Shift / scale factor** — the per-direction multiplier exponent (0–14); window = `field << shift`.
- **`snd_wscale` / `rcv_wscale`** — the peer's shift (for our sends) / our shift (for the peer's sends).
- **Bandwidth-delay product (BDP)** — bandwidth × RTT; the window needed to fill a pipe.
- **Long fat network (LFN)** — a high-BDP path (high bandwidth and/or latency).
- **Window field** — the 16-bit wire field; its *interpreted* value is `field << shift`.
- **Receive-window autotuning** — growing the advertised window toward the BDP per connection.
- **Option stripping** — a middlebox removing the WS option, breaking the negotiation.
- **Shift cap (14)** — the maximum shift, keeping the window below `2^30` for sequence-math safety.
- **PAWS** — the timestamp-based wrapped-duplicate defense that makes large windows safe (Day 16).

## M. Reference tables

**M.1 — The Window Scale option**

```text
   bytes:  [NOP][kind=3][len=3][shift]   = 4 bytes (NOP-padded)
   shift ∈ [0, 14];  window = field << shift;  max = 65535 << 14 ≈ 1 GB
```

**M.2 — Shift → max window & granularity**

```text
   shift   multiplier   max window (65535 << shift)   granularity (window step)
   ─────   ──────────   ──────────────────────────    ─────────────────────────
   0       ×1            65,535 (64 KB)                1 byte
   7       ×128          ~8.4 MB                        128 bytes
   10      ×1024         ~67 MB                         1 KB
   14      ×16384        ~1.07 GB                       16 KB
```

**M.3 — Which RFC 7323 half does what**

```text
   feature          day   role
   ──────────────   ───   ──────────────────────────────────────────────
   Timestamps/PAWS  16    per-ACK RTT + reject wrapped old duplicates (safety)
   Window Scaling   17    lift the 64 KB window cap on long-fat paths (speed)
   together         —     scaling unlocks high-speed; PAWS makes it safe
```

> Re-type the window-scale negotiation and the `SND.WND` shift with the book closed, then `cargo test`. Your
> stack can now fill a fast, far pipe — the last 16-bit window is gone, and (because Day 16 gave you PAWS)
> it's safe to do so.
