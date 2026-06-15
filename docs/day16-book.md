# Day 16 — TCP, Part 14: Timestamps, RTT Measurement, and PAWS (RFC 7323)

> Goal: spend the Day 15 options framework on the first option that rides on *every* segment — the
> **Timestamps** option (RFC 7323 §3). One 12-byte option, two payoffs. First, **RTTM**: by stamping each
> segment with our clock and having the peer echo it back, we can measure the round-trip time on *every* ACK
> — not one sample per window, and without Karn's "don't time a retransmission" caveat. Second, **PAWS**
> (Protect Against Wrapped Sequences): on a fast, long-lived connection the 32-bit sequence number wraps, and
> an ancient duplicate can land inside the current window; its *timestamp* exposes it as old, so we drop it.
> This is the chapter where `on_segment` (built yesterday) earns its keep.

One option, two unrelated-seeming problems, both dissolved by the same idea: **attach a monotonic clock to
every segment.** RTTM gets dense, Karn-free samples because the peer echoes the timestamp of exactly the data
it's acking; PAWS gets a wrap-proof "is this segment old?" test because an ancient segment carries an ancient
timestamp no matter what its recycled sequence number says. Timestamps are also the quiet prerequisite for
several later real-world features (safe TIME_WAIT reuse, Day 7; RACK loss detection, Day 6).

**Contents**

Volume I — the chapter
1. The mental model: two problems, one option
2. The Timestamps option and how it is negotiated
3. RTTM: an RTT sample on every ACK
4. PAWS: rejecting a wrapped old duplicate
5. `TS.Recent` and the echo rule
6. The timestamp clock and where it is refreshed
7. The Rust
8. Worked example: RTT and a PAWS drop
9. The code, walked end to end
10. Verification
11. Why this, not that
12. Honesty: what production does, and what we don't
13. Rebuild it yourself — checklist + exercises
14. What the next step adds

Volume II — the exhaustive reference
- A. RFC 7323 timestamps in full
- B. RTTM in depth — why per-ACK samples beat Karn
- C. PAWS in depth — the wrapped-sequence problem
- D. The timestamp clock — resolution and the uptime leak
- E. The sequence-space wrap math
- F. A worked RTTM + PAWS trace
- G. Comparison to real stacks — randomized offsets and TIME_WAIT reuse
- H. Security — timestamp fingerprinting and the randomized-offset fix
- I. Performance — the 12-byte cost and the sampling win
- J. Extended FAQ
- K. Anki starter deck
- L. Glossary
- M. Reference tables

---

# Volume I — the chapter

## 1. The mental model: two problems, one option

By Day 6 our RTO adapted to a measured RTT, but the measurement was coarse: one sample per window (time the
oldest unacked segment when its ACK lands), and **suppressed entirely for retransmitted data** (Karn's
algorithm — you can't tell which copy an ACK answers). On a connection with one segment in flight that is
fine; on a fat pipe it is one sample per round trip when you could have dozens.

Separately, TCP's sequence number is only 32 bits. At 10 Gbit/s the sequence space wraps in a few seconds
(§E). If an old segment was delayed in the network long enough, its (recycled) sequence number can fall
inside the *current* window and be mistaken for fresh data — silent corruption.

Both problems are solved by attaching a monotonic **timestamp** to every segment. RTTM falls out because the
peer echoes the exact timestamp of the data it is acknowledging. PAWS falls out because a genuinely old
segment carries an old timestamp, no matter what its sequence number looks like. It's a beautiful economy:
*time* is a second, independent ordering of the byte stream, and once you carry it, both "how long did this
take?" and "is this stale?" become trivial.

## 2. The Timestamps option and how it is negotiated

The option is 10 bytes, conventionally padded to 12 with two leading NOPs so it lands on a 4-byte boundary:

```text
   [ NOP | NOP | kind=8 | len=10 | TSval (4) | TSecr (4) ]
```

- **TSval** — the sender's current timestamp clock.
- **TSecr** ("echo reply") — the most recent TSval the sender received from the peer, echoed back.

Negotiation is symmetric and happens only in the handshake (RFC 7323 §3.2): each side offers timestamps by
putting the option in its SYN. Timestamps are used **only if both SYNs carried them.** So:

- We always offer timestamps in our SYN (active open) and in our SYN-ACK *iff the peer's SYN offered it*
  (passive open).
- `ts_enabled` becomes true exactly when the other side also offered.

Once enabled, the option appears on **every** segment for the life of the connection — data, pure ACKs, FIN,
even the zero-window probe. This is the first per-segment option (MSS/window-scale/SACK-permitted are
SYN-only), which is why it cost 12 of our 40 option bytes on every segment and shaped the SACK budget
(Day 18 §5).

## 3. RTTM: an RTT sample on every ACK

When we send a segment, its TSval is "now". The peer copies that value into the TSecr of whatever ACK
acknowledges it. When that ACK arrives, the round-trip time is simply:

```text
   RTT = now − TSecr
```

No queue bookkeeping, no Karn exclusion: the echoed value pins the measurement to a specific send, even if
that data was retransmitted, because the peer echoes the timestamp of the segment it *actually received*. So
with timestamps on, we feed the estimator from TSecr on every data-acking ACK and let the queue's own
(Karn-limited) sample lapse. Without timestamps we keep the Day 6 behavior. The code is a clean fork:

```rust
if self.ts_enabled {
    if let Some((_, tsecr)) = opts.timestamps {
        self.rtt.sample(self.ts_val.wrapping_sub(tsecr) as u64);
    }
    let _ = self.retx.ack(self.send.una, now_ms); // still clear, ignore its sample
} else if let Some(rtt_ms) = self.retx.ack(self.send.una, now_ms) {
    self.rtt.sample(rtt_ms);
}
```

The density matters: on a fat pipe with 50 segments in flight, timestamps give ~50 RTT samples per round
trip vs Day 6's one — so SRTT/RTTVAR track a changing path far faster, and the RTO is both tighter and more
responsive (§B).

## 4. PAWS: rejecting a wrapped old duplicate

`TS.Recent` holds the newest TSval we have accepted from the peer. PAWS (RFC 7323 §5) says: a segment whose
TSval is **older** than `TS.Recent` is an old duplicate — drop it (but send an ACK so the peer re-syncs).
"Older" is the wrapping serial comparison from Day 3, so it is correct across the timestamp clock's own
32-bit wrap:

```rust
if seq::before(tsval, self.ts_recent) {
    return Some(self.segment(self.send.nxt, self.recv.nxt, ACK, &[])); // PAWS reject
}
```

This sits at the very top of the ESTABLISHED handler, before we act on the segment's ACK or data — an old
duplicate must influence *nothing*. A legitimate retransmission is *not* rejected: the peer stamps the resend
with its *current* clock, so its TSval is newer, not older. PAWS is the timestamp's killer app for
correctness: the 32-bit sequence number alone *cannot* distinguish a wrapped ancient duplicate from fresh
data (both have in-window sequence numbers), but the timestamp can, because the network can't make a segment
*younger* than when it was sent (§C).

## 5. `TS.Recent` and the echo rule

We update `TS.Recent` from an incoming segment when (RFC 7323 §4.3):

- its TSval is at least `TS.Recent` (it survived PAWS), **and**
- its sequence number is at or below the left window edge (`SEG.SEQ <= RCV.NXT`), i.e. it is the in-order
  data/ACK we are actually consuming — not a buffered future segment.

```rust
if !seq::after(th.seq, self.recv.nxt) {
    self.ts_recent = tsval;
}
```

Then every segment we emit echoes `TS.Recent` as its TSecr. That is the value the peer uses for *its* RTTM,
so the measurement is mutual. The sequence guard matters: if we updated `TS.Recent` from a *future*
(out-of-order) segment, a later in-order segment with an *earlier* timestamp could be wrongly PAWS-rejected.
By only advancing `TS.Recent` from segments at/under the window's left edge, we keep it tied to the data
we've actually accepted in order.

## 6. The timestamp clock and where it is refreshed

TSval is our clock. We keep it in a `ts_val: u32` field and refresh it from `now_ms` at the top of every
time-aware entry point — `on_segment`, `on_tick`, `poll_transmit`, `close`, and the constructors. `segment()`
(which builds a packet with `&self`) then reads `ts_val` without needing the clock threaded through it. Using
`now_ms as u32` (milliseconds) gives a clock that advances steadily, which is all RFC 7323 requires; real
stacks often use a coarser tick (and a *randomized per-connection offset* for privacy, §H), but ms is fine
here and makes the RTT samples read in real units. The "refresh one field at each `&mut` entry point" pattern
is the same trick as the persist timer (Day 14): keep the clock in state, refresh at the boundaries, so
`&self` builders can read it.

## 7. The Rust

`src/tcp.rs`:
- `OPT_TS = 8`; `TcpOptions.timestamps: Option<(u32, u32)>`; a `kind == OPT_TS && len == 10` arm in
  `parse_options`; `ts_option(tsval, tsecr) -> [u8; 12]`.
- `Connection`: `ts_enabled`, `ts_recent`, `ts_val`.
- Constructors offer timestamps in SYN / SYN-ACK (the latter only if the peer did) and seed state.
- `segment()` appends the Timestamps option when `ts_enabled`.
- `on_segment`: refresh `ts_val`; learn timestamps in the SYN-ACK path; PAWS + `TS.Recent` at the top of
  ESTABLISHED; RTTM in the new-data-acked branch.

Nothing changes for a connection that didn't negotiate timestamps — `ts_enabled` is false, so every segment
is byte-identical to Day 15 and all prior tests pass untouched. The `Option<(u32, u32)>` for `timestamps`
encodes "present or not" in the type (like MSS's `Option<u16>`), so "no timestamp on this segment" is `None`,
not a sentinel value.

## 8. Worked example: RTT and a PAWS drop

Timestamps negotiated, `TS.Recent = 5000` after the handshake.

```text
   RTTM
   t=0    we send "hi"  → segment TSval=0
   t=120  peer ACK ack=3, TSecr=0     → RTT = 120 − 0 = 120 ms  (first sample → RTO 360)

   PAWS
   TS.Recent = 5000
   old dup arrives: seq in-window, TSval=4000  → 4000 < 5000 → DROP, re-ACK RCV.NXT (data ignored)
   fresh seg arrives: same seq, TSval=5002      → accepted; TS.Recent ← 5002; data delivered
```

The PAWS drop is the headline: two segments with the *same in-window sequence number*, distinguished purely
by their timestamps — the old one (4000 < 5000) rejected, the fresh one (5002) accepted. Sequence numbers
alone could not tell them apart.

## 9. The code, walked end to end

- `parse_options` now also yields `timestamps`.
- The SYN/SYN-ACK builders assemble `MSS [+ WS] [+ TS] [+ SACK-Perm]` into one options blob; the SYN-ACK
  includes TS only if the peer's SYN did.
- `on_segment` refreshes `ts_val`, enables timestamps when the SYN-ACK confirms, applies PAWS, keeps
  `TS.Recent`, and samples RTT from TSecr.
- `segment()` carries the option on every outgoing segment when enabled.
- `main.rs` already parses options and routes through `on_segment` (Day 15), so it needs no change beyond the
  progress note.

## 10. Verification

`cargo test` adds:
- `parse_options_reads_timestamps` — and rejects a wrong-length TS option.
- `timestamps_negotiated_and_synack_echoes_peer` — SYN-ACK carries `MSS + TS(our clock, peer TSval)`.
- `timestamps_disabled_when_peer_does_not_offer`.
- `rttm_samples_rtt_from_echoed_timestamp` — RTT measured from TSecr drives the RTO (120 → 360).
- `paws_rejects_an_old_timestamp_segment` — a stale-TSval duplicate is dropped; a fresh one is taken.
- `timestamped_connection_emits_timestamps_on_data` — data segments carry `TS(clock, TS.Recent)`.

## 11. Why this, not that

| Decision | Alternative | Why |
|---|---|---|
| Sample RTT from TSecr when enabled | Always use the retx-queue sample | Timestamps give a clean per-ACK sample immune to Karn's ambiguity; far more samples → a tighter RTO (§B). |
| Keep `ts_val` as a refreshed field | Thread `now_ms` into `segment()` | `segment()` is `&self` and called from a dozen sites; refreshing one field at each `&mut` entry is less invasive. |
| ms-resolution TSval | A coarse RFC-style tick | Milliseconds advance monotonically (all PAWS needs) and make RTT samples read in real units; documented. |
| PAWS at the top of ESTABLISHED | Check after ACK/data processing | An old duplicate must influence *nothing* — reject before it can move SND.UNA or deliver bytes. |
| Enable only if both SYNs offer | Always send timestamps | RFC 7323 §3.2: timestamps are bilateral; sending them unsolicited can confuse a peer that didn't ask. |

## 12. Honesty: what production does, and what we don't

- **No randomized per-connection timestamp offset.** Our TSval is the raw `now_ms`, which is essentially the
  host's uptime/boot-relative clock — and that **leaks the host's uptime** and lets distinct connections be
  correlated to one machine (§H). RFC 7323 §5.4 recommends a *random per-connection offset* added to the
  clock so the value reveals neither uptime nor cross-connection identity; Linux does this. We don't
  (exercise, §H).
- **`TS.Recent` update uses `RCV.NXT`, not `Last.ACK.sent`.** RFC 7323 §4.3 specifies updating `TS.Recent`
  when `SEG.SEQ <= Last.ACK.sent` (the exact left edge of what we last acknowledged). We approximate with
  `SEG.SEQ <= RCV.NXT`, which is correct on our in-order link but slightly off in corner cases a reordering
  network could produce (exercise E1).
- **No 24-day PAWS timeout reset.** RFC 7323 §5.5: if a connection is idle longer than the clock could plausibly
  represent (~24 days at the coarsest tick), `TS.Recent` is considered stale and PAWS is suspended until a
  fresh segment re-seeds it. We never reset (exercise E3); irrelevant at our timescales.
- **We don't seed SRTT from the SYN-ACK timestamp.** RFC 7323 permits measuring RTT from the handshake's
  timestamp echo to get an estimate one round trip earlier; we wait for the first data exchange (exercise
  E2).
- **Clock resolution.** Ms is fine for our RTTs; RFC 7323 §5.4 requires the clock tick between 1 ms and
  1 s and to wrap no faster than the MSL — ms satisfies both. A sub-ms LAN RTT can read as 0 ms, which our
  MIN_RTO floor (200 ms, Day 6) absorbs.

None of these change the day-16 contract (per-ACK RTT, wrapped-duplicate rejection); they are privacy and
corner-case hardening.

## 13. Rebuild it yourself — checklist + exercises

**Blank-file checklist:**

- [ ] Draw the Timestamps option bytes (with padding). What do TSval and TSecr mean?
- [ ] When are timestamps *enabled*? What does each side put in TSecr in its SYN vs SYN-ACK?
- [ ] How does TSecr give an RTT sample that beats Karn's restriction?
- [ ] State the PAWS rule and the `TS.Recent` update rule. Why is PAWS checked first?
- [ ] Why is a retransmission never rejected by PAWS?

**Exercises:**

- **E1.** Add the RFC 7323 §4.3 refinement: update `TS.Recent` only if `SEG.SEQ <= Last.ACK.sent`, tracked
  precisely (store the last ack you sent rather than approximating with `RCV.NXT`).
- **E2.** Sample RTT from the SYN-ACK's TSecr to seed `SRTT` before the first data exchange.
- **E3.** Implement the PAWS 24-day outdated-`TS.Recent` reset (RFC 7323 §5.5) for an idle connection.
- **E4.** ✅ *Done* (Days 17–18): verify against a real Linux peer — capture its SYN options with
  `tcpdump -v` and confirm `parse_options` reads MSS, window-scale, SACK-permitted, and timestamps.
- **E5.** Add a **random per-connection timestamp offset** (RFC 7323 §5.4) so TSval leaks neither uptime nor
  cross-connection identity (§H).

## 14. What the next step adds

Day 17 adds the other half of RFC 7323: the **Window Scale** option. Our advertised receive window is a
16-bit field — at most 64 KB, far too small for a fast, high-latency "long fat" path. Window scaling
negotiates a left-shift (0–14) applied to the window field, stretching the effective window to as much as
~1 GB. It is, like timestamps, negotiated once in the SYN exchange, and it forces `SND.WND` to widen from
`u16` to `u32` — the last place our windows were still pinned to 16 bits.

---

# Volume II — the exhaustive reference

## A. RFC 7323 timestamps in full

The Timestamps option (RFC 7323 §3, originally RFC 1323) carries two 32-bit values and obeys a small echo
protocol:

```text
   field    meaning
   ──────   ─────────────────────────────────────────────────────────────────
   TSval    the SENDER's current timestamp clock value (its "now")
   TSecr    the value of TSval the sender most recently RECEIVED and is echoing
```

The echo algorithm (RFC 7323 §4):

1. On every segment we send, **TSval = our current clock**.
2. **TSecr = `TS.Recent`** — the latest TSval we've accepted from the peer (or 0 in our SYN, where we have
   nothing to echo yet).
3. On receiving a segment, if it passes PAWS and is at/under the left window edge, **`TS.Recent` ← its
   TSval** (§5).
4. The peer does the symmetric thing, so each side's TSecr always reflects the other's clock — giving both
   sides RTTM.

The handshake bootstraps it: our SYN carries `TSval = clock, TSecr = 0` (nothing to echo); the SYN-ACK
carries `TSval = clock, TSecr = peer's SYN TSval`; from then on both echo each other's latest. Timestamps are
"used" only if *both* SYNs carried the option — a one-shot bilateral negotiation, no mid-connection
enabling.

## B. RTTM in depth — why per-ACK samples beat Karn

Day 6's RTT measurement had two limits, both removed by timestamps:

```text
   limit (Day 6)                              timestamps fix
   ────────────────────────────────────────  ─────────────────────────────────────────
   one sample per window (time oldest unacked) one sample PER ACK (TSecr dates each one)
   Karn: NO sample from a retransmitted segment ANY ACK gives a sample (TSecr disambiguates
                                                the copy — the peer echoes what it received)
```

Why TSecr defeats Karn's ambiguity: Karn's problem was "an ACK names a sequence number, not which
transmission of it." With timestamps, the *receiver echoes the TSval of the segment it actually got* — so the
TSecr identifies the exact send the ACK answers, even across retransmissions. If we sent copy 1 at TSval=100
and copy 2 (retransmit) at TSval=350, and the ACK echoes TSecr=350, the receiver got copy 2, and `now −
350` is the true RTT of *that* copy. Karn's restriction existed precisely because the old mechanism couldn't
do this; timestamps make it unnecessary.

The *density* win is large on fat pipes: with `W` segments in flight, you get ~`W` samples per RTT instead of
1, so SRTT/RTTVAR converge in a fraction of the round trips and track a changing path (a route flap, a
congestion onset) almost immediately. This sharper RTO is the difference between a stack that spuriously
retransmits on a jittery path and one that rides it out. Timestamps also underpin **RACK** (Day 6 §F):
per-segment send times (which timestamps provide) let a sender detect loss by *time* ("a later segment was
acked and enough time passed") rather than by 3-dup-ACK counting — more robust to reordering.

## C. PAWS in depth — the wrapped-sequence problem

The problem PAWS solves: TCP's sequence number is 32 bits, so the sequence space is 4 GiB. On a fast link,
the *same sequence number* is reused every 4 GiB of data — and if an old segment (carrying sequence number
`X`) was delayed in the network long enough, the connection may have *wrapped all the way around* and now be
legitimately using `X` again. The old segment's sequence number is *in-window* and indistinguishable, by
sequence number alone, from current data. Accepting it is **silent data corruption** — the worst kind of bug,
because no checksum or sequence check catches it.

PAWS adds a second, independent ordering: **time**. Every segment carries a timestamp; the network can delay
a segment but cannot make it *younger*. So a wrapped old duplicate carries a timestamp from when it was
*originally* sent — older than anything we've recently accepted (`TS.Recent`). The rule:

```text
   reject SEG if  SEG.TSval < TS.Recent   (modular comparison, RFC 1982)
                  AND SEG is otherwise in-window
```

The assumption that makes it sound: within the time it takes the sequence space to wrap (4 GiB / bandwidth),
the timestamp clock advances by at least one tick (so a wrapped duplicate is reliably "older"). RFC 7323 §5.2
formalizes this: the timestamp clock must tick at most once per `2³¹` bytes of the fastest expected send rate
— ms resolution satisfies this for any realistic link. Without PAWS, window scaling (Day 17) would be
*dangerous*: a bigger window means more in-flight data means faster wrapping means more chances for a wrapped
duplicate to land in-window. This is why RFC 7323 packages timestamps and window scaling together — scaling
*needs* PAWS to be safe on a long-fat network.

## D. The timestamp clock — resolution and the uptime leak

RFC 7323 §5.4 constrains the timestamp clock:

```text
   requirement                          why
   ──────────────────────────────────   ──────────────────────────────────────────
   tick between 1 ms and 1 s             fine enough for RTTM, coarse enough to not wrap fast
   wrap slower than the MSL (~2 min)     so a wrapped TSval can't alias within one segment lifetime
   monotonically non-decreasing          PAWS comparisons assume time only moves forward
   ideally a random per-connection offset  privacy (§H)
```

Our `now_ms as u32` ticks every millisecond, wraps every ~49.7 days (far slower than the MSL), and is
monotonic (from `Instant`, Day 6) — satisfying the first three. It does **not** add a random offset, so our
TSval is essentially the host's milliseconds-since-start, which is the privacy problem of §H. Real stacks use
a coarser tick (Linux historically 1 ms via jiffies, now finer) plus a per-connection random offset, so the
value is monotonic *within* a connection (PAWS works) but reveals nothing *across* connections or about
uptime.

## E. The sequence-space wrap math

When does the 32-bit sequence space actually wrap? `4 GiB / bandwidth`:

```text
   bandwidth      time to send 4 GiB (one wrap)
   ────────────   ─────────────────────────────
   10 Mbit/s      ~3400 s   (~57 min)   — wrap is a non-issue, MSL >> needed
   1 Gbit/s       ~34 s                  — getting close to the MSL
   10 Gbit/s      ~3.4 s                 — wraps FASTER than a segment's max lifetime!
   100 Gbit/s     ~0.34 s                — multiple wraps within one MSL
```

The danger threshold is when the wrap time approaches the **MSL** (~2 minutes, the max a segment can linger):
at 10 Gbit/s the space wraps in 3.4 s, so a segment delayed even a few seconds can reappear with an in-window
(wrapped) sequence number while a *different* segment legitimately occupies that number now. Below ~17 Mbit/s
the wrap takes longer than the MSL and the problem can't occur (an old segment dies before its number is
reused). Above it, PAWS is mandatory — which is exactly the regime window scaling (Day 17) targets (fast,
long-fat paths). The numbers show *why* timestamps and window scaling shipped together in RFC 1323/7323:
scaling enables the high-speed/large-window regime, and that regime is precisely where sequence wrap becomes
a corruption hazard that only PAWS catches.

## F. A worked RTTM + PAWS trace

A timestamped connection, our clock advancing, showing both mechanisms. Times are our ms clock.

```text
   RTTM (sharpening the RTO with dense samples):
   t=0     U→C  data seq=1 "ab"  TSval=0  TSecr=5000
   t=120   C→U  ACK ack=3        TSval=5060 TSecr=0     → RTT = 120 − 0 = 120; SRTT=120, RTO=360
   t=200   U→C  data seq=3 "cd"  TSval=200 TSecr=5060   (TS.Recent advanced to 5060)
   t=320   C→U  ACK ack=5        TSval=5160 TSecr=200   → RTT = 320 − 200 = 120; another sample
   ... every ACK yields a fresh RTT, even for retransmits ...

   PAWS (rejecting a wrapped old duplicate):
   TS.Recent = 5160 (from the last accepted segment)
   t=400   C→U  data seq=5 "XX"  TSval=4000  → before(4000, 5160) → DROP; re-ACK ack=5 (RCV.NXT unmoved)
   t=410   C→U  data seq=5 "ef"  TSval=5200  → after(5200, 5160) → ACCEPT; TS.Recent←5200; deliver "ef"
```

Note the two `seq=5` segments at t=400 and t=410: identical, in-window sequence numbers, distinguished *only*
by timestamp. The wrapped old duplicate (TSval 4000, from a previous trip around the sequence space) is
rejected; the genuine data (TSval 5200) is accepted. Without PAWS, the t=400 "XX" would corrupt the stream.

## G. Comparison to real stacks — randomized offsets and TIME_WAIT reuse

```text
   aspect                 Linux                                  this stack
   ────────────────────   ─────────────────────────────────────  ──────────────────────
   on by default          yes (net.ipv4.tcp_timestamps=1)         offered always
   clock                  ms-ish tick + random per-conn offset    raw now_ms (no offset)
   RTTM                   per-ACK from TSecr                       per-ACK from TSecr ✓
   PAWS                   yes                                      yes ✓
   TS.Recent update       SEG.SEQ <= Last.ACK.sent                 SEG.SEQ <= RCV.NXT (approx)
   TIME_WAIT reuse        timestamps enable tcp_tw_reuse           n/a (passive close)
   RACK loss detection    uses per-segment timestamps              not implemented
```

A real-world payoff we don't exploit: **timestamps make `tcp_tw_reuse` safe** (Day 7 §C). Reusing a 4-tuple
still in TIME_WAIT is dangerous because an old duplicate could be accepted by the new incarnation — but if
both incarnations use timestamps, PAWS rejects the old one (its timestamp predates the new connection), so
the kernel can safely reuse the 4-tuple. This is why `tcp_tw_reuse` requires timestamps and `tcp_tw_recycle`
(which keyed off them per-host) broke NAT. Timestamps also feed **RACK** (Day 6 §F), modern loss detection.
So timestamps quietly enable two features (safe TW reuse, RACK) beyond the two (RTTM, PAWS) they advertise.

## H. Security — timestamp fingerprinting and the randomized-offset fix

- **Uptime leak.** A raw timestamp clock (like ours, `now_ms`) is essentially "time since boot." An attacker
  observing TSval across two captures can compute the host's **uptime** (how long since it booted) — useful
  reconnaissance (a long-uptime host may be unpatched) and a deanonymization signal. This was a real,
  widely-noted issue with early timestamp implementations.
- **Cross-connection correlation.** If every connection from a host shares one clock, an observer can tell
  two connections come from the *same machine* (their TSvals are consistent with one clock), defeating
  per-connection anonymity (e.g. behind NAT or a privacy proxy). 
- **The fix (RFC 7323 §5.4): a random per-connection offset.** Add a random 32-bit value per connection to
  the clock. Within a connection, TSval is still monotonic (PAWS works); across connections, the offsets are
  unrelated, so neither uptime nor same-host correlation leaks. Linux does this. We don't (exercise E5) — our
  TSval leaks uptime, a genuine privacy gap.
- **Timestamp-based OS fingerprinting.** The presence, value, and tick rate of timestamps are part of an OS
  fingerprint (nmap/p0f), and the *clock skew* derivable from timestamps can even be used as a hardware
  fingerprint (distinct machines have slightly different crystal frequencies — "remote physical device
  fingerprinting", Kohno et al.).
- **PAWS as a defense.** On the positive side, PAWS *strengthens* security: it's part of the TIME_WAIT
  assassination defense (Day 7 §I) and makes wrapped-sequence injection (an attacker timing an injected
  segment to a sequence reuse) far harder, since the injected segment also needs a plausible timestamp.

The theme: timestamps are a double-edged tool — they fix RTT and wrap-safety but, naively implemented, leak
uptime and correlate connections; the random-offset fix (which we omit) is mandatory for a privacy-respecting
stack.

## I. Performance — the 12-byte cost and the sampling win

- **The cost: 12 bytes on every segment.** Timestamps are the only per-segment option, so every data/ACK
  carries 12 fewer payload bytes (within the MSS) and 12 more header bytes. On bulk transfer that's ~0.8% of
  a 1500-byte packet — negligible. On pure ACKs it's 12 bytes added to a 40-byte segment (30% bigger ACKs),
  also negligible in bandwidth but a real factor in ACK-heavy workloads. This 12-byte cost is also what
  squeezes SACK to 3 blocks (Day 18 §5).
- **The win: a tighter, more responsive RTO.** Dense per-ACK samples (§B) mean SRTT/RTTVAR track the path in
  ~1 RTT instead of ~`W` RTTs, so the RTO is both smaller (less wasted wait on a real loss) and more
  accurate (fewer spurious retransmits on a jittery path). For a long-lived bulk transfer this measurably
  improves goodput under variable conditions.
- **PAWS is free on the fast path.** One modular comparison per segment at the top of the handler — a
  branch, no allocation. Its *value* (preventing silent corruption on a 10 Gbit/s wrap) is enormous relative
  to its cost.
- **Our cost** is the 12-byte option build per segment (a `[u8; 12]`, stack-allocated) and the PAWS/TS.Recent
  branches — trivial. The performance *gap* vs production is the missing dense-sample exploitation for
  features like RACK, not the RTTM itself.

## J. Extended FAQ

1. **What two problems does one timestamp option solve?** RTTM (per-ACK RTT) and PAWS (wrapped-duplicate
   rejection).
2. **What are TSval and TSecr?** The sender's current clock; the latest TSval it received, echoed back.
3. **How are timestamps negotiated?** Both SYNs must carry the option; bilateral, handshake-only.
4. **On which segments does the option appear?** Every segment, once enabled (the only per-segment option).
5. **How does TSecr give an RTT?** `now − TSecr` — the echoed value dates the exact send being acked.
6. **Why does that beat Karn?** The peer echoes the timestamp of the copy it *received*, disambiguating
   retransmissions.
7. **How many RTT samples per RTT with timestamps?** ~one per ACK (≈ window size), vs Day 6's one.
8. **What is `TS.Recent`?** The newest TSval we've accepted from the peer; echoed as our TSecr.
9. **When do we update `TS.Recent`?** TSval ≥ TS.Recent (passes PAWS) AND SEG.SEQ ≤ RCV.NXT (in order).
10. **What is the PAWS rule?** Reject an in-window segment whose TSval < TS.Recent (an old duplicate).
11. **Why check PAWS first?** An old duplicate must influence nothing — reject before ACK/data processing.
12. **Why isn't a retransmission PAWS-rejected?** The peer re-stamps the resend with its *current* clock
    (newer).
13. **What corruption does PAWS prevent?** A wrapped old duplicate with an in-window (recycled) sequence
    number being accepted as fresh data.
14. **When does the sequence space wrap dangerously?** When wrap time approaches the MSL — ~10 Gbit/s (§E).
15. **Why do timestamps and window scaling ship together?** Scaling enables the high-speed regime where wrap
    is a hazard; PAWS makes it safe.
16. **What clock do we use?** `now_ms as u32` — monotonic, ms resolution.
17. **Where is `ts_val` refreshed?** At every time-aware `&mut` entry point (`on_segment`, `on_tick`, etc.).
18. **Does a non-timestamped connection change?** No — byte-identical to Day 15.
19. **What's the uptime leak?** A raw timestamp clock reveals time-since-boot to an observer (§H).
20. **What's the fix?** A random per-connection offset (RFC 7323 §5.4) — we don't do it.
21. **What other features do timestamps enable?** Safe `tcp_tw_reuse` (Day 7) and RACK loss detection
    (Day 6) (§G).
22. **What does TSecr in our SYN equal?** 0 — we have nothing to echo yet.
23. **What is the 24-day reset?** Suspending PAWS if `TS.Recent` is implausibly old on an idle connection
    (§12).
24. **What does the option cost?** 12 bytes per segment (and it caps SACK at 3 blocks, Day 18).
25. **Why is `on_segment` (Day 15) the key seam?** Timestamps ride every segment, and `on_segment` carries
    the parsed options.

## K. Anki starter deck

```text
Q: One timestamp option solves which two problems?  A: RTTM (per-ACK RTT) and PAWS (wrapped-duplicate reject).
Q: TSval and TSecr?  A: sender's current clock; latest received TSval echoed back.
Q: How are timestamps negotiated?  A: both SYNs carry the option (bilateral, handshake-only).
Q: How does TSecr give an RTT?  A: now − TSecr — the echoed value dates the exact acked send.
Q: Why does that beat Karn?  A: the peer echoes the timestamp of the copy it received (disambiguates retransmits).
Q: What is TS.Recent?  A: the newest TSval accepted from the peer; echoed as our TSecr.
Q: When update TS.Recent?  A: TSval ≥ TS.Recent AND SEG.SEQ ≤ RCV.NXT (in order).
Q: The PAWS rule?  A: reject an in-window segment whose TSval < TS.Recent.
Q: Why check PAWS first?  A: an old duplicate must influence nothing (before ACK/data).
Q: Why isn't a retransmission PAWS-rejected?  A: the peer re-stamps the resend with its current (newer) clock.
Q: What corruption does PAWS prevent?  A: a wrapped old duplicate with a recycled in-window sequence number.
Q: When does sequence wrap get dangerous?  A: when wrap time nears the MSL (~10 Gbit/s).
Q: Why ship timestamps + window scaling together?  A: scaling enables the high-speed regime; PAWS makes it safe.
Q: What's the timestamp uptime leak / fix?  A: raw clock reveals uptime; fix = random per-connection offset.
Q: What else do timestamps enable?  A: safe tcp_tw_reuse and RACK loss detection.
```

## L. Glossary

- **Timestamps option** — a 12-byte per-segment option carrying TSval and TSecr (RFC 7323 §3).
- **TSval** — the sender's current timestamp clock value.
- **TSecr (echo reply)** — the latest TSval received from the peer, echoed back.
- **RTTM (RTT Measurement)** — measuring RTT per-ACK via `now − TSecr`.
- **`TS.Recent`** — the newest accepted peer TSval; the PAWS reference and our echoed TSecr.
- **PAWS (Protect Against Wrapped Sequences)** — rejecting an in-window segment with an old timestamp.
- **Sequence wrap** — the 32-bit sequence space recycling, a corruption hazard at high speed.
- **Random per-connection offset** — RFC 7323 §5.4 privacy measure (we omit it).
- **Uptime leak** — a raw timestamp clock revealing time-since-boot.
- **RACK** — time-based loss detection enabled by per-segment timestamps.

## M. Reference tables

**M.1 — The Timestamps option**

```text
   bytes:  [NOP][NOP][8][10][TSval ×4][TSecr ×4]   = 12 bytes
   TSval = our clock now
   TSecr = TS.Recent (latest peer TSval; 0 in our SYN)
```

**M.2 — RTTM: Day 6 vs timestamps**

```text
   aspect              Day 6 (queue)            timestamps
   ─────────────────   ──────────────────────   ─────────────────────────
   samples per RTT     1 (oldest unacked)        ~window size (per ACK)
   retransmits         no sample (Karn)          sample OK (TSecr disambiguates)
   source              now − sent_at_ms          now − TSecr
```

**M.3 — PAWS decision**

```text
   condition                          action
   ────────────────────────────────   ─────────────────────────────────
   TSval < TS.Recent (in-window seg)   DROP (old duplicate); re-ACK RCV.NXT
   TSval ≥ TS.Recent, SEG.SEQ ≤ RCV.NXT accept; TS.Recent ← TSval
   retransmission (newer TSval)        accept (not rejected)
```

> Re-type `parse_options`' TS arm, the PAWS check, and the TSecr RTT sample with the book closed, then
> `cargo test`. Your RTO is now fed by every ACK, and a wrapped sequence number can no longer fool your
> receiver — the two gifts of carrying time on every segment.
