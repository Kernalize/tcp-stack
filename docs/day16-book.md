# Day 16 — TCP, Part 14: Timestamps, RTT Measurement, and PAWS (RFC 7323)

> Goal: spend the Day 15 options framework on the first option that rides on *every* segment — the
> **Timestamps** option (RFC 7323 §3). One 12-byte option, two payoffs. First, **RTTM**: by stamping
> each segment with our clock and having the peer echo it back, we can measure the round-trip time on
> *every* ACK — not one sample per window, and without Karn's "don't time a retransmission" caveat.
> Second, **PAWS** (Protect Against Wrapped Sequences): on a fast, long-lived connection the 32-bit
> sequence number wraps, and an ancient duplicate can land inside the current window; its *timestamp*
> exposes it as old, so we drop it. This is the chapter where `on_segment` (built yesterday) earns
> its keep.

**Contents**
1. The mental model: two problems, one option
2. The Timestamps option and how it is negotiated
3. RTTM: an RTT sample on every ACK
4. PAWS: rejecting a wrapped old duplicate
5. `TS.Recent` and the echo rule
6. The timestamp clock and where it is refreshed
7. The Rust
8. Worked example: RTT and a PAWS drop
9. The code, walked
10. Verification
11. Why this, not that
12. Rebuild it yourself — checklist + exercises
13. What the next day adds

---

## 1. The mental model: two problems, one option

By Day 6 our RTO adapted to a measured RTT, but the measurement was coarse: one sample per window
(time the oldest unacked segment when its ACK lands), and **suppressed entirely for retransmitted
data** (Karn's algorithm — you can't tell which copy an ACK answers). On a connection with one
segment in flight that is fine; on a fat pipe it is one sample per round trip when you could have
dozens.

Separately, TCP's sequence number is only 32 bits. At 10 Gbit/s the sequence space wraps in a few
seconds. If an old segment was delayed in the network long enough, its (recycled) sequence number can
fall inside the *current* window and be mistaken for fresh data — silent corruption.

Both problems are solved by attaching a monotonic **timestamp** to every segment. RTTM falls out
because the peer echoes the exact timestamp of the data it is acknowledging. PAWS falls out because a
genuinely old segment carries an old timestamp, no matter what its sequence number looks like.

## 2. The Timestamps option and how it is negotiated

The option is 10 bytes, conventionally padded to 12 with two leading NOPs so it lands on a 4-byte
boundary:

```text
  [ NOP | NOP | kind=8 | len=10 | TSval (4) | TSecr (4) ]
```

- **TSval** — the sender's current timestamp clock.
- **TSecr** ("echo reply") — the most recent TSval the sender received from the peer, echoed back.

Negotiation is symmetric and happens only in the handshake (RFC 7323 §3.2): each side offers
timestamps by putting the option in its SYN. Timestamps are used **only if both SYNs carried them.**
So:

- We always offer timestamps in our SYN (active open) and in our SYN-ACK *iff the peer's SYN offered*
  (passive open).
- `ts_enabled` becomes true exactly when the other side also offered.

Once enabled, the option appears on **every** segment for the life of the connection — data, pure
ACKs, FIN, even the zero-window probe.

## 3. RTTM: an RTT sample on every ACK

When we send a segment, its TSval is "now". The peer copies that value into the TSecr of whatever ACK
acknowledges it. When that ACK arrives, the round-trip time is simply:

```text
  RTT = now − TSecr
```

No queue bookkeeping, no Karn exclusion: the echoed value pins the measurement to a specific send,
even if that data was retransmitted, because the peer echoes the timestamp of the segment it actually
received. So with timestamps on, we feed the estimator from TSecr on every data-acking ACK and let
the queue's own (Karn-limited) sample lapse. Without timestamps we keep the Day 6 behavior. The code
is a clean fork:

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

## 4. PAWS: rejecting a wrapped old duplicate

`TS.Recent` holds the newest TSval we have accepted from the peer. PAWS (RFC 7323 §5) says: a segment
whose TSval is **older** than `TS.Recent` is an old duplicate — drop it (but send an ACK so the peer
re-syncs). "Older" is the wrapping serial comparison from Day 3, so it is correct across the
timestamp clock's own 32-bit wrap:

```rust
if seq::before(tsval, self.ts_recent) {
    return Some(self.segment(self.send.nxt, self.recv.nxt, ACK, &[])); // PAWS reject
}
```

This sits at the very top of the ESTABLISHED handler, before we act on the segment's ACK or data — an
old duplicate must influence nothing. A legitimate retransmission is *not* rejected: the peer stamps
the resend with its *current* clock, so its TSval is newer, not older.

## 5. `TS.Recent` and the echo rule

We update `TS.Recent` from an incoming segment when (RFC 7323 §4.3):

- its TSval is at least `TS.Recent` (it survived PAWS), **and**
- its sequence number is at or below the left window edge (`SEG.SEQ <= RCV.NXT`), i.e. it is the
  in-order data/ACK we are actually consuming — not a buffered future segment.

```rust
if !seq::after(th.seq, self.recv.nxt) {
    self.ts_recent = tsval;
}
```

Then every segment we emit echoes `TS.Recent` as its TSecr. That is the value the peer uses for *its*
RTTM, so the measurement is mutual.

## 6. The timestamp clock and where it is refreshed

TSval is our clock. We keep it in a `ts_val: u32` field and refresh it from `now_ms` at the top of
every time-aware entry point — `on_segment`, `on_tick`, `poll_transmit`, `close`, and the
constructors. `segment()` (which builds a packet with `&self`) then reads `ts_val` without needing
the clock threaded through it. Using `now_ms as u32` (milliseconds) gives a clock that advances
steadily, which is all RFC 7323 requires; real stacks often use a coarser tick, but ms is fine here
and makes the RTT samples read in real units.

## 7. The Rust

`src/tcp.rs`:
- `OPT_TS = 8`; `TcpOptions.timestamps: Option<(u32, u32)>`; a `kind == OPT_TS && len == 10` arm in
  `parse_options`; `ts_option(tsval, tsecr) -> [u8; 12]`.
- `Connection`: `ts_enabled`, `ts_recent`, `ts_val`.
- Constructors offer timestamps in SYN / SYN-ACK (the latter only if the peer did) and seed state.
- `segment()` appends the Timestamps option when `ts_enabled`.
- `on_segment`: refresh `ts_val`; learn timestamps in the SYN-ACK path; PAWS + `TS.Recent` at the top
  of ESTABLISHED; RTTM in the new-data-acked branch.

Nothing changes for a connection that didn't negotiate timestamps — `ts_enabled` is false, so every
segment is byte-identical to Day 15 and all prior tests pass untouched.

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

## 9. The code, walked

- `parse_options` now also yields `timestamps`.
- The SYN/SYN-ACK builders assemble `MSS [+ TS]` into one options blob; the SYN-ACK includes TS only
  if the peer's SYN did.
- `on_segment` refreshes `ts_val`, enables timestamps when the SYN-ACK confirms, applies PAWS, keeps
  `TS.Recent`, and samples RTT from TSecr.
- `segment()` carries the option on every outgoing segment when enabled.
- `main.rs` already parses options and routes through `on_segment` (Day 15), so it needs no change
  beyond the progress note.

## 10. Verification

`cargo test` (83 total) adds:
- `parse_options_reads_timestamps` — and rejects a wrong-length TS option.
- `timestamps_negotiated_and_synack_echoes_peer` — SYN-ACK carries `MSS + TS(our clock, peer TSval)`.
- `timestamps_disabled_when_peer_does_not_offer`.
- `rttm_samples_rtt_from_echoed_timestamp` — RTT measured from TSecr drives the RTO (120 → 360).
- `paws_rejects_an_old_timestamp_segment` — a stale-TSval duplicate is dropped; a fresh one is taken.
- `timestamped_connection_emits_timestamps_on_data` — data segments carry `TS(clock, TS.Recent)`.

## 11. Why this, not that

| Decision | Alternative | Why |
|---|---|---|
| Sample RTT from TSecr when enabled | Always use the retx-queue sample | Timestamps give a clean per-ACK sample immune to Karn's ambiguity; far more samples → a tighter RTO. |
| Keep `ts_val` as a refreshed field | Thread `now_ms` into `segment()` | `segment()` is `&self` and called from a dozen sites; refreshing one field at each `&mut` entry is less invasive and just as correct. |
| ms-resolution TSval | A coarse RFC-style tick | Milliseconds advance monotonically (all PAWS needs) and make RTT samples read in real units; documented. |
| PAWS at the top of ESTABLISHED | Check after ACK/data processing | An old duplicate must influence *nothing* — reject before it can move SND.UNA or deliver bytes. |
| Enable only if both SYNs offer | Always send timestamps | RFC 7323 §3.2: timestamps are bilateral; sending them unsolicited can confuse a peer that didn't ask. |

## 12. Rebuild it yourself — checklist + exercises

**Blank-file checklist:**
- [ ] Draw the Timestamps option bytes (with padding). What do TSval and TSecr mean?
- [ ] When are timestamps *enabled*? What does each side put in TSecr in its SYN vs SYN-ACK?
- [ ] How does TSecr give an RTT sample that beats Karn's restriction?
- [ ] State the PAWS rule and the `TS.Recent` update rule. Why is PAWS checked first?
- [ ] Why is a retransmission never rejected by PAWS?

**Exercises:**
- **E1.** Add the RFC 7323 §4.3 refinement: only update `TS.Recent` if `SEG.SEQ <= Last.ACK.sent`
  tracked precisely (store the last ack you sent rather than approximating with `RCV.NXT`).
- **E2.** Sample RTT from the SYN-ACK's TSecr to seed `SRTT` before the first data exchange.
- **E3.** Implement the PAWS "24-day" outdated-`TS.Recent` reset (RFC 7323 §5.5) for an idle
  connection.
- **E4.** Verify against a real Linux peer: capture its SYN options with `tcpdump -v` and confirm
  `parse_options` reads its MSS, window-scale (Day 17), SACK-permitted (Day 18), and timestamps.

## 13. What the next day adds

Day 17 adds the other half of RFC 7323: the **Window Scale** option. Our advertised receive window is
a 16-bit field — at most 64 KB, far too small for a fast, high-latency "long fat" path. Window scaling
negotiates a left-shift (0–14) applied to the window field, stretching the effective window to as much
as 1 GB. It is, like timestamps, negotiated once in the SYN exchange, and it forces `SND.WND` to widen
from `u16` to `u32` — the last place our windows were still pinned to 16 bits.

> Re-type `parse_options`' TS arm, the PAWS check, and the TSecr RTT sample with the book closed, then
> `cargo test`. Your RTO is now fed by every ACK, and a wrapped sequence number can no longer fool
> your receiver.
