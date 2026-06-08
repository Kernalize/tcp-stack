# Day 17 — TCP, Part 15: Window Scaling (the Other Half of RFC 7323)

> Goal: lift the 64 KB ceiling on the window. TCP's window field is only 16 bits, so without help a
> receiver can advertise at most 65 535 bytes — and on a "long fat" path (high bandwidth × high
> latency) that caps throughput far below the link's capacity. **Window scaling** (RFC 7323 §2)
> negotiates a left-shift, applied to the window field, that stretches the effective window up to
> ~1 GB. It is negotiated once in the SYN exchange, like timestamps, and it forces the last 16-bit
> window in our code — `SND.WND` — to widen to 32 bits.

**Contents**
1. The mental model: the bandwidth-delay product and a 16-bit field
2. The Window Scale option and how it is negotiated
3. The asymmetry: each side scales its own window
4. Widening `SND.WND` to `u32`
5. Why our own advertised scale is 0
6. The Rust
7. Worked example: a 128 000-byte window from a 1000-byte field
8. The code, walked
9. Verification
10. Why this, not that
11. Rebuild it yourself — checklist + exercises
12. What the next day adds

---

## 1. The mental model: the bandwidth-delay product and a 16-bit field

To keep a pipe full, a sender must have at least one **bandwidth × round-trip-time** worth of data in
flight before the first ACK returns. On a 1 Gbit/s link with 80 ms RTT that is `1e9/8 × 0.080 ≈
10 MB`. But the receiver can only *advertise* what fits in the 16-bit window field: 65 535 bytes. The
sender, obeying flow control, stops after 64 KB and waits — using `64 KB / 10 MB ≈ 0.6 %` of the
link. The window field, sized in 1981, is the bottleneck.

Window scaling fixes it without changing the field: both ends agree, at connection setup, on a
**shift count** `S` (0–14). Thereafter a window field value `W` is interpreted as `W << S`. With
`S = 14`, a full field of 65 535 means `65 535 × 16 384 ≈ 1 GB` — plenty for any path.

## 2. The Window Scale option and how it is negotiated

The option is 3 bytes, padded to 4 with a leading NOP:

```text
  [ NOP | kind=3 | len=3 | shift ]
```

Negotiation mirrors timestamps (RFC 7323 §2.2):

- A host offers scaling by putting the option in its **SYN** (and, for a passive open, in its
  **SYN-ACK** *only if the SYN offered it*).
- Scaling is used only if **both** SYNs carried the option.
- The shift in a host's option applies to *that host's* future window fields — it tells the peer
  "multiply my advertised window by `2^shift`."
- The SYN/SYN-ACK windows themselves are **never** scaled; the shift takes effect only on subsequent
  segments. (We never need to special-case this, because we apply the shift in ESTABLISHED, after the
  handshake.)

## 3. The asymmetry: each side scales its own window

The subtle part: window scaling is **per-direction**. There are two independent shifts:

- `snd_wscale` — the shift the *peer* advertised. We apply it to the peer's window field to get the
  true `SND.WND` (how much *we* may send).
- `rcv_wscale` — the shift *we* advertised. The peer applies it to our window field to get how much
  *it* may send us.

They need not be equal. A big-buffer server and a tiny embedded client can each pick the shift that
suits their own receive buffer. So "enabling window scaling" is really "I learn the peer's shift for
the data I send, and the peer learns my shift for the data it sends."

## 4. Widening `SND.WND` to `u32`

`SND.WND` is the peer's advertised window — and with scaling it can exceed 65 535. So the
`SendSequence.wnd` field changes from `u16` to `u32`, and the flow-control math follows:

```rust
let new_wnd = (th.window as u32) << self.snd_wscale;   // recover the true window
self.send.wnd = new_wnd;
// usable window = min(SND.WND, cwnd) − FlightSize   — now entirely in u32
```

This is the last place a window lived in 16 bits. The receive window we *advertise* stays a `u16`
field (see below), and the duplicate-ACK "window unchanged" test now compares the *scaled* values, so
a pure window update is still distinguished from a real duplicate (Day 14).

## 5. Why our own advertised scale is 0

We negotiate scaling — we send the Window Scale option — but with a shift of **0**. Our receive
buffer is only ~1 KB, so we have no large window to advertise; scaling our own field would gain
nothing and only risk rounding a tiny window down. Sending shift 0 still *enables* the feature, which
is what lets us honor the peer's (possibly huge) window in the other direction. That is the honest
choice for this stack: implement the mechanism fully, advertise truthfully. Bumping our receive
buffer and advertising a real shift is a one-line exercise once the buffer grows.

## 6. The Rust

`src/tcp.rs`:
- `OPT_WS = 3`, `OUR_RCV_WSCALE = 0`, `MAX_WSCALE = 14`; `TcpOptions.window_scale: Option<u8>`; a
  `kind == OPT_WS && len == 3` arm in `parse_options` that clamps the shift to 14; `ws_option(shift)
  -> [u8; 4]`.
- `SendSequence.wnd: u32`; a `snd_wscale: u8` field on `Connection`.
- SYN offers `ws_option(0)`; SYN-ACK includes it only if the peer's SYN did; `on_segment`'s SYN_SENT
  branch adopts the peer's shift from the SYN-ACK.
- ESTABLISHED applies `(th.window as u32) << snd_wscale`.

A connection that didn't negotiate scaling has `snd_wscale = 0`, so `W << 0 = W` — identical to
before, and every prior test passes.

## 7. Worked example: a 128 000-byte window from a 1000-byte field

Peer's SYN offers window scale 7 (×128); both sides enable scaling.

```text
  handshake:  peer SYN  WS=7   →  snd_wscale = 7
  later ACK:  window field = 1000
              SND.WND = 1000 << 7 = 128 000 bytes
```

The sender may now keep 128 000 unacknowledged bytes in flight (subject to cwnd), versus the 1000 a
naive reading of the field would allow — a 128× difference, all from one shift negotiated at setup.

## 8. The code, walked

- `parse_options` yields `window_scale` (clamped).
- The SYN/SYN-ACK builders concatenate `MSS [+ WS] [+ TS]` — each sub-blob already 4-byte aligned, so
  the concatenation is too.
- `accept` sets `snd_wscale` from the peer's SYN; `on_segment` sets it from the SYN-ACK (active open).
- ESTABLISHED left-shifts the incoming window into the now-`u32` `SND.WND`; the dup-ACK comparison
  uses the scaled values.
- `usable_window` drops its old `as u32` cast — the math is `u32` throughout.

`main.rs` already parses options and routes through `on_segment`, so it needs only the progress note.

## 9. Verification

`cargo test` (88 total) adds:
- `parse_options_reads_and_clamps_window_scale` — reads a shift, clamps `> 14` to 14, rejects a
  wrong-length option.
- `synack_offers_window_scale_when_peer_does` / `synack_omits_window_scale_when_peer_silent`.
- `peer_window_is_left_shifted_by_negotiated_scale` — a 1000-byte field with shift 7 becomes
  `SND.WND = 128 000`.
- `active_open_adopts_peer_window_scale`.

## 10. Why this, not that

| Decision | Alternative | Why |
|---|---|---|
| Advertise our own scale = 0 | Pick a non-zero shift | Our receive buffer is ~1 KB; a shift would only round it down. Sending the option at shift 0 still enables scaling so we can honor the peer's window. |
| Apply the shift in ESTABLISHED | Also scale the SYN/SYN-ACK window | RFC 7323 §2.2: the handshake windows are unscaled; applying the shift only after the handshake matches the spec without a special case. |
| Widen only `SND.WND` to `u32` | Widen the advertised field too | The wire field stays 16 bits by definition; only the *interpreted* send window can exceed 64 KB. |
| Clamp the peer's shift to 14 | Trust it | RFC 7323 §2.3 caps the shift at 14; a larger value is a bug or attack and must be clamped. |

## 11. Rebuild it yourself — checklist + exercises

**Blank-file checklist:**
- [ ] Why does a 16-bit window throttle a long-fat-network path? Compute a BDP example.
- [ ] Draw the Window Scale option bytes. What does the shift apply to?
- [ ] Explain the per-direction asymmetry: what are `snd_wscale` and `rcv_wscale`?
- [ ] Why must `SND.WND` become `u32` but the advertised field stay 16 bits?
- [ ] Why do we advertise shift 0, and what does that still buy us?

**Exercises:**
- **E1.** Grow the receive buffer to, say, 256 KB and advertise a real `rcv_wscale`; scale the
  window we emit (`field = real_window >> rcv_wscale`) and add a test.
- **E2.** Enforce RFC 7323 §2.2: ignore a Window Scale option that arrives on a non-SYN segment.
- **E3.** Combine with Day 16: confirm a SYN-ACK carrying MSS + WS + TS parses correctly and the data
  offset / checksum are right.
- **E4.** Capture a real Linux SYN with `tcpdump -v` and verify `parse_options` reads its window
  scale alongside MSS, SACK-permitted, and timestamps.

## 12. What the next day adds

Day 18 is the big one: **Selective Acknowledgment** (SACK, RFC 2018). Today a single lost segment
forces the sender to retransmit *everything* after it, because a cumulative ACK can only say "I have
through byte N." SACK lets the receiver also say "…and I separately have bytes N+1000 to N+2000," so
the sender retransmits only the genuine hole. It uses the option framework (a SACK-Permitted option in
the SYN, SACK blocks in ACKs), the reassembler's buffered ranges (to *generate* blocks), and the
retransmission queue (to *act* on them) — the culmination of the last several days.

> Re-type the window-scale negotiation and the `SND.WND` shift with the book closed, then
> `cargo test`. Your stack can now fill a fast, far pipe — the last 16-bit window is gone.
