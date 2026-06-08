# Day 15 — TCP, Part 13: TCP Options and MSS Negotiation

> Goal: open the door we have kept shut for fourteen days. Every segment we have built carries a bare
> 20-byte TCP header, and every segment we received, we parsed only the fixed 20 bytes and *skipped*
> whatever options followed. But the options field is where TCP's modern features live — MSS, window
> scaling, timestamps, SACK. This chapter builds the **machinery to parse and emit options**, then
> uses it for the most fundamental one: **Maximum Segment Size** (RFC 9293 §3.7.1). We read the
> peer's MSS from its SYN, advertise our own, and finally segment outgoing data to the *negotiated*
> size instead of a hardcoded 1460. That framework is the foundation Days 16–18 (timestamps, window
> scaling, SACK) all build on.

**Contents**
1. The mental model: the options field
2. The option wire format (kind / length / value, NOP, EOL)
3. The MSS option specifically
4. Parsing: a defensive option walker
5. Emitting: generalizing `build_packet` and the data offset
6. Negotiating the send MSS (the `min`, and the default)
7. Segmenting outgoing data to the negotiated MSS
8. The design choice: `TcpOptions` beside `TcpHeader`, and `on_segment`
9. Worked example: a handshake with options
10. The code, walked
11. Verification
12. Why this, not that
13. Rebuild it yourself — checklist + exercises
14. What the next day adds

---

## 1. The mental model: the options field

A TCP header is 20 bytes *minimum*. The "data offset" field (4 bits, in units of 32-bit words) says
how long the header actually is, from 5 words (20 bytes, no options) up to 15 words (60 bytes, up to
40 bytes of options). Everything between byte 20 and `data_offset × 4` is the **options area**; the
payload starts after it.

```text
  ┌──────────────── TCP header ─────────────────┐
  │ 20 fixed bytes │ 0–40 bytes of options (pad) │ ... payload ...
  └────────────────┴─────────────────────────────┘
   data_offset (words) = (20 + option_bytes) / 4
```

Until today we wrote `data_offset = 5` always and read `&segment[data_offset..]` as the payload,
silently jumping over any options the peer sent. That was fine for a stack with no options to
exchange. Now we have something to say (our MSS) and something to hear (the peer's), so we must both
**write** an option into our SYN/SYN-ACK and **read** one out of theirs.

## 2. The option wire format (kind / length / value, NOP, EOL)

Options are a sequence of TLV-ish entries. Two are special single-byte forms; the rest are
length-prefixed (RFC 9293 §3.1):

| Kind | Name | Form | Meaning |
|---:|---|---|---|
| 0 | End of Option List | 1 byte | stop parsing; pad the rest with zeros |
| 1 | No-Operation (NOP) | 1 byte | filler, used to 4-byte-align the next option |
| 2 | Maximum Segment Size | `[2, 4, hi, lo]` | the sender's receive MSS (SYN only) |
| 3 | Window Scale | `[3, 3, shift]` | (Day 17) |
| 4 | SACK-Permitted | `[4, 2]` | (Day 18) |
| 5 | SACK | `[5, len, …]` | (Day 18) |
| 8 | Timestamps | `[8, 10, …]` | (Day 16) |

For the length-prefixed kinds, **the length byte counts the kind and length bytes themselves**. So
MSS is `length = 4`: one kind byte + one length byte + two value bytes. The whole options area must
end on a 4-byte boundary (because `data_offset` is in words); senders pad with NOPs and/or a single
EOL. The MSS option is conveniently already 4 bytes, so it needs no padding on its own.

## 3. The MSS option specifically

MSS is the largest **payload** (not counting headers) the advertiser is willing to *receive* in one
segment. Crucially:

- It is **only meaningful on a SYN** (the handshake is the one chance to set it; it cannot change
  mid-connection).
- Each side advertises its *own* receive MSS. So the peer's MSS option tells **us** the biggest
  segment **we** may send; our MSS option tells the peer the biggest it may send us.
- The value is the link MTU minus 40 (20 IP + 20 TCP). On our 1500-byte TUN that is **1460**.

If a SYN carries no MSS option, RFC 9293 §3.7.1 says assume 536 for IPv4. Real peers always send one,
so in practice the default only matters for our synthetic, option-less test SYNs; we default it to
our own 1460 there (a documented deviation) so those tests still segment at full size.

## 4. Parsing: a defensive option walker

`parse_options(&[u8]) -> TcpOptions` walks the option bytes. The hazards are all about **trusting a
length from the wire**, so the walker is written to never loop forever and never index out of bounds:

```rust
while i < opts.len() {
    match opts[i] {
        OPT_END => break,        // 0: stop
        OPT_NOP => i += 1,       // 1: single-byte padding
        kind => {
            if i + 1 >= opts.len() { break; }     // no length byte → truncated
            let len = opts[i + 1] as usize;
            if len < 2 || i + len > opts.len() { break; } // len<2 (incl. 0!) or overruns → stop
            let data = &opts[i + 2 .. i + len];
            if kind == OPT_MSS && data.len() == 2 {
                out.mss = Some(u16::from_be_bytes([data[0], data[1]]));
            }
            i += len;
        }
    }
}
```

The two guards that matter: `len < 2` rejects a zero/one length (a hostile `len = 0` would otherwise
never advance `i` — an infinite loop), and `i + len > opts.len()` rejects a length that claims more
bytes than exist. Unknown kinds are skipped by their length, exactly as a real stack must, so adding
timestamps/SACK later is just another `if kind == …` arm. `TcpOptions` starts with one field,
`mss: Option<u16>`, and grows over the next three days.

## 5. Emitting: generalizing `build_packet` and the data offset

`build_packet` gains an `options: &[u8]` parameter (the raw, already-4-byte-aligned blob; pass `&[]`
for none). Three things change inside it:

```rust
let tcp_hdr_len = 20 + options.len();              // fixed + options
pkt[t + 12] = ((tcp_hdr_len / 4) as u8) << 4;      // data offset in 32-bit words
pkt[t + 20 .. t + 20 + options.len()].copy_from_slice(options);
pkt[t + tcp_hdr_len ..].copy_from_slice(payload);  // payload starts after the options
```

A `debug_assert!(options.len() % 4 == 0)` guards the alignment invariant. The MSS blob is built by a
tiny helper, `mss_option(mss) -> [2, 4, hi, lo]`, which is already 4 bytes. The checksum is computed
over the whole TCP segment *including the options*, so nothing special is needed there — the existing
`tcp_checksum` already covers `&pkt[t..]`.

A neat property falls out: when `options` is empty, `tcp_hdr_len = 20`, the data offset is `5` again,
and a data/ACK segment is byte-for-byte identical to before. Only SYN and SYN-ACK grow — exactly the
two segments that carry MSS.

## 6. Negotiating the send MSS (the `min`, and the default)

The connection stores one new value, `send_mss: u16` — the largest payload we will put in a segment:

```text
  send_mss = min(OUR_MSS, peer_advertised_MSS)
```

Set at the handshake:

- **Passive open** (`accept`): the peer's SYN options arrive alongside the header; `send_mss =
  peer.mss.map_or(DEFAULT, |m| m.min(OUR_MSS))`.
- **Active open** (`connect` → SYN-ACK in `on_segment`): we start at the default and lower it to
  `min(OUR_MSS, peer.mss)` when the SYN-ACK reveals the peer's MSS.

`OUR_MSS` is derived from the congestion module's `MSS` (same 1500-byte link), so the literal 1460
lives in exactly one place. Note the deliberate asymmetry of roles: we *advertise* `OUR_MSS` (our
receive capacity) and *segment by* `send_mss` (bounded by the peer's receive capacity).

## 7. Segmenting outgoing data to the negotiated MSS

`poll_transmit` had `let mss = crate::congestion::MSS as usize;` — a hardcoded 1460. One line
changes it to the negotiated value:

```rust
let mss = self.send_mss as usize;
```

Now a peer that advertised a 500-byte MSS gets 500-byte segments, even though our congestion window
(which still counts in 1460-byte units) would happily allow a larger one. The congestion window is a
*byte budget*; the MSS is the *per-segment cap*. They are different limits and now correctly
independent — `min(usable_window, send_mss, buffered)` per segment, with Nagle still holding a
sub-`send_mss` tail.

## 8. The design choice: `TcpOptions` beside `TcpHeader`, and `on_segment`

The obvious move is to add an `options` field to `TcpHeader`. We did **not** — `TcpHeader` is built by
literal in ~40 test sites, and adding a field would force a mechanical edit to every one and bury the
real change in noise. Instead:

- `parse_options` is a **separate** function; the parsed `TcpOptions` travels *beside* the header.
- A new method `on_segment(th, payload, opts, now_ms)` carries the options into the state machine.
- The old `on_packet_at(th, payload, now_ms)` becomes a one-line wrapper that passes
  `&TcpOptions::default()`, so its ~30 existing test callers are untouched.

`main` parses the options off the wire once (`&l4[20..data_offset]`) and calls `on_segment` /
`accept` with them. This keeps the diff focused, and it is the right seam for Day 16: timestamps ride
on *every* segment, and `on_segment` is exactly where they will be read.

## 9. Worked example: a handshake with options

Client SYN advertises MSS 1460; we (ISS 0) reply.

```text
  client → us:  SYN seq=100  options=[2,4,05,b4]      (MSS 1460)
                parse_options → { mss: Some(1460) }
  us:           send_mss = min(OUR_MSS 1460, 1460) = 1460
  us → client:  SYN-ACK seq=0 ack=101 options=[2,4,05,b4]   (data_offset = 24 / i.e. 6 words)
                len = 20 IP + 24 TCP = 44 bytes
  client → us:  ACK  (no options) → ESTABLISHED
```

If the client had said MSS 500, our `send_mss` would be 500 and a 1200-byte write would leave as
`500 + 500` with a 200-byte tail held by Nagle — never a single 1200-byte (or 1460-clipped) segment.

## 10. The code, walked

`src/tcp.rs`:
- Constants `OPT_END/OPT_NOP/OPT_MSS`, `OUR_MSS` (from `congestion::MSS`), `DEFAULT_SEND_MSS`.
- `TcpOptions { mss: Option<u16> }` + `parse_options` + `mss_option`.
- `build_packet` gains `options: &[u8]`; `segment_opts` exposes it; `segment` forwards `&[]`.
- `send_mss` field; set in both constructors; SYN/SYN-ACK now emit `mss_option(OUR_MSS)`.
- `on_segment` (new) carries `opts`; `on_packet_at` wraps it; the SYN-ACK path learns the peer MSS.
- `poll_transmit` chops by `self.send_mss`.

`src/main.rs`: parse `opts` once; pass to `on_segment` and `accept`.

## 11. Verification

`cargo test` (77 total) adds:
- `parse_options_handles_mss_nop_eol_and_malformed` — MSS read past NOPs, stops at EOL, and survives
  truncated / zero-length options without panicking or looping.
- `synack_advertises_our_mss_and_negotiates_send_mss` — the SYN-ACK carries `OUR_MSS`; `send_mss`
  becomes `min(OUR_MSS, peer)`.
- `missing_peer_mss_falls_back_to_default`.
- `outgoing_data_is_segmented_to_negotiated_mss` — a 500-byte MSS yields 500-byte segments.
- `active_open_learns_peer_mss_from_synack`.
- The existing `accept_produces_valid_synack` now asserts the 44-byte SYN-ACK and the emitted MSS.

## 12. Why this, not that

| Decision | Alternative | Why |
|---|---|---|
| `TcpOptions` beside `TcpHeader` | Add `options` field to `TcpHeader` | Avoids editing ~40 literal test headers; keeps the diff about the feature, and `on_segment` is the right seam for per-segment options (Day 16). |
| Default send MSS = `OUR_MSS` | RFC's 536 for a missing MSS option | Real peers always advertise; the default only affects our option-less test SYNs, where full-size segmentation keeps existing tests honest. Documented deviation. |
| `send_mss` separate from cwnd's MSS | One shared MSS everywhere | They are different limits — a per-segment size cap vs a bytes-in-flight budget — and conflating them breaks the moment a peer advertises a small MSS. |
| Derive `OUR_MSS` from `congestion::MSS` | Repeat the literal `1460` | One source of truth for the link's segment size; no drift. |
| Defensive `parse_options` (stop on bad length) | Trust the wire | A `len = 0` would infinite-loop and an overlong `len` would panic; never trust a length you didn't write. |

## 13. Rebuild it yourself — checklist + exercises

**Blank-file checklist:**
- [ ] How does a receiver find the options area and the payload? (data offset.)
- [ ] Write the MSS option bytes for 1460 by hand. What does the length byte count?
- [ ] Whose receive capacity does an MSS option describe — and which direction does it bound?
- [ ] Why must `parse_options` reject `len < 2`?
- [ ] Why is `send_mss` distinct from the congestion window's MSS unit?

**Exercises:**
- **E1.** Make `OUR_MSS` reflect the real interface MTU instead of a constant (query the TUN MTU).
- **E2.** Honor the RFC default of 536 when no MSS option is present, and add a test SYN that carries
  an explicit MSS so existing full-size tests still pass.
- **E3.** Emit a NOP-padded option list (e.g. MSS + a 2-byte option) and confirm `data_offset` and
  the checksum are still correct.
- **E4.** Add `parse_options` arms for SACK-Permitted (kind 4) and Window Scale (kind 3) now, even
  though they are unused, and unit-test the walker against a real Linux SYN's option bytes.

## 14. What the next day adds

Day 16 spends the new framework on **TCP timestamps** (RFC 7323 §3–4). A timestamp option on every
segment lets us (a) measure RTT on *every* ACK instead of one sample per window, sharpening the RTO,
and (b) implement **PAWS** — Protect Against Wrapped Sequences — which rejects an old duplicate that
has wrapped around the 32-bit sequence space on a fast, long-lived connection. It is the first option
that rides on every segment, which is exactly why we built `on_segment` today.

> Re-type `parse_options`, the `build_packet` options path, and the `min`-based `send_mss` with the
> book closed, then `cargo test`. You have built the option layer the rest of modern TCP stands on.
