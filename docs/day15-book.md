# Day 15 — TCP, Part 13: TCP Options and MSS Negotiation

> Goal: open the door we have kept shut for fourteen days. Every segment we have built carries a bare
> 20-byte TCP header, and every segment we received, we parsed only the fixed 20 bytes and *skipped* whatever
> options followed. But the options field is where TCP's modern features live — MSS, window scaling,
> timestamps, SACK. This chapter builds the **machinery to parse and emit options**, then uses it for the
> most fundamental one: **Maximum Segment Size** (RFC 9293 §3.7.1). We read the peer's MSS from its SYN,
> advertise our own, and finally segment outgoing data to the *negotiated* size instead of a hardcoded 1460.
> That framework is the foundation Days 16–18 (timestamps, window scaling, SACK) all build on.

This is an *infrastructure* day: the single feature (MSS) is modest, but the **option-parsing and
option-emitting machinery** it forces us to build is what the next three days stand on. Get the defensive
option walker and the data-offset arithmetic right here, and timestamps, window scaling, and SACK become
"add one `if` arm and one builder."

**Contents**

Volume I — the chapter
1. The mental model: the options field
2. The option wire format (kind / length / value, NOP, EOL)
3. The MSS option specifically
4. Parsing: a defensive option walker
5. Emitting: generalizing `build_packet` and the data offset
6. Negotiating the send MSS (the `min`, and the default)
7. Segmenting outgoing data to the negotiated MSS
8. The design choice: `TcpOptions` beside `TcpHeader`
9. Worked example: a handshake with options
10. The Rust: the walker's safety and the parse-beside-header seam
11. The code, walked end to end
12. Verification
13. Why this, not that
14. Honesty: what production does, and what later days added
15. Rebuild it yourself — checklist + exercises
16. What the next step adds

Volume II — the exhaustive reference
- A. The TCP option registry and the 40-byte budget
- B. MSS, MTU, MRU, and the 40-byte subtraction
- C. Path MTU Discovery and MSS clamping
- D. The option walker as attack surface
- E. NOP padding and 4-byte alignment, exhaustively
- F. A worked option-parse trace (a real Linux SYN)
- G. Comparison to real stacks — option ordering and middleboxes
- H. Security — tiny-MSS DoS and the option parser
- I. Performance — MSS too small vs too big
- J. Extended FAQ
- K. Anki starter deck
- L. Glossary
- M. Reference tables

---

# Volume I — the chapter

## 1. The mental model: the options field

A TCP header is 20 bytes *minimum*. The "data offset" field (4 bits, in units of 32-bit words) says how long
the header actually is, from 5 words (20 bytes, no options) up to 15 words (60 bytes, up to 40 bytes of
options). Everything between byte 20 and `data_offset × 4` is the **options area**; the payload starts after
it.

```text
   ┌──────────────── TCP header ─────────────────┐
   │ 20 fixed bytes │ 0–40 bytes of options (pad) │ ... payload ...
   └────────────────┴─────────────────────────────┘
    data_offset (words) = (20 + option_bytes) / 4
```

Until today we wrote `data_offset = 5` always and read `&segment[data_offset..]` as the payload, silently
jumping over any options the peer sent. That was fine for a stack with no options to exchange. Now we have
something to say (our MSS) and something to hear (the peer's), so we must both **write** an option into our
SYN/SYN-ACK and **read** one out of theirs. The 4-bit data-offset cap is the quiet constraint behind every
option-design tradeoff: there are only 40 bytes, and every feature competes for them (the budget arithmetic
that decides "3 SACK blocks with timestamps" is §A, and Day 18 §5).

## 2. The option wire format (kind / length / value, NOP, EOL)

Options are a sequence of TLV-ish entries. Two are special single-byte forms; the rest are length-prefixed
(RFC 9293 §3.1):

| Kind | Name | Form | Meaning |
|---:|---|---|---|
| 0 | End of Option List | 1 byte | stop parsing; pad the rest with zeros |
| 1 | No-Operation (NOP) | 1 byte | filler, used to 4-byte-align the next option |
| 2 | Maximum Segment Size | `[2, 4, hi, lo]` | the sender's receive MSS (SYN only) |
| 3 | Window Scale | `[3, 3, shift]` | (Day 17) |
| 4 | SACK-Permitted | `[4, 2]` | (Day 18) |
| 5 | SACK | `[5, len, …]` | (Day 18) |
| 8 | Timestamps | `[8, 10, …]` | (Day 16) |

For the length-prefixed kinds, **the length byte counts the kind and length bytes themselves**. So MSS is
`length = 4`: one kind byte + one length byte + two value bytes. The whole options area must end on a 4-byte
boundary (because `data_offset` is in words); senders pad with NOPs and/or a single EOL. The MSS option is
conveniently already 4 bytes, so it needs no padding on its own. (Why NOPs and not just one EOL? Because
options that aren't naturally word-aligned — window scale (3 bytes), SACK-permitted (2 bytes) — are NOP-padded
*individually* so each starts on a clean boundary, §E.)

## 3. The MSS option specifically

MSS is the largest **payload** (not counting headers) the advertiser is willing to *receive* in one segment.
Crucially:

- It is **only meaningful on a SYN** (the handshake is the one chance to set it; it cannot change
  mid-connection).
- Each side advertises its *own* receive MSS. So the peer's MSS option tells **us** the biggest segment **we**
  may send; our MSS option tells the peer the biggest it may send us. (Same per-direction asymmetry as the
  window, Day 8, and window scaling, Day 17.)
- The value is the link MTU minus 40 (20 IP + 20 TCP). On our 1500-byte TUN that is **1460**.

If a SYN carries no MSS option, RFC 9293 §3.7.1 says assume 536 for IPv4. Real peers always send one, so in
practice the default only matters for our synthetic, option-less test SYNs; we default it to our own 1460
there (a documented deviation) so those tests still segment at full size.

## 4. Parsing: a defensive option walker

`parse_options(&[u8]) -> TcpOptions` walks the option bytes. The hazards are all about **trusting a length
from the wire**, so the walker is written to never loop forever and never index out of bounds:

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

The two guards that matter: `len < 2` rejects a zero/one length (a hostile `len = 0` would otherwise never
advance `i` — an infinite loop), and `i + len > opts.len()` rejects a length that claims more bytes than
exist. Unknown kinds are skipped by their length, exactly as a real stack must, so adding timestamps/SACK
later is just another `if kind == …` arm. `TcpOptions` starts with one field, `mss: Option<u16>`, and grows
over the next three days into the multi-field struct Day 18 finishes (§14).

## 5. Emitting: generalizing `build_packet` and the data offset

`build_packet` gains an `options: &[u8]` parameter (the raw, already-4-byte-aligned blob; pass `&[]` for
none). Three things change inside it:

```rust
let tcp_hdr_len = 20 + options.len();              // fixed + options
pkt[t + 12] = ((tcp_hdr_len / 4) as u8) << 4;      // data offset in 32-bit words
pkt[t + 20 .. t + 20 + options.len()].copy_from_slice(options);
pkt[t + tcp_hdr_len ..].copy_from_slice(payload);  // payload starts after the options
```

A `debug_assert!(options.len() % 4 == 0)` guards the alignment invariant (later written
`options.len().is_multiple_of(4)`). The MSS blob is built by a tiny helper, `mss_option(mss) -> [2, 4, hi,
lo]`, which is already 4 bytes. The checksum is computed over the whole TCP segment *including the options*,
so nothing special is needed there — the existing `tcp_checksum` already covers `&pkt[t..]`.

A neat property falls out: when `options` is empty, `tcp_hdr_len = 20`, the data offset is `5` again, and a
data/ACK segment is byte-for-byte identical to before. Only SYN and SYN-ACK grow — exactly the two segments
that carry MSS at this stage.

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

`OUR_MSS` is derived from the congestion module's `MSS` (same 1500-byte link), so the literal 1460 lives in
exactly one place. Note the deliberate asymmetry of roles: we *advertise* `OUR_MSS` (our receive capacity)
and *segment by* `send_mss` (bounded by the peer's receive capacity). The `min` is the negotiation — neither
side dictates; the smaller of the two receive capacities governs each direction's segment size.

## 7. Segmenting outgoing data to the negotiated MSS

`poll_transmit` had `let mss = crate::congestion::MSS as usize;` — a hardcoded 1460. One line changes it to
the negotiated value:

```rust
let mss = self.send_mss as usize;
```

Now a peer that advertised a 500-byte MSS gets 500-byte segments, even though our congestion window (which
still counts in 1460-byte units) would happily allow a larger one. The congestion window is a *byte budget*;
the MSS is the *per-segment cap*. They are different limits and now correctly independent —
`min(usable_window, send_mss, buffered)` per segment, with Nagle still holding a sub-`send_mss` tail.

## 8. The design choice: `TcpOptions` beside `TcpHeader`

The obvious move is to add an `options` field to `TcpHeader`. We did **not** — `TcpHeader` is built by literal
in ~40 test sites, and adding a field would force a mechanical edit to every one and bury the real change in
noise. Instead:

- `parse_options` is a **separate** function; the parsed `TcpOptions` travels *beside* the header.
- A new method `on_segment(th, payload, opts, now_ms)` carries the options into the state machine.
- The old `on_packet_at(th, payload, now_ms)` becomes a one-line wrapper that passes
  `&TcpOptions::default()`, so its ~30 existing test callers are untouched.

`main` parses the options off the wire once (`&l4[20..data_offset]`) and calls `on_segment` / `accept` with
them. This keeps the diff focused, and it is the right seam for Day 16: timestamps ride on *every* segment,
and `on_segment` is exactly where they will be read. (This is the same "evolve the API by adding a wrapper"
move as Day 12's `_at` constructors — §10.)

## 9. Worked example: a handshake with options

Client SYN advertises MSS 1460; we (ISS 0) reply.

```text
   client → us:  SYN seq=100  options=[2,4,05,b4]      (MSS 1460; 0x05b4 = 1460)
                 parse_options → { mss: Some(1460) }
   us:           send_mss = min(OUR_MSS 1460, 1460) = 1460
   us → client:  SYN-ACK seq=0 ack=101 options=[2,4,05,b4]   (data_offset = 24/4 = 6 words)
                 len = 20 IP + 24 TCP = 44 bytes
   client → us:  ACK  (no options) → ESTABLISHED
```

If the client had said MSS 500, our `send_mss` would be 500 and a 1200-byte write would leave as `500 + 500`
with a 200-byte tail held by Nagle — never a single 1200-byte (or 1460-clipped) segment.

## 10. The Rust: the walker's safety and the parse-beside-header seam

- **The walker can't loop or over-read.** Every length-prefixed branch first checks there *is* a length byte
  (`i + 1 >= opts.len()`), then that the length is sane (`len < 2`) and in-bounds (`i + len > opts.len()`).
  The `len < 2` check is subtle but vital: `len` includes the kind+length bytes, so the minimum legal value
  is 2; a hostile `len = 0` or `1` would advance `i` by less than the bytes consumed (or not at all),
  risking an infinite loop. Slicing `&opts[i+2 .. i+len]` is only reached after both bounds are proven, so it
  can't panic. This is the Day-1 parser discipline (validate length, never trust the wire) applied to the
  option layer.
- **`TcpOptions` beside `TcpHeader` is a deliberate decoupling.** Keeping options out of the header struct
  means the ~40 test `TcpHeader { … }` literals never change as options accumulate (Days 16–18 add four more
  fields to `TcpOptions`, zero to `TcpHeader`). The parsed options flow as a separate `&TcpOptions` argument
  — a clean seam that also makes "this segment had no options" expressible as `TcpOptions::default()` without
  a sentinel.
- **`Option<u16>` for MSS** distinguishes "no MSS option present" (`None`) from "MSS option = 0" — which
  matters because the *absence* triggers the RFC 536 default, while a present (if tiny) value is honored.
  Encoding presence in the type, not a magic number, is the idiomatic Rust move.

## 11. The code, walked end to end

`src/tcp.rs`:
- Constants `OPT_END/OPT_NOP/OPT_MSS`, `OUR_MSS` (from `congestion::MSS`), `DEFAULT_SEND_MSS`.
- `TcpOptions { mss: Option<u16> }` + `parse_options` + `mss_option`.
- `build_packet` gains `options: &[u8]`; `segment_opts` exposes it; `segment` forwards `&[]`.
- `send_mss` field; set in both constructors; SYN/SYN-ACK now emit `mss_option(OUR_MSS)`.
- `on_segment` (new) carries `opts`; `on_packet_at` wraps it; the SYN-ACK path learns the peer MSS.
- `poll_transmit` chops by `self.send_mss`.

`src/main.rs`: parse `opts` once; pass to `on_segment` and `accept`.

## 12. Verification

`cargo test` adds:
- `parse_options_handles_mss_nop_eol_and_malformed` — MSS read past NOPs, stops at EOL, and survives
  truncated / zero-length options without panicking or looping.
- `synack_advertises_our_mss_and_negotiates_send_mss` — the SYN-ACK carries `OUR_MSS`; `send_mss` becomes
  `min(OUR_MSS, peer)`.
- `missing_peer_mss_falls_back_to_default`.
- `outgoing_data_is_segmented_to_negotiated_mss` — a 500-byte MSS yields 500-byte segments.
- `active_open_learns_peer_mss_from_synack`.
- The existing `accept_produces_valid_synack` now asserts the 44-byte SYN-ACK and the emitted MSS.

## 13. Why this, not that

| Decision | Alternative | Why |
|---|---|---|
| `TcpOptions` beside `TcpHeader` | Add `options` field to `TcpHeader` | Avoids editing ~40 literal test headers; `on_segment` is the right seam for per-segment options (Day 16). |
| Default send MSS = `OUR_MSS` | RFC's 536 for a missing option | Real peers always advertise; the default only affects option-less test SYNs, where full-size segmentation keeps tests honest. Documented. |
| `send_mss` separate from cwnd's MSS | One shared MSS everywhere | Different limits — a per-segment size cap vs a bytes-in-flight budget; conflating them breaks when a peer advertises a small MSS. |
| Derive `OUR_MSS` from `congestion::MSS` | Repeat the literal `1460` | One source of truth for the link's segment size; no drift. |
| Defensive `parse_options` (stop on bad length) | Trust the wire | A `len = 0` would infinite-loop; an overlong `len` would panic. Never trust a length you didn't write (§D). |

## 14. Honesty: what production does, and what later days added

- **The framework was built to grow, and did.** `TcpOptions` gained `timestamps` (Day 16), `window_scale`
  (Day 17), and `sack_permitted` + `sack_blocks` + `sack_block_count` (Day 18). `parse_options` gained an
  arm per option; the builders (`ws_option`, `ts_option`, `sack_perm_option`, `sack_option`) mirror
  `mss_option`. Day 15's defensive walker and `is_multiple_of` alignment are exactly what made those
  additions one-arm-each. This day's real product is that extensibility.
- **No Path MTU Discovery (PMTUD).** We learn the MSS from the SYN but never *discover* the true path MTU
  (which can be smaller than either end's link MTU due to tunnels/VPNs). A real stack does PMTUD (or
  PLPMTUD) and may **clamp** the MSS (§C). On a mismatched path our 1460-byte segments could be fragmented
  or dropped; on our local TUN the MTU is uniform so it doesn't arise.
- **No MSS clamping.** Middleboxes (routers, firewalls) often rewrite the MSS option in transiting SYNs to
  force a smaller segment (PPPoE's famous 1492 clamp). We neither clamp nor expect clamping.
- **No minimum-MSS floor.** We honor whatever (positive) MSS the peer sends; a tiny MSS (e.g. 1) is a DoS
  vector (§H) that real stacks floor (often at ~88 or 256). Exercise: add a floor.
- **MSS counts payload only, on IPv4.** The 40-byte subtraction (20 IP + 20 TCP) assumes no IP options and
  IPv4; IPv6 subtracts 60 (40 IPv6 + 20 TCP), and IP/TCP options shrink it further. We assume the clean
  1500−40 = 1460 case.

None of these change the day-15 contract (we parse/emit options and segment to the negotiated MSS); they are
the path-awareness and hardening a production stack adds.

## 15. Rebuild it yourself — checklist + exercises

**Blank-file checklist:**

- [ ] How does a receiver find the options area and the payload? (data offset.)
- [ ] Write the MSS option bytes for 1460 by hand. What does the length byte count?
- [ ] Whose receive capacity does an MSS option describe — and which direction does it bound?
- [ ] Why must `parse_options` reject `len < 2`?
- [ ] Why is `send_mss` distinct from the congestion window's MSS unit?

**Exercises:**

- **E1.** Make `OUR_MSS` reflect the real interface MTU instead of a constant (query the TUN MTU).
- **E2.** Honor the RFC default of 536 when no MSS option is present, and add a test SYN that carries an
  explicit MSS so existing full-size tests still pass.
- **E3.** Emit a NOP-padded option list (e.g. MSS + a 2-byte option) and confirm `data_offset` and the
  checksum are still correct (§E).
- **E4.** ✅ *Done* (Days 16–18): add `parse_options` arms for timestamps, window scale, and SACK, and
  unit-test the walker against a real Linux SYN's option bytes (§F).
- **E5.** Add a **minimum MSS floor** (e.g. 256): clamp a peer's tiny MSS up, defending against the
  tiny-MSS DoS (§H).

## 16. What the next step adds

Day 16 spends the new framework on **TCP timestamps** (RFC 7323 §3–4). A timestamp option on every segment
lets us (a) measure RTT on *every* ACK instead of one sample per window, sharpening the RTO, and (b)
implement **PAWS** — Protect Against Wrapped Sequences — which rejects an old duplicate that has wrapped
around the 32-bit sequence space on a fast, long-lived connection. It is the first option that rides on
*every* segment, which is exactly why we built `on_segment` today.

---

# Volume II — the exhaustive reference

## A. The TCP option registry and the 40-byte budget

The IANA "TCP Option Kind Numbers" registry has dozens of entries; the ones that matter in practice, and
their sizes (padded to alignment):

```text
   kind  name                  bytes (padded)   where        our day
   ────  ────────────────────  ──────────────   ──────────   ──────
   0     End of Option List    1                 anywhere     15
   1     No-Operation          1                 anywhere     15
   2     Maximum Segment Size  4                 SYN          15
   3     Window Scale          4 (3 + 1 NOP)     SYN          17
   4     SACK-Permitted        4 (2 + 2 NOP)     SYN          18
   5     SACK                  4 + 8N            ACK          18
   8     Timestamps            12 (10 + 2 NOP)   any          16
   19    MD5 Signature         18                any          (BGP)
   28    User Timeout          4                 any          —
   34    TCP Fast Open Cookie  6–18              SYN          —
```

The **40-byte ceiling** (60-byte max header − 20 fixed) is the hard constraint everything competes for. A
typical modern SYN carries MSS(4) + SACK-Perm(4) + Timestamps(12) + Window Scale(4) = 24 bytes, leaving 16.
A data/ACK segment with Timestamps(12) leaves 28 — which is exactly why SACK is capped at 3 blocks once
timestamps are present (28 = 4 + 8·3, Day 18 §5). This budget arithmetic — *which options coexist in 40
bytes* — is the recurring constraint of the whole options era, and it's why the order options were added to
TCP (MSS first, then window scale and timestamps co-designed to share space, then SACK sized to fit
alongside) is no accident.

## B. MSS, MTU, MRU, and the 40-byte subtraction

The chain of sizes from link to payload:

```text
   MTU (Maximum Transmission Unit)  = largest IP packet the link carries (Ethernet: 1500)
   MSS (Maximum Segment Size)       = MTU − IP header − TCP header
                                     = 1500 − 20 − 20 = 1460   (IPv4, no options)
                                     = 1500 − 40 − 20 = 1440   (IPv6)
   payload per segment              ≤ min(our send_mss, peer's advertised MSS)
```

Key relationships and gotchas:

- **MSS is payload only** — it excludes the IP and TCP headers, so an MSS-1460 segment is a 1500-byte IP
  packet. Confusing MSS with MTU (off by 40) is a classic error.
- **IP/TCP options shrink it.** If the IP header carries options (rare) or the TCP segment carries its *own*
  options (timestamps, etc.), the *effective* payload is smaller than the advertised MSS — the advertised
  value assumes a 20+20 baseline, and the actual data room is `MSS − (TCP option bytes on this segment)`.
  A timestamped segment carries 12 fewer data bytes than its MSS suggests.
- **MRU** (Maximum Receive Unit) is the link-layer mirror; for our purposes MTU = MRU on the symmetric TUN.
- **Each side's MSS is its *receive* limit**, so the effective send size in each direction is the *peer's*
  advertised MSS (bounded further by our own — the `min`). This is why we *advertise* `OUR_MSS` but *segment
  by* `send_mss`.

## C. Path MTU Discovery and MSS clamping

The MSS option only reflects each *endpoint's* link MTU. The **path** between them may have a smaller MTU
(a VPN, a PPPoE link, a tunnel that adds encapsulation overhead). Two mechanisms cope:

- **Path MTU Discovery (PMTUD, RFC 1191).** The sender sets the IP "Don't Fragment" bit (we do — `0x4000`)
  and sends full-MSS segments. A router that can't forward a too-big packet drops it and returns an ICMP
  "Fragmentation Needed" with the next-hop MTU; the sender lowers its effective MSS and retries. The fatal
  flaw: many firewalls **block ICMP**, so the ICMP never arrives — the sender keeps sending too-big packets
  that vanish, and the connection hangs (the "PMTUD black hole"). This is one of the most insidious
  real-world TCP failures: a connection that handshakes fine (small packets) but stalls the moment it sends
  a full-size segment.
- **PLPMTUD (RFC 4821).** Packetization-Layer PMTUD avoids relying on ICMP: the sender *probes* with
  progressively larger packets and infers the path MTU from which sizes get acked — robust to ICMP
  filtering.
- **MSS clamping.** Middleboxes (home routers especially) rewrite the MSS option *in transit* on SYNs,
  lowering it so endpoints never send packets too big for the path (e.g. clamp to 1492 for PPPoE, or to the
  tunnel MTU on a VPN gateway). It's a pragmatic, widely-deployed hack that sidesteps PMTUD's fragility by
  fixing the MSS at connection setup.

We do *none* of this: we advertise/learn the MSS and trust it. Our TUN link has a uniform MTU, so there's no
path mismatch to discover. On the real internet, a stack without PMTUD/clamping awareness can hit the black
hole; exercise: react to an ICMP "Frag Needed" by lowering `send_mss`.

## D. The option walker as attack surface

A length field controlled by the sender is the textbook parser vulnerability, and the option walker is where
it lives. The hazards our guards prevent:

```text
   malicious input              without our guard                 our guard
   ──────────────────────────   ───────────────────────────────   ────────────────────────
   len = 0                       i never advances → infinite loop   len < 2 → break
   len = 1                       advance by 1, but slice expects ≥2  len < 2 → break
   len > remaining bytes         slice out of bounds → panic         i + len > opts.len() → break
   kind with no length byte      read opts[i+1] OOB                  i + 1 >= opts.len() → break
   huge option count             unbounded work                      bounded by opts.len() (≤ 40)
```

Real-world option-parser bugs are legion: the **SACK Panic** (Day 18 §G) abused SACK *processing* (not
parsing) to overflow retransmit-queue arithmetic; older stacks had option-parser overflows and infinite
loops on crafted lengths. The discipline — *validate the length before you trust it, and bound every loop by
the actual buffer* — is the same one Day 1 drilled for the IP header, applied to a variable-length, nested
structure where it matters even more (the length is attacker-chosen at every step). Our walker is total
(terminates on any input) and panic-free (every index is bounds-checked), which is the correctness bar a
wire parser must clear.

## E. NOP padding and 4-byte alignment, exhaustively

Why all the NOPs? Because `data_offset` counts 32-bit *words*, so the options area must be a multiple of 4
bytes, *and* most implementations like each multi-byte option to start on a word boundary for clean access.
The single-byte NOP (kind 1) is the universal filler:

```text
   option            natural size   padded to 4-align    padded form
   ───────────────   ────────────   ─────────────────    ─────────────────────────────
   MSS               4              4 (already aligned)   [2,4,hi,lo]
   Window Scale      3              4                     [NOP, 3,3,shift]
   SACK-Permitted    2              4                     [NOP, NOP, 4,2]
   Timestamps        10             12                    [NOP, NOP, 8,10, val×4, ecr×4]
   SACK (N blocks)   2+8N           4+8N                  [NOP, NOP, 5,len, blocks…]
```

Our builders each emit a *self-aligned* blob (MSS is 4; `ws_option` prepends one NOP to make 4; `ts_option`
and `sack_option` prepend two NOPs to make 12 / 4+8N), so concatenating any set of them stays 4-aligned by
construction — which is why `segment_opts` can just join them and the `debug_assert!(len % 4 == 0)` always
holds. The alternative (a global NOP/EOL pad at the end) works too and is what the EOL (kind 0) is for —
"stop, pad the rest with zeros to the word boundary" — but per-option self-alignment composes more cleanly
when multiple options stack (Days 16–18). The cost is a couple of wasted NOP bytes per option; the benefit is
that adding an option never disturbs another's alignment.

## F. A worked option-parse trace (a real Linux SYN)

A typical Linux SYN's option bytes, decoded by our walker. `tcpdump -v` would print `mss 1460,sackOK,TS val
… ecr 0,nop,wscale 7`:

```text
   bytes:  02 04 05 b4 | 04 02 | 08 0a [TSval×4] [TSecr×4] | 01 | 03 03 07
   i=0:    kind 2 (MSS),  len 4 → value 0x05b4 = 1460     → out.mss = Some(1460); i += 4
   i=4:    kind 4 (SACK-Perm), len 2 → (no data)          → out.sack_permitted = true; i += 2   (Day 18)
   i=6:    kind 8 (Timestamps), len 10 → TSval, TSecr     → out.timestamps = Some((v,e)); i += 10 (Day 16)
   i=16:   kind 1 (NOP) → i += 1                          (alignment filler before wscale)
   i=17:   kind 3 (Window Scale), len 3 → shift 7         → out.window_scale = Some(7); i += 3   (Day 17)
   i=20:   i == opts.len() → done
```

At day 15 only the MSS arm exists, so the walker reads `mss = 1460` and *skips* the rest by their lengths
(the `i += len` in the `kind =>` branch) — which is exactly the "unknown kinds are skipped gracefully"
property that lets a day-15 stack interoperate with a fully-featured Linux peer. By Day 18 every arm exists
and the whole line decodes. The NOP at i=16 is the alignment filler Linux inserts so window-scale (3 bytes)
lands on a clean boundary after the 10-byte timestamps option (§E).

## G. Comparison to real stacks — option ordering and middleboxes

```text
   aspect             real stacks                                this stack
   ────────────────   ────────────────────────────────────────  ──────────────────────
   option order       fixed conventional order per OS            MSS, WS, TS, SACK-Perm (our order)
   unknown options    skipped by length                          skipped by length ✓
   MSS clamping       middleboxes rewrite in transit              none (trust the value)
   PMTUD              ICMP-based or PLPMTUD                       none (uniform TUN MTU)
   minimum MSS        floored (~88–256)                           none (any positive value)
   option stripping   some middleboxes strip unknown options      n/a
```

Two real-world hazards we sidestep: **middlebox option stripping** (some firewalls remove options they don't
understand — historically window-scale and SACK got stripped, silently degrading connections, which is part
of why new TCP options are hard to deploy and QUIC moved to UDP), and **option-order sensitivity** (buggy
middleboxes that only recognize options in a specific order). Our endpoints fully control both ends and the
TUN passes options untouched, so neither bites — but they're why the modern internet is "ossified" against
new TCP options, a major motivation for QUIC (Day 9 §J, Day 11 §C).

## H. Security — tiny-MSS DoS and the option parser

- **Tiny-MSS amplification DoS.** A malicious peer advertises a *very small* MSS (e.g. 1). The victim then
  segments every byte of its (possibly large) response into 1-byte segments — each a 41-byte packet — so a
  small request elicits a huge number of tiny packets, amplifying the victim's outbound packet rate
  enormously (a packet-rate DoS the victim inflicts on itself and the network). The defense is a **minimum
  MSS floor** (Linux `tcp_min_snd_mss`, ~48–256): clamp a peer's tiny MSS up to a sane minimum. We have no
  floor (exercise E5) — a real hardening gap.
- **The option parser itself** (§D) is attack surface: crafted lengths aiming for infinite loops or
  out-of-bounds reads. Our walker is total and bounds-checked, so it's safe; the discipline matters because
  a single missing check (the `len < 2` guard especially) turns a parser into a hang or crash.
- **Option-based fingerprinting.** The *set and order* of options a stack emits (MSS value, window scale,
  SACK-permitted, timestamps, their order) is a reliable OS fingerprint (nmap, p0f use it). Not a
  vulnerability per se, but a privacy/recon consideration — our fixed option set is identifiable.
- **MSS-based evasion.** A tiny MSS forces tiny segments that can split application-layer keywords across
  packets, evading naive IDS signature matching (the segment-overlap evasion lineage, Day 9 §I). Floors and
  reassembly-before-inspection defend.

The theme: the MSS is an attacker-influenced *amplification* knob (tiny MSS → many packets) and the option
parser is attacker-controlled *parsing*, so a hardened stack floors the MSS and writes a total, bounds-checked
walker — the floor being the one defense our teaching version omits.

## I. Performance — MSS too small vs too big

- **MSS too small** → more segments for the same data → more headers (overhead) and more packets (the
  per-packet costs of Day 13 §I) → lower throughput and higher CPU. A 536-MSS connection on a 1500-MTU link
  wastes ~63% more packets than a 1460-MSS one for the same bytes.
- **MSS too big (bigger than the path MTU)** → IP fragmentation (if DF clear) or black-holing (if DF set and
  PMTUD fails, §C). Fragmentation is a performance and reliability disaster: one lost fragment loses the
  whole packet, and fragment reassembly is slow and a security hazard (Day 9 §I). This is *worse* than too
  small — hence the conservative "advertise your link MTU, discover the path" approach.
- **The sweet spot is the path MTU minus 40** — as large as possible without fragmenting. PMTUD/clamping
  exist to find it. Jumbo frames (9000-byte MTU) push it higher on controlled datacenter links, cutting
  per-byte overhead further.
- **Our cost** is one `min` per handshake and segmenting by `send_mss` in `poll_transmit` — free. The
  *performance correctness* win is that we now segment to the *peer's* capacity, so a small-MSS peer isn't
  sent oversized segments it would fragment or drop.

## J. Extended FAQ

1. **Where do TCP options live?** Between the 20-byte fixed header and the payload, up to 40 bytes, sized by
   the data offset.
2. **What's the data offset?** TCP header length in 32-bit words (5–15 → 20–60 bytes).
3. **What does the option length byte count?** The kind and length bytes too (MSS len = 4).
4. **What are NOP and EOL?** Single-byte filler (alignment) and end-of-options marker (kind 1 and 0).
5. **What is the MSS option?** The advertiser's maximum *receive* segment payload, SYN-only.
6. **Whose capacity does an MSS describe?** The advertiser's receive capacity → bounds what the *peer* sends.
7. **What is MSS for a 1500 MTU?** 1460 (1500 − 20 IP − 20 TCP) on IPv4.
8. **What if a SYN has no MSS option?** Assume 536 (RFC); we default to OUR_MSS for option-less test SYNs.
9. **What is `send_mss`?** `min(OUR_MSS, peer's MSS)` — our per-segment payload cap.
10. **Why is `send_mss` separate from cwnd's MSS?** Per-segment size cap vs bytes-in-flight budget — different
    limits.
11. **Why must `parse_options` reject `len < 2`?** A zero/one length wouldn't advance `i` → infinite loop.
12. **Why reject `i + len > opts.len()`?** A length claiming more bytes than exist → out-of-bounds slice.
13. **How are unknown options handled?** Skipped by their length — so we interoperate with richer peers.
14. **Why `TcpOptions` beside `TcpHeader`?** To avoid editing ~40 test header literals; `on_segment` is the
    options seam.
15. **What property holds when options are empty?** The segment is byte-identical to the pre-options build
    (data offset 5).
16. **What is Path MTU Discovery?** Finding the smallest MTU on the path via DF + ICMP (or probing) (§C).
17. **What is the PMTUD black hole?** Firewalls blocking the ICMP, so too-big packets vanish and the
    connection hangs.
18. **What is MSS clamping?** Middleboxes rewriting the MSS option in transit to fit the path (§C).
19. **What is the tiny-MSS DoS?** A tiny advertised MSS forcing many tiny segments — packet-rate
    amplification (§H).
20. **What's the defense?** A minimum MSS floor (e.g. 256).
21. **Why all the NOPs?** To 4-byte-align options (the data offset is in words) (§E).
22. **Did the option framework grow?** Yes — timestamps (16), window scale (17), SACK (18) each added an
    arm/builder.
23. **Does MSS count headers?** No — payload only; an MSS-1460 segment is a 1500-byte packet.
24. **Can MSS change mid-connection?** No — SYN-only; it's fixed at the handshake.
25. **What's the real product of day 15?** The extensible, defensive option layer the rest of modern TCP
    stands on.

## K. Anki starter deck

```text
Q: Where do TCP options live?  A: between the 20-byte fixed header and the payload, ≤40 bytes (data offset).
Q: What's the data offset?  A: TCP header length in 32-bit words (5–15 → 20–60 bytes).
Q: What does an option's length byte count?  A: the kind and length bytes too (MSS len = 4).
Q: What is the MSS option?  A: the advertiser's max receive segment payload, SYN-only.
Q: Whose capacity does MSS describe / what does it bound?  A: the advertiser's receive capacity → bounds the peer's sending.
Q: MSS for a 1500 MTU (IPv4)?  A: 1460 (1500 − 20 − 20).
Q: send_mss formula?  A: min(OUR_MSS, peer's advertised MSS).
Q: Why is send_mss separate from cwnd's MSS?  A: per-segment size cap vs bytes-in-flight budget.
Q: Why must parse_options reject len < 2?  A: a 0/1 length wouldn't advance i → infinite loop.
Q: How are unknown options handled?  A: skipped by their length (interoperate with richer peers).
Q: Why TcpOptions beside TcpHeader?  A: avoid editing ~40 test header literals; on_segment is the options seam.
Q: Why all the NOPs in options?  A: to 4-byte-align (the data offset is in words).
Q: What is Path MTU Discovery / its black hole?  A: find path MTU via DF+ICMP; hangs if firewalls block the ICMP.
Q: What is MSS clamping?  A: middleboxes rewriting the MSS in transit to fit the path.
Q: What is the tiny-MSS DoS and its defense?  A: a tiny MSS → many tiny segments (amplification); floor the MSS.
```

## L. Glossary

- **Options area** — the 0–40 bytes between the fixed TCP header and the payload.
- **Data offset** — TCP header length in 32-bit words; locates the payload.
- **Kind / length / value** — the option encoding; length includes the kind+length bytes.
- **NOP / EOL** — single-byte filler (kind 1, alignment) / end-of-options (kind 0).
- **MSS (Maximum Segment Size)** — the advertiser's max receive payload (SYN-only).
- **MTU / MRU** — link's max transmission/receive unit; MSS = MTU − 40.
- **`send_mss`** — our negotiated per-segment payload cap (`min(OUR_MSS, peer MSS)`).
- **Path MTU Discovery (PMTUD)** — finding the smallest MTU on the path.
- **MSS clamping** — middleboxes rewriting the MSS option in transit.
- **Tiny-MSS DoS** — advertising a tiny MSS to force packet-rate amplification.
- **`TcpOptions`** — the parsed-options struct carried beside `TcpHeader`.

## M. Reference tables

**M.1 — Option encoding**

```text
   form               bytes              example
   ────────────────   ────────────────   ──────────────────
   single-byte        1                  EOL [0], NOP [1]
   length-prefixed    2 + value          MSS [2,4,hi,lo]
   (length counts kind + length + value)
```

**M.2 — Size chain**

```text
   quantity   value (IPv4, 1500 MTU)   = MTU − …
   ────────   ─────────────────────    ────────────
   MTU        1500                      —
   MSS        1460                      − 20 IP − 20 TCP
   payload    ≤ min(send_mss, peer)     − any TCP options on the segment
```

**M.3 — Where each option is valid**

```text
   option            valid on        changes mid-conn?   our day
   ───────────────   ─────────────   ─────────────────   ──────
   MSS               SYN only         no                  15
   Window Scale      SYN only         no                  17
   SACK-Permitted    SYN only         no                  18
   Timestamps        any segment      —                   16
   SACK              ACK segments     —                   18
```

> Re-type `parse_options`, the `build_packet` options path, and the `min`-based `send_mss` with the book
> closed, then `cargo test`. You have built the option layer the rest of modern TCP stands on — and a
> defensive walker that an attacker's crafted length can't loop or crash.
