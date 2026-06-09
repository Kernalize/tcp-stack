# Day 18 — TCP, Part 16: Selective Acknowledgment (SACK, RFC 2018)

> Goal: stop punishing a sender for *one* lost packet. With only the cumulative ACK, a receiver can
> say no more than "I have everything through byte N" — so when segment 2 of a 10-segment burst is
> lost but 3–10 arrive, the sender is *blind* to that and, on a timeout, re-sends 2 **and** 3–10,
> data the receiver already holds. **Selective Acknowledgment** (RFC 2018) adds a second channel:
> the receiver also reports the *islands* it has buffered above the hole ("…and I separately have
> bytes N+1000 … N+9000"), so the sender retransmits **only the hole**. This is the payoff day of the
> last several: it uses the **option framework** (Day 15) to negotiate and carry blocks, the
> **reassembler's** buffered ranges (Day 9) to *generate* them, and the **retransmission queue**
> (Day 12) to *act* on them.

**Contents**

Volume I — the chapter
1. The mental model: the cost of a single hole
2. Two halves: SACK-Permitted (negotiate) and SACK (report)
3. The SACK-Permitted option, byte by byte
4. The SACK option, byte by byte
5. The 40-byte budget: why at most three blocks
6. The receiver's job: generating blocks from the reassembler
7. The sender's job: consuming blocks and retransmitting only holes
8. Modular sequence math for block coverage
9. The Rust: types, ownership, and why a fixed array
10. A fully worked loss-recovery trace — go-back-N vs SACK
11. An annotated SACK option on the wire (hex)
12. The code, walked end to end
13. Verification — the tests, and why each exists
14. Why this, not that
15. Honesty: what production does that we don't
16. Rebuild it yourself — checklist + exercises
17. What the next day adds

Volume II — the exhaustive reference
- A. RFC 2018 in full: every field, every rule
- B. D-SACK (RFC 2883) — acknowledging *duplicates*
- C. RFC 6675 — the real selective-retransmission algorithm
- D. The option-space accounting, exhaustively
- E. A complete annotated connection trace (loss + SACK recovery)
- F. Comparison to real stacks — Linux, FreeBSD, lwIP, smoltcp
- G. Security — SACK as attack surface (SACK Panic, and ours)
- H. Performance — what SACK buys, and what it costs
- I. Extended FAQ — thirty questions a careful reader asks
- J. Anki starter deck
- K. Glossary
- L. Reference tables

---

# Volume I — the chapter

## 1. The mental model: the cost of a single hole

TCP's acknowledgement is **cumulative**: an ACK number `A` means "I have received every byte up to
and including `A−1`; send me `A` next." It is a single high-water mark. That one number is wonderfully
robust — it is self-describing, idempotent, and survives lost ACKs (a later ACK supersedes an earlier
one) — but it is also *lossy in the information-theoretic sense*: it cannot describe a gap.

Picture a sender that puts ten 1000-byte segments on the wire, sequence numbers `1000, 2000, …,
10000` (each segment `[start, start+1000)`). The second segment is dropped by a congested router. The
receiver gets segment 1, then segments 3 through 10. What can it say?

```text
   sent:      [1000)[2000)[3000)[4000)[5000)[6000)[7000)[8000)[9000)[10000)
   arrived:   [1000)   ✗   [3000)[4000)[5000)[6000)[7000)[8000)[9000)[10000)
                       lost
   cumulative ACK the receiver can send:  ack = 2000   (everything through 1999)
```

The receiver buffers 3–10 (Day 9's reassembler), but its **cumulative ACK is stuck at 2000** — it
cannot advance past the hole at `[2000, 3000)`, no matter how much arrives behind it. Every segment
that arrives after the hole produces *another* ACK 2000. To the sender these look like **duplicate
ACKs**, and three of them trigger a fast retransmit of segment 2 (Day 10). Good so far.

But now ask: **what happens on a retransmission timeout?** Before today, our `RetxQueue::due` resends
*every* unacknowledged segment whose timer has elapsed — and after an RTO they all have. So the
sender re-sends segment 2 (correct) **and** segments 3–10 (pure waste: the receiver already has
them, buffered). That is **go-back-N** behavior: one loss costs you a whole window of retransmission.
On a long-fat path with a 10 MB window, a single drop could cost 10 MB of redundant data and a
collapse of the congestion window.

The information the sender is missing is small and specific: *"I have 3–10; the only thing I lack is
2."* SACK is exactly the wire format for that sentence. The cumulative ACK still carries the
high-water mark; SACK adds **up to a few extra (left, right) ranges** of data received *above* the
hole. The sender combines the two — "everything below `SND.UNA` is gone, these islands are also
gone, therefore the holes are *only* what's left" — and retransmits the holes alone.

The principle to carry: **the cumulative ACK answers "how far?"; SACK answers "what else?"** Neither
replaces the other. SACK is *advisory and additive* — it never moves the cumulative point, and a
sender that ignores SACK is still correct (just slower). That careful layering is what let SACK be
deployed across the 1990s Internet without a flag day.

## 2. Two halves: SACK-Permitted (negotiate) and SACK (report)

RFC 2018 is two options that work together:

- **SACK-Permitted (kind 4)** — a 2-byte flag sent **only in the SYN / SYN-ACK**. It means "I can
  *process* SACK information." Like window scaling and timestamps (Days 16–17), it is **negotiated**:
  SACK is used on a connection only if **both** SYNs carried SACK-Permitted. If either side stays
  silent, the feature is off and we fall back to pure cumulative ACKs. This is the handshake-time
  capability exchange.

- **SACK (kind 5)** — the actual data, sent in **ACK segments after the handshake**, carrying 1–4
  blocks, each a `(left edge, right edge)` pair of 32-bit sequence numbers describing a contiguous
  run of out-of-order data the sender of *this* ACK has buffered.

Note the asymmetry of *roles*, which is the same asymmetry as flow control: a host wears **two hats**
on one connection.

- As a **data receiver**, it *generates* SACK blocks (from its reassembler) to describe the holes in
  what it's getting, and ships them on its ACKs.
- As a **data sender**, it *consumes* the SACK blocks on incoming ACKs to learn which of its
  segments landed, and prunes its retransmissions accordingly.

Our stack is mostly a data *receiver* (it's an echo/HTTP server: it receives a request, then sends a
small reply), so the generating half is the one that runs constantly in practice. But we implement
**both** halves so the mechanism is complete and the active-open (client) path works too.

## 3. The SACK-Permitted option, byte by byte

It is the simplest option in TCP: a kind and a length, no payload.

```text
   +--------+--------+
   | Kind=4 | Len=2  |
   +--------+--------+
```

The *presence* of the option is the entire message; there is nothing to carry. `Len=2` counts the
kind and length bytes themselves (as all length-prefixed options do).

Two bytes is not a multiple of four, and the TCP **data offset** counts whole 32-bit words, so the
*total* options area must be padded to a 4-byte boundary. We pad each option blob independently with
leading **NOP**s so the concatenation stays aligned — the same trick used for window scale and
timestamps:

```text
   [ NOP | NOP | Kind=4 | Len=2 ]      ← 4 bytes, self-aligned
```

In a real SYN it rides alongside the others, e.g. Linux's classic
`<mss 1460, sackOK, timestamp …, nop, wscale 7>`. The exact NOP placement varies by stack; what
matters is that the whole options field is a multiple of four and every option is parseable.

## 4. The SACK option, byte by byte

The real thing. After a 1-byte kind and 1-byte length come **N blocks**, each **8 bytes** (two
32-bit sequence numbers):

```text
   +--------+--------+--------+--------+--------+--------+--------+--------+ ...
   | Kind=5 | Len    |      Left edge of 1st block       |   Right edge …  |
   +--------+--------+--------+--------+--------+--------+--------+--------+ ...
            |        |<------------ 8 bytes per block ----------->|
            └ Len = 2 + 8·N
```

- **Kind = 5.**
- **Length = 2 + 8·N**, where N is the number of blocks (so Length ∈ {10, 18, 26, 34} for N = 1…4).
- Each block is **`(Left edge, Right edge)`**, big-endian u32s:
  - **Left edge** = the first sequence number of this contiguous received run.
  - **Right edge** = the sequence number *just past* the last byte of the run — **exclusive**, the
    same half-open `[left, right)` convention we use everywhere (it makes `right − left` the length
    and makes adjacent blocks meet exactly at a shared number).

A block `[1200, 1300)` therefore says "I have the 100 bytes 1200…1299, buffered, out of order." The
blocks describe data **strictly above** the cumulative ACK (there is no point SACKing data already
covered by the high-water mark), and they are **disjoint** (no overlaps).

Like SACK-Permitted, the option is padded with two leading NOPs to keep the field 4-byte aligned:

```text
   [ NOP | NOP | Kind=5 | Len | block₁ | block₂ | … ]
     1     1     1        1     8        8
   total = 4 + 8·N  bytes   (a multiple of 4 for every N)
```

RFC 2018 §4 says the **first** block SHOULD report the **most recently received** segment, and the
remaining blocks repeat older ones (so a single lost ACK can't erase the news). That ordering is a
SHOULD, not a MUST; our reassembler doesn't track arrival order, so we emit blocks in **ascending
sequence order** instead — correct, just slightly less robust to a lost ACK (we'll revisit this in
§15 and exercise E4).

## 5. The 40-byte budget: why at most three blocks

The TCP header length field (the data offset) is **4 bits**, counting 32-bit words. The maximum is
`15 words = 60 bytes`. The fixed header is 20 bytes, so the **options area is at most 40 bytes**.
Every option you want on a segment competes for those 40 bytes. Let's do the arithmetic that pins
down how many SACK blocks fit.

Once a connection is established with **timestamps** (Day 16), *every* segment we send carries a
Timestamps option. With its two NOP pads that is **12 bytes**:

```text
   Timestamps:  [NOP][NOP][8][10][TSval×4][TSecr×4]   = 12 bytes
```

That leaves `40 − 12 = 28` bytes for SACK. A SACK option with N blocks, padded, is `4 + 8·N` bytes:

```text
   N=1 → 12 bytes      N=2 → 20 bytes      N=3 → 28 bytes      N=4 → 36 bytes
```

So with timestamps on, the largest SACK that fits is **N = 3** (28 bytes, exactly filling the
remaining space: 12 + 28 = 40). N = 4 (36 bytes) would need 48 and overflows. Without timestamps you
could fit four (36 ≤ 40). Because timestamps are the common case and we always want SACK to coexist
with them, we cap generation at **three blocks**:

```rust
const MAX_SACK_BLOCKS: usize = 3;
```

Three blocks describe up to three separate holes simultaneously — far more than our 1 KB receive
window will ever produce. When *parsing* an incoming option we accept up to **four** (a peer without
timestamps may send four), storing them in a fixed `[(u32,u32); 4]`.

This budget is the quiet reason SACK and the timestamp option were co-designed in RFC 7323's lineage:
they were meant to share 40 bytes, and three SACK blocks + timestamps is the exact fit.

## 6. The receiver's job: generating blocks from the reassembler

Here is the lovely part: we already built the data structure that knows the answer. The Day-9
**reassembler** buffers out-of-order fragments keyed by offset in a `BTreeMap`. The set of buffered
ranges *is* the set of SACK blocks. We only need to read them out as absolute sequence ranges and
coalesce neighbors:

```rust
pub fn sack_blocks(&self) -> Vec<(u32, u32)> {
    let mut blocks: Vec<(u32, u32)> = Vec::new();
    for (&off, frag) in &self.frags {
        let left = self.base.wrapping_add(off);
        let right = left.wrapping_add(frag.len() as u32);
        match blocks.last_mut() {
            // BTreeMap yields ascending offsets, so a fragment whose left edge meets the
            // previous block's right edge extends it (the gap between them closed exactly).
            Some(last) if last.1 == left => last.1 = right,
            _ => blocks.push((left, right)),
        }
    }
    blocks
}
```

Three things to notice:

- **Offsets → absolute sequence numbers.** The reassembler stores `offset = seq − base` to keep
  ordering wrap-free (Day 9). SACK blocks are *absolute* sequence numbers, so we add `base` back.
- **Coalescing.** Two fragments that happen to be adjacent (`prev.right == next.left`) are one
  contiguous run and become **one** block. This keeps the option compact — three blocks can describe
  three *holes*, not three fragments. Without coalescing, a burst that arrives as ten adjacent
  out-of-order fragments would want ten blocks and blow the budget.
- **Ascending order**, because `BTreeMap` iterates ascending. (See §15 for the RFC's
  most-recent-first SHOULD.)

When do we attach these to an ACK? On the **data path**, whenever we send an ACK and SACK is on:

```rust
fn ack_options(&self) -> Vec<u8> {
    let mut o = Vec::new();
    if self.ts_enabled {
        o.extend_from_slice(&ts_option(self.ts_val, self.ts_recent));
    }
    if self.sack_ok {
        let blocks = self.reasm.sack_blocks();
        if !blocks.is_empty() {
            let take = blocks.len().min(MAX_SACK_BLOCKS);
            o.extend_from_slice(&sack_option(&blocks[..take]));
        }
    }
    o
}
```

If the reassembler has no buffered fragments (everything arrived in order), `sack_blocks()` is empty
and no SACK option is emitted — the ACK is a plain cumulative ACK, byte-for-byte as before. The cost
is paid only when there's actually a hole to report.

## 7. The sender's job: consuming blocks and retransmitting only holes

When *we* are the data sender and an ACK arrives carrying SACK blocks, we mark the matching segments
in our retransmission queue as **selectively acknowledged** so loss recovery skips them. Each queued
segment now remembers its byte range and a `sacked` flag:

```rust
struct Unacked {
    start_seq: u32,   // first sequence number this segment covers (its left edge)
    end_seq: u32,     // one past the last byte (covers [start_seq, end_seq))
    packet: Vec<u8>,
    sent_at_ms: u64,
    retries: u32,
    sacked: bool,     // a peer SACK block covers it → don't retransmit it
}
```

Marking is a containment test of each segment against each block:

```rust
pub fn mark_sacked(&mut self, blocks: &[(u32, u32)]) {
    for s in &mut self.segments {
        if s.sacked { continue; }
        for &(left, right) in blocks {
            let covered = !seq::before(s.start_seq, left) && !seq::after(s.end_seq, right);
            if covered { s.sacked = true; break; }
        }
    }
}
```

A segment `[start, end)` is covered by a block `[left, right)` iff `left ≤ start` **and**
`end ≤ right` — the segment sits entirely inside the SACKed range. We require **full** coverage: a
block that only partially overlaps a segment does *not* mark it (a half-received segment must still be
resent in full; we don't track sub-segment receipt).

Then the two retransmit paths skip SACKed segments:

```rust
// Retransmission timeout: resend only the holes, never SACKed data.
pub fn due(&mut self, now_ms: u64, rto_ms: u64) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for s in &mut self.segments {
        if !s.sacked && now_ms.saturating_sub(s.sent_at_ms) >= rto_ms {
            s.sent_at_ms = now_ms; s.retries += 1; out.push(s.packet.clone());
        }
    }
    out
}

// Fast retransmit: the OLDEST segment the peer has NOT selectively acked — the first hole.
pub fn fast_retransmit(&mut self, now_ms: u64) -> Option<Vec<u8>> {
    self.segments.iter_mut().find(|s| !s.sacked).map(|s| {
        s.retries += 1; s.sent_at_ms = now_ms; s.packet.clone()
    })
}
```

Before SACK, `due` re-sent the whole outstanding window after a timeout (go-back-N), and
`fast_retransmit` blindly re-sent `segments.first()`. Now both consult `sacked`: the timeout sweep
re-sends only the genuine holes, and fast retransmit picks the first hole rather than the first
segment (which SACK may show the peer already holds).

One invariant makes this safe: **the segment at `SND.UNA` is never SACKed.** SACK blocks describe
data *above* the cumulative point, so the oldest unacknowledged segment — the actual hole — is always
a retransmit candidate. There is never a deadlock where everything is SACKed but `SND.UNA` won't
advance. (If the peer *reneges* — drops data it once SACKed — a production stack must cope; see §15.)

## 8. Modular sequence math for block coverage

Sequence numbers wrap at 2³², so "≤" can't be a plain integer compare — `4_000_000_000 ≤ 5` is true
on the wrapping circle. We reuse Day 3's serial-number helpers (`src/seq.rs`, RFC 1982):

- `seq::before(a, b)` — `a` is strictly before `b` (the wrapping difference `a − b` lands in the
  upper half).
- `seq::after(a, b)` — `before(b, a)`.

The two clauses of "segment `[start, end)` ⊆ block `[left, right)`":

```text
   start ≥ left      ⟺   NOT (start < left)   ⟺   !seq::before(start, left)
   end   ≤ right     ⟺   NOT (end > right)    ⟺   !seq::after(end, right)
```

Equality is included on both sides — exactly what we want, because a segment can begin exactly at a
block's left edge or end exactly at its right edge. Working through one case to feel it: segment
`[1200, 1300)`, block `[1200, 1400)`. `!before(1200, 1200)` → `!false` → `true`. `!after(1300, 1400)`
→ `!false` → `true`. Covered. Now a partial: segment `[1200, 1300)`, block `[1200, 1250)`.
`!before(1200,1200)` → true; `!after(1300, 1250)` → `!true` → false. Not covered — correct, the
segment isn't fully inside the block.

## 9. The Rust: types, ownership, and why a fixed array

The parsed options struct gains three fields:

```rust
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct TcpOptions {
    pub mss: Option<u16>,
    pub timestamps: Option<(u32, u32)>,
    pub window_scale: Option<u8>,
    pub sack_permitted: bool,
    pub sack_blocks: [(u32, u32); 4],   // a FIXED array, not a Vec
    pub sack_block_count: usize,
}
```

Why a fixed `[(u32,u32); 4]` and a count, instead of the more natural `Vec<(u32,u32)>`? Because
`TcpOptions` **derives `Copy`**, and `Vec` is not `Copy` (it owns a heap allocation; copying it would
either be a move or need an explicit clone). Keeping `Copy` lets the struct be passed and stored by
value with zero ceremony, exactly as the MSS/timestamp/window-scale fields already are. The maximum
useful block count is four (the option-space cap), so a 4-element array is not a compromise — it is
the exact upper bound, with **no heap allocation** on the parse path. `sack_block_count` says how
many of the four slots are valid. This is the classic embedded-systems pattern: a small, statically
bounded collection becomes an array + length, not a `Vec`.

(`[(u32,u32); 4]` is `Copy` because arrays are `Copy` when their element is, and `Default` because
the standard library implements `Default` for arrays up to length 32 when the element is `Default`.
So all the derives keep working and existing `TcpOptions { ..Default::default() }` call sites are
untouched.)

Parsing adds two arms to the option walker, mirroring the others (kind, length-check, decode):

```rust
} else if kind == OPT_SACK_PERM && data.is_empty() {
    out.sack_permitted = true;                       // a bare flag, len 2, no payload
} else if kind == OPT_SACK && !data.is_empty() && data.len().is_multiple_of(8) {
    let n = (data.len() / 8).min(out.sack_blocks.len());   // up to 4
    for k in 0..n {
        let b = &data[k * 8..k * 8 + 8];
        let left  = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
        let right = u32::from_be_bytes([b[4], b[5], b[6], b[7]]);
        out.sack_blocks[k] = (left, right);
    }
    out.sack_block_count = n;
}
```

Note the **defensive length checks**, the same discipline as every parser in this project: a
SACK-Permitted option must have an empty payload (`data.is_empty()`, i.e. `Len == 2`); a SACK option
must have a *positive multiple of 8* bytes of blocks. Anything else is malformed and silently
ignored — we never index past the slice, never panic on a hostile packet. (`is_multiple_of` is the
modern, panic-free way to write `% 8 == 0`; the project switched to it for clippy on Rust 1.95.)

The two builders produce padded, self-aligned blobs:

```rust
fn sack_perm_option() -> [u8; 4] { [OPT_NOP, OPT_NOP, OPT_SACK_PERM, 2] }

fn sack_option(blocks: &[(u32, u32)]) -> Vec<u8> {
    let n = blocks.len().min(MAX_SACK_BLOCKS);
    if n == 0 { return Vec::new(); }
    let len = 2 + 8 * n;
    let mut out = Vec::with_capacity(2 + len);
    out.extend_from_slice(&[OPT_NOP, OPT_NOP, OPT_SACK, len as u8]);
    for &(left, right) in &blocks[..n] {
        out.extend_from_slice(&left.to_be_bytes());
        out.extend_from_slice(&right.to_be_bytes());
    }
    debug_assert!(out.len().is_multiple_of(4), "SACK option must be 4-byte aligned");
    out
}
```

The `debug_assert!` documents and checks the alignment invariant — `4 + 8·n` is always a multiple of
4 — so a future change that breaks it fails loudly in tests rather than silently corrupting the data
offset.

## 10. A fully worked loss-recovery trace — go-back-N vs SACK

Numbers make it concrete. A sender transmits four 100-byte segments; `SND.UNA = 1000` to start.
**Segment 2 `[1100,1200)` is lost.** Both sides negotiated SACK.

```text
   segment   range            fate
   ───────   ─────────────    ───────────────
   seg1      [1000, 1100)     arrives
   seg2      [1100, 1200)     LOST
   seg3      [1200, 1300)     arrives (out of order — gap at 1100)
   seg4      [1300, 1400)     arrives (out of order, adjacent to seg3)
```

**Receiver side**, step by step (RCV.NXT starts at 1000):

```text
   recv seg1 [1000,1100)  in order   → deliver, RCV.NXT = 1100, no buffered frags
                                        ACK 1100   (no SACK — nothing buffered)
   recv seg3 [1200,1300)  gap!        → buffer it; RCV.NXT stays 1100
                                        ACK 1100 + SACK[1200,1300)        ← a hole is now reported
   recv seg4 [1300,1400)  gap, adj.   → buffer it; coalesces with seg3
                                        ACK 1100 + SACK[1200,1400)        ← one coalesced block
```

That second and third ACK both acknowledge `1100` cumulatively (a **duplicate ACK** — no new data) but
each carries a SACK block that grows as more arrives. The third reports `[1200,1400)`: "still missing
1100…1199, but I have 1200…1399."

**Sender side**: it holds seg1–seg4 in the retx queue. ACK 1100 advances `SND.UNA` to 1100 and drops
seg1. Then come the dup ACKs with SACK:

```text
   ACK 1100, SACK[1200,1300)   → mark seg3 sacked.   dup-ack count = 1
   ACK 1100, SACK[1200,1400)   → mark seg3, seg4 sacked. dup-ack count = 2
   (a third dup ACK)           → dup-ack count = 3 → FAST RETRANSMIT
                                  fast_retransmit() = first NON-sacked = seg2 [1100,1200)
```

Only **seg2** goes back on the wire. Now compare the timeout case, the one that used to hurt:

```text
   WITHOUT SACK, on RTO:  due() resends seg2, seg3, seg4   (3 segments — 2 of them wasted)
   WITH    SACK, on RTO:  due() resends seg2 only           (seg3, seg4 are sacked → skipped)
```

That is the whole game. The receiver buffered 3–10 once; SACK ensures the sender never sends them
again. When seg2's retransmission finally arrives, the receiver's reassembler fills the hole and
delivers `1100…1399` in one contiguous run, `RCV.NXT` jumps to 1400, the cumulative ACK leaps
forward, and the queue empties.

Scale this from 4 segments to a 7000-segment window (10 MB at 1448 B/seg) and the difference is
"resend one 1.5 KB packet" versus "resend 10 MB" — and, because each spurious retransmission is also
read by the congestion controller as more loss, SACK additionally protects `cwnd` from a needless
collapse.

## 11. An annotated SACK option on the wire (hex)

The third receiver ACK above — cumulative ack 1100, one coalesced SACK block `[1200, 1400)`, with
timestamps also on — carries these option bytes (decimal 1100 = `0x44C`, 1200 = `0x4B0`,
1400 = `0x578`):

```text
   offset  bytes        meaning
   ──────  ───────────  ─────────────────────────────────────────────
   +0      01           NOP                     ┐ timestamps option
   +1      01           NOP                     │  (12 bytes; TSval/TSecr
   +2      08 0a        kind 8, len 10          │   values elided as xx)
   +4      xx xx xx xx  TSval                    │
   +8      xx xx xx xx  TSecr                   ┘
   +12     01           NOP                     ┐ SACK option
   +13     01           NOP                     │  (12 bytes for one block)
   +14     05 0a        kind 5, len 10 (=2+8)   │
   +16     00 00 04 b0  left  edge  = 1200      │  ← block [1200, 1400)
   +20     00 00 05 78  right edge  = 1400      ┘
                                                  total options = 24 bytes
                                                  data offset = (20 + 24)/4 = 11 words
```

Read it the way `tcpdump -v` would: `… nop,nop,TS val … ecr …,nop,nop,sack 1 {1200:1400}`. The
cumulative `ack 1100` lives in the fixed header (bytes 8–11 of the TCP header); the SACK block lives
in the options. Two channels, one segment.

## 12. The code, walked end to end

Everything lives in `src/tcp.rs`, plus one method in `src/reassembly.rs`. Following one connection's
life:

- **Constants** — `OPT_SACK_PERM = 4`, `OPT_SACK = 5`, `MAX_SACK_BLOCKS = 3`.
- **`parse_options`** — two new arms read SACK-Permitted (sets `sack_permitted`) and SACK blocks
  (fills `sack_blocks[..sack_block_count]`), both with strict length checks.
- **Builders** — `sack_perm_option()` and `sack_option(&blocks)` emit padded, aligned blobs.
- **`Connection.sack_ok`** — the negotiated flag.
- **Active open (`connect`)** — the SYN always offers `sack_perm_option()`; `sack_ok` starts `false`.
- **Passive open (`accept`)** — `sack_ok = opts.sack_permitted` (the peer's SYN), and the SYN-ACK
  echoes `sack_perm_option()` only when `sack_ok`.
- **`on_segment`, SYN_SENT** — adopting the SYN-ACK: `if opts.sack_permitted { self.sack_ok = true }`.
- **`on_segment`, ESTABLISHED, ACK handling** — *first thing* inside the `ACK` branch:
  `if self.sack_ok && opts.sack_block_count > 0 { self.retx.mark_sacked(…) }`. It runs before the
  cumulative-ack and dup-ack logic so the subsequent fast retransmit already sees fresh `sacked`
  flags.
- **`on_segment`, ESTABLISHED, data path** — the ACK we send is now built from `ack_options()`
  (timestamps + SACK) via `segment_opts`, instead of the plain `segment()`. When there are no
  buffered frags, `ack_options()` is empty and the ACK is identical to before.
- **`Reassembler::sack_blocks()`** — turns buffered fragments into coalesced absolute ranges.
- **`RetxQueue`** — `Unacked` gains `start_seq` and `sacked`; `record` takes `start_seq`;
  `mark_sacked` sets the flag; `due` and `fast_retransmit` skip SACKed segments.

`src/main.rs` needs **no logic change** — it already parses options off the wire and passes them to
`on_segment`, which now does the SACK work; only the day-banner comment is updated.

The dependency story stays clean and upward: `reassembly` gained a pure read-only method;
`seq`'s comparators are reused for coverage; `tcp` wires it together. No new module, no new
dependency, no cycle.

## 13. Verification — the tests, and why each exists

`cargo test` now runs **101** tests (88 before + 13 new), all offline, no TUN/sudo. The SACK
additions, and the question each answers:

In `src/tcp.rs`:

- `parse_options_reads_sack_permitted` — *Do we recognize the SYN flag, even bundled with MSS?*
- `parse_options_reads_sack_blocks` — *Do we decode N blocks with correct edges, and reject a
  non-multiple-of-8 length?*
- `syn_offers_sack_permitted` — *Does our active-open SYN advertise SACK?*
- `synack_offers_sack_when_peer_permits` / `synack_omits_sack_when_peer_silent` — *Is the SYN-ACK
  echo conditional on the peer, and is `sack_ok` set to match?* (The negotiation contract.)
- `active_open_enables_sack_from_synack` — *Does the client turn SACK on only after the SYN-ACK
  confirms?*
- `out_of_order_data_acks_with_a_sack_block` — the headline: *out-of-order data produces a dup ACK
  whose cumulative number is unmoved and which carries the exact SACK block `[104,106)`.*
- `no_sack_block_when_data_is_in_order` — *In-order data advances the cumulative ACK and emits no
  SACK option* (we pay nothing when there's no hole).
- `sack_marks_segment_so_retransmit_skips_it` — the sender core: *a SACK block marks the middle
  segment; fast retransmit returns the first hole, and an RTO sweep resends only the holes.*
- `partial_sack_block_does_not_mark_a_segment` — *partial coverage must not mark* (full-containment
  rule).

In `src/reassembly.rs`:

- `sack_blocks_empty_when_in_order` — *no buffered data → no blocks.*
- `sack_blocks_reports_disjoint_buffered_ranges` — *two holes → two ascending blocks, right edge
  exclusive.*
- `sack_blocks_coalesces_adjacent_fragments` — *two abutting fragments → one block* (the budget
  saver).

Every pre-existing test still passes unchanged, which is itself a result: connections that *don't*
negotiate SACK (the default in most tests) take byte-identical paths, because `ack_options()` returns
empty and `mark_sacked` is never called.

Live, with your hands: run the stack, then induce reordering and loss with
`sudo tc qdisc add dev tun0 root netem delay 50ms reorder 25% 50% loss 5%` and drive a bulk transfer
(`head -c 200000 /dev/urandom | nc 192.168.0.2 8080`). With `sudo tcpdump -i tun0 -n -v` you'll see
our ACKs sprout `sack 1 {…}` / `sack 2 {…}` blocks as holes open, and watch them vanish as the
holes fill. Remove the qdisc with `sudo tc qdisc del dev tun0 root`.

## 14. Why this, not that

| Decision | Alternative | Why |
|---|---|---|
| Generate blocks straight from the reassembler | Keep a second "SACK scoreboard" structure | The reassembler already *is* the set of received-out-of-order ranges; a second copy could drift. One source of truth. |
| Cap generation at 3 blocks | Emit 4 | 3 always coexists with timestamps inside 40 bytes (§5); 4 doesn't. We still *parse* 4. |
| Coalesce adjacent fragments into one block | One block per fragment | Three *holes* are worth describing; three *fragments* waste the budget when data arrives piecewise. |
| Emit blocks ascending | Most-recent-first (RFC 2018 §4 SHOULD) | Our reassembler doesn't track arrival order; ascending is correct, just slightly less robust to a lost ACK. (Exercise E4.) |
| Mark a segment SACKed only on *full* coverage | Track partial / sub-segment receipt | We retransmit whole segments; partial bookkeeping adds complexity for no gain at our segment sizes. |
| Keep SACK state across RTOs | Clear it on every timeout | Clearing would re-send data the peer holds — the very waste we're removing. (Reneging is handled differently; §15.) |
| Pragmatic "skip SACKed, resend holes" | Full RFC 6675 pipe/scoreboard | 6675's `pipe`/`IsLost` estimator is the production algorithm; ours captures the *correctness* win (no redundant sends) without the rate-control machinery. (§C.) |
| Fixed `[(u32,u32);4]` in `TcpOptions` | `Vec<(u32,u32)>` | Keeps `TcpOptions: Copy`, zero heap on the parse path; 4 is the hard upper bound anyway. |

## 15. Honesty: what production does that we don't

- **Reneging.** A receiver is *allowed* to drop data it previously SACKed (e.g. under memory
  pressure) — the SACK is advisory, only the cumulative ACK is binding. A real sender therefore keeps
  SACK state but, on a retransmission timeout, **clears the scoreboard** and falls back to the
  cumulative point (RFC 6675 §5.1), so reneged data is re-sent. We keep our `sacked` marks across
  RTOs (simpler, and our peer — the Linux kernel — never reneges in practice). Exercise E5.
- **D-SACK (RFC 2883).** SACK can also report a block *below* the cumulative ACK to say "I received a
  **duplicate**" — telling the sender a retransmission was spurious (the original wasn't lost, just
  late), so it can undo a needless `cwnd` reduction. We neither generate nor interpret D-SACK. §B.
- **RFC 6675 loss recovery.** The modern algorithm uses the scoreboard to compute `pipe` (bytes
  actually in flight) and an `IsLost()` heuristic (a segment is "lost" once 3 higher segments are
  SACKed), retransmitting holes *while keeping the pipe full*. Our fast retransmit sends one hole per
  dup-ACK episode and leans on the RTO for the rest. §C.
- **Most-recent-first ordering.** We emit ascending (§14).
- **Send-side segmentation of retransmits.** We resend each original segment verbatim; a real stack
  may *repacketize* (merge/split) on retransmission. Out of scope.
- **Window-scaled large scoreboards.** With a 10 MB window there can be far more than three holes; a
  real scoreboard tracks them all and the three-block option is just the *most useful* subset to
  report each ACK. Our 1 KB window never gets there.

None of these are correctness bugs for our peer set — they are the difference between "a faithful,
testable SACK" and "the Linux TCP stack."

## 16. Rebuild it yourself — checklist + exercises

**Blank-file checklist** (write these from memory, then check against the chapter):

- [ ] Why can't a cumulative ACK describe a hole? What does the sender do wrong on RTO without SACK?
- [ ] Draw the SACK-Permitted and SACK option bytes. What is `Len` for N blocks? Why right-exclusive?
- [ ] Do the 40-byte arithmetic: why 3 blocks with timestamps, 4 without?
- [ ] Where do the blocks we *send* come from? Why coalesce? Why add `base` back?
- [ ] How does a received block mark a segment? Write the two modular comparisons.
- [ ] Why is the segment at `SND.UNA` never SACKed — and why does that prevent deadlock?
- [ ] Why a fixed array, not a `Vec`, in `TcpOptions`?

**Exercises:**

- **E1.** Add a unit test where the receiver buffers **two** disjoint holes and assert the ACK carries
  a 2-block SACK option in ascending order.
- **E2.** Enforce RFC 2018 §3 strictly: ignore a SACK *option* (kind 5) that arrives on a SYN, and a
  SACK-Permitted (kind 4) that arrives on a non-SYN. Add tests.
- **E3.** Implement send-side **selective fast recovery**: when fast retransmit fires, resend *all*
  current holes (the non-SACKed segments below the highest SACK), not just the first. Measure the
  recovery-time difference under `netem`.
- **E4.** Switch block emission to **most-recent-first** (RFC 2018 §4): track each fragment's arrival
  order in the reassembler and report the newest block first, then the rest ascending.
- **E5.** Handle **reneging**: on an RTO in `on_tick`, clear all `sacked` flags so the timeout sweep
  re-sends everything from `SND.UNA`. Add a test that SACKs a segment, times out, and asserts it *is*
  resent.
- **E6.** Implement **D-SACK** generation (RFC 2883): when a segment arrives that is wholly below
  `RCV.NXT` (a duplicate), report it as the first SACK block. Then interpret an incoming D-SACK on the
  sender to detect a spurious retransmit.
- **E7.** Implement the RFC 6675 `pipe` estimator and `IsLost()` and drive retransmission from them;
  compare throughput under 2 % loss against today's code.

Finish line: re-type `parse_options`'s SACK arms, `sack_blocks()`, and `mark_sacked` with the book
closed, then `cargo test`. Make Anki cards from whatever you got wrong — especially the
right-edge-exclusive convention and the 40-byte budget.

## 17. What the next day adds

With SACK, our receiver tells the truth about holes and our sender stops wasting the network on data
the peer already has — the reliability core is now genuinely efficient under loss. Natural next steps,
each a real TCP feature with its own chapter: **RFC 5961** in-window validation (rate-limited
challenge ACKs; reject off-path RST/SYN injection), a **distinct CLOSE_WAIT** with true **half-close**
(let the local app keep sending after the peer's FIN), or **NewReno/CUBIC** congestion control to
replace the RFC 5681 Reno we ship. Any of them builds directly on the machinery these eighteen days
assembled.

> Re-type the SACK negotiation, generation, and consumption with the book closed, then `cargo test`.
> Your stack now recovers from loss the way every modern TCP does: lose one, resend one.

---

# Volume II — the exhaustive reference

## A. RFC 2018 in full: every field, every rule

RFC 2018 ("TCP Selective Acknowledgment Options", October 1996) defines exactly two options and a
small set of rules. The whole specification fits on a few pages; here it is, mapped to our code.

**A.1 — SACK-Permitted Option (§2).**

```text
   +--------+--------+
   |Kind = 4|Length=2|
   +--------+--------+
```

Rules:
- MAY be sent in a SYN (and SYN-ACK) only. MUST NOT be sent on a non-SYN segment.
- Sending it means "this end can receive and process the SACK option once the connection opens."
- SACK options (kind 5) MAY be used only if **both** ends sent SACK-Permitted in their SYNs.

Our mapping: `sack_perm_option()` builds it; `parse_options` sets `sack_permitted`; `accept` /
`connect` / the SYN_SENT branch implement the both-ends rule via `sack_ok`. (We don't currently
*reject* a kind-4 on a non-SYN — exercise E2 — but we only ever *consult* `sack_permitted` during the
handshake, so a stray one is harmless.)

**A.2 — SACK Option (§3).**

```text
   +--------+--------+
   | Kind=5 | Length |
   +--------+--------+--------+--------+
   |      Left Edge of 1st Block       |
   +--------+--------+--------+--------+
   |      Right Edge of 1st Block      |
   +--------+--------+--------+--------+
   |                . . .              |
   +--------+--------+--------+--------+
   |      Left Edge of nth Block       |
   +--------+--------+--------+--------+
   |      Right Edge of nth Block      |
   +--------+--------+--------+--------+
```

Rules and definitions:
- **Left Edge of Block** — the first sequence number of this block.
- **Right Edge of Block** — the sequence number *immediately following* the last sequence number of
  this block (exclusive).
- A SACK option reports data the receiver holds that is **not contiguous** with `RCV.NXT` — i.e. data
  above one or more holes.
- The first block MUST report the most recently received segment; subsequent blocks SHOULD report
  the most recently received that are not in the first block; older blocks SHOULD be repeated for
  robustness against ACK loss.
- The receiver MUST NOT report bytes it has discarded; it MAY shrink coverage later only if it
  reneged (and reneging is discouraged).
- The number of blocks is bounded by the option space (≤ 4, fewer with timestamps).

Our mapping: `sack_option()` builds it (right-exclusive edges, `Len = 2 + 8·N`);
`Reassembler::sack_blocks()` produces the ranges; we deviate on the "most recently received first"
SHOULD (we emit ascending). The "MUST NOT report discarded bytes" rule holds automatically because we
read directly from the live reassembler.

**A.3 — Generating SACKs (receiver, §4).** When the data receiver has out-of-order data queued, it
includes a SACK option on the ACK it would send anyway. The cumulative ACK number is whatever
`RCV.NXT` is; SACK is purely additional. We do exactly this on the data path.

**A.4 — Interpreting SACKs (sender, §5).** The data sender keeps a per-segment "this range has been
SACKed" flag (the *scoreboard*) and does not retransmit SACKed ranges as long as the SACK information
is valid. On RTO, the scoreboard is discarded (to handle reneging) and the sender falls back to the
cumulative ACK. We implement the "don't retransmit SACKed ranges" part faithfully; we keep the
scoreboard across RTOs (§15, exercise E5).

## B. D-SACK (RFC 2883) — acknowledging *duplicates*

RFC 2883 extends SACK with one new convention, no new option: the **first** SACK block may report a
sequence range that is **already covered by the cumulative ACK** (i.e. below `RCV.NXT`) or that is a
duplicate of data in a later block. That signals "I received this data **again** (a duplicate)."

Why it matters: it lets the sender detect a **spurious retransmission**. Suppose the sender's RTO
fired too early, it resent a segment that wasn't actually lost (just delayed), and now the receiver
has two copies. With D-SACK the receiver says "I got `[1100,1200)` a second time"; the sender realizes
its retransmit was unnecessary, that the loss it inferred wasn't real, and can **undo** the congestion
window reduction it made (a "half-back-off" reversal). Without D-SACK, the sender wrongly believes the
network dropped a packet and needlessly slows down.

Detecting a D-SACK on receive: a first block whose right edge is `≤ RCV.NXT` (wholly below the
cumulative point) is a D-SACK for already-acknowledged data; a first block wholly inside a later
(regular) block is a D-SACK for out-of-order duplicate data.

We implement neither side (exercise E6). For a stack whose peer is a sane Linux kernel on a LAN, early
RTOs are rare, so the missed optimization is small — but on a lossy/variable path D-SACK is a real
win and is universally deployed today.

## C. RFC 6675 — the real selective-retransmission algorithm

RFC 2018 says *what* to put on the wire; **RFC 6675** ("A Conservative Loss Recovery Algorithm Based
on SACK", 2012, obsoleting RFC 3517) says *how a sender should use it* to keep transmitting at the
right rate during recovery. It is the algorithm in production TCPs (alongside its successor ideas like
RACK-TLP). The pieces:

- **The scoreboard.** Per-segment SACK state over the whole outstanding window — exactly our `sacked`
  flag, but tracked for every byte range, not just whole queued segments.
- **`HighACK` / `HighData`.** The highest cumulatively-acked and highest-sent sequence numbers.
- **`pipe`** — an estimate of the bytes *actually in flight*: walk the scoreboard from `HighACK` to
  `HighData` and count bytes that are neither SACKed nor deemed lost. This is the key quantity:
  during recovery the sender may transmit (new data or retransmissions) whenever `pipe < cwnd`,
  keeping the network exactly as full as congestion control allows — no more go-back-N bursts, no
  stalling.
- **`IsLost(seq)`** — a segment is considered lost if at least `DupThresh` (3) segments *above* it
  have been SACKed, or `DupThresh×SMSS` bytes above it are SACKed. This turns "3 dup ACKs" into a
  per-segment, SACK-aware test.
- **`NextSeg()`** — picks the next thing to send during recovery: the lowest hole that `IsLost`
  flags, else new data, else a not-yet-retransmitted hole.

Our implementation captures the **correctness** half of 6675 — never retransmit SACKed data — but not
the **rate-control** half (`pipe`-driven transmission). Concretely: we mark `sacked`, skip those on
retransmit, and resend one hole per dup-ACK episode, relying on the RTO and cumulative ACK to mop up
the rest. That is enough to demonstrate the SACK win and to interoperate; it is not enough to sustain
full throughput through heavy loss. Exercise E7 is to build `pipe`/`IsLost`/`NextSeg` on top of the
scoreboard we now have.

A one-paragraph mental model of the difference: **without 6675**, recovery is "retransmit the hole,
then wait"; **with 6675**, recovery is "retransmit the hole *and* keep sending whatever else the
congestion window permits, using the scoreboard to know precisely how much is really out there." The
second keeps a fast-far pipe full while a hole is being repaired.

## D. The option-space accounting, exhaustively

Every byte of the 40-byte options area, for the option combinations our stack actually emits:

```text
   Segment type            options present                         bytes   data offset
   ─────────────────────   ─────────────────────────────────────  ─────   ───────────
   SYN (active open)        MSS(4) WS(4) TS(12) SACK-Perm(4)         24      11 words
   SYN-ACK (all offered)    MSS(4) WS(4) TS(12) SACK-Perm(4)         24      11 words
   SYN-ACK (peer MSS only)  MSS(4)                                    4       6 words
   data / ACK, TS only      TS(12)                                   12       8 words
   dup ACK, TS + 1 block    TS(12) SACK(12)                          24      11 words
   dup ACK, TS + 2 blocks   TS(12) SACK(20)                          32      13 words
   dup ACK, TS + 3 blocks   TS(12) SACK(28)                          40      15 words ← max
   dup ACK, no TS, 4 blocks SACK(36)                                  36      14 words
```

The last full row is why `MAX_SACK_BLOCKS = 3`: with timestamps (our normal state), three blocks
fill the options area to the brim (40 bytes, the 15-word maximum data offset). One more block would
require 48 bytes and a 17-word header that the 4-bit data-offset field cannot encode. The
no-timestamps row shows the absolute ceiling of four blocks (36 ≤ 40), which is why we *parse* up to
four even though we never *emit* four.

Per-option byte breakdowns:

```text
   MSS:          [02][04][hi][lo]                                   = 4
   Window Scale: [01-NOP][03][03][shift]                            = 4
   Timestamps:   [01][01][08][0a][TSval×4][TSecr×4]                 = 12
   SACK-Perm:    [01][01][04][02]                                   = 4
   SACK (N):     [01][01][05][len][ (left×4)(right×4) × N ]         = 4 + 8N
```

## E. A complete annotated connection trace (loss + SACK recovery)

A full ESTABLISHED exchange with a mid-stream loss, both directions, our side's TCB annotated.
`C` = client (the data sender, here the peer), `U` = us (the data receiver). Client sends 5×100-byte
segments starting at seq 5000; segment 2 `[5100,5200)` is lost. SACK and timestamps negotiated.
`RCV.NXT` starts at 5000.

```text
   #  dir  seg / flags                 us: RCV.NXT  reasm buffered     we send
   ─  ───  ──────────────────────────  ───────────  ────────────────  ───────────────────────────
   1  C→U  [5000,5100) PSH,ACK         5100         —                 ACK 5100                    (in order)
   2   ✗   [5100,5200)  LOST           5100         —                 —
   3  C→U  [5200,5300) PSH,ACK         5100         {5200..5300}      ACK 5100, SACK[5200,5300)   (hole!)
   4  C→U  [5300,5400) PSH,ACK         5100         {5200..5400}      ACK 5100, SACK[5200,5400)   (coalesced)
   5  C→U  [5400,5500) PSH,ACK         5100         {5200..5500}      ACK 5100, SACK[5200,5500)   (coalesced)
   ─  ───  the client now has 3 dup ACKs with growing SACK → fast-retransmits seg2 only ────────────
   6  C→U  [5100,5200) PSH,ACK (retx)  5500         —                 ACK 5500                    (gap filled!)
```

At step 6 the retransmitted seg2 fills `[5100,5200)`; the reassembler flushes `5100…5499`
contiguously, `RCV.NXT` leaps to 5500, the buffered set empties, and our ACK jumps to the cumulative
high-water mark with **no** SACK option (nothing buffered). The client's retx queue, which had marked
seg3/seg4/seg5 `sacked` from steps 3–5, now sees `SND.UNA = 5500` and drops everything. One lost
segment, one retransmission. Contrast the pre-SACK world, where step 6's recovery (or an RTO) would
have re-sent `[5100,5500)` — four segments, three of them already safely in our buffer.

## F. Comparison to real stacks — Linux, FreeBSD, lwIP, smoltcp

```text
   stack         SACK generate   SACK consume / recovery        D-SACK   notes
   ───────────   ─────────────   ────────────────────────────   ──────   ───────────────────────────
   Linux         yes             full RFC 6675 + RACK-TLP        yes      tcp_sacktag_write_queue();
                                                                          scoreboard via skb bits
   FreeBSD       yes             RFC 6675-style scoreboard       yes      sack_filter, sackhint
   lwIP          yes (opt.)      basic, LWIP_TCP_SACK_OUT        no       embedded; off by default
   smoltcp       generate only   no send-side SACK recovery      no       Rust; receiver-side blocks
   this stack    yes (≤3 blk)    "skip SACKed, resend holes"     no       receiver-complete; sender pragmatic
```

The instructive neighbor is **smoltcp** (the Rust embedded stack): it, like us, focuses on generating
correct SACK blocks for a receiver and does not implement full send-side SACK recovery — because the
generate side is cheap and universally useful, while the consume side (6675) is where the real
complexity and the throughput payoff live. Linux is the far end: a decade of SACK refinements,
RACK-TLP time-based loss detection layered on the scoreboard, and careful handling of reneging and
attacks (§G).

## G. Security — SACK as attack surface (SACK Panic, and ours)

Options are attacker-controlled bytes, so SACK is attack surface — both the parsing and the data
structures it feeds.

- **CVE-2019-11477 / -11478 / -11479 ("SACK Panic", Linux, 2019).** A remote attacker sent a stream
  of small segments and crafted SACKs that fragmented the kernel's retransmit queue into many tiny
  `skb`s; a 16-bit field counting segments-per-`skb` could overflow (`tcp_fragment` integer
  overflow), triggering a kernel panic — a remote denial of service from a few packets. The fixes
  capped queue fragmentation and hardened the arithmetic. The lesson: SACK processing touches the
  retransmit queue, and an attacker who can steer that data structure can turn an optimization into a
  crash.
- **Our exposure.** The parse path is bounds-checked and allocation-free: a malformed length stops
  parsing (no panic, no over-read), the block count is capped at four into a fixed array (no
  unbounded growth), and `mark_sacked` is an O(segments × blocks) scan over a queue bounded by our
  tiny window. There is no integer arithmetic on attacker counts that can overflow into an allocation
  size. A hostile SACK can at worst mark our own segments `sacked` (suppressing a retransmission of
  data we sent) — and since SACK blocks must lie above `SND.UNA`, it cannot stall the cumulative
  point. Still, the honest note: a real stack must rate-limit and sanity-check SACK against what it
  actually sent, which we don't (we trust the blocks); see exercise E2 and the RFC 5961 direction.
- **General discipline.** Every option parser in this project follows the same rule — validate
  length, never index past the slice, never trust a count — which is exactly the discipline whose
  absence caused SACK Panic.

## H. Performance — what SACK buys, and what it costs

- **The win** is bandwidth and recovery time under loss. With a window of `W` segments and a single
  loss, go-back-N recovery re-sends up to `W` segments; SACK re-sends `1`. On a 10 MB
  bandwidth-delay-product path that is the difference between a ~1.5 KB retransmission and a 10 MB
  one — and, because each spurious retransmit is also read as congestion, SACK additionally avoids an
  unnecessary `cwnd` collapse. The benefit grows with the BDP, which is exactly why SACK matters most
  on the long-fat networks window scaling (Day 17) unlocked.
- **The cost** is small: a few bytes of options per ACK while a hole is open (we pay nothing when
  there's no hole), an O(buffered-fragments) scan to build blocks, and an O(segments × blocks) scan
  to mark the scoreboard. Both scans are over structures bounded by the window. There is no extra
  allocation on the generate path beyond the small option `Vec`, and none on the parse path.
- **Where real stacks spend more:** maintaining a precise per-byte scoreboard over a multi-megabyte
  window, the `pipe` walk each ACK, and repacketization of retransmissions. At our window sizes these
  are negligible.

## I. Extended FAQ — thirty questions a careful reader asks

1. **Does SACK replace the cumulative ACK?** No. The cumulative ACK still carries the high-water mark
   on every segment; SACK is purely additional information in the options.
2. **Can a SACK block be below the cumulative ACK?** Only as **D-SACK** (RFC 2883), to report a
   duplicate. A normal SACK block is always above `RCV.NXT`.
3. **Why is the right edge exclusive?** So `right − left` is the byte count and adjacent blocks meet
   at one shared number — the same `[start, end)` convention as everywhere in the stack.
4. **What if SACK blocks and the cumulative ACK disagree?** They can't, by construction: blocks
   describe data above the cumulative point. If a block were below it, that's D-SACK semantics.
5. **How many blocks can one ACK carry?** Up to 4 by option space, 3 once timestamps are present
   (§D). We emit ≤ 3, parse ≤ 4.
6. **What happens if both SYNs don't carry SACK-Permitted?** SACK is off; we send plain cumulative
   ACKs and full (go-back-N on RTO) retransmission. `sack_ok` stays false.
7. **Is SACK-Permitted ever sent after the SYN?** No — SYN/SYN-ACK only. It's a one-time capability
   exchange.
8. **Do we send SACK on every ACK?** Only when SACK is negotiated *and* the reassembler has buffered
   out-of-order data. In-order traffic emits no SACK option.
9. **Why coalesce adjacent fragments?** To describe *holes*, not fragments. Ten adjacent
   out-of-order fragments are one block, not ten — vital for the 3-block budget.
10. **Why emit ascending, not most-recent-first?** Our reassembler doesn't track arrival order; the
    RFC's ordering is a SHOULD. Ascending is correct; exercise E4 adds recency.
11. **What marks a segment SACKed?** Full containment in a block: `left ≤ start && end ≤ right`,
    modular. Partial overlap does not.
12. **Why full containment, not partial?** We retransmit whole segments; sub-segment receipt tracking
    buys nothing at our sizes.
13. **Can the segment at `SND.UNA` be SACKed?** No — blocks are above the cumulative point, so the
    oldest unacked (the hole) is always a retransmit candidate. This prevents deadlock.
14. **What does fast retransmit send now?** The first **non-SACKed** segment (the first real hole),
    not blindly the oldest.
15. **What does an RTO send now?** Only non-SACKed due segments — the holes — instead of the whole
    outstanding window.
16. **Do we clear SACK state on RTO?** No (simplification). Production clears it to handle reneging
    (§15, E5).
17. **What is reneging?** A receiver dropping data it previously SACKed. Legal but discouraged; the
    cumulative ACK remains binding.
18. **Why keep `start_seq` now?** To match SACK blocks against queued segments. Before SACK we only
    needed `end_seq` (for cumulative acking).
19. **Why a fixed array in `TcpOptions`?** To keep the struct `Copy` (no heap), with 4 as the exact
    upper bound.
20. **Does `main.rs` change?** No logic change — it already routes parsed options to `on_segment`.
21. **Does SACK help our echo server much?** The *generate* side runs constantly (we're a receiver);
    the *consume* side matters when we send (the HTTP reply, or bulk `nc` echoes) under loss.
22. **Is SACK compatible with window scaling and timestamps?** Yes — they're independent options that
    share the 40-byte area; the budget (§D) is the only interaction.
23. **What does `tcpdump` show?** `sack N {l:r,…}` on ACKs, alongside `nop`/`TS`. `tshark -O tcp`
    decodes each block.
24. **Could a peer send overlapping blocks?** A conformant one won't (blocks are disjoint). We don't
    rely on disjointness for safety — `mark_sacked` is idempotent.
25. **What if a SACK names data we never sent?** It can only mark segments we have queued; a phantom
    range matches nothing. (A hardened stack would still sanity-check; E2.)
26. **Why does `sack_option` return an empty `Vec` for zero blocks?** So the caller adds no option at
    all when there's nothing to report — the common case stays zero-overhead.
27. **What's the maximum data offset we ever emit?** 15 words (60 bytes) — TS + 3 SACK blocks, the
    field's maximum (§D).
28. **Is the `debug_assert!` in `sack_option` load-bearing?** It documents and tests the 4-byte
    alignment invariant; release builds drop it. A misalignment would corrupt the data offset.
29. **How is this tested without a network?** Unit tests construct headers/options and call
    `on_segment` / the `RetxQueue` directly, asserting emitted blocks and retransmit selection — 13
    new tests, all offline.
30. **What's the single biggest thing still missing?** RFC 6675 `pipe`-driven recovery (E7): the
    rate-control half that keeps a fast pipe full *during* loss recovery.

## J. Anki starter deck

```text
Q: What does a cumulative TCP ACK fundamentally not express?  A: a gap — data received above a hole.
Q: SACK option kind?  A: 5 (and SACK-Permitted is kind 4).
Q: SACK option length for N blocks?  A: 2 + 8N bytes.
Q: SACK block right edge — inclusive or exclusive?  A: exclusive (one past the last byte).
Q: Max SACK blocks with timestamps present?  A: 3 (40−12 = 28 ≥ 4+8·3).
Q: Where does SACK-Permitted appear?  A: SYN / SYN-ACK only.
Q: When is SACK used on a connection?  A: only if BOTH SYNs carried SACK-Permitted.
Q: Where do the SACK blocks we send come from?  A: the reassembler's buffered ranges (coalesced).
Q: Coverage test for "segment [s,e) is SACKed by [l,r)"?  A: l ≤ s AND e ≤ r (modular).
Q: After SACK, what does an RTO retransmit?  A: only non-SACKed segments (the holes).
Q: Why never re-clear SACK state every RTO?  A: it would resend data the peer already holds.
Q: When MUST a real sender clear the scoreboard?  A: to handle reneging (RFC 6675 §5.1).
Q: D-SACK (RFC 2883) reports what?  A: a received duplicate → detect a spurious retransmit.
Q: RFC 6675 `pipe` is?  A: estimated bytes actually in flight, to keep sending during recovery.
Q: Why a fixed [(u32,u32);4] not a Vec in TcpOptions?  A: to keep the struct Copy, no heap.
Q: What was "SACK Panic" (2019)?  A: crafted SACKs overflowed Linux retransmit-queue arithmetic → DoS.
```

## K. Glossary

- **SACK** — Selective Acknowledgment. TCP option (kind 5) letting a receiver report non-contiguous
  data it holds above the cumulative ACK.
- **SACK-Permitted** — TCP option (kind 4) in the SYN that negotiates SACK use.
- **SACK block** — one `(left, right)` pair; a contiguous run of received out-of-order data,
  right edge exclusive.
- **Cumulative ACK** — the classic ACK number; "I have everything below this."
- **Scoreboard** — the sender's per-range record of which outstanding data has been SACKed.
- **Hole** — a range below the highest SACKed data that has *not* been SACKed; a (presumed-lost)
  segment to retransmit.
- **Coalesce** — merge adjacent received ranges into one block.
- **Go-back-N** — retransmit everything from the lost segment onward; the pre-SACK timeout behavior.
- **Reneging** — a receiver discarding data it previously SACKed.
- **D-SACK** — Duplicate-SACK (RFC 2883); a block reporting duplicate receipt, to flag spurious
  retransmits.
- **`pipe`** — RFC 6675's estimate of bytes in flight, driving transmission during recovery.
- **`IsLost()`** — RFC 6675's per-segment loss test (≥ 3 higher segments SACKed).
- **Right-exclusive** — the `[left, right)` convention: `right` is one past the last byte.

## L. Reference tables

**L.1 — TCP option kinds this stack handles**

```text
   kind  name             length    where            our field / fn
   ────  ───────────────  ────────  ───────────────  ─────────────────────────────
   0     End of options   1         anywhere         (loop break)
   1     NOP              1         anywhere         (padding / alignment)
   2     MSS              4         SYN              mss / mss_option
   3     Window Scale     3 (+NOP)  SYN              window_scale / ws_option
   4     SACK-Permitted   2 (+2NOP) SYN              sack_permitted / sack_perm_option
   5     SACK             2+8N      ACK              sack_blocks / sack_option
   8     Timestamps       10 (+2NOP) any            timestamps / ts_option
```

**L.2 — SACK option size vs block count**

```text
   blocks N   option bytes (incl. 2 NOP)   fits with TS(12)?   data offset (SACK only)
   ────────   ─────────────────────────    ─────────────────   ───────────────────────
   1          12                            yes (24 ≤ 40)       8 words
   2          20                            yes (32 ≤ 40)       10 words
   3          28                            yes (40 = 40)       12 words
   4          36                            no  (48 > 40)       14 words
```

**L.3 — Loss recovery: before vs after SACK (single loss in a window of W segments)**

```text
   event            without SACK              with SACK
   ──────────────   ───────────────────────   ──────────────────────────
   3 dup ACKs       fast-retransmit oldest     fast-retransmit first hole
   RTO timeout      resend ALL W outstanding   resend only the holes
   redundant data   up to (W−1) segments       0 segments
   cwnd impact      collapse on each spurious  protected (no spurious sends)
```

> Re-type `sack_blocks()` (generate), `mark_sacked()` (consume), and the `due`/`fast_retransmit`
> skips with the book closed, then `cargo test`. When your stack can lose one and resend one — while
> the receiver reports its holes truthfully — you own RFC 2018.
