# Doc 9 — TCP, Part 7: Out-of-Order Reassembly

> Goal: deliver a **contiguous, in-order** byte stream even when segments arrive jumbled. Until now we
> accepted data only when `seq == RCV.NXT` and dropped everything else — so a single reordered or
> gap-leaving segment stalled the connection. This chapter adds a receive buffer that holds out-of-order
> data until the gap fills, then releases the unbroken run. It's the receive-side twin of Doc 6's
> retransmission, and it's what finally lets a real file cross a lossy, reordering link.

The network is allowed to scramble your packets, and TCP is obliged to un-scramble them. The receiver
becomes a little sorting buffer: it accepts data that arrives early, parks it, and releases bytes to the
application only as an unbroken run. The two recurring subtleties — keeping order across the sequence-wrap,
and what to *say* when you can't deliver (the duplicate ACK) — are where this chapter earns its depth, and
where SACK (Doc 18) and fast retransmit (Doc 10) both plug in.

**Contents**

Volume I — the chapter
1. The mental model: the network does not keep order
2. Two different "windows": the buffer vs the advertised window
3. The data structure — offset-keyed fragments
4. The algorithm — trim, buffer, drain
5. The sequence-wrap problem, and the offset trick
6. Duplicate ACKs — the bridge to fast retransmit
7. Worked example
8. The Rust: `BTreeMap` range queries and the offset trick
9. The code, walked end to end
10. Verification
11. Why this, not that
12. Honesty: what production does, and what later days added
13. Rebuild it yourself — checklist + exercises
14. What the next step adds

Volume II — the exhaustive reference
- A. Reassembly data-structure choices (BTreeMap, interval tree, list)
- B. The four cases of a segment vs `RCV.NXT`, exhaustively
- C. The sequence-wrap problem in full (offsets, the 2³¹ assumption, PAWS)
- D. Duplicate ACKs and fast retransmit (the 3-dupACK heuristic and reordering)
- E. Generating SACK blocks from the reassembler (the Doc 18 connection)
- F. Buffer management and the advertised window
- G. A worked multi-gap reassembly trace
- H. Comparison to real stacks — the out-of-order queue and collapse
- I. Security — buffer exhaustion and overlap attacks
- J. Performance — buffering, copies, and head-of-line blocking
- K. Extended FAQ
- L. Anki starter deck
- M. Glossary
- N. Reference tables

---

# Volume I — the chapter

## 1. The mental model: the network does not keep order

IP makes no ordering promise. Two segments can take different paths and arrive reversed; a lost segment
gets retransmitted and arrives *after* the ones that followed it; a duplicate can show up minutes late.
Yet TCP must hand the application bytes in exactly the order they were sent, exactly once. The receiver
therefore can't simply act on each segment as it lands — it must **reassemble**.

The rule is precise: bytes are *delivered* to the application (and acknowledged cumulatively) only when
they form an **unbroken run starting at `RCV.NXT`**. Anything beyond a gap is held in a buffer,
contributing nothing to `RCV.NXT`, until the missing bytes arrive and bridge it.

This is the mirror image of Doc 6. There, the *sender* kept unacknowledged data so it could resend. Here,
the *receiver* keeps early-arriving data so it can reorder. Together they make a lossy, reordering network
look like a clean pipe to the application above — the core illusion TCP sells.

## 2. Two different "windows": the buffer vs the advertised window

Don't confuse two things that both sound like "the window":

- The **advertised receive window** (`RCV.WND`, Doc 8) — a *number* we put in outgoing segments saying "I
  can accept this many more bytes." It throttles the sender.
- The **reassembly buffer** — the actual *storage* holding out-of-order bytes until they're contiguous.
  Its occupancy is what *should* drive the advertised window down.

In a full stack they're linked: `RCV.WND = buffer_capacity − buffered_bytes` (§F). We keep `RCV.WND` a
constant 1024 (Doc 8's simplification — our echo server drains instantly), so the link is loose here, but
the reassembly buffer is now real. We do enforce one consequence of the window: data that arrives more
than `MAX_AHEAD` past `RCV.NXT` is *outside any window we'd advertise* and is discarded (RFC 9293
§3.10.7.4), which also bounds how much we'll ever buffer (a hostile peer can't make us hoard unbounded
memory — §I).

## 3. The data structure — offset-keyed fragments

The reassembler (`src/reassembly.rs`) is:

```rust
pub struct Reassembler {
    base:  u32,                    // offset 0 = the peer's first DATA byte (IRS + 1)
    frags: BTreeMap<u32, Vec<u8>>, // out-of-order pieces, keyed by offset, mutually disjoint
}
```

A `BTreeMap` keyed by **offset from `base`** gives us, for free, the one operation the algorithm needs:
"the buffered fragment with the smallest offset ≥ X" (`range(x..).next()`). Each fragment is the raw bytes
of one early-arriving segment. As gaps fill, fragments are removed and handed out. Why offsets instead of
raw sequence numbers? Ordering — see §5. (Alternative structures — interval trees, sorted lists — are
weighed in §A.)

## 4. The algorithm — trim, buffer, drain

`recv(seq, data, rcv_nxt)` does three things, then returns whatever is now contiguous:

```text
   1. TRIM   — if the segment starts at or before RCV.NXT, drop the already-delivered prefix.
               If nothing new remains, it's a pure duplicate → return nothing.
   2. BUFFER — store the (trimmed) fragment at its offset. Discard data absurdly far ahead
               (> MAX_AHEAD past RCV.NXT) as out-of-window.
   3. DRAIN  — walk fragments from RCV.NXT's offset: while the next fragment starts exactly where
               we are, pop it and append; stop at the first gap. Return the concatenation.
```

The caller then advances `RCV.NXT` by *exactly the returned length* — never by the raw segment size,
because an out-of-order segment delivers zero even though it carried bytes.

The drain loop is the heart:

```rust
let mut cur = nxt_off;
while let Some((&o, _)) = self.frags.range(cur..).next() {
    if o != cur { break; }                       // a gap remains — stop
    let bytes = self.frags.remove(&o).unwrap();
    cur = cur.wrapping_add(bytes.len() as u32);
    out.extend_from_slice(&bytes);
}
```

**Simplification (honest):** we assume buffered future fragments don't *overlap each other* — true for our
sender, which emits every byte range exactly once, so a reorder is just disjoint ranges in a shuffled
order. We *do* correctly trim a fragment overlapping already-delivered bytes, and drop exact duplicates.
Arbitrary overlapping retransmissions (a sender that re-segments differently) would need byte-interval
merging — exercise E3, and the source of the classic overlap attacks (§I).

## 5. The sequence-wrap problem, and the offset trick

Why not key the `BTreeMap` by the raw 32-bit sequence number? Because sequence numbers **wrap**, and
`BTreeMap` orders by ordinary `u32` comparison. Near the wrap, sequence `0xFFFF_FFF0` is *earlier* than
`0x0000_0010` in TCP's modular sense, but `u32` ordering puts it *later* — so the map would order
fragments wrongly and the drain loop would see phantom gaps.

The fix: store **offsets from a fixed base** (`seq − base`, where `base` is the peer's first data byte).
Over a connection these offsets grow monotonically from 0, so plain integer order *is* the correct order —
no modular reasoning needed in the map. The one assumption is that a single connection moves fewer than
2³¹ bytes *while a gap is open*, so offsets never themselves wrap into ambiguity. That holds for any
realistic transfer; a production stack tracks the wrap explicitly and uses RFC 7323 timestamps (PAWS,
Doc 16) to disambiguate an ancient wrapped duplicate from current data (§C).

`base` is known the moment we reach ESTABLISHED: it's `IRS + 1` (the SYN consumed `IRS`). For a passive
open we set it in `accept`; for an active open we don't learn the peer's ISN until the SYN-ACK, so we
rebase the reassembler right there (`reasm = Reassembler::new(self.recv.nxt)` in the SYN_SENT branch).

## 6. Duplicate ACKs — the bridge to fast retransmit

When data arrives out of order, we deliver nothing — but we must not stay silent. We reply with a
**duplicate ACK**: a bare ACK re-advertising the *same* `RCV.NXT` we sent before. To the sender, repeated
identical ACKs are a signal: "I'm still missing the byte at `RCV.NXT`, but segments after it are reaching
me." Three of these in a row is TCP's **fast-retransmit** trigger — the sender resends the presumed-lost
segment immediately, without waiting for its RTO (Doc 10).

The duplicate ACK is the receiver's *only* way to say "I have a hole" with cumulative ACKs alone — it
can't say *which* later bytes it has. That limitation is exactly what **SACK** (Doc 18) fixes: the SACK
option attached to the dup ACK names the buffered ranges, so the sender knows precisely what to resend.
The reassembler's buffered fragments *are* the SACK blocks (§E) — this day builds the structure that Doc 18
reads out.

## 7. Worked example

Base = 101 (peer ISN 100, so first data byte is at seq 101 → offset 0). The peer sends "he" (101) then
"lo" (103), but they arrive reversed:

```text
   recv("lo" @ seq 103, RCV.NXT=101):
      off = 103−101 = 2,  nxt_off = 0      → 2 > 0, future → buffer frags{2:"lo"}
      drain from 0: smallest frag is at 2 ≠ 0 → gap → deliver nothing
      ⇒ return ""  → we send a DUP ACK (ack=101), RCV.NXT stays 101

   recv("he" @ seq 101, RCV.NXT=101):
      off = 0,  nxt_off = 0                → buffer frags{0:"he", 2:"lo"}
      drain from 0: frag@0 == 0 → take "he", cur=2; frag@2 == 2 → take "lo", cur=4; none@4 → stop
      ⇒ return "helo"  → RCV.NXT advances by 4 → 105, we echo "helo", ack=105
```

Exactly what `tcp::tests::reassembles_out_of_order_data` asserts. A duplicate ("abc" re-sent after it was
delivered) trims to empty and returns nothing; a partial overlap ("bcXY" when "abc" is already in) trims
the "bc" and delivers just "XY" (the four cases are enumerated in §B).

## 8. The Rust: `BTreeMap` range queries and the offset trick

- **`BTreeMap::range(cur..).next()` is the perfect primitive.** It finds the smallest key ≥ `cur` in
  `O(log n)`, which is exactly "the next buffered fragment at or after where I am." A `HashMap` couldn't
  do this (no order); a `Vec` would need a sort or scan. The data structure is chosen to make the drain
  loop trivial.
- **Offsets, not sequence numbers, as keys** — so the tree's natural `u32` ordering *is* the stream order
  (§5). This is a small, deep idea: pick a representation in which the operation you need is free.
- **Fragments own their bytes.** `BTreeMap<u32, Vec<u8>>` — each fragment owns a `Vec<u8>`. `remove(&o)`
  *moves* the `Vec` out (no copy) to append to the output; the map relinquishes ownership cleanly. The
  only copy is `extend_from_slice` into the contiguous output run.
- **`wrapping_sub`/`wrapping_add` at the boundary.** `seq − base` and advancing `cur` use wrapping
  arithmetic so the offset math is correct even if the *base*-relative offset crosses 2³² (it won't in
  practice, but the code is honest about the type).

## 9. The code, walked end to end

| Piece | Role |
|---|---|
| `src/reassembly.rs` | the `Reassembler`: `recv()` (trim/buffer/drain) + `sack_blocks()` (Doc 18) |
| `Connection.reasm` | one reassembler per connection; rebased on SYN-ACK for active open |
| `on_segment` data branch | feeds every data segment to `reasm`; ACKs delivered bytes, else dup-ACKs |

The control flow in `on_segment`'s ESTABLISHED branch: a non-empty payload goes to
`self.reasm.recv(th.seq, payload, self.recv.nxt)`. If it returns bytes, we advance `RCV.NXT` by their
length and deliver them into the receive buffer (the app reads via `take_received`, Doc 11). If it returns
empty (out-of-order or duplicate), `RCV.NXT` is untouched. Either way we send an ACK carrying the current
`RCV.NXT` — a fresh ACK for in-order data, a duplicate ACK for a hole (now also carrying SACK blocks when
negotiated, Doc 18). In-order data behaves exactly as before — the reassembler returns it immediately with
an empty buffer.

## 10. Verification

`cargo test` proves reassembly offline. Coverage:

- `reassembly::*` — in-order passthrough; out-of-order buffer then gap-fill; duplicate of delivered data;
  partial overlap trimming; multiple gaps filled in any order; far-out-of-window discard; (Doc 18) SACK
  blocks reported, coalesced, and empty when in order.
- `tcp::reassembles_out_of_order_data` — end-to-end: the second chunk arrives first and draws a duplicate
  ACK (RCV.NXT unmoved), then the first chunk flushes both and we deliver/echo the contiguous "helo" with
  `ack = 105` and a valid checksum.
- All prior data/teardown tests still pass — in-order behavior is unchanged.

Live (your hands): run the stack and induce reordering with
`sudo tc qdisc add dev tun0 root netem delay 50ms reorder 25% 50%`, then `nc` a few lines. The log shows
duplicate ACKs when a segment jumps the queue, and the echo still comes back intact and in order. Remove
it with `sudo tc qdisc del dev tun0 root`.

## 11. Why this, not that

| Decision | We chose | Real TCP |
|---|---|---|
| Buffer keying | offset from a fixed base (`BTreeMap<u32,_>`) | same idea; Linux uses an rb-tree of byte ranges |
| Overlapping fragments | assume disjoint future frags; trim vs delivered only | full byte-interval merge of arbitrary overlaps |
| Advertised window vs buffer | window constant 1024, buffer real | `RCV.WND = capacity − buffered`, dynamically |
| Out-of-window data | discard beyond `MAX_AHEAD` | discard beyond `RCV.WND`, exactly |
| SACK | doc 9: cumulative ACK + dup-ACKs only | doc 18 adds RFC 2018 blocks from this buffer |
| Outgoing segmentation | echo a run in one segment (doc 9); MSS-split Doc 11/15 | split to MSS, respecting the send window |

## 12. Honesty: what production does, and what later days added

- **SACK reads this buffer (Doc 18).** The reassembler's buffered fragments are precisely the data a SACK
  option reports; Doc 18 added `Reassembler::sack_blocks()` to coalesce them into `(left, right)` ranges
  for the ACK (§E). Doc 9 builds the structure; Doc 18 makes the receiver *tell* the sender about the
  holes.
- **No overlapping-fragment merge.** We assume future fragments are disjoint (true for our sender). A
  general receiver must merge arbitrary overlapping byte intervals — and do it *carefully*, because naive
  overlap handling is a security hole (§I).
- **Static window, not buffer-driven.** A real receiver sets `RCV.WND = capacity − buffered` so a stalled
  reassembly buffer throttles the sender (§F); ours is a flat 1024.
- **No buffer "collapse."** Under memory pressure Linux *collapses* the out-of-order queue (merges
  adjacent skbs, prunes) rather than dropping; we just bound by `MAX_AHEAD` (§H).
- **Outgoing segmentation came later.** Doc 9 echoes a delivered run as one segment; MSS-bounded
  segmentation arrives with the send buffer (Doc 11) and MSS negotiation (Doc 15).
- **The 2³¹ offset assumption.** We assume a gap never spans > 2 GB; a production stack handles the full
  wrap with timestamps/PAWS (§C).

None of these change the doc-9 contract (reordered data is delivered in order, duplicates dropped); they
are the breadth the later days add.

## 13. Rebuild it yourself — checklist + exercises

**Blank-file checklist:**

- [ ] The delivery rule: bytes flow to the app only as an unbroken run from `RCV.NXT`.
- [ ] The three steps — trim already-delivered prefix, buffer the rest, drain contiguous — and why
      `RCV.NXT` advances by the *delivered* length, not the segment length.
- [ ] Why offsets-from-base, not raw sequence numbers, key the buffer (the wrap).
- [ ] What a duplicate ACK means and why three of them matter to the sender.
- [ ] Why the reassembler's fragments are the SACK blocks (Doc 18).

**Exercises:**

- **E1.** Make `RCV.WND` dynamic: advertise `capacity − buffered_bytes` so a stalled reassembly buffer
  actually throttles the sender (ties Doc 8 to this chapter; §F).
- **E2.** ✅ *Done* (Doc 18): report the buffered byte ranges as **SACK** blocks (RFC 2018) so the sender
  retransmits only the true gaps.
- **E3.** Handle arbitrary **overlapping** fragments by merging byte intervals, then prove it with a test
  that feeds overlapping retransmissions — and think about the overlap attack (§I).
- **E4.** ✅ *Done* (Docs 11/15): segment **outgoing** data to a negotiated MSS so a large delivered run
  echoes as multiple MTU-sized segments, each queued for retransmission.
- **E5.** Implement buffer **collapse**: when buffered bytes near the cap, merge adjacent fragments and
  prune, rather than discarding new arrivals (§H).

## 14. What the next step adds

The receiver can now reorder; the sender can now retransmit (Doc 6) and respect the receiver's window
(Doc 8). The missing governor is **congestion control** (Doc 10) — limiting the sender by what the
*network* can carry: slow start, congestion avoidance (AIMD), and **fast retransmit / fast recovery**
driven by the very duplicate ACKs we started emitting here. The effective send limit becomes
`min(SND.WND, cwnd)`.

---

# Volume II — the exhaustive reference

## A. Reassembly data-structure choices (BTreeMap, interval tree, list)

The reassembler must support: insert a fragment, find the fragment at/after a given offset, remove a
fragment, and (Doc 18) iterate fragments in order. Options:

```text
   structure              insert    "next ≥ x"    in-order iter   notes
   ────────────────────   ───────   ───────────   ─────────────   ──────────────────────────
   sorted Vec<(off,bytes)>  O(n)     O(log n) bin   O(n)            simple; shifty on insert
   BTreeMap<off, bytes>     O(log n) O(log n) range  O(n)            our choice — clean, ordered
   interval tree            O(log n) O(log n)       O(n)            needed for overlap merging
   linked list of segs      O(n)     O(n)            O(n)            cache-unfriendly; classic BSD
   rb-tree of byte ranges   O(log n) O(log n)       O(n)            Linux tcp_ooo (with collapse)
```

`BTreeMap` is the sweet spot for a disjoint-fragment model: ordered, log-time range queries, and Rust's
`range(x..).next()` expresses "next fragment at or after x" directly. If we needed arbitrary overlap
merging (§I), an interval tree keyed by byte ranges would be the right upgrade. Linux uses a red-black
tree of out-of-order ranges with a "collapse" pass under memory pressure (§H).

## B. The four cases of a segment vs `RCV.NXT`, exhaustively

Every arriving data segment `[seq, seq+len)` falls into one of four cases relative to `RCV.NXT`:

```text
   case            condition                          action
   ─────────────   ────────────────────────────────   ──────────────────────────────────────
   1 in-order      seq == RCV.NXT                      deliver (+ drain any buffered that now connect)
   2 future (gap)  seq >  RCV.NXT                      buffer; deliver nothing; dup-ACK
   3 duplicate     seq+len ≤ RCV.NXT                   drop entirely (all bytes already delivered)
   4 partial overlap seq < RCV.NXT < seq+len           trim the delivered prefix; deliver the new tail
```

Our `recv` handles all four: the TRIM step covers 3 and 4 (skip `RCV.NXT − seq` bytes; if that's ≥ the
segment, it's a pure duplicate → nothing), the BUFFER + DRAIN steps cover 1 and 2. Case 4 is the subtle
one — a retransmission that overlaps what we already have, where we keep only the genuinely new bytes
(`trims_partial_overlap_with_delivered`). The one case we *don't* fully handle is overlap between two
*buffered future* fragments (§I, E3), which our sender never produces.

## C. The sequence-wrap problem in full (offsets, the 2³¹ assumption, PAWS)

TCP sequence numbers are 32-bit and wrap. "Order" on the wire is RFC 1982 modular order, not integer
order. A naive `BTreeMap<seq, _>` breaks near the wrap: it would sort `0xFFFF_FFF0` *after*
`0x0000_0010`, inverting two fragments that are actually adjacent across the seam, and the drain loop
would never connect them.

The **offset trick** sidesteps this: subtract a fixed `base` so keys are `0, 1, 2, …` growing
monotonically; integer order then equals stream order. The assumption it buys: within the lifetime of an
open gap, the stream advances < 2³¹ bytes, so two live offsets are never ≥ 2³¹ apart (which would make
their *offset* comparison ambiguous too). For any real transfer a gap closes in milliseconds, long before
2 GB flows, so this is safe.

The remaining hazard a production stack must handle is an **old wrapped duplicate**: on a very fast,
long-lived connection the *sequence space itself* wraps (4 GB), and an ancient delayed segment could carry
a sequence number that lands in the current window — looking valid. **PAWS** (Protect Against Wrapped
Sequences, RFC 7323 §5, Doc 16) defends with timestamps: every segment carries a timestamp, and one whose
timestamp predates the most recent (`TS.Recent`) is rejected as a stale duplicate regardless of its
sequence number. Reassembly correctness on the open internet ultimately rests on timestamps; our offset
trick is the LAN-correct version.

## D. Duplicate ACKs and fast retransmit (the 3-dupACK heuristic and reordering)

A **duplicate ACK** is an ACK that acknowledges no new data (same `ack` as before, no payload, window
unchanged). It is generated whenever the receiver gets a segment it can't deliver in order — i.e., a
future segment past a gap. So a *burst* of dup-ACKs means "segments are arriving, but the one at `RCV.NXT`
is missing."

**Why three?** Because a *single* reordering (segment N and N+1 swapped) produces *one* dup-ACK that is
**not** a loss — the missing segment is right behind. Two could still be mild reordering. The designers
chose **three** dup-ACKs (`DupThresh = 3`) as the threshold that strongly implies loss rather than
reordering, balancing fast recovery against false positives. The sender then **fast-retransmits** the
segment at `RCV.NXT` immediately (Doc 10), recovering in ~1 RTT instead of ~1 RTO.

The heuristic's weakness is exactly reordering: a path that reorders by 3+ positions triggers spurious
fast retransmits. Modern stacks add **RACK** (time-based loss detection, RFC 8985) and **D-SACK** (Doc 18
§B) to detect and undo these. Doc 9 *generates* the dup-ACKs; Doc 10 *acts* on them; Doc 18's SACK makes
them precise.

## E. Generating SACK blocks from the reassembler (the Doc 18 connection)

The reassembler's `frags` are, by construction, the set of received-out-of-order byte ranges — which is
*exactly* what a SACK option reports. Doc 18 added:

```rust
pub fn sack_blocks(&self) -> Vec<(u32, u32)> {
    let mut blocks = Vec::new();
    for (&off, frag) in &self.frags {
        let left = self.base.wrapping_add(off);
        let right = left.wrapping_add(frag.len() as u32);
        match blocks.last_mut() {
            Some(last) if last.1 == left => last.1 = right,  // coalesce adjacent
            _ => blocks.push((left, right)),
        }
    }
    blocks
}
```

Two doc-9 design choices pay off here: the **`BTreeMap` order** means the blocks come out ascending for
free, and **disjoint fragments** mean each is a clean range (only *adjacent* ones need coalescing). The
single most valuable thing about building a real reassembly buffer at doc 9 — rather than the doc-4 "drop
out-of-order" hack — is that it becomes the source of truth SACK reads from. This is why the curriculum
puts reassembly (Doc 9) before SACK (Doc 18): you can't *report* holes you don't *track*.

## F. Buffer management and the advertised window

In a full stack the reassembly buffer and the advertised window are two ends of one resource:

```text
   RCV.WND = receive_buffer_capacity − bytes_currently_buffered
```

When out-of-order data piles up (a persistent gap), `bytes_currently_buffered` rises, so `RCV.WND` falls,
so the *sender slows down* — flow control automatically backs off a sender whose data the receiver can't
yet deliver. When the gap fills and the buffer drains to the app, `RCV.WND` reopens. This coupling is why
flow control (Doc 8) and reassembly (Doc 9) are really one system: the buffer is the physical thing; the
window is its advertised free space.

We decouple them (flat 1024 window, real buffer bounded by `MAX_AHEAD`) because our echo server drains
instantly, so the buffer is almost always empty. A bulk receiver *must* couple them, or it either drops
data (window too big for the buffer) or stalls throughput (window too small). Exercise E1 makes the
coupling real; §C of doc 8 covers the silly-window pitfall of doing it carelessly.

## G. A worked multi-gap reassembly trace

Base 1000. Three gaps fill in a scrambled order (`multiple_gaps_fill_in_any_order`):

```text
   recv "gh" @1006 (off 6), RCV.NXT=1000:  buffer {6:"gh"}            drain@0: gap → ""   (dup-ACK)
   recv "def"@1003 (off 3), RCV.NXT=1000:  buffer {3:"def", 6:"gh"}   drain@0: gap → ""   (dup-ACK)
   recv "abc"@1000 (off 0), RCV.NXT=1000:  buffer {0:"abc",3:"def",6:"gh"}
       drain@0: 0=="abc"(cur→3), 3=="def"(cur→6), 6=="gh"(cur→8), none@8 → "abcdefgh"
       ⇒ RCV.NXT 1000→1008, deliver 8 bytes, buffer now empty
```

The head fragment (`abc`) is the keystone: until it arrives, the two later fragments sit buffered
contributing nothing to `RCV.NXT` (and drawing dup-ACKs); the instant the head arrives, the whole chain
connects and flushes in one delivery. This is *head-of-line blocking* in miniature (§J) — and exactly why
a single lost segment can stall a whole window's worth of received data from reaching the app.

## H. Comparison to real stacks — the out-of-order queue and collapse

```text
   aspect             Linux                                    this stack
   ────────────────   ──────────────────────────────────────  ────────────────────────
   OoO structure      rb-tree of out-of-order skbs (ranges)    BTreeMap<offset, Vec<u8>>
   overlap handling   trims/merges arbitrary overlaps          disjoint-only (+ trim vs delivered)
   memory pressure    "collapse": merge adjacent, then prune   bound by MAX_AHEAD, discard far data
   window coupling    RCV.WND = free buffer (autotuned)        flat 1024
   SACK generation    from the OoO tree                        from frags (Doc 18)
   delivery           wake reader when in-order prefix grows   recv_buf + take_received
```

Linux's **collapse** is the interesting bit: rather than dropping out-of-order data when memory is tight,
it *collapses* the queue — merging adjacent skbs into fewer, larger ones to cut per-skb overhead, and only
pruning (dropping) as a last resort. This preserves received data (avoiding retransmission) while bounding
memory. We take the simpler path: a hard `MAX_AHEAD` ceiling beyond which new far-ahead data is discarded.
Both bound memory; collapse is gentler on goodput.

## I. Security — buffer exhaustion and overlap attacks

- **Reassembly buffer exhaustion.** Out-of-order data must be held *somewhere*. An attacker who sends lots
  of *future* segments (each past a gap they never fill) can make a naive receiver buffer unbounded memory
  per connection — and open many connections — for a DoS. Our `MAX_AHEAD` ceiling caps per-connection
  buffering (we discard data too far ahead), which is the essential defense; a real stack also bounds
  total OoO memory and collapses/prunes (§H).
- **Overlapping-fragment attacks (the IP-fragment lineage: Teardrop, Bonk, overlap).** When a reassembler
  accepts *overlapping* pieces and must choose which bytes win, attackers craft overlaps so that an IDS
  and the endpoint reassemble *different* byte streams — smuggling content past inspection (IDS evasion,
  Ptacek & Newsham 1998), or triggering reassembly bugs (the original Teardrop crashed kernels via
  malformed IP-fragment overlaps). TCP has the same hazard at the segment layer. Our **disjoint-only**
  assumption sidesteps the *choice* (we never merge overlapping future fragments), but a general
  overlap-merging reassembler (E3) must define a deterministic, spec-compliant policy (favor first-received,
  or favor lowest sequence) and match what middleboxes expect — getting it wrong is an evasion vector.
- **Low-rate / gap-holding.** Holding a gap open (never sending the missing segment) keeps a connection's
  buffer occupied and its window depressed; bounded buffers and connection timeouts defend.

The theme: reassembly is *attacker-controlled buffering plus an ordering decision*, so a hardened
reassembler bounds the memory and makes the overlap policy explicit and inspection-consistent.

## J. Performance — buffering, copies, and head-of-line blocking

- **Head-of-line blocking (HOLB).** The §G keystone effect: bytes that have *arrived* can't be delivered
  until an *earlier* lost segment is retransmitted and fills the hole. The application waits on data the
  receiver already has — a fundamental cost of an in-order byte stream over a lossy network. This is the
  single biggest motivation for **QUIC** (and HTTP/3): QUIC multiplexes independent streams over one
  connection so a loss on stream A doesn't block stream B — per-stream reassembly instead of
  per-connection. TCP can't do that; its one byte stream means one HOLB queue.
- **Copy cost.** We copy each fragment into a `Vec` on buffer, and `extend_from_slice` into the output run
  on drain. Real stacks keep packet buffers (skbs) and reference byte ranges to avoid copies until the app
  reads.
- **Buffering memory.** Out-of-order data is dead weight until its gap fills — held memory that does no
  work. The window-coupling (§F) ensures a sender can't make the receiver hold more than its buffer;
  collapse (§H) keeps the held memory compact.
- **Our cost** is `O(log n)` per fragment insert/lookup (`n` = buffered fragments, tiny on a real path)
  and `O(delivered)` to drain. At our scale negligible; the conceptual cost (HOLB) is inherent to TCP, not
  our implementation.

## K. Extended FAQ

1. **Why must TCP reassemble?** IP doesn't preserve order; TCP promises an in-order stream.
2. **When are bytes delivered to the app?** Only as an unbroken run from `RCV.NXT`.
3. **By how much does `RCV.NXT` advance per segment?** By the *delivered* (contiguous) length, not the
   segment length.
4. **Why a `BTreeMap`?** Ordered, log-time "next fragment ≥ x" — exactly the drain query.
5. **Why key by offset, not sequence number?** Sequence numbers wrap; offsets give correct integer order
   (§5/§C).
6. **What is `base`?** The peer's first data byte, `IRS + 1`; offset 0.
7. **When is the reassembler rebased?** On active open, when the SYN-ACK reveals the peer's ISN.
8. **What are the four segment cases?** In-order, future (gap), duplicate, partial overlap (§B).
9. **What does TRIM do?** Drops the already-delivered prefix of an overlapping/duplicate segment.
10. **What does a duplicate ACK signal?** "I'm missing `RCV.NXT`, but later segments are arriving."
11. **Why three dup-ACKs for fast retransmit?** One/two can be benign reordering; three implies loss
    (§D).
12. **What discards far-ahead data?** The `MAX_AHEAD` ceiling — out-of-window per RFC 9293 §3.10.7.4.
13. **What's the disjoint-fragment assumption?** Future fragments don't overlap each other (true for our
    sender).
14. **How would overlapping fragments be handled?** Byte-interval merging (E3) — carefully, it's an
    evasion vector (§I).
15. **How do the fragments become SACK blocks?** `sack_blocks()` reads them as ascending coalesced ranges
    (Doc 18, §E).
16. **Why build a real buffer if SACK is far off?** Because SACK *needs* a buffer to report from; you
    can't report holes you don't track.
17. **What couples the buffer to `RCV.WND`?** `RCV.WND = capacity − buffered` (§F) — ours is decoupled
    (flat 1024).
18. **What is buffer collapse?** Merging/pruning the OoO queue under memory pressure (Linux; §H).
19. **What is head-of-line blocking?** Arrived bytes blocked by an earlier missing segment (§J).
20. **What protocol fixes HOLB?** QUIC/HTTP-3 with independent streams (§J).
21. **Does in-order data hit the buffer?** It passes straight through (drain returns it immediately, empty
    buffer).
22. **What is the 2³¹ assumption?** A gap never spans > 2 GB, so offsets stay unambiguous (§C).
23. **What handles a wrapped ancient duplicate?** PAWS/timestamps (Doc 16), not the offset trick.
24. **Can a buffer-exhaustion attack hurt us?** Bounded by `MAX_AHEAD` per connection (§I).
25. **What's the receive-side twin of retransmission?** Reassembly — sender keeps to resend, receiver
    keeps to reorder.

## L. Anki starter deck

```text
Q: When does TCP deliver received bytes to the app?  A: only as an unbroken run from RCV.NXT.
Q: By how much does RCV.NXT advance per segment?  A: by the contiguous delivered length, not the seg size.
Q: Why key the reassembly map by offset, not sequence number?  A: seq numbers wrap; offsets give integer order.
Q: What is the reassembler's base?  A: the peer's first data byte (IRS+1), offset 0.
Q: Four cases of a segment vs RCV.NXT?  A: in-order, future(gap), duplicate, partial overlap.
Q: What does a duplicate ACK signal?  A: "missing RCV.NXT, but later segments are arriving."
Q: Why three dup-ACKs for fast retransmit?  A: one/two can be reordering; three implies loss.
Q: What bounds how much we buffer?  A: MAX_AHEAD (out-of-window data discarded).
Q: Disjoint-fragment assumption?  A: future fragments don't overlap each other (true for our sender).
Q: How do reassembler fragments become SACK blocks?  A: ascending coalesced (left,right) ranges (Doc 18).
Q: Why build the buffer before SACK?  A: you can't report holes you don't track.
Q: What is head-of-line blocking?  A: arrived bytes blocked by an earlier missing segment.
Q: What protocol removes HOLB?  A: QUIC/HTTP-3 (independent per-stream reassembly).
Q: PAWS defends what here?  A: an ancient wrapped duplicate landing in the current window (Doc 16).
Q: Receive-side twin of Doc 6 retransmission?  A: reassembly (keep early data to reorder).
```

## M. Glossary

- **Reassembly** — buffering out-of-order segments and delivering bytes contiguously from `RCV.NXT`.
- **Fragment** — one buffered out-of-order segment's bytes (here keyed by offset).
- **`base` / offset** — the peer's first data byte; `offset = seq − base`, giving wrap-free ordering.
- **Trim / buffer / drain** — the three steps of `recv`.
- **Duplicate ACK** — an ACK acknowledging no new data; signals a hole; 3 → fast retransmit.
- **`MAX_AHEAD`** — the cap on how far past `RCV.NXT` we buffer (out-of-window).
- **SACK block** — a `(left, right)` range of buffered out-of-order data (Doc 18), read from the
  reassembler.
- **Collapse** — merging/pruning the out-of-order queue under memory pressure (real stacks).
- **Head-of-line blocking (HOLB)** — arrived data delayed by an earlier missing segment.
- **PAWS** — timestamp-based defense against wrapped-sequence duplicates (Doc 16).

## N. Reference tables

**N.1 — The three steps of `recv`**

```text
   step     condition                         action
   ──────   ───────────────────────────────   ───────────────────────────────────
   TRIM     seq ≤ RCV.NXT                      drop delivered prefix; pure dup → return ""
   BUFFER   off − nxt_off ≤ MAX_AHEAD          insert frag at offset; else discard (out-of-window)
   DRAIN    frag at cur == cur                 pop & append; stop at first gap; return run
```

**N.2 — Segment classification**

```text
   case              test                         delivers   RCV.NXT
   ───────────────   ──────────────────────────   ────────   ─────────
   in-order          seq == RCV.NXT               its bytes  advances
   future / gap      seq > RCV.NXT                nothing    unchanged (dup-ACK)
   duplicate         seq+len ≤ RCV.NXT            nothing    unchanged
   partial overlap   seq < RCV.NXT < seq+len      the tail   advances by the tail
```

**N.3 — Receive-side vs send-side reliability**

```text
   side       keeps                       so it can           day
   ────────   ─────────────────────────   ─────────────────   ───
   sender     unacked data (retx queue)   retransmit          6
   receiver   out-of-order data (reasm)   reorder/deliver     9
   both       → a lossy/reordering net looks like a clean pipe
```

> Re-type the `Reassembler` from this chapter with the book closed, then `cargo test`. You now hold both
> halves of reliable, ordered delivery: retransmission on the send side (Doc 6) and reassembly on the
> receive side (Doc 9) — and you've built the buffer that SACK (Doc 18) will one day read its truth from.
