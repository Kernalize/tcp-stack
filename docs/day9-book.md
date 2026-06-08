# Day 9 — TCP, Part 7: Out-of-Order Reassembly

> Goal: deliver a **contiguous, in-order** byte stream even when segments arrive jumbled. Until
> now we accepted data only when `seq == RCV.NXT` and dropped everything else — so a single
> reordered or gap-leaving segment stalled the connection. This chapter adds a receive buffer that
> holds out-of-order data until the gap fills, then releases the unbroken run. It's the receive-side
> twin of Day 6's retransmission, and it's what finally lets a real file cross a lossy link.

**Contents**
1. The mental model: the network does not keep order
2. Two different "windows": the buffer vs the advertised window
3. The data structure — offset-keyed fragments
4. The algorithm — trim, buffer, drain
5. The sequence-wrap problem, and the offset trick
6. Duplicate ACKs — the bridge to fast retransmit
7. Worked example
8. The code, walked
9. Verification
10. Why this, not that
11. Rebuild it yourself — checklist + exercises
12. What's next

---

## 1. The mental model: the network does not keep order

IP makes no ordering promise. Two segments can take different paths and arrive reversed; a lost
segment gets retransmitted and arrives *after* the ones that followed it. Yet TCP must hand the
application bytes in exactly the order they were sent. The receiver therefore can't simply act on
each segment as it lands — it must **reassemble**.

The rule is precise: bytes are *delivered* to the application (and, here, echoed and acknowledged)
only when they form an unbroken run starting at `RCV.NXT`. Anything beyond a gap is held in a
buffer, contributing nothing to `RCV.NXT`, until the missing bytes arrive and bridge it.

This is the mirror image of Day 6. There, the *sender* kept unacknowledged data so it could
resend. Here, the *receiver* keeps early-arriving data so it can reorder. Together they make a
lossy, reordering network look like a clean pipe.

---

## 2. Two different "windows": the buffer vs the advertised window

Don't confuse two things that both sound like "the window":

- The **advertised receive window** (`RCV.WND`, Day 8) — a *number* we put in outgoing segments
  saying "I can accept this many more bytes." It throttles the sender.
- The **reassembly buffer** — the actual *storage* holding out-of-order bytes until they're
  contiguous. Its occupancy is what *should* drive the advertised window down.

In a full stack they're linked: `RCV.WND = buffer_capacity − buffered_bytes`. We keep `RCV.WND` a
constant 1024 (Day 8's simplification — our echo server drains instantly), so the link is loose
here, but the reassembly buffer is now real. We do enforce one consequence of the window: data
that arrives more than `MAX_AHEAD` past `RCV.NXT` is *outside any window we'd advertise* and is
discarded (RFC 9293 §3.10.7.4), which also bounds how much we'll ever buffer.

---

## 3. The data structure — offset-keyed fragments

The reassembler (`src/reassembly.rs`) is:

```rust
pub struct Reassembler {
    base:  u32,                    // offset 0 = the peer's first DATA byte (IRS + 1)
    frags: BTreeMap<u32, Vec<u8>>, // out-of-order pieces, keyed by offset, mutually disjoint
}
```

A `BTreeMap` keyed by **offset from `base`** gives us, for free, the one operation the algorithm
needs: "the buffered fragment with the smallest offset ≥ X" (`range(x..).next()`). Each fragment
is the raw bytes of one early-arriving segment. As gaps fill, fragments are removed and handed out.

Why offsets instead of raw sequence numbers? Ordering — see §5.

---

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

The caller then advances `RCV.NXT` by *exactly the returned length* — never by the raw segment
size, because an out-of-order segment delivers zero even though it carried bytes.

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

**Simplification (honest):** we assume buffered future fragments don't *overlap each other* — true
for our sender, which emits every byte range exactly once, so a reorder is just disjoint ranges in
a shuffled order. We *do* correctly trim a fragment overlapping already-delivered bytes, and drop
exact duplicates. Arbitrary overlapping retransmissions (a sender that re-segments differently)
would need byte-interval merging — exercise E3.

---

## 5. The sequence-wrap problem, and the offset trick

Why not key the `BTreeMap` by the raw 32-bit sequence number? Because sequence numbers **wrap**,
and `BTreeMap` orders by ordinary `u32` comparison. Near the wrap, sequence `0xFFFF_FFF0` is
*earlier* than `0x0000_0010` in TCP's modular sense, but `u32` ordering puts it *later* — so the
map would order fragments wrongly and the drain loop would see phantom gaps.

The fix: store **offsets from a fixed base** (`seq − base`, where `base` is the peer's first data
byte). Over a connection these offsets grow monotonically from 0, so plain integer order *is* the
correct order — no modular reasoning needed in the map. The one assumption is that a single
connection moves fewer than 2³¹ bytes, so offsets never themselves wrap into ambiguity. That holds
for any realistic transfer; a production stack tracks the wrap explicitly (and uses RFC 7323
timestamps to disambiguate, PAWS).

`base` is known the moment we reach ESTABLISHED: it's `IRS + 1` (the SYN consumed `IRS`). For a
passive open we set it in `accept`; for an active open we don't learn the peer's ISN until the
SYN-ACK, so we rebase the reassembler right there.

---

## 6. Duplicate ACKs — the bridge to fast retransmit

When data arrives out of order, we deliver nothing — but we must not stay silent. We reply with a
**duplicate ACK**: a bare ACK re-advertising the *same* `RCV.NXT` we sent before. To the sender,
repeated identical ACKs are a signal: "I'm still missing the byte at `RCV.NXT`, but segments after
it are reaching me." Three of these in a row is TCP's **fast-retransmit** trigger — the sender
resends the presumed-lost segment immediately, without waiting for its RTO.

We don't yet act on dup-ACKs as a *sender* (that's Day 10's congestion control), but emitting them
correctly as a *receiver* now means the machinery is in place for the other half to hook into.

---

## 7. Worked example

Base = 101 (peer ISN 100, so first data byte is at seq 101 → offset 0). The peer sends "he" (101)
then "lo" (103), but they arrive reversed:

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

Exactly what `tcp::tests::reassembles_out_of_order_data` asserts. A duplicate ("abc" re-sent after
it was delivered) trims to empty and returns nothing; a partial overlap ("bcXY" when "abc" is
already in) trims the "bc" and delivers just "XY".

---

## 8. The code, walked

| Piece | Role |
|---|---|
| `src/reassembly.rs` | the `Reassembler`: `recv()` (trim/buffer/drain) + offset bookkeeping |
| `Connection.reasm` | one reassembler per connection; rebased on SYN-ACK for active open |
| `on_packet_at` data branch | feeds every data segment to `reasm`; echoes delivered bytes, else dup-ACKs |

The control flow in `on_packet_at`'s ESTABLISHED branch: a non-empty payload now goes to
`self.reasm.recv(th.seq, payload, self.recv.nxt)`. If it returns bytes, we advance `RCV.NXT` by
their length, echo them (queued for retransmission as in Day 6), and ACK. If it returns empty
(out-of-order or duplicate), we send a duplicate ACK and leave `RCV.NXT` untouched. In-order data
behaves exactly as before — the reassembler returns it immediately with an empty buffer.

One known simplification carried over: we don't segment *outgoing* data to an MSS, so a large
delivered run is echoed in a single segment. Real reorder cases (a few small segments) stay well
under the MTU; bulk outgoing segmentation is future work alongside congestion control.

---

## 9. Verification

`cargo test` → **52 green**. Reassembly coverage:

- `reassembly::*` (6) — in-order passthrough; out-of-order buffer then gap-fill; duplicate of
  delivered data; partial overlap trimming; multiple gaps filled in any order; far-out-of-window
  discard.
- `tcp::reassembles_out_of_order_data` — end-to-end: the second chunk arrives first and draws a
  duplicate ACK (RCV.NXT unmoved), then the first chunk flushes both and we echo the contiguous
  "helo" with `ack = 105` and a valid checksum.
- All prior data/teardown tests still pass — in-order behavior is unchanged.

Live (your hands), via `tcp-stack-run`: run the stack and induce reordering with
`sudo tc qdisc add dev tun0 root netem delay 50ms reorder 25% 50%`, then `nc` a few lines. The log
shows duplicate ACKs when a segment jumps the queue, and the echo still comes back intact and
in order. Remove it with `sudo tc qdisc del dev tun0 root`.

---

## 10. Why this, not that

| Decision | We chose | Real TCP |
|---|---|---|
| Buffer keying | offset from a fixed base (`BTreeMap<u32,_>`) | same idea; some use an interval tree of byte ranges |
| Overlapping fragments | assume disjoint future frags; trim vs delivered only | full byte-interval merge of arbitrary overlaps |
| Advertised window vs buffer | window constant 1024, buffer real | `RCV.WND = capacity − buffered`, dynamically |
| Out-of-window data | discard beyond `MAX_AHEAD` | discard beyond `RCV.WND`, exactly |
| SACK | none (only cumulative ACK + dup-ACKs) | RFC 2018 selective ACK reports the buffered ranges |
| Outgoing segmentation | none (echo a run in one segment) | split to MSS, respecting the send window |

---

## 11. Rebuild it yourself — checklist + exercises

From a blank file:
1. The delivery rule: bytes flow to the app only as an unbroken run from `RCV.NXT`.
2. The three steps — trim already-delivered prefix, buffer the rest, drain contiguous — and why
   `RCV.NXT` advances by the *delivered* length, not the segment length.
3. Why offsets-from-base, not raw sequence numbers, key the buffer (the wrap).
4. What a duplicate ACK means and why three of them matter to the sender.

**Exercises:**
- **E1.** Make `RCV.WND` dynamic: advertise `capacity − buffered_bytes` so a stalled reassembly
  buffer actually throttles the sender (ties Day 8 to this chapter).
- **E2.** Add **SACK** (RFC 2018): report the buffered byte ranges in an ACK option so the sender
  retransmits only the true gaps, not everything after them.
- **E3.** Handle arbitrary **overlapping** fragments by merging byte intervals, then prove it with
  a test that feeds overlapping retransmissions.
- **E4.** Segment **outgoing** data to a negotiated MSS so a large delivered run echoes as multiple
  MTU-sized segments, each queued for retransmission.

---

## 12. What's next

The receiver can now reorder; the sender can now retransmit (Day 6) and respect the receiver's
window (Day 8). The missing governor is **congestion control** — limiting the sender by what the
*network* (not the receiver) can carry: slow start, congestion avoidance (AIMD), and
fast retransmit / fast recovery driven by the very duplicate ACKs we started emitting here. The
effective send limit becomes `min(SND.WND, cwnd)`. That's Day 10, the next summit.

> Re-type the `Reassembler` from this chapter with the book closed, then `cargo test`. You now hold
> both halves of reliable, ordered delivery: retransmission on the send side (Day 6) and
> reassembly on the receive side (Day 9).
