# Day 2 — Replying to Pings: the Internet Checksum and the First Write

> Goal: make `ping 192.168.0.2` actually succeed (0% loss). To do that we must, for the
> first time, **build a packet and write it to the wire** — and that forces us to learn the
> **Internet Checksum** (RFC 1071), the one piece of arithmetic shared by IP, ICMP, TCP and
> UDP. After this you can compute and verify the checksum by hand and know exactly why
> `ping` was silent on Day 1.

**Contents**
1. Recap and the plan
2. The modular refactor — why now, what moved
3. The Internet Checksum — the whole theory
4. A worked checksum, by hand
5. Building the Echo Reply — four edits
6. Writing to the wire — `iface.send` and why ping now works
7. Verification — what each test proves
8. Design choices and alternatives
9. Rebuild it yourself — checklist + exercises
10. What the next step adds (TCP)

---

## 1. Recap and the plan

Day 1 we could *read* a ping (ICMP Echo Request, type 8) but never answered, so `ping`
reported 100% loss. An Echo *Reply* (type 0) carrying the same payload is what makes the
round trip complete. Building that reply means writing correct bytes back — including a
correct checksum, or the kernel/peer silently drops our packet. So Day 2 is two things:
**the checksum** (the hard concept) and **the reply** (the first write).

---

## 2. The modular refactor — why now, what moved

Day 1 lived entirely in `main.rs` — correct, because there was one caller of the IP parser.
Now ICMP-reply also needs IP logic (to rewrite addresses and the header checksum), so there
are 2+ callers and the "split when there are 2+ callers" rule (day1-book.md §13) kicks in:

| Module | Holds | Public API used elsewhere |
|---|---|---|
| `utils.rs` | the Internet checksum | `utils::checksum(&[u8]) -> u16` |
| `ip.rs` | IPv4 parse + header-checksum writer | `ip::parse`, `ip::write_header_checksum` |
| `icmp.rs` | ICMP parse + echo-reply builder | `icmp::parse`, `icmp::name`, `icmp::build_echo_reply` |
| `main.rs` | the recv/dispatch/send loop | — |

`mod utils; mod ip; mod icmp;` at the top of `main.rs` pulls them in. Modules reference each
other with `crate::` paths (e.g. `icmp.rs` does `use crate::{ip, utils};`). Each module
carries its own `#[cfg(test)]` tests — tests live next to the code they test. We do **not**
declare `ethernet`/`arp`/`tcp` yet: they have no code, and `mod`-ing an empty file adds
nothing. Declaring a module is what makes the compiler compile that file.

---

## 3. The Internet Checksum — the whole theory

**What it is.** A 16-bit value stored in IP/ICMP/TCP/UDP headers so the receiver can detect
bit errors. It is the **16-bit one's-complement of the one's-complement sum** of the data,
treated as a sequence of 16-bit big-endian words.

**Why a checksum at all.** Wires, memory, and routers flip bits. A checksum is a cheap
integrity check: recompute it on arrival; if it doesn't match, the data was corrupted in
transit, so drop it. It is *not* cryptographic — it stops accidents, not attackers (that's
TLS's job). It's deliberately weak-but-fast because every packet pays for it.

**Why *one's-complement* specifically.** Three reasons that all mattered in 1981 and still
do:

1. **Endianness independence.** The one's-complement sum has the property that it comes out
   the same whether you process the bytes big- or little-endian (you'd byte-swap the final
   result, but routers can incrementally update it without caring). This let machines of
   different endianness interoperate cheaply.
2. **Incremental update.** A router that decrements TTL can patch the checksum with a couple
   of adds instead of re-summing the whole header (RFC 1624) — because of how one's-complement
   arithmetic composes.
3. **The verify trick (below).** It makes checking almost free.

**The algorithm**, line by line (this is `utils::checksum`):

```rust
let mut sum: u32 = 0;                       // 32 bits so carries can pile up
for each 16-bit big-endian word w:
    sum += w;                               // ordinary addition, carries go into the high half
if one leftover byte:                       // odd-length data
    sum += (last_byte as u32) << 8;         // it's the HIGH byte of a 0x..00 word
while sum >> 16 != 0:                        // "end-around carry":
    sum = (sum & 0xffff) + (sum >> 16);     //   fold the high half back into the low half
return !(sum as u16);                        // one's complement (bitwise NOT)
```

- **Why `u32` for `sum`.** Adding many `u16`s overflows 16 bits constantly. We let the
  carries accumulate in the upper 16 bits of a `u32`, then fold them in at the end.
- **End-around carry.** One's-complement addition means a carry out of the top bit gets
  added back at the bottom. `(sum & 0xffff) + (sum >> 16)` does exactly that; we loop because
  the fold itself can produce a new carry.
- **Odd byte.** If the data has an odd number of bytes, the final lone byte is the *high*
  byte of a 16-bit word whose low byte is 0 — hence `<< 8`.
- **Final NOT.** The stored checksum is the complement of the sum.

**The verify trick.** Because the stored value is the complement of the sum of everything
else, summing *everything including the checksum* gives all-ones (`0xFFFF`), and the
complement of `0xFFFF` is `0x0000`. So: **to check a header, run the exact same function
over it including its checksum field and expect 0.** No special-casing. Our tests and the
live `MISMATCH` logic both lean on this.

**Reused everywhere.** IP checksums *only its header*. ICMP checksums *its whole message*.
TCP/UDP checksum their segment *plus a "pseudo-header"* (src/dst IP + protocol + length) —
same `checksum()` function, different byte ranges. One helper, four protocols — the "reuse
physically" rule made concrete.

---

## 4. A worked checksum, by hand

Take the canonical header (checksum field shown as `0000` while we compute it):

```
4500 0073 0000 4000 4011 0000 c0a8 0001 c0a8 00c7
```

Add the ten 16-bit words:

```
4500 + 0073 + 0000 + 4000 + 4011 + 0000 + c0a8 + 0001 + c0a8 + 00c7 = 0x2_479C
```

End-around carry — fold the high half (`0x2`) into the low half (`0x479C`):

```
0x479C + 0x2 = 0x479E
```

One's complement:

```
~0x479E = 0xB861     ← this is the checksum you store
```

Now **verify**: redo the sum but with the real checksum `B861` in place instead of `0000`.
The new folded sum is `0x479E + 0xB861 = 0xFFFF`, and `~0xFFFF = 0x0000`. Zero ⇒ valid.
That is precisely what `utils::checksum` returns and what the `valid_header_verifies_to_zero`
test asserts.

---

## 5. Building the Echo Reply — four edits

An Echo Reply is an Echo Request with four changes, so `icmp::build_echo_reply` **copies the
request and edits in place** — which also means the data payload is echoed back for free
(it's just... still there).

```
copy request → reply
1. swap IP source (12..16) ↔ destination (16..20)   // send it back to the pinger
2. set IP TTL (byte 8) = 64                          // fresh hop budget
3. recompute IP HEADER checksum over reply[..ihl*4]  // header changed → old checksum invalid
4. set ICMP type (reply[ihl*4]) = 0                  // 8 (request) → 0 (reply)
   recompute ICMP checksum over reply[ihl*4..]       // type changed → old checksum invalid
```

Order matters: do the IP-field edits *before* the IP checksum, and the ICMP type edit
*before* the ICMP checksum. Each checksum must be the last thing you touch in its region.
Two separate checksums because IP covers only its header while ICMP covers its whole message
— different byte ranges, same function.

Why swap rather than build fresh: a from-scratch IP/ICMP header builder is more code and
more bug surface; for echo, "mutate the request" is the standard, minimal, correct move.
(When we build TCP segments from nothing, we *will* write a real header builder.)

Why this returns `None` for non-echo-requests: we must not "reply" to a reply or to an
unreachable message — that would create loops or nonsense. Guarding on `type == 8` is the
contract.

---

## 6. Writing to the wire — `iface.send` and why ping now works

`iface.send(&reply)` is `write(fd, reply)` on the TUN device (the mirror of the `recv`/`read`
from day1-book.md §2-under-the-hood). To the kernel it looks as if a packet `192.168.0.2 →
192.168.0.1` *arrived from* `tun0`. The kernel routes it to the `ping` process, which sees
its Echo Reply, matches it by id/seq, and prints `64 bytes from 192.168.0.2: icmp_seq=1
ttl=64 time=0.2 ms`. Loss drops to 0%. You have built a host that answers pings using a
network stack you wrote.

If a checksum were wrong, the kernel would drop the reply before `ping` ever saw it — which
is exactly why Day 1 (no reply at all) and "a reply with a bad checksum" look identical from
the outside, and why we test the checksums offline rather than trusting the live run.

---

## 7. Verification — what each test proves

`cargo test` (11 tests, all green) — no TUN, no sudo:

- `utils::computes_known_checksum` — our algorithm reproduces the known `0xB861` (matches §4).
- `utils::valid_header_verifies_to_zero` — the verify trick holds.
- `utils::odd_length_pads_last_byte` — the odd-byte branch is correct.
- `ip::checksum_round_trips` — write then verify a header → sums to 0.
- `icmp::reply_is_well_formed` — the reply has type 0, swapped addresses, **both checksums
  valid (each region sums to 0)**, and the data payload unchanged.
- `icmp::ignores_non_echo_request` — we don't reply to non-requests.
- (plus the Day-1 parse tests, now living in `ip`/`icmp`).

Live test (your hands): run the stack, `ping -c3 192.168.0.2` from terminal 2 — expect
replies and **0% loss**. `sudo tcpdump -i tun0 -n -v` should now show *both* the request and
the reply.

---

## 8. Design choices and alternatives

| Decision | We chose | Alternative | Why ours |
|---|---|---|---|
| Reply construction | mutate a copy of the request | build header from scratch | minimal code; data echoes for free; fewer bugs |
| Checksum location | one `utils::checksum` | per-layer copies | reuse rule; one place to get right |
| Sum accumulator | `u32` + end-around fold | `u16` with manual carry checks | simpler, idiomatic, fast enough |
| Error integrity | Internet checksum | CRC32 / none | it's what the RFCs mandate on the wire; CRC is link-layer's job |
| When to refactor | now (2+ callers) | keep one big file | modules clarify ownership as the stack grows |

What production does more: hardware **checksum offload** (the NIC computes it, the OS sets a
"checksum unnecessary" flag); strict validation of the *incoming* IP checksum before trusting
a packet (we currently parse first and only cross-check with etherparse — exercise E2);
rate-limiting ICMP replies to resist ping floods.

---

## 9. Rebuild it yourself — checklist + exercises

From memory you should be able to:
1. Write `checksum`: u32 sum of BE words → odd-byte `<< 8` → end-around fold → `!`.
2. State and use the verify-to-zero property.
3. Write `build_echo_reply`: copy → swap addrs → TTL → IP checksum → type 0 → ICMP checksum.
4. Explain why a wrong checksum makes the reply vanish silently.

**Exercises:**
- **E1.** Hand-compute the checksum of the Day-1 ping IP header (zero the field first); then
  confirm your number with a one-line test.
- **E2.** **Validate incoming** IP checksums: in `ip::parse` (or the loop), reject a packet
  whose header doesn't verify to 0. Add a `ParseError::BadChecksum` and a test.
- **E3.** Make `build_echo_reply` set its own IP `identification` field (e.g. a counter)
  instead of echoing the request's. Does ping still work? Why?
- **E4.** Implement ICMP **Destination Port Unreachable** (type 3, code 3) for UDP packets to
  closed ports — your first *generated* (not mutated) ICMP message.

---

## 10. What the next step adds (TCP)

Next is the real prize: **TCP**. Step 3 is the **three-way handshake** — respond to a `SYN`
with a `SYN-ACK`, accept the client's `ACK`, and reach the `ESTABLISHED` state. That
introduces the **Transmission Control Block** (per-connection state), **sequence/acknowledgement
numbers** (32-bit, mod 2³²), the **Initial Sequence Number**, and the **connection table**
keyed by the 4-tuple (src ip, src port, dst ip, dst port). Unlike ICMP, TCP has *memory* —
that state machine is the heart of the project.

> Re-type `utils.rs`, `ip.rs`, and `icmp.rs` from this chapter with it closed, then run
> `cargo test`. Make Anki cards from anything you had to peek at — especially the end-around
> carry and the verify-to-zero trick.

---
---

# VOLUME II — The Exhaustive Reference (Day 2)

> Volume I above is the narrative that gets ping replying. Volume II makes you own the checksum and
> packet construction completely: every checksum variant, the math with proofs, the build technique,
> the code line-by-line, and the testing — so you can re-derive Day 2 from first principles.

## Contents of Volume II (Day 2)
- A. Error detection in general — why checksums, and the alternatives
- B. One's-complement arithmetic, completely (with proofs)
- C. The Internet checksum algorithm — variants and optimizations
- D. Packet construction — the general technique (mutate vs build)
- E. `utils.rs` and `icmp.rs` line-by-line (Day-2 additions)
- F. Writing to the wire — `iface.send` internals
- (continues: debugging, exercises, FAQ, glossary, tables)

---

## A. Error detection in general — why checksums, and the alternatives

### A.1 — The problem error detection solves

Bits flip. A cosmic ray, a marginal cable, a flaky router buffer, a bug — any can corrupt a byte in
transit. Without a check, the receiver would act on garbage (wrong length, wrong address, corrupted
data). An **error-detecting code** appends redundancy computed from the data so the receiver can
recompute it and notice a mismatch. Note "detecting," not "correcting": internet checksums only tell
you *that* something broke (so you drop and let a higher layer retransmit), not *what* — error
*correction* (ECC, FEC) costs more redundancy and lives where retransmission is impossible (deep
space, storage).

### A.2 — The design axes

Any check trades off along: **strength** (what fraction/patterns of errors it catches), **cost**
(CPU per byte), **size** (bits of overhead), and **incremental updatability** (can a router patch it
cheaply?). The internet picked *cheap, small, updatable, weak* — deliberately — because every packet
pays the cost, links are mostly reliable, and stronger checks already exist below (link CRC) and the
end-to-end check is just a last-resort sanity net (the end-to-end principle again).

### A.3 — The alternatives, and why IP didn't use them

| Scheme | Strength | Cost | Used where |
|--------|----------|------|------------|
| **Parity bit** | 1 bit; catches odd # of flips only | trivial | ancient serial links, RAM (per byte) |
| **Internet checksum (1's-comp)** | weak; misses reorders/cancels | very low; updatable | **IP/ICMP/TCP/UDP headers** |
| **Fletcher / Adler-32** | stronger than 1's-comp, still cheap | low | zlib (Adler-32), some protocols |
| **CRC-32** | catches all bursts ≤ 32 bits, most others | moderate (table/HW) | **Ethernet (L2)**, ZIP, disk |
| **Cryptographic hash (SHA-256)** | detects *adversarial* tampering | high | TLS, signatures, integrity vs attackers |

Why IP uses the one's-complement checksum and not CRC: (1) it's computable with just add/fold on any
1970s CPU (no lookup table), (2) it's **endianness-independent** (§B), (3) it's **incrementally
updatable** by routers (§C.5) — CRC is none of these cheaply. Ethernet *does* use CRC-32 because the
NIC hardware computes it for free and the link is where most corruption happens. So a packet is
covered by *both*: a strong CRC per hop (L2) and a weak end-to-end checksum (L3/L4). Defense in
depth across layers.

### A.4 — Why not just trust the link CRC?

Because the CRC protects only *one hop* and only the *link*. Corruption can happen *inside* a router
(bad memory, a software bug) between receiving (CRC checked) and re-transmitting (new CRC computed) —
the famous "router with bad RAM silently corrupting packets." The end-to-end IP/TCP checksum catches
that, because it's computed by the original sender and verified by the final receiver, spanning the
whole path. This is the canonical illustration of the end-to-end argument: only the endpoints can
guarantee the property; intermediate checks are optimizations, not guarantees.

---

## B. One's-complement arithmetic, completely

Day 1 §R sketched this; here it is in full, because the checksum *is* this arithmetic.

### B.1 — Representations recap

In n-bit one's complement, a negative value −x is `~x` (bitwise NOT). There are two zeros: `+0`
(all bits 0) and `−0` (all bits 1). Positive range `0…2^(n-1)−1`, negative `−(2^(n-1)−1)…−0`. For
16-bit: `+0 = 0x0000`, `−0 = 0xFFFF`, max `+32767 = 0x7FFF`, min `−32767 = 0x8000`.

### B.2 — Addition with end-around carry

To add two one's-complement numbers: add as unsigned; if the addition overflows the top bit, add the
carry (value 1) back into the low bit. Worked, 8-bit:
```
  0xF0 (-15)  +  0x20 (+32)
= 0x110                       (overflow: carry out)
  low 8 bits = 0x10, carry = 1
  0x10 + 1 = 0x11 (+17)       ✓  (-15 + 32 = 17)
```
The end-around carry is not a hack — it's what makes the wrap land on the correct value in a system
with two zeros. Equivalent statement: one's-complement addition is **addition modulo 2ⁿ − 1** (§R.2),
with the result `0` represented as `−0 = all-ones` rather than `+0`.

### B.3 — Why two zeros don't break the checksum

The checksum stores `~sum`. If the data is all zeros, `sum = 0` and `~0 = 0xFFFF` is stored — a valid
"the sum is zero" indication that isn't confused with "no checksum." (UDP exploits the two zeros: a
*computed* checksum that comes out `0x0000` is transmitted as `0xFFFF`, reserving `0x0000` to mean
"checksum not computed." TCP has no such exemption — its checksum is mandatory.)

### B.4 — Commutativity, associativity, and the consequences

Modular addition is commutative and associative (§R.3), so:
- You may sum words in **any order** → SIMD/wide summation is valid.
- You may sum in **any grouping** → sum 32 or 64 bits at a time, fold at the end.
- **Reordering whole words is undetectable** (a known weakness, §R.6) — the same property that buys
  speed costs strength.
These are not incidental; they're why the checksum is fast and why it's weak, both from one algebraic
fact.

### B.5 — The relationship to two's complement (don't confuse them)

| | One's complement | Two's complement |
|---|---|---|
| Negate | invert bits | invert bits, add 1 |
| Zeros | two (+0, −0) | one |
| Used for | the Internet checksum | signed integers in CPUs/Rust |
| In our code | `!sum` in `checksum` | `i32`/`i8` (we don't use these for fields) |

Rust's `!` gives the one's complement of the bit pattern (what the checksum needs); Rust's signed
integer *arithmetic* is two's complement (what your CPU does). Day 2 uses the former, never the
latter.

---

## C. The Internet checksum algorithm — variants and optimizations

The naive word-by-word loop (our `utils::checksum`) is correct and clear. Production code uses
equivalent-but-faster forms; understanding them cements *why* the algebra of §B matters.

### C.1 — The canonical (our) form, restated

Sum 16-bit big-endian words into a wide accumulator; add the odd trailing byte as a high-byte word;
fold carries until the high half is zero; bitwise-NOT. O(n), one pass, no table.

### C.2 — Deferred folding (sum first, fold once)

Because addition is associative (§B.4), you needn't fold after every add — accumulate everything in a
`u32` (or `u64`), then fold the carries at the very end (a couple of fold steps). A `u32` accumulator
can sum up to 65,536 sixteen-bit words before it could overflow 32 bits — far more than any packet —
so for IP/TCP-sized data, **fold-once** is safe and is what our loop effectively does (it folds after
the loop, not inside it).

### C.3 — Wide summation (32/64-bit at a time)

Sum the data as `u32` or `u64` chunks, then fold the wide accumulator down to 16 bits at the end. By
associativity/commutativity this gives the identical result while doing ¼ or ⅛ the add operations —
a real speedup for multi-gigabit software checksumming. The fold-down: repeatedly add the high half
to the low half (64→32→16). Same algebra, fewer instructions.

### C.4 — Endianness-independent summation

Per §R.4, you can sum in host byte order and only byte-swap the final 16-bit result. So on a
little-endian CPU you skip the per-word `from_be_bytes` swap entirely (sum raw `u16`s as the memory
holds them) and swap once at the end. We *don't* do this (we keep `from_be_bytes` for clarity), but
it's why production checksum routines look like they "ignore" endianness — they've pushed the single
swap to the end.

### C.5 — Incremental update (RFC 1624), derived

A router changing one 16-bit field from `old` to `new` shouldn't re-sum the whole header. Since the
checksum is `~Σ`, and Σ is a sum, replacing `old` with `new` changes Σ by `(new − old)`. In
one's-complement terms the new checksum is:
```
new_checksum = ~( ~old_checksum + ~old_field + new_field )
```
(all in one's-complement arithmetic). This is O(1) regardless of header size — what lets routers
forward at line rate while decrementing TTL. It works *only because* of associativity (§B.4): the
local change composes with the rest of the sum without recomputation.

### C.6 — Hardware offload

Modern NICs compute IP/TCP/UDP checksums in hardware. The OS marks the packet "checksum offload" and
fills a placeholder; the NIC computes the real value on the way out (and verifies on the way in,
setting a "checksum OK" flag so the stack can skip it). This is why a packet captured *before* the
NIC (e.g. on the loopback or with certain capture points) may show a "bad" checksum that's actually
fine — Wireshark even warns "checksum offload?" for exactly this. On our TUN path there's no NIC, so
we compute in software (our `utils::checksum`).

### C.7 — The pseudo-header detail (TCP/UDP, preview of Day 3)

IP checksums only its header. TCP and UDP checksum a **pseudo-header** (src/dst IP, protocol,
transport length) **plus** the transport header and data. The pseudo-header is never transmitted — it
binds the checksum to the addresses so a misdelivered segment is detected. Same `utils::checksum`
function, different byte range (you prepend the 12-byte pseudo-header). UDP may send checksum 0 to
mean "not computed" (IPv4 only); TCP must always compute it. Full treatment in day3-book.md §8.

---

## D. Packet construction — the general technique

Day 1 only read packets; Day 2 writes the first one. There are two ways to produce an outgoing
packet, and knowing when to use each is a real skill.

### D.1 — Mutate-in-place vs build-from-scratch

- **Mutate a received packet** (what `build_echo_reply` does): copy the request, change the few
  fields that differ, recompute the affected checksums. Cheapest and least error-prone when the
  response *resembles* the request (echo reply ≈ echo request with swapped addresses + flipped type).
  Bonus: any field/payload you don't touch is automatically correct (the data echoes for free).
- **Build from scratch** (what `tcp::build_packet` does, Day 3): allocate a zeroed buffer and write
  every field. Necessary when the response has *no* corresponding request to mutate (a SYN-ACK, a
  fresh data segment, a generated ICMP error). More code, more places to get a field wrong.

The rule: mutate when the response is a near-copy; build when it's genuinely new. Day 2 is mutate;
Day 3 introduces build.

### D.2 — The invariant order of operations

Whichever method, the order is fixed by a dependency: **a checksum must be the last thing you write
in its region, after every other field in that region is final.** For the echo reply:
1. change IP fields (swap src/dst, set TTL) → 2. compute IP header checksum → 3. change ICMP fields
(type 8→0) → 4. compute ICMP checksum. If you computed a checksum and *then* changed a field it
covers, the checksum would be stale and the kernel/peer would drop the packet. This is the single
most common packet-construction bug.

### D.3 — Two checksums, two regions

The IP checksum covers **only the IP header** (`reply[..header_len]`); the ICMP checksum covers **the
whole ICMP message** (`reply[header_len..]`). They are independent computations over disjoint ranges
with the same `utils::checksum`. Getting the ranges wrong (e.g. checksumming the whole packet for the
IP field) silently produces an invalid packet. (TCP/UDP add the pseudo-header twist — Day 3.)

### D.4 — Zero-the-field-first, always

Before computing any checksum, the checksum field in that region must be 0 (the algorithm sums the
field, so it can't already contain the answer). `ip::write_header_checksum` zeroes bytes 10–11 first;
`build_echo_reply` zeroes the ICMP checksum bytes before summing. Forgetting this yields a checksum
computed over a stale value — wrong, and a classic bug.

### D.5 — Big-endian on the way out

Every multi-byte field you *write* uses `to_be_bytes()` — the mirror of `from_be_bytes` on the way
in. The checksum result, addresses, lengths: all big-endian into the buffer. A little-endian write is
the same silent corruption as a little-endian read, just on transmit.

### D.6 — Length and buffer discipline

The outgoing buffer must be exactly the packet length (for `iface.send`, you pass `&reply[..]` where
`reply.len()` is the full packet). `build_echo_reply` returns a `Vec` sized to the request (same
length, since echo preserves size). For built packets, total length = sum of header sizes + payload,
and the IP Total Length field must match — a mismatch confuses receivers and some checksums.

---

## E. `utils.rs` and `icmp.rs` line-by-line (Day-2 additions)

(Day-1 §O covered `ip.rs`/`utils.rs` parse side; here are the Day-2 additions in full.)

### E.1 — `utils::checksum` — see Day 1 §O.1 for the full line-by-line

The function is unchanged from where Day 1 introduced it; its complete walkthrough (the `u32`
accumulator, `chunks_exact(2)` + `by_ref()`, the odd-byte `<<8`, the end-around `while` fold, the
final `!`) lives in **day1-book.md §O.1**, with the math in §R there. Day 2 is where it's first
*used* for real (computing, not just the concept).

### E.2 — `ip::write_header_checksum`, line by line

```rust
pub fn write_header_checksum(header: &mut [u8]) {
    header[10] = 0;
    header[11] = 0;
    let c = utils::checksum(header);
    let [hi, lo] = c.to_be_bytes();
    header[10] = hi;
    header[11] = lo;
}
```
- `&mut [u8]` — exclusive borrow; we write into it. The caller passes exactly the IP header slice
  (`&mut pkt[..20]` / `&mut reply[..header_len]`), so `header` *is* the region to checksum.
- `header[10] = 0; header[11] = 0;` — zero the checksum field first (D.4). Bytes 10–11 are the IP
  header checksum's location.
- `utils::checksum(header)` — sum over the whole passed slice (the header, with its checksum field
  now zero). Returns the 16-bit result.
- `c.to_be_bytes()` destructured into `[hi, lo]` — big-endian (D.5).
- write `hi`/`lo` back into 10–11. Now the header verifies to 0 (the round-trip test asserts this).

### E.3 — `icmp::build_echo_reply`, line by line

```rust
pub fn build_echo_reply(request: &[u8], header_len: usize) -> Option<Vec<u8>> {
    if request.len() < header_len + 8 { return None; }
    if request[header_len] != 8 { return None; }
```
- Guard: need a full IP header + the 8-byte ICMP header, or we can't safely index. `Option`/`None`
  because the only failure is "not a well-formed echo request" — a single reason.
- `request[header_len]` is the ICMP **type** byte (first byte after the IP header). `!= 8` → not an
  echo request → `None` (we must not "reply" to replies/errors — D in spirit).

```rust
    let mut reply = request.to_vec();
```
- Copy the request into an owned `Vec` we can mutate (mutate-in-place strategy, D.1). The payload
  comes along for free → echoed verbatim.

```rust
    let (mut src, mut dst) = ([0u8; 4], [0u8; 4]);
    src.copy_from_slice(&reply[12..16]);
    dst.copy_from_slice(&reply[16..20]);
    reply[12..16].copy_from_slice(&dst);
    reply[16..20].copy_from_slice(&src);
```
- Swap source/destination via temporaries. The temporaries avoid an overlapping
  borrow-of-self (you can't `copy_from_slice` one part of `reply` from another part simultaneously —
  see day1 §AR.12). After this, the reply is addressed back to the pinger.

```rust
    reply[8] = 64;
    ip::write_header_checksum(&mut reply[..header_len]);
```
- Reset TTL (byte 8). Then recompute the IP checksum **after** the IP-field edits (order, D.2), over
  exactly the header.

```rust
    reply[header_len] = 0;
    reply[header_len + 2] = 0;
    reply[header_len + 3] = 0;
    let c = utils::checksum(&reply[header_len..]);
    let [hi, lo] = c.to_be_bytes();
    reply[header_len + 2] = hi;
    reply[header_len + 3] = lo;
    Some(reply)
}
```
- Set ICMP type to 0 (echo reply). Zero the ICMP checksum field (bytes header_len+2..+4). Recompute
  over the **whole ICMP message** (`reply[header_len..]`, D.3). Write it big-endian. Return the
  finished packet. Note both checksums are recomputed because both regions changed.

### E.4 — The tests, restated

`icmp::reply_is_well_formed` asserts type 0, swapped addresses, **both** regions verify to 0, and the
payload unchanged. `ip::checksum_round_trips` asserts write-then-verify = 0. These encode D.2–D.4 as
executable checks — if you violate the order or forget to zero a field, a test goes red.

---

## F. Writing to the wire — `iface.send` internals

### F.1 — What `send` actually does

`iface.send(&reply)` is `write(tun_fd, reply)` — it hands the bytes to the TUN driver, which presents
them to the kernel's IP layer as if the packet **arrived from** `tun0` (the mirror of `recv`/`read`,
day1 §F.4). The kernel then routes/delivers it normally: for our echo reply addressed to
`192.168.0.1`, the kernel hands it to the waiting `ping` process.

### F.2 — Why a bad checksum vanishes here

After `write`, the kernel (or, for a real peer, the receiving host) validates the IP and ICMP
checksums. If either fails, the packet is **silently discarded** — no error returns to us, `send`
still reports success. That's why "I sent a reply but ping still shows loss" almost always means a
checksum bug (day1 §P.8), and why we verify checksums in *offline tests* rather than trusting the
live result.

### F.3 — Partial writes and return value

`write` returns how many bytes were accepted. For a packet-oriented device like TUN, a single write
maps to a single packet and normally accepts the whole buffer; we propagate any error with `?`. (For
stream fds you'd loop on short writes; for TUN a packet is atomic.) We don't currently inspect the
returned count — a robustness nit, not a correctness bug for our sizes.

### F.4 — Blocking and ordering

Like `recv`, `send` on the blocking fd may block if the device queue is full (rare for our volume).
Packets we write are delivered in order. Under the future event loop (day1 §AI), `send` on a
non-blocking fd could return `WouldBlock`, and you'd queue the packet to retry on writability — part
of the same refactor that enables retransmission.

### F.5 — The round trip, end to end

`ping` → kernel routes to tun0 → our `recv` → parse → `build_echo_reply` (valid checksums) → our
`send` → kernel sees a packet "from tun0" to 192.168.0.1 → delivers to `ping` → `ping` matches it by
id/seq → prints `64 bytes from 192.168.0.2 ... time=0.2 ms`, loss 0%. Every arrow is something this
project now implements or drives. That round trip is the Day-2 milestone made concrete.

---

## G. Debugging the checksum and the reply

Day-2 bugs are almost all "the packet went out but vanished." Here's how to find each.

### G.1 — Symptom: ping still 100% loss after adding the reply

The reply is being dropped. In order of likelihood:
1. **Bad checksum** (IP or ICMP). Wireshark flags it red; or assert `utils::checksum(&reply[..20])
   == 0` and `utils::checksum(&reply[20..]) == 0` offline.
2. **Forgot to zero the checksum field** before computing → checksum over a stale value.
3. **Wrong checksum range** — checksummed the whole packet for the IP field, or only the header for
   ICMP.
4. **Little-endian write** — used `to_ne_bytes`/manual wrong order instead of `to_be_bytes`.
5. **Didn't actually call `send`**, or sent `&reply[..0]`.
6. **Addresses not swapped** — reply addressed to yourself; never reaches `ping`.

### G.2 — The offline triage (no live run needed)

Build the reply in a unit test and assert, in order: type byte == 0; `reply[12..16]` == original dst;
`reply[16..20]` == original src; `utils::checksum(&reply[..header_len]) == 0`; `utils::checksum(&
reply[header_len..]) == 0`; payload unchanged. The first assertion that fails localizes the bug
exactly. This is `reply_is_well_formed` — run it before ever touching `tun0`.

### G.3 — The live triage (three terminals)

Terminal 1: the stack. Terminal 2: `ping -c1 192.168.0.2`. Terminal 3:
`sudo tcpdump -i tun0 -n -vv`. You should see **two** lines: echo request (in) and echo reply (out).
- No reply line → you didn't `send` (or it errored).
- Reply line present but ping still loss → checksum (tcpdump `-vv` shows "incorrect" if so; Wireshark
  is clearer). 
- Reply present, checksum OK, still loss → addresses/id/seq wrong (ping can't match it).

### G.4 — Hand-verifying a checksum

Take the reply's 20-byte IP header, sum the ten 16-bit words *including* the checksum field; you must
get `0xFFFF` (which `utils::checksum` then complements to 0). If you get anything else, the stored
checksum is wrong. Repeat over the ICMP message. This is the §R.5 verify theorem used as a debugger.

### G.5 — Wireshark's "checksum offload" red herring

If you ever capture on a real NIC (not TUN), Wireshark may flag *outgoing* checksums as bad because
the NIC fills them in *after* capture (hardware offload, §C.6). On TUN there's no offload, so a red
checksum is a *real* bug. Know the difference so you don't chase a non-bug on hardware or dismiss a
real one on TUN.

### G.6 — `tracing` instead of `println!`

For deeper debugging, the `tracing` dependency lets you add structured, filterable logs
(`RUST_LOG=debug`) without editing call sites. We use `println!` for teaching clarity, but a
`tracing::debug!("reply csum ip={} icmp={}", ...)` is how you'd instrument the build path in a real
session.

---

## H. Day 2 exercises with full worked solutions

### H.1 — Compute a checksum by hand
**Q.** Header `45 00 00 28 00 01 00 00 40 06 00 00 0a 00 00 01 0a 00 00 02` (field zeroed). Checksum?
**A.** Sum: 4500+0028+0001+0000+4006+0000+0a00+0001+0a00+0002 = 0x... step: 4500+28=4528; +1=4529;
+4006=852F; +0A00=8F2F; +1=8F30; +0A00=9930; +2=9932. Sum 0x9932, no high carry. `~0x9932 = 0x66CD`.
Verify: 0x9932 + 0x66CD = 0xFFFF → 0. ✓

### H.2 — Verify a checksum
**Q.** Is `0x66CD` correct for H.1's header? Show the check.
**A.** Sum all ten words including `66CD`: previous 0x9932 + 0x66CD = 0xFFFF; `~0xFFFF = 0`. Zero ⇒
valid.

### H.3 — The odd-byte path
**Q.** What does `checksum(&[0x12, 0x34, 0x56])` compute, conceptually?
**A.** Words: `0x1234`, then the lone `0x56` becomes `0x5600` (high byte). Sum `0x1234 + 0x5600 =
0x6834`; `~0x6834 = 0x97CB`. (Equals `checksum(&[0x12,0x34,0x56,0x00])`.)

### H.4 — Why zero the field first? (break it)
**Q.** What happens if you compute the IP checksum *without* zeroing bytes 10–11 first?
**A.** You sum the old checksum value as if it were data, getting a wrong result; the stored checksum
won't verify to 0, and the packet is dropped. Always zero first.

### H.5 — Build an echo reply by hand
**Q.** Given request IP src=192.168.0.1 dst=192.168.0.2, ICMP type 8, list the exact byte changes.
**A.** bytes 12–15 → `c0 a8 00 02`; bytes 16–19 → `c0 a8 00 01`; byte 8 → `40`; bytes 10–11 →
recomputed IP checksum; byte 20 → `00`; bytes 22–23 → recomputed ICMP checksum. Everything else
unchanged.

### H.6 — Order dependency (find the bug)
**Q.** A teammate computes the IP checksum, *then* sets TTL=64. Why is the packet dropped?
**A.** The checksum was computed before TTL changed, so it no longer matches the header. Checksum
must come *after* all field edits in its region (D.2).

### H.7 — Validate incoming checksums (code)
**Q.** Add rejection of corrupt incoming IP headers.
**A.** `if utils::checksum(&packet[..header_len]) != 0 { return Err(ParseError::BadChecksum); }` after
the length guards; add the enum variant; test good→Ok, flipped-byte→BadChecksum.

### H.8 — ICMP with no pseudo-header (explain)
**Q.** Why can `build_echo_reply` checksum `reply[header_len..]` directly, with no pseudo-header?
**A.** ICMP's checksum covers only the ICMP message; unlike TCP/UDP it doesn't include IP addresses.
So the raw ICMP byte range is the entire input. (TCP/UDP would need the 12-byte pseudo-header
prepended.)

### H.9 — UDP checksum-zero rule (explain)
**Q.** Why might a UDP datagram carry checksum 0x0000, and what does TCP do differently?
**A.** In IPv4, UDP checksum is optional; 0x0000 means "not computed" (a *computed* zero is sent as
0xFFFF via the two-zeros trick). TCP's checksum is mandatory — 0 is never special.

### H.10 — Incremental update (math)
**Q.** A router changes TTL from 64 (in some 16-bit word `old`) to 63 (`new`). Sketch the new
checksum without re-summing.
**A.** `new_checksum = ~(~old_checksum + ~old_word + new_word)` in one's-complement arithmetic
(RFC 1624). O(1); only the changed word participates.

---

## I. Day 2 FAQ

**1. Why does the checksum use a `u32` accumulator?** To hold carries from summing many 16-bit words
before folding (§C.2).

**2. Do I checksum the payload in the IP header checksum?** No — IP checksums *only its header*.
TCP/UDP checksum their data (with a pseudo-header); ICMP checksums its whole message.

**3. Why does a valid checksum verify to 0?** Because the stored value is `~sum`, so summing
everything (incl. the field) gives all-ones, complemented to 0 (§R.5).

**4. Why did my reply get dropped with no error?** Bad checksum (or wrong addresses) → silent
discard by the kernel/peer (§F.2). Verify checksums offline.

**5. Why two checksums for one ping reply?** IP header and ICMP message are separate regions with
separate checksum fields (§D.3).

**6. Can I reuse `utils::checksum` for TCP later?** Yes — same function, you just prepend the 12-byte
pseudo-header to the TCP segment (§C.7, day3).

**7. Why mutate the request instead of building a reply?** Less code, fewer bugs, and the payload
echoes for free (§D.1). Build-from-scratch is for responses with no matching request.

**8. Why must the checksum field be zero during computation?** The field is part of the summed data;
it can't contain its own answer (§D.4).

**9. Is ping's "64 bytes" the IP or ICMP size?** It's the ICMP payload framing convention; the IP
packet is 84 bytes (20 IP + 8 ICMP header + 56 data). Don't conflate the numbers.

**10. Why is endianness relevant when *writing*?** Multi-byte fields go out big-endian; `to_be_bytes`
on write mirrors `from_be_bytes` on read. A wrong-endian write corrupts just like a wrong-endian
read.

**11. What's the smallest valid ICMP echo I can reply to?** 8 bytes of ICMP header (id/seq, no data);
our guard requires `header_len + 8`.

**12. Does the kernel re-checksum my reply?** No — you computed it; the kernel/peer *verifies* it. If
it's wrong, drop. (On real NICs, hardware offload may compute outgoing ones — not on TUN.)

---

## J. Day-2 glossary

- **Adler-32** — a fast checksum (zlib); stronger than the Internet checksum, weaker than CRC.
- **checksum** — redundancy computed from data to *detect* (not correct) corruption.
- **CRC (Cyclic Redundancy Check)** — polynomial-division check; Ethernet/disk use CRC-32; catches
  all bursts up to its width.
- **echo reply / request** — ICMP types 0 / 8; the ping exchange.
- **end-around carry** — adding the overflow carry back into the low bit; makes one's-complement
  addition mod (2ⁿ−1).
- **error correction (ECC/FEC)** — adds enough redundancy to *fix* errors, not just detect (deep
  space, RAM).
- **Fletcher checksum** — position-sensitive checksum; catches reorderings the Internet checksum
  misses.
- **hardware offload** — NIC computes/verifies checksums (and segmentation) instead of the CPU.
- **incremental update** — patching a checksum in O(1) when one field changes (RFC 1624).
- **Internet checksum** — the 16-bit one's-complement sum (RFC 1071); IP/ICMP/TCP/UDP.
- **mutate-in-place** — build a reply by editing a copy of the request (vs build-from-scratch).
- **one's complement** — bit-inversion representation/arithmetic; the checksum's basis; two zeros.
- **parity** — a single bit catching odd numbers of flips; the simplest check.
- **pseudo-header** — IP fields fed into the TCP/UDP checksum (not ICMP/IP).
- **two's complement** — signed-integer representation (invert+1); CPU/Rust arithmetic.
- **verify-to-zero** — a valid Internet checksum, re-summed including its field, yields 0.

## K. Day-2 reference tables

### K.1 — The checksum algorithm as a step table

| Step | Operation | Code |
|------|-----------|------|
| 1 | accumulate 16-bit BE words | `sum += u16::from_be_bytes([w0,w1]) as u32` |
| 2 | odd trailing byte → high byte | `sum += (last as u32) << 8` |
| 3 | fold carries (repeat) | `sum = (sum & 0xffff) + (sum >> 16)` |
| 4 | one's complement | `!(sum as u16)` |
| verify | re-sum incl. field → expect 0 | `checksum(region) == 0` |

### K.2 — ICMP echo header fields (bytes after the IP header)

| Offset (from ICMP start) | Field | Echo Request | Echo Reply |
|---|---|---|---|
| 0 | type | 8 | 0 |
| 1 | code | 0 | 0 |
| 2–3 | checksum | computed | recomputed |
| 4–5 | identifier | set by pinger | echoed |
| 6–7 | sequence | n | echoed |
| 8+ | data | timestamp+filler | echoed verbatim |

### K.3 — Which region each checksum covers

| Checksum | Covers | Pseudo-header? | Field location |
|----------|--------|----------------|----------------|
| IPv4 header | the IP header only (IHL×4 bytes) | no | IP bytes 10–11 |
| ICMP | the whole ICMP message | no | ICMP bytes 2–3 |
| TCP (day3) | pseudo-header + TCP header + data | **yes** | TCP bytes 16–17 |
| UDP | pseudo-header + UDP header + data | yes (optional in v4) | UDP bytes 6–7 |

### K.4 — Error-detection strength comparison

| Scheme | Single-bit | Burst | Reorder words | Adversary |
|--------|-----------|-------|---------------|-----------|
| Parity | odd only | poor | no | no |
| Internet checksum | yes | most | **no** (misses) | no |
| Fletcher/Adler | yes | better | yes | no |
| CRC-32 | yes | all ≤32 bits | yes | no |
| SHA-256 (HMAC) | yes | yes | yes | **yes** |

### K.5 — The four edits of an echo reply

| # | Edit | Bytes | Why |
|---|------|-------|-----|
| 1 | swap src/dst | 12–19 | send back to pinger |
| 2 | reset TTL | 8 | fresh hop budget |
| 3 | IP checksum | 10–11 | header changed |
| 4 | type 8→0 + ICMP checksum | hl, hl+2..hl+4 | it's now a reply |

## L. The modular refactor — line-by-line and the module graph

Day 2 split `main.rs` into modules. Here's the structure and why each `use`/`mod` line exists.

### L.1 — The `mod` declarations in `main.rs`

```rust
mod icmp;
mod ip;
mod utils;
```
Each `mod X;` tells the compiler to compile `src/X.rs` as a submodule of the crate. Without the
declaration the file is *not compiled* (which is why `ethernet`/`arp`/`tcp` stay undeclared until they
have code). Order doesn't matter; alphabetical is just tidy.

### L.2 — The `use crate::...` lines inside modules

```rust
// in ip.rs
use crate::utils;
// in icmp.rs
use crate::{ip, utils};
```
`crate::` is the absolute path from the crate root. `ip` needs `utils` (for `checksum`); `icmp` needs
both `ip` (for `write_header_checksum`) and `utils` (for the ICMP checksum). These lines *are* the
dependency edges — readable in the source.

### L.3 — The dependency graph (acyclic, layered)

```
        utils                 (depends on nothing)
        ╱     ╲
      ip       │
     ╱  ╲      │
  icmp   tcp   │             (ip, icmp, tcp all use utils; icmp, tcp use ip)
     ╲    │   ╱
       main                   (uses all)
```
No cycles: `utils` is a leaf; `ip` sits above it; `icmp`/`tcp` above `ip`; `main` on top. This mirrors
the protocol stack (checksum primitive → IP → ICMP/TCP → driver). A cycle would be a design smell;
the layering prevents it.

### L.4 — Visibility (`pub`)

Items used across module boundaries are `pub` (`checksum`, `parse`, `Ipv4Header` + its fields,
`write_header_checksum`, `build_echo_reply`, …). Items private to a module aren't marked `pub`. The
compiler enforces this: a missing `pub` produces a "private item" error at the call site, which is how
you discover the intended API surface.

### L.5 — Tests travel with their module

Each module carries `#[cfg(test)] mod tests`. Tests are child modules, so they can see private items
of their parent — you can test internals without making them `pub`. They compile only under
`cargo test`. This is why splitting into modules didn't scatter the tests: each file owns its own.

### L.6 — Why split now and not Day 1

Day 1 had one caller of IP logic → one file was right (no premature structure). Day 2's ICMP reply
created a *second* caller of IP/checksum logic → the "2+ callers" threshold (day1 §13) → split. The
refactor is behavior-preserving (all Day-1 tests still pass, now living in `ip`/`icmp`), which is the
safe way to refactor: move code, keep tests green.

## M. The checksum across the stack — one function, four protocols

`utils::checksum` is reused by every layer; the only differences are the byte range and whether a
pseudo-header is prepended. Seeing them together cements the "reuse physically" rule.

- **IPv4 header:** `checksum(&packet[..ihl*4])`. Header only. No pseudo-header. (Day 2.)
- **ICMP:** `checksum(&icmp_message)`. Whole message. No pseudo-header. (Day 2.)
- **UDP:** `checksum(pseudo_header ++ udp_header ++ data)`. Optional in IPv4 (0 = none). (UDP exercise.)
- **TCP:** `checksum(pseudo_header ++ tcp_header ++ data)`. Mandatory. (Day 3.)

The pseudo-header (for TCP/UDP) is 12 bytes: src IP, dst IP, zero, protocol, transport length. It's
*input only* — never sent. The reason it exists (binding the checksum to the addresses, to catch
misdelivery) is the one conceptual addition over IP/ICMP. Everything else is the same one's-complement
sum you wrote once. When you reach Day 3, the TCP checksum will feel familiar precisely because it's
this function with a 12-byte prefix — the payoff of putting it in `utils`.

---

## N. A full byte-level trace: echo request → echo reply

The whole Day-2 transformation, byte for byte. Request in, reply out.

### N.1 — The request (84 bytes), annotated

```
off  bytes         field            value
 0   45            ver/IHL          v4, 20-byte header
 1   00            DSCP/ECN         0
 2   00 54         total length     84
 4   ab cd         identification   0xABCD
 6   40 00         flags/frag       DF
 8   40            TTL              64
 9   01            protocol         1 = ICMP
10   b8 6a         IP checksum      0xB86A (valid for this header)
12   c0 a8 00 01   src              192.168.0.1 (pinger)
16   c0 a8 00 02   dst              192.168.0.2 (us)
20   08            ICMP type        8 = Echo Request
21   00            ICMP code        0
22   <c0> <c1>     ICMP checksum    (valid)
24   12 34         identifier       0x1234
26   00 01         sequence         1
28   .. (56 bytes) data             timestamp + filler
```

### N.2 — Applying the four edits

```
edit 1 (swap):  bytes 12–15 → c0 a8 00 02   ;  bytes 16–19 → c0 a8 00 01
edit 2 (TTL):   byte 8 → 40 (unchanged here, but explicitly reset)
edit 3 (IP cks):bytes 10–11 → recompute over bytes 0–19 (now src/dst swapped)
edit 4 (ICMP):  byte 20 → 00 (type reply); bytes 22–23 → recompute over bytes 20–83
```

### N.3 — The reply (84 bytes), annotated

```
off  bytes         field            value
 0   45            ver/IHL          v4 (unchanged)
 2   00 54         total length     84 (unchanged — same size)
 8   40            TTL              64
 9   01            protocol         1 = ICMP
10   <n0> <n1>     IP checksum      RECOMPUTED (src/dst changed → new value)
12   c0 a8 00 02   src              192.168.0.2 (us)   ← was dst
16   c0 a8 00 01   dst              192.168.0.1        ← was src
20   00            ICMP type        0 = Echo Reply     ← was 8
21   00            ICMP code        0
22   <m0> <m1>     ICMP checksum    RECOMPUTED (type changed → new value)
24   12 34         identifier       0x1234 (echoed)
26   00 01         sequence         1 (echoed)
28   .. (56 bytes) data             echoed verbatim
```

### N.4 — Why only two checksums changed

Changing src/dst (IP region) invalidates the **IP** checksum → recompute it. Changing the type byte
(ICMP region) invalidates the **ICMP** checksum → recompute it. The identifier, sequence, and data
are unchanged, so the pinger matches the reply to its request — which is the whole point of echoing
them. Everything in this trace is exactly what `build_echo_reply` + its test enforce.

### N.5 — Verifying the trace offline

For the produced reply: `utils::checksum(&reply[..20]) == 0` and `utils::checksum(&reply[20..]) == 0`
(both regions valid), `reply[20] == 0`, `&reply[12..16] == [192,168,0,2]`, `&reply[16..20] ==
[192,168,0,1]`, `&reply[24..] == &request[24..]`. All assertable without a network — the §G.2 triage.

---

## O. Performance of the checksum

### O.1 — It's the one O(n) step

Parsing is O(1) (fixed offsets); the checksum is O(n) in the bytes it covers — you must touch every
byte at least once. For an echo reply you checksum the 20-byte IP header plus the full ICMP message
(84 bytes here). For bulk TCP later, you'd checksum every payload byte — which is why checksumming is
the part hardware offloads (§C.6) and the part worth optimizing (§C.3 wide summation).

### O.2 — Cost in context

Per echo reply: one `to_vec` (heap copy of ~84 bytes), a few field writes, two checksum passes (~104
bytes total), one `send` syscall + copy. The syscall dominates; the checksum is a rounding error at
this size. At multi-gigabit data rates the checksum *would* matter, and you'd use wide summation and/
or offload. For a teaching stack, the naive loop is correct and fast enough by orders of magnitude.

### O.3 — Avoiding the per-reply allocation

`build_echo_reply` allocates a `Vec` each call (via `to_vec`). At high reply rates you'd reuse a
scratch buffer (mutate `buf` in place and `send` a sub-slice) to avoid heap traffic — the first
optimization you'd make if profiling showed allocation pressure. We keep the `Vec` for clarity; it's
listed in the §AE/AE-style simplifications.

### O.4 — Why we don't optimize yet

Premature optimization would obscure the learning. The naive checksum maps 1:1 to RFC 1071 and to the
math in §B/§R; a SIMD version would be faster but unreadable. The right time to optimize is when a
benchmark says so (day1 §S), not before. Knowing the *fast* forms exist (§C) is enough for now.

---

## P. Security notes — ICMP attacks Day 2 enables and defends

Building an ICMP responder is your first taste of being a network *endpoint* an attacker can poke.

### P.1 — Ping flood / echo amplification

If you reply to every echo request unconditionally (as we do), an attacker can flood you with
requests, and worse, **spoof the victim's source address** so your replies go to the victim
(reflection). On a broadcast network this becomes the classic **Smurf** amplification. Hardening: rate-
limit echo replies (e.g. token bucket per source), and don't reply to broadcast/multicast destinations.
Our stack does neither yet — a deliberate simplification and a good exercise.

### P.2 — ICMP tunneling / covert channels

Echo *data* is arbitrary and echoed verbatim — so it's a covert channel: tools like `icmptunnel`
smuggle TCP/SSH inside ping payloads to bypass firewalls that allow ICMP. As the *responder*, you'd
faithfully echo whatever you're sent. Blue-team detection: anomalous echo payload sizes/entropy/rates.
This connects Day 2 directly to your security track (you can now both build and recognize it).

### P.3 — Ping of Death / malformed input

Historically, oversized or overlapping-fragment ICMP crashed reassembly buffers. Our defense is the
same length discipline as Day 1: `build_echo_reply` guards `request.len() >= header_len + 8` before
indexing, so a runt request returns `None` instead of panicking. A reply builder that indexed blindly
would be crashable by a crafted short packet.

### P.4 — Information disclosure via replies

TTL in your replies hints at your OS; echoing data confirms reachability and timing. ICMP error
messages (if you generated them) quote the offending packet's header + 8 bytes, leaking ports/seq.
Security-sensitive hosts rate-limit and sometimes suppress ICMP for this reason — a tradeoff against
the PMTUD breakage that blocking ICMP causes (day1 §H.9).

### P.5 — The defensive checklist (carry forward)

1. **Validate before acting** — `build_echo_reply`'s type/length guards.
2. **Rate-limit responses** — don't be an amplifier (not yet implemented).
3. **Don't reply to broadcast/multicast echo.**
4. **Verify incoming checksums** — don't act on corrupt packets (exercise H.7).
5. **Fail closed** — on anything unexpected, drop and move on (our `None`/`continue` paths).

---

## Q. Day-2 self-test and the bridge to Day 3

### Q.1 — Self-test (answer cold)

1. State the three steps of the Internet checksum, then the verify rule.
2. Why a `u32` accumulator and end-around carry?
3. Why does a valid header sum to 0?
4. Two error patterns the checksum misses.
5. List the four edits that turn an echo request into a reply, in the correct order.
6. Why must each checksum be computed *after* its region's other edits?
7. Which region does the IP checksum cover? The ICMP checksum?
8. Why does the echoed data not need touching?
9. Why does a reply with a bad checksum produce the *same* symptom as no reply at all?
10. What does the TCP checksum add over IP/ICMP, and why?
11. When do you mutate-in-place vs build-from-scratch?
12. Why did Day 2 justify splitting into modules?

### Q.2 — Mastery checklist

- [ ] Re-type `utils::checksum` and `ip::write_header_checksum` from memory.
- [ ] Re-type `build_echo_reply` with the four edits in the right order.
- [ ] Compute and verify an IP checksum by hand.
- [ ] Produce the §N request→reply byte trace from a blank page.
- [ ] Make `ping` reply with 0% loss live, and confirm both packets in tcpdump.
- [ ] Explain the pseudo-header you'll need on Day 3 without looking.

### Q.3 — Bridge to Day 3

Day 1 read packets; Day 2 wrote one (a near-copy of a request). **Day 3 writes packets from
scratch** and, for the first time, keeps **state across packets**: the TCP three-way handshake. The
checksum you mastered here returns immediately — TCP's checksum is this exact function with a 12-byte
pseudo-header (§C.7, §M). The build technique (lay out bytes, checksum last, big-endian) scales from
the echo reply to a synthesized SYN-ACK. And the modular structure you refactored into is where
`tcp.rs` slots in. Everything Day 2 taught is load-bearing for Day 3.

Open `day3-book.md`. The stack grows a memory.

---

## R. Extended exercises set II (with solutions)

### R.1 — Reuse the checksum for UDP
**Q.** Sketch a UDP checksum call for a datagram us→peer with 4 data bytes.
**A.** Build `pseudo = src.octets() ++ dst.octets() ++ [0, 17] ++ (udp_len as u16).to_be_bytes()`,
then `checksum(&[pseudo, udp_header_with_field_zeroed, data].concat())`. udp_len = 8 + 4 = 12. If the
result is 0x0000, transmit 0xFFFF (two-zeros rule).

### R.2 — Detect a canceling error
**Q.** Show two single-byte changes to a header that the checksum will NOT catch.
**A.** Add 1 to one 16-bit word and subtract 1 from another (e.g. byte 5 +1, byte 7 −1 within
different words such that the mod-65535 sum is unchanged). The sum is identical → checksum unchanged →
undetected. This is the §B.4 weakness made concrete.

### R.3 — Round-trip property test
**Q.** Write a property: for any 20-byte header, writing then verifying the checksum yields 0.
**A.** `proptest!(|(h: [u8;20])| { let mut h = h; ip::write_header_checksum(&mut h); assert_eq!(utils::
checksum(&h), 0); })`. Holds for *every* input by §R.5.

### R.4 — Why does the ICMP reply preserve total length?
**A.** Echo reply carries the same data as the request, so the packet size is identical; we don't
touch bytes 2–3. (If you *changed* the data length, you'd have to update Total Length and the IP
checksum.)

### R.5 — Build an ICMP echo *request* (originate)
**A.** See day1 §AX: 20-byte IP header (proto 1, your src/dst) + 8-byte ICMP (type 8, id, seq),
IP checksum then ICMP checksum, both with field zeroed first. Sending it makes you a ping *client*.

### R.6 — What if you forget to swap addresses?
**A.** The reply is addressed `192.168.0.2 → 192.168.0.2` (or unchanged `…→…0.2`); the kernel won't
route it to the pinger, so ping still shows loss even with valid checksums. (§G.1 cause #6.)

### R.7 — Incremental-update a TTL decrement
**Q.** Header checksum `0xB86A`, a router decrements TTL changing the word `0x4001`→`0x3F01`. New
checksum?
**A.** `new = ~(~0xB86A + ~0x4001 + 0x3F01)` (one's-complement). `~0xB86A=0x4795`, `~0x4001=0xBFFE`;
`0x4795+0xBFFE=0x10793`→ fold `0x0793+1=0x0794`; `+0x3F01=0x4695`; `~0x4695=0xB96A`. (TTL down by 1 →
checksum up by 1 in this field's position — sanity-checkable.)

### R.8 — Verify "two zeros" handling
**Q.** What does `checksum` return for 16 bytes of `0xFF`?
**A.** Eight words of `0xFFFF`. Sum = 8×0xFFFF = 0x7FFF8; fold: 0xFFF8 + 0x7 = 0xFFFF; `~0xFFFF =
0x0000`. So all-ones data → checksum 0x0000 (the +0 zero), consistent and unambiguous.

### R.9 — Minimal reply size
**Q.** Smallest echo request `build_echo_reply` accepts?
**A.** `header_len + 8` bytes (20 + 8 = 28): a 20-byte IP header + an 8-byte ICMP header with no data.
Anything shorter → `None`.

### R.10 — Why `Option`, not `Result`, for `build_echo_reply`?
**A.** The only failure is "not a well-formed echo request" — one reason. `Option`/`None` matches the
shape; a `Result` with a single error variant would add noise (day1 §G.7–G.8).

## S. The history of ping and ICMP

- **ICMP** was specified in **RFC 792 (1981)** alongside IP, by Jon Postel — the internet's built-in
  diagnostic/error channel from the start.
- **`ping`** was written by **Mike Muuss in 1983** in a single evening, named after sonar (send a
  pulse, listen for the echo). It's one of the most-used network tools ever, and its source is a
  classic. The "64 bytes from…" output format is Muuss's.
- **`traceroute`** (Van Jacobson, 1987) layered the TTL trick (§day1 H.5) on top of ICMP Time
  Exceeded — using an *error* mechanism as a *measurement* tool, an enduringly clever idea.
- ICMP's role *grew* in IPv6 (RFC 4443 + Neighbor Discovery), absorbing ARP's job — so "block all
  ICMP" went from bad IPv4 advice to network-breaking on IPv6.
- The deprecations (Source Quench, RFC 6633) and additions (extended messages, RFC 4884) show a
  protocol that's been pruned and grown over 40 years but whose core — echo and error reporting —
  is exactly what you implemented.

The takeaway: you reimplemented a 1981 protocol and a 1983 tool, and they still run the modern
internet's diagnostics largely unchanged. That longevity is the payoff of the simple, layered design
you're learning.

## T. How real stacks build replies (comparison)

| Aspect | Our stack | Linux / production |
|---|---|---|
| Reply buffer | `Vec` via `to_vec` per reply | pre-allocated `sk_buff` from a pool; often clone-and-modify the request skb |
| Address swap | copy octets via temporaries | swap header pointers/fields in the skb in place |
| Checksum | software `utils::checksum` | NIC offload (hardware) or optimized SIMD when in software |
| Rate limiting | none | ICMP rate limit (`net.ipv4.icmp_ratelimit`) to resist floods |
| Broadcast echo | would reply (bug) | `icmp_echo_ignore_broadcasts=1` by default — won't amplify |
| Validation | length + (exercise) checksum | full checksum + sanity checks before responding |
| Which requests answered | all type-8 | configurable (`icmp_echo_ignore_all` can disable ping) |

The shapes are the same — receive, validate, build a reply, checksum, send — but production adds
buffer reuse, hardware offload, rate limiting, and policy knobs. Our version is the legible core those
optimizations wrap. Reading Linux's `net/ipv4/icmp.c` (`icmp_echo` / `icmp_reply`) after this is
illuminating: you'll recognize the structure immediately.

## U. Final Day-2 reference tables

### U.1 — Checksum facts at a glance
| Question | Answer |
|---|---|
| Algorithm | one's-complement 16-bit sum, then NOT |
| Accumulator width | u32 (hold carries), fold at end |
| Odd byte | becomes the high byte (`<<8`) |
| Verify | re-sum incl. field → 0 |
| IP covers | header only |
| ICMP covers | whole message, no pseudo-header |
| TCP/UDP covers | pseudo-header + segment |
| Field zeroed first? | always |
| Endianness | big-endian words; result big-endian |

### U.2 — Echo reply construction quick card
```
reply = request.to_vec()
swap reply[12..16] <-> reply[16..20]      # addresses
reply[8] = 64                              # TTL
zero reply[10..12]; reply[10..12] = checksum(reply[..ihl*4])    # IP cksum
reply[ihl*4] = 0                           # ICMP type -> reply
zero reply[ihl*4+2 .. ihl*4+4]; that = checksum(reply[ihl*4..]) # ICMP cksum
send(reply)
```

### U.3 — Symptom → cause (Day 2)
| Symptom | Cause |
|---|---|
| ping still 100% loss, reply seen in tcpdump | bad checksum |
| ping loss, no reply in tcpdump | didn't send / send errored |
| checksum "incorrect" in Wireshark (TUN) | real bug (no offload on TUN) |
| reply present, valid cksum, still loss | addresses/id/seq wrong |
| panic on a short ping | missing length guard |

---

## V. The kernel's role in delivering our reply

When we `iface.send(reply)`, a lot happens on the kernel side before `ping` prints its line.

### V.1 — Injection
`write(tun_fd, reply)` copies our bytes into the kernel and the TUN driver presents them to the IP
receive path as a packet that *arrived on* tun0. From the kernel's perspective there's no difference
between "a packet came in off a wire" and "a userspace process wrote one to the TUN fd" — that
symmetry is the entire trick that lets us be the peer.

### V.2 — Receive processing
The kernel runs its normal ingress: verify the IP header (version, IHL, **checksum** — this is where
a bad checksum dies), check the destination is local (192.168.0.1 is the host's tun0 address), read
the protocol (1 = ICMP), and hand it to the kernel's ICMP code.

### V.3 — ICMP matching
The kernel's ICMP layer sees type 0 (echo reply), validates the **ICMP checksum**, and matches it to
an outstanding echo request by **identifier** (the `ping` process registered its id). It then delivers
the reply to that `ping` socket.

### V.4 — ping computes the result
`ping` reads the reply, extracts the timestamp it embedded in the request's data (echoed back),
computes RTT = now − timestamp, confirms the sequence number, and prints `64 bytes from 192.168.0.2:
icmp_seq=1 ttl=64 time=0.2 ms`. Loss for that seq → 0%.

### V.5 — Where each of our fields is checked
- **IP checksum** → kernel ingress (V.2). Wrong ⇒ silent drop.
- **dst address** → must be local, else not delivered to us. (We set it to the pinger.)
- **protocol = 1** → routes to ICMP code.
- **ICMP checksum** → ICMP layer (V.3). Wrong ⇒ drop.
- **type = 0** → recognized as a reply.
- **identifier** → matches the request to *this* ping process.
- **sequence** → loss/RTT accounting.
- **echoed data/timestamp** → RTT computation.
Every field we set or preserved has a consumer on the other side. That's why each one matters and why
getting any wrong makes the reply useless even if "sent."

### V.6 — The mirror with day1 §F
Day-1 §F traced packet *in* (kernel → our recv). This is packet *out* (our send → kernel → ping).
Together they're the full duplex of "bytes in, bytes out" — the definition of a stack from Volume I
§1, now realized in both directions.

## W. Day 2 in 80 facts (rapid review)

1. Day 2 = the write half of "bytes in, bytes out."
2. The Internet checksum (RFC 1071) is the centerpiece.
3. It detects corruption; it does not correct it.
4. It's deliberately weak and fast (end-to-end principle).
5. Algorithm: sum 16-bit BE words, fold carries, bitwise NOT.
6. Accumulator is u32 to hold carries.
7. Odd trailing byte becomes the high byte (`<<8`).
8. End-around carry = add overflow back into the low bit.
9. That makes it addition modulo 2¹⁶−1.
10. One's complement has two zeros: +0 (0x0000), −0 (0xFFFF).
11. A valid region re-sums (incl. field) to 0xFFFF → complement 0.
12. So "verify" = run checksum over data incl. field, expect 0.
13. Zero the checksum field before computing.
14. Write the result big-endian (`to_be_bytes`).
15. IP checksum covers the IP header only.
16. ICMP checksum covers the whole ICMP message.
17. ICMP has no pseudo-header.
18. TCP/UDP checksums add a 12-byte pseudo-header.
19. Pseudo-header = src IP, dst IP, 0, protocol, transport length.
20. The pseudo-header binds the checksum to the addresses.
21. The pseudo-header is never transmitted.
22. UDP checksum is optional in IPv4; 0x0000 = "not computed."
23. A computed UDP zero is sent as 0xFFFF (two-zeros trick).
24. TCP checksum is mandatory.
25. Parity catches odd flips only; CRC is stronger; the Internet checksum is in between (weak).
26. Ethernet uses CRC-32 (hardware); IP uses the 1's-comp checksum.
27. The checksum misses canceling errors and word reorderings.
28. Reordering invisibility comes from addition's commutativity.
29. Routers can incrementally update the checksum (RFC 1624), O(1).
30. Incremental update works because addition is associative.
31. NICs offload checksums in hardware.
32. On TUN there's no offload → software checksum.
33. Wireshark may flag offloaded outgoing checksums as "bad" (red herring on real NICs).
34. On TUN a red checksum is a real bug.
35. Day 2's milestone: ping replies, 0% loss.
36. Echo Reply = ICMP type 0; Echo Request = type 8.
37. We build the reply by mutating a copy of the request.
38. Mutate-in-place: cheap, fewer bugs, data echoes for free.
39. Build-from-scratch: for responses with no matching request (Day 3 SYN-ACK).
40. The four edits: swap addrs, TTL, IP checksum, type+ICMP checksum.
41. Edit order: change fields first, checksum last (per region).
42. A checksum computed before a later edit is stale → drop.
43. Swap src↔dst so the reply goes back to the pinger.
44. Reset TTL to 64 on the reply.
45. Recompute IP checksum (addresses changed).
46. Set ICMP type 8→0.
47. Recompute ICMP checksum (type changed).
48. id/seq/data are echoed unchanged.
49. The pinger matches the reply by identifier and sequence.
50. RTT = now − echoed timestamp (in the data).
51. A bad checksum is dropped silently — no error from send.
52. So "sent but ping still loss" ⇒ suspect the checksum.
53. Verify checksums offline (cargo test) — don't trust the live run.
54. `iface.send` = `write(tun_fd, bytes)`.
55. The kernel treats it as a packet arriving on tun0.
56. The kernel verifies IP + ICMP checksums on ingress.
57. Day 2 split main.rs into utils/ip/icmp modules.
58. `mod X;` compiles src/X.rs; undeclared files aren't compiled.
59. `use crate::utils` etc. are the dependency edges.
60. Dependency graph: utils ← ip ← icmp; main on top; acyclic.
61. The graph mirrors the protocol stack.
62. `pub` marks the cross-module API surface.
63. Tests live in each module (`#[cfg(test)]`), can see privates.
64. Refactor was behavior-preserving (Day-1 tests still green).
65. Split happened at the "2+ callers" threshold.
66. `utils::checksum` is reused by ip, icmp (and later tcp).
67. "Reuse physically" = import one function, don't copy-paste.
68. `ip::write_header_checksum` zeroes the field, sums, writes BE.
69. `build_echo_reply` returns Option (one failure mode).
70. It guards `len >= header_len + 8` before indexing.
71. It returns None for non-type-8 (won't reply to replies/errors).
72. Address swap uses temporaries to avoid borrow-of-self overlap.
73. Ping was written by Mike Muuss in 1983, named after sonar.
74. ICMP is RFC 792 (1981), by Jon Postel.
75. Traceroute (1987) reuses ICMP Time Exceeded.
76. Unconditional echo replies enable ping floods / Smurf amplification.
77. Hardening: rate-limit replies, ignore broadcast echo.
78. ICMP data is arbitrary → covert channels (icmptunnel).
79. Length guards prevent Ping-of-Death-style crashes.
80. Day 2's checksum + build technique carry directly into Day 3's TCP.

## X. Day-2 mastery checklist

- [ ] Re-type `utils::checksum`; explain u32, fold, odd-byte, NOT.
- [ ] State and use the verify-to-zero property.
- [ ] Compute an IP checksum by hand and verify it.
- [ ] Re-type `ip::write_header_checksum` (zero-first, BE-write).
- [ ] Re-type `build_echo_reply`: four edits, correct order, two regions.
- [ ] Explain why each checksum covers the range it does.
- [ ] Produce the §N request→reply byte trace cold.
- [ ] Explain the pseudo-header and why TCP/UDP need it.
- [ ] Make ping reply 0% loss live; confirm both packets in tcpdump.
- [ ] Name two errors the checksum can't catch, and why.
- [ ] Explain the silent-drop symptom of a bad checksum.
- [ ] Reproduce the module dependency graph from memory.

When every box is checked, Day 2 is owned.

---

## Y. Detection vs recovery — where the checksum sits in reliability

The checksum is half of a story the rest of the project completes. Understanding the split clarifies
what Day 2 does and doesn't give you.

### Y.1 — Detection ≠ recovery
The checksum **detects** corruption and the receiver **drops** the bad packet. That's it. Nothing
about the checksum *recovers* the lost data — the corrupted packet is simply gone. Detection is
necessary but not sufficient for reliability.

### Y.2 — Who recovers?
- **ICMP/UDP: nobody.** A dropped echo reply just means `ping` records a loss for that sequence; a
  dropped UDP datagram is gone unless the application resends. There is no automatic recovery.
- **TCP: retransmission.** TCP detects the loss (a missing ACK / duplicate ACKs) and **resends** the
  data. This is the reliability machinery of the day-5 roadmap, and it's *built on top of* detection:
  the checksum drops corrupt segments; the ACK/timer logic notices they didn't arrive and resends.

### Y.3 — The layered division of labor
- **Link layer (CRC):** strong per-hop detection; drops corrupt frames.
- **IP checksum:** detects header corruption end-to-end; drops the packet.
- **TCP/UDP checksum:** detects transport+data corruption end-to-end; drops the segment.
- **TCP retransmission:** *recovers* from any drop (corruption-caused or congestion-caused).
Each layer detects; only TCP recovers. Day 2 gave you detection (the checksum). Days 3–5 + the
roadmap give you recovery (sequence numbers, ACKs, timers). Seeing this now means the retransmission
work later reads as "the recovery half of what the checksum started."

### Y.4 — Why detection must come first
You can't recover from a loss you didn't notice, and you can't trust data you didn't verify. So the
checksum (and the drop-on-mismatch) is the foundation; reliability is layered on top. That ordering —
verify, then recover — is why this project does checksums (Day 2) before reliable delivery (later).

## Z. Worked ICMP checksum for our echo reply

The IP checksum was worked in §H.1/§4 of day2 and day1 §R; here's the ICMP side, which people skip.

### Z.1 — The ICMP message to checksum
A minimal 8-byte echo reply ICMP (no data): `00 00 00 00 12 34 00 01` — type 0, code 0, checksum 0
(field zeroed), id 0x1234, seq 0x0001.

### Z.2 — The computation
Words: `0x0000`, `0x0000` (the zeroed checksum field), `0x1234`, `0x0001`.
Sum = 0x0000 + 0x0000 + 0x1234 + 0x0001 = `0x1235`. No carry above 16 bits.
Checksum = `~0x1235 = 0xEDCA`.
So bytes 2–3 become `ED CA`.

### Z.3 — Verify
Re-sum with the field set: `0x0000 + 0xEDCA + 0x1234 + 0x0001 = 0xFFFF` → `~0xFFFF = 0`. Valid. ✓

### Z.4 — With real ping data
A real reply has 56 data bytes too; you'd sum all of them (28 words for the 56 data bytes + the 4
header words), fold, NOT. The principle is identical — just more words. The point of Z.1–Z.3 is to
see the arithmetic on a tiny, checkable message: type/code contribute 0x0000, id/seq contribute, the
field is zeroed during compute and set after.

### Z.5 — Why type 8 vs 0 changes the checksum
Echo request has type byte 0x08 (word `0x0800` with code), reply has 0x00 (word `0x0000`). That
0x0800 difference shifts the sum by 0x0800, so the reply's checksum differs from the request's by a
corresponding amount. This is exactly why flipping the type *requires* recomputing the ICMP checksum
(edit 4) — change the input, change the output.

## AA. Common Day-2 mistakes gallery

Ten real mistakes, each with the giveaway symptom.

1. **Forgot to zero the checksum field** → checksum includes its own old value → invalid. *Symptom:*
   reply dropped; offline `checksum(region) != 0`.
2. **Checksummed the wrong range** (whole packet for IP, header-only for ICMP) → invalid. *Symptom:*
   one region verifies, the other doesn't.
3. **Computed checksum before editing a field it covers** → stale. *Symptom:* changing TTL/type after
   the checksum.
4. **Wrote the result little-endian** → byte-swapped checksum. *Symptom:* off-by-byte-swap value.
5. **Didn't swap addresses** → reply addressed to self. *Symptom:* valid checksums, still 100% loss.
6. **Swapped addresses but forgot to recompute the IP checksum** → invalid IP header. *Symptom:* IP
   checksum nonzero.
7. **Used `Iface::new`** (PI header) → offsets shifted → you mutate the wrong bytes. *Symptom:*
   garbage reply / version-0 parse.
8. **Replied to non-echo-requests** (type 3/11) → loops or nonsense. *Symptom:* storms of replies.
9. **Indexed without the length guard** → panic on a short request. *Symptom:* crash.
10. **Allocated/!sent** — built the reply but forgot `iface.send`. *Symptom:* no reply line in
    tcpdump.

Each maps to a §G triage step. The meta-lesson (again): build the offline test that asserts type,
addresses, and both checksums — it catches 1–6 and 9 instantly, before you ever touch the wire.

## AB. Day-2 RFC index and acronyms

### AB.1 — RFCs for Day 2
| RFC | Title | Relevance |
|-----|-------|-----------|
| 1071 | Computing the Internet Checksum | the algorithm + worked examples |
| 1624 | Incremental Updating of the Internet Checksum | router O(1) update |
| 792 | ICMP | echo request/reply format |
| 768 | UDP | the optional-checksum / two-zeros rule |
| 9293 | TCP | the pseudo-header checksum (preview) |
| 1141 | Incremental checksum (obsoleted by 1624) | historical |

### AB.2 — Day-2 acronyms
- **CRC** Cyclic Redundancy Check · **ECC/FEC** Error-Correcting Code / Forward Error Correction ·
  **ICMP** Internet Control Message Protocol · **RTT** Round-Trip Time · **TLV** Type-Length-Value ·
  **NIC** Network Interface Card · **GSO/TSO** Generic/TCP Segmentation Offload · **PI** Packet
  Information (the TUN header) · **MSS** Maximum Segment Size (preview).

---

## AC. Checksum strength — a probability analysis

How good *is* the Internet checksum? Quantifying it shows why it's "good enough end-to-end" but not a
strong guarantee.

### AC.1 — Undetected-error probability for random corruption
The checksum is 16 bits. If corruption is *random* (each possible corrupted value equally likely),
the probability that a corrupted packet happens to produce the *same* 16-bit checksum is ≈ 1/2¹⁶ =
**1/65,536 ≈ 0.0015%**. So roughly 1 in 65,536 random corruptions slips through undetected at this
layer. That sounds rare, but at billions of packets it's non-trivial — which is why stronger checks
(CRC at L2) and recovery (TCP retransmit) exist around it.

### AC.2 — But corruption isn't random
Real-world bit errors are often *structured* (a stuck bit, a byte swap, a buffer mis-copy), and here
the checksum has known blind spots (§B.4):
- **Reordering whole 16-bit words** → sum unchanged → **always missed**.
- **Canceling changes** (+1 in one word, −1 in another) → sum unchanged → **always missed**.
- **A 16-bit word changed to its complement-pair** in a canceling way → missed.
So the *practical* miss rate for some structured errors is 100%, not 1/65536. This is the precise
sense in which it's "weak": strong against random noise, blind to specific structured faults.

### AC.3 — Why this is acceptable
Three reasons: (1) the link layer's **CRC-32** already catches essentially all transmission-induced
errors per hop (CRC catches all bursts ≤ 32 bits and reorderings); (2) TCP **retransmits** anything
lost for any reason; (3) the Internet checksum's job is a cheap *end-to-end* sanity check for the
errors the lower layers can't see (e.g. router memory corruption), not a cryptographic or
comprehensive guarantee. Defense in depth: weak-but-end-to-end + strong-but-per-hop + recovery.

### AC.4 — When it's not enough
For adversarial tampering it's useless (an attacker recomputes it trivially) — that's TLS/HMAC's job.
For high-integrity storage/transmission you'd use CRC or ECC. The lesson: match the check to the
threat. The Internet checksum is tuned for *cheap detection of accidental, lower-layer-invisible
corruption*, and it's optimal for exactly that niche.

### AC.5 — Stronger alternatives' costs
| Check | Bits | Undetected (random) | Reorder-safe? | Cost |
|-------|------|---------------------|---------------|------|
| Internet checksum | 16 | ~1/65,536 | no | ~free |
| Fletcher-16 | 16 | ~1/65,536 but position-sensitive | yes | low |
| CRC-16 | 16 | ~1/65,536, all bursts ≤16 | yes | table/HW |
| CRC-32 | 32 | ~1/4·10⁹, all bursts ≤32 | yes | table/HW |
The Internet checksum trades reorder-safety for the endianness-independence and incremental-update
properties only one's-complement gives — a conscious 1981 design choice.

## AD. The Day-2 reference card (one screen)

```
INTERNET CHECKSUM (RFC 1071)
  compute:  sum 16-bit BE words into u32; +odd byte<<8; fold carries; !low16
  verify:   checksum(region incl. field) == 0
  field=0 before compute; write result big-endian
COVERAGE
  IPv4   : header only            (bytes 10-11)   no pseudo-header
  ICMP   : whole message          (bytes 2-3)     no pseudo-header
  TCP/UDP: pseudo-hdr + segment    (16-17 / 6-7)   pseudo-header REQUIRED
  pseudo-header (12B): srcIP dstIP 0 proto len  (input only, not sent)
  UDP: checksum optional in IPv4 (0=none; computed-0 sent as 0xFFFF)
ECHO REPLY (mutate the request)
  1 swap src/dst (12-19)   2 TTL=64 (8)
  3 IP cksum (10-11)        4 type 8->0 (hl) + ICMP cksum (hl+2..hl+4)
  order: edit fields THEN checksum, per region
SEND
  iface.send(&reply) = write(tun_fd); kernel verifies cksums, drops if bad (silent)
SYMPTOM->CAUSE
  reply seen, ping loss  -> bad checksum
  no reply seen          -> didn't send
  valid cksum, ping loss -> addresses/id/seq wrong
MODULES
  utils(checksum) <- ip <- icmp ; main on top ; pub = API ; tests per file
```

## AE. Clean-architecture principles this refactor demonstrates

The Day-2 module split is a small but real lesson in structuring code.

### AE.1 — Single responsibility
Each module does one thing: `utils` = the checksum primitive; `ip` = IPv4 header concerns; `icmp` =
ICMP concerns. A function's home is decided by *what concept it belongs to*, not by what happens to
call it. `write_header_checksum` lives in `ip` (it's about the IP header) even though `icmp` calls it.

### AE.2 — Dependencies point toward stability
`utils` (the most stable, general primitive) depends on nothing; volatile, specific code (`icmp`)
depends on it, not vice versa. This "stable dependencies" direction means a change in `icmp` never
forces a change in `utils`. The acyclic graph (§L.3) encodes it.

### AE.3 — Encapsulation via `pub`
Only the intended API is `pub`; internals stay private. Callers can't depend on internals they
shouldn't, so you can refactor a module's guts without breaking others. The compiler enforces the
boundary.

### AE.4 — Tests as a safety net for refactoring
Because every module ships tests, the Day-1→Day-2 refactor (moving parse code into modules) was
provably behavior-preserving: move code, run `cargo test`, green = safe. Refactoring without tests is
guessing; with them it's mechanical.

### AE.5 — Refactor at the right time
Day 1 had one caller → one file (no premature structure). Day 2's second caller crossed the threshold
→ split. "Refactor when duplication/▽callers appear, not before" avoids both copy-paste rot and
speculative over-engineering. The codebase's structure tracks its actual needs.

### AE.6 — Why this matters for a stack specifically
A TCP stack grows to many interacting pieces (IP, ICMP, TCP, timers, buffers). Without clean module
boundaries it becomes an unmaintainable tangle (real stacks that skipped this are infamous). Starting
the discipline now, at 4 small modules, means it scales as `tcp.rs` and the event loop arrive.

## AF. Testing the reply — beyond the unit test

### AF.1 — What the unit test proves
`reply_is_well_formed` proves the *bytes* are correct: type, addresses, both checksums verify, payload
echoed. This is necessary and catches almost everything.

### AF.2 — What it doesn't prove
It doesn't prove the *kernel/peer accepts* it (delivery), or that timing/ordering is right, or that
you handle weird inputs (a fragmented ping, a ping with options, a huge ping). Those need integration
and property/fuzz testing.

### AF.3 — Property tests for Day 2
- *Reply preserves payload:* for any echo request, `build_echo_reply` returns a packet whose data
  region equals the request's.
- *Reply checksums valid:* for any echo request, both regions of the reply verify to 0.
- *Idempotent addresses:* swapping twice returns the original (a sanity check on the swap).
- *Rejects non-echo:* for any request with type ≠ 8, returns `None`.

### AF.4 — Fuzzing `build_echo_reply`
Feed random byte strings as "requests"; assert it never panics and never returns a packet with an
invalid checksum. The length guard is what makes it pass on short/garbage input. This is the same
hardening step as the parser (day1 §U.3), applied to the builder.

### AF.5 — Live conformance with packetdrill
Script: inject an echo request, expect an echo reply with swapped addresses, type 0, valid checksums.
packetdrill asserts the exact response bytes — RFC-conformance for your reply path, deterministically.

---

## AG. Day 2 and the security track, in depth

Building an ICMP responder puts you on both sides of several real techniques.

### AG.1 — As an attacker's target (what you'd defend)
Your unconditional echo responder is, as shipped, a small liability: it answers every request, so it
can be used for **host discovery** (an attacker pings a range to find live hosts — `nmap -sn`), for
**amplification/reflection** if it answered broadcast or if source addresses are spoofed, and as a
**timing oracle** (RTT leaks load/distance). Defenses you'd add: rate-limit replies, ignore
broadcast/multicast, optionally don't reply at all (stealth), and never reply to spoofed-looking
broadcast sources.

### AG.2 — As an attacker's tool (what you could build)
The same `build_*` skill builds offensive packets: a **ping sweep** scanner (send echo requests
across a subnet, map who replies), a **covert channel** (stuff data in echo payloads —
`icmptunnel`-style), or **OS fingerprinting** (TTL and ICMP quirks differ by OS). Crafting packets is
the core red-team primitive, and you now have it.

### AG.3 — IDS/IPS perspective (blue team)
Snort/Suricata are, at their core, fast packet parsers (exactly what you built) plus a rule engine.
A rule like "alert on > N ICMP echo requests/sec from one source" detects ping sweeps; "alert on echo
payload entropy > X or size anomaly" flags tunneling. Your parsing skill *is* the IDS's core skill;
the difference is scale and a rule language on top.

### AG.4 — Concrete tooling to explore
- `nmap -sn 192.168.0.0/24` — ping sweep (watch it in your tcpdump).
- `hping3 --icmp --flood 192.168.0.2` — ICMP flood (test your rate-limiting once you add it).
- `scapy`: `sr1(IP(dst="192.168.0.2")/ICMP())` — craft/inspect a single echo and its reply.
- Reading: Snort's ICMP preprocessor; the Smurf/Ping-of-Death CVE writeups.

### AG.5 — The mindset transfer
Day 1 taught "a parser is a trust boundary." Day 2 adds "a *responder* is an attack surface": every
packet you emit can be observed, abused (amplification), or fingerprinted. Designing responders that
are correct *and* hard to abuse (validate, rate-limit, fail closed) is the security-engineering
discipline this project is quietly teaching. Both red and blue start from the byte-level fluency you
now have.

## AH. Worked-checksum gallery II

Five more, varied, to build speed. Cover the answer; compute.

### AH.1 — A header with options (IHL 6)
**Q.** Checksum the words `4600 0030 1234 4000 4006 0000 c0a8 0001 0808 0808 0102 0304` (a 24-byte
header, field zeroed)?
**A.** Sum: 4600+0030=4630; +1234=5864; +4000=9864; +4006=D86A; +0000=D86A; +C0A8=19912; fold low
0x9912+1=0x9913; +0001=9914; +0808=A11C; +0808=A924; +0102=AA26; +0304=AD2A. Sum 0xAD2A, no high
carry. `~0xAD2A = 0x52D5`. (24-byte header = 12 words; IHL 6 means 4 option bytes, summed like any
words.)

### AH.2 — All-zero data
**Q.** `checksum(&[0,0,0,0])`?
**A.** Sum 0; `~0 = 0xFFFF`. (The −0 representation — a valid "sum is zero".)

### AH.3 — One word, max
**Q.** `checksum(&[0xFF, 0xFF])`?
**A.** Sum 0xFFFF; no fold; `~0xFFFF = 0x0000`.

### AH.4 — Triggering a fold
**Q.** `checksum(&[0xFF,0xFF, 0x00,0x02])`?
**A.** 0xFFFF + 0x0002 = 0x10001; fold: 0x0001 + 0x1 = 0x0002; `~0x0002 = 0xFFFD`.

### AH.5 — The verify check
**Q.** For AH.4's data with `0xFFFD` appended as a field-region, does it verify?
**A.** 0xFFFF + 0x0002 + 0xFFFD = 0x1FFFE; fold 0xFFFE + 0x1 = 0xFFFF; `~0xFFFF = 0`. ✓ Verifies.

These five exercise: options-length headers, the −0 case, a single max word, carry folding, and
verification. If all five are easy, the checksum is genuinely yours.

## AI. Mini-project — build your own `ping` (uses all of Day 1 + Day 2)

A satisfying capstone that proves you can both *originate* and *parse*. Outline (you write the core).

### AI.1 — What it does
Send ICMP echo requests to a target on `tun0`, parse the replies, and print `seq`, `ttl`, and `RTT` —
your own `ping`. (Target a real host on a real interface for replies, or have a second instance of
your stack reply.)

### AI.2 — The pieces you already have
- **Build an echo request** (day1 §AX, day2 §R.5): IP header (proto 1, your src, target dst) + ICMP
  (type 8, id = your pid, seq = counter, a timestamp in the data), both checksums.
- **Send** it via `iface.send`.
- **Parse** the reply (day1 §E, §10): IP header → protocol 1 → ICMP → type 0, matching id/seq.
- **Checksum** (`utils::checksum`) to build and to validate.

### AI.3 — The new glue
- A **timestamp**: write `Instant::now()` (or epoch nanos) into the request's data bytes; on the
  reply, read it back and compute RTT = now − that.
- A **sequence counter** incremented per request.
- A **loop** sending one request per second, printing each reply (or "timeout" if none in 1s — which
  needs the non-blocking/timeout pattern, a nice motivation for the event loop, day1 §AI).

### AI.4 — Why it's the right exercise here
It uses *every* Day-1/Day-2 skill at once — parse, build, checksum (both directions), send, recv — and
nothing from Day 3+. Completing it means the foundation is solid before TCP's complexity. It's also
genuinely useful and a great portfolio artifact ("I wrote ping from scratch over a userspace stack").

### AI.5 — Stretch goals
- Match the real ping output format exactly.
- Compute min/avg/max/mdev RTT and loss % over N pings.
- Add `-c count` and `-i interval` flags.
- Handle ICMP errors (type 3/11) targeting your request (print "host unreachable" / "ttl exceeded").
- Implement a tiny traceroute by sending increasing-TTL requests and reading Time Exceeded.

---

## AJ. Day-2 FAQ II (deeper questions)

**1. Could I compute the checksum left-to-right or right-to-left — does order matter?** No — addition
is commutative/associative (§B.4), so any order/grouping gives the same result. That's also why
SIMD/wide summation is valid.

**2. Why not just use a stronger checksum like CRC for IP?** CRC isn't endianness-independent or
incrementally updatable cheaply, and it needs a table or hardware. The 1's-comp checksum was chosen
for 1981 CPUs and router updatability. Ethernet uses CRC where hardware does it for free.

**3. If the checksum is so weak, why trust the internet?** You don't trust it alone — link CRC
(strong, per-hop) + this (end-to-end sanity) + TCP retransmission (recovery) + TLS (vs attackers)
layer up. Defense in depth.

**4. What's the difference between the IP checksum and the TCP checksum besides range?** TCP includes
a 12-byte pseudo-header (src/dst IP, proto, length) so the checksum is bound to the addresses; IP's
covers only its own header.

**5. Why does UDP allow a zero checksum but TCP doesn't?** Historical/performance: UDP is "best
effort," so IPv4 made its checksum optional (0 = none). TCP is reliable, so it's mandatory. IPv6
makes even UDP's mandatory.

**6. When I change the type from 8 to 0, why does the checksum change by a predictable amount?**
Because the sum changes by exactly the difference in that word (0x0800 → 0x0000), and the checksum is
the complement of the sum. Incremental-update (§C.5) exploits this.

**7. Why recompute the IP checksum when I only swapped addresses, not the length?** The checksum
covers *all* header bytes including the addresses; changing any byte invalidates it.

**8. Is the pseudo-header sent on the wire?** No — it's input to the checksum only. The receiver
reconstructs it from the IP header it already has.

**9. Does `iface.send` compute any checksum for me?** No — on TUN there's no NIC offload; you compute
all checksums in software. (On a real NIC, offload might.)

**10. Why is my checksum off by a byte-swap?** You wrote it with `to_ne_bytes`/wrong order instead of
`to_be_bytes`. Wire is big-endian on write too.

**11. Can two different packets have the same checksum?** Yes (only 2¹⁶ values) — that's the ~1/65536
collision rate (§AC.1) and why it's weak.

**12. Why does the reply preserve id and seq?** So the *pinger* can match the reply to the specific
request it sent (and compute RTT/loss). They're the correlation key.

**13. What if the request had IP options (IHL > 5)?** `header_len = IHL×4` handles it; the ICMP
message still starts at `header_len`, and the IP checksum covers the longer header. Our code is
correct for options because it never hardcodes 20.

**14. Could I reply from a different source address than the request's destination?** You could, but
the pinger expects the reply's source to be the address it pinged; a mismatch confuses it. We use the
request's destination (us) as the reply's source.

**15. Why u16 for the checksum return but u32 internally?** Internally we need room for carries; the
final folded, complemented value fits in 16 bits (the field width).

**16. Is there a checksum over the IP *payload*?** Not by IP — IP only checksums its header. The
payload's integrity is the transport's job (TCP/UDP/ICMP checksums).

**17. What happens if I send a reply with total_length wrong?** Receivers may truncate or drop;
some checksums (TCP/UDP, which include length in the pseudo-header) would also fail. Keep
total_length consistent with the actual bytes.

**18. Why does the kernel, not us, match the reply to ping?** Because `ping` is a normal process with
an ICMP socket; the kernel demultiplexes by ICMP id to the right socket. We're just the peer that
produced the reply.

**19. Could I implement Day 2 without modules?** Yes, but with two callers of IP/checksum logic the
single file would duplicate or tangle; modules keep it clean (§AE).

**20. What's the very next new concept in Day 3?** State across packets (the TCB) and building a
packet from scratch (the SYN-ACK) — plus the TCP checksum, which is this checksum + a pseudo-header.

## AK. Day 2 — deeper facts (81–150)

81. The checksum's weakness and speed both come from addition being commutative.
82. CRC-32 catches all burst errors up to 32 bits; the Internet checksum doesn't.
83. Ethernet's FCS is a CRC-32 computed by the NIC.
84. A packet is covered by L2 CRC (per hop) and L3/L4 checksum (end to end).
85. The end-to-end checksum catches in-router (post-CRC) corruption.
86. One's-complement addition = addition mod 2¹⁶−1.
87. There are two zeros: 0x0000 (+0) and 0xFFFF (−0).
88. A valid region sums to 0xFFFF (−0), complemented to 0x0000.
89. UDP sends a computed-zero checksum as 0xFFFF to disambiguate.
90. IPv6 dropped the IP header checksum entirely.
91. IPv6 makes the UDP checksum mandatory.
92. Routers use incremental update (RFC 1624) to avoid re-summing.
93. Incremental update is O(1); full recompute is O(header).
94. Hardware checksum offload moves the work to the NIC.
95. Wireshark may show offloaded outgoing checksums as "bad" (a non-bug on real NICs).
96. On TUN there is no offload; a bad checksum is a real bug.
97. The IP checksum field is bytes 10–11; ICMP's is bytes 2–3.
98. TCP's checksum field is bytes 16–17; UDP's is bytes 6–7.
99. The pseudo-header is 12 bytes: srcIP, dstIP, 0, proto, length.
100. The pseudo-header binds the transport checksum to the IP addresses.
101. Echo reply = mutate the request (swap, TTL, two checksums).
102. The data payload echoes for free because we copy the request.
103. Build-from-scratch is for responses with no matching request.
104. A SYN-ACK (Day 3) is build-from-scratch.
105. Order: edit a region's fields, then its checksum.
106. Zero the checksum field before computing.
107. Write checksum (and all multi-byte fields) big-endian.
108. A bad checksum is dropped silently by the kernel/peer.
109. So verify checksums offline, not via the live ping.
110. `reply_is_well_formed` asserts type, addresses, both checksums, payload.
111. The length guard (`>= header_len + 8`) prevents panics on short requests.
112. We return None (not panic) for malformed/non-echo requests.
113. Modules: utils ← ip ← icmp; main on top; acyclic.
114. `mod X;` is what compiles src/X.rs.
115. `pub` defines the cross-module API surface.
116. Tests live per-module and can access privates.
117. The refactor was behavior-preserving (tests stayed green).
118. Refactor at the "2+ callers" threshold, not before.
119. `utils::checksum` is reused by ip, icmp, (and tcp later).
120. ping was written by Mike Muuss in 1983.
121. ICMP is RFC 792 (1981).
122. Unconditional echo replies enable host discovery and amplification.
123. Hardening: rate-limit, ignore broadcast, fail closed.
124. ICMP payloads can carry covert channels (icmptunnel).
125. IDS/IPS are fast parsers + rule engines (your skill at scale).
126. Detection (checksum) ≠ recovery (retransmission).
127. ICMP/UDP have no recovery; TCP retransmits.
128. You can't recover from a loss you didn't detect — detection comes first.
129. Random-corruption miss rate ≈ 1/65536; structured misses can be 100%.
130. For adversaries, use HMAC/TLS, not a checksum.
131. The reply preserves id/seq so the pinger correlates it.
132. RTT = now − the timestamp echoed in the data.
133. The kernel demultiplexes the reply to ping by ICMP id.
134. `iface.send` = write(tun_fd); kernel treats it as arriving on tun0.
135. The kernel verifies IP+ICMP checksums on ingress of our reply.
136. Every field we set has a consumer on the other side.
137. A reply with wrong addresses is valid but undeliverable to ping.
138. The checksum is the one O(n) step; parsing is O(1).
139. Per-reply Vec allocation is the first thing to pool for speed.
140. Don't optimize the checksum until a benchmark says so.
141. SIMD/wide checksum is valid by associativity.
142. Endianness-independent summation swaps only the final result.
143. The verify trick turns checking into "sum to 0."
144. Fletcher/Adler are position-sensitive (catch reorders) but uncommon in IP.
145. The build technique scales from echo reply to TCP segments.
146. Day 2 = the write half of "bytes in, bytes out."
147. Day 1's read + Day 2's write = full duplex over TUN.
148. The checksum + pseudo-header reappears unchanged in TCP.
149. Clean modules now make tcp.rs slot in cleanly later.
150. Build the offline test before touching the wire — every time.

---

---
---

# VOLUME III — Reference Tables (Day 2)

> Checksum and reply lookup material. Memorize the bold rows.

## RT2.1 — The checksum, every form

| Form | What | When to use |
|------|------|-------------|
| Word-by-word (ours) | sum u16 BE words, fold, NOT | clarity, teaching, low rate |
| Deferred fold | sum into u32, fold once at end | slightly faster; same result |
| Wide (32/64-bit) | sum wide chunks, fold down | multi-Gbps software path |
| Endianness-skip | sum in host order, swap result once | avoid per-word swaps |
| Incremental (RFC 1624) | patch on one-field change | routers (TTL decrement) |
| Hardware offload | NIC computes/verifies | real NICs (not TUN) |

## RT2.2 — Checksum coverage matrix

| Protocol | Range checksummed | Pseudo-header | Field bytes | Mandatory? |
|----------|-------------------|---------------|-------------|------------|
| IPv4 | header (IHL×4) | no | 10–11 | yes |
| ICMP | whole message | no | 2–3 | yes |
| UDP (IPv4) | pseudo + header + data | yes | 6–7 | optional (0=none) |
| UDP (IPv6) | pseudo + header + data | yes | 6–7 | yes |
| TCP | pseudo + header + data | yes | 16–17 | yes |

## RT2.3 — The pseudo-header (IPv4, 12 bytes)

| Bytes | Field |
|-------|-------|
| 0–3 | source IP |
| 4–7 | destination IP |
| 8 | zero |
| 9 | protocol (6 TCP / 17 UDP) |
| 10–11 | transport length (header + data) |

Input to the TCP/UDP checksum only; never transmitted.

## RT2.4 — Echo reply: field-by-field diff vs request

| Field | Request | Reply | Recompute? |
|-------|---------|-------|-----------|
| IP src (12–15) | pinger | us | — |
| IP dst (16–19) | us | pinger | — |
| IP TTL (8) | (incoming) | 64 | — |
| IP checksum (10–11) | valid | **recomputed** | yes (header changed) |
| ICMP type (hl) | 8 | 0 | — |
| ICMP checksum (hl+2..hl+4) | valid | **recomputed** | yes (type changed) |
| ICMP id/seq/data | x | x (echoed) | no |

## RT2.5 — Error-detection schemes, ranked

| Scheme | Bits | Strength | Reorder-safe | Cost | Internet use |
|--------|------|----------|--------------|------|--------------|
| Parity | 1 | very weak | no | trivial | legacy |
| Internet checksum | 16 | weak | **no** | very low | IP/ICMP/TCP/UDP |
| Fletcher-16 | 16 | moderate | yes | low | some protocols |
| Adler-32 | 32 | moderate | yes | low | zlib |
| CRC-16 | 16 | strong (bursts) | yes | table/HW | some links |
| CRC-32 | 32 | strong | yes | table/HW | Ethernet, ZIP |
| HMAC-SHA256 | 256 | cryptographic | yes | high | TLS |

## RT2.6 — Symptom → cause (Day 2, consolidated)

| Symptom | Likely cause | Fix |
|---------|-------------|-----|
| reply in tcpdump, ping loss | bad IP or ICMP checksum | zero field, correct range, BE write |
| no reply in tcpdump | didn't call send / send errored | send the reply; check `?` |
| valid checksums, ping loss | addresses/id/seq wrong | swap addrs; echo id/seq |
| panic on short ping | missing length guard | guard `>= header_len + 8` |
| version parses as 0 | Iface::new (PI header) | use without_packet_info |
| reply storms | replying to non-echo | guard type == 8 |
| off-by-byteswap checksum | to_ne_bytes used | use to_be_bytes |

## RT2.7 — Day-2 commands

```bash
# build + verify offline
wsl -d Ubuntu -- bash -lc 'cd <proj> && cargo test'
# run + observe the reply
<binary>                              # terminal 1
sudo ip addr add 192.168.0.1/24 dev tun0 && sudo ip link set tun0 up
ping -c3 192.168.0.2                   # expect 0% loss now
sudo tcpdump -i tun0 -n -vv           # expect request AND reply lines
```

## RT2.8 — One's-complement quick facts

| Fact | Value |
|------|-------|
| Negation | bitwise NOT (no +1) |
| Zeros | two: 0x0000 (+0), 0xFFFF (−0) |
| Addition | with end-around carry = mod 2¹⁶−1 |
| Valid checksum sum (incl. field) | 0xFFFF |
| `checksum()` of that | 0x0000 |
| Rust operator for it | `!` (on the folded u16) |

## RT2.9 — Reply construction pseudo-code (memorize)

```
fn build_echo_reply(request, header_len):
    if request.len() < header_len + 8: return None
    if request[header_len] != 8:       return None        # type 8 only
    reply = request.clone()
    swap reply[12..16] <-> reply[16..20]                   # IP src/dst
    reply[8] = 64                                          # TTL
    reply[10..12] = 0; reply[10..12] = checksum(reply[..header_len])
    reply[header_len] = 0                                  # type -> reply
    reply[header_len+2..+4] = 0
    reply[header_len+2..+4] = checksum(reply[header_len..])
    return Some(reply)
```

---

## RT2.10 — Protocol / ICMP recap (Day-2 relevant)

| IP proto | name | checksum'd how |
|----------|------|----------------|
| 1 | ICMP | whole message, no pseudo-header |
| 6 | TCP | pseudo-header + segment |
| 17 | UDP | pseudo-header + segment (optional v4) |

| ICMP (type,code) | name | do we reply? |
|------------------|------|--------------|
| (8,0) | Echo Request | **yes → type 0** |
| (0,0) | Echo Reply | no (it's already a reply) |
| (3,*) | Unreachable | no |
| (11,0) | Time Exceeded | no |

---

## AM. `main.rs` ICMP dispatch arm — line by line (Day 2)

The Day-2 addition to the main loop is the ICMP arm that sends a reply. Walk it:

```rust
1 => {
    if let Some(i) = icmp::parse(l4) {
```
- `1 =>` matches `hdr.protocol == 1` (ICMP) in the dispatch `match`. `l4 = &packet[hdr.header_len..]`
  is the ICMP message (payload after the IP header). `icmp::parse` returns `Option<IcmpHeader>`;
  `if let Some(i)` handles the well-formed case, dropping (printing nothing actionable) on a runt.

```rust
        println!(
            "         └── ICMP type={} code={} ({})  id={} seq={}",
            i.typ, i.code, icmp::name(i.typ, i.code), i.id, i.seq
        );
```
- Human-readable log of the parsed ICMP, using `icmp::name` to label the (type, code) pair. Pure
  observability; no effect on the wire.

```rust
        if i.typ == 8 {
            if let Some(reply) = icmp::build_echo_reply(packet, hdr.header_len) {
                iface.send(&reply)?;
                println!("         → sent Echo Reply ({} bytes)", reply.len());
            }
        }
```
- Only **type 8** (Echo Request) triggers a reply — we must not answer replies/errors.
- `build_echo_reply(packet, hdr.header_len)` takes the **whole packet** (it needs the IP header to
  swap addresses and rewrite the IP checksum) plus where the IP header ends. It returns
  `Option<Vec<u8>>` — `None` if the request is malformed (guarded inside).
- `iface.send(&reply)?` writes the reply to the wire; `?` propagates any I/O error up to `main`'s
  `io::Result`.
- The log line confirms a reply went out (useful when cross-checking with tcpdump).

```rust
    }
}
```
- Closes the `if let Some(i)` and the `1 =>` arm. If `icmp::parse` returned `None` (too short), we
  simply fall through — no reply, no crash (the fail-closed behavior).

Note what this arm does *not* do: no rate limiting, no broadcast check, no incoming-checksum
validation. Those are the §AG/§H.7 hardening exercises. The arm is the minimal correct responder.

## AN. Annotated source — `utils.rs` (complete, as of Day 2)

The whole file, reproduced with inline reference notes (the canonical artifact to read and re-type).

```rust
//! Shared helpers. Day 2: the Internet Checksum (RFC 1071), reused by ip/icmp/(tcp).

/// Internet checksum: 16-bit one's-complement of the one's-complement sum of `data`
/// as 16-bit big-endian words.
///   compute: zero the field, call this, store result.
///   verify : call this over data INCLUDING the field → 0 means valid.
pub fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;                       // u32 holds carries above bit 15
    let mut chunks = data.chunks_exact(2);      // iterate full 16-bit words
    for w in chunks.by_ref() {                  // by_ref so .remainder() stays available
        sum += u16::from_be_bytes([w[0], w[1]]) as u32;   // big-endian word, widened
    }
    if let [last] = chunks.remainder() {        // odd trailing byte?
        sum += (*last as u32) << 8;             // it's the HIGH byte of a 0x..00 word
    }
    while sum >> 16 != 0 {                       // end-around carry fold (may iterate)
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)                                // one's complement of the folded sum
}
```

Notes per line:
- `pub` — used by other modules.
- `sum: u32` — see §C.2; a `u16` would drop carries.
- `chunks_exact(2)` + `by_ref()` — §G.14 (day1) and §O.1; lets us read the odd remainder after.
- `from_be_bytes` — wire is big-endian (§D, day1).
- `(*last as u32) << 8` — RFC 1071's odd-byte rule (§C.1).
- `while ... fold` — §B.2/§R.2 end-around carry; `while` because the fold can carry again.
- `!(sum as u16)` — the final complement; no semicolon → it's the return value.

```rust
#[cfg(test)]
mod tests {
    use super::*;
    // Wikipedia's worked IPv4 header; stored checksum 0xb861 is correct.
    const HDR: [u8; 20] = [
        0x45,0x00,0x00,0x73,0x00,0x00,0x40,0x00,0x40,0x11,0xb8,0x61,
        0xc0,0xa8,0x00,0x01,0xc0,0xa8,0x00,0xc7,
    ];
    #[test] fn computes_known_checksum() {
        let mut h = HDR; h[10]=0; h[11]=0;       // zero the field
        assert_eq!(checksum(&h), 0xb861);        // must reproduce the known value
    }
    #[test] fn valid_header_verifies_to_zero() {
        assert_eq!(checksum(&HDR), 0);           // verify trick
    }
    #[test] fn odd_length_pads_last_byte() {
        assert_eq!(checksum(&[0x12,0x34,0x56]), checksum(&[0x12,0x34,0x56,0x00]));
    }
}
```

This is the complete `utils.rs`. If you can reproduce it — function and tests — with this page
closed, you own the checksum end to end. The same treatment of `ip.rs` and `icmp.rs` is in §E plus
day1 §O.

---

## AO. Annotated source — `ip.rs` and `icmp.rs` (complete, as of Day 2)

The two protocol files in full, with inline notes. Together with §AN (`utils.rs`) this is the whole
Day-2 codebase to read and re-type.

### AO.1 — `ip.rs`

```rust
//! IPv4 layer (RFC 791). Parse (day1) + header-checksum writer (day2).
use std::net::Ipv4Addr;     // free Display/eq/.octets() for addresses
use crate::utils;            // for utils::checksum

#[derive(Debug, PartialEq, Eq)]   // Debug=logs/tests; Eq=assert_eq! on headers
pub struct Ipv4Header {
    pub version: u8,
    pub header_len: usize,   // BYTES (IHL*4); payload starts here
    pub total_len: usize,    // whole datagram bytes (from the wire)
    pub ttl: u8,
    pub protocol: u8,        // 1 ICMP / 6 TCP / 17 UDP
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ParseError {        // typed causes → diagnosable logs
    TooShort { have: usize, need: usize },
    NotIpv4 { version: u8 },
    HeaderLongerThanPacket { header_len: usize, have: usize },
}

pub fn parse(packet: &[u8]) -> Result<Ipv4Header, ParseError> {
    if packet.len() < 20 {                                  // GUARD 1: min header
        return Err(ParseError::TooShort { have: packet.len(), need: 20 });
    }
    let version = packet[0] >> 4;                           // high nibble
    if version != 4 {
        return Err(ParseError::NotIpv4 { version });        // catches IFF_NO_PI bug (v=0)
    }
    let ihl = (packet[0] & 0x0f) as usize;                  // low nibble
    let header_len = ihl * 4;                               // words → bytes
    if packet.len() < header_len {                          // GUARD 2: declared hdr fits
        return Err(ParseError::HeaderLongerThanPacket { header_len, have: packet.len() });
    }
    let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;  // BE
    let ttl = packet[8];
    let protocol = packet[9];
    let src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    Ok(Ipv4Header { version, header_len, total_len, ttl, protocol, src, dst })
}

/// Recompute the IP header checksum (bytes 10-11) over `header` (exactly the IP header).
pub fn write_header_checksum(header: &mut [u8]) {
    header[10] = 0; header[11] = 0;            // zero the field first (required)
    let c = utils::checksum(header);            // sum over the header
    let [hi, lo] = c.to_be_bytes();             // big-endian out
    header[10] = hi; header[11] = lo;
}
```
Key points recap: two guards make all indexing panic-free; `from_be_bytes` for the only multi-byte
field; `write_header_checksum` is the build-side mirror that zeroes-then-fills. Tests (in the file)
cover parse fields, both rejections, the etherparse oracle, and the checksum round-trip.

### AO.2 — `icmp.rs`

```rust
//! ICMP layer (RFC 792). Parse (day1) + echo reply (day2).
use crate::{ip, utils};

#[derive(Debug, PartialEq, Eq)]
pub struct IcmpHeader { pub typ: u8, pub code: u8, pub checksum: u16, pub id: u16, pub seq: u16 }

pub fn parse(payload: &[u8]) -> Option<IcmpHeader> {     // Option: one failure mode
    if payload.len() < 8 { return None; }                // 8-byte header minimum
    Some(IcmpHeader {
        typ: payload[0],
        code: payload[1],
        checksum: u16::from_be_bytes([payload[2], payload[3]]),
        id: u16::from_be_bytes([payload[4], payload[5]]),
        seq: u16::from_be_bytes([payload[6], payload[7]]),
    })
}

pub fn name(typ: u8, code: u8) -> &'static str {         // label (type, code)
    match (typ, code) {
        (8, 0) => "Echo Request (ping)",
        (0, 0) => "Echo Reply (pong)",
        (3, 0) => "Net Unreachable",
        (3, 1) => "Host Unreachable",
        (3, 3) => "Port Unreachable",
        (11, 0) => "Time Exceeded (TTL=0)",
        _ => "other",
    }
}

/// Build an Echo Reply from an Echo Request (full IP packet). Mutate-in-place strategy.
pub fn build_echo_reply(request: &[u8], header_len: usize) -> Option<Vec<u8>> {
    if request.len() < header_len + 8 { return None; }   // need IP hdr + 8B ICMP
    if request[header_len] != 8 { return None; }         // type 8 (request) only

    let mut reply = request.to_vec();                    // copy → payload echoes free

    // IP edits: swap src/dst via temporaries (avoid borrow-of-self overlap)
    let (mut src, mut dst) = ([0u8; 4], [0u8; 4]);
    src.copy_from_slice(&reply[12..16]);
    dst.copy_from_slice(&reply[16..20]);
    reply[12..16].copy_from_slice(&dst);
    reply[16..20].copy_from_slice(&src);
    reply[8] = 64;                                       // TTL
    ip::write_header_checksum(&mut reply[..header_len]); // IP cksum AFTER edits

    // ICMP edits: type → 0, recompute ICMP checksum over the whole message
    reply[header_len] = 0;
    reply[header_len + 2] = 0;
    reply[header_len + 3] = 0;
    let c = utils::checksum(&reply[header_len..]);
    let [hi, lo] = c.to_be_bytes();
    reply[header_len + 2] = hi;
    reply[header_len + 3] = lo;

    Some(reply)
}
```
Key points recap: `Option` for the single failure mode; guard before indexing; mutate-a-copy so the
payload echoes; swap via temporaries; **each checksum computed after its region's edits**, field
zeroed first, written big-endian. The file's tests assert the reply is well-formed (type 0, swapped
addresses, both regions verify to 0, payload preserved) and that non-echo requests return `None`.

### AO.3 — Reading the whole codebase at once

With §AN + §AO you have all three protocol files annotated, and §AM the main-loop dispatch. The
entire Day-2 stack is ~4 small files: a checksum primitive, an IP parser+checksum-writer, an ICMP
parser+reply-builder, and a loop that wires them. That smallness is the point — you can hold the
whole thing in your head, which is exactly why building the 1% yourself makes the 99% (real stacks)
readable later (day1 §N.6).

---

## AP. Capstone — instrumenting the reply path

A practical exercise: add temporary instrumentation that proves each step of the reply is correct,
live. This is how you'd debug the path for real, and it cements the order-of-operations.

### AP.1 — The goal
For one ping, print: the parsed request, each edit applied, and the two checksums *as verified* (each
region summing to 0) before sending. If any verification prints non-zero, you've localized the bug to
that region.

### AP.2 — Where to add it (conceptually)
In `build_echo_reply`, after each region's checksum is written, assert/log its validity:
```
// after ip::write_header_checksum(&mut reply[..header_len]):
debug_assert_eq!(utils::checksum(&reply[..header_len]), 0, "IP cksum not valid");
// after writing the ICMP checksum:
debug_assert_eq!(utils::checksum(&reply[header_len..]), 0, "ICMP cksum not valid");
```
`debug_assert_eq!` runs only in debug builds (free in release), so it's safe to leave in. If either
fires, the edit/order is wrong.

### AP.3 — A log of one reply
With `println!` instrumentation you'd see, per ping:
```
[#0001] IPv4 192.168.0.1 → 192.168.0.2 proto=1 (ICMP) total=84B ttl=64
         └── ICMP type=8 code=0 (Echo Request (ping)) id=4660 seq=1
         · reply: src=192.168.0.2 dst=192.168.0.1 type=0
         · ip cksum verifies: 0    icmp cksum verifies: 0
         → sent Echo Reply (84 bytes)
```
The two "verifies: 0" lines are the proof the packet is well-formed before it hits the wire — the
live mirror of the `reply_is_well_formed` unit test.

### AP.4 — Cross-check with tcpdump
Run `sudo tcpdump -i tun0 -n -vv` alongside. For each ping you should see the request (in) and the
reply (out), and with `-vv` tcpdump will say the checksums are correct. Three views agreeing (your
log, the assertions, tcpdump) = certainty. This is the §AT (day1) "look at the bytes" discipline made
into a routine.

### AP.5 — Removing it
Instrumentation is temporary; once the path is trusted, drop the `println!`s (or gate them behind
`tracing::debug!` so `RUST_LOG` controls them). The `debug_assert_eq!`s can stay — they cost nothing
in release and document the invariants.

## AQ. ICMP reply vs TCP segment construction — a preview

Day 3 builds packets from scratch. Comparing it to the ICMP reply you just wrote shows what's the
same and what's new.

| Aspect | ICMP echo reply (Day 2) | TCP segment (Day 3) |
|---|---|---|
| Strategy | mutate a copy of the request | build a zeroed buffer from scratch |
| IP header | inherited from request (swap addrs) | written field by field |
| IP checksum | `ip::write_header_checksum` | same function |
| L4 checksum | ICMP: over the message, no pseudo-header | TCP: over **pseudo-header** + segment |
| State needed | none (stateless) | the TCB (seq/ack/window) |
| What varies | type, addresses | ports, seq, ack, flags, window, data |
| Same skills | zero-field-then-checksum, big-endian, order | identical |

The new things in Day 3 are (1) building rather than mutating, (2) the pseudo-header in the checksum,
and (3) *state*. Everything else — the checksum function, the byte-layout discipline, big-endian, the
"checksum last" order — transfers unchanged. That's why Day 2 is the right rung before Day 3: you've
practiced packet construction on the easy case (mutate, no pseudo-header, no state) before the hard
one.

## AR. Exercises III (with solutions)

### AR.1 — Add the debug assertions
**Q.** Add the two `debug_assert_eq!` checksum-verifications to `build_echo_reply`. Do existing tests
still pass?
**A.** Yes — the reply is well-formed, so both regions verify to 0; the asserts never fire. They now
guard against future edits that break the order.

### AR.2 — Break the order on purpose
**Q.** Move `reply[8] = 64` (TTL) to *after* `ip::write_header_checksum`. What happens?
**A.** The IP checksum is computed before TTL changes → stale → the `debug_assert_eq!(checksum(ip),
0)` fires (and live ping drops). Demonstrates the "checksum last" rule.

### AR.3 — Echo a larger ping
**Q.** `ping -s 1000 192.168.0.2`. Does `build_echo_reply` need changes?
**A.** No — it copies the whole request (any size) and checksums `reply[header_len..]` (any length).
The payload (1000 bytes) echoes; checksums cover it. Size-agnostic by construction.

### AR.4 — Reply with the wrong total_length
**Q.** Set IP total_length to 20 in the reply (header only) while keeping the data. Symptom?
**A.** Receivers think the datagram is 20 bytes; the ICMP message is truncated/ignored; ping likely
shows loss. Keep total_length consistent with the actual bytes (we don't touch it, so it's correct).

### AR.5 — Count replies
**Q.** Add a counter of echo replies sent; print it every 10.
**A.** A `u64` incremented after each `iface.send` in the ICMP arm; `if n % 10 == 0 { println!(...) }`.
A warm-up for the per-connection counters TCP needs.

### AR.6 — Validate incoming ICMP checksum
**Q.** Before replying, verify the *request's* ICMP checksum; drop if invalid.
**A.** `if utils::checksum(&l4) != 0 { return; }` in the ICMP arm (a corrupt request shouldn't be
echoed). Test with a deliberately corrupted request.

### AR.7 — Reply only to a specific id
**Q.** Reply only to pings with a given identifier (simulate a filter).
**A.** Guard `if i.id == TARGET_ID` around the reply. Shows how id demultiplexes — the seed of TCP's
4-tuple demux.

### AR.8 — Measure reply build cost
**Q.** Time `build_echo_reply` over 1e6 calls. What dominates?
**A.** The `to_vec` allocation + the checksum pass. At 84 bytes both are tiny; the point is to *see*
that the syscall (send), not the build, dominates real cost (§O).

---

## AS. The checksum's interactions with fragmentation, NAT, and IPv6

The checksum doesn't live in isolation; three other mechanisms touch it in ways worth knowing.

### AS.1 — Fragmentation
When IP fragments a datagram, **each fragment gets its own IP header with its own IP header
checksum** (the header differs per fragment: MF flag, fragment offset). But the **transport
checksum** (TCP/UDP/ICMP) is computed over the *whole* reassembled payload, so it can only be
*verified after reassembly* — the receiver reassembles the fragments, then checks the one transport
checksum. Consequence: a fragmented packet's transport integrity isn't known until all fragments
arrive; a lost fragment means the whole datagram is dropped. This is one reason fragmentation is
avoided (PMTUD prefers sending smaller un-fragmented packets). We don't fragment, so we always
checksum a complete message — simpler and a reason the in-order/whole-message assumption holds.

### AS.2 — NAT must fix checksums
A NAT router rewrites the source IP (and, for PAT, the source port) of outgoing packets. That changes
bytes covered by **both** the IP header checksum **and** the transport checksum (the transport
checksum's pseudo-header includes the IP addresses, and PAT changes the ports inside the segment). So
NAT must **recompute or incrementally update** (RFC 1624) both checksums on every translated packet —
exactly the incremental-update math from §C.5, applied at scale. This is why NAT is more than
"swap an address": it's address swap + two checksum fixes per packet, per direction. It also breaks
protocols that embed addresses in their payload (FTP, SIP) unless an ALG fixes those too.

### AS.3 — IPv6 removed the IP header checksum
IPv6 has **no header checksum at all** (RFC 8200). Rationale: the link layer (CRC) catches
transmission errors per hop, and the transport layer (TCP/UDP — now *mandatory* checksums in IPv6,
including UDP) catches end-to-end errors, so the IP-layer checksum was deemed redundant *and* a
per-router cost (every router had to update it on TTL/hop-limit decrement). Removing it lets IPv6
routers forward faster. So the very `write_header_checksum` you wrote is *gone* in IPv6 — a concrete
example of a "simplification by deletion" learned from 20 years of IPv4. (IPv6's transport checksums
still use a pseudo-header, updated for 128-bit addresses.)

### AS.4 — The pattern across all three
Each interaction is the same algebra (the sum is associative, so local changes compose) viewed from a
different angle: fragmentation splits the *header* checksum per fragment but keeps one *transport*
checksum; NAT *patches* both checksums incrementally; IPv6 *deletes* the redundant one. Master the
one's-complement sum (§B/§R) and all three follow.

### AS.5 — What this means for our stack
We're IPv4, un-fragmented, no NAT — the simplest case, where one IP checksum + one transport checksum
per packet, computed over complete messages, is exactly right. Knowing the interactions tells you
what would change if you extended toward real conditions (add fragmentation handling → per-fragment IP
checksums + reassembly-then-verify; add NAT → incremental dual-checksum updates; add IPv6 → drop the
IP checksum, keep the pseudo-header transport one).

## AT. Day 2 — deeper facts (151–210)

151. Each IP fragment carries its own IP header checksum.
152. The transport checksum is verified only after reassembly.
153. A lost fragment drops the whole datagram.
154. PMTUD avoids fragmentation by sending smaller packets.
155. NAT changes the source IP → must fix the IP header checksum.
156. NAT's port change (PAT) is inside the segment → must fix the transport checksum.
157. The transport pseudo-header includes IPs, so NAT touches it too.
158. NAT uses incremental checksum update (RFC 1624) for speed.
159. NAT breaks payload-embedded-address protocols (FTP/SIP) without an ALG.
160. IPv6 has no IP header checksum.
161. IPv6 removed it to save per-router work (redundant with L2 CRC + L4).
162. IPv6 makes UDP's checksum mandatory.
163. IPv6 transport checksums still use a (128-bit) pseudo-header.
164. The one's-complement sum is associative → local changes compose (incremental update).
165. The same property makes word-reordering undetectable.
166. CRC is not incrementally updatable cheaply → routers don't use it for IP.
167. Ethernet's CRC-32 is computed/checked by the NIC hardware.
168. A packet has both an L2 CRC (per hop) and L3/L4 checksum (end to end).
169. The end-to-end checksum catches in-router corruption the CRC can't.
170. Our stack: IPv4, no fragmentation, no NAT → one IP + one transport checksum, whole messages.
171. `to_vec` copies the request so the reply can be mutated independently.
172. The payload echoes because it's copied and never touched.
173. Swapping addresses via temporaries avoids overlapping borrows.
174. `debug_assert_eq!` verifies checksums in debug builds for free.
175. `tracing::debug!` + RUST_LOG is the production logging path.
176. The reply is size-agnostic: any ping size echoes correctly.
177. total_length must match the actual bytes or receivers misparse.
178. ICMP id demultiplexes replies to the right ping process.
179. id is the seed idea of TCP's 4-tuple demultiplexing.
180. The reply build cost is dwarfed by the send syscall.
181. Building from scratch (Day 3) replaces mutate-in-place.
182. TCP's checksum = our checksum + a 12-byte pseudo-header.
183. TCP construction needs state (the TCB); ICMP reply doesn't.
184. The "checksum last per region" rule transfers to TCP.
185. Big-endian on write transfers to TCP.
186. The zero-field-first rule transfers to TCP.
187. Detection (checksum) is necessary before recovery (retransmit).
188. ICMP/UDP have no recovery; TCP does.
189. A bad checksum is dropped silently — verify offline.
190. Three-view debugging: your log, asserts, tcpdump.
191. The whole Day-2 stack is ~4 small files.
192. Smallness is the point: hold it in your head.
193. Building 1% yourself makes the 99% (real stacks) readable.
194. utils::checksum is the most-reused function in the codebase.
195. ip::write_header_checksum is the build-side mirror of verification.
196. icmp::build_echo_reply returns Option (one failure mode).
197. The main ICMP arm replies only to type 8.
198. It does no rate-limiting yet (an amplification risk).
199. It does no incoming-checksum validation yet (an exercise).
200. It fails closed (drops) on malformed input.
201. ping (1983) and ICMP (1981) still run modern diagnostics.
202. traceroute reuses ICMP Time Exceeded (an error as a tool).
203. Snort/Suricata are fast parsers + rules — your skill at scale.
204. The checksum's ~1/65536 random miss rate is why stronger checks layer on.
205. For adversaries use HMAC/TLS, not a checksum.
206. The verify trick: a valid region sums to 0.
207. End-around carry makes the sum mod 2¹⁶−1.
208. Two zeros: 0x0000 and 0xFFFF.
209. UDP sends a computed-zero checksum as 0xFFFF.
210. Day 2 = write half; Day 1 = read half; together = full duplex.

---

## AU. Full API reference — every public item (as of Day 2)

The complete public surface of the codebase, with signatures and one-line purposes. This is the
"what can I call" lookup.

### AU.1 — `utils`
| Item | Signature | Purpose |
|------|-----------|---------|
| `checksum` | `pub fn checksum(data: &[u8]) -> u16` | Internet checksum (RFC 1071) over any byte range |

### AU.2 — `ip`
| Item | Signature | Purpose |
|------|-----------|---------|
| `Ipv4Header` | `pub struct { version, header_len, total_len, ttl, protocol, src, dst }` | parsed IPv4 header |
| `ParseError` | `pub enum { TooShort, NotIpv4, HeaderLongerThanPacket }` | typed parse failures |
| `parse` | `pub fn parse(packet: &[u8]) -> Result<Ipv4Header, ParseError>` | parse an IPv4 header |
| `write_header_checksum` | `pub fn write_header_checksum(header: &mut [u8])` | compute+store IP header checksum |

### AU.3 — `icmp`
| Item | Signature | Purpose |
|------|-----------|---------|
| `IcmpHeader` | `pub struct { typ, code, checksum, id, seq }` | parsed ICMP header |
| `parse` | `pub fn parse(payload: &[u8]) -> Option<IcmpHeader>` | parse an ICMP header |
| `name` | `pub fn name(typ: u8, code: u8) -> &'static str` | label a (type, code) pair |
| `build_echo_reply` | `pub fn build_echo_reply(request: &[u8], header_len: usize) -> Option<Vec<u8>>` | build an echo reply |

### AU.4 — `main`
| Item | Signature | Purpose |
|------|-----------|---------|
| `protocol_name` | `fn protocol_name(protocol: u8) -> &'static str` | label an IP protocol number |
| `main` | `fn main() -> std::io::Result<()>` | open tun0, recv/parse/dispatch/reply loop |

### AU.5 — Types from dependencies we use
| Item | From | Use |
|------|------|-----|
| `Iface`, `Mode` | `tun_tap` | the TUN device + TUN/TAP mode |
| `Ipv4HeaderSlice` | `etherparse` | the parsing oracle (cross-check) |
| `Ipv4Addr` | `std::net` | IPv4 addresses with Display/eq/octets |

This table is the contract between modules; everything not listed is private. When Day 3 adds `tcp`,
its public items (`Quad`, `State`, `TcpHeader`, `parse`, `Connection::{accept,on_packet,state}`,
`flags_str`) join this reference.

## AV. Lab — reproduce the 0%-loss result, with checkpoints

A guided run that proves Day 2 works, with a verification gate at each step.

### AV.1 — Build and self-verify
```bash
wsl -d Ubuntu -- bash -lc 'cd /mnt/c/Users/daasa/Projects/tcp-stack && cargo test'
```
**Checkpoint:** all tests pass (incl. `reply_is_well_formed`, `checksum_round_trips`). If red, fix
before touching the wire — the bug is in the bytes, and the test names which.

### AV.2 — Grant capability and run
```bash
sudo setcap cap_net_admin=eip /home/daasa/.tcp-stack-target/debug/tcp-stack
/home/daasa/.tcp-stack-target/debug/tcp-stack
```
**Checkpoint:** prints "TUN interface up: tun0" and blocks. If `PermissionDenied`, re-run setcap or
use sudo. If `ResourceBusy`, `sudo ip link delete tun0`.

### AV.3 — Configure the interface (terminal 2)
```bash
sudo ip addr add 192.168.0.1/24 dev tun0 && sudo ip link set tun0 up
ip addr show tun0
```
**Checkpoint:** `tun0` shows `UP` and `inet 192.168.0.1/24`. If not, the address/route didn't take.

### AV.4 — Ping
```bash
ping -c3 192.168.0.2
```
**Checkpoint:** **0% packet loss**, three replies with `ttl=64 time=…`. This is the Day-2 milestone.
If 100% loss, go to §AW.

### AV.5 — Observe both packets (terminal 3)
```bash
sudo tcpdump -i tun0 -n -vv
```
**Checkpoint:** for each ping, an `ICMP echo request` (in) **and** an `ICMP echo reply` (out), both
with correct checksums (tcpdump `-vv` notes incorrect ones). Three views agree → done.

### AV.6 — Stress it a little
```bash
ping -c10 -i 0.2 192.168.0.2      # 10 pings, faster
ping -s 1000 192.168.0.2          # larger payload
```
**Checkpoint:** still 0% loss; larger ping echoes its 1000-byte payload (size-agnostic reply).

## AW. Lab troubleshooting (the 0%-loss gate)

If §AV.4 shows loss, work this table top to bottom:

| Check | Command/look | If wrong |
|-------|--------------|----------|
| Reply emitted? | tcpdump shows a reply line | no → stack didn't `send` (or `build_echo_reply` returned None) |
| IP checksum valid? | tcpdump `-vv` / Wireshark / `checksum(&reply[..20])==0` | recompute after IP edits, field zeroed, BE |
| ICMP checksum valid? | same over `reply[20..]` | recompute after type edit, field zeroed, BE |
| Addresses swapped? | reply src=.2 dst=.1 | swap bytes 12–19 |
| Type flipped? | reply ICMP type=0 | set `reply[header_len]=0` |
| Using without_packet_info? | first byte 0x45, not 0x00 | switch from `Iface::new` |
| Interface up + addressed? | `ip addr show tun0` | re-run the `ip addr`/`ip link` commands |
| setcap applied? | `getcap <binary>` | re-run setcap (after every build) |

The fastest path: rerun `cargo test` first. If `reply_is_well_formed` is green, the *bytes* are
correct and the problem is environmental (interface/cap/PI-header), not in the reply logic. That split
— "is it the bytes or the environment?" — is the first question to answer, and the offline test
answers it instantly.

---

## AX. Fully worked multi-word checksums (every step shown)

Practice the arithmetic on bigger inputs than the toy examples. Cover the work; compute each.

### AX.1 — A 16-byte input, every word
Data: `12 34 56 78 9a bc de f0 0f ed cb a9 87 65 43 21` (8 words).
```
word  value    running sum
1     0x1234   0x1234
2     0x5678   0x68AC
3     0x9ABC   0x10368   (carry into bit16)
4     0xDEF0   0x1E258
5     0x0FED   0x1F245
6     0xCBA9   0x2BDEE
7     0x8765   0x34553
8     0x4321   0x38874
```
Sum = 0x38874. Fold: `0x8874 + 0x3 = 0x8877`. (high half 0x3, low 0x8874). No further carry.
Checksum = `~0x8877 = 0x7788`.
Verify: 0x8877 + 0x7788 = 0xFFFF → ~ = 0. ✓

### AX.2 — A 20-byte IP header (10 words), end to end
Data (field zeroed): `45 00 00 14 00 00 40 00 40 06 00 00 0a 0a 0a 01 0a 0a 0a 02`.
```
4500 + 0014 = 4514
+0000 = 4514
+4000 = 8514
+4006 = C51A
+0000 = C51A
+0A0A = CF24
+0A01 = D925
+0A0A = E32F
+0A02 = ED31
```
Sum = 0xED31, no high carry. Checksum = `~0xED31 = 0x12CE`.
Verify: 0xED31 + 0x12CE = 0xFFFF → 0. ✓ Store `12 CE` in bytes 10–11.

### AX.3 — An odd-length input (5 bytes)
Data: `aa bb cc dd ee`. Words: `0xAABB`, `0xCCDD`, then lone `0xEE` → `0xEE00`.
```
0xAABB + 0xCCDD = 0x17798 → fold 0x7798 + 1 = 0x7799
0x7799 + 0xEE00 = 0x16599 → fold 0x6599 + 1 = 0x659A
~0x659A = 0x9A65
```
Checksum = `0x9A65`.

### AX.4 — Demonstrating the reorder blind spot
Data A: `00 01 00 02`. Data B (words swapped): `00 02 00 01`.
A: 0x0001 + 0x0002 = 0x0003 → ~ = 0xFFFC.
B: 0x0002 + 0x0001 = 0x0003 → ~ = 0xFFFC.
**Same checksum** despite different byte order — the reorder weakness (§AC.2) made concrete. A CRC
would differ.

### AX.5 — Demonstrating a canceling error
Data A: `00 05 00 05`. Data B: `00 06 00 04` (+1 then −1).
A: 0x0005+0x0005 = 0x000A. B: 0x0006+0x0004 = 0x000A. **Same sum, same checksum** — undetected. This
is why the checksum is "weak": structured canceling changes slip through.

## AY. Day 2 — deeper facts (211–260)

211. The checksum sums 16-bit words regardless of field boundaries.
212. Folding can iterate (a fold can produce a new carry).
213. The accumulator must be wider than 16 bits (u32 here).
214. Reordering two 16-bit words leaves the checksum unchanged.
215. A +1/−1 canceling change across words is undetected.
216. CRC catches both reorders and canceling changes; the checksum doesn't.
217. The checksum is chosen for speed/updatability, not strength.
218. Verify = sum incl. field → expect 0.
219. Compute = zero field, sum, complement, store.
220. Write the stored checksum big-endian.
221. IP header checksum field is bytes 10–11.
222. ICMP checksum field is bytes 2–3 (of the ICMP message).
223. TCP checksum field is bytes 16–17 (of the segment).
224. UDP checksum field is bytes 6–7.
225. The pseudo-header is 12 bytes for IPv4.
226. Pseudo-header = srcIP(4) dstIP(4) zero(1) proto(1) length(2).
227. The pseudo-header is never transmitted.
228. It binds the transport checksum to the addresses.
229. UDP checksum 0x0000 = "not computed" (IPv4 only).
230. A computed-zero UDP checksum is sent as 0xFFFF.
231. TCP checksum is always mandatory.
232. IPv6 has no IP header checksum.
233. IPv6 makes UDP checksum mandatory.
234. Fragmentation: per-fragment IP checksum, one transport checksum after reassembly.
235. NAT must fix both IP and transport checksums.
236. NAT uses incremental update for speed.
237. Routers incrementally update the IP checksum on TTL decrement.
238. Incremental update: ~(~old_cksum + ~old_word + new_word).
239. It's O(1) regardless of header size.
240. Hardware offload computes checksums on the NIC.
241. On TUN there's no offload; a red checksum is a real bug.
242. Echo reply = mutate the request, two checksums, swapped addresses.
243. The data echoes because it's copied unchanged.
244. build_echo_reply returns Option (one failure mode: malformed/non-echo).
245. It guards len >= header_len + 8 before indexing.
246. Address swap uses temporaries to avoid borrow overlap.
247. Each checksum is computed AFTER its region's field edits.
248. iface.send = write(tun_fd); kernel treats it as arriving on tun0.
249. The kernel verifies IP+ICMP checksums and matches by id.
250. RTT = now − the timestamp echoed in the data.
251. Day 2 split main.rs into utils/ip/icmp modules.
252. mod X; compiles src/X.rs; pub defines the API.
253. The dependency graph is acyclic: utils ← ip ← icmp ← main.
254. The refactor preserved behavior (tests stayed green).
255. utils::checksum is reused across all layers.
256. Detection (checksum) precedes recovery (TCP retransmit).
257. The whole Day-2 stack is ~4 small, readable files.
258. The checksum + pseudo-header recur unchanged in TCP (Day 3).
259. The build technique (zero, checksum-last, BE) transfers to TCP.
260. Day 2 milestone: ping replies with 0% loss, verified three ways.

---

## AZ. End-to-end consolidation — every checksum in one ping round trip

Trace a single `ping` and note *every* checksum computed/verified along the way. This ties Day 2's
piece into the whole picture.

### AZ.1 — Outbound request (ping → us)
1. `ping` builds an ICMP echo request; the kernel computes its **ICMP checksum**.
2. The kernel wraps it in IP and computes the **IP header checksum**.
3. (On a real link) the NIC computes the **Ethernet CRC**; on TUN, none.
4. The packet is "transmitted" on tun0 → delivered to our `recv`.

### AZ.2 — Our processing
5. We parse the IP header. (We *don't* validate its checksum by default — exercise H.7 adds it.)
6. We parse the ICMP header, see type 8.
7. We `build_echo_reply`: recompute the **IP header checksum** (addresses changed) and the **ICMP
   checksum** (type changed) — the two Day-2 computations.

### AZ.3 — Inbound reply (us → ping)
8. We `send` the reply → kernel ingress on tun0.
9. The kernel verifies our **IP header checksum** (drops if bad).
10. The ICMP layer verifies our **ICMP checksum** (drops if bad), matches by id, delivers to `ping`.
11. `ping` computes RTT from the echoed timestamp and prints 0% loss.

### AZ.4 — The tally
Per round trip: 2 checksums computed by the kernel (request), 2 recomputed by us (reply), 4 verified
by the kernel (2 on our reply's ingress; the request's were verified when... actually the request's
were computed by the kernel and would be verified by *us* if we validated). The point: the checksum
is computed and verified **at every hop and endpoint**, in both directions — it's the most-executed
piece of arithmetic on the internet. You implemented the endpoint half for one protocol; multiply by
every packet, every protocol, every host, and you grasp why it had to be cheap (§A.2).

### AZ.5 — Where a single bad bit dies
If a bit flips in our reply's IP header after we checksum it (e.g. a bug overwrote a byte), step 9
catches it and drops it — `ping` sees loss. If it flips in the ICMP data, step 10 catches it. If it
flips on a real wire, the NIC CRC (per hop) likely catches it first. Layered detection means a
corruption is caught at the first layer that covers the corrupted bytes. That's the defense-in-depth
payoff of having multiple checks.

## BA. How to study Day 2 (Learning-OS aligned)

Per your Learning OS, here's the most effective way to internalize this chapter.

### BA.1 — Type the core yourself
The checksum is a "core" — hand-type `utils::checksum` from the §AN listing with the book closed, then
`cargo test`. Re-derive the end-around carry and the verify trick rather than memorizing them.
`build_echo_reply` is glue/construction — re-typing it cements the order-of-operations.

### BA.2 — Anki from your own slips
Make cards only for what *you* got wrong: if you forgot to zero the checksum field, make a card "why
zero the field first?" If you mis-ordered the TTL edit and checksum, card the "checksum last" rule.
Cards from textbook facts you already knew are wasted; cards from your bugs stick.

### BA.3 — Compute by hand until it's automatic
Do §AX and §H.1/§H.14 (day1) on paper until summing 16-bit words, folding, and complementing is
reflexive. This is the one bit of arithmetic the whole rest of the project (and TCP) reuses; fluency
pays off repeatedly.

### BA.4 — Teach it (the real finish line)
Per rule #5, the finish line is "can I teach it?" Explain to someone (or rubber-duck): "why does a
valid header checksum to zero, and why is the checksum recomputed when I swap addresses?" If you can
teach both cleanly, Day 2 is owned. Use `/tcp-tutor` to have me grade your explanation.

### BA.5 — Connect to the daily lane
Your WIP=2 includes a daily habit lane. A good Day-2 habit: one checksum-by-hand per day for a week
(varied inputs from §AX) until it's muscle memory, plus a LeetCode bit-manipulation problem (shifts/
masks) to reinforce §C. Small, daily, compounding — the Learning-OS pattern.

## BB. Day 2 — deeper facts (261–300)

261. The checksum is computed/verified at every hop and endpoint.
262. It's the most-executed arithmetic on the internet (hence "must be cheap").
263. Per ping round trip, ~4 checksums are computed and ~4 verified.
264. Layered detection: corruption caught at the first layer covering it.
265. NIC CRC catches most wire corruption per hop.
266. The end-to-end checksum catches in-router corruption.
267. We don't validate the incoming IP checksum by default (an exercise).
268. A bug overwriting a reply byte → kernel drops it on ingress.
269. Type the checksum yourself (it's a "core" per the Learning OS).
270. build_echo_reply is glue — re-type it to cement order.
271. Anki only from your own slips, not textbook facts.
272. Compute checksums by hand until reflexive.
273. The finish line is "can I teach it?"
274. Daily habit: one hand-checksum + one bit-manipulation problem.
275. The verify trick: valid region sums to 0.
276. Zero the field before computing.
277. Checksum last, after a region's other edits.
278. Big-endian on write (to_be_bytes).
279. IP checksum covers the header only.
280. ICMP checksum covers the whole message.
281. TCP/UDP add a 12-byte pseudo-header.
282. Pseudo-header binds the checksum to the addresses.
283. UDP checksum optional in IPv4 (0 = none; computed-0 → 0xFFFF).
284. TCP checksum always mandatory.
285. IPv6 dropped the IP header checksum.
286. Fragmentation: per-fragment IP checksum; one transport checksum after reassembly.
287. NAT fixes both checksums incrementally.
288. Routers update the IP checksum incrementally on TTL decrement.
289. Incremental update is O(1).
290. Hardware offload moves checksums to the NIC.
291. On TUN, software checksums; a red checksum is a real bug.
292. The reply mutates a copy; the payload echoes for free.
293. iface.send = write(tun_fd).
294. The kernel matches the reply to ping by ICMP id.
295. RTT = now − echoed timestamp.
296. Day 2 split into utils/ip/icmp modules at the 2+-callers threshold.
297. The module graph is acyclic and mirrors the stack.
298. The build technique transfers directly to TCP.
299. Detection precedes recovery; TCP adds recovery later.
300. Day 2 = the write half; ping replies, 0% loss, verified three ways.

---

## BC. Ten more worked checksums (drill set)

Cover answers; compute. Speed comes from reps.

1. `[00 00]` → sum 0 → `~0 = 0xFFFF`.
2. `[ff ff]` → 0xFFFF → `~ = 0x0000`.
3. `[ff ff ff ff]` → 0xFFFF+0xFFFF=0x1FFFE → fold 0xFFFE+1=0xFFFF → `~=0`.
4. `[00 01 00 02 00 03]` → 0x0006 → `~=0xFFF9`.
5. `[12 34]` → 0x1234 → `~=0xEDCB`.
6. `[80 00 80 00]` → 0x10000 → fold 0x0000+1=0x0001 → `~=0xFFFE`.
7. `[ab cd ef]` (odd) → 0xABCD + 0xEF00 = 0x19ACD → fold 0x9ACD+1=0x9ACE → `~=0x6531`.
8. `[45 00 00 14]` → 0x4500+0x0014=0x4514 → `~=0xBAEB`.
9. `[c0 a8 00 01 c0 a8 00 02]` → 0xC0A8+0x0001+0xC0A8+0x0002 = 0x18153 → fold 0x8153+1=0x8154 →
   `~=0x7EAB`.
10. `[08 00 00 00 12 34 00 01]` (echo request header, field zeroed) → 0x0800+0x0000+0x1234+0x0001 =
    0x1A35 → `~=0xE5CA`. (Compare the reply, §Z.2: type 0 → 0xEDCA. The 0x0800 difference shifts the
    sum, hence the different checksum — exactly why flipping type requires recompute.)

Self-check: every answer, summed back with the checksum word, gives 0xFFFF (the verify trick).

## BD. RFC 1071 — annotated walkthrough

RFC 1071 ("Computing the Internet Checksum," 1988) is short and worth reading; here's a guided tour
mapping its prose to our code.

### BD.1 — Section 1: the definition
RFC 1071 defines the checksum as "the 16-bit one's complement of the one's complement sum of all
16-bit words." That single sentence is our entire `utils::checksum`: the *sum* (with end-around
carry) then the *complement*.

### BD.2 — The key properties it lists (and where we rely on each)
- **Commutative/associative** → "may be calculated in any order, and in parallel" → licenses wide
  summation (§C.3) and the fold-once optimization (§C.2).
- **Byte-order independent** ("the sum may be calculated in either byte order") → §C.4; you can sum
  in host order and swap the result once.
- **Parallelizable** → SIMD checksum routines.
- **Incrementally updatable** → expanded in RFC 1624 (§C.5); routers patch on TTL change.
These aren't incidental remarks — they're the design rationale, and each maps to a real optimization
in production stacks.

### BD.3 — The odd-byte rule
RFC 1071 specifies that if the data has an odd number of bytes, the last byte is padded with a zero
byte **on the right** to form a final 16-bit word — i.e. the lone byte is the *high* byte. Our code:
`sum += (last as u32) << 8`. The `<<8` is exactly "pad with a zero low byte."

### BD.4 — The "deferred carry" technique
RFC 1071 explicitly suggests accumulating in a larger register and folding carries at the end (rather
than after each add) for efficiency — precisely our `u32` accumulator + post-loop `while` fold. The
RFC's own example code does this; ours mirrors it.

### BD.5 — What the RFC does NOT claim
It does not claim strong error detection — it's upfront that this is a cheap check, and it points to
the layered model (link CRC + this) for robustness. Reading the RFC dispels any notion that the
checksum is "secure" or "comprehensive"; it's a fast sanity check, by design (§A.2, §AC).

### BD.6 — Why read RFCs at all
This is the skill the curriculum wants: the *primary source* is precise and short, and learning to
map its prose to code (as above) is how you implement *any* protocol from spec. RFC 1071 is an ideal
first RFC to practice on — small, concrete, with example code and worked numbers.

## BE. The same checksum in C, Python, and Rust

Seeing one algorithm in three languages cements that it's about the *math*, not the syntax — and
shows why Rust's version is both safe and clear.

### BE.1 — C (the classic, from RFC 1071-style code)
```c
uint16_t checksum(const uint8_t *data, size_t len) {
    uint32_t sum = 0;
    while (len > 1) { sum += (data[0] << 8) | data[1]; data += 2; len -= 2; }
    if (len) sum += data[0] << 8;                 // odd byte, high half
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);  // fold
    return (uint16_t)~sum;
}
```
Note the manual pointer arithmetic and length tracking — easy to get an off-by-one or read past the
end (no bounds checks). This is where C parsers get buffer over-reads.

### BE.2 — Python (clarity, no manual pointers)
```python
def checksum(data: bytes) -> int:
    if len(data) % 2: data += b"\x00"             # pad odd
    s = sum(int.from_bytes(data[i:i+2], "big") for i in range(0, len(data), 2))
    while s >> 16: s = (s & 0xffff) + (s >> 16)   # fold
    return (~s) & 0xffff
```
Slicing + `int.from_bytes(..., "big")` makes endianness explicit; no pointers to mismanage. Slower,
but obviously correct.

### BE.3 — Rust (ours: safe and explicit)
```rust
pub fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut chunks = data.chunks_exact(2);
    for w in chunks.by_ref() { sum += u16::from_be_bytes([w[0], w[1]]) as u32; }
    if let [last] = chunks.remainder() { sum += (*last as u32) << 8; }
    while sum >> 16 != 0 { sum = (sum & 0xffff) + (sum >> 16); }
    !(sum as u16)
}
```
`chunks_exact(2)` + `remainder()` replaces C's manual length tracking with a bounds-checked iterator;
`from_be_bytes` makes endianness explicit like Python; and it compiles to code as fast as the C. You
get C's speed, Python's clarity, and memory safety — the reason the project is in Rust.

### BE.4 — The lesson
The three differ only in *how they walk the bytes safely*; the math (sum BE words, fold, complement)
is identical. When you read a checksum routine in any language/codebase, you'll now recognize the same
three steps under the syntax. That transfer — algorithm over syntax — is what makes you fast across
languages.

---

## BF. Cross-reference index (Day 2)

| Concept | RFC | Code | Section |
|---------|-----|------|---------|
| Internet checksum | 1071 | `utils::checksum` | §3–§6 (V1), §B–§C, §R (day1) |
| Incremental update | 1624 | (routers; not us) | §C.5, §R.7 |
| One's complement | — | `!` in checksum | §B, §R |
| IP header checksum | 791 | `ip::write_header_checksum` | §E.2, §AO.1 |
| ICMP echo reply | 792 | `icmp::build_echo_reply` | §5, §E.3, §AO.2 |
| Pseudo-header | 9293/768 | (tcp, day3) | §C.7, §M, RT2.3 |
| Mutate vs build | — | echo reply / (tcp) | §D.1, §AQ |
| Module refactor | — | `mod`/`use crate::` | §L, §AE |
| iface.send | — | `iface.send(&reply)` | §F, §V |
| Detection vs recovery | — | checksum / (tcp retransmit) | §Y |
| Strength/probability | — | — | §AC |
| Fragmentation/NAT/IPv6 | 1191/1631/8200 | — | §AS |
| Security (ICMP attacks) | — | (hardening exercises) | §P, §AG |

## BG. Generating an ICMP error from scratch — Destination Unreachable

So far we only *mutated* a request (echo reply). Generating an ICMP **error** is your first
build-from-scratch ICMP message and a bridge to building TCP segments. Use case: a UDP datagram
arrives for a port nothing is listening on → reply ICMP Type 3 Code 3 (Port Unreachable).

### BG.1 — The structure of an ICMP error
An ICMP error message (types 3, 11, 12) has the 8-byte ICMP header **plus a body that quotes the
offending packet**: the original IP header + the first 8 bytes of its payload. That quoted data lets
the *original sender* match the error to the flow that caused it (the first 8 bytes contain the
UDP/TCP ports or ICMP id/seq).

```
ICMP error layout:
  [0] type (3)   [1] code (3)   [2..4] checksum   [4..8] unused (zero)
  [8..]  the offending IP header + first 8 bytes of its payload
```

### BG.2 — Building it (the steps)
To reply Port Unreachable to an offending packet `orig` (full IP packet):
1. Build a **new IP header**: src = us (the offending packet's dst), dst = the offending sender
   (orig's src), protocol 1 (ICMP), TTL 64, total_length = 20 + 8 + (orig IP header + 8 bytes).
2. Build the **ICMP header**: type 3, code 3, checksum 0 (for now), bytes 4–7 = 0 (unused).
3. Append the **quoted data**: `orig[..orig_ihl + 8]` (the offending IP header + 8 payload bytes).
4. **IP checksum** over the new IP header; **ICMP checksum** over the whole new ICMP message.
5. `iface.send` it.

### BG.3 — Why this is build-from-scratch
There's no request to mutate — the offending packet is a *different* protocol (UDP) going the *other*
way; you synthesize the entire ICMP error. This is exactly the technique Day 3 uses for the SYN-ACK
(build, don't mutate). The reused skills: zero-field-then-checksum, big-endian, checksum-last,
length consistency. The new wrinkle: assembling a packet from multiple parts (new headers + quoted
bytes).

### BG.4 — Pseudocode
```
fn icmp_port_unreachable(orig: &[u8], orig_ihl: usize, me: Ipv4Addr) -> Vec<u8> {
    let quote = &orig[..orig_ihl + 8];              // offending IP header + 8 bytes
    let icmp_len = 8 + quote.len();
    let total = 20 + icmp_len;
    let mut p = vec![0u8; total];
    // IP header
    p[0] = 0x45; p[2..4] = (total as u16).to_be_bytes();
    p[6..8] = 0x4000u16.to_be_bytes(); p[8] = 64; p[9] = 1;     // proto ICMP
    p[12..16] = me.octets();                         // src = us
    p[16..20] = orig[12..16];                        // dst = original sender
    ip::write_header_checksum(&mut p[..20]);
    // ICMP
    p[20] = 3; p[21] = 3;                            // type 3 code 3
    // p[22..24] checksum = 0 for now; p[24..28] unused = 0
    p[28..28+quote.len()].copy_from_slice(quote);    // quoted data
    let c = utils::checksum(&p[20..]);
    p[22..24].copy_from_slice(&c.to_be_bytes());
    p
}
```

### BG.5 — Why it matters
Generating errors is half of being a real network endpoint (TCP must send RSTs; routers send Time
Exceeded). Doing it once for ICMP Port Unreachable teaches the build-from-scratch pattern you'll use
for every generated packet from Day 3 on, and it's a satisfying exercise that exercises the new
"assemble from parts + quote the original" skill.

## BH. Exercises IV (with solutions)

### BH.1 — Implement Port Unreachable
**Q.** Wire `icmp_port_unreachable` into the UDP arm (protocol 17) for packets to a closed port.
**A.** In the `17 =>` arm, if no "listener" matches the dst port, call the BG.4 builder with the
offending packet and `iface.send` it. Test: `nc -u 192.168.0.2 9999` → expect a Port Unreachable in
tcpdump.

### BH.2 — Verify the error's checksums
**Q.** Assert the generated error is well-formed offline.
**A.** `utils::checksum(&p[..20]) == 0` and `utils::checksum(&p[20..]) == 0`; type==3, code==3; dst ==
offending src; the quoted bytes == `orig[..orig_ihl+8]`.

### BH.3 — Why quote only 8 bytes of payload?
**A.** RFC 792's minimum: enough to include the transport ports (TCP/UDP src+dst ports are the first
4 bytes; 8 covers ports + seq start) so the sender can demultiplex the error. (Modern stacks may
quote more, RFC 4884.)

### BH.4 — Time Exceeded (type 11)
**Q.** Sketch generating a Time Exceeded when a forwarded packet's TTL hits 0.
**A.** Same as BG.4 but type 11, code 0, dst = the packet's source, quoting the offending header + 8
bytes. (We don't forward, so we don't generate these — but it's the same pattern, and it's what
makes traceroute work from the *responder* side.)

### BH.5 — Compare error vs echo construction
**Q.** What's structurally different between building an echo reply and an ICMP error?
**A.** Echo reply *mutates* the request (same protocol, reversed direction, payload echoed). The error
is *built fresh* (new IP+ICMP headers) and *quotes* a different packet. Both end with two checksums;
the error is the build-from-scratch case (like TCP).

---

## BI. UDP, exhaustively (the checksum's other consumer)

UDP (RFC 768) is the simplest transport and a perfect Day-2 add: it reuses the checksum (with a
pseudo-header) and needs no state. Implementing a UDP echo is a smaller cousin of the TCP work ahead.

### BI.1 — The header (8 bytes)
```
[0..2] source port    [2..4] destination port
[4..6] length         [6..8] checksum
[8..]  data
```
- **Ports** — demultiplexing (which app), like TCP.
- **Length** — UDP header + data, in bytes (≥ 8).
- **Checksum** — Internet checksum over pseudo-header + UDP header + data. Optional in IPv4
  (0x0000 = not computed); mandatory in IPv6.

### BI.2 — The pseudo-header (same shape as TCP's)
```
srcIP(4) dstIP(4) zero(1) proto=17(1) udp_length(2)
```
12 bytes, prepended to the UDP header+data for the checksum, then discarded. `proto = 17`. The udp
length appears twice (in the header and the pseudo-header) — a deliberate redundancy the checksum
ties together.

### BI.3 — Statelessness
UDP keeps **no connection state**: no handshake, no sequence numbers, no ACKs, no teardown. Each
datagram is independent — it may be lost, duplicated, or reordered, and UDP won't tell you. So a UDP
"echo server" is just: parse, swap ports/addresses, fix the two checksums, send. No TCB, no table —
which is exactly why it's the right warm-up before TCP's state machine.

### BI.4 — Why apps choose UDP
- **DNS** (port 53): one tiny request/reply; a handshake would double latency.
- **DHCP** (67/68): the client has no IP yet, so it must broadcast — only UDP can.
- **VoIP/video/games**: a late packet is useless; better to drop than wait (TCP's in-order delivery
  would stall on a loss).
- **QUIC** (HTTP/3): builds its *own* reliability/ordering/congestion over UDP, in userspace — the
  spiritual sibling of this whole project. They chose UDP precisely to escape kernel-TCP ossification
  and implement transport logic where it can evolve.

### BI.5 — The checksum-0 rule (revisited)
In IPv4, a UDP sender may skip the checksum by sending 0x0000 ("not computed"). A *computed* checksum
that comes out 0x0000 is transmitted as 0xFFFF instead (using the two-zeros property, §B.3), so
0x0000 unambiguously means "none." IPv6 forbids skipping (no IP-layer checksum to fall back on), so
UDP-over-IPv6 must always compute it.

### BI.6 — UDP vs TCP at a glance
| | UDP | TCP |
|---|---|---|
| Header | 8 bytes | 20+ bytes |
| State | none | TCB per connection |
| Reliability | none | retransmission |
| Ordering | none | sequence numbers |
| Flow/congestion control | none | yes |
| Checksum | optional (v4) | mandatory |
| Use | DNS, DHCP, VoIP, QUIC | HTTP, SSH, most apps |
This contrast is the clearest way to see *what TCP adds* — every TCP feature is a row UDP lacks.

## BJ. A UDP echo server — implementation walkthrough

Smaller than TCP echo; uses everything from Day 2.

### BJ.1 — Dispatch
In the main loop's `17 =>` arm (protocol 17), parse the 8-byte UDP header, then echo.

### BJ.2 — Parse
```rust
fn parse_udp(seg: &[u8]) -> Option<(u16, u16, &[u8])> {   // (sport, dport, data)
    if seg.len() < 8 { return None; }
    let sport = u16::from_be_bytes([seg[0], seg[1]]);
    let dport = u16::from_be_bytes([seg[2], seg[3]]);
    let len = u16::from_be_bytes([seg[4], seg[5]]) as usize;
    let data = &seg[8..len.min(seg.len())];
    Some((sport, dport, data))
}
```

### BJ.3 — Build the echo (mutate or build)
Like the ICMP reply, you can mutate the request: swap UDP ports, swap IP src/dst, recompute IP
checksum, recompute UDP checksum (with the pseudo-header). The data echoes for free.
```
swap IP src/dst (12..19); reply[8]=64; ip::write_header_checksum(&mut reply[..20])
swap UDP ports (20..22 <-> 22..24)
zero UDP checksum (26..28); udp_cksum = checksum(pseudo_header ++ reply[20..]); write it
```
`pseudo_header = us.octets() ++ peer.octets() ++ [0,17] ++ (udp_len as u16).to_be_bytes()`.

### BJ.4 — The one new wrinkle vs ICMP
The **pseudo-header**. ICMP's checksum was over the bare message; UDP's prepends the 12-byte pseudo-
header (addresses + proto + length). That's the *only* conceptual difference — and it's the same
wrinkle TCP has, so doing UDP echo first makes the TCP checksum trivial later.

### BJ.5 — Test it
`echo -n hi | nc -u 192.168.0.2 7` (port 7 = echo) → see your datagram come back. Offline: assert the
reply's IP and UDP checksums verify to 0 (the UDP one with the pseudo-header), ports swapped, data
echoed.

### BJ.6 — Why do this before TCP
UDP echo exercises the pseudo-header checksum (new) with *no* state (familiar). TCP echo adds the
pseudo-header checksum (now familiar) *plus* state (new). Splitting the two new concepts across two
protocols — pseudo-header on UDP, state on TCP — is gentler than meeting both at once. It's an
optional but recommended rung.

## BK. UDP exercises (with solutions)

### BK.1 — Build the UDP pseudo-header
**Q.** For a 12-byte UDP datagram us(192.168.0.2)→peer(192.168.0.1), give the pseudo-header bytes.
**A.** `c0 a8 00 02  c0 a8 00 01  00  11  00 0c` (us, peer, zero, proto 17, length 12).

### BK.2 — Why is the length in the pseudo-header AND the UDP header?
**A.** Redundancy the checksum binds: if either is corrupted inconsistently, the checksum fails. It
also lets the receiver detect truncation.

### BK.3 — Echo a DNS-shaped datagram
**Q.** `dig @192.168.0.2 example.com` sends UDP to port 53. What would a naive echo do?
**A.** Echo the DNS *query* bytes back to the client's source port — not a valid DNS *response*, so
`dig` would error. Echo proves the transport works; a real DNS server would parse and answer. (Shows
the line between transport echo and application logic.)

### BK.4 — Checksum-zero handling
**Q.** A received UDP datagram has checksum 0x0000. Do you validate it?
**A.** No — in IPv4, 0x0000 means "not computed," so skip validation. (In IPv6 a 0 would be invalid.)

### BK.5 — Compare to the ICMP reply
**Q.** What changes in the build vs the ICMP echo reply?
**A.** Swap *ports* (not type), and the L4 checksum includes the *pseudo-header*. Everything else
(swap addrs, TTL, IP checksum, big-endian, checksum-last) is identical.

---

## BL. A worked pseudo-header checksum (UDP/TCP preview)

The pseudo-header is the one new thing in transport checksums. Work one fully so it's concrete before
Day 3.

### BL.1 — The scenario
A UDP datagram us(192.168.0.2)→peer(192.168.0.1), src port 7, dst port 4660, no data (8-byte UDP).
udp_length = 8.

### BL.2 — Assemble the input
Pseudo-header (12 bytes) + UDP header (8 bytes, checksum field zeroed):
```
pseudo: c0 a8 00 02 | c0 a8 00 01 | 00 11 | 00 08
udp   : 00 07 | 12 34 | 00 08 | 00 00      (sport 7, dport 0x1234, len 8, cksum 0)
```

### BL.3 — Sum the words
```
c0a8 + 0002 = c0aa
+c0a8 = 18152  → keep going in u32: 0x18152
+0001 = 18153
+0011 = 18164
+0008 = 1816c
+0007 = 18173
+1234 = 193a7
+0008 = 193af
+0000 = 193af
```
Sum = 0x193AF. Fold: `0x93AF + 0x1 = 0x93B0`. No further carry.
Checksum = `~0x93B0 = 0x6C4F`. Store `6C 4F` in the UDP checksum field (bytes 6–7).

### BL.4 — Verify
Re-sum with `0x6C4F` in the field: previous (field=0) folded sum was 0x93B0; add 0x6C4F →
0x93B0 + 0x6C4F = 0xFFFF → `~ = 0`. ✓

### BL.5 — The takeaway
The *only* difference from the ICMP checksum (§Z) is the 12-byte pseudo-header prepended to the sum.
Everything else — sum, fold, complement, verify-to-zero — is identical. When Day 3's TCP checksum
appears, it's this exact computation with proto 6 instead of 17 and the TCP header/data instead of
UDP's. You've now done it by hand once; the code (`tcp::tcp_checksum`) just automates this.

## BM. Pitfalls when extending Day 2 (UDP echo / ICMP errors)

The build-from-scratch and pseudo-header additions introduce new failure modes.

1. **Forgot the pseudo-header in the transport checksum** → checksum valid over the segment alone but
   *invalid* with the pseudo-header → peer drops it. Symptom: UDP/TCP reply dropped though the ICMP
   reply works. Always prepend the pseudo-header for UDP/TCP.
2. **Wrong protocol byte in the pseudo-header** (17 vs 6) → checksum mismatch. Match it to the L4.
3. **Wrong length in the pseudo-header** (used IP total_length instead of *transport* length) →
   mismatch. The pseudo-header length is the L4 header + data, not the whole IP packet.
4. **Built total_length wrong** when assembling from parts → receiver truncates/drops. total_length =
   IP header + everything after.
5. **Quoted too few/many bytes in an ICMP error** → the sender can't match it (too few) or it's
   oversized. RFC 792 minimum is the IP header + 8 bytes.
6. **Reused a stale buffer** when building from scratch → leftover bytes pollute the new packet.
   Start from `vec![0u8; total]` (zeroed) and write every field.
7. **Off-by-one in multi-part assembly** (`copy_from_slice` length mismatch panics) → size the
   destination slice exactly to the source.
8. **Forgot to zero the unused ICMP error bytes (4–7)** → they contribute garbage to the checksum and
   confuse parsers. Zeroed buffer handles this if you don't overwrite them.

Each maps to a `debug_assert`/offline test you can add: verify both checksums (with pseudo-header for
L4), assert total_length matches the buffer, assert the quoted bytes equal the original. Build the
test, then the bug can't survive.

## BN. Day 2 — deeper facts (301–340)

301. UDP (RFC 768) is the simplest transport: an 8-byte header, no state.
302. UDP fields: src port, dst port, length, checksum.
303. UDP checksum uses a 12-byte pseudo-header (proto 17).
304. UDP checksum is optional in IPv4 (0 = none), mandatory in IPv6.
305. A computed-zero UDP checksum is sent as 0xFFFF.
306. UDP has no handshake, sequence numbers, ACKs, or teardown.
307. DNS uses UDP/53 (low latency); large replies use TCP/53.
308. DHCP uses UDP/67-68 and must broadcast (client has no IP yet).
309. VoIP/games prefer UDP (a late packet is worse than a lost one).
310. QUIC implements reliability over UDP, in userspace (HTTP/3).
311. A UDP echo server is stateless: parse, swap, two checksums, send.
312. The pseudo-header is the only new wrinkle vs the ICMP checksum.
313. ICMP errors (type 3/11/12) quote the offending IP header + 8 bytes.
314. The quoted 8 bytes contain the transport ports / icmp id+seq.
315. Generating an ICMP error is build-from-scratch (like a SYN-ACK).
316. Port Unreachable = ICMP type 3 code 3.
317. Time Exceeded = ICMP type 11 code 0 (traceroute).
318. Build-from-scratch starts from a zeroed buffer; write every field.
319. total_length must equal IP header + all following bytes.
320. The pseudo-header length is the transport length, not IP total_length.
321. Wrong pseudo-header proto/length → checksum mismatch → drop.
322. The pseudo-header is input only; never transmitted.
323. The pseudo-header binds the checksum to the addresses.
324. Echo reply mutates; ICMP error and TCP segments build fresh.
325. Both end with two checksums (IP + transport).
326. The transport checksum covers pseudo-header + L4 header + data.
327. The ICMP checksum covers only the ICMP message (no pseudo-header).
328. UDP echo exercises the pseudo-header without state (TCP warm-up).
329. TCP echo adds state on top of the pseudo-header checksum.
330. Splitting new concepts across protocols eases learning.
331. The checksum math (sum, fold, complement) is identical everywhere.
332. Only the byte range and pseudo-header presence differ per protocol.
333. The verify trick (sum incl. field → 0) holds for all of them.
334. Build the offline test before the live run — always.
335. debug_assert the checksums in build functions (free in release).
336. C checksum code uses manual pointers (over-read risk); Rust uses safe iterators.
337. Python checksum is slow but obviously correct (explicit slicing).
338. RFC 1071 is short, with example code; an ideal first RFC.
339. RFC 1071's listed properties map to real optimizations.
340. Day 2 = the write half; ping replies 0% loss; the checksum is the centerpiece.

---

## BO. The complete Day-2 data flow (annotated diagram)

```
  ping process                    KERNEL                         our stack (tun0 fd)
       │                            │                                   │
       │ sendmsg(echo req)          │                                   │
       │ ──────────────────────────►│ ICMP cksum computed               │
       │                            │ IP cksum computed                 │
       │                            │ route → tun0                      │
       │                            │ ──────write(fd)──────────────────►│ recv(buf)
       │                            │                                   │ ip::parse  (no cksum check*)
       │                            │                                   │ icmp::parse → type 8
       │                            │                                   │ build_echo_reply:
       │                            │                                   │   swap addrs, TTL
       │                            │                                   │   IP cksum (recompute)
       │                            │                                   │   type→0, ICMP cksum
       │                            │ ◄──────send=write(fd)─────────────│ iface.send(reply)
       │                            │ IP cksum VERIFY (drop if bad)      │
       │                            │ dst local? yes (tun0=.1)          │
       │                            │ ICMP cksum VERIFY (drop if bad)    │
       │                            │ match by id → ping socket         │
       │ ◄──────recvmsg(echo rep)───│                                   │
       │ RTT = now − ts; 0% loss    │                                   │
```
`*` we don't validate the incoming IP checksum by default (exercise H.7). Every "cksum" label is a
place the §B/§R arithmetic runs. The two **recompute** steps on our side are the entirety of Day-2's
new code; the two **VERIFY** steps on the kernel side are why a bad checksum vanishes silently.

## BP. Building the reply for a 1000-byte ping (the length math)

A larger ping exercises the size-agnostic claim and the length fields.

### BP.1 — The request sizes
`ping -s 1000` sends 1000 bytes of ICMP *data*. So: ICMP message = 8 (header) + 1000 (data) = 1008
bytes; IP packet = 20 (header) + 1008 = **1028 bytes**; IP total_length = 1028 = 0x0404.

### BP.2 — What build_echo_reply does (unchanged)
- `to_vec()` copies all 1028 bytes (header + 1008 ICMP). The 1000-byte payload comes along → echoed.
- Swap addresses, TTL, IP checksum over `reply[..20]` (header only — unaffected by payload size).
- type→0, ICMP checksum over `reply[20..]` (all 1008 bytes — the checksum *does* cover the payload).
- total_length (0x0404) is untouched and stays correct (same size reply).
No code changes; the function is size-agnostic because it slices by `header_len` and `..`, never
hardcoding sizes.

### BP.3 — The one thing that scales: the ICMP checksum cost
The IP checksum is still over 20 bytes (O(1)-ish). The ICMP checksum now sums 1008 bytes — ~504
words. Still negligible per packet, but it's the part that grows with payload, and at bulk TCP data
rates this is the cost hardware offload targets (§C.6, §O).

### BP.4 — MTU note
1028 bytes < 1500 MTU, so no fragmentation. `ping -s 2000` would exceed the MTU → the *kernel*
fragments the request (or PMTUD/DF kicks in); our stack would then receive fragments, which we don't
reassemble (a known simplification, §AS.1). So the size-agnostic claim holds up to the MTU; beyond it,
fragmentation is a separate concern we defer.

### BP.5 — Verifying the large reply
Offline: build the reply for a synthetic 1028-byte request; assert `utils::checksum(&reply[..20]) ==
0`, `utils::checksum(&reply[20..]) == 0` (now over 1008 bytes), addresses swapped, type 0, and
`reply[28..] == request[28..]` (the 1000-byte payload echoed). Same assertions as the small ping,
larger data — proving size-agnosticism by test.

## BQ. Day 2 — deeper facts (341–380)

341. The two "recompute" steps (IP + ICMP cksum) are Day-2's entire new code.
342. The kernel verifies our reply's checksums on ingress.
343. A bad checksum is dropped before ping sees it.
344. We don't validate the incoming IP checksum by default.
345. build_echo_reply is size-agnostic (slices, no hardcoded sizes).
346. A 1000-byte ping → 1028-byte IP packet (20+8+1000).
347. The IP checksum covers only the 20-byte header regardless of payload.
348. The ICMP checksum covers the whole message, including 1000 data bytes.
349. The ICMP checksum cost grows with payload; the IP one doesn't.
350. 1028 bytes < 1500 MTU → no fragmentation.
351. Beyond the MTU, the kernel fragments; we don't reassemble.
352. total_length stays correct because the reply is the same size.
353. The payload echoes because it's copied and untouched.
354. The pseudo-header (UDP/TCP) is the only new checksum wrinkle.
355. ICMP has no pseudo-header.
356. The pseudo-header carries proto (17 UDP / 6 TCP) and transport length.
357. Wrong proto/length in the pseudo-header → checksum mismatch.
358. The verify trick holds with the pseudo-header too.
359. UDP echo = pseudo-header checksum, no state.
360. TCP echo = pseudo-header checksum + state.
361. ICMP error generation quotes the offending header + 8 bytes.
362. Build-from-scratch starts from a zeroed buffer.
363. Assemble-from-parts needs exact slice sizes (or copy_from_slice panics).
364. The checksum math is identical across IP/ICMP/UDP/TCP.
365. Only the byte range and pseudo-header presence differ.
366. RFC 1071 defines the algorithm; RFC 1624 the incremental update.
367. The C version uses manual pointers (over-read risk).
368. The Rust version uses bounds-checked iterators (safe).
369. Same speed as C, clarity like Python, memory-safe.
370. The algorithm transfers across languages; only byte-walking differs.
371. Detection (checksum) ≠ recovery (TCP retransmit).
372. Layered detection: caught at the first covering layer.
373. NIC CRC (per hop) + IP/transport checksum (end to end) + retransmit.
374. The checksum is the most-run arithmetic on the internet.
375. It must be cheap because every packet pays for it.
376. It's weak by design; strength lives in CRC/TLS where warranted.
377. Day 2 split into modules at the 2+-callers threshold.
378. Re-type the checksum (a core); re-type build_echo_reply (glue).
379. Teach it (the finish line): why verify-to-zero, why recompute on swap.
380. Day 2 milestone: ping 0% loss, verified by tests + tcpdump + by hand.

---

## BR. Byte-layout reference tables (Day 2 messages)

### BR.1 — ICMP Echo (request and reply share this layout)
| Offset (in ICMP message) | Bytes | Field | Request | Reply |
|---|---|---|---|---|
| 0 | 1 | type | 8 | 0 |
| 1 | 1 | code | 0 | 0 |
| 2–3 | 2 | checksum | computed | recomputed |
| 4–5 | 2 | identifier | set | echoed |
| 6–7 | 2 | sequence | n | echoed |
| 8.. | var | data | payload | echoed |

### BR.2 — ICMP Destination Unreachable (type 3)
| Offset | Bytes | Field | Value |
|---|---|---|---|
| 0 | 1 | type | 3 |
| 1 | 1 | code | 0–15 (3 = port) |
| 2–3 | 2 | checksum | computed |
| 4–7 | 4 | unused | 0 |
| 8.. | var | quoted | offending IP header + 8 bytes |

### BR.3 — ICMP Time Exceeded (type 11)
| Offset | Bytes | Field | Value |
|---|---|---|---|
| 0 | 1 | type | 11 |
| 1 | 1 | code | 0 (TTL) / 1 (reassembly) |
| 2–3 | 2 | checksum | computed |
| 4–7 | 4 | unused | 0 |
| 8.. | var | quoted | offending IP header + 8 bytes |

### BR.4 — UDP header
| Offset | Bytes | Field |
|---|---|---|
| 0–1 | 2 | source port |
| 2–3 | 2 | destination port |
| 4–5 | 2 | length (header + data) |
| 6–7 | 2 | checksum (with pseudo-header) |
| 8.. | var | data |

### BR.5 — IPv4 / UDP / TCP pseudo-header (12 bytes, IPv4)
| Offset | Bytes | Field |
|---|---|---|
| 0–3 | 4 | source IP |
| 4–7 | 4 | destination IP |
| 8 | 1 | zero |
| 9 | 1 | protocol (17 UDP / 6 TCP) |
| 10–11 | 2 | transport length |

## BS. Day 2 — deeper facts (381–420)

381. ICMP echo request and reply share one layout; only type (and checksum) differ.
382. The identifier correlates a reply to the sending process.
383. The sequence number tracks per-ping loss/RTT.
384. ICMP errors put 4 unused bytes after the checksum, then the quote.
385. The quote = offending IP header + first 8 bytes.
386. 8 bytes covers the transport ports (and TCP seq start).
387. Port Unreachable = type 3 code 3 (UDP to a closed port).
388. Time Exceeded = type 11 (TTL=0), the traceroute signal.
389. UDP length includes the 8-byte header.
390. UDP checksum field is bytes 6–7.
391. The pseudo-header is 12 bytes for IPv4.
392. Pseudo-header proto: 17 for UDP, 6 for TCP.
393. Pseudo-header length = transport header + data (not IP total_length).
394. The pseudo-header is checksum input only.
395. ICMP needs no pseudo-header.
396. The IP header checksum covers 20 bytes regardless of payload.
397. The transport/ICMP checksum covers the payload too.
398. build_echo_reply is size-agnostic.
399. A 1000-byte ping → 1028-byte packet, echoed unchanged.
400. Past the MTU, the kernel fragments; we don't reassemble.
401. Detection precedes recovery.
402. The checksum is the most-executed arithmetic on the internet.
403. It's weak by design; CRC/TLS provide strength where needed.
404. One's complement: invert; two zeros; end-around carry.
405. Verify: sum incl. field → 0.
406. Compute: zero field, sum, complement, store big-endian.
407. Checksum last, after a region's edits.
408. Two checksums per IP packet with a transport payload (IP + transport).
409. ICMP reply recomputes IP (addrs changed) + ICMP (type changed).
410. Routers incrementally update the IP checksum on TTL decrement.
411. NAT fixes both checksums per translated packet.
412. IPv6 dropped the IP header checksum.
413. Hardware offload computes checksums on the NIC.
414. On TUN, software checksums; red = real bug.
415. Modules: utils ← ip ← icmp, acyclic, mirror the stack.
416. Tests live per module and access privates.
417. The refactor preserved behavior (tests green).
418. UDP echo is the stateless warm-up before stateful TCP.
419. The build technique (zero, checksum-last, BE) is universal.
420. Day 2 = the write half; the checksum is the centerpiece.

## BT. Rust idioms used in Day 2 (quick reference)

- **`&[u8]` / `&mut [u8]`** — shared/exclusive borrowed byte views; the parse/build inputs.
- **`Vec<u8>` + `to_vec()`** — owned, growable buffer for an outgoing packet (mutate-a-copy).
- **`copy_from_slice`** — bulk byte copy (panics on length mismatch — size exactly).
- **`u16::from_be_bytes` / `.to_be_bytes()`** — big-endian read/write of multi-byte fields.
- **`chunks_exact(2)` + `by_ref()` + `.remainder()`** — walk 16-bit words, handle the odd byte.
- **`Option<Vec<u8>>` return** — "a reply or nothing," for the single-failure-mode builder.
- **`if let [last] = slice`** — slice pattern matching the length-1 remainder.
- **`!` on `u16`** — one's complement (the checksum's final step).
- **`debug_assert_eq!`** — invariant checks free in release (verify checksums in build fns).
- **`mod` / `use crate::` / `pub`** — module structure and the cross-module API surface.
- **field-init shorthand** (`ParseError::NotIpv4 { version }`) — concise struct/enum construction.
- **destructuring** (`let [hi, lo] = c.to_be_bytes()`) — name the two checksum bytes.

Each idiom maps to a concrete line in `utils`/`ip`/`icmp`. Recognizing them makes the code (and any
Rust packet code you read next, e.g. smoltcp) legible at a glance.

---

## BU. An annotated lab transcript (what a real Day-2 session looks like)

A narrated walkthrough of bringing Day 2 up, with the actual output and what each line means.

### BU.1 — Build + test
```
$ cargo test
   Compiling tcp-stack v0.1.0
    Finished test [unoptimized + debuginfo]
running 11 tests
test utils::tests::computes_known_checksum ... ok
test utils::tests::valid_header_verifies_to_zero ... ok
test ip::tests::checksum_round_trips ... ok
test icmp::tests::reply_is_well_formed ... ok
...
test result: ok. 11 passed; 0 failed
```
*Meaning:* the bytes are correct before any network. If `reply_is_well_formed` were red, you'd fix
the reply logic now, not chase it live.

### BU.2 — setcap + run
```
$ sudo setcap cap_net_admin=eip /home/daasa/.tcp-stack-target/debug/tcp-stack
$ /home/daasa/.tcp-stack-target/debug/tcp-stack
✓ TUN interface up: tun0
→ In another terminal:
    sudo ip addr add 192.168.0.1/24 dev tun0
    sudo ip link set tun0 up
    ping 192.168.0.2
──────────────────────────────────────────────
```
*Meaning:* the TUN device exists and we're blocked on `recv`. The instructions print our own next
steps.

### BU.3 — Configure + ping (terminal 2)
```
$ sudo ip addr add 192.168.0.1/24 dev tun0 && sudo ip link set tun0 up
$ ping -c3 192.168.0.2
PING 192.168.0.2 (192.168.0.2) 56(84) bytes of data.
64 bytes from 192.168.0.2: icmp_seq=1 ttl=64 time=0.21 ms
64 bytes from 192.168.0.2: icmp_seq=2 ttl=64 time=0.18 ms
64 bytes from 192.168.0.2: icmp_seq=3 ttl=64 time=0.19 ms
--- 192.168.0.2 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss
```
*Meaning:* **0% loss** — the Day-2 milestone. The `64 bytes` and `ttl=64` confirm our reply's size and
TTL; the sub-ms RTT is expected over a local TUN.

### BU.4 — The stack's log (terminal 1)
```
[#0001] IPv4 192.168.0.1 → 192.168.0.2 proto=1 (ICMP) total=84B ttl=64
         └── ICMP type=8 code=0 (Echo Request (ping)) id=... seq=1
         → sent Echo Reply (84 bytes)
[#0002] ... seq=2 → sent Echo Reply (84 bytes)
[#0003] ... seq=3 → sent Echo Reply (84 bytes)
```
*Meaning:* three requests in, three replies out — matches ping's "3 received."

### BU.5 — tcpdump cross-check (terminal 3)
```
$ sudo tcpdump -i tun0 -n -vv
IP 192.168.0.1 > 192.168.0.2: ICMP echo request, id ..., seq 1, length 64
IP 192.168.0.2 > 192.168.0.1: ICMP echo reply,   id ..., seq 1, length 64
...
```
*Meaning:* both request and reply on the wire, addresses correctly swapped, checksums correct (with
`-vv` tcpdump would flag bad ones). Three views (test, log, tcpdump) agree → certainty.

### BU.6 — What you just proved
The full Day-2 path works: receive → parse → build a valid reply (two checksums) → send → kernel
accepts → ping matches. You built a host that answers pings using a stack you wrote, and verified it
three independent ways. That triangulated confidence is the habit to carry into Day 3, where the
state machine makes "does it actually work?" a harder question.

## BV. Day 2 — deeper facts (421–460)

421. `cargo test` proves the bytes before any network setup.
422. If `reply_is_well_formed` is green, a live failure is environmental.
423. setcap must be re-run after each build.
424. The stack blocks on `recv` until a packet arrives.
425. `64 bytes` in ping output is the ICMP payload framing.
426. `ttl=64` in the reply is the TTL we set.
427. Sub-ms RTT is normal over a local TUN.
428. The stack log should show one reply per request.
429. tcpdump shows both request and reply lines.
430. Three agreeing views = certainty.
431. The reply's addresses are swapped vs the request.
432. The reply's checksums are correct (tcpdump -vv flags bad ones).
433. A bad checksum → no reply delivered → ping loss.
434. The pinger matches replies by ICMP id.
435. The sequence number tracks per-packet loss.
436. ping computes RTT from the echoed timestamp.
437. 0% loss is the Day-2 milestone.
438. Day 1 had 100% loss (no reply); Day 2 has 0% (reply sent).
439. The two checksum recomputes are Day-2's entire new code.
440. The kernel verifies our reply's checksums on ingress.
441. We don't validate the request's IP checksum by default.
442. build_echo_reply mutates a copy; the payload echoes.
443. It's size-agnostic; a 1000-byte ping echoes too.
444. UDP echo is the stateless pseudo-header warm-up.
445. ICMP error generation is build-from-scratch (quotes the original).
446. TCP segments (Day 3) are build-from-scratch with state.
447. The checksum + pseudo-header recur unchanged in Day 3.
448. The module structure makes tcp.rs slot in cleanly.
449. Detection (checksum) precedes recovery (retransmit).
450. The checksum is weak, cheap, endianness-independent, updatable.
451. CRC is strong but not cheaply updatable → links, not IP.
452. The end-to-end checksum catches in-router corruption.
453. Layered detection: first covering layer catches it.
454. RFC 1071 (algorithm) + 1624 (incremental) are the sources.
455. Type the checksum yourself; re-type build_echo_reply.
456. Anki from your own slips.
457. Teach it — the real finish line.
458. Daily habit: a hand-checksum + a bit-manipulation problem.
459. /tcp-tutor grades your explanation against the code.
460. Day 2 owned = re-type both, hand-checksum, teach verify-to-zero, 0% loss live.

## BW. How Day 2 connects to the rest of the curriculum

- **To Day 3 (TCP):** the checksum + pseudo-header and the build technique are reused directly; the
  echo-server pattern foreshadows the TCP echo.
- **To the security track:** packet construction (build-from-scratch) is the red-team primitive;
  responder hardening (rate-limit, validate, fail-closed) is the blue-team discipline; fuzzing the
  builder is the robustness step.
- **To the systems track:** `iface.send`/`recv` are syscalls; the future event loop (non-blocking +
  epoll) for retransmission is core systems work, and the per-packet cost analysis (§O) is
  performance engineering.
- **To the daily lane:** hand-checksums and bit-manipulation LeetCode reinforce §C/§R; a blog post
  "how ping really works (and how I made it reply)" is the teach-it finish line and portfolio piece.
- **To later projects:** every protocol you build (DNS, a TCP stack proper, an IDS) reuses the
  parse/build/checksum trio. Day 2 is where construction (not just parsing) became a skill you own.

Day 2 looks small (a checksum and a reply), but it's the hinge from *reading* the network to
*participating* in it — the prerequisite for everything stateful and everything offensive/defensive
that follows.

---

## BX. Day-2 FAQ III

**1. Can I checksum a buffer that includes more than the region (e.g. trailing bytes)?** No — the
checksum must cover exactly the defined region (IP header, or ICMP message, or pseudo-header+segment).
Extra bytes change the sum and invalidate it.

**2. Why is the IP checksum over the header only, not the payload?** To keep router cost O(header) and
because the transport layer checksums its own payload. Checking the payload at every router would be
wasteful and redundant.

**3. If I forget the pseudo-header for UDP/TCP, will it ever accidentally work?** No — the peer
includes the pseudo-header when verifying, so omitting it on your side guarantees a mismatch → drop.
ICMP works without it because ICMP genuinely has none.

**4. What's the difference between `to_vec()` and a slice for building?** `to_vec()` makes an owned,
mutable `Vec` (needed to edit and to outlive the borrow of `buf`); a slice is a read-only view. We
build into a `Vec`, then `send(&vec)`.

**5. Can two pings interleave and confuse the matching?** No — each ping process has a distinct ICMP
id, and the kernel demultiplexes by id. The sequence number disambiguates within one process.

**6. Why does the reply keep the same identifier?** So the *original* pinger recognizes it as the
answer to *its* request. Changing it would make ping ignore the reply.

**7. Is the ICMP checksum affected by the IP header?** No — ICMP's checksum covers only the ICMP
message. The IP header has its own separate checksum. (TCP/UDP differ — they pull IP fields into the
pseudo-header.)

**8. Could I implement Day 2 with `etherparse` building the reply?** You could, but you'd learn the
crate, not the protocol. We use etherparse only as an oracle; building by hand is the point.

**9. Why `debug_assert` and not `assert` for the checksum invariants?** `debug_assert` is compiled out
in release, so it's a free in-development safety net without a runtime cost in production.

**10. What if the request's own checksum is bad?** By default we don't check (we parse and reply).
A robust stack validates it first and drops corrupt requests (exercise H.7 / AR.6).

**11. Does the order of the two checksums (IP then ICMP) matter?** They're independent regions, so the
order between them doesn't matter — what matters is each is computed *after* its own region's field
edits.

**12. How big can an ICMP reply be?** Up to the IP max (65,535) minus headers; in practice bounded by
the MTU (1500) unless fragmented. We echo whatever size came in.

**13. Why does the kernel "trust" our reply at all?** It doesn't blindly — it verifies the checksums
and that the destination is local before delivering. It treats our `write` like any received packet.

**14. Could a wrong total_length pass the checksum?** The IP checksum covers total_length, so a wrong
value would need a compensating change to still sum correctly — possible but you'd have made two
errors. Keep it consistent with the actual bytes.

**15. Is there any state in Day 2?** No — echo is stateless (the `packet_count` is just a log
counter). State arrives in Day 3 (the TCB). That statelessness is why Day 2 is simpler than Day 3.

**16. Why is UDP's checksum optional but not IP's or TCP's?** UDP is "best effort" and predates some
hardening; IPv4 let senders skip it for speed. IP's protects routing-critical header fields; TCP's is
essential to reliable delivery. IPv6 made UDP's mandatory.

**17. What's the relationship between this and `ping`'s "DUP!" or reordering output?** Those come from
duplicated/reordered replies; our simple responder sends exactly one reply per request in order, so
you won't see them unless you introduce delay/loss (e.g. `tc netem`).

**18. Can I batch replies for many pings?** Not in our blocking loop (one at a time). Batching
(`sendmmsg`) is a performance optimization tied to the event-loop refactor.

**19. Why is the reply's TTL reset to 64 rather than copied?** A reply is a fresh packet originating
from us; it should start with a full hop budget, not inherit the request's (possibly decremented) TTL.

**20. What single Day-2 skill matters most for Day 3?** Building a valid packet (correct fields,
checksum last, big-endian) — Day 3 builds SYN-ACKs the same way, just with a pseudo-header and state.

## BY. Day 2 — deeper facts (461–500)

461. The checksum must cover exactly its region — no more, no less.
462. The IP checksum is header-only to bound router cost.
463. Omitting the pseudo-header for UDP/TCP guarantees a mismatch.
464. ICMP genuinely has no pseudo-header.
465. `to_vec()` gives an owned, mutable, outliving buffer.
466. Pings interleave safely via distinct ICMP ids.
467. The reply keeps the request's id so ping recognizes it.
468. ICMP checksum is independent of the IP header.
469. We use etherparse as an oracle, not to build.
470. `debug_assert` is free in release.
471. We don't validate the request's checksum by default.
472. The two reply checksums are independent regions.
473. Reply size is bounded by the MTU in practice.
474. The kernel verifies our reply before delivering.
475. total_length is covered by the IP checksum.
476. Day 2 is stateless; state begins Day 3.
477. UDP checksum is optional in IPv4, mandatory in IPv6.
478. Duplicated/reordered replies cause ping "DUP!"/reorder output.
479. Our responder sends one in-order reply per request.
480. Batching replies needs the event loop.
481. The reply's TTL is reset to 64 (fresh packet).
482. The key Day-3 skill from Day 2 is building a valid packet.
483. Checksum last; big-endian; field zeroed first.
484. IP checksum over the header; transport over pseudo+segment.
485. One's complement: invert; two zeros; end-around carry.
486. Verify = sum incl. field → 0.
487. Detection (checksum) precedes recovery (retransmit).
488. The checksum is weak by design and layered with CRC/TLS.
489. NIC offload computes checksums on real hardware.
490. On TUN, software; red checksum = real bug.
491. Routers update the IP checksum incrementally on TTL change.
492. NAT fixes both checksums per packet.
493. IPv6 dropped the IP header checksum.
494. Modules: utils ← ip ← icmp, acyclic, mirror the stack.
495. The refactor preserved behavior (tests green).
496. UDP echo = pseudo-header checksum, no state (warm-up).
497. ICMP error generation = build-from-scratch + quote (like SYN-ACK).
498. Three-view debugging: test, log, tcpdump.
499. Teach it (verify-to-zero, recompute-on-swap) = Day 2 owned.
500. Day 2 milestone: ping 0% loss; the write half of the stack.

## BZ. Debugging tools, deeper (Day-2 specific)

- **`cargo test`** — the first and fastest check; offline, deterministic. Run on every change.
- **`tcpdump -i tun0 -n -vv`** — see request + reply; `-vv` flags bad checksums.
- **`tcpdump -i tun0 -X`** — hex dump to cross-check exact bytes against your parser's output.
- **Wireshark** (`-w cap.pcap` then open) — clickable field tree; "checksum: incorrect" in red is
  decisive on TUN (no offload). "Follow stream" for the conversation.
- **`debug_assert_eq!(utils::checksum(region), 0, ...)`** in `build_*` — fail fast on an invalid
  region during development.
- **`RUST_LOG=debug` + `tracing::debug!`** — structured, filterable logs without editing call sites
  (the `tracing` deps are already present).
- **`ip -s link show tun0`** — rx/tx packet and error counters; confirms packets are flowing.
- **`getcap <binary>`** — confirm `cap_net_admin` is set (empty after a rebuild → re-setcap).
- **`tc qdisc add dev tun0 root netem loss 10% delay 50ms`** — inject loss/delay to test robustness
  (and to *see* the difference between detection and recovery — Day 2 detects/drops, doesn't recover).

The workflow: `cargo test` (bytes) → run + `tcpdump` (wire) → Wireshark if a generated packet is
silently dropped (checksum) → `tc netem` to stress. Each tool answers a specific question; knowing
which to reach for is the debugging skill.

---

## CA. Reference card II — the complete Day-2 mental model on one screen

```
GOAL: make ping reply (0% loss) → first WRITE to the wire.
CHECKSUM (RFC 1071), reused by IP/ICMP/UDP/TCP:
  sum 16-bit BE words (u32) → +odd<<8 → fold carries → !low16
  verify: sum incl. field == 0    | compute: field=0, sum, !, store BE
  IP=header only(10-11) | ICMP=msg(2-3) | UDP/TCP=pseudo+seg(6-7/16-17)
  pseudo(12B)= srcIP dstIP 0 proto len   (input only)
  UDP cksum optional in v4 (0=none; computed-0 → 0xFFFF); TCP/IPv6 mandatory
ECHO REPLY (mutate the request):
  swap addrs(12-19) | TTL=64(8) | IP cksum(10-11) | type 8→0 | ICMP cksum
  order: edit region's fields THEN its checksum
BUILD-FROM-SCRATCH (ICMP error, later TCP): zeroed buf, write all, checksum last
SEND: iface.send=write(fd); kernel VERIFIES cksums (drops silently if bad)
SYMPTOM→CAUSE: reply seen+loss=bad cksum | no reply=didn't send | valid+loss=addr/id
MODULES: utils ← ip ← icmp (acyclic) | mod=compile | pub=API | tests per file
DETECTION (cksum, drop) ≠ RECOVERY (TCP retransmit, later)
MILESTONE: ping 0% loss, verified by cargo test + tcpdump + by hand
```

## CB. Day 2 — deeper facts (501–580)

501. Day 2's goal: make ping reply, 0% loss.
502. It's the first time we write to the wire.
503. The checksum is the centerpiece concept.
504. RFC 1071 defines it; RFC 1624 the incremental update.
505. Algorithm: sum BE words, fold, complement.
506. u32 accumulator holds carries.
507. Odd byte → high byte (<<8).
508. End-around carry → addition mod 2¹⁶−1.
509. One's complement has two zeros.
510. Valid region sums to 0xFFFF → complement 0.
511. Verify = sum incl. field == 0.
512. Compute = field 0, sum, complement, store BE.
513. IP covers the header only.
514. ICMP covers the whole message.
515. UDP/TCP cover pseudo-header + segment.
516. Pseudo-header = srcIP dstIP 0 proto len, 12 bytes.
517. Pseudo-header is input only, never sent.
518. UDP checksum optional in IPv4.
519. Computed-zero UDP checksum → 0xFFFF.
520. TCP checksum always mandatory.
521. IPv6 dropped the IP header checksum; UDP mandatory there.
522. Echo reply mutates the request.
523. Four edits: swap addrs, TTL, IP cksum, type+ICMP cksum.
524. Edit fields then checksum, per region.
525. The payload echoes because it's copied.
526. The reply is size-agnostic.
527. ICMP errors quote the offending header + 8 bytes.
528. ICMP error generation is build-from-scratch.
529. TCP segments are build-from-scratch with state.
530. Build-from-scratch starts from a zeroed buffer.
531. iface.send = write(tun_fd).
532. The kernel verifies our reply's checksums.
533. A bad checksum is dropped silently.
534. The pinger matches replies by ICMP id.
535. RTT from the echoed timestamp.
536. Day 2 split into utils/ip/icmp modules.
537. mod X; compiles src/X.rs.
538. pub defines the cross-module API.
539. Tests live per module.
540. The refactor preserved behavior.
541. utils::checksum is the most-reused function.
542. Detection precedes recovery.
543. ICMP/UDP have no recovery; TCP retransmits.
544. The checksum is weak by design.
545. CRC (links) is strong; TLS handles adversaries.
546. The end-to-end checksum catches in-router corruption.
547. Layered detection: first covering layer catches it.
548. NIC offload computes checksums on real hardware.
549. On TUN, software; red checksum = real bug.
550. Routers incrementally update the IP checksum.
551. NAT fixes both checksums per packet.
552. Fragmentation: per-fragment IP cksum, one transport cksum.
553. We don't fragment/reassemble (a simplification).
554. We don't validate the incoming IP checksum by default.
555. build_echo_reply returns Option (one failure mode).
556. It guards len before indexing.
557. It returns None for non-type-8.
558. Address swap via temporaries (avoid borrow overlap).
559. debug_assert checksums in build fns (free in release).
560. tracing + RUST_LOG is the production logging path.
561. cargo test proves bytes offline (no sudo/TUN).
562. setcap after every build.
563. tcpdump -vv flags bad checksums.
564. Wireshark "checksum incorrect" is decisive on TUN.
565. tc netem injects loss/delay to test robustness.
566. UDP echo is the stateless pseudo-header warm-up.
567. The pseudo-header is the one new checksum wrinkle.
568. The build technique transfers to TCP.
569. The checksum + pseudo-header recur unchanged in Day 3.
570. The module structure makes tcp.rs slot in cleanly.
571. ping (1983, Muuss); ICMP (1981, Postel).
572. traceroute reuses Time Exceeded.
573. Snort/Suricata are parsers + rules at scale.
574. The checksum is the most-run arithmetic on the internet.
575. It must be cheap because every packet pays.
576. Type the checksum; re-type build_echo_reply; Anki from slips; teach it.
577. /tcp-tutor grades your explanation.
578. Three-view debugging: test, log, tcpdump.
579. Day 2 = the write half; Day 1 = read; together = full duplex.
580. Milestone: ping 0% loss, verified three ways.

## CC. What's truly new in Day 3 (deep preview)

Day 3 (TCP handshake) adds exactly three new things; everything else is Day-1/Day-2 skills reused.

### CC.1 — New thing 1: state across packets (the TCB)
ICMP/UDP echo are stateless — handle a packet, forget it. TCP must *remember*: which connections
exist (a `HashMap<Quad, Connection>`), and per connection, the sequence-number bookkeeping
(SND.UNA/NXT, RCV.NXT). This is the single biggest conceptual jump — from a parser to a *machine with
memory*.

### CC.2 — New thing 2: building from scratch with a pseudo-header
The SYN-ACK has no request to mutate (the SYN is the client's; our reply is a fresh packet), so it's
built from scratch (like the §BG ICMP error). Its checksum uses the pseudo-header (like §BL's UDP) —
both techniques you've now previewed. So "new" here is really "combine two things you've seen."

### CC.3 — New thing 3: sequence-number arithmetic
32-bit sequence numbers that wrap (mod 2³²), the +1 for SYN/FIN, cumulative ACKs, and (eventually)
modular comparison. This is the bookkeeping that makes reliable, ordered delivery possible — the
heart of TCP.

### CC.4 — What transfers unchanged
- The checksum (`utils::checksum`) — identical, just with a pseudo-header (you did this for UDP).
- The build discipline — zero the buffer, write fields big-endian, checksum last.
- Bounds-guarded parsing — `tcp::parse` mirrors `ip::parse`/`icmp::parse`.
- The module structure — `tcp.rs` slots in alongside `ip`/`icmp`.
- `iface.recv`/`send` — the same I/O.

### CC.5 — The honest difficulty curve
Day 1: read. Day 2: write (stateless). Day 3+: write with *state and arithmetic*. The jump is real,
which is why Days 1–2 built the foundation carefully. With packet parsing, construction, and the
checksum owned, Day 3's only genuinely hard part is the state machine — and that's where the learning
payoff is highest.

---

## CD. Final consolidated tables (Day 2)

### CD.1 — Every checksum the stack computes/verifies
| Where | Layer | Range | Pseudo? | Action |
|-------|-------|-------|---------|--------|
| ping builds request | ICMP | message | no | compute (kernel) |
| ping builds request | IP | header | no | compute (kernel) |
| we receive request | IP | header | no | (we skip; exercise validates) |
| we build reply | IP | header | no | recompute (`write_header_checksum`) |
| we build reply | ICMP | message | no | recompute |
| kernel ingest reply | IP | header | no | verify (drop if bad) |
| kernel ingest reply | ICMP | message | no | verify (drop if bad) |

### CD.2 — Edit → checksum dependency
| If you change… | …recompute |
|----------------|-----------|
| any IP header byte (addr/TTL/length/proto) | IP header checksum |
| any ICMP byte (type/code/id/seq/data) | ICMP checksum |
| any TCP/UDP byte OR either IP address | transport checksum (pseudo-header includes addrs) |

### CD.3 — Optional vs mandatory checksums
| Protocol | IPv4 | IPv6 |
|----------|------|------|
| IP header | mandatory | (no IP checksum) |
| ICMP | mandatory | mandatory (ICMPv6) |
| UDP | optional (0=none) | mandatory |
| TCP | mandatory | mandatory |

### CD.4 — The Day-2 code map
| File | Adds in Day 2 | Lines (approx) |
|------|---------------|----------------|
| utils.rs | `checksum` | the core |
| ip.rs | `write_header_checksum` | small |
| icmp.rs | `build_echo_reply` | medium |
| main.rs | ICMP reply arm; `mod` decls | small |

## CE. Day 2 — deeper facts (581–650)

581. The kernel computes the request's checksums; we (could) verify them.
582. We recompute the reply's IP + ICMP checksums.
583. The kernel verifies the reply's checksums on ingress.
584. Changing an IP byte → recompute the IP checksum.
585. Changing an ICMP byte → recompute the ICMP checksum.
586. Changing an IP address → recompute the transport checksum too (pseudo-header).
587. IP header checksum: mandatory in v4, gone in v6.
588. ICMP/ICMPv6 checksum: always mandatory.
589. UDP checksum: optional in v4, mandatory in v6.
590. TCP checksum: always mandatory.
591. utils.rs adds the core (`checksum`).
592. ip.rs adds `write_header_checksum`.
593. icmp.rs adds `build_echo_reply`.
594. main.rs adds the ICMP reply arm + mod declarations.
595. The checksum sums 16-bit BE words.
596. u32 accumulator; fold carries at the end.
597. Odd byte becomes the high byte (<<8).
598. One's complement: invert; two zeros; end-around carry.
599. Verify: sum incl. field == 0.
600. Compute: field 0, sum, complement, store BE.
601. IP checksum covers the header only.
602. ICMP checksum covers the whole message.
603. UDP/TCP cover pseudo-header + segment.
604. Pseudo-header: srcIP dstIP 0 proto len.
605. Pseudo-header binds the checksum to addresses.
606. Pseudo-header is input only.
607. Echo reply mutates the request.
608. The payload echoes for free.
609. Reply is size-agnostic.
610. ICMP errors quote the offending header + 8 bytes.
611. ICMP error generation is build-from-scratch.
612. TCP segments build from scratch with state.
613. iface.send = write(tun_fd).
614. A bad checksum is dropped silently.
615. Ping matches replies by ICMP id.
616. RTT from the echoed timestamp.
617. Detection (checksum) precedes recovery (retransmit).
618. The checksum is weak by design.
619. CRC (links) + checksum (end to end) + retransmit (recovery).
620. NIC offload computes checksums on hardware.
621. On TUN, software; red = real bug.
622. Routers update the IP checksum incrementally.
623. NAT fixes both checksums per packet.
624. We don't fragment/reassemble.
625. We don't validate the incoming IP checksum by default.
626. Modules acyclic: utils ← ip ← icmp.
627. The refactor preserved behavior.
628. UDP echo = pseudo-header, no state.
629. The build technique transfers to TCP.
630. Day 3 adds state, build-from-scratch, sequence arithmetic.
631. State (the TCB) is the biggest jump.
632. SYN-ACK is build-from-scratch + pseudo-header.
633. Sequence numbers are 32-bit and wrap.
634. SYN and FIN each consume a sequence number.
635. ACK is cumulative.
636. The checksum transfers unchanged to TCP.
637. The build discipline transfers to TCP.
638. tcp::parse mirrors ip/icmp::parse.
639. tcp.rs slots into the existing module structure.
640. iface.recv/send are the same I/O.
641. cargo test proves bytes offline.
642. tcpdump/Wireshark are the wire ground truth.
643. tc netem stresses with loss/delay.
644. debug_assert checksums in build fns.
645. Type the checksum; re-type build_echo_reply.
646. Anki from your slips; teach it.
647. /tcp-tutor grades your explanation.
648. Three-view debugging: test, log, tcpdump.
649. Day 2 = the write half; ping 0% loss.
650. Day 2 owned: re-type both, hand-checksum, teach verify-to-zero, 0% live.

## CF. Day-2 self-exam (50 questions, no answers)

1. What is Day 2's milestone? 2. What's the first thing Day 2 does that Day 1 didn't?
3. State the checksum algorithm. 4. Why a u32 accumulator? 5. What is end-around carry?
6. Why two zeros in one's complement? 7. State the verify rule. 8. How do you compute (4 steps)?
9. What range does the IP checksum cover? 10. The ICMP checksum? 11. The TCP/UDP checksum?
12. What is the pseudo-header? 13. Why does it exist? 14. Is it transmitted? 15. UDP checksum-0
meaning? 16. Why is TCP's mandatory? 17. List the four echo-reply edits. 18. Why checksum last?
19. Why recompute the IP checksum after swapping addresses? 20. Why recompute ICMP after flipping
type? 21. Why does the payload echo for free? 22. Why is the reply size-agnostic? 23. What is
mutate-in-place vs build-from-scratch? 24. When use each? 25. What does an ICMP error quote, and why?
26. Port Unreachable type/code? 27. Time Exceeded type? 28. What does iface.send do? 29. Why does a
bad checksum vanish silently? 30. How does the kernel match a reply to ping? 31. How is RTT computed?
32. Why did Day 2 justify modules? 33. Draw the module dependency graph. 34. What does `mod X;` do?
35. What does `pub` control? 36. Where do tests live? 37. Why was the refactor safe? 38. Detection vs
recovery? 39. Who recovers from loss? 40. Why is the checksum weak, and why is that OK? 41. Name two
errors it misses. 42. How do routers update it cheaply? 43. What must NAT fix? 44. What did IPv6
change? 45. What is checksum offload? 46. Why is a red checksum on TUN a real bug? 47. What's new in
Day 3 (three things)? 48. What transfers unchanged to Day 3? 49. What's the single most important
Day-2 skill for Day 3? 50. How do you know Day 2 is *owned*, not just read?

If you can answer all 50 cold, Day 2 is yours.

---

## CG. Tracing a corrupted packet through detection

To feel *why* the checksum matters, follow a single bit flip and watch where it's caught.

### CG.1 — The setup
We send a valid echo reply: IP header with checksum `0xB86A`, ICMP message with its checksum. On the
wire (or in a buggy memory copy), one bit flips in byte 14 of the IP header (part of the source
address): `0xC0` → `0xC8`.

### CG.2 — What the corruption does to the sum
Byte 14 is the high byte of the word at offset 14–15. Changing `0xC0xx` to `0xC8xx` increases that
word by `0x0800`, so the one's-complement sum increases by `0x0800`. The stored checksum was computed
for the *old* sum, so the new sum-incl-field is no longer `0xFFFF` — it's `0xFFFF + 0x0800 = 0x07FF`
(after fold), not zero.

### CG.3 — Where it's caught
The receiving kernel runs `checksum(ip_header)` and gets a **nonzero** result (≈`0xF800` after
complement) instead of 0. Verdict: **corrupt → drop**. The packet never reaches the application. The
single flipped bit was detected by the 16-bit checksum because it changed the sum.

### CG.4 — A corruption that slips through
Now flip *two* bits that cancel: increase the word at 12–13 by 1 and decrease the word at 14–15 by 1.
The net change to the sum is 0, so the checksum still verifies to 0 → **accepted despite corruption**.
This is the §AC.2 blind spot, made concrete: the checksum catches the single flip but misses the
canceling pair. (A CRC would catch both; the link-layer CRC likely catches the transmission-induced
one anyway — defense in depth.)

### CG.5 — The layered catch
On a real path, the same single-bit flip would *also* fail the link-layer **CRC-32** at the next hop
(which is stronger), so it'd be dropped even earlier. The IP checksum is the backstop for corruption
the CRC can't see (e.g., introduced inside a router after the CRC was checked). Two independent checks,
two independent chances to catch it.

### CG.6 — The lesson
A checksum turns "silently act on corrupt data" into "detect and drop." Detection is the whole job;
recovery (resend) is TCP's. Watching one bit flip get caught (or slip through a canceling pair) is the
most concrete way to internalize both the *value* and the *limits* of the Internet checksum.

## CH. Day 2 — deeper facts (651–720)

651. A single bit flip changes the one's-complement sum → detected.
652. The receiver's checksum comes out nonzero → drop.
653. A canceling two-bit change leaves the sum unchanged → missed.
654. CRC-32 (links) catches both; it's stronger.
655. The IP checksum backstops corruption the CRC can't see.
656. Detection turns "act on garbage" into "drop."
657. Recovery (resend) is TCP's job, not the checksum's.
658. Two independent checks = two chances to catch corruption.
659. The link CRC often catches transmission flips first.
660. The end-to-end checksum catches in-router corruption.
661. Changing a word by X changes the sum by X.
662. The stored checksum is the complement of the old sum.
663. So a changed word makes sum-incl-field ≠ 0xFFFF.
664. Which makes the verify result ≠ 0 → drop.
665. Canceling changes net to 0 sum delta → undetected.
666. This is the checksum's structural blind spot.
667. Reordering whole words is also undetected.
668. These weaknesses come from addition's commutativity.
669. The same property enables wide/parallel summation.
670. The checksum is weak, cheap, updatable, endianness-independent.
671. CRC is strong but not cheaply updatable.
672. TLS/HMAC handle adversarial tampering.
673. Match the check to the threat model.
674. IP checksum: header only. ICMP: message. TCP/UDP: pseudo+segment.
675. Verify: sum incl. field == 0.
676. Compute: field 0, sum, complement, store BE.
677. Echo reply: swap addrs, TTL, IP cksum, type+ICMP cksum.
678. Checksum last per region.
679. The payload echoes for free.
680. iface.send = write(tun_fd); kernel verifies, drops if bad.
681. Ping matches by id; RTT from echoed timestamp.
682. Day 2 is stateless; Day 3 adds the TCB.
683. SYN-ACK is build-from-scratch + pseudo-header.
684. Sequence numbers wrap mod 2³².
685. SYN/FIN each consume a sequence number.
686. ACK is cumulative ("next expected").
687. The checksum transfers unchanged to TCP.
688. tcp::parse mirrors ip/icmp::parse.
689. The module structure absorbs tcp.rs.
690. UDP echo is the stateless pseudo-header warm-up.
691. ICMP error generation quotes the offending header + 8 bytes.
692. Build-from-scratch starts zeroed; write all fields.
693. total_length = IP header + everything after.
694. The pseudo-header length is the transport length.
695. NAT fixes both checksums incrementally.
696. Routers update the IP checksum on TTL decrement.
697. IPv6 dropped the IP header checksum.
698. NIC offload computes checksums on hardware.
699. On TUN, software; red = real bug.
700. cargo test proves bytes offline.
701. tcpdump -vv flags bad checksums.
702. Wireshark "checksum incorrect" is decisive on TUN.
703. tc netem injects loss/delay.
704. debug_assert checksums in build fns (free in release).
705. tracing + RUST_LOG for structured logs.
706. The Rust checksum is safe (iterators) and fast (like C).
707. The C version risks over-reads (manual pointers).
708. RFC 1071 (algorithm) + 1624 (incremental) are the sources.
709. RFC 1071 lists properties that map to real optimizations.
710. Detection precedes recovery — always.
711. The checksum is the most-run arithmetic on the internet.
712. It must be cheap because every packet pays.
713. Three-view debugging: test, log, tcpdump.
714. Type the checksum; re-type build_echo_reply.
715. Anki from your slips; teach it (the finish line).
716. /tcp-tutor grades your explanation.
717. Day 2 = the write half; Day 1 = the read half.
718. Together = full duplex over TUN.
719. Day 2 milestone: ping 0% loss, verified three ways.
720. Day 2 owned = re-type both, hand-checksum, teach verify-to-zero, 0% live.

## CI. Consolidated glossary (Day 2, alphabetical)

- **Adler-32 / Fletcher** — stronger, position-sensitive checksums (catch reorders); uncommon in IP.
- **build-from-scratch** — synthesize a packet in a zeroed buffer (SYN-ACK, ICMP error).
- **checksum (Internet)** — RFC 1071 one's-complement 16-bit sum; detect, not correct.
- **CRC** — cyclic redundancy check; strong, used at the link layer.
- **detection vs recovery** — checksum detects+drops; TCP recovers (retransmits).
- **echo reply/request** — ICMP type 0 / 8; the ping exchange.
- **end-around carry** — fold overflow back into the low bit; makes the sum mod 2¹⁶−1.
- **incremental update** — patch a checksum in O(1) on one-field change (RFC 1624).
- **mutate-in-place** — build a reply by editing a copy of the request.
- **offload** — NIC computes/verifies checksums in hardware.
- **one's complement** — invert bits; two zeros; the checksum's arithmetic.
- **pseudo-header** — IP fields fed into the TCP/UDP checksum (12 bytes, IPv4).
- **Time Exceeded / Unreachable** — ICMP error types (11 / 3); quote the offending header + 8 bytes.
- **two's complement** — signed-integer representation (invert+1); CPU/Rust arithmetic.
- **verify-to-zero** — a valid region re-summed including its checksum field yields 0.

---

*(Volume II/III conclude next installment: CJ. the genuine Day-2 closing and bridge to Day 3,
completing Day 2 to 5000.)*
