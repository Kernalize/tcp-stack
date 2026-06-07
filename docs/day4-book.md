# Day 4 — TCP, Part 2: Data Transfer (an Echo Server)

> Goal: once a connection is ESTABLISHED, accept the bytes the client sends, acknowledge
> them, and send them back. `printf 'hi' | nc 192.168.0.2 8080` should print `hi`. This is
> the payoff — a working TCP application running on a stack you wrote.

**Contents**
1. What "data transfer" requires
2. Accepting in-order data (and why only in-order, for now)
3. Acknowledgements: cumulative ACK and piggybacking
4. Sending data: consuming sequence numbers
5. The echo logic, walked
6. Modular sequence arithmetic and the simplifications we made
7. The PSH flag
8. Verification
9. Design choices and alternatives
10. Rebuild it yourself — checklist + exercises
11. What the next step adds

---

## 1. What "data transfer" requires

In ESTABLISHED, each segment may carry payload bytes starting at sequence number `seg.seq`.
To turn unreliable packets into an ordered byte stream we must, per segment: decide whether
the data is the next expected bytes, accept it if so, move our "next expected" pointer
forward, and tell the peer how far we've received (an ACK). To *prove* the stream works
end-to-end we also send data — here, the same bytes back (echo).

---

## 2. Accepting in-order data (and why only in-order, for now)

We accept a segment's data only when `seg.seq == RCV.NXT` — i.e. it is exactly the next byte
we expect. Then:

```rust
self.recv.nxt = self.recv.nxt.wrapping_add(payload.len() as u32);
```

`RCV.NXT` now points just past the bytes we hold. If a segment arrives out of order
(`seg.seq > RCV.NXT`, a gap) or is a duplicate (`seg.seq < RCV.NXT`), we currently drop it.
A full stack buffers out-of-order segments and reassembles them when the gap fills; that
(plus retransmission) is the reliability work of a later step. In-order-only is a real
simplification but keeps the core idea clean: **the receiver advances a single cumulative
pointer.**

---

## 3. Acknowledgements: cumulative ACK and piggybacking

TCP's ACK is **cumulative**: `ACK = N` means "I have received everything up to but not
including N; send N next." So after taking 2 bytes at seq 101, we advance `RCV.NXT` to 103
and any segment we send carries `ack = 103`.

**Piggybacking:** an ACK is just a field + a flag on a segment, so it can ride along on a
data segment. Our echo segment is `PSH|ACK` with `ack = RCV.NXT` — it simultaneously sends
data back *and* acknowledges the data we received. One packet, two jobs. (If we had no data
to send, we'd emit a bare `ACK` segment; a real stack also uses *delayed ACKs* to batch
these — §9.)

---

## 4. Sending data: consuming sequence numbers

When we send `k` payload bytes we stamp them with `seq = SND.NXT`, then:

```rust
self.send.nxt = self.send.nxt.wrapping_add(k as u32);
```

Those `k` sequence numbers are now "in flight." `SND.UNA` (oldest unacknowledged) stays put
until the peer ACKs them; the window `SND.UNA .. SND.NXT` is the unacknowledged data a real
stack would keep buffered for retransmission. We update `SND.UNA` from the peer's ACK field
(a simplification — see §6).

---

## 5. The echo logic, walked

`Connection::on_packet` in ESTABLISHED:

```text
if segment has an ACK:           SND.UNA = seg.ack          // peer acknowledged our data
if payload non-empty AND seg.seq == RCV.NXT:                 // in-order data
    RCV.NXT += payload.len()                                 // accept it
    out = segment(seq = SND.NXT, ack = RCV.NXT, PSH|ACK, payload)   // echo + acknowledge
    SND.NXT += payload.len()                                 // our data consumes seq space
    return out                                               // main.rs sends it
```

The handshake's final ACK can itself carry data (a client may send immediately), so
`on_packet` first completes SYN_RCVD→ESTABLISHED and then falls through into this same data
path — no special case needed.

---

## 6. Modular sequence arithmetic and the simplifications we made

Sequence numbers are 32-bit and wrap, so "is A before B?" is **modular**, not plain `<`:
the RFC defines comparisons so that, e.g., `0xFFFFFFFF` is "before" `0x00000001`. A correct
stack uses these modular comparisons to decide whether a seq/ack is acceptable (in-window).
We sidestepped that with two honest simplifications, both flagged in code:

- **In-order only** (`seg.seq == RCV.NXT` exactly) — no acceptance *window* check yet.
- **`SND.UNA = seg.ack` unconditionally** — a real stack only advances UNA, and only if the
  ack falls in `(SND.UNA, SND.NXT]` mod 2³² (otherwise it's a stale or bogus ack to ignore).

These are fine for a cooperative `nc` over a lossless TUN link; they are the first things to
harden for the open internet (Step 6).

---

## 7. The PSH flag

`PSH` ("push") asks the receiver to deliver buffered data to the application promptly rather
than waiting for more. For our echo it's mostly cosmetic (we act on every segment
immediately), but we set it on outgoing data because that's what a sender of a small,
complete message does, and it's what `nc`/`tcpdump` expect to see.

---

## 8. Verification

`cargo test` → 16 green (no TUN/sudo). The new one, `established_echoes_data`:
- establishes a connection, then feeds an in-order 2-byte segment;
- asserts `RCV.NXT` 101→103 and `SND.NXT` 1→3;
- asserts the echo is a valid IP+TCP packet (`utils::checksum(ip)==0`,
  `tcp_checksum(...)==0`), flags `PSH|ACK`, `seq=1`, `ack=103`, payload `"hi"`.

Live (your hands): run the stack, then
```bash
printf 'hello\n' | nc -q1 192.168.0.2 8080
```
`nc` prints `hello` back — the bytes made a full round trip through your TCP. `tcpdump -i
tun0` shows: SYN, SYN-ACK, ACK, then the data segment and your echo (`P.` flags) with the
matching seq/ack numbers.

---

## 9. Design choices and alternatives

| Decision | We chose | Alternative | Why / caveat |
|---|---|---|---|
| Out-of-order data | drop | buffer + reassemble | reassembly needs a receive queue; reliability step |
| ACK strategy | piggyback on echo | delayed/standalone ACKs | fine for request/response; delayed-ACK batches for efficiency |
| Send window | ignore peer's window | obey SND.WND (flow control) | we never flood `nc`; flow control matters for bulk transfer |
| Nagle's algorithm | off (send immediately) | coalesce small writes | Nagle reduces tiny-packet overhead; irrelevant for echo |
| UNA update | trust seg.ack | validate in (UNA, NXT] | required against stale/forged acks on a real network |

---

## 10. Rebuild it yourself — checklist + exercises

From memory:
1. The in-order test `seg.seq == RCV.NXT` and the `RCV.NXT += len` advance.
2. Why an ACK is cumulative and how the echo piggybacks it.
3. `seq = SND.NXT` on send, then `SND.NXT += len`; what `SND.UNA` means.
4. Why sequence comparisons must be modular.

**Exercises:**
- **E1.** Send a **bare ACK** for received data when you have nothing to echo (generalize
  beyond echo): build an `ACK` segment with `seq=SND.NXT, ack=RCV.NXT`, no payload.
- **E2.** Buffer **one** out-of-order segment and deliver it once the gap fills; add a test.
- **E3.** Implement the modular `is_between_wrapping(start, x, end)` helper (RFC 9293 style)
  and use it to validate incoming acks; test the wraparound boundary.
- **E4.** Respect `SND.WND`: don't send more unacknowledged data than the peer's advertised
  window.

---

## 11. What the next step adds

Step 5 is **teardown**: handle the client's `FIN` (it consumes a sequence number, like SYN),
ACK it, send our own `FIN`, and walk the closing states (CLOSE_WAIT → LAST_ACK, or
FIN_WAIT_1 → FIN_WAIT_2 → TIME_WAIT). After that the connection lifecycle is complete:
open → transfer → close. Reliability (retransmission/RTO) and congestion control are the
final hardening, and require moving off the purely blocking I/O model — covered with design
notes at the end.

> Re-type the ESTABLISHED branch of `on_packet` from this chapter, then `cargo test`.
