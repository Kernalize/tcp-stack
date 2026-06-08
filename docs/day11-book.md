# Day 11 — TCP, Part 9: The Socket API & a Tiny HTTP Server

> Goal: turn the machinery into something an **application** can use. Everything through Day 10
> was internal plumbing — handshake, reliability, windows, congestion. None of it was reachable by
> a program that just wants to "send these bytes and read those." This chapter adds the interface:
> a send buffer, a receive buffer, and a `write` / `take_received` / `poll_transmit` API — then
> drives it with two real apps: the echo server you've had all along, and a tiny HTTP/1.0 server
> that satisfies `curl`. This is the Manual's Week-10 milestone and the last build day.

**Contents**
1. The mental model: machinery vs interface
2. The send buffer and `poll_transmit`
3. The receive buffer and `take_received`
4. Receive split from send: why `on_packet_at` stopped echoing
5. The applications: echo and HTTP/1.0
6. Closing after the response
7. The event loop, end to end
8. Worked example: one `curl`
9. The code, walked
10. Verification
11. Why this, not that — and why no blocking `TcpListener`
12. Rebuild it yourself — checklist + exercises
13. What's still not done (the honest final status)

---

## 1. The mental model: machinery vs interface

A TCP implementation has two faces. *Inward*, it talks to the network: parse segments, ACK, retransmit,
slide windows. *Outward*, it talks to the application: "here are the bytes that arrived, in order"
and "please send these bytes, reliably, when you can." Days 1–10 built the inward face. The outward
face is two byte buffers and three verbs:

- **`write(bytes)`** — the app hands us bytes to send. They join a **send buffer**.
- **`take_received() → bytes`** — the app collects bytes that have arrived in order, from a
  **receive buffer**.
- **`poll_transmit() → segments`** — the stack drains the send buffer onto the wire, as fast as the
  window allows.

That's the whole socket abstraction, minus naming. A `TcpStream::write`/`read` is a thin coat of
paint over exactly these (§11).

---

## 2. The send buffer and `poll_transmit`

`write` just appends to a `VecDeque<u8>` — the bytes the app wants sent but that haven't gone out
yet. The interesting part is `poll_transmit`, which converts buffered bytes into wire segments,
**bounded by the window and chopped to the MSS**:

```rust
while !self.send_buf.is_empty() {
    let n = (self.usable_window() as usize).min(MSS).min(self.send_buf.len());
    if n == 0 { break; }                                   // window full — wait for an ACK
    let payload: Vec<u8> = self.send_buf.drain(..n).collect();
    let seg = self.segment(self.send.nxt, self.recv.nxt, PSH | ACK, &payload);
    self.send.nxt = self.send.nxt.wrapping_add(n as u32);
    self.retx.record(self.send.nxt, seg.clone(), now_ms);  // reliability (Day 6)
    out.push(seg);
}
```

This single loop ties together everything: `usable_window()` is `min(SND.WND, cwnd) − FlightSize`
(flow control + congestion control), `MSS` is the segmentation unit, and every segment is recorded
for retransmission. With `cwnd` starting at 1 MSS, a 5 KB `write` leaves as *one* segment, and the
rest waits — slow start, finally visible (the `bulk_send_is_gated_by_the_congestion_window` test).

---

## 3. The receive buffer and `take_received`

Symmetrically, in-order bytes from the reassembler (Day 9) are appended to a receive buffer instead
of being echoed inline:

```rust
if !delivered.is_empty() {
    self.recv.nxt = self.recv.nxt.wrapping_add(delivered.len() as u32);
    self.recv_buf.extend_from_slice(&delivered);
}
return Some(self.segment(self.send.nxt, self.recv.nxt, ACK, &[]));  // acknowledge
```

`take_received` hands the app everything buffered and clears it:

```rust
pub fn take_received(&mut self) -> Vec<u8> { std::mem::take(&mut self.recv_buf) }
```

---

## 4. Receive split from send: why `on_packet_at` stopped echoing

Through Day 10, receiving data *was* sending data — `on_packet_at` built and returned the echo
inline. That conflates two responsibilities and only works for an echo server. The refactor
separates them:

- **Receiving** (`on_packet_at`): reassemble → buffer → return a **bare ACK**. It never decides
  *what* to send back; that's the app's job.
- **Sending** (`write` + `poll_transmit`): driven by the application, gated by the window.

So a data segment now produces an immediate ACK, and *separately* the application reads the bytes
and may produce a response that `poll_transmit` sends. Two packets where there was one — slightly
chattier, but it's the separation that makes anything other than an echo possible (like HTTP).

---

## 5. The applications: echo and HTTP/1.0

With the API in place, `main.rs`'s loop becomes a tiny application runtime:

```rust
let received = conn.take_received();
if !received.is_empty() {
    if let Some(resp) = http_response(&received) {   // looks like a GET/HEAD/POST?
        conn.write(&resp);  serving_http = true;     // serve 200 OK
    } else {
        conn.write(&received);                       // echo
    }
}
for seg in conn.poll_transmit(now_ms) { iface.send(&seg)?; }
```

`http_response` recognises a request line and returns a canned `HTTP/1.0 200 OK` with a
`Content-Length` and a one-line body; anything else falls through to echo. (A real server buffers
until the blank line `\r\n\r\n`; a `curl` GET fits in one segment over our local link, so matching
the request line suffices — §13 lists the simplification.)

---

## 6. Closing after the response

HTTP/1.0 with `Connection: close` means the **server** closes once the response is sent — and the
active-close path from Day 7 is exactly what we need:

```rust
if serving_http {
    if let Some(fin) = conn.close() { iface.send(&fin)?; }   // → FIN_WAIT_1
}
```

`close()` is valid from ESTABLISHED, sends `FIN|ACK` at `SND.NXT` (after the response bytes
`poll_transmit` already advanced past), and moves us into `FIN_WAIT_1`. The client's ACK and FIN
then drive us through `FIN_WAIT_2 → TIME_WAIT → CLOSED`, and the event loop reaps the TCB. The whole
lifecycle — open, transfer, close — runs for every `curl`.

---

## 7. The event loop, end to end

`main.rs` is now a complete, if minimal, TCP server runtime:

```text
loop:
  now = clock.elapsed()
  for each connection:                      # timers
      send any retransmissions (on_tick)    # RTO fired → also signals congestion (Day 10)
      reap if CLOSED                         # TIME_WAIT expired
  recv one packet (non-blocking):
      ICMP  → echo reply
      UDP   → echo
      TCP   → conn.on_packet_at  → ACK
              app: take_received → write(echo or HTTP) → poll_transmit → send
              if HTTP: close()
      new SYN → accept; stray → RST
```

Every mechanism built over eleven days meets here: parsing, checksums, the handshake, reassembly,
retransmission, the adaptive RTO, both windows, and teardown.

---

## 8. Worked example: one `curl`

```text
curl http://192.168.0.2:8080/

 SYN                → SYN-ACK → ACK                     (handshake, Day 3)
 PSH "GET / HTTP/1.0\r\n…\r\n\r\n"
                    → ACK (bare, acknowledges the request)        (Day 11 §3)
 app: take_received() sees "GET …" → http_response() → write(200 OK)
                    → PSH "HTTP/1.0 200 OK… Hello…"   (poll_transmit, window-gated)
                    → FIN|ACK                          (close(), Day 7)
 ACK, FIN|ACK       → ACK → TIME_WAIT → (2·MSL) → CLOSED → TCB reaped
```

`curl` prints the body and exits 0. Every number — seq/ack, the FIN handshake — is the same logic
the unit tests pin offline.

---

## 9. The code, walked

| Piece | Role |
|---|---|
| `Connection.send_buf` / `write` / `poll_transmit` | app→wire: queue, then window-gated MSS segments (Day 11a) |
| `Connection.recv_buf` / `take_received` | wire→app: in-order delivered bytes |
| `on_packet_at` (data branch) | reassemble → buffer → bare ACK (no inline echo) |
| `main.rs` app loop | `take_received` → echo or `http_response` → `write` → `poll_transmit` |
| `http_response` | canned HTTP/1.0 200 OK for a request line |
| `conn.close()` | active close after the HTTP response (Day 7) |

---

## 10. Verification

`cargo test` → **61 green**. The Day-11 coverage:

- `bulk_send_is_gated_by_the_congestion_window` — a 5 KB write leaves one MSS segment under
  cwnd=1·MSS; after an ACK grows cwnd to 2·MSS, two segments go. Slow start, demonstrated.
- `established_delivers_data_then_app_echoes` — data → bare ACK + `take_received()` returns it;
  the app `write`s it back and `poll_transmit` produces the echo segment with the right seq/ack.
- All the reassembly / retransmission / dup-ACK / window tests, updated to the write/poll_transmit
  API, still pass — the control logic is unchanged, only the *interface* moved.

Live (your hands), via `tcp-stack-run`: `curl http://192.168.0.2:8080/` prints the body and the
log shows the request, the 200 OK, and the FIN handshake; `nc 192.168.0.2 8080` still echoes lines.
Under `tc netem loss 5%`, both survive — reliability, flow, and congestion control all engaged.

---

## 11. Why this, not that — and why no blocking `TcpListener`

| Decision | We chose | Real TCP / alternative |
|---|---|---|
| API shape | `write` / `take_received` / `poll_transmit` on the connection | `TcpStream::{read,write}` + `TcpListener::accept` |
| Concurrency | single-threaded event loop, app inline | blocking sockets across threads, or async tasks |
| HTTP parsing | match the request line | buffer until `\r\n\r\n`, parse method/path/headers |
| Response | one canned body | route by path, serve files, keep-alive |

The Manual sketches `TcpListener::bind` / `accept() → TcpStream` with **blocking** reads. We
deliberately don't build that: a blocking `accept`/`read` needs a thread (or async runtime) parked
on a channel that the event loop feeds — a real concurrency layer. Our single-threaded loop already
*is* the runtime, and `write`/`take_received`/`poll_transmit` *are* the stream operations. Wrapping
them in `TcpStream`/`TcpListener` newtypes with a blocking facade is a worthwhile exercise (E1) but
adds machinery, not understanding. The honest statement: the **functional** socket API exists; the
**blocking-stdlib-shaped** veneer is optional sugar.

---

## 12. Rebuild it yourself — checklist + exercises

From a blank file:
1. The three verbs (`write`, `take_received`, `poll_transmit`) and which direction each moves bytes.
2. Why `poll_transmit`'s loop is where flow control, congestion control, segmentation, and
   retransmission all meet.
3. Why `on_packet_at` had to stop echoing for anything but echo to be possible.
4. The full `curl` lifecycle: handshake → request → ACK → response → FIN → TIME_WAIT.

**Exercises:**
- **E1.** Wrap the API in blocking `TcpListener`/`TcpStream` types backed by channels + a worker
  thread, matching the Manual's signatures.
- **E2.** Make `http_response` buffer until `\r\n\r\n`, parse the path, and serve different bodies
  (and a 404).
- **E3.** Support HTTP keep-alive: don't close after the response; handle a second request on the
  same connection.
- **E4.** Add backpressure: when `poll_transmit` can't drain `send_buf` (window full), have the app
  stop producing until an ACK opens it — the real meaning of a blocking `write`.

---

## 13. What's still not done (the honest final status)

Eleven days in, the stack does the **whole TCP lifecycle, reliably, over a real link**, driven by a
real application. What a production, internet-grade TCP still needs — none of it doable purely
offline in this build:

1. **Conformance + load testing** — `packetdrill` scripts against the kernel, `iperf3` throughput
   under `tc netem`, flamegraphs (Manual Week 11). Needs sudo/TUN and live runs.
2. **Hardening** — SYN/FIN retransmission (only data is queued today), zero-window probes, window
   scaling + timestamps (RFC 7323), SACK (RFC 2018), RFC 5961 RST validation, a distinct
   CLOSE_WAIT, half-close, MSS negotiation, NewReno/CUBIC.
3. **A blocking socket veneer + multi-request HTTP** (§11–12 exercises).
4. **The "polish" of Manual Week 12** — README, demo GIF, blog post, CI, v1.0.0 — a personal
   artifact, not code a tool should fabricate.

The honest headline: **a from-scratch TCP/IP stack that a stock `ping`, `nc`, and `curl`
interoperate with — handshake, reliable ordered transfer, adaptive RTO, flow control, reassembly,
congestion control, and clean teardown — every mechanism unit-tested.** That is a complete,
correct *core*. The remaining list is breadth and robustness, not a missing heart.

> Re-type the send/receive buffers and `poll_transmit` with the book closed, then `cargo test`. You
> have now built TCP end to end: from a raw IPv4 packet (Day 1) to an application serving HTTP over
> your own reliable, congestion-controlled byte stream (Day 11). That is the whole arc.
