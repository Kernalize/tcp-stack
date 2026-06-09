# Day 11 — TCP, Part 9: The Socket API & a Tiny HTTP Server

> Goal: turn the machinery into something an **application** can use. Everything through Day 10 was
> internal plumbing — handshake, reliability, windows, congestion. None of it was reachable by a program
> that just wants to "send these bytes and read those." This chapter adds the interface: a send buffer, a
> receive buffer, and a `write` / `take_received` / `poll_transmit` API — then drives it with two real
> apps: the echo server you've had all along, and a tiny HTTP/1.0 server that satisfies `curl`. This is the
> Manual's Week-10 milestone and the day the stack becomes a *server*.

For ten days the stack talked only to the network. Today it grows its *other* face — the one an
application sees. The lesson is that a "socket" is not magic: it's two byte buffers and three verbs
(`write`, `take_received`, `poll_transmit`), and `poll_transmit` is the single place where flow control,
congestion control, segmentation, and retransmission all finally meet and *bind*.

**Contents**

Volume I — the chapter
1. The mental model: machinery vs interface
2. The send buffer and `poll_transmit`
3. The receive buffer and `take_received`
4. Receive split from send: why the handler stopped echoing
5. The applications: echo and HTTP/1.0
6. Closing after the response
7. The event loop, end to end
8. Worked example: one `curl`
9. The Rust: `VecDeque`, `mem::take`, and the borrow dance
10. The code, walked
11. Verification
12. Why this, not that — and why no blocking `TcpListener`
13. Honesty: the final status
14. Rebuild it yourself — checklist + exercises
15. What the next step adds

Volume II — the exhaustive reference
- A. The BSD sockets API we're reimplementing, call by call
- B. Blocking, non-blocking, and async — the concurrency models
- C. HTTP/1.0 → 1.1 → 2 → 3, and the close-delimited body
- D. Send/receive buffer design and backpressure
- E. How `poll_transmit` ties every layer together
- F. A worked `curl`, byte by byte
- G. Comparison to real stacks — the socket layer and C10K
- H. Security — HTTP parsing as attack surface
- I. Performance — the receive/send split and the extra ACK
- J. Extended FAQ
- K. Anki starter deck
- L. Glossary
- M. Reference tables

---

# Volume I — the chapter

## 1. The mental model: machinery vs interface

A TCP implementation has two faces. *Inward*, it talks to the network: parse segments, ACK, retransmit,
slide windows. *Outward*, it talks to the application: "here are the bytes that arrived, in order" and
"please send these bytes, reliably, when you can." Days 1–10 built the inward face. The outward face is
two byte buffers and three verbs:

- **`write(bytes)`** — the app hands us bytes to send. They join a **send buffer**.
- **`take_received() → bytes`** — the app collects bytes that have arrived in order, from a **receive
  buffer**.
- **`poll_transmit() → segments`** — the stack drains the send buffer onto the wire, as fast as the window
  allows.

That's the whole socket abstraction, minus naming. A `TcpStream::write`/`read` is a thin coat of paint over
exactly these (§A). The deep point: the application's view (a reliable, ordered, flow-controlled byte
stream) is an *illusion* maintained by the inward machinery; the socket API is the seam where the illusion
is handed over.

## 2. The send buffer and `poll_transmit`

`write` just appends to a `VecDeque<u8>` — the bytes the app wants sent but that haven't gone out yet. The
interesting part is `poll_transmit`, which converts buffered bytes into wire segments, **bounded by the
window and chopped to the MSS**:

```rust
while !self.send_buf.is_empty() {
    let n = (self.usable_window() as usize).min(mss).min(self.send_buf.len());
    if n == 0 { break; }                                   // window full — wait for an ACK
    // (Nagle, Day 13: hold a sub-MSS tail while data is in flight, unless TCP_NODELAY)
    let payload: Vec<u8> = self.send_buf.drain(..n).collect();
    let seg = self.segment(self.send.nxt, self.recv.nxt, PSH | ACK, &payload);
    self.send.nxt = self.send.nxt.wrapping_add(n as u32);
    self.retx.record(self.send.nxt.wrapping_sub(n as u32), self.send.nxt, seg.clone(), now_ms);
    out.push(seg);
}
```

This single loop ties together everything: `usable_window()` is `min(SND.WND, cwnd) − FlightSize` (flow
control + congestion control), `mss` is the segmentation unit (negotiated on Day 15), and every segment is
recorded for retransmission (Day 6). With `cwnd` starting at 1 MSS, a 5 KB `write` leaves as *one* segment,
and the rest waits — slow start, finally *visible* and *binding* (`bulk_send_is_gated_by_the_congestion_window`).
This is the moment Day 10's congestion control stopped being theoretical: it now actually clamps a real
backlog.

## 3. The receive buffer and `take_received`

Symmetrically, in-order bytes from the reassembler (Day 9) are appended to a receive buffer instead of
being echoed inline:

```rust
if !delivered.is_empty() {
    self.recv.nxt = self.recv.nxt.wrapping_add(delivered.len() as u32);
    self.recv_buf.extend_from_slice(&delivered);
}
return Some(self.segment_opts(self.send.nxt, self.recv.nxt, ACK, &self.ack_options(), &[]));  // acknowledge
```

`take_received` hands the app everything buffered and clears it in one move:

```rust
pub fn take_received(&mut self) -> Vec<u8> { std::mem::take(&mut self.recv_buf) }
```

## 4. Receive split from send: why the handler stopped echoing

Through Day 10, receiving data *was* sending data — `on_segment` built and returned the echo inline. That
conflates two responsibilities and only works for an echo server. The refactor separates them:

- **Receiving** (`on_segment`): reassemble → buffer → return a **bare ACK**. It never decides *what* to
  send back; that's the app's job.
- **Sending** (`write` + `poll_transmit`): driven by the application, gated by the window.

So a data segment now produces an immediate ACK, and *separately* the application reads the bytes and may
produce a response that `poll_transmit` sends. Two packets where there was one — slightly chattier, but it's
the separation that makes anything other than an echo possible (like HTTP), and it mirrors how every real
stack works: the protocol ACKs autonomously; the application sends on its own schedule. (§I weighs the
extra-ACK cost.)

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

`http_response` recognises a request line and returns a canned `HTTP/1.0 200 OK` with a `Content-Length`
and a one-line body; anything else falls through to echo. (A real server buffers until the blank line
`\r\n\r\n`; a `curl` GET fits in one segment over our local link, so matching the request line suffices —
§13, §C, §H list the simplifications.)

## 6. Closing after the response

HTTP/1.0 with `Connection: close` means the **server** closes once the response is sent — and the
active-close path from Day 7 is exactly what we need:

```rust
if serving_http {
    if let Some(fin) = conn.close(now_ms) { iface.send(&fin)?; }   // → FIN_WAIT_1
}
```

`close()` is valid from ESTABLISHED, sends `FIN|ACK` at `SND.NXT` (after the response bytes `poll_transmit`
already advanced past), queues the FIN for retransmission (Day 12), and moves us into `FIN_WAIT_1`. The
client's ACK and FIN then drive us through `FIN_WAIT_2 → TIME_WAIT → CLOSED`, and the event loop reaps the
TCB. The whole lifecycle — open, transfer, close — runs for every `curl`, and this is the **first** code
path where our binary actively closes (Day 7's machinery, finally exercised live).

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
         TCP   → conn.on_segment  → ACK
                 app: take_received → write(echo or HTTP) → poll_transmit → send
                 if HTTP: close()
         new SYN → accept; stray → RST
```

Every mechanism built over eleven days meets here: parsing, checksums, the handshake, reassembly,
retransmission, the adaptive RTO, both windows, congestion control, and teardown.

## 8. Worked example: one `curl`

```text
   curl http://192.168.0.2:8080/

    SYN                → SYN-ACK → ACK                     (handshake, Day 3)
    PSH "GET / HTTP/1.0\r\n…\r\n\r\n"
                       → ACK (bare, acknowledges the request)        (§3)
    app: take_received() sees "GET …" → http_response() → write(200 OK)
                       → PSH "HTTP/1.0 200 OK… Hello…"   (poll_transmit, window-gated)
                       → FIN|ACK                          (close(), Day 7)
    ACK, FIN|ACK       → ACK → TIME_WAIT → (2·MSL) → CLOSED → TCB reaped
```

`curl` prints the body and exits 0. Every number — seq/ack, the FIN handshake — is the same logic the unit
tests pin offline. (§F traces it byte by byte.)

## 9. The Rust: `VecDeque`, `mem::take`, and the borrow dance

- **`VecDeque<u8>` for the send buffer.** `write` appends to the back; `poll_transmit` drains from the front
  (`drain(..n)`). A `VecDeque` is the right structure for a FIFO byte queue — O(1) push-back and
  pop-front — versus a `Vec` whose front-removal is O(n). The receive buffer is a plain `Vec<u8>` because we
  only ever append and then take *all* of it.
- **`std::mem::take` for the receive hand-off.** `take_received` swaps the `recv_buf` with an empty `Vec`
  and returns the old one — moving ownership to the app with **zero copy** and leaving a fresh empty buffer.
  This is the idiomatic Rust "take everything and reset" move; the alternative (`clone()` then `clear()`)
  would copy every byte.
- **The borrow dance in the loop.** `main` calls `conn.take_received()` (an `&mut` borrow), then
  `conn.write(...)` (another), then `conn.poll_transmit()` (another) — each borrow begins and ends within
  one statement, so the borrow checker is satisfied without any `Rc`/`RefCell`. Returning owned `Vec`s from
  these methods (rather than handing out references into the connection) is what keeps the borrows short and
  the loop clean.
- **`drain(..n).collect()`** moves `n` bytes out of the deque into the segment payload in one shot, leaving
  the rest queued for the next `poll_transmit`.

## 10. The code, walked end to end

| Piece | Role |
|---|---|
| `Connection.send_buf` / `write` / `poll_transmit` | app→wire: queue, then window-gated MSS segments |
| `Connection.recv_buf` / `take_received` | wire→app: in-order delivered bytes, moved out via `mem::take` |
| `on_segment` (data branch) | reassemble → buffer → bare ACK (no inline echo) |
| `main.rs` app loop | `take_received` → echo or `http_response` → `write` → `poll_transmit` |
| `http_response` | canned HTTP/1.0 200 OK for a request line |
| `conn.close(now_ms)` | active close after the HTTP response (Day 7) |

## 11. Verification

`cargo test` proves the API offline. The Day-11 coverage:

- `bulk_send_is_gated_by_the_congestion_window` — a 5 KB write leaves one MSS segment under cwnd=1·MSS;
  after an ACK grows cwnd to 2·MSS, two segments go. Slow start, demonstrated and *binding*.
- `established_delivers_data_then_app_echoes` — data → bare ACK + `take_received()` returns it; the app
  `write`s it back and `poll_transmit` produces the echo segment with the right seq/ack.
- The Nagle tests (`nagle_holds_small_write_until_prior_data_acked`, `nodelay_sends_small_write_immediately`,
  Day 13) exercise `poll_transmit`'s hold logic.
- All the reassembly / retransmission / dup-ACK / window tests, updated to the write/poll_transmit API,
  still pass — the control logic is unchanged, only the *interface* moved.

Live (your hands): `curl http://192.168.0.2:8080/` prints the body and the log shows the request, the
200 OK, and the FIN handshake; `nc 192.168.0.2 8080` still echoes lines. Under `tc netem loss 5%`, both
survive — reliability, flow, and congestion control all engaged.

## 12. Why this, not that — and why no blocking `TcpListener`

| Decision | We chose | Real TCP / alternative |
|---|---|---|
| API shape | `write` / `take_received` / `poll_transmit` on the connection | `TcpStream::{read,write}` + `TcpListener::accept` |
| Concurrency | single-threaded event loop, app inline | blocking sockets across threads, or async tasks |
| HTTP parsing | match the request line | buffer until `\r\n\r\n`, parse method/path/headers |
| Response | one canned body | route by path, serve files, keep-alive |

The Manual sketches `TcpListener::bind` / `accept() → TcpStream` with **blocking** reads. We deliberately
don't build that: a blocking `accept`/`read` needs a thread (or async runtime) parked on a channel that the
event loop feeds — a real concurrency layer (§B). Our single-threaded loop already *is* the runtime, and
`write`/`take_received`/`poll_transmit` *are* the stream operations. Wrapping them in
`TcpStream`/`TcpListener` newtypes with a blocking facade is a worthwhile exercise (E1) but adds machinery,
not understanding. The honest statement: the **functional** socket API exists; the **blocking-stdlib-shaped**
veneer is optional sugar.

## 13. Honesty: the final status

Eleven days in (and now eighteen), the stack does the **whole TCP lifecycle, reliably, over a real link**,
driven by a real application. The status, *updated* for everything Days 12–18 added since this chapter was
first written:

- **Done since day 11:** SYN/SYN-ACK/FIN retransmission (Day 12), exponential RTO backoff (Day 12), Nagle +
  `TCP_NODELAY` (Day 13), zero-window probes / persist timer (Day 14), TCP options framework + MSS
  negotiation (Day 15), timestamps + RTTM + PAWS (Day 16), window scaling (Day 17), and SACK (Day 18). The
  original day-11 "not done" list has largely been *done*.
- **Still genuinely missing:** RFC 5961 in-window RST/SYN validation, a distinct CLOSE_WAIT + half-close,
  modern congestion control (NewReno/CUBIC — we ship Reno), SACK-based loss recovery's full RFC 6675
  scoreboard, and a blocking `TcpListener`/`TcpStream` veneer with multi-request/keep-alive HTTP.
- **Live testing breadth:** `packetdrill` conformance against the kernel, `iperf3` throughput under
  `tc netem`, and flamegraphs — all need sudo/TUN and live runs, not offline tests.
- **The "polish":** README/demo/CI/release — a personal artifact, not code to fabricate.

The honest headline: **a from-scratch TCP/IP stack that a stock `ping`, `nc`, and `curl` interoperate
with — handshake, reliable ordered transfer, adaptive RTO, flow control, reassembly, congestion control,
options (MSS/timestamps/window-scale/SACK), and clean teardown — every mechanism unit-tested.** A complete,
correct core; the remainder is breadth and robustness, not a missing heart.

## 14. Rebuild it yourself — checklist + exercises

**Blank-file checklist:**

- [ ] The three verbs (`write`, `take_received`, `poll_transmit`) and which direction each moves bytes.
- [ ] Why `poll_transmit`'s loop is where flow control, congestion control, segmentation, and
      retransmission all meet.
- [ ] Why the data handler had to stop echoing for anything but echo to be possible.
- [ ] The full `curl` lifecycle: handshake → request → ACK → response → FIN → TIME_WAIT.
- [ ] Why `mem::take` (not clone) is the right receive hand-off.

**Exercises:**

- **E1.** Wrap the API in blocking `TcpListener`/`TcpStream` types backed by channels + a worker thread,
  matching the Manual's signatures (§B).
- **E2.** Make `http_response` buffer until `\r\n\r\n`, parse the path, and serve different bodies (and a
  404) (§H).
- **E3.** Support HTTP keep-alive: don't close after the response; handle a second request on the same
  connection (§C) — and note this avoids the TIME_WAIT cost (Day 7).
- **E4.** Add real backpressure: when `poll_transmit` can't drain `send_buf` (window full), have the app
  stop producing until an ACK opens it — the real meaning of a blocking `write` (§D).
- **E5.** Add request smuggling defenses: reject conflicting `Content-Length`/`Transfer-Encoding`, cap
  header size and count (§H).

## 15. What the next step adds

The lifecycle is complete and application-driven. The remaining days are **hardening** — making the stack
robust against loss and a hostile network, and speaking TCP's full option vocabulary: control-segment
retransmission (Day 12), Nagle (Day 13), zero-window probes (Day 14), MSS negotiation (Day 15), timestamps
(Day 16), window scaling (Day 17), and SACK (Day 18). Each builds directly on the socket API and event loop
assembled here.

---

# Volume II — the exhaustive reference

## A. The BSD sockets API we're reimplementing, call by call

The POSIX/BSD sockets API is the interface every networked program uses; our three verbs are its core.
Mapping them:

```text
   BSD call            what it does                            our analogue
   ─────────────────   ─────────────────────────────────────  ──────────────────────────
   socket()            create an endpoint                      Connection (per flow)
   bind() + listen()   claim a port, become a listener         implicit (any SYN → accept)
   accept()            return a new connected socket            (no queue; TCB created on SYN)
   connect()           active open                              Connection::connect (tests)
   write()/send()      queue bytes to send                      write() → send_buf
   read()/recv()       read received bytes                      take_received()
   close()             graceful close                           close() → FIN (Day 7)
   shutdown(SHUT_WR)   half-close one direction                 (unsupported; Day 5 §E)
   setsockopt(NODELAY) disable Nagle                            set_nodelay() (Day 13)
```

The two BSD ideas we *don't* model are the **listening socket** (a passive endpoint that spawns a new
connected socket per `accept`, with backlog queues — Day 3 §I) and **blocking semantics** (a `read` that
sleeps until data arrives — §B). Our event loop collapses the listener into "any SYN makes a TCB" and
replaces blocking with polling. The functional behavior (queue bytes, read bytes, close) is identical; the
*shape* differs.

## B. Blocking, non-blocking, and async — the concurrency models

How an application waits for I/O is the defining axis of a server's design:

```text
   model              the app does…                    server shape           our build
   ────────────────   ──────────────────────────────   ────────────────────   ────────────
   blocking           read() sleeps until data           thread per connection  no
   non-blocking poll  read() returns WouldBlock; spin    one loop, poll fds     yes (the loop)
   readiness (epoll)  wait on many fds at once            one loop, scalable     conceptually
   async/await        await a future; runtime schedules   tasks on a runtime     no (but our loop IS one)
```

A **blocking** `TcpStream::read` (the Manual's sketch) needs the reading code to be a separate thread (or
async task), because *something* must keep servicing the network while that thread sleeps — and that
something is an event loop feeding the thread via a channel. So "add blocking sockets" really means "add a
concurrency layer on top of the event loop," which is why we treat it as optional sugar (E1). Our
single-threaded `write`/`take_received`/`poll_transmit` loop *is* the non-blocking model, and it's exactly
the architecture high-performance servers (nginx, Redis, Node) use — one loop, never block, multiplex many
connections. The blocking model (thread-per-connection) is simpler to *write* but doesn't scale to C10K
(§G).

## C. HTTP/1.0 → 1.1 → 2 → 3, and the close-delimited body

Our server speaks minimal HTTP/1.0. The lineage, and what each version asks of TCP:

```text
   version   year   key feature                       TCP relationship
   ───────   ────   ───────────────────────────────   ───────────────────────────────────
   HTTP/1.0  1996   one request/response per conn      open → req → resp → close (our model)
   HTTP/1.1  1997   keep-alive, chunked, pipelining    persistent conn (avoid handshake/TIME_WAIT)
   HTTP/2    2015   multiplexed streams over one conn   one TCP conn; suffers TCP HOLB (Day 9 §J)
   HTTP/3    2022   over QUIC (UDP)                     abandons TCP for per-stream reassembly
```

HTTP/1.0's **close-delimited body** is what lets our server be so simple: with `Connection: close`, the
body ends when the connection closes, so we don't even need `Content-Length` to be correct (though we send
it) — `curl` reads until EOF. HTTP/1.1 keep-alive (E3) reuses one connection for many requests, amortizing
the Day-3 handshake and the Day-7 TIME_WAIT (the close-storm fix, Day 7 §J) — which is why it became the
default. HTTP/2 multiplexes streams but still rides one TCP connection, so a single packet loss head-of-line
blocks *all* streams (Day 9 §J); HTTP/3 moves to QUIC over UDP precisely to escape that. The arc:
application protocols kept pushing against TCP's one-ordered-stream model until HTTP/3 left it.

## D. Send/receive buffer design and backpressure

The two buffers are the seam between application speed and network speed, and they're where **backpressure**
lives:

- **Send buffer (`send_buf`).** The app `write`s faster than the window allows; the excess queues here. In
  a real blocking API, when this buffer is full, `write()` *blocks* (or returns `EWOULDBLOCK`) — that's
  backpressure telling the app "slow down, the network can't keep up." Our `write` never blocks (it just
  appends), so an app could queue unbounded data; E4 adds the real backpressure. `SO_SNDBUF` sizes this in
  a real stack.
- **Receive buffer (`recv_buf`).** Data arrives faster than the app `read`s; it queues here, and its
  occupancy *should* shrink the advertised `RCV.WND` (Day 8 §F, Day 9 §F) — the receiver-side backpressure
  that throttles the *sender*. We keep a flat window, so our receive buffer doesn't push back. `SO_RCVBUF`
  sizes it; autotuning grows it to the BDP.

Backpressure is the whole reason buffers are bounded: an unbounded buffer turns "the network is slow" into
"the application's memory fills up." A correct socket couples buffer fullness to flow control (receive) and
to `write` blocking (send), so slowness propagates as a *signal*, not an OOM.

## E. How `poll_transmit` ties every layer together

`poll_transmit` is the integration point of the entire stack — every layer's contribution shows up in its
one loop:

```text
   n = min( usable_window(),    ←── flow control (SND.WND) ∧ congestion control (cwnd) ∧ −FlightSize
            mss,                ←── segmentation (Day 15 negotiated MSS)
            send_buf.len() )    ←── how much the app actually queued
   if n == 0: stop              ←── window full → wait for an ACK to slide it open
   if Nagle && n<mss && in-flight: stop   ←── Nagle (Day 13): coalesce small writes
   build PSH|ACK segment        ←── header + timestamps (Day 16) [+ checksums, Day 3]
   advance SND.NXT by n         ←── sequence-space accounting (Day 3)
   retx.record(...)             ←── reliability (Day 6): keep it for retransmission
```

Reading this loop top to bottom is reading the whole curriculum: Day 3's sequence numbers, Day 6's
retransmission, Day 8's flow control, Day 10's congestion control, Day 13's Nagle, Day 15's MSS, Day 16's
timestamps. That convergence is *why* the socket API is the right capstone: it's the first code that has to
honor every mechanism at once, and the place each one finally earns its keep against a real backlog.

## F. A worked `curl`, byte by byte

A full `curl http://192.168.0.2:8080/`, our ISS 0, client ISN 100, abbreviated headers. `C`=client, `U`=us.

```text
   ① C→U  SYN  seq=100  <mss,ws,ts,sackOK>          handshake (Days 3,15–18)
   ② U→C  SYN,ACK seq=0 ack=101 <mss,ws,ts,sackOK>
   ③ C→U  ACK  seq=101 ack=1
      —— ESTABLISHED, RCV.NXT=101, SND.NXT=1 ——
   ④ C→U  PSH,ACK seq=101 ack=1  "GET / HTTP/1.0\r\nHost: …\r\n\r\n"  (say 40 bytes)
      U: reasm delivers 40 bytes → recv_buf; RCV.NXT=141
   ⑤ U→C  ACK seq=1 ack=141                          bare ACK of the request (§3)
      U app: take_received() = "GET …" → http_response() → write("HTTP/1.0 200 OK\r\n…\r\nHello\n")
   ⑥ U→C  PSH,ACK seq=1 ack=141  "HTTP/1.0 200 OK…Hello\n"  (poll_transmit, window-gated; say 38 bytes)
      U: SND.NXT=39; retx.record
   ⑦ U→C  FIN,ACK seq=39 ack=141                     close() after the response → FIN_WAIT_1
   ⑧ C→U  ACK seq=141 ack=39                          acks our response data
   ⑨ C→U  ACK seq=141 ack=40                          acks our FIN → FIN_WAIT_2
   ⑩ C→U  FIN,ACK seq=141 ack=40                      client's FIN → RCV.NXT=142
   ⑪ U→C  ACK seq=40 ack=142                          → TIME_WAIT → (2·MSL) → CLOSED, reaped
```

Notice the **two** segments ⑤ and ⑥ where a pure echo server had one: ⑤ is the protocol's autonomous ACK of
the request, ⑥ is the application's response (§4, §I). And ⑦'s FIN at seq 39 sits *after* the 38 response
bytes (seq 1–38), because `close()` reads `SND.NXT` *after* `poll_transmit` advanced it past the response.

## G. Comparison to real stacks — the socket layer and C10K

```text
   aspect            real systems                                this stack
   ───────────────   ─────────────────────────────────────────  ────────────────────────
   socket layer      VFS file descriptors; read/write syscalls   methods on Connection
   listener          bind/listen/accept + backlog queues          implicit (SYN → TCB)
   concurrency       threads, epoll/kqueue, io_uring, async        single non-blocking loop
   send/recv buffers  SO_SNDBUF/SO_RCVBUF, autotuned               VecDeque / Vec, fixed window
   HTTP server       nginx/Apache/Node: routing, keep-alive, TLS   canned 200 OK, close
   scale             C10K/C10M via epoll + zero-copy               one loop, one packet/iter
```

The **C10K problem** (handling 10,000 concurrent connections) is exactly the blocking-vs-event-loop choice
(§B): thread-per-connection collapses under 10k threads (context-switch and memory overhead), so scalable
servers use an event loop over `epoll` — *our* architecture, just with a scalable readiness primitive
instead of poll+sleep. Our stack is structurally a C10K-style server (one loop, never block); what it lacks
for scale is `epoll` (Day 6 §E), zero-copy buffers, and TLS — not a different *shape*.

## H. Security — HTTP parsing as attack surface

The moment we parse an application protocol off the wire, every classic web-server vulnerability becomes
relevant — and our deliberately naive parser illustrates the hazards by *not* defending them:

- **Request smuggling.** When a `Content-Length` and a `Transfer-Encoding: chunked` header disagree, a
  front-end proxy and a back-end server may frame the request *differently*, letting an attacker smuggle a
  second request past the proxy. Real servers must reject conflicting framing; our "match the request line"
  parser ignores bodies entirely (it can't smuggle because it doesn't frame — but a real parser must, and
  must do it consistently with any proxy).
- **Slowloris / slow-read DoS.** An attacker opens many connections and sends the request *one byte at a
  time*, never completing the `\r\n\r\n`, holding server resources. A real server caps per-connection time
  and header size; our single-loop model is naturally resistant (no thread is pinned) but an unbounded
  `recv_buf` could still grow — bound it (E5).
- **Header injection / oversized headers.** Unbounded header count/size → memory exhaustion; CRLF injection
  in a reflected value → response splitting. Cap and sanitize.
- **Path traversal.** If `http_response` ever served files by path, `GET /../../etc/passwd` must be
  rejected — normalize and confine paths.

We serve a canned response, so most of these are latent, but the lesson is real: **the HTTP parser is an
attack surface as much as the TCP parser** (Day 1's discipline — validate length, never trust input —
applies one layer up), and request *framing* in particular (Content-Length vs chunked vs close-delimited)
is where the subtle, high-impact bugs live.

## I. Performance — the receive/send split and the extra ACK

- **The extra ACK.** Splitting receive from send (§4) means a request now draws a *bare ACK* and then,
  separately, the response — two segments where the inline echo sent one. On a request/response workload
  that's one extra packet per exchange. Real stacks reclaim it with **delayed ACK** (Day 4 §B): hold the
  bare ACK briefly so it can *piggyback* on the response, collapsing back to one segment. We ACK
  immediately, so we pay the extra packet — a deliberate simplicity-for-clarity trade.
- **Copies.** `write` copies app bytes into `send_buf`; `poll_transmit`'s `drain(..n).collect()` copies them
  into the segment; the receive path copies reassembled bytes into `recv_buf` and `take_received` moves them
  out (the one *non*-copy, via `mem::take`). A zero-copy stack would reference buffers instead; we copy for
  clarity.
- **Segmentation cost.** `poll_transmit` builds one segment per MSS chunk — N syscalls/allocations for N
  segments. Real stacks use TSO/GSO (Day 6 §K) to hand the NIC one big buffer it splits. We emit each
  segment individually.
- **The win that matters:** congestion control finally *binds* (§2) — a bulk `write` is correctly paced by
  `cwnd`, so the stack behaves on a shared, lossy network. Correctness under load, not raw speed, is the
  day-11 performance story.

## J. Extended FAQ

1. **What is the socket API here?** Two buffers + three verbs: `write`, `take_received`, `poll_transmit`.
2. **What does `write` do?** Appends app bytes to the `send_buf` (a `VecDeque`); doesn't send immediately.
3. **What does `poll_transmit` do?** Drains `send_buf` into window-gated, MSS-sized segments, recording each
   for retransmission.
4. **Why is `poll_transmit` the integration point?** It honors flow control, congestion control,
   segmentation, Nagle, timestamps, and retransmission at once (§E).
5. **What does `take_received` do?** Moves all in-order received bytes to the app via `mem::take` (zero
   copy).
6. **Why did the handler stop echoing inline?** To separate receiving (ACK) from sending (app-driven) so
   non-echo apps (HTTP) are possible.
7. **Why two packets now where there was one?** A bare ACK plus the app's response; delayed ACK would
   recombine them (§I).
8. **How does congestion control finally bind?** A bulk `write` exceeds `cwnd`, so `poll_transmit` paces it
   (§2).
9. **What HTTP does the server speak?** Minimal HTTP/1.0, `Connection: close`, canned 200 OK.
10. **Why does HTTP/1.0 let the server be so simple?** Close-delimited body — the body ends at connection
    close (§C).
11. **Who actively closes for HTTP?** The server (`close()` after the response) — the first live active
    close.
12. **Why `VecDeque` for send, `Vec` for receive?** FIFO drain-front for send; append-then-take-all for
    receive.
13. **Why `mem::take` for receive?** Hands the buffer to the app with no copy, leaving a fresh empty one.
14. **What is the C10K problem?** Scaling to 10k connections — solved by event loops (our shape) over
    epoll, not threads (§G).
15. **Why no blocking `TcpListener`?** It needs a concurrency layer (thread/async) atop the loop; our verbs
    already are the stream ops (§B).
16. **What is backpressure?** Buffer fullness propagating "slow down" — `write` blocks (send) / window
    shrinks (receive) (§D).
17. **Does our `write` block?** No (it appends); real backpressure is exercise E4.
18. **What is HTTP keep-alive and why want it?** Reuse one connection for many requests — avoids handshake +
    TIME_WAIT (§C).
19. **What is request smuggling?** Conflicting Content-Length/Transfer-Encoding letting requests slip past a
    proxy (§H).
20. **Is the HTTP parser an attack surface?** Yes — same "validate everything" discipline as the TCP parser
    (§H).
21. **Where does the FIN's sequence number come from after a response?** `SND.NXT` *after* `poll_transmit`
    advanced past the response bytes (§F ⑦).
22. **What mechanisms meet in the event loop?** All of them — parse, checksum, handshake, reassembly, retx,
    RTO, windows, congestion, teardown (§7).
23. **What's still missing after day 11?** RFC 5961, distinct CLOSE_WAIT/half-close, NewReno/CUBIC, a
    blocking veneer (§13).
24. **What did Days 12–18 add?** Control-seg retransmission, Nagle, zero-window probes, MSS, timestamps,
    window scaling, SACK (§13).
25. **Is this a complete TCP?** A complete, tested *core* that real clients interoperate with; the rest is
    breadth/robustness (§13).

## K. Anki starter deck

```text
Q: The socket API here?  A: two buffers + three verbs: write, take_received, poll_transmit.
Q: What does write() do?  A: appends app bytes to send_buf (VecDeque), not sent yet.
Q: What does poll_transmit() do?  A: drains send_buf into window-gated, MSS-sized, retransmit-recorded segments.
Q: Why is poll_transmit the integration point?  A: it honors flow+congestion control, MSS, Nagle, timestamps, retx at once.
Q: What does take_received() do?  A: moves all in-order received bytes to the app via mem::take (zero copy).
Q: Why did on_segment stop echoing inline?  A: to split receiving (ACK) from sending (app-driven) → non-echo apps possible.
Q: How does congestion control finally bind?  A: a bulk write exceeds cwnd, so poll_transmit paces it.
Q: HTTP/1.0 close-delimited body means?  A: the body ends when the connection closes (no length needed).
Q: Who actively closes for HTTP/1.0?  A: the server, after the response (close() → Day 7).
Q: VecDeque vs Vec for the buffers?  A: VecDeque (FIFO drain-front) for send; Vec (append/take-all) for receive.
Q: Why no blocking TcpListener?  A: it needs a thread/async layer; our verbs already ARE the stream ops.
Q: The C10K problem is solved by?  A: an event loop over epoll (our shape), not thread-per-connection.
Q: What is backpressure?  A: buffer fullness signaling "slow down" (write blocks / RCV.WND shrinks).
Q: What is HTTP request smuggling?  A: conflicting Content-Length/Transfer-Encoding desyncing proxy and server.
Q: What did Days 12–18 add to day 11's status?  A: control-seg retx, Nagle, zero-window probes, MSS, timestamps, wscale, SACK.
```

## L. Glossary

- **Socket API** — the application interface: `write` / `take_received` / `poll_transmit` (≈ BSD
  read/write/close).
- **Send buffer (`send_buf`)** — queued app bytes awaiting transmission (`VecDeque<u8>`).
- **Receive buffer (`recv_buf`)** — in-order received bytes awaiting the app (`Vec<u8>`).
- **`poll_transmit`** — drains the send buffer into window-gated MSS segments; the stack's integration
  point.
- **`take_received` / `mem::take`** — zero-copy hand-off of received bytes to the app.
- **Backpressure** — buffer fullness propagating as a "slow down" signal.
- **Blocking vs non-blocking vs async** — concurrency models for waiting on I/O.
- **C10K / C10M** — the challenge of many concurrent connections; solved by event loops.
- **HTTP/1.0 close-delimited body** — the response body ends at connection close.
- **HTTP keep-alive** — reusing one connection for multiple requests.
- **Request smuggling / Slowloris** — HTTP-layer attacks on framing / slow input.

## M. Reference tables

**M.1 — The three verbs**

```text
   verb              direction     buffer        gated by
   ───────────────   ───────────   ───────────   ─────────────────────────────
   write(bytes)      app → stack    send_buf      nothing (just queues)
   poll_transmit()   stack → wire   send_buf      min(SND.WND, cwnd) − FlightSize, MSS, Nagle
   take_received()   stack → app    recv_buf      nothing (takes all)
```

**M.2 — Inline echo (≤Day 10) vs split API (Day 11)**

```text
                      ≤ Day 10 (echo)              Day 11 (split)
   ────────────────   ──────────────────────────  ──────────────────────────────
   data arrives       on_segment builds the echo   on_segment buffers + bare ACK
   who decides reply  the protocol handler         the application (take_received → write)
   packets per req    1 (echo = ack + data)        2 (bare ACK, then response) [delayed-ACK recombines]
   non-echo apps      impossible                   possible (HTTP, …)
```

**M.3 — HTTP versions vs TCP**

```text
   version    persistence        multiplexing   transport   HOLB
   ────────   ─────────────────  ────────────   ─────────   ───────────────
   HTTP/1.0   close per request   no             TCP         n/a (our model)
   HTTP/1.1   keep-alive          pipelining     TCP         per-connection
   HTTP/2     keep-alive          streams         TCP         per-connection (TCP HOLB)
   HTTP/3     keep-alive          streams         QUIC/UDP    per-stream (no cross-stream HOLB)
```

> Re-type the send/receive buffers and `poll_transmit` with the book closed, then `cargo test`. You have now
> built TCP end to end: from a raw IPv4 packet (Day 1) to an application serving HTTP over your own reliable,
> congestion-controlled byte stream (Day 11). That is the whole arc — and `poll_transmit` is the one function
> where every day of it meets.
