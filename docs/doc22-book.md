# Doc 22 — TCP, Part 20: The Socket API — `TcpListener` / `TcpStream`, Active Half-Close, Keep-Alive HTTP

> Goal: give everything we've built an **application to drive it**. For twenty days the "socket API"
> has been `Connection::{write, take_received, poll_transmit}` plus the hand-written event loop in
> `main` — the *mechanism*. A program can't call that; it wants `std::net`: bind a listener, accept a
> stream, `read`/`write` it. Today we build that veneer — a blocking `TcpListener` / `TcpStream` over
> the `Connection` state machine — and, crucially, make it **testable with no TUN device** by
> abstracting I/O behind a `PacketIo` trait and wiring two façades back-to-back through in-memory
> queues. A full handshake → transfer → four-way close runs offline and deterministically.
>
> Three things land together, because building the API exposes what was missing:
> 1. **The façade** — `PacketIo`, `TcpStream`, `TcpListener`, blocking `Read`/`Write`.
> 2. **Active half-close** — a client that `shutdown(SHUT_WR)`s (sends its FIN) must still *receive*
>    the response. Our `FIN_WAIT_1/2` only handled teardown; now they deliver data too. (Doc 19 did
>    the passive mirror: keep *sending* in CLOSE_WAIT; today: keep *receiving* in FIN_WAIT_2.)
> 3. **Real HTTP** — buffer the full request head (`\r\n\r\n`), parse it, and support
>    **keep-alive**: many requests on one connection, closing only when the response says so.
>
> This is the day the stack stops being a packet demo and becomes something you can program against.

**Contents**

Volume I — the chapter
1. The mental model: mechanism vs. ergonomics
2. The `PacketIo` seam — why the façade needs no TUN to test
3. `poll`: one connection's event loop, distilled
4. `TcpStream` — connect, read, write, close
5. `TcpListener` — bind, accept, and the single-connection simplification
6. Blocking `Read`/`Write` over a non-blocking core
7. Active half-close: receiving in FIN_WAIT_2
8. The loopback: two stacks in one thread, no network
9. Keep-alive HTTP: buffer the head, serve many, close on request
10. The Rust: trait objects vs generics, the `take` shadowing trap, `Rc<RefCell>` loopback
11. A fully worked façade trace — connect to close
12. The code, walked end to end
13. Verification — the eight new tests, and why each exists
14. Why this, not that
15. Honesty: what production does that we don't
16. Rebuild it yourself — checklist + exercises
17. What the next day adds

Volume II — the exhaustive reference
- A. The BSD sockets API we're modelling
- B. `shutdown()` vs `close()`, and the two half-closes
- C. The full `PacketIo` contract and a TUN implementation sketch
- D. Blocking vs non-blocking vs async — where this façade sits
- E. HTTP/1.1 persistence rules (RFC 9112 §9.3) in full
- F. The single-connection listener, and what a real demux needs
- G. Comparison to real stacks & libraries — std::net, smoltcp, tokio
- H. Testing networked code without a network
- I. Extended FAQ — thirty questions a careful reader asks
- J. Anki starter deck
- K. Glossary
- L. Reference tables

---

# Volume I — the chapter

## 1. The mental model: mechanism vs. ergonomics

There are two layers to "TCP" in any system:

```text
   ergonomics (the API a program calls)     ← TcpListener::accept() → TcpStream; stream.read()/write()
   ───────────────────────────────────────
   mechanism (the protocol state machine)   ← Connection: on_segment / poll_transmit / on_tick
```

We built the mechanism first (Docs 3–21) and exercised it with a bespoke event loop in `main`. That
was right — you can't wrap what doesn't work. But no application speaks `on_segment`; applications
speak `read`/`write`. The kernel hides the mechanism behind file descriptors and the sockets API;
we hide it behind `TcpStream`/`TcpListener`.

The veneer's only job is **to drive the mechanism on the program's behalf** — to pump packets,
timers, and transmission until a blocking call (`read`, `write`, `accept`) can make progress. It adds
no protocol logic. That separation is why the façade is ~250 lines: all the hard parts already exist.

## 2. The `PacketIo` seam — why the façade needs no TUN to test

A naive façade would talk to the TUN device directly — and then could only be tested on Linux, as
root, against a real kernel. Instead we abstract the transport behind one trait:

```rust
pub trait PacketIo {
    fn send(&mut self, packet: &[u8]) -> io::Result<()>;
    fn try_recv(&mut self) -> io::Result<Option<Vec<u8>>>;   // non-blocking: None = nothing ready
}
```

`send` puts a whole IPv4 datagram on the wire; `try_recv` pulls one if ready (never blocks, so the
pump can move on to timers). That's the entire contract. Production implements it over the TUN device;
tests implement it over an in-memory `VecDeque`. Two test transports cross-wired ("what A sends, B
receives, and vice versa") connect two complete stacks in a single thread — a **loopback** — so the
whole handshake/transfer/teardown runs offline and deterministically (§8).

This is dependency inversion: the façade depends on the *abstraction* `PacketIo`, not the *concrete*
TUN device, so the device can be swapped for a mock. It's the single most important design decision in
the module — it's what makes a "networking" feature unit-testable at all.

## 3. `poll`: one connection's event loop, distilled

The heart of the façade is one non-blocking method that is `main`'s entire event loop boiled down to
a single connection:

```rust
pub fn poll(&mut self, now_ms: u64) -> io::Result<()> {
    for pkt in self.conn.on_tick(now_ms) {            // 1. timers: RTO retransmits, persist probes
        self.io.send(&pkt)?;
    }
    while let Some(pkt) = self.io.try_recv()? {        // 2. ingest every datagram ready right now
        if let Some((th, payload, opts)) = parse_for(self.quad, &pkt) {
            if let Some(out) = self.conn.on_segment(&th, &payload, &opts, now_ms) {
                self.io.send(&out)?;
            }
        }
    }
    for seg in self.conn.poll_transmit(now_ms) {       // 3. flush newly-sendable data
        self.io.send(&seg)?;
    }
    Ok(())
}
```

Three phases — **timers, ingest, transmit** — exactly the order `main` uses. `poll` is idempotent and
non-blocking: call it whenever and it advances the connection as far as the currently-available
packets and the clock allow. Every blocking operation is a loop over `poll` plus a condition.

`parse_for` demuxes: parse IPv4 + TCP and accept the segment *only if its 4-tuple matches this
stream's* (we're single-connection; a packet for anyone else is ignored). It's the façade's tiny
routing table.

## 4. `TcpStream` — connect, read, write, close

```rust
pub struct TcpStream<T: PacketIo> {
    conn: Connection,    // the state machine (Docs 3–21)
    io: T,               // the transport
    quad: Quad,          // our 4-tuple, for demuxing in poll
    rbuf: VecDeque<u8>,  // received bytes not yet handed to the caller (sub-buffer reads)
    start: Instant,      // wall clock for the blocking veneer
}
```

`connect` builds an active-open `Connection`, sends the SYN, and returns the stream in SYN_SENT;
pumping (`poll`) or a blocking `read`/`write` completes the handshake. The non-blocking core —
`poll`, `state`, `established`, `peer_closed`, `feed` (buffer app bytes), `recv_all` (drain delivered
bytes), `close` — is what the loopback tests drive directly. The blocking `Read`/`Write` impls (§6)
sit on top.

Note `recv_all`, not `take`: a method named `take` would be **shadowed** by `std::io::Read::take`
(which consumes `self` by value and so wins method resolution). A subtle Rust trap we hit and §10
dissects.

## 5. `TcpListener` — bind, accept, and the single-connection simplification

```rust
pub struct TcpListener<T: PacketIo> { io: Option<T>, local: (Ipv4Addr, u16) }
```

`poll_accept` drains ready datagrams; on the first SYN addressed to our local `(addr, port)`, it calls
`Connection::accept` (creating the server TCB in SYN_RCVD), sends the SYN-ACK, and hands the transport
to a fresh `TcpStream`. The blocking `accept` loops `poll_accept` then pumps the new stream to
ESTABLISHED.

The simplification: **one connection per listener.** When `poll_accept` succeeds it does
`self.io.take()` — moving the transport out of the listener into the stream — so the listener is
spent. A real `TcpListener` keeps accepting and demuxes many connections over one device by a
connection table (exactly what `main` does). Our façade is a teaching veneer; the single-connection
limit keeps ownership trivial and is called out in the doc comment. (§F covers the real demux.)

## 6. Blocking `Read`/`Write` over a non-blocking core

`std::io::Read`/`Write` are blocking interfaces — `read` returns when there's data, `write` accepts
bytes. We implement them as thin loops over the non-blocking `poll`:

```rust
impl<T: PacketIo> Read for TcpStream<T> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            self.poll(self.now())?;
            self.drain_delivered();
            if !self.rbuf.is_empty() {
                let n = buf.len().min(self.rbuf.len());
                for slot in buf.iter_mut().take(n) { *slot = self.rbuf.pop_front().unwrap(); }
                return Ok(n);
            }
            if self.conn.peer_closed() { return Ok(0); }   // EOF — the std convention
            std::thread::sleep(Duration::from_millis(2));   // let timers / the peer progress
        }
    }
}
```

The `rbuf` exists because `read` returns *up to* `buf.len()` bytes and must keep the rest — whereas
the connection delivers data in whole runs. `Ok(0)` is the universal EOF signal, returned exactly when
the peer has closed (`peer_closed()`) and the buffer is empty.

`Write::write` buffers and pumps once; `flush` pumps until the send buffer drains onto the wire. These
use a real `Instant` clock (`self.now()`); the loopback tests bypass them and drive `poll(now_ms)`
with a logical clock, so the blocking veneer's `sleep` never runs in tests.

## 7. Active half-close: receiving in FIN_WAIT_2

Building the façade surfaced a real gap. The canonical HTTP client does:

```text
   write(request);  shutdown(SHUT_WR);   // "I'm done sending" → our FIN → FIN_WAIT_1/2
   while read(...) > 0 { consume response }   // still RECEIVING after we've closed our send side
```

Doc 19 implemented the *passive* half-close (stay in CLOSE_WAIT, keep **sending**). This is the
*active* half-close (in FIN_WAIT_2, keep **receiving**) — the mirror image. But our `FIN_WAIT_1/2`
blocks only handled FIN/ACK for teardown; data arriving there was dropped. The loopback test
"client half-closes, server replies" failed, exposing it.

The fix mirrors Doc 19: deliver incoming data (via the reassembler) and ACK it, *in addition* to the
teardown logic, in both FIN_WAIT_1 and FIN_WAIT_2:

```rust
if self.state == State::FinWait2 {
    if !payload.is_empty() {                                  // Doc 22: receive side still open
        let delivered = self.reasm.recv(th.seq, payload, self.recv.nxt);
        if !delivered.is_empty() {
            self.recv.nxt = self.recv.nxt.wrapping_add(delivered.len() as u32);
            self.recv_buf.extend_from_slice(&delivered);
        }
    }
    let fin_seq = th.seq.wrapping_add(payload.len() as u32); // FIN may piggyback on data
    if th.flags & FIN != 0 && fin_seq == self.recv.nxt { /* … → TIME_WAIT … */ }
    if !payload.is_empty() { return Some(/* ACK */); }
    return None;
}
```

Now both directions of half-close work: either end can stop sending while the other keeps going —
which is what makes a TCP connection two *independent* pipes, the theme since Doc 19.

## 8. The loopback: two stacks in one thread, no network

The test transport is a pair of shared queues:

```rust
#[derive(Clone)]
struct Pipe { tx: Queue, rx: Queue }   // Queue = Rc<RefCell<VecDeque<Vec<u8>>>>
impl PacketIo for Pipe {
    fn send(&mut self, p: &[u8]) -> io::Result<()> { self.tx.borrow_mut().push_back(p.to_vec()); Ok(()) }
    fn try_recv(&mut self) -> io::Result<Option<Vec<u8>>> { Ok(self.rx.borrow_mut().pop_front()) }
}
fn pipe_pair() -> (Pipe, Pipe) {                 // cross-wire: a.tx == b.rx, a.rx == b.tx
    let a2b = Queue::default(); let b2a = Queue::default();
    (Pipe { tx: a2b.clone(), rx: b2a.clone() }, Pipe { tx: b2a, rx: a2b })
}
```

Two `TcpStream`s over a crossed pair are two complete TCP endpoints connected by a zero-latency,
lossless "wire" — entirely in memory, one thread. The test drives them with a *shared logical clock*:

```rust
for t in 0..50 {
    if server.is_none() { server = listener.poll_accept(t)?; }
    client.poll(t)?;
    if let Some(s) = server.as_mut() { s.poll(t)?; }
    if client.established() && server.is_some_and(|s| s.established()) { break; }
}
```

Because everything is synchronous and deterministic, the handshake/transfer/close is reproducible to
the byte — no sleeps, no flakiness, no root, no TUN. This is how you unit-test a network stack (§H).

## 9. Keep-alive HTTP: buffer the head, serve many, close on request

The old `main` recognised HTTP by its first bytes and replied on the request line — fine for one
`curl` GET in one segment, but not HTTP. `src/http.rs` does it properly, as pure functions over bytes
(so it's unit-tested):

```rust
pub fn request_head_len(buf: &[u8]) -> Option<usize>   // bytes through the blank line \r\n\r\n, or None
pub fn parse_request(head: &[u8]) -> Option<Request>   // method, path, version, keep_alive
pub fn response(req: &Request) -> Vec<u8>              // 200 OK with matching Connection header
```

Persistence follows RFC 9112 §9.3: **HTTP/1.1 defaults to keep-alive** (close only on
`Connection: close`); **HTTP/1.0 defaults to close** (persist only on `Connection: keep-alive`). The
server's serving loop (in `main`) buffers per connection until a full head arrives, serves *every*
complete request in the buffer (handling pipelining), and closes only when a response is non-persistent:

```rust
while let Some(head_len) = http::request_head_len(hbuf) {
    let head: Vec<u8> = hbuf.drain(..head_len).collect();
    match http::parse_request(&head) {
        Some(req) => { conn.write(&http::response(&req)); if !req.keep_alive { closing_http = true; break; } }
        None => { closing_http = true; break; }     // malformed → close
    }
}
```

A `Content-Length` header is always sent, because under keep-alive there's no closing FIN to mark the
body's end — the peer must frame it by length.

## 10. The Rust: trait objects vs generics, the `take` trap, `Rc<RefCell>` loopback

**Generics over trait objects.** `TcpStream<T: PacketIo>` is *generic* over the transport, not
`TcpStream` holding a `Box<dyn PacketIo>`. Generics monomorphise — the compiler stamps out a
specialised `TcpStream<TunDevice>` and `TcpStream<Pipe>` with no virtual dispatch — and let the test
`Pipe` and a real TUN coexist with zero runtime cost. A `dyn` object would be simpler to store in a
heterogeneous collection but we never need one.

**The `take` shadowing trap.** Our first `recv_all` was named `take`. It would not compile: a method
`take(self, limit)` exists on `std::io::Read`, which `TcpStream` implements. Rust method resolution
tries receiver adjustments *by value first*, and `Read::take` takes `self` by value, so it matched
before our `&mut self` inherent `take` was even considered — every `stream.take()` resolved to
`Read::take`, demanding an argument. Renaming to `recv_all` sidesteps it. The lesson: an inherent
`&mut self` method can be shadowed by a by-value trait method of the same name.

**`Rc<RefCell<VecDeque>>` for the loopback queues.** The two endpoints must *share* the same queues
(A's `tx` is B's `rx`). `Rc` gives shared ownership (single-threaded, so no `Arc`), `RefCell` gives
interior mutability (both ends mutate through a shared reference), `VecDeque` is the FIFO. `#[derive(Clone)]`
on `Pipe` clones the `Rc`s — sharing the queues, not copying them. This trio is the idiomatic
single-threaded shared-mutable-state pattern.

## 11. A fully worked façade trace — connect to close

Client `192.168.0.1:40000` → server `192.168.0.2:80`, over a loopback, logical clock `t`:

```text
   t   actor            action                                   wire (A=client→server, B=server→client)
   ──  ───────────────  ───────────────────────────────────────  ────────────────────────────────────────
   0   client.connect   Connection::connect → SYN                 A: SYN seq=C
   0   listener.accept  sees SYN → Connection::accept → SYN-ACK   B: SYN,ACK seq=S ack=C+1
   1   client.poll      ingests SYN-ACK → final ACK; ESTABLISHED  A: ACK seq=C+1 ack=S+1
   1   server.poll      ingests ACK; ESTABLISHED                  —
   50  client.feed+poll "hello…" → segment                        A: PSH,ACK + data
   51  server.poll      ingests data → ACK; recv_all() == "hello" B: ACK
   80  server.feed+poll "…back" → segment                         B: PSH,ACK + data
   81  client.poll      ingests data → ACK; recv_all() == "back"  A: ACK
   110 client.close     FIN; FIN_WAIT_1                            A: FIN,ACK
   111 server.poll      ingests FIN → ACK; CLOSE_WAIT (peer EOF)  B: ACK
   111 client.poll      ingests ACK of FIN; FIN_WAIT_2            —
   160 server.close     FIN; LAST_ACK                              B: FIN,ACK
   161 client.poll      ingests FIN → ACK; TIME_WAIT              A: ACK
   161 server.poll      ingests ACK of FIN; CLOSED                —
```

Every line is one `poll` call moving one endpoint forward; the test asserts the data at t=51/81 and
the end states (client TIME_WAIT, server CLOSED). The whole conversation is mechanism we already had,
now driven by the veneer instead of `main`.

## 12. The code, walked end to end

**`src/socket.rs`** (the façade, `#![allow(dead_code)]` — an embeddable API exercised by its loopback
tests; the demo `main` keeps its raw multi-protocol loop):
- `PacketIo` — the transport trait (§2).
- `parse_for` — demux a datagram to this stream's 4-tuple (§3).
- `TcpStream` — `connect`, `poll`, `state`/`established`/`peer_closed`, `feed`, `recv_all`, `close`,
  and the blocking `Read`/`Write` impls (§§4, 6).
- `TcpListener` — `bind`, `poll_accept`, `accept` (§5).
- `#[cfg(test)]` loopback `Pipe` + two integration tests (§8, §13).

**`src/http.rs`** (HTTP/1.x, pure functions, fully unit-tested): `request_head_len`,
`looks_like_request`, `parse_request`, `response`, the `Request`/`Version` types (§9).

**`src/tcp.rs`**: data delivery added to `FIN_WAIT_1`/`FIN_WAIT_2` (active half-close, §7).

**`src/main.rs`**: `mod http; mod socket;`; the TCP handler now keeps a per-connection
`http_bufs: HashMap<Quad, Vec<u8>>`, accumulates an HTTP client's bytes, serves each complete request
(keep-alive), and closes only on a non-persistent response — falling back to echo for raw `nc`.

## 13. Verification — the eight new tests, and why each exists

`cargo test` — **125 passing** (117 + 8). Six pin the HTTP parser; two are full loopback integrations.

HTTP (`src/http.rs`):
- **`head_len_detects_blank_line`** — finds `\r\n\r\n`, returns `None` while incomplete, and on a
  *pipelined* buffer returns only the first head's length (leaving the rest). The framing primitive.
- **`parses_request_line_and_version`** — method/path/version extracted; HTTP/1.1 defaults keep-alive.
- **`http11_closes_only_on_connection_close`** — 1.1 persists unless `Connection: close`
  (case-insensitive header).
- **`http10_persists_only_on_keep_alive`** — 1.0 closes unless `Connection: keep-alive`.
- **`rejects_malformed_request_line`** — garbage, missing version, and unsupported HTTP/2 → `None`.
- **`response_reflects_keep_alive_and_method`** — the response's `Connection` header and version match
  persistence; `Content-Length` is present; `HEAD` sends headers only.

Façade (`src/socket.rs`):
- **`loopback_handshake_transfer_and_close`** — two façades over a crossed pipe complete the
  three-way handshake, transfer data **both directions**, and run the full four-way close to
  client-TIME_WAIT / server-CLOSED — entirely offline.
- **`loopback_half_close_then_server_replies`** — the client half-closes (sends FIN), the server
  (CLOSE_WAIT) still sends a reply, and the client (FIN_WAIT_2) still receives it. This is the test
  that exposed the active-half-close gap (§7); it fails without the FIN_WAIT_2 receive path.

## 14. Why this, not that

**Why a `PacketIo` trait instead of taking the TUN device directly?** Testability. Dependency
inversion lets a loopback `Pipe` stand in for the kernel, so the whole façade is unit-tested with no
root, no TUN, no network. (§2, §H.)

**Why a non-blocking `poll` with blocking `Read`/`Write` on top, rather than blocking primitives?**
Because the non-blocking core is what's testable (drive it with a logical clock) and composable; the
blocking veneer is a thin loop for ergonomics. Building blocking-on-non-blocking is the standard
shape (it's how async runtimes expose blocking adapters too).

**Why single-connection listeners?** To keep ownership trivial for a teaching veneer. Multi-connection
demux is exactly what `main` already demonstrates with a connection table; duplicating it in the
façade would add a lot of code for no new concept. (§5, §F.)

**Why `recv_all` and not `take`?** `std::io::Read::take` shadows a same-named inherent `&mut self`
method. (§10.)

**Why add data-receive to FIN_WAIT_1/2 now?** The façade made the active-half-close pattern (the
normal HTTP client) testable, and it failed — surfacing that our teardown states dropped incoming
data. It's a genuine correctness fix, the mirror of Doc 19. (§7.)

**Why keep `main`'s raw loop instead of rewriting it on the façade?** `main` also serves ICMP and UDP
and many simultaneous connections over one device — the multi-protocol demux the single-connection
façade deliberately doesn't do. The façade is the *library* API; `main` is the *router*.

## 15. Honesty: what production does that we don't

- **Single-connection listener.** `poll_accept` hands its transport to the one stream it produces; a
  real `TcpListener` accepts unboundedly and demuxes by a connection table. (§F.)
- **No real concurrency.** The blocking `Read`/`Write` `sleep`-poll a single connection; they don't
  integrate with an executor or `epoll`. A production stack registers readiness with the OS poller; an
  async one wakes a task. (§D.)
- **The façade isn't wired into `main`.** `main` keeps its own loop; the façade is exercised by its
  loopback tests. Wiring a multi-connection façade *as* the server is a larger refactor (it would own
  the device and the table).
- **HTTP is a toy.** One canned body, no routing, no request body / chunked transfer-encoding, no
  `Date`/`Server` headers, no HTTP/2. Just enough to demonstrate framing + keep-alive.
- **No write backpressure surfaced.** `Write::write` always accepts all bytes into the send buffer;
  it never reports a full window to the caller (a real socket would block or `WouldBlock`).
- **Loopback is lossless and zero-latency.** Great for correctness; it doesn't exercise loss/RTT (that
  needs `tc netem` against the live binary). The reliability machinery (Docs 6–21) is still tested
  directly by the `tcp`/`congestion` unit tests.

## 16. Rebuild it yourself — checklist + exercises

**Checklist**

- [ ] `PacketIo { send, try_recv }`.
- [ ] `TcpStream<T>` with `connect`, `poll` (timers → ingest → transmit), `feed`, `recv_all`,
      `peer_closed`, `close`; blocking `Read`/`Write` on top.
- [ ] `parse_for(quad, packet)` demux helper.
- [ ] `TcpListener<T>` with `bind`, `poll_accept` (SYN → `Connection::accept` → stream), `accept`.
- [ ] FIN_WAIT_1/2: deliver incoming data + ACK (active half-close).
- [ ] `src/http.rs`: `request_head_len`, `parse_request`, `response`, keep-alive rules.
- [ ] `main`: per-connection HTTP buffer + keep-alive serving loop; echo fallback.
- [ ] Loopback `Pipe` + a handshake→transfer→close test. `cargo test` green (125), clippy clean.

**Exercises**

1. **E1 — multi-connection listener.** Give `TcpListener` a `HashMap<Quad, ...>` and a shared
   `PacketIo`, demuxing many streams over one transport (what `main` does). Accept two loopback
   clients at once.
2. **E2 — wire the façade into `main`.** Replace `main`'s hand-rolled TCP handling with the
   (multi-connection) façade, keeping ICMP/UDP on the side.
3. **E3 — `WouldBlock` write backpressure.** Make `Write::write` return the number of bytes the send
   buffer actually accepted (bounded by the window), so a bulk writer feels backpressure.
4. **E4 — request body.** Parse `Content-Length`, read the body after the head, and echo it back —
   then `POST` to the server with `curl -d`.
5. **E5 — real `shutdown`.** Add `TcpStream::shutdown_write()` (FIN without closing the read side) and
   a loopback test of the full active-half-close HTTP pattern: write, shutdown_write, read to EOF.

Make Anki cards from the `poll` three-phase loop and the `PacketIo` seam — those are the two ideas
that turn a state machine into a socket.

## 17. What the next day adds

Tomorrow is the **robustness pack** — the hardening that turns "correct on the happy path" into
"hard to break": RFC 5961 §5 (the blind *data* injection defence — tighten ACK acceptability with a
challenge ACK), a **randomized challenge-ACK throttle** (closing the CVE-2016-5696 side channel from
Doc 19), and **reaper timeouts** for connections stuck in CLOSE_WAIT / FIN_WAIT_2 (so a peer that
vanishes can't pin a connection forever). With the API in place today and the hardening tomorrow, the
stack is a complete, defensible TCP endpoint.

---

# Volume II — the exhaustive reference

## A. The BSD sockets API we're modelling

The veneer maps onto the calls every networked program uses:

```text
   BSD socket call                 our façade
   ─────────────────────────────   ────────────────────────────────────────
   socket()+bind()+listen()        TcpListener::bind(io, local)
   accept()                        TcpListener::accept() → TcpStream
   socket()+connect()              TcpStream::connect(io, local, remote)
   read()/recv()                   <TcpStream as Read>::read  (or recv_all, non-blocking)
   write()/send()                  <TcpStream as Write>::write (or feed + poll)
   shutdown(SHUT_WR)               close()  (sends our FIN; read side stays open — see B)
   close()                         drop after close() completes the teardown
   recv() == 0                     read() == Ok(0) / peer_closed()  (EOF)
```

The shapes match deliberately: a programmer who knows `std::net::TcpStream` can read ours. The
difference is that the kernel's versions block in the OS scheduler; ours block by pumping a userspace
state machine.

## B. `shutdown()` vs `close()`, and the two half-closes

```text
   call                  effect on the wire           our side's state
   ───────────────────   ──────────────────────────   ────────────────────────
   shutdown(SHUT_WR)     send FIN now                 ESTABLISHED → FIN_WAIT_1
   shutdown(SHUT_RD)     stop reading (local only)    (no wire effect; not modelled)
   close()               FIN at last fd reference     ESTABLISHED → FIN_WAIT_1, then drop
```

The two half-closes, now both implemented:

```text
   passive half-close (Doc 19):  peer sends FIN  → we ACK, CLOSE_WAIT, keep SENDING until we close
   active  half-close (Doc 22):  we send FIN     → FIN_WAIT_2, keep RECEIVING until peer closes
```

Together they realise TCP's two-independent-pipes model: each direction closes on its own schedule.
The canonical HTTP/1.0 client uses the active half-close — request, `shutdown(SHUT_WR)`, read the
response to EOF, `close()`.

## C. The full `PacketIo` contract and a TUN implementation sketch

`PacketIo` carries whole IPv4 datagrams (the façade does its own IP+TCP parsing in `parse_for`).
Contract:

```text
   send(packet):   transmit one complete IPv4 datagram. Blocking-or-not is the impl's choice;
                   the façade calls it from poll's timer/ingest/transmit phases.
   try_recv():     Ok(Some(datagram)) if one is ready; Ok(None) if none right now (MUST NOT block);
                   Err(e) for a real I/O error.
```

A TUN implementation (production), sketched:

```rust
struct TunIo { iface: tun_tap::Iface, buf: [u8; 1504] }
impl PacketIo for TunIo {
    fn send(&mut self, p: &[u8]) -> io::Result<()> { self.iface.send(p)?; Ok(()) }
    fn try_recv(&mut self) -> io::Result<Option<Vec<u8>>> {
        match self.iface.recv(&mut self.buf) {                 // iface set non-blocking
            Ok(n) => Ok(Some(self.buf[..n].to_vec())),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(e),
        }
    }
}
```

That's the whole bridge to the kernel — the same `set_non_blocking` + `WouldBlock` pattern `main`
already uses. We keep it out of `socket.rs` so the module compiles and tests without `tun_tap` in the
loop, but it's a dozen lines to wire up live.

## D. Blocking vs non-blocking vs async — where this façade sits

```text
   model           how a read waits                        our analogue
   ─────────────   ─────────────────────────────────────   ───────────────────────────────
   blocking        OS parks the thread until data           Read::read (sleep-poll loop)
   non-blocking    returns WouldBlock; caller retries       poll + recv_all (the core)
   readiness (poll/epoll)  OS signals which fds are ready    main's loop (one fd, manual)
   async (tokio)   executor wakes a task on readiness        (not implemented)
```

Our core is **non-blocking** (`poll`), and the blocking `Read`/`Write` are a `sleep`-poll veneer on
top — fine for a teaching façade, wasteful at scale (a real blocking socket parks the thread in the
kernel; a real server uses `epoll`/`io_uring` or async). The non-blocking core is the right primitive:
everything else (blocking, async) is built from it.

## E. HTTP/1.1 persistence rules (RFC 9112 §9.3) in full

```text
   version   default        Connection: keep-alive   Connection: close
   ───────   ────────────   ──────────────────────   ─────────────────
   HTTP/1.1  persistent     persistent (redundant)   close after response
   HTTP/1.0  close          persistent               close after response
```

Rules we implement:
1. A connection is persistent by default in 1.1, non-persistent in 1.0.
2. A `Connection: close` makes it non-persistent (either version).
3. A `Connection: keep-alive` makes a 1.0 connection persistent.
4. A persistent response MUST be self-delimiting — we always send `Content-Length` (the alternative,
   chunked transfer-encoding, we don't do).
5. After a non-persistent response, the server closes (we send FIN).

We don't implement: pipelining responses out of order (we serve in order — correct), `Connection`
header listing other hop-by-hop headers, or 1.1's `100-continue`.

## F. The single-connection listener, and what a real demux needs

Our `poll_accept` consumes its transport into the accepted stream. A real listener must:

```text
   • own the device for its whole life (not move it away);
   • keep a table: HashMap<Quad, Connection> (or per-connection stream handles);
   • on each datagram, look up the 4-tuple → route to that connection's state machine;
   • on a SYN to a 4-tuple with no entry → accept (create a TCB), enqueue for accept();
   • multiplex reads/writes across all of them (one device, many flows).
```

This is precisely `main`'s connection table. The façade omits it to keep ownership a single move; E1
adds it. The concept (route by 4-tuple) is unchanged — only the plumbing grows.

## G. Comparison to real stacks & libraries

```text
   aspect                std::net (kernel)   smoltcp            tokio::net          ours (Doc 22)
   ───────────────────   ─────────────────   ────────────────   ─────────────────   ──────────────
   API shape             TcpListener/Stream  Socket + poll      async Listener/Stream  TcpListener/Stream
   I/O model             blocking / nonblk   non-blocking poll  async (readiness)   nonblk core + blk veneer
   transport             kernel TUN/NIC      a Device trait     kernel              PacketIo trait
   multi-connection      yes                 yes (SocketSet)    yes                 single (E1)
   testable offline      no (needs kernel)   yes (loopback)     partially           yes (loopback)
   half-close (both)     yes                 yes                yes                 yes (Doc 19 + 22)
```

The closest sibling is **smoltcp**: a `Device` trait (our `PacketIo`), a poll-driven core, offline
loopback testing. We're a single-connection teaching cut of the same shape.

## H. Testing networked code without a network

The technique generalises beyond TCP:

1. **Abstract the I/O boundary** behind a trait (`PacketIo`) — never call the device directly from
   logic.
2. **Inject time** — pass `now_ms` in rather than reading a clock, so tests drive a logical clock
   (we've done this since Doc 6).
3. **Loopback the abstraction** — wire two instances through in-memory queues so they talk to each
   other deterministically.
4. **Step, don't sleep** — a non-blocking `poll(now)` the test calls in a controlled order, instead
   of real blocking + threads (which make tests flaky).

The payoff: the entire stack — handshake, data, loss recovery, teardown — is provable with `cargo
test`, on any OS, in milliseconds. The live TUN run (root, Linux) then validates only the *last mile*
(the kernel bridge), which the unit tests can't cover.

## I. Extended FAQ — thirty questions a careful reader asks

1. **What's the difference between the façade and `Connection`?** `Connection` is the protocol state
   machine; the façade (`TcpStream`/`TcpListener`) is the `std::net`-shaped API that *drives* it.
2. **What does `poll` do?** One non-blocking pump: fire timers, ingest ready packets, flush sendable
   data — `main`'s loop for one connection.
3. **Why is `poll` non-blocking?** So blocking `read`/`write`/`accept` can be built as loops over it,
   and so tests can step it deterministically.
4. **What is `PacketIo`?** The transport abstraction: `send` a datagram, `try_recv` one (non-blocking).
   TUN in production, in-memory queues in tests.
5. **Why abstract I/O at all?** To test the façade with no TUN/root/network — dependency inversion.
6. **What's a loopback here?** Two façades wired through crossed in-memory queues: two TCP endpoints in
   one thread, no wire.
7. **Why `Rc<RefCell<VecDeque>>` for the queues?** Shared (Rc) + interior-mutable (RefCell) FIFO
   (VecDeque), the single-threaded shared-mutable pattern; both ends mutate the same queue.
8. **Why generic `TcpStream<T>` not `Box<dyn PacketIo>`?** Monomorphisation: zero-cost, lets TUN and
   the test `Pipe` coexist without dynamic dispatch.
9. **Why `recv_all` instead of `take`?** `std::io::Read::take` (by-value `self`) shadows a same-named
   inherent `&mut self` method in resolution.
10. **How does `read` signal EOF?** `Ok(0)` when `peer_closed()` and the read buffer is empty — the
    std convention.
11. **What's `rbuf` for?** `read` returns up to `buf.len()` bytes; `rbuf` holds the remainder of a
    delivered run between calls.
12. **What clock do blocking `Read`/`Write` use?** A stored `Instant` (`self.now()`); tests bypass
    them and drive `poll(now_ms)` with a logical clock.
13. **Why does `accept` consume the listener's transport?** Single-connection simplification: the one
    stream takes the device; the listener is then spent.
14. **How would multi-connection work?** A connection table keyed by 4-tuple + a shared device —
    exactly `main`'s design (E1).
15. **What is active half-close?** We send FIN (FIN_WAIT_2) but keep *receiving* — the HTTP client
    pattern. Added today.
16. **How does it differ from Doc 19's half-close?** Doc 19 = passive (CLOSE_WAIT, keep sending);
    Doc 22 = active (FIN_WAIT_2, keep receiving). Mirror images.
17. **What broke without the FIN_WAIT_2 receive path?** The loopback "client half-closes, server
    replies" test — the client dropped the reply.
18. **How does keep-alive HTTP frame requests?** Buffer until `\r\n\r\n`; serve each complete head;
    one connection, many requests.
19. **HTTP/1.1 vs 1.0 persistence?** 1.1 keeps alive unless `Connection: close`; 1.0 closes unless
    `Connection: keep-alive`.
20. **Why always send `Content-Length`?** Under keep-alive there's no closing FIN to delimit the body;
    the peer frames it by length.
21. **What happens to a non-HTTP connection?** It's echoed (raw `nc`); only recognised HTTP clients
    get the buffering/keep-alive path.
22. **Where's the per-connection HTTP buffer?** `main`'s `http_bufs: HashMap<Quad, Vec<u8>>`, cleaned
    up when the connection closes.
23. **Is the façade wired into `main`?** No — `main` keeps its multi-protocol loop; the façade is the
    embeddable API, tested by loopback. Hence `#![allow(dead_code)]`.
24. **Why `#![allow(dead_code)]` on the module?** It's a library API the demo binary doesn't call —
    the same convention as `Connection::connect` (test-only). Exercised by its tests.
25. **Can the façade lose packets / measure RTT?** The loopback is lossless and zero-latency; loss/RTT
    are validated against the live binary with `tc netem`, and the reliability logic by unit tests.
26. **Is this async?** No — non-blocking core + blocking veneer. Async would wake tasks on readiness
    (D); the non-blocking core is the right base for it.
27. **How is time injected for tests?** `poll(now_ms)` takes the clock as a parameter; the loopback
    drives a shared logical `t`.
28. **What's the smallest real change to run the façade live?** A `PacketIo` impl over the TUN device
    (~12 lines, §C) + a driver loop calling `poll`.
29. **Why test HTTP separately from the façade?** HTTP parsing is pure functions over bytes — fastest
    to test in isolation; the façade tests cover the transport.
30. **Biggest thing still missing after today?** Multi-connection demux in the façade (E1/E2) and the
    robustness hardening (tomorrow).

## J. Anki starter deck

```text
Q: Mechanism vs ergonomics in TCP?  A: Connection state machine vs TcpStream/TcpListener API over it.
Q: What does the façade add to the protocol?  A: nothing — it only DRIVES the existing state machine.
Q: PacketIo is?  A: the transport trait: send(datagram) + try_recv() (non-blocking). TUN or loopback.
Q: Why abstract I/O behind a trait?  A: to unit-test the stack with no TUN/root/network.
Q: poll's three phases?  A: timers → ingest ready packets → flush sendable data.
Q: How are blocking read/write built?  A: as loops over the non-blocking poll + a condition.
Q: read() EOF signal?  A: Ok(0) when peer_closed() and the buffer is empty.
Q: A loopback test is?  A: two façades over crossed in-memory queues — two endpoints, one thread.
Q: Why Rc<RefCell<VecDeque>> for loopback queues?  A: shared, interior-mutable FIFO; both ends share it.
Q: Active half-close?  A: we FIN (FIN_WAIT_2) but keep receiving (the HTTP client pattern).
Q: Passive half-close (Doc 19)?  A: peer FINs (CLOSE_WAIT) but we keep sending.
Q: Why rename take()→recv_all()?  A: std::io::Read::take (by-value self) shadows the inherent method.
Q: HTTP/1.1 default persistence?  A: keep-alive (close only on Connection: close).
Q: HTTP/1.0 default persistence?  A: close (persist only on Connection: keep-alive).
Q: Why always send Content-Length on keep-alive?  A: no closing FIN to delimit the body.
Q: Generic TcpStream<T> vs Box<dyn>?  A: monomorphised, zero-cost; TUN and test pipe coexist.
```

## K. Glossary

- **Façade** — `TcpStream`/`TcpListener`: the `std::net`-shaped API over the `Connection` mechanism.
- **`PacketIo`** — the transport trait (`send`/`try_recv`); decouples the façade from the TUN device.
- **`poll`** — the non-blocking per-connection pump: timers, ingest, transmit.
- **Loopback** — two façades wired through shared in-memory queues; an in-thread network.
- **Active half-close** — sending our FIN (FIN_WAIT_2) while still receiving.
- **Passive half-close** — receiving the peer's FIN (CLOSE_WAIT) while still sending.
- **Keep-alive** — reusing one TCP connection for multiple HTTP requests.
- **Persistent connection** — an HTTP connection that stays open after a response (HTTP/1.1 default).
- **`recv_all`** — our non-blocking "drain all received bytes" (named to avoid `Read::take`).
- **Monomorphisation** — the compiler specialising a generic per concrete type, eliminating dispatch.

## L. Reference tables

**L.1 — façade API surface**

```text
   type / method                       blocking?   role
   ─────────────────────────────────   ─────────   ────────────────────────────────────
   PacketIo::send / try_recv           no          transport (TUN or loopback)
   TcpStream::connect                  no          active open (sends SYN)
   TcpStream::poll                     no          one pump (timers/ingest/transmit)
   TcpStream::feed / recv_all          no          buffer to send / drain received (tests)
   TcpStream::close / peer_closed      no          our FIN / peer-EOF query
   <TcpStream as Read>::read           yes          blocking read (Ok(0) = EOF)
   <TcpStream as Write>::write/flush   yes          blocking write / drain
   TcpListener::bind                   no           passive open setup
   TcpListener::poll_accept            no           accept one (non-blocking)
   TcpListener::accept                 yes          accept one (blocks to ESTABLISHED)
```

**L.2 — half-close, both directions**

```text
   who closes first   their state path                         their open direction
   ────────────────   ──────────────────────────────────────  ────────────────────
   active (we FIN)    ESTABLISHED → FIN_WAIT_1 → FIN_WAIT_2     still RECEIVING (Doc 22)
   passive (peer FIN) ESTABLISHED → CLOSE_WAIT → LAST_ACK        still SENDING  (Doc 19)
```

**L.3 — HTTP keep-alive decision**

```text
   request                              keep_alive   server action after response
   ──────────────────────────────────  ──────────   ────────────────────────────
   GET / HTTP/1.1                       true         keep open, serve next request
   GET / HTTP/1.1  Connection: close    false        send FIN, close
   GET / HTTP/1.0                       false        send FIN, close
   GET / HTTP/1.0  Connection: keep-alive  true      keep open
   (malformed)                          —            send FIN, close
```

> Re-type `PacketIo`, `TcpStream::poll` (the three phases), and the loopback `Pipe` with the book
> closed, then `cargo test`. When two of your own TCP stacks shake hands, trade data both ways, and
> close cleanly — all in one thread, no network — you've turned a protocol into a socket, and you're
> ready to make it bulletproof tomorrow.
