# Doc 29 — TCP, Part 27: Many Connections at Once — the Multi-Connection Socket Server

> Goal: serve *more than one* connection through the socket façade. Doc 22 built a `std::net`-shaped
> veneer — `TcpListener` / `TcpStream` over a `PacketIo` transport — that runs a full handshake →
> transfer → close offline, with no TUN device. But it was deliberately **single-connection**: the
> listener *moves* its one transport into the stream it accepts, so it can serve exactly one client and
> then it's spent. That was the right teaching stepping-stone — it isolated the blocking-API ergonomics
> from the harder problem of *demultiplexing*. This chapter solves the harder problem.
>
> A real server has **one** wire (or one TUN device, or one UDP socket) and **many** connections
> sharing it. Every datagram that arrives must be routed to the right connection — or, if it's a SYN to
> a listening port, used to *open* a new one. The thing that makes this possible is that TCP already
> gives every connection a globally unique name: the **4-tuple** `(remote IP, remote port, local IP,
> local port)`. A server keeps a **table** keyed by that 4-tuple, and routing is a hash lookup. This is
> exactly what `src/main.rs` already does for the live stack (its `HashMap<Quad, Connection>`); Doc 29
> lifts that pattern into the reusable, testable `TcpServer` in `src/socket.rs`, removing the Doc-22
> "one connection at a time" limitation and completing the socket layer.
>
> We build `TcpServer<T: PacketIo>`: it owns one transport and a connection table, demuxes every
> inbound datagram, accepts new connections on a SYN, drives *all* connections' timers and transmission
> from one `poll`, hands established connections to the application by 4-tuple, and reaps closed ones.
> Then we test it the way the whole façade is tested — offline, deterministically — by wiring two
> clients and one server through an in-memory shared medium and watching the server keep their bytes
> separate.

**Contents**

Volume I — the chapter
1. The mental model: one wire, many connections, demux by 4-tuple
2. The Doc 22 limitation: a transport owned by a single stream
3. The connection table: keyed by `Quad`
4. Routing one datagram: parse, look up, dispatch — or accept
5. The accept backlog: announce each connection once
6. One `poll` drives everything: timers, ingest, transmit, reap
7. The per-connection API: `accept_one` / `send` / `recv` / `close`
8. `PacketIo` and a shared medium for offline testing
9. The Rust: `TcpServer`, `parse_any`, `poll`
10. A fully worked trace — two clients, one server
11. The code, walked end to end
12. Verification — the concurrency test
13. Why this, not that
14. Honesty: what production servers do that we don't
15. Rebuild it yourself — checklist + exercises
16. What comes after

Volume II — the exhaustive reference
- A. The 4-tuple, and why it is the demultiplexing key
- B. SYN handling and the accept backlog
- C. A connection's lifecycle in the table (accept → established → reaped)
- D. `PacketIo`: the production TUN vs the loopback test medium
- E. `TcpServer` vs `main`'s event loop — same pattern, two shapes
- F. Comparison to real servers — `accept()`, epoll, the thundering herd
- G. Extended FAQ — twenty questions a careful reader asks
- H. Anki starter deck
- I. Glossary
- J. Reference tables

---

# Volume I — the chapter

## 1. The mental model: one wire, many connections, demux by 4-tuple

A server socket is not one conversation — it's a switchboard. Packets for hundreds of connections
arrive interleaved on the same interface, and the server must sort each one to its conversation. TCP
makes this trivial *in principle*: a connection is uniquely identified by its **4-tuple**

```text
   (remote IP, remote port, local IP, local port)
```

Two different clients talking to the same `server:80` differ in their remote `(IP, port)`; the same
client opening two connections differs in its remote *port*. So the 4-tuple is globally unique per
connection, and the server's entire routing logic is: **parse the datagram, build its 4-tuple, look it
up in a table.** Hit → hand the segment to that connection. Miss → if it's a SYN to a port we're
listening on, create a new connection; otherwise drop (or RST). That hash-lookup is the whole idea;
everything else in this chapter is bookkeeping around it.

## 2. The Doc 22 limitation: a transport owned by a single stream

Doc 22's `TcpStream<T>` *owns* its transport `T` (the `PacketIo`), because a single connection driving
a single pipe is the simplest possible ergonomics:

```rust
pub struct TcpStream<T: PacketIo> { conn: Connection, io: T, quad: Quad, /* … */ }
```

And `TcpListener::poll_accept` literally **moves** the transport out of the listener and into the new
stream:

```rust
let io = self.io.take().unwrap(); // single-connection: hand the transport over
return Ok(Some(TcpStream { conn, io, quad, /* … */ }));
```

After that `take()`, the listener has `None` and can never accept again. This is fine for a loopback
test of one connection, but a server needs the *opposite* ownership: the transport must stay in one
place and be *shared* across many connections, with a central router deciding which connection each
datagram belongs to. That central owner is `TcpServer`.

## 3. The connection table: keyed by `Quad`

`TcpServer` owns the transport and a table of connections keyed by their 4-tuple (`Quad`), plus two
small structures for the accept handoff:

```rust
// src/socket.rs
pub struct TcpServer<T: PacketIo> {
    io: T,
    local: (Ipv4Addr, u16),
    conns: HashMap<Quad, Connection>,
    backlog: VecDeque<Quad>,    // connections that just reached ESTABLISHED, awaiting accept_one()
    announced: HashSet<Quad>,   // quads already handed to the backlog (announce-once)
}
```

`conns` is the switchboard. `local` is the `(addr, port)` the server is bound to, so it can tell a SYN
*for us* from a stray packet. `backlog` and `announced` implement `accept()` semantics (§5): a
connection appears in `backlog` exactly once, the first poll after it reaches ESTABLISHED.

## 4. Routing one datagram: parse, look up, dispatch — or accept

A free function `parse_any` turns raw bytes into `(Quad, header, payload, options)` with *no*
per-connection filtering — the server routes by the returned `Quad`, unlike Doc 22's `parse_for` which
filtered against one connection's quad:

```rust
// src/socket.rs
fn parse_any(packet: &[u8]) -> Option<(Quad, TcpHeader, Vec<u8>, tcp::TcpOptions)> {
    let iph = ip::parse(packet).ok()?;
    if iph.protocol != 6 { return None; }                 // TCP only
    let l4 = &packet[iph.header_len..];
    let th = tcp::parse(l4)?;
    let quad = Quad { remote: (iph.src, th.src_port), local: (iph.dst, th.dst_port) };
    let off = th.data_offset.min(l4.len());
    let payload = l4[off..].to_vec();
    let opts = tcp::parse_options(&l4[20..off]);
    Some((quad, th, payload, opts))
}
```

Note the quad orientation: from the *receiver's* view, `remote` is the packet's **source** and `local`
is its **destination**. The routing decision in `poll`:

```text
   parse → quad
   if quad.local ≠ our (addr, port):  drop          (not addressed to this server)
   else if conns has quad:            conn.on_segment(...)   → maybe send a reply
   else if SYN (and not ACK):         Connection::accept(...) → send SYN-ACK, insert into table
   else:                              drop            (stray segment to no connection)
```

## 5. The accept backlog: announce each connection once

`Connection::accept` returns a connection in **SYN_RCVD**, not yet ESTABLISHED — the handshake finishes
a round later when the client's final ACK arrives and is routed to it. So "a new connection is ready
for the application" is a *transition* to ESTABLISHED, which the server detects each poll:

```rust
// src/socket.rs — poll, step 3
if conn.state() == State::Established && !self.announced.contains(quad) {
    self.announced.insert(*quad);
    self.backlog.push_back(*quad);
}
```

`announced` guarantees each connection is enqueued **once** — without it, every subsequent poll would
re-announce an already-accepted connection. The application pulls from the backlog with `accept_one()`
(the non-blocking analogue of `accept()` returning a new socket).

## 6. One `poll` drives everything: timers, ingest, transmit, reap

A single `poll(now_ms)` is the entire event loop for *all* connections, in four phases:

```rust
// src/socket.rs — TcpServer::poll, abridged
pub fn poll(&mut self, now_ms: u64) -> io::Result<()> {
    // 1. Timers / retransmissions for every connection.
    for conn in self.conns.values_mut() {
        for pkt in conn.on_tick(now_ms) { self.io.send(&pkt)?; }
    }
    // 2. Ingest + route every ready datagram (accept new connections on a SYN).
    while let Some(pkt) = self.io.try_recv()? {
        let Some((quad, th, payload, opts)) = parse_any(&pkt) else { continue };
        if quad.local != self.local { continue; }
        if let Some(conn) = self.conns.get_mut(&quad) {
            if let Some(out) = conn.on_segment(&th, &payload, &opts, now_ms) { self.io.send(&out)?; }
        } else if th.flags & tcp::SYN != 0 && th.flags & tcp::ACK == 0 {
            if let Some((conn, synack)) =
                Connection::accept(quad.remote.0, quad.local.0, &th, &opts, now_ms) {
                self.io.send(&synack)?;
                self.conns.insert(quad, conn);
            }
        }
    }
    // 3. Flush each connection's new data; announce the newly-established.
    for (quad, conn) in self.conns.iter_mut() {
        for seg in conn.poll_transmit(now_ms) { self.io.send(&seg)?; }
        if conn.state() == State::Established && !self.announced.contains(quad) {
            self.announced.insert(*quad);
            self.backlog.push_back(*quad);
        }
    }
    // 4. Reap fully-closed connections.
    let announced = &mut self.announced;
    self.conns.retain(|quad, conn| {
        let keep = conn.state() != State::Closed;
        if !keep { announced.remove(quad); }
        keep
    });
    Ok(())
}
```

The order mirrors the single-connection `TcpStream::poll` (timers → ingest → transmit), generalized to
a table: drive every connection's clock, route every packet, flush every connection's pending bytes,
then garbage-collect the dead. Step 4's `retain` also clears `announced` for reaped quads, so a future
connection that happens to reuse the 4-tuple is announced afresh.

## 7. The per-connection API: `accept_one` / `send` / `recv` / `close`

The application interacts with the server by 4-tuple — exactly how a real server holds a *set* of
accepted sockets:

```rust
pub fn accept_one(&mut self) -> Option<Quad>;          // next newly-established connection (FIFO)
pub fn send(&mut self, quad: &Quad, data: &[u8]);      // queue bytes on one connection
pub fn recv(&mut self, quad: &Quad) -> Vec<u8>;        // drain one connection's delivered bytes
pub fn close(&mut self, quad: &Quad, now_ms) -> io::Result<()>;  // FIN one connection
pub fn state(&self, quad: &Quad) -> Option<State>;     // inspect one connection
pub fn peer_closed(&self, quad: &Quad) -> bool;        // did this peer half-close (EOF)?
pub fn connection_count(&self) -> usize;               // how many are live
```

`accept_one` returns a `Quad` (a handle), not an owned stream — because the connection lives in the
server's table, shared with the router. The application uses that handle to drive the connection while
the server keeps demuxing everyone else's packets.

## 8. `PacketIo` and a shared medium for offline testing

The façade abstracts the transport behind `PacketIo` (Doc 22) precisely so it can be tested without a
TUN device. For *one* connection, two cross-wired queues (a `Pipe`) suffice. For *many* connections to
one server, the test needs a **shared medium**: all clients write "up" to the server, and the server
broadcasts "down" to every client inbox — and each client ignores datagrams not for its own 4-tuple,
exactly as a real shared link (Ethernet) works.

```rust
// the server reads one "up" queue and broadcasts every send to all client inboxes
struct ServerSide { up: Q, down: Vec<Q> }
impl PacketIo for ServerSide {
    fn send(&mut self, p: &[u8]) -> io::Result<()> {
        for q in &self.down { q.borrow_mut().push_back(p.to_vec()); }   // broadcast
        Ok(())
    }
    fn try_recv(&mut self) -> io::Result<Option<Vec<u8>>> { Ok(self.up.borrow_mut().pop_front()) }
}
// each client writes "up" to the server and reads only its own inbox
struct ClientSide { up: Q, down: Q }
```

A client's `TcpStream` already filters received datagrams against its own quad (`parse_for`), so the
broadcast is harmless: client B silently drops the packets meant for client A. This models a real
shared segment faithfully and keeps the test single-threaded and deterministic.

## 9. The Rust: `TcpServer`, `parse_any`, `poll`

The pieces above compose into ~150 lines in `src/socket.rs`. The whole module is `#![allow(dead_code)]`
because it is an *embeddable* API exercised by tests — the demo `main` keeps its own raw multi-protocol
loop (it also serves ICMP and UDP, which a TCP-only server can't). `TcpServer` is the library-API
embodiment of what `main` does for TCP: the same `HashMap<Quad, Connection>` demux, packaged for reuse
and proven with a concurrency test rather than a live run.

## 10. A fully worked trace — two clients, one server

Two clients (`A` from `:40001`, `B` from `:40002`) connect to `server:80` over the shared medium; one
logical clock drives all three.

```text
   tick  event
   ────  ──────────────────────────────────────────────────────────────────────────────
    0    A.connect → SYN(A) up;  B.connect → SYN(B) up
    0    server.poll: reads SYN(A) → accept → TCB_A (SYN_RCVD), SYN-ACK(A) broadcast down
                      reads SYN(B) → accept → TCB_B (SYN_RCVD), SYN-ACK(B) broadcast down
    1    A.poll: reads SYN-ACK(A) (B ignores it) → ACK(A) up;  B.poll likewise → ACK(B) up
    2    server.poll: routes ACK(A) → TCB_A ESTABLISHED → backlog=[A];
                      routes ACK(B) → TCB_B ESTABLISHED → backlog=[A,B]
   ───   connection_count() == 2; accept_one() → A; accept_one() → B; accept_one() → None
   100   A.feed("hello from A"); B.feed("hello from B")
   …     server.poll routes A's data → TCB_A.recv_buf; B's → TCB_B.recv_buf  (never crossed)
   …     test echoes: server.send(A, recv(A));  server.send(B, recv(B))
   …     A.recv_all() == "hello from A";  B.recv_all() == "hello from B"
```

The point the trace makes: at tick 2 the server holds **two** connections in one table, each in its own
state, and every byte is demuxed to the correct one — `A`'s "hello from A" never leaks into `B`'s
buffer, because they hash to different `Quad`s.

## 11. The code, walked end to end

- **`bind(io, local)`** creates the server with an empty table.
- **`poll`** (the loop, §6) is called by the application as often as it likes; each call advances all
  connections by the supplied `now_ms`.
- **Routing** (`parse_any` + the `poll` step-2 match) is the demux: lookup-or-accept by 4-tuple.
- **`accept_one`** drains the backlog FIFO; the app then drives that connection by quad.
- **`send`/`recv`/`close`/`state`/`peer_closed`** are thin per-quad wrappers over the underlying
  `Connection::{write, take_received, close, state, peer_closed}` — the same primitives Doc 11 exposed,
  now selected by 4-tuple.
- **Reaping** (`poll` step 4) removes connections that reached CLOSED and forgets their `announced`
  entry, bounding the table.

## 12. Verification — the concurrency test

`socket::server_demuxes_two_concurrent_connections` (offline, simulated clock):

```text
   1. Build the shared medium (one "up" queue, two client inboxes), a TcpServer, two TcpStream clients.
   2. Drive one clock until BOTH ends of BOTH connections are ESTABLISHED.
      assert: client_a.established() && client_b.established()
      assert: server.connection_count() == 2          ← two connections in one table
   3. assert: accept_one() yields two distinct quads, then None.
   4. Each client feeds distinct bytes; the server echoes each back by quad.
      assert: client_a.recv_all() == "hello from A"
      assert: client_b.recv_all() == "hello from B"    ← bytes never crossed connections
```

This proves the three things that distinguish a server from a single connection: it **tracks** many
connections at once, **accepts** each as a distinct endpoint, and **demuxes** their data without
cross-talk. Together with the Doc 22 single-connection handshake/transfer/close tests, the socket layer
is fully exercised offline. 151 tests total, green, clippy `-D warnings` clean.

## 13. Why this, not that

- **Why a `HashMap<Quad, …>` and not a `Vec`?** Routing is per-packet and must be O(1); a 4-tuple hash
  is the natural key. Real stacks use a hash table with the same key (plus a separate listener lookup).
- **Why return a `Quad` handle from `accept_one`, not an owned `TcpStream`?** Because the connection
  must stay in the server's table to keep receiving routed packets. Handing out an owned stream would
  recreate the Doc-22 ownership problem (the transport can't be in two places). The handle pattern is
  how a real server holds many fds and `select`s over them.
- **Why announce-once with a `HashSet`?** A connection reaches ESTABLISHED on one specific poll; without
  a "seen" set, every later poll would re-enqueue it. The set makes the backlog a true event queue.
- **Why keep the single-connection `TcpListener`/`TcpStream`?** They're the simplest ergonomics for a
  *client* (which is genuinely one connection) and for teaching the blocking API in isolation. The
  client side of the concurrency test uses `TcpStream`.
- **Why not wire `TcpServer` into `main`?** `main` multiplexes ICMP, UDP, *and* TCP at the IP layer; a
  TCP-only `TcpServer` can't serve the other two. `main` keeps its own loop by design, and `TcpServer`
  is the reusable library form of its TCP demux (§E).

## 14. Honesty: what production servers do that we don't

- **A real OS event loop.** Production servers block in `epoll`/`kqueue`/`io_uring` and wake on
  readiness; we poll on a caller-supplied clock. The demux logic is identical; the readiness mechanism
  differs.
- **A separate listen socket and accept queue.** The kernel keeps a *listener* (matched by local
  port with a wildcard remote) distinct from established connections, with its own SYN queue and accept
  queue, backlog limits, and SYN-cookie fallback (Doc 27). We fold "is this a SYN to our port" into the
  same table lookup.
- **Per-connection buffering limits, fairness, and backpressure.** A real server bounds memory per
  connection and across connections; ours has unbounded per-connection buffers.
- **Concurrency.** Production servers spread connections across threads/cores (`SO_REUSEPORT`,
  sharded accept queues) to avoid a single-lock bottleneck and the thundering herd. We are
  single-threaded by design.
- **Address wildcards.** `bind(0.0.0.0:80)` accepts on any local IP; we bind one exact `(addr, port)`.

## 15. Rebuild it yourself — checklist + exercises

Checklist (extending `src/socket.rs`):
1. `parse_any` — raw bytes → `(Quad, header, payload, opts)`, no per-connection filter.
2. `TcpServer` struct: `io`, `local`, `conns: HashMap<Quad, Connection>`, `backlog`, `announced`.
3. `poll`: timers → ingest+route (lookup or accept) → transmit+announce → reap.
4. `accept_one` / `send` / `recv` / `close` / `state` / `peer_closed` / `connection_count`.
5. A shared-medium test transport (`ServerSide` broadcasts; `ClientSide` reads its own inbox).
6. The two-concurrent-connections test: established×2, distinct accepts, no cross-talk.

Exercises:
- **(a)** Add a real RST for stray segments to no connection (mirror `main`'s behaviour) and test it.
- **(b)** Bound the table: cap `conns.len()`, and fall back to SYN cookies (Doc 27) when full —
  wiring Doc 27 into the façade.
- **(c)** Give `accept_one` a blocking sibling `accept()` that polls until the backlog is non-empty.
- **(d)** Run two **BBR** connections (Doc 28) through one `TcpServer` and watch them share the
  (simulated) bottleneck — the multi-flow experiment Doc 28 set up.
- **(e)** Add `0.0.0.0` wildcard binding: accept a SYN to *any* local IP on the bound port.

## 16. What comes after

With BBR (Doc 28) and the multi-connection `TcpServer`, the stack is **feature-complete** against its
own roadmap: every algorithm and façade the README listed is built and tested offline. What remains is
not new code but *live* exercise that needs sudo + a TUN device + a real network — `packetdrill`
conformance against the kernel, `iperf3` throughput under `tc netem` loss/reordering, flamegraph
profiling, and actually rate-pacing the sender to BBR's computed rate (Doc 28, exercise (a)). Those are
the subjects no offline unit test can stand in for, and so they are where this book ends and a live lab
begins.

---

# Volume II — the exhaustive reference

## A. The 4-tuple, and why it is the demultiplexing key

TCP defines a connection as the pair of endpoints `(local socket, remote socket)`, each socket being an
`(IP, port)`. Four numbers, and they are unique by construction: the OS won't let two connections share
all four (it would be ambiguous which one a segment belongs to). So the 4-tuple is a perfect hash key
for routing. Listening sockets are the one wrinkle — they match a *wildcard* remote `(*, *)` on a fixed
local `(addr, port)` — which is why a real stack looks up established connections first and falls back
to the listener; we fold both into one table plus the "SYN to our port" rule.

## B. SYN handling and the accept backlog

```text
   segment to no existing connection:
       SYN (no ACK) to our (addr, port):  Connection::accept → SYN_RCVD, send SYN-ACK, insert
       anything else:                     drop  (a real stack RSTs; exercise (a))

   connection reaching ESTABLISHED (client's final ACK routed in):
       first poll after the transition:   push quad to backlog (announce-once via `announced`)

   application:
       accept_one():                      pop the backlog FIFO → a Quad handle (or None)
```

The split between "SYN creates a SYN_RCVD connection" and "the ACK promotes it and announces it" is the
server-side handshake, table-resident. Doc 27's SYN cookies are the alternative path when the backlog
would overflow — not yet wired into `TcpServer` (exercise (b)), but present in `main`.

## C. A connection's lifecycle in the table

```text
   (absent) ──SYN──▶ SYN_RCVD ──client ACK──▶ ESTABLISHED ──announce once──▶ app drives it
                                                    │
                                       data / half-close / close (per quad)
                                                    ▼
                              FIN_WAIT / CLOSE_WAIT / LAST_ACK / TIME_WAIT …
                                                    ▼
                                                 CLOSED ──poll step 4 reap──▶ (absent)
```

`announced` is cleared on reap, so a later connection reusing the same 4-tuple is announced again.

## D. `PacketIo`: the production TUN vs the loopback test medium

```text
   trait PacketIo { fn send(&mut self, &[u8]) -> io::Result<()>;
                    fn try_recv(&mut self) -> io::Result<Option<Vec<u8>>>; }   // non-blocking recv

   production:  send → write the IPv4 datagram to the TUN device; try_recv → read one (non-blocking)
   single test: Pipe — two cross-wired in-memory queues (a.tx == b.rx, a.rx == b.tx)
   multi  test: ServerSide broadcasts every send to all client inboxes; ClientSide reads its own.
                Each client filters by quad, so a broadcast models a shared L2 segment exactly.
```

`try_recv` returning `Ok(None)` ("nothing ready") is what lets one `poll` interleave I/O with timers
and transmission instead of blocking on a read.

## E. `TcpServer` vs `main`'s event loop — same pattern, two shapes

```text
   main (src/main.rs)                      TcpServer (src/socket.rs)
   ─────────────────────────────────       ───────────────────────────────────
   HashMap<Quad, Connection>               HashMap<Quad, Connection>
   demux IP→{ICMP, UDP, TCP}               TCP only
   accept / SYN cookies / RST              accept (RST & cookies are exercises)
   serves echo + HTTP application          hands connections to the caller by quad
   one TUN device                          one PacketIo (TUN or test medium)
   tested live (nc / curl / ping)          tested offline (loopback concurrency test)
```

They are the same demultiplexing pattern at two altitudes: `main` is the concrete multi-protocol
server; `TcpServer` is the reusable, offline-testable TCP core of it.

## F. Comparison to real servers — `accept()`, epoll, the thundering herd

A real server: `socket(); bind(); listen(backlog); loop { fd = accept(); epoll_ctl(ADD, fd); }` and an
event loop that `epoll_wait`s and dispatches readable fds. The kernel demuxes by 4-tuple in C; `accept`
pops the kernel's *accept queue* (the connections that finished the handshake) — exactly our
`accept_one` over `backlog`. The "thundering herd" is multiple threads waking on one listener; modern
servers shard with `SO_REUSEPORT`. Our `poll` is the userspace analogue of `epoll_wait` + the dispatch
loop, single-threaded, with the table in Rust instead of the kernel.

## G. Extended FAQ — twenty questions a careful reader asks

1. **Why can the server share one transport across connections but Doc 22 couldn't?** Doc 22's stream
   *owns* the transport; `TcpServer` owns it centrally and routes — the opposite ownership.
2. **What if two clients pick the same source port?** They can't collide unless they're also the same
   source IP — then they'd be the same connection. Different IP or port → different `Quad`.
3. **How does the server know a SYN is "for it"?** `quad.local == self.local` (its bound addr+port).
4. **What happens to a stray ACK to no connection?** Dropped here (a real stack RSTs, or checks it as a
   returning SYN cookie — `main` does both; exercise (a)/(b)).
5. **When is a connection announced to the app?** The first poll after it reaches ESTABLISHED, once,
   via the `announced` set.
6. **Why FIFO backlog?** It mirrors the kernel accept queue's order; fairness to earlier arrivals.
7. **Does `recv` block?** No — it drains whatever in-order bytes are delivered; `poll` does the I/O.
8. **How are closed connections cleaned up?** `poll` step 4 `retain`s only non-CLOSED connections and
   removes their `announced` entry.
9. **Can the table grow without bound?** Yes here — production caps it; exercise (b) adds the cap +
   SYN-cookie fallback.
10. **Is routing O(1)?** Yes — a single `HashMap` lookup by `Quad` per datagram.
11. **Why does `accept_one` return a `Quad`, not a stream?** The connection must stay in the table to
    keep receiving routed packets; the quad is the handle to drive it.
12. **Could two `TcpServer`s share a medium?** Yes (different `local`); each ignores the other's
    packets via the `quad.local != self.local` filter.
13. **Does the server handle half-close per connection?** Yes — `peer_closed(quad)` and `close(quad)`
    are per-connection, like Doc 19's half-close.
14. **What drives retransmission for all connections?** `poll` step 1 calls every connection's
    `on_tick(now_ms)`, which fires its RTO/RACK-TLP/persist/keepalive timers.
15. **Why is the module `#![allow(dead_code)]`?** It's an embeddable API exercised by tests; the demo
    `main` uses its own loop, so the bin would otherwise flag it unused.
16. **How is the concurrency test deterministic?** One shared `now_ms` clock advanced in a loop; no
    threads, no wall-clock timing.
17. **Could the broadcast medium cause a client to mis-handle another's packet?** No — each client's
    `parse_for` drops datagrams whose quad isn't its own.
18. **Does `TcpServer` support active open (connect)?** No — it's a passive server; the client side uses
    `TcpStream::connect`. Add a `connect`-into-the-table method if you want both.
19. **What's the relationship to BBR (Doc 28)?** Orthogonal: each `Connection` in the table has its own
    congestion controller; you can `use_bbr()` per connection (exercise (d)).
20. **Is this how `main` actually serves `nc`/`curl`?** Yes — `main` is the same demux plus ICMP/UDP and
    the echo/HTTP application; `TcpServer` is its TCP core, lifted out and unit-tested.

## H. Anki starter deck

```text
   Q: What uniquely identifies a TCP connection?  A: The 4-tuple (remote IP, remote port, local IP,
      local port).
   Q: Why was Doc 22's façade single-connection?  A: The stream OWNS its transport; the listener moves
      it on accept, so it's spent after one.
   Q: What does TcpServer own?  A: One PacketIo transport + a HashMap<Quad, Connection> table.
   Q: How is an inbound datagram routed?  A: parse → 4-tuple → table lookup; hit = dispatch, miss+SYN =
      accept, else drop.
   Q: What are the four phases of poll()?  A: timers, ingest+route, transmit+announce, reap.
   Q: Why the `announced` HashSet?  A: To enqueue each connection on the accept backlog exactly once.
   Q: What does accept_one() return?  A: The Quad of the next newly-established connection (a handle).
   Q: How are closed connections removed?  A: poll step 4 retains only non-CLOSED conns.
   Q: Why isn't TcpServer wired into main?  A: main also serves ICMP/UDP; a TCP-only server can't.
   Q: How is the multi-connection test kept offline & deterministic?  A: A shared in-memory medium and
      one simulated clock.
```

## I. Glossary

```text
   Quad           the 4-tuple (remote IP, remote port, local IP, local port) — the demux key
   PacketIo       transport trait: send a datagram, non-blocking try_recv a datagram
   TcpServer      multi-connection server: one transport + a connection table
   backlog        FIFO of connections that just reached ESTABLISHED, awaiting accept_one
   announced      set of quads already enqueued on the backlog (announce-once)
   accept_one     pop the next ready connection's quad (non-blocking accept)
   parse_any      parse a datagram to (Quad, header, payload, opts), no per-conn filter
   reap           remove a CLOSED connection from the table (poll step 4)
   shared medium  test transport where the server broadcasts and clients filter by quad
   listener       (real stacks) a socket matching a wildcard remote on a fixed local port
```

## J. Reference tables

```text
   TcpServer method        connection primitive it wraps        notes
   ─────────────────────   ──────────────────────────────────   ─────────────────────────────
   bind(io, local)         —                                    empty table, bound (addr, port)
   poll(now)               on_tick / on_segment / poll_transmit drives ALL connections once
   accept_one()            (backlog)                             next established quad, FIFO
   send(quad, data)        Connection::write                    queue app bytes on one conn
   recv(quad)              Connection::take_received            drain one conn's in-order bytes
   close(quad, now)        Connection::close                    FIN one conn
   state(quad)             Connection::state                    inspect one conn (or None)
   peer_closed(quad)       Connection::peer_closed              did this peer half-close?
   connection_count()      conns.len()                          live connections in the table
```

| Aspect | Doc 22 `TcpListener`/`TcpStream` | Doc 29 `TcpServer` |
|---|---|---|
| Connections | one | many (a table) |
| Transport ownership | moved into the stream | held centrally, shared |
| Routing | filter against one quad | lookup by quad |
| Accept | one stream, then spent | `accept_one` backlog, repeatable |
| Tested by | one-connection handshake/transfer/close | two concurrent connections, no cross-talk |
