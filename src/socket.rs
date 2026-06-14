//! Day 22 — a blocking `TcpListener` / `TcpStream` façade over the `Connection` state machine.
//!
//! Until now the "socket API" has been `Connection::{write, take_received, poll_transmit}` plus the
//! event loop in `main` — the *mechanism*. This module is the *ergonomics*: the `std::net`-shaped
//! veneer a program actually calls — `TcpListener::bind(..).accept()` → a `TcpStream` you `read` and
//! `write`. Each blocking call drives the same `Connection`, pumping I/O until it can make progress.
//!
//! I/O is abstracted behind [`PacketIo`] so the façade needs no TUN device to test: production wires
//! it to the kernel TUN; the tests wire two façades back-to-back through in-memory queues (a
//! loopback) and run a full handshake → transfer → close **offline and deterministically**. The
//! whole module is `allow(dead_code)` because it is an embeddable API exercised by those tests — the
//! demo `main` keeps its raw multi-protocol loop (it also serves ICMP/UDP and many connections).
//! Theory: `docs/day22-book.md`.
#![allow(dead_code)]

use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use crate::ip;
use crate::tcp::{self, Connection, Quad, State, TcpHeader};

/// The packet transport the façade sends/receives whole IPv4 datagrams over. Production: the TUN
/// device. Tests: an in-memory queue pair. `try_recv` is **non-blocking** — `Ok(None)` means
/// "nothing ready right now" so the pump can move on to timers and transmission.
pub trait PacketIo {
    fn send(&mut self, packet: &[u8]) -> io::Result<()>;
    fn try_recv(&mut self) -> io::Result<Option<Vec<u8>>>;
}

/// Demux one received datagram for `quad`: parse IPv4 + TCP and, only if the 4-tuple matches this
/// connection, return the header, payload, and options. Packets for other connections are ignored
/// (the façade is single-connection; a full stack would route by a table, as `main` does).
fn parse_for(quad: Quad, packet: &[u8]) -> Option<(TcpHeader, Vec<u8>, tcp::TcpOptions)> {
    let iph = ip::parse(packet).ok()?;
    if iph.protocol != 6 {
        return None;
    }
    let l4 = &packet[iph.header_len..];
    let th = tcp::parse(l4)?;
    let q = Quad { remote: (iph.src, th.src_port), local: (iph.dst, th.dst_port) };
    if q != quad {
        return None;
    }
    let off = th.data_offset.min(l4.len());
    let payload = l4[off..].to_vec();
    let opts = tcp::parse_options(&l4[20..off]);
    Some((th, payload, opts))
}

/// A connected TCP endpoint: a `Connection` plus its transport and a small read buffer for the
/// leftover of a partial `read`. Generic over the transport so it is testable without a TUN device.
pub struct TcpStream<T: PacketIo> {
    conn: Connection,
    io: T,
    quad: Quad,
    rbuf: VecDeque<u8>, // received bytes not yet handed to the caller (for sub-buffer reads)
    start: Instant,     // wall clock for the blocking Read/Write veneer
}

impl<T: PacketIo> TcpStream<T> {
    /// Active open: send a SYN to `remote` and return the stream in SYN_SENT. Pump (`poll`) or call a
    /// blocking `read`/`write` to complete the handshake.
    pub fn connect(mut io: T, local: (Ipv4Addr, u16), remote: (Ipv4Addr, u16), now_ms: u64) -> io::Result<Self> {
        let (conn, syn) = Connection::connect(local, remote, now_ms);
        io.send(&syn)?;
        Ok(Self { conn, io, quad: Quad { remote, local }, rbuf: VecDeque::new(), start: Instant::now() })
    }

    /// Milliseconds since the stream was created — the clock for the blocking veneer.
    fn now(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }

    /// One **non-blocking** pump of the connection: fire retransmission/persist timers, ingest every
    /// datagram currently ready, then flush any newly-sendable data. This is the whole event loop for
    /// one connection, and the primitive every blocking call is built on.
    pub fn poll(&mut self, now_ms: u64) -> io::Result<()> {
        for pkt in self.conn.on_tick(now_ms) {
            self.io.send(&pkt)?;
        }
        while let Some(pkt) = self.io.try_recv()? {
            if let Some((th, payload, opts)) = parse_for(self.quad, &pkt) {
                if let Some(out) = self.conn.on_segment(&th, &payload, &opts, now_ms) {
                    self.io.send(&out)?;
                }
            }
        }
        for seg in self.conn.poll_transmit(now_ms) {
            self.io.send(&seg)?;
        }
        Ok(())
    }

    pub fn state(&self) -> State {
        self.conn.state()
    }

    pub fn established(&self) -> bool {
        self.conn.state() == State::Established
    }

    /// Has the peer half-closed (sent its FIN)? Once true and the read buffer is drained, reads are
    /// at EOF.
    pub fn peer_closed(&self) -> bool {
        self.conn.peer_closed()
    }

    /// Queue application bytes for transmission (non-blocking). They go out on the next `poll`.
    pub fn feed(&mut self, data: &[u8]) {
        self.conn.write(data);
    }

    /// Drain all received, in-order application bytes (non-blocking): the read buffer plus whatever
    /// the connection has delivered since the last call. (Named `recv_all`, not `take`, to avoid
    /// being shadowed by `std::io::Read::take`, which consumes `self` by value.)
    pub fn recv_all(&mut self) -> Vec<u8> {
        self.drain_delivered();
        self.rbuf.drain(..).collect()
    }

    fn drain_delivered(&mut self) {
        let delivered = self.conn.take_received();
        self.rbuf.extend(delivered);
    }

    /// Close our send side (FIN). From ESTABLISHED this is an active close; from CLOSE_WAIT it
    /// finishes a passive half-close (Day 19).
    pub fn close(&mut self, now_ms: u64) -> io::Result<()> {
        if let Some(fin) = self.conn.close(now_ms) {
            self.io.send(&fin)?;
        }
        Ok(())
    }
}

impl<T: PacketIo> Read for TcpStream<T> {
    /// Blocking read: pump until at least one byte is available, or EOF (the peer's FIN with an empty
    /// buffer → `Ok(0)`, the std convention).
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            self.poll(self.now())?;
            self.drain_delivered();
            if !self.rbuf.is_empty() {
                let n = buf.len().min(self.rbuf.len());
                for slot in buf.iter_mut().take(n) {
                    *slot = self.rbuf.pop_front().unwrap();
                }
                return Ok(n);
            }
            if self.conn.peer_closed() {
                return Ok(0); // EOF
            }
            std::thread::sleep(Duration::from_millis(2)); // let timers/the peer make progress
        }
    }
}

impl<T: PacketIo> Write for TcpStream<T> {
    /// Buffer `data` and pump once; the bytes flow out as the send window allows.
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.conn.write(data);
        self.poll(self.now())?;
        Ok(data.len())
    }

    /// Block until the send buffer has drained onto the wire (handed to the segmenter; not
    /// necessarily acknowledged).
    fn flush(&mut self) -> io::Result<()> {
        while !self.conn.send_buffer_empty() {
            self.poll(self.now())?;
            std::thread::sleep(Duration::from_millis(2));
        }
        Ok(())
    }
}

/// A passive-open listener bound to a local address. Single-connection: `accept` moves the transport
/// into the returned stream (a full stack would keep the listener and demux by a connection table).
pub struct TcpListener<T: PacketIo> {
    io: Option<T>,
    local: (Ipv4Addr, u16),
}

impl<T: PacketIo> TcpListener<T> {
    pub fn bind(io: T, local: (Ipv4Addr, u16)) -> Self {
        Self { io: Some(io), local }
    }

    /// **Non-blocking** accept: drain ready datagrams; on the first SYN addressed to us, build the
    /// server `Connection`, send the SYN-ACK, and hand the transport to a new `TcpStream` (in
    /// SYN_RCVD — pump it to reach ESTABLISHED). `Ok(None)` if no SYN is ready (or the listener has
    /// already produced its one stream).
    pub fn poll_accept(&mut self, now_ms: u64) -> io::Result<Option<TcpStream<T>>> {
        let local = self.local;
        let io = match self.io.as_mut() {
            Some(io) => io,
            None => return Ok(None),
        };
        while let Some(pkt) = io.try_recv()? {
            let iph = match ip::parse(&pkt) {
                Ok(h) if h.protocol == 6 && h.dst == local.0 => h,
                _ => continue,
            };
            let l4 = &pkt[iph.header_len..];
            let th = match tcp::parse(l4) {
                Some(th) if th.dst_port == local.1 => th,
                _ => continue,
            };
            let off = th.data_offset.min(l4.len());
            let opts = tcp::parse_options(&l4[20..off]);
            if let Some((conn, synack)) = Connection::accept(iph.src, iph.dst, &th, &opts, now_ms) {
                io.send(&synack)?;
                let quad = Quad { remote: (iph.src, th.src_port), local: (iph.dst, th.dst_port) };
                let io = self.io.take().unwrap(); // single-connection: hand the transport over
                return Ok(Some(TcpStream {
                    conn,
                    io,
                    quad,
                    rbuf: VecDeque::new(),
                    start: Instant::now(),
                }));
            }
        }
        Ok(None)
    }

    /// Blocking accept: pump until a SYN arrives and the connection reaches ESTABLISHED.
    pub fn accept(&mut self) -> io::Result<TcpStream<T>> {
        let start = Instant::now();
        loop {
            let now = start.elapsed().as_millis() as u64;
            if let Some(mut stream) = self.poll_accept(now)? {
                while !stream.established() {
                    stream.poll(stream.now())?;
                    std::thread::sleep(Duration::from_millis(2));
                }
                return Ok(stream);
            }
            std::thread::sleep(Duration::from_millis(2));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    type Queue = Rc<RefCell<VecDeque<Vec<u8>>>>;

    /// A loopback transport: bytes we `send` land in `tx`; `try_recv` pulls from `rx`. Two pipes
    /// cross-wired (`a.tx == b.rx`, `a.rx == b.tx`) connect two stacks back to back, in one thread.
    #[derive(Clone)]
    struct Pipe {
        tx: Queue,
        rx: Queue,
    }
    impl PacketIo for Pipe {
        fn send(&mut self, packet: &[u8]) -> io::Result<()> {
            self.tx.borrow_mut().push_back(packet.to_vec());
            Ok(())
        }
        fn try_recv(&mut self) -> io::Result<Option<Vec<u8>>> {
            Ok(self.rx.borrow_mut().pop_front())
        }
    }
    fn pipe_pair() -> (Pipe, Pipe) {
        let a2b: Queue = Default::default();
        let b2a: Queue = Default::default();
        (Pipe { tx: a2b.clone(), rx: b2a.clone() }, Pipe { tx: b2a, rx: a2b })
    }

    #[test]
    fn loopback_handshake_transfer_and_close() {
        let (client_io, server_io) = pipe_pair();
        let server_addr = (Ipv4Addr::new(192, 168, 0, 2), 80);
        let client_addr = (Ipv4Addr::new(192, 168, 0, 1), 40000);

        let mut listener = TcpListener::bind(server_io, server_addr);
        let mut client = TcpStream::connect(client_io, client_addr, server_addr, 0).unwrap();

        // Drive both ends with a shared logical clock until the handshake completes.
        let mut server: Option<TcpStream<Pipe>> = None;
        for t in 0..50u64 {
            if server.is_none() {
                server = listener.poll_accept(t).unwrap();
            }
            client.poll(t).unwrap();
            if let Some(s) = server.as_mut() {
                s.poll(t).unwrap();
            }
            if client.established() && server.as_ref().is_some_and(|s| s.established()) {
                break;
            }
        }
        let mut server = server.expect("server accepted a connection");
        assert!(client.established(), "client reached ESTABLISHED");
        assert!(server.established(), "server reached ESTABLISHED");

        // Client → server.
        client.feed(b"hello over a hand-rolled TCP");
        for t in 50..80u64 {
            client.poll(t).unwrap();
            server.poll(t).unwrap();
        }
        assert_eq!(server.recv_all(), b"hello over a hand-rolled TCP");

        // Server → client (the reverse direction of the same connection).
        server.feed(b"and hello back");
        for t in 80..110u64 {
            server.poll(t).unwrap();
            client.poll(t).unwrap();
        }
        assert_eq!(client.recv_all(), b"and hello back");

        // Client closes its send side; the server sees EOF and enters CLOSE_WAIT.
        client.close(110).unwrap();
        for t in 110..160u64 {
            client.poll(t).unwrap();
            server.poll(t).unwrap();
        }
        assert!(server.peer_closed(), "server saw the client's FIN (EOF)");
        assert_eq!(server.state(), State::CloseWait);
        assert_eq!(client.state(), State::FinWait2); // our FIN acked, awaiting theirs

        // The server closes its half → the four-way teardown completes.
        server.close(160).unwrap();
        for t in 160..400u64 {
            client.poll(t).unwrap();
            server.poll(t).unwrap();
        }
        assert_eq!(client.state(), State::TimeWait); // active closer lingers in TIME_WAIT
        assert_eq!(server.state(), State::Closed); // passive closer: LAST_ACK → CLOSED
    }

    #[test]
    fn loopback_half_close_then_server_replies() {
        // The client half-closes after sending; the server must still be able to send afterward
        // (Day 19 half-close), exercised end to end through the façade.
        let (client_io, server_io) = pipe_pair();
        let server_addr = (Ipv4Addr::new(192, 168, 0, 2), 80);
        let client_addr = (Ipv4Addr::new(192, 168, 0, 1), 40001);
        let mut listener = TcpListener::bind(server_io, server_addr);
        let mut client = TcpStream::connect(client_io, client_addr, server_addr, 0).unwrap();
        let mut server = None;
        for t in 0..50u64 {
            if server.is_none() {
                server = listener.poll_accept(t).unwrap();
            }
            client.poll(t).unwrap();
            if let Some(s) = server.as_mut() {
                s.poll(t).unwrap();
            }
            if client.established() && server.as_ref().is_some_and(|s| s.established()) {
                break;
            }
        }
        let mut server = server.unwrap();

        client.feed(b"request");
        for t in 50..70u64 {
            client.poll(t).unwrap();
            server.poll(t).unwrap();
        }
        client.close(70).unwrap(); // half-close: client's send side done
        for t in 70..100u64 {
            client.poll(t).unwrap();
            server.poll(t).unwrap();
        }
        assert_eq!(server.recv_all(), b"request");
        assert!(server.peer_closed());

        // The server is now in CLOSE_WAIT but may still send — the whole point of half-close.
        server.feed(b"a reply after your FIN");
        for t in 100..140u64 {
            server.poll(t).unwrap();
            client.poll(t).unwrap();
        }
        assert_eq!(client.recv_all(), b"a reply after your FIN");
    }
}
