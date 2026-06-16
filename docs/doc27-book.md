# Doc 27 — TCP, Part 25: SYN Cookies — A Stateless Handshake Under Flood (RFC 4987)

> Goal: survive a SYN flood. Every passive open so far allocates a Transmission Control Block the
> instant a SYN arrives — a TCB in SYN_RCVD, holding sequence numbers, buffers, timers — and waits
> for the client's final ACK. That's correct, but it's a *resource trap*: an attacker can send a
> torrent of SYNs from spoofed addresses, never completing any handshake, and the server fills its
> memory with half-open connections that will never finish. This is the classic **SYN flood**, and a
> naive accept path falls over to it: the half-open *backlog* exhausts, and legitimate SYNs are
> dropped. The whole attack costs the attacker nothing (spoofed SYNs, no state) and costs the server
> everything (a TCB per SYN).
>
> **SYN cookies** (RFC 4987) flip the asymmetry. When the backlog is full, the server stops
> allocating a TCB on the SYN. Instead it encodes the handshake into the **SYN-ACK's initial sequence
> number** — a *cookie* that packs a coarse timestamp, the client's advertised MSS, and a keyed hash
> of the connection's 4-tuple — and then *forgets everything*. No TCB, no memory, no backlog entry.
> A real client echoes that cookie (as `ack = cookie + 1`) in its final ACK; the server recomputes
> the cookie from the 4-tuple and its secret, checks it matches, and *only then* allocates the TCB —
> directly in ESTABLISHED. A spoofed SYN that never returns an ACK costs the server exactly one
> stateless SYN-ACK and zero memory. The state lives *in the sequence number*, carried by the network
> and authenticated on return.

**Contents**

Volume I — the chapter
1. The mental model: state in the sequence number
2. The SYN flood, and why the backlog exhausts
3. The cookie: what to pack into 32 bits
4. Generating a cookie
5. Validating a returned cookie
6. Reconstructing the connection — straight to ESTABLISHED
7. The backlog policy: cookies only under pressure
8. What SYN cookies cost: the lost options
9. The Rust: keyed mixing, bit-packing, a no-TCB SYN-ACK
10. A fully worked cookie handshake
11. The code, walked end to end
12. Verification — the four new tests
13. Why this, not that
14. Honesty: what production does that we don't
15. Rebuild it yourself — checklist + exercises
16. What comes after

Volume II — the exhaustive reference
- A. RFC 4987: SYN-flood mitigations, the menu
- B. The cookie format, bit by bit
- C. The keyed hash — why ours isn't SipHash
- D. The MSS table, and which options survive
- E. Backlog accounting and when to switch
- F. Comparison to real stacks — the sysctls
- G. Extended FAQ — twenty-five questions a careful reader asks
- H. Anki starter deck
- I. Glossary
- J. Reference tables

---

# Volume I — the chapter

## 1. The mental model: state in the sequence number

A TCP server, on receiving a SYN, must remember three things until the final ACK arrives: *who* the
client is (the 4-tuple), *its* initial sequence number, and *what it negotiated* (at minimum, the
MSS). Normally that memory is a TCB. SYN cookies ask: **what if we didn't keep the memory, but put it
on the wire instead?**

The SYN-ACK already carries a 32-bit field the server chooses freely: its **initial sequence number**
(ISS). Normally the ISS is random (Doc 3, RFC 6528). SYN cookies make the ISS *carry information* — a
**cookie** that encodes the handshake parameters and a cryptographic-ish signature. The server sends
this cookie as its ISS and discards all state. The TCP protocol then does the server's bookkeeping
*for free*: the client must acknowledge the SYN-ACK by sending `ack = ISS + 1 = cookie + 1`. That
returning ACK hands the cookie *back* to the server, which re-derives the handshake from it. The
sequence number — a field that existed anyway — becomes the storage, and the network becomes the
memory.

The genius is the **authentication**: the cookie includes a hash keyed by a secret only the server
knows, over the connection's 4-tuple. An attacker can't forge a valid cookie (they don't have the
secret), and a cookie for one connection won't validate for another (the 4-tuple is bound in). So the
server can trust a returned cookie *without having remembered sending it*.

## 2. The SYN flood, and why the backlog exhausts

Walk the attack against a naive accept path:

```text
   attacker (spoofing random source IPs)        server (TCB per SYN)
   ──────────────────────────────────────       ──────────────────────────────
   SYN from 1.2.3.4 ───────────────────────▶    allocate TCB #1 (SYN_RCVD), send SYN-ACK
   SYN from 5.6.7.8 ───────────────────────▶    allocate TCB #2 (SYN_RCVD), send SYN-ACK
   SYN from 9.10.11.12 ────────────────────▶    allocate TCB #3 …
   … thousands per second, NONE ever ACKed …    backlog fills with half-open TCBs
                                                  → memory exhausts; new (legitimate) SYNs dropped
```

The cost asymmetry is the whole problem. Each spoofed SYN is ~40 bytes and *no state* for the
attacker (they don't even process the SYN-ACK — it goes to the spoofed address, which discards it).
But each SYN costs the server a full TCB and a backlog slot, held for the SYN_RCVD timeout (tens of
seconds). A modest packet rate exhausts the backlog, and the server can no longer accept *real*
connections. The attacker spends nothing; the server spends everything.

The half-open **backlog** is the finite resource: the number of connections the server will hold in
SYN_RCVD at once. When it's full, a naive server drops new SYNs. SYN cookies are what let the server
keep accepting *without* the backlog — by not using it at all under flood.

## 3. The cookie: what to pack into 32 bits

The cookie is the server's ISS — exactly 32 bits — and must encode everything needed to (a) expire
old cookies, (b) recover the negotiated MSS, and (c) authenticate the handshake. The classic
(Bernstein) layout, and ours:

```text
   bit  31            26 25  24 23                              0
        ┌───────────────┬──────┬─────────────────────────────────┐
        │  counter (6)  │mss(2)│            MAC (24)             │
        └───────────────┴──────┴─────────────────────────────────┘
   counter : a slow time counter (advances ~once a minute) → bounds cookie lifetime
   mss     : a 2-bit index into a small table of standard MSS values → recovers the client's MSS
   MAC     : low 24 bits of a keyed hash over (secret, 4-tuple, client ISN, counter) → authenticity
```

Why each:
- **Counter** (for expiry): a cookie must not be valid forever, or a captured cookie could be replayed
  indefinitely. A coarse counter (here `now / 64 s`, low 6 bits) lets validation reject cookies more
  than a couple of ticks old — they're only good for a window long enough to complete a handshake.
- **MSS index** (the one option we must keep): the server forgot the SYN, so it forgot the client's
  advertised MSS. Without it the server would have to assume the conservative 536-byte default,
  crippling throughput. Two bits index a table of common MSS values (§D), recovering it
  approximately.
- **MAC** (authenticity): a keyed hash binds the cookie to *this* 4-tuple and the client's ISN, signed
  by the server's secret. Without it, anyone could fabricate a cookie. 24 bits is a deliberate
  trade-off — enough to make forgery a 1-in-16-million guess per attempt, small enough to leave room
  for the counter and MSS (§B).

## 4. Generating a cookie

When the backlog is full and a SYN arrives, the server computes a cookie instead of allocating a TCB:

```rust
pub fn syn_cookie(secret, local, remote, peer_isn, peer_mss, now_ms) -> u32 {
    let counter = (now_ms / COOKIE_TICK_MS) as u32;                       // slow time counter
    let mss_idx = COOKIE_MSS_TABLE.iter().rposition(|&m| m <= peer_mss).unwrap_or(0) as u32; // round down
    let mac = cookie_mix(secret, local, remote, peer_isn, counter) & 0x00FF_FFFF;            // keyed hash
    ((counter & 0x3f) << 26) | ((mss_idx & 0x3) << 24) | mac
}
```

`peer_isn` is the client's ISN (the SYN's `seq`), bound into the MAC so the cookie is specific to this
handshake. `mss_idx` rounds the client's advertised MSS *down* to the nearest table entry (never up —
overstating the MSS would fragment). The server sends this as the SYN-ACK's ISS (`seq = cookie`,
`ack = peer_isn + 1`), carrying only the MSS option (§8), and stores nothing.

## 5. Validating a returned cookie

A final ACK arriving for a connection the server has *no record of* might be a returning cookie. The
ACK's `ack` field is `cookie + 1`, and its `seq` is `peer_isn + 1`, so the server recovers both and
re-derives the cookie:

```rust
pub fn check_syn_cookie(secret, local, remote, peer_isn, cookie, now_ms) -> Option<u16> {
    let counter_bits = (cookie >> 26) & 0x3f;
    let mss_idx      = ((cookie >> 24) & 0x3) as usize;
    let mac          =  cookie & 0x00FF_FFFF;
    let now_counter  = (now_ms / COOKIE_TICK_MS) as u32;
    for back in 0..=2 {                                    // accept this tick or the previous two
        let c = now_counter.wrapping_sub(back);
        if (c & 0x3f) == counter_bits
            && (cookie_mix(secret, local, remote, peer_isn, c) & 0x00FF_FFFF) == mac {
            return Some(COOKIE_MSS_TABLE[mss_idx]);        // authentic + recent → recover the MSS
        }
    }
    None                                                   // forged or expired → caller RSTs
}
```

Two checks make it safe: the **MAC** must match (so it was minted by *this* server's secret for *this*
4-tuple and ISN — unforgeable without the secret), and the **counter** must be recent (within a couple
of ticks — so an old cookie can't be replayed days later). If both pass, the encoded MSS is recovered
and the connection can be built; if not, it's a stray ACK or an attack, and the server RSTs.

The crucial property: validation requires **no stored state** — just the secret (a single per-process
value) and the fields in the packet. The server authenticates a handshake it has no memory of
initiating.

## 6. Reconstructing the connection — straight to ESTABLISHED

A valid cookie means the three-way handshake is *complete* (SYN seen, SYN-ACK sent, final ACK
received) — there was simply never a TCB during it. So the server builds the TCB directly in
**ESTABLISHED**, reconstructing the sequence state from the cookie and the final ACK:

```rust
pub fn from_syn_cookie(local, remote, peer_isn, cookie, send_mss, now_ms) -> Connection {
    let iss = cookie;  // our SYN-ACK's ISS was the cookie; it consumed `cookie`, so SND.NXT = cookie+1
    Connection {
        state: State::Established,
        send: SendSequence { iss, una: iss+1, nxt: iss+1, wnd },   // SND.UNA = SND.NXT = cookie+1
        recv: RecvSequence { irs: peer_isn, nxt: peer_isn+1, wnd }, // RCV.NXT = the client's next byte
        send_mss: send_mss.min(OUR_MSS),
        ts_enabled: false, snd_wscale: 0, sack_ok: false,           // options were not negotiated (§8)
        /* … the rest as a fresh connection … */
    }
}
```

`SND.NXT = cookie + 1` because our SYN-ACK consumed sequence number `cookie` (a SYN-ACK's SYN bit
occupies one sequence number). `RCV.NXT = peer_isn + 1` because the client's SYN consumed `peer_isn`.
The connection is now indistinguishable from one opened the normal way — except no half-open state
ever existed.

## 7. The backlog policy: cookies only under pressure

SYN cookies have costs (§8 — they lose options), so a server doesn't use them *always* — only when the
half-open backlog is actually under pressure. Our `main` checks the backlog occupancy on each SYN:

```rust
if is_syn && half_open_count() < SYN_BACKLOG {
    // room in the backlog → normal passive open (allocate a TCB in SYN_RCVD, full option negotiation)
} else if is_syn {
    // backlog full → stateless SYN cookie (no TCB, only the MSS survives)
}
```

Under normal load — a handful of connections, the backlog far from full — the server does the ordinary
handshake with full option negotiation (timestamps, window scale, SACK). Only when an attacker (or a
genuine connection storm) fills the backlog does it switch to cookies, trading option richness for
survival. This is exactly how Linux behaves (`tcp_syncookies = 1` means "use cookies *when the backlog
overflows*," not "always"). Our live demo, never under flood, takes the normal path — so the
handshake you watch on the wire is unchanged; cookies are the emergency valve.

## 8. What SYN cookies cost: the lost options

The cookie is 32 bits. The MSS fits (as a 2-bit index). But the SYN's *other* options —
**timestamps, window scale, SACK-permitted** — don't fit, and the server forgot the SYN that carried
them. So a cookie connection **loses those options**:

```text
   option            normal handshake        SYN-cookie handshake
   ───────────────   ─────────────────────   ───────────────────────
   MSS               negotiated              recovered (table-rounded)
   timestamps        negotiated (RTTM/PAWS)  LOST (no RTTM, no PAWS)
   window scale      negotiated (>64 KB win) LOST (window capped at 64 KB)
   SACK-permitted    negotiated              LOST (go-back-N recovery)
```

This is a real, well-known limitation: connections accepted via cookies have degraded performance (no
window scaling on a fat pipe, no SACK under loss). That's an acceptable trade during an attack — a
slower connection beats *no* connection — and it's *why* cookies are used only under flood, not
always. (Linux can encode timestamps into the cookie+TS-option to claw back window scale and SACK; a
clever extension we note but don't implement, §D.) Our `from_syn_cookie` honestly disables
timestamps, window scale, and SACK on cookie connections.

## 9. The Rust: keyed mixing, bit-packing, a no-TCB SYN-ACK

**The keyed mix.** `cookie_mix` folds the secret, 4-tuple, client ISN, and counter through FNV-style
wrapping-multiply rounds into 32 bits, of which we keep 24 for the MAC. It is deliberately *not*
cryptographic — a real stack uses SipHash (a keyed PRF designed for exactly this) — but it shows the
structure: a value an attacker can't reproduce without the secret. `u32::from(Ipv4Addr)` turns an
address into the integer to mix; `.wrapping_mul` keeps the arithmetic in-bounds.

**Bit-packing the cookie.** `((counter & 0x3f) << 26) | ((mss_idx & 0x3) << 24) | mac` assembles the
three fields with shifts and masks; validation reverses it with `(cookie >> 26) & 0x3f` etc. This is
the same field-packing as a header, just into a single `u32` instead of a byte array — a reminder that
a "sequence number" is, here, a tiny structured message.

**A SYN-ACK with no `Connection`.** `build_syn_cookie_synack` calls `build_packet` directly — the
first time we synthesize a TCP segment *without* a `Connection` object, because the whole point is
that none exists. It carries only the MSS option (§8) and is fire-and-forget: if the SYN-ACK is lost,
the client retransmits its SYN and gets a fresh cookie (a new counter, but still valid). No
retransmission queue, no state.

**A `match` on flags in the accept path.** With no connection, the segment could be a SYN (open), a
returning cookie ACK (a bare ACK), or junk (RST). We classify by flag bits (`is_syn`, `is_bare_ack`)
and branch — the no-connection case grew from "SYN or not" to a small dispatch, because cookies add a
*second* way a stateless packet can be meaningful.

## 10. A fully worked cookie handshake

Backlog full. Client `192.168.0.1:40000` → server `192.168.0.2:80`. Client ISN = 1000, advertises
MSS 1460. Server secret `S`, time such that `counter = 42`.

```text
   #  dir       segment                                   server action
   ── ────────  ────────────────────────────────────────  ───────────────────────────────────────────
   1  client▶   SYN seq=1000 (MSS 1460)                    backlog FULL → cookie = pack(42, mss_idx=2,
                                                            MAC(S, 4-tuple, 1000, 42)).  NO TCB.
   2  ▶client   SYN,ACK seq=cookie ack=1001 (MSS opt)      stateless SYN-ACK; server forgets everything
        ── (a spoofed SYN would stop here: server spent one packet, zero memory) ──
   3  client▶   ACK seq=1001 ack=cookie+1                  no TCB for this 4-tuple → try cookie:
                                                            cookie = ack−1; peer_isn = seq−1 = 1000;
                                                            check_syn_cookie(S, 4-tuple, 1000, cookie, now)
                                                            → MAC matches, counter recent → MSS 1460.
                                                            from_syn_cookie → TCB in ESTABLISHED:
                                                              SND.NXT = cookie+1,  RCV.NXT = 1001.
   4  client▶   PSH,ACK seq=1001 … data …                 ordinary ESTABLISHED data transfer
```

At step 1 the server commits *nothing* — a flood of step-1 SYNs costs one SYN-ACK each and no memory,
so the backlog never exhausts. Only a client that actually returns at step 3 with a *valid* cookie
gets a TCB. The attacker's asymmetry is destroyed: spoofed SYNs are free for the server too. (The unit
tests drive exactly this: `syn_cookie` → `check_syn_cookie` round-trips, tampering fails, and
`from_syn_cookie` produces a working ESTABLISHED connection.)

## 11. The code, walked end to end

`src/tcp.rs` adds the cookie machinery as free functions (no `Connection` needed to mint/check a
cookie) plus one constructor:
- `cookie_mix` (private) — the keyed hash (§9).
- `syn_cookie` — mint a cookie from the SYN (§4).
- `check_syn_cookie` — validate a returned cookie, recover the MSS (§5).
- `build_syn_cookie_synack` — the stateless SYN-ACK (§9).
- `Connection::from_syn_cookie` — build the TCB in ESTABLISHED from a validated cookie (§6).

`src/main.rs` wires the policy (§7): a per-process `syn_secret` (random at startup); on a SYN, normal
`accept` while the SYN_RCVD backlog is under `SYN_BACKLOG`, else a cookie; on a bare ACK to no
connection, `check_syn_cookie` → `from_syn_cookie` or a RST. The normal path (and the live demo) is
untouched until the backlog fills.

## 12. Verification — the four new tests

`cargo test` — **137 passing** (133 + 4). The cookie functions are pure, so they're tested directly.

- **`syn_cookie_round_trips_and_recovers_mss`** — a cookie minted for a handshake validates with the
  matching parameters and recovers the (table-rounded) MSS; a smaller advertised MSS rounds down to
  the right table entry.
- **`syn_cookie_rejects_tampering`** — a wrong secret, wrong 4-tuple (port *or* address), wrong client
  ISN, or a single flipped bit all fail to validate. This is the authenticity property — an attacker
  can't forge or transplant a cookie.
- **`syn_cookie_expires`** — a cookie validates now and one tick later, but not many ticks later. The
  replay window is bounded.
- **`from_syn_cookie_builds_established_connection`** — a validated cookie reconstructs an ESTABLISHED
  connection with the correct `SND.NXT = cookie + 1` and `RCV.NXT = peer_isn + 1`, and it then
  delivers and acknowledges data like any other connection.

Every prior test still passes: the cookie path is additive (the normal `accept` is unchanged), and
`main`'s policy only diverges when the backlog is full — which no test triggers.

## 13. Why this, not that

**Why put state in the sequence number instead of just a bigger backlog?** A bigger backlog is still
*finite* — the attacker just sends more SYNs. Cookies make the per-SYN cost *zero memory*, so there's
nothing to exhaust. It's an asymmetry fix, not a capacity bump. (§§2, 10.)

**Why a keyed MAC in the cookie?** So the server can *trust* a returned cookie without having
remembered sending it — only the server's secret could have minted it for this 4-tuple. Without the
MAC, anyone could fabricate a cookie and open a connection. (§§3, 5.)

**Why a time counter?** To bound the replay window — a captured cookie is useless after a couple of
ticks, so an old SYN-ACK can't be replayed indefinitely. (§3.)

**Why round the MSS *down*?** Overstating the MSS would cause fragmentation or drops; the conservative
table entry below the client's advertised value is always safe. (§4.)

**Why only under backlog pressure, not always?** Cookies lose timestamps/window-scale/SACK (§8), so
they degrade performance — a worthwhile trade only when the alternative is dropping connections. Under
normal load, the full handshake is better. (§7.)

**Why build straight to ESTABLISHED?** A valid returned cookie *proves* the three-way handshake
completed; there's no half-open state to pass through — the TCB is born established. (§6.)

## 14. Honesty: what production does that we don't

- **The hash isn't cryptographic.** We use an FNV-style mix; a real stack uses **SipHash** (a keyed
  PRF) so the MAC can't be reverse-engineered from observed cookies. Our mix demonstrates the
  structure but wouldn't withstand a determined attacker analyzing many cookies. (§C; exercise E1.)
- **Options are dropped, not clawed back.** Linux can encode the timestamp option to recover window
  scale and SACK on cookie connections (RFC 7323 §5.5 + the TS option); we simply lose them. (§8;
  E2.)
- **Two secrets, rotated.** Production uses two secrets and rotates them so cookies stay valid across a
  rotation; we use one fixed per-process secret. (E3.)
- **Backlog accounting is a scan.** We count SYN_RCVD connections by scanning the table each SYN
  (O(n)); a real stack keeps a counter. Fine at our scale.
- **No SYN_RCVD timeout.** Independently of cookies, a real stack times out half-open connections (the
  Manual's `syn_received_timeout`) so the backlog drains even without cookies; we rely on the
  connection's own retransmission giving up. (E4.)
- **Cookies are always available here.** Linux's `tcp_syncookies` has three modes (off / on-overflow /
  always); we hardcode "on backlog overflow." The mechanism is the same.

The cookie *structure* — stateless SYN-ACK, ISN-as-cookie, keyed authentication, recover-and-build —
is real RFC 4987; the gaps are the hash strength and option-clawback refinements.

## 15. Rebuild it yourself — checklist + exercises

**Checklist**

- [ ] `cookie_mix(secret, local, remote, peer_isn, counter)` — a keyed hash → 32 bits.
- [ ] `syn_cookie(...)` — pack `[counter:6][mss_idx:2][mac:24]`, MSS rounded down via a table.
- [ ] `check_syn_cookie(...)` — verify the MAC for the current/previous couple of counters; recover
      the MSS; reject otherwise.
- [ ] `build_syn_cookie_synack(...)` — stateless SYN-ACK (ISS = cookie, MSS option only).
- [ ] `Connection::from_syn_cookie(...)` — build ESTABLISHED with `SND.NXT = cookie+1`,
      `RCV.NXT = peer_isn+1`, options disabled.
- [ ] `main`: per-process secret; normal `accept` under `SYN_BACKLOG`, cookie above it; validate a
      bare ACK to no connection as a returning cookie, else RST.
- [ ] `cargo test` green (137), `cargo clippy -- -D warnings` clean.

**Exercises**

1. **E1 — SipHash.** Replace `cookie_mix` with SipHash-2-4 keyed by the secret; show observed cookies
   don't leak the key.
2. **E2 — timestamp clawback.** Encode the window-scale/SACK bits into the low bits of the TCP
   timestamp option (echoed by the client) and recover them on the cookie ACK, so cookie connections
   keep window scaling and SACK.
3. **E3 — secret rotation.** Keep two secrets; mint with the newer, validate against both; rotate on a
   timer. Show a cookie minted just before rotation still validates after.
4. **E4 — SYN_RCVD timeout.** Independently of cookies, reap a half-open connection after N seconds
   (the `syn_received_timeout`), so the backlog drains even without cookies.
5. **E5 — flood it (live).** Send a burst of spoofed SYNs (e.g. `hping3 -S --flood --rand-source`) to
   the running stack; watch the log switch to "SYN cookie (no TCB)" and confirm a real `curl` still
   completes via the cookie path.

Make Anki cards from the cookie layout `[counter:6][mss:2][mac:24]` and "state in the sequence number."

## 16. What comes after

SYN cookies close the last *robustness* gap — the accept path now survives a flood. With it, every
connection state, modern loss detection and congestion control, the full lifecycle, and the complete
RFC 5961/1337/4987 robustness suite are in place. What remains is genuinely *breadth*: **BBR**
(model-based congestion control — a different philosophy from CUBIC's loss-based curve), a
**multi-connection socket façade** wired into `main`, and the live `packetdrill`/`iperf3` conformance
and throughput validation that needs a real network. The protocol engine is complete; these are the
research frontier and the production-validation mile.

---

# Volume II — the exhaustive reference

## A. RFC 4987: SYN-flood mitigations, the menu

RFC 4987 ("TCP SYN Flooding Attacks and Common Mitigations") surveys the defenses; SYN cookies are one:

```text
   mitigation              idea                                      cost
   ─────────────────────   ───────────────────────────────────────   ──────────────────────────
   bigger backlog          hold more half-open TCBs                   still finite; just delays it
   SYN_RCVD timeout        reap half-open faster                      helps; doesn't stop a fast flood
   SYN cache               compact half-open state (not a full TCB)   less memory/SYN, still O(SYNs)
   SYN cookies             NO state until the ACK returns            O(1) memory; loses some options
   firewall / rate-limit   drop SYNs upstream                         coarse; can hit real traffic
```

SYN cookies are the only mitigation that makes the per-SYN memory cost *zero*. The trade is the lost
options (§8), which is why they're typically engaged only on backlog overflow — the SYN cache (compact
state, keeps options) is the gentler first line, cookies the last resort under heavy flood.

## B. The cookie format, bit by bit

Our 32-bit cookie (Bernstein layout):

```text
   bits 31–26 (6)   counter   = (now_ms / 64000) mod 64   — expiry; reject if not within ~2 ticks
   bits 25–24 (2)   mss_idx   = index into COOKIE_MSS_TABLE — recovers the MSS (rounded down)
   bits 23–0 (24)   MAC       = cookie_mix(secret, 4-tuple, peer_isn, counter) & 0xFFFFFF — authenticity
```

The bit budget is the design tension: more MAC bits = harder to forge but fewer for counter/MSS.
24 MAC bits give a 1-in-16,777,216 forgery chance per guess (and the attacker must also guess the
4-tuple and land the ACK), which is ample; 6 counter bits give 64 ticks ≈ 68 minutes of distinct
values (we only use ~3); 2 MSS bits index 4 common MSS values. Real implementations make similar
splits (Linux: 32-bit cookie, ~24-bit MAC, MSS index, a few counter bits).

## C. The keyed hash — why ours isn't SipHash

`cookie_mix` is FNV-style: `h = (h ⊕ field)·prime`, one round per field, keyed by the secret as the
initial `h`. It's fast and mixes well enough to *demonstrate* SYN cookies, but it is **not** a secure
keyed PRF — an attacker who collects many `(4-tuple, cookie)` pairs could, in principle, solve for the
secret or find collisions, because FNV is not designed to resist key-recovery.

Production uses **SipHash** (Aumasson–Bernstein), a keyed PRF designed precisely for short,
key-dependent hashes in hostile settings (it's also Rust's default `HashMap` hasher, for HashDoS
resistance). The cookie's security rests entirely on the MAC being unforgeable without the secret, so
a real deployment *must* use SipHash (or HMAC); our FNV mix is a teaching placeholder, flagged
loudly. The *structure* of cookies is independent of the hash choice — swap `cookie_mix` for SipHash
(E1) and everything else is unchanged.

## D. The MSS table, and which options survive

```text
   COOKIE_MSS_TABLE = [536, 1220, 1460, 8960]   (2-bit index)
     536  — the IPv4 minimum MSS (RFC 9293 default), for paths with small MTUs / tunnels
     1220 — typical for IPv6 / some tunnels (1280 MTU − 60)
     1460 — standard Ethernet (1500 MTU − 40)
     8960 — jumbo frames (9000 MTU − 40)
```

The client's advertised MSS is rounded *down* to the nearest entry (never up — overstating fragments).
This is the *only* option a basic cookie preserves. The others (timestamps, window scale, SACK) are
lost (§8) because they don't fit in 32 bits and the SYN was forgotten. The clever clawback (Linux):
the *timestamp option* is echoed by the client in the final ACK, so the server can stash the
window-scale shift and SACK-permitted flag in the low bits of the timestamp it sent, and recover them
when the client echoes it — restoring the high-throughput options even under cookies. We don't (E2).

## E. Backlog accounting and when to switch

```text
   on each SYN:
     half_open = count of connections in SYN_RCVD
     if half_open < SYN_BACKLOG:  normal accept (TCB in SYN_RCVD, full options)
     else:                        SYN cookie (no TCB, MSS only)
```

The backlog is the half-open population, not all connections — an ESTABLISHED connection isn't a
flood risk. Linux exposes this as `net.ipv4.tcp_max_syn_backlog` (the half-open limit) and
`net.ipv4.tcp_syncookies` (0 = off, 1 = on overflow, 2 = always). Our `SYN_BACKLOG = 128` with
"cookies on overflow" mirrors mode 1. Counting by scanning the table is O(n) per SYN; a production
stack keeps a live counter incremented on SYN_RCVD entry and decremented on the transition to
ESTABLISHED or on reaping.

## F. Comparison to real stacks — the sysctls

```text
   aspect                Linux                              ours (Doc 27)
   ───────────────────   ────────────────────────────────   ──────────────────────────
   enable                net.ipv4.tcp_syncookies (0/1/2)    cookies on backlog overflow
   backlog limit         net.ipv4.tcp_max_syn_backlog       SYN_BACKLOG = 128
   cookie hash           SipHash, two rotating secrets      FNV-style, one secret (E1/E3)
   options under cookie  MSS + TS-clawback (wscale, SACK)    MSS only (E2)
   SYN_RCVD timeout      yes (also drains the backlog)       relies on retransmit give-up (E4)
   SYN cache             yes (gentler first line)            not implemented
```

Our column is "real SYN-cookie structure, on backlog overflow, with the hash strength, secret
rotation, and option clawback as exercises."

## G. Extended FAQ — twenty-five questions a careful reader asks

1. **What attack do SYN cookies defend?** A SYN flood — spoofed SYNs that fill the half-open backlog
   with TCBs that never complete.
2. **Why is a SYN flood cheap for the attacker?** A spoofed SYN is ~40 bytes and zero state; the
   server pays a TCB + backlog slot per SYN.
3. **What's the core idea?** Don't allocate a TCB on the SYN; encode the handshake in the SYN-ACK's
   ISN (a cookie) and rebuild on the final ACK.
4. **What's in the cookie?** A time counter (expiry), an MSS index, and a keyed MAC over the
   4-tuple + client ISN.
5. **Why the time counter?** To bound the replay window — old cookies stop validating after a couple
   of ticks.
6. **Why the MSS index?** The server forgot the SYN (and the client's MSS); the index recovers it so
   throughput isn't crippled.
7. **Why the MAC?** Authenticity — only the server's secret could have minted this cookie for this
   4-tuple, so a returned cookie is trustworthy without stored state.
8. **How does the client return the cookie?** As `ack = cookie + 1` in its final ACK (normal TCP).
9. **How does the server recover `peer_isn`?** From the final ACK's `seq − 1`.
10. **What if the cookie is forged?** The MAC won't match → `check_syn_cookie` returns `None` → the
    server RSTs.
11. **What if the cookie is old?** The counter won't match a recent tick → rejected.
12. **What state does the server keep per cookie?** None — only the one per-process secret.
13. **What does a spoofed SYN cost the server now?** One stateless SYN-ACK and zero memory.
14. **What options are lost?** Timestamps, window scale, SACK — they don't fit in 32 bits.
15. **Why round MSS down?** Overstating it would fragment; the table entry below is always safe.
16. **Why not use cookies always?** They degrade performance (lost options); use them only when the
    backlog is under pressure.
17. **How is "under pressure" measured?** The count of SYN_RCVD (half-open) connections vs
    `SYN_BACKLOG`.
18. **What state does a validated cookie produce?** A TCB directly in ESTABLISHED — the handshake is
    already complete.
19. **What are `SND.NXT`/`RCV.NXT` after a cookie?** `cookie + 1` and `peer_isn + 1`.
20. **Is our hash secure?** No — it's FNV-style for teaching; production uses SipHash (§C).
21. **Could an attacker brute-force the MAC?** 24 bits = 1-in-16M per guess, and they must also guess
    the 4-tuple and land the ACK — impractical.
22. **Does the normal handshake change?** No — cookies engage only on backlog overflow; otherwise the
    full handshake (with options) runs.
23. **What if the cookie SYN-ACK is lost?** The client retransmits its SYN; the server mints a fresh
    cookie (new counter) — no state to lose.
24. **How is this tested offline?** Pure-function round-trip/tamper/expiry tests plus a constructor
    test that builds and uses an ESTABLISHED connection.
25. **Biggest things still missing?** A cryptographic hash (SipHash), option clawback via timestamps,
    secret rotation, and a SYN_RCVD timeout — all exercises.

## H. Anki starter deck

```text
Q: What attack do SYN cookies defend?  A: SYN flood — half-open backlog exhaustion from spoofed SYNs.
Q: The core trick?  A: encode the handshake in the SYN-ACK's ISN (a cookie); allocate no TCB until the ACK returns.
Q: Cookie layout?  A: [counter:6][mss_idx:2][mac:24] in 32 bits.
Q: Why a counter in the cookie?  A: expiry — reject cookies more than a couple of ticks old.
Q: Why an MSS index?  A: the server forgot the SYN's MSS; the index recovers it (rounded down).
Q: Why a keyed MAC?  A: so a returned cookie is trustworthy without stored state (only the secret mints it).
Q: How does the client return the cookie?  A: ack = cookie + 1 in the final ACK.
Q: Server recovers peer_isn from?  A: the final ACK's seq − 1.
Q: State kept per outstanding cookie?  A: none — just one per-process secret.
Q: What options does a cookie connection lose?  A: timestamps, window scale, SACK (don't fit in 32 bits).
Q: Why round MSS down, not up?  A: overstating the MSS fragments; lower is always safe.
Q: When are cookies used?  A: only when the half-open backlog is full (not always).
Q: A validated cookie builds a connection in which state?  A: ESTABLISHED (the handshake is complete).
Q: Our hash vs production?  A: FNV-style (teaching) vs SipHash (a keyed PRF).
Q: Cost of a spoofed SYN to the server now?  A: one stateless SYN-ACK, zero memory.
```

## I. Glossary

- **SYN flood** — a denial-of-service attack sending many (often spoofed) SYNs to exhaust the
  half-open backlog.
- **Half-open / backlog** — connections in SYN_RCVD awaiting the final ACK; a finite resource.
- **SYN cookie** — a SYN-ACK ISN that encodes the handshake so no TCB is needed until the ACK returns.
- **MAC (in the cookie)** — a keyed hash binding the cookie to the 4-tuple + client ISN, signed by the
  server secret.
- **Counter (in the cookie)** — a coarse time value bounding the cookie's validity window.
- **MSS index** — the 2-bit encoding of the client's MSS into the cookie.
- **Secret** — the per-process key the server uses to mint and verify cookies; never sent.
- **`tcp_syncookies` / `tcp_max_syn_backlog`** — the Linux knobs for cookie mode and backlog size.
- **SipHash** — the keyed PRF a production stack uses for the cookie MAC.

## J. Reference tables

**J.1 — the cookie handshake vs the normal handshake**

```text
   step              normal                          SYN cookie (backlog full)
   ───────────────   ─────────────────────────────   ───────────────────────────────
   on SYN            allocate TCB (SYN_RCVD)         compute cookie, allocate NOTHING
   SYN-ACK ISS       random (RFC 6528)               the cookie
   state held        a full TCB + backlog slot       none (just the secret)
   on final ACK      complete the TCB → ESTABLISHED  validate cookie → build TCB → ESTABLISHED
   options           MSS, TS, wscale, SACK           MSS only
   flood resistance  exhausts the backlog            O(1) memory per SYN
```

**J.2 — the cookie's 32 bits**

```text
   field      bits   value                                            recovered as
   ────────   ────   ──────────────────────────────────────────────   ─────────────────────
   counter    6      (now_ms / 64000) mod 64                           expiry check (±2 ticks)
   mss_idx    2      index of largest table MSS ≤ advertised           COOKIE_MSS_TABLE[idx]
   MAC        24     cookie_mix(secret, 4-tuple, peer_isn, counter)    recomputed + compared
```

**J.3 — the robustness suite, complete**

```text
   threat                         defence                         chapter
   ────────────────────────────   ─────────────────────────────   ───────
   blind RST                      RFC 5961 §3 (challenge ACK)      19
   blind SYN                      RFC 5961 §4 (challenge ACK)      19
   TIME-WAIT assassination        RFC 1337 (ignore RST in TW)      19
   blind data injection           RFC 5961 §5 (ACK acceptability)  23
   challenge-ACK oracle           randomized throttle (CVE-2016-5696) 23
   resource leak (half-closed)    CLOSE_WAIT/FIN_WAIT_2 reaper      23
   dead idle peer                 keepalive                        26
   SYN flood                      SYN cookies                      27
```

> Re-type `syn_cookie`, `check_syn_cookie`, and `from_syn_cookie` with the book closed, then
> `cargo test`. When a flood of spoofed SYNs costs your server nothing — no TCB, no backlog — while a
> real client still completes the handshake by handing back a cookie it never knew it was carrying,
> you've put the connection's state into the sequence number and made the accept path unfloodable.
