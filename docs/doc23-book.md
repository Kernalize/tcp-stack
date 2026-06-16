# Doc 23 — TCP, Part 21: The Robustness Pack — RFC 5961 §5, Challenge-ACK Throttling, Reaper Timeouts

> Goal: close the last gaps between "correct on the happy path" and "hard to break." Doc 19 hardened
> the connection against blind **RST** and **SYN** attacks (RFC 5961 §§3–4) and TIME-WAIT
> assassination (RFC 1337). Three holes remained, and today we close all three:
>
> 1. **Blind data injection (RFC 5961 §5).** Our ACK acceptance was still RFC 793-grade — an ACK for
>    data we never sent was silently ignored rather than challenged. We tighten it to the §5 window
>    `SND.UNA − MAX.SND.WND ≤ SEG.ACK ≤ SND.NXT` and answer anything outside it with a challenge ACK.
> 2. **Challenge-ACK throttling (CVE-2016-5696).** Emitting an unbounded stream of challenge ACKs is
>    itself a reflection vector, and doing it with a *shared, predictable* counter (early Linux)
>    turned the defence into an off-path **oracle**. We add a *per-connection, randomized* budget.
> 3. **Half-close reaper timeouts.** A peer that vanishes can pin a connection in CLOSE_WAIT (the
>    famous fd leak) or FIN_WAIT_2 forever. We add idle timeouts that reap them.
>
> None of these change the happy path; all three make the stack defensible against a peer that is
> buggy, gone, or hostile. With them, the connection lifecycle is not just *complete* but *robust* —
> the last item on the project's "Limitations → Hardening" list.

**Contents**

Volume I — the chapter
1. The mental model: three ways a peer misbehaves
2. RFC 5961 §5 — the ACK acceptability window
3. `MAX.SND.WND` — why the lower bound exists
4. The challenge ACK as an oracle: CVE-2016-5696
5. The throttle: a per-connection, randomized budget
6. The CLOSE_WAIT leak and the FIN_WAIT_2 hang
7. The reaper: idle timeouts on the lingering states
8. The Rust: wrapping bounds, `rand` in the budget, idempotent timers
9. A worked trace — a blind data-injection probe, defeated
10. The code, walked end to end
11. Verification — the four new tests, and why each exists
12. Why this, not that
13. Honesty: what production does that we don't
14. Rebuild it yourself — checklist + exercises
15. What comes after — the project, complete

Volume II — the exhaustive reference
- A. RFC 5961 in full, §§3–5 together (with Doc 19)
- B. The ACK acceptability window, every case
- C. CVE-2016-5696 in detail — the side channel and the fix
- D. The half-closed states and their real-world timeouts
- E. RFC 1337 recap and the TIME_WAIT family of hazards
- F. Comparison to real stacks — Linux, FreeBSD, the sysctls
- G. The threat model, end to end — what we now resist
- H. Extended FAQ — thirty questions a careful reader asks
- I. Anki starter deck
- J. Glossary
- K. Reference tables

---

# Volume I — the chapter

## 1. The mental model: three ways a peer misbehaves

A connection faces three kinds of trouble beyond ordinary loss and reordering:

```text
   trouble                         today's defence
   ─────────────────────────────   ──────────────────────────────────────────────
   a forged segment (off-path)     RFC 5961 §5: challenge an unacceptable ACK (data injection)
   our own defence used against us  throttle challenge ACKs (CVE-2016-5696 oracle)
   a peer that simply vanishes      reap idle CLOSE_WAIT / FIN_WAIT_2 connections
```

The first is malice (an attacker who guessed the 4-tuple); the second is malice *exploiting* our
first defence; the third is mere absence (a crashed peer, a yanked cable, a buggy app that forgets to
`close()`). All three leave a *correct* stack either acting on a lie, leaking information, or leaking
memory. Robustness is refusing all three. Doc 19 did the RST/SYN half; today does the ACK/data half
plus the resource-leak half.

## 2. RFC 5961 §5 — the ACK acceptability window

Recall the blind-injection threat (Doc 19 §8): an off-path attacker who knows the 4-tuple tries to
land a forged segment in our window. To inject *data*, they need the data's sequence number in our
*receive* window (hard) **and** a plausible *ACK* number. Our ACK check was the loose RFC 793 rule:

```text
   RFC 793:    accept if  SND.UNA < SEG.ACK ≤ SND.NXT
```

and segments failing it were silently dropped — including an ACK *above* `SND.NXT` (acking data we
never sent), which is exactly the fingerprint of a blind probe. RFC 5961 §5 replaces "drop silently"
with "challenge," and widens the *acceptable* range so genuine old duplicates still pass:

```text
   RFC 5961 §5: acceptable if  SND.UNA − MAX.SND.WND ≤ SEG.ACK ≤ SND.NXT
                otherwise → send a challenge ACK, drop the segment
```

Our implementation is one predicate plus one guard at the top of ACK processing:

```rust
fn ack_acceptable(&self, ack: u32) -> bool {
    let low = self.send.una.wrapping_sub(self.max_snd_wnd);
    !seq::before(ack, low) && !seq::after(ack, self.send.nxt)   // low ≤ ack ≤ SND.NXT (mod 2^32)
}
// …in the ACK branch of on_segment:
if !self.ack_acceptable(th.ack) {
    return self.maybe_challenge(now_ms);   // RFC 5961 §5
}
```

The upper bound `≤ SND.NXT` is the teeth: an ACK for unsent data is no longer trusted *or* silently
dropped — it's challenged, so a genuine peer can resynchronise and a forger learns nothing (the
challenge flies to the real host, not the attacker). The lower bound is subtler — §3.

## 3. `MAX.SND.WND` — why the lower bound exists

Why `SND.UNA − MAX.SND.WND` and not just "`≤ SND.NXT`"? Because some perfectly legitimate ACKs are
*below* `SND.UNA`: a delayed duplicate ACK, reordered behind a newer one. We don't want to challenge
those (they're harmless and common). RFC 5961 §5 tolerates ACKs up to one *maximum send window*
below `SND.UNA` — far enough back to cover any in-flight duplicate, not so far that an attacker has
room to maneuver.

`MAX.SND.WND` is the **largest send window the peer has ever advertised** — the widest the
conversation has ever been, hence the furthest back a stale-but-real ACK could legitimately refer.
We track it as we track everything else, right where the window is read each segment:

```rust
let new_wnd = (th.window as u32) << self.snd_wscale;
self.send.wnd = new_wnd;
self.max_snd_wnd = self.max_snd_wnd.max(new_wnd);   // Doc 23
```

Two subtleties:

- It's the **max**, not the current window. A momentary zero window (`new_wnd == 0`) doesn't shrink
  the acceptability range — the lower bound stays anchored to the widest the window ever was, so a
  duplicate ACK from when the window was open still passes.
- The subtraction **wraps**. With `SND.UNA = 1` and `MAX.SND.WND = 65535`, `low = 1 − 65535` wraps
  to `≈0xFFFF0002` — a huge number near the top of the sequence space. That's correct: the modular
  `seq::before` then treats the acceptable range as the arc from just-below-`UNA`, around through the
  wrap, up to `SND.NXT`. Plain `u32` subtraction would underflow-panic in debug or give nonsense;
  `wrapping_sub` + `seq::before` is the only correct way to express a window on a circle.

## 4. The challenge ACK as an oracle: CVE-2016-5696

The challenge ACK (Doc 19 §10) is a beautiful defence — it makes a forger prove liveness it can't.
But a defence that emits an *observable, deterministic* signal can become an *oracle*, and that's
exactly what happened.

RFC 5961 §3 notes that challenge ACKs should be rate-limited (an attacker could otherwise reflect a
flood through you). Linux implemented the limit with a **single global counter** —
`sysctl_tcp_challenge_ack_limit`, default 100/second, shared across *all* connections. In 2016,
researchers (CVE-2016-5696, "Off-Path TCP Exploits: Global Rate Limit Considered Dangerous") showed
the shared counter leaks cross-connection information:

```text
   1. The attacker opens its OWN connection to the target and deliberately burns the global
      challenge-ACK budget for this second (e.g. by sending segments that elicit challenge ACKs).
   2. The attacker then sends a forged segment to a DIFFERENT, targeted connection (guessing its
      4-tuple) that WOULD elicit a challenge ACK if that connection exists.
   3. The attacker checks its own connection: did a challenge ACK still come back this second?
        • no  → the global budget was spent on the targeted connection → that connection EXISTS,
                and the forged segment fell in its window (leaking sequence-number information).
        • yes → the budget wasn't touched there.
   4. Repeat, one bit of inference at a time, to learn the targeted connection's sequence numbers —
      enough to then inject a real RST or data, blind.
```

A *shared, deterministic* signal became a side channel that *undid* the very blind-attack protection
RFC 5961 was meant to provide. The lesson is general and worth burning in: **a security mechanism
that emits a measurable, predictable signal can be turned into an oracle.**

## 5. The throttle: a per-connection, randomized budget

The fix has two parts, both essential:

- **Per-connection**, not global — so burning one connection's budget tells you nothing about
  another's.
- **Randomized** — so the count itself can't be inferred by an observer counting challenge ACKs.

Our `maybe_challenge` replaces every direct `challenge_ack()`:

```rust
fn maybe_challenge(&mut self, now_ms: u64) -> Option<Vec<u8>> {
    const WINDOW_MS: u64 = 1000;
    if now_ms.wrapping_sub(self.challenge_window_ms) >= WINDOW_MS {
        self.challenge_window_ms = now_ms;
        self.challenge_budget = 1 + rand::random::<u32>() % CHALLENGE_ACK_MAX;  // randomized refill
    }
    if self.challenge_budget == 0 {
        return None;                  // throttled — drop silently this window
    }
    self.challenge_budget -= 1;
    Some(self.challenge_ack())
}
```

Each connection gets its own budget, refilled to a fresh random `1..=CHALLENGE_ACK_MAX` value each
second. The first challenge in a window always goes out (the budget is at least 1); beyond the
randomized ceiling, challenges are suppressed until the next refill. Every challenge-ACK site — the
in-window RST (Doc 19 §9), the in-window SYN (§11), and today's §5 ACK check — now routes through
`maybe_challenge`, so the throttle covers all of them uniformly.

The non-determinism is the point: an off-path observer can't predict when the budget runs out, so the
"was a challenge sent?" bit no longer carries reliable information.

## 6. The CLOSE_WAIT leak and the FIN_WAIT_2 hang

The third trouble is absence, not malice. Two states wait on something that might never come:

- **CLOSE_WAIT** waits for the **local application** to call `close()` (Doc 19 §3). If the app forgets
  — a missing cleanup, an exception that skips it — the connection sits in CLOSE_WAIT *forever*,
  holding a TCB and (in a real OS) a file descriptor. This is the single most common networking
  resource leak; every backend engineer eventually learns to read `ss -tan | grep CLOSE-WAIT` as
  "find the bug."
- **FIN_WAIT_2** waits for the **peer's FIN** after our FIN was ACKed. If the peer crashes between
  ACKing our FIN and sending its own, we wait indefinitely. (This is why Linux has `tcp_fin_timeout`,
  default 60s.)

A correct-but-naive stack leaks in both cases. The fix is a bounded wait.

## 7. The reaper: idle timeouts on the lingering states

We already had a timer loop — `on_tick` reaps TIME_WAIT after 2·MSL (Doc 7). The reaper extends it to
the two lingering states, keyed off the **last time a segment arrived**:

```rust
self.last_active_ms = now_ms;   // set at the top of on_segment, every segment

// …in on_tick:
const FIN_WAIT2_TIMEOUT_MS: u64 = 60_000;
const CLOSE_WAIT_TIMEOUT_MS: u64 = 120_000;
let idle = now_ms.saturating_sub(self.last_active_ms);
if (self.state == State::FinWait2 && idle >= FIN_WAIT2_TIMEOUT_MS)
    || (self.state == State::CloseWait && idle >= CLOSE_WAIT_TIMEOUT_MS)
{
    self.state = State::Closed;
}
```

Keying off `last_active_ms` (not the time we *entered* the state) is deliberate: an **active
half-close still exchanging data** — a client in FIN_WAIT_2 reading a long response (Doc 22) — keeps
receiving segments, each resetting `last_active_ms`, so it is *never* reaped while productive. Only a
*genuinely idle* half-closed connection is collected. `main` already deletes any connection that
reaches `Closed`, so the reaper plugs straight into the existing reaping path.

## 8. The Rust: wrapping bounds, `rand` in the budget, idempotent timers

**Wrapping arithmetic for a windowed bound.** `self.send.una.wrapping_sub(self.max_snd_wnd)` is the
only correct way to compute "one max-window below UNA" on a 32-bit circle — and it must be paired with
`seq::before`/`seq::after`, never `<`/`>`, so the comparison respects the wrap (§3). This is the same
discipline as every sequence comparison since Doc 3, applied to a *range bound* rather than a point.

**`rand` for the budget, but determinism where it matters.** The budget refill uses
`rand::random::<u32>()` (the same OS RNG as the ISN, Doc 3) so the count is unpredictable. But the
*expression* `1 + rand % MAX` guarantees the budget is always `≥ 1`, so the *first* challenge in any
window is deterministic — which is what the tests rely on (a single challenge always succeeds), while
the *cap* (`≤ MAX`) is what the throttle test checks. Randomness for security, a guaranteed floor for
testability.

**Idempotent, side-effect-only timers.** `on_tick` is called every loop iteration with the current
time; the reaper (like the TIME_WAIT expiry) just *reads* `now_ms − last_active_ms` and flips state
when the threshold is crossed. It holds no timer object, schedules nothing, and is safe to call
arbitrarily often — the same "pass time in, compute from it" style that has kept every timer in this
project (RTO, persist, TIME_WAIT) unit-testable without sleeping.

## 9. A worked trace — a blind data-injection probe, defeated

Connection ESTABLISHED, `SND.UNA = 1`, `SND.NXT = 1` (nothing in flight), `RCV.NXT = 101`,
`MAX.SND.WND = 65535`. An off-path attacker, having guessed the 4-tuple, sends a forged segment
trying to inject data — with an ACK number meant to look plausible:

```text
   forged: seq=101 (in our recv window), ack=5000 (a guess), data="evil"
   ──────────────────────────────────────────────────────────────────────────────────────
   ack_acceptable(5000)?  low = 1 − 65535 = 0xFFFF0002
                          5000 ≤ SND.NXT(1)?  → after(5000, 1) is true → NOT ≤ → UNacceptable
   → maybe_challenge: budget ≥ 1 → CHALLENGE ACK (seq=SND.NXT=1, ack=RCV.NXT=101); DROP the segment
   → the data "evil" is NEVER delivered; SND.UNA/SND.NXT untouched; state ESTABLISHED
   ──────────────────────────────────────────────────────────────────────────────────────
   the challenge ACK flies to the REAL host at the spoofed source — the attacker (off-path) can't see
   it, learns nothing, and (with the throttle) can't even reliably count whether one was sent.
```

Even though the attacker guessed a sequence number *inside* our receive window (the hard part), the
forged ACK gives the game away, and the §5 check turns a potential data injection into a harmless
challenge. Compare the pre-Doc-23 behaviour: the segment's ACK was simply not "between UNA and NXT,"
so the ACK branch did nothing and processing fell through to *data handling* — which, for an in-window
seq, would have **delivered "evil" to the application.** That's the hole we closed.

## 10. The code, walked end to end

All in `src/tcp.rs`.

**New state** on the TCB: `max_snd_wnd` (§5 window), `challenge_budget` + `challenge_window_ms`
(throttle), `last_active_ms` (reaper). Initialised in both constructors (`accept`/`connect`).

**`ack_acceptable`** (§2) — the RFC 5961 §5 predicate.

**`maybe_challenge`** (§5) — the throttled challenge ACK; now the *only* way challenge ACKs are
emitted. The old `challenge_ack` (the raw builder) is called only from inside it.

**Three call-site changes** route every challenge through the throttle: `on_rst` (in-window RST,
Doc 19) now takes `now_ms` and calls `maybe_challenge`; the in-window SYN check calls
`maybe_challenge`; and the new §5 guard at the top of the ACK branch calls it.

**`MAX.SND.WND` tracking** — one line where the send window is read each segment.

**`last_active_ms`** — set at the top of `on_segment`; read by the reaper in `on_tick` alongside the
existing TIME_WAIT expiry.

That's the whole pack: ~40 lines of logic, each on a path a hostile or absent peer exercises.

## 11. Verification — the four new tests, and why each exists

`cargo test` — **129 passing** (125 + 4).

- **`ack_for_unsent_data_gets_challenge_ack`** — an ACK above `SND.NXT` yields a challenge ACK
  (`seq=SND.NXT, ack=RCV.NXT`) and leaves the connection ESTABLISHED. This is the §5 defence and the
  §9 trace, made executable — and the test that would *deliver* injected data without the fix.
- **`challenge_acks_are_rate_limited`** — fifty in-window RSTs at the same instant produce *at least
  one* challenge ACK but *no more than `CHALLENGE_ACK_MAX`*, and never reset the connection. Pins both
  the throttle cap and that the budget refills only with time (CVE-2016-5696 hardening).
- **`fin_wait2_reaped_after_idle_timeout`** — drive to FIN_WAIT_2, then `on_tick` just before the
  timeout (still waiting) and just after (→ CLOSED). The `tcp_fin_timeout` analogue.
- **`close_wait_reaped_after_idle_timeout`** — drive to CLOSE_WAIT, then `on_tick` past the reaper
  threshold → CLOSED. Bounds the classic fd leak.

Every existing test still passes: the §5 check accepts all legitimate ACKs (new-data, duplicate,
window-update, zero-window, handshake), the throttle always allows the first challenge, and the
reaper only fires in two specific idle states.

## 12. Why this, not that

**Why challenge an out-of-window ACK instead of dropping it (the old behaviour)?** Because a silent
drop both fails to help a genuine peer resynchronise *and* — for an in-window seq — let processing
fall through to deliver injected data. The challenge both defends and recovers. (§9.)

**Why `SND.UNA − MAX.SND.WND` for the lower bound, not just `≤ SND.NXT`?** To tolerate legitimately
old duplicate ACKs (reordered behind newer ones) without challenging them, while still bounding how
far back an attacker can aim. (§3.)

**Why the *max* window, not the current one?** A transient zero window mustn't shrink the
acceptability range and start challenging valid old ACKs. The widest the window ever was is the
furthest back a real ACK could refer. (§3.)

**Why per-connection *and* randomized throttling?** Per-connection removes the cross-connection
channel; randomization removes the count signal. Either alone leaves an oracle (CVE-2016-5696 was a
shared *and* deterministic counter). (§§4–5.)

**Why key the reaper off `last_active_ms` rather than state-entry time?** So an active half-close
still doing useful work (a client reading a long response in FIN_WAIT_2) is never reaped — only a
genuinely idle connection is. (§7.)

**Why a 60s / 120s split?** Mirrors real practice: FIN_WAIT_2 waits on the *peer* (Linux's 60s
`tcp_fin_timeout`); CLOSE_WAIT waits on the *local app*, which deserves a bit more grace, but still
bounded against a forgotten `close()`. (§D.)

## 13. Honesty: what production does that we don't

- **§5 only in the synchronized data path.** We apply the ACK-acceptability check in the
  ESTABLISHED/CLOSE_WAIT block (where data transfer lives); the minimal ACK handling in the FIN_WAIT
  / CLOSING / LAST_ACK states still uses exact-match checks. Sufficient for the injection threat
  (which targets ESTABLISHED), but a fully uniform §5 would apply everywhere.
- **The throttle is time-bucketed, not token-bucketed.** A fixed ~1s window with a randomized cap, not
  a smooth token-bucket rate; good enough to break the oracle, coarser than Linux's current scheme.
- **No SYN-cookie / accept-queue defence.** We still create a TCB per SYN with no backlog limit, so a
  SYN flood can exhaust memory (a Phase-5 hardening item; the Manual notes a `syn_received_timeout`
  and SYN cookies).
- **No keepalive.** A real stack offers `SO_KEEPALIVE` to probe an idle but *not* half-closed
  ESTABLISHED connection; our reaper only covers the two half-closed states, and an idle ESTABLISHED
  connection lives forever (as it does by default on real systems too, until keepalive).
- **No PAWS on the §5 lower bound interplay**, no ECN, no RACK-TLP. As noted on prior days — these are
  the next layers, not gaps in what we built.
- **The echo/HTTP server in `main`** drives CLOSE_WAIT promptly (it closes when its buffer drains), so
  the CLOSE_WAIT reaper rarely fires live; it's the safety net for a *misbehaving* app, exercised by
  the unit test.

## 14. Rebuild it yourself — checklist + exercises

**Checklist**

- [ ] Add `max_snd_wnd`, `challenge_budget`, `challenge_window_ms`, `last_active_ms` to the TCB; init
      in both constructors (`max_snd_wnd = initial wnd`, `challenge_budget = 1 + rand % MAX`,
      `challenge_window_ms = last_active_ms = now_ms`).
- [ ] `ack_acceptable(ack)`: `SND.UNA − MAX.SND.WND ≤ ack ≤ SND.NXT` via `wrapping_sub` + `seq::`.
- [ ] `maybe_challenge(now_ms)`: randomized per-window budget; route the RST, SYN, and §5 challenges
      through it.
- [ ] §5 guard at the top of the ACK branch: unacceptable → `maybe_challenge`, return.
- [ ] Track `max_snd_wnd` where the send window is read; set `last_active_ms` atop `on_segment`.
- [ ] Reaper in `on_tick`: FIN_WAIT_2 (60s) / CLOSE_WAIT (120s) idle → CLOSED.
- [ ] `cargo test` green (129), `cargo clippy -- -D warnings` clean.

**Exercises**

1. **E1 — uniform §5.** Apply `ack_acceptable` in the FIN_WAIT/CLOSING/LAST_ACK ACK handling too, and
   test that an out-of-window ACK in FIN_WAIT_2 is challenged.
2. **E2 — SYN cookies.** Defend SYN_RCVD against a flood: encode the connection state in the ISN
   (a SYN cookie) so you needn't allocate a TCB until the final ACK proves the client. Add a
   `syn_received_timeout` reaper.
3. **E3 — keepalive.** Add `SO_KEEPALIVE`: after an idle ESTABLISHED interval, send a keepalive probe
   (a segment with `seq = SND.NXT − 1`); drop the connection after N unanswered probes.
4. **E4 — token-bucket throttle.** Replace the fixed-window challenge budget with a token bucket
   (rate + burst) and show it smooths the cap while still breaking the oracle.
5. **E5 — measure the oracle.** Write a test simulating the CVE-2016-5696 probe against a *shared*
   counter (a deliberately-wrong implementation) and show the per-connection randomized budget defeats
   it.

Make Anki cards from the §5 window inequality and the "shared+deterministic = oracle" lesson — those
are the two ideas that *are* Doc 23.

## 15. What comes after — the project, complete

With today's pack, the README's "Limitations → Hardening" list is closed: NewReno (Doc 20), RFC 6675
SACK recovery (Doc 21), the socket API + keep-alive HTTP (Doc 22), and now RFC 5961 §5 + challenge
throttling + reaper timeouts (Doc 23). The stack is a **correct, tested, and defensible** TCP/IP
endpoint: handshake, reliable in-order transfer, adaptive RTO, flow control, reassembly, congestion
control with modern loss recovery, window scaling, timestamps/PAWS, SACK, the full close lifecycle
with both half-closes, RFC 5961/1337 robustness, a socket façade, and an HTTP/1.1 server — all proven
offline by 129 unit tests, clippy-clean.

What genuinely remains is the work that *needs a network*: live conformance testing with
`packetdrill` against the kernel, throughput under `iperf3` + `tc netem`, and profiling — plus the
named exercises (CUBIC, RACK-TLP, SYN cookies, keepalive, multi-connection façade). Those are
*validation and breadth*, not missing core. The core is done.

---

# Volume II — the exhaustive reference

## A. RFC 5961 in full, §§3–5 together (with Doc 19)

RFC 5961 ("Improving TCP's Robustness to Blind In-Window Attacks") has three defences. Docs 19 and 23
together implement all three:

```text
   section   attack                 defence                                    day
   ───────   ────────────────────   ────────────────────────────────────────   ────
   §3        blind RST              exact RCV.NXT → reset; in-window → challenge  19
   §4        blind SYN             any SYN in sync state → challenge, no reset   19
   §5        blind data injection  ACK ∉ [UNA−MAX.SND.WND, NXT] → challenge      23
   (§throttle) reflection/oracle   rate-limit challenge ACKs (per-conn, random)  23
   (RFC 1337) TIME-WAIT assassin   ignore RST in TIME_WAIT                       19
```

The unifying principle across all of them: **raise the bar from "in window" to "exact / acceptable"
for any state-changing action, and use a (throttled) challenge ACK to let a genuine peer re-prove
itself.**

## B. The ACK acceptability window, every case

`MAX = MAX.SND.WND`, the largest send window seen. Acceptable iff `UNA − MAX ≤ ACK ≤ SND.NXT`.

```text
   incoming ACK relative to our state          acceptable?   action
   ─────────────────────────────────────────   ───────────   ────────────────────────────
   UNA < ACK ≤ SND.NXT  (acks new data)         yes           advance UNA, RTT, cwnd
   ACK == UNA           (duplicate ACK)         yes           dup-ACK logic (fast retransmit)
   UNA−MAX ≤ ACK < UNA  (old duplicate)         yes           ignored (already acked) — no challenge
   ACK > SND.NXT        (acks unsent data)      NO            challenge ACK, drop  ← the §5 teeth
   ACK < UNA−MAX        (ancient / forged)      NO            challenge ACK, drop
```

The middle row is why the lower bound exists: a delayed duplicate ACK from when the window was open is
*acceptable* (we just ignore it), not challenged. The last two rows are the defence — and crucially,
before Doc 23 an `ACK > SND.NXT` with an in-window *seq* fell through to data delivery.

## C. CVE-2016-5696 in detail — the side channel and the fix

The vulnerability (Cao, Qian, et al., USENIX Security 2016):

```text
   precondition: Linux ≥3.6 used a GLOBAL challenge-ACK counter, default 100/sec, shared by all conns.

   the probe (to learn whether conn X exists and infer its seq numbers):
     a. attacker opens a connection A to the server it controls.
     b. attacker sends, to A, segments that elicit challenge ACKs until the global 100/sec is nearly spent.
     c. attacker sends a forged in-window probe to the TARGET connection X (guessed 4-tuple). If X
        exists and the probe is in-window, the server emits a challenge ACK — spending global budget.
     d. attacker, on A, checks: are there still challenge ACKs left this second?
          fewer than expected → budget was spent elsewhere → X exists and probe was in-window.
     e. binary-search the sequence space, one second (one bit) at a time, to pin X's window — then
        inject a blind RST (kill X) or blind data.

   the fix (Linux 4.7+):
     • make the limit PER-SOCKET, not global (no cross-connection signal), AND
     • RANDOMIZE it (commit "tcp: make challenge acks less predictable") so the count can't be read.
```

Our `maybe_challenge` is both per-connection and randomized — the same fix, at teaching scale. The
deep lesson: rate-limiting is necessary (anti-reflection) but a *shared, predictable* limit is a
covert channel. Defences must not themselves be measurable oracles.

## D. The half-closed states and their real-world timeouts

```text
   state         waits on            our timeout   real-world analogue
   ───────────   ─────────────────   ───────────   ───────────────────────────────────────────
   FIN_WAIT_2    the peer's FIN       60 s          Linux net.ipv4.tcp_fin_timeout (default 60 s)
   CLOSE_WAIT    the local app's      120 s         no kernel timeout — relies on the app +
                 close()                              SO_KEEPALIVE; a leak if the app forgets
   TIME_WAIT     2·MSL to elapse      240 s (Doc 7) fixed 2·MSL (Linux ~60 s, MSL tuned down)
```

CLOSE_WAIT is special: the kernel genuinely *can't* time it out safely in general (the app might
legitimately be slow to close), so real systems lean on the application and on keepalive rather than a
hard kernel timeout. Our 120s reaper is a pragmatic safety net for a teaching stack whose "app" should
always close promptly — it bounds a *bug*, not normal operation.

## E. RFC 1337 recap and the TIME_WAIT family of hazards

From Doc 19, for completeness alongside the rest of the robustness pack:

- **RFC 1337 — TIME-WAIT assassination.** A stray RST in TIME_WAIT could end it early, freeing the
  4-tuple before delayed duplicates of the old connection have died — corrupting a new incarnation.
  Fix: **ignore RSTs in TIME_WAIT** (Doc 19's `on_rst`).
- **TIME-WAIT exhaustion** (related, not implemented): a busy client that actively closes many
  short-lived connections accumulates TIME_WAIT entries; real stacks mitigate with `tcp_tw_reuse` /
  port-range tuning. We just let them expire at 2·MSL.

## F. Comparison to real stacks — Linux, FreeBSD, the sysctls

```text
   defence                  Linux                          FreeBSD            ours (Doc 23)
   ──────────────────────   ────────────────────────────   ────────────────   ─────────────────
   RFC 5961 §5 ACK window   yes                            yes                yes (ESTABLISHED path)
   challenge-ACK limit      per-socket, randomized (4.7+)  rate-limited       per-conn, randomized
   FIN_WAIT_2 timeout       tcp_fin_timeout (60 s)         net.inet.tcp...    60 s
   CLOSE_WAIT timeout       app + keepalive                app + keepalive    120 s reaper (safety net)
   SYN flood               SYN cookies                    SYN cache/cookies  none (E2)
   keepalive               SO_KEEPALIVE                   SO_KEEPALIVE       none (E3)
```

The relevant sysctls, for orientation: `net.ipv4.tcp_challenge_ack_limit` (the CVE-2016-5696 knob,
now per-socket+randomized internally), `net.ipv4.tcp_fin_timeout`, `net.ipv4.tcp_max_syn_backlog` +
`tcp_syncookies`, `net.ipv4.tcp_keepalive_time`. Our column is "the §5/throttle/reaper core, real and
tested; SYN cookies and keepalive as exercises."

## G. The threat model, end to end — what we now resist

Putting Docs 19 and 23 together, against an **off-path** attacker who knows (or guesses) the 4-tuple:

```text
   attacker goal           pre-19            after 19          after 23
   ─────────────────────   ───────────────   ───────────────   ──────────────────────────────
   reset via RST           in-window kills   exact-only        exact-only (challenges throttled)
   reset via SYN           in-window kills   challenge, safe   challenge, safe + throttled
   inject data             possible          (RST/SYN only)    challenged (§5) — primary fix
   TIME-WAIT assassinate   possible          ignored (1337)    ignored
   oracle via challenges   n/a               possible (!)      defeated (per-conn randomized)
   pin a vanished peer     forever           forever           reaped (60 s / 120 s)
```

What we still *don't* resist: an **on-path** attacker (that's TLS's job, not TCP's), SYN floods
(E2), and idle-ESTABLISHED resource use (keepalive, E3). For a blind off-path adversary — the threat
RFC 5961 targets — the connection is now hard to perturb.

## H. Extended FAQ — thirty questions a careful reader asks

1. **What is RFC 5961 §5?** The blind-data-injection defence: tighten ACK acceptability and challenge
   anything outside the window.
2. **The acceptable ACK range?** `SND.UNA − MAX.SND.WND ≤ SEG.ACK ≤ SND.NXT`.
3. **What's the upper bound for?** Rejecting an ACK for data we never sent (`> SND.NXT`) — the probe
   fingerprint.
4. **What's the lower bound for?** Tolerating genuinely old duplicate ACKs without challenging them.
5. **Why `MAX.SND.WND`, not the current window?** A transient zero window mustn't shrink the range and
   start challenging valid old ACKs.
6. **How is `MAX.SND.WND` tracked?** `max_snd_wnd = max(max_snd_wnd, new_wnd)` where the send window is
   read each segment.
7. **Why does the subtraction wrap?** It's a bound on a 32-bit circle; `wrapping_sub` + `seq::before`
   is the only correct expression.
8. **What happens to an unacceptable ACK now?** A (throttled) challenge ACK, and the segment is
   dropped — not delivered.
9. **What happened before Doc 23?** An out-of-window ACK was silently ignored, and for an in-window
   seq, processing fell through to *deliver* the data.
10. **What is a challenge ACK again?** A bare ACK of our state (`seq=SND.NXT, ack=RCV.NXT`) that only a
    genuine on-path peer can usefully answer.
11. **Why throttle challenge ACKs?** Unbounded, they're a reflection vector; and a *measurable* count
    can be an oracle.
12. **What was CVE-2016-5696?** A global, deterministic challenge-ACK counter that leaked
    cross-connection existence/sequence info to an off-path attacker.
13. **How does our throttle fix it?** Per-connection (no cross-channel) and randomized (no count
    signal) budget, refilled each ~second.
14. **Why is the budget `1 + rand % MAX`?** So it's randomized (`security`) but always `≥ 1` (the
    first challenge always works — testability).
15. **Which sites route through the throttle?** All three: in-window RST (Doc 19), in-window SYN
    (Doc 19), and the §5 ACK check (Doc 23).
16. **Does the throttle ever drop a legitimate challenge?** Only under a flood within one window — and
    then a genuine peer simply retransmits and is challenged next window.
17. **What's the CLOSE_WAIT leak?** The app never calls `close()`, so the connection (and fd) sits in
    CLOSE_WAIT forever.
18. **What's the FIN_WAIT_2 hang?** The peer crashed after ACKing our FIN, never sending its own.
19. **How does the reaper fix both?** Idle timeouts (60s FIN_WAIT_2, 120s CLOSE_WAIT) → CLOSED.
20. **Why key off `last_active_ms`, not entry time?** So an active half-close still receiving data
    isn't reaped while productive.
21. **What updates `last_active_ms`?** The top of `on_segment` — every arriving segment.
22. **Where does the reaper run?** `on_tick`, beside the TIME_WAIT expiry; `main` then deletes any
    `Closed` connection.
23. **Why 60 vs 120 seconds?** FIN_WAIT_2 waits on the peer (Linux's 60s); CLOSE_WAIT waits on the
    local app, given a bit more grace but still bounded.
24. **Does §5 break duplicate-ACK fast retransmit?** No — `ACK == SND.UNA` is acceptable (within the
    range), so dup-ACK logic runs as before.
25. **Does §5 break the handshake?** No — the final ACK (`ack == SND.NXT`) is acceptable.
26. **Is §5 applied in every state?** We apply it in ESTABLISHED/CLOSE_WAIT (the data path); E1
    extends it to the FIN_WAIT states.
27. **Could an on-path attacker still inject?** Yes — on-path attackers see the sequence numbers; TCP
    can't stop them. That's TLS's job.
28. **Do we defend SYN floods now?** No — that's SYN cookies (E2), separate from this pack.
29. **How are all four features tested offline?** Construct headers + drive `on_segment`/`on_tick`
    with a logical clock; assert challenge ACKs, the throttle cap, and reaper transitions.
30. **Is the project "done" after today?** The core/hardening is complete and tested; what remains is
    live conformance/load testing and breadth exercises (CUBIC, RACK, SYN cookies, keepalive).

## I. Anki starter deck

```text
Q: RFC 5961 §5 defends against?  A: blind data injection — via tighter ACK acceptability + challenge.
Q: The §5 acceptable ACK range?  A: SND.UNA − MAX.SND.WND ≤ SEG.ACK ≤ SND.NXT.
Q: §5 upper bound rejects?  A: an ACK for data we never sent (> SND.NXT) — the probe fingerprint.
Q: §5 lower bound tolerates?  A: genuinely old duplicate ACKs (no challenge).
Q: Why MAX.SND.WND not current window?  A: a zero window mustn't shrink the range and challenge valid ACKs.
Q: Unacceptable ACK → ?  A: a (throttled) challenge ACK; drop the segment.
Q: CVE-2016-5696 was?  A: a global, deterministic challenge-ACK counter usable as an off-path oracle.
Q: The two-part fix?  A: per-connection (no cross-channel) AND randomized (no count signal) budget.
Q: Why budget = 1 + rand%MAX?  A: randomized for security, ≥1 so the first challenge always works.
Q: CLOSE_WAIT leak?  A: app never calls close() → connection/fd pinned forever.
Q: FIN_WAIT_2 hang?  A: peer crashed after ACKing our FIN, never sent its own.
Q: Reaper timeouts?  A: FIN_WAIT_2 60s, CLOSE_WAIT 120s, keyed off last segment time.
Q: Why key the reaper off last_active?  A: an active half-close still receiving isn't reaped.
Q: General security lesson of the day?  A: a measurable, predictable defence signal can be an oracle.
Q: What TCP can't defend (it's TLS's job)?  A: on-path attackers who can read the traffic.
```

## J. Glossary

- **Blind data injection** — an off-path attacker inserting data into a connection by guessing the
  4-tuple and an in-window sequence/ACK.
- **ACK acceptability (RFC 5961 §5)** — `SND.UNA − MAX.SND.WND ≤ ACK ≤ SND.NXT`; outside → challenge.
- **`MAX.SND.WND`** — the largest send window the peer has advertised; the §5 lower-bound anchor.
- **Challenge ACK** — a bare ACK of current state, sent to make a suspicious sender re-prove liveness.
- **ACK throttling** — rate-limiting challenge ACKs (anti-reflection); must be per-connection +
  randomized to avoid being an oracle.
- **Oracle (side channel)** — an observable signal that leaks otherwise-hidden state (CVE-2016-5696).
- **Reaper** — the `on_tick` logic that reaps idle connections in lingering states.
- **CLOSE_WAIT leak** — connections pinned in CLOSE_WAIT because the app never closed (an fd leak).
- **`tcp_fin_timeout`** — the kernel knob bounding FIN_WAIT_2 (Linux default 60s).
- **TIME-WAIT assassination (RFC 1337)** — a stray RST ending TIME_WAIT early; we ignore RSTs there.

## K. Reference tables

**K.1 — challenge-ACK sites, all throttled (Doc 23)**

```text
   trigger                              rule                   throttled?   reset connection?
   ──────────────────────────────────  ─────────────────────  ──────────   ─────────────────
   in-window inexact RST (Doc 19 §3)    RFC 5961 §3            yes          no
   in-window SYN (Doc 19 §4)            RFC 5961 §4            yes          no
   unacceptable ACK (Doc 23 §5)         RFC 5961 §5            yes          no
   exact-RCV.NXT RST                    RFC 5961 §3            n/a          YES (honored)
```

**K.2 — reaper timeouts**

```text
   state         timeout   waits on            keyed off
   ───────────   ───────   ─────────────────   ─────────────
   FIN_WAIT_2    60 s      the peer's FIN       last_active_ms
   CLOSE_WAIT    120 s     local app close()    last_active_ms
   TIME_WAIT     2·MSL     2·MSL elapsing       time_wait_ms (Doc 7)
```

**K.3 — the robustness pack, by file/function**

```text
   feature                     where                                   tested by
   ─────────────────────────   ─────────────────────────────────────   ──────────────────────────────
   §5 ACK acceptability        ack_acceptable + ACK-branch guard       ack_for_unsent_data_gets_challenge_ack
   MAX.SND.WND tracking        the send-window read in on_segment       (via the above)
   challenge-ACK throttle      maybe_challenge (+ all challenge sites)  challenge_acks_are_rate_limited
   FIN_WAIT_2 reaper           on_tick + last_active_ms                 fin_wait2_reaped_after_idle_timeout
   CLOSE_WAIT reaper           on_tick + last_active_ms                 close_wait_reaped_after_idle_timeout
```

> Re-type `ack_acceptable`, `maybe_challenge`, and the `on_tick` reaper with the book closed, then
> `cargo test`. When your stack shrugs off a forged in-window data segment with a single (throttled)
> challenge ACK, and quietly collects a connection whose peer has vanished — without ever bothering a
> healthy one — you've made it not just correct but *robust*, and the core of the project is complete.
