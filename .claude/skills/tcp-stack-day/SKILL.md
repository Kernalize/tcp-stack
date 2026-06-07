---
name: tcp-stack-day
description: "Produce the next day's tcp-stack deliverable in the established format: heavily-commented reference code in the correct module PLUS a detailed docs/dayN-book.md, then build+test in WSL. Use when the user says 'do day N', 'next day', or names the next feature (ICMP echo reply, three-way handshake, etc.)."
trigger: /tcp-day
---

# tcp-stack-day

Build one unit of the 12-week curriculum (`docs/Manual.md` Phases 1–5) to a consistent,
high standard. The day's *concept* comes from `docs/Manual.md`; the *format* is fixed here.

## Steps
1. **Read first.** `docs/Manual.md` (the phase for this day), the previous `docs/dayN-book.md`,
   and the current `src/main.rs` so the new work continues cleanly and contradicts nothing.
2. **Write the code** in the RIGHT place:
   - Early days: in `src/main.rs`. Refactor logic into `src/{ip,icmp,tcp,utils}.rs` only when
     a function has 2+ callers (see day1-book.md §13 "code location").
   - Comments are teaching-grade: every non-obvious line says *what* and *why*, with RFC refs.
3. **Always make it verifiable without sudo/TUN.** Add `#[cfg(test)]` unit tests (known
   packets, rejection paths, and a differential check vs `etherparse` where applicable) so
   `cargo test` proves correctness offline.
4. **Build + test in WSL** (see the `tcp-stack-run` skill) and confirm green before claiming done.
5. **Write `docs/dayN-book.md`** in this structure (the from-scratch teaching format):
   `mental model → the mechanism → the header/protocol field-by-field → relevant Rust
   (ownership/error-handling) → bit math & endianness as needed → verification → the code
   walked end-to-end → a "why this not that" alternatives table → a blank-file rebuild
   checklist + 3–5 exercises → what the next day adds.` Dense, worked numeric examples,
   ASCII diagrams, honest about what production does differently.

## Learning OS constraints (non-negotiable)
- This is a "from scratch" project: the user **hand-types the cores** (parsers, the TCP state
  machine). When the day's core is his to type, the book + comments are the guide and you
  may scaffold/test, but offer him the implementation rather than dumping it — unless he
  explicitly asks you to write it (he sometimes does, for a reference he'll re-type).
- Reuse physically: shared helpers (e.g. the checksum) live in `utils.rs` and are imported,
  not copy-pasted.
- Finish line = "can I teach it?" → after the book, remind him to re-type the code with the
  book closed, and to make Anki cards from his own bugs.

## Hygiene
Quote all shell paths/globs; never unquoted `{...}` with a redirect (creates junk files).
Don't write throwaway files to the repo root; code → `src/`, docs → `docs/`.
