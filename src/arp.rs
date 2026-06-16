//! ARP — Address Resolution Protocol (RFC 826): maps IP addresses → MAC addresses.
//!
//! STATUS: empty, and likely STAYS empty. ARP is a Layer-2 concept. On our **TUN**
//! (Layer 3) path there are no MAC addresses, so there is nothing to resolve — the
//! kernel routes packets to `tun0` by IP and hands them straight to us.
//!
//! WHEN THIS FILE WOULD FILL UP: only on the optional **TAP** (Layer 2) detour, where
//! you'd answer ARP "who has 192.168.0.2?" requests with our fake MAC before any IP
//! traffic could flow. See `docs/doc1-book.md` §2.
