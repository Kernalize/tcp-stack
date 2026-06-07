//! Ethernet framing (L2) — IEEE 802.3 / DIX.
//!
//! STATUS: empty, and likely STAYS empty on the main path. We use a **TUN** device
//! (Layer 3), so the kernel hands us raw IP packets with NO Ethernet header. MAC
//! addresses and EtherType never appear. See `docs/day1-book.md` §2 (TUN vs TAP).
//!
//! WHEN THIS FILE WOULD FILL UP: only if you take the optional **TAP** (Layer 2)
//! detour — then you'd parse the 14-byte Ethernet header (dest MAC, src MAC,
//! EtherType) here and dispatch 0x0800 → IP, 0x0806 → ARP (`arp.rs`).
