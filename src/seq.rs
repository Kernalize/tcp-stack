//! 32-bit sequence-number arithmetic (RFC 9293 §3.4, built on RFC 1982 serial numbers).
//!
//! TCP sequence and acknowledgement numbers are 32-bit and **wrap around** at 2³². So "is A
//! before B?" cannot be a plain `<` — after `0xFFFFFFFF` comes `0`, and a naive comparison
//! would mis-order packets across the wrap. These helpers do *modular* comparison: A is "before"
//! B if the wrapping difference `A − B` lands in the negative half of the circle. They're the
//! basis for validating which seq/ack numbers are acceptable. Theory: `docs/doc3-book.md`.

/// Modular "is `a` strictly before `b`" on the 32-bit sequence circle.
///
/// True when `a − b` (wrapping) is in the upper half (sign bit set), i.e. `a` is behind `b` by
/// less than 2³¹. This is RFC 1982 serial-number comparison.
pub fn before(a: u32, b: u32) -> bool {
    a.wrapping_sub(b) & 0x8000_0000 != 0
}

/// Modular "is `a` strictly after `b`" — just `before` with the arguments swapped.
pub fn after(a: u32, b: u32) -> bool {
    before(b, a)
}

/// True if `x` lies in the half-open window `(start, end]` on the wrapping circle, i.e.
/// `start < x <= end` modulo 2³². This is the shape of TCP's acceptability tests (e.g. an
/// acknowledgement is acceptable when `SND.UNA < ACK <= SND.NXT`).
pub fn between(start: u32, x: u32, end: u32) -> bool {
    after(x, start) && !after(x, end)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_order() {
        assert!(before(1, 2));
        assert!(!before(2, 1));
        assert!(after(2, 1));
        assert!(!before(5, 5)); // equal is neither before nor after
        assert!(!after(5, 5));
    }

    #[test]
    fn handles_wraparound() {
        // Just before the wrap is "before" just after it.
        assert!(before(0xFFFF_FFFF, 0));
        assert!(after(0, 0xFFFF_FFFF));
        assert!(!before(0, 0xFFFF_FFFF));
    }

    #[test]
    fn window_inclusive_of_end_exclusive_of_start() {
        assert!(between(100, 150, 200)); // strictly inside
        assert!(between(100, 200, 200)); // x == end is included
        assert!(!between(100, 100, 200)); // x == start is excluded
        assert!(!between(100, 250, 200)); // past the end
        assert!(!between(100, 50, 200)); // before the start
    }

    #[test]
    fn window_across_the_wrap() {
        // Window (0xFFFFFFFE, 3] wraps past 0; 1 is inside it.
        assert!(between(0xFFFF_FFFE, 1, 3));
        assert!(between(0xFFFF_FFFE, 0xFFFF_FFFF, 3));
        assert!(between(0xFFFF_FFFE, 3, 3));
        assert!(!between(0xFFFF_FFFE, 4, 3)); // just past the end
        assert!(!between(0xFFFF_FFFE, 0xFFFF_FFFE, 3)); // == start excluded
    }
}
