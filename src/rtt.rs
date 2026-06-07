//! RTT estimation and the retransmission timeout (RFC 6298).
//!
//! The stack currently uses a fixed 200 ms RTO. A real one measures the round-trip time of
//! acknowledged data and adapts: `RTO = SRTT + max(G, K·RTTVAR)`, where SRTT is the smoothed RTT
//! and RTTVAR its variation. This makes the timeout track the actual path — short on a LAN, long
//! on a satellite link — so we neither resend too eagerly nor wait too long. All in integer
//! milliseconds so it's deterministic and unit-testable; the event loop will feed it RTT samples
//! (now − the acked segment's send time) and read `rto()`.

const ALPHA_SHIFT: u32 = 3; // SRTT gain  α = 1/8  (RFC 6298)
const BETA_SHIFT: u32 = 2; //  RTTVAR gain β = 1/4
const K: u64 = 4; // RTO = SRTT + K·RTTVAR
const G_MS: u64 = 1; // clock granularity (the floor for K·RTTVAR)
const MIN_RTO_MS: u64 = 200; // RFC 6298 SHOULDs 1000ms; we use 200 for a local TUN link
const MAX_RTO_MS: u64 = 60_000;

/// Smoothed RTT estimator producing an adaptive retransmission timeout.
#[allow(dead_code)] // wired into the connection/event loop next; exercised by tests now
#[derive(Debug, Default)]
pub struct RttEstimator {
    srtt_ms: Option<u64>, // smoothed RTT; None until the first sample
    rttvar_ms: u64,       // RTT variation
}

#[allow(dead_code)]
impl RttEstimator {
    /// Feed one RTT measurement (ms), e.g. now − the acked segment's send time. Don't sample a
    /// retransmitted segment (Karn's algorithm) — the caller skips those.
    pub fn sample(&mut self, rtt_ms: u64) {
        match self.srtt_ms {
            None => {
                // First measurement (RFC 6298 §2.2): SRTT = R, RTTVAR = R/2.
                self.srtt_ms = Some(rtt_ms);
                self.rttvar_ms = rtt_ms / 2;
            }
            Some(srtt) => {
                // Subsequent (§2.3): RTTVAR = (1−β)·RTTVAR + β·|SRTT−R|; SRTT = (1−α)·SRTT + α·R.
                let delta = if srtt > rtt_ms { srtt - rtt_ms } else { rtt_ms - srtt };
                self.rttvar_ms = self.rttvar_ms - (self.rttvar_ms >> BETA_SHIFT) + (delta >> BETA_SHIFT);
                self.srtt_ms = Some(srtt - (srtt >> ALPHA_SHIFT) + (rtt_ms >> ALPHA_SHIFT));
            }
        }
    }

    /// The current retransmission timeout (ms), clamped to a sane range.
    pub fn rto(&self) -> u64 {
        match self.srtt_ms {
            None => MIN_RTO_MS, // no sample yet → conservative default
            Some(srtt) => (srtt + (K * self.rttvar_ms).max(G_MS)).clamp(MIN_RTO_MS, MAX_RTO_MS),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_sample_uses_default_rto() {
        assert_eq!(RttEstimator::default().rto(), MIN_RTO_MS);
    }

    #[test]
    fn first_sample() {
        let mut e = RttEstimator::default();
        e.sample(100); // SRTT=100, RTTVAR=50 → RTO = 100 + 4·50 = 300
        assert_eq!(e.rto(), 300);
    }

    #[test]
    fn converges_on_steady_rtt() {
        let mut e = RttEstimator::default();
        e.sample(100); // SRTT=100, RTTVAR=50
        e.sample(100); // delta=0 → RTTVAR=50−12+0=38; SRTT=100−12+12=100 → RTO=100+4·38=252
        assert_eq!(e.rto(), 252);
    }

    #[test]
    fn clamps_low_rtt_to_minimum() {
        let mut e = RttEstimator::default();
        e.sample(10); // SRTT=10, RTTVAR=5 → RTO = 10 + 20 = 30 → clamped up to MIN_RTO 200
        assert_eq!(e.rto(), 200);
    }

    #[test]
    fn clamps_high_rtt_to_maximum() {
        let mut e = RttEstimator::default();
        e.sample(100_000); // huge → RTO would exceed 60s → clamped to MAX_RTO
        assert_eq!(e.rto(), MAX_RTO_MS);
    }
}
