use serde::{Deserialize, Serialize};

/// Hybrid Logical Clock timestamp.
///
/// Ordering: wall_ms first, then logical counter, then node_id (lexicographic).
/// Field declaration order matches comparison priority — derived Ord is correct.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct HlcTimestamp {
    pub wall_ms: u64,
    pub logical: u32,
    pub node_id: [u8; 8],
}

/// Hybrid Logical Clock (Kulkarni & Demirbas 2014).
pub struct HlcClock {
    last: HlcTimestamp,
    node_id: [u8; 8],
}

impl HlcClock {
    pub fn new(node_id: [u8; 8], initial_wall_ms: u64) -> Self {
        Self {
            last: HlcTimestamp {
                wall_ms: initial_wall_ms,
                logical: 0,
                node_id,
            },
            node_id,
        }
    }

    /// Generate a send timestamp: advance to max(last, now), bump logical on ties.
    ///
    /// If the logical counter would overflow u32::MAX (possible only when generating
    /// more than 4 billion events within a single millisecond, or under a mocked
    /// clock), wall_ms is advanced by 1ms and logical resets to 0.  This preserves
    /// strict monotonicity: (wall+1, 0) > (wall, u32::MAX).
    pub fn send(&mut self, now_ms: u64) -> HlcTimestamp {
        let mut new_wall = self.last.wall_ms.max(now_ms);
        let new_logical = if new_wall == self.last.wall_ms {
            match self.last.logical.checked_add(1) {
                Some(l) => l,
                // Logical counter exhausted for this millisecond; advance wall.
                None => {
                    new_wall += 1;
                    0
                }
            }
        } else {
            0
        };
        self.last = HlcTimestamp {
            wall_ms: new_wall,
            logical: new_logical,
            node_id: self.node_id,
        };
        self.last
    }

    /// Receive a remote timestamp: advance to max(local, observed, now) + 1 logical.
    ///
    /// Same overflow handling as `send`: if the logical increment would wrap,
    /// wall_ms is advanced by 1ms and logical resets to 0.
    pub fn receive(&mut self, now_ms: u64, observed: &HlcTimestamp) -> HlcTimestamp {
        let mut new_wall = self.last.wall_ms.max(observed.wall_ms).max(now_ms);
        let new_logical = if new_wall == self.last.wall_ms && new_wall == observed.wall_ms {
            let max_logical = self.last.logical.max(observed.logical);
            match max_logical.checked_add(1) {
                Some(l) => l,
                None => {
                    new_wall += 1;
                    0
                }
            }
        } else if new_wall == self.last.wall_ms {
            match self.last.logical.checked_add(1) {
                Some(l) => l,
                None => {
                    new_wall += 1;
                    0
                }
            }
        } else if new_wall == observed.wall_ms {
            match observed.logical.checked_add(1) {
                Some(l) => l,
                None => {
                    new_wall += 1;
                    0
                }
            }
        } else {
            0
        };
        self.last = HlcTimestamp {
            wall_ms: new_wall,
            logical: new_logical,
            node_id: self.node_id,
        };
        self.last
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NODE_A: [u8; 8] = [0xAA; 8];
    const NODE_B: [u8; 8] = [0xBB; 8];

    #[test]
    fn send_same_wall_increments_logical() {
        let mut clock = HlcClock::new(NODE_A, 1000);
        let t1 = clock.send(1000);
        let t2 = clock.send(1000);
        assert_eq!(t1.wall_ms, 1000);
        assert_eq!(t2.wall_ms, 1000);
        assert!(
            t2.logical > t1.logical,
            "logical must increase on same wall time"
        );
    }

    #[test]
    fn send_advancing_wall_resets_logical() {
        let mut clock = HlcClock::new(NODE_A, 1000);
        let t1 = clock.send(1000);
        assert!(t1.logical > 0);
        let t2 = clock.send(2000);
        assert_eq!(t2.wall_ms, 2000);
        assert_eq!(t2.logical, 0, "logical must reset to 0 when wall advances");
    }

    #[test]
    fn receive_same_wall_takes_max_logical_plus_one() {
        let wall = 5000u64;
        let mut clock = HlcClock::new(NODE_A, wall);
        // Advance local logical to 3.
        clock.send(wall);
        clock.send(wall);
        clock.send(wall);
        let local_logical = clock.last.logical; // should be 3

        let observed = HlcTimestamp {
            wall_ms: wall,
            logical: 10,
            node_id: NODE_B,
        };
        let result = clock.receive(wall, &observed);
        assert_eq!(result.wall_ms, wall);
        assert_eq!(
            result.logical,
            local_logical.max(observed.logical) + 1,
            "receive must take max of both logicals + 1"
        );
    }

    #[test]
    fn receive_message_wall_ahead_uses_message_logical_plus_one() {
        let mut clock = HlcClock::new(NODE_A, 1000);
        clock.send(1000);

        let observed = HlcTimestamp {
            wall_ms: 9000,
            logical: 7,
            node_id: NODE_B,
        };
        let result = clock.receive(1000, &observed);
        assert_eq!(result.wall_ms, 9000, "wall must jump to message wall");
        assert_eq!(result.logical, 8, "logical must be msg.logical + 1");
    }

    #[test]
    fn receive_now_wall_ahead_resets_logical() {
        let mut clock = HlcClock::new(NODE_A, 1000);
        clock.send(1000);

        let observed = HlcTimestamp {
            wall_ms: 1000,
            logical: 5,
            node_id: NODE_B,
        };
        // now_ms is far ahead of both local and observed
        let result = clock.receive(9000, &observed);
        assert_eq!(result.wall_ms, 9000);
        assert_eq!(result.logical, 0, "logical resets when now_ms dominates");
    }

    #[test]
    fn send_logical_overflow_advances_wall() {
        // Seed clock at (wall=1000, logical=u32::MAX).
        let mut clock = HlcClock {
            last: HlcTimestamp {
                wall_ms: 1000,
                logical: u32::MAX,
                node_id: NODE_A,
            },
            node_id: NODE_A,
        };
        let t = clock.send(1000);
        assert_eq!(t.wall_ms, 1001, "wall must advance when logical overflows");
        assert_eq!(t.logical, 0, "logical must reset after wall advance");
        // The new timestamp must be strictly greater than the seed.
        assert!(
            t > HlcTimestamp { wall_ms: 1000, logical: u32::MAX, node_id: NODE_A },
            "post-overflow timestamp must be greater than pre-overflow"
        );
    }

    #[test]
    fn receive_logical_overflow_advances_wall() {
        // Both local and observed at (wall=1000, logical=u32::MAX).
        let mut clock = HlcClock {
            last: HlcTimestamp {
                wall_ms: 1000,
                logical: u32::MAX,
                node_id: NODE_A,
            },
            node_id: NODE_A,
        };
        let observed = HlcTimestamp {
            wall_ms: 1000,
            logical: u32::MAX,
            node_id: NODE_B,
        };
        let t = clock.receive(1000, &observed);
        assert_eq!(t.wall_ms, 1001, "wall must advance when logical overflows in receive");
        assert_eq!(t.logical, 0);
    }

    #[test]
    fn receive_observed_logical_overflow_advances_wall() {
        // Local is behind; observed.logical == u32::MAX, so observed.logical + 1 overflows.
        let mut clock = HlcClock::new(NODE_A, 500);
        let observed = HlcTimestamp {
            wall_ms: 1000,
            logical: u32::MAX,
            node_id: NODE_B,
        };
        let t = clock.receive(500, &observed);
        assert_eq!(t.wall_ms, 1001, "wall must advance when observed.logical overflows");
        assert_eq!(t.logical, 0);
    }

    #[test]
    fn ord_higher_wall_sorts_greater() {
        let low = HlcTimestamp {
            wall_ms: 100,
            logical: 99,
            node_id: NODE_B,
        };
        let high = HlcTimestamp {
            wall_ms: 200,
            logical: 0,
            node_id: NODE_A,
        };
        assert!(
            high > low,
            "higher wall_ms must sort greater regardless of logical"
        );
    }

    #[test]
    fn ord_same_wall_higher_logical_sorts_greater() {
        let low = HlcTimestamp {
            wall_ms: 500,
            logical: 1,
            node_id: NODE_A,
        };
        let high = HlcTimestamp {
            wall_ms: 500,
            logical: 2,
            node_id: NODE_A,
        };
        assert!(high > low, "higher logical must sort greater on same wall");
    }

    #[test]
    fn ord_same_wall_same_logical_node_id_is_tiebreaker() {
        let a = HlcTimestamp {
            wall_ms: 500,
            logical: 1,
            node_id: [0x01; 8],
        };
        let b = HlcTimestamp {
            wall_ms: 500,
            logical: 1,
            node_id: [0x02; 8],
        };
        assert!(b > a, "node_id is the final tiebreaker");
    }
}
