//! Circuit breaker — pure state machine for embedding provider failure protection.
//!
//! States: closed (normal), open (tripped), half_open (cooldown expired, probe).
//! No I/O, no allocator, no external dependencies.

const std = @import("std");

pub const State = enum { closed, open, half_open };

pub const CircuitBreaker = struct {
    state: State,
    failure_count: u32,
    threshold: u32,
    cooldown_ns: u64,
    last_failure_ns: i128,

    pub fn init(threshold: u32, cooldown_ms: u32) CircuitBreaker {
        return .{
            .state = .closed,
            .failure_count = 0,
            .threshold = threshold,
            .cooldown_ns = @as(u64, cooldown_ms) * 1_000_000,
            .last_failure_ns = 0,
        };
    }

    /// Can we attempt an operation? Returns true if closed or half_open (cooldown expired).
    pub fn allow(self: *CircuitBreaker) bool {
        switch (self.state) {
            .closed => return true,
            .open => {
                const now = std.time.nanoTimestamp();
                if (now - self.last_failure_ns >= self.cooldown_ns) {
                    self.state = .half_open;
                    return true;
                }
                return false;
            },
            .half_open => return true,
        }
    }

    /// Record successful operation. Resets to closed.
    pub fn recordSuccess(self: *CircuitBreaker) void {
        self.state = .closed;
        self.failure_count = 0;
    }

    /// Record failed operation. Increments counter, trips to open at threshold.
    pub fn recordFailure(self: *CircuitBreaker) void {
        self.failure_count +|= 1;
        self.last_failure_ns = std.time.nanoTimestamp();

        if (self.state == .half_open or (self.state == .closed and self.failure_count >= self.threshold)) {
            self.state = .open;
        }
    }

    /// Is the breaker currently tripped?
    pub fn isOpen(self: *const CircuitBreaker) bool {
        return self.state == .open;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "init creates closed state with zero failure count" {
    const cb = CircuitBreaker.init(5, 1000);
    try std.testing.expectEqual(State.closed, cb.state);
    try std.testing.expectEqual(@as(u32, 0), cb.failure_count);
    try std.testing.expectEqual(@as(u64, 1_000_000_000), cb.cooldown_ns);
    try std.testing.expectEqual(@as(i128, 0), cb.last_failure_ns);
}

test "allow returns true when closed" {
    var cb = CircuitBreaker.init(5, 1000);
    try std.testing.expect(cb.allow());
    try std.testing.expectEqual(State.closed, cb.state);
}

test "recordFailure increments count" {
    var cb = CircuitBreaker.init(5, 1000);
    cb.recordFailure();
    try std.testing.expectEqual(@as(u32, 1), cb.failure_count);
    cb.recordFailure();
    try std.testing.expectEqual(@as(u32, 2), cb.failure_count);
}

test "threshold failures trips to open" {
    var cb = CircuitBreaker.init(3, 1000);
    cb.recordFailure();
    cb.recordFailure();
    try std.testing.expectEqual(State.closed, cb.state);
    cb.recordFailure(); // 3rd failure hits threshold
    try std.testing.expectEqual(State.open, cb.state);
    try std.testing.expect(cb.isOpen());
}

test "allow returns false when open before cooldown" {
    var cb = CircuitBreaker.init(1, 999_999);
    cb.recordFailure(); // trips immediately (threshold=1)
    try std.testing.expectEqual(State.open, cb.state);
    try std.testing.expect(!cb.allow());
}

test "open transitions to half_open after cooldown" {
    var cb = CircuitBreaker.init(1, 0); // 0ms cooldown — expires immediately
    cb.recordFailure(); // trips to open
    try std.testing.expectEqual(State.open, cb.state);
    try std.testing.expect(cb.allow()); // cooldown already expired → half_open
    try std.testing.expectEqual(State.half_open, cb.state);
}

test "half_open plus success transitions to closed" {
    var cb = CircuitBreaker.init(1, 0);
    cb.recordFailure(); // → open
    _ = cb.allow(); // → half_open
    try std.testing.expectEqual(State.half_open, cb.state);
    cb.recordSuccess();
    try std.testing.expectEqual(State.closed, cb.state);
    try std.testing.expectEqual(@as(u32, 0), cb.failure_count);
}

test "half_open plus failure transitions to open" {
    var cb = CircuitBreaker.init(1, 0);
    cb.recordFailure(); // → open
    _ = cb.allow(); // → half_open
    try std.testing.expectEqual(State.half_open, cb.state);
    const before = cb.last_failure_ns;
    cb.recordFailure(); // → open again, timestamp updated
    try std.testing.expectEqual(State.open, cb.state);
    try std.testing.expect(cb.last_failure_ns >= before);
}

test "recordSuccess resets failure count" {
    var cb = CircuitBreaker.init(5, 1000);
    cb.recordFailure();
    cb.recordFailure();
    try std.testing.expectEqual(@as(u32, 2), cb.failure_count);
    cb.recordSuccess();
    try std.testing.expectEqual(@as(u32, 0), cb.failure_count);
    try std.testing.expectEqual(State.closed, cb.state);
}

test "isOpen reflects state correctly" {
    var cb = CircuitBreaker.init(2, 999_999);
    try std.testing.expect(!cb.isOpen());
    cb.recordFailure();
    try std.testing.expect(!cb.isOpen()); // still closed
    cb.recordFailure(); // trips to open
    try std.testing.expect(cb.isOpen());
    cb.recordSuccess(); // back to closed
    try std.testing.expect(!cb.isOpen());
}

test "multiple success failure cycles" {
    var cb = CircuitBreaker.init(3, 0);
    // Partial failures then success resets count
    cb.recordFailure();
    cb.recordFailure();
    try std.testing.expectEqual(@as(u32, 2), cb.failure_count);
    cb.recordSuccess();
    try std.testing.expectEqual(@as(u32, 0), cb.failure_count);
    try std.testing.expectEqual(State.closed, cb.state);

    // Need full threshold again to trip
    cb.recordFailure();
    try std.testing.expectEqual(State.closed, cb.state);
    cb.recordFailure();
    try std.testing.expectEqual(State.closed, cb.state);
    cb.recordFailure(); // 3rd → open
    try std.testing.expectEqual(State.open, cb.state);

    // Recover via half_open
    _ = cb.allow(); // 0ms cooldown → half_open
    cb.recordSuccess();
    try std.testing.expectEqual(State.closed, cb.state);
    try std.testing.expectEqual(@as(u32, 0), cb.failure_count);
}

test "threshold zero trips immediately on first failure" {
    var cb = CircuitBreaker.init(0, 1000);
    try std.testing.expectEqual(State.closed, cb.state);
    cb.recordFailure(); // failure_count=1 >= threshold=0 → open
    try std.testing.expectEqual(State.open, cb.state);
    try std.testing.expect(cb.isOpen());
}
