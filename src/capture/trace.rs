use crate::agent::profiler::StackTraceEvent;

/// A unique stack trace (kernel + user frames), trimmed to actual depth.
///
/// Derives `Hash` and `Eq` so it can be used as a `HashMap` key for
/// per-session deduplication. Rust's `HashMap` handles hashing internally
/// via SipHash — no explicit hashing code needed.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct StackTrace {
    pub kernel_frames: Vec<u64>,
    pub user_frames: Vec<u64>,
}

impl StackTrace {
    /// Constructs a `StackTrace` from a raw BPF event, trimming fixed-size
    /// arrays to actual depth. Negative `stack_sz` indicates a BPF fetch
    /// failure — treated as an empty stack (not an error here; the BPF error
    /// ringbuffer already recorded it).
    pub(crate) fn from_event(event: &StackTraceEvent) -> Self {
        let kernel_frames = if event.kernel_stack_sz > 0 {
            let count = event.kernel_stack_sz as usize / std::mem::size_of::<u64>();
            event.kernel_stack[..count].to_vec()
        } else {
            Vec::new()
        };

        let user_frames = if event.user_stack_sz > 0 {
            let count = event.user_stack_sz as usize / std::mem::size_of::<u64>();
            event.user_stack[..count].to_vec()
        } else {
            Vec::new()
        };

        Self {
            kernel_frames,
            user_frames,
        }
    }
}

/// A stack sample received from the BPF ring buffer, ready for ingestion
/// by the `CaptureOrchestrator`. Decouples the capture module from the
/// raw BPF struct layout.
pub(crate) struct StackSample {
    pub pid: u32,
    pub trace: StackTrace,
}

impl StackSample {
    pub(crate) fn from_event(event: &StackTraceEvent) -> Self {
        Self {
            pid: event.pid,
            trace: StackTrace::from_event(event),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::profiler::{MAX_STACK_DEPTH, TASK_COMM_LEN};
    use rstest::rstest;

    fn make_event(kernel_depth: usize, user_depth: usize) -> StackTraceEvent {
        let mut event = StackTraceEvent {
            pid: 42,
            comm: [0u8; TASK_COMM_LEN],
            kernel_stack_sz: 0,
            user_stack_sz: 0,
            kernel_stack: [0u64; MAX_STACK_DEPTH],
            user_stack: [0u64; MAX_STACK_DEPTH],
        };
        for i in 0..kernel_depth {
            event.kernel_stack[i] = 0xdead_0000 + i as u64;
        }
        event.kernel_stack_sz = (kernel_depth * 8) as i32;

        for i in 0..user_depth {
            event.user_stack[i] = 0xbeef_0000 + i as u64;
        }
        event.user_stack_sz = (user_depth * 8) as i32;

        event
    }

    // -----------------------------------------------------------------------
    // Frame trimming — rstest table
    // -----------------------------------------------------------------------

    #[rstest]
    #[case::both_populated(3, 5, 3, 5)]
    #[case::kernel_only(4, 0, 4, 0)]
    #[case::user_only(0, 7, 0, 7)]
    #[case::both_empty(0, 0, 0, 0)]
    #[case::single_frame_each(1, 1, 1, 1)]
    #[case::max_depth(127, 127, 127, 127)]
    fn from_event_trims_to_actual_depth(
        #[case] kernel_depth: usize,
        #[case] user_depth: usize,
        #[case] expected_kernel: usize,
        #[case] expected_user: usize,
    ) {
        let event = make_event(kernel_depth, user_depth);
        let trace = StackTrace::from_event(&event);
        assert_eq!(trace.kernel_frames.len(), expected_kernel);
        assert_eq!(trace.user_frames.len(), expected_user);
    }

    #[test]
    fn from_event_preserves_frame_addresses() {
        let event = make_event(3, 2);
        let trace = StackTrace::from_event(&event);
        assert_eq!(trace.kernel_frames[0], 0xdead_0000);
        assert_eq!(trace.kernel_frames[2], 0xdead_0002);
        assert_eq!(trace.user_frames[1], 0xbeef_0001);
    }

    // -----------------------------------------------------------------------
    // Negative stack_sz (BPF fetch failure) — rstest table
    // -----------------------------------------------------------------------

    #[rstest]
    #[case::both_negative(-14, -14)]
    #[case::kernel_negative_only(-2, 0)]
    #[case::user_negative_only(0, -2)]
    fn negative_stack_sz_yields_empty_frames(#[case] kernel_sz: i32, #[case] user_sz: i32) {
        let mut event = make_event(0, 0);
        event.kernel_stack_sz = kernel_sz;
        event.user_stack_sz = user_sz;

        let trace = StackTrace::from_event(&event);
        assert!(trace.kernel_frames.is_empty());
        assert!(trace.user_frames.is_empty());
    }

    // -----------------------------------------------------------------------
    // Hash/Eq contract
    // -----------------------------------------------------------------------

    #[test]
    fn identical_traces_have_equal_hash() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let event = make_event(3, 2);
        let a = StackTrace::from_event(&event);
        let b = StackTrace::from_event(&event);

        let hash = |t: &StackTrace| {
            let mut h = DefaultHasher::new();
            t.hash(&mut h);
            h.finish()
        };

        assert_eq!(a, b);
        assert_eq!(hash(&a), hash(&b));
    }

    #[test]
    fn different_traces_are_not_equal() {
        let a = StackTrace::from_event(&make_event(3, 2));
        let b = StackTrace::from_event(&make_event(4, 2));
        assert_ne!(a, b);
    }

    // -----------------------------------------------------------------------
    // StackSample
    // -----------------------------------------------------------------------

    #[test]
    fn stack_sample_extracts_pid() {
        let event = make_event(1, 1);
        let sample = StackSample::from_event(&event);
        assert_eq!(sample.pid, 42);
        assert_eq!(sample.trace.kernel_frames.len(), 1);
    }
}
