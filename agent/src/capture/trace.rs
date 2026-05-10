use serde::Serialize;
use std::hash::{Hash, Hasher};

use crate::agent::profiler::{StackTraceEvent, UserStackFrame, BUILD_ID_SIZE};
use tracing::error;

const METRIC_USER_FRAMES_FALLBACK: &str = "bistouri_profiler_user_frames_fallback";

/// Kernel `bpf_stack_build_id_status` enum values.
/// Parsed from the raw `i32` status field in `UserStackFrame`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BuildIdStatus {
    Empty,
    Valid,
    FallbackIp,
}

impl TryFrom<i32> for BuildIdStatus {
    type Error = i32;

    fn try_from(value: i32) -> std::result::Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Empty),
            1 => Ok(Self::Valid),
            2 => Ok(Self::FallbackIp),
            other => Err(other),
        }
    }
}

/// A resolved user-space frame with build_id and file offset.
/// The kernel computed the file offset from the VMA — ASLR is already handled.
/// The symbolizer adjusts by `(p_vaddr - p_offset)` for symbol table lookup.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub(crate) struct UserFrame {
    pub build_id: [u8; BUILD_ID_SIZE],
    pub file_offset: u64,
}

/// A unique stack trace (kernel + user frames), trimmed to actual depth.
///
/// Kernel frames are raw instruction pointers (symbolized via /proc/kallsyms).
/// User frames carry per-frame build_id and file offset from `BPF_F_USER_BUILD_ID`,
/// enabling the symbolizer to attribute frames to specific DSOs without needing
/// /proc/pid/maps.
///
/// Frames where the kernel could not resolve a build_id (`BPF_STACK_BUILD_ID_IP`)
/// are dropped — they require /proc/pid/maps de-ASLR which is not yet implemented.
/// A metric counter tracks their frequency for future prioritization.
///
/// Uses pre-computed hashing: the content hash is computed once during
/// construction and cached in `cached_hash`. The `Hash` impl feeds only
/// this `u64`, eliminating repeated ~400-byte hashing on every `HashMap`
/// lookup during deduplication.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct StackTrace {
    cached_hash: u64,
    pub kernel_frames: Vec<u64>,
    pub user_frames: Vec<UserFrame>,
}

impl PartialEq for StackTrace {
    fn eq(&self, other: &Self) -> bool {
        // Fast-reject: if pre-computed hashes differ, frames definitely differ.
        // Avoids the expensive Vec comparison for non-matching traces.
        self.cached_hash == other.cached_hash
            && self.kernel_frames == other.kernel_frames
            && self.user_frames == other.user_frames
    }
}

impl Eq for StackTrace {}

impl Hash for StackTrace {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.cached_hash.hash(state);
    }
}

impl StackTrace {
    /// Computes the content hash from frames using the standard hasher.
    /// Called once during construction — the result is cached for all
    /// subsequent `HashMap` lookups.
    fn compute_content_hash(kernel_frames: &[u64], user_frames: &[UserFrame]) -> u64 {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        kernel_frames.hash(&mut hasher);
        user_frames.hash(&mut hasher);
        hasher.finish()
    }

    /// Constructs a `StackTrace` from pre-built frame vectors, computing
    /// the content hash once at construction time.
    pub(crate) fn new(kernel_frames: Vec<u64>, user_frames: Vec<UserFrame>) -> Self {
        let cached_hash = Self::compute_content_hash(&kernel_frames, &user_frames);
        Self {
            cached_hash,
            kernel_frames,
            user_frames,
        }
    }

    /// Constructs a `StackTrace` from a raw BPF event, trimming fixed-size
    /// arrays to actual depth. Negative `stack_sz` indicates a BPF fetch
    /// failure — treated as an empty stack (not an error here; the BPF error
    /// ringbuffer already recorded it).
    ///
    /// User frames are parsed from `UserStackFrame` structs returned by
    /// `bpf_get_stack` with `BPF_F_USER_BUILD_ID`. Each frame has a status:
    /// - `Valid` (1): build_id + file_offset resolved by kernel → stored
    /// - `FallbackIp` (2): raw IP fallback (JIT, vDSO) → logged, metriced, dropped
    /// - `Empty` (0): end-of-trace sentinel → stops parsing
    pub(crate) fn from_event(event: &StackTraceEvent) -> Self {
        let kernel_frames = if event.kernel_stack_sz > 0 {
            let count = event.kernel_stack_sz as usize / std::mem::size_of::<u64>();
            event.kernel_stack[..count].to_vec()
        } else {
            Vec::new()
        };

        let user_frames = if event.user_stack_sz > 0 {
            let count = event.user_stack_sz as usize / std::mem::size_of::<UserStackFrame>();
            Self::parse_user_frames(&event.user_stack[..count])
        } else {
            Vec::new()
        };

        Self::new(kernel_frames, user_frames)
    }

    fn parse_user_frames(raw: &[UserStackFrame]) -> Vec<UserFrame> {
        let mut frames = Vec::with_capacity(raw.len());
        for frame in raw {
            let status = match BuildIdStatus::try_from(frame.status) {
                Ok(s) => s,
                Err(unknown) => {
                    error!(
                        status = unknown,
                        "unknown user_stack_frame status, skipping frame",
                    );
                    continue;
                }
            };

            match status {
                BuildIdStatus::Empty => break,
                BuildIdStatus::Valid => {
                    frames.push(UserFrame {
                        build_id: frame.build_id,
                        file_offset: frame.offset_or_ip,
                    });
                }
                BuildIdStatus::FallbackIp => {
                    error!(
                        ip = format_args!("{:#x}", frame.offset_or_ip),
                        "user frame has no build_id (BPF_STACK_BUILD_ID_IP), \
                         de-ASLR for fallback frames not yet implemented",
                    );
                    metrics::counter!(METRIC_USER_FRAMES_FALLBACK).increment(1);
                }
            }
        }
        frames
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

    /// Status constants for test readability (mirror BuildIdStatus discriminants).
    const VALID: i32 = 1;
    const FALLBACK_IP: i32 = 2;
    const EMPTY: i32 = 0;

    /// Helper: builds a zero-initialized event, then populates kernel frames
    /// (raw IPs) and user frames (UserStackFrame with status/build_id/offset).
    fn make_event(
        kernel_depth: usize,
        user_frames: &[(i32, [u8; BUILD_ID_SIZE], u64)],
    ) -> StackTraceEvent {
        let mut event = StackTraceEvent {
            pid: 42,
            comm: [0u8; TASK_COMM_LEN],
            kernel_stack_sz: 0,
            user_stack_sz: 0,
            kernel_stack: [0u64; MAX_STACK_DEPTH],
            user_stack: [UserStackFrame {
                status: 0,
                build_id: [0u8; BUILD_ID_SIZE],
                offset_or_ip: 0,
            }; MAX_STACK_DEPTH],
        };

        for i in 0..kernel_depth {
            event.kernel_stack[i] = 0xdead_0000 + i as u64;
        }
        event.kernel_stack_sz = (kernel_depth * 8) as i32;

        for (i, (status, build_id, offset_or_ip)) in user_frames.iter().enumerate() {
            event.user_stack[i] = UserStackFrame {
                status: *status,
                build_id: *build_id,
                offset_or_ip: *offset_or_ip,
            };
        }
        event.user_stack_sz = (user_frames.len() * std::mem::size_of::<UserStackFrame>()) as i32;

        event
    }

    /// Convenience: build_id filled with a single repeated byte.
    fn bid(byte: u8) -> [u8; BUILD_ID_SIZE] {
        [byte; BUILD_ID_SIZE]
    }

    // -----------------------------------------------------------------------
    // Kernel frame trimming — rstest table
    // -----------------------------------------------------------------------

    #[rstest]
    #[case::populated(3, 3)]
    #[case::empty(0, 0)]
    #[case::single(1, 1)]
    #[case::max_depth(127, 127)]
    fn kernel_frame_trimming(#[case] depth: usize, #[case] expected: usize) {
        let event = make_event(depth, &[]);
        let trace = StackTrace::from_event(&event);
        assert_eq!(trace.kernel_frames.len(), expected);
    }

    // -----------------------------------------------------------------------
    // User frame parsing — rstest table
    // -----------------------------------------------------------------------

    #[rstest]
    #[case::single_valid(
        &[(VALID, bid(0xAA), 0x1000)],
        1,
        "single valid frame stored"
    )]
    #[case::multiple_valid(
        &[(VALID, bid(0xAA), 0x1000), (VALID, bid(0xBB), 0x2000)],
        2,
        "multiple valid frames stored"
    )]
    #[case::fallback_dropped(
        &[(FALLBACK_IP, [0; BUILD_ID_SIZE], 0xFFFF_CAFE)],
        0,
        "fallback IP frame is dropped"
    )]
    #[case::empty_terminates(
        &[(VALID, bid(0xAA), 0x1000), (EMPTY, [0; BUILD_ID_SIZE], 0), (VALID, bid(0xCC), 0x3000)],
        1,
        "EMPTY status terminates parsing, trailing VALID is not reached"
    )]
    #[case::mixed_valid_and_fallback(
        &[(VALID, bid(0xAA), 0x100), (FALLBACK_IP, [0; BUILD_ID_SIZE], 0xDEAD), (VALID, bid(0xBB), 0x200)],
        2,
        "fallback frame dropped, both valid frames stored"
    )]
    #[case::all_fallback(
        &[(FALLBACK_IP, [0; BUILD_ID_SIZE], 0x1), (FALLBACK_IP, [0; BUILD_ID_SIZE], 0x2)],
        0,
        "all-fallback trace yields zero user frames"
    )]
    #[case::unknown_status_skipped(
        &[(99, [0; BUILD_ID_SIZE], 0x42), (VALID, bid(0xAA), 0x100)],
        1,
        "unknown status code skipped, subsequent valid frame stored"
    )]
    fn user_frame_parsing(
        #[case] raw_frames: &[(i32, [u8; BUILD_ID_SIZE], u64)],
        #[case] expected_count: usize,
        #[case] description: &str,
    ) {
        let event = make_event(0, raw_frames);
        let trace = StackTrace::from_event(&event);
        assert_eq!(trace.user_frames.len(), expected_count, "{description}");
    }

    #[test]
    fn valid_frame_preserves_build_id_and_offset() {
        let event = make_event(0, &[(VALID, bid(0xAA), 0x1000)]);
        let trace = StackTrace::from_event(&event);
        assert_eq!(trace.user_frames[0].build_id, bid(0xAA));
        assert_eq!(trace.user_frames[0].file_offset, 0x1000);
    }

    #[test]
    fn kernel_frames_preserve_addresses() {
        let event = make_event(3, &[]);
        let trace = StackTrace::from_event(&event);
        assert_eq!(trace.kernel_frames[0], 0xdead_0000);
        assert_eq!(trace.kernel_frames[2], 0xdead_0002);
    }

    // -----------------------------------------------------------------------
    // Negative stack_sz (BPF fetch failure) — rstest table
    // -----------------------------------------------------------------------

    #[rstest]
    #[case::both_negative(-14, -14)]
    #[case::kernel_negative_only(-2, 0)]
    #[case::user_negative_only(0, -2)]
    fn negative_stack_sz_yields_empty_frames(#[case] kernel_sz: i32, #[case] user_sz: i32) {
        let mut event = make_event(0, &[]);
        event.kernel_stack_sz = kernel_sz;
        event.user_stack_sz = user_sz;

        let trace = StackTrace::from_event(&event);
        assert!(trace.kernel_frames.is_empty());
        assert!(trace.user_frames.is_empty());
    }

    // -----------------------------------------------------------------------
    // Hash/Eq contract — rstest table
    // -----------------------------------------------------------------------

    #[rstest]
    #[case::same_build_id_same_offset(
        &[(VALID, bid(0xAA), 0x1000)],
        &[(VALID, bid(0xAA), 0x1000)],
        true,
        "identical frames are equal"
    )]
    #[case::different_build_id(
        &[(VALID, bid(0xAA), 0x1000)],
        &[(VALID, bid(0xBB), 0x1000)],
        false,
        "different build_ids are not equal"
    )]
    #[case::different_offset(
        &[(VALID, bid(0xAA), 0x1000)],
        &[(VALID, bid(0xAA), 0x2000)],
        false,
        "different offsets are not equal"
    )]
    fn hash_eq_contract(
        #[case] frames_a: &[(i32, [u8; BUILD_ID_SIZE], u64)],
        #[case] frames_b: &[(i32, [u8; BUILD_ID_SIZE], u64)],
        #[case] expected_equal: bool,
        #[case] description: &str,
    ) {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let a = StackTrace::from_event(&make_event(1, frames_a));
        let b = StackTrace::from_event(&make_event(1, frames_b));

        assert_eq!(a == b, expected_equal, "{description}");

        if expected_equal {
            let hash = |t: &StackTrace| {
                let mut h = DefaultHasher::new();
                t.hash(&mut h);
                h.finish()
            };
            assert_eq!(hash(&a), hash(&b), "{description}: hash mismatch");
        }
    }

    // -----------------------------------------------------------------------
    // StackSample
    // -----------------------------------------------------------------------

    #[test]
    fn stack_sample_extracts_pid() {
        let event = make_event(1, &[(VALID, bid(0xFF), 0x42)]);
        let sample = StackSample::from_event(&event);
        assert_eq!(sample.pid, 42);
        assert_eq!(sample.trace.kernel_frames.len(), 1);
        assert_eq!(sample.trace.user_frames.len(), 1);
    }

    // -----------------------------------------------------------------------
    // BuildIdStatus enum
    // -----------------------------------------------------------------------

    #[rstest]
    #[case::empty(0, Ok(BuildIdStatus::Empty))]
    #[case::valid(1, Ok(BuildIdStatus::Valid))]
    #[case::fallback(2, Ok(BuildIdStatus::FallbackIp))]
    #[case::unknown_3(3, Err(3))]
    #[case::unknown_neg(-1, Err(-1))]
    fn build_id_status_try_from(
        #[case] raw: i32,
        #[case] expected: std::result::Result<BuildIdStatus, i32>,
    ) {
        assert_eq!(BuildIdStatus::try_from(raw), expected);
    }

    // -----------------------------------------------------------------------
    // Layout sanity — ensure Rust and C agree on UserStackFrame size
    // -----------------------------------------------------------------------

    #[test]
    fn user_stack_frame_size_matches_c() {
        assert_eq!(
            std::mem::size_of::<UserStackFrame>(),
            32,
            "UserStackFrame must be 32 bytes to match C struct user_stack_frame"
        );
    }
}
