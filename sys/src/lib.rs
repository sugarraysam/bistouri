//! Shared Linux system utilities for the Bistouri workspace.
//!
//! Pure parsing functions with zero runtime dependencies. Consumers
//! provide raw data (file contents, byte slices) and handle their
//! own I/O and error types.

pub mod kernel;
