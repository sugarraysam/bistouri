//! Bistouri trigger configuration types — the schema shared between the
//! agent (runtime config loading) and crd-gen (Kubernetes CRD generation).
//!
//! These types define the canonical wire format for `trigger.yaml`:
//!
//! ```yaml
//! targets:
//!   - rule:
//!       type: Exact
//!       comm: "my-app"
//!     resources:
//!       - resource: memory
//!         threshold: 10.0
//! ```
//!
//! The `schemars` feature gate adds `JsonSchema` derives required by `crd-gen`
//! without bloating the agent's dependency tree.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

#[cfg(feature = "schemars")]
use schemars::JsonSchema;

// ---------------------------------------------------------------------------
// Validation constants — single source of truth for Rust + CRD CEL rules
// ---------------------------------------------------------------------------

/// Maximum length for `service_id` — aligns with K8s/DNS naming conventions.
pub const SERVICE_ID_MAX_LEN: usize = 32;

/// Regex pattern for valid `service_id` values.
pub const SERVICE_ID_PATTERN: &str = r"^[a-z][a-z0-9_-]*$";

/// Maximum length for process `comm` strings (kernel `TASK_COMM_LEN - 1`).
pub const COMM_MAX_LEN: usize = 15;

/// PSI threshold exclusive lower bound.
pub const THRESHOLD_EXCLUSIVE_MIN: f64 = 0.0;

/// PSI threshold exclusive upper bound.
pub const THRESHOLD_EXCLUSIVE_MAX: f64 = 100.0;

/// Maximum number of target entries in a config.
pub const MAX_TARGETS: usize = 64;

/// Maximum number of PSI resources per target (Memory, Cpu, Io).
pub const MAX_RESOURCES_PER_TARGET: usize = 3;

/// Which PSI resource to watch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schemars", derive(JsonSchema))]
#[serde(rename_all = "lowercase")]
pub enum PsiResource {
    Memory,
    Cpu,
    Io,
}

impl std::fmt::Display for PsiResource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PsiResource::Memory => write!(f, "memory"),
            PsiResource::Cpu => write!(f, "cpu"),
            PsiResource::Io => write!(f, "io"),
        }
    }
}

/// Per-resource trigger configuration within a target rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schemars", derive(JsonSchema))]
pub struct ResourceConfig {
    /// The PSI resource to watch.
    pub resource: PsiResource,
    /// PSI stall threshold as a percentage of the 1 000 ms time window.
    /// Must be in the range (0.0, 100.0) exclusive.
    pub threshold: f64,
}

/// How to match a process comm string.
///
/// Uses an internally-tagged serde representation (`type` field) so the
/// YAML wire format is:
///
/// ```yaml
/// rule:
///   type: Exact   # or Prefix
///   comm: "my-app"
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schemars", derive(JsonSchema))]
#[serde(tag = "type")]
pub enum MatchRule {
    /// Match the process comm string exactly.
    Exact {
        /// Process comm. Max 15 bytes (kernel TASK_COMM_LEN - 1).
        comm: String,
    },
    /// Match any comm string that starts with the configured prefix.
    Prefix {
        /// Process comm prefix. Max 15 bytes (kernel TASK_COMM_LEN - 1).
        comm: String,
    },
}

impl MatchRule {
    /// Returns the comm string regardless of match kind.
    pub fn comm(&self) -> &str {
        match self {
            MatchRule::Exact { comm } | MatchRule::Prefix { comm } => comm,
        }
    }
}

/// A single target: a process matching rule and its associated PSI resources.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schemars", derive(JsonSchema))]
pub struct TargetConfig {
    /// Process matching rule.
    pub rule: MatchRule,
    /// Logical service identity. Required for multi-tenant routing.
    /// Identifies the service being profiled within a tenant.
    pub service_id: String,
    /// One or more PSI resources to watch for this target.
    pub resources: Vec<ResourceConfig>,
    /// Unique rule identifier assigned by the agent after deserialization.
    /// Not part of the YAML schema — never serialized or deserialized.
    #[serde(skip, default)]
    #[cfg_attr(feature = "schemars", schemars(skip))]
    pub rule_id: u32,
    /// Per-target labels merged with agent-level labels (target wins on conflict).
    /// Optional — used for injecting team, version, or environment metadata.
    #[serde(default)]
    pub labels: HashMap<String, String>,
}
