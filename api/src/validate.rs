//! Config validation logic — the single source of truth.
//!
//! This module contains all validation rules that apply to a
//! `BistouriConfig`. The same rules are mirrored as CEL expressions in
//! the CRD definition (`cr.rs`). The `test_every_validation_error_has_cel_rule`
//! test enforces that every error variant here has a corresponding CEL rule
//! in the generated CRD.

use std::collections::HashSet;

use crate::config::{
    PsiResource, TargetConfig, COMM_MAX_LEN, SERVICE_ID_MAX_LEN, THRESHOLD_EXCLUSIVE_MAX,
    THRESHOLD_EXCLUSIVE_MIN,
};
use thiserror::Error;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Config validation errors.
///
/// Each variant corresponds to a CEL rule in the CRD. The
/// `test_every_validation_error_has_cel_rule` test in `cr.rs` enforces
/// this mapping.
#[derive(Error, Debug)]
pub enum ConfigValidationError {
    #[error("at least one target rule is required")]
    EmptyTargets,

    #[error("target rule {rule_id} has no resources defined")]
    EmptyResources { rule_id: u32 },

    #[error("duplicate (comm, resource) pair: comm '{comm}', resource {resource}")]
    DuplicateCommResource { comm: String, resource: PsiResource },

    #[error("comm string '{comm}' exceeds {COMM_MAX_LEN} characters kernel limit")]
    CommTooLong { comm: String },

    #[error(
        "threshold {threshold} for comm '{comm}' must be in the range \
         ({THRESHOLD_EXCLUSIVE_MIN}, {THRESHOLD_EXCLUSIVE_MAX}) exclusive"
    )]
    InvalidThreshold { threshold: f64, comm: String },

    #[error("invalid service_id '{service_id}': {reason}")]
    InvalidServiceId {
        service_id: String,
        reason: &'static str,
    },

    #[error("duplicate service_id '{service_id}' across targets")]
    DuplicateServiceId { service_id: String },
}

// ---------------------------------------------------------------------------
// Validation functions
// ---------------------------------------------------------------------------

/// Validates that `service_id` matches `^[a-z][a-z0-9_-]*$` and is
/// 1–[`SERVICE_ID_MAX_LEN`] chars.
fn validate_service_id(id: &str) -> Result<(), ConfigValidationError> {
    if id.is_empty() {
        return Err(ConfigValidationError::InvalidServiceId {
            service_id: id.into(),
            reason: "must not be empty",
        });
    }
    if id.len() > SERVICE_ID_MAX_LEN {
        return Err(ConfigValidationError::InvalidServiceId {
            service_id: id.into(),
            reason: "must be at most 32 characters",
        });
    }
    let mut chars = id.chars();
    // SAFETY: checked non-empty above, so `next()` always returns `Some`.
    let first = chars
        .next()
        .expect("chars is non-empty after is_empty check");
    if !first.is_ascii_lowercase() {
        return Err(ConfigValidationError::InvalidServiceId {
            service_id: id.into(),
            reason: "must start with a lowercase letter [a-z]",
        });
    }
    for ch in chars {
        if !(ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_' || ch == '-') {
            return Err(ConfigValidationError::InvalidServiceId {
                service_id: id.into(),
                reason: "must contain only lowercase letters, digits, underscores, and hyphens [a-z0-9_-]",
            });
        }
    }
    Ok(())
}

/// Validate a slice of [`TargetConfig`] entries.
///
/// This is the canonical validation function — both the agent's
/// `TriggerConfig::try_new()` and the CRD's CEL rules enforce the same
/// invariants. The mapping is verified by the
/// `test_every_validation_error_has_cel_rule` test in `cr.rs`.
pub fn validate_targets(targets: &[TargetConfig]) -> Result<(), ConfigValidationError> {
    if targets.is_empty() {
        return Err(ConfigValidationError::EmptyTargets);
    }

    // Global duplicate detection: (comm, resource) must be unique across
    // all targets. Duplicate pairs would produce conflicting PSI watchers
    // for the same cgroup — the second would be silently dropped.
    let mut seen_pairs: HashSet<(&str, PsiResource)> = HashSet::new();
    let mut seen_service_ids: HashSet<&str> = HashSet::new();

    for target in targets {
        let comm = target.rule.comm();

        if comm.len() > COMM_MAX_LEN {
            return Err(ConfigValidationError::CommTooLong { comm: comm.into() });
        }

        // service_id validation: ^[a-z][a-z0-9_-]*$, 1–32 chars, unique.
        validate_service_id(&target.service_id)?;
        if !seen_service_ids.insert(&target.service_id) {
            return Err(ConfigValidationError::DuplicateServiceId {
                service_id: target.service_id.clone(),
            });
        }

        if target.resources.is_empty() {
            return Err(ConfigValidationError::EmptyResources {
                rule_id: target.rule_id,
            });
        }

        for res_cfg in &target.resources {
            if res_cfg.threshold <= THRESHOLD_EXCLUSIVE_MIN
                || res_cfg.threshold >= THRESHOLD_EXCLUSIVE_MAX
            {
                return Err(ConfigValidationError::InvalidThreshold {
                    threshold: res_cfg.threshold,
                    comm: comm.into(),
                });
            }

            if !seen_pairs.insert((comm, res_cfg.resource)) {
                return Err(ConfigValidationError::DuplicateCommResource {
                    comm: comm.into(),
                    resource: res_cfg.resource,
                });
            }
        }
    }
    Ok(())
}
