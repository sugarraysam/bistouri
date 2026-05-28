//! `BistouriConfig` Kubernetes Custom Resource type.
//!
//! Gated on the `kube` feature. Consumers:
//!
//! - `api/src/bin/crd-gen.rs` — calls `BistouriConfig::crd()` to emit the CRD YAML.
//! - `bistouri-agent` (KubeConfigWatcher) — watches `BistouriConfig` CRs via
//!   `kube::Api<BistouriConfig>` and converts the spec to a `TriggerConfig`.
//!
//! # Schema notes
//!
//! `MatchRule` is an internally-tagged serde enum (`#[serde(tag = "type")]`).
//! kube-rs's structural schema merger rejects this because the `type` discriminant
//! appears in multiple subschemas with different enum values. We work around it
//! with a hand-written `match_rule_schema` injected via `#[schemars(schema_with)]`
//! on the `rule` field of `TargetConfigSchema`.
//!
//! `TargetConfigSchema` is a CRD-generation-only wrapper over the canonical
//! `TargetConfig` from `bistouri_api::config`. It exists solely to override the
//! `rule` field schema; the agent uses `TargetConfig` directly.
//!
//! # CEL cost budgeting
//!
//! All array fields carry `maxItems` to keep CEL cost estimates within the
//! Kubernetes budget:
//!
//! | field     | maxItems | rationale                                      |
//! |-----------|----------|------------------------------------------------|
//! | targets   | 64       | generous upper bound for any real workload      |
//! | resources | 3        | exact — only Memory / Cpu / Io exist            |
//!
//! `comm` carries `maxLength: 15` (kernel `TASK_COMM_LEN - 1`) in the hand-written
//! schema, bounding string-comparison cost in CEL rules.

use std::collections::HashMap;

use crate::config::{MatchRule, ResourceConfig, TargetConfig, COMM_MAX_LEN};
use kube::CustomResource;
use schemars::JsonSchema;
use schemars::Schema;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// MatchRule schema override
// ---------------------------------------------------------------------------

/// Returns a hand-written OpenAPI schema for `MatchRule`.
///
/// Necessary because kube-rs rejects internally-tagged enums: the `type`
/// discriminant field would have different `enum` values per subschema.
fn match_rule_schema(_gen: &mut schemars::generate::SchemaGenerator) -> Schema {
    serde_json::from_value(serde_json::json!({
        "type": "object",
        "description": "Process comm matching rule.",
        "required": ["type", "comm"],
        "properties": {
            "type": {
                "type": "string",
                "enum": ["Exact", "Prefix"],
                "description": "Exact: match the full comm string. Prefix: match any comm that starts with this string."
            },
            "comm": {
                "type": "string",
                // maxLength bounds CEL string-comparison cost.
                "maxLength": COMM_MAX_LEN,
                "description": "Process comm string. Max 15 bytes (kernel TASK_COMM_LEN - 1)."
            }
        },
        "additionalProperties": false
    }))
    .expect("match_rule_schema literal is valid JSON")
}

// ---------------------------------------------------------------------------
// TargetConfigSchema — CRD schema wrapper
// ---------------------------------------------------------------------------

/// Schema-generation wrapper for `TargetConfig`.
///
/// Identical wire format to `TargetConfig`; differs only in how the `rule`
/// field is represented in the OpenAPI schema (hand-written vs. derived).
/// The agent never instantiates this type at runtime.
#[derive(Serialize, Deserialize, Clone, Debug, JsonSchema)]
pub struct TargetConfigSchema {
    /// Process matching rule.
    #[schemars(schema_with = "match_rule_schema")]
    pub rule: MatchRule,
    /// Logical service identity. Required for multi-tenant routing.
    #[schemars(length(min = 1, max = 32), regex(pattern = r"^[a-z][a-z0-9_-]*$"))]
    pub service_id: String,
    /// PSI resources to watch for this target. At most 3 (Memory, Cpu, Io).
    #[schemars(length(max = 3))]
    pub resources: Vec<ResourceConfig>,
    /// Per-target labels (optional). Merged with agent-level labels.
    #[serde(default)]
    pub labels: HashMap<String, String>,
}

impl From<TargetConfigSchema> for TargetConfig {
    fn from(t: TargetConfigSchema) -> Self {
        TargetConfig {
            rule: t.rule,
            service_id: t.service_id,
            resources: t.resources,
            rule_id: 0, // assigned later by TriggerConfig::assign_rule_ids
            labels: t.labels,
        }
    }
}

// ---------------------------------------------------------------------------
// BistouriConfig — the Custom Resource
// ---------------------------------------------------------------------------

/// Bistouri trigger configuration — defines PSI threshold rules per process comm.
///
/// Apply a `BistouriConfig` CR in the same namespace as the agent to configure
/// which processes to watch and at what PSI thresholds. The agent hot-reloads
/// when the CR changes.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, JsonSchema)]
#[kube(
    group = "bistouri.dev",
    version = "v1alpha1",
    kind = "BistouriConfig",
    namespaced,
    shortname = "bc",
    doc = "Bistouri trigger configuration — PSI threshold rules per process comm.",
    // ── CEL validation rules ────────────────────────────────────────────────
    // Mirror of `bistouri_api::validate::validate_targets()`. The
    // `test_every_validation_error_has_cel_rule` test enforces that
    // every ConfigValidationError variant has a corresponding CEL rule.
    //
    // Rule 1: at least one target.
    validation = Rule::new("size(self.spec.targets) > 0")
        .message("spec.targets must not be empty"),
    // Rule 2: thresholds strictly between 0 and 100 (OpenAPI bounds are inclusive).
    // Cost: O(targets × resources) = O(64 × 3) = O(192).
    validation = Rule::new(
        "self.spec.targets.all(t, t.resources.all(r, r.threshold > 0.0 && r.threshold < 100.0))"
    ).message("threshold must be strictly between 0.0 and 100.0 (exclusive)"),
    // Rule 3: each target has at least one resource.
    validation = Rule::new(
        "self.spec.targets.all(t, size(t.resources) > 0)"
    ).message("each target must declare at least one resource"),
    // Rule 4: no duplicate resource types within the same target.
    // Uses a fixed 3-element literal to enumerate resources without an O(n²)
    // cross-product.
    // Cost: O(targets × 3 × resources) = O(64 × 3 × 3) = O(576).
    validation = Rule::new(concat!(
        "self.spec.targets.all(t,",
        "  [\"memory\", \"cpu\", \"io\"].all(res,",
        "    t.resources.filter(r, r.resource == res).size() <= 1",
        "  )",
        ")"
    )).message("duplicate resource type within a single target — each PSI resource may appear at most once per target"),
    // Rule 5: each target must declare a non-empty service_id.
    validation = Rule::new(
        "self.spec.targets.all(t, size(t.service_id) > 0)"
    ).message("each target must declare a service_id"),
    // Rule 6: service_id must be unique across targets.
    // No duplicates ⟺ for every pair (i, j) where i < j, ids differ.
    // Cost: O(targets²) = O(64²) = O(4096).
    validation = Rule::new(concat!(
        "self.spec.targets.all(a, ",
        "self.spec.targets.filter(b, b.service_id == a.service_id).size() == 1)"
    )).message("duplicate service_id across targets — each target must have a unique service_id"),
    // Rule 7: global (comm, resource) uniqueness across all targets.
    // For every pair of targets, if the comms match, their resource lists
    // must not share any resource type. CEL has no `reduce` or `unique`,
    // so we check pairwise: no two distinct targets share (comm, resource).
    // Cost: O(targets² × resources²) = O(64² × 3²) = O(36864).
    validation = Rule::new(concat!(
        "self.spec.targets.all(a, self.spec.targets.all(b, ",
        "a.service_id == b.service_id || ",
        "a.resources.all(ar, b.resources.all(br, ",
        "a.rule.comm + '/' + ar.resource != b.rule.comm + '/' + br.resource))))"
    )).message("duplicate (comm, resource) pair across targets — each PSI resource may appear at most once per comm"),
)]
pub struct BistouriConfigSpec {
    /// Process targets to watch. At least one required.
    // maxItems gives the CEL estimator a concrete bound for nested iterations.
    #[schemars(length(max = 64))]
    pub targets: Vec<TargetConfigSchema>,
}

// ---------------------------------------------------------------------------
// Tests — enforce CRD ↔ Rust validation sync
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use kube::core::CustomResourceExt;

    /// Golden-file test: the committed CRD YAML must match what the Rust
    /// types generate. Fails if someone changes the Rust types, CEL rules,
    /// or OpenAPI annotations without running `make generate-crd`.
    #[test]
    fn test_crd_yaml_in_sync() {
        let generated = BistouriConfig::crd();
        let generated_json: serde_json::Value =
            serde_json::to_value(&generated).expect("CRD serialization failed");

        // Resolve path relative to the crate root (api/).
        let committed_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../deployment/crd/bistouriconfig.yaml");
        let committed_bytes = std::fs::read_to_string(&committed_path).unwrap_or_else(|e| {
            panic!(
                "failed to read committed CRD at {}: {e}\n\
                 Run `make generate-crd` in public/bistouri/ to create it.",
                committed_path.display()
            )
        });
        let committed_json: serde_json::Value = serde_json::from_str(&committed_bytes)
            .unwrap_or_else(|e| {
                panic!(
                    "failed to parse committed CRD as JSON: {e}\n\
                     The file may be corrupt. Run `make generate-crd` to regenerate."
                )
            });

        assert_eq!(
            generated_json, committed_json,
            "\n\nCRD YAML is stale!\n\
             The committed deployment/crd/bistouriconfig.yaml does not match\n\
             the output of BistouriConfig::crd().\n\n\
             Run `make generate-crd` in public/bistouri/ to update it.\n"
        );
    }
}
