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

use crate::config::{MatchRule, ResourceConfig, TargetConfig};
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
                "maxLength": 15,
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
    /// PSI resources to watch for this target. At most 3 (Memory, Cpu, Io).
    #[schemars(length(max = 3))]
    pub resources: Vec<ResourceConfig>,
}

impl From<TargetConfigSchema> for TargetConfig {
    fn from(t: TargetConfigSchema) -> Self {
        TargetConfig {
            rule: t.rule,
            resources: t.resources,
            rule_id: 0, // assigned later by TriggerConfig::assign_rule_ids
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
    // Fast-fail admission checks. The agent performs the full validation in
    // TriggerConfig::validate() on every load. CEL rules are intentionally a
    // subset to stay within the cost budget.
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
    // cross-product. Cross-target dedup is enforced by TriggerConfig::validate().
    // Cost: O(targets × 3 × resources) = O(64 × 3 × 3) = O(576).
    validation = Rule::new(concat!(
        "self.spec.targets.all(t,",
        "  [\"memory\", \"cpu\", \"io\"].all(res,",
        "    t.resources.filter(r, r.resource == res).size() <= 1",
        "  )",
        ")"
    )).message("duplicate resource type within a single target — each PSI resource may appear at most once per target"),
)]
pub struct BistouriConfigSpec {
    /// Process targets to watch. At least one required.
    // maxItems gives the CEL estimator a concrete bound for nested iterations.
    #[schemars(length(max = 64))]
    pub targets: Vec<TargetConfigSchema>,
}
