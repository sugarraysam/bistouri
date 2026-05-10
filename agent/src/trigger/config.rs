use crate::trigger::error::{Result, TriggerError};
use serde::Deserialize;
use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;
use tracing::{error, info, warn};

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type")]
pub(crate) enum MatchRule {
    Exact { comm: String },
    Prefix { comm: String },
}

impl MatchRule {
    pub(crate) fn comm(&self) -> &str {
        match self {
            MatchRule::Exact { comm } => comm,
            MatchRule::Prefix { comm } => comm,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum PsiResource {
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
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct ResourceConfig {
    pub(crate) resource: PsiResource,
    /// PSI stall threshold as a percentage of the 1 000 ms time window.
    /// Must be in the range (0.0, 100.0) exclusive.
    pub(crate) threshold: f64,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct TargetConfig {
    pub(crate) rule: MatchRule,
    pub(crate) resources: Vec<ResourceConfig>,
    /// Unique identifier assigned during construction.
    /// Not user-facing — derived from the target's position in the Vec.
    #[serde(skip)]
    pub(crate) rule_id: u32,
}

#[derive(Debug, Deserialize)]
pub(crate) struct TriggerConfig {
    pub(crate) targets: Vec<TargetConfig>,
}

impl TriggerConfig {
    /// Single constructor: assigns rule IDs and validates in one place.
    pub(crate) fn try_new(targets: Vec<TargetConfig>) -> Result<Self> {
        let mut config = TriggerConfig { targets };
        config.assign_rule_ids();
        config.validate()?;
        config.warn_overlapping_prefixes();
        Ok(config)
    }

    /// Loads and validates config from a YAML file. This performs synchronous
    /// file I/O and should be called from `spawn_blocking`.
    pub(crate) fn load_from_file(path: &str) -> Result<Self> {
        let contents = std::fs::read_to_string(path).map_err(TriggerError::ConfigIo)?;
        let raw: TriggerConfig =
            serde_yml::from_str(&contents).map_err(TriggerError::ConfigParse)?;
        Self::try_new(raw.targets)
    }

    /// Loads config from file if it exists, falling back to default config.
    /// Config parsing runs in `spawn_blocking` to protect the event loop.
    pub(crate) async fn load_or_default(path: &Path) -> Arc<Self> {
        let path = path.to_path_buf();
        match tokio::task::spawn_blocking(move || {
            Self::load_from_file(path.to_str().unwrap_or_default())
        })
        .await
        {
            Ok(Ok(config)) => {
                let comms: Vec<&str> = config.targets.iter().map(|t| t.rule.comm()).collect();
                info!(
                    target_count = config.targets.len(),
                    ?comms,
                    "loaded trigger config",
                );
                Arc::new(config)
            }
            Ok(Err(e)) => {
                warn!(error = %e, "failed to load config, using default");
                Arc::new(Self::default_config())
            }
            Err(e) => {
                error!(error = %e, "config load task panicked, using default");
                Arc::new(Self::default_config())
            }
        }
    }

    /// Minimal default config: watch the bistouri-agent process itself for
    /// Memory and CPU pressure at 10% threshold.
    pub(crate) fn default_config() -> Self {
        Self::try_new(vec![TargetConfig {
            rule: MatchRule::Exact {
                comm: "bistouri-agent".to_string(),
            },
            resources: vec![
                ResourceConfig {
                    resource: PsiResource::Memory,
                    threshold: 10.0,
                },
                ResourceConfig {
                    resource: PsiResource::Cpu,
                    threshold: 10.0,
                },
            ],
            rule_id: 0,
        }])
        // Safe: we control these inputs and they are known-valid.
        .expect("default config must be valid")
    }

    /// Assigns stable, 1-indexed rule IDs based on position in the targets Vec.
    fn assign_rule_ids(&mut self) {
        for (i, target) in self.targets.iter_mut().enumerate() {
            target.rule_id = (i + 1) as u32;
        }
    }

    fn validate(&self) -> Result<()> {
        if self.targets.is_empty() {
            return Err(TriggerError::EmptyTargets);
        }

        // Global duplicate detection: (comm, resource) must be unique across
        // all targets. Duplicate pairs would produce conflicting PSI watchers
        // for the same cgroup — the second would be silently dropped.
        let mut seen_pairs: HashSet<(&str, PsiResource)> = HashSet::new();

        for target in &self.targets {
            let comm = target.rule.comm();

            if comm.len() > 15 {
                return Err(TriggerError::CommTooLong { comm: comm.into() });
            }

            if target.resources.is_empty() {
                return Err(TriggerError::EmptyResources {
                    rule_id: target.rule_id,
                });
            }

            for res_cfg in &target.resources {
                if res_cfg.threshold <= 0.0 || res_cfg.threshold >= 100.0 {
                    return Err(TriggerError::InvalidThreshold {
                        threshold: res_cfg.threshold,
                        comm: comm.into(),
                    });
                }

                if !seen_pairs.insert((comm, res_cfg.resource)) {
                    return Err(TriggerError::DuplicateCommResource {
                        comm: comm.into(),
                        resource: res_cfg.resource,
                    });
                }
            }
        }
        Ok(())
    }

    /// Returns the target for the given rule_id in O(1).
    /// Rule IDs are 1-indexed and assigned by `assign_rule_ids`.
    pub(crate) fn target_for_rule(&self, rule_id: u32) -> &TargetConfig {
        &self.targets[(rule_id as usize) - 1]
    }

    /// Warns about overlapping Prefix rules where one comm pattern is a prefix
    /// of another. Both the userspace radix trie and BPF LPM trie return only
    /// the longest prefix match, so the shorter rule is effectively shadowed.
    /// This is not an error — the behavior is deterministic — but may surprise
    /// users who expect both rules to fire independently.
    fn warn_overlapping_prefixes(&self) {
        let prefixes: Vec<(u32, &str)> = self
            .targets
            .iter()
            .filter_map(|t| match &t.rule {
                MatchRule::Prefix { comm } => Some((t.rule_id, comm.as_str())),
                _ => None,
            })
            .collect();

        for (i, (id_a, comm_a)) in prefixes.iter().enumerate() {
            for (id_b, comm_b) in &prefixes[i + 1..] {
                if comm_b.starts_with(comm_a) {
                    warn!(
                        shadowed_rule = id_a,
                        shadowed_comm = comm_a,
                        shadowing_rule = id_b,
                        shadowing_comm = comm_b,
                        "prefix rule shadowed by longer prefix — only the longest match fires",
                    );
                } else if comm_a.starts_with(comm_b) {
                    warn!(
                        shadowed_rule = id_b,
                        shadowed_comm = comm_b,
                        shadowing_rule = id_a,
                        shadowing_comm = comm_a,
                        "prefix rule shadowed by longer prefix — only the longest match fires",
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn parse_yaml(yaml: &str) -> std::result::Result<TriggerConfig, TriggerError> {
        let raw: TriggerConfig = serde_yml::from_str(yaml).map_err(TriggerError::ConfigParse)?;
        TriggerConfig::try_new(raw.targets)
    }

    fn exact_target(comm: &str, resources: Vec<ResourceConfig>) -> TargetConfig {
        TargetConfig {
            rule: MatchRule::Exact {
                comm: comm.to_string(),
            },
            resources,
            rule_id: 0,
        }
    }

    fn prefix_target(comm: &str, resources: Vec<ResourceConfig>) -> TargetConfig {
        TargetConfig {
            rule: MatchRule::Prefix {
                comm: comm.to_string(),
            },
            resources,
            rule_id: 0,
        }
    }

    fn res(resource: PsiResource, threshold: f64) -> ResourceConfig {
        ResourceConfig {
            resource,
            threshold,
        }
    }

    // -----------------------------------------------------------------------
    // YAML parsing
    // -----------------------------------------------------------------------

    #[test]
    fn parse_valid_exact_and_prefix() {
        let yaml = r#"
targets:
  - rule:
      type: Exact
      comm: node
    resources:
      - resource: memory
        threshold: 10
  - rule:
      type: Prefix
      comm: "worker-"
    resources:
      - resource: cpu
        threshold: 50
"#;
        let config = parse_yaml(yaml).unwrap();
        assert_eq!(config.targets.len(), 2);
        assert!(matches!(&config.targets[0].rule, MatchRule::Exact { comm } if comm == "node"));
        assert!(matches!(&config.targets[1].rule, MatchRule::Prefix { comm } if comm == "worker-"));
        assert_eq!(config.targets[0].resources[0].resource, PsiResource::Memory);
        assert_eq!(config.targets[1].resources[0].resource, PsiResource::Cpu);
    }

    #[test]
    fn parse_multi_resource_target() {
        let yaml = r#"
targets:
  - rule:
      type: Exact
      comm: bistouri
    resources:
      - resource: memory
        threshold: 10
      - resource: cpu
        threshold: 20
"#;
        let config = parse_yaml(yaml).unwrap();
        assert_eq!(config.targets.len(), 1);
        assert_eq!(config.targets[0].resources.len(), 2);
        assert_eq!(config.targets[0].resources[0].resource, PsiResource::Memory);
        assert_eq!(config.targets[0].resources[1].resource, PsiResource::Cpu);
        assert_eq!(config.targets[0].resources[0].threshold, 10.0);
        assert_eq!(config.targets[0].resources[1].threshold, 20.0);
    }

    // -----------------------------------------------------------------------
    // Threshold validation — rstest table
    // -----------------------------------------------------------------------

    #[rstest]
    #[case::zero(0.0, true)]
    #[case::negative(-5.0, true)]
    #[case::just_above_zero(0.001, false)]
    #[case::boundary_one(1.0, false)]
    #[case::valid_fifty(50.0, false)]
    #[case::boundary_99(99.0, false)]
    #[case::hundred(100.0, true)]
    #[case::over_hundred(150.0, true)]
    fn threshold_validation(#[case] threshold: f64, #[case] should_fail: bool) {
        let result = TriggerConfig::try_new(vec![exact_target(
            "node",
            vec![res(PsiResource::Memory, threshold)],
        )]);
        assert_eq!(
            result.is_err(),
            should_fail,
            "threshold={threshold}, expected fail={should_fail}, got {:?}",
            result,
        );
        if should_fail {
            assert!(matches!(
                result.unwrap_err(),
                TriggerError::InvalidThreshold { .. }
            ));
        }
    }

    // -----------------------------------------------------------------------
    // Comm length validation — rstest table
    // -----------------------------------------------------------------------

    #[rstest]
    #[case::at_limit("123456789012345", false)] // 15 chars — max allowed
    #[case::over_limit("1234567890123456", true)] // 16 chars — exceeds kernel TASK_COMM_LEN - 1
    #[case::short("node", false)]
    #[case::empty("", false)] // empty comm is valid syntactically
    fn comm_length_validation(#[case] comm: &str, #[case] should_fail: bool) {
        let result = TriggerConfig::try_new(vec![exact_target(
            comm,
            vec![res(PsiResource::Memory, 10.0)],
        )]);
        assert_eq!(result.is_err(), should_fail);
        if should_fail {
            assert!(matches!(
                result.unwrap_err(),
                TriggerError::CommTooLong { .. }
            ));
        }
    }

    // -----------------------------------------------------------------------
    // Empty targets / resources validation
    // -----------------------------------------------------------------------

    #[test]
    fn empty_targets_fails() {
        let yaml = "targets: []\n";
        let result = parse_yaml(yaml);
        assert!(matches!(result, Err(TriggerError::EmptyTargets)));
    }

    #[test]
    fn empty_resources_fails() {
        let result = TriggerConfig::try_new(vec![exact_target("node", vec![])]);
        assert!(matches!(result, Err(TriggerError::EmptyResources { .. })));
    }

    // -----------------------------------------------------------------------
    // Duplicate (comm, resource) validation — rstest table
    // -----------------------------------------------------------------------

    #[rstest]
    #[case::same_target_dup_resource(
        vec![exact_target("node", vec![
            res(PsiResource::Memory, 10.0),
            res(PsiResource::Memory, 20.0),
        ])],
        true,
        "same resource listed twice within one target"
    )]
    #[case::cross_target_dup_resource(
        vec![
            exact_target("node", vec![res(PsiResource::Cpu, 10.0)]),
            exact_target("node", vec![res(PsiResource::Cpu, 20.0)]),
        ],
        true,
        "same (comm, resource) across two separate targets"
    )]
    #[case::different_resources_ok(
        vec![exact_target("node", vec![
            res(PsiResource::Memory, 10.0),
            res(PsiResource::Cpu, 20.0),
        ])],
        false,
        "different resources for same comm is valid"
    )]
    #[case::different_comms_same_resource_ok(
        vec![
            exact_target("node", vec![res(PsiResource::Memory, 10.0)]),
            exact_target("python", vec![res(PsiResource::Memory, 10.0)]),
        ],
        false,
        "same resource for different comms is valid"
    )]
    #[case::all_three_resources_ok(
        vec![exact_target("app", vec![
            res(PsiResource::Memory, 10.0),
            res(PsiResource::Cpu, 20.0),
            res(PsiResource::Io, 30.0),
        ])],
        false,
        "all three resources for one comm is valid"
    )]
    fn duplicate_comm_resource_validation(
        #[case] targets: Vec<TargetConfig>,
        #[case] should_fail: bool,
        #[case] description: &str,
    ) {
        let result = TriggerConfig::try_new(targets);
        assert_eq!(result.is_err(), should_fail, "case: {description}");
        if should_fail {
            assert!(matches!(
                result.unwrap_err(),
                TriggerError::DuplicateCommResource { .. }
            ));
        }
    }

    // -----------------------------------------------------------------------
    // Rule ID assignment
    // -----------------------------------------------------------------------

    #[test]
    fn rule_ids_assigned_sequentially() {
        let config = TriggerConfig::try_new(vec![
            exact_target("node", vec![res(PsiResource::Memory, 10.0)]),
            exact_target("python", vec![res(PsiResource::Cpu, 20.0)]),
            prefix_target("go-", vec![res(PsiResource::Io, 30.0)]),
        ])
        .unwrap();
        assert_eq!(config.targets[0].rule_id, 1);
        assert_eq!(config.targets[1].rule_id, 2);
        assert_eq!(config.targets[2].rule_id, 3);
    }

    // -----------------------------------------------------------------------
    // Serde error cases — rstest table
    // -----------------------------------------------------------------------

    #[rstest]
    #[case::unknown_resource(
        r#"
targets:
  - rule:
      type: Exact
      comm: node
    resources:
      - resource: disk
        threshold: 10
"#,
        "unknown resource"
    )]
    #[case::missing_threshold(
        r#"
targets:
  - rule:
      type: Exact
      comm: node
    resources:
      - resource: memory
"#,
        "missing threshold"
    )]
    #[case::missing_resources_field(
        r#"
targets:
  - rule:
      type: Exact
      comm: node
"#,
        "missing resources field"
    )]
    fn serde_parse_failures(#[case] yaml: &str, #[case] description: &str) {
        let result = parse_yaml(yaml);
        assert!(
            matches!(result, Err(TriggerError::ConfigParse(_))),
            "case '{description}' should fail with ConfigParse, got: {:?}",
            result,
        );
    }

    // -----------------------------------------------------------------------
    // Default config
    // -----------------------------------------------------------------------

    #[test]
    fn default_config_is_valid() {
        let config = TriggerConfig::default_config();
        assert_eq!(config.targets.len(), 1);
        assert_eq!(config.targets[0].resources.len(), 2);
        assert_eq!(config.targets[0].rule_id, 1);
        assert_eq!(config.targets[0].resources[0].resource, PsiResource::Memory);
        assert_eq!(config.targets[0].resources[1].resource, PsiResource::Cpu);
    }

    // -----------------------------------------------------------------------
    // Overlapping prefix warning (not an error)
    // -----------------------------------------------------------------------

    #[test]
    fn overlapping_prefixes_does_not_error() {
        let config = TriggerConfig::try_new(vec![
            prefix_target("work", vec![res(PsiResource::Cpu, 10.0)]),
            prefix_target("worker-", vec![res(PsiResource::Memory, 10.0)]),
        ]);
        // Overlapping prefixes are valid — just a warning, not an error.
        assert!(config.is_ok());
    }
}
