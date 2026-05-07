use crate::trigger::error::{Result, TriggerError};
use serde::Deserialize;
use std::path::Path;
use std::sync::Arc;
use tracing::{error, warn};

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type")]
pub(crate) enum MatchRule {
    Exact { comm: String },
    Prefix { comm: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum PsiResource {
    Memory,
    Cpu,
    Io,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct TargetConfig {
    pub(crate) rule: MatchRule,
    pub(crate) resource: PsiResource,
    /// PSI stall threshold as a percentage of the 1 000 ms time window (1–99).
    pub(crate) threshold: u8,
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
            Ok(Ok(config)) => Arc::new(config),
            Ok(Err(e)) => {
                warn!(error = %e, "failed to load config, using defaults");
                Arc::new(Self::default_config())
            }
            Err(e) => {
                error!(error = %e, "config load task panicked, using defaults");
                Arc::new(Self::default_config())
            }
        }
    }

    /// Minimal default config: watch the bistouri process itself for
    /// Memory and CPU pressure at 10% threshold.
    pub(crate) fn default_config() -> Self {
        Self::try_new(vec![
            TargetConfig {
                rule: MatchRule::Exact {
                    comm: "bistouri".to_string(),
                },
                resource: PsiResource::Memory,
                threshold: 10,
                rule_id: 0,
            },
            TargetConfig {
                rule: MatchRule::Exact {
                    comm: "bistouri".to_string(),
                },
                resource: PsiResource::Cpu,
                threshold: 10,
                rule_id: 0,
            },
        ])
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
        for target in &self.targets {
            let comm = match &target.rule {
                MatchRule::Exact { comm } => comm,
                MatchRule::Prefix { comm } => comm,
            };
            if comm.len() > 15 {
                return Err(TriggerError::CommTooLong { comm: comm.clone() });
            }
            if target.threshold == 0 || target.threshold >= 100 {
                return Err(TriggerError::InvalidThreshold {
                    threshold: target.threshold,
                    comm: comm.clone(),
                });
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

    fn parse_yaml(yaml: &str) -> std::result::Result<TriggerConfig, TriggerError> {
        let raw: TriggerConfig = serde_yml::from_str(yaml).map_err(TriggerError::ConfigParse)?;
        TriggerConfig::try_new(raw.targets)
    }

    #[test]
    fn parse_valid_exact_and_prefix() {
        let yaml = r#"
targets:
  - rule:
      type: Exact
      comm: node
    resource: memory
    threshold: 10
  - rule:
      type: Prefix
      comm: "worker-"
    resource: cpu
    threshold: 50
"#;
        let config = parse_yaml(yaml).unwrap();
        assert_eq!(config.targets.len(), 2);
        assert!(matches!(&config.targets[0].rule, MatchRule::Exact { comm } if comm == "node"));
        assert!(matches!(&config.targets[1].rule, MatchRule::Prefix { comm } if comm == "worker-"));
        assert_eq!(config.targets[0].resource, PsiResource::Memory);
        assert_eq!(config.targets[1].resource, PsiResource::Cpu);
    }

    #[test]
    fn empty_targets_fails() {
        let yaml = "targets: []\n";
        let result = parse_yaml(yaml);
        assert!(matches!(result, Err(TriggerError::EmptyTargets)));
    }

    #[test]
    fn threshold_zero_fails() {
        let yaml = r#"
targets:
  - rule:
      type: Exact
      comm: node
    resource: memory
    threshold: 0
"#;
        let result = parse_yaml(yaml);
        assert!(matches!(result, Err(TriggerError::InvalidThreshold { .. })));
    }

    #[test]
    fn threshold_hundred_fails() {
        let yaml = r#"
targets:
  - rule:
      type: Exact
      comm: node
    resource: memory
    threshold: 100
"#;
        let result = parse_yaml(yaml);
        assert!(matches!(result, Err(TriggerError::InvalidThreshold { .. })));
    }

    #[test]
    fn threshold_boundary_valid() {
        let yaml_1 = r#"
targets:
  - rule:
      type: Exact
      comm: node
    resource: memory
    threshold: 1
"#;
        let yaml_99 = r#"
targets:
  - rule:
      type: Exact
      comm: node
    resource: memory
    threshold: 99
"#;
        assert!(parse_yaml(yaml_1).is_ok());
        assert!(parse_yaml(yaml_99).is_ok());
    }

    #[test]
    fn comm_exceeds_kernel_limit() {
        let yaml = r#"
targets:
  - rule:
      type: Exact
      comm: "1234567890123456"
    resource: memory
    threshold: 10
"#;
        let result = parse_yaml(yaml);
        assert!(matches!(result, Err(TriggerError::CommTooLong { .. })));
    }

    #[test]
    fn comm_at_kernel_limit() {
        let yaml = r#"
targets:
  - rule:
      type: Exact
      comm: "123456789012345"
    resource: memory
    threshold: 10
"#;
        assert!(parse_yaml(yaml).is_ok());
    }

    #[test]
    fn rule_ids_assigned_sequentially() {
        let yaml = r#"
targets:
  - rule:
      type: Exact
      comm: node
    resource: memory
    threshold: 10
  - rule:
      type: Exact
      comm: python
    resource: cpu
    threshold: 20
  - rule:
      type: Prefix
      comm: "go-"
    resource: io
    threshold: 30
"#;
        let config = parse_yaml(yaml).unwrap();
        assert_eq!(config.targets[0].rule_id, 1);
        assert_eq!(config.targets[1].rule_id, 2);
        assert_eq!(config.targets[2].rule_id, 3);
    }

    #[test]
    fn unknown_resource_fails() {
        let yaml = r#"
targets:
  - rule:
      type: Exact
      comm: node
    resource: disk
    threshold: 10
"#;
        let result = parse_yaml(yaml);
        assert!(matches!(result, Err(TriggerError::ConfigParse(_))));
    }

    #[test]
    fn missing_threshold_fails() {
        let yaml = r#"
targets:
  - rule:
      type: Exact
      comm: node
    resource: memory
"#;
        let result = parse_yaml(yaml);
        assert!(matches!(result, Err(TriggerError::ConfigParse(_))));
    }

    #[test]
    fn default_config_is_valid() {
        let config = TriggerConfig::default_config();
        assert_eq!(config.targets.len(), 2);
        assert_eq!(config.targets[0].rule_id, 1);
        assert_eq!(config.targets[1].rule_id, 2);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn overlapping_prefixes_does_not_error() {
        let config =
            TriggerConfig::try_new(vec![prefix_target("work", 0), prefix_target("worker-", 0)]);
        // Overlapping prefixes are valid — just a warning, not an error.
        assert!(config.is_ok());
    }

    fn prefix_target(comm: &str, _unused: u32) -> TargetConfig {
        TargetConfig {
            rule: MatchRule::Prefix {
                comm: comm.to_string(),
            },
            resource: PsiResource::Cpu,
            threshold: 10,
            rule_id: 0,
        }
    }
}
