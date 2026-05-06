use serde::Deserialize;

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
    /// Unique identifier assigned by TriggerConfig during loading.
    /// Not user-facing — derived from the target's position in the Vec.
    #[serde(skip)]
    pub(crate) rule_id: u32,
}

#[derive(Debug, Deserialize)]
pub(crate) struct TriggerConfig {
    pub(crate) targets: Vec<TargetConfig>,
}

impl TriggerConfig {
    pub(crate) fn load_from_file(path: &str) -> std::result::Result<Self, anyhow::Error> {
        let contents = std::fs::read_to_string(path)?;
        let mut config: TriggerConfig = serde_yml::from_str(&contents)?;
        config.assign_rule_ids();
        config.validate()?;
        Ok(config)
    }

    /// Assigns stable, 1-indexed rule IDs based on position in the targets Vec.
    /// This is the single source of truth for rule_id assignment.
    fn assign_rule_ids(&mut self) {
        for (i, target) in self.targets.iter_mut().enumerate() {
            target.rule_id = (i + 1) as u32;
        }
    }

    fn validate(&self) -> std::result::Result<(), anyhow::Error> {
        for target in &self.targets {
            let comm = match &target.rule {
                MatchRule::Exact { comm } => comm,
                MatchRule::Prefix { comm } => comm,
            };
            if comm.len() > 15 {
                anyhow::bail!("Comm string '{}' exceeds 15 characters kernel limit", comm);
            }
            if target.threshold == 0 || target.threshold >= 100 {
                anyhow::bail!(
                    "Threshold {} for comm '{}' must be between 1 and 99 (inclusive)",
                    target.threshold,
                    comm
                );
            }
        }
        Ok(())
    }

    /// Returns the target for the given rule_id in O(1).
    /// Rule IDs are 1-indexed and assigned by `assign_rule_ids`.
    pub(crate) fn target_for_rule(&self, rule_id: u32) -> &TargetConfig {
        &self.targets[(rule_id as usize) - 1]
    }
}
