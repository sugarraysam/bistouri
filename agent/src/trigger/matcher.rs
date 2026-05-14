use crate::trigger::config::{MatchRule, TriggerConfig};
use radix_trie::{Trie, TrieCommon};

#[derive(Debug, Clone, Copy)]
enum MatchKind {
    Exact,
    Prefix,
}

/// Matches process comm strings against configured rules using a radix trie.
///
/// Exact rules match only the exact comm string. Prefix rules match any comm
/// string that starts with the configured pattern. The trie provides O(L) lookup
/// where L is the length of the comm string.
///
/// Multiple rules may share the same comm pattern (e.g., same process monitored
/// for both Memory and CPU pressure). The trie stores a `Vec` of (rule_id, kind)
/// pairs per key to support this.
pub(crate) struct CommMatcher {
    trie: Trie<String, Vec<(u32, MatchKind)>>,
}

impl CommMatcher {
    pub(crate) fn new(config: &TriggerConfig) -> Self {
        let mut trie = Trie::new();
        for target in &config.targets {
            let (comm, kind) = match &target.rule {
                MatchRule::Exact { comm } => (comm.clone(), MatchKind::Exact),
                MatchRule::Prefix { comm } => (comm.clone(), MatchKind::Prefix),
            };
            trie.map_with_default(
                comm,
                |entries| entries.push((target.rule_id, kind)),
                vec![(target.rule_id, kind)],
            );
        }
        Self { trie }
    }

    /// Returns all rule_ids matching the given comm string.
    pub(crate) fn match_comm(&self, comm: &str) -> Vec<u32> {
        // Direct lookup: handles exact matches AND prefix rules where comm == pattern.
        if let Some(entries) = self.trie.get(comm) {
            return entries.iter().map(|(id, _)| *id).collect();
        }
        // Ancestor lookup: only valid for Prefix rules.
        if let Some(node) = self.trie.get_ancestor(comm) {
            if let Some(entries) = node.value() {
                return entries
                    .iter()
                    .filter(|(_, kind)| matches!(kind, MatchKind::Prefix))
                    .map(|(id, _)| *id)
                    .collect();
            }
        }
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trigger::config::{PsiResource, ResourceConfig, TargetConfig, TriggerConfig};
    use rstest::rstest;

    fn make_config(targets: Vec<TargetConfig>) -> TriggerConfig {
        TriggerConfig::try_new(targets).unwrap()
    }

    fn exact_target(comm: &str) -> TargetConfig {
        TargetConfig {
            rule: MatchRule::Exact {
                comm: comm.to_string(),
            },
            service_id: comm.to_string(),
            resources: vec![ResourceConfig {
                resource: PsiResource::Memory,
                threshold: 10.0,
            }],
            rule_id: 0,
            labels: Default::default(),
        }
    }

    fn prefix_target(comm: &str) -> TargetConfig {
        TargetConfig {
            rule: MatchRule::Prefix {
                comm: comm.to_string(),
            },
            service_id: format!("{}_svc", comm.replace('-', "_").trim_end_matches('_')),
            resources: vec![ResourceConfig {
                resource: PsiResource::Cpu,
                threshold: 10.0,
            }],
            rule_id: 0,
            labels: Default::default(),
        }
    }

    // -----------------------------------------------------------------------
    // Exact match — rstest table
    // -----------------------------------------------------------------------

    #[rstest]
    #[case::exact_hit("node", "node", true)]
    #[case::longer_string("node", "nodejs", false)]
    #[case::shorter_string("node", "nod", false)]
    #[case::completely_different("node", "python", false)]
    #[case::empty_input("node", "", false)]
    fn exact_match(#[case] pattern: &str, #[case] input: &str, #[case] should_match: bool) {
        let config = make_config(vec![exact_target(pattern)]);
        let matcher = CommMatcher::new(&config);
        assert_eq!(
            !matcher.match_comm(input).is_empty(),
            should_match,
            "exact pattern='{pattern}', input='{input}'",
        );
    }

    // -----------------------------------------------------------------------
    // Prefix match — rstest table
    // -----------------------------------------------------------------------

    #[rstest]
    #[case::prefix_extends("worker-", "worker-1", true)]
    #[case::prefix_extends_long("worker-", "worker-abc", true)]
    #[case::prefix_exact_pattern("worker-", "worker-", true)]
    #[case::shorter_than_prefix("worker-", "work", false)]
    #[case::one_char_short("worker-", "worker", false)]
    #[case::completely_different("worker-", "python", false)]
    fn prefix_match(#[case] pattern: &str, #[case] input: &str, #[case] should_match: bool) {
        let config = make_config(vec![prefix_target(pattern)]);
        let matcher = CommMatcher::new(&config);
        assert_eq!(
            !matcher.match_comm(input).is_empty(),
            should_match,
            "prefix pattern='{pattern}', input='{input}'",
        );
    }

    // -----------------------------------------------------------------------
    // Multi-rule matching
    // -----------------------------------------------------------------------

    #[test]
    fn multiple_rules_exact_and_prefix() {
        let config = make_config(vec![exact_target("node"), prefix_target("worker-")]);
        let matcher = CommMatcher::new(&config);
        assert_eq!(matcher.match_comm("node"), vec![1]);
        assert!(matcher.match_comm("nodejs").is_empty());
        assert_eq!(matcher.match_comm("worker-1"), vec![2]);
        assert!(matcher.match_comm("python").is_empty());
    }

    #[test]
    fn empty_config_matches_nothing() {
        // Empty config fails try_new, so build matcher directly.
        let matcher = CommMatcher { trie: Trie::new() };
        assert!(matcher.match_comm("anything").is_empty());
    }

    #[test]
    fn same_comm_multiple_targets() {
        let config = make_config(vec![
            TargetConfig {
                rule: MatchRule::Exact {
                    comm: "bistouri".to_string(),
                },
                service_id: "bistouri_mem".to_string(),
                resources: vec![ResourceConfig {
                    resource: PsiResource::Memory,
                    threshold: 10.0,
                }],
                rule_id: 0,
                labels: Default::default(),
            },
            TargetConfig {
                rule: MatchRule::Exact {
                    comm: "bistouri".to_string(),
                },
                service_id: "bistouri_cpu".to_string(),
                resources: vec![ResourceConfig {
                    resource: PsiResource::Cpu,
                    threshold: 10.0,
                }],
                rule_id: 0,
                labels: Default::default(),
            },
        ]);
        let matcher = CommMatcher::new(&config);
        let mut ids = matcher.match_comm("bistouri");
        ids.sort();
        assert_eq!(ids, vec![1, 2]);
    }
}
