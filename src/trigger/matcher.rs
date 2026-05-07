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
    use crate::trigger::config::{PsiResource, TargetConfig, TriggerConfig};

    fn make_config(targets: Vec<TargetConfig>) -> TriggerConfig {
        TriggerConfig::try_new(targets).unwrap()
    }

    fn exact_target(comm: &str, rule_id: u32) -> TargetConfig {
        TargetConfig {
            rule: MatchRule::Exact {
                comm: comm.to_string(),
            },
            resource: PsiResource::Memory,
            threshold: 10,
            rule_id,
        }
    }

    fn prefix_target(comm: &str, rule_id: u32) -> TargetConfig {
        TargetConfig {
            rule: MatchRule::Prefix {
                comm: comm.to_string(),
            },
            resource: PsiResource::Cpu,
            threshold: 10,
            rule_id,
        }
    }

    #[test]
    fn exact_match_succeeds() {
        let config = make_config(vec![exact_target("node", 1)]);
        let matcher = CommMatcher::new(&config);
        assert_eq!(matcher.match_comm("node"), vec![1]);
    }

    #[test]
    fn exact_match_rejects_longer_string() {
        let config = make_config(vec![exact_target("node", 1)]);
        let matcher = CommMatcher::new(&config);
        assert!(matcher.match_comm("nodejs").is_empty());
    }

    #[test]
    fn exact_match_rejects_shorter_string() {
        let config = make_config(vec![exact_target("node", 1)]);
        let matcher = CommMatcher::new(&config);
        assert!(matcher.match_comm("nod").is_empty());
    }

    #[test]
    fn prefix_match_succeeds() {
        let config = make_config(vec![prefix_target("worker-", 0)]);
        let matcher = CommMatcher::new(&config);
        assert_eq!(matcher.match_comm("worker-1"), vec![1]);
        assert_eq!(matcher.match_comm("worker-abc"), vec![1]);
    }

    #[test]
    fn prefix_match_exact_pattern_succeeds() {
        let config = make_config(vec![prefix_target("worker-", 0)]);
        let matcher = CommMatcher::new(&config);
        assert_eq!(matcher.match_comm("worker-"), vec![1]);
    }

    #[test]
    fn prefix_match_rejects_non_prefix() {
        let config = make_config(vec![prefix_target("worker-", 0)]);
        let matcher = CommMatcher::new(&config);
        assert!(matcher.match_comm("work").is_empty());
        assert!(matcher.match_comm("worker").is_empty());
    }

    #[test]
    fn no_match_returns_empty() {
        let config = make_config(vec![exact_target("node", 1)]);
        let matcher = CommMatcher::new(&config);
        assert!(matcher.match_comm("python").is_empty());
    }

    #[test]
    fn multiple_rules_exact_and_prefix() {
        let config = make_config(vec![exact_target("node", 0), prefix_target("worker-", 0)]);
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
    fn same_comm_multiple_rules() {
        let config = make_config(vec![
            exact_target("bistouri", 1),
            TargetConfig {
                rule: MatchRule::Exact {
                    comm: "bistouri".to_string(),
                },
                resource: PsiResource::Cpu,
                threshold: 10,
                rule_id: 2,
            },
        ]);
        let matcher = CommMatcher::new(&config);
        let mut ids = matcher.match_comm("bistouri");
        ids.sort();
        assert_eq!(ids, vec![1, 2]);
    }
}
