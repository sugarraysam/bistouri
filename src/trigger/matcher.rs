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
pub(crate) struct CommMatcher {
    trie: Trie<String, (u32, MatchKind)>,
}

impl CommMatcher {
    pub(crate) fn new(config: &TriggerConfig) -> Self {
        let mut trie = Trie::new();
        for target in &config.targets {
            let (comm, kind) = match &target.rule {
                MatchRule::Exact { comm } => (comm.clone(), MatchKind::Exact),
                MatchRule::Prefix { comm } => (comm.clone(), MatchKind::Prefix),
            };
            trie.insert(comm, (target.rule_id, kind));
        }
        Self { trie }
    }

    /// Returns the rule_id of the first matching rule for the given comm string.
    pub(crate) fn match_comm(&self, comm: &str) -> Option<u32> {
        // Direct lookup: handles exact matches AND prefix rules where comm == pattern.
        if let Some((rule_id, _)) = self.trie.get(comm) {
            return Some(*rule_id);
        }
        // Ancestor lookup: only valid for Prefix rules.
        // Filters out false positives like Exact("node") matching "nodejs".
        if let Some(node) = self.trie.get_ancestor(comm) {
            if let Some((rule_id, MatchKind::Prefix)) = node.value() {
                return Some(*rule_id);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trigger::config::{PsiResource, TargetConfig, TriggerConfig};

    fn make_config(targets: Vec<TargetConfig>) -> TriggerConfig {
        TriggerConfig { targets }
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
        assert_eq!(matcher.match_comm("node"), Some(1));
    }

    #[test]
    fn exact_match_rejects_longer_string() {
        let config = make_config(vec![exact_target("node", 1)]);
        let matcher = CommMatcher::new(&config);
        assert_eq!(matcher.match_comm("nodejs"), None);
    }

    #[test]
    fn exact_match_rejects_shorter_string() {
        let config = make_config(vec![exact_target("node", 1)]);
        let matcher = CommMatcher::new(&config);
        assert_eq!(matcher.match_comm("nod"), None);
    }

    #[test]
    fn prefix_match_succeeds() {
        let config = make_config(vec![prefix_target("worker-", 2)]);
        let matcher = CommMatcher::new(&config);
        assert_eq!(matcher.match_comm("worker-1"), Some(2));
        assert_eq!(matcher.match_comm("worker-abc"), Some(2));
    }

    #[test]
    fn prefix_match_exact_pattern_succeeds() {
        let config = make_config(vec![prefix_target("worker-", 2)]);
        let matcher = CommMatcher::new(&config);
        assert_eq!(matcher.match_comm("worker-"), Some(2));
    }

    #[test]
    fn prefix_match_rejects_non_prefix() {
        let config = make_config(vec![prefix_target("worker-", 2)]);
        let matcher = CommMatcher::new(&config);
        assert_eq!(matcher.match_comm("work"), None);
        assert_eq!(matcher.match_comm("worker"), None);
    }

    #[test]
    fn no_match_returns_none() {
        let config = make_config(vec![exact_target("node", 1)]);
        let matcher = CommMatcher::new(&config);
        assert_eq!(matcher.match_comm("python"), None);
    }

    #[test]
    fn multiple_rules_exact_and_prefix() {
        let config = make_config(vec![exact_target("node", 1), prefix_target("worker-", 2)]);
        let matcher = CommMatcher::new(&config);
        assert_eq!(matcher.match_comm("node"), Some(1));
        assert_eq!(matcher.match_comm("nodejs"), None);
        assert_eq!(matcher.match_comm("worker-1"), Some(2));
        assert_eq!(matcher.match_comm("python"), None);
    }

    #[test]
    fn empty_config_matches_nothing() {
        let config = make_config(vec![]);
        let matcher = CommMatcher::new(&config);
        assert_eq!(matcher.match_comm("anything"), None);
    }
}
