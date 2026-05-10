use crate::agent::profiler::TASK_COMM_LEN;
use crate::trigger::config::{MatchRule, TriggerConfig};
use crate::trigger::error::{Result, TriggerError};
use libbpf_rs::MapCore;

/// Layout-compatible with the BPF `struct comm_lpm_key` in profiler.h.
#[repr(C)]
struct CommLpmKey {
    prefixlen: u32,
    comm: [u8; TASK_COMM_LEN],
}

impl CommLpmKey {
    fn to_bytes(&self) -> &[u8] {
        // SAFETY: CommLpmKey is #[repr(C)] with no padding ambiguity.
        // The struct is trivially copyable and the returned slice borrows self.
        unsafe {
            std::slice::from_raw_parts(
                (self as *const CommLpmKey) as *const u8,
                std::mem::size_of::<CommLpmKey>(),
            )
        }
    }

    fn from_rule(rule: &MatchRule) -> Self {
        let mut key = CommLpmKey {
            prefixlen: 0,
            comm: [0; TASK_COMM_LEN],
        };
        match rule {
            MatchRule::Exact { comm } => {
                let bytes = comm.as_bytes();
                key.comm[..bytes.len()].copy_from_slice(bytes);
                // +1 accounts for the NUL terminator position, differentiating
                // "node" from "nodejs" at the bit-prefix level.
                key.prefixlen = ((bytes.len() + 1) * 8) as u32;
            }
            MatchRule::Prefix { comm } => {
                let bytes = comm.as_bytes();
                key.comm[..bytes.len()].copy_from_slice(bytes);
                key.prefixlen = (bytes.len() * 8) as u32;
            }
        }
        key
    }
}

/// Owns a `MapHandle` to the BPF `comm_lpm_trie` map and tracks inserted
/// keys on the Rust side to avoid relying on kernel-side LPM trie iteration.
pub(crate) struct BpfTrie {
    map: libbpf_rs::MapHandle,
    inserted_keys: Vec<Vec<u8>>,
}

impl BpfTrie {
    pub(crate) fn new(map: libbpf_rs::MapHandle) -> Self {
        Self {
            map,
            inserted_keys: Vec::new(),
        }
    }

    /// Clears all existing entries and repopulates from the given config.
    pub(crate) fn repopulate(&mut self, config: &TriggerConfig) -> Result<()> {
        // Delete previously inserted keys. Ignore ENOENT — the entry may
        // have been removed by a concurrent BPF program (harmless race).
        for key in self.inserted_keys.drain(..) {
            let _ = self.map.delete(&key);
        }

        for target in &config.targets {
            let key = CommLpmKey::from_rule(&target.rule);
            let key_bytes = key.to_bytes();

            self.map
                .update(
                    key_bytes,
                    &target.rule_id.to_ne_bytes(),
                    libbpf_rs::MapFlags::ANY,
                )
                .map_err(TriggerError::BpfTrieUpdate)?;

            self.inserted_keys.push(key_bytes.to_vec());
        }

        Ok(())
    }
}
