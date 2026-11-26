//! Portable TimeShift identity and preview data. Storage, signatures, paths,
//! write authorization and guarded publication stay in native adapters.
use serde_json::{Value, json};

pub fn valid_id(id: &str) -> bool {
    id.len() == 32
        && id
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

#[derive(Debug, PartialEq, Eq)]
pub struct ChangedRegion {
    pub common_prefix_lines: usize,
    pub common_suffix_lines: usize,
    pub remove: String,
    pub insert: String,
}

impl ChangedRegion {
    pub fn to_json(&self) -> Value {
        json!({"common_prefix_lines":self.common_prefix_lines,
            "common_suffix_lines":self.common_suffix_lines,
            "remove":self.remove,"insert":self.insert})
    }
}

/// Linear-time changed line region, not a general-purpose diff algorithm.
pub fn changed_region(current: &str, restored: &str) -> ChangedRegion {
    let current: Vec<_> = current.split_inclusive('\n').collect();
    let restored: Vec<_> = restored.split_inclusive('\n').collect();
    let prefix = current
        .iter()
        .zip(&restored)
        .take_while(|(a, b)| a == b)
        .count();
    let suffix = current[prefix..]
        .iter()
        .rev()
        .zip(restored[prefix..].iter().rev())
        .take_while(|(a, b)| a == b)
        .count();
    ChangedRegion {
        common_prefix_lines: prefix,
        common_suffix_lines: suffix,
        remove: current[prefix..current.len() - suffix].concat(),
        insert: restored[prefix..restored.len() - suffix].concat(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn preview_preserves_line_endings_and_wire_keys() {
        assert_eq!(
            changed_region("a\nb\nc", "a\nx\nc").to_json(),
            json!({"common_prefix_lines":1,"common_suffix_lines":1,"remove":"b\n","insert":"x\n"})
        );
        assert_eq!(changed_region("", "text").insert, "text");
        assert_eq!(changed_region("same", "same").remove, "");
        assert_eq!(changed_region("a\r\n", "a\n").remove, "a\r\n");
    }
    #[test]
    fn checkpoint_identity_is_lowercase_and_exact_length() {
        assert!(valid_id(&"a".repeat(32)));
        assert!(!valid_id(&"A".repeat(32)));
        assert!(!valid_id(&"a".repeat(31)));
        assert!(!valid_id(&"g".repeat(32)));
    }
}
