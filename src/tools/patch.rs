//! Exact, hash-guarded text patches.

use sha2::{Digest, Sha256};

use super::filesystem::{MAX_TEXT_BYTES, MutationError, MutationRoot, read_text};
use super::write::{RecordStage, check_size, publish};
use MutationError::Rejected;

pub(super) fn apply_patch(
    root: &MutationRoot,
    path: &str,
    expected_sha256: &str,
    old: &str,
    new: &str,
    record_stage: &mut RecordStage<'_>,
) -> Result<String, MutationError> {
    if expected_sha256.len() != 64 || !expected_sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(Rejected("Expected a 64-digit SHA-256 value"));
    }
    check_size(old)?;
    check_size(new)?;
    if old.is_empty() {
        return Err(Rejected("Patch target must be nonempty"));
    }

    let target = root.target(path)?;
    let prior = target
        .metadata()?
        .ok_or(Rejected("Patch target does not exist"))?;
    let file = target.open_existing(&prior)?;
    let input = read_text(&file, &prior)?;
    if !expected_sha256.eq_ignore_ascii_case(&checksum(&input)) {
        return Err(Rejected("Patch conflict: SHA-256 does not match"));
    }

    let start = input
        .find(old)
        .ok_or(Rejected("Patch target text was not found"))?;
    // Start just after the first match's initial character to catch overlaps.
    let next = start
        + old
            .chars()
            .next()
            .expect("nonempty patch target")
            .len_utf8();
    if input[next..].contains(old) {
        return Err(Rejected("Patch target text occurs more than once"));
    }
    let size = input.len() - old.len() + new.len();
    if size > MAX_TEXT_BYTES {
        return Err(Rejected("Patched file exceeds the 65536-byte limit"));
    }
    let mut updated = String::with_capacity(size);
    updated.push_str(&input[..start]);
    updated.push_str(new);
    updated.push_str(&input[start + old.len()..]);

    publish(&target, Some((&file, &prior)), &updated, record_stage)?;
    Ok(checksum(&updated))
}

pub(super) fn edit_file(
    root: &MutationRoot,
    path: &str,
    target_text: &str,
    replacement: &str,
    replace_all: bool,
    record_stage: &mut RecordStage<'_>,
) -> Result<String, MutationError> {
    if target_text.is_empty() {
        return Err(Rejected("Target text must be nonempty"));
    }
    check_size(replacement)?;

    let target = root.target(path)?;
    let prior = target
        .metadata()?
        .ok_or(Rejected("Target file does not exist"))?;
    let file = target.open_existing(&prior)?;
    let input = read_text(&file, &prior)?;

    if !input.contains(target_text) {
        return Err(Rejected("Target text was not found in file"));
    }

    let updated = if replace_all {
        input.replace(target_text, replacement)
    } else {
        let start = input.find(target_text).expect("contains checked");
        let mut res = String::with_capacity(input.len() + replacement.len());
        res.push_str(&input[..start]);
        res.push_str(replacement);
        res.push_str(&input[start + target_text.len()..]);
        res
    };

    if updated.len() > MAX_TEXT_BYTES {
        return Err(Rejected("Updated file exceeds the 65536-byte limit"));
    }

    publish(&target, Some((&file, &prior)), &updated, record_stage)?;
    Ok(checksum(&updated))
}

pub(super) fn checksum(text: &str) -> String {
    format!("{:x}", Sha256::digest(text.as_bytes()))
}
