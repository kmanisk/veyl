//! Bounded, deterministic encoding for the audit ledger.

use std::io::{self, BufRead, Read};

use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

pub(super) const MAX_RECORD: usize = 16 * 1024;
const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Tip {
    pub sequence: u64,
    pub hash: String,
}

impl Default for Tip {
    fn default() -> Self {
        Self {
            sequence: 0,
            hash: GENESIS.to_owned(),
        }
    }
}

pub(super) fn seal(mut record: Value, tip: &Tip) -> io::Result<(Vec<u8>, Tip)> {
    let sequence = tip
        .sequence
        .checked_add(1)
        .ok_or_else(|| broken(u64::MAX))?;
    record["version"] = Value::from(1);
    record["sequence"] = Value::from(sequence);
    record["prev_hash"] = Value::from(tip.hash.clone());
    let hash = digest(&record)?;
    record["hash"] = Value::from(hash.clone());
    let mut bytes = serde_json::to_vec(&record)?;
    bytes.push(b'\n');
    if bytes.len() > MAX_RECORD {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "audit record exceeds size limit",
        ));
    }
    Ok((bytes, Tip { sequence, hash }))
}

fn digest(record: &Value) -> io::Result<String> {
    Ok(format!("{:x}", Sha256::digest(serde_json::to_vec(record)?)))
}

pub(super) fn read_line(reader: &mut impl BufRead, line: &mut Vec<u8>) -> io::Result<usize> {
    line.clear();
    reader.take(MAX_RECORD as u64 + 1).read_until(b'\n', line)
}

pub(super) fn verify_line(line: &[u8], tip: &Tip) -> io::Result<(Tip, Value)> {
    let sequence = tip
        .sequence
        .checked_add(1)
        .ok_or_else(|| broken(u64::MAX))?;
    let invalid = || broken(sequence);
    if line.len() > MAX_RECORD || !line.ends_with(b"\n") {
        return Err(invalid());
    }
    let bytes = &line[..line.len() - 1];
    let mut record: Value = serde_json::from_slice(bytes).map_err(|_| invalid())?;
    if serde_json::to_vec(&record)? != bytes
        || record.get("version").and_then(Value::as_u64) != Some(1)
        || record.get("sequence").and_then(Value::as_u64) != Some(sequence)
        || record.get("prev_hash").and_then(Value::as_str) != Some(&tip.hash)
    {
        return Err(invalid());
    }
    let hash = record
        .as_object_mut()
        .and_then(|record| record.remove("hash"))
        .and_then(|value| value.as_str().map(str::to_owned))
        .ok_or_else(invalid)?;
    if digest(&record)? != hash {
        return Err(invalid());
    }
    Ok((Tip { sequence, hash }, record))
}

pub(super) fn broken(sequence: u64) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("Broken audit chain or hash at sequence {sequence}"),
    )
}
