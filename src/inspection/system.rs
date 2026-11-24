//! On-demand kernel-backed Linux diagnostics. No shell, arbitrary paths,
//! environment dumps, or continuous sampling. Each section is bounded.
use crate::tools::MutationRoot;
use serde_json::{Map, Value, json};
use std::{
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
};

#[path = "live.rs"]
mod live;
const SECTIONS: [&str; 9] = [
    "resources",
    "gpu",
    "storage",
    "network",
    "audio",
    "bluetooth",
    "desktop",
    "sway",
    "services",
];
const MAX_ENTRIES: usize = 48;

fn text(path: impl AsRef<Path>) -> Option<String> {
    let mut buf = String::new();
    File::open(path)
        .ok()?
        .take(8193)
        .read_to_string(&mut buf)
        .ok()?;
    if buf.len() > 8192 {
        return None;
    }
    Some(buf.trim().to_owned())
}
fn number(path: impl AsRef<Path>) -> Option<u64> {
    text(path)?.parse().ok()
}
fn signed(path: impl AsRef<Path>) -> Option<i64> {
    text(path)?.parse().ok()
}
fn name(path: &Path) -> String {
    path.file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned()
}
fn link_name(path: impl AsRef<Path>) -> Option<String> {
    fs::read_link(path).ok().map(|p| name(&p))
}
fn inventory(
    path: &str,
    select: impl Fn(&Path) -> bool,
    collect: impl Fn(&Path) -> Value,
) -> Value {
    let Ok(entries) = fs::read_dir(path) else {
        return json!({"available":false,"source":path,"items":[],"truncated":false});
    };
    let mut paths: Vec<PathBuf> = Vec::new();
    let mut truncated = false;
    // Bound the traversal as well as the result count.
    for (i, entry) in entries.enumerate() {
        if i >= 512 {
            truncated = true;
            break;
        }
        let Ok(entry) = entry else {
            continue;
        };
        let p = entry.path();
        if !select(&p) {
            continue;
        }
        if paths.len() >= MAX_ENTRIES {
            truncated = true;
            break;
        }
        paths.push(p);
    }
    paths.sort();
    json!({"available":true,"source":path,"truncated":truncated,"items":paths.iter().map(|p| collect(p)).collect::<Vec<_>>()})
}
fn resources(root: Option<&MutationRoot>) -> Value {
    let mut v = super::system(root);
    v["uptime_seconds"] =
        json!(text("/proc/uptime").and_then(|s| s.split_whitespace().next()?.parse::<f64>().ok()));
    let mem = text("/proc/meminfo");
    let field = |key: &str| -> Option<u64> {
        mem.as_ref()?.lines().find_map(|line| {
            line.strip_prefix(key)?
                .split_whitespace()
                .next()?
                .parse()
                .ok()
        })
    };
    v["swap_total_kib"] = json!(field("SwapTotal:"));
    v["swap_free_kib"] = json!(field("SwapFree:"));
    v["pressure"] = json!({
        "cpu": text("/proc/pressure/cpu"),
        "memory": text("/proc/pressure/memory"),
        "io": text("/proc/pressure/io")
    });
    let mut cpuinfo = String::new();
    if let Ok(file) = File::open("/proc/cpuinfo") {
        let _ = file.take(8192).read_to_string(&mut cpuinfo);
    }
    v["cpu_model"] = json!(cpuinfo.lines().find_map(|l| {
        l.strip_prefix("model name")?
            .split_once(':')
            .map(|(_, v)| v.trim().to_owned())
    }));
    v["thermal"] = inventory(
        "/sys/class/thermal",
        |p| name(p).starts_with("thermal_zone"),
        |p| json!({"id":name(p),"type":text(p.join("type")),"temperature_millicelsius":signed(p.join("temp"))}),
    );
    v["power"] = inventory(
        "/sys/class/power_supply",
        |_| true,
        |p| json!({"name":name(p),"type":text(p.join("type")),"status":text(p.join("status")),"capacity_percent":number(p.join("capacity")),"online":number(p.join("online"))}),
    );
    v
}
fn gpu() -> Value {
    inventory(
        "/sys/bus/pci/devices",
        |p| text(p.join("class")).is_some_and(|v| v.starts_with("0x03")),
        |p| {
            // Do not wake a suspended discrete GPU for telemetry.
            let runtime = text(p.join("power/runtime_status"));
            let awake = runtime.as_deref() == Some("active");
            json!({"pci_address":name(p),"vendor_id":text(p.join("vendor")),"device_id":text(p.join("device")),
            "class":text(p.join("class")),"driver":link_name(p.join("driver")),
            "runtime_status":runtime,
            "busy_percent":awake.then(||number(p.join("gpu_busy_percent"))).flatten(),
            "vram_total_bytes":awake.then(||number(p.join("mem_info_vram_total"))).flatten(),
            "vram_used_bytes":awake.then(||number(p.join("mem_info_vram_used"))).flatten()})
        },
    )
}
fn storage(root: Option<&MutationRoot>) -> Value {
    json!({"workspace_filesystem":super::system(root)["workspace_filesystem"],
    "devices":inventory("/sys/class/block", |p|!name(p).starts_with("loop"), |p|{
        json!({"name":name(p),"size_bytes":number(p.join("size")).and_then(|v|v.checked_mul(512)),
          "partition":number(p.join("partition")),"read_only":number(p.join("ro")).map(|v|v!=0),
          "removable":number(p.join("removable")).map(|v|v!=0),
          "rotational":number(p.join("queue/rotational")).map(|v|v!=0),"model":text(p.join("device/model"))})
    })})
}
fn network() -> Value {
    inventory(
        "/sys/class/net",
        |_| true,
        |p| {
            json!({"interface":name(p),"state":text(p.join("operstate")),
        "mtu":number(p.join("mtu")),"carrier":number(p.join("carrier")).map(|v|v!=0),
        "rx_bytes":number(p.join("statistics/rx_bytes")),"tx_bytes":number(p.join("statistics/tx_bytes"))})
        },
    )
}
fn audio() -> Value {
    inventory(
        "/sys/class/sound",
        |p| {
            name(p)
                .strip_prefix("card")
                .is_some_and(|v| v.parse::<u32>().is_ok())
        },
        |p| json!({"card":name(p),"id":text(p.join("id")),"driver":link_name(p.join("device/driver"))}),
    )
}
fn bluetooth() -> Value {
    inventory(
        "/sys/class/bluetooth",
        |p| {
            name(p)
                .strip_prefix("hci")
                .is_some_and(|v| v.parse::<u32>().is_ok())
        },
        |p| json!({"adapter":name(p),"driver":link_name(p.join("device/driver"))}),
    )
}
fn desktop() -> Value {
    inventory(
        "/sys/class/drm",
        |p| name(p).starts_with("card") && name(p).contains('-'),
        |p| {
            let status = text(p.join("status"));
            let connected = status.as_deref() == Some("connected");
            let modes = if connected {
                text(p.join("modes"))
                    .map(|s| s.lines().take(32).map(str::to_owned).collect::<Vec<_>>())
            } else {
                None
            };
            json!({"connector":name(p),"status":status,"enabled":text(p.join("enabled")),"supported_modes":modes})
        },
    )
}
pub(super) fn inspect(
    args: &Map<String, Value>,
    root: Option<&MutationRoot>,
) -> Result<Value, String> {
    if args.keys().any(|k| k != "sections") {
        return Err("Unexpected system_inspect argument".into());
    }
    let sections: Vec<&str> = match args.get("sections") {
        None => vec!["resources"],
        Some(value) => {
            let list = value
                .as_array()
                .filter(|v| !v.is_empty() && v.len() <= SECTIONS.len())
                .ok_or("Expected 1 to 9 subsystem names")?;
            let mut sections = Vec::new();
            for v in list {
                let s = v
                    .as_str()
                    .filter(|s| SECTIONS.contains(s))
                    .ok_or("Unknown subsystem")?;
                if sections.contains(&s) {
                    return Err("Duplicate subsystem".into());
                }
                sections.push(s);
            }
            sections
        }
    };
    let mut result = Map::new();
    for s in sections {
        result.insert(
            s.into(),
            match s {
                "resources" => resources(root),
                "gpu" => gpu(),
                "storage" => storage(root),
                "network" => network(),
                "audio" => { let mut v=audio();v["session"]=live::audio();v },
                "bluetooth" => { let mut v=bluetooth();v["session"]=live::bluetooth();v },
                "desktop" => desktop(),
                "sway" => live::sway(),
                "services" => live::services(),
                _ => unreachable!(),
            },
        );
    }
    Ok(
        json!({"schema_version":1,"read_only":true,"sections":result,
        "limitations":"Kernel inventory plus fixed read-only session probes. Unavailable components are explicit. GPU telemetry does not wake suspended GPUs. No journal contents or arbitrary commands."}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn strict_sections_and_native_resources() {
        assert!(
            inspect(
                json!({"sections":["/etc/passwd"]}).as_object().unwrap(),
                None
            )
            .is_err()
        );
        assert!(inspect(json!({"sections":["gpu","gpu"]}).as_object().unwrap(), None).is_err());
        assert!(inspect(json!({"path":"/tmp"}).as_object().unwrap(), None).is_err());
        let result=inspect(json!({"sections":["resources","gpu","storage","network","audio","bluetooth","desktop"]}).as_object().unwrap(),None).unwrap();
        assert_eq!(result["read_only"], true);
        assert!(
            result["sections"]["resources"]["memory_total_kib"]
                .as_u64()
                .is_some_and(|v| v > 0)
        );
        assert!(result["sections"]["gpu"]["items"].is_array());
        assert!(result["sections"]["storage"]["devices"]["items"].is_array());
        assert!(result["sections"]["network"]["items"].is_array());
    }
}
