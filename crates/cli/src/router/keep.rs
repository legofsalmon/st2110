//! What the router keeps between runs: the log of connections made from its page, and
//! the demo facility's connections, in one small JSON file (`--state`), so that a
//! restart loses neither.
//!
//! The file holds one section per registry, keyed by its Query API URL (`demo` for the
//! demo facility), so that routers for different registries can share it. Each write
//! reads the file again and replaces only this router's section, and lands whole: it is
//! written beside the file and renamed over it.

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The most log entries kept for each registry.
pub(crate) const LOG_LIMIT: usize = 200;

/// The file's layout version.
const VERSION: u32 = 1;

/// One registry's section.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub(crate) struct Section {
    /// Each take, oldest first: what was asked for, and what happened.
    #[serde(default)]
    pub log: Vec<Value>,
    /// The demo facility's Receivers, as [`super::demo::Facility::export`] gives them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub demo: Option<Value>,
}

#[derive(Default, Serialize, Deserialize)]
struct File {
    version: u32,
    #[serde(default)]
    registries: BTreeMap<String, Section>,
}

/// The state file, or none with `--no-state`.
pub(crate) struct Keeper {
    path: Option<PathBuf>,
    key: String,
    /// Held while the file is written, so that two writes from this router do not cross.
    writing: Mutex<()>,
}

impl Keeper {
    pub(crate) fn new(path: Option<PathBuf>, key: &str) -> Self {
        Self { path, key: key.to_string(), writing: Mutex::new(()) }
    }

    pub(crate) fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// This router's section, as kept. A file that cannot be read is put aside, with a
    /// warning, rather than written over.
    pub(crate) fn load(&self) -> Section {
        let Some(path) = &self.path else {
            return Section::default();
        };
        match read(path) {
            Ok(mut file) => file.registries.remove(&self.key).unwrap_or_default(),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Section::default(),
            Err(e) => {
                let aside = path.with_extension("unreadable.json");
                let moved = fs::rename(path, &aside).is_ok();
                eprintln!(
                    "st2110: {} cannot be read ({e}), so the router starts with nothing kept{}",
                    path.display(),
                    if moved { format!("; it is now {}", aside.display()) } else { String::new() }
                );
                Section::default()
            }
        }
    }

    /// Changes this router's section and writes the file.
    pub(crate) fn update(&self, change: impl FnOnce(&mut Section)) {
        let Some(path) = &self.path else { return };
        let Ok(_writing) = self.writing.lock() else { return };
        let mut file = read(path).unwrap_or_default();
        file.version = VERSION;
        let section = file.registries.entry(self.key.clone()).or_default();
        change(section);
        if section.log.len() > LOG_LIMIT {
            let extra = section.log.len() - LOG_LIMIT;
            section.log.drain(..extra);
        }
        if let Err(e) = write(path, &file) {
            eprintln!("st2110: {} cannot be written, so this is not kept: {e}", path.display());
        }
    }
}

fn read(path: &Path) -> io::Result<File> {
    let text = fs::read_to_string(path)?;
    let file: File = serde_json::from_str(&text).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    if file.version > VERSION {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "written by a newer st2110"));
    }
    Ok(file)
}

fn write(path: &Path, file: &File) -> io::Result<()> {
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        fs::create_dir_all(dir)?;
    }
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".{}.tmp", std::process::id()));
    let temporary = path.with_file_name(name);
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    // The log names the facility's devices: for this user's eyes.
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let result = (|| {
        let mut out = options.open(&temporary)?;
        out.write_all(serde_json::to_string_pretty(file).map_err(io::Error::other)?.as_bytes())?;
        out.write_all(b"\n")?;
        out.sync_all()?;
        fs::rename(&temporary, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

/// Where the router keeps its state unless told: this user's application data.
pub(crate) fn default_path() -> Option<PathBuf> {
    let home = || std::env::var_os("HOME").filter(|h| !h.is_empty()).map(PathBuf::from);
    let dir = if cfg!(target_os = "macos") {
        home()?.join("Library/Application Support/st2110")
    } else if cfg!(windows) {
        PathBuf::from(std::env::var_os("LOCALAPPDATA")?).join("st2110")
    } else {
        match std::env::var_os("XDG_STATE_HOME").filter(|d| !d.is_empty()) {
            Some(dir) => PathBuf::from(dir).join("st2110"),
            None => home()?.join(".local/state/st2110"),
        }
    };
    Some(dir.join("router.json"))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn keeps_each_registry_apart_and_trims_the_log() {
        let dir = std::env::temp_dir().join(format!("st2110-keep-{}", std::process::id()));
        let path = dir.join("router.json");
        let demo = Keeper::new(Some(path.clone()), "demo");
        let other = Keeper::new(Some(path.clone()), "http://registry.example/");
        assert_eq!(demo.load(), Section::default());
        for n in 0..LOG_LIMIT + 5 {
            demo.update(|s| s.log.push(json!({"n": n})));
        }
        demo.update(|s| s.demo = Some(json!({"receivers": {}})));
        other.update(|s| s.log.push(json!({"n": "other"})));
        let kept = demo.load();
        assert_eq!(kept.log.len(), LOG_LIMIT);
        assert_eq!(kept.log[0], json!({"n": 5}));
        assert_eq!(kept.demo, Some(json!({"receivers": {}})));
        assert_eq!(other.load().log, vec![json!({"n": "other"})]);
        // A file it cannot read is put aside, not written over.
        fs::write(&path, "not json").unwrap();
        assert_eq!(demo.load(), Section::default());
        assert!(dir.join("router.unreadable.json").exists());
        assert!(Keeper::new(None, "demo").path().is_none());
        let _ = fs::remove_dir_all(&dir);
    }
}
