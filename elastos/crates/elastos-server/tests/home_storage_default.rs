//! N0: each storage default lives under the person's Home. Every test runs the
//! real `elastos` binary with a cleared environment whose HOME is a temp dir,
//! and puts a file where the Home storage directory belongs. The entry point
//! must then refuse, naming that exact path. A `/tmp/elastos/storage` default
//! opens storage elsewhere, so the Home path never appears.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

struct Home {
    temp: tempfile::TempDir,
    home: PathBuf,
    data: PathBuf,
}

impl Home {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("home");
        #[cfg(target_os = "macos")]
        let data = home.join("Library/Application Support/elastos");
        #[cfg(not(target_os = "macos"))]
        let data = home.join(".local/share/elastos");
        std::fs::create_dir_all(&data).unwrap();
        std::fs::write(data.join("storage"), b"not a directory").unwrap();
        Self { temp, home, data }
    }

    fn capsule(&self, manifest: Option<&str>) -> PathBuf {
        let dir = self.temp.path().join("capsule");
        std::fs::create_dir_all(&dir).unwrap();
        if let Some(manifest) = manifest {
            std::fs::write(dir.join("capsule.json"), manifest).unwrap();
        }
        dir
    }

    /// Runs `elastos <args>` until it exits, or kills its group at the deadline.
    fn run(&self, args: &[&str]) -> String {
        let mut child = Command::new(env!("CARGO_BIN_EXE_elastos"))
            .args(args)
            .env_clear()
            .env("HOME", &self.home)
            .env("XDG_DATA_HOME", self.home.join(".local/share"))
            .env("PATH", self.temp.path().join("no-bin"))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut pipe = child.stderr.take().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut text = String::new();
            let _ = pipe.read_to_string(&mut text);
            let _ = tx.send(text);
        });
        let deadline = Instant::now() + Duration::from_secs(60);
        while child.try_wait().unwrap().is_none() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
        }
        unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL) };
        let _ = child.kill();
        let _ = child.wait();
        rx.recv_timeout(Duration::from_secs(10)).unwrap_or_default()
    }
}

fn assert_refused_at(stderr: &str, storage: &Path) {
    let expected = format!("cannot open storage {}", storage.display());
    assert!(
        stderr.contains(&expected),
        "want {expected:?}; stderr:\n{stderr}"
    );
}

#[test]
fn run_without_manifest_defaults_storage_to_home() {
    let home = Home::new();
    let capsule = home.capsule(None);
    let stderr = home.run(&["run", capsule.to_str().unwrap()]);
    assert_refused_at(&stderr, &home.data.join("storage"));
}

#[test]
fn run_data_capsule_defaults_storage_to_home() {
    let home = Home::new();
    let capsule = home.capsule(Some(
        r#"{"schema":"elastos.capsule/v1","name":"n0-data","version":"0.1.0",
            "description":"N0 fixture","author":"ElastOS","role":"content",
            "type":"data","entrypoint":"index.html"}"#,
    ));
    let stderr = home.run(&["run", capsule.to_str().unwrap()]);
    assert_refused_at(&stderr, &home.data.join("storage"));
}
