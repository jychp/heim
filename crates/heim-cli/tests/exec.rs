use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

static TEMP_DIR_COUNTER: AtomicUsize = AtomicUsize::new(0);

#[test]
fn exec_binary_runs_allowed_command() {
    let temp = TempDir::new();
    let policy = temp.write_policy(
        r#"
[[grants]]
name = "test.run"
provider = "test.provider"
allow = ["*"]
commands = ["rustc *"]
approval = "grant"
"#,
    );

    let output = heim_command(temp.path())
        .args([
            "exec",
            "--file",
            policy.to_str().expect("policy path"),
            "test.run",
            "--",
            "rustc",
            "--version",
        ])
        .output()
        .expect("heim command output");

    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert!(stdout(&output).starts_with("rustc "));
    assert!(stderr(&output).is_empty());
}

#[test]
fn exec_binary_reports_spawn_failure() {
    let temp = TempDir::new();
    let policy = temp.write_policy(
        r#"
[[grants]]
name = "test.missing"
provider = "test.provider"
allow = ["*"]
commands = ["heim-missing-command-for-test"]
approval = "grant"
"#,
    );

    let output = heim_command(temp.path())
        .args([
            "exec",
            "--file",
            policy.to_str().expect("policy path"),
            "test.missing",
            "--",
            "heim-missing-command-for-test",
        ])
        .output()
        .expect("heim command output");

    assert_eq!(output.status.code(), Some(1));
    assert!(stdout(&output).is_empty());
    assert!(
        stderr(&output).contains("failed to execute command heim-missing-command-for-test"),
        "stderr: {}",
        stderr(&output)
    );
}

fn heim_command(config_root: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_heim"));
    command
        .env("XDG_CONFIG_HOME", config_root.join("xdg"))
        .env("HOME", config_root.join("home"))
        .env("APPDATA", config_root.join("appdata"));
    command
}

fn stdout(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new() -> Self {
        let id = TEMP_DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("heim-cli-exec-test-{}-{id}", std::process::id()));
        fs::create_dir_all(&path).expect("temp dir");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn write_policy(&self, contents: &str) -> PathBuf {
        let path = self.path.join("policy.toml");
        fs::write(&path, contents).expect("policy file");
        path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}
