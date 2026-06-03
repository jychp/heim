use std::process::Command;

#[test]
fn heimd_binary_reports_ok() {
    let output = Command::new(env!("CARGO_BIN_EXE_heimd"))
        .arg("doctor")
        .output()
        .expect("heimd command output");

    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert_eq!(stdout(&output), "heimd: ok\n");
    assert!(stderr(&output).is_empty());
}

fn stdout(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}
