use std::path::PathBuf;
use std::process::{Command, Output};

fn rustscale_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rustscale"))
}

fn run(args: &[&str]) -> Output {
    Command::new(rustscale_bin())
        .args(args)
        .output()
        .expect("failed to run rustscale")
}

fn stdout_lines(args: &[&str]) -> Vec<String> {
    let output = run(args);
    assert!(
        output.status.success(),
        "rustscale {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("completion output should be UTF-8")
        .lines()
        .map(str::to_owned)
        .collect()
}

#[test]
fn generates_bash_zsh_and_fish_scripts() {
    for (shell, marker) in [
        ("bash", "complete -F _rustscale_completion rustscale"),
        ("zsh", "compdef _rustscale_completion rustscale"),
        ("fish", "complete -c rustscale"),
    ] {
        let output = run(&["completion", shell]);
        assert!(output.status.success(), "{shell} generation failed");
        let script = String::from_utf8(output.stdout).expect("script should be UTF-8");
        assert!(script.contains(marker), "missing {shell} registration");
        assert!(script.contains("rustscale __complete --"));
        assert!(output.stderr.is_empty());
    }
}

#[test]
fn hidden_command_completes_top_level_and_nested_contexts() {
    assert_eq!(stdout_lines(&["__complete", "--", "st"]), ["status"]);
    assert_eq!(
        stdout_lines(&["__complete", "--", "file", ""]),
        ["cp", "get"]
    );
    assert_eq!(stdout_lines(&["__complete", "--", "wa"]), ["wait"]);
    assert_eq!(stdout_lines(&["__complete", "--", "n"]), ["netcheck", "nc"]);
    assert!(stdout_lines(&["__complete", "--", "nc", "peer", ""]).is_empty());
    assert_eq!(
        stdout_lines(&["__complete", "--", "wait", "--time"]),
        ["--timeout"]
    );
    assert_eq!(
        stdout_lines(&["__complete", "--", "drive", "sh"]),
        ["share"]
    );
    assert_eq!(
        stdout_lines(&["__complete", "--", "dns", ""]),
        ["status", "query"]
    );
    assert_eq!(stdout_lines(&["__complete", "--", "dns", "q"]), ["query"]);
    assert_eq!(
        stdout_lines(&["__complete", "--", "drive", "st"]),
        ["status"]
    );
}

#[test]
fn hidden_command_completes_flags_and_equals_values() {
    assert_eq!(
        stdout_lines(&["__complete", "--", "status", "--act"]),
        ["--active"]
    );
    assert_eq!(
        stdout_lines(&["__complete", "--", "file", "get", "--conflict=r",]),
        ["--conflict=rename"]
    );
}

#[test]
fn hidden_command_is_quiet_for_unknown_and_stopped_inputs() {
    assert!(stdout_lines(&["__complete", "--", "unknown", ""]).is_empty());
    assert!(stdout_lines(&["__complete", "--", "ping", "peer", "--t"]).is_empty());
    assert!(stdout_lines(&["__complete", "--", "status", "--", ""]).is_empty());
}
