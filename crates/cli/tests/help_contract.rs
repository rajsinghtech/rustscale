use std::process::Command;

fn invoke(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_rustscale"))
        .args(args)
        .output()
        .expect("run CLI")
}

#[test]
fn command_help_spellings_are_offline_successful_and_stdout_only() {
    for args in [["status", "--help"], ["help", "status"]] {
        let output = invoke(&args);
        assert!(output.status.success(), "{args:?}: {output:?}");
        assert_eq!(
            String::from_utf8_lossy(&output.stdout),
            "usage: tailscale status [--json] [--peers=true|false] [--active]\n"
        );
        assert!(output.stderr.is_empty(), "{args:?}: {output:?}");
    }
}

#[test]
fn invalid_command_is_nonzero_and_stderr_only() {
    let output = invoke(&["definitely-not-a-command"]);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("unknown subcommand 'definitely-not-a-command'"));
}
