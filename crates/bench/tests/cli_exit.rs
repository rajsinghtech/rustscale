use std::process::Command;

fn bench() -> Command {
    Command::new(env!("CARGO_BIN_EXE_rustscale-bench"))
}

#[test]
fn contract_errors_use_exit_two() {
    let status = bench()
        .args(["client", "--target", "127.0.0.1:1"])
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(2));
}

#[test]
fn runtime_failures_use_exit_one() {
    let status = bench()
        .args([
            "client",
            "--transport",
            "kernel-tcp",
            "--target",
            "127.0.0.1:0",
        ])
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(1));
}
