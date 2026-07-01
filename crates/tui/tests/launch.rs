use std::process::Command;

#[test]
fn bastion_binary_starts_from_the_workspace() {
    let output = Command::new(env!("CARGO_BIN_EXE_bastion-tui"))
        .output()
        .expect("bastion binary should run");

    assert!(
        output.status.success(),
        "bastion should exit successfully: {output:?}"
    );

    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf-8");
    assert_eq!("Bastion\n", stdout);
}
