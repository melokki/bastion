#![cfg(unix)]

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

#[test]
fn install_script_installs_bastion_from_default_git_repo() {
    let fixture = InstallFixture::new("default");

    let output = fixture.run_script(&[]);

    assert!(
        output.status.success(),
        "installer should succeed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let cargo_args = fixture.cargo_args();
    let cargo_args_lines = fixture.cargo_args_lines();
    assert!(cargo_args.contains("install"));
    assert!(cargo_args.contains("--git"));
    assert!(cargo_args.contains("https://codeberg.org/melokki/bastion.git"));
    assert!(cargo_args.contains("--branch"));
    assert!(cargo_args.contains("main"));
    assert!(cargo_args.contains("--locked"));
    assert!(cargo_args.contains("--bin"));
    assert!(cargo_args.contains("bastion"));
    assert!(cargo_args.contains("--root"));
    assert!(cargo_args.contains(fixture.home().join(".cargo").to_str().unwrap()));
    assert_eq!(Some("bastion"), cargo_args_lines.last().map(String::as_str));
    assert!(fixture.home().join(".cargo/bin/bastion").is_file());
}

#[test]
fn install_script_respects_repo_branch_and_install_root_overrides() {
    let fixture = InstallFixture::new("overrides");
    let install_root = fixture.root().join("custom-root");

    let output = fixture.run_script(&[
        (
            "BASTION_REPO_URL",
            "ssh://git@codeberg.org/melokki/bastion.git",
        ),
        ("BASTION_BRANCH", "release/v0.1"),
        ("BASTION_INSTALL_ROOT", install_root.to_str().unwrap()),
    ]);

    assert!(
        output.status.success(),
        "installer should succeed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let cargo_args = fixture.cargo_args();
    let cargo_args_lines = fixture.cargo_args_lines();
    assert!(cargo_args.contains("ssh://git@codeberg.org/melokki/bastion.git"));
    assert!(cargo_args.contains("release/v0.1"));
    assert!(cargo_args.contains(install_root.to_str().unwrap()));
    assert_eq!(Some("bastion"), cargo_args_lines.last().map(String::as_str));
    assert!(install_root.join("bin/bastion").is_file());
}

struct InstallFixture {
    root: PathBuf,
    home: PathBuf,
    fake_bin: PathBuf,
    cargo_log: PathBuf,
}

impl InstallFixture {
    fn new(name: &str) -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "bastion-install-test-{name}-{}-{unique}",
            std::process::id()
        ));
        let home = root.join("home");
        let fake_bin = root.join("bin");
        let cargo_log = root.join("cargo-args");

        fs::create_dir_all(&home).expect("home should be created");
        fs::create_dir_all(&fake_bin).expect("fake bin should be created");
        write_executable(
            &fake_bin.join("git"),
            r#"#!/usr/bin/env bash
set -euo pipefail
exit 0
"#,
        );
        write_executable(
            &fake_bin.join("cargo"),
            r#"#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$@" > "$BASTION_TEST_CARGO_LOG"
root=""
previous=""
for argument in "$@"; do
  if [ "$previous" = "--root" ]; then
    root="$argument"
  fi
  previous="$argument"
done
if [ -z "$root" ]; then
  echo "missing --root" >&2
  exit 1
fi
mkdir -p "$root/bin"
printf '#!/usr/bin/env bash\n' > "$root/bin/bastion"
chmod +x "$root/bin/bastion"
"#,
        );

        Self {
            root,
            home,
            fake_bin,
            cargo_log,
        }
    }

    fn root(&self) -> &Path {
        &self.root
    }

    fn home(&self) -> &Path {
        &self.home
    }

    fn cargo_args(&self) -> String {
        fs::read_to_string(&self.cargo_log).expect("cargo args should be recorded")
    }

    fn cargo_args_lines(&self) -> Vec<String> {
        let args = fs::read_to_string(&self.cargo_log).expect("cargo args should be recorded");
        args.lines().map(str::to_owned).collect()
    }

    fn run_script(&self, envs: &[(&str, &str)]) -> std::process::Output {
        let path = format!(
            "{}:{}",
            self.fake_bin.display(),
            std::env::var("PATH").unwrap_or_default()
        );
        let mut command = Command::new("bash");
        command
            .arg("scripts/install.sh")
            .env("HOME", &self.home)
            .env("PATH", path)
            .env("BASTION_TEST_CARGO_LOG", &self.cargo_log);
        for (key, value) in envs {
            command.env(key, value);
        }
        command.output().expect("install script should be runnable")
    }
}

impl Drop for InstallFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn write_executable(path: &Path, contents: &str) {
    fs::write(path, contents).expect("fake executable should be written");
    let mut permissions = fs::metadata(path)
        .expect("fake executable metadata should be readable")
        .permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions).expect("fake executable should be executable");
}
