# Bastion

Bastion is a local-first terminal vault for passwords and developer secrets.

## Install

Prerequisites:

- `git`
- Rust and Cargo

Install the latest `main` branch:

```bash
bash -c "$(curl -fsSL https://codeberg.org/melokki/bastion/raw/branch/main/scripts/install.sh)"
```

The installer builds the `bastion` binary from this git repository and installs it to:

```bash
~/.cargo/bin/bastion
```

Behind the scenes, it selects the root workspace package explicitly:

```bash
cargo install --git https://codeberg.org/melokki/bastion.git --branch main --locked --bin bastion --root "$HOME/.cargo" bastion
```

If `bastion` is not found after installation, add Cargo's bin directory to your shell profile:

```bash
export PATH="$HOME/.cargo/bin:$PATH"
```

## Install Options

Use a private SSH repo URL:

```bash
BASTION_REPO_URL="ssh://git@codeberg.org/melokki/bastion.git" \
bash -c "$(curl -fsSL https://codeberg.org/melokki/bastion/raw/branch/main/scripts/install.sh)"
```

Install from a specific branch:

```bash
BASTION_BRANCH="main" \
bash -c "$(curl -fsSL https://codeberg.org/melokki/bastion/raw/branch/main/scripts/install.sh)"
```

Install to a custom root:

```bash
BASTION_INSTALL_ROOT="$HOME/.local" \
bash -c "$(curl -fsSL https://codeberg.org/melokki/bastion/raw/branch/main/scripts/install.sh)"
```

That installs the binary to:

```bash
$HOME/.local/bin/bastion
```

## Run

```bash
bastion
```
