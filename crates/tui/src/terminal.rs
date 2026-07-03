use crate::{AppAction, AppState, Effect, map_event_for_state, render_app, update};
use bastion_core::{Vault, load_vault, resolve_vault_path, save_vault};
use chrono::Utc;
use crossterm::event;
use std::io;
use std::path::Path;
use std::time::Duration;

pub fn run_terminal_app() -> io::Result<()> {
    let vault_path = resolve_vault_path().map_err(io::Error::other)?;

    ratatui::run(|terminal| {
        let mut state = AppState::default();
        let startup_effects = update(
            &mut state,
            AppAction::StartApp {
                vault_exists: vault_path.exists(),
            },
        );
        handle_effects(&mut state, &vault_path, startup_effects, false);

        loop {
            terminal.draw(|frame| render_app(frame, &state))?;

            if !event::poll(next_poll_timeout(&state))? {
                let now = Utc::now();
                let mut effects = update(&mut state, AppAction::RevealExpired { now });
                effects.extend(update(&mut state, AppAction::ClipboardClearDue { now }));
                effects.extend(update(&mut state, AppAction::AutoLockTick { now }));
                handle_effects(&mut state, &vault_path, effects, false);
                continue;
            }

            let Some(action) = map_event_for_state(&state, event::read()?) else {
                continue;
            };
            let quit_requested = matches!(action, AppAction::QuitRequested);
            let now = Utc::now();
            update(&mut state, AppAction::UserActivity { now });
            let effects = update(&mut state, action);
            let effects = effects
                .into_iter()
                .chain(update(&mut state, AppAction::AutoLockTick { now }))
                .collect::<Vec<_>>();
            if handle_effects(&mut state, &vault_path, effects, quit_requested) {
                break Ok(());
            }
        }
    })
}

fn next_poll_timeout(state: &AppState) -> Duration {
    let next_deadline = [
        state.reveal_expires_at(),
        state
            .clipboard_state()
            .pending_clear()
            .map(|pending| pending.clear_at()),
        state.auto_lock_deadline(),
    ]
    .into_iter()
    .flatten()
    .min();

    match next_deadline {
        Some(deadline) => {
            let remaining = deadline - Utc::now();
            remaining
                .to_std()
                .unwrap_or_else(|_| Duration::from_millis(0))
                .min(Duration::from_millis(250))
        }
        None => Duration::from_millis(250),
    }
}

fn handle_effects(
    state: &mut AppState,
    vault_path: &Path,
    effects: Vec<Effect>,
    quit_requested: bool,
) -> bool {
    let mut pending = effects;
    while let Some(effect) = pending.pop() {
        match effect {
            Effect::Quit => return true,
            Effect::CreateVault => {
                pending.extend(update(
                    state,
                    AppAction::CreateVaultSucceeded {
                        vault: Vault::new_personal(Utc::now()),
                    },
                ));
            }
            Effect::LoadVault => {
                let action = match load_vault(vault_path, state.master_passphrase()) {
                    Ok(vault) => AppAction::UnlockSucceeded { vault },
                    Err(error) => AppAction::UnlockFailed { error },
                };
                pending.extend(update(state, action));
            }
            Effect::SaveVault if quit_requested => {
                if save_or_report(state, vault_path) {
                    pending.extend(update(state, AppAction::QuitAfterSaveSucceeded));
                }
            }
            Effect::SaveVault => {
                save_or_report(state, vault_path);
            }
            Effect::CheckForUpdates
            | Effect::CopySecretToClipboard { .. }
            | Effect::CopyTextToClipboard { .. }
            | Effect::ClearClipboard
            | Effect::ClearClipboardIfUnchanged { .. } => {}
        }
    }
    false
}

fn save_or_report(state: &mut AppState, vault_path: &Path) -> bool {
    let Some(vault) = state.unlocked_vault() else {
        return false;
    };
    let action = match save_vault(vault_path, vault, state.master_passphrase()) {
        Ok(()) => AppAction::SaveSucceeded,
        Err(error) => AppAction::SaveFailed { error },
    };
    let saved = matches!(action, AppAction::SaveSucceeded);
    update(state, action);
    saved
}

#[cfg(test)]
mod tests {
    use super::handle_effects;
    use crate::{AppAction, AppState, Effect, Screen, VaultSession, update};
    use bastion_core::backup_path;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn create_effect_writes_encrypted_vault_and_load_effect_unlocks_it() {
        let path = test_vault_path("create-load");
        let mut created = AppState::default();
        update(
            &mut created,
            AppAction::MasterPassphraseChanged {
                passphrase: "correct horse battery staple".to_owned(),
                confirmation: "correct horse battery staple".to_owned(),
            },
        );

        let should_quit = handle_effects(&mut created, &path, vec![Effect::CreateVault], false);

        assert!(!should_quit);
        assert_eq!(Screen::Main, created.screen());
        assert!(matches!(created.session(), VaultSession::Unlocked { .. }));
        assert!(!created.is_dirty());
        assert!(path.exists());

        let mut loaded = AppState::default();
        update(
            &mut loaded,
            AppAction::MasterPassphraseChanged {
                passphrase: "correct horse battery staple".to_owned(),
                confirmation: String::new(),
            },
        );

        handle_effects(&mut loaded, &path, vec![Effect::LoadVault], false);

        assert_eq!(Screen::Main, loaded.screen());
        assert!(matches!(loaded.session(), VaultSession::Unlocked { .. }));

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(backup_path(&path));
    }

    fn test_vault_path(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("bastion-tui-{name}-{nonce}.bst"))
    }
}
