use crate::{AppAction, AppState, MasterPassphraseField, NavigationDirection, PanelFocus, Screen};
use chrono::Utc;
use crossterm::event::{Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

pub fn map_event(event: Event) -> Option<AppAction> {
    match event {
        Event::Key(key) if key.kind == KeyEventKind::Press => map_key(key, None),
        _ => None,
    }
}

pub fn map_event_for_state(state: &AppState, event: Event) -> Option<AppAction> {
    match event {
        Event::Key(key) if key.kind == KeyEventKind::Press => map_key_for_state(key, state),
        Event::Paste(text) if matches!(state.screen(), Screen::Onboarding | Screen::Locked) => {
            Some(AppAction::MasterPassphraseTextInput { text })
        }
        Event::Paste(text) if state.screen() == Screen::Form => {
            Some(AppAction::FormTextInput { text })
        }
        _ => None,
    }
}

fn map_key_for_state(key: KeyEvent, state: &AppState) -> Option<AppAction> {
    if key.modifiers.contains(KeyModifiers::CONTROL) {
        return map_control_key(key);
    }

    match state.screen() {
        Screen::Onboarding => map_onboarding_key(key, state.master_passphrase_field()),
        Screen::Locked => map_locked_key(key),
        Screen::Form => map_form_key(key),
        Screen::SecretTypePicker => match key.code {
            KeyCode::Esc => Some(AppAction::CancelPicker),
            KeyCode::Enter => Some(AppAction::PickPostgresCredential),
            _ => map_key(key, Some(Screen::SecretTypePicker)),
        },
        Screen::Modal => map_modal_key(key, state),
        _ => match key.code {
            KeyCode::Char('e') => state
                .selected_secret()
                .map(|secret_id| AppAction::StartEditPostgres { secret_id }),
            KeyCode::Char('d') => state
                .selected_secret()
                .map(|secret_id| AppAction::DeleteSecretRequested { secret_id }),
            _ => map_key(key, Some(state.screen())),
        },
    }
}

fn map_onboarding_key(key: KeyEvent, field: MasterPassphraseField) -> Option<AppAction> {
    match key.code {
        KeyCode::Esc => Some(AppAction::QuitRequested),
        KeyCode::Enter => Some(AppAction::CreateVaultRequested),
        KeyCode::Tab | KeyCode::BackTab => Some(AppAction::FocusMasterPassphraseField {
            field: match field {
                MasterPassphraseField::Passphrase => MasterPassphraseField::Confirmation,
                MasterPassphraseField::Confirmation => MasterPassphraseField::Passphrase,
            },
        }),
        KeyCode::Backspace => Some(AppAction::MasterPassphraseBackspace),
        KeyCode::Char(character) if !key.modifiers.contains(KeyModifiers::ALT) => {
            Some(AppAction::MasterPassphraseTextInput {
                text: character.to_string(),
            })
        }
        _ => None,
    }
}

fn map_locked_key(key: KeyEvent) -> Option<AppAction> {
    match key.code {
        KeyCode::Esc => Some(AppAction::QuitRequested),
        KeyCode::Enter => Some(AppAction::UnlockVaultRequested),
        KeyCode::Backspace => Some(AppAction::MasterPassphraseBackspace),
        KeyCode::Char(character) if !key.modifiers.contains(KeyModifiers::ALT) => {
            Some(AppAction::MasterPassphraseTextInput {
                text: character.to_string(),
            })
        }
        _ => None,
    }
}

fn map_key(key: KeyEvent, screen: Option<Screen>) -> Option<AppAction> {
    if key.modifiers.contains(KeyModifiers::CONTROL) {
        return map_control_key(key);
    }

    match key.code {
        KeyCode::Char('1') => Some(AppAction::FocusPanel {
            panel: PanelFocus::Items,
        }),
        KeyCode::Char('2') => Some(AppAction::FocusPanel {
            panel: PanelFocus::Tags,
        }),
        KeyCode::Char('a') => Some(AppAction::StartSecretTypePicker),
        KeyCode::Char('e') => None,
        KeyCode::Char('d') => None,
        KeyCode::Char('c') => Some(AppAction::CopySelectedPasswordRequested),
        KeyCode::Char('u') => Some(AppAction::CopySelectedUsernameRequested),
        KeyCode::Char('l') => Some(AppAction::LockRequested),
        KeyCode::Char('/') => Some(AppAction::SearchRequested),
        KeyCode::Char('q') => Some(AppAction::QuitRequested),
        KeyCode::Char('j') | KeyCode::Down => Some(AppAction::Navigate {
            direction: NavigationDirection::Next,
        }),
        KeyCode::Char('k') | KeyCode::Up => Some(AppAction::Navigate {
            direction: NavigationDirection::Previous,
        }),
        KeyCode::Esc => match screen {
            Some(Screen::SecretTypePicker) => Some(AppAction::CancelPicker),
            Some(Screen::Form) => Some(AppAction::FormEscapePressed),
            _ => None,
        },
        KeyCode::Enter => match screen {
            Some(Screen::SecretTypePicker) => Some(AppAction::PickPostgresCredential),
            Some(Screen::Form) => Some(AppAction::FormEnterPressed),
            _ => Some(AppAction::PickPostgresCredential),
        },
        KeyCode::Tab => Some(AppAction::FormNextField),
        KeyCode::BackTab => Some(AppAction::FormPreviousField),
        _ => None,
    }
}

fn map_control_key(key: KeyEvent) -> Option<AppAction> {
    match key.code {
        KeyCode::Char('c') => Some(AppAction::QuitRequested),
        KeyCode::Char('s') => Some(AppAction::FormSaveRequested { now: Utc::now() }),
        _ => None,
    }
}

fn map_form_key(key: KeyEvent) -> Option<AppAction> {
    match key.code {
        KeyCode::Esc => Some(AppAction::FormEscapePressed),
        KeyCode::Enter => Some(AppAction::FormEnterPressed),
        KeyCode::Tab => Some(AppAction::FormNextField),
        KeyCode::BackTab => Some(AppAction::FormPreviousField),
        KeyCode::Backspace => Some(AppAction::FormBackspace),
        KeyCode::Char(character) if !key.modifiers.contains(KeyModifiers::ALT) => {
            Some(AppAction::FormTextInput {
                text: character.to_string(),
            })
        }
        _ => None,
    }
}

fn map_modal_key(key: KeyEvent, state: &AppState) -> Option<AppAction> {
    match (key.code, state.modal()) {
        (KeyCode::Esc, Some(crate::ModalState::DeleteSecret(_))) => {
            Some(AppAction::DeleteCancelled)
        }
        (KeyCode::Esc, Some(crate::ModalState::DiscardChanges)) => {
            Some(AppAction::DiscardChangesCancelled)
        }
        (KeyCode::Esc, Some(crate::ModalState::QuitWithoutSaving)) => {
            Some(AppAction::QuitWithoutSavingCancelled)
        }
        (KeyCode::Enter, Some(crate::ModalState::DeleteSecret(secret_id))) => {
            Some(AppAction::DeleteSecretConfirmed {
                secret_id,
                now: Utc::now(),
            })
        }
        (KeyCode::Enter, Some(crate::ModalState::DiscardChanges)) => {
            Some(AppAction::DiscardChangesConfirmed)
        }
        (KeyCode::Enter, Some(crate::ModalState::QuitWithoutSaving)) => {
            Some(AppAction::QuitWithoutSavingConfirmed)
        }
        _ => map_key(key, Some(Screen::Modal)),
    }
}
