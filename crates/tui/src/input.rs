use crate::{
    AppAction, AppState, MasterPassphraseField, NavigationDirection, PanelFocus, Screen,
    SecretTypeChoice,
};
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
        Event::Paste(text) if state.modal() == Some(crate::ModalState::CommandPalette) => {
            Some(AppAction::CommandPaletteTextInput { text })
        }
        Event::Paste(text) if state.is_search_active() => Some(AppAction::SearchTextInput { text }),
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
    if key.code == KeyCode::Char('?') {
        return Some(AppAction::HelpRequested);
    }

    if state.is_search_active() {
        if key.modifiers.contains(KeyModifiers::CONTROL) {
            return map_search_control_key(key);
        }
        return map_search_key(key);
    }

    if state.modal() == Some(crate::ModalState::CommandPalette)
        && key.modifiers.contains(KeyModifiers::CONTROL)
    {
        return map_command_palette_control_key(key);
    }

    if key.modifiers.contains(KeyModifiers::CONTROL) {
        return map_control_key(key);
    }

    match state.screen() {
        Screen::Onboarding => map_onboarding_key(key, state.master_passphrase_field()),
        Screen::Locked => map_locked_key(key),
        Screen::Form => map_form_key(key, state),
        Screen::SecretTypePicker => match key.code {
            KeyCode::Esc => Some(AppAction::CancelPicker),
            KeyCode::Enter => match state.secret_type_choice() {
                SecretTypeChoice::DatabaseCredential => Some(AppAction::PickDatabaseCredential),
                SecretTypeChoice::ApiToken => Some(AppAction::PickApiToken),
                SecretTypeChoice::AccountRecovery => Some(AppAction::PickAccountRecovery),
            },
            KeyCode::Char(character @ '1'..='9') => Some(AppAction::ChooseSecretType(
                character.to_digit(10).expect("digit should parse") as usize - 1,
            )),
            KeyCode::Up | KeyCode::Char('k') => Some(AppAction::SelectPreviousSecretType),
            KeyCode::Down | KeyCode::Char('j') => Some(AppAction::SelectNextSecretType),
            _ => None,
        },
        Screen::ApiTokenKindPicker => match key.code {
            KeyCode::Esc => Some(AppAction::CancelPicker),
            KeyCode::Enter => Some(AppAction::PickApiTokenKind),
            KeyCode::Char(character @ '1'..='9') => Some(AppAction::ChooseApiTokenKind(
                character.to_digit(10).expect("digit should parse") as usize - 1,
            )),
            KeyCode::Up | KeyCode::Char('k') => Some(AppAction::SelectPreviousApiTokenKind),
            KeyCode::Down | KeyCode::Char('j') => Some(AppAction::SelectNextApiTokenKind),
            _ => None,
        },
        Screen::RecoveryKindPicker => match key.code {
            KeyCode::Esc => Some(AppAction::CancelPicker),
            KeyCode::Enter => Some(AppAction::PickRecoveryKind),
            KeyCode::Char(character @ '1'..='9') => Some(AppAction::ChooseRecoveryKind(
                character.to_digit(10).expect("digit should parse") as usize - 1,
            )),
            KeyCode::Up | KeyCode::Char('k') => Some(AppAction::SelectPreviousRecoveryKind),
            KeyCode::Down | KeyCode::Char('j') => Some(AppAction::SelectNextRecoveryKind),
            _ => None,
        },
        Screen::DatabaseEnginePicker => match key.code {
            KeyCode::Esc => Some(AppAction::CancelPicker),
            KeyCode::Enter => Some(AppAction::PickDatabaseEngine),
            KeyCode::Char(character @ '1'..='4') => Some(AppAction::ChooseDatabaseEngine(
                character.to_digit(10).expect("digit should parse") as usize - 1,
            )),
            KeyCode::Up | KeyCode::Char('k') => Some(AppAction::SelectPreviousDatabaseEngine),
            KeyCode::Down | KeyCode::Char('j') => Some(AppAction::SelectNextDatabaseEngine),
            _ => None,
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

fn map_search_key(key: KeyEvent) -> Option<AppAction> {
    match key.code {
        KeyCode::Esc => Some(AppAction::SearchCleared),
        KeyCode::Backspace => Some(AppAction::SearchBackspace),
        KeyCode::Enter => Some(AppAction::SearchRunSelected),
        KeyCode::Up | KeyCode::Char('k') => Some(AppAction::Navigate {
            direction: NavigationDirection::Previous,
        }),
        KeyCode::Down | KeyCode::Char('j') => Some(AppAction::Navigate {
            direction: NavigationDirection::Next,
        }),
        KeyCode::Char(character @ '1'..='9') => Some(AppAction::SearchChooseNumber(
            character.to_digit(10).expect("digit should parse") as usize - 1,
        )),
        KeyCode::Char(character) if !key.modifiers.contains(KeyModifiers::ALT) => {
            Some(AppAction::SearchTextInput {
                text: character.to_string(),
            })
        }
        _ => None,
    }
}

fn map_search_control_key(key: KeyEvent) -> Option<AppAction> {
    match key.code {
        KeyCode::Char('c') => Some(AppAction::SearchCleared),
        KeyCode::Char('u') => Some(AppAction::SearchClearQuery),
        KeyCode::Char('n') => Some(AppAction::Navigate {
            direction: NavigationDirection::Next,
        }),
        KeyCode::Char('p') => Some(AppAction::Navigate {
            direction: NavigationDirection::Previous,
        }),
        _ => None,
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
        KeyCode::Char('r') => Some(AppAction::RevealSelectedSecretRequested),
        KeyCode::Char('l') => Some(AppAction::LockRequested),
        KeyCode::Char('/') => Some(AppAction::SearchRequested),
        KeyCode::Char(' ') => Some(AppAction::CommandPaletteRequested),
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
            _ => None,
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

fn map_form_key(key: KeyEvent, _state: &AppState) -> Option<AppAction> {
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
        (KeyCode::Esc, Some(crate::ModalState::RevealSecret(_))) => {
            Some(AppAction::RevealSecretCancelled)
        }
        (KeyCode::Esc, Some(crate::ModalState::UpdateAvailable)) => {
            Some(AppAction::UpdateDismissed)
        }
        (KeyCode::Esc, Some(crate::ModalState::Help)) => Some(AppAction::HelpClosed),
        (KeyCode::Esc, Some(crate::ModalState::CommandPalette)) => {
            Some(AppAction::CommandPaletteClosed)
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
        (KeyCode::Enter, Some(crate::ModalState::RevealSecret(_))) => {
            Some(AppAction::RevealSecretConfirmed { now: Utc::now() })
        }
        (KeyCode::Enter, Some(crate::ModalState::UpdateAvailable)) => {
            Some(AppAction::UpdateDismissed)
        }
        (KeyCode::Char('s'), Some(crate::ModalState::UpdateAvailable)) => {
            let crate::UpdateState::Available(info) = state.update_state() else {
                return Some(AppAction::UpdateDismissed);
            };
            Some(AppAction::UpdateSkipped {
                version: info.version.clone(),
            })
        }
        (KeyCode::Enter, Some(crate::ModalState::CommandPalette)) => {
            Some(AppAction::CommandPaletteRunSelected)
        }
        (KeyCode::Backspace, Some(crate::ModalState::CommandPalette)) => {
            Some(AppAction::CommandPaletteBackspace)
        }
        (KeyCode::Char(character @ '1'..='9'), Some(crate::ModalState::CommandPalette)) => {
            Some(AppAction::CommandPaletteChooseNumber(
                character.to_digit(10).expect("digit should parse") as usize - 1,
            ))
        }
        (KeyCode::Down | KeyCode::Char('j'), Some(crate::ModalState::CommandPalette)) => {
            Some(AppAction::CommandPaletteNavigate {
                direction: NavigationDirection::Next,
            })
        }
        (KeyCode::Up | KeyCode::Char('k'), Some(crate::ModalState::CommandPalette)) => {
            Some(AppAction::CommandPaletteNavigate {
                direction: NavigationDirection::Previous,
            })
        }
        (KeyCode::Char(character), Some(crate::ModalState::CommandPalette))
            if !key.modifiers.contains(KeyModifiers::ALT) =>
        {
            Some(AppAction::CommandPaletteTextInput {
                text: character.to_string(),
            })
        }
        _ => None,
    }
}

fn map_command_palette_control_key(key: KeyEvent) -> Option<AppAction> {
    match key.code {
        KeyCode::Char('c') => Some(AppAction::CommandPaletteClosed),
        KeyCode::Char('u') => Some(AppAction::CommandPaletteClearQuery),
        KeyCode::Char('n') => Some(AppAction::CommandPaletteNavigate {
            direction: NavigationDirection::Next,
        }),
        KeyCode::Char('p') => Some(AppAction::CommandPaletteNavigate {
            direction: NavigationDirection::Previous,
        }),
        _ => None,
    }
}
