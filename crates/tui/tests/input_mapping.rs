use bastion_core::{
    DatabaseEngine, PostgreSqlCredential, PostgreSqlCredentialInput, Secret, Vault,
};
use bastion_tui::{
    AppAction, AppState, MasterPassphraseField, PanelFocus, map_event, map_event_for_state, update,
};
use chrono::{TimeZone, Utc};
use crossterm::event::{
    Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers, MouseEvent, MouseEventKind,
};

#[test]
fn keyboard_input_maps_to_actions() {
    assert!(matches!(
        map_event(Event::Key(key(KeyCode::Char('1')))),
        Some(AppAction::FocusPanel {
            panel: PanelFocus::Items
        })
    ));
    assert!(matches!(
        map_event(Event::Key(key(KeyCode::Char('2')))),
        Some(AppAction::FocusPanel {
            panel: PanelFocus::Tags
        })
    ));
    assert!(matches!(
        map_event(Event::Key(key(KeyCode::Char('a')))),
        Some(AppAction::StartSecretTypePicker)
    ));
    assert!(matches!(
        map_event(Event::Key(key(KeyCode::Char('q')))),
        Some(AppAction::QuitRequested)
    ));
    assert!(matches!(
        map_event(Event::Key(KeyEvent::new(
            KeyCode::Char('s'),
            KeyModifiers::CONTROL
        ))),
        Some(AppAction::FormSaveRequested { .. })
    ));
}

#[test]
fn mouse_input_does_not_create_actions() {
    let event = Event::Mouse(MouseEvent {
        kind: MouseEventKind::Down(crossterm::event::MouseButton::Left),
        column: 10,
        row: 10,
        modifiers: KeyModifiers::NONE,
    });

    assert!(map_event(event).is_none());
}

#[test]
fn stateful_shortcuts_target_selected_secret_without_mouse() {
    let vault = vault_with_postgres_secret();
    let secret_id = vault.secrets()[0].id();
    let state = unlocked_state(vault);

    assert!(map_event_for_state(&state, Event::Key(key(KeyCode::Enter))).is_none());
    assert!(matches!(
        map_event_for_state(&state, Event::Key(key(KeyCode::Char('e')))),
        Some(AppAction::StartEditPostgres { secret_id: id }) if id == secret_id
    ));
    assert!(matches!(
        map_event_for_state(&state, Event::Key(key(KeyCode::Char('d')))),
        Some(AppAction::DeleteSecretRequested { secret_id: id }) if id == secret_id
    ));
    assert!(matches!(
        map_event_for_state(&state, Event::Key(key(KeyCode::Char('l')))),
        Some(AppAction::LockRequested)
    ));
    assert!(matches!(
        map_event_for_state(&state, Event::Key(key(KeyCode::Char('r')))),
        Some(AppAction::RevealSelectedSecretRequested)
    ));
    assert!(matches!(
        map_event_for_state(&state, Event::Key(key(KeyCode::Char('?')))),
        Some(AppAction::HelpRequested)
    ));
    assert!(matches!(
        map_event_for_state(&state, Event::Key(key(KeyCode::Char(' ')))),
        Some(AppAction::CommandPaletteRequested)
    ));
}

#[test]
fn search_mode_maps_typing_to_search_prompt_and_arrows_to_results() {
    let mut state = unlocked_state(vault_with_postgres_secret());

    assert!(matches!(
        map_event_for_state(&state, Event::Key(key(KeyCode::Char('/')))),
        Some(AppAction::SearchRequested)
    ));
    update(&mut state, AppAction::SearchRequested);

    assert!(matches!(
        map_event_for_state(&state, Event::Key(key(KeyCode::Char('p')))),
        Some(AppAction::SearchTextInput { text }) if text == "p"
    ));
    assert!(matches!(
        map_event_for_state(&state, Event::Paste("rod".to_owned())),
        Some(AppAction::SearchTextInput { text }) if text == "rod"
    ));
    assert!(matches!(
        map_event_for_state(&state, Event::Key(key(KeyCode::Char('1')))),
        Some(AppAction::SearchChooseNumber(0))
    ));
    assert!(matches!(
        map_event_for_state(&state, Event::Key(key(KeyCode::Char('j')))),
        Some(AppAction::Navigate { .. })
    ));
    assert!(matches!(
        map_event_for_state(&state, Event::Key(key(KeyCode::Down))),
        Some(AppAction::Navigate { .. })
    ));
    assert!(matches!(
        map_event_for_state(&state, Event::Key(key(KeyCode::Up))),
        Some(AppAction::Navigate { .. })
    ));
    assert!(matches!(
        map_event_for_state(&state, Event::Key(key(KeyCode::Backspace))),
        Some(AppAction::SearchBackspace)
    ));
    assert!(matches!(
        map_event_for_state(&state, Event::Key(key(KeyCode::Enter))),
        Some(AppAction::SearchRunSelected)
    ));
    assert!(matches!(
        map_event_for_state(&state, Event::Key(control_key('u'))),
        Some(AppAction::SearchClearQuery)
    ));
    assert!(matches!(
        map_event_for_state(&state, Event::Key(control_key('n'))),
        Some(AppAction::Navigate { .. })
    ));
    assert!(matches!(
        map_event_for_state(&state, Event::Key(control_key('p'))),
        Some(AppAction::Navigate { .. })
    ));
    assert!(matches!(
        map_event_for_state(&state, Event::Key(control_key('c'))),
        Some(AppAction::SearchCleared)
    ));
    assert!(matches!(
        map_event_for_state(&state, Event::Key(key(KeyCode::Esc))),
        Some(AppAction::SearchCleared)
    ));
}

#[test]
fn form_input_maps_typed_pasted_and_backspace_text() {
    let mut state = unlocked_state(Vault::new_personal(timestamp()));
    update(&mut state, AppAction::StartAddPostgres);

    assert!(map_event_for_state(&state, Event::Key(key(KeyCode::Up))).is_none());
    assert!(map_event_for_state(&state, Event::Key(key(KeyCode::Down))).is_none());
    assert!(matches!(
        map_event_for_state(&state, Event::Key(key(KeyCode::Char('1')))),
        Some(AppAction::FormTextInput { text }) if text == "1"
    ));
    assert!(matches!(
        map_event_for_state(&state, Event::Key(key(KeyCode::Char('P')))),
        Some(AppAction::FormTextInput { text }) if text == "P"
    ));
    assert!(matches!(
        map_event_for_state(&state, Event::Paste("roduction DB".to_owned())),
        Some(AppAction::FormTextInput { text }) if text == "roduction DB"
    ));
    assert!(matches!(
        map_event_for_state(&state, Event::Key(key(KeyCode::Backspace))),
        Some(AppAction::FormBackspace)
    ));
}

#[test]
fn picker_traps_background_panel_shortcuts() {
    let mut state = unlocked_state(vault_with_postgres_secret());
    update(&mut state, AppAction::StartSecretTypePicker);

    for code in [KeyCode::Char('a'), KeyCode::Char('l'), KeyCode::Char('q')] {
        assert!(map_event_for_state(&state, Event::Key(key(code))).is_none());
    }
    assert!(matches!(
        map_event_for_state(&state, Event::Key(key(KeyCode::Char('1')))),
        Some(AppAction::ChooseSecretType(0))
    ));
    assert!(matches!(
        map_event_for_state(&state, Event::Key(key(KeyCode::Char('2')))),
        Some(AppAction::ChooseSecretType(1))
    ));
    assert!(matches!(
        map_event_for_state(&state, Event::Key(key(KeyCode::Down))),
        Some(AppAction::SelectNextSecretType)
    ));
    update(&mut state, AppAction::SelectNextSecretType);
    assert!(matches!(
        map_event_for_state(&state, Event::Key(key(KeyCode::Char('k')))),
        Some(AppAction::SelectPreviousSecretType)
    ));
    assert!(matches!(
        map_event_for_state(&state, Event::Key(key(KeyCode::Enter))),
        Some(AppAction::PickApiToken)
    ));
    update(&mut state, AppAction::SelectPreviousSecretType);
    assert!(matches!(
        map_event_for_state(&state, Event::Key(key(KeyCode::Enter))),
        Some(AppAction::PickDatabaseCredential)
    ));
    update(&mut state, AppAction::SelectPreviousSecretType);
    assert!(matches!(
        map_event_for_state(&state, Event::Key(key(KeyCode::Enter))),
        Some(AppAction::PickAccountRecovery)
    ));
    assert!(matches!(
        map_event_for_state(&state, Event::Key(key(KeyCode::Esc))),
        Some(AppAction::CancelPicker)
    ));

    update(&mut state, AppAction::PickAccountRecovery);
    assert!(matches!(
        map_event_for_state(&state, Event::Key(key(KeyCode::Char('2')))),
        Some(AppAction::ChooseRecoveryKind(1))
    ));
    assert!(matches!(
        map_event_for_state(&state, Event::Key(key(KeyCode::Down))),
        Some(AppAction::SelectNextRecoveryKind)
    ));
    assert!(matches!(
        map_event_for_state(&state, Event::Key(key(KeyCode::Enter))),
        Some(AppAction::PickRecoveryKind)
    ));
    assert!(matches!(
        map_event_for_state(&state, Event::Key(key(KeyCode::Esc))),
        Some(AppAction::CancelPicker)
    ));
}

#[test]
fn modal_traps_background_panel_shortcuts() {
    let vault = vault_with_postgres_secret();
    let secret_id = vault.secrets()[0].id();
    let mut state = unlocked_state(vault);
    update(&mut state, AppAction::DeleteSecretRequested { secret_id });

    for code in [
        KeyCode::Char('1'),
        KeyCode::Char('2'),
        KeyCode::Char('a'),
        KeyCode::Char('j'),
        KeyCode::Char('k'),
        KeyCode::Char('l'),
        KeyCode::Char('q'),
        KeyCode::Up,
        KeyCode::Down,
    ] {
        assert!(map_event_for_state(&state, Event::Key(key(code))).is_none());
    }
    assert!(matches!(
        map_event_for_state(&state, Event::Key(key(KeyCode::Enter))),
        Some(AppAction::DeleteSecretConfirmed { secret_id: id, .. }) if id == secret_id
    ));
    assert!(matches!(
        map_event_for_state(&state, Event::Key(key(KeyCode::Esc))),
        Some(AppAction::DeleteCancelled)
    ));
}

#[test]
fn reveal_modal_maps_enter_and_escape_without_background_shortcuts() {
    let vault = vault_with_postgres_secret();
    let mut state = unlocked_state(vault);
    update(&mut state, AppAction::RevealSelectedSecretRequested);

    for code in [
        KeyCode::Char('1'),
        KeyCode::Char('2'),
        KeyCode::Char('a'),
        KeyCode::Char('j'),
        KeyCode::Char('k'),
        KeyCode::Char('l'),
        KeyCode::Char('q'),
        KeyCode::Up,
        KeyCode::Down,
    ] {
        assert!(map_event_for_state(&state, Event::Key(key(code))).is_none());
    }
    assert!(matches!(
        map_event_for_state(&state, Event::Key(key(KeyCode::Enter))),
        Some(AppAction::RevealSecretConfirmed { .. })
    ));
    assert!(matches!(
        map_event_for_state(&state, Event::Key(key(KeyCode::Esc))),
        Some(AppAction::RevealSecretCancelled)
    ));
}

#[test]
fn help_overlay_closes_with_escape_and_traps_background_shortcuts() {
    let mut state = unlocked_state(vault_with_postgres_secret());
    update(&mut state, AppAction::HelpRequested);

    for code in [
        KeyCode::Char('1'),
        KeyCode::Char('2'),
        KeyCode::Char('a'),
        KeyCode::Char('j'),
        KeyCode::Char('k'),
        KeyCode::Char('l'),
        KeyCode::Char('q'),
        KeyCode::Up,
        KeyCode::Down,
        KeyCode::Enter,
    ] {
        assert!(map_event_for_state(&state, Event::Key(key(code))).is_none());
    }
    assert!(matches!(
        map_event_for_state(&state, Event::Key(key(KeyCode::Esc))),
        Some(AppAction::HelpClosed)
    ));
}

#[test]
fn command_palette_maps_typing_navigation_enter_and_escape() {
    let mut state = unlocked_state(vault_with_postgres_secret());
    update(&mut state, AppAction::CommandPaletteRequested);

    assert!(matches!(
        map_event_for_state(&state, Event::Key(key(KeyCode::Char('s')))),
        Some(AppAction::CommandPaletteTextInput { text }) if text == "s"
    ));
    assert!(matches!(
        map_event_for_state(&state, Event::Paste("earch".to_owned())),
        Some(AppAction::CommandPaletteTextInput { text }) if text == "earch"
    ));
    assert!(matches!(
        map_event_for_state(&state, Event::Key(key(KeyCode::Backspace))),
        Some(AppAction::CommandPaletteBackspace)
    ));
    assert!(matches!(
        map_event_for_state(&state, Event::Key(key(KeyCode::Down))),
        Some(AppAction::CommandPaletteNavigate { .. })
    ));
    assert!(matches!(
        map_event_for_state(&state, Event::Key(key(KeyCode::Char('j')))),
        Some(AppAction::CommandPaletteNavigate { .. })
    ));
    assert!(matches!(
        map_event_for_state(&state, Event::Key(key(KeyCode::Up))),
        Some(AppAction::CommandPaletteNavigate { .. })
    ));
    assert!(matches!(
        map_event_for_state(&state, Event::Key(key(KeyCode::Char('k')))),
        Some(AppAction::CommandPaletteNavigate { .. })
    ));
    assert!(matches!(
        map_event_for_state(&state, Event::Key(key(KeyCode::Enter))),
        Some(AppAction::CommandPaletteRunSelected)
    ));
    assert!(matches!(
        map_event_for_state(&state, Event::Key(key(KeyCode::Char('1')))),
        Some(AppAction::CommandPaletteChooseNumber(0))
    ));
    assert!(matches!(
        map_event_for_state(&state, Event::Key(control_key('u'))),
        Some(AppAction::CommandPaletteClearQuery)
    ));
    assert!(matches!(
        map_event_for_state(&state, Event::Key(control_key('n'))),
        Some(AppAction::CommandPaletteNavigate { .. })
    ));
    assert!(matches!(
        map_event_for_state(&state, Event::Key(control_key('p'))),
        Some(AppAction::CommandPaletteNavigate { .. })
    ));
    assert!(matches!(
        map_event_for_state(&state, Event::Key(control_key('c'))),
        Some(AppAction::CommandPaletteClosed)
    ));
    assert!(matches!(
        map_event_for_state(&state, Event::Key(key(KeyCode::Esc))),
        Some(AppAction::CommandPaletteClosed)
    ));
}

#[test]
fn database_engine_picker_maps_navigation_numbers_and_escape() {
    let mut state = unlocked_state(vault_with_postgres_secret());
    update(&mut state, AppAction::StartAddPostgres);
    update(&mut state, AppAction::FormNextField);
    update(&mut state, AppAction::FormNextField);
    update(&mut state, AppAction::FormEnterPressed);

    assert!(matches!(
        map_event_for_state(&state, Event::Key(key(KeyCode::Char('2')))),
        Some(AppAction::ChooseDatabaseEngine(1))
    ));
    assert!(matches!(
        map_event_for_state(&state, Event::Key(key(KeyCode::Down))),
        Some(AppAction::SelectNextDatabaseEngine)
    ));
    assert!(matches!(
        map_event_for_state(&state, Event::Key(key(KeyCode::Up))),
        Some(AppAction::SelectPreviousDatabaseEngine)
    ));
    assert!(matches!(
        map_event_for_state(&state, Event::Key(key(KeyCode::Enter))),
        Some(AppAction::PickDatabaseEngine)
    ));
    assert!(matches!(
        map_event_for_state(&state, Event::Key(key(KeyCode::Esc))),
        Some(AppAction::CancelPicker)
    ));
}

#[test]
fn onboarding_input_maps_to_master_passphrase_flow() {
    let state = AppState::default();

    assert!(matches!(
        map_event_for_state(&state, Event::Key(key(KeyCode::Char('c')))),
        Some(AppAction::MasterPassphraseTextInput { text }) if text == "c"
    ));
    assert!(matches!(
        map_event_for_state(&state, Event::Paste("orrect horse".to_owned())),
        Some(AppAction::MasterPassphraseTextInput { text }) if text == "orrect horse"
    ));
    assert!(matches!(
        map_event_for_state(&state, Event::Key(key(KeyCode::Backspace))),
        Some(AppAction::MasterPassphraseBackspace)
    ));
    assert!(matches!(
        map_event_for_state(&state, Event::Key(key(KeyCode::Tab))),
        Some(AppAction::FocusMasterPassphraseField {
            field: MasterPassphraseField::Confirmation
        })
    ));
    assert!(matches!(
        map_event_for_state(&state, Event::Key(key(KeyCode::Enter))),
        Some(AppAction::CreateVaultRequested)
    ));
}

#[test]
fn locked_input_maps_to_unlock_flow() {
    let mut state = AppState::default();
    update(&mut state, AppAction::StartApp { vault_exists: true });

    assert!(matches!(
        map_event_for_state(&state, Event::Key(key(KeyCode::Char('s')))),
        Some(AppAction::MasterPassphraseTextInput { text }) if text == "s"
    ));
    assert!(matches!(
        map_event_for_state(&state, Event::Key(key(KeyCode::Enter))),
        Some(AppAction::UnlockVaultRequested)
    ));
}

fn key(code: KeyCode) -> KeyEvent {
    KeyEvent {
        code,
        modifiers: KeyModifiers::NONE,
        kind: KeyEventKind::Press,
        state: crossterm::event::KeyEventState::NONE,
    }
}

fn control_key(character: char) -> KeyEvent {
    KeyEvent {
        code: KeyCode::Char(character),
        modifiers: KeyModifiers::CONTROL,
        kind: KeyEventKind::Press,
        state: crossterm::event::KeyEventState::NONE,
    }
}

fn unlocked_state(vault: Vault) -> AppState {
    let mut state = AppState::default();
    update(&mut state, AppAction::UnlockSucceeded { vault });
    state
}

fn vault_with_postgres_secret() -> Vault {
    let mut vault = Vault::new_personal(timestamp());
    vault.add_secret(
        Secret::new_postgres(
            PostgreSqlCredential::new(PostgreSqlCredentialInput {
                title: "Production DB".to_owned(),
                engine: DatabaseEngine::PostgreSql,
                hostname: "db.example.com".to_owned(),
                port: 5432,
                database: "app_production".to_owned(),
                username: "app_user".to_owned(),
                password: "correct horse battery staple".to_owned(),
                schema: Some("public".to_owned()),
                tags: vec!["production".to_owned()],
            })
            .expect("credential should be valid"),
            timestamp(),
        ),
        timestamp(),
    );
    vault
}

fn timestamp() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 7, 1, 12, 0, 0).unwrap()
}
