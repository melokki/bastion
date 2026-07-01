use bastion_core::{PostgreSqlCredential, PostgreSqlCredentialInput, Secret, Vault};
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
}

#[test]
fn form_input_maps_typed_pasted_and_backspace_text() {
    let mut state = unlocked_state(Vault::new_personal(timestamp()));
    update(&mut state, AppAction::StartAddPostgres);

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
