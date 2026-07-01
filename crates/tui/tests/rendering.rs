use bastion_core::{PostgreSqlCredential, PostgreSqlCredentialInput, Secret, Vault};
use bastion_tui::{AppAction, AppState, MasterPassphraseField, PanelFocus, render_app, update};
use chrono::{TimeZone, Utc};
use ratatui::{Terminal, backend::TestBackend};

#[test]
fn renders_main_layout_with_empty_vault() {
    let output = render_state(unlocked_state(empty_vault()), 100, 30);

    assert!(output.contains("Vault: Personal"));
    assert!(output.contains("Search: -"));
    assert!(output.contains("Items"));
    assert!(output.contains("Tags"));
    assert!(output.contains("Details"));
    assert!(output.contains("No secrets yet"));
    assert!(output.contains("Add a PostgreSQL Credential"));
    assert!(output.contains("All 0"));
    assert!(output.contains("Untagged 0"));
    assert!(output.contains("a add"));
    assert!(output.contains("l lock"));
    assert!(output.contains("q quit"));
}

#[test]
fn renders_lock_and_onboarding_without_exposing_passphrase() {
    let mut onboarding = AppState::default();
    update(
        &mut onboarding,
        AppAction::MasterPassphraseChanged {
            passphrase: "correct horse battery staple".to_owned(),
            confirmation: "correct horse battery staple".to_owned(),
        },
    );

    let mut locked = AppState::default();
    update(&mut locked, AppAction::StartApp { vault_exists: true });
    update(
        &mut locked,
        AppAction::MasterPassphraseChanged {
            passphrase: "correct horse battery staple".to_owned(),
            confirmation: String::new(),
        },
    );

    let onboarding_output = render_state(onboarding, 80, 24);
    let locked_output = render_state(locked, 80, 24);

    assert!(onboarding_output.contains("Bastion cannot recover this passphrase"));
    assert!(onboarding_output.contains("••••"));
    assert!(!onboarding_output.contains("correct horse battery staple"));
    assert!(locked_output.contains("Vault locked"));
    assert!(locked_output.contains("••••"));
    assert!(!locked_output.contains("correct horse battery staple"));
}

#[test]
fn renders_onboarding_focus_status_and_keyboard_guidance() {
    let mut state = AppState::default();
    update(
        &mut state,
        AppAction::MasterPassphraseTextInput {
            text: "short".to_owned(),
        },
    );
    update(
        &mut state,
        AppAction::FocusMasterPassphraseField {
            field: MasterPassphraseField::Confirmation,
        },
    );
    update(&mut state, AppAction::CreateVaultRequested);

    let output = render_state(state, 100, 30);

    assert!(output.contains("› Confirm passphrase"));
    assert!(!output.contains("focused"));
    assert!(output.contains("Master passphrase is too short."));
    assert!(output.contains("[Tab] switch field"));
    assert!(output.contains("[Enter] create vault"));
    assert!(output.contains("[Esc] quit"));
}

#[test]
fn renders_locked_screen_keyboard_guidance() {
    let mut state = AppState::default();
    update(&mut state, AppAction::StartApp { vault_exists: true });

    let output = render_state(state, 100, 30);

    assert!(output.contains("› Master passphrase  █"));
    assert!(!output.contains("focused"));
    assert!(output.contains("[Enter] unlock"));
    assert!(output.contains("[Esc] quit"));
}

#[test]
fn renders_locked_passphrase_mask_with_exact_typed_length_and_cursor() {
    let mut state = AppState::default();
    update(&mut state, AppAction::StartApp { vault_exists: true });
    update(
        &mut state,
        AppAction::MasterPassphraseTextInput {
            text: "x".to_owned(),
        },
    );

    let output = render_state(state, 100, 30);

    assert!(output.contains("› Master passphrase  •█"));
    assert!(!output.contains("› Master passphrase  ••••"));
    assert!(!output.contains("x"));
}

#[test]
fn renders_add_form_with_focused_input_cursor_and_keycap_shortcuts() {
    let mut state = unlocked_state(empty_vault());
    update(&mut state, AppAction::StartAddPostgres);
    update(
        &mut state,
        AppAction::FormTextInput {
            text: "Production DB".to_owned(),
        },
    );

    let output = render_state(state, 100, 30);

    assert!(output.contains("Vault: Personal"));
    assert!(output.contains("Items"));
    assert!(output.contains("Details"));
    assert!(!output.contains("Add a PostgreSQL Credential to get started."));
    assert!(output.contains("New PostgreSQL Credential"));
    assert!(output.contains("Basic"));
    assert!(output.contains("Connection"));
    assert!(output.contains("Credentials"));
    assert!(output.contains("› Title     Production DB█"));
    assert!(output.contains("[Tab] next field"));
    assert!(output.contains("[Shift+Tab] previous field"));
    assert!(output.contains("[Ctrl+S] save"));
    assert!(output.contains("[Esc] cancel"));
}

#[test]
fn renders_secret_type_picker_as_opaque_overlay_with_keycaps() {
    let mut state = unlocked_state(empty_vault());
    update(&mut state, AppAction::StartSecretTypePicker);

    let output = render_state(state, 100, 30);

    assert!(output.contains("Vault: Personal"));
    assert!(output.contains("Items"));
    assert!(output.contains("Details"));
    assert!(output.contains("Add Secret"));
    assert!(output.contains("What do you want to store?"));
    assert!(output.contains("› PostgreSQL Credential"));
    assert!(output.contains("[Enter] select"));
    assert!(output.contains("[Esc] cancel"));
}

#[test]
fn renders_discard_confirmation_over_form_with_keycaps() {
    let mut state = unlocked_state(empty_vault());
    update(&mut state, AppAction::StartAddPostgres);
    update(
        &mut state,
        AppAction::FormTextInput {
            text: "Production DB".to_owned(),
        },
    );
    update(&mut state, AppAction::FormEscapePressed);

    let output = render_state(state, 100, 30);

    assert!(output.contains("Vault: Personal"));
    assert!(output.contains("New PostgreSQL Credential"));
    assert!(output.contains("Discard unsaved changes?"));
    assert!(output.contains("[Enter] discard changes"));
    assert!(output.contains("[Esc] cancel"));
}

#[test]
fn renders_quit_without_saving_confirmation_over_main_with_keycaps() {
    let mut state = unlocked_state(empty_vault());
    update(
        &mut state,
        AppAction::AddPostgresCredential {
            credential: PostgreSqlCredential::new(postgres_input("Production DB", &["production"]))
                .expect("credential should be valid"),
            now: timestamp(),
        },
    );
    update(&mut state, AppAction::QuitRequested);
    update(
        &mut state,
        AppAction::SaveFailed {
            error: bastion_core::VaultPersistenceError::PathUnavailable,
        },
    );

    let output = render_state(state, 100, 30);

    assert!(output.contains("Vault: Personal"));
    assert!(output.contains("Quit without saving?"));
    assert!(output.contains("[Enter] quit without saving"));
    assert!(output.contains("[Esc] cancel"));
}

#[test]
fn renders_add_form_password_with_exact_mask_and_cursor() {
    let mut state = unlocked_state(empty_vault());
    update(&mut state, AppAction::StartAddPostgres);
    for _ in 0..7 {
        update(&mut state, AppAction::FormNextField);
    }
    update(
        &mut state,
        AppAction::FormTextInput {
            text: "@".to_owned(),
        },
    );

    let output = render_state(state, 100, 30);

    assert!(output.contains("› Password  •█"));
    assert!(!output.contains("› Password  ••••"));
    assert!(!output.contains("@"));
}

#[test]
fn renders_edit_form_with_prefilled_focused_title_and_masked_password() {
    let vault = vault_with_postgres_secret("Production DB", &["production"]);
    let secret_id = vault.secrets()[0].id();
    let mut state = unlocked_state(vault);
    update(&mut state, AppAction::StartEditPostgres { secret_id });

    let output = render_state(state, 100, 30);

    assert!(output.contains("Vault: Personal"));
    assert!(output.contains("Edit Production DB"));
    assert!(output.contains("Saved"));
    assert!(output.contains("Metadata"));
    assert!(output.contains("Updated  saved"));
    assert!(output.contains("› Title     Production DB█"));
    assert!(output.contains("Password"));
    assert!(output.contains("••••"));
    assert!(output.contains("[Ctrl+S] save"));
    assert!(!output.contains("correct horse battery staple"));
}

#[test]
fn renders_postgresql_details_with_masked_password() {
    let output = render_state(
        unlocked_state(vault_with_postgres_secret("Production DB", &["production"])),
        100,
        30,
    );

    assert!(output.contains("Production DB"));
    assert!(output.contains("PostgreSQL Credential"));
    assert!(output.contains("app_user"));
    assert!(output.contains("••••"));
    assert!(!output.contains("correct horse battery staple"));
}

#[test]
fn renders_too_small_screen_below_minimum_size() {
    let output = render_state(unlocked_state(empty_vault()), 79, 23);

    assert!(output.contains("Terminal too small"));
}

#[test]
fn focused_panel_is_visible_in_rendered_main_layout() {
    let mut state = unlocked_state(empty_vault());
    update(
        &mut state,
        AppAction::FocusPanel {
            panel: PanelFocus::Tags,
        },
    );

    let output = render_state(state, 100, 30);

    assert!(output.contains("Tags [2] focused"));
}

#[test]
fn delete_confirmation_identifies_the_selected_secret_without_password() {
    let vault = vault_with_postgres_secret("Production DB", &["production"]);
    let secret_id = vault.secrets()[0].id();
    let mut state = unlocked_state(vault);
    update(&mut state, AppAction::DeleteSecretRequested { secret_id });

    let output = render_state(state, 100, 30);

    assert!(output.contains("Vault: Personal"));
    assert!(output.contains("Delete this secret?"));
    assert!(output.contains("Production DB"));
    assert!(output.contains("db.example.com"));
    assert!(output.contains("app_production"));
    assert!(output.contains("app_user"));
    assert!(output.contains("[Enter] delete"));
    assert!(output.contains("[Esc] cancel"));
    assert!(!output.contains("[ Delete ] [ Cancel ]"));
    assert!(!output.contains("correct horse battery staple"));
}

fn render_state(state: AppState, width: u16, height: u16) -> String {
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).expect("test backend should create terminal");
    terminal
        .draw(|frame| render_app(frame, &state))
        .expect("render should succeed");

    terminal.backend().to_string()
}

fn empty_vault() -> Vault {
    Vault::new_personal(timestamp())
}

fn unlocked_state(vault: Vault) -> AppState {
    let mut state = AppState::default();
    update(&mut state, AppAction::UnlockSucceeded { vault });
    state
}

fn vault_with_postgres_secret(title: &str, tags: &[&str]) -> Vault {
    let mut vault = empty_vault();
    vault.add_secret(
        Secret::new_postgres(
            PostgreSqlCredential::new(postgres_input(title, tags))
                .expect("credential should be valid"),
            timestamp(),
        ),
        timestamp(),
    );
    vault
}

fn postgres_input(title: &str, tags: &[&str]) -> PostgreSqlCredentialInput {
    PostgreSqlCredentialInput {
        title: title.to_owned(),
        hostname: "db.example.com".to_owned(),
        port: 5432,
        database: "app_production".to_owned(),
        username: "app_user".to_owned(),
        password: "correct horse battery staple".to_owned(),
        schema: Some("public".to_owned()),
        tags: tags.iter().map(|tag| (*tag).to_owned()).collect(),
    }
}

fn timestamp() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 7, 1, 12, 0, 0).unwrap()
}
