use bastion_core::{
    PostgreSqlCredential, PostgreSqlCredentialInput, Secret, Vault, VaultPersistenceError,
};
use bastion_tui::{
    AppAction, AppState, Effect, FormField, FormMode, ModalState, PanelFocus, Screen, SecretRef,
    SelectedFilter, VaultSession, update,
};
use chrono::{TimeZone, Utc};

#[test]
fn start_app_routes_to_onboarding_when_no_vault_exists() {
    let mut state = AppState::default();

    let effects = update(
        &mut state,
        AppAction::StartApp {
            vault_exists: false,
        },
    );

    assert_eq!(Screen::Onboarding, state.screen());
    assert!(effects.is_empty());
}

#[test]
fn start_app_routes_to_locked_when_vault_exists() {
    let mut state = AppState::default();

    let effects = update(&mut state, AppAction::StartApp { vault_exists: true });

    assert_eq!(Screen::Locked, state.screen());
    assert!(effects.is_empty());
}

#[test]
fn unlock_success_enters_main_with_unlocked_session() {
    let mut state = AppState::default();
    let vault = empty_vault();

    let effects = update(&mut state, AppAction::UnlockSucceeded { vault });

    assert_eq!(Screen::Main, state.screen());
    assert!(matches!(state.session(), VaultSession::Unlocked { .. }));
    assert!(effects.is_empty());
}

#[test]
fn unlock_failure_stays_locked_with_safe_status() {
    let mut state = AppState::default();
    update(&mut state, AppAction::StartApp { vault_exists: true });

    let effects = update(
        &mut state,
        AppAction::UnlockFailed {
            error: VaultPersistenceError::AuthenticationFailed,
        },
    );

    assert_eq!(Screen::Locked, state.screen());
    assert_eq!(
        Some("Could not unlock vault. Check the master passphrase."),
        state.status_message()
    );
    assert!(matches!(state.session(), VaultSession::Locked));
    assert!(effects.is_empty());
}

#[test]
fn create_vault_success_enters_main_and_requests_save() {
    let mut state = AppState::default();
    let vault = empty_vault();

    let effects = update(&mut state, AppAction::CreateVaultSucceeded { vault });

    assert_eq!(Screen::Main, state.screen());
    assert!(state.is_dirty());
    assert_eq!(vec![Effect::SaveVault], effects);
}

#[test]
fn onboarding_validates_master_passphrase_before_create_effect() {
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
            field: bastion_tui::MasterPassphraseField::Confirmation,
        },
    );
    update(
        &mut state,
        AppAction::MasterPassphraseTextInput {
            text: "short".to_owned(),
        },
    );

    let effects = update(&mut state, AppAction::CreateVaultRequested);

    assert_eq!(Screen::Onboarding, state.screen());
    assert_eq!(
        Some("Master passphrase is too short."),
        state.status_message()
    );
    assert!(effects.is_empty());
}

#[test]
fn onboarding_create_request_uses_entered_matching_passphrases() {
    let mut state = AppState::default();

    update(
        &mut state,
        AppAction::MasterPassphraseTextInput {
            text: "correct horse battery staple".to_owned(),
        },
    );
    update(
        &mut state,
        AppAction::FocusMasterPassphraseField {
            field: bastion_tui::MasterPassphraseField::Confirmation,
        },
    );
    update(
        &mut state,
        AppAction::MasterPassphraseTextInput {
            text: "correct horse battery staple".to_owned(),
        },
    );

    let effects = update(&mut state, AppAction::CreateVaultRequested);

    assert_eq!(Screen::Onboarding, state.screen());
    assert_eq!("correct horse battery staple", state.master_passphrase());
    assert_eq!(None, state.status_message());
    assert_eq!(vec![Effect::CreateVault], effects);
}

#[test]
fn locked_unlock_request_uses_typed_master_passphrase() {
    let mut state = AppState::default();
    update(&mut state, AppAction::StartApp { vault_exists: true });
    update(
        &mut state,
        AppAction::MasterPassphraseTextInput {
            text: "correct horse battery staple".to_owned(),
        },
    );

    let effects = update(&mut state, AppAction::UnlockVaultRequested);

    assert_eq!(Screen::Locked, state.screen());
    assert_eq!("correct horse battery staple", state.master_passphrase());
    assert_eq!(vec![Effect::LoadVault], effects);
}

#[test]
fn lock_clears_unlocked_state_and_requests_clipboard_clear() {
    let mut state = unlocked_state(vault_with_postgres_secret("Production DB", &["production"]));
    update(&mut state, AppAction::StartAddPostgres);

    let effects = update(&mut state, AppAction::LockRequested);

    assert_eq!(Screen::Locked, state.screen());
    assert!(matches!(state.session(), VaultSession::Locked));
    assert_eq!(None, state.selected_secret());
    assert_eq!(None, state.form());
    assert_eq!(None, state.modal());
    assert_eq!(None, state.status_message());
    assert_eq!(vec![Effect::ClearClipboard], effects);
}

#[test]
fn panel_focus_actions_switch_focus() {
    let mut state = unlocked_state(empty_vault());

    update(
        &mut state,
        AppAction::FocusPanel {
            panel: PanelFocus::Tags,
        },
    );
    assert_eq!(PanelFocus::Tags, state.panel_focus());

    update(
        &mut state,
        AppAction::FocusPanel {
            panel: PanelFocus::Items,
        },
    );
    assert_eq!(PanelFocus::Items, state.panel_focus());
}

#[test]
fn tag_selection_updates_filter_and_selected_secret() {
    let mut vault = empty_vault();
    let local = Secret::new_postgres(
        PostgreSqlCredential::new(postgres_input("Local DB", &["local"]))
            .expect("credential should be valid"),
        timestamp(),
    );
    let local_id = local.id();
    let production = Secret::new_postgres(
        PostgreSqlCredential::new(postgres_input("Production DB", &["production"]))
            .expect("credential should be valid"),
        timestamp(),
    );
    let production_id = production.id();
    vault.add_secret(local, timestamp());
    vault.add_secret(production, timestamp());
    let mut state = unlocked_state(vault);

    update(
        &mut state,
        AppAction::SelectFilter {
            filter: SelectedFilter::Tag("production".to_owned()),
        },
    );

    assert_eq!(
        &SelectedFilter::Tag("production".to_owned()),
        state.selected_filter()
    );
    assert_eq!(Some(production_id), state.selected_secret());

    update(
        &mut state,
        AppAction::SelectFilter {
            filter: SelectedFilter::Tag("local".to_owned()),
        },
    );

    assert_eq!(Some(local_id), state.selected_secret());
}

#[test]
fn create_edit_delete_mutations_mark_dirty_and_request_save() {
    let mut state = unlocked_state(empty_vault());
    let effects = update(
        &mut state,
        AppAction::AddPostgresCredential {
            credential: PostgreSqlCredential::new(postgres_input("Production DB", &["production"]))
                .expect("credential should be valid"),
            now: timestamp(),
        },
    );

    assert!(state.is_dirty());
    assert_eq!(vec![Effect::SaveVault], effects);
    let secret_id = state
        .selected_secret()
        .expect("new secret should be selected");

    let effects = update(
        &mut state,
        AppAction::EditPostgresCredential {
            secret_id,
            credential: PostgreSqlCredential::new(postgres_input("Staging DB", &["staging"]))
                .expect("credential should be valid"),
            now: timestamp(),
        },
    );

    assert_eq!(vec![Effect::SaveVault], effects);

    let effects = update(
        &mut state,
        AppAction::DeleteSecretConfirmed {
            secret_id,
            now: timestamp(),
        },
    );

    assert_eq!(vec![Effect::SaveVault], effects);
    assert_eq!(None, state.selected_secret());
}

#[test]
fn secret_type_picker_action_opens_picker_screen() {
    let mut state = unlocked_state(empty_vault());

    let effects = update(&mut state, AppAction::StartSecretTypePicker);

    assert_eq!(Screen::SecretTypePicker, state.screen());
    assert!(effects.is_empty());
}

#[test]
fn start_edit_form_tracks_target_secret_and_dirty_state() {
    let vault = vault_with_postgres_secret("Production DB", &["production"]);
    let secret_id = vault.secrets()[0].id();
    let mut state = unlocked_state(vault);

    let effects = update(&mut state, AppAction::StartEditPostgres { secret_id });

    assert_eq!(Screen::Form, state.screen());
    let form = state.form().expect("edit form should be active");
    assert_eq!(FormMode::EditPostgreSqlCredential(secret_id), form.mode());
    assert!(!form.is_dirty());
    assert!(effects.is_empty());
}

#[test]
fn delete_request_opens_confirmation_modal() {
    let vault = vault_with_postgres_secret("Production DB", &["production"]);
    let secret_id = vault.secrets()[0].id();
    let mut state = unlocked_state(vault);

    let effects = update(&mut state, AppAction::DeleteSecretRequested { secret_id });

    assert_eq!(Screen::Modal, state.screen());
    assert_eq!(Some(ModalState::DeleteSecret(secret_id)), state.modal());
    assert!(effects.is_empty());
}

#[test]
fn save_success_clears_dirty_state() {
    let mut state = unlocked_state(empty_vault());
    update(
        &mut state,
        AppAction::AddPostgresCredential {
            credential: PostgreSqlCredential::new(postgres_input("Production DB", &["production"]))
                .expect("credential should be valid"),
            now: timestamp(),
        },
    );

    let effects = update(&mut state, AppAction::SaveSucceeded);

    assert!(!state.is_dirty());
    assert_eq!(None, state.status_message());
    assert!(effects.is_empty());
}

#[test]
fn save_failure_keeps_dirty_state_and_safe_status() {
    let mut state = unlocked_state(empty_vault());
    update(
        &mut state,
        AppAction::AddPostgresCredential {
            credential: PostgreSqlCredential::new(postgres_input("Production DB", &["production"]))
                .expect("credential should be valid"),
            now: timestamp(),
        },
    );

    let effects = update(
        &mut state,
        AppAction::SaveFailed {
            error: VaultPersistenceError::PathUnavailable,
        },
    );

    assert!(state.is_dirty());
    assert_eq!(
        Some("Vault path could not be resolved."),
        state.status_message()
    );
    assert!(effects.is_empty());
}

#[test]
fn quit_with_dirty_vault_saves_before_quitting() {
    let mut state = unlocked_state(empty_vault());
    update(
        &mut state,
        AppAction::AddPostgresCredential {
            credential: PostgreSqlCredential::new(postgres_input("Production DB", &["production"]))
                .expect("credential should be valid"),
            now: timestamp(),
        },
    );

    let effects = update(&mut state, AppAction::QuitRequested);

    assert_eq!(vec![Effect::SaveVault], effects);
    assert!(state.is_dirty());

    let effects = update(&mut state, AppAction::QuitAfterSaveSucceeded);
    assert_eq!(vec![Effect::Quit], effects);
    assert!(!state.is_dirty());
}

#[test]
fn quit_after_save_failure_requires_explicit_confirmation() {
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
            error: VaultPersistenceError::PathUnavailable,
        },
    );

    assert_eq!(Screen::Modal, state.screen());
    assert_eq!(Some(ModalState::QuitWithoutSaving), state.modal());
    assert!(state.is_dirty());

    let effects = update(&mut state, AppAction::QuitWithoutSavingConfirmed);
    assert_eq!(vec![Effect::Quit], effects);
}

#[test]
fn copy_actions_produce_clipboard_effects() {
    let vault = vault_with_postgres_secret("Production DB", &["production"]);
    let secret_id = vault.secrets()[0].id();
    let mut state = unlocked_state(vault);

    assert_eq!(
        vec![Effect::CopySecretToClipboard(
            SecretRef::PostgreSqlPassword(secret_id)
        )],
        update(&mut state, AppAction::CopyPasswordRequested { secret_id })
    );
    assert_eq!(
        vec![Effect::CopyTextToClipboard("app_user".to_owned())],
        update(&mut state, AppAction::CopyUsernameRequested { secret_id })
    );
}

#[test]
fn selecting_postgresql_credential_from_picker_opens_add_form() {
    let mut state = unlocked_state(empty_vault());
    update(&mut state, AppAction::StartSecretTypePicker);

    let effects = update(&mut state, AppAction::PickPostgresCredential);

    assert_eq!(Screen::Form, state.screen());
    let form = state.form().expect("add form should exist");
    assert_eq!(FormMode::AddPostgreSqlCredential, form.mode());
    assert_eq!("5432", form.value(FormField::Port));
    assert_eq!("public", form.value(FormField::Schema));
    assert!(effects.is_empty());
}

#[test]
fn real_selected_tag_prefills_add_form_tags() {
    let mut state = unlocked_state(empty_vault());
    update(
        &mut state,
        AppAction::SelectFilter {
            filter: SelectedFilter::Tag("production".to_owned()),
        },
    );
    update(&mut state, AppAction::StartAddPostgres);

    assert_eq!(
        "production",
        state
            .form()
            .expect("add form should exist")
            .value(FormField::Tags)
    );
}

#[test]
fn synthetic_filters_do_not_prefill_add_form_tags() {
    let mut state = unlocked_state(empty_vault());
    update(
        &mut state,
        AppAction::SelectFilter {
            filter: SelectedFilter::Untagged,
        },
    );
    update(&mut state, AppAction::StartAddPostgres);

    assert_eq!(
        "",
        state
            .form()
            .expect("add form should exist")
            .value(FormField::Tags)
    );
}

#[test]
fn invalid_form_save_stays_in_form_without_save_effect() {
    let mut state = unlocked_state(empty_vault());
    update(&mut state, AppAction::StartAddPostgres);
    update(
        &mut state,
        AppAction::FormFieldChanged {
            field: FormField::Title,
            value: "   ".to_owned(),
        },
    );
    update(
        &mut state,
        AppAction::FormFieldChanged {
            field: FormField::Password,
            value: "correct horse battery staple".to_owned(),
        },
    );

    let effects = update(
        &mut state,
        AppAction::FormSaveRequested { now: timestamp() },
    );

    let form = state.form().expect("form should remain");
    assert_eq!(Screen::Form, state.screen());
    assert_eq!(Some(FormField::Title), form.focused_field());
    assert_eq!("   ", form.value(FormField::Title));
    assert!(!state.is_dirty());
    assert!(effects.is_empty());
}

#[test]
fn valid_add_form_creates_secret_and_saves() {
    let mut state = unlocked_state(empty_vault());
    update(&mut state, AppAction::StartAddPostgres);
    fill_valid_form(&mut state, "Production DB");

    let effects = update(
        &mut state,
        AppAction::FormSaveRequested { now: timestamp() },
    );

    assert_eq!(Screen::Main, state.screen());
    assert!(state.selected_secret().is_some());
    assert!(state.is_dirty());
    assert_eq!(vec![Effect::SaveVault], effects);
}

#[test]
fn enter_does_not_save_form_and_tab_moves_focus() {
    let mut state = unlocked_state(empty_vault());
    update(&mut state, AppAction::StartAddPostgres);

    let effects = update(&mut state, AppAction::FormEnterPressed);
    assert!(effects.is_empty());
    assert!(!state.is_dirty());

    update(&mut state, AppAction::FormNextField);
    assert_eq!(
        Some(FormField::Tags),
        state.form().expect("form should exist").focused_field()
    );
    update(&mut state, AppAction::FormPreviousField);
    assert_eq!(
        Some(FormField::Title),
        state.form().expect("form should exist").focused_field()
    );
}

#[test]
fn cancelled_discard_returns_to_form() {
    let mut state = unlocked_state(empty_vault());
    update(&mut state, AppAction::StartAddPostgres);
    update(&mut state, AppAction::FormChanged);
    update(&mut state, AppAction::FormEscapePressed);

    let effects = update(&mut state, AppAction::DiscardChangesCancelled);

    assert_eq!(Screen::Form, state.screen());
    assert_eq!(None, state.modal());
    assert!(effects.is_empty());
}

#[test]
fn text_input_and_backspace_edit_the_focused_form_field() {
    let mut state = unlocked_state(empty_vault());
    update(&mut state, AppAction::StartAddPostgres);

    update(
        &mut state,
        AppAction::FormTextInput {
            text: "Production D".to_owned(),
        },
    );
    update(
        &mut state,
        AppAction::FormTextInput {
            text: "B".to_owned(),
        },
    );
    update(&mut state, AppAction::FormBackspace);

    let form = state.form().expect("form should remain active");
    assert_eq!("Production D", form.value(FormField::Title));
    assert!(form.is_dirty());
}

#[test]
fn delete_cancel_returns_to_main_without_deleting_secret() {
    let vault = vault_with_postgres_secret("Production DB", &["production"]);
    let secret_id = vault.secrets()[0].id();
    let mut state = unlocked_state(vault);
    update(&mut state, AppAction::DeleteSecretRequested { secret_id });

    let effects = update(&mut state, AppAction::DeleteCancelled);

    assert_eq!(Screen::Main, state.screen());
    assert_eq!(None, state.modal());
    assert_eq!(Some(secret_id), state.selected_secret());
    assert!(!state.is_dirty());
    assert!(effects.is_empty());
}

#[test]
fn valid_edit_form_updates_existing_secret_and_saves() {
    let vault = vault_with_postgres_secret("Production DB", &["production"]);
    let secret_id = vault.secrets()[0].id();
    let mut state = unlocked_state(vault);
    update(&mut state, AppAction::StartEditPostgres { secret_id });
    update(
        &mut state,
        AppAction::FormFieldChanged {
            field: FormField::Title,
            value: "Staging DB".to_owned(),
        },
    );

    let effects = update(
        &mut state,
        AppAction::FormSaveRequested { now: timestamp() },
    );

    assert_eq!(Screen::Main, state.screen());
    assert_eq!(Some(secret_id), state.selected_secret());
    assert!(state.is_dirty());
    assert_eq!(vec![Effect::SaveVault], effects);
    let VaultSession::Unlocked { vault } = state.session() else {
        panic!("state should remain unlocked");
    };
    assert_eq!("Staging DB", vault.secrets()[0].title());
}

#[test]
fn cancelled_quit_without_saving_returns_to_dirty_main_screen() {
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
            error: VaultPersistenceError::PathUnavailable,
        },
    );

    let effects = update(&mut state, AppAction::QuitWithoutSavingCancelled);

    assert_eq!(Screen::Main, state.screen());
    assert_eq!(None, state.modal());
    assert!(state.is_dirty());
    assert!(effects.is_empty());
}

#[test]
fn debug_output_redacts_app_state_details() {
    let state = unlocked_state(vault_with_postgres_secret("Production DB", &["production"]));
    let debug = format!("{state:?}");

    assert!(!debug.contains("Production DB"));
    assert!(!debug.contains("db.example.com"));
    assert!(!debug.contains("app_user"));
    assert!(!debug.contains("production"));
}

#[test]
fn debug_output_redacts_form_state_values() {
    let mut state = unlocked_state(empty_vault());
    update(&mut state, AppAction::StartAddPostgres);
    fill_valid_form(&mut state, "Production DB");

    let debug = format!("{:?}", state.form().expect("form should exist"));

    assert!(!debug.contains("Production DB"));
    assert!(!debug.contains("db.example.com"));
    assert!(!debug.contains("app_user"));
    assert!(!debug.contains("correct horse battery staple"));
}

#[test]
fn dirty_form_escape_opens_discard_confirmation() {
    let mut state = unlocked_state(empty_vault());
    update(&mut state, AppAction::StartAddPostgres);
    update(&mut state, AppAction::FormChanged);

    let effects = update(&mut state, AppAction::FormEscapePressed);

    assert_eq!(Screen::Modal, state.screen());
    assert_eq!(Some(ModalState::DiscardChanges), state.modal());
    assert!(effects.is_empty());
}

#[test]
fn confirmed_discard_returns_to_main_without_changing_vault() {
    let mut state = unlocked_state(empty_vault());
    update(&mut state, AppAction::StartAddPostgres);
    update(&mut state, AppAction::FormChanged);
    update(&mut state, AppAction::FormEscapePressed);

    let effects = update(&mut state, AppAction::DiscardChangesConfirmed);

    assert_eq!(Screen::Main, state.screen());
    assert_eq!(None, state.form());
    assert_eq!(None, state.modal());
    assert!(!state.is_dirty());
    assert!(effects.is_empty());
}

#[test]
fn quit_is_ignored_in_forms() {
    let mut state = unlocked_state(empty_vault());
    update(&mut state, AppAction::StartAddPostgres);
    update(&mut state, AppAction::FormChanged);

    let effects = update(&mut state, AppAction::QuitRequested);

    assert_eq!(Screen::Form, state.screen());
    assert!(state.form().expect("form should exist").is_dirty());
    assert!(effects.is_empty());
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

fn fill_valid_form(state: &mut AppState, title: &str) {
    for (field, value) in [
        (FormField::Title, title),
        (FormField::Hostname, "db.example.com"),
        (FormField::Database, "app_production"),
        (FormField::Username, "app_user"),
        (FormField::Password, "correct horse battery staple"),
        (FormField::Tags, "production"),
    ] {
        update(
            state,
            AppAction::FormFieldChanged {
                field,
                value: value.to_owned(),
            },
        );
    }
}
