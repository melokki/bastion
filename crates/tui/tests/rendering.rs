use bastion_core::{
    ApiKeyToken, ApiKeyTokenInput, ApiTokenKind, DatabaseEngine, PostgreSqlCredential,
    PostgreSqlCredentialInput, Secret, Vault,
};
use bastion_tui::{
    AppAction, AppState, FormField, MasterPassphraseField, PanelFocus, SelectedFilter, render_app,
    update,
};
use chrono::{TimeZone, Utc};
use ratatui::{Terminal, backend::TestBackend, buffer::Buffer, style::Color};

#[test]
fn renders_main_layout_with_empty_vault() {
    let output = render_state(unlocked_state(empty_vault()), 100, 30);

    assert!(output.contains("Vault: Personal"));
    assert!(!output.contains("Search: -"));
    assert!(output.contains("Items"));
    assert!(output.contains("Tags"));
    assert!(output.contains("Details"));
    assert!(output.contains("No secrets yet"));
    assert!(output.contains("Add your first Database Credential."));
    assert!(output.contains("[a] add secret"));
    assert!(output.contains("All 0"));
    assert!(output.contains("Untagged 0"));
    assert!(output.contains("[a] add"));
    assert!(output.contains("[/] search"));
    assert!(output.contains("[Space] commands"));
    assert!(output.contains("[?] help"));
    assert!(output.contains("[r] reveal"));
    assert!(output.contains("[l] lock"));
    assert!(!output.contains("Add a Database Credential to get started."));
}

#[test]
fn renders_empty_selected_tag_state() {
    let mut state = unlocked_state(vault_with_postgres_secret("Production DB", &["production"]));
    update(
        &mut state,
        AppAction::SelectFilter {
            filter: SelectedFilter::Tag("staging".to_owned()),
        },
    );

    let output = render_state(state, 100, 30);

    assert!(output.contains("Tag: #staging"));
    assert!(output.contains("No items tagged #staging."));
    assert!(output.contains("[a] add secret"));
    assert!(!output.contains("No secrets yet"));
}

#[test]
fn renders_empty_untagged_state() {
    let mut state = unlocked_state(vault_with_postgres_secret("Production DB", &["production"]));
    update(
        &mut state,
        AppAction::SelectFilter {
            filter: SelectedFilter::Untagged,
        },
    );

    let output = render_state(state, 100, 30);

    assert!(output.contains("Tag: untagged"));
    assert!(output.contains("No untagged secrets."));
    assert!(output.contains("[a] add secret"));
    assert!(!output.contains("No secrets yet"));
}

#[test]
fn renders_search_palette_overlay_without_filtering_main_list() {
    let mut state = unlocked_state(vault_with_two_postgres_secrets());
    update(&mut state, AppAction::SearchRequested);
    update(
        &mut state,
        AppAction::SearchTextInput {
            text: "local".to_owned(),
        },
    );

    let output = render_state(state, 100, 30);

    assert!(output.contains("Vault: Personal"));
    assert!(output.contains("Production DB"));
    assert!(output.contains("Search Items"));
    assert!(output.contains("> local█"));
    assert!(output.contains("1 Local DB"));
    assert!(output.contains("#local"));
    assert!(output.contains("[Enter] select"));
    assert!(output.contains("[Esc] close"));
}

#[test]
fn renders_empty_search_state_without_matching_password_plaintext() {
    let mut input = postgres_input("Production DB", &["production"]);
    input.password = "needle-only-password".to_owned();
    let mut vault = empty_vault();
    vault.add_secret(
        Secret::new_postgres(
            PostgreSqlCredential::new(input).expect("credential should be valid"),
            timestamp(),
        ),
        timestamp(),
    );
    let mut state = unlocked_state(vault);
    update(&mut state, AppAction::SearchRequested);
    update(
        &mut state,
        AppAction::SearchTextInput {
            text: "needle".to_owned(),
        },
    );

    let output = render_state(state, 100, 30);

    assert!(output.contains("No items found for \"needle\"."));
    assert!(!output.contains("needle-only-password"));
}

#[test]
fn renders_copy_feedback_without_exposing_password() {
    let mut state = unlocked_state(vault_with_postgres_secret("Production DB", &["production"]));
    update(&mut state, AppAction::CopySelectedPasswordRequested);

    let output = render_state(state, 100, 30);

    assert!(output.contains("Copied password for Production DB."));
    assert!(output.contains("[c] password"));
    assert!(!output.contains("correct horse battery staple"));
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
    assert!(!output.contains("Add a Database Credential to get started."));
    assert!(output.contains("New Database Credential"));
    assert!(output.contains("Basic"));
    assert!(output.contains("Connection"));
    assert!(output.contains("Credentials"));
    assert!(output.contains("› Title     Production DB█"));
    assert!(output.contains("Engine    PostgreSQL ▾"));
    assert!(output.contains("[Enter] choose engine"));
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
    assert!(output.contains("› 1 Database Credential"));
    assert!(output.contains("API Token / Access Token"));
    assert!(output.contains("Account Recovery"));
    assert!(output.contains("Store hostname, port, database, username, and password."));
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
    assert!(output.contains("New Database Credential"));
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
    for _ in 0..8 {
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
    assert!(output.contains("Database Credential"));
    assert!(output.contains("Engine: PostgreSQL"));
    assert!(output.contains("postgresql://app_user:*******@db.example.com:5432"));
    assert!(output.contains("app_production?schema=public"));
    assert!(output.contains("Schema    public"));
    assert!(output.contains("app_user"));
    assert!(output.contains("••••"));
    assert!(!output.contains("correct horse battery staple"));
}

#[test]
fn renders_postgresql_details_without_empty_schema_line() {
    let output = render_state(
        unlocked_state(vault_with_postgres_secret_and_schema(
            "Production DB",
            &["production"],
            Some("   ".to_owned()),
        )),
        100,
        30,
    );

    assert!(output.contains("Production DB"));
    assert!(output.contains("Database Credential"));
    assert!(!output.contains("Schema"));
    assert!(!output.contains("correct horse battery staple"));
}

#[test]
fn renders_api_key_token_details_with_masked_token() {
    let output = render_state(unlocked_state(vault_with_api_key_token()), 100, 30);

    assert!(output.contains("Cloudflare API Token"));
    assert!(output.contains("Type: API Key / Token"));
    assert!(output.contains("Kind: API Key"));
    assert!(output.contains("Service   Cloudflare"));
    assert!(output.contains("Account   ops@example.com"));
    assert!(output.contains("Token     ••••"));
    assert!(!output.contains("cf-secret-token"));
}

#[test]
fn renders_revealed_password_only_while_reveal_state_is_active() {
    let mut state = unlocked_state(vault_with_postgres_secret("Production DB", &["production"]));
    let now = timestamp();
    update(&mut state, AppAction::RevealSelectedSecretRequested);
    update(&mut state, AppAction::RevealSecretConfirmed { now });

    let revealed = render_state(state, 100, 30);

    assert!(revealed.contains("Password  correct horse battery staple"));

    let mut expired_state =
        unlocked_state(vault_with_postgres_secret("Production DB", &["production"]));
    update(&mut expired_state, AppAction::RevealSelectedSecretRequested);
    update(&mut expired_state, AppAction::RevealSecretConfirmed { now });
    update(
        &mut expired_state,
        AppAction::RevealExpired {
            now: now + chrono::Duration::seconds(11),
        },
    );

    let expired = render_state(expired_state, 100, 30);

    assert!(expired.contains("Password  ••••"));
    assert!(!expired.contains("correct horse battery staple"));
}

#[test]
fn renders_revealed_api_token_only_while_reveal_state_is_active() {
    let mut state = unlocked_state(vault_with_api_key_token());
    update(&mut state, AppAction::RevealSelectedSecretRequested);
    update(
        &mut state,
        AppAction::RevealSecretConfirmed { now: timestamp() },
    );

    let output = render_state(state, 100, 30);

    assert!(output.contains("Token     cf-secret-token"));
}

#[test]
fn renders_help_overlay_with_grouped_shortcuts() {
    let mut state = unlocked_state(empty_vault());
    update(&mut state, AppAction::HelpRequested);

    let output = render_state(state, 100, 30);

    assert!(output.contains("Help"));
    assert!(output.contains("Panels"));
    assert!(output.contains("Search"));
    assert!(output.contains("Secrets"));
    assert!(output.contains("Global"));
    assert!(output.contains("/        Search items within current tag/filter"));
    assert!(output.contains("r        Reveal selected secret temporarily"));
    assert!(output.contains("Space    Command palette"));
    assert!(output.contains("?        Help"));
}

#[test]
fn renders_command_palette_with_filtered_commands() {
    let mut state = unlocked_state(vault_with_postgres_secret("Production DB", &["production"]));
    update(&mut state, AppAction::CommandPaletteRequested);
    update(
        &mut state,
        AppAction::CommandPaletteTextInput {
            text: "copy".to_owned(),
        },
    );

    let output = render_state(state, 100, 30);

    assert!(output.contains("Command Palette"));
    assert!(output.contains("> copy█"));
    assert!(output.contains("════════════════════════════════════════"));
    assert!(output.contains("› 1 Copy password/token"));
    assert!(output.contains("Copy username/account"));
    assert!(output.contains("[1-9] choose"));
    assert!(output.contains("[Enter] run"));
    assert!(output.contains("[Esc] close"));
    assert!(output.contains("      [↑/↓] move"));
    assert!(!output.contains("correct horse battery staple"));
}

#[test]
fn renders_database_engine_picker_as_separate_numbered_list() {
    let mut state = unlocked_state(empty_vault());
    update(&mut state, AppAction::StartAddPostgres);
    update(&mut state, AppAction::FormNextField);
    update(&mut state, AppAction::FormNextField);
    update(&mut state, AppAction::FormEnterPressed);
    update(&mut state, AppAction::SelectNextDatabaseEngine);

    let output = render_backend(state, 100, 30);
    let text = output.to_string();

    assert!(text.contains("Database Engine"));
    assert!(text.contains("  1 PostgreSQL"));
    assert!(text.contains("› 2 MySQL"));
    assert!(text.contains("  3 MariaDB"));
    assert!(text.contains("  4 Other"));
    assert!(text.contains("[1-4] select"));
    assert!(text.contains("[Esc] back"));
    assert_row_has_background(output.buffer(), "› 2 MySQL");
}

#[test]
fn command_palette_selected_result_has_strong_background_highlight() {
    let mut state = unlocked_state(vault_with_postgres_secret("Production DB", &["production"]));
    update(&mut state, AppAction::CommandPaletteRequested);
    update(
        &mut state,
        AppAction::CommandPaletteTextInput {
            text: "copy".to_owned(),
        },
    );

    let output = render_backend(state, 100, 30);

    assert_row_has_background(output.buffer(), "› 1 Copy password/token");
    assert_row_background_color(
        output.buffer(),
        "› 1 Copy password/token",
        Color::Indexed(236),
    );
    assert_text_foreground_color(
        output.buffer(),
        "════════════════════════════════════════",
        Color::Gray,
    );
}

#[test]
fn renders_secret_type_picker_with_api_key_token_option() {
    let mut state = unlocked_state(empty_vault());
    update(&mut state, AppAction::StartSecretTypePicker);
    update(&mut state, AppAction::SelectNextSecretType);

    let output = render_state(state, 100, 30);

    assert!(output.contains("Database Credential"));
    assert!(output.contains("› 2 API Token / Access Token"));
    assert!(output.contains("Account Recovery"));
    assert!(
        output.contains("Store tokens for APIs, CLIs, automation, registries, and integrations.")
    );
    assert!(output.contains("[↑/↓] choose"));
    assert!(output.contains("[Enter] select"));
}

#[test]
fn renders_secret_type_picker_with_account_recovery_option() {
    let mut state = unlocked_state(empty_vault());
    update(&mut state, AppAction::StartSecretTypePicker);
    update(&mut state, AppAction::SelectNextSecretType);
    update(&mut state, AppAction::SelectNextSecretType);

    let output = render_state(state, 100, 30);

    assert!(output.contains("Database Credential"));
    assert!(output.contains("API Token / Access Token"));
    assert!(output.contains("› 3 Account Recovery"));
    assert!(output.contains("Store recovery codes, phrases, keys, files, or instructions."));
}

#[test]
fn selected_item_uses_pointer_and_background_highlight() {
    let output = render_backend(
        unlocked_state(vault_with_postgres_secret("Production DB", &["production"])),
        100,
        30,
    );

    assert!(output.to_string().contains("› Production DB"));
    assert_row_has_background(output.buffer(), "› Production DB");
}

#[test]
fn selected_tag_filter_uses_pointer_and_background_highlight() {
    let mut state = unlocked_state(vault_with_postgres_secret("Production DB", &["production"]));
    update(
        &mut state,
        AppAction::SelectFilter {
            filter: SelectedFilter::Tag("production".to_owned()),
        },
    );

    let output = render_backend(state, 100, 30);

    assert!(output.to_string().contains("› #production 1"));
    assert_row_has_background(output.buffer(), "› #production 1");
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
fn details_panel_renders_to_the_right_of_the_secret_list_with_a_clear_divider() {
    let output = render_backend(
        unlocked_state(vault_with_postgres_secret("Production DB", &["production"])),
        100,
        30,
    );

    let item = position_containing(output.buffer(), "› Production DB")
        .expect("selected item should render");
    let details =
        position_containing(output.buffer(), "Details").expect("details panel should render");
    let detail_text = position_containing(output.buffer(), "Type: Database Credential")
        .expect("details content should render");

    assert!(
        details.0 > item.0,
        "details panel title should be right of item list"
    );
    assert!(
        detail_text.0 > item.0,
        "details content should be right of item list"
    );
    assert!(
        vertical_rule_between(output.buffer(), item.0, detail_text.0),
        "expected a visible vertical divider between list and details"
    );
}

#[test]
fn renders_recovery_code_set_material_as_multiline_textarea() {
    let mut state = unlocked_state(empty_vault());
    update(&mut state, AppAction::PickAccountRecovery);
    update(&mut state, AppAction::PickRecoveryKind);
    for _ in 0..5 {
        update(&mut state, AppAction::FormNextField);
    }
    update(
        &mut state,
        AppAction::FormFieldChanged {
            field: FormField::RecoveryMaterial,
            value: "gho_111\n\ngho_222\ngho_333".to_owned(),
        },
    );

    let output = render_state(state, 100, 30);

    assert!(output.contains("Recovery Code Set"));
    assert!(output.contains("Codes"));
    assert!(output.contains("┌──────────────────────────────────────────────────────────┐"));
    assert!(output.contains("•••••••"));
    assert!(output.contains("•••••••█"));
    assert!(!output.contains("gho_111"));
    assert!(!output.contains("gho_222"));
    assert!(!output.contains("gho_333"));
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
    render_backend(state, width, height).to_string()
}

fn render_backend(state: AppState, width: u16, height: u16) -> TestBackend {
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).expect("test backend should create terminal");
    terminal
        .draw(|frame| render_app(frame, &state))
        .expect("render should succeed");

    terminal.backend().clone()
}

fn assert_row_has_background(buffer: &Buffer, label: &str) {
    let row = row_containing(buffer, label)
        .unwrap_or_else(|| panic!("expected rendered row containing {label:?}"));

    let has_background = (buffer.area.x..buffer.area.x + buffer.area.width).any(|x| {
        buffer
            .cell((x, row))
            .is_some_and(|cell| cell.bg != Color::Reset)
    });

    assert!(
        has_background,
        "expected row containing {label:?} to have a background highlight"
    );
}

fn assert_row_background_color(buffer: &Buffer, label: &str, expected: Color) {
    let row = row_containing(buffer, label)
        .unwrap_or_else(|| panic!("expected rendered row containing {label:?}"));

    let has_expected_background = (buffer.area.x..buffer.area.x + buffer.area.width).any(|x| {
        buffer
            .cell((x, row))
            .is_some_and(|cell| cell.bg == expected)
    });

    assert!(
        has_expected_background,
        "expected row containing {label:?} to use background {expected:?}"
    );
}

fn assert_text_foreground_color(buffer: &Buffer, text: &str, expected: Color) {
    let width = text.chars().count() as u16;
    let has_expected_foreground = (buffer.area.y..buffer.area.y + buffer.area.height).any(|y| {
        let row = (buffer.area.x..buffer.area.x + buffer.area.width)
            .filter_map(|x| buffer.cell((x, y)))
            .map(|cell| cell.symbol())
            .collect::<String>();
        row.match_indices(text).any(|(byte_index, _)| {
            let column_offset = row[..byte_index].chars().count() as u16;
            let start = buffer.area.x + column_offset;
            (start..start + width).all(|column| {
                buffer
                    .cell((column, y))
                    .is_some_and(|cell| cell.fg == expected)
            })
        })
    });

    assert!(
        has_expected_foreground,
        "expected text {text:?} to use foreground {expected:?}"
    );
}

fn row_containing(buffer: &Buffer, needle: &str) -> Option<u16> {
    (buffer.area.y..buffer.area.y + buffer.area.height).find(|&y| {
        let row = (buffer.area.x..buffer.area.x + buffer.area.width)
            .filter_map(|x| buffer.cell((x, y)))
            .map(|cell| cell.symbol())
            .collect::<String>();
        row.contains(needle)
    })
}

fn position_containing(buffer: &Buffer, needle: &str) -> Option<(u16, u16)> {
    (buffer.area.y..buffer.area.y + buffer.area.height).find_map(|y| {
        let row = (buffer.area.x..buffer.area.x + buffer.area.width)
            .filter_map(|x| buffer.cell((x, y)))
            .map(|cell| cell.symbol())
            .collect::<String>();
        row.find(needle).map(|x| (buffer.area.x + x as u16, y))
    })
}

fn vertical_rule_between(buffer: &Buffer, left_x: u16, right_x: u16) -> bool {
    if left_x >= right_x {
        return false;
    }

    (buffer.area.y..buffer.area.y + buffer.area.height).any(|y| {
        (left_x + 1..right_x).any(|x| {
            buffer
                .cell((x, y))
                .is_some_and(|cell| matches!(cell.symbol(), "│" | "┤" | "├" | "┬" | "┴" | "┼"))
        })
    })
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
    vault_with_postgres_secret_and_schema(title, tags, Some("public".to_owned()))
}

fn vault_with_two_postgres_secrets() -> Vault {
    let mut vault = empty_vault();
    for (title, tags) in [
        ("Local DB", ["local"].as_slice()),
        ("Production DB", ["production"].as_slice()),
    ] {
        vault.add_secret(
            Secret::new_postgres(
                PostgreSqlCredential::new(postgres_input(title, tags))
                    .expect("credential should be valid"),
                timestamp(),
            ),
            timestamp(),
        );
    }
    vault
}

fn vault_with_postgres_secret_and_schema(
    title: &str,
    tags: &[&str],
    schema: Option<String>,
) -> Vault {
    let mut vault = empty_vault();
    let mut input = postgres_input(title, tags);
    input.schema = schema;
    vault.add_secret(
        Secret::new_postgres(
            PostgreSqlCredential::new(input).expect("credential should be valid"),
            timestamp(),
        ),
        timestamp(),
    );
    vault
}

fn vault_with_api_key_token() -> Vault {
    let mut vault = empty_vault();
    vault.add_secret(
        Secret::new_api_key_token(
            ApiKeyToken::new(api_key_token_input()).expect("token should be valid"),
            timestamp(),
        ),
        timestamp(),
    );
    vault
}

fn postgres_input(title: &str, tags: &[&str]) -> PostgreSqlCredentialInput {
    PostgreSqlCredentialInput {
        title: title.to_owned(),
        engine: DatabaseEngine::PostgreSql,
        hostname: "db.example.com".to_owned(),
        port: 5432,
        database: "app_production".to_owned(),
        username: "app_user".to_owned(),
        password: "correct horse battery staple".to_owned(),
        schema: Some("public".to_owned()),
        tags: tags.iter().map(|tag| (*tag).to_owned()).collect(),
    }
}

fn api_key_token_input() -> ApiKeyTokenInput {
    ApiKeyTokenInput {
        title: "Cloudflare API Token".to_owned(),
        service: "Cloudflare".to_owned(),
        kind: ApiTokenKind::ApiKey,
        token: "cf-secret-token".to_owned(),
        account: Some("ops@example.com".to_owned()),
        url: Some("https://dash.cloudflare.com".to_owned()),
        tags: vec!["production".to_owned()],
    }
}

fn timestamp() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 7, 1, 12, 0, 0).unwrap()
}
