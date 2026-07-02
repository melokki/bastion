use crate::{
    AppState, FormField, FormMode, MasterPassphraseField, ModalState, PanelFocus, Screen,
    SelectedFilter, VaultSession,
};
use bastion_core::{RecoveryMaterial, Secret, SecretFilter, SecretKind, Vault};
use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap},
};
use secrecy::ExposeSecret;

const MIN_WIDTH: u16 = 80;
const MIN_HEIGHT: u16 = 24;

pub fn render_app(frame: &mut Frame<'_>, state: &AppState) {
    let area = frame.area();
    if area.width < MIN_WIDTH || area.height < MIN_HEIGHT {
        frame.render_widget(
            Paragraph::new("Terminal too small\nMinimum size is 80x24.")
                .block(Block::bordered().title("Bastion")),
            area,
        );
        return;
    }

    match state.screen() {
        Screen::Onboarding => render_onboarding(frame, area, state),
        Screen::Locked => render_locked(frame, area, state),
        Screen::Main => {
            render_main(frame, area, state);
            if state.is_search_active() {
                render_search_palette(frame, area, state);
            }
        }
        Screen::SecretTypePicker => {
            render_main(frame, area, state);
            render_picker(frame, area, state);
        }
        Screen::ApiTokenKindPicker => {
            render_main(frame, area, state);
            render_api_token_kind_picker(frame, area, state);
        }
        Screen::RecoveryKindPicker => {
            render_main(frame, area, state);
            render_recovery_kind_picker(frame, area, state);
        }
        Screen::Form => {
            render_main(frame, area, state);
            render_form(frame, area, state);
        }
        Screen::Modal => {
            render_modal_background(frame, area, state);
            render_modal(frame, area, state);
        }
    }
}

fn render_onboarding(frame: &mut Frame<'_>, area: Rect, state: &AppState) {
    let passphrase_mask = state.master_passphrase_mask();
    let confirmation_mask = state.master_passphrase_confirmation_mask();
    let text = vec![
        Line::from("No vault was found."),
        Line::from("Create your local encrypted vault."),
        Line::from("Bastion cannot recover this passphrase."),
        Line::from(""),
        master_passphrase_line(
            "Master passphrase",
            &passphrase_mask,
            state.master_passphrase_field() == MasterPassphraseField::Passphrase,
        ),
        master_passphrase_line(
            "Confirm passphrase",
            &confirmation_mask,
            state.master_passphrase_field() == MasterPassphraseField::Confirmation,
        ),
        Line::from(""),
        status_line(state),
        Line::from(""),
        shortcut_line(&[
            ("Tab", "switch field"),
            ("Enter", "create vault"),
            ("Esc", "quit"),
        ]),
    ];
    render_popup_paragraph(frame, centered(area, 62, 12), "Welcome to Bastion", text);
}

fn render_locked(frame: &mut Frame<'_>, area: Rect, state: &AppState) {
    let passphrase_mask = state.master_passphrase_mask();
    let text = vec![
        Line::from("Vault locked"),
        Line::from(""),
        master_passphrase_line("Master passphrase", &passphrase_mask, true),
        Line::from(""),
        status_line(state),
        Line::from(""),
        shortcut_line(&[("Enter", "unlock"), ("Esc", "quit")]),
    ];
    render_popup_paragraph(frame, centered(area, 54, 11), "Bastion", text);
}

fn render_main(frame: &mut Frame<'_>, area: Rect, state: &AppState) {
    let footer_height = if state.status_message().is_some() {
        4
    } else {
        3
    };
    let [header, body, footer] = Layout::vertical([
        Constraint::Length(3),
        Constraint::Fill(1),
        Constraint::Length(footer_height),
    ])
    .areas(area);
    let [left, details] =
        Layout::horizontal([Constraint::Length(32), Constraint::Fill(1)]).areas(body);
    let [items, tags] =
        Layout::vertical([Constraint::Percentage(60), Constraint::Fill(1)]).areas(left);

    let VaultSession::Unlocked { vault } = state.session() else {
        return;
    };

    render_header(frame, header, vault, state);
    render_items(frame, items, vault, state);
    render_tags(frame, tags, vault, state);
    render_details(frame, details, vault, state);
    render_footer(frame, footer, state);
}

fn render_header(frame: &mut Frame<'_>, area: Rect, vault: &Vault, state: &AppState) {
    frame.render_widget(
        Paragraph::new(format!(
            "Vault: {}        Tag: {}",
            vault.name(),
            filter_label(state.selected_filter()),
        ))
        .block(Block::bordered().title("Bastion")),
        area,
    );
}

fn render_items(frame: &mut Frame<'_>, area: Rect, vault: &Vault, state: &AppState) {
    let items = vault.visible_secrets(secret_filter(state.selected_filter()));
    let title = if state.panel_focus() == PanelFocus::Items {
        "Items [1] focused"
    } else {
        "Items [1]"
    };
    if items.is_empty() {
        frame.render_widget(
            Paragraph::new(empty_items_message(state))
                .block(panel_block(title, state.panel_focus() == PanelFocus::Items)),
            area,
        );
        return;
    }
    let selected_index = items
        .iter()
        .position(|secret| Some(secret.id()) == state.selected_secret());
    let mut list_state = ListState::default();
    list_state.select(selected_index);

    let panel_focused = state.panel_focus() == PanelFocus::Items;
    let rows = items
        .iter()
        .map(|secret| ListItem::new(secret.title().to_owned()))
        .collect::<Vec<_>>();
    frame.render_stateful_widget(
        selectable_list(rows, title, panel_focused),
        area,
        &mut list_state,
    );
}

fn render_tags(frame: &mut Frame<'_>, area: Rect, vault: &Vault, state: &AppState) {
    let counts = vault.tag_counts();
    let title = if state.panel_focus() == PanelFocus::Tags {
        "Tags [2] focused"
    } else {
        "Tags [2]"
    };
    let mut selected_index = if matches!(state.selected_filter(), SelectedFilter::All) {
        Some(0)
    } else {
        None
    };
    let mut rows = vec![ListItem::new(format!("All {}", counts.all))];
    rows.extend(counts.tags.iter().enumerate().map(|(index, (tag, count))| {
        if state.selected_filter() == &SelectedFilter::Tag(tag.clone()) {
            selected_index = Some(index + 1);
        }
        ListItem::new(format!("#{tag} {count}"))
    }));
    let untagged_index = rows.len();
    if matches!(state.selected_filter(), SelectedFilter::Untagged) {
        selected_index = Some(untagged_index);
    }
    rows.push(ListItem::new(format!("Untagged {}", counts.untagged)));

    let mut list_state = ListState::default();
    list_state.select(selected_index);
    let panel_focused = state.panel_focus() == PanelFocus::Tags;
    frame.render_stateful_widget(
        selectable_list(rows, title, panel_focused),
        area,
        &mut list_state,
    );
}

fn render_details(frame: &mut Frame<'_>, area: Rect, vault: &Vault, state: &AppState) {
    let Some(secret) = state
        .selected_secret()
        .and_then(|id| vault.secrets().iter().find(|secret| secret.id() == id))
    else {
        frame.render_widget(
            Paragraph::new(empty_details_lines(state)).block(panel_block("Details", false)),
            area,
        );
        return;
    };

    frame.render_widget(
        Paragraph::new(secret_lines(secret, state)).block(panel_block("Details", false)),
        area,
    );
}

fn secret_lines(secret: &Secret, state: &AppState) -> Vec<Line<'static>> {
    match secret.kind() {
        SecretKind::PostgreSqlCredential(credential) => {
            let password = if state.is_revealed(crate::SecretRef::PostgreSqlPassword(secret.id())) {
                credential.password().expose_secret().to_owned()
            } else {
                "••••••••••••••••".to_owned()
            };
            let mut lines = vec![
                Line::from(credential.title().to_owned()).style(Style::new().bold()),
                Line::from("Type: PostgreSQL Credential"),
                Line::from(""),
                Line::from("Connection"),
                Line::from(format!("Hostname  {}", credential.hostname())),
                Line::from(format!("Port      {}", credential.port())),
                Line::from(format!("Database  {}", credential.database())),
            ];
            if let Some(schema) = credential.schema() {
                lines.push(Line::from(format!("Schema    {schema}")));
            }
            lines.extend([
                Line::from(""),
                Line::from("Credentials"),
                Line::from(format!("Username  {}", credential.username())),
                Line::from(format!("Password  {password}")),
            ]);
            lines
        }
        SecretKind::ApiKeyToken(token) => {
            let secret_token = if state.is_revealed(crate::SecretRef::ApiKeyToken(secret.id())) {
                token.token().expose_secret().to_owned()
            } else {
                "••••••••••••••••".to_owned()
            };
            let mut lines = vec![
                Line::from(token.title().to_owned()).style(Style::new().bold()),
                Line::from("Type: API Key / Token"),
                Line::from(format!("Kind: {}", token.kind().label())),
                Line::from(""),
                Line::from("Token"),
                Line::from(format!("Service   {}", token.service())),
            ];
            if let Some(account) = token.account() {
                lines.push(Line::from(format!("Account   {account}")));
            }
            if let Some(url) = token.url() {
                lines.push(Line::from(format!("URL       {url}")));
            }
            lines.extend([
                Line::from(""),
                Line::from("Secret"),
                Line::from(format!("Token     {secret_token}")),
            ]);
            lines
        }
        SecretKind::AccountRecovery(item) => {
            let mut lines = vec![
                Line::from(item.title().to_owned()).style(Style::new().bold()),
                Line::from("Type: Account Recovery"),
                Line::from(format!("Kind: {}", item.kind().label())),
                Line::from(format!("Service: {}", item.service())),
            ];
            if let Some(account) = item.account() {
                lines.push(Line::from(format!("Account: {account}")));
            }
            if !item.tags().is_empty() {
                lines.push(Line::from(format!("Tags: {}", item.tags().join(", "))));
            }
            lines.extend([Line::from(""), Line::from("Recovery material")]);
            match item.material() {
                RecoveryMaterial::CodeSet(_) => {
                    let (unused, total) = item.recovery_code_counts();
                    lines.push(Line::from(format!(
                        "Status     {unused} unused / {total} total"
                    )));
                    lines.push(Line::from("Next code  ••••••••••••••••"));
                }
                RecoveryMaterial::Phrase(phrase) => {
                    lines.push(Line::from(format!("Word count {}", phrase.word_count())));
                    lines.push(Line::from("Phrase     ••••••••••••••••"));
                }
                RecoveryMaterial::Key(_) => {
                    lines.push(Line::from(format!("Format     {}", item.format().label())));
                    lines.push(Line::from("Value      ••••••••••••••••"));
                }
                RecoveryMaterial::FileReference(reference) => {
                    if let Some(file_name) = reference.file_name() {
                        lines.push(Line::from(format!("File name  {file_name}")));
                    }
                    lines.push(Line::from(format!("Location   {}", reference.location())));
                }
                RecoveryMaterial::Instructions(_) => {
                    lines.push(Line::from("Instructions  ••••••••••••••••"));
                }
                RecoveryMaterial::SecurityQuestions(questions) => {
                    lines.push(Line::from(format!("Questions  {}", questions.len())));
                    lines.push(Line::from("Answers    ••••••••••••••••"));
                }
            }
            lines
        }
    }
}

fn empty_details_lines(state: &AppState) -> Vec<Line<'static>> {
    vec![
        Line::from(empty_items_message(state)).style(Style::new().add_modifier(Modifier::BOLD)),
        Line::from(""),
        Line::from("Add your first PostgreSQL credential."),
        Line::from(""),
        shortcut_line(&[("a", "add secret")]),
    ]
}

fn empty_items_message(state: &AppState) -> String {
    empty_filter_message(state.selected_filter())
}

fn empty_filter_message(filter: &SelectedFilter) -> String {
    match filter {
        SelectedFilter::All => "No secrets yet".to_owned(),
        SelectedFilter::Untagged => "No untagged secrets.".to_owned(),
        SelectedFilter::Tag(tag) => format!("No items tagged #{tag}."),
    }
}

fn render_footer(frame: &mut Frame<'_>, area: Rect, state: &AppState) {
    let shortcuts = match state.screen() {
        Screen::Main if state.status_message().is_some() => shortcut_line(&[
            ("c", "password"),
            ("r", "reveal"),
            ("a", "add"),
            ("/", "search"),
            ("Space", "commands"),
            ("?", "help"),
            ("l", "lock"),
        ]),
        Screen::Main => shortcut_line(&[
            ("1", "items"),
            ("2", "tags"),
            ("/", "search"),
            ("Space", "commands"),
            ("?", "help"),
            ("r", "reveal"),
            ("a", "add"),
            ("l", "lock"),
        ]),
        Screen::Form => shortcut_line(&[
            ("Tab", "next field"),
            ("Shift+Tab", "previous field"),
            ("Ctrl+S", "save"),
            ("Esc", "cancel"),
            ("?", "help"),
        ]),
        Screen::SecretTypePicker => shortcut_line(&[("Enter", "select"), ("Esc", "cancel")]),
        Screen::Onboarding => shortcut_line(&[
            ("Tab", "switch field"),
            ("Enter", "create vault"),
            ("Esc", "quit"),
        ]),
        Screen::Locked => shortcut_line(&[("Enter", "unlock"), ("Esc", "quit")]),
        _ => shortcut_line(&[("q", "quit")]),
    };
    let text = if state.screen() == Screen::Main {
        match state.status_message() {
            Some(message) => vec![
                Line::from(message.to_owned()).style(Style::new().fg(Color::Yellow)),
                shortcuts,
            ],
            None => vec![shortcuts],
        }
    } else {
        vec![shortcuts]
    };
    frame.render_widget(Paragraph::new(text).block(Block::bordered()), area);
}

fn render_picker(frame: &mut Frame<'_>, area: Rect, state: &AppState) {
    let database_selected =
        state.secret_type_choice() == crate::SecretTypeChoice::DatabaseCredential;
    let token_selected = state.secret_type_choice() == crate::SecretTypeChoice::ApiToken;
    let recovery_selected = state.secret_type_choice() == crate::SecretTypeChoice::AccountRecovery;
    let (details_title, details_body, examples) = match state.secret_type_choice() {
        crate::SecretTypeChoice::DatabaseCredential => (
            "Database Credential",
            "Store hostname, port, database, username, and password.",
            "Examples: PostgreSQL, MySQL, MariaDB.",
        ),
        crate::SecretTypeChoice::ApiToken => (
            "API Token / Access Token",
            "Store tokens for APIs, CLIs, automation, registries, and integrations.",
            "Examples: GitHub PAT, Cloudflare API token, webhook secret.",
        ),
        crate::SecretTypeChoice::AccountRecovery => (
            "Account Recovery",
            "Store recovery codes, phrases, keys, files, or instructions.",
            "Examples: GitHub codes, Proton phrase, Tuta code.",
        ),
    };
    let text = vec![
        Line::from("What do you want to store?"),
        Line::from(""),
        picker_row("Database Credential", database_selected),
        picker_row("API Token / Access Token", token_selected),
        picker_row("Account Recovery", recovery_selected),
        Line::from(""),
        section_header(details_title),
        Line::from(details_body),
        Line::from(examples),
        Line::from(""),
        shortcut_line(&[("↑/↓", "choose"), ("Enter", "select"), ("Esc", "cancel")]),
    ];
    render_popup_paragraph(frame, centered(area, 76, 14), "Add Secret", text);
}

fn render_api_token_kind_picker(frame: &mut Frame<'_>, area: Rect, state: &AppState) {
    let choice = state.api_token_kind_choice();
    let (details, examples) = match choice {
        crate::ApiTokenKindChoice::PersonalAccessToken => (
            "Token for user-owned API or CLI access.",
            "Examples: GitHub PAT, GitLab PAT, Codeberg token.",
        ),
        crate::ApiTokenKindChoice::ApiKey => (
            "Provider-issued API key for service access.",
            "Examples: Stripe, Cloudflare, OpenAI.",
        ),
        crate::ApiTokenKindChoice::BearerToken => (
            "Generic token used in Authorization headers.",
            "Use when the token is pasted as Bearer <token>.",
        ),
        crate::ApiTokenKindChoice::RegistryToken => (
            "Token for package or container registries.",
            "Examples: npm, crates.io, Docker registry.",
        ),
        crate::ApiTokenKindChoice::AppPassword => (
            "App-specific password for mail, calendar, or sync.",
            "Examples: Gmail app password, iCloud app password.",
        ),
        crate::ApiTokenKindChoice::WebhookSecret => (
            "Secret used to verify incoming webhook payloads.",
            "Examples: GitHub, Stripe, Slack webhook secret.",
        ),
        crate::ApiTokenKindChoice::OAuthClientSecret => (
            "Client secret for OAuth applications.",
            "Usually stored together with client ID and redirect URLs.",
        ),
        crate::ApiTokenKindChoice::GenericToken => (
            "Use when no other kind fits.",
            "Good for one-off integration secrets.",
        ),
    };
    let text = vec![
        Line::from("What kind of access secret do you want to store?"),
        Line::from(""),
        picker_row(
            "Personal Access Token",
            choice == crate::ApiTokenKindChoice::PersonalAccessToken,
        ),
        picker_row("API Key", choice == crate::ApiTokenKindChoice::ApiKey),
        picker_row(
            "Bearer Token",
            choice == crate::ApiTokenKindChoice::BearerToken,
        ),
        picker_row(
            "Registry Token",
            choice == crate::ApiTokenKindChoice::RegistryToken,
        ),
        picker_row(
            "App Password",
            choice == crate::ApiTokenKindChoice::AppPassword,
        ),
        picker_row(
            "Webhook Secret",
            choice == crate::ApiTokenKindChoice::WebhookSecret,
        ),
        picker_row(
            "OAuth Client Secret",
            choice == crate::ApiTokenKindChoice::OAuthClientSecret,
        ),
        picker_row(
            "Generic Token",
            choice == crate::ApiTokenKindChoice::GenericToken,
        ),
        Line::from(""),
        section_header(api_token_kind_label(choice)),
        Line::from(details),
        Line::from(examples),
        Line::from(""),
        shortcut_line(&[("↑/↓", "choose"), ("Enter", "select"), ("Esc", "back")]),
    ];
    render_popup_paragraph(frame, centered(area, 82, 20), "Access Token Type", text);
}

fn render_recovery_kind_picker(frame: &mut Frame<'_>, area: Rect, state: &AppState) {
    let choice = state.recovery_kind_choice();
    let (details, examples) = match choice {
        crate::RecoveryKindChoice::RecoveryCodeSet => (
            "Multiple backup codes, usually one code per line.",
            "Examples: GitHub, Google, Microsoft.",
        ),
        crate::RecoveryKindChoice::RecoveryPhrase => (
            "A phrase or ordered words used for recovery.",
            "Examples: Proton recovery phrase, wallet seed phrase.",
        ),
        crate::RecoveryKindChoice::RecoveryKey => (
            "One single recovery code, key, or token.",
            "Examples: Tuta recovery code, Apple recovery key.",
        ),
        crate::RecoveryKindChoice::RecoveryFile => (
            "A reference to a recovery kit, PDF, or key file.",
            "Examples: recovery kit PDF, offline emergency kit.",
        ),
        crate::RecoveryKindChoice::RecoveryInstructions => (
            "Manual recovery steps, offline notes, or procedure.",
            "Examples: where recovery papers are stored.",
        ),
        crate::RecoveryKindChoice::SecurityQuestions => (
            "Security questions with secret answers.",
            "Examples: bank security questions.",
        ),
    };
    let text = vec![
        Line::from("What kind of recovery material do you want to store?"),
        Line::from(""),
        picker_row(
            "Recovery Code Set",
            choice == crate::RecoveryKindChoice::RecoveryCodeSet,
        ),
        picker_row(
            "Recovery Phrase",
            choice == crate::RecoveryKindChoice::RecoveryPhrase,
        ),
        picker_row(
            "Recovery Key",
            choice == crate::RecoveryKindChoice::RecoveryKey,
        ),
        picker_row(
            "Recovery File",
            choice == crate::RecoveryKindChoice::RecoveryFile,
        ),
        picker_row(
            "Recovery Instructions",
            choice == crate::RecoveryKindChoice::RecoveryInstructions,
        ),
        picker_row(
            "Security Questions",
            choice == crate::RecoveryKindChoice::SecurityQuestions,
        ),
        Line::from(""),
        section_header(recovery_kind_label(choice)),
        Line::from(details),
        Line::from(examples),
        Line::from(""),
        shortcut_line(&[("↑/↓", "choose"), ("Enter", "select"), ("Esc", "back")]),
    ];
    render_popup_paragraph(frame, centered(area, 82, 18), "Account Recovery Type", text);
}

fn render_form(frame: &mut Frame<'_>, area: Rect, state: &AppState) {
    let Some(form) = state.form() else {
        return;
    };
    let mut text = vec![
        form_mode_line(form.mode(), form.value(FormField::Title), form.is_dirty()),
        Line::from(""),
    ];
    text.extend(form_body_lines(form));
    text.extend([
        form_metadata_line(form.mode(), form.is_dirty()),
        Line::from(""),
        shortcut_line(&[
            ("Tab", "next field"),
            ("Shift+Tab", "previous field"),
            ("Ctrl+S", "save"),
            ("Esc", "cancel"),
        ]),
    ]);
    let title = match form.mode() {
        FormMode::AddPostgreSqlCredential | FormMode::EditPostgreSqlCredential(_) => {
            "PostgreSQL Credential"
        }
        FormMode::AddApiKeyToken | FormMode::EditApiKeyToken(_) => "API Key / Token",
        FormMode::AddAccountRecovery(kind) => recovery_form_title(kind),
    };
    render_popup_paragraph(frame, centered(area, 80, 22), title, text);
}

fn form_body_lines(form: &crate::FormState) -> Vec<Line<'static>> {
    let focused_field = form.focused_field();
    let mut lines = vec![
        section_header("Basic"),
        form_input_line(
            "Title",
            form.value(FormField::Title),
            focused_field == Some(FormField::Title),
        ),
        form_input_line(
            "Tags",
            form.value(FormField::Tags),
            focused_field == Some(FormField::Tags),
        ),
        Line::from(""),
    ];

    match form.mode() {
        FormMode::AddPostgreSqlCredential | FormMode::EditPostgreSqlCredential(_) => {
            lines.extend([
                section_header("Connection"),
                form_input_line(
                    "Hostname",
                    form.value(FormField::Hostname),
                    focused_field == Some(FormField::Hostname),
                ),
                form_input_line(
                    "Port",
                    form.value(FormField::Port),
                    focused_field == Some(FormField::Port),
                ),
                form_input_line(
                    "Database",
                    form.value(FormField::Database),
                    focused_field == Some(FormField::Database),
                ),
                form_input_line(
                    "Schema",
                    form.value(FormField::Schema),
                    focused_field == Some(FormField::Schema),
                ),
                Line::from(""),
                section_header("Credentials"),
                form_input_line(
                    "Username",
                    form.value(FormField::Username),
                    focused_field == Some(FormField::Username),
                ),
                form_input_line(
                    "Password",
                    &mask_value(form.value(FormField::Password)),
                    focused_field == Some(FormField::Password),
                ),
            ]);
        }
        FormMode::AddApiKeyToken | FormMode::EditApiKeyToken(_) => {
            lines.extend([
                section_header("Token"),
                form_input_line(
                    "Service",
                    form.value(FormField::Service),
                    focused_field == Some(FormField::Service),
                ),
                form_input_line(
                    "Account",
                    form.value(FormField::Account),
                    focused_field == Some(FormField::Account),
                ),
                form_input_line(
                    "URL",
                    form.value(FormField::Url),
                    focused_field == Some(FormField::Url),
                ),
                Line::from(""),
                section_header("Secret"),
                form_input_line(
                    "Token",
                    &mask_value(form.value(FormField::Token)),
                    focused_field == Some(FormField::Token),
                ),
            ]);
        }
        FormMode::AddAccountRecovery(kind) => {
            lines.extend([
                section_header("Recovery"),
                form_input_line(
                    "Service",
                    form.value(FormField::Service),
                    focused_field == Some(FormField::Service),
                ),
                form_input_line(
                    "Account",
                    form.value(FormField::Account),
                    focused_field == Some(FormField::Account),
                ),
                form_input_line(
                    "URL",
                    form.value(FormField::Url),
                    focused_field == Some(FormField::Url),
                ),
                Line::from(""),
                section_header(recovery_form_title(kind)),
                form_input_line(
                    recovery_material_label(kind),
                    &mask_value(form.value(FormField::RecoveryMaterial)),
                    focused_field == Some(FormField::RecoveryMaterial),
                ),
            ]);
        }
    }

    lines
}

fn render_modal(frame: &mut Frame<'_>, area: Rect, state: &AppState) {
    let (title, text) = match state.modal() {
        Some(ModalState::DeleteSecret(secret_id)) => {
            ("Delete Secret", delete_modal_lines(state, secret_id))
        }
        Some(ModalState::DiscardChanges) => (
            "Discard Changes",
            vec![
                Line::from("Discard unsaved changes?"),
                Line::from(""),
                shortcut_line(&[("Enter", "discard changes"), ("Esc", "cancel")]),
            ],
        ),
        Some(ModalState::QuitWithoutSaving) => (
            "Quit Bastion",
            vec![
                Line::from("Quit without saving?"),
                Line::from(""),
                shortcut_line(&[("Enter", "quit without saving"), ("Esc", "cancel")]),
            ],
        ),
        Some(ModalState::RevealSecret(secret_ref)) => {
            ("Reveal Secret", reveal_modal_lines(state, secret_ref))
        }
        Some(ModalState::Help) => ("Help", help_lines()),
        Some(ModalState::CommandPalette) => ("Command Palette", command_palette_lines(state)),
        None => ("Confirm", Vec::new()),
    };
    let height = match state.modal() {
        Some(ModalState::Help) => 22,
        Some(ModalState::CommandPalette) => 16,
        _ => 10,
    };
    render_popup_paragraph(frame, centered(area, 68, height), title, text);
}

fn render_modal_background(frame: &mut Frame<'_>, area: Rect, state: &AppState) {
    if matches!(
        state.modal(),
        Some(ModalState::DiscardChanges | ModalState::Help)
    ) && state.form().is_some()
    {
        render_main(frame, area, state);
        render_form(frame, area, state);
        return;
    }

    if matches!(state.session(), VaultSession::Unlocked { .. }) {
        render_main(frame, area, state);
    }
}

fn delete_modal_lines(state: &AppState, secret_id: bastion_core::SecretId) -> Vec<Line<'static>> {
    let mut lines = vec![Line::from("Delete this secret?")];
    if let VaultSession::Unlocked { vault } = state.session()
        && let Some(secret) = vault
            .secrets()
            .iter()
            .find(|secret| secret.id() == secret_id)
    {
        lines.extend(delete_secret_summary(secret));
    }
    lines.push(Line::from(""));
    lines.push(shortcut_line(&[("Enter", "delete"), ("Esc", "cancel")]));
    lines
}

fn reveal_modal_lines(state: &AppState, secret_ref: crate::SecretRef) -> Vec<Line<'static>> {
    let field = match secret_ref {
        crate::SecretRef::PostgreSqlPassword(_) => "password",
        crate::SecretRef::PostgreSqlUsername(_) => "username",
        crate::SecretRef::ApiKeyToken(_) => "token",
    };
    let title = match secret_ref {
        crate::SecretRef::PostgreSqlPassword(secret_id)
        | crate::SecretRef::PostgreSqlUsername(secret_id)
        | crate::SecretRef::ApiKeyToken(secret_id) => title_for_secret(state, secret_id),
    }
    .unwrap_or_else(|| "selected item".to_owned());

    vec![
        Line::from(format!("Reveal {field} for {title}?")),
        Line::from(""),
        Line::from("The value will hide after 10 seconds or when context changes."),
        Line::from(""),
        shortcut_line(&[("Enter", "reveal for 10 seconds"), ("Esc", "cancel")]),
    ]
}

fn title_for_secret(state: &AppState, secret_id: bastion_core::SecretId) -> Option<String> {
    let VaultSession::Unlocked { vault } = state.session() else {
        return None;
    };
    vault
        .secrets()
        .iter()
        .find(|secret| secret.id() == secret_id)
        .map(|secret| secret.title().to_owned())
}

fn help_lines() -> Vec<Line<'static>> {
    vec![
        section_header("Panels"),
        Line::from("1        Focus Items panel"),
        Line::from("2        Focus Tags panel"),
        Line::from("↑/↓ jk   Move in focused panel"),
        Line::from(""),
        section_header("Search"),
        Line::from("/        Search items within current tag/filter"),
        Line::from("Esc      Clear search or go back"),
        Line::from(""),
        section_header("Secrets"),
        Line::from("a        Add secret"),
        Line::from("e        Edit selected secret"),
        Line::from("d        Delete selected secret"),
        Line::from("c        Copy password/token"),
        Line::from("u        Copy username/account"),
        Line::from("r        Reveal selected secret temporarily"),
        Line::from(""),
        section_header("Global"),
        Line::from("Space    Command palette"),
        Line::from("?        Help"),
        Line::from("l        Lock vault"),
    ]
}

fn render_search_palette(frame: &mut Frame<'_>, area: Rect, state: &AppState) {
    let mut lines = vec![
        Line::from(format!("> {}█", state.search_query())),
        Line::from(""),
    ];
    let items = state.search_palette_items();
    if items.is_empty() {
        lines.push(Line::from(format!(
            "No items found for \"{}\".",
            state.search_query()
        )));
    } else {
        lines.extend(items.into_iter().take(9).map(|(label, selected)| {
            Line::from(format!("{} {label}", if selected { "›" } else { " " }))
        }));
    }
    lines.extend([
        Line::from(""),
        shortcut_line(&[
            ("↑/↓", "move"),
            ("1-9", "choose"),
            ("Enter", "select"),
            ("Esc", "close"),
        ]),
    ]);
    let width = area.width.saturating_mul(4) / 5;
    let height = 16;
    let title = state.search_palette_title();
    render_popup_paragraph(frame, centered(area, width, height), &title, lines);
}

fn command_palette_lines(state: &AppState) -> Vec<Line<'static>> {
    let mut lines = vec![
        Line::from(format!("> {}█", state.command_palette_query())),
        Line::from(""),
    ];
    let items = state.command_palette_items();
    if items.is_empty() {
        lines.push(Line::from(format!(
            "No commands found for \"{}\".",
            state.command_palette_query()
        )));
    } else {
        lines.extend(
            items
                .into_iter()
                .take(9)
                .enumerate()
                .map(|(index, (label, selected))| {
                    Line::from(format!(
                        "{} {} {label}",
                        if selected { "›" } else { " " },
                        index + 1
                    ))
                }),
        );
    }
    lines.extend([
        Line::from(""),
        shortcut_line(&[
            ("↑/↓", "move"),
            ("1-9", "choose"),
            ("Enter", "run"),
            ("Esc", "close"),
        ]),
    ]);
    lines
}

fn delete_secret_summary(secret: &Secret) -> Vec<Line<'static>> {
    match secret.kind() {
        SecretKind::PostgreSqlCredential(credential) => vec![
            Line::from(format!("Title     {}", credential.title())),
            Line::from(format!("Hostname  {}", credential.hostname())),
            Line::from(format!("Database  {}", credential.database())),
            Line::from(format!("Username  {}", credential.username())),
        ],
        SecretKind::ApiKeyToken(token) => {
            let mut lines = vec![
                Line::from(format!("Title    {}", token.title())),
                Line::from(format!("Service  {}", token.service())),
            ];
            if let Some(account) = token.account() {
                lines.push(Line::from(format!("Account  {account}")));
            }
            lines
        }
        SecretKind::AccountRecovery(item) => vec![
            Line::from(format!("Title    {}", item.title())),
            Line::from(format!("Type     {}", item.kind().label())),
            Line::from(format!("Service  {}", item.service())),
        ],
    }
}

fn panel_block(title: &'static str, focused: bool) -> Block<'static> {
    let style = if focused {
        Style::new().fg(Color::Yellow).add_modifier(Modifier::BOLD)
    } else {
        Style::default()
    };
    Block::new()
        .borders(Borders::ALL)
        .title(title)
        .border_style(style)
}

fn active_window_block<'a>(title: &'a str) -> Block<'a> {
    Block::new()
        .borders(Borders::ALL)
        .title(title)
        .border_style(Style::new().fg(Color::Yellow).add_modifier(Modifier::BOLD))
}

fn selectable_list<'a>(
    rows: Vec<ListItem<'a>>,
    title: &'static str,
    panel_focused: bool,
) -> List<'a> {
    List::new(rows)
        .block(panel_block(title, panel_focused))
        .highlight_symbol("› ")
        .highlight_style(selected_row_style(panel_focused))
}

fn selected_row_style(panel_focused: bool) -> Style {
    if panel_focused {
        Style::new()
            .fg(Color::White)
            .bg(Color::DarkGray)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::new().fg(Color::Gray).bg(Color::Indexed(236))
    }
}

fn render_popup_paragraph<'a>(
    frame: &mut Frame<'_>,
    popup: Rect,
    title: &'a str,
    text: Vec<Line<'a>>,
) {
    frame.render_widget(Clear, popup);
    frame.render_widget(
        Paragraph::new(text)
            .style(Style::new().bg(Color::Black))
            .block(active_window_block(title))
            .wrap(Wrap { trim: true }),
        popup,
    );
}

fn shortcut_line(shortcuts: &[(&str, &str)]) -> Line<'static> {
    let mut spans = Vec::new();
    for (index, (key, action)) in shortcuts.iter().enumerate() {
        if index > 0 {
            spans.push(Span::raw("   "));
        }
        spans.push(Span::styled(
            format!("[{key}]"),
            Style::new().fg(Color::Yellow).add_modifier(Modifier::BOLD),
        ));
        spans.push(Span::raw(format!(" {action}")));
    }
    Line::from(spans)
}

fn form_mode_line(mode: FormMode, title: &str, dirty: bool) -> Line<'static> {
    match mode {
        FormMode::AddPostgreSqlCredential => {
            Line::from("New PostgreSQL Credential").style(Style::new().bold())
        }
        FormMode::EditPostgreSqlCredential(_) => {
            let title = if title.trim().is_empty() {
                "PostgreSQL Credential"
            } else {
                title
            };
            let status = if dirty { "Modified" } else { "Saved" };
            Line::from(vec![
                Span::styled(format!("Edit {title}"), Style::new().bold()),
                Span::raw("                                      "),
                Span::styled(status, Style::new().fg(Color::Yellow)),
            ])
        }
        FormMode::AddApiKeyToken => Line::from("New API Key / Token").style(Style::new().bold()),
        FormMode::AddAccountRecovery(kind) => {
            Line::from(format!("New {}", recovery_form_title(kind))).style(Style::new().bold())
        }
        FormMode::EditApiKeyToken(_) => {
            let title = if title.trim().is_empty() {
                "API Key / Token"
            } else {
                title
            };
            let status = if dirty { "Modified" } else { "Saved" };
            Line::from(vec![
                Span::styled(format!("Edit {title}"), Style::new().bold()),
                Span::raw("                                      "),
                Span::styled(status, Style::new().fg(Color::Yellow)),
            ])
        }
    }
}

fn form_metadata_line(mode: FormMode, dirty: bool) -> Line<'static> {
    match mode {
        FormMode::AddPostgreSqlCredential => Line::from(""),
        FormMode::AddApiKeyToken => Line::from(""),
        FormMode::AddAccountRecovery(_) => Line::from(""),
        FormMode::EditPostgreSqlCredential(_) => {
            let status = if dirty { "unsaved changes" } else { "saved" };
            Line::from(vec![
                Span::raw(""),
                Span::styled("Metadata", Style::new().add_modifier(Modifier::BOLD)),
                Span::raw(format!("  Updated  {status}")),
            ])
        }
        FormMode::EditApiKeyToken(_) => {
            let status = if dirty { "unsaved changes" } else { "saved" };
            Line::from(vec![
                Span::raw(""),
                Span::styled("Metadata", Style::new().add_modifier(Modifier::BOLD)),
                Span::raw(format!("  Updated  {status}")),
            ])
        }
    }
}

fn section_header(title: &str) -> Line<'static> {
    Line::from(Span::styled(
        title.to_owned(),
        Style::new().add_modifier(Modifier::BOLD),
    ))
}

fn picker_row(label: &str, selected: bool) -> Line<'static> {
    let marker = if selected { "›" } else { " " };
    let style = if selected {
        Style::new()
            .fg(Color::White)
            .bg(Color::DarkGray)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default()
    };
    Line::from(format!("{marker} {label}")).style(style)
}

fn api_token_kind_label(choice: crate::ApiTokenKindChoice) -> &'static str {
    match choice {
        crate::ApiTokenKindChoice::PersonalAccessToken => "Personal Access Token",
        crate::ApiTokenKindChoice::ApiKey => "API Key",
        crate::ApiTokenKindChoice::BearerToken => "Bearer Token",
        crate::ApiTokenKindChoice::RegistryToken => "Registry Token",
        crate::ApiTokenKindChoice::AppPassword => "App Password",
        crate::ApiTokenKindChoice::WebhookSecret => "Webhook Secret",
        crate::ApiTokenKindChoice::OAuthClientSecret => "OAuth Client Secret",
        crate::ApiTokenKindChoice::GenericToken => "Generic Token",
    }
}

fn recovery_kind_label(choice: crate::RecoveryKindChoice) -> &'static str {
    match choice {
        crate::RecoveryKindChoice::RecoveryCodeSet => "Recovery Code Set",
        crate::RecoveryKindChoice::RecoveryPhrase => "Recovery Phrase",
        crate::RecoveryKindChoice::RecoveryKey => "Recovery Key",
        crate::RecoveryKindChoice::RecoveryFile => "Recovery File",
        crate::RecoveryKindChoice::RecoveryInstructions => "Recovery Instructions",
        crate::RecoveryKindChoice::SecurityQuestions => "Security Questions",
    }
}

fn recovery_form_title(choice: crate::RecoveryKindChoice) -> &'static str {
    match choice {
        crate::RecoveryKindChoice::RecoveryCodeSet => "Recovery Code Set",
        crate::RecoveryKindChoice::RecoveryPhrase => "Recovery Phrase",
        crate::RecoveryKindChoice::RecoveryKey => "Recovery Key",
        crate::RecoveryKindChoice::RecoveryFile => "Recovery File Reference",
        crate::RecoveryKindChoice::RecoveryInstructions => "Recovery Instructions",
        crate::RecoveryKindChoice::SecurityQuestions => "Security Questions",
    }
}

fn recovery_material_label(choice: crate::RecoveryKindChoice) -> &'static str {
    match choice {
        crate::RecoveryKindChoice::RecoveryCodeSet => "Codes",
        crate::RecoveryKindChoice::RecoveryPhrase => "Phrase",
        crate::RecoveryKindChoice::RecoveryKey => "Key",
        crate::RecoveryKindChoice::RecoveryFile => "Location",
        crate::RecoveryKindChoice::RecoveryInstructions => "Steps",
        crate::RecoveryKindChoice::SecurityQuestions => "Answer",
    }
}

fn form_input_line(label: &str, value: &str, focused: bool) -> Line<'static> {
    let marker = if focused { "›" } else { " " };
    let cursor = if focused { "█" } else { "" };
    Line::from(vec![
        Span::raw(marker),
        Span::raw(" "),
        Span::raw(format!("{label:<8}")),
        Span::raw("  "),
        Span::raw(value.to_owned()),
        Span::raw(cursor),
    ])
}

fn mask_value(value: &str) -> String {
    "•".repeat(value.chars().count())
}

fn secret_filter(filter: &SelectedFilter) -> SecretFilter<'_> {
    match filter {
        SelectedFilter::All => SecretFilter::All,
        SelectedFilter::Untagged => SecretFilter::Untagged,
        SelectedFilter::Tag(tag) => SecretFilter::Tag(tag),
    }
}

fn filter_label(filter: &SelectedFilter) -> String {
    match filter {
        SelectedFilter::All => "all".to_owned(),
        SelectedFilter::Untagged => "untagged".to_owned(),
        SelectedFilter::Tag(tag) => format!("#{tag}"),
    }
}

fn centered(area: Rect, width: u16, height: u16) -> Rect {
    let [_, center, _] = Layout::vertical([
        Constraint::Fill(1),
        Constraint::Length(height.min(area.height)),
        Constraint::Fill(1),
    ])
    .areas(area);
    let [_, center, _] = Layout::horizontal([
        Constraint::Fill(1),
        Constraint::Length(width.min(area.width)),
        Constraint::Fill(1),
    ])
    .areas(center);
    center
}

fn master_passphrase_line<'a>(label: &'a str, masked: &'a str, focused: bool) -> Line<'a> {
    let marker = if focused { "›" } else { " " };
    let cursor = if focused { "█" } else { "" };
    Line::from(vec![
        Span::raw(marker),
        Span::raw(" "),
        Span::raw(label),
        Span::raw("  "),
        Span::raw(masked),
        Span::raw(cursor),
    ])
}

fn status_line(state: &AppState) -> Line<'static> {
    match state.status_message() {
        Some(message) => Line::from(message.to_owned()).style(Style::new().fg(Color::Yellow)),
        None => Line::from(""),
    }
}
