use crate::{
    AppState, FormField, FormMode, MasterPassphraseField, ModalState, PanelFocus,
    Screen::{self},
    SecretTypeChoice, SelectedFilter, UpdateState, VaultSession,
    app::database_engine_choices,
};
use bastion_core::{RecoveryMaterial, RotationStatus, Secret, SecretFilter, SecretKind, Vault};
use chrono::Utc;
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

const PALETTE_WIDTH: u16 = 76;
const PALETTE_HEIGHT: u16 = 16;
const SMALL_MODAL_WIDTH: u16 = 68;
const PICKER_WIDTH: u16 = 82;
const ADD_SECRET_WIDTH: u16 = 82;
const DATABASE_ENGINE_WIDTH: u16 = 82;
const FORM_WIDTH: u16 = 80;
const FORM_HEIGHT: u16 = 24;
const LOCKED_WIDTH: u16 = 64;
const LOCKED_HEIGHT: u16 = 14;
const ONBOARDING_WIDTH: u16 = 68;
const ONBOARDING_HEIGHT: u16 = 18;
const POPUP_HORIZONTAL_PADDING: u16 = 1;

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
        Screen::DatabaseEnginePicker => {
            render_main(frame, area, state);
            render_form(frame, area, state);
            render_database_engine_picker(frame, area, state);
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
    let passphrase_focused = state.master_passphrase_field() == MasterPassphraseField::Passphrase;
    let confirmation_focused =
        state.master_passphrase_field() == MasterPassphraseField::Confirmation;

    let mut body = vec![
        section_header("Create your encrypted vault"),
        Line::from("Choose a master passphrase for this local vault."),
        Line::from(""),
        Line::from(vec![
            Span::styled(
                "Important",
                Style::new().fg(Color::Yellow).add_modifier(Modifier::BOLD),
            ),
            Span::raw("  Bastion cannot recover this passphrase."),
        ]),
        Line::from(""),
        section_header("Master passphrase"),
        master_passphrase_input_line(
            &passphrase_mask,
            state.master_passphrase().is_empty(),
            passphrase_focused,
            "enter a long, unique passphrase",
        ),
        section_header("Confirm passphrase"),
        master_passphrase_input_line(
            &confirmation_mask,
            state.master_passphrase_confirmation().is_empty(),
            confirmation_focused,
            "type it again",
        ),
        Line::from(""),
    ];

    body.extend(onboarding_passphrase_check_lines(state));
    body.push(status_line(state));

    let footer = shortcut_line(&[
        ("Tab", "switch field"),
        ("Enter", "create vault"),
        ("Esc", "quit"),
    ]);

    render_popup_with_footer(
        frame,
        centered(area, ONBOARDING_WIDTH, ONBOARDING_HEIGHT),
        "Welcome to Bastion",
        body,
        footer,
    );
}

fn render_locked(frame: &mut Frame<'_>, area: Rect, state: &AppState) {
    let passphrase_mask = state.master_passphrase_mask();
    let mut body = vec![
        section_header("Bastion is locked"),
        Line::from("Your vault is encrypted and unavailable until unlocked."),
        Line::from(""),
        section_header("Master passphrase"),
        master_passphrase_input_line(
            &passphrase_mask,
            state.master_passphrase().is_empty(),
            true,
            "enter your master passphrase",
        ),
        Line::from(""),
        section_header("Status"),
        locked_status_line(state),
    ];

    if state.status_message().is_none() {
        body.extend([
            Line::from(""),
            Line::from("Press Enter to unlock the vault.").style(muted_style()),
        ]);
    }

    let footer = shortcut_line(&[("Enter", "unlock"), ("Esc", "quit")]);
    render_popup_with_footer(
        frame,
        centered(area, LOCKED_WIDTH, LOCKED_HEIGHT),
        "Bastion",
        body,
        footer,
    );
}

fn render_main(frame: &mut Frame<'_>, area: Rect, state: &AppState) {
    let footer_height = 4;
    let [header, body, footer] = Layout::vertical([
        Constraint::Length(3),
        Constraint::Fill(1),
        Constraint::Length(footer_height),
    ])
    .areas(area);
    let [left, divider, details] = Layout::horizontal([
        Constraint::Length(36),
        Constraint::Length(1),
        Constraint::Fill(1),
    ])
    .areas(body);
    let [items, tags] =
        Layout::vertical([Constraint::Percentage(60), Constraint::Fill(1)]).areas(left);

    let VaultSession::Unlocked { vault } = state.session() else {
        return;
    };

    render_header(frame, header, vault, state);
    render_items(frame, items, vault, state);
    render_tags(frame, tags, vault, state);
    render_vertical_divider(frame, divider);
    render_details(frame, details, vault, state);
    render_footer(frame, footer, state);
}

fn render_vertical_divider(frame: &mut Frame<'_>, area: Rect) {
    let lines = (0..area.height)
        .map(|_| Line::from("│").style(muted_style()))
        .collect::<Vec<_>>();
    frame.render_widget(Paragraph::new(lines), area);
}

fn render_header(frame: &mut Frame<'_>, area: Rect, vault: &Vault, state: &AppState) {
    let header_text = if let Some(status) = vault_attention_label(state) {
        format!(
            "Vault: {}   Filter: {}   {}",
            vault.name(),
            filter_label(state.selected_filter()),
            status,
        )
    } else {
        format!(
            "Vault: {}   Filter: {}",
            vault.name(),
            filter_label(state.selected_filter())
        )
    };

    frame.render_widget(
        Paragraph::new(header_text).block(Block::bordered().title("Bastion")),
        area,
    );
}

fn render_items(frame: &mut Frame<'_>, area: Rect, vault: &Vault, state: &AppState) {
    let items = vault.visible_secrets(secret_filter(state.selected_filter()));
    let panel_focused = state.panel_focus() == PanelFocus::Items;
    let title = format!(
        "Items [1]{} · {} · {}",
        if panel_focused { " focused" } else { "" },
        items.len(),
        filter_label(state.selected_filter()),
    );

    if items.is_empty() {
        frame.render_widget(
            Paragraph::new(empty_items_lines(state)).block(panel_block(&title, panel_focused)),
            area,
        );
        return;
    }

    let selected_index = items
        .iter()
        .position(|secret| Some(secret.id()) == state.selected_secret());
    let mut list_state = ListState::default();
    list_state.select(selected_index);

    let row_width = area.width.saturating_sub(4);
    let rows = items
        .iter()
        .map(|secret| ListItem::new(secret_list_line(secret, row_width)))
        .collect::<Vec<_>>();
    frame.render_stateful_widget(
        selectable_list(rows, &title, panel_focused),
        area,
        &mut list_state,
    );
}

fn render_tags(frame: &mut Frame<'_>, area: Rect, vault: &Vault, state: &AppState) {
    let counts = vault.tag_counts();
    let panel_focused = state.panel_focus() == PanelFocus::Tags;
    let title = format!(
        "Tags [2]{} · {}",
        if panel_focused { " focused" } else { "" },
        counts.tags.len() + 2,
    );
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
        ListItem::new(format!(
            "#{} {}",
            soft_truncate(tag, area.width.saturating_sub(8) as usize),
            count
        ))
    }));
    let untagged_index = rows.len();
    if matches!(state.selected_filter(), SelectedFilter::Untagged) {
        selected_index = Some(untagged_index);
    }
    rows.push(ListItem::new(format!("Untagged {}", counts.untagged)));

    let mut list_state = ListState::default();
    list_state.select(selected_index);
    frame.render_stateful_widget(
        selectable_list(rows, &title, panel_focused),
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
        Paragraph::new(secret_lines(secret, state))
            .block(panel_block("Details", false))
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn secret_lines(secret: &Secret, state: &AppState) -> Vec<Line<'static>> {
    let mut lines = vec![
        Line::from(secret.title().to_owned()).style(Style::new().bold()),
        tag_chips_line("Tags", secret.tags()),
        Line::from(""),
    ];

    match secret.kind() {
        SecretKind::DatabaseCredential(credential) => {
            let password = if state.is_revealed(crate::SecretRef::PostgreSqlPassword(secret.id())) {
                credential.password().expose_secret().to_owned()
            } else {
                "••••••••••••••••".to_owned()
            };

            lines.extend([
                section_header("Type"),
                Line::from("Database Credential"),
                Line::from(""),
                section_header("Connection"),
                detail_row("Engine", credential.engine().label()),
                detail_row("Hostname", credential.hostname()),
                detail_row("Port", &credential.port().to_string()),
                detail_row("Database", credential.database()),
            ]);
            if let Some(schema) = credential.schema() {
                lines.push(detail_row("Schema", schema));
            }
            lines.extend([
                Line::from(""),
                section_header("Credentials"),
                detail_row_with_hint("Username", credential.username(), "u copy"),
                detail_row_with_hint("Password", &password, "c copy · r reveal"),
                Line::from(""),
                section_header("Connection string"),
            ]);
            lines.extend(connection_string_lines(
                &credential.masked_connection_string(),
            ));
        }
        SecretKind::ApiKeyToken(token) => {
            let secret_token = if state.is_revealed(crate::SecretRef::ApiKeyToken(secret.id())) {
                token.token().expose_secret().to_owned()
            } else {
                "••••••••••••••••".to_owned()
            };

            lines.extend([
                section_header("Type"),
                Line::from("API Key / Token"),
                Line::from(""),
                section_header("Token"),
                detail_row("Kind", token.kind().label()),
                detail_row("Service", token.service()),
            ]);
            if let Some(account) = token.account() {
                lines.push(detail_row_with_hint("Account", account, "u copy"));
            }
            if let Some(url) = token.url() {
                lines.push(detail_row("URL", url));
            }
            lines.extend([
                Line::from(""),
                section_header("Secret"),
                detail_row_with_hint("Token", &secret_token, "c copy · r reveal"),
            ]);
        }
        SecretKind::AccountRecovery(item) => {
            lines.extend([
                section_header("Type"),
                Line::from("Account Recovery"),
                Line::from(""),
                section_header("Recovery"),
                detail_row("Kind", item.kind().label()),
                detail_row("Service", item.service()),
            ]);
            if let Some(account) = item.account() {
                lines.push(detail_row("Account", account));
            }
            lines.extend([Line::from(""), section_header("Recovery material")]);
            match item.material() {
                RecoveryMaterial::CodeSet(_) => {
                    let (unused, total) = item.recovery_code_counts();
                    lines.push(detail_row(
                        "Status",
                        &format!("{unused} unused / {total} total"),
                    ));
                    if unused <= 2 {
                        lines.push(Line::styled("Low unused recovery codes", danger_style()));
                    }
                    lines.push(detail_row("Next code", "••••••••••••••••"));
                }
                RecoveryMaterial::Phrase(phrase) => {
                    lines.push(detail_row("Word count", &phrase.word_count().to_string()));
                    lines.push(detail_row("Phrase", "••••••••••••••••"));
                }
                RecoveryMaterial::Key(_) => {
                    lines.push(detail_row("Format", item.format().label()));
                    lines.push(detail_row("Value", "••••••••••••••••"));
                }
                RecoveryMaterial::FileReference(reference) => {
                    if let Some(file_name) = reference.file_name() {
                        lines.push(detail_row("File name", file_name));
                    }
                    lines.push(detail_row("Location", reference.location()));
                }
                RecoveryMaterial::Instructions(_) => {
                    lines.push(detail_row("Instructions", "••••••••••••••••"));
                }
                RecoveryMaterial::SecurityQuestions(questions) => {
                    lines.push(detail_row("Questions", &questions.len().to_string()));
                    lines.push(detail_row("Answers", "••••••••••••••••"));
                }
            }
        }
    }

    append_secret_metadata_lines(&mut lines, secret);

    lines
}

fn append_secret_metadata_lines(lines: &mut Vec<Line<'static>>, secret: &Secret) {
    if !secret.custom_fields().is_empty() {
        lines.extend([Line::from(""), section_header("Custom fields")]);
        lines.extend(
            secret
                .custom_fields()
                .iter()
                .map(|field| detail_row(field.label(), field.display_value())),
        );
    }

    let rotation = secret.rotation();
    if rotation.is_configured() {
        let now = Utc::now();
        let status = rotation.status(now);
        lines.extend([
            Line::from(""),
            section_header("Rotation"),
            rotation_status_row(status),
        ]);
        if let Some(next_due_at) = rotation.next_due_at() {
            lines.push(detail_row(
                "Next due",
                &next_due_at.date_naive().to_string(),
            ));
        }
        if let Some(last_rotated_at) = rotation.last_rotated_at {
            lines.push(detail_row(
                "Rotated",
                &last_rotated_at.date_naive().to_string(),
            ));
        }
        if let Some(days) = rotation.rotate_every_days {
            lines.push(detail_row("Every", &format!("{days} days")));
        }
    }
}

fn rotation_status_row(status: RotationStatus) -> Line<'static> {
    let style = match status {
        RotationStatus::NotConfigured | RotationStatus::Healthy => Style::new(),
        RotationStatus::DueSoon | RotationStatus::Due => Style::new().fg(Color::Yellow),
        RotationStatus::Expired => danger_style(),
    };
    Line::from(vec![
        Span::raw(format!("{:<12}", "Status")),
        Span::styled(status.label().to_owned(), style),
    ])
}

fn connection_string_lines(value: &str) -> Vec<Line<'static>> {
    if let Some(split_index) = value.rfind('/') {
        let (prefix, suffix) = value.split_at(split_index + 1);
        if !suffix.is_empty() {
            return vec![Line::from(prefix.to_owned()), Line::from(suffix.to_owned())];
        }
    }

    vec![Line::from(value.to_owned())]
}

fn empty_details_lines(state: &AppState) -> Vec<Line<'static>> {
    match state.selected_filter() {
        SelectedFilter::All => vec![
            Line::from("No secrets yet").style(Style::new().add_modifier(Modifier::BOLD)),
            Line::from(""),
            Line::from("Start by adding your first secret."),
            Line::from(""),
            shortcut_line(&[("a", "add secret"), ("Space", "commands")]),
        ],
        SelectedFilter::Untagged => vec![
            Line::from("No untagged secrets").style(Style::new().add_modifier(Modifier::BOLD)),
            Line::from(""),
            Line::from("Switch to All, or add a secret without tags."),
            Line::from(""),
            shortcut_line(&[("a", "add secret"), ("1", "items"), ("2", "tags")]),
        ],
        SelectedFilter::Tag(tag) => vec![
            Line::from(format!("No items tagged #{tag}"))
                .style(Style::new().add_modifier(Modifier::BOLD)),
            Line::from(""),
            Line::from("Add a new item with this tag, or switch to All."),
            Line::from(""),
            shortcut_line(&[("a", "add secret"), ("2", "tags")]),
        ],
    }
}

fn empty_items_lines(state: &AppState) -> Vec<Line<'static>> {
    match state.selected_filter() {
        SelectedFilter::All => vec![
            Line::from("No secrets yet").style(Style::new().add_modifier(Modifier::BOLD)),
            Line::from(""),
            Line::from("Start by adding one."),
            Line::from(""),
            shortcut_line(&[("a", "add secret"), ("Space", "commands")]),
        ],
        SelectedFilter::Untagged => vec![
            Line::from("No untagged secrets").style(Style::new().add_modifier(Modifier::BOLD)),
            Line::from(""),
            Line::from("Switch filters or add a secret without tags."),
        ],
        SelectedFilter::Tag(tag) => vec![
            Line::from(format!("No items tagged #{tag}"))
                .style(Style::new().add_modifier(Modifier::BOLD)),
            Line::from(""),
            Line::from("Add a new item with this tag, or switch to All."),
        ],
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

    let mut text = Vec::new();
    if let Some(message) = state.status_message() {
        text.push(Line::from(message.to_owned()).style(Style::new().fg(Color::Yellow)));
    } else if state.screen() == Screen::Main
        && let Some(status) = vault_attention_label(state)
    {
        text.push(Line::from(status).style(Style::new().fg(Color::Yellow)));
    }
    text.push(shortcuts);

    frame.render_widget(Paragraph::new(text).block(Block::bordered()), area);
}

fn render_picker(frame: &mut Frame<'_>, area: Rect, state: &AppState) {
    let selected_choice = state.secret_type_choice();
    let selected_option = selected_choice.option();
    let popup = centered(area, ADD_SECRET_WIDTH, 16);

    frame.render_widget(Clear, popup);

    let block = active_window_block("Add Secret");
    let inner = block.inner(popup);

    frame.render_widget(block, popup);

    let [body_area, separator_area, footer_area] = Layout::vertical([
        Constraint::Fill(1),
        Constraint::Length(1),
        Constraint::Length(1),
    ])
    .areas(inner);

    let body_area = padded(body_area, POPUP_HORIZONTAL_PADDING, 0);
    let [options_area, divider_area, details_area] = Layout::horizontal([
        Constraint::Length(30),
        Constraint::Length(1),
        Constraint::Fill(1),
    ])
    .areas(body_area);

    let last_used = state.last_secret_type_choice().option().label;
    let mut option_lines = vec![
        Line::from("What do you want to store?"),
        Line::from(vec![
            Span::raw("Last used: "),
            Span::styled(last_used, Style::new().fg(Color::Yellow)),
        ]),
        Line::from(""),
    ];
    option_lines.extend(
        SecretTypeChoice::options()
            .iter()
            .enumerate()
            .map(|(index, option)| {
                picker_row(
                    &format!("{} {}", index + 1, option.label),
                    option.choice == selected_choice,
                    options_area.width,
                )
            }),
    );

    frame.render_widget(
        Paragraph::new(option_lines)
            .style(Style::new().bg(Color::Black))
            .wrap(Wrap { trim: false }),
        options_area,
    );

    render_inner_vertical_separator(frame, divider_area);

    frame.render_widget(
        Paragraph::new(choice_detail_lines(
            selected_option.label,
            selected_option.description,
            selected_option.best_for,
            selected_option.examples,
        ))
        .style(Style::new().bg(Color::Black))
        .wrap(Wrap { trim: false }),
        padded(details_area, POPUP_HORIZONTAL_PADDING, 0),
    );

    frame.render_widget(
        Paragraph::new(palette_separator(separator_area.width))
            .style(Style::new().bg(Color::Black)),
        separator_area,
    );

    frame.render_widget(
        Paragraph::new(shortcut_line(&[
            ("↑/↓", "choose"),
            ("Enter", "select"),
            ("Esc", "cancel"),
        ]))
        .style(Style::new().bg(Color::Black)),
        padded(footer_area, POPUP_HORIZONTAL_PADDING, 0),
    );
}

fn render_api_token_kind_picker(frame: &mut Frame<'_>, area: Rect, state: &AppState) {
    let selected_choice = state.api_token_kind_choice();
    let selected_option = selected_choice.option();
    let popup = centered(area, PICKER_WIDTH, 20);

    frame.render_widget(Clear, popup);

    let block = active_window_block("Access Token Type");
    let inner = block.inner(popup);

    frame.render_widget(block, popup);

    let [body_area, separator_area, footer_area] = Layout::vertical([
        Constraint::Fill(1),
        Constraint::Length(1),
        Constraint::Length(1),
    ])
    .areas(inner);

    let body_area = padded(body_area, POPUP_HORIZONTAL_PADDING, 0);
    let [options_area, divider_area, details_area] = Layout::horizontal([
        Constraint::Length(31),
        Constraint::Length(1),
        Constraint::Fill(1),
    ])
    .areas(body_area);

    let mut option_lines = vec![Line::from("What kind of access secret?"), Line::from("")];
    option_lines.extend(crate::ApiTokenKindChoice::options().iter().enumerate().map(
        |(index, option)| {
            picker_row(
                &format!("{} {}", index + 1, option.label),
                option.choice == selected_choice,
                options_area.width,
            )
        },
    ));

    frame.render_widget(
        Paragraph::new(option_lines)
            .style(Style::new().bg(Color::Black))
            .wrap(Wrap { trim: false }),
        options_area,
    );

    render_inner_vertical_separator(frame, divider_area);

    frame.render_widget(
        Paragraph::new(choice_detail_lines(
            selected_option.label,
            selected_option.description,
            selected_option.best_for,
            selected_option.examples,
        ))
        .style(Style::new().bg(Color::Black))
        .wrap(Wrap { trim: false }),
        padded(details_area, POPUP_HORIZONTAL_PADDING, 0),
    );

    frame.render_widget(
        Paragraph::new(palette_separator(separator_area.width))
            .style(Style::new().bg(Color::Black)),
        separator_area,
    );

    frame.render_widget(
        Paragraph::new(shortcut_line(&[
            ("↑/↓", "choose"),
            ("Enter", "select"),
            ("Esc", "back"),
        ]))
        .style(Style::new().bg(Color::Black)),
        padded(footer_area, POPUP_HORIZONTAL_PADDING, 0),
    );
}

fn render_recovery_kind_picker(frame: &mut Frame<'_>, area: Rect, state: &AppState) {
    let selected_choice = state.recovery_kind_choice();
    let selected_option = selected_choice.option();
    let popup = centered(area, PICKER_WIDTH, 18);

    frame.render_widget(Clear, popup);

    let block = active_window_block("Account Recovery Type");
    let inner = block.inner(popup);

    frame.render_widget(block, popup);

    let [body_area, separator_area, footer_area] = Layout::vertical([
        Constraint::Fill(1),
        Constraint::Length(1),
        Constraint::Length(1),
    ])
    .areas(inner);

    let body_area = padded(body_area, POPUP_HORIZONTAL_PADDING, 0);
    let [options_area, divider_area, details_area] = Layout::horizontal([
        Constraint::Length(31),
        Constraint::Length(1),
        Constraint::Fill(1),
    ])
    .areas(body_area);

    let mut option_lines = vec![Line::from("What recovery material?"), Line::from("")];
    option_lines.extend(crate::RecoveryKindChoice::options().iter().enumerate().map(
        |(index, option)| {
            picker_row(
                &format!("{} {}", index + 1, option.label),
                option.choice == selected_choice,
                options_area.width,
            )
        },
    ));

    frame.render_widget(
        Paragraph::new(option_lines)
            .style(Style::new().bg(Color::Black))
            .wrap(Wrap { trim: false }),
        options_area,
    );

    render_inner_vertical_separator(frame, divider_area);

    frame.render_widget(
        Paragraph::new(choice_detail_lines(
            selected_option.label,
            selected_option.description,
            selected_option.best_for,
            selected_option.examples,
        ))
        .style(Style::new().bg(Color::Black))
        .wrap(Wrap { trim: false }),
        padded(details_area, POPUP_HORIZONTAL_PADDING, 0),
    );

    frame.render_widget(
        Paragraph::new(palette_separator(separator_area.width))
            .style(Style::new().bg(Color::Black)),
        separator_area,
    );

    frame.render_widget(
        Paragraph::new(shortcut_line(&[
            ("↑/↓", "choose"),
            ("Enter", "select"),
            ("Esc", "back"),
        ]))
        .style(Style::new().bg(Color::Black)),
        padded(footer_area, POPUP_HORIZONTAL_PADDING, 0),
    );
}

fn render_form(frame: &mut Frame<'_>, area: Rect, state: &AppState) {
    let Some(form) = state.form() else {
        return;
    };
    let mut body = vec![
        form_mode_line(form.mode(), form.value(FormField::Title), form.is_dirty()),
        form_progress_line(state, form),
        Line::from(""),
    ];

    if let Some(error) = form.validation_error() {
        body.push(Line::styled(
            format!(
                "Cannot save yet — {} needs attention.",
                form_field_title(error.field())
            ),
            danger_style(),
        ));
        body.push(Line::from(""));
    }

    if let Some(warning) = form_auto_lock_warning_line(state) {
        body.push(warning);
        body.push(Line::from(""));
    }

    body.extend(form_body_lines(form));
    body.extend([
        Line::from(""),
        form_metadata_line(form.mode(), form.is_dirty()),
    ]);

    let title = match form.mode() {
        FormMode::AddPostgreSqlCredential | FormMode::EditPostgreSqlCredential(_) => {
            "Database Credential"
        }
        FormMode::AddApiKeyToken | FormMode::EditApiKeyToken(_) => "API Key / Token",
        FormMode::AddAccountRecovery(kind) => recovery_form_title(kind),
    };
    let footer = form_footer_lines(form);
    let visible_body_height = form_visible_body_height(footer.len());
    let body = fit_form_body_to_visible_area(body, visible_body_height);
    render_popup_with_footer_lines(
        frame,
        centered(area, FORM_WIDTH, FORM_HEIGHT),
        title,
        body,
        footer,
    );
}

fn form_footer_lines(form: &crate::FormState) -> Vec<Line<'static>> {
    if form.focused_field() == Some(FormField::Engine) {
        vec![
            shortcut_line(&[
                ("Tab", "next"),
                ("Shift+Tab", "previous"),
                ("Enter", "choose engine"),
            ]),
            shortcut_line(&[("Ctrl+S", "save"), ("Esc", "cancel"), ("?", "help")]),
        ]
    } else {
        let mut primary = vec![
            ("Tab", "next"),
            ("Shift+Tab", "previous"),
            ("Ctrl+S", "save"),
        ];
        if form
            .focused_field()
            .is_some_and(|field| field_supports_generation(form.mode(), field))
        {
            primary.push(("Ctrl+G", "generate"));
        }
        vec![
            shortcut_line(&primary),
            shortcut_line(&[("Esc", "cancel"), ("?", "help")]),
        ]
    }
}

fn field_supports_generation(mode: FormMode, field: FormField) -> bool {
    match field {
        FormField::Password | FormField::Token => true,
        FormField::RecoveryMaterial => match mode {
            FormMode::AddAccountRecovery(kind) => recovery_material_supports_generation(kind),
            _ => false,
        },
        _ => false,
    }
}

fn recovery_material_supports_generation(kind: crate::RecoveryKindChoice) -> bool {
    matches!(
        kind,
        crate::RecoveryKindChoice::RecoveryCodeSet | crate::RecoveryKindChoice::RecoveryKey
    )
}

fn form_visible_body_height(footer_lines: usize) -> usize {
    FORM_HEIGHT.saturating_sub(3 + footer_lines as u16).max(1) as usize
}

fn fit_form_body_to_visible_area(
    lines: Vec<Line<'static>>,
    visible_height: usize,
) -> Vec<Line<'static>> {
    if visible_height == 0 || lines.len() <= visible_height {
        return lines;
    }

    let fixed_lines = form_fixed_header_lines(&lines).min(lines.len());
    if fixed_lines >= visible_height {
        return lines.into_iter().take(visible_height).collect();
    }

    let dynamic_height = visible_height - fixed_lines;
    let mut fixed = lines[..fixed_lines].to_vec();
    let dynamic = &lines[fixed_lines..];
    let focus_index = dynamic
        .iter()
        .position(line_starts_with_focus_marker)
        .unwrap_or(0);

    let scroll_start = command_palette_scroll_start(focus_index, dynamic.len(), dynamic_height);
    let scroll_end = (scroll_start + dynamic_height).min(dynamic.len());
    let mut visible = dynamic[scroll_start..scroll_end].to_vec();

    apply_line_scroll_indicators(
        &mut visible,
        scroll_start,
        scroll_end,
        dynamic.len(),
        dynamic_height,
    );

    fixed.extend(visible);
    fixed
}

fn form_fixed_header_lines(lines: &[Line<'static>]) -> usize {
    let has_validation_summary = line_plain_text(lines.get(3)).starts_with("Cannot save yet");
    let warning_index = if has_validation_summary { 5 } else { 3 };

    if line_plain_text(lines.get(warning_index)).starts_with("Auto-lock") {
        warning_index + 2
    } else if has_validation_summary {
        5
    } else {
        3
    }
}

fn line_starts_with_focus_marker(line: &Line<'static>) -> bool {
    line.spans
        .first()
        .is_some_and(|span| span.content.starts_with('›'))
}

fn line_plain_text(line: Option<&Line<'static>>) -> String {
    line.map(|line| {
        line.spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect::<String>()
    })
    .unwrap_or_default()
}

fn apply_line_scroll_indicators(
    lines: &mut Vec<Line<'static>>,
    scroll_start: usize,
    scroll_end: usize,
    total_rows: usize,
    visible_height: usize,
) {
    if visible_height == 0 || total_rows <= visible_height || lines.is_empty() {
        return;
    }

    if scroll_start > 0 {
        lines.insert(0, Line::styled("↑ more", scroll_indicator_style()));
        if lines.len() > visible_height {
            lines.pop();
        }
    }

    if scroll_end < total_rows {
        if lines.len() >= visible_height {
            lines.pop();
        }
        lines.push(Line::styled("↓ more", scroll_indicator_style()));
    }
}

fn form_auto_lock_warning_line(state: &AppState) -> Option<Line<'static>> {
    let seconds = auto_lock_seconds_remaining(state)?;
    if seconds > 60 {
        return None;
    }

    Some(Line::styled(
        format!(
            "Auto-lock in {} — unsaved form values will be discarded.",
            format_duration(seconds)
        ),
        Style::new().fg(Color::Yellow).add_modifier(Modifier::BOLD),
    ))
}

fn form_progress_line(state: &AppState, form: &crate::FormState) -> Line<'static> {
    let Some((current, total)) = state.form_field_progress() else {
        return Line::from("");
    };

    let focused = form
        .focused_field()
        .map(form_field_title)
        .unwrap_or("field");

    Line::from(vec![
        Span::styled(
            format!("Field {current}/{total}"),
            Style::new().fg(Color::Yellow).add_modifier(Modifier::BOLD),
        ),
        Span::raw(" · "),
        Span::styled(focused.to_owned(), muted_style()),
    ])
}

fn form_body_lines(form: &crate::FormState) -> Vec<Line<'static>> {
    let focused_field = form.focused_field();
    let mut lines = vec![section_header("Basic")];

    push_form_input_line(
        &mut lines,
        form,
        FormField::Title,
        "Title",
        form.value(FormField::Title),
    );
    push_form_input_line(
        &mut lines,
        form,
        FormField::Tags,
        "Tags",
        form.value(FormField::Tags),
    );
    lines.push(Line::from(""));

    match form.mode() {
        FormMode::AddPostgreSqlCredential | FormMode::EditPostgreSqlCredential(_) => {
            lines.push(section_header("Connection"));
            push_form_select_line(
                &mut lines,
                form,
                FormField::Engine,
                "Engine",
                form.value(FormField::Engine),
            );
            push_form_input_line(
                &mut lines,
                form,
                FormField::Hostname,
                "Hostname",
                form.value(FormField::Hostname),
            );
            push_form_input_line(
                &mut lines,
                form,
                FormField::Port,
                "Port",
                form.value(FormField::Port),
            );
            push_form_input_line(
                &mut lines,
                form,
                FormField::Database,
                "Database",
                form.value(FormField::Database),
            );
            push_form_input_line(
                &mut lines,
                form,
                FormField::Schema,
                "Schema",
                form.value(FormField::Schema),
            );
            lines.push(Line::from(""));
            lines.push(section_header("Credentials"));
            push_form_input_line(
                &mut lines,
                form,
                FormField::Username,
                "Username",
                form.value(FormField::Username),
            );
            push_form_input_line(
                &mut lines,
                form,
                FormField::Password,
                "Password",
                &mask_value(form.value(FormField::Password)),
            );
        }
        FormMode::AddApiKeyToken | FormMode::EditApiKeyToken(_) => {
            lines.push(section_header("Token"));
            push_form_input_line(
                &mut lines,
                form,
                FormField::Service,
                "Service",
                form.value(FormField::Service),
            );
            push_form_input_line(
                &mut lines,
                form,
                FormField::Account,
                "Account",
                form.value(FormField::Account),
            );
            push_form_input_line(
                &mut lines,
                form,
                FormField::Url,
                "URL",
                form.value(FormField::Url),
            );
            lines.push(Line::from(""));
            lines.push(section_header("Secret"));
            push_form_input_line(
                &mut lines,
                form,
                FormField::Token,
                "Token",
                &mask_value(form.value(FormField::Token)),
            );
        }
        FormMode::AddAccountRecovery(kind) => {
            lines.push(section_header("Recovery"));
            push_form_input_line(
                &mut lines,
                form,
                FormField::Service,
                "Service",
                form.value(FormField::Service),
            );
            push_form_input_line(
                &mut lines,
                form,
                FormField::Account,
                "Account",
                form.value(FormField::Account),
            );
            push_form_input_line(
                &mut lines,
                form,
                FormField::Url,
                "URL",
                form.value(FormField::Url),
            );
            lines.push(Line::from(""));
            lines.push(section_header(recovery_form_title(kind)));
            lines.extend(recovery_material_input_lines(
                recovery_material_label(kind),
                form.value(FormField::RecoveryMaterial),
                focused_field == Some(FormField::RecoveryMaterial),
            ));
            if let Some(error) = form.validation_error()
                && error.field() == FormField::RecoveryMaterial
            {
                lines.push(form_error_line(error.message()));
            } else if focused_field == Some(FormField::RecoveryMaterial) {
                lines.push(form_helper_line(recovery_material_helper_text(kind)));
            }
        }
    }

    lines.push(Line::from(""));
    lines.push(section_header("Metadata"));
    lines.extend(custom_fields_input_lines(
        form.value(FormField::CustomFields),
        focused_field == Some(FormField::CustomFields),
    ));
    if let Some(error) = form.validation_error()
        && error.field() == FormField::CustomFields
    {
        lines.push(form_error_line(error.message()));
    } else if focused_field == Some(FormField::CustomFields) {
        lines.push(form_helper_line(
            "One field per line. Use Label=value, or Label*=value for sensitive values.",
        ));
    }
    push_form_input_line(
        &mut lines,
        form,
        FormField::ExpiresAt,
        "Expires",
        form.value(FormField::ExpiresAt),
    );
    push_form_input_line(
        &mut lines,
        form,
        FormField::RotateEveryDays,
        "Rotate days",
        form.value(FormField::RotateEveryDays),
    );
    push_form_input_line(
        &mut lines,
        form,
        FormField::LastRotatedAt,
        "Rotated",
        form.value(FormField::LastRotatedAt),
    );

    lines
}

fn render_modal(frame: &mut Frame<'_>, area: Rect, state: &AppState) {
    match state.modal() {
        Some(ModalState::CommandPalette) => {
            render_command_palette(frame, area, state);
        }
        Some(ModalState::DeleteSecret(secret_id)) => {
            render_popup_with_footer(
                frame,
                centered(area, SMALL_MODAL_WIDTH, 10),
                "Delete Secret",
                delete_modal_body(state, secret_id),
                shortcut_line(&[("Enter", "delete"), ("Esc", "cancel")]),
            );
        }
        Some(ModalState::DiscardChanges) => {
            render_popup_with_footer(
                frame,
                centered(area, SMALL_MODAL_WIDTH, 12),
                "Discard Changes",
                discard_changes_body(state),
                shortcut_line(&[("Enter", "discard changes"), ("Esc", "cancel")]),
            );
        }
        Some(ModalState::QuitWithoutSaving) => {
            render_popup_with_footer(
                frame,
                centered(area, SMALL_MODAL_WIDTH, 10),
                "Quit Bastion",
                vec![Line::from("Quit without saving?")],
                shortcut_line(&[("Enter", "quit without saving"), ("Esc", "cancel")]),
            );
        }
        Some(ModalState::RevealSecret(secret_ref)) => {
            render_popup_with_footer(
                frame,
                centered(area, SMALL_MODAL_WIDTH, 10),
                "Reveal Secret",
                reveal_modal_body(state, secret_ref),
                shortcut_line(&[("Enter", "reveal for 10 seconds"), ("Esc", "cancel")]),
            );
        }
        Some(ModalState::UpdateAvailable) => {
            render_popup_with_footer(
                frame,
                centered(area, SMALL_MODAL_WIDTH, 16),
                "Update Available",
                update_available_body(state),
                shortcut_line(&[
                    ("Enter", "remind me later"),
                    ("s", "skip version"),
                    ("Esc", "close"),
                ]),
            );
        }
        Some(ModalState::Help) => {
            render_popup_paragraph(
                frame,
                centered(area, SMALL_MODAL_WIDTH, 22),
                "Help",
                help_lines(),
            );
        }
        None => {
            render_popup_paragraph(
                frame,
                centered(area, SMALL_MODAL_WIDTH, 10),
                "Confirm",
                Vec::new(),
            );
        }
    }
}

fn update_available_body(state: &AppState) -> Vec<Line<'static>> {
    let UpdateState::Available(info) = state.update_state() else {
        return vec![Line::from("No update information is available.")];
    };

    let mut lines = vec![
        section_header("Update available"),
        Line::from(format!("Bastion {} is available.", info.version)),
        Line::from(""),
        detail_row("Current", &info.current_version.to_string()),
        detail_row("Latest", &info.version.to_string()),
        Line::from(""),
        section_header("Release notes"),
    ];

    lines.extend(
        info.release_notes
            .iter()
            .take(5)
            .map(|note| Line::from(format!("• {note}"))),
    );
    lines.extend([
        Line::from(""),
        section_header("Install"),
        Line::from("Bastion will not update automatically."),
        Line::from("Install manually from the release page."),
    ]);

    lines
}

fn render_database_engine_picker(frame: &mut Frame<'_>, area: Rect, state: &AppState) {
    let popup = centered(area, DATABASE_ENGINE_WIDTH, 16);

    frame.render_widget(Clear, popup);

    let block = active_window_block("Database Engine");
    let inner = block.inner(popup);

    frame.render_widget(block, popup);

    let [body_area, separator_area, footer_area] = Layout::vertical([
        Constraint::Fill(1),
        Constraint::Length(1),
        Constraint::Length(1),
    ])
    .areas(inner);

    let body_area = padded(body_area, POPUP_HORIZONTAL_PADDING, 0);
    let [options_area, divider_area, details_area] = Layout::horizontal([
        Constraint::Length(31),
        Constraint::Length(1),
        Constraint::Fill(1),
    ])
    .areas(body_area);

    let mut option_lines = vec![Line::from("Choose database engine"), Line::from("")];
    option_lines.extend(
        database_engine_choices()
            .iter()
            .enumerate()
            .map(|(index, engine)| {
                let selected = *engine == state.database_engine_choice();
                picker_row(
                    &format!("{} {}", index + 1, engine.label()),
                    selected,
                    options_area.width,
                )
            }),
    );

    frame.render_widget(
        Paragraph::new(option_lines)
            .style(Style::new().bg(Color::Black))
            .wrap(Wrap { trim: false }),
        options_area,
    );

    render_inner_vertical_separator(frame, divider_area);

    frame.render_widget(
        Paragraph::new(database_engine_detail_lines(state.database_engine_choice()))
            .style(Style::new().bg(Color::Black))
            .wrap(Wrap { trim: false }),
        padded(details_area, POPUP_HORIZONTAL_PADDING, 0),
    );

    frame.render_widget(
        Paragraph::new(palette_separator(separator_area.width))
            .style(Style::new().bg(Color::Black)),
        separator_area,
    );

    frame.render_widget(
        Paragraph::new(shortcut_line(&[
            ("↑/↓", "choose"),
            ("1-4", "select"),
            ("Enter", "select"),
            ("Esc", "back"),
        ]))
        .style(Style::new().bg(Color::Black)),
        padded(footer_area, POPUP_HORIZONTAL_PADDING, 0),
    );
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

fn discard_changes_body(state: &AppState) -> Vec<Line<'static>> {
    let mut lines = vec![Line::from("Discard unsaved changes?"), Line::from("")];

    if let Some(form) = state.form() {
        lines.push(section_header(form_kind_label(form.mode())));
        let title = form.value(FormField::Title);
        if !title.trim().is_empty() {
            lines.push(detail_row("Title", title));
        }
        lines.push(Line::from(""));
    }

    lines.push(Line::styled("Unsaved edits will be lost.", danger_style()));
    lines
}

fn delete_modal_body(state: &AppState, secret_id: bastion_core::SecretId) -> Vec<Line<'static>> {
    let mut lines = vec![
        Line::from("Delete this secret?"),
        Line::from("This cannot be undone.")
            .style(Style::new().fg(Color::Red).add_modifier(Modifier::BOLD)),
    ];
    if let VaultSession::Unlocked { vault } = state.session()
        && let Some(secret) = vault
            .secrets()
            .iter()
            .find(|secret| secret.id() == secret_id)
    {
        lines.push(Line::from(""));
        lines.extend(delete_secret_summary(secret));
    }
    lines
}

fn reveal_modal_body(state: &AppState, secret_ref: crate::SecretRef) -> Vec<Line<'static>> {
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
        section_header("Safety"),
        Line::from("c copies the primary secret value"),
        Line::from("r reveals for 10 seconds"),
        Line::from("l locks the vault and clears sensitive UI state"),
        Line::from("clipboard clears automatically"),
        Line::from(""),
        section_header("Global"),
        Line::from("Space    Command palette"),
        Line::from("?        Help"),
        Line::from("l        Lock vault"),
    ]
}

fn render_search_palette(frame: &mut Frame<'_>, area: Rect, state: &AppState) {
    let width = area.width.min(PALETTE_WIDTH);
    let height = PALETTE_HEIGHT;
    let popup = centered(area, width, height);

    frame.render_widget(Clear, popup);

    let title = state.search_palette_title();
    let block = active_window_block(&title);
    let inner = block.inner(popup);

    frame.render_widget(block, popup);

    let [
        input_area,
        top_separator_area,
        results_area,
        bottom_separator_area,
        footer_area,
    ] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Fill(1),
        Constraint::Length(1),
        Constraint::Length(1),
    ])
    .areas(inner);

    frame.render_widget(
        Paragraph::new(palette_input_line(
            state.search_query(),
            "type to search visible secrets",
        ))
        .style(Style::new().bg(Color::Black)),
        padded(input_area, POPUP_HORIZONTAL_PADDING, 0),
    );

    frame.render_widget(
        Paragraph::new(palette_separator(top_separator_area.width))
            .style(Style::new().bg(Color::Black)),
        top_separator_area,
    );

    let items = state.search_palette_items();
    if items.is_empty() {
        frame.render_widget(
            Paragraph::new(vec![
                Line::from("No matching secrets"),
                Line::from("Try another search term or press Esc to close."),
            ])
            .style(Style::new().bg(Color::Black)),
            padded(results_area, POPUP_HORIZONTAL_PADDING, 0),
        );
    } else {
        let results_area = padded(results_area, POPUP_HORIZONTAL_PADDING, 0);
        let query = state.search_query().to_owned();
        let visible_height = results_area.height as usize;
        let total_rows = items.len();
        let selected_row_index = items
            .iter()
            .position(|(_, selected)| *selected)
            .unwrap_or(0);
        let scroll_start =
            command_palette_scroll_start(selected_row_index, total_rows, visible_height);
        let scroll_end = (scroll_start + visible_height).min(total_rows);

        let mut rows = items
            .into_iter()
            .skip(scroll_start)
            .take(visible_height)
            .map(|(label, selected)| {
                ListItem::new(search_result_line(
                    &label,
                    &query,
                    selected,
                    results_area.width,
                ))
                .style(if selected {
                    selected_row_style(true)
                } else {
                    Style::default()
                })
            })
            .collect::<Vec<_>>();

        apply_scroll_indicators(
            &mut rows,
            scroll_start,
            scroll_end,
            total_rows,
            visible_height,
            results_area.width,
        );

        frame.render_widget(
            List::new(rows).style(Style::new().bg(Color::Black)),
            results_area,
        );
    }

    frame.render_widget(
        Paragraph::new(palette_separator(bottom_separator_area.width))
            .style(Style::new().bg(Color::Black)),
        bottom_separator_area,
    );

    frame.render_widget(
        Paragraph::new(palette_footer_line(&[
            ("↑/↓", "move"),
            ("1-9", "choose"),
            ("Enter", "select"),
            ("Esc", "close"),
        ]))
        .style(Style::new().bg(Color::Black)),
        padded(footer_area, POPUP_HORIZONTAL_PADDING, 0),
    );
}

fn render_command_palette(frame: &mut Frame<'_>, area: Rect, state: &AppState) {
    let width = area.width.min(PALETTE_WIDTH);
    let height = PALETTE_HEIGHT;
    let popup = centered(area, width, height);

    frame.render_widget(Clear, popup);

    let block = active_window_block("Command Palette");
    let inner = block.inner(popup);

    frame.render_widget(block, popup);

    let [
        input_area,
        top_separator_area,
        results_area,
        bottom_separator_area,
        footer_area,
    ] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Fill(1),
        Constraint::Length(1),
        Constraint::Length(1),
    ])
    .areas(inner);

    frame.render_widget(
        Paragraph::new(palette_input_line(
            state.command_palette_query(),
            "type a command or alias",
        ))
        .style(Style::new().bg(Color::Black)),
        padded(input_area, POPUP_HORIZONTAL_PADDING, 0),
    );

    frame.render_widget(
        Paragraph::new(palette_separator(top_separator_area.width))
            .style(Style::new().bg(Color::Black)),
        top_separator_area,
    );

    let items = state.command_palette_items();
    if items.is_empty() {
        frame.render_widget(
            Paragraph::new(vec![
                Line::from("No matching commands"),
                Line::from("Try add, copy, reveal, search, or lock."),
            ])
            .style(Style::new().bg(Color::Black)),
            padded(results_area, POPUP_HORIZONTAL_PADDING, 0),
        );
    } else {
        let results_area = padded(results_area, POPUP_HORIZONTAL_PADDING, 0);
        let [commands_area, divider_area, details_area] = Layout::horizontal([
            Constraint::Length(31),
            Constraint::Length(1),
            Constraint::Fill(1),
        ])
        .areas(results_area);

        let mut rows = Vec::new();
        let mut current_group: Option<&'static str> = None;
        let mut command_index = 1usize;
        let mut selected_row_index = None;

        for item in items.iter() {
            if current_group != Some(item.group) {
                current_group = Some(item.group);
                rows.push(ListItem::new(Line::from(Span::styled(
                    pad_or_truncate(item.group, commands_area.width),
                    Style::new().fg(Color::Yellow).add_modifier(Modifier::BOLD),
                ))));
            }

            if item.selected {
                selected_row_index = Some(rows.len());
            }

            let line = command_palette_row_line(item, command_index, commands_area.width);
            let style = if item.selected {
                selected_row_style(true)
            } else if !item.available {
                muted_style()
            } else {
                Style::default()
            };
            rows.push(ListItem::new(line).style(style));
            command_index += 1;
        }

        let visible_height = commands_area.height as usize;
        let total_rows = rows.len();
        let selected_row_index = selected_row_index.unwrap_or(0);
        let scroll_start =
            command_palette_scroll_start(selected_row_index, total_rows, visible_height);
        let scroll_end = (scroll_start + visible_height).min(total_rows);
        let has_hidden_commands = total_rows > visible_height;

        let mut visible_rows = rows
            .into_iter()
            .skip(scroll_start)
            .take(visible_height)
            .collect::<Vec<_>>();

        apply_scroll_indicators(
            &mut visible_rows,
            scroll_start,
            scroll_end,
            total_rows,
            visible_height,
            commands_area.width,
        );

        frame.render_widget(
            List::new(visible_rows).style(Style::new().bg(Color::Black)),
            commands_area,
        );

        render_inner_vertical_separator(frame, divider_area);

        let mut detail_lines = match (
            state.selected_command_label(),
            state.selected_command_description(),
        ) {
            (Some(label), Some(description)) => {
                let mut lines = vec![
                    section_header(label),
                    Line::from(""),
                    section_header("Description"),
                    Line::from(description),
                ];

                if label == "Delete selected item" {
                    lines.extend([
                        Line::from(""),
                        section_header("Danger"),
                        Line::styled(
                            "This removes the selected secret from the vault.",
                            danger_style(),
                        ),
                    ]);
                }

                if let Some(reason) = state.selected_command_unavailable_reason() {
                    lines.extend([
                        Line::from(""),
                        section_header("Unavailable"),
                        Line::styled(reason, danger_style()),
                    ]);
                }

                lines
            }
            _ => Vec::new(),
        };

        if has_hidden_commands {
            detail_lines.extend([
                Line::from(""),
                Line::styled(
                    format!(
                        "Showing {}-{} of {} rows",
                        scroll_start + 1,
                        scroll_end,
                        total_rows
                    ),
                    muted_style(),
                ),
                Line::styled("Use ↑/↓ to scroll commands.", muted_style()),
            ]);
        }

        frame.render_widget(
            Paragraph::new(detail_lines)
                .style(Style::new().bg(Color::Black))
                .wrap(Wrap { trim: false }),
            padded(details_area, POPUP_HORIZONTAL_PADDING, 0),
        );
    }

    frame.render_widget(
        Paragraph::new(palette_separator(bottom_separator_area.width))
            .style(Style::new().bg(Color::Black)),
        bottom_separator_area,
    );

    frame.render_widget(
        Paragraph::new(palette_footer_line(&[
            ("↑/↓", "move"),
            ("1-9", "choose"),
            ("Enter", "run"),
            ("Esc", "close"),
        ]))
        .style(Style::new().bg(Color::Black)),
        padded(footer_area, POPUP_HORIZONTAL_PADDING, 0),
    );
}

fn render_inner_vertical_separator(frame: &mut Frame<'_>, area: Rect) {
    let lines = (0..area.height)
        .map(|_| Line::from("│").style(muted_style()))
        .collect::<Vec<_>>();

    frame.render_widget(
        Paragraph::new(lines).style(Style::new().bg(Color::Black)),
        area,
    );
}

fn command_palette_scroll_start(
    selected_row_index: usize,
    total_rows: usize,
    visible_height: usize,
) -> usize {
    if visible_height == 0 || total_rows <= visible_height {
        return 0;
    }

    let half_window = visible_height.saturating_sub(1) / 2;
    let max_start = total_rows.saturating_sub(visible_height);

    selected_row_index
        .saturating_sub(half_window)
        .min(max_start)
}

fn apply_scroll_indicators(
    rows: &mut Vec<ListItem<'static>>,
    scroll_start: usize,
    scroll_end: usize,
    total_rows: usize,
    visible_height: usize,
    width: u16,
) {
    if visible_height == 0 || total_rows <= visible_height || rows.is_empty() {
        return;
    }

    if scroll_start > 0 {
        rows.insert(
            0,
            ListItem::new(Line::styled(
                pad_or_truncate("↑ more", width),
                scroll_indicator_style(),
            )),
        );
        if rows.len() > visible_height {
            rows.pop();
        }
    }

    if scroll_end < total_rows {
        if rows.len() >= visible_height {
            rows.pop();
        }
        rows.push(ListItem::new(Line::styled(
            pad_or_truncate("↓ more", width),
            scroll_indicator_style(),
        )));
    }
}

fn command_palette_row_line(
    item: &crate::app::CommandPaletteItem,
    command_index: usize,
    width: u16,
) -> Line<'static> {
    let marker = if item.selected { "›" } else { " " };
    let text = format!("{marker} {command_index} {}", item.label);
    Line::from(pad_or_truncate(&text, width))
}

fn pad_or_truncate(value: &str, width: u16) -> String {
    let width = width as usize;
    if width == 0 {
        return String::new();
    }

    let mut output = soft_truncate(value, width);
    let len = output.chars().count();
    if len < width {
        output.push_str(&" ".repeat(width - len));
    }
    output
}

fn choice_detail_lines(
    label: &'static str,
    description: &'static str,
    best_for: &'static str,
    examples: &'static str,
) -> Vec<Line<'static>> {
    let mut lines = vec![section_header(label)];

    push_optional_detail_section(&mut lines, "Description", description);
    push_optional_detail_section(&mut lines, "Best for", best_for);
    push_optional_detail_section(&mut lines, "Examples", examples);

    lines
}

fn push_optional_detail_section(lines: &mut Vec<Line<'static>>, title: &'static str, value: &str) {
    let value = value.trim();
    if value.is_empty() {
        return;
    }

    if !lines.is_empty() {
        lines.push(Line::from(""));
    }

    lines.push(section_header(title));
    lines.push(Line::from(value.to_owned()));
}

fn palette_separator(width: u16) -> Line<'static> {
    Line::styled("─".repeat(width as usize), Style::new().fg(Color::Gray))
}

fn secret_list_line(secret: &Secret, width: u16) -> Line<'static> {
    let badge = secret_type_badge(secret);
    let width = width as usize;
    let badge_width = badge.chars().count();
    let title_width = width.saturating_sub(badge_width + 2);

    Line::from(vec![
        Span::raw(format!(
            "{:<title_width$}",
            soft_truncate(secret.title(), title_width),
            title_width = title_width
        )),
        Span::raw("  "),
        Span::styled(badge, Style::new().fg(Color::Yellow)),
    ])
}

fn secret_type_badge(secret: &Secret) -> &'static str {
    match secret.kind() {
        SecretKind::DatabaseCredential(_) => "DB",
        SecretKind::ApiKeyToken(_) => "API",
        SecretKind::AccountRecovery(_) => "REC",
    }
}

fn tag_chips_line(label: &str, tags: &[String]) -> Line<'static> {
    if tags.is_empty() {
        return detail_row(label, "none");
    }

    let mut spans = vec![Span::raw(format!("{label:<12}"))];
    for tag in tags {
        spans.push(Span::styled(
            format!(" #{tag} "),
            Style::new().fg(Color::Yellow).bg(Color::DarkGray),
        ));
        spans.push(Span::raw(" "));
    }
    Line::from(spans)
}

fn detail_row(label: &str, value: &str) -> Line<'static> {
    Line::from(vec![
        Span::raw(format!("{label:<12}")),
        Span::raw(value.to_owned()),
    ])
}

fn detail_row_with_hint(label: &str, value: &str, hint: &str) -> Line<'static> {
    Line::from(vec![
        Span::raw(format!("{label:<12}")),
        Span::raw(value.to_owned()),
        Span::raw("  "),
        Span::styled(hint.to_owned(), muted_style()),
    ])
}

fn search_result_line(label: &str, query: &str, selected: bool, width: u16) -> Line<'static> {
    let marker = if selected { "› " } else { "  " };
    let visible = pad_or_truncate(&format!("{marker}{label}"), width);
    let query = query.trim().to_lowercase();
    if query.is_empty() {
        return Line::from(visible);
    }

    let lower = visible.to_lowercase();
    let Some(start) = lower.find(&query) else {
        return Line::from(visible);
    };
    let end = start + query.len();
    if !visible.is_char_boundary(start) || !visible.is_char_boundary(end) {
        return Line::from(visible);
    }

    Line::from(vec![
        Span::raw(visible[..start].to_owned()),
        Span::styled(
            visible[start..end].to_owned(),
            Style::new().fg(Color::Yellow).add_modifier(Modifier::BOLD),
        ),
        Span::raw(visible[end..].to_owned()),
    ])
}

fn database_engine_detail_lines(engine: bastion_core::DatabaseEngine) -> Vec<Line<'static>> {
    let default_port = engine
        .default_port()
        .map(|port| port.to_string())
        .unwrap_or_else(|| "not fixed".to_owned());
    let (description, best_for, connection_hint) = match engine {
        bastion_core::DatabaseEngine::PostgreSql => (
            "PostgreSQL-compatible connection settings.",
            "Most production Postgres databases and local development databases.",
            "Usually uses host, port, database, schema, username, and password.",
        ),
        bastion_core::DatabaseEngine::MySql => (
            "MySQL-compatible connection settings.",
            "MySQL servers, managed MySQL instances, and legacy applications.",
            "Use this when the service expects a MySQL connection string or MySQL client.",
        ),
        bastion_core::DatabaseEngine::MariaDb => (
            "MariaDB-compatible connection settings.",
            "MariaDB servers and MySQL-compatible deployments using MariaDB.",
            "Use this for MariaDB deployments, even when the client protocol is MySQL-compatible.",
        ),
        bastion_core::DatabaseEngine::Other => (
            "Generic database credential settings.",
            "Databases that do not fit the built-in presets.",
            "Keep the generic fields and add context in the title or tags.",
        ),
    };

    let mut lines = vec![section_header(engine.label())];

    push_optional_detail_section(&mut lines, "Default port", &default_port);
    push_optional_detail_section(&mut lines, "Connection hint", connection_hint);
    push_optional_detail_section(&mut lines, "Description", description);
    push_optional_detail_section(&mut lines, "Best for", best_for);

    lines
}

fn delete_secret_summary(secret: &Secret) -> Vec<Line<'static>> {
    match secret.kind() {
        SecretKind::DatabaseCredential(credential) => vec![
            Line::from(format!("Title     {}", credential.title())),
            Line::from(format!("Engine    {}", credential.engine().label())),
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

fn panel_block<'a>(title: &'a str, focused: bool) -> Block<'a> {
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

fn selectable_list<'a>(rows: Vec<ListItem<'a>>, title: &'a str, panel_focused: bool) -> List<'a> {
    List::new(rows)
        .block(panel_block(title, panel_focused))
        .highlight_symbol("› ")
        .highlight_style(selected_row_style(panel_focused))
}

fn muted_style() -> Style {
    Style::new().fg(Color::Indexed(244))
}

fn checklist_style() -> Style {
    Style::new()
        .fg(Color::Indexed(214))
        .add_modifier(Modifier::BOLD)
}

fn scroll_indicator_style() -> Style {
    Style::new()
        .fg(Color::Indexed(214))
        .add_modifier(Modifier::BOLD)
}

fn danger_style() -> Style {
    Style::new().fg(Color::Red).add_modifier(Modifier::BOLD)
}

fn invalid_field_style(focused: bool) -> Style {
    if focused {
        Style::new()
            .fg(Color::White)
            .bg(Color::Indexed(52))
            .add_modifier(Modifier::BOLD)
    } else {
        danger_style()
    }
}

fn selected_row_style(panel_focused: bool) -> Style {
    if panel_focused {
        Style::new()
            .fg(Color::Indexed(214))
            .bg(Color::Indexed(238))
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

    let block = active_window_block(title);
    let inner = padded(block.inner(popup), POPUP_HORIZONTAL_PADDING, 0);

    frame.render_widget(block, popup);
    frame.render_widget(
        Paragraph::new(text)
            .style(Style::new().bg(Color::Black))
            .wrap(Wrap { trim: false }),
        inner,
    );
}

fn render_popup_with_footer<'a>(
    frame: &mut Frame<'_>,
    popup: Rect,
    title: &'a str,
    body: Vec<Line<'a>>,
    footer: Line<'a>,
) {
    render_popup_with_footer_lines(frame, popup, title, body, vec![footer]);
}

fn render_popup_with_footer_lines<'a>(
    frame: &mut Frame<'_>,
    popup: Rect,
    title: &'a str,
    body: Vec<Line<'a>>,
    footer: Vec<Line<'a>>,
) {
    frame.render_widget(Clear, popup);

    let block = active_window_block(title);
    let inner = block.inner(popup);

    frame.render_widget(block, popup);

    let footer_height = footer.len().max(1) as u16;

    let [body_area, separator_area, footer_area] = Layout::vertical([
        Constraint::Fill(1),
        Constraint::Length(1),
        Constraint::Length(footer_height),
    ])
    .areas(inner);

    frame.render_widget(
        Paragraph::new(body)
            .style(Style::new().bg(Color::Black))
            .wrap(Wrap { trim: false }),
        padded(body_area, POPUP_HORIZONTAL_PADDING, 0),
    );

    frame.render_widget(
        Paragraph::new(palette_separator(separator_area.width))
            .style(Style::new().bg(Color::Black)),
        separator_area,
    );

    frame.render_widget(
        Paragraph::new(footer).style(Style::new().bg(Color::Black)),
        padded(footer_area, POPUP_HORIZONTAL_PADDING, 0),
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

fn palette_footer_line(shortcuts: &[(&str, &str)]) -> Line<'static> {
    let mut line = shortcut_line(shortcuts);
    line.spans.insert(0, Span::raw("      "));
    line
}

fn form_mode_line(mode: FormMode, title: &str, dirty: bool) -> Line<'static> {
    let status = if dirty { "Modified" } else { "Saved" };
    match mode {
        FormMode::AddPostgreSqlCredential => {
            Line::from("New database credential").style(Style::new().bold())
        }
        FormMode::EditPostgreSqlCredential(_) => {
            let title = if title.trim().is_empty() {
                "Database Credential"
            } else {
                title
            };
            Line::from(vec![
                Span::styled("Editing database credential", Style::new().bold()),
                Span::raw("  "),
                Span::raw(title.to_owned()),
                Span::raw("  "),
                Span::styled(status, Style::new().fg(Color::Yellow)),
            ])
        }
        FormMode::AddApiKeyToken => {
            Line::from("New API token / access token").style(Style::new().bold())
        }
        FormMode::AddAccountRecovery(kind) => {
            Line::from(format!("New {}", recovery_form_title(kind))).style(Style::new().bold())
        }
        FormMode::EditApiKeyToken(_) => {
            let title = if title.trim().is_empty() {
                "API Key / Token"
            } else {
                title
            };
            Line::from(vec![
                Span::styled("Editing API token / access token", Style::new().bold()),
                Span::raw("  "),
                Span::raw(title.to_owned()),
                Span::raw("  "),
                Span::styled(status, Style::new().fg(Color::Yellow)),
            ])
        }
    }
}

fn form_metadata_line(mode: FormMode, dirty: bool) -> Line<'static> {
    match mode {
        FormMode::AddPostgreSqlCredential
        | FormMode::AddApiKeyToken
        | FormMode::AddAccountRecovery(_) => Line::from(""),
        FormMode::EditPostgreSqlCredential(_) | FormMode::EditApiKeyToken(_) => {
            let status = if dirty { "unsaved changes" } else { "saved" };
            Line::from(vec![
                Span::styled("Metadata", Style::new().add_modifier(Modifier::BOLD)),
                Span::raw("  "),
                Span::raw(status),
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

fn picker_row(label: &str, selected: bool, width: u16) -> Line<'static> {
    let marker = if selected { "›" } else { " " };
    let style = if selected {
        selected_row_style(true)
    } else {
        Style::default()
    };

    Line::from(pad_or_truncate(&format!("{marker} {label}"), width)).style(style)
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

fn form_input_line(
    field: FormField,
    label: &str,
    value: &str,
    focused: bool,
    invalid: bool,
) -> Line<'static> {
    let marker = if focused { "›" } else { " " };
    let cursor = if focused { "█" } else { "" };
    let label = form_label(label, field);
    let is_empty = value.is_empty();
    let visible_value = if is_empty {
        form_placeholder(field).to_owned()
    } else {
        value.to_owned()
    };

    let label_style = if invalid {
        danger_style()
    } else {
        Style::default()
    };
    let value = if invalid {
        Span::styled(
            if focused {
                format!("[{}{}]", visible_value, cursor)
            } else {
                visible_value
            },
            invalid_field_style(focused),
        )
    } else if focused {
        Span::styled(
            format!("[{}{}]", visible_value, cursor),
            selected_row_style(true),
        )
    } else if is_empty {
        Span::styled(visible_value, muted_style())
    } else {
        Span::raw(visible_value)
    };

    Line::from(vec![
        Span::raw(marker),
        Span::raw(" "),
        Span::styled(format!("{label:<10}"), label_style),
        Span::raw("  "),
        value,
    ])
}

fn form_select_line(
    field: FormField,
    label: &str,
    value: &str,
    focused: bool,
    invalid: bool,
) -> Line<'static> {
    let marker = if focused { "›" } else { " " };
    let cursor = if focused { "█" } else { "" };
    let label = form_label(label, field);
    let label_style = if invalid {
        danger_style()
    } else {
        Style::default()
    };
    let value = if invalid {
        Span::styled(
            if focused {
                format!("[{} ▾{}]", value, cursor)
            } else {
                format!("{} ▾", value)
            },
            invalid_field_style(focused),
        )
    } else if focused {
        Span::styled(format!("[{} ▾{}]", value, cursor), selected_row_style(true))
    } else {
        Span::raw(format!("{} ▾", value))
    };

    Line::from(vec![
        Span::raw(marker),
        Span::raw(" "),
        Span::styled(format!("{label:<10}"), label_style),
        Span::raw("  "),
        value,
    ])
}

fn push_form_input_line(
    lines: &mut Vec<Line<'static>>,
    form: &crate::FormState,
    field: FormField,
    label: &str,
    value: &str,
) {
    let focused = form.focused_field() == Some(field);
    let invalid = form
        .validation_error()
        .is_some_and(|error| error.field() == field);
    lines.push(form_input_line(field, label, value, focused, invalid));

    if let Some(error) = form.validation_error()
        && error.field() == field
    {
        lines.push(form_error_line(error.message()));
    } else if focused {
        if let Some(helper) = form_helper_text(field) {
            lines.push(form_helper_line(helper));
        }
    }
}

fn push_form_select_line(
    lines: &mut Vec<Line<'static>>,
    form: &crate::FormState,
    field: FormField,
    label: &str,
    value: &str,
) {
    let focused = form.focused_field() == Some(field);
    let invalid = form
        .validation_error()
        .is_some_and(|error| error.field() == field);
    lines.push(form_select_line(field, label, value, focused, invalid));

    if let Some(error) = form.validation_error()
        && error.field() == field
    {
        lines.push(form_error_line(error.message()));
    } else if focused {
        if let Some(helper) = form_helper_text(field) {
            lines.push(form_helper_line(helper));
        }
    }
}

fn form_error_line(message: &str) -> Line<'static> {
    Line::from(vec![
        Span::raw("  ! "),
        Span::styled(message.to_owned(), danger_style()),
    ])
}

fn form_helper_line(message: &str) -> Line<'static> {
    Line::from(vec![
        Span::raw("    "),
        Span::styled(message.to_owned(), muted_style()),
    ])
}

fn form_helper_text(field: FormField) -> Option<&'static str> {
    match field {
        FormField::Tags => Some("Separate tags with commas, for example: prod, github."),
        FormField::Engine => Some("Press Enter to choose the database engine."),
        FormField::Hostname => Some("Use a hostname, IP address, or local name such as localhost."),
        FormField::Port => Some("Use the service port. Defaults update when the engine changes."),
        FormField::Schema => Some("Optional. PostgreSQL commonly uses public."),
        FormField::Url => Some("Optional. Store the related login or provider URL."),
        FormField::Account => Some("Optional. Store the email, username, or account identifier."),
        FormField::Password => Some("Generate a strong value with Ctrl+G."),
        FormField::Token => Some("Generate a random token with Ctrl+G."),
        FormField::RecoveryMaterial => {
            Some("Paste one code per line, or paste the full recovery value.")
        }
        FormField::CustomFields => Some("Use Label=value, or Label*=value for sensitive fields."),
        FormField::ExpiresAt | FormField::LastRotatedAt => Some("Use YYYY-MM-DD."),
        FormField::RotateEveryDays => Some("Use a number of days, for example 90."),
        _ => None,
    }
}

fn form_label(label: &str, field: FormField) -> String {
    if is_required_field(field) {
        format!("{label}*")
    } else {
        label.to_owned()
    }
}

fn is_required_field(field: FormField) -> bool {
    matches!(
        field,
        FormField::Title
            | FormField::Engine
            | FormField::Hostname
            | FormField::Port
            | FormField::Database
            | FormField::Username
            | FormField::Password
            | FormField::Service
            | FormField::Token
            | FormField::RecoveryMaterial
    )
}

fn form_placeholder(field: FormField) -> &'static str {
    match field {
        FormField::Title => "required title",
        FormField::Tags => "optional, comma separated",
        FormField::Engine => "choose engine",
        FormField::Hostname => "db.example.com",
        FormField::Port => "5432",
        FormField::Database => "database name",
        FormField::Account => "optional account",
        FormField::Url => "optional URL",
        FormField::Username => "username",
        FormField::Password => "password",
        FormField::Token => "token",
        FormField::RecoveryMaterial => "recovery material",
        FormField::Schema => "optional schema",
        FormField::Service => "service name",
        FormField::CustomFields => "Label=value",
        FormField::ExpiresAt => "YYYY-MM-DD",
        FormField::RotateEveryDays => "90",
        FormField::LastRotatedAt => "YYYY-MM-DD",
    }
}

fn custom_fields_input_lines(value: &str, focused: bool) -> Vec<Line<'static>> {
    const WIDTH: usize = 58;
    const VISIBLE_LINES: usize = 3;

    let marker = if focused { "›" } else { " " };
    let mut lines = vec![
        Line::from(format!(
            "{marker} {:<10}",
            form_label("Custom", FormField::CustomFields)
        )),
        Line::from("  ┌──────────────────────────────────────────────────────────┐"),
    ];

    let mut visible_lines = if value.trim().is_empty() {
        vec![form_placeholder(FormField::CustomFields).to_owned()]
    } else {
        value.lines().map(str::to_owned).collect::<Vec<_>>()
    };

    while visible_lines.len() < VISIBLE_LINES {
        visible_lines.push(String::new());
    }

    for (index, content) in visible_lines.into_iter().take(VISIBLE_LINES).enumerate() {
        let mut visible = soft_truncate(&content, WIDTH);
        if focused
            && index
                == value
                    .lines()
                    .count()
                    .saturating_sub(1)
                    .min(VISIBLE_LINES - 1)
        {
            visible.push('█');
        }
        let style = if value.trim().is_empty() && index == 0 {
            muted_style()
        } else {
            Style::default()
        };
        lines.push(Line::from(vec![
            Span::raw("  │"),
            Span::styled(format!("{visible:<WIDTH$}"), style),
            Span::raw("│"),
        ]));
    }

    lines.push(Line::from(
        "  └──────────────────────────────────────────────────────────┘",
    ));
    lines
}

fn recovery_material_helper_text(kind: crate::RecoveryKindChoice) -> &'static str {
    match kind {
        crate::RecoveryKindChoice::RecoveryCodeSet => {
            "Paste one code per line. Ctrl+G generates 10 new random codes."
        }
        crate::RecoveryKindChoice::RecoveryKey => {
            "Paste the recovery key. Ctrl+G can generate a random key."
        }
        crate::RecoveryKindChoice::RecoveryPhrase => {
            "Paste the full phrase exactly as given, preserving word order."
        }
        crate::RecoveryKindChoice::RecoveryFile => {
            "Store the file name, path, or offline location reference."
        }
        crate::RecoveryKindChoice::RecoveryInstructions => {
            "Write clear manual steps for account recovery."
        }
        crate::RecoveryKindChoice::SecurityQuestions => {
            "Use one question and answer per line when possible."
        }
    }
}

fn recovery_material_input_lines(label: &str, value: &str, focused: bool) -> Vec<Line<'static>> {
    const WIDTH: usize = 58;
    const VISIBLE_LINES: usize = 4;

    let marker = if focused { "›" } else { " " };
    let mut lines = vec![
        Line::from(format!("{marker} {label:<8}")),
        Line::from("  ┌──────────────────────────────────────────────────────────┐"),
    ];

    let mut masked_lines = value.split('\n').map(mask_value).collect::<Vec<_>>();
    if masked_lines.is_empty() {
        masked_lines.push(String::new());
    }
    while masked_lines.len() < VISIBLE_LINES {
        masked_lines.push(String::new());
    }

    let last_content_index = value.split('\n').count().saturating_sub(1);
    for (index, content) in masked_lines.into_iter().take(VISIBLE_LINES).enumerate() {
        let mut visible = content.chars().take(WIDTH).collect::<String>();
        if focused && index == last_content_index.min(VISIBLE_LINES - 1) {
            visible.push('█');
        }
        lines.push(Line::from(format!(
            "  │ {visible:<width$} │",
            width = WIDTH
        )));
    }

    lines.push(Line::from(
        "  └──────────────────────────────────────────────────────────┘",
    ));
    lines
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

fn vault_attention_label(state: &AppState) -> Option<String> {
    if let Some(seconds) = reveal_seconds_remaining(state) {
        return Some(format!("Reveal hides in {seconds}s"));
    }

    if state.is_dirty() {
        Some("Modified".to_owned())
    } else if let Some(seconds) = auto_lock_seconds_remaining(state) {
        Some(format!("Auto-lock in {}", format_duration(seconds)))
    } else {
        None
    }
}

fn reveal_seconds_remaining(state: &AppState) -> Option<i64> {
    let expires_at = state.reveal_expires_at()?;
    Some((expires_at - Utc::now()).num_seconds().max(0))
}

fn auto_lock_seconds_remaining(state: &AppState) -> Option<i64> {
    if !matches!(
        state.screen(),
        Screen::Main | Screen::Form | Screen::DatabaseEnginePicker
    ) {
        return None;
    }

    let deadline = state.auto_lock_deadline()?;
    Some((deadline - Utc::now()).num_seconds().max(0))
}

fn format_duration(seconds: i64) -> String {
    if seconds < 60 {
        return format!("{seconds}s");
    }

    let minutes = (seconds + 59) / 60;
    format!("{minutes}m")
}

fn palette_input_line(query: &str, placeholder: &'static str) -> Line<'static> {
    if query.is_empty() {
        Line::from(vec![
            Span::raw("> "),
            Span::styled(placeholder, muted_style()),
            Span::raw("█"),
        ])
    } else {
        Line::from(format!("> {query}█"))
    }
}

fn soft_truncate(value: &str, max_chars: usize) -> String {
    if max_chars == 0 {
        return String::new();
    }

    if value.chars().count() <= max_chars {
        return value.to_owned();
    }

    if max_chars == 1 {
        return "…".to_owned();
    }

    let mut output = value.chars().take(max_chars - 1).collect::<String>();
    output.push('…');
    output
}

fn form_kind_label(mode: FormMode) -> &'static str {
    match mode {
        FormMode::AddPostgreSqlCredential => "New database credential",
        FormMode::EditPostgreSqlCredential(_) => "Database credential",
        FormMode::AddApiKeyToken => "New API key / token",
        FormMode::EditApiKeyToken(_) => "API key / token",
        FormMode::AddAccountRecovery(_) => "Account recovery",
    }
}

fn form_field_title(field: FormField) -> &'static str {
    match field {
        FormField::Title => "Title",
        FormField::Service => "Service",
        FormField::Engine => "Engine",
        FormField::Hostname => "Hostname",
        FormField::Port => "Port",
        FormField::Database => "Database",
        FormField::Account => "Account",
        FormField::Url => "URL",
        FormField::Username => "Username",
        FormField::Password => "Password",
        FormField::Token => "Token",
        FormField::RecoveryMaterial => "Recovery material",
        FormField::Schema => "Schema",
        FormField::Tags => "Tags",
        FormField::CustomFields => "Custom fields",
        FormField::ExpiresAt => "Expires at",
        FormField::RotateEveryDays => "Rotate every",
        FormField::LastRotatedAt => "Last rotated",
    }
}

fn padded(area: Rect, horizontal: u16, vertical: u16) -> Rect {
    let horizontal = horizontal.min(area.width / 2);
    let vertical = vertical.min(area.height / 2);

    Rect {
        x: area.x + horizontal,
        y: area.y + vertical,
        width: area.width.saturating_sub(horizontal * 2),
        height: area.height.saturating_sub(vertical * 2),
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

fn master_passphrase_input_line(
    masked: &str,
    is_empty: bool,
    focused: bool,
    placeholder: &'static str,
) -> Line<'static> {
    let marker = if focused { "›" } else { " " };
    let cursor = if focused { "█" } else { "" };
    let value = if is_empty {
        format!("{placeholder}{cursor}")
    } else {
        format!("{masked}{cursor}")
    };

    let value = format!("[{value}]");
    let value_span = if focused {
        Span::styled(value, selected_row_style(true))
    } else if is_empty {
        Span::styled(value, muted_style())
    } else {
        Span::raw(value)
    };

    Line::from(vec![Span::raw(marker), Span::raw(" "), value_span])
}

fn onboarding_passphrase_check_lines(state: &AppState) -> Vec<Line<'static>> {
    let passphrase = state.master_passphrase();
    let confirmation = state.master_passphrase_confirmation();

    let mut lines = vec![section_header("Passphrase")];
    if passphrase.is_empty() {
        lines.push(checklist_line(
            "•",
            "Enter a master passphrase.",
            muted_style(),
        ));
    } else {
        lines.push(checklist_line(
            "✓",
            "Master passphrase entered.",
            checklist_style(),
        ));
    }

    if confirmation.is_empty() {
        lines.push(checklist_line(
            "•",
            "Confirm the passphrase.",
            muted_style(),
        ));
    } else if passphrase == confirmation {
        lines.push(checklist_line(
            "✓",
            "Confirmation matches.",
            checklist_style(),
        ));
    } else {
        lines.push(checklist_line(
            "!",
            "Confirmation does not match.",
            danger_style(),
        ));
    }

    lines
}

fn checklist_line(symbol: &'static str, text: &'static str, style: Style) -> Line<'static> {
    Line::from(vec![
        Span::styled(symbol, style),
        Span::raw(" "),
        Span::raw(text),
    ])
}

fn locked_status_line(state: &AppState) -> Line<'static> {
    match state.status_message() {
        Some(message) => Line::from(message.to_owned()).style(Style::new().fg(Color::Yellow)),
        None => Line::from("Ready to unlock.").style(muted_style()),
    }
}

fn status_line(state: &AppState) -> Line<'static> {
    match state.status_message() {
        Some(message) => Line::from(message.to_owned()).style(Style::new().fg(Color::Yellow)),
        None => Line::from(""),
    }
}
