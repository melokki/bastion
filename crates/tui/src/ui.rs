use crate::{
    AppState, FormField, FormMode, MasterPassphraseField, ModalState, PanelFocus, Screen,
    SelectedFilter, VaultSession,
};
use bastion_core::{Secret, SecretFilter, SecretKind, Vault};
use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap},
};

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
        Screen::Main => render_main(frame, area, state),
        Screen::SecretTypePicker => {
            render_main(frame, area, state);
            render_picker(frame, area);
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
    let search = if state.is_search_active() {
        format!("{}█", state.search_query())
    } else {
        "-".to_owned()
    };
    frame.render_widget(
        Paragraph::new(format!(
            "Vault: {}        Tag: {}        Search: {}",
            vault.name(),
            filter_label(state.selected_filter()),
            search
        ))
        .block(Block::bordered().title("Bastion")),
        area,
    );
}

fn render_items(frame: &mut Frame<'_>, area: Rect, vault: &Vault, state: &AppState) {
    let items =
        vault.search_visible_secrets(secret_filter(state.selected_filter()), state.search_query());
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
        Paragraph::new(secret_lines(secret)).block(panel_block("Details", false)),
        area,
    );
}

fn secret_lines(secret: &Secret) -> Vec<Line<'static>> {
    match secret.kind() {
        SecretKind::PostgreSqlCredential(credential) => {
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
                Line::from("Password  ••••••••••••••••"),
            ]);
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
    if state.is_search_active() && !state.search_query().trim().is_empty() {
        return format!(
            "No results for \"{}\" in {}.",
            state.search_query(),
            filter_label(state.selected_filter())
        );
    }

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
        Screen::Main if state.is_search_active() => {
            shortcut_line(&[("Esc", "clear search"), ("↑/↓", "results")])
        }
        Screen::Main => shortcut_line(&[
            ("a", "add"),
            ("e", "edit"),
            ("d", "delete"),
            ("c", "password"),
            ("u", "username"),
            ("l", "lock"),
            ("q", "quit"),
        ]),
        Screen::Form => shortcut_line(&[
            ("Tab", "next field"),
            ("Shift+Tab", "previous field"),
            ("Ctrl+S", "save"),
            ("Esc", "cancel"),
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

fn render_picker(frame: &mut Frame<'_>, area: Rect) {
    let text = vec![
        Line::from("What do you want to store?"),
        Line::from(""),
        Line::from("› PostgreSQL Credential"),
        Line::from(""),
        shortcut_line(&[("Enter", "select"), ("Esc", "cancel")]),
    ];
    render_popup_paragraph(frame, centered(area, 54, 9), "Add Secret", text);
}

fn render_form(frame: &mut Frame<'_>, area: Rect, state: &AppState) {
    let Some(form) = state.form() else {
        return;
    };
    let focused_field = form.focused_field();
    let text = vec![
        form_mode_line(form.mode(), form.value(FormField::Title), form.is_dirty()),
        Line::from(""),
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
        form_metadata_line(form.mode(), form.is_dirty()),
        Line::from(""),
        shortcut_line(&[
            ("Tab", "next field"),
            ("Shift+Tab", "previous field"),
            ("Ctrl+S", "save"),
            ("Esc", "cancel"),
        ]),
    ];
    render_popup_paragraph(frame, centered(area, 80, 22), "PostgreSQL Credential", text);
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
        None => ("Confirm", Vec::new()),
    };
    render_popup_paragraph(frame, centered(area, 62, 10), title, text);
}

fn render_modal_background(frame: &mut Frame<'_>, area: Rect, state: &AppState) {
    if matches!(state.modal(), Some(ModalState::DiscardChanges)) && state.form().is_some() {
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

fn delete_secret_summary(secret: &Secret) -> Vec<Line<'static>> {
    match secret.kind() {
        SecretKind::PostgreSqlCredential(credential) => vec![
            Line::from(format!("Title     {}", credential.title())),
            Line::from(format!("Hostname  {}", credential.hostname())),
            Line::from(format!("Database  {}", credential.database())),
            Line::from(format!("Username  {}", credential.username())),
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

fn active_window_block(title: &'static str) -> Block<'static> {
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
    title: &'static str,
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
    }
}

fn form_metadata_line(mode: FormMode, dirty: bool) -> Line<'static> {
    match mode {
        FormMode::AddPostgreSqlCredential => Line::from(""),
        FormMode::EditPostgreSqlCredential(_) => {
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
