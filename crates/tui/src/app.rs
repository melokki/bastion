use bastion_core::{
    PostgreSqlCredential, PostgreSqlCredentialInput, Secret, SecretFilter, SecretId, SecretKind,
    ValidationError, Vault, VaultMutationError, VaultPersistenceError, validate_master_passphrase,
};
use chrono::{DateTime, Utc};
use secrecy::ExposeSecret;
use std::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Screen {
    Onboarding,
    Locked,
    Main,
    SecretTypePicker,
    Form,
    Modal,
}

#[derive(Debug)]
pub enum AppAction {
    StartApp {
        vault_exists: bool,
    },
    CreateVaultRequested,
    CreateVaultSucceeded {
        vault: Vault,
    },
    UnlockVaultRequested,
    UnlockSucceeded {
        vault: Vault,
    },
    UnlockFailed {
        error: VaultPersistenceError,
    },
    MasterPassphraseChanged {
        passphrase: String,
        confirmation: String,
    },
    MasterPassphraseTextInput {
        text: String,
    },
    MasterPassphraseBackspace,
    FocusMasterPassphraseField {
        field: MasterPassphraseField,
    },
    LockRequested,
    SaveSucceeded,
    SaveFailed {
        error: VaultPersistenceError,
    },
    QuitRequested,
    QuitAfterSaveSucceeded,
    QuitWithoutSavingConfirmed,
    FocusPanel {
        panel: PanelFocus,
    },
    SelectFilter {
        filter: SelectedFilter,
    },
    StartSecretTypePicker,
    PickPostgresCredential,
    CancelPicker,
    StartAddPostgres,
    StartEditPostgres {
        secret_id: SecretId,
    },
    FormChanged,
    FormFieldChanged {
        field: FormField,
        value: String,
    },
    FormTextInput {
        text: String,
    },
    FormBackspace,
    FormNextField,
    FormPreviousField,
    FormEnterPressed,
    FormSaveRequested {
        now: DateTime<Utc>,
    },
    FormEscapePressed,
    DiscardChangesConfirmed,
    DiscardChangesCancelled,
    DeleteCancelled,
    QuitWithoutSavingCancelled,
    AddPostgresCredential {
        credential: PostgreSqlCredential,
        now: DateTime<Utc>,
    },
    EditPostgresCredential {
        secret_id: SecretId,
        credential: PostgreSqlCredential,
        now: DateTime<Utc>,
    },
    DeleteSecretRequested {
        secret_id: SecretId,
    },
    DeleteSecretConfirmed {
        secret_id: SecretId,
        now: DateTime<Utc>,
    },
    CopyPasswordRequested {
        secret_id: SecretId,
    },
    CopyUsernameRequested {
        secret_id: SecretId,
    },
    CopySelectedPasswordRequested,
    CopySelectedUsernameRequested,
    SearchRequested,
    Navigate {
        direction: NavigationDirection,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PanelFocus {
    Items,
    Tags,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MasterPassphraseField {
    Passphrase,
    Confirmation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NavigationDirection {
    Previous,
    Next,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SelectedFilter {
    All,
    Untagged,
    Tag(String),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FormMode {
    AddPostgreSqlCredential,
    EditPostgreSqlCredential(SecretId),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FormField {
    Title,
    Hostname,
    Port,
    Database,
    Username,
    Password,
    Schema,
    Tags,
}

impl FormField {
    const ALL: [Self; 8] = [
        Self::Title,
        Self::Tags,
        Self::Hostname,
        Self::Port,
        Self::Database,
        Self::Schema,
        Self::Username,
        Self::Password,
    ];
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecretRef {
    PostgreSqlPassword(SecretId),
    PostgreSqlUsername(SecretId),
}

#[derive(Debug)]
pub enum VaultSession {
    Locked,
    Unlocked { vault: Vault },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Effect {
    LoadVault,
    CreateVault,
    SaveVault,
    CopySecretToClipboard(SecretRef),
    CopyTextToClipboard(String),
    ClearClipboard,
    Quit,
}

pub struct AppState {
    screen: Screen,
    session: VaultSession,
    panel_focus: PanelFocus,
    selected_filter: SelectedFilter,
    selected_secret: Option<SecretId>,
    form: Option<FormState>,
    modal: Option<ModalState>,
    status_message: Option<String>,
    dirty_vault: bool,
    pending_quit_after_save: bool,
    master_passphrase_input: String,
    master_passphrase_confirmation: String,
    master_passphrase_field: MasterPassphraseField,
}

impl fmt::Debug for AppState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AppState")
            .field("screen", &self.screen)
            .field(
                "session",
                &match self.session {
                    VaultSession::Locked => "Locked",
                    VaultSession::Unlocked { .. } => "Unlocked { vault: [redacted] }",
                },
            )
            .field("panel_focus", &self.panel_focus)
            .field("selected_filter", &"[redacted]")
            .field("selected_secret", &self.selected_secret)
            .field("form", &self.form.as_ref().map(|_| "[redacted]"))
            .field("modal", &self.modal)
            .field("status_message", &self.status_message)
            .field("dirty_vault", &self.dirty_vault)
            .field("pending_quit_after_save", &self.pending_quit_after_save)
            .finish()
    }
}

impl AppState {
    pub fn screen(&self) -> Screen {
        self.screen
    }

    pub fn session(&self) -> &VaultSession {
        &self.session
    }

    pub fn panel_focus(&self) -> PanelFocus {
        self.panel_focus
    }

    pub fn selected_filter(&self) -> &SelectedFilter {
        &self.selected_filter
    }

    pub fn selected_secret(&self) -> Option<SecretId> {
        self.selected_secret
    }

    pub fn status_message(&self) -> Option<&str> {
        self.status_message.as_deref()
    }

    pub fn form(&self) -> Option<&FormState> {
        self.form.as_ref()
    }

    pub fn modal(&self) -> Option<ModalState> {
        self.modal
    }

    pub fn is_dirty(&self) -> bool {
        self.dirty_vault
    }

    pub fn master_passphrase(&self) -> &str {
        &self.master_passphrase_input
    }

    pub fn unlocked_vault(&self) -> Option<&Vault> {
        match &self.session {
            VaultSession::Locked => None,
            VaultSession::Unlocked { vault } => Some(vault),
        }
    }

    pub fn master_passphrase_field(&self) -> MasterPassphraseField {
        self.master_passphrase_field
    }

    pub fn master_passphrase_mask(&self) -> String {
        mask_secret(&self.master_passphrase_input)
    }

    pub fn master_passphrase_confirmation_mask(&self) -> String {
        mask_secret(&self.master_passphrase_confirmation)
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            screen: Screen::Onboarding,
            session: VaultSession::Locked,
            panel_focus: PanelFocus::Items,
            selected_filter: SelectedFilter::All,
            selected_secret: None,
            form: None,
            modal: None,
            status_message: None,
            dirty_vault: false,
            pending_quit_after_save: false,
            master_passphrase_input: String::new(),
            master_passphrase_confirmation: String::new(),
            master_passphrase_field: MasterPassphraseField::Passphrase,
        }
    }
}

#[derive(Eq, PartialEq)]
pub struct FormState {
    mode: FormMode,
    dirty: bool,
    values: PostgresFormValues,
    focused_field: FormField,
    validation_error: Option<FormValidationError>,
}

impl fmt::Debug for FormState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FormState")
            .field("mode", &self.mode)
            .field("dirty", &self.dirty)
            .field("values", &"[redacted]")
            .field("focused_field", &self.focused_field)
            .field("validation_error", &self.validation_error)
            .finish()
    }
}

impl FormState {
    pub fn mode(&self) -> FormMode {
        self.mode
    }

    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    pub fn value(&self, field: FormField) -> &str {
        self.values.value(field)
    }

    pub fn focused_field(&self) -> Option<FormField> {
        Some(self.focused_field)
    }

    pub fn validation_error(&self) -> Option<&FormValidationError> {
        self.validation_error.as_ref()
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct FormValidationError {
    field: FormField,
    message: String,
}

#[derive(Debug, Eq, PartialEq)]
struct PostgresFormValues {
    title: String,
    hostname: String,
    port: String,
    database: String,
    username: String,
    password: String,
    schema: String,
    tags: String,
}

impl PostgresFormValues {
    fn new_for_add(prefilled_tags: String) -> Self {
        Self {
            title: String::new(),
            hostname: String::new(),
            port: "5432".to_owned(),
            database: String::new(),
            username: String::new(),
            password: String::new(),
            schema: "public".to_owned(),
            tags: prefilled_tags,
        }
    }

    fn from_credential(credential: &PostgreSqlCredential) -> Self {
        Self {
            title: credential.title().to_owned(),
            hostname: credential.hostname().to_owned(),
            port: credential.port().to_string(),
            database: credential.database().to_owned(),
            username: credential.username().to_owned(),
            password: credential.password().expose_secret().to_string(),
            schema: credential.schema().unwrap_or_default().to_owned(),
            tags: credential.tags().join(", "),
        }
    }

    fn value(&self, field: FormField) -> &str {
        match field {
            FormField::Title => &self.title,
            FormField::Hostname => &self.hostname,
            FormField::Port => &self.port,
            FormField::Database => &self.database,
            FormField::Username => &self.username,
            FormField::Password => &self.password,
            FormField::Schema => &self.schema,
            FormField::Tags => &self.tags,
        }
    }

    fn set(&mut self, field: FormField, value: String) {
        match field {
            FormField::Title => self.title = value,
            FormField::Hostname => self.hostname = value,
            FormField::Port => self.port = value,
            FormField::Database => self.database = value,
            FormField::Username => self.username = value,
            FormField::Password => self.password = value,
            FormField::Schema => self.schema = value,
            FormField::Tags => self.tags = value,
        }
    }

    fn push(&mut self, field: FormField, text: &str) {
        match field {
            FormField::Title => self.title.push_str(text),
            FormField::Hostname => self.hostname.push_str(text),
            FormField::Port => self.port.push_str(text),
            FormField::Database => self.database.push_str(text),
            FormField::Username => self.username.push_str(text),
            FormField::Password => self.password.push_str(text),
            FormField::Schema => self.schema.push_str(text),
            FormField::Tags => self.tags.push_str(text),
        }
    }

    fn pop(&mut self, field: FormField) -> Option<char> {
        match field {
            FormField::Title => self.title.pop(),
            FormField::Hostname => self.hostname.pop(),
            FormField::Port => self.port.pop(),
            FormField::Database => self.database.pop(),
            FormField::Username => self.username.pop(),
            FormField::Password => self.password.pop(),
            FormField::Schema => self.schema.pop(),
            FormField::Tags => self.tags.pop(),
        }
    }

    fn credential_input(&self) -> Result<PostgreSqlCredentialInput, FormValidationError> {
        let port = self
            .port
            .trim()
            .parse::<u16>()
            .map_err(|_| FormValidationError {
                field: FormField::Port,
                message: "Port must be between 1 and 65535.".to_owned(),
            })?;

        Ok(PostgreSqlCredentialInput {
            title: self.title.clone(),
            hostname: self.hostname.clone(),
            port,
            database: self.database.clone(),
            username: self.username.clone(),
            password: self.password.clone(),
            schema: Some(self.schema.clone()),
            tags: parse_tags(&self.tags),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModalState {
    DeleteSecret(SecretId),
    DiscardChanges,
    QuitWithoutSaving,
}

pub fn update(state: &mut AppState, action: AppAction) -> Vec<Effect> {
    match action {
        AppAction::StartApp { vault_exists } => {
            state.screen = if vault_exists {
                Screen::Locked
            } else {
                Screen::Onboarding
            };
            state.master_passphrase_field = MasterPassphraseField::Passphrase;
            Vec::new()
        }
        AppAction::CreateVaultRequested => {
            match validate_master_passphrase(
                &state.master_passphrase_input,
                &state.master_passphrase_confirmation,
            ) {
                Ok(()) => {
                    state.status_message = None;
                    vec![Effect::CreateVault]
                }
                Err(error) => {
                    state.status_message = Some(safe_validation_message(error).to_owned());
                    Vec::new()
                }
            }
        }
        AppAction::CreateVaultSucceeded { vault } => {
            unlock_with_vault(state, vault);
            state.dirty_vault = true;
            vec![Effect::SaveVault]
        }
        AppAction::UnlockVaultRequested => vec![Effect::LoadVault],
        AppAction::UnlockSucceeded { vault } => {
            unlock_with_vault(state, vault);
            Vec::new()
        }
        AppAction::UnlockFailed { error } => {
            state.screen = Screen::Locked;
            state.session = VaultSession::Locked;
            state.status_message = Some(error.safe_message().to_owned());
            Vec::new()
        }
        AppAction::MasterPassphraseChanged {
            passphrase,
            confirmation,
        } => {
            state.master_passphrase_input = passphrase;
            state.master_passphrase_confirmation = confirmation;
            Vec::new()
        }
        AppAction::MasterPassphraseTextInput { text } => {
            match state.screen {
                Screen::Onboarding => match state.master_passphrase_field {
                    MasterPassphraseField::Passphrase => {
                        state.master_passphrase_input.push_str(&text)
                    }
                    MasterPassphraseField::Confirmation => {
                        state.master_passphrase_confirmation.push_str(&text)
                    }
                },
                Screen::Locked => state.master_passphrase_input.push_str(&text),
                _ => {}
            }
            state.status_message = None;
            Vec::new()
        }
        AppAction::MasterPassphraseBackspace => {
            match state.screen {
                Screen::Onboarding => match state.master_passphrase_field {
                    MasterPassphraseField::Passphrase => {
                        state.master_passphrase_input.pop();
                    }
                    MasterPassphraseField::Confirmation => {
                        state.master_passphrase_confirmation.pop();
                    }
                },
                Screen::Locked => {
                    state.master_passphrase_input.pop();
                }
                _ => {}
            }
            Vec::new()
        }
        AppAction::FocusMasterPassphraseField { field } => {
            if state.screen == Screen::Onboarding {
                state.master_passphrase_field = field;
            }
            Vec::new()
        }
        AppAction::LockRequested => {
            state.screen = Screen::Locked;
            state.session = VaultSession::Locked;
            state.selected_secret = None;
            state.form = None;
            state.modal = None;
            state.status_message = None;
            state.dirty_vault = false;
            state.pending_quit_after_save = false;
            state.master_passphrase_input.clear();
            state.master_passphrase_confirmation.clear();
            state.master_passphrase_field = MasterPassphraseField::Passphrase;
            vec![Effect::ClearClipboard]
        }
        AppAction::SaveSucceeded => {
            state.dirty_vault = false;
            state.status_message = None;
            Vec::new()
        }
        AppAction::SaveFailed { error } => {
            state.dirty_vault = true;
            state.status_message = Some(error.safe_message().to_owned());
            if state.pending_quit_after_save {
                state.screen = Screen::Modal;
                state.modal = Some(ModalState::QuitWithoutSaving);
            }
            Vec::new()
        }
        AppAction::QuitRequested => {
            if state.screen == Screen::Form {
                return Vec::new();
            }

            if state.dirty_vault {
                state.pending_quit_after_save = true;
                vec![Effect::SaveVault]
            } else {
                vec![Effect::Quit]
            }
        }
        AppAction::QuitAfterSaveSucceeded => {
            state.dirty_vault = false;
            state.pending_quit_after_save = false;
            vec![Effect::Quit]
        }
        AppAction::QuitWithoutSavingConfirmed => {
            state.pending_quit_after_save = false;
            vec![Effect::Quit]
        }
        AppAction::FocusPanel { panel } => {
            state.panel_focus = panel;
            Vec::new()
        }
        AppAction::SelectFilter { filter } => {
            state.panel_focus = PanelFocus::Tags;
            state.selected_filter = filter;
            state.selected_secret = first_visible_secret_id(state);
            Vec::new()
        }
        AppAction::StartSecretTypePicker => {
            state.screen = Screen::SecretTypePicker;
            Vec::new()
        }
        AppAction::PickPostgresCredential => {
            start_add_postgres(state);
            Vec::new()
        }
        AppAction::CancelPicker => {
            state.screen = Screen::Main;
            Vec::new()
        }
        AppAction::StartAddPostgres => {
            start_add_postgres(state);
            Vec::new()
        }
        AppAction::StartEditPostgres { secret_id } => {
            if let Some(values) = postgres_values_for_secret(state, secret_id) {
                state.screen = Screen::Form;
                state.form = Some(FormState {
                    mode: FormMode::EditPostgreSqlCredential(secret_id),
                    dirty: false,
                    values,
                    focused_field: FormField::Title,
                    validation_error: None,
                });
            }
            Vec::new()
        }
        AppAction::FormChanged => {
            if let Some(form) = &mut state.form {
                form.dirty = true;
            }
            Vec::new()
        }
        AppAction::FormFieldChanged { field, value } => {
            if let Some(form) = &mut state.form {
                form.values.set(field, value);
                form.dirty = true;
                form.validation_error = None;
            }
            Vec::new()
        }
        AppAction::FormTextInput { text } => {
            if let Some(form) = &mut state.form {
                form.values.push(form.focused_field, &text);
                form.dirty = true;
                form.validation_error = None;
            }
            Vec::new()
        }
        AppAction::FormBackspace => {
            if let Some(form) = &mut state.form {
                if form.values.pop(form.focused_field).is_some() {
                    form.dirty = true;
                    form.validation_error = None;
                }
            }
            Vec::new()
        }
        AppAction::FormNextField => {
            move_form_focus(state, 1);
            Vec::new()
        }
        AppAction::FormPreviousField => {
            move_form_focus(state, -1);
            Vec::new()
        }
        AppAction::FormEnterPressed => Vec::new(),
        AppAction::FormSaveRequested { now } => save_form(state, now),
        AppAction::FormEscapePressed => {
            if state.form.as_ref().is_some_and(|form| form.dirty) {
                state.screen = Screen::Modal;
                state.modal = Some(ModalState::DiscardChanges);
            } else {
                state.screen = Screen::Main;
                state.form = None;
                state.modal = None;
            }
            Vec::new()
        }
        AppAction::DiscardChangesConfirmed => {
            state.screen = Screen::Main;
            state.form = None;
            state.modal = None;
            Vec::new()
        }
        AppAction::DiscardChangesCancelled => {
            state.screen = Screen::Form;
            state.modal = None;
            Vec::new()
        }
        AppAction::DeleteCancelled => {
            state.screen = Screen::Main;
            state.modal = None;
            Vec::new()
        }
        AppAction::QuitWithoutSavingCancelled => {
            state.screen = Screen::Main;
            state.modal = None;
            state.pending_quit_after_save = false;
            Vec::new()
        }
        AppAction::AddPostgresCredential { credential, now } => {
            let Some(vault) = unlocked_vault_mut(state) else {
                return Vec::new();
            };
            let secret = Secret::new_postgres(credential, now);
            let secret_id = secret.id();
            vault.add_secret(secret, now);
            state.screen = Screen::Main;
            state.form = None;
            state.selected_secret = Some(secret_id);
            state.dirty_vault = true;
            vec![Effect::SaveVault]
        }
        AppAction::EditPostgresCredential {
            secret_id,
            credential,
            now,
        } => match replace_postgres(state, secret_id, credential, now) {
            Ok(()) => {
                state.screen = Screen::Main;
                state.form = None;
                state.selected_secret = Some(secret_id);
                state.dirty_vault = true;
                vec![Effect::SaveVault]
            }
            Err(_) => Vec::new(),
        },
        AppAction::DeleteSecretRequested { secret_id } => {
            state.screen = Screen::Modal;
            state.modal = Some(ModalState::DeleteSecret(secret_id));
            Vec::new()
        }
        AppAction::DeleteSecretConfirmed { secret_id, now } => {
            let Some(vault) = unlocked_vault_mut(state) else {
                return Vec::new();
            };
            if vault.delete_secret(secret_id, now).is_err() {
                return Vec::new();
            }
            state.screen = Screen::Main;
            state.modal = None;
            state.selected_secret = first_visible_secret_id(state);
            state.dirty_vault = true;
            vec![Effect::SaveVault]
        }
        AppAction::CopyPasswordRequested { secret_id } => {
            set_copy_status(state, secret_id, "password");
            vec![Effect::CopySecretToClipboard(
                SecretRef::PostgreSqlPassword(secret_id),
            )]
        }
        AppAction::CopyUsernameRequested { secret_id } => {
            match username_for_secret(state, secret_id) {
                Some(username) => {
                    set_copy_status(state, secret_id, "username");
                    vec![Effect::CopyTextToClipboard(username)]
                }
                None => Vec::new(),
            }
        }
        AppAction::CopySelectedPasswordRequested => match state.selected_secret {
            Some(secret_id) => {
                set_copy_status(state, secret_id, "password");
                vec![Effect::CopySecretToClipboard(
                    SecretRef::PostgreSqlPassword(secret_id),
                )]
            }
            None => Vec::new(),
        },
        AppAction::CopySelectedUsernameRequested => match state.selected_secret {
            Some(secret_id) => match username_for_secret(state, secret_id) {
                Some(username) => {
                    set_copy_status(state, secret_id, "username");
                    vec![Effect::CopyTextToClipboard(username)]
                }
                None => Vec::new(),
            },
            None => Vec::new(),
        },
        AppAction::SearchRequested => {
            state.status_message = Some("Search will be added later.".to_owned());
            Vec::new()
        }
        AppAction::Navigate { direction } => {
            match state.panel_focus {
                PanelFocus::Items => move_selected_secret(state, direction),
                PanelFocus::Tags => move_selected_filter(state, direction),
            }
            Vec::new()
        }
    }
}

fn unlock_with_vault(state: &mut AppState, vault: Vault) {
    state.screen = Screen::Main;
    state.session = VaultSession::Unlocked { vault };
    state.panel_focus = PanelFocus::Items;
    state.selected_filter = SelectedFilter::All;
    state.selected_secret = first_visible_secret_id(state);
    state.status_message = None;
    state.form = None;
    state.modal = None;
    state.pending_quit_after_save = false;
}

fn first_visible_secret_id(state: &AppState) -> Option<SecretId> {
    match &state.session {
        VaultSession::Locked => None,
        VaultSession::Unlocked { vault } => vault
            .visible_secrets(state.selected_filter.as_secret_filter())
            .first()
            .map(|secret| secret.id()),
    }
}

fn unlocked_vault_mut(state: &mut AppState) -> Option<&mut Vault> {
    match &mut state.session {
        VaultSession::Locked => None,
        VaultSession::Unlocked { vault } => Some(vault),
    }
}

fn replace_postgres(
    state: &mut AppState,
    secret_id: SecretId,
    credential: PostgreSqlCredential,
    now: DateTime<Utc>,
) -> Result<(), VaultMutationError> {
    let Some(vault) = unlocked_vault_mut(state) else {
        return Err(VaultMutationError::SecretNotFound);
    };
    vault.replace_postgres_secret(secret_id, credential, now)
}

fn start_add_postgres(state: &mut AppState) {
    state.screen = Screen::Form;
    state.form = Some(FormState {
        mode: FormMode::AddPostgreSqlCredential,
        dirty: false,
        values: PostgresFormValues::new_for_add(prefill_tags(state)),
        focused_field: FormField::Title,
        validation_error: None,
    });
}

fn prefill_tags(state: &AppState) -> String {
    match &state.selected_filter {
        SelectedFilter::Tag(tag) => tag.clone(),
        SelectedFilter::All | SelectedFilter::Untagged => String::new(),
    }
}

fn postgres_values_for_secret(state: &AppState, secret_id: SecretId) -> Option<PostgresFormValues> {
    let VaultSession::Unlocked { vault } = &state.session else {
        return None;
    };
    let secret = vault
        .secrets()
        .iter()
        .find(|secret| secret.id() == secret_id)?;
    match secret.kind() {
        SecretKind::PostgreSqlCredential(credential) => {
            Some(PostgresFormValues::from_credential(credential))
        }
    }
}

fn username_for_secret(state: &AppState, secret_id: SecretId) -> Option<String> {
    let VaultSession::Unlocked { vault } = &state.session else {
        return None;
    };
    let secret = vault
        .secrets()
        .iter()
        .find(|secret| secret.id() == secret_id)?;
    match secret.kind() {
        SecretKind::PostgreSqlCredential(credential) => Some(credential.username().to_owned()),
    }
}

fn title_for_secret(state: &AppState, secret_id: SecretId) -> Option<String> {
    let VaultSession::Unlocked { vault } = &state.session else {
        return None;
    };
    let secret = vault
        .secrets()
        .iter()
        .find(|secret| secret.id() == secret_id)?;
    match secret.kind() {
        SecretKind::PostgreSqlCredential(credential) => Some(credential.title().to_owned()),
    }
}

fn set_copy_status(state: &mut AppState, secret_id: SecretId, field: &str) {
    if let Some(title) = title_for_secret(state, secret_id) {
        state.status_message = Some(format!("Copied {field} for {title}."));
    }
}

fn move_form_focus(state: &mut AppState, offset: isize) {
    let Some(form) = &mut state.form else {
        return;
    };
    let current = FormField::ALL
        .iter()
        .position(|field| *field == form.focused_field)
        .unwrap_or(0);
    let len = FormField::ALL.len() as isize;
    let next = (current as isize + offset).rem_euclid(len) as usize;
    form.focused_field = FormField::ALL[next];
}

fn save_form(state: &mut AppState, now: DateTime<Utc>) -> Vec<Effect> {
    let Some(form) = &mut state.form else {
        return Vec::new();
    };

    let input = match form.values.credential_input() {
        Ok(input) => input,
        Err(error) => {
            form.focused_field = error.field;
            form.validation_error = Some(error);
            return Vec::new();
        }
    };

    let credential = match PostgreSqlCredential::new(input) {
        Ok(credential) => credential,
        Err(error) => {
            let field = field_for_validation_error(&error);
            form.focused_field = field;
            form.validation_error = Some(FormValidationError {
                field,
                message: safe_validation_message(error).to_owned(),
            });
            return Vec::new();
        }
    };

    match form.mode {
        FormMode::AddPostgreSqlCredential => {
            let Some(vault) = unlocked_vault_mut(state) else {
                return Vec::new();
            };
            let secret = Secret::new_postgres(credential, now);
            let secret_id = secret.id();
            vault.add_secret(secret, now);
            state.selected_secret = Some(secret_id);
        }
        FormMode::EditPostgreSqlCredential(secret_id) => {
            if replace_postgres(state, secret_id, credential, now).is_err() {
                return Vec::new();
            }
            state.selected_secret = Some(secret_id);
        }
    }

    state.screen = Screen::Main;
    state.form = None;
    state.modal = None;
    state.dirty_vault = true;
    vec![Effect::SaveVault]
}

fn field_for_validation_error(error: &ValidationError) -> FormField {
    match error {
        ValidationError::MissingRequiredField("title") => FormField::Title,
        ValidationError::MissingRequiredField("hostname") => FormField::Hostname,
        ValidationError::MissingRequiredField("database") => FormField::Database,
        ValidationError::MissingRequiredField("username") => FormField::Username,
        ValidationError::MissingRequiredField("password") => FormField::Password,
        ValidationError::InvalidPort => FormField::Port,
        ValidationError::InvalidTag => FormField::Tags,
        ValidationError::MissingRequiredField(_) => FormField::Title,
        ValidationError::MasterPassphraseTooShort
        | ValidationError::MasterPassphraseConfirmationMismatch => FormField::Password,
    }
}

fn safe_validation_message(error: ValidationError) -> &'static str {
    match error {
        ValidationError::MissingRequiredField(_) => "Required field is missing.",
        ValidationError::InvalidPort => "Port must be between 1 and 65535.",
        ValidationError::InvalidTag => "Tags may contain letters, numbers, '-' and '_'.",
        ValidationError::MasterPassphraseTooShort => "Master passphrase is too short.",
        ValidationError::MasterPassphraseConfirmationMismatch => {
            "Master passphrase confirmation does not match."
        }
    }
}

fn parse_tags(tags: &str) -> Vec<String> {
    tags.split(',')
        .map(str::trim)
        .filter(|tag| !tag.is_empty())
        .map(str::to_owned)
        .collect()
}

fn mask_secret(value: &str) -> String {
    "•".repeat(value.chars().count())
}

impl SelectedFilter {
    fn as_secret_filter(&self) -> SecretFilter<'_> {
        match self {
            Self::All => SecretFilter::All,
            Self::Untagged => SecretFilter::Untagged,
            Self::Tag(tag) => SecretFilter::Tag(tag),
        }
    }
}

fn move_selected_secret(state: &mut AppState, direction: NavigationDirection) {
    let VaultSession::Unlocked { vault } = &state.session else {
        return;
    };
    let visible = vault.visible_secrets(state.selected_filter.as_secret_filter());
    if visible.is_empty() {
        state.selected_secret = None;
        return;
    }
    let current = state
        .selected_secret
        .and_then(|selected| visible.iter().position(|secret| secret.id() == selected))
        .unwrap_or(0);
    let next = next_index(current, visible.len(), direction);
    state.selected_secret = Some(visible[next].id());
}

fn move_selected_filter(state: &mut AppState, direction: NavigationDirection) {
    let VaultSession::Unlocked { vault } = &state.session else {
        return;
    };
    let filters = filters_for_vault(vault);
    let current = filters
        .iter()
        .position(|filter| filter == &state.selected_filter)
        .unwrap_or(0);
    let next = next_index(current, filters.len(), direction);
    state.selected_filter = filters[next].clone();
    state.selected_secret = first_visible_secret_id(state);
}

fn filters_for_vault(vault: &Vault) -> Vec<SelectedFilter> {
    let counts = vault.tag_counts();
    let mut filters = Vec::with_capacity(counts.tags.len() + 2);
    filters.push(SelectedFilter::All);
    filters.extend(counts.tags.keys().cloned().map(SelectedFilter::Tag));
    filters.push(SelectedFilter::Untagged);
    filters
}

fn next_index(current: usize, len: usize, direction: NavigationDirection) -> usize {
    match direction {
        NavigationDirection::Previous => (current + len - 1) % len,
        NavigationDirection::Next => (current + 1) % len,
    }
}
