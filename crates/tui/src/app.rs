use bastion_core::{
    AccountRecovery, AccountRecoveryInput, ApiKeyToken, ApiKeyTokenInput, ApiTokenKind,
    PostgreSqlCredential, PostgreSqlCredentialInput, RecoveryMaterialInput, RecoveryMaterialKind,
    Secret, SecretFilter, SecretId, SecretKind, ValidationError, Vault, VaultMutationError,
    VaultPersistenceError, validate_master_passphrase,
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
    ApiTokenKindPicker,
    RecoveryKindPicker,
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
    SelectNextSecretType,
    SelectPreviousSecretType,
    PickDatabaseCredential,
    PickApiToken,
    PickAccountRecovery,
    PickPostgresCredential,
    PickApiKeyToken,
    SelectNextApiTokenKind,
    SelectPreviousApiTokenKind,
    PickApiTokenKind,
    SelectNextRecoveryKind,
    SelectPreviousRecoveryKind,
    PickRecoveryKind,
    CancelPicker,
    StartAddPostgres,
    StartAddApiKeyToken,
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
    AddApiKeyToken {
        token: ApiKeyToken,
        now: DateTime<Utc>,
    },
    EditApiKeyToken {
        secret_id: SecretId,
        token: ApiKeyToken,
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
    RevealSelectedSecretRequested,
    RevealSecretConfirmed {
        now: DateTime<Utc>,
    },
    RevealSecretCancelled,
    RevealExpired {
        now: DateTime<Utc>,
    },
    HelpRequested,
    HelpClosed,
    CommandPaletteRequested,
    CommandPaletteClosed,
    CommandPaletteTextInput {
        text: String,
    },
    CommandPaletteBackspace,
    CommandPaletteClearQuery,
    CommandPaletteNavigate {
        direction: NavigationDirection,
    },
    CommandPaletteRunSelected,
    CommandPaletteChooseNumber(usize),
    SearchRequested,
    SearchTextInput {
        text: String,
    },
    SearchBackspace,
    SearchClearQuery,
    SearchRunSelected,
    SearchChooseNumber(usize),
    SearchCleared,
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
    AddApiKeyToken,
    EditApiKeyToken(SecretId),
    AddAccountRecovery(RecoveryKindChoice),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FormField {
    Title,
    Service,
    Hostname,
    Port,
    Database,
    Account,
    Url,
    Username,
    Password,
    Token,
    RecoveryMaterial,
    Schema,
    Tags,
}

impl FormField {
    fn fields_for_mode(mode: FormMode) -> &'static [Self] {
        match mode {
            FormMode::AddPostgreSqlCredential | FormMode::EditPostgreSqlCredential(_) => &[
                Self::Title,
                Self::Tags,
                Self::Hostname,
                Self::Port,
                Self::Database,
                Self::Schema,
                Self::Username,
                Self::Password,
            ],
            FormMode::AddApiKeyToken | FormMode::EditApiKeyToken(_) => &[
                Self::Title,
                Self::Tags,
                Self::Service,
                Self::Account,
                Self::Url,
                Self::Token,
            ],
            FormMode::AddAccountRecovery(_) => &[
                Self::Title,
                Self::Tags,
                Self::Service,
                Self::Account,
                Self::Url,
                Self::RecoveryMaterial,
            ],
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecretTypeChoice {
    DatabaseCredential,
    ApiToken,
    AccountRecovery,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApiTokenKindChoice {
    PersonalAccessToken,
    ApiKey,
    BearerToken,
    RegistryToken,
    AppPassword,
    WebhookSecret,
    OAuthClientSecret,
    GenericToken,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryKindChoice {
    RecoveryCodeSet,
    RecoveryPhrase,
    RecoveryKey,
    RecoveryFile,
    RecoveryInstructions,
    SecurityQuestions,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecretRef {
    PostgreSqlPassword(SecretId),
    PostgreSqlUsername(SecretId),
    ApiKeyToken(SecretId),
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
    search_active: bool,
    search_query: String,
    search_selected_index: usize,
    secret_type_choice: SecretTypeChoice,
    api_token_kind_choice: ApiTokenKindChoice,
    recovery_kind_choice: RecoveryKindChoice,
    reveal_state: Option<RevealState>,
    command_palette: CommandPaletteState,
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

    pub fn is_search_active(&self) -> bool {
        self.search_active
    }

    pub fn search_query(&self) -> &str {
        &self.search_query
    }

    pub fn secret_type_choice(&self) -> SecretTypeChoice {
        self.secret_type_choice
    }

    pub fn api_token_kind_choice(&self) -> ApiTokenKindChoice {
        self.api_token_kind_choice
    }

    pub fn recovery_kind_choice(&self) -> RecoveryKindChoice {
        self.recovery_kind_choice
    }

    pub fn revealed_secret(&self) -> Option<SecretRef> {
        self.reveal_state.map(|state| state.secret_ref)
    }

    pub fn reveal_expires_at(&self) -> Option<DateTime<Utc>> {
        self.reveal_state.map(|state| state.revealed_until)
    }

    pub fn is_revealed(&self, secret_ref: SecretRef) -> bool {
        self.revealed_secret() == Some(secret_ref)
    }

    pub fn command_palette_query(&self) -> &str {
        &self.command_palette.query
    }

    pub fn selected_command_label(&self) -> Option<&'static str> {
        selected_palette_command(self).map(CommandPaletteCommand::label)
    }

    pub fn command_palette_items(&self) -> Vec<(&'static str, bool)> {
        let selected = selected_palette_command(self);
        filtered_palette_commands(self)
            .into_iter()
            .map(|command| (command.label(), Some(command) == selected))
            .collect()
    }

    pub fn search_palette_title(&self) -> String {
        match &self.selected_filter {
            SelectedFilter::All => "Search Items".to_owned(),
            SelectedFilter::Untagged => "Search Items in Untagged".to_owned(),
            SelectedFilter::Tag(tag) => format!("Search Items in #{tag}"),
        }
    }

    pub fn search_palette_items(&self) -> Vec<(String, bool)> {
        let VaultSession::Unlocked { vault } = &self.session else {
            return Vec::new();
        };
        vault
            .search_visible_secrets(self.selected_filter.as_secret_filter(), &self.search_query)
            .into_iter()
            .enumerate()
            .map(|(index, secret)| {
                let tags = secret
                    .tags()
                    .iter()
                    .map(|tag| format!("#{tag}"))
                    .collect::<Vec<_>>()
                    .join(" ");
                let label = if tags.is_empty() {
                    format!("{} {}", index + 1, secret.title())
                } else {
                    format!("{} {}   {}", index + 1, secret.title(), tags)
                };
                (label, index == self.search_selected_index)
            })
            .collect()
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
            search_active: false,
            search_query: String::new(),
            search_selected_index: 0,
            secret_type_choice: SecretTypeChoice::DatabaseCredential,
            api_token_kind_choice: ApiTokenKindChoice::PersonalAccessToken,
            recovery_kind_choice: RecoveryKindChoice::RecoveryCodeSet,
            reveal_state: None,
            command_palette: CommandPaletteState::default(),
        }
    }
}

#[derive(Debug, Default, Eq, PartialEq)]
struct CommandPaletteState {
    query: String,
    selected_index: usize,
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
    service: String,
    hostname: String,
    port: String,
    database: String,
    account: String,
    url: String,
    username: String,
    password: String,
    api_token_kind: ApiTokenKind,
    token: String,
    recovery_material: String,
    schema: String,
    tags: String,
}

impl PostgresFormValues {
    fn new_for_add(prefilled_tags: String) -> Self {
        Self {
            title: String::new(),
            service: String::new(),
            hostname: String::new(),
            port: "5432".to_owned(),
            database: String::new(),
            account: String::new(),
            url: String::new(),
            username: String::new(),
            password: String::new(),
            api_token_kind: ApiTokenKind::GenericToken,
            token: String::new(),
            recovery_material: String::new(),
            schema: "public".to_owned(),
            tags: prefilled_tags,
        }
    }

    fn new_for_api_key_token_add(prefilled_tags: String) -> Self {
        Self {
            title: String::new(),
            service: String::new(),
            hostname: String::new(),
            port: String::new(),
            database: String::new(),
            account: String::new(),
            url: String::new(),
            username: String::new(),
            password: String::new(),
            api_token_kind: ApiTokenKind::PersonalAccessToken,
            token: String::new(),
            recovery_material: String::new(),
            schema: String::new(),
            tags: prefilled_tags,
        }
    }

    fn new_for_account_recovery_add(prefilled_tags: String) -> Self {
        Self {
            title: String::new(),
            service: String::new(),
            hostname: String::new(),
            port: String::new(),
            database: String::new(),
            account: String::new(),
            url: String::new(),
            username: String::new(),
            password: String::new(),
            api_token_kind: ApiTokenKind::GenericToken,
            token: String::new(),
            recovery_material: String::new(),
            schema: String::new(),
            tags: prefilled_tags,
        }
    }

    fn from_credential(credential: &PostgreSqlCredential) -> Self {
        Self {
            title: credential.title().to_owned(),
            service: String::new(),
            hostname: credential.hostname().to_owned(),
            port: credential.port().to_string(),
            database: credential.database().to_owned(),
            account: String::new(),
            url: String::new(),
            username: credential.username().to_owned(),
            password: credential.password().expose_secret().to_string(),
            api_token_kind: ApiTokenKind::GenericToken,
            token: String::new(),
            recovery_material: String::new(),
            schema: credential.schema().unwrap_or_default().to_owned(),
            tags: credential.tags().join(", "),
        }
    }

    fn from_api_key_token(token: &ApiKeyToken) -> Self {
        Self {
            title: token.title().to_owned(),
            service: token.service().to_owned(),
            hostname: String::new(),
            port: String::new(),
            database: String::new(),
            account: token.account().unwrap_or_default().to_owned(),
            url: token.url().unwrap_or_default().to_owned(),
            username: String::new(),
            password: String::new(),
            api_token_kind: token.kind(),
            token: token.token().expose_secret().to_string(),
            recovery_material: String::new(),
            schema: String::new(),
            tags: token.tags().join(", "),
        }
    }

    fn value(&self, field: FormField) -> &str {
        match field {
            FormField::Title => &self.title,
            FormField::Service => &self.service,
            FormField::Hostname => &self.hostname,
            FormField::Port => &self.port,
            FormField::Database => &self.database,
            FormField::Account => &self.account,
            FormField::Url => &self.url,
            FormField::Username => &self.username,
            FormField::Password => &self.password,
            FormField::Token => &self.token,
            FormField::RecoveryMaterial => &self.recovery_material,
            FormField::Schema => &self.schema,
            FormField::Tags => &self.tags,
        }
    }

    fn set(&mut self, field: FormField, value: String) {
        match field {
            FormField::Title => self.title = value,
            FormField::Service => self.service = value,
            FormField::Hostname => self.hostname = value,
            FormField::Port => self.port = value,
            FormField::Database => self.database = value,
            FormField::Account => self.account = value,
            FormField::Url => self.url = value,
            FormField::Username => self.username = value,
            FormField::Password => self.password = value,
            FormField::Token => self.token = value,
            FormField::RecoveryMaterial => self.recovery_material = value,
            FormField::Schema => self.schema = value,
            FormField::Tags => self.tags = value,
        }
    }

    fn push(&mut self, field: FormField, text: &str) {
        match field {
            FormField::Title => self.title.push_str(text),
            FormField::Service => self.service.push_str(text),
            FormField::Hostname => self.hostname.push_str(text),
            FormField::Port => self.port.push_str(text),
            FormField::Database => self.database.push_str(text),
            FormField::Account => self.account.push_str(text),
            FormField::Url => self.url.push_str(text),
            FormField::Username => self.username.push_str(text),
            FormField::Password => self.password.push_str(text),
            FormField::Token => self.token.push_str(text),
            FormField::RecoveryMaterial => self.recovery_material.push_str(text),
            FormField::Schema => self.schema.push_str(text),
            FormField::Tags => self.tags.push_str(text),
        }
    }

    fn pop(&mut self, field: FormField) -> Option<char> {
        match field {
            FormField::Title => self.title.pop(),
            FormField::Service => self.service.pop(),
            FormField::Hostname => self.hostname.pop(),
            FormField::Port => self.port.pop(),
            FormField::Database => self.database.pop(),
            FormField::Account => self.account.pop(),
            FormField::Url => self.url.pop(),
            FormField::Username => self.username.pop(),
            FormField::Password => self.password.pop(),
            FormField::Token => self.token.pop(),
            FormField::RecoveryMaterial => self.recovery_material.pop(),
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

    fn api_key_token_input(&self) -> ApiKeyTokenInput {
        ApiKeyTokenInput {
            title: self.title.clone(),
            service: self.service.clone(),
            kind: self.api_token_kind,
            token: self.token.clone(),
            account: Some(self.account.clone()),
            url: Some(self.url.clone()),
            tags: parse_tags(&self.tags),
        }
    }

    fn account_recovery_input(&self, kind: RecoveryKindChoice) -> AccountRecoveryInput {
        AccountRecoveryInput {
            title: self.title.clone(),
            service: self.service.clone(),
            account: Some(self.account.clone()),
            url: Some(self.url.clone()),
            kind: recovery_material_kind(kind),
            material: recovery_material_input(kind, self.recovery_material.clone()),
            tags: parse_tags(&self.tags),
        }
    }
}

fn recovery_material_kind(kind: RecoveryKindChoice) -> RecoveryMaterialKind {
    match kind {
        RecoveryKindChoice::RecoveryCodeSet => RecoveryMaterialKind::RecoveryCodeSet,
        RecoveryKindChoice::RecoveryPhrase => RecoveryMaterialKind::RecoveryPhrase,
        RecoveryKindChoice::RecoveryKey => RecoveryMaterialKind::RecoveryKey,
        RecoveryKindChoice::RecoveryFile => RecoveryMaterialKind::RecoveryFile,
        RecoveryKindChoice::RecoveryInstructions => RecoveryMaterialKind::RecoveryInstructions,
        RecoveryKindChoice::SecurityQuestions => RecoveryMaterialKind::SecurityQuestions,
    }
}

fn api_token_kind(kind: ApiTokenKindChoice) -> ApiTokenKind {
    match kind {
        ApiTokenKindChoice::PersonalAccessToken => ApiTokenKind::PersonalAccessToken,
        ApiTokenKindChoice::ApiKey => ApiTokenKind::ApiKey,
        ApiTokenKindChoice::BearerToken => ApiTokenKind::BearerToken,
        ApiTokenKindChoice::RegistryToken => ApiTokenKind::RegistryToken,
        ApiTokenKindChoice::AppPassword => ApiTokenKind::AppPassword,
        ApiTokenKindChoice::WebhookSecret => ApiTokenKind::WebhookSecret,
        ApiTokenKindChoice::OAuthClientSecret => ApiTokenKind::OAuthClientSecret,
        ApiTokenKindChoice::GenericToken => ApiTokenKind::GenericToken,
    }
}

fn recovery_material_input(kind: RecoveryKindChoice, value: String) -> RecoveryMaterialInput {
    match kind {
        RecoveryKindChoice::RecoveryCodeSet => RecoveryMaterialInput::CodeSet(value),
        RecoveryKindChoice::RecoveryPhrase => RecoveryMaterialInput::Phrase(value),
        RecoveryKindChoice::RecoveryKey => RecoveryMaterialInput::Key(value),
        RecoveryKindChoice::RecoveryFile => RecoveryMaterialInput::FileReference {
            file_name: None,
            location: value,
            checksum: None,
        },
        RecoveryKindChoice::RecoveryInstructions => RecoveryMaterialInput::Instructions(value),
        RecoveryKindChoice::SecurityQuestions => {
            RecoveryMaterialInput::SecurityQuestions(vec![bastion_core::SecurityQuestionInput {
                question: "Recovery question".to_owned(),
                answer: value,
            }])
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModalState {
    DeleteSecret(SecretId),
    DiscardChanges,
    QuitWithoutSaving,
    RevealSecret(SecretRef),
    Help,
    CommandPalette,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CommandPaletteCommand {
    AddPostgres,
    AddApiToken,
    AddAccountRecovery,
    EditSelected,
    DeleteSelected,
    FocusItems,
    FocusTags,
    Search,
    SelectAllFilter,
    SelectUntaggedFilter,
    LockVault,
    Help,
    Quit,
    RevealSelected,
    CopyPrimary,
    CopySecondary,
}

impl CommandPaletteCommand {
    const fn label(self) -> &'static str {
        match self {
            Self::AddPostgres => "Add Postgres credentials",
            Self::AddApiToken => "Add API token",
            Self::AddAccountRecovery => "Add account recovery",
            Self::EditSelected => "Edit selected item",
            Self::DeleteSelected => "Delete selected item",
            Self::FocusItems => "Focus Items panel",
            Self::FocusTags => "Focus Tags panel",
            Self::Search => "Search items",
            Self::SelectAllFilter => "Select All filter",
            Self::SelectUntaggedFilter => "Select Untagged filter",
            Self::LockVault => "Lock vault",
            Self::Help => "Help",
            Self::Quit => "Quit",
            Self::RevealSelected => "Reveal selected secret",
            Self::CopyPrimary => "Copy password/token",
            Self::CopySecondary => "Copy username/account",
        }
    }

    const fn aliases(self) -> &'static [&'static str] {
        match self {
            Self::AddPostgres => &["a", "add", "db", "database", "postgres", "pg"],
            Self::AddApiToken => &["a", "add", "api", "token"],
            Self::AddAccountRecovery => &["a", "add", "account", "recovery", "2fa"],
            Self::EditSelected => &["e", "edit"],
            Self::DeleteSelected => &["d", "del", "delete", "remove"],
            Self::FocusItems => &["1", "items"],
            Self::FocusTags => &["2", "tags"],
            Self::Search => &["/", "find", "search"],
            Self::SelectAllFilter => &["all"],
            Self::SelectUntaggedFilter => &["untagged"],
            Self::LockVault => &["l", "lock"],
            Self::Help => &["?", "help"],
            Self::Quit => &["q", "quit"],
            Self::RevealSelected => &["r", "reveal"],
            Self::CopyPrimary => &["c", "copy", "password", "token"],
            Self::CopySecondary => &["u", "copy", "username", "account"],
        }
    }

    fn is_available(self, state: &AppState) -> bool {
        match self {
            Self::EditSelected
            | Self::DeleteSelected
            | Self::RevealSelected
            | Self::CopyPrimary
            | Self::CopySecondary => state.selected_secret.is_some(),
            Self::SelectAllFilter => !matches!(state.selected_filter, SelectedFilter::All),
            Self::SelectUntaggedFilter => {
                !matches!(state.selected_filter, SelectedFilter::Untagged)
            }
            Self::AddPostgres
            | Self::AddApiToken
            | Self::AddAccountRecovery
            | Self::FocusItems
            | Self::FocusTags
            | Self::Search
            | Self::LockVault
            | Self::Help
            | Self::Quit => true,
        }
    }
}

const COMMAND_PALETTE_COMMANDS: &[CommandPaletteCommand] = &[
    CommandPaletteCommand::AddPostgres,
    CommandPaletteCommand::AddApiToken,
    CommandPaletteCommand::AddAccountRecovery,
    CommandPaletteCommand::EditSelected,
    CommandPaletteCommand::DeleteSelected,
    CommandPaletteCommand::FocusItems,
    CommandPaletteCommand::FocusTags,
    CommandPaletteCommand::Search,
    CommandPaletteCommand::SelectAllFilter,
    CommandPaletteCommand::SelectUntaggedFilter,
    CommandPaletteCommand::LockVault,
    CommandPaletteCommand::Help,
    CommandPaletteCommand::Quit,
    CommandPaletteCommand::RevealSelected,
    CommandPaletteCommand::CopyPrimary,
    CommandPaletteCommand::CopySecondary,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RevealState {
    secret_ref: SecretRef,
    revealed_until: DateTime<Utc>,
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
            state.search_active = false;
            state.search_query.clear();
            state.search_selected_index = 0;
            clear_reveal(state);
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
            if state.screen != Screen::Main || state.search_active {
                return Vec::new();
            }
            state.panel_focus = panel;
            Vec::new()
        }
        AppAction::SelectFilter { filter } => {
            if state.screen != Screen::Main || state.search_active {
                return Vec::new();
            }
            state.panel_focus = PanelFocus::Tags;
            state.selected_filter = filter;
            state.selected_secret = first_visible_secret_id(state);
            clear_reveal(state);
            Vec::new()
        }
        AppAction::StartSecretTypePicker => {
            state.screen = Screen::SecretTypePicker;
            state.secret_type_choice = SecretTypeChoice::DatabaseCredential;
            clear_reveal(state);
            Vec::new()
        }
        AppAction::SelectNextSecretType => {
            if state.screen == Screen::SecretTypePicker {
                state.secret_type_choice = next_secret_type_choice(state.secret_type_choice, 1);
            }
            Vec::new()
        }
        AppAction::SelectPreviousSecretType => {
            if state.screen == Screen::SecretTypePicker {
                state.secret_type_choice = next_secret_type_choice(state.secret_type_choice, -1);
            }
            Vec::new()
        }
        AppAction::PickDatabaseCredential | AppAction::PickPostgresCredential => {
            start_add_postgres(state);
            Vec::new()
        }
        AppAction::PickApiToken | AppAction::PickApiKeyToken => {
            state.screen = Screen::ApiTokenKindPicker;
            state.api_token_kind_choice = ApiTokenKindChoice::PersonalAccessToken;
            clear_reveal(state);
            Vec::new()
        }
        AppAction::PickAccountRecovery => {
            state.screen = Screen::RecoveryKindPicker;
            state.recovery_kind_choice = RecoveryKindChoice::RecoveryCodeSet;
            clear_reveal(state);
            Vec::new()
        }
        AppAction::SelectNextApiTokenKind => {
            if state.screen == Screen::ApiTokenKindPicker {
                state.api_token_kind_choice =
                    next_api_token_kind_choice(state.api_token_kind_choice, 1);
            }
            Vec::new()
        }
        AppAction::SelectPreviousApiTokenKind => {
            if state.screen == Screen::ApiTokenKindPicker {
                state.api_token_kind_choice =
                    next_api_token_kind_choice(state.api_token_kind_choice, -1);
            }
            Vec::new()
        }
        AppAction::PickApiTokenKind => {
            if state.screen == Screen::ApiTokenKindPicker {
                start_add_api_key_token(state);
            }
            Vec::new()
        }
        AppAction::SelectNextRecoveryKind => {
            if state.screen == Screen::RecoveryKindPicker {
                state.recovery_kind_choice =
                    next_recovery_kind_choice(state.recovery_kind_choice, 1);
            }
            Vec::new()
        }
        AppAction::SelectPreviousRecoveryKind => {
            if state.screen == Screen::RecoveryKindPicker {
                state.recovery_kind_choice =
                    next_recovery_kind_choice(state.recovery_kind_choice, -1);
            }
            Vec::new()
        }
        AppAction::PickRecoveryKind => {
            if state.screen == Screen::RecoveryKindPicker {
                start_add_account_recovery(state, state.recovery_kind_choice);
            }
            Vec::new()
        }
        AppAction::CancelPicker => {
            state.screen = match state.screen {
                Screen::ApiTokenKindPicker | Screen::RecoveryKindPicker => Screen::SecretTypePicker,
                _ => Screen::Main,
            };
            Vec::new()
        }
        AppAction::StartAddPostgres => {
            clear_reveal(state);
            start_add_postgres(state);
            Vec::new()
        }
        AppAction::StartAddApiKeyToken => {
            clear_reveal(state);
            start_add_api_key_token(state);
            Vec::new()
        }
        AppAction::StartEditPostgres { secret_id } => {
            clear_reveal(state);
            if let Some((mode, values)) = form_values_for_secret(state, secret_id) {
                state.screen = Screen::Form;
                state.form = Some(FormState {
                    mode,
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
        AppAction::AddApiKeyToken { token, now } => {
            let Some(vault) = unlocked_vault_mut(state) else {
                return Vec::new();
            };
            let secret = Secret::new_api_key_token(token, now);
            let secret_id = secret.id();
            vault.add_secret(secret, now);
            state.screen = Screen::Main;
            state.form = None;
            state.selected_secret = Some(secret_id);
            state.dirty_vault = true;
            vec![Effect::SaveVault]
        }
        AppAction::EditApiKeyToken {
            secret_id,
            token,
            now,
        } => match replace_api_key_token(state, secret_id, token, now) {
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
            clear_reveal(state);
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
            match primary_secret_ref(state, secret_id) {
                Some((field, secret_ref)) => {
                    set_copy_status(state, secret_id, field);
                    vec![Effect::CopySecretToClipboard(secret_ref)]
                }
                None => Vec::new(),
            }
        }
        AppAction::CopyUsernameRequested { secret_id } => {
            match secondary_copy_value(state, secret_id) {
                Some((field, value)) => {
                    set_copy_status(state, secret_id, field);
                    vec![Effect::CopyTextToClipboard(value)]
                }
                None => Vec::new(),
            }
        }
        AppAction::CopySelectedPasswordRequested => match state.selected_secret {
            Some(secret_id) => match primary_secret_ref(state, secret_id) {
                Some((field, secret_ref)) => {
                    set_copy_status(state, secret_id, field);
                    vec![Effect::CopySecretToClipboard(secret_ref)]
                }
                None => Vec::new(),
            },
            None => Vec::new(),
        },
        AppAction::CopySelectedUsernameRequested => match state.selected_secret {
            Some(secret_id) => match secondary_copy_value(state, secret_id) {
                Some((field, value)) => {
                    set_copy_status(state, secret_id, field);
                    vec![Effect::CopyTextToClipboard(value)]
                }
                None => {
                    state.status_message = Some("No account value for selected item.".to_owned());
                    Vec::new()
                }
            },
            None => Vec::new(),
        },
        AppAction::RevealSelectedSecretRequested => {
            if state.screen != Screen::Main {
                return Vec::new();
            }
            match state
                .selected_secret
                .and_then(|secret_id| primary_secret_ref(state, secret_id))
            {
                Some((_, secret_ref)) => {
                    state.screen = Screen::Modal;
                    state.modal = Some(ModalState::RevealSecret(secret_ref));
                }
                None => state.status_message = Some("No revealable secret selected.".to_owned()),
            }
            Vec::new()
        }
        AppAction::RevealSecretConfirmed { now } => {
            if let Some(ModalState::RevealSecret(secret_ref)) = state.modal {
                state.reveal_state = Some(RevealState {
                    secret_ref,
                    revealed_until: now + chrono::Duration::seconds(10),
                });
                state.screen = Screen::Main;
                state.modal = None;
                state.status_message = Some("Secret revealed for 10 seconds.".to_owned());
            }
            Vec::new()
        }
        AppAction::RevealSecretCancelled => {
            state.screen = Screen::Main;
            state.modal = None;
            Vec::new()
        }
        AppAction::RevealExpired { now } => {
            if state
                .reveal_state
                .is_some_and(|reveal| now >= reveal.revealed_until)
            {
                clear_reveal(state);
            }
            Vec::new()
        }
        AppAction::HelpRequested => {
            if !matches!(
                state.screen,
                Screen::Main | Screen::Form | Screen::SecretTypePicker | Screen::Modal
            ) {
                return Vec::new();
            }
            state.screen = Screen::Modal;
            state.modal = Some(ModalState::Help);
            Vec::new()
        }
        AppAction::HelpClosed => {
            state.modal = None;
            state.screen = if state.form.is_some() {
                Screen::Form
            } else {
                Screen::Main
            };
            Vec::new()
        }
        AppAction::CommandPaletteRequested => {
            if state.screen != Screen::Main || state.is_search_active() {
                return Vec::new();
            }
            state.screen = Screen::Modal;
            state.modal = Some(ModalState::CommandPalette);
            state.command_palette = CommandPaletteState::default();
            Vec::new()
        }
        AppAction::CommandPaletteClosed => {
            if state.modal == Some(ModalState::CommandPalette) {
                state.screen = Screen::Main;
                state.modal = None;
            }
            Vec::new()
        }
        AppAction::CommandPaletteTextInput { text } => {
            if state.modal == Some(ModalState::CommandPalette) {
                state.command_palette.query.push_str(&text);
                state.command_palette.selected_index = 0;
            }
            Vec::new()
        }
        AppAction::CommandPaletteBackspace => {
            if state.modal == Some(ModalState::CommandPalette) {
                state.command_palette.query.pop();
                state.command_palette.selected_index = 0;
            }
            Vec::new()
        }
        AppAction::CommandPaletteClearQuery => {
            if state.modal == Some(ModalState::CommandPalette) {
                state.command_palette.query.clear();
                state.command_palette.selected_index = 0;
            }
            Vec::new()
        }
        AppAction::CommandPaletteNavigate { direction } => {
            if state.modal != Some(ModalState::CommandPalette) {
                return Vec::new();
            }
            let len = filtered_palette_commands(state).len();
            if len == 0 {
                state.command_palette.selected_index = 0;
            } else {
                let current = state.command_palette.selected_index.min(len - 1);
                state.command_palette.selected_index = next_index(current, len, direction);
            }
            Vec::new()
        }
        AppAction::CommandPaletteRunSelected => run_selected_palette_command(state),
        AppAction::CommandPaletteChooseNumber(index) => {
            if state.modal != Some(ModalState::CommandPalette) {
                return Vec::new();
            }
            run_palette_command_at(state, index)
        }
        AppAction::SearchRequested => {
            if state.screen != Screen::Main {
                return Vec::new();
            }
            clear_reveal(state);
            state.search_active = true;
            state.search_selected_index = 0;
            state.panel_focus = PanelFocus::Items;
            state.status_message = None;
            state.selected_secret = first_visible_secret_id(state);
            Vec::new()
        }
        AppAction::SearchTextInput { text } => {
            if state.screen != Screen::Main || !state.search_active {
                return Vec::new();
            }
            state.search_query.push_str(&text);
            state.search_selected_index = 0;
            state.status_message = None;
            clear_reveal(state);
            Vec::new()
        }
        AppAction::SearchBackspace => {
            if state.screen != Screen::Main || !state.search_active {
                return Vec::new();
            }
            state.search_query.pop();
            state.search_selected_index = 0;
            clear_reveal(state);
            Vec::new()
        }
        AppAction::SearchClearQuery => {
            if state.screen != Screen::Main || !state.search_active {
                return Vec::new();
            }
            state.search_query.clear();
            state.search_selected_index = 0;
            clear_reveal(state);
            Vec::new()
        }
        AppAction::SearchRunSelected => {
            if state.screen != Screen::Main || !state.search_active {
                return Vec::new();
            }
            if let Some(secret_id) = search_result_id(state, state.search_selected_index) {
                state.selected_secret = Some(secret_id);
                state.panel_focus = PanelFocus::Items;
            }
            state.search_active = false;
            state.search_query.clear();
            state.search_selected_index = 0;
            clear_reveal_if_not_selected(state);
            Vec::new()
        }
        AppAction::SearchChooseNumber(index) => {
            if state.screen != Screen::Main || !state.search_active {
                return Vec::new();
            }
            if let Some(secret_id) = search_result_id(state, index) {
                state.selected_secret = Some(secret_id);
                state.panel_focus = PanelFocus::Items;
                state.search_active = false;
                state.search_query.clear();
                state.search_selected_index = 0;
                clear_reveal_if_not_selected(state);
            }
            Vec::new()
        }
        AppAction::SearchCleared => {
            if state.screen != Screen::Main || !state.search_active {
                return Vec::new();
            }
            state.search_active = false;
            state.search_query.clear();
            state.search_selected_index = 0;
            state.status_message = None;
            clear_reveal(state);
            Vec::new()
        }
        AppAction::Navigate { direction } => {
            if state.screen != Screen::Main {
                return Vec::new();
            }
            if state.search_active {
                move_search_result(state, direction);
            } else {
                match state.panel_focus {
                    PanelFocus::Items => move_selected_secret(state, direction),
                    PanelFocus::Tags => move_selected_filter(state, direction),
                }
            }
            clear_reveal_if_not_selected(state);
            Vec::new()
        }
    }
}

fn filtered_palette_commands(state: &AppState) -> Vec<CommandPaletteCommand> {
    let query = state.command_palette.query.trim().to_lowercase();
    COMMAND_PALETTE_COMMANDS
        .iter()
        .copied()
        .filter(|command| command.is_available(state))
        .filter(|command| command_matches_query(*command, &query))
        .collect()
}

fn next_secret_type_choice(current: SecretTypeChoice, offset: isize) -> SecretTypeChoice {
    const CHOICES: &[SecretTypeChoice] = &[
        SecretTypeChoice::DatabaseCredential,
        SecretTypeChoice::ApiToken,
        SecretTypeChoice::AccountRecovery,
    ];
    CHOICES[next_choice_index(CHOICES, current, offset)]
}

fn next_api_token_kind_choice(current: ApiTokenKindChoice, offset: isize) -> ApiTokenKindChoice {
    const CHOICES: &[ApiTokenKindChoice] = &[
        ApiTokenKindChoice::PersonalAccessToken,
        ApiTokenKindChoice::ApiKey,
        ApiTokenKindChoice::BearerToken,
        ApiTokenKindChoice::RegistryToken,
        ApiTokenKindChoice::AppPassword,
        ApiTokenKindChoice::WebhookSecret,
        ApiTokenKindChoice::OAuthClientSecret,
        ApiTokenKindChoice::GenericToken,
    ];
    CHOICES[next_choice_index(CHOICES, current, offset)]
}

fn next_recovery_kind_choice(current: RecoveryKindChoice, offset: isize) -> RecoveryKindChoice {
    const CHOICES: &[RecoveryKindChoice] = &[
        RecoveryKindChoice::RecoveryCodeSet,
        RecoveryKindChoice::RecoveryPhrase,
        RecoveryKindChoice::RecoveryKey,
        RecoveryKindChoice::RecoveryFile,
        RecoveryKindChoice::RecoveryInstructions,
        RecoveryKindChoice::SecurityQuestions,
    ];
    CHOICES[next_choice_index(CHOICES, current, offset)]
}

fn next_choice_index<T: Copy + Eq>(choices: &[T], current: T, offset: isize) -> usize {
    let current = choices
        .iter()
        .position(|choice| *choice == current)
        .unwrap_or(0);
    (current as isize + offset).rem_euclid(choices.len() as isize) as usize
}

fn selected_palette_command(state: &AppState) -> Option<CommandPaletteCommand> {
    palette_command_at(state, state.command_palette.selected_index)
}

fn run_selected_palette_command(state: &mut AppState) -> Vec<Effect> {
    run_palette_command_at(state, state.command_palette.selected_index)
}

fn command_matches_query(command: CommandPaletteCommand, query: &str) -> bool {
    if query.is_empty() {
        return true;
    }

    if query.chars().count() == 1 {
        return command.aliases().iter().any(|alias| *alias == query);
    }

    command.label().to_lowercase().contains(query)
        || command.aliases().iter().any(|alias| alias.contains(query))
}

fn palette_command_at(state: &AppState, index: usize) -> Option<CommandPaletteCommand> {
    filtered_palette_commands(state).get(index).copied()
}

fn run_palette_command_at(state: &mut AppState, index: usize) -> Vec<Effect> {
    let Some(command) = palette_command_at(state, index) else {
        return Vec::new();
    };

    state.screen = Screen::Main;
    state.modal = None;

    match command {
        CommandPaletteCommand::AddPostgres => {
            clear_reveal(state);
            start_add_postgres(state);
            Vec::new()
        }
        CommandPaletteCommand::AddApiToken => {
            clear_reveal(state);
            state.screen = Screen::ApiTokenKindPicker;
            state.api_token_kind_choice = ApiTokenKindChoice::PersonalAccessToken;
            Vec::new()
        }
        CommandPaletteCommand::AddAccountRecovery => {
            clear_reveal(state);
            state.screen = Screen::RecoveryKindPicker;
            state.recovery_kind_choice = RecoveryKindChoice::RecoveryCodeSet;
            Vec::new()
        }
        CommandPaletteCommand::EditSelected => {
            clear_reveal(state);
            if let Some(secret_id) = state.selected_secret
                && let Some((mode, values)) = form_values_for_secret(state, secret_id)
            {
                state.screen = Screen::Form;
                state.form = Some(FormState {
                    mode,
                    dirty: false,
                    values,
                    focused_field: FormField::Title,
                    validation_error: None,
                });
            }
            Vec::new()
        }
        CommandPaletteCommand::DeleteSelected => {
            clear_reveal(state);
            if let Some(secret_id) = state.selected_secret {
                state.screen = Screen::Modal;
                state.modal = Some(ModalState::DeleteSecret(secret_id));
            }
            Vec::new()
        }
        CommandPaletteCommand::FocusItems => {
            state.panel_focus = PanelFocus::Items;
            Vec::new()
        }
        CommandPaletteCommand::FocusTags => {
            state.panel_focus = PanelFocus::Tags;
            Vec::new()
        }
        CommandPaletteCommand::Search => {
            clear_reveal(state);
            state.search_active = true;
            state.search_selected_index = 0;
            state.panel_focus = PanelFocus::Items;
            state.status_message = None;
            state.selected_secret = first_visible_secret_id(state);
            Vec::new()
        }
        CommandPaletteCommand::SelectAllFilter => {
            state.panel_focus = PanelFocus::Tags;
            state.selected_filter = SelectedFilter::All;
            state.selected_secret = first_visible_secret_id(state);
            Vec::new()
        }
        CommandPaletteCommand::SelectUntaggedFilter => {
            state.panel_focus = PanelFocus::Tags;
            state.selected_filter = SelectedFilter::Untagged;
            state.selected_secret = first_visible_secret_id(state);
            Vec::new()
        }
        CommandPaletteCommand::Help => {
            state.screen = Screen::Modal;
            state.modal = Some(ModalState::Help);
            Vec::new()
        }
        CommandPaletteCommand::LockVault => {
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
            state.search_active = false;
            state.search_query.clear();
            state.search_selected_index = 0;
            clear_reveal(state);
            vec![Effect::ClearClipboard]
        }
        CommandPaletteCommand::Quit => {
            if state.dirty_vault {
                state.pending_quit_after_save = true;
                vec![Effect::SaveVault]
            } else {
                vec![Effect::Quit]
            }
        }
        CommandPaletteCommand::RevealSelected => request_reveal_selected(state),
        CommandPaletteCommand::CopyPrimary => copy_selected_primary(state),
        CommandPaletteCommand::CopySecondary => copy_selected_secondary(state),
    }
}

fn request_reveal_selected(state: &mut AppState) -> Vec<Effect> {
    match state
        .selected_secret
        .and_then(|secret_id| primary_secret_ref(state, secret_id))
    {
        Some((_, secret_ref)) => {
            state.screen = Screen::Modal;
            state.modal = Some(ModalState::RevealSecret(secret_ref));
        }
        None => state.status_message = Some("No revealable secret selected.".to_owned()),
    }
    Vec::new()
}

fn copy_selected_primary(state: &mut AppState) -> Vec<Effect> {
    match state.selected_secret {
        Some(secret_id) => match primary_secret_ref(state, secret_id) {
            Some((field, secret_ref)) => {
                set_copy_status(state, secret_id, field);
                vec![Effect::CopySecretToClipboard(secret_ref)]
            }
            None => Vec::new(),
        },
        None => Vec::new(),
    }
}

fn copy_selected_secondary(state: &mut AppState) -> Vec<Effect> {
    match state.selected_secret {
        Some(secret_id) => match secondary_copy_value(state, secret_id) {
            Some((field, value)) => {
                set_copy_status(state, secret_id, field);
                vec![Effect::CopyTextToClipboard(value)]
            }
            None => {
                state.status_message = Some("No account value for selected item.".to_owned());
                Vec::new()
            }
        },
        None => Vec::new(),
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
    state.search_active = false;
    state.search_query.clear();
    state.search_selected_index = 0;
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

fn search_result_id(state: &AppState, index: usize) -> Option<SecretId> {
    match &state.session {
        VaultSession::Locked => None,
        VaultSession::Unlocked { vault } => vault
            .search_visible_secrets(
                state.selected_filter.as_secret_filter(),
                &state.search_query,
            )
            .get(index)
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

fn replace_api_key_token(
    state: &mut AppState,
    secret_id: SecretId,
    token: ApiKeyToken,
    now: DateTime<Utc>,
) -> Result<(), VaultMutationError> {
    let Some(vault) = unlocked_vault_mut(state) else {
        return Err(VaultMutationError::SecretNotFound);
    };
    vault.replace_api_key_token_secret(secret_id, token, now)
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

fn start_add_api_key_token(state: &mut AppState) {
    let mut values = PostgresFormValues::new_for_api_key_token_add(prefill_tags(state));
    values.api_token_kind = api_token_kind(state.api_token_kind_choice);
    state.screen = Screen::Form;
    state.form = Some(FormState {
        mode: FormMode::AddApiKeyToken,
        dirty: false,
        values,
        focused_field: FormField::Title,
        validation_error: None,
    });
}

fn start_add_account_recovery(state: &mut AppState, kind: RecoveryKindChoice) {
    state.screen = Screen::Form;
    state.form = Some(FormState {
        mode: FormMode::AddAccountRecovery(kind),
        dirty: false,
        values: PostgresFormValues::new_for_account_recovery_add(prefill_tags(state)),
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

fn form_values_for_secret(
    state: &AppState,
    secret_id: SecretId,
) -> Option<(FormMode, PostgresFormValues)> {
    let VaultSession::Unlocked { vault } = &state.session else {
        return None;
    };
    let secret = vault
        .secrets()
        .iter()
        .find(|secret| secret.id() == secret_id)?;
    match secret.kind() {
        SecretKind::PostgreSqlCredential(credential) => Some((
            FormMode::EditPostgreSqlCredential(secret_id),
            PostgresFormValues::from_credential(credential),
        )),
        SecretKind::ApiKeyToken(token) => Some((
            FormMode::EditApiKeyToken(secret_id),
            PostgresFormValues::from_api_key_token(token),
        )),
        SecretKind::AccountRecovery(_) => None,
    }
}

fn primary_secret_ref(state: &AppState, secret_id: SecretId) -> Option<(&'static str, SecretRef)> {
    let VaultSession::Unlocked { vault } = &state.session else {
        return None;
    };
    let secret = vault
        .secrets()
        .iter()
        .find(|secret| secret.id() == secret_id)?;
    match secret.kind() {
        SecretKind::PostgreSqlCredential(_) => {
            Some(("password", SecretRef::PostgreSqlPassword(secret_id)))
        }
        SecretKind::ApiKeyToken(_) => Some(("token", SecretRef::ApiKeyToken(secret_id))),
        SecretKind::AccountRecovery(_) => None,
    }
}

fn secondary_copy_value(state: &AppState, secret_id: SecretId) -> Option<(&'static str, String)> {
    let VaultSession::Unlocked { vault } = &state.session else {
        return None;
    };
    let secret = vault
        .secrets()
        .iter()
        .find(|secret| secret.id() == secret_id)?;
    match secret.kind() {
        SecretKind::PostgreSqlCredential(credential) => {
            Some(("username", credential.username().to_owned()))
        }
        SecretKind::ApiKeyToken(token) => token
            .account()
            .map(|account| ("account", account.to_owned())),
        SecretKind::AccountRecovery(_) => None,
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
        SecretKind::ApiKeyToken(token) => Some(token.title().to_owned()),
        SecretKind::AccountRecovery(item) => Some(item.title().to_owned()),
    }
}

fn set_copy_status(state: &mut AppState, secret_id: SecretId, field: &str) {
    if let Some(title) = title_for_secret(state, secret_id) {
        state.status_message = Some(format!("Copied {field} for {title}."));
    }
}

fn clear_reveal(state: &mut AppState) {
    state.reveal_state = None;
}

fn clear_reveal_if_not_selected(state: &mut AppState) {
    let Some(revealed) = state.revealed_secret() else {
        return;
    };
    let revealed_secret_id = match revealed {
        SecretRef::PostgreSqlPassword(secret_id)
        | SecretRef::PostgreSqlUsername(secret_id)
        | SecretRef::ApiKeyToken(secret_id) => secret_id,
    };
    if Some(revealed_secret_id) != state.selected_secret {
        clear_reveal(state);
    }
}

fn move_form_focus(state: &mut AppState, offset: isize) {
    let Some(form) = &mut state.form else {
        return;
    };
    let fields = FormField::fields_for_mode(form.mode);
    let current = fields
        .iter()
        .position(|field| *field == form.focused_field)
        .unwrap_or(0);
    let len = fields.len() as isize;
    let next = (current as isize + offset).rem_euclid(len) as usize;
    form.focused_field = fields[next];
}

fn save_form(state: &mut AppState, now: DateTime<Utc>) -> Vec<Effect> {
    let Some(form) = &mut state.form else {
        return Vec::new();
    };

    match form.mode {
        FormMode::AddPostgreSqlCredential => {
            let Some(credential) = postgres_credential_from_form(form) else {
                return Vec::new();
            };
            let Some(vault) = unlocked_vault_mut(state) else {
                return Vec::new();
            };
            let secret = Secret::new_postgres(credential, now);
            let secret_id = secret.id();
            vault.add_secret(secret, now);
            state.selected_secret = Some(secret_id);
        }
        FormMode::EditPostgreSqlCredential(secret_id) => {
            let Some(credential) = postgres_credential_from_form(form) else {
                return Vec::new();
            };
            if replace_postgres(state, secret_id, credential, now).is_err() {
                return Vec::new();
            }
            state.selected_secret = Some(secret_id);
        }
        FormMode::AddApiKeyToken => {
            let Some(token) = api_key_token_from_form(form) else {
                return Vec::new();
            };
            let Some(vault) = unlocked_vault_mut(state) else {
                return Vec::new();
            };
            let secret = Secret::new_api_key_token(token, now);
            let secret_id = secret.id();
            vault.add_secret(secret, now);
            state.selected_secret = Some(secret_id);
        }
        FormMode::EditApiKeyToken(secret_id) => {
            let Some(token) = api_key_token_from_form(form) else {
                return Vec::new();
            };
            if replace_api_key_token(state, secret_id, token, now).is_err() {
                return Vec::new();
            }
            state.selected_secret = Some(secret_id);
        }
        FormMode::AddAccountRecovery(kind) => {
            let Some(item) = account_recovery_from_form(form, kind) else {
                return Vec::new();
            };
            let Some(vault) = unlocked_vault_mut(state) else {
                return Vec::new();
            };
            let secret = Secret::new_account_recovery(item, now);
            let secret_id = secret.id();
            vault.add_secret(secret, now);
            state.selected_secret = Some(secret_id);
        }
    }

    state.screen = Screen::Main;
    state.form = None;
    state.modal = None;
    state.dirty_vault = true;
    vec![Effect::SaveVault]
}

fn postgres_credential_from_form(form: &mut FormState) -> Option<PostgreSqlCredential> {
    let input = match form.values.credential_input() {
        Ok(input) => input,
        Err(error) => {
            form.focused_field = error.field;
            form.validation_error = Some(error);
            return None;
        }
    };

    match PostgreSqlCredential::new(input) {
        Ok(credential) => Some(credential),
        Err(error) => {
            let field = field_for_validation_error(&error);
            form.focused_field = field;
            form.validation_error = Some(FormValidationError {
                field,
                message: safe_validation_message(error).to_owned(),
            });
            None
        }
    }
}

fn api_key_token_from_form(form: &mut FormState) -> Option<ApiKeyToken> {
    match ApiKeyToken::new(form.values.api_key_token_input()) {
        Ok(token) => Some(token),
        Err(error) => {
            let field = field_for_validation_error(&error);
            form.focused_field = field;
            form.validation_error = Some(FormValidationError {
                field,
                message: safe_validation_message(error).to_owned(),
            });
            None
        }
    }
}

fn account_recovery_from_form(
    form: &mut FormState,
    kind: RecoveryKindChoice,
) -> Option<AccountRecovery> {
    match AccountRecovery::new(form.values.account_recovery_input(kind)) {
        Ok(item) => Some(item),
        Err(error) => {
            let field = field_for_validation_error(&error);
            form.focused_field = field;
            form.validation_error = Some(FormValidationError {
                field,
                message: safe_validation_message(error).to_owned(),
            });
            None
        }
    }
}

fn field_for_validation_error(error: &ValidationError) -> FormField {
    match error {
        ValidationError::MissingRequiredField("title") => FormField::Title,
        ValidationError::MissingRequiredField("hostname") => FormField::Hostname,
        ValidationError::MissingRequiredField("database") => FormField::Database,
        ValidationError::MissingRequiredField("username") => FormField::Username,
        ValidationError::MissingRequiredField("password") => FormField::Password,
        ValidationError::MissingRequiredField("service") => FormField::Service,
        ValidationError::MissingRequiredField("token") => FormField::Token,
        ValidationError::MissingRequiredField("recovery codes")
        | ValidationError::MissingRequiredField("recovery phrase")
        | ValidationError::MissingRequiredField("recovery key")
        | ValidationError::MissingRequiredField("recovery file location")
        | ValidationError::MissingRequiredField("recovery instructions")
        | ValidationError::MissingRequiredField("security question")
        | ValidationError::MissingRequiredField("security answer") => FormField::RecoveryMaterial,
        ValidationError::InvalidPort => FormField::Port,
        ValidationError::InvalidTag => FormField::Tags,
        ValidationError::InvalidSecretShape => FormField::Title,
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
        ValidationError::InvalidSecretShape => "Secret fields do not match the selected kind.",
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

fn move_search_result(state: &mut AppState, direction: NavigationDirection) {
    let VaultSession::Unlocked { vault } = &state.session else {
        return;
    };
    let visible = vault.search_visible_secrets(
        state.selected_filter.as_secret_filter(),
        &state.search_query,
    );
    if visible.is_empty() {
        state.search_selected_index = 0;
        return;
    }
    let current = state.search_selected_index.min(visible.len() - 1);
    state.search_selected_index = next_index(current, visible.len(), direction);
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
