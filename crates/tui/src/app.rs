use bastion_core::{
    AccountRecovery, AccountRecoveryInput, ApiKeyToken, ApiKeyTokenInput, ApiTokenKind,
    CustomField, CustomFieldInput, DatabaseEngine, PostgreSqlCredential, PostgreSqlCredentialInput,
    RecoveryCodeId, RecoveryCodeStatus, RecoveryMaterialInput, RecoveryMaterialKind,
    RotationMetadata, Secret, SecretFilter, SecretGeneratorConfig, SecretId, SecretKind,
    UpdateInfo, ValidationError, Vault, VaultMutationError, VaultPersistenceError, Version,
    generate_secret, validate_master_passphrase,
};
use chrono::{DateTime, NaiveDate, Utc};
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
    DatabaseEnginePicker,
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
    UpdateAvailable {
        info: UpdateInfo,
    },
    NoUpdateAvailable,
    UpdateCheckFailed {
        message: String,
    },
    UpdateDismissed,
    UpdateSkipped {
        version: Version,
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
    UserActivity {
        now: DateTime<Utc>,
    },
    AutoLockTick {
        now: DateTime<Utc>,
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
    ChooseSecretType(usize),
    PickDatabaseCredential,
    PickApiToken,
    PickAccountRecovery,
    PickPostgresCredential,
    PickApiKeyToken,
    SelectNextApiTokenKind,
    SelectPreviousApiTokenKind,
    ChooseApiTokenKind(usize),
    PickApiTokenKind,
    SelectNextRecoveryKind,
    SelectPreviousRecoveryKind,
    ChooseRecoveryKind(usize),
    PickRecoveryKind,
    SelectNextDatabaseEngine,
    SelectPreviousDatabaseEngine,
    PickDatabaseEngine,
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
    ChooseDatabaseEngine(usize),
    FormBackspace,
    FormNextField,
    FormPreviousField,
    FormEnterPressed,
    GenerateForFocusedField,
    CustomFieldsSelectNext,
    CustomFieldsSelectPrevious,
    CustomFieldsAdd,
    CustomFieldsDeleteSelected,
    CustomFieldsToggleSensitive,
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
    CopyNextUnusedRecoveryCodeRequested {
        secret_id: SecretId,
    },
    MarkRecoveryCodeUsed {
        secret_id: SecretId,
        code_id: RecoveryCodeId,
        now: DateTime<Utc>,
    },
    MarkRecoveryCodeUnused {
        secret_id: SecretId,
        code_id: RecoveryCodeId,
        now: DateTime<Utc>,
    },
    ClipboardClearDue {
        now: DateTime<Utc>,
    },
    ClipboardClearSucceeded {
        copy_id: ClipboardCopyId,
    },
    ClipboardClearSkippedBecauseChanged {
        copy_id: ClipboardCopyId,
    },
    ClipboardClearFailed {
        copy_id: ClipboardCopyId,
    },
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
    Engine,
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
    CustomFields,
    ExpiresAt,
    RotateEveryDays,
    LastRotatedAt,
}

impl FormField {
    fn fields_for_mode(mode: FormMode) -> &'static [Self] {
        match mode {
            FormMode::AddPostgreSqlCredential | FormMode::EditPostgreSqlCredential(_) => &[
                Self::Title,
                Self::Tags,
                Self::Engine,
                Self::Hostname,
                Self::Port,
                Self::Database,
                Self::Schema,
                Self::Username,
                Self::Password,
                Self::CustomFields,
                Self::ExpiresAt,
                Self::RotateEveryDays,
                Self::LastRotatedAt,
            ],
            FormMode::AddApiKeyToken | FormMode::EditApiKeyToken(_) => &[
                Self::Title,
                Self::Tags,
                Self::Service,
                Self::Account,
                Self::Url,
                Self::Token,
                Self::CustomFields,
                Self::ExpiresAt,
                Self::RotateEveryDays,
                Self::LastRotatedAt,
            ],
            FormMode::AddAccountRecovery(_) => &[
                Self::Title,
                Self::Tags,
                Self::Service,
                Self::Account,
                Self::Url,
                Self::RecoveryMaterial,
                Self::CustomFields,
                Self::ExpiresAt,
                Self::RotateEveryDays,
                Self::LastRotatedAt,
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

#[derive(Clone, Copy, Debug)]
pub struct SecretTypeOption {
    pub choice: SecretTypeChoice,
    pub label: &'static str,
    pub description: &'static str,
    pub best_for: &'static str,
    pub examples: &'static str,
}

impl SecretTypeChoice {
    pub const OPTIONS: &'static [SecretTypeOption] = &[
        SecretTypeOption {
            choice: SecretTypeChoice::DatabaseCredential,
            label: "Database Credential",
            description: "Store hostname, port, database, username, and password.",
            best_for: "Database passwords, connection strings, local/dev/stage credentials.",
            examples: "PostgreSQL, MySQL, MariaDB.",
        },
        SecretTypeOption {
            choice: SecretTypeChoice::ApiToken,
            label: "API Token / Access Token",
            description: "Store tokens for APIs, CLIs, automation, registries, and integrations.",
            best_for: "GitHub PATs, registry tokens, API keys, app passwords, webhook secrets.",
            examples: "GitHub PAT, Cloudflare API token, webhook secret.",
        },
        SecretTypeOption {
            choice: SecretTypeChoice::AccountRecovery,
            label: "Account Recovery",
            description: "Store recovery codes, phrases, keys, files, or instructions.",
            best_for: "Backup codes, recovery phrases, recovery keys, and emergency access notes.",
            examples: "GitHub codes, Proton recovery phrase, Tuta recovery code.",
        },
    ];

    pub fn options() -> &'static [SecretTypeOption] {
        Self::OPTIONS
    }

    pub fn option(self) -> &'static SecretTypeOption {
        Self::options()
            .iter()
            .find(|option| option.choice == self)
            .expect("SecretTypeChoice is missing from SecretTypeChoice::OPTIONS")
    }

    pub fn from_index(index: usize) -> Option<Self> {
        Self::options().get(index).map(|option| option.choice)
    }

    pub fn from_number_key(character: char) -> Option<Self> {
        let index = character.to_digit(10)?.checked_sub(1)? as usize;
        Self::from_index(index)
    }

    pub fn next(self) -> Self {
        let options = Self::options();

        let Some(current_index) = options.iter().position(|option| option.choice == self) else {
            return self;
        };

        let next_index = (current_index + 1) % options.len();
        options[next_index].choice
    }

    pub fn previous(self) -> Self {
        let options = Self::options();

        let Some(current_index) = options.iter().position(|option| option.choice == self) else {
            return self;
        };

        let previous_index = if current_index == 0 {
            options.len() - 1
        } else {
            current_index - 1
        };

        options[previous_index].choice
    }
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

#[derive(Clone, Copy, Debug)]
pub struct ApiTokenKindOption {
    pub choice: ApiTokenKindChoice,
    pub label: &'static str,
    pub description: &'static str,
    pub best_for: &'static str,
    pub examples: &'static str,
}

impl ApiTokenKindChoice {
    pub const OPTIONS: &'static [ApiTokenKindOption] = &[
        ApiTokenKindOption {
            choice: ApiTokenKindChoice::PersonalAccessToken,
            label: "Personal Access Token",
            description: "Token for user-owned API or CLI access.",
            best_for: "Developer accounts, source control, command-line tools, and automation.",
            examples: "GitHub PAT, GitLab PAT, Codeberg token.",
        },
        ApiTokenKindOption {
            choice: ApiTokenKindChoice::ApiKey,
            label: "API Key",
            description: "Provider-issued API key for service access.",
            best_for: "Third-party services where the provider gives a single API key.",
            examples: "Stripe, Cloudflare, OpenAI.",
        },
        ApiTokenKindOption {
            choice: ApiTokenKindChoice::BearerToken,
            label: "Bearer Token",
            description: "Generic token used in Authorization headers.",
            best_for: "Tokens pasted exactly as Bearer credentials in HTTP integrations.",
            examples: "Bearer <token>, temporary integration token.",
        },
        ApiTokenKindOption {
            choice: ApiTokenKindChoice::RegistryToken,
            label: "Registry Token",
            description: "Token for package or container registries.",
            best_for: "Publishing, pulling, or automating access to package/container registries.",
            examples: "npm, crates.io, Docker registry.",
        },
        ApiTokenKindOption {
            choice: ApiTokenKindChoice::AppPassword,
            label: "App Password",
            description: "App-specific password for mail, calendar, or sync.",
            best_for: "Services that require per-app passwords instead of your account password.",
            examples: "Gmail app password, iCloud app password.",
        },
        ApiTokenKindOption {
            choice: ApiTokenKindChoice::WebhookSecret,
            label: "Webhook Secret",
            description: "Secret used to verify incoming webhook payloads.",
            best_for: "Signing or verifying callbacks from external systems.",
            examples: "GitHub, Stripe, Slack webhook secret.",
        },
        ApiTokenKindOption {
            choice: ApiTokenKindChoice::OAuthClientSecret,
            label: "OAuth Client Secret",
            description: "Client secret for OAuth applications.",
            best_for: "OAuth applications that also have a client ID and redirect URLs.",
            examples: "OAuth app client secret, social login integration secret.",
        },
        ApiTokenKindOption {
            choice: ApiTokenKindChoice::GenericToken,
            label: "Generic Token",
            description: "Use when no other token kind fits.",
            best_for: "One-off integration secrets or tokens with unclear provider semantics.",
            examples: "Custom integration token, internal service token.",
        },
    ];

    pub fn options() -> &'static [ApiTokenKindOption] {
        Self::OPTIONS
    }

    pub fn option(self) -> &'static ApiTokenKindOption {
        Self::options()
            .iter()
            .find(|option| option.choice == self)
            .expect("ApiTokenKindChoice is missing from ApiTokenKindChoice::OPTIONS")
    }

    pub fn from_index(index: usize) -> Option<Self> {
        Self::options().get(index).map(|option| option.choice)
    }

    pub fn from_number_key(character: char) -> Option<Self> {
        let index = character.to_digit(10)?.checked_sub(1)? as usize;
        Self::from_index(index)
    }

    pub fn next(self) -> Self {
        let options = Self::options();

        let Some(current_index) = options.iter().position(|option| option.choice == self) else {
            return self;
        };

        let next_index = (current_index + 1) % options.len();
        options[next_index].choice
    }

    pub fn previous(self) -> Self {
        let options = Self::options();

        let Some(current_index) = options.iter().position(|option| option.choice == self) else {
            return self;
        };

        let previous_index = if current_index == 0 {
            options.len() - 1
        } else {
            current_index - 1
        };

        options[previous_index].choice
    }
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

#[derive(Clone, Copy, Debug)]
pub struct RecoveryKindOption {
    pub choice: RecoveryKindChoice,
    pub label: &'static str,
    pub description: &'static str,
    pub best_for: &'static str,
    pub examples: &'static str,
}

impl RecoveryKindChoice {
    pub const OPTIONS: &'static [RecoveryKindOption] = &[
        RecoveryKindOption {
            choice: RecoveryKindChoice::RecoveryCodeSet,
            label: "Recovery Code Set",
            description: "Multiple backup codes, usually one code per line.",
            best_for: "Accounts that give several one-time backup codes for 2FA recovery.",
            examples: "GitHub, Google, Microsoft.",
        },
        RecoveryKindOption {
            choice: RecoveryKindChoice::RecoveryPhrase,
            label: "Recovery Phrase",
            description: "A phrase or ordered words used for recovery.",
            best_for: "Recovery phrases where word order matters and all words must be kept together.",
            examples: "Proton recovery phrase, wallet seed phrase.",
        },
        RecoveryKindOption {
            choice: RecoveryKindChoice::RecoveryKey,
            label: "Recovery Key",
            description: "One single recovery code, key, or token.",
            best_for: "Services that issue one long recovery key instead of multiple backup codes.",
            examples: "Tuta recovery code, Apple recovery key.",
        },
        RecoveryKindOption {
            choice: RecoveryKindChoice::RecoveryFile,
            label: "Recovery File",
            description: "A reference to a recovery kit, PDF, or key file.",
            best_for: "Offline files or emergency kits that live outside the vault.",
            examples: "Recovery kit PDF, offline emergency kit.",
        },
        RecoveryKindOption {
            choice: RecoveryKindChoice::RecoveryInstructions,
            label: "Recovery Instructions",
            description: "Manual recovery steps, offline notes, or procedure.",
            best_for: "Human-readable notes about where/how account recovery should be done.",
            examples: "Where recovery papers are stored, emergency access steps.",
        },
        RecoveryKindOption {
            choice: RecoveryKindChoice::SecurityQuestions,
            label: "Security Questions",
            description: "Security questions with secret answers.",
            best_for: "Legacy services that still use question-and-answer recovery.",
            examples: "Bank security questions, old account recovery questions.",
        },
    ];

    pub fn options() -> &'static [RecoveryKindOption] {
        Self::OPTIONS
    }

    pub fn option(self) -> &'static RecoveryKindOption {
        Self::options()
            .iter()
            .find(|option| option.choice == self)
            .expect("RecoveryKindChoice is missing from RecoveryKindChoice::OPTIONS")
    }

    pub fn from_index(index: usize) -> Option<Self> {
        Self::options().get(index).map(|option| option.choice)
    }

    pub fn from_number_key(character: char) -> Option<Self> {
        let index = character.to_digit(10)?.checked_sub(1)? as usize;
        Self::from_index(index)
    }

    pub fn next(self) -> Self {
        let options = Self::options();

        let Some(current_index) = options.iter().position(|option| option.choice == self) else {
            return self;
        };

        let next_index = (current_index + 1) % options.len();
        options[next_index].choice
    }

    pub fn previous(self) -> Self {
        let options = Self::options();

        let Some(current_index) = options.iter().position(|option| option.choice == self) else {
            return self;
        };

        let previous_index = if current_index == 0 {
            options.len() - 1
        } else {
            current_index - 1
        };

        options[previous_index].choice
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecretRef {
    PostgreSqlPassword(SecretId),
    PostgreSqlUsername(SecretId),
    ApiKeyToken(SecretId),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClipboardCopyId(pub u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClipboardCopyKind {
    SafeText,
    SensitiveSecret,
    SensitiveConnectionString,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PendingClipboardClear {
    copy_id: ClipboardCopyId,
    kind: ClipboardCopyKind,
    clear_at: DateTime<Utc>,
}

impl PendingClipboardClear {
    pub fn copy_id(&self) -> ClipboardCopyId {
        self.copy_id
    }

    pub fn kind(&self) -> ClipboardCopyKind {
        self.kind
    }

    pub fn clear_at(&self) -> DateTime<Utc> {
        self.clear_at
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ClipboardState {
    pending_clear: Option<PendingClipboardClear>,
}

impl ClipboardState {
    pub fn pending_clear(&self) -> Option<&PendingClipboardClear> {
        self.pending_clear.as_ref()
    }
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
    CheckForUpdates,
    CopySecretToClipboard {
        copy_id: ClipboardCopyId,
        secret_ref: SecretRef,
        kind: ClipboardCopyKind,
        clear_after_seconds: Option<i64>,
    },
    CopyTextToClipboard {
        copy_id: ClipboardCopyId,
        value: String,
        kind: ClipboardCopyKind,
        clear_after_seconds: Option<i64>,
    },
    ClearClipboard,
    ClearClipboardIfUnchanged {
        copy_id: ClipboardCopyId,
    },
    Quit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AutoLockTimeout {
    OneMinute,
    FiveMinutes,
    FifteenMinutes,
    ThirtyMinutes,
    Never,
}

impl AutoLockTimeout {
    pub const fn default_safe() -> Self {
        Self::FiveMinutes
    }

    fn duration(self) -> Option<chrono::Duration> {
        match self {
            Self::OneMinute => Some(chrono::Duration::minutes(1)),
            Self::FiveMinutes => Some(chrono::Duration::minutes(5)),
            Self::FifteenMinutes => Some(chrono::Duration::minutes(15)),
            Self::ThirtyMinutes => Some(chrono::Duration::minutes(30)),
            Self::Never => None,
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum UpdateState {
    #[default]
    Idle,
    Available(UpdateInfo),
    Skipped(Version),
    Failed(String),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommandPaletteItem {
    pub group: &'static str,
    pub label: &'static str,
    pub description: &'static str,
    pub selected: bool,
    pub available: bool,
    pub unavailable_reason: Option<&'static str>,
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
    last_secret_type_choice: SecretTypeChoice,
    api_token_kind_choice: ApiTokenKindChoice,
    recovery_kind_choice: RecoveryKindChoice,
    database_engine_choice: DatabaseEngine,
    direct_kind_picker_flow: bool,
    reveal_state: Option<RevealState>,
    clipboard_state: ClipboardState,
    update_state: UpdateState,
    next_clipboard_copy_id: u64,
    auto_lock_timeout: AutoLockTimeout,
    last_activity_at: Option<DateTime<Utc>>,
    command_palette: CommandPaletteState,
    recent_commands: Vec<CommandPaletteCommand>,
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

    pub fn form_field_progress(&self) -> Option<(usize, usize)> {
        let form = self.form.as_ref()?;
        let fields = FormField::fields_for_mode(form.mode);
        let current = fields
            .iter()
            .position(|field| *field == form.focused_field)?
            + 1;

        Some((current, fields.len()))
    }

    pub fn master_passphrase(&self) -> &str {
        &self.master_passphrase_input
    }

    pub fn master_passphrase_confirmation(&self) -> &str {
        &self.master_passphrase_confirmation
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

    pub fn last_secret_type_choice(&self) -> SecretTypeChoice {
        self.last_secret_type_choice
    }

    pub fn api_token_kind_choice(&self) -> ApiTokenKindChoice {
        self.api_token_kind_choice
    }

    pub fn recovery_kind_choice(&self) -> RecoveryKindChoice {
        self.recovery_kind_choice
    }

    pub fn database_engine_choice(&self) -> DatabaseEngine {
        self.database_engine_choice
    }

    pub fn revealed_secret(&self) -> Option<SecretRef> {
        self.reveal_state.map(|state| state.secret_ref)
    }

    pub fn clipboard_state(&self) -> &ClipboardState {
        &self.clipboard_state
    }

    pub fn update_state(&self) -> &UpdateState {
        &self.update_state
    }

    pub fn reveal_expires_at(&self) -> Option<DateTime<Utc>> {
        self.reveal_state.map(|state| state.revealed_until)
    }

    pub fn auto_lock_deadline(&self) -> Option<DateTime<Utc>> {
        Some(self.last_activity_at? + self.auto_lock_timeout.duration()?)
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

    pub fn selected_command_description(&self) -> Option<&'static str> {
        selected_palette_command(self).map(CommandPaletteCommand::description)
    }

    pub fn selected_command_unavailable_reason(&self) -> Option<&'static str> {
        selected_palette_command(self).and_then(|command| command.unavailable_reason(self))
    }

    pub fn command_palette_items(&self) -> Vec<CommandPaletteItem> {
        let selected = selected_palette_command(self);
        visible_palette_commands(self)
            .into_iter()
            .map(|(group, command)| CommandPaletteItem {
                group,
                label: command.label(),
                description: command.description(),
                selected: Some(command) == selected,
                available: command.is_available(self),
                unavailable_reason: command.unavailable_reason(self),
            })
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
            last_secret_type_choice: SecretTypeChoice::DatabaseCredential,
            api_token_kind_choice: ApiTokenKindChoice::PersonalAccessToken,
            recovery_kind_choice: RecoveryKindChoice::RecoveryCodeSet,
            database_engine_choice: DatabaseEngine::PostgreSql,
            direct_kind_picker_flow: false,
            reveal_state: None,
            clipboard_state: ClipboardState::default(),
            update_state: UpdateState::default(),
            next_clipboard_copy_id: 1,
            auto_lock_timeout: AutoLockTimeout::default_safe(),
            last_activity_at: None,
            command_palette: CommandPaletteState::default(),
            recent_commands: Vec::new(),
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
    custom_fields_expanded: bool,
    selected_custom_field_index: usize,
    custom_field_focus: CustomFieldFormFocus,
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
            .field("custom_fields_expanded", &self.custom_fields_expanded)
            .field(
                "selected_custom_field_index",
                &self.selected_custom_field_index,
            )
            .field("custom_field_focus", &self.custom_field_focus)
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

    pub fn custom_fields(&self) -> &[CustomFieldFormValue] {
        &self.values.custom_fields
    }

    pub fn custom_fields_expanded(&self) -> bool {
        self.custom_fields_expanded
    }

    pub fn selected_custom_field_index(&self) -> Option<usize> {
        if self.values.custom_fields.is_empty() {
            None
        } else {
            Some(
                self.selected_custom_field_index
                    .min(self.values.custom_fields.len() - 1),
            )
        }
    }

    pub fn selected_custom_field(&self) -> Option<&CustomFieldFormValue> {
        self.selected_custom_field_index()
            .and_then(|index| self.values.custom_fields.get(index))
    }

    pub fn custom_field_focus(&self) -> CustomFieldFormFocus {
        self.custom_field_focus
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CustomFieldFormFocus {
    Label,
    Value,
    Sensitive,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CustomFieldFormValue {
    label: String,
    value: String,
    sensitive: bool,
}

impl CustomFieldFormValue {
    fn new(label: String, value: String, sensitive: bool) -> Self {
        Self {
            label,
            value,
            sensitive,
        }
    }

    pub fn label(&self) -> &str {
        &self.label
    }

    pub fn value(&self) -> &str {
        &self.value
    }

    pub fn is_sensitive(&self) -> bool {
        self.sensitive
    }

    pub fn display_value(&self) -> String {
        if self.sensitive {
            mask_secret(&self.value)
        } else {
            self.value.clone()
        }
    }
}

fn form_state(mode: FormMode, values: PostgresFormValues) -> FormState {
    FormState {
        mode,
        dirty: false,
        values,
        focused_field: FormField::Title,
        custom_fields_expanded: false,
        selected_custom_field_index: 0,
        custom_field_focus: CustomFieldFormFocus::Label,
        validation_error: None,
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct FormValidationError {
    field: FormField,
    message: String,
}

impl FormValidationError {
    pub fn field(&self) -> FormField {
        self.field
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

#[derive(Debug, Eq, PartialEq)]
struct PostgresFormValues {
    title: String,
    service: String,
    database_engine: DatabaseEngine,
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
    custom_fields: Vec<CustomFieldFormValue>,
    expires_at: String,
    rotate_every_days: String,
    last_rotated_at: String,
}

impl PostgresFormValues {
    fn new_for_add(prefilled_tags: String) -> Self {
        Self {
            title: String::new(),
            service: String::new(),
            database_engine: DatabaseEngine::PostgreSql,
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
            custom_fields: Vec::new(),
            expires_at: String::new(),
            rotate_every_days: String::new(),
            last_rotated_at: String::new(),
        }
    }

    fn new_for_api_key_token_add(prefilled_tags: String) -> Self {
        Self {
            title: String::new(),
            service: String::new(),
            database_engine: DatabaseEngine::PostgreSql,
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
            custom_fields: Vec::new(),
            expires_at: String::new(),
            rotate_every_days: String::new(),
            last_rotated_at: String::new(),
        }
    }

    fn new_for_account_recovery_add(prefilled_tags: String) -> Self {
        Self {
            title: String::new(),
            service: String::new(),
            database_engine: DatabaseEngine::PostgreSql,
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
            custom_fields: Vec::new(),
            expires_at: String::new(),
            rotate_every_days: String::new(),
            last_rotated_at: String::new(),
        }
    }

    fn from_credential(credential: &PostgreSqlCredential) -> Self {
        Self {
            title: credential.title().to_owned(),
            service: String::new(),
            database_engine: credential.engine(),
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
            custom_fields: Vec::new(),
            expires_at: String::new(),
            rotate_every_days: String::new(),
            last_rotated_at: String::new(),
        }
    }

    fn from_api_key_token(token: &ApiKeyToken) -> Self {
        Self {
            title: token.title().to_owned(),
            service: token.service().to_owned(),
            database_engine: DatabaseEngine::PostgreSql,
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
            custom_fields: Vec::new(),
            expires_at: String::new(),
            rotate_every_days: String::new(),
            last_rotated_at: String::new(),
        }
    }

    fn load_secret_metadata(&mut self, secret: &Secret) {
        self.custom_fields = secret
            .custom_fields()
            .iter()
            .map(|field| {
                CustomFieldFormValue::new(
                    field.label().to_owned(),
                    field.value().expose_secret().to_owned(),
                    field.is_sensitive(),
                )
            })
            .collect();

        let rotation = secret.rotation();
        self.expires_at = rotation
            .expires_at
            .map(|date| date.date_naive().to_string())
            .unwrap_or_default();
        self.rotate_every_days = rotation
            .rotate_every_days
            .map(|days| days.to_string())
            .unwrap_or_default();
        self.last_rotated_at = rotation
            .last_rotated_at
            .map(|date| date.date_naive().to_string())
            .unwrap_or_default();
    }

    fn value(&self, field: FormField) -> &str {
        match field {
            FormField::Title => &self.title,
            FormField::Service => &self.service,
            FormField::Engine => self.database_engine.label(),
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
            FormField::CustomFields => "",
            FormField::ExpiresAt => &self.expires_at,
            FormField::RotateEveryDays => &self.rotate_every_days,
            FormField::LastRotatedAt => &self.last_rotated_at,
        }
    }

    fn set(&mut self, field: FormField, value: String) {
        match field {
            FormField::Title => self.title = value,
            FormField::Service => self.service = value,
            FormField::Engine => {
                if let Some(engine) = parse_database_engine(&value) {
                    self.apply_database_engine(engine);
                }
            }
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
            FormField::CustomFields => {}
            FormField::ExpiresAt => self.expires_at = value,
            FormField::RotateEveryDays => self.rotate_every_days = value,
            FormField::LastRotatedAt => self.last_rotated_at = value,
        }
    }

    fn apply_database_engine(&mut self, engine: DatabaseEngine) {
        let old_default = self
            .database_engine
            .default_port()
            .map(|port| port.to_string());
        let should_update_port = self.port.trim().is_empty()
            || old_default
                .as_deref()
                .is_some_and(|default_port| self.port.trim() == default_port);

        self.database_engine = engine;

        if should_update_port {
            self.port = engine
                .default_port()
                .map(|port| port.to_string())
                .unwrap_or_default();
        }
    }

    fn push(&mut self, field: FormField, text: &str) {
        match field {
            FormField::Title => self.title.push_str(text),
            FormField::Service => self.service.push_str(text),
            FormField::Engine => {}
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
            FormField::CustomFields => {}
            FormField::ExpiresAt => self.expires_at.push_str(text),
            FormField::RotateEveryDays => self.rotate_every_days.push_str(text),
            FormField::LastRotatedAt => self.last_rotated_at.push_str(text),
        }
    }

    fn pop(&mut self, field: FormField) -> Option<char> {
        match field {
            FormField::Title => self.title.pop(),
            FormField::Service => self.service.pop(),
            FormField::Engine => None,
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
            FormField::CustomFields => None,
            FormField::ExpiresAt => self.expires_at.pop(),
            FormField::RotateEveryDays => self.rotate_every_days.pop(),
            FormField::LastRotatedAt => self.last_rotated_at.pop(),
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
            engine: self.database_engine,
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
    UpdateAvailable,
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
    ShowRotationDue,
    ShowRotationExpired,
    ShowRotationDueSoon,
    SelectAllFilter,
    SelectUntaggedFilter,
    LockVault,
    Help,
    Quit,
    RevealSelected,
    CopyPrimary,
    CopySecondary,
    CopyNextRecoveryCode,
    MarkNextRecoveryCodeUsed,
    MarkFirstUsedRecoveryCodeUnused,
}

impl CommandPaletteCommand {
    const fn label(self) -> &'static str {
        match self {
            Self::AddPostgres => "Add Database Credential",
            Self::AddApiToken => "Add API token",
            Self::AddAccountRecovery => "Add account recovery",
            Self::EditSelected => "Edit selected item",
            Self::DeleteSelected => "Delete selected item",
            Self::FocusItems => "Focus Items panel",
            Self::FocusTags => "Focus Tags panel",
            Self::Search => "Search items",
            Self::ShowRotationDue => "Show rotation due secrets",
            Self::ShowRotationExpired => "Show expired secrets",
            Self::ShowRotationDueSoon => "Show secrets due soon",
            Self::SelectAllFilter => "Select All filter",
            Self::SelectUntaggedFilter => "Select Untagged filter",
            Self::LockVault => "Lock vault",
            Self::Help => "Help",
            Self::Quit => "Quit",
            Self::RevealSelected => "Reveal selected secret",
            Self::CopyPrimary => "Copy password/token",
            Self::CopySecondary => "Copy username/account",
            Self::CopyNextRecoveryCode => "Copy next recovery code",
            Self::MarkNextRecoveryCodeUsed => "Mark next recovery code used",
            Self::MarkFirstUsedRecoveryCodeUnused => "Mark used recovery code unused",
        }
    }

    const fn description(self) -> &'static str {
        match self {
            Self::AddPostgres => "Create a new database credential secret.",
            Self::AddApiToken => {
                "Create a new API key, access token, app password, or webhook secret."
            }
            Self::AddAccountRecovery => {
                "Create new account recovery material such as backup codes or recovery keys."
            }
            Self::EditSelected => "Edit the currently selected secret.",
            Self::DeleteSelected => "Delete the currently selected secret after confirmation.",
            Self::FocusItems => "Move keyboard focus to the Items panel.",
            Self::FocusTags => "Move keyboard focus to the Tags panel.",
            Self::Search => "Search visible secrets within the current filter.",
            Self::ShowRotationDue => "Search for secrets whose rotation is due or overdue.",
            Self::ShowRotationExpired => "Search for secrets whose expiration date has passed.",
            Self::ShowRotationDueSoon => "Search for secrets due for rotation within 7 days.",
            Self::SelectAllFilter => "Show all secrets regardless of tag.",
            Self::SelectUntaggedFilter => "Show only secrets without tags.",
            Self::LockVault => "Lock the vault and clear sensitive in-memory UI state.",
            Self::Help => "Open the keyboard shortcut help window.",
            Self::Quit => "Quit Bastion. Unsaved changes are saved first when possible.",
            Self::RevealSelected => {
                "Temporarily reveal the primary secret value for the selected item."
            }
            Self::CopyPrimary => "Copy the primary secret value, such as a password or token.",
            Self::CopySecondary => "Copy the secondary account value, such as username or account.",
            Self::CopyNextRecoveryCode => {
                "Copy the next unused recovery code for the selected item."
            }
            Self::MarkNextRecoveryCodeUsed => "Mark the next unused recovery code as used.",
            Self::MarkFirstUsedRecoveryCodeUnused => "Mark the first used recovery code as unused.",
        }
    }

    const fn group(self) -> &'static str {
        match self {
            Self::AddPostgres | Self::AddApiToken | Self::AddAccountRecovery => "Create",
            Self::EditSelected
            | Self::DeleteSelected
            | Self::RevealSelected
            | Self::CopyPrimary
            | Self::CopySecondary
            | Self::CopyNextRecoveryCode
            | Self::MarkNextRecoveryCodeUsed
            | Self::MarkFirstUsedRecoveryCodeUnused => "Current Item",
            Self::FocusItems
            | Self::FocusTags
            | Self::Search
            | Self::ShowRotationDue
            | Self::ShowRotationExpired
            | Self::ShowRotationDueSoon
            | Self::SelectAllFilter
            | Self::SelectUntaggedFilter => "Navigation",
            Self::LockVault | Self::Help | Self::Quit => "Global",
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
            Self::ShowRotationDue => &["rotation", "rotate", "due"],
            Self::ShowRotationExpired => &["rotation", "expired", "expires"],
            Self::ShowRotationDueSoon => &["rotation", "soon"],
            Self::SelectAllFilter => &["all"],
            Self::SelectUntaggedFilter => &["untagged"],
            Self::LockVault => &["l", "lock"],
            Self::Help => &["?", "help"],
            Self::Quit => &["q", "quit"],
            Self::RevealSelected => &["r", "reveal"],
            Self::CopyPrimary => &["c", "copy", "password", "token"],
            Self::CopySecondary => &["u", "copy", "username", "account"],
            Self::CopyNextRecoveryCode => &["copy", "recovery", "code"],
            Self::MarkNextRecoveryCodeUsed => &["mark", "used", "recovery", "code"],
            Self::MarkFirstUsedRecoveryCodeUnused => &["mark", "unused", "recovery", "code"],
        }
    }

    fn is_available(self, state: &AppState) -> bool {
        match self {
            Self::EditSelected
            | Self::DeleteSelected
            | Self::RevealSelected
            | Self::CopyPrimary
            | Self::CopySecondary => state.selected_secret.is_some(),
            Self::CopyNextRecoveryCode | Self::MarkNextRecoveryCodeUsed => state
                .selected_secret
                .is_some_and(|secret_id| next_unused_recovery_code_id(state, secret_id).is_some()),
            Self::MarkFirstUsedRecoveryCodeUnused => state
                .selected_secret
                .is_some_and(|secret_id| first_used_recovery_code_id(state, secret_id).is_some()),
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
            | Self::ShowRotationDue
            | Self::ShowRotationExpired
            | Self::ShowRotationDueSoon
            | Self::LockVault
            | Self::Help
            | Self::Quit => true,
        }
    }

    fn unavailable_reason(self, state: &AppState) -> Option<&'static str> {
        if self.is_available(state) {
            return None;
        }

        match self {
            Self::EditSelected => Some("Select an item first to edit it."),
            Self::DeleteSelected => Some("Select an item first to delete it."),
            Self::RevealSelected => Some("Select an item first to reveal its secret."),
            Self::CopyPrimary => Some("Select an item first to copy its password or token."),
            Self::CopySecondary => Some("Select an item first to copy its username or account."),
            Self::CopyNextRecoveryCode | Self::MarkNextRecoveryCodeUsed => {
                Some("Select an account recovery item with unused codes first.")
            }
            Self::MarkFirstUsedRecoveryCodeUnused => {
                Some("Select an account recovery item with used codes first.")
            }
            Self::SelectAllFilter => Some("The All filter is already active."),
            Self::SelectUntaggedFilter => Some("The Untagged filter is already active."),
            _ => Some("This command is not available right now."),
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
    CommandPaletteCommand::ShowRotationDue,
    CommandPaletteCommand::ShowRotationExpired,
    CommandPaletteCommand::ShowRotationDueSoon,
    CommandPaletteCommand::SelectAllFilter,
    CommandPaletteCommand::SelectUntaggedFilter,
    CommandPaletteCommand::LockVault,
    CommandPaletteCommand::Help,
    CommandPaletteCommand::Quit,
    CommandPaletteCommand::RevealSelected,
    CommandPaletteCommand::CopyPrimary,
    CommandPaletteCommand::CopySecondary,
    CommandPaletteCommand::CopyNextRecoveryCode,
    CommandPaletteCommand::MarkNextRecoveryCodeUsed,
    CommandPaletteCommand::MarkFirstUsedRecoveryCodeUnused,
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
            vec![Effect::CheckForUpdates]
        }
        AppAction::CreateVaultRequested => {
            match validate_master_passphrase(
                &state.master_passphrase_input,
                &state.master_passphrase_confirmation,
            ) {
                Ok(()) => {
                    state.status_message = Some("Creating encrypted vault...".to_owned());
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
        AppAction::UnlockVaultRequested => {
            state.status_message = Some("Unlocking vault...".to_owned());
            vec![Effect::LoadVault]
        }
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
        AppAction::UpdateAvailable { info } => {
            state.update_state = UpdateState::Available(info);
            show_update_prompt_if_main(state);
            Vec::new()
        }
        AppAction::NoUpdateAvailable => {
            state.update_state = UpdateState::Idle;
            Vec::new()
        }
        AppAction::UpdateCheckFailed { message } => {
            state.update_state = UpdateState::Failed(message);
            state.status_message =
                Some("Could not check for updates. Bastion will continue normally.".to_owned());
            Vec::new()
        }
        AppAction::UpdateDismissed => {
            if state.modal == Some(ModalState::UpdateAvailable) {
                state.screen = Screen::Main;
                state.modal = None;
            }
            Vec::new()
        }
        AppAction::UpdateSkipped { version } => {
            state.update_state = UpdateState::Skipped(version);
            if state.modal == Some(ModalState::UpdateAvailable) {
                state.screen = Screen::Main;
                state.modal = None;
            }
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
        AppAction::UserActivity { now } => {
            state.last_activity_at = Some(now);
            Vec::new()
        }
        AppAction::AutoLockTick { now } => {
            if matches!(state.session, VaultSession::Locked) {
                return Vec::new();
            }
            let Some(deadline) = state.auto_lock_deadline() else {
                return Vec::new();
            };
            if now < deadline {
                return Vec::new();
            }

            lock_after_inactivity(state);
            vec![Effect::ClearClipboard]
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
            state.secret_type_choice = state.last_secret_type_choice;
            state.direct_kind_picker_flow = false;
            clear_reveal(state);
            Vec::new()
        }
        AppAction::SelectNextSecretType => {
            if state.screen == Screen::SecretTypePicker {
                state.secret_type_choice = state.secret_type_choice.next();
            }
            Vec::new()
        }
        AppAction::SelectPreviousSecretType => {
            if state.screen == Screen::SecretTypePicker {
                state.secret_type_choice = state.secret_type_choice.previous();
            }
            Vec::new()
        }
        AppAction::ChooseSecretType(index) => {
            if state.screen != Screen::SecretTypePicker {
                return Vec::new();
            }
            match SecretTypeChoice::from_index(index) {
                Some(SecretTypeChoice::DatabaseCredential) => {
                    state.secret_type_choice = SecretTypeChoice::DatabaseCredential;
                    state.last_secret_type_choice = SecretTypeChoice::DatabaseCredential;
                    start_add_postgres(state);
                }
                Some(SecretTypeChoice::ApiToken) => {
                    state.secret_type_choice = SecretTypeChoice::ApiToken;
                    state.last_secret_type_choice = SecretTypeChoice::ApiToken;
                    state.screen = Screen::ApiTokenKindPicker;
                    state.api_token_kind_choice = ApiTokenKindChoice::PersonalAccessToken;
                    state.direct_kind_picker_flow = false;
                    clear_reveal(state);
                }
                Some(SecretTypeChoice::AccountRecovery) => {
                    state.secret_type_choice = SecretTypeChoice::AccountRecovery;
                    state.last_secret_type_choice = SecretTypeChoice::AccountRecovery;
                    state.screen = Screen::RecoveryKindPicker;
                    state.recovery_kind_choice = RecoveryKindChoice::RecoveryCodeSet;
                    state.direct_kind_picker_flow = false;
                    clear_reveal(state);
                }
                None => {}
            }
            Vec::new()
        }
        AppAction::PickDatabaseCredential | AppAction::PickPostgresCredential => {
            state.last_secret_type_choice = SecretTypeChoice::DatabaseCredential;
            start_add_postgres(state);
            Vec::new()
        }
        AppAction::PickApiToken | AppAction::PickApiKeyToken => {
            state.last_secret_type_choice = SecretTypeChoice::ApiToken;
            state.screen = Screen::ApiTokenKindPicker;
            state.api_token_kind_choice = ApiTokenKindChoice::PersonalAccessToken;
            state.direct_kind_picker_flow = false;
            clear_reveal(state);
            Vec::new()
        }
        AppAction::PickAccountRecovery => {
            state.last_secret_type_choice = SecretTypeChoice::AccountRecovery;
            state.screen = Screen::RecoveryKindPicker;
            state.recovery_kind_choice = RecoveryKindChoice::RecoveryCodeSet;
            state.direct_kind_picker_flow = false;
            clear_reveal(state);
            Vec::new()
        }
        AppAction::SelectNextApiTokenKind => {
            if state.screen == Screen::ApiTokenKindPicker {
                state.api_token_kind_choice = state.api_token_kind_choice.next();
            }
            Vec::new()
        }
        AppAction::SelectPreviousApiTokenKind => {
            if state.screen == Screen::ApiTokenKindPicker {
                state.api_token_kind_choice = state.api_token_kind_choice.previous();
            }
            Vec::new()
        }
        AppAction::ChooseApiTokenKind(index) => {
            if state.screen == Screen::ApiTokenKindPicker
                && let Some(choice) = ApiTokenKindChoice::from_index(index)
            {
                state.api_token_kind_choice = choice;
                start_add_api_key_token(state);
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
                state.recovery_kind_choice = state.recovery_kind_choice.next();
            }
            Vec::new()
        }
        AppAction::SelectPreviousRecoveryKind => {
            if state.screen == Screen::RecoveryKindPicker {
                state.recovery_kind_choice = state.recovery_kind_choice.previous();
            }
            Vec::new()
        }
        AppAction::ChooseRecoveryKind(index) => {
            if state.screen == Screen::RecoveryKindPicker
                && let Some(choice) = RecoveryKindChoice::from_index(index)
            {
                state.recovery_kind_choice = choice;
                start_add_account_recovery(state, choice);
            }
            Vec::new()
        }
        AppAction::PickRecoveryKind => {
            if state.screen == Screen::RecoveryKindPicker {
                start_add_account_recovery(state, state.recovery_kind_choice);
            }
            Vec::new()
        }
        AppAction::SelectNextDatabaseEngine => {
            if state.screen == Screen::DatabaseEnginePicker {
                state.database_engine_choice =
                    next_database_engine(state.database_engine_choice, 1);
            }
            Vec::new()
        }
        AppAction::SelectPreviousDatabaseEngine => {
            if state.screen == Screen::DatabaseEnginePicker {
                state.database_engine_choice =
                    next_database_engine(state.database_engine_choice, -1);
            }
            Vec::new()
        }
        AppAction::PickDatabaseEngine => {
            if state.screen == Screen::DatabaseEnginePicker {
                select_database_engine_choice(state, state.database_engine_choice);
            }
            Vec::new()
        }
        AppAction::CancelPicker => {
            state.screen = match state.screen {
                Screen::DatabaseEnginePicker => Screen::Form,
                Screen::ApiTokenKindPicker | Screen::RecoveryKindPicker
                    if state.direct_kind_picker_flow =>
                {
                    Screen::Main
                }
                Screen::ApiTokenKindPicker | Screen::RecoveryKindPicker => Screen::SecretTypePicker,
                _ => Screen::Main,
            };
            state.direct_kind_picker_flow = false;
            Vec::new()
        }
        AppAction::StartAddPostgres => {
            clear_reveal(state);
            state.last_secret_type_choice = SecretTypeChoice::DatabaseCredential;
            start_add_postgres(state);
            Vec::new()
        }
        AppAction::StartAddApiKeyToken => {
            clear_reveal(state);
            state.last_secret_type_choice = SecretTypeChoice::ApiToken;
            start_add_api_key_token(state);
            Vec::new()
        }
        AppAction::StartEditPostgres { secret_id } => {
            clear_reveal(state);
            if let Some((mode, values)) = form_values_for_secret(state, secret_id) {
                state.screen = Screen::Form;
                state.form = Some(form_state(mode, values));
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
                let changed = if form.focused_field == FormField::CustomFields {
                    push_selected_custom_field_text(form, &text)
                } else {
                    form.values.push(form.focused_field, &text);
                    true
                };
                if changed {
                    form.dirty = true;
                    form.validation_error = None;
                }
            }
            Vec::new()
        }
        AppAction::ChooseDatabaseEngine(index) => {
            if state.screen == Screen::DatabaseEnginePicker
                && let Some(engine) = database_engine_choice_at(index)
            {
                state.database_engine_choice = engine;
                select_database_engine_choice(state, engine);
            }
            Vec::new()
        }
        AppAction::FormBackspace => {
            if let Some(form) = &mut state.form {
                let changed = if form.focused_field == FormField::CustomFields {
                    pop_selected_custom_field_text(form)
                } else {
                    form.values.pop(form.focused_field).is_some()
                };
                if changed {
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
        AppAction::FormEnterPressed => {
            if let Some(form) = &mut state.form {
                match form.focused_field {
                    FormField::Engine => {
                        state.database_engine_choice = form.values.database_engine;
                        state.screen = Screen::DatabaseEnginePicker;
                    }
                    FormField::CustomFields => {
                        if form.custom_fields_expanded
                            && form.custom_field_focus == CustomFieldFormFocus::Sensitive
                            && !form.values.custom_fields.is_empty()
                        {
                            let index = form
                                .selected_custom_field_index
                                .min(form.values.custom_fields.len() - 1);
                            if let Some(field) = form.values.custom_fields.get_mut(index) {
                                field.sensitive = !field.sensitive;
                                form.dirty = true;
                                form.validation_error = None;
                            }
                        } else {
                            form.custom_fields_expanded = !form.custom_fields_expanded;
                            if form.custom_fields_expanded && form.values.custom_fields.is_empty() {
                                form.custom_field_focus = CustomFieldFormFocus::Label;
                            }
                        }
                    }
                    _ => {}
                }
            }
            Vec::new()
        }
        AppAction::GenerateForFocusedField => {
            generate_for_focused_field(state);
            Vec::new()
        }
        AppAction::CustomFieldsSelectNext => {
            select_custom_field(state, 1);
            Vec::new()
        }
        AppAction::CustomFieldsSelectPrevious => {
            select_custom_field(state, -1);
            Vec::new()
        }
        AppAction::CustomFieldsAdd => {
            add_custom_field(state);
            Vec::new()
        }
        AppAction::CustomFieldsDeleteSelected => {
            delete_selected_custom_field(state);
            Vec::new()
        }
        AppAction::CustomFieldsToggleSensitive => {
            toggle_selected_custom_field_sensitive(state);
            Vec::new()
        }
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
                    copy_sensitive_secret(state, secret_id, field, secret_ref)
                }
                None => {
                    state.status_message =
                        Some("No copyable secret value for selected item.".to_owned());
                    Vec::new()
                }
            }
        }
        AppAction::CopyUsernameRequested { secret_id } => {
            match secondary_copy_value(state, secret_id) {
                Some((field, value)) => copy_safe_text(state, secret_id, field, value),
                None => {
                    state.status_message = Some("No account value for selected item.".to_owned());
                    Vec::new()
                }
            }
        }
        AppAction::CopySelectedPasswordRequested => match state.selected_secret {
            Some(secret_id) => match primary_secret_ref(state, secret_id) {
                Some((field, secret_ref)) => {
                    copy_sensitive_secret(state, secret_id, field, secret_ref)
                }
                None => {
                    state.status_message =
                        Some("No copyable secret value for selected item.".to_owned());
                    Vec::new()
                }
            },
            None => {
                state.status_message = Some("Select an item first.".to_owned());
                Vec::new()
            }
        },
        AppAction::CopySelectedUsernameRequested => match state.selected_secret {
            Some(secret_id) => match secondary_copy_value(state, secret_id) {
                Some((field, value)) => copy_safe_text(state, secret_id, field, value),
                None => {
                    state.status_message = Some("No account value for selected item.".to_owned());
                    Vec::new()
                }
            },
            None => {
                state.status_message = Some("Select an item first.".to_owned());
                Vec::new()
            }
        },
        AppAction::CopyNextUnusedRecoveryCodeRequested { secret_id } => {
            copy_next_unused_recovery_code(state, secret_id)
        }
        AppAction::MarkRecoveryCodeUsed {
            secret_id,
            code_id,
            now,
        } => mark_recovery_code_used(state, secret_id, code_id, now),
        AppAction::MarkRecoveryCodeUnused {
            secret_id,
            code_id,
            now,
        } => mark_recovery_code_unused(state, secret_id, code_id, now),
        AppAction::ClipboardClearDue { now } => {
            let Some(pending) = state.clipboard_state.pending_clear else {
                return Vec::new();
            };

            if now < pending.clear_at {
                return Vec::new();
            }

            state.clipboard_state.pending_clear = None;
            vec![Effect::ClearClipboardIfUnchanged {
                copy_id: pending.copy_id,
            }]
        }
        AppAction::ClipboardClearSucceeded { copy_id: _ } => {
            state.status_message = Some("Clipboard cleared.".to_owned());
            Vec::new()
        }
        AppAction::ClipboardClearSkippedBecauseChanged { copy_id: _ } => {
            state.status_message = Some(
                "Clipboard was changed by another application. Bastion did not overwrite it."
                    .to_owned(),
            );
            Vec::new()
        }
        AppAction::ClipboardClearFailed { copy_id: _ } => {
            state.status_message = Some("Could not confirm clipboard was cleared.".to_owned());
            Vec::new()
        }
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
                if matches!(
                    state.status_message.as_deref(),
                    Some("Secret revealed for 10 seconds.")
                        | Some("Secret revealed for 10 seconds. It will hide automatically.")
                ) {
                    state.status_message = None;
                }
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
    visible_palette_commands(state)
        .into_iter()
        .map(|(_, command)| command)
        .collect()
}

fn visible_palette_commands(state: &AppState) -> Vec<(&'static str, CommandPaletteCommand)> {
    let query = state.command_palette.query.trim().to_lowercase();
    let mut items = Vec::new();

    if query.is_empty() {
        for command in state.recent_commands.iter().copied() {
            if command_matches_query(command, &query) {
                items.push(("Recent", command));
            }
        }
    }

    for command in COMMAND_PALETTE_COMMANDS.iter().copied() {
        if !command_matches_query(command, &query) {
            continue;
        }

        if query.is_empty() && state.recent_commands.contains(&command) {
            continue;
        }

        items.push((command.group(), command));
    }

    items
}

fn next_database_engine(current: DatabaseEngine, offset: isize) -> DatabaseEngine {
    let choices = database_engine_choices();
    choices[next_choice_index(choices, current, offset)]
}

pub(crate) fn database_engine_choices() -> &'static [DatabaseEngine] {
    &[
        DatabaseEngine::PostgreSql,
        DatabaseEngine::MySql,
        DatabaseEngine::MariaDb,
        DatabaseEngine::Other,
    ]
}

fn database_engine_choice_at(index: usize) -> Option<DatabaseEngine> {
    database_engine_choices().get(index).copied()
}

fn select_database_engine_choice(state: &mut AppState, engine: DatabaseEngine) {
    if let Some(form) = &mut state.form
        && matches!(
            form.mode,
            FormMode::AddPostgreSqlCredential | FormMode::EditPostgreSqlCredential(_)
        )
    {
        form.values.apply_database_engine(engine);
        form.dirty = true;
        form.validation_error = None;
    }
    state.screen = Screen::Form;
}

fn next_choice_index<T: Copy + Eq>(choices: &[T], current: T, offset: isize) -> usize {
    let current = choices
        .iter()
        .position(|choice| *choice == current)
        .unwrap_or(0);
    (current as isize + offset).rem_euclid(choices.len() as isize) as usize
}

fn parse_database_engine(value: &str) -> Option<DatabaseEngine> {
    match value.trim().to_lowercase().as_str() {
        "postgresql" | "postgres" | "pg" => Some(DatabaseEngine::PostgreSql),
        "mysql" => Some(DatabaseEngine::MySql),
        "mariadb" => Some(DatabaseEngine::MariaDb),
        "other" => Some(DatabaseEngine::Other),
        _ => None,
    }
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
        || command.description().to_lowercase().contains(query)
        || command.aliases().iter().any(|alias| alias.contains(query))
}

fn palette_command_at(state: &AppState, index: usize) -> Option<CommandPaletteCommand> {
    filtered_palette_commands(state).get(index).copied()
}

fn record_recent_palette_command(state: &mut AppState, command: CommandPaletteCommand) {
    state.recent_commands.retain(|recent| *recent != command);
    state.recent_commands.insert(0, command);
    state.recent_commands.truncate(4);
}

fn open_search_with_query(state: &mut AppState, query: &str) {
    clear_reveal(state);
    state.search_active = true;
    state.search_query = query.to_owned();
    state.search_selected_index = 0;
    state.panel_focus = PanelFocus::Items;
    state.status_message = None;
    if query.is_empty() {
        state.selected_secret = first_visible_secret_id(state);
    }
}

fn run_palette_command_at(state: &mut AppState, index: usize) -> Vec<Effect> {
    let Some(command) = palette_command_at(state, index) else {
        return Vec::new();
    };

    if !command.is_available(state) {
        state.status_message = Some(
            command
                .unavailable_reason(state)
                .unwrap_or("Command unavailable.")
                .to_owned(),
        );
        return Vec::new();
    }

    record_recent_palette_command(state, command);
    state.screen = Screen::Main;
    state.modal = None;

    match command {
        CommandPaletteCommand::AddPostgres => {
            clear_reveal(state);
            state.last_secret_type_choice = SecretTypeChoice::DatabaseCredential;
            start_add_postgres(state);
            Vec::new()
        }
        CommandPaletteCommand::AddApiToken => {
            clear_reveal(state);
            state.last_secret_type_choice = SecretTypeChoice::ApiToken;
            state.screen = Screen::ApiTokenKindPicker;
            state.api_token_kind_choice = ApiTokenKindChoice::PersonalAccessToken;
            state.direct_kind_picker_flow = true;
            Vec::new()
        }
        CommandPaletteCommand::AddAccountRecovery => {
            clear_reveal(state);
            state.last_secret_type_choice = SecretTypeChoice::AccountRecovery;
            state.screen = Screen::RecoveryKindPicker;
            state.recovery_kind_choice = RecoveryKindChoice::RecoveryCodeSet;
            state.direct_kind_picker_flow = true;
            Vec::new()
        }
        CommandPaletteCommand::EditSelected => {
            clear_reveal(state);
            if let Some(secret_id) = state.selected_secret
                && let Some((mode, values)) = form_values_for_secret(state, secret_id)
            {
                state.screen = Screen::Form;
                state.form = Some(form_state(mode, values));
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
            open_search_with_query(state, "");
            Vec::new()
        }
        CommandPaletteCommand::ShowRotationDue => {
            open_search_with_query(state, "rotation:due");
            Vec::new()
        }
        CommandPaletteCommand::ShowRotationExpired => {
            open_search_with_query(state, "rotation:expired");
            Vec::new()
        }
        CommandPaletteCommand::ShowRotationDueSoon => {
            open_search_with_query(state, "rotation:soon");
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
        CommandPaletteCommand::CopyNextRecoveryCode => match state.selected_secret {
            Some(secret_id) => copy_next_unused_recovery_code(state, secret_id),
            None => Vec::new(),
        },
        CommandPaletteCommand::MarkNextRecoveryCodeUsed => {
            let now = Utc::now();
            match state.selected_secret.and_then(|secret_id| {
                next_unused_recovery_code_id(state, secret_id).map(|code_id| (secret_id, code_id))
            }) {
                Some((secret_id, code_id)) => {
                    mark_recovery_code_used(state, secret_id, code_id, now)
                }
                None => Vec::new(),
            }
        }
        CommandPaletteCommand::MarkFirstUsedRecoveryCodeUnused => {
            let now = Utc::now();
            match state.selected_secret.and_then(|secret_id| {
                first_used_recovery_code_id(state, secret_id).map(|code_id| (secret_id, code_id))
            }) {
                Some((secret_id, code_id)) => {
                    mark_recovery_code_unused(state, secret_id, code_id, now)
                }
                None => Vec::new(),
            }
        }
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
            Some((field, secret_ref)) => copy_sensitive_secret(state, secret_id, field, secret_ref),
            None => Vec::new(),
        },
        None => Vec::new(),
    }
}

fn copy_selected_secondary(state: &mut AppState) -> Vec<Effect> {
    match state.selected_secret {
        Some(secret_id) => match secondary_copy_value(state, secret_id) {
            Some((field, value)) => copy_safe_text(state, secret_id, field, value),
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
    show_update_prompt_if_main(state);
}

fn lock_after_inactivity(state: &mut AppState) {
    state.screen = Screen::Locked;
    state.session = VaultSession::Locked;
    state.selected_secret = None;
    state.form = None;
    state.modal = None;
    state.dirty_vault = false;
    state.pending_quit_after_save = false;
    state.master_passphrase_input.clear();
    state.master_passphrase_confirmation.clear();
    state.master_passphrase_field = MasterPassphraseField::Passphrase;
    state.search_active = false;
    state.search_query.clear();
    state.search_selected_index = 0;
    state.last_activity_at = None;
    clear_reveal(state);
    state.status_message =
        Some("Vault locked after inactivity. Unsaved form was discarded.".to_owned());
}

fn show_update_prompt_if_main(state: &mut AppState) {
    if state.screen == Screen::Main && matches!(state.update_state, UpdateState::Available(_)) {
        state.screen = Screen::Modal;
        state.modal = Some(ModalState::UpdateAvailable);
    }
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

fn replace_metadata(
    state: &mut AppState,
    secret_id: SecretId,
    custom_fields: Vec<CustomField>,
    rotation: RotationMetadata,
    now: DateTime<Utc>,
) -> Result<(), VaultMutationError> {
    let Some(vault) = unlocked_vault_mut(state) else {
        return Err(VaultMutationError::SecretNotFound);
    };
    vault.replace_secret_metadata(secret_id, custom_fields, rotation, now)
}

fn start_add_postgres(state: &mut AppState) {
    state.screen = Screen::Form;
    state.form = Some(form_state(
        FormMode::AddPostgreSqlCredential,
        PostgresFormValues::new_for_add(prefill_tags(state)),
    ));
}

fn start_add_api_key_token(state: &mut AppState) {
    let mut values = PostgresFormValues::new_for_api_key_token_add(prefill_tags(state));
    values.api_token_kind = api_token_kind(state.api_token_kind_choice);
    state.screen = Screen::Form;
    state.form = Some(form_state(FormMode::AddApiKeyToken, values));
}

fn start_add_account_recovery(state: &mut AppState, kind: RecoveryKindChoice) {
    state.screen = Screen::Form;
    state.form = Some(form_state(
        FormMode::AddAccountRecovery(kind),
        PostgresFormValues::new_for_account_recovery_add(prefill_tags(state)),
    ));
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
        SecretKind::DatabaseCredential(credential) => {
            let mut values = PostgresFormValues::from_credential(credential);
            values.load_secret_metadata(secret);
            Some((FormMode::EditPostgreSqlCredential(secret_id), values))
        }
        SecretKind::ApiKeyToken(token) => {
            let mut values = PostgresFormValues::from_api_key_token(token);
            values.load_secret_metadata(secret);
            Some((FormMode::EditApiKeyToken(secret_id), values))
        }
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
        SecretKind::DatabaseCredential(_) => {
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
        SecretKind::DatabaseCredential(credential) => {
            Some(("username", credential.username().to_owned()))
        }
        SecretKind::ApiKeyToken(token) => token
            .account()
            .map(|account| ("account", account.to_owned())),
        SecretKind::AccountRecovery(_) => None,
    }
}

fn copy_sensitive_secret(
    state: &mut AppState,
    secret_id: SecretId,
    field: &'static str,
    secret_ref: SecretRef,
) -> Vec<Effect> {
    let copy_id = next_clipboard_copy_id(state);
    let clear_after_seconds = Some(30);
    state.clipboard_state.pending_clear = Some(PendingClipboardClear {
        copy_id,
        kind: ClipboardCopyKind::SensitiveSecret,
        clear_at: Utc::now() + chrono::Duration::seconds(30),
    });
    set_copy_status(
        state,
        secret_id,
        field,
        ClipboardCopyKind::SensitiveSecret,
        clear_after_seconds,
    );
    vec![Effect::CopySecretToClipboard {
        copy_id,
        secret_ref,
        kind: ClipboardCopyKind::SensitiveSecret,
        clear_after_seconds,
    }]
}

fn copy_safe_text(
    state: &mut AppState,
    secret_id: SecretId,
    field: &'static str,
    value: String,
) -> Vec<Effect> {
    let copy_id = next_clipboard_copy_id(state);
    set_copy_status(state, secret_id, field, ClipboardCopyKind::SafeText, None);
    vec![Effect::CopyTextToClipboard {
        copy_id,
        value,
        kind: ClipboardCopyKind::SafeText,
        clear_after_seconds: None,
    }]
}

fn copy_next_unused_recovery_code(state: &mut AppState, secret_id: SecretId) -> Vec<Effect> {
    let Some((title, value)) = next_unused_recovery_code_value(state, secret_id) else {
        state.status_message = Some("No unused recovery code for selected item.".to_owned());
        return Vec::new();
    };

    let copy_id = next_clipboard_copy_id(state);
    let clear_after_seconds = Some(30);
    state.clipboard_state.pending_clear = Some(PendingClipboardClear {
        copy_id,
        kind: ClipboardCopyKind::SensitiveSecret,
        clear_at: Utc::now() + chrono::Duration::seconds(30),
    });
    state.status_message = Some(format!(
        "Copied next recovery code for {title}. Clipboard will be cleared in 30s."
    ));
    vec![Effect::CopyTextToClipboard {
        copy_id,
        value,
        kind: ClipboardCopyKind::SensitiveSecret,
        clear_after_seconds,
    }]
}

fn mark_recovery_code_used(
    state: &mut AppState,
    secret_id: SecretId,
    code_id: RecoveryCodeId,
    now: DateTime<Utc>,
) -> Vec<Effect> {
    let Some(vault) = unlocked_vault_mut(state) else {
        return Vec::new();
    };
    if vault
        .mark_recovery_code_used(secret_id, code_id, now)
        .is_err()
    {
        state.status_message = Some("Could not mark recovery code used.".to_owned());
        return Vec::new();
    }

    state.dirty_vault = true;
    state.status_message = Some("Marked recovery code used.".to_owned());
    vec![Effect::SaveVault]
}

fn mark_recovery_code_unused(
    state: &mut AppState,
    secret_id: SecretId,
    code_id: RecoveryCodeId,
    now: DateTime<Utc>,
) -> Vec<Effect> {
    let Some(vault) = unlocked_vault_mut(state) else {
        return Vec::new();
    };
    if vault
        .mark_recovery_code_unused(secret_id, code_id, now)
        .is_err()
    {
        state.status_message = Some("Could not mark recovery code unused.".to_owned());
        return Vec::new();
    }

    state.dirty_vault = true;
    state.status_message = Some("Marked recovery code unused.".to_owned());
    vec![Effect::SaveVault]
}

fn next_unused_recovery_code_value(
    state: &AppState,
    secret_id: SecretId,
) -> Option<(String, String)> {
    let VaultSession::Unlocked { vault } = &state.session else {
        return None;
    };
    let secret = vault
        .secrets()
        .iter()
        .find(|secret| secret.id() == secret_id)?;
    let SecretKind::AccountRecovery(item) = secret.kind() else {
        return None;
    };
    let code = item.next_unused_recovery_code()?;
    Some((
        secret.title().to_owned(),
        code.value().expose_secret().to_owned(),
    ))
}

fn next_unused_recovery_code_id(state: &AppState, secret_id: SecretId) -> Option<RecoveryCodeId> {
    let VaultSession::Unlocked { vault } = &state.session else {
        return None;
    };
    let secret = vault
        .secrets()
        .iter()
        .find(|secret| secret.id() == secret_id)?;
    let SecretKind::AccountRecovery(item) = secret.kind() else {
        return None;
    };
    item.next_unused_recovery_code().map(|code| code.id())
}

fn first_used_recovery_code_id(state: &AppState, secret_id: SecretId) -> Option<RecoveryCodeId> {
    let VaultSession::Unlocked { vault } = &state.session else {
        return None;
    };
    let secret = vault
        .secrets()
        .iter()
        .find(|secret| secret.id() == secret_id)?;
    let SecretKind::AccountRecovery(item) = secret.kind() else {
        return None;
    };
    item.recovery_codes()
        .iter()
        .find(|code| code.status() == RecoveryCodeStatus::Used)
        .map(|code| code.id())
}

fn next_clipboard_copy_id(state: &mut AppState) -> ClipboardCopyId {
    let copy_id = ClipboardCopyId(state.next_clipboard_copy_id);
    state.next_clipboard_copy_id += 1;
    copy_id
}

fn set_copy_status(
    state: &mut AppState,
    secret_id: SecretId,
    field: &str,
    kind: ClipboardCopyKind,
    clear_after_seconds: Option<i64>,
) {
    let item_label = secret_title(state, secret_id).unwrap_or("selected item");

    state.status_message = match (kind, clear_after_seconds) {
        (ClipboardCopyKind::SafeText, _) => Some(format!("Copied {field} for {item_label}.")),
        (
            ClipboardCopyKind::SensitiveSecret | ClipboardCopyKind::SensitiveConnectionString,
            Some(seconds),
        ) => Some(format!(
            "Copied {field} for {item_label}. Clipboard will be cleared in {seconds}s."
        )),
        (
            ClipboardCopyKind::SensitiveSecret | ClipboardCopyKind::SensitiveConnectionString,
            None,
        ) => Some(format!(
            "Copied {field} for {item_label}. Clipboard auto-clear is disabled."
        )),
    };
}

fn secret_title(state: &AppState, secret_id: SecretId) -> Option<&str> {
    let VaultSession::Unlocked { vault } = &state.session else {
        return None;
    };
    vault
        .secrets()
        .iter()
        .find(|secret| secret.id() == secret_id)
        .map(Secret::title)
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

    if form.focused_field == FormField::CustomFields
        && form.custom_fields_expanded
        && !form.values.custom_fields.is_empty()
    {
        match (offset.signum(), form.custom_field_focus) {
            (1, CustomFieldFormFocus::Label) => {
                form.custom_field_focus = CustomFieldFormFocus::Value;
                return;
            }
            (1, CustomFieldFormFocus::Value) => {
                form.custom_field_focus = CustomFieldFormFocus::Sensitive;
                return;
            }
            (-1, CustomFieldFormFocus::Sensitive) => {
                form.custom_field_focus = CustomFieldFormFocus::Value;
                return;
            }
            (-1, CustomFieldFormFocus::Value) => {
                form.custom_field_focus = CustomFieldFormFocus::Label;
                return;
            }
            _ => {}
        }
    }

    let fields = FormField::fields_for_mode(form.mode);
    let current = fields
        .iter()
        .position(|field| *field == form.focused_field)
        .unwrap_or(0);
    let len = fields.len() as isize;
    let next = (current as isize + offset).rem_euclid(len) as usize;
    form.focused_field = fields[next];

    if form.focused_field == FormField::CustomFields {
        form.custom_field_focus = CustomFieldFormFocus::Label;
        clamp_selected_custom_field_index(form);
    }
}

fn select_custom_field(state: &mut AppState, offset: isize) {
    let Some(form) = &mut state.form else {
        return;
    };
    if form.focused_field != FormField::CustomFields || !form.custom_fields_expanded {
        return;
    }
    let len = form.values.custom_fields.len();
    if len == 0 {
        form.selected_custom_field_index = 0;
        return;
    }
    let current = form.selected_custom_field_index.min(len - 1);
    let next = (current as isize + offset).rem_euclid(len as isize) as usize;
    form.selected_custom_field_index = next;
    form.custom_field_focus = CustomFieldFormFocus::Label;
}

fn add_custom_field(state: &mut AppState) {
    let Some(form) = &mut state.form else {
        return;
    };
    if form.focused_field != FormField::CustomFields {
        return;
    }
    form.custom_fields_expanded = true;
    form.values.custom_fields.push(CustomFieldFormValue::new(
        String::new(),
        String::new(),
        false,
    ));
    form.selected_custom_field_index = form.values.custom_fields.len() - 1;
    form.custom_field_focus = CustomFieldFormFocus::Label;
    form.dirty = true;
    form.validation_error = None;
}

fn delete_selected_custom_field(state: &mut AppState) {
    let Some(form) = &mut state.form else {
        return;
    };
    if form.focused_field != FormField::CustomFields || form.values.custom_fields.is_empty() {
        return;
    }
    let index = form
        .selected_custom_field_index
        .min(form.values.custom_fields.len() - 1);
    form.values.custom_fields.remove(index);
    clamp_selected_custom_field_index(form);
    form.custom_field_focus = CustomFieldFormFocus::Label;
    form.dirty = true;
    form.validation_error = None;
}

fn toggle_selected_custom_field_sensitive(state: &mut AppState) {
    let Some(form) = &mut state.form else {
        return;
    };
    if form.focused_field != FormField::CustomFields || form.values.custom_fields.is_empty() {
        return;
    }
    let index = form
        .selected_custom_field_index
        .min(form.values.custom_fields.len() - 1);
    if let Some(field) = form.values.custom_fields.get_mut(index) {
        field.sensitive = !field.sensitive;
        form.dirty = true;
        form.validation_error = None;
    }
}

fn push_selected_custom_field_text(form: &mut FormState, text: &str) -> bool {
    if !form.custom_fields_expanded || form.values.custom_fields.is_empty() {
        return false;
    }
    let index = form
        .selected_custom_field_index
        .min(form.values.custom_fields.len() - 1);
    let Some(field) = form.values.custom_fields.get_mut(index) else {
        return false;
    };
    match form.custom_field_focus {
        CustomFieldFormFocus::Label => field.label.push_str(text),
        CustomFieldFormFocus::Value => field.value.push_str(text),
        CustomFieldFormFocus::Sensitive => return false,
    }
    true
}

fn pop_selected_custom_field_text(form: &mut FormState) -> bool {
    if !form.custom_fields_expanded || form.values.custom_fields.is_empty() {
        return false;
    }
    let index = form
        .selected_custom_field_index
        .min(form.values.custom_fields.len() - 1);
    let Some(field) = form.values.custom_fields.get_mut(index) else {
        return false;
    };
    match form.custom_field_focus {
        CustomFieldFormFocus::Label => field.label.pop().is_some(),
        CustomFieldFormFocus::Value => field.value.pop().is_some(),
        CustomFieldFormFocus::Sensitive => false,
    }
}

fn clamp_selected_custom_field_index(form: &mut FormState) {
    if form.values.custom_fields.is_empty() {
        form.selected_custom_field_index = 0;
    } else {
        form.selected_custom_field_index = form
            .selected_custom_field_index
            .min(form.values.custom_fields.len() - 1);
    }
}

fn generate_for_focused_field(state: &mut AppState) {
    let Some(form) = &mut state.form else {
        return;
    };

    let generated = match generated_value_for_focused_field(form.mode, form.focused_field) {
        Some(Ok(value)) => value,
        Some(Err(())) => {
            state.status_message = Some("Could not generate a value.".to_owned());
            return;
        }
        None => {
            state.status_message = Some(
                "Move to a password, token, or supported recovery field to generate a value."
                    .to_owned(),
            );
            return;
        }
    };

    form.values.set(form.focused_field, generated);
    form.dirty = true;
    form.validation_error = None;
    state.status_message = Some(format!(
        "Generated {} for {}.",
        generated_kind_label(form.mode, form.focused_field),
        form_field_display_name(form.focused_field)
    ));
}

fn generated_value_for_focused_field(
    mode: FormMode,
    field: FormField,
) -> Option<Result<String, ()>> {
    match field {
        FormField::Password => Some(generate_value(SecretGeneratorConfig::password())),
        FormField::Token => Some(generate_value(SecretGeneratorConfig::base64_url_token(32))),
        FormField::RecoveryMaterial => match mode {
            FormMode::AddAccountRecovery(crate::RecoveryKindChoice::RecoveryCodeSet) => {
                Some(generate_recovery_code_set())
            }
            FormMode::AddAccountRecovery(crate::RecoveryKindChoice::RecoveryKey) => {
                Some(generate_value(SecretGeneratorConfig::base64_url_token(32)))
            }
            _ => None,
        },
        _ => None,
    }
}

fn generate_value(config: SecretGeneratorConfig) -> Result<String, ()> {
    generate_secret(&config)
        .map(|value| value.expose_secret().to_owned())
        .map_err(|_| ())
}

fn generate_recovery_code_set() -> Result<String, ()> {
    let mut codes = Vec::new();
    for _ in 0..10 {
        codes.push(generate_value(SecretGeneratorConfig::base64_url_token(12))?);
    }
    Ok(codes.join("\n"))
}

fn generated_kind_label(mode: FormMode, field: FormField) -> &'static str {
    match field {
        FormField::Password => "password",
        FormField::Token => "token",
        FormField::RecoveryMaterial => match mode {
            FormMode::AddAccountRecovery(crate::RecoveryKindChoice::RecoveryCodeSet) => {
                "recovery code set"
            }
            FormMode::AddAccountRecovery(crate::RecoveryKindChoice::RecoveryKey) => "recovery key",
            _ => "recovery value",
        },
        _ => "value",
    }
}

fn form_field_display_name(field: FormField) -> &'static str {
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

fn save_form(state: &mut AppState, now: DateTime<Utc>) -> Vec<Effect> {
    let Some(form) = &mut state.form else {
        return Vec::new();
    };

    match form.mode {
        FormMode::AddPostgreSqlCredential => {
            let Some(credential) = postgres_credential_from_form(form) else {
                return Vec::new();
            };
            let Some((custom_fields, rotation)) = metadata_from_form(form) else {
                return Vec::new();
            };
            let Some(vault) = unlocked_vault_mut(state) else {
                return Vec::new();
            };
            let mut secret = Secret::new_postgres(credential, now);
            secret.set_custom_fields(custom_fields, now);
            secret.set_rotation(rotation, now);
            let secret_id = secret.id();
            vault.add_secret(secret, now);
            state.selected_secret = Some(secret_id);
        }
        FormMode::EditPostgreSqlCredential(secret_id) => {
            let Some(credential) = postgres_credential_from_form(form) else {
                return Vec::new();
            };
            let Some((custom_fields, rotation)) = metadata_from_form(form) else {
                return Vec::new();
            };
            if replace_postgres(state, secret_id, credential, now).is_err() {
                return Vec::new();
            }
            if replace_metadata(state, secret_id, custom_fields, rotation, now).is_err() {
                return Vec::new();
            }
            state.selected_secret = Some(secret_id);
        }
        FormMode::AddApiKeyToken => {
            let Some(token) = api_key_token_from_form(form) else {
                return Vec::new();
            };
            let Some((custom_fields, rotation)) = metadata_from_form(form) else {
                return Vec::new();
            };
            let Some(vault) = unlocked_vault_mut(state) else {
                return Vec::new();
            };
            let mut secret = Secret::new_api_key_token(token, now);
            secret.set_custom_fields(custom_fields, now);
            secret.set_rotation(rotation, now);
            let secret_id = secret.id();
            vault.add_secret(secret, now);
            state.selected_secret = Some(secret_id);
        }
        FormMode::EditApiKeyToken(secret_id) => {
            let Some(token) = api_key_token_from_form(form) else {
                return Vec::new();
            };
            let Some((custom_fields, rotation)) = metadata_from_form(form) else {
                return Vec::new();
            };
            if replace_api_key_token(state, secret_id, token, now).is_err() {
                return Vec::new();
            }
            if replace_metadata(state, secret_id, custom_fields, rotation, now).is_err() {
                return Vec::new();
            }
            state.selected_secret = Some(secret_id);
        }
        FormMode::AddAccountRecovery(kind) => {
            let Some(item) = account_recovery_from_form(form, kind) else {
                return Vec::new();
            };
            let Some((custom_fields, rotation)) = metadata_from_form(form) else {
                return Vec::new();
            };
            let Some(vault) = unlocked_vault_mut(state) else {
                return Vec::new();
            };
            let mut secret = Secret::new_account_recovery(item, now);
            secret.set_custom_fields(custom_fields, now);
            secret.set_rotation(rotation, now);
            let secret_id = secret.id();
            vault.add_secret(secret, now);
            state.selected_secret = Some(secret_id);
        }
    }

    state.screen = Screen::Main;
    state.form = None;
    state.modal = None;
    state.dirty_vault = true;
    state.status_message = Some("Saving vault...".to_owned());
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

fn metadata_from_form(form: &mut FormState) -> Option<(Vec<CustomField>, RotationMetadata)> {
    let custom_fields = match custom_fields_from_form(form) {
        Ok(fields) => fields,
        Err(error) => {
            form.focused_field = error.field;
            form.custom_fields_expanded = true;
            form.custom_field_focus = CustomFieldFormFocus::Label;
            form.validation_error = Some(error);
            return None;
        }
    };
    let rotation = match parse_rotation_metadata(
        &form.values.expires_at,
        &form.values.rotate_every_days,
        &form.values.last_rotated_at,
    ) {
        Ok(rotation) => rotation,
        Err(error) => {
            form.focused_field = error.field;
            form.validation_error = Some(error);
            return None;
        }
    };

    Some((custom_fields, rotation))
}

fn custom_fields_from_form(form: &mut FormState) -> Result<Vec<CustomField>, FormValidationError> {
    let mut fields = Vec::new();
    for (index, field) in form.values.custom_fields.iter().enumerate() {
        if field.label.trim().is_empty() {
            form.selected_custom_field_index = index;
            return Err(FormValidationError {
                field: FormField::CustomFields,
                message: "Custom field labels cannot be empty.".to_owned(),
            });
        }
        let custom_field = CustomField::new(CustomFieldInput {
            label: field.label.trim().to_owned(),
            value: field.value.clone(),
            sensitive: field.sensitive,
        })
        .map_err(|_| FormValidationError {
            field: FormField::CustomFields,
            message: "Custom field labels cannot be empty.".to_owned(),
        })?;
        fields.push(custom_field);
    }
    Ok(fields)
}

fn parse_rotation_metadata(
    expires_at: &str,
    rotate_every_days: &str,
    last_rotated_at: &str,
) -> Result<RotationMetadata, FormValidationError> {
    Ok(RotationMetadata {
        expires_at: parse_optional_date(expires_at, FormField::ExpiresAt)?,
        rotate_every_days: parse_optional_days(rotate_every_days)?,
        last_rotated_at: parse_optional_date(last_rotated_at, FormField::LastRotatedAt)?,
    })
}

fn parse_optional_date(
    value: &str,
    field: FormField,
) -> Result<Option<DateTime<Utc>>, FormValidationError> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }

    let date = NaiveDate::parse_from_str(value, "%Y-%m-%d").map_err(|_| FormValidationError {
        field,
        message: "Use date format YYYY-MM-DD.".to_owned(),
    })?;
    let Some(datetime) = date.and_hms_opt(0, 0, 0) else {
        return Err(FormValidationError {
            field,
            message: "Use date format YYYY-MM-DD.".to_owned(),
        });
    };
    Ok(Some(DateTime::from_naive_utc_and_offset(datetime, Utc)))
}

fn parse_optional_days(value: &str) -> Result<Option<u16>, FormValidationError> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }

    let days = value.parse::<u16>().map_err(|_| FormValidationError {
        field: FormField::RotateEveryDays,
        message: "Rotate every must be a number of days.".to_owned(),
    })?;
    if days == 0 {
        return Err(FormValidationError {
            field: FormField::RotateEveryDays,
            message: "Rotate every must be at least 1 day.".to_owned(),
        });
    }
    Ok(Some(days))
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
