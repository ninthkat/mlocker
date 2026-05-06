mod model;

use std::{collections::HashSet, path::Path};

use egui::{Color32, Frame, Margin, RichText, Rounding, Stroke, TextEdit};
use model::{
    fingerprint, generate_recovery_phrase, LoginForm, LoginItem, OpenForm, PasskeyForm,
    PasskeyItem, PasswordKind, SshKeyForm, SshKeyItem, VaultSession, WalletAccount,
};
use zeroize::Zeroize;

const APP_BG: Color32 = Color32::from_rgb(249, 250, 253);
const SURFACE: Color32 = Color32::from_rgb(255, 255, 255);
const SURFACE_ALT: Color32 = Color32::from_rgb(246, 247, 251);
const SURFACE_WARM: Color32 = Color32::from_rgb(252, 248, 255);
const BORDER: Color32 = Color32::from_rgb(226, 229, 239);
const BORDER_STRONG: Color32 = Color32::from_rgb(203, 210, 226);
const TEXT: Color32 = Color32::from_rgb(20, 24, 39);
const MUTED: Color32 = Color32::from_rgb(95, 103, 125);
const SIDEBAR: Color32 = Color32::from_rgb(247, 248, 252);
const SIDEBAR_TEXT: Color32 = Color32::from_rgb(28, 32, 48);
const SIDEBAR_MUTED: Color32 = Color32::from_rgb(103, 111, 134);
const ACCENT: Color32 = Color32::from_rgb(101, 62, 245);
const ACCENT_DARK: Color32 = Color32::from_rgb(79, 45, 216);
const ACCENT_SOFT: Color32 = Color32::from_rgb(240, 235, 255);
const GREEN: Color32 = Color32::from_rgb(16, 163, 91);
const GREEN_SOFT: Color32 = Color32::from_rgb(231, 249, 240);
const GOLD_TEXT: Color32 = Color32::from_rgb(214, 137, 0);
const WARNING_TEXT: Color32 = Color32::from_rgb(177, 91, 6);

#[cfg(feature = "core-integration")]
mod core_bridge {
    #[allow(unused_imports)]
    use mlocker_core::{
        derive_ethereum_account, derive_password, derive_root_key_with_passphrase,
        derive_solana_account, parse_mnemonic, LoginItem, PasswordDerivationRequest,
        PasswordOptions, Vault, DEFAULT_APP_DOMAIN,
    };

    pub const STATUS: &str = "Ready.";
}

#[cfg(not(feature = "core-integration"))]
mod core_bridge {
    pub const STATUS: &str = "Preview mode.";
}

fn main() -> eframe::Result<()> {
    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([1536.0, 1024.0]),
        ..Default::default()
    };

    eframe::run_native(
        "mlocker",
        native_options,
        Box::new(|cc| Ok(Box::new(MlockerDesktop::new(cc)))),
    )
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Screen {
    OpenVault,
    Vault,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum VaultTab {
    Items,
    AddItem,
    Wallet,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum AddItemKind {
    Login,
    SshKey,
    Passkey,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum SelectedItem {
    Login(usize),
    SshKey(usize),
    Passkey(usize),
}

#[derive(Clone)]
enum DisplayItem {
    Login(usize, LoginItem),
    SshKey(usize, SshKeyItem),
    Passkey(usize, PasskeyItem),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ItemCollection {
    AllItems,
    Favorites,
    Recent,
    Trash,
    Category(CategoryKind),
    Folder(FolderKind),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CategoryKind {
    Logins,
    CreditCards,
    SecureNotes,
    Identities,
    Passwords,
    SshKeys,
    Passkeys,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum FolderKind {
    Personal,
    Work,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SortMode {
    TitleAsc,
    TitleDesc,
    Type,
}

#[derive(Clone, Copy)]
enum IconKind {
    Lock,
    Grid,
    Star,
    Clock,
    Trash,
    Login,
    Card,
    Note,
    User,
    Key,
    Folder,
    Ssh,
    Passkey,
    Wallet,
    Search,
    Filter,
    Sort,
    Copy,
    Eye,
    Edit,
    More,
    Shield,
    Chevron,
}

struct MlockerDesktop {
    screen: Screen,
    tab: VaultTab,
    add_item_kind: AddItemKind,
    open_form: OpenForm,
    login_form: LoginForm,
    ssh_key_form: SshKeyForm,
    passkey_form: PasskeyForm,
    vault: Option<VaultSession>,
    selected_item: Option<SelectedItem>,
    collection: ItemCollection,
    favorite_items: HashSet<SelectedItem>,
    trashed_items: HashSet<SelectedItem>,
    recent_items: Vec<SelectedItem>,
    sort_mode: SortMode,
    filters_visible: bool,
    filter_logins: bool,
    filter_ssh_keys: bool,
    filter_passkeys: bool,
    details_menu_for: Option<SelectedItem>,
    item_filter: String,
    status: String,
}

impl MlockerDesktop {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        apply_theme(&cc.egui_ctx);

        let mut open_form = OpenForm::default();
        let mut status = String::from(core_bridge::STATUS);
        if !Path::new(&open_form.create_path).exists() {
            match generate_recovery_phrase() {
                Ok(phrase) => {
                    open_form.create_recovery_phrase = phrase;
                    status = format!("Create a new personal vault: {}", open_form.create_path);
                }
                Err(message) => {
                    status = message;
                }
            }
        }

        Self {
            screen: Screen::OpenVault,
            tab: VaultTab::Items,
            add_item_kind: AddItemKind::Login,
            open_form,
            login_form: LoginForm::default(),
            ssh_key_form: SshKeyForm::default(),
            passkey_form: PasskeyForm::default(),
            vault: None,
            selected_item: None,
            collection: ItemCollection::AllItems,
            favorite_items: HashSet::new(),
            trashed_items: HashSet::new(),
            recent_items: Vec::new(),
            sort_mode: SortMode::TitleAsc,
            filters_visible: false,
            filter_logins: true,
            filter_ssh_keys: true,
            filter_passkeys: true,
            details_menu_for: None,
            item_filter: String::new(),
            status,
        }
    }

    fn generate_create_recovery_phrase(&mut self) {
        match generate_recovery_phrase() {
            Ok(phrase) => {
                self.open_form.create_recovery_phrase = phrase;
                self.status = String::from("Generated a new recovery phrase.");
            }
            Err(message) => {
                self.status = message;
            }
        }
    }

    fn create_vault(&mut self) {
        let path = self.open_form.create_path.trim().to_owned();
        let passphrase = self.open_form.create_passphrase.trim().to_owned();

        if path.is_empty() {
            self.status = String::from("Choose where the new vault should live.");
            return;
        }

        if Path::new(&path).exists() {
            self.status = String::from("A vault already exists at that path. Use Open vault.");
            return;
        }

        if passphrase.len() < 8 {
            self.status = String::from("Use at least 8 characters for the new vault password.");
            return;
        }

        if self
            .open_form
            .create_recovery_phrase
            .split_whitespace()
            .count()
            < 12
        {
            self.generate_create_recovery_phrase();
        }

        let recovery_phrase = self.open_form.create_recovery_phrase.trim().to_owned();
        match VaultSession::restore(&path, &passphrase, &recovery_phrase) {
            Ok(session) => self.finish_unlock(session, "Created encrypted vault"),
            Err(message) => {
                self.status = message;
            }
        }
    }

    fn open_vault(&mut self) {
        let path = self.open_form.open_path.trim();
        let passphrase = self.open_form.open_passphrase.trim();
        let recovery_phrase = self.open_form.open_recovery_phrase.trim();

        if path.is_empty() {
            self.status = String::from("Enter a vault path before opening.");
            return;
        }

        if passphrase.is_empty() && recovery_phrase.split_whitespace().count() < 12 {
            self.status = String::from("Enter the vault password or paste the recovery phrase.");
            return;
        }

        match VaultSession::open(path, passphrase, recovery_phrase) {
            Ok(session) => self.finish_unlock(session, "Opened encrypted vault"),
            Err(message) => {
                self.status = message;
            }
        }
    }

    fn restore_vault(&mut self) {
        let path = self.open_form.restore_path.trim();
        let passphrase = self.open_form.restore_passphrase.trim();
        let recovery_phrase = self.open_form.restore_recovery_phrase.trim();

        if path.is_empty() {
            self.status = String::from("Choose where the restored vault should live.");
            return;
        }

        if recovery_phrase.split_whitespace().count() < 12 {
            self.status = String::from("Paste the full recovery phrase before restoring.");
            return;
        }

        if passphrase.len() < 8 {
            self.status = String::from("Use at least 8 characters for the vault password.");
            return;
        }

        match VaultSession::restore(path, passphrase, recovery_phrase) {
            Ok(session) => self.finish_unlock(session, "Restored encrypted vault"),
            Err(message) => {
                self.status = message;
            }
        }
    }

    fn finish_unlock(&mut self, session: VaultSession, action: &str) {
        let vault_name = session.path.clone();
        let next_ssh_path = session.next_ssh_derivation_path();
        self.vault = Some(session);
        self.screen = Screen::Vault;
        self.tab = VaultTab::Items;
        self.add_item_kind = AddItemKind::Login;
        self.selected_item = None;
        self.collection = ItemCollection::AllItems;
        self.favorite_items.clear();
        self.trashed_items.clear();
        self.recent_items.clear();
        self.details_menu_for = None;
        self.ssh_key_form.derivation_path = next_ssh_path;
        self.status = format!("{action}: {vault_name}");
        self.open_form.open_passphrase.zeroize();
        self.open_form.open_recovery_phrase.zeroize();
        self.open_form.create_passphrase.zeroize();
        self.open_form.create_recovery_phrase.zeroize();
        self.open_form.restore_passphrase.zeroize();
        self.open_form.restore_recovery_phrase.zeroize();
    }

    fn lock_vault(&mut self) {
        self.vault = None;
        self.screen = Screen::OpenVault;
        self.tab = VaultTab::Items;
        self.add_item_kind = AddItemKind::Login;
        self.selected_item = None;
        self.collection = ItemCollection::AllItems;
        self.favorite_items.clear();
        self.trashed_items.clear();
        self.recent_items.clear();
        self.details_menu_for = None;
        self.status = String::from("Vault locked and session state cleared.");
    }

    fn add_login(&mut self) {
        let Some(vault) = self.vault.as_mut() else {
            self.status = String::from("Open a vault before adding an item.");
            return;
        };

        if let Err(message) = self.login_form.validate() {
            self.status = message;
            return;
        }

        if vault.uses_core_persistence()
            && self.login_form.password_kind == PasswordKind::MnemonicDerived
            && self.login_form.password_length != 24
        {
            self.status =
                String::from("Persistent vault items currently use 24-character passwords.");
            return;
        }

        let password = match vault.build_login_password(&self.login_form) {
            Ok(password) => password,
            Err(message) => {
                self.status = message;
                return;
            }
        };
        let item = LoginItem::from_form(&vault.seed, &self.login_form, password);
        let item_title = item.title.clone();
        if let Err(message) = vault.persist_login_item(&item) {
            self.status = message;
            return;
        }
        vault.items.push(item);
        let selection = SelectedItem::Login(vault.items.len() - 1);
        self.selected_item = Some(selection);
        record_recent_item(&mut self.recent_items, selection);
        self.tab = VaultTab::Items;
        self.collection = ItemCollection::AllItems;
        self.status = format!("Added login item: {item_title}");
        self.login_form.clear_secret_inputs();
    }

    fn add_ssh_key(&mut self) {
        let Some(vault) = self.vault.as_mut() else {
            self.status = String::from("Open a vault before adding an item.");
            return;
        };

        if let Err(message) = self.ssh_key_form.validate() {
            self.status = message;
            return;
        }

        let item = match vault.derive_ssh_key(&self.ssh_key_form) {
            Ok(item) => item,
            Err(message) => {
                self.status = message;
                return;
            }
        };
        let label = item.label.clone();
        if let Err(message) = vault.persist_ssh_key_item(&item) {
            self.status = message;
            return;
        }
        vault.ssh_keys.push(item);
        let selection = SelectedItem::SshKey(vault.ssh_keys.len() - 1);
        self.selected_item = Some(selection);
        record_recent_item(&mut self.recent_items, selection);
        self.tab = VaultTab::Items;
        self.collection = ItemCollection::AllItems;
        self.status = format!("Added SSH key item: {label}");
        let next_path = vault.next_ssh_derivation_path();
        self.ssh_key_form.clear_inputs(next_path);
    }

    fn add_passkey(&mut self) {
        let Some(vault) = self.vault.as_mut() else {
            self.status = String::from("Open a vault before adding an item.");
            return;
        };

        if let Err(message) = self.passkey_form.validate() {
            self.status = message;
            return;
        }

        let item = match vault.derive_passkey(&self.passkey_form) {
            Ok(item) => item,
            Err(message) => {
                self.status = message;
                return;
            }
        };
        let label = item.label.clone();
        if let Err(message) = vault.persist_passkey_item(&item) {
            self.status = message;
            return;
        }
        vault.passkeys.push(item);
        let selection = SelectedItem::Passkey(vault.passkeys.len() - 1);
        self.selected_item = Some(selection);
        record_recent_item(&mut self.recent_items, selection);
        self.tab = VaultTab::Items;
        self.collection = ItemCollection::AllItems;
        self.status = format!("Added passkey item: {label}");
        self.passkey_form.clear_secret_inputs();
    }

    fn filtered_items(&self) -> Vec<DisplayItem> {
        let filter = self.item_filter.trim().to_lowercase();
        let mut items: Vec<_> = self
            .all_display_items()
            .into_iter()
            .filter(|item| self.item_matches_collection(item, self.collection))
            .filter(|item| self.item_matches_type_filters(item))
            .filter(|item| filter.is_empty() || item.matches_search(&filter))
            .collect();

        match self.collection {
            ItemCollection::Recent => {
                items.sort_by_key(|item| {
                    self.recent_items
                        .iter()
                        .position(|selection| *selection == item.selection())
                        .unwrap_or(usize::MAX)
                });
            }
            _ => sort_display_items(&mut items, self.sort_mode),
        }

        items
    }

    fn all_display_items(&self) -> Vec<DisplayItem> {
        let Some(vault) = self.vault.as_ref() else {
            return Vec::new();
        };

        let mut items: Vec<_> = vault
            .items
            .iter()
            .enumerate()
            .map(|(index, item)| DisplayItem::Login(index, item.clone()))
            .collect();
        items.extend(
            vault
                .ssh_keys
                .iter()
                .enumerate()
                .map(|(index, item)| DisplayItem::SshKey(index, item.clone())),
        );
        items.extend(
            vault
                .passkeys
                .iter()
                .enumerate()
                .map(|(index, item)| DisplayItem::Passkey(index, item.clone())),
        );
        items
    }

    fn item_matches_collection(&self, item: &DisplayItem, collection: ItemCollection) -> bool {
        let selection = item.selection();
        let trashed = self.trashed_items.contains(&selection);

        match collection {
            ItemCollection::Trash => trashed,
            _ if trashed => false,
            ItemCollection::AllItems => true,
            ItemCollection::Favorites => self.favorite_items.contains(&selection),
            ItemCollection::Recent => self.recent_items.contains(&selection),
            ItemCollection::Category(category) => item.matches_category(category),
            ItemCollection::Folder(FolderKind::Personal) => true,
            ItemCollection::Folder(FolderKind::Work) => false,
        }
    }

    fn item_matches_type_filters(&self, item: &DisplayItem) -> bool {
        match item {
            DisplayItem::Login(_, _) => self.filter_logins,
            DisplayItem::SshKey(_, _) => self.filter_ssh_keys,
            DisplayItem::Passkey(_, _) => self.filter_passkeys,
        }
    }

    fn collection_count(&self, collection: ItemCollection) -> usize {
        self.all_display_items()
            .iter()
            .filter(|item| self.item_matches_collection(item, collection))
            .count()
    }

    fn select_collection(&mut self, collection: ItemCollection) {
        self.collection = collection;
        self.tab = VaultTab::Items;
        self.selected_item = None;
        self.details_menu_for = None;
        self.status = format!("Showing {}.", collection.title());
    }

    fn cycle_sort_mode(&mut self) {
        self.sort_mode = match self.sort_mode {
            SortMode::TitleAsc => SortMode::TitleDesc,
            SortMode::TitleDesc => SortMode::Type,
            SortMode::Type => SortMode::TitleAsc,
        };
        self.status = format!("Sort: {}.", self.sort_mode.label());
    }

    fn record_recent(&mut self, selection: SelectedItem) {
        record_recent_item(&mut self.recent_items, selection);
    }

    fn show_open_screen(&mut self, ui: &mut egui::Ui) {
        let sidebar_height = ui.available_height().max(660.0);
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.horizontal_top(|ui| {
                    app_sidebar_frame().show(ui, |ui| {
                        ui.set_width(248.0);
                        ui.set_min_height(sidebar_height);
                        brand_header(ui);
                        ui.add_space(20.0);
                        sidebar_item(ui, "All Items", "0", true);
                        sidebar_item(ui, "Favorites", "0", false);
                        sidebar_item(ui, "Recent", "0", false);
                        sidebar_item(ui, "Trash", "0", false);
                        ui.add_space(20.0);
                        sidebar_heading(ui, "CATEGORIES");
                        sidebar_item(ui, "Logins", "0", false);
                        sidebar_item(ui, "Secure Notes", "0", false);
                        sidebar_item(ui, "Wallet", "3", false);
                        ui.with_layout(egui::Layout::bottom_up(egui::Align::Min), |ui| {
                            security_score_card(ui);
                        });
                    });

                    ui.add_space(24.0);

                    ui.vertical(|ui| {
                        ui.set_min_width(700.0);
                        ui.add_space(4.0);
                        setup_header(ui, &self.open_form.create_path);
                        ui.add_space(24.0);
                        status_banner(ui, &self.status);
                        ui.add_space(14.0);

                        let default_missing = !Path::new(&self.open_form.open_path).exists();
                        if default_missing {
                            self.show_create_vault_card(ui);
                            ui.add_space(14.0);
                            self.show_open_vault_card(ui);
                        } else {
                            self.show_open_vault_card(ui);
                            ui.add_space(14.0);
                            self.show_create_vault_card(ui);
                        }
                        ui.add_space(14.0);
                        self.show_restore_vault_card(ui);
                    });
                });
            });
    }

    fn show_open_vault_card(&mut self, ui: &mut egui::Ui) {
        panel_frame().show(ui, |ui| {
            card_title(ui, "Open existing vault", "Encrypted file");
            ui.add_space(16.0);

            labelled_text(
                ui,
                "Vault path",
                &mut self.open_form.open_path,
                false,
                "personal.vault",
            );
            labelled_text(
                ui,
                "Vault password",
                &mut self.open_form.open_passphrase,
                true,
                "password",
            );
            field_label(ui, "Recovery phrase");
            ui.add(
                TextEdit::multiline(&mut self.open_form.open_recovery_phrase)
                    .desired_rows(4)
                    .desired_width(f32::INFINITY)
                    .hint_text("optional recovery words"),
            );

            ui.add_space(12.0);
            if ui
                .add(primary_button("Open vault").min_size(egui::vec2(150.0, 40.0)))
                .clicked()
            {
                self.open_vault();
            }
        });
    }

    fn show_create_vault_card(&mut self, ui: &mut egui::Ui) {
        warm_panel().show(ui, |ui| {
            card_title(ui, "Create personal vault", "New file");
            ui.add_space(16.0);

            labelled_text(
                ui,
                "Vault path",
                &mut self.open_form.create_path,
                false,
                "personal.vault",
            );
            labelled_text(
                ui,
                "New password",
                &mut self.open_form.create_passphrase,
                true,
                "8+ characters",
            );
            field_label(ui, "Generated recovery phrase");
            let mut recovery_preview = self.open_form.create_recovery_phrase.clone();
            ui.add(
                TextEdit::multiline(&mut recovery_preview)
                    .desired_rows(3)
                    .desired_width(f32::INFINITY)
                    .interactive(false),
            );

            ui.add_space(12.0);
            ui.horizontal(|ui| {
                if ui
                    .add(secondary_button("Generate phrase").min_size(egui::vec2(138.0, 40.0)))
                    .clicked()
                {
                    self.generate_create_recovery_phrase();
                }
                if ui
                    .add(secondary_button("Copy phrase").min_size(egui::vec2(112.0, 40.0)))
                    .clicked()
                {
                    ui.output_mut(|output| {
                        output.copied_text = self.open_form.create_recovery_phrase.clone();
                    });
                    self.status = String::from("Copied recovery phrase.");
                }
                if ui
                    .add(primary_button("Create vault").min_size(egui::vec2(132.0, 40.0)))
                    .clicked()
                {
                    self.create_vault();
                }
            });
        });
    }

    fn show_restore_vault_card(&mut self, ui: &mut egui::Ui) {
        panel_frame().show(ui, |ui| {
            card_title(ui, "Restore vault", "Known phrase");
            ui.add_space(16.0);

            labelled_text(
                ui,
                "Restore path",
                &mut self.open_form.restore_path,
                false,
                "personal.vault",
            );
            labelled_text(
                ui,
                "Vault password",
                &mut self.open_form.restore_passphrase,
                true,
                "8+ characters",
            );
            field_label(ui, "Recovery phrase");
            ui.add(
                TextEdit::multiline(&mut self.open_form.restore_recovery_phrase)
                    .desired_rows(5)
                    .desired_width(f32::INFINITY)
                    .hint_text("twelve or more recovery words"),
            );

            ui.add_space(12.0);
            if ui
                .add(primary_button("Restore vault").min_size(egui::vec2(150.0, 40.0)))
                .clicked()
            {
                self.restore_vault();
            }
        });
    }

    fn show_vault(&mut self, ctx: &egui::Context) {
        self.show_sidebar(ctx);

        egui::CentralPanel::default()
            .frame(Frame::none().fill(APP_BG).inner_margin(Margin::same(24.0)))
            .show(ctx, |ui| match self.tab {
                VaultTab::Items => self.show_items(ui),
                VaultTab::AddItem => self.show_add_item(ui),
                VaultTab::Wallet => self.show_wallet(ui),
            });
    }

    fn show_sidebar(&mut self, ctx: &egui::Context) {
        let (login_count, ssh_count, passkey_count, wallet_count, vault_name) =
            self.vault.as_ref().map_or_else(
                || (0, 0, 0, 0, String::from("personal.vault")),
                |vault| {
                    let vault_name = Path::new(&vault.path)
                        .file_name()
                        .and_then(|name| name.to_str())
                        .unwrap_or("personal.vault")
                        .to_owned();
                    (
                        vault.items.len(),
                        vault.ssh_keys.len(),
                        vault.passkeys.len(),
                        vault.wallet_accounts.len(),
                        vault_name,
                    )
                },
            );
        let item_count = login_count + ssh_count + passkey_count;
        let favorites_count = self.collection_count(ItemCollection::Favorites);
        let recent_count = self.collection_count(ItemCollection::Recent);
        let trash_count = self.collection_count(ItemCollection::Trash);

        egui::SidePanel::left("vault_sidebar")
            .resizable(false)
            .exact_width(304.0)
            .frame(app_sidebar_frame())
            .show(ctx, |ui| {
                brand_header(ui);
                ui.add_space(24.0);

                self.sidebar_collection_item(
                    ui,
                    IconKind::Grid,
                    "All Items",
                    &item_count.to_string(),
                    ItemCollection::AllItems,
                );
                self.sidebar_collection_item(
                    ui,
                    IconKind::Star,
                    "Favorites",
                    &favorites_count.to_string(),
                    ItemCollection::Favorites,
                );
                self.sidebar_collection_item(
                    ui,
                    IconKind::Clock,
                    "Recent",
                    &recent_count.to_string(),
                    ItemCollection::Recent,
                );
                self.sidebar_collection_item(
                    ui,
                    IconKind::Trash,
                    "Trash",
                    &trash_count.to_string(),
                    ItemCollection::Trash,
                );

                ui.add_space(22.0);
                sidebar_heading(ui, "CATEGORIES");
                self.sidebar_collection_item(
                    ui,
                    IconKind::Login,
                    "Logins",
                    &login_count.to_string(),
                    ItemCollection::Category(CategoryKind::Logins),
                );
                self.sidebar_collection_item(
                    ui,
                    IconKind::Card,
                    "Credit Cards",
                    "0",
                    ItemCollection::Category(CategoryKind::CreditCards),
                );
                self.sidebar_collection_item(
                    ui,
                    IconKind::Note,
                    "Secure Notes",
                    "0",
                    ItemCollection::Category(CategoryKind::SecureNotes),
                );
                self.sidebar_collection_item(
                    ui,
                    IconKind::User,
                    "Identities",
                    "0",
                    ItemCollection::Category(CategoryKind::Identities),
                );
                self.sidebar_collection_item(
                    ui,
                    IconKind::Key,
                    "Passwords",
                    &login_count.to_string(),
                    ItemCollection::Category(CategoryKind::Passwords),
                );
                self.sidebar_collection_item(
                    ui,
                    IconKind::Ssh,
                    "SSH Keys",
                    &ssh_count.to_string(),
                    ItemCollection::Category(CategoryKind::SshKeys),
                );
                self.sidebar_collection_item(
                    ui,
                    IconKind::Passkey,
                    "Passkeys",
                    &passkey_count.to_string(),
                    ItemCollection::Category(CategoryKind::Passkeys),
                );

                ui.add_space(22.0);
                sidebar_heading(ui, "FOLDERS");
                self.sidebar_collection_item(
                    ui,
                    IconKind::Folder,
                    "Personal",
                    &item_count.to_string(),
                    ItemCollection::Folder(FolderKind::Personal),
                );
                self.sidebar_collection_item(
                    ui,
                    IconKind::Folder,
                    "Work",
                    "0",
                    ItemCollection::Folder(FolderKind::Work),
                );
                sidebar_tab_item(
                    ui,
                    &mut self.tab,
                    VaultTab::Wallet,
                    IconKind::Wallet,
                    "Wallet",
                    &wallet_count.to_string(),
                );

                ui.with_layout(egui::Layout::bottom_up(egui::Align::Min), |ui| {
                    if ui
                        .add(sidebar_button("Lock vault").min_size(egui::vec2(236.0, 38.0)))
                        .clicked()
                    {
                        self.lock_vault();
                    }

                    ui.add_space(12.0);
                    user_footer(ui, &vault_name);
                    ui.add_space(18.0);
                    security_score_card(ui);
                });
            });
    }

    fn sidebar_collection_item(
        &mut self,
        ui: &mut egui::Ui,
        icon: IconKind,
        label: &str,
        count: &str,
        collection: ItemCollection,
    ) {
        let selected = self.tab == VaultTab::Items && self.collection == collection;
        if sidebar_row(ui, icon, label, count, selected).clicked() {
            self.select_collection(collection);
        }
    }

    fn show_items(&mut self, ui: &mut egui::Ui) {
        if self.vault.is_none() {
            return;
        };

        let filtered_items = self.filtered_items();
        if self.selected_item.is_none_or(|selection| {
            !filtered_items
                .iter()
                .any(|item| item.selection() == selection)
        }) {
            self.selected_item = filtered_items.first().map(DisplayItem::selection);
            self.details_menu_for = None;
        }

        ui.vertical(|ui| {
            ui.horizontal(|ui| {
                search_box(ui, &mut self.item_filter, 512.0);
                ui.add_space(10.0);
                if ui
                    .add(primary_button("+  New Item").min_size(egui::vec2(132.0, 46.0)))
                    .clicked()
                {
                    self.tab = VaultTab::AddItem;
                }
            });

            ui.add_space(22.0);
            ui.horizontal_top(|ui| {
                ui.vertical(|ui| {
                    ui.set_width(518.0);
                    ui.horizontal(|ui| {
                        ui.vertical(|ui| {
                            ui.label(
                                RichText::new(self.collection.title())
                                    .size(20.0)
                                    .strong()
                                    .color(TEXT),
                            );
                            ui.label(
                                RichText::new(format!("{} items", filtered_items.len()))
                                    .color(MUTED),
                            );
                        });
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if toolbar_button(ui, IconKind::Sort, self.sort_mode.label()).clicked()
                            {
                                self.cycle_sort_mode();
                            }
                            if toolbar_button(ui, IconKind::Filter, "Filter").clicked() {
                                self.filters_visible = !self.filters_visible;
                                self.status = if self.filters_visible {
                                    String::from("Filters are visible.")
                                } else {
                                    String::from("Filters are hidden.")
                                };
                            }
                        });
                    });
                    ui.add_space(16.0);

                    if self.filters_visible {
                        self.show_filter_controls(ui);
                        ui.add_space(12.0);
                    }

                    if filtered_items.is_empty() {
                        empty_state(ui, self.collection.empty_message());
                    } else {
                        egui::ScrollArea::vertical()
                            .auto_shrink([false, false])
                            .show(ui, |ui| {
                                for item in filtered_items {
                                    let selection = item.selection();
                                    let selected = self.selected_item == Some(selection);
                                    let favorite = self.favorite_items.contains(&selection);
                                    let trashed = self.trashed_items.contains(&selection);
                                    if item_row(ui, &item, selected, favorite, trashed) {
                                        self.selected_item = Some(selection);
                                        self.details_menu_for = None;
                                        self.record_recent(selection);
                                        self.status = format!("Selected {}.", item.title());
                                    }
                                    ui.add_space(10.0);
                                }
                            });
                    }
                });

                ui.add_space(24.0);

                ui.vertical(|ui| {
                    ui.set_min_width(520.0);
                    match self.selected_display_item() {
                        Some(DisplayItem::Login(index, item)) => {
                            self.login_item_details(ui, SelectedItem::Login(index), &item);
                        }
                        Some(DisplayItem::SshKey(index, item)) => {
                            self.ssh_key_details(ui, SelectedItem::SshKey(index), &item);
                        }
                        Some(DisplayItem::Passkey(index, item)) => {
                            self.passkey_details(ui, SelectedItem::Passkey(index), &item);
                        }
                        None => detail_empty_state(ui),
                    }
                });
            });
        });
    }

    fn show_filter_controls(&mut self, ui: &mut egui::Ui) {
        soft_frame().show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.checkbox(&mut self.filter_logins, "Logins");
                ui.checkbox(&mut self.filter_ssh_keys, "SSH keys");
                ui.checkbox(&mut self.filter_passkeys, "Passkeys");
                if ui.add(secondary_button("Reset filters")).clicked() {
                    self.filter_logins = true;
                    self.filter_ssh_keys = true;
                    self.filter_passkeys = true;
                    self.status = String::from("Filters reset.");
                }
            });
        });
    }

    fn selected_display_item(&self) -> Option<DisplayItem> {
        let vault = self.vault.as_ref()?;
        match self.selected_item? {
            SelectedItem::Login(index) => vault
                .items
                .get(index)
                .cloned()
                .map(|item| DisplayItem::Login(index, item)),
            SelectedItem::SshKey(index) => vault
                .ssh_keys
                .get(index)
                .cloned()
                .map(|item| DisplayItem::SshKey(index, item)),
            SelectedItem::Passkey(index) => vault
                .passkeys
                .get(index)
                .cloned()
                .map(|item| DisplayItem::Passkey(index, item)),
        }
    }

    fn show_add_item(&mut self, ui: &mut egui::Ui) {
        page_title(ui, "Add item", "vault item");
        ui.add_space(16.0);

        ui.horizontal(|ui| {
            ui.selectable_value(&mut self.add_item_kind, AddItemKind::Login, "Login");
            ui.selectable_value(&mut self.add_item_kind, AddItemKind::SshKey, "SSH key");
            ui.selectable_value(&mut self.add_item_kind, AddItemKind::Passkey, "Passkey");
        });
        ui.add_space(16.0);

        match self.add_item_kind {
            AddItemKind::Login => self.show_add_login(ui),
            AddItemKind::SshKey => self.show_add_ssh_key(ui),
            AddItemKind::Passkey => self.show_add_passkey(ui),
        }
    }

    fn show_add_login(&mut self, ui: &mut egui::Ui) {
        ui.columns(2, |columns| {
            columns[0].set_min_width(600.0);
            panel_frame().show(&mut columns[0], |ui| {
                card_title(ui, "Login details", "Vault item");
                ui.add_space(14.0);
                egui::Grid::new("add_login_grid")
                    .num_columns(2)
                    .spacing([18.0, 13.0])
                    .show(ui, |ui| {
                        field_label(ui, "Title");
                        ui.add(
                            TextEdit::singleline(&mut self.login_form.title)
                                .hint_text("GitHub")
                                .desired_width(430.0),
                        );
                        ui.end_row();

                        field_label(ui, "Username");
                        ui.add(
                            TextEdit::singleline(&mut self.login_form.username)
                                .hint_text("name@example.com")
                                .desired_width(430.0),
                        );
                        ui.end_row();

                        field_label(ui, "URL");
                        ui.add(
                            TextEdit::singleline(&mut self.login_form.url)
                                .hint_text("https://github.com")
                                .desired_width(430.0),
                        );
                        ui.end_row();

                        field_label(ui, "Password type");
                        ui.horizontal(|ui| {
                            ui.selectable_value(
                                &mut self.login_form.password_kind,
                                PasswordKind::MnemonicDerived,
                                "Mnemonic derived",
                            );
                            ui.selectable_value(
                                &mut self.login_form.password_kind,
                                PasswordKind::UserInput,
                                "User input",
                            );
                        });
                        ui.end_row();

                        match self.login_form.password_kind {
                            PasswordKind::MnemonicDerived => {
                                field_label(ui, "Password length");
                                ui.add(
                                    egui::DragValue::new(&mut self.login_form.password_length)
                                        .range(16..=64)
                                        .speed(1),
                                );
                                ui.end_row();

                                field_label(ui, "Symbols");
                                ui.checkbox(
                                    &mut self.login_form.include_symbols,
                                    "Include symbols",
                                );
                                ui.end_row();
                            }
                            PasswordKind::UserInput => {
                                field_label(ui, "Password");
                                ui.add(
                                    TextEdit::singleline(&mut self.login_form.user_password)
                                        .password(true)
                                        .hint_text("saved password")
                                        .desired_width(430.0),
                                );
                                ui.end_row();
                            }
                        }

                        field_label(ui, "2FA secret");
                        ui.add(
                            TextEdit::singleline(&mut self.login_form.totp_secret)
                                .password(true)
                                .hint_text("base32 secret or otpauth:// URL")
                                .desired_width(430.0),
                        );
                        ui.end_row();

                        field_label(ui, "Notes");
                        ui.add(
                            TextEdit::multiline(&mut self.login_form.notes)
                                .desired_rows(5)
                                .desired_width(430.0),
                        );
                        ui.end_row();
                    });

                ui.add_space(18.0);
                if ui
                    .add(primary_button("Add login item").min_size(egui::vec2(158.0, 38.0)))
                    .clicked()
                {
                    self.add_login();
                }
            });

            warm_panel().show(&mut columns[1], |ui| {
                card_title(ui, "Password", "Local preview");
                ui.add_space(14.0);
                policy_line(ui, "Type", self.login_form.password_kind.label());
                if self.login_form.password_kind == PasswordKind::MnemonicDerived {
                    policy_line(
                        ui,
                        "Length",
                        &format!("{} characters", self.login_form.password_length),
                    );
                    policy_line(
                        ui,
                        "Alphabet",
                        if self.login_form.include_symbols {
                            "Letters, numbers, symbols"
                        } else {
                            "Letters and numbers"
                        },
                    );
                    if let Some(vault) = self.vault.as_ref() {
                        policy_line(ui, "Password path", &vault.next_password_path());
                    }
                }
                policy_line(ui, "Persistence", "Stored after Add login item");
                ui.add_space(12.0);
                ui.label(
                    RichText::new("Password material stays inside the encrypted vault.")
                        .color(GOLD_TEXT),
                );
            });
        });
    }

    fn show_add_ssh_key(&mut self, ui: &mut egui::Ui) {
        if self.ssh_key_form.derivation_path.trim().is_empty() {
            if let Some(vault) = self.vault.as_ref() {
                self.ssh_key_form.derivation_path = vault.next_ssh_derivation_path();
            }
        }

        ui.columns(2, |columns| {
            columns[0].set_min_width(600.0);
            panel_frame().show(&mut columns[0], |ui| {
                card_title(ui, "SSH key", "Agent identity");
                ui.add_space(14.0);
                egui::Grid::new("add_ssh_key_grid")
                    .num_columns(2)
                    .spacing([18.0, 13.0])
                    .show(ui, |ui| {
                        field_label(ui, "Label");
                        ui.add(
                            TextEdit::singleline(&mut self.ssh_key_form.label)
                                .hint_text("GitHub SSH")
                                .desired_width(430.0),
                        );
                        ui.end_row();

                        field_label(ui, "Derivation path");
                        ui.add(
                            TextEdit::singleline(&mut self.ssh_key_form.derivation_path)
                                .hint_text("m/101010'/0'")
                                .desired_width(430.0),
                        );
                        ui.end_row();

                        field_label(ui, "Comment");
                        ui.add(
                            TextEdit::singleline(&mut self.ssh_key_form.comment)
                                .hint_text("mlocker")
                                .desired_width(430.0),
                        );
                        ui.end_row();
                    });

                ui.add_space(18.0);
                if ui
                    .add(primary_button("Add SSH key").min_size(egui::vec2(142.0, 38.0)))
                    .clicked()
                {
                    self.add_ssh_key();
                }
            });

            warm_panel().show(&mut columns[1], |ui| {
                card_title(ui, "SSH agent", "OpenSSH");
                ui.add_space(14.0);
                policy_line(ui, "Key type", "ed25519");
                policy_line(ui, "Storage", "Public metadata only");
                policy_line(ui, "Signing", "Agent derives from unlocked vault");
                ui.add_space(12.0);
                ui.label(
                    RichText::new("Start the CLI ssh-agent and set SSH_AUTH_SOCK for ssh.")
                        .color(GOLD_TEXT),
                );
            });
        });
    }

    fn show_add_passkey(&mut self, ui: &mut egui::Ui) {
        ui.columns(2, |columns| {
            columns[0].set_min_width(600.0);
            panel_frame().show(&mut columns[0], |ui| {
                card_title(ui, "Passkey", "WebAuthn");
                ui.add_space(14.0);
                egui::Grid::new("add_passkey_grid")
                    .num_columns(2)
                    .spacing([18.0, 13.0])
                    .show(ui, |ui| {
                        field_label(ui, "Label");
                        ui.add(
                            TextEdit::singleline(&mut self.passkey_form.label)
                                .hint_text("GitHub Passkey")
                                .desired_width(430.0),
                        );
                        ui.end_row();

                        field_label(ui, "RP ID");
                        ui.add(
                            TextEdit::singleline(&mut self.passkey_form.relying_party_id)
                                .hint_text("github.com")
                                .desired_width(430.0),
                        );
                        ui.end_row();

                        field_label(ui, "Username");
                        ui.add(
                            TextEdit::singleline(&mut self.passkey_form.username)
                                .hint_text("name@example.com")
                                .desired_width(430.0),
                        );
                        ui.end_row();

                        field_label(ui, "Notes");
                        ui.add(
                            TextEdit::multiline(&mut self.passkey_form.notes)
                                .desired_rows(5)
                                .desired_width(430.0),
                        );
                        ui.end_row();
                    });

                ui.add_space(18.0);
                if ui
                    .add(primary_button("Add passkey").min_size(egui::vec2(142.0, 38.0)))
                    .clicked()
                {
                    self.add_passkey();
                }
            });

            warm_panel().show(&mut columns[1], |ui| {
                card_title(ui, "Credential", "MVP");
                ui.add_space(14.0);
                policy_line(ui, "Algorithm", "EdDSA");
                policy_line(ui, "Storage", "Encrypted vault metadata");
                policy_line(ui, "Browser flow", "WebAuthn mediation pending");
                ui.add_space(12.0);
                ui.label(
                    RichText::new("Credential material is derived while the vault is unlocked.")
                        .color(GOLD_TEXT),
                );
            });
        });
    }

    fn show_wallet(&mut self, ui: &mut egui::Ui) {
        let Some(vault) = self.vault.as_ref() else {
            return;
        };

        page_title(
            ui,
            "Wallet",
            &format!("fingerprint {}", fingerprint(&vault.seed)),
        );
        ui.add_space(16.0);

        panel_frame().show(ui, |ui| {
            ui.horizontal(|ui| {
                card_title(ui, "Derived accounts", "Preview");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    stat_badge(ui, &format!("{} accounts", vault.wallet_accounts.len()));
                });
            });
            ui.add_space(14.0);
            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    for account in &vault.wallet_accounts {
                        wallet_row(ui, account);
                        ui.add_space(8.0);
                    }
                });
        });
    }
}

impl DisplayItem {
    fn selection(&self) -> SelectedItem {
        match self {
            DisplayItem::Login(index, _) => SelectedItem::Login(*index),
            DisplayItem::SshKey(index, _) => SelectedItem::SshKey(*index),
            DisplayItem::Passkey(index, _) => SelectedItem::Passkey(*index),
        }
    }

    fn title(&self) -> &str {
        match self {
            DisplayItem::Login(_, item) => &item.title,
            DisplayItem::SshKey(_, item) => &item.label,
            DisplayItem::Passkey(_, item) => &item.label,
        }
    }

    fn subtitle(&self) -> &str {
        match self {
            DisplayItem::Login(_, item) => &item.username,
            DisplayItem::SshKey(_, item) => &item.derivation_path,
            DisplayItem::Passkey(_, item) => &item.relying_party_id,
        }
    }

    fn id(&self) -> &str {
        match self {
            DisplayItem::Login(_, item) => &item.id,
            DisplayItem::SshKey(_, item) => &item.id,
            DisplayItem::Passkey(_, item) => &item.id,
        }
    }

    fn type_rank(&self) -> usize {
        match self {
            DisplayItem::Login(_, _) => 0,
            DisplayItem::SshKey(_, _) => 1,
            DisplayItem::Passkey(_, _) => 2,
        }
    }

    fn matches_category(&self, category: CategoryKind) -> bool {
        match category {
            CategoryKind::Logins | CategoryKind::Passwords => {
                matches!(self, DisplayItem::Login(_, _))
            }
            CategoryKind::SshKeys => matches!(self, DisplayItem::SshKey(_, _)),
            CategoryKind::Passkeys => matches!(self, DisplayItem::Passkey(_, _)),
            CategoryKind::CreditCards | CategoryKind::SecureNotes | CategoryKind::Identities => {
                false
            }
        }
    }

    fn matches_search(&self, filter: &str) -> bool {
        match self {
            DisplayItem::Login(_, item) => {
                item.title.to_lowercase().contains(filter)
                    || item.username.to_lowercase().contains(filter)
                    || item.url.to_lowercase().contains(filter)
            }
            DisplayItem::SshKey(_, item) => {
                item.label.to_lowercase().contains(filter)
                    || item.derivation_path.to_lowercase().contains(filter)
                    || item.comment.to_lowercase().contains(filter)
            }
            DisplayItem::Passkey(_, item) => {
                item.label.to_lowercase().contains(filter)
                    || item.relying_party_id.to_lowercase().contains(filter)
                    || item.username.to_lowercase().contains(filter)
            }
        }
    }
}

impl ItemCollection {
    fn title(self) -> &'static str {
        match self {
            ItemCollection::AllItems => "All Items",
            ItemCollection::Favorites => "Favorites",
            ItemCollection::Recent => "Recent",
            ItemCollection::Trash => "Trash",
            ItemCollection::Category(category) => category.title(),
            ItemCollection::Folder(folder) => folder.title(),
        }
    }

    fn empty_message(self) -> &'static str {
        match self {
            ItemCollection::AllItems => "No items yet.",
            ItemCollection::Favorites => "No favorite items.",
            ItemCollection::Recent => "No recently opened items.",
            ItemCollection::Trash => "Trash is empty.",
            ItemCollection::Category(category) => category.empty_message(),
            ItemCollection::Folder(folder) => folder.empty_message(),
        }
    }
}

impl CategoryKind {
    fn title(self) -> &'static str {
        match self {
            CategoryKind::Logins => "Logins",
            CategoryKind::CreditCards => "Credit Cards",
            CategoryKind::SecureNotes => "Secure Notes",
            CategoryKind::Identities => "Identities",
            CategoryKind::Passwords => "Passwords",
            CategoryKind::SshKeys => "SSH Keys",
            CategoryKind::Passkeys => "Passkeys",
        }
    }

    fn empty_message(self) -> &'static str {
        match self {
            CategoryKind::CreditCards => "No credit cards saved yet.",
            CategoryKind::SecureNotes => "No secure notes saved yet.",
            CategoryKind::Identities => "No identities saved yet.",
            _ => "No matching items in this category.",
        }
    }
}

impl FolderKind {
    fn title(self) -> &'static str {
        match self {
            FolderKind::Personal => "Personal",
            FolderKind::Work => "Work",
        }
    }

    fn empty_message(self) -> &'static str {
        match self {
            FolderKind::Personal => "No personal items.",
            FolderKind::Work => "No work items.",
        }
    }
}

impl SortMode {
    fn label(self) -> &'static str {
        match self {
            SortMode::TitleAsc => "A-Z",
            SortMode::TitleDesc => "Z-A",
            SortMode::Type => "Type",
        }
    }
}

impl eframe::App for MlockerDesktop {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        match self.screen {
            Screen::OpenVault => {
                egui::CentralPanel::default()
                    .frame(Frame::none().fill(APP_BG).inner_margin(Margin::same(28.0)))
                    .show(ctx, |ui| {
                        self.show_open_screen(ui);
                    });
            }
            Screen::Vault => self.show_vault(ctx),
        }
    }
}

fn apply_theme(ctx: &egui::Context) {
    let mut style = (*ctx.style()).clone();
    style.spacing.item_spacing = egui::vec2(10.0, 8.0);
    style.spacing.button_padding = egui::vec2(12.0, 7.0);
    style.spacing.window_margin = Margin::same(18.0);
    style.visuals = egui::Visuals::light();
    style.visuals.panel_fill = APP_BG;
    style.visuals.window_fill = SURFACE;
    style.visuals.extreme_bg_color = SURFACE;
    style.visuals.faint_bg_color = SURFACE_ALT;
    style.visuals.code_bg_color = Color32::from_rgb(239, 244, 249);
    style.visuals.warn_fg_color = WARNING_TEXT;
    style.visuals.selection.bg_fill = ACCENT;
    style.visuals.selection.stroke = Stroke::new(1.0, Color32::WHITE);
    style.visuals.widgets.noninteractive.fg_stroke = Stroke::new(1.0, TEXT);
    style.visuals.widgets.inactive.rounding = Rounding::same(6.0);
    style.visuals.widgets.hovered.rounding = Rounding::same(6.0);
    style.visuals.widgets.active.rounding = Rounding::same(6.0);
    style.visuals.widgets.inactive.bg_stroke = Stroke::new(1.0, BORDER);
    style.visuals.widgets.hovered.bg_stroke = Stroke::new(1.0, BORDER_STRONG);
    style.visuals.widgets.active.bg_stroke = Stroke::new(1.0, ACCENT);
    style.visuals.widgets.inactive.weak_bg_fill = SURFACE;
    style.visuals.widgets.hovered.weak_bg_fill = ACCENT_SOFT;
    style.visuals.widgets.active.weak_bg_fill = ACCENT_SOFT;
    ctx.set_style(style);
}

fn app_sidebar_frame() -> Frame {
    Frame::none()
        .fill(SIDEBAR)
        .stroke(Stroke::new(1.0, BORDER))
        .inner_margin(Margin::symmetric(18.0, 22.0))
}

fn record_recent_item(recent_items: &mut Vec<SelectedItem>, selection: SelectedItem) {
    recent_items.retain(|item| *item != selection);
    recent_items.insert(0, selection);
    recent_items.truncate(24);
}

fn sort_display_items(items: &mut [DisplayItem], sort_mode: SortMode) {
    match sort_mode {
        SortMode::TitleAsc => items.sort_by_key(|item| item.title().to_lowercase()),
        SortMode::TitleDesc => {
            items.sort_by_key(|item| std::cmp::Reverse(item.title().to_lowercase()))
        }
        SortMode::Type => items.sort_by_key(|item| (item.type_rank(), item.title().to_lowercase())),
    }
}

fn panel_frame() -> Frame {
    Frame::none()
        .fill(SURFACE)
        .stroke(Stroke::new(1.0, BORDER))
        .rounding(12.0)
        .inner_margin(Margin::same(20.0))
}

fn soft_frame() -> Frame {
    Frame::none()
        .fill(SURFACE)
        .stroke(Stroke::new(1.0, BORDER))
        .rounding(10.0)
        .inner_margin(Margin::same(14.0))
}

fn warm_panel() -> Frame {
    Frame::none()
        .fill(SURFACE_WARM)
        .stroke(Stroke::new(1.0, Color32::from_rgb(226, 216, 255)))
        .rounding(12.0)
        .inner_margin(Margin::same(20.0))
}

fn primary_button(label: &str) -> egui::Button<'_> {
    egui::Button::new(RichText::new(label).strong().color(Color32::WHITE))
        .fill(ACCENT)
        .stroke(Stroke::new(1.0, ACCENT_DARK))
        .rounding(8.0)
}

fn secondary_button(label: &str) -> egui::Button<'_> {
    egui::Button::new(RichText::new(label).color(TEXT))
        .fill(SURFACE)
        .stroke(Stroke::new(1.0, BORDER_STRONG))
        .rounding(8.0)
}

fn sidebar_button(label: &str) -> egui::Button<'_> {
    egui::Button::new(RichText::new(label).strong().color(ACCENT_DARK))
        .fill(ACCENT_SOFT)
        .stroke(Stroke::new(1.0, Color32::from_rgb(223, 214, 255)))
        .rounding(8.0)
}

fn brand_header(ui: &mut egui::Ui) {
    ui.horizontal(|ui| {
        Frame::none()
            .fill(Color32::from_rgb(143, 111, 255))
            .rounding(9.0)
            .inner_margin(Margin::symmetric(10.0, 10.0))
            .show(ui, |ui| {
                draw_inline_icon(ui, IconKind::Lock, Color32::WHITE, 22.0);
            });
        ui.add_space(10.0);
        ui.label(RichText::new("Vault").size(22.0).strong().color(TEXT));
    });
}

fn setup_header(ui: &mut egui::Ui, path: &str) {
    ui.horizontal(|ui| {
        ui.vertical(|ui| {
            ui.label(
                RichText::new("Personal vault")
                    .size(28.0)
                    .strong()
                    .color(TEXT),
            );
            ui.label(RichText::new(path).color(MUTED));
        });
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            stat_badge(ui, "default");
        });
    });
}

fn status_banner(ui: &mut egui::Ui, status: &str) {
    Frame::none()
        .fill(SURFACE)
        .stroke(Stroke::new(1.0, BORDER))
        .rounding(8.0)
        .inner_margin(Margin::symmetric(12.0, 8.0))
        .show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new("Status").strong().color(TEXT));
                ui.label(RichText::new(status).color(MUTED));
            });
        });
}

fn sidebar_heading(ui: &mut egui::Ui, label: &str) {
    ui.label(
        RichText::new(label)
            .size(11.0)
            .strong()
            .color(SIDEBAR_MUTED),
    );
    ui.add_space(8.0);
}

fn sidebar_item(ui: &mut egui::Ui, label: &str, count: &str, selected: bool) {
    let icon = match label {
        "All Items" => IconKind::Grid,
        "Favorites" => IconKind::Star,
        "Recent" => IconKind::Clock,
        "Trash" => IconKind::Trash,
        "Logins" => IconKind::Login,
        "Secure Notes" => IconKind::Note,
        "Wallet" => IconKind::Wallet,
        _ => IconKind::Folder,
    };
    let _ = sidebar_row(ui, icon, label, count, selected);
}

fn sidebar_tab_item(
    ui: &mut egui::Ui,
    tab: &mut VaultTab,
    value: VaultTab,
    icon: IconKind,
    label: &str,
    count: &str,
) {
    let selected = *tab == value;
    if sidebar_row(ui, icon, label, count, selected).clicked() {
        *tab = value;
    }
}

fn sidebar_row(
    ui: &mut egui::Ui,
    icon: IconKind,
    label: &str,
    count: &str,
    selected: bool,
) -> egui::Response {
    let fill = if selected { ACCENT_SOFT } else { SIDEBAR };
    let icon_color = if selected { ACCENT } else { SIDEBAR_MUTED };
    let text_color = if selected { ACCENT_DARK } else { SIDEBAR_TEXT };
    let inner = Frame::none()
        .fill(fill)
        .rounding(8.0)
        .inner_margin(Margin::symmetric(10.0, 9.0))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                draw_inline_icon(ui, icon, icon_color, 18.0);
                ui.add_space(8.0);
                ui.label(RichText::new(label).color(text_color));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if selected {
                        Frame::none()
                            .fill(Color32::from_rgb(232, 223, 255))
                            .rounding(10.0)
                            .inner_margin(Margin::symmetric(7.0, 2.0))
                            .show(ui, |ui| {
                                ui.label(
                                    RichText::new(count).size(12.0).strong().color(ACCENT_DARK),
                                );
                            });
                    } else {
                        ui.label(RichText::new(count).color(SIDEBAR_MUTED));
                    }
                });
            });
        });
    let response = ui.interact(
        inner.response.rect,
        ui.make_persistent_id(("sidebar-row", label)),
        egui::Sense::click(),
    );
    ui.add_space(4.0);
    response
}

fn security_score_card(ui: &mut egui::Ui) {
    panel_frame().show(ui, |ui| {
        ui.horizontal(|ui| {
            draw_inline_icon(ui, IconKind::Shield, GREEN, 26.0);
            ui.add_space(8.0);
            ui.label(RichText::new("Security Score").strong().color(TEXT));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                Frame::none()
                    .fill(GREEN_SOFT)
                    .stroke(Stroke::new(1.0, Color32::from_rgb(129, 229, 178)))
                    .rounding(16.0)
                    .inner_margin(Margin::symmetric(9.0, 4.0))
                    .show(ui, |ui| {
                        ui.label(RichText::new("92").strong().color(GREEN));
                    });
            });
        });
        ui.add_space(10.0);
        ui.label(RichText::new("Excellent").strong().color(GREEN));
        ui.label(
            RichText::new("Your vault is in great shape.")
                .size(12.0)
                .color(MUTED),
        );
    });
}

fn user_footer(ui: &mut egui::Ui, vault_name: &str) {
    ui.horizontal(|ui| {
        Frame::none()
            .fill(Color32::from_rgb(167, 75, 212))
            .rounding(18.0)
            .inner_margin(Margin::symmetric(10.0, 7.0))
            .show(ui, |ui| {
                ui.label(RichText::new("M").strong().color(Color32::WHITE));
            });
        ui.add_space(8.0);
        ui.vertical(|ui| {
            ui.label(RichText::new("mlocker").strong().color(TEXT));
            ui.label(RichText::new(vault_name).size(12.0).color(MUTED));
        });
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            draw_inline_icon(ui, IconKind::Chevron, SIDEBAR_MUTED, 16.0);
        });
    });
}

fn page_title(ui: &mut egui::Ui, title: &str, meta: &str) {
    ui.horizontal(|ui| {
        ui.label(RichText::new(title).size(24.0).strong().color(TEXT));
        stat_badge(ui, meta);
    });
}

fn card_title(ui: &mut egui::Ui, title: &str, meta: &str) {
    ui.horizontal(|ui| {
        ui.label(RichText::new(title).size(18.0).strong().color(TEXT));
        stat_badge(ui, meta);
    });
}

fn stat_badge(ui: &mut egui::Ui, text: &str) {
    Frame::none()
        .fill(ACCENT_SOFT)
        .stroke(Stroke::new(1.0, Color32::from_rgb(224, 215, 255)))
        .rounding(12.0)
        .inner_margin(Margin::symmetric(10.0, 4.0))
        .show(ui, |ui| {
            ui.label(RichText::new(text).size(12.0).strong().color(ACCENT_DARK));
        });
}

fn field_label(ui: &mut egui::Ui, label: &str) {
    ui.label(RichText::new(label).strong().color(MUTED));
}

fn labelled_text(ui: &mut egui::Ui, label: &str, value: &mut String, password: bool, hint: &str) {
    field_label(ui, label);
    ui.add(
        TextEdit::singleline(value)
            .password(password)
            .hint_text(hint)
            .desired_width(f32::INFINITY),
    );
    ui.add_space(12.0);
}

fn policy_line(ui: &mut egui::Ui, label: &str, value: &str) {
    soft_frame().show(ui, |ui| {
        ui.horizontal(|ui| {
            ui.label(RichText::new(label).strong().color(TEXT));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.label(RichText::new(value).color(GOLD_TEXT));
            });
        });
    });
    ui.add_space(8.0);
}

fn search_box(ui: &mut egui::Ui, value: &mut String, width: f32) {
    Frame::none()
        .fill(SURFACE)
        .stroke(Stroke::new(1.0, BORDER))
        .rounding(10.0)
        .inner_margin(Margin::symmetric(14.0, 10.0))
        .show(ui, |ui| {
            ui.set_width(width);
            ui.horizontal(|ui| {
                draw_inline_icon(ui, IconKind::Search, MUTED, 18.0);
                ui.add(
                    TextEdit::singleline(value)
                        .hint_text("Search for items or folders")
                        .desired_width(width - 112.0),
                );
                Frame::none()
                    .fill(SURFACE_ALT)
                    .rounding(7.0)
                    .inner_margin(Margin::symmetric(7.0, 3.0))
                    .show(ui, |ui| {
                        ui.label(RichText::new("K").size(12.0).strong().color(MUTED));
                    });
            });
        });
}

fn toolbar_button(ui: &mut egui::Ui, icon: IconKind, label: &str) -> egui::Response {
    let inner = Frame::none()
        .fill(APP_BG)
        .rounding(8.0)
        .inner_margin(Margin::symmetric(8.0, 5.0))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                draw_inline_icon(ui, icon, MUTED, 16.0);
                ui.add_space(4.0);
                ui.label(RichText::new(label).color(TEXT));
            });
        });
    ui.interact(
        inner.response.rect,
        ui.make_persistent_id(("toolbar-button", label)),
        egui::Sense::click(),
    )
}

fn empty_state(ui: &mut egui::Ui, message: &str) {
    soft_frame().show(ui, |ui| {
        ui.set_min_height(180.0);
        ui.centered_and_justified(|ui| {
            ui.label(RichText::new(message).color(MUTED));
        });
    });
}

fn item_row(
    ui: &mut egui::Ui,
    item: &DisplayItem,
    selected: bool,
    favorite: bool,
    trashed: bool,
) -> bool {
    let fill = if selected {
        ACCENT_SOFT
    } else if trashed {
        Color32::from_rgb(250, 242, 242)
    } else {
        SURFACE
    };
    let inner = Frame::none()
        .fill(fill)
        .rounding(8.0)
        .inner_margin(Margin::symmetric(12.0, 10.0))
        .show(ui, |ui| {
            ui.set_min_height(50.0);
            ui.horizontal(|ui| {
                app_icon(ui, item.title());
                ui.add_space(10.0);
                ui.vertical(|ui| {
                    ui.label(RichText::new(item.title()).strong().color(TEXT));
                    ui.label(RichText::new(item.subtitle()).size(12.0).color(MUTED));
                });
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if trashed {
                        draw_inline_icon(ui, IconKind::Trash, WARNING_TEXT, 19.0);
                    } else {
                        draw_inline_icon(
                            ui,
                            IconKind::Star,
                            if favorite { ACCENT } else { SIDEBAR_MUTED },
                            19.0,
                        );
                    }
                });
            });
        });
    ui.interact(
        inner.response.rect,
        ui.make_persistent_id(("item-row", item.selection())),
        egui::Sense::click(),
    )
    .clicked()
}

fn app_icon(ui: &mut egui::Ui, title: &str) {
    app_icon_sized(ui, title, 42.0);
}

fn app_icon_large(ui: &mut egui::Ui, title: &str) {
    app_icon_sized(ui, title, 58.0);
}

fn app_icon_sized(ui: &mut egui::Ui, title: &str, size: f32) {
    let letter = title
        .chars()
        .next()
        .map(|ch| ch.to_ascii_uppercase())
        .unwrap_or('L');
    let (rect, _) = ui.allocate_exact_size(egui::vec2(size, size), egui::Sense::hover());
    ui.painter()
        .rect(rect, 10.0, SURFACE, Stroke::new(1.0, BORDER));
    ui.painter().text(
        rect.center(),
        egui::Align2::CENTER_CENTER,
        letter.to_string(),
        egui::FontId::proportional(size * 0.52),
        brand_color(title),
    );
}

fn brand_color(title: &str) -> Color32 {
    let title = title.to_ascii_lowercase();
    if title.contains("google") {
        Color32::from_rgb(66, 133, 244)
    } else if title.contains("github") {
        Color32::from_rgb(17, 24, 39)
    } else if title.contains("stripe") {
        Color32::from_rgb(99, 91, 255)
    } else if title.contains("amazon") {
        Color32::from_rgb(245, 158, 11)
    } else if title.contains("apple") {
        Color32::from_rgb(75, 85, 99)
    } else if title.contains("facebook") {
        Color32::from_rgb(24, 119, 242)
    } else {
        ACCENT
    }
}

fn draw_inline_icon(ui: &mut egui::Ui, kind: IconKind, color: Color32, size: f32) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(size, size), egui::Sense::hover());
    draw_icon(ui.painter(), rect.shrink(1.0), kind, color);
}

fn icon_button(ui: &mut egui::Ui, kind: IconKind, tooltip: &str) -> egui::Response {
    icon_button_colored(ui, kind, tooltip, MUTED)
}

fn icon_button_colored(
    ui: &mut egui::Ui,
    kind: IconKind,
    tooltip: &str,
    color: Color32,
) -> egui::Response {
    let (rect, response) = ui.allocate_exact_size(egui::vec2(32.0, 32.0), egui::Sense::click());
    let fill = if response.hovered() {
        SURFACE_ALT
    } else {
        SURFACE
    };
    let stroke = if response.hovered() {
        Stroke::new(1.0, BORDER_STRONG)
    } else {
        Stroke::new(1.0, Color32::TRANSPARENT)
    };
    ui.painter().rect(rect, 8.0, fill, stroke);
    draw_icon(ui.painter(), rect.shrink(8.0), kind, color);
    response.on_hover_text(tooltip)
}

fn draw_icon(painter: &egui::Painter, rect: egui::Rect, kind: IconKind, color: Color32) {
    let stroke = Stroke::new((rect.width() / 12.0).clamp(1.3, 2.0), color);
    let thin = Stroke::new((rect.width() / 16.0).clamp(1.0, 1.5), color);
    let center = rect.center();
    let left = rect.left();
    let right = rect.right();
    let top = rect.top();
    let bottom = rect.bottom();
    let width = rect.width();
    let height = rect.height();

    match kind {
        IconKind::Lock => {
            let body = egui::Rect::from_min_max(
                egui::pos2(left + width * 0.18, top + height * 0.45),
                egui::pos2(right - width * 0.18, bottom - height * 0.08),
            );
            painter.rect_stroke(body, 2.0, stroke);
            painter.line_segment(
                [
                    egui::pos2(left + width * 0.30, top + height * 0.46),
                    egui::pos2(left + width * 0.30, top + height * 0.32),
                ],
                stroke,
            );
            painter.line_segment(
                [
                    egui::pos2(left + width * 0.70, top + height * 0.46),
                    egui::pos2(left + width * 0.70, top + height * 0.32),
                ],
                stroke,
            );
            painter.line_segment(
                [
                    egui::pos2(left + width * 0.30, top + height * 0.32),
                    egui::pos2(left + width * 0.70, top + height * 0.32),
                ],
                stroke,
            );
        }
        IconKind::Grid => {
            for row in 0..2 {
                for column in 0..2 {
                    let x = left + width * (0.12 + column as f32 * 0.46);
                    let y = top + height * (0.12 + row as f32 * 0.46);
                    let tile = egui::Rect::from_min_size(
                        egui::pos2(x, y),
                        egui::vec2(width * 0.30, height * 0.30),
                    );
                    painter.rect_stroke(tile, 2.0, stroke);
                }
            }
        }
        IconKind::Star => {
            let mut points = Vec::with_capacity(11);
            for index in 0..10 {
                let radius = if index % 2 == 0 {
                    width * 0.46
                } else {
                    width * 0.20
                };
                let angle =
                    -std::f32::consts::FRAC_PI_2 + index as f32 * std::f32::consts::PI / 5.0;
                points.push(egui::pos2(
                    center.x + radius * angle.cos(),
                    center.y + radius * angle.sin(),
                ));
            }
            points.push(points[0]);
            painter.add(egui::Shape::line(points, stroke));
        }
        IconKind::Clock => {
            painter.circle_stroke(center, width * 0.43, stroke);
            painter.line_segment([center, egui::pos2(center.x, top + height * 0.25)], stroke);
            painter.line_segment([center, egui::pos2(right - width * 0.24, center.y)], stroke);
        }
        IconKind::Trash => {
            painter.line_segment(
                [
                    egui::pos2(left + width * 0.22, top + height * 0.30),
                    egui::pos2(right - width * 0.22, top + height * 0.30),
                ],
                stroke,
            );
            painter.rect_stroke(
                egui::Rect::from_min_max(
                    egui::pos2(left + width * 0.28, top + height * 0.34),
                    egui::pos2(right - width * 0.28, bottom - height * 0.10),
                ),
                1.5,
                stroke,
            );
            painter.line_segment(
                [
                    egui::pos2(center.x - width * 0.14, top + height * 0.20),
                    egui::pos2(center.x + width * 0.14, top + height * 0.20),
                ],
                stroke,
            );
        }
        IconKind::Login | IconKind::Card | IconKind::Wallet => {
            painter.rect_stroke(rect.shrink(width * 0.12), 2.0, stroke);
            painter.line_segment(
                [
                    egui::pos2(left + width * 0.18, center.y),
                    egui::pos2(right - width * 0.18, center.y),
                ],
                thin,
            );
        }
        IconKind::Note => {
            painter.rect_stroke(rect.shrink(width * 0.14), 2.0, stroke);
            painter.line_segment(
                [
                    egui::pos2(right - width * 0.30, top + height * 0.14),
                    egui::pos2(right - width * 0.14, top + height * 0.30),
                ],
                thin,
            );
            painter.line_segment(
                [
                    egui::pos2(left + width * 0.26, center.y),
                    egui::pos2(right - width * 0.26, center.y),
                ],
                thin,
            );
        }
        IconKind::User => {
            painter.circle_stroke(
                egui::pos2(center.x, top + height * 0.32),
                width * 0.16,
                stroke,
            );
            painter.line_segment(
                [
                    egui::pos2(left + width * 0.24, bottom - height * 0.18),
                    egui::pos2(right - width * 0.24, bottom - height * 0.18),
                ],
                stroke,
            );
        }
        IconKind::Key | IconKind::Ssh | IconKind::Passkey => {
            painter.circle_stroke(
                egui::pos2(left + width * 0.34, center.y),
                width * 0.18,
                stroke,
            );
            painter.line_segment(
                [
                    egui::pos2(left + width * 0.50, center.y),
                    egui::pos2(right - width * 0.12, center.y),
                ],
                stroke,
            );
            painter.line_segment(
                [
                    egui::pos2(right - width * 0.28, center.y),
                    egui::pos2(right - width * 0.28, bottom - height * 0.24),
                ],
                stroke,
            );
        }
        IconKind::Folder => {
            let points = vec![
                egui::pos2(left + width * 0.10, top + height * 0.30),
                egui::pos2(left + width * 0.36, top + height * 0.30),
                egui::pos2(left + width * 0.46, top + height * 0.42),
                egui::pos2(right - width * 0.10, top + height * 0.42),
                egui::pos2(right - width * 0.10, bottom - height * 0.14),
                egui::pos2(left + width * 0.10, bottom - height * 0.14),
                egui::pos2(left + width * 0.10, top + height * 0.30),
            ];
            painter.add(egui::Shape::line(points, stroke));
        }
        IconKind::Search => {
            painter.circle_stroke(
                egui::pos2(center.x - width * 0.08, center.y - height * 0.08),
                width * 0.28,
                stroke,
            );
            painter.line_segment(
                [
                    egui::pos2(center.x + width * 0.14, center.y + height * 0.14),
                    egui::pos2(right - width * 0.08, bottom - height * 0.08),
                ],
                stroke,
            );
        }
        IconKind::Filter => {
            for (index, scale) in [0.80_f32, 0.56, 0.32].iter().enumerate() {
                let y = top + height * (0.24 + index as f32 * 0.25);
                painter.line_segment(
                    [
                        egui::pos2(center.x - width * scale / 2.0, y),
                        egui::pos2(center.x + width * scale / 2.0, y),
                    ],
                    stroke,
                );
            }
        }
        IconKind::Sort => {
            painter.line_segment(
                [
                    egui::pos2(left + width * 0.32, bottom - height * 0.18),
                    egui::pos2(left + width * 0.32, top + height * 0.18),
                ],
                stroke,
            );
            painter.line_segment(
                [
                    egui::pos2(left + width * 0.22, top + height * 0.30),
                    egui::pos2(left + width * 0.32, top + height * 0.18),
                ],
                stroke,
            );
            painter.line_segment(
                [
                    egui::pos2(left + width * 0.42, top + height * 0.30),
                    egui::pos2(left + width * 0.32, top + height * 0.18),
                ],
                stroke,
            );
            painter.line_segment(
                [
                    egui::pos2(right - width * 0.32, top + height * 0.18),
                    egui::pos2(right - width * 0.32, bottom - height * 0.18),
                ],
                stroke,
            );
            painter.line_segment(
                [
                    egui::pos2(right - width * 0.42, bottom - height * 0.30),
                    egui::pos2(right - width * 0.32, bottom - height * 0.18),
                ],
                stroke,
            );
            painter.line_segment(
                [
                    egui::pos2(right - width * 0.22, bottom - height * 0.30),
                    egui::pos2(right - width * 0.32, bottom - height * 0.18),
                ],
                stroke,
            );
        }
        IconKind::Copy => {
            painter.rect_stroke(
                egui::Rect::from_min_max(
                    egui::pos2(left + width * 0.18, top + height * 0.22),
                    egui::pos2(right - width * 0.24, bottom - height * 0.16),
                ),
                2.0,
                stroke,
            );
            painter.rect_stroke(
                egui::Rect::from_min_max(
                    egui::pos2(left + width * 0.32, top + height * 0.10),
                    egui::pos2(right - width * 0.10, bottom - height * 0.30),
                ),
                2.0,
                thin,
            );
        }
        IconKind::Eye => {
            let points = vec![
                egui::pos2(left + width * 0.08, center.y),
                egui::pos2(center.x, top + height * 0.28),
                egui::pos2(right - width * 0.08, center.y),
                egui::pos2(center.x, bottom - height * 0.28),
                egui::pos2(left + width * 0.08, center.y),
            ];
            painter.add(egui::Shape::line(points, stroke));
            painter.circle_stroke(center, width * 0.12, stroke);
        }
        IconKind::Edit => {
            painter.line_segment(
                [
                    egui::pos2(left + width * 0.20, bottom - height * 0.18),
                    egui::pos2(right - width * 0.18, top + height * 0.20),
                ],
                stroke,
            );
            painter.line_segment(
                [
                    egui::pos2(left + width * 0.18, bottom - height * 0.18),
                    egui::pos2(left + width * 0.34, bottom - height * 0.14),
                ],
                stroke,
            );
        }
        IconKind::More => {
            for x in [0.25_f32, 0.50, 0.75] {
                painter.circle_filled(egui::pos2(left + width * x, center.y), width * 0.07, color);
            }
        }
        IconKind::Shield => {
            let points = vec![
                egui::pos2(center.x, top + height * 0.08),
                egui::pos2(right - width * 0.14, top + height * 0.22),
                egui::pos2(right - width * 0.20, bottom - height * 0.28),
                egui::pos2(center.x, bottom - height * 0.08),
                egui::pos2(left + width * 0.20, bottom - height * 0.28),
                egui::pos2(left + width * 0.14, top + height * 0.22),
            ];
            painter.add(egui::Shape::convex_polygon(
                points,
                Color32::TRANSPARENT,
                stroke,
            ));
            painter.line_segment(
                [
                    egui::pos2(left + width * 0.34, center.y),
                    egui::pos2(center.x - width * 0.04, bottom - height * 0.34),
                ],
                stroke,
            );
            painter.line_segment(
                [
                    egui::pos2(center.x - width * 0.04, bottom - height * 0.34),
                    egui::pos2(right - width * 0.28, top + height * 0.36),
                ],
                stroke,
            );
        }
        IconKind::Chevron => {
            painter.line_segment(
                [
                    egui::pos2(left + width * 0.22, top + height * 0.40),
                    egui::pos2(center.x, bottom - height * 0.34),
                ],
                stroke,
            );
            painter.line_segment(
                [
                    egui::pos2(center.x, bottom - height * 0.34),
                    egui::pos2(right - width * 0.22, top + height * 0.40),
                ],
                stroke,
            );
        }
    }
}

fn wallet_row(ui: &mut egui::Ui, account: &WalletAccount) {
    soft_frame().show(ui, |ui| {
        ui.horizontal(|ui| {
            ui.set_min_height(38.0);
            ui.vertical(|ui| {
                ui.label(RichText::new(&account.chain).strong().color(TEXT));
                ui.label(RichText::new(&account.path).size(12.0).color(MUTED));
            });
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if icon_button(ui, IconKind::Copy, "Copy address").clicked() {
                    ui.output_mut(|output| output.copied_text = account.address.clone());
                }
                ui.monospace(&account.address);
            });
        });
    });
}

impl MlockerDesktop {
    fn login_item_details(&mut self, ui: &mut egui::Ui, selection: SelectedItem, item: &LoginItem) {
        panel_frame().show(ui, |ui| {
            ui.set_min_height(640.0);
            ui.horizontal(|ui| {
                app_icon_large(ui, &item.title);
                ui.add_space(14.0);
                ui.vertical(|ui| {
                    ui.add_space(5.0);
                    ui.label(RichText::new(&item.title).size(22.0).strong().color(TEXT));
                    stat_badge(ui, "Login");
                });
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    self.detail_action_buttons(ui, selection);
                });
            });
            ui.add_space(20.0);
            self.detail_more_panel(ui, selection);

            detail_row(
                ui,
                (&item.id, "email"),
                "Email",
                &item.username,
                true,
                false,
            );
            password_detail_row(ui, (&item.id, "password"), &item.password);
            if let Some(secret) = &item.totp_secret {
                match mlocker_core::generate_totp_now(secret) {
                    Ok(code) => detail_row(
                        ui,
                        (&item.id, "totp"),
                        "2FA code",
                        &format!("{} ({}s)", code.code, code.seconds_remaining),
                        true,
                        false,
                    ),
                    Err(_) => detail_row(
                        ui,
                        (&item.id, "totp-invalid"),
                        "2FA code",
                        "Invalid secret",
                        false,
                        false,
                    ),
                }
            }
            detail_row(ui, (&item.id, "website"), "Website", &item.url, true, false);

            soft_frame().show(ui, |ui| {
                ui.horizontal(|ui| {
                    Frame::none()
                        .fill(GREEN_SOFT)
                        .rounding(14.0)
                        .inner_margin(Margin::symmetric(9.0, 5.0))
                        .show(ui, |ui| {
                            ui.label(RichText::new("OK").strong().color(GREEN));
                        });
                    ui.vertical(|ui| {
                        ui.label(RichText::new("Strong Password").strong().color(GREEN));
                        ui.label(
                            RichText::new("This password is deterministic and unique.")
                                .size(12.0)
                                .color(MUTED),
                        );
                    });
                });
            });
            ui.add_space(12.0);

            soft_frame().show(ui, |ui| {
                ui.label(RichText::new("Notes").strong().color(MUTED));
                ui.add_space(8.0);
                if item.notes.is_empty() {
                    ui.label(RichText::new("No notes saved for this item.").color(MUTED));
                } else {
                    ui.label(RichText::new(&item.notes).color(TEXT));
                }
            });
            ui.add_space(18.0);
            ui.label(
                RichText::new(format!("Item id {}", item.id))
                    .size(12.0)
                    .color(MUTED),
            );
        });
    }

    fn ssh_key_details(&mut self, ui: &mut egui::Ui, selection: SelectedItem, item: &SshKeyItem) {
        panel_frame().show(ui, |ui| {
            ui.set_min_height(640.0);
            ui.horizontal(|ui| {
                app_icon_large(ui, &item.label);
                ui.add_space(14.0);
                ui.vertical(|ui| {
                    ui.add_space(5.0);
                    ui.label(RichText::new(&item.label).size(22.0).strong().color(TEXT));
                    stat_badge(ui, "SSH key");
                });
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    self.detail_action_buttons(ui, selection);
                });
            });
            ui.add_space(20.0);
            self.detail_more_panel(ui, selection);

            detail_row(
                ui,
                (&item.id, "public-key"),
                "Public key",
                &item.public_key,
                true,
                false,
            );
            detail_row(
                ui,
                (&item.id, "path"),
                "Path",
                &item.derivation_path,
                true,
                false,
            );
            detail_row(
                ui,
                (&item.id, "comment"),
                "Comment",
                &item.comment,
                true,
                false,
            );

            soft_frame().show(ui, |ui| {
                ui.horizontal(|ui| {
                    Frame::none()
                        .fill(GREEN_SOFT)
                        .rounding(14.0)
                        .inner_margin(Margin::symmetric(9.0, 5.0))
                        .show(ui, |ui| {
                            ui.label(RichText::new("OK").strong().color(GREEN));
                        });
                    ui.vertical(|ui| {
                        ui.label(RichText::new("Ready for SSH Agent").strong().color(GREEN));
                        ui.label(
                            RichText::new(
                                "The private key is derived only while the vault is unlocked.",
                            )
                            .size(12.0)
                            .color(MUTED),
                        );
                    });
                });
            });
            ui.add_space(18.0);
            ui.label(
                RichText::new(format!("Item id {}", item.id))
                    .size(12.0)
                    .color(MUTED),
            );
        });
    }

    fn passkey_details(&mut self, ui: &mut egui::Ui, selection: SelectedItem, item: &PasskeyItem) {
        panel_frame().show(ui, |ui| {
            ui.set_min_height(640.0);
            ui.horizontal(|ui| {
                app_icon_large(ui, &item.label);
                ui.add_space(14.0);
                ui.vertical(|ui| {
                    ui.add_space(5.0);
                    ui.label(RichText::new(&item.label).size(22.0).strong().color(TEXT));
                    stat_badge(ui, "Passkey");
                });
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    self.detail_action_buttons(ui, selection);
                });
            });
            ui.add_space(20.0);
            self.detail_more_panel(ui, selection);

            detail_row(
                ui,
                (&item.id, "rp-id"),
                "RP ID",
                &item.relying_party_id,
                true,
                false,
            );
            detail_row(
                ui,
                (&item.id, "username"),
                "Username",
                &item.username,
                true,
                false,
            );
            detail_row(
                ui,
                (&item.id, "credential-id"),
                "Credential ID",
                &item.credential_id,
                true,
                false,
            );
            detail_row(
                ui,
                (&item.id, "public-key"),
                "Public key",
                &item.public_key,
                true,
                false,
            );
            detail_row(
                ui,
                (&item.id, "algorithm"),
                "Algorithm",
                &item.algorithm,
                false,
                false,
            );
            detail_row(
                ui,
                (&item.id, "path"),
                "Path",
                &item.derivation_path,
                false,
                false,
            );

            soft_frame().show(ui, |ui| {
                ui.horizontal(|ui| {
                    Frame::none()
                        .fill(GREEN_SOFT)
                        .rounding(14.0)
                        .inner_margin(Margin::symmetric(9.0, 5.0))
                        .show(ui, |ui| {
                            ui.label(RichText::new("OK").strong().color(GREEN));
                        });
                    ui.vertical(|ui| {
                        ui.label(RichText::new("Passkey Credential").strong().color(GREEN));
                        ui.label(
                            RichText::new("Stored for future WebAuthn mediation.")
                                .size(12.0)
                                .color(MUTED),
                        );
                    });
                });
            });
            ui.add_space(12.0);

            soft_frame().show(ui, |ui| {
                ui.label(RichText::new("Notes").strong().color(MUTED));
                ui.add_space(8.0);
                if item.notes.is_empty() {
                    ui.label(RichText::new("No notes saved for this item.").color(MUTED));
                } else {
                    ui.label(RichText::new(&item.notes).color(TEXT));
                }
            });
            ui.add_space(18.0);
            ui.label(
                RichText::new(format!("Item id {}", item.id))
                    .size(12.0)
                    .color(MUTED),
            );
        });
    }

    fn detail_action_buttons(&mut self, ui: &mut egui::Ui, selection: SelectedItem) {
        if icon_button(ui, IconKind::More, "More actions").clicked() {
            self.details_menu_for = if self.details_menu_for == Some(selection) {
                None
            } else {
                Some(selection)
            };
            self.status = String::from("More actions toggled.");
        }

        if icon_button(ui, IconKind::Edit, "Edit in form").clicked() {
            self.load_selected_into_form(selection);
        }

        let favorite = self.favorite_items.contains(&selection);
        let favorite_color = if favorite { ACCENT } else { MUTED };
        if icon_button_colored(ui, IconKind::Star, "Toggle favorite", favorite_color).clicked() {
            if favorite {
                self.favorite_items.remove(&selection);
                self.status = String::from("Removed item from Favorites.");
            } else {
                self.favorite_items.insert(selection);
                self.status = String::from("Added item to Favorites.");
            }
        }
    }

    fn detail_more_panel(&mut self, ui: &mut egui::Ui, selection: SelectedItem) {
        if self.details_menu_for != Some(selection) {
            return;
        }

        soft_frame().show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                if self.trashed_items.contains(&selection) {
                    if ui.add(secondary_button("Restore from Trash")).clicked() {
                        self.trashed_items.remove(&selection);
                        self.collection = ItemCollection::AllItems;
                        self.details_menu_for = None;
                        self.status = String::from("Item restored from Trash.");
                    }
                } else if ui.add(secondary_button("Move to Trash")).clicked() {
                    self.trashed_items.insert(selection);
                    self.favorite_items.remove(&selection);
                    self.details_menu_for = None;
                    self.status = String::from("Item moved to Trash.");
                }

                if ui.add(secondary_button("Copy item id")).clicked() {
                    if let Some(item) = self.selected_display_item() {
                        ui.output_mut(|output| output.copied_text = item.id().to_owned());
                        self.status = String::from("Copied item id.");
                    }
                }
            });
        });
        ui.add_space(10.0);
    }

    fn load_selected_into_form(&mut self, selection: SelectedItem) {
        let Some(item) = self.selected_display_item() else {
            self.status = String::from("Select an item before editing.");
            return;
        };

        if item.selection() != selection {
            self.status = String::from("Select an item before editing.");
            return;
        }

        match item {
            DisplayItem::Login(_, item) => {
                self.add_item_kind = AddItemKind::Login;
                self.login_form.title = item.title;
                self.login_form.username = item.username;
                self.login_form.url = item.url;
                self.login_form.totp_secret = item.totp_secret.unwrap_or_default();
                self.login_form.notes = item.notes;
                self.login_form.password_kind = item.password.kind();
                self.login_form.user_password = match item.password {
                    model::LoginPassword::MnemonicDerived { .. } => String::new(),
                    model::LoginPassword::UserInput { value } => value,
                };
            }
            DisplayItem::SshKey(_, item) => {
                self.add_item_kind = AddItemKind::SshKey;
                self.ssh_key_form.label = item.label;
                self.ssh_key_form.derivation_path = item.derivation_path;
                self.ssh_key_form.comment = item.comment;
            }
            DisplayItem::Passkey(_, item) => {
                self.add_item_kind = AddItemKind::Passkey;
                self.passkey_form.label = item.label;
                self.passkey_form.relying_party_id = item.relying_party_id;
                self.passkey_form.username = item.username;
                self.passkey_form.notes = item.notes;
            }
        }

        self.tab = VaultTab::AddItem;
        self.details_menu_for = None;
        self.status = String::from("Loaded item into Add Item form.");
    }
}

fn detail_empty_state(ui: &mut egui::Ui) {
    panel_frame().show(ui, |ui| {
        ui.set_min_height(640.0);
        ui.centered_and_justified(|ui| {
            ui.label(RichText::new("Select an item").size(18.0).color(MUTED));
        });
    });
}

fn password_detail_row(
    ui: &mut egui::Ui,
    id_source: impl std::hash::Hash,
    password: &model::LoginPassword,
) {
    let value = password.value();
    let reveal_id = ui.make_persistent_id(("detail-reveal", id_source));
    let mut revealed = ui
        .data_mut(|data| data.get_persisted::<bool>(reveal_id))
        .unwrap_or(false);

    soft_frame().show(ui, |ui| {
        ui.horizontal(|ui| {
            ui.vertical(|ui| {
                ui.set_min_width((ui.available_width() - 96.0).max(220.0));
                ui.label(RichText::new("Password").color(MUTED));
                let display_value = if revealed {
                    value.to_owned()
                } else {
                    "•".repeat(value.chars().count().clamp(12, 20))
                };
                ui.add(
                    egui::Label::new(RichText::new(display_value).size(15.0).color(TEXT)).wrap(),
                );
                ui.add_space(4.0);
                ui.horizontal_wrapped(|ui| {
                    stat_badge(ui, password.kind().label());
                    if let Some(path) = password.path() {
                        ui.label(RichText::new(format!("Password path {path}")).color(MUTED));
                    }
                });
            });
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if icon_button(ui, IconKind::Copy, "Copy").clicked() {
                    ui.output_mut(|output| output.copied_text = value.to_owned());
                }
                if icon_button(
                    ui,
                    IconKind::Eye,
                    if revealed {
                        "Hide password"
                    } else {
                        "Reveal password"
                    },
                )
                .clicked()
                {
                    revealed = !revealed;
                    ui.data_mut(|data| data.insert_persisted(reveal_id, revealed));
                }
            });
        });
    });
    ui.add_space(10.0);
}

fn detail_row(
    ui: &mut egui::Ui,
    id_source: impl std::hash::Hash,
    label: &str,
    value: &str,
    copyable: bool,
    secret: bool,
) {
    let reveal_id = ui.make_persistent_id(("detail-reveal", id_source));
    let mut revealed = ui
        .data_mut(|data| data.get_persisted::<bool>(reveal_id))
        .unwrap_or(false);

    soft_frame().show(ui, |ui| {
        ui.horizontal(|ui| {
            ui.vertical(|ui| {
                ui.set_min_width((ui.available_width() - 96.0).max(220.0));
                ui.label(RichText::new(label).color(MUTED));
                let display_value = if secret {
                    if revealed {
                        value.to_owned()
                    } else {
                        "•".repeat(value.chars().count().clamp(12, 20))
                    }
                } else {
                    value.to_owned()
                };
                ui.add(
                    egui::Label::new(RichText::new(display_value).size(15.0).color(TEXT)).wrap(),
                );
            });
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if copyable && icon_button(ui, IconKind::Copy, "Copy").clicked() {
                    ui.output_mut(|output| output.copied_text = value.to_owned());
                }
                if secret
                    && icon_button(
                        ui,
                        IconKind::Eye,
                        if revealed {
                            "Hide password"
                        } else {
                            "Reveal password"
                        },
                    )
                    .clicked()
                {
                    revealed = !revealed;
                    ui.data_mut(|data| data.insert_persisted(reveal_id, revealed));
                }
            });
        });
    });
    ui.add_space(10.0);
}
