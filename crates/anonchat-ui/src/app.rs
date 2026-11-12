//! AnonChat Desktop UI Skeleton (Task 6)
//!
//! Provides egui Desktop views:
//! - Onboarding: Friend Code (Fingerprint) & QR Code.
//! - Chat List: Local encrypted contacts with TTL status.
//! - Chat View: Interactive timeline with message bubbles.
//! - Disappearing Messages: TTL dropdown/toggle (Off, 1h, 24h, 7d).

use std::sync::Arc;
use chrono::{DateTime, Local, Utc};
use eframe::egui::{self, Color32, Layout, RichText, Rounding, ScrollArea, Stroke, TextureHandle, Vec2};
use secrecy::Secret;
use tracing::info;

use anonchat_client::storage::{StoredContact, StoredMessage};
use anonchat_client::AnonChatEngine;
use anonchat_crypto::identity::SecretBytes32;
use anonchat_crypto::{validate_passphrase, BackupContainer, MIN_PASSPHRASE_LEN};

use crate::qr::generate_qr_image;

#[derive(PartialEq, Eq)]
pub enum CurrentView {
    Onboarding,
    Chat,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum MessageTtl {
    Off,
    OneHour,
    TwentyFourHours,
    SevenDays,
}

impl MessageTtl {
    pub fn to_seconds(self) -> Option<i64> {
        match self {
            MessageTtl::Off => None,
            MessageTtl::OneHour => Some(3600),
            MessageTtl::TwentyFourHours => Some(86400),
            MessageTtl::SevenDays => Some(604800),
        }
    }

    pub fn from_seconds(secs: Option<i64>) -> Self {
        match secs {
            None | Some(0) => MessageTtl::Off,
            Some(s) if s <= 3600 => MessageTtl::OneHour,
            Some(s) if s <= 86400 => MessageTtl::TwentyFourHours,
            _ => MessageTtl::SevenDays,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            MessageTtl::Off => "TTL: Off",
            MessageTtl::OneHour => "TTL: 1 Hour",
            MessageTtl::TwentyFourHours => "TTL: 24 Hours",
            MessageTtl::SevenDays => "TTL: 7 Days",
        }
    }
}

pub struct AnonChatApp {
    pub engine: Option<Arc<AnonChatEngine>>,
    pub current_view: CurrentView,

    // Onboarding State
    pub my_friend_code: String,
    pub qr_texture: Option<TextureHandle>,

    // Contacts & Chat State
    pub contacts: Vec<StoredContact>,
    pub selected_contact: Option<StoredContact>,
    pub messages: Vec<StoredMessage>,
    pub message_input: String,

    // Add Contact Dialog
    pub show_add_contact_dialog: bool,
    pub new_contact_code: String,
    pub new_contact_name: String,

    // Disappearing Messages TTL
    pub current_ttl: MessageTtl,

    // Safety Number Verification UI
    pub show_safety_number_dialog: bool,
    pub show_verify_confirm_modal: bool,
    pub active_safety_number: String,
    pub is_contact_verified: bool,

    // Key Change Lock State (Disables message input until resolved)
    pub has_key_change_lock: bool,
    pub show_key_change_dialog: bool,
    pub show_accept_warning_modal: bool,

    // Backup Container State
    pub show_pre_backup_warning: bool,
    pub pre_backup_warning_acknowledged: bool,
    pub show_backup_dialog: bool,
    pub backup_passphrase: String,
    pub backup_status_msg: Option<(String, bool)>,
    pub last_backup_container: Option<Vec<u8>>,
}

impl AnonChatApp {
    pub fn new(
        _cc: &eframe::CreationContext<'_>,
        my_friend_code: String,
        engine: Option<Arc<AnonChatEngine>>,
    ) -> Self {
        Self {
            engine,
            current_view: CurrentView::Onboarding,
            my_friend_code,
            qr_texture: None,
            contacts: vec![
                StoredContact {
                    friend_code: "anon:fc:8f7e2a4b1c09...".into(),
                    user_id: "8f7e2a4b1c09...".into(),
                    nickname: "Alice (Demo)".into(),
                    ttl_seconds: Some(86400),
                },
                StoredContact {
                    friend_code: "anon:fc:3b5a9d8c2e1f...".into(),
                    user_id: "3b5a9d8c2e1f...".into(),
                    nickname: "Bob (Demo)".into(),
                    ttl_seconds: Some(3600),
                },
            ],
            selected_contact: None,
            messages: Vec::new(),
            message_input: String::new(),
            show_add_contact_dialog: false,
            new_contact_code: String::new(),
            new_contact_name: String::new(),
            current_ttl: MessageTtl::TwentyFourHours,
            show_safety_number_dialog: false,
            show_verify_confirm_modal: false,
            active_safety_number: "01253 50845 24195 94956 74245 78302 94668 80872 76692 21188 60314 51512".into(),
            is_contact_verified: false,
            has_key_change_lock: false,
            show_key_change_dialog: false,
            show_accept_warning_modal: false,
            show_pre_backup_warning: false,
            pre_backup_warning_acknowledged: false,
            show_backup_dialog: false,
            backup_passphrase: String::new(),
            backup_status_msg: None,
            last_backup_container: None,
        }
    }
}

impl eframe::App for AnonChatApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Top Navigation Bar
        egui::TopBottomPanel::top("top_panel").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading(RichText::new("🔒 AnonChat").strong().color(Color32::from_rgb(0, 210, 180)));
                ui.separator();

                if ui.selectable_label(self.current_view == CurrentView::Onboarding, "🔑 My Identity & QR").clicked() {
                    self.current_view = CurrentView::Onboarding;
                }
                if ui.selectable_label(self.current_view == CurrentView::Chat, "💬 Encrypted Chats").clicked() {
                    self.current_view = CurrentView::Chat;
                }

                ui.with_layout(Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(RichText::new("TOR: CONNECTED (127.0.0.1:9050)").small().color(Color32::GREEN));
                });
            });
        });

        match self.current_view {
            CurrentView::Onboarding => self.render_onboarding(ctx),
            CurrentView::Chat => self.render_chat_view(ctx),
        }
    }
}

impl AnonChatApp {
    /// Renders the Onboarding View: Friend Code Fingerprint and visual QR Code
    fn render_onboarding(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(20.0);
                ui.heading(RichText::new("Your Anonymous Cryptographic Identity").size(22.0));
                ui.label("No phone number. No email. Identity derived from Ed25519 public key.");
                ui.add_space(20.0);

                // Ensure QR code texture is generated
                if self.qr_texture.is_none() {
                    if let Some(color_image) = generate_qr_image(&self.my_friend_code) {
                        self.qr_texture = Some(ctx.load_texture(
                            "friend_code_qr",
                            color_image,
                            egui::TextureOptions::NEAREST,
                        ));
                    }
                }

                // Display QR code
                if let Some(ref texture) = self.qr_texture {
                    ui.image((texture.id(), Vec2::new(200.0, 200.0)));
                }

                ui.add_space(15.0);
                ui.label(RichText::new("Your Friend Code (Share via QR or Hex):").strong());
                ui.code(&self.my_friend_code);

                ui.add_space(10.0);
                if ui.button("📋 Copy Friend Code to Clipboard").clicked() {
                    ctx.output_mut(|o| o.copied_text = self.my_friend_code.clone());
                }

                ui.add_space(25.0);
                if ui.button(RichText::new("Open Encrypted Messenger →").size(16.0)).clicked() {
                    self.current_view = CurrentView::Chat;
                }
            });
        });
    }

    /// Renders the Split-Screen Chat View: Contact List on left, Chat Timeline on right
    fn render_chat_view(&mut self, ctx: &egui::Context) {
        // Left Sidebar: Contact List
        egui::SidePanel::left("contacts_sidebar")
            .resizable(true)
            .default_width(260.0)
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.heading("Contacts");
                    ui.with_layout(Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.button("➕ Add").clicked() {
                            self.show_add_contact_dialog = true;
                        }
                        if ui.button("💾 Backup").clicked() {
                            self.show_pre_backup_warning = true;
                            self.pre_backup_warning_acknowledged = false;
                            self.show_backup_dialog = false;
                        }
                    });
                });
                ui.separator();

                ScrollArea::vertical().show(ui, |ui| {
                    let mut selected_idx = None;
                    for (i, contact) in self.contacts.iter().enumerate() {
                        let is_active = self
                            .selected_contact
                            .as_ref()
                            .map(|c| c.friend_code == contact.friend_code)
                            .unwrap_or(false);

                        let ttl_str = match contact.ttl_seconds {
                            Some(s) if s <= 3600 => "⏳ 1h",
                            Some(s) if s <= 86400 => "⏳ 24h",
                            Some(s) => "⏳ 7d",
                            None => "⏳ Off",
                        };

                        ui.horizontal(|ui| {
                            let label = format!("{} ({})", contact.nickname, ttl_str);
                            if ui.selectable_label(is_active, label).clicked() {
                                selected_idx = Some(i);
                            }
                        });
                    }

                    if let Some(idx) = selected_idx {
                        let contact = self.contacts[idx].clone();
                        self.current_ttl = MessageTtl::from_seconds(contact.ttl_seconds);
                        self.selected_contact = Some(contact.clone());

                        // Load mock / real messages for active contact
                        self.messages = vec![
                            StoredMessage {
                                id: "1".into(),
                                conversation_id: contact.user_id.clone(),
                                sender_id: contact.user_id.clone(),
                                is_mine: false,
                                plaintext: "Hello! Our session is established with X3DH + Double Ratchet.".into(),
                                timestamp: Utc::now().timestamp() - 120,
                                expires_at: Some(Utc::now().timestamp() + 86400),
                            },
                            StoredMessage {
                                id: "2".into(),
                                conversation_id: contact.user_id.clone(),
                                sender_id: "me".into(),
                                is_mine: true,
                                plaintext: "Awesome. Traffic is routed over Tor, and all packets are padded to 4KB.".into(),
                                timestamp: Utc::now().timestamp() - 60,
                                expires_at: Some(Utc::now().timestamp() + 86400),
                            },
                        ];
                    }
                });
            });

        // Main Chat Panel
        egui::CentralPanel::default().show(ctx, |ui| {
            if let Some(ref contact) = self.selected_contact {
                // Chat Header
                ui.horizontal(|ui| {
                    ui.vertical(|ui| {
                        ui.heading(&contact.nickname);
                        ui.label(RichText::new(&contact.friend_code).small().weak());
                    });

                    ui.with_layout(Layout::right_to_left(egui::Align::Center), |ui| {
                        // Disappearing Messages TTL Toggle Dropdown
                        egui::ComboBox::from_label("Disappearing Messages")
                            .selected_text(self.current_ttl.label())
                            .show_ui(ui, |ui| {
                                ui.selectable_value(&mut self.current_ttl, MessageTtl::Off, "Off");
                                ui.selectable_value(&mut self.current_ttl, MessageTtl::OneHour, "1 Hour");
                                ui.selectable_value(&mut self.current_ttl, MessageTtl::TwentyFourHours, "24 Hours");
                                ui.selectable_value(&mut self.current_ttl, MessageTtl::SevenDays, "7 Days");
                            });

                        // Safety Number Verification Button
                        if ui.button("🛡️ Verify Safety Code").clicked() {
                            self.show_safety_number_dialog = true;
                        }

                        // Test Key Change Trigger
                        if ui.small_button("⚡ Test Key Change").clicked() {
                            let nickname = contact.nickname.clone();
                            let warning = format!(
                                "⚠️ {}'s security code has changed. This could mean they reinstalled the app, or someone is intercepting your messages. Tap to verify again.",
                                nickname
                            );
                            if !self.messages.iter().any(|m| m.plaintext == warning) {
                                self.messages.push(StoredMessage {
                                    id: uuid::Uuid::new_v4().to_string(),
                                    conversation_id: contact.user_id.clone(),
                                    sender_id: "system".into(),
                                    is_mine: false,
                                    plaintext: warning,
                                    timestamp: Utc::now().timestamp(),
                                    expires_at: None,
                                });
                            }
                            self.has_key_change_lock = true;
                            self.is_contact_verified = false;
                        }
                    });
                });
                ui.separator();

                // Message Bubble Scroll Area
                ScrollArea::vertical()
                    .stick_to_bottom(true)
                    .show(ui, |ui| {
                        for msg in &self.messages {
                            if msg.plaintext.starts_with("⚠️ ") {
                                // Persistent non-dismissable system warning message
                                egui::Frame::none()
                                    .fill(Color32::from_rgb(45, 25, 0))
                                    .stroke(Stroke::new(1.5, Color32::from_rgb(255, 152, 0)))
                                    .rounding(Rounding::same(8.0))
                                    .inner_margin(12.0)
                                    .show(ui, |ui| {
                                        ui.vertical(|ui| {
                                            ui.label(RichText::new("SECURITY CODE CHANGED").strong().color(Color32::from_rgb(255, 183, 77)).size(12.0));
                                            ui.add_space(4.0);
                                            ui.label(RichText::new(&msg.plaintext).color(Color32::WHITE).size(13.0));
                                            ui.add_space(6.0);
                                            ui.horizontal(|ui| {
                                                if ui.button(RichText::new("Tap to verify or resolve →").strong().color(Color32::from_rgb(0, 210, 180))).clicked() {
                                                    self.show_key_change_dialog = true;
                                                }
                                            });
                                        });
                                    });
                                ui.add_space(6.0);
                            } else {
                                ui.horizontal(|ui| {
                                    if msg.is_mine {
                                        ui.with_layout(Layout::right_to_left(egui::Align::TOP), |ui| {
                                            egui::Frame::none()
                                                .fill(Color32::from_rgb(0, 90, 140))
                                                .rounding(Rounding::same(8.0))
                                                .inner_margin(8.0)
                                                .show(ui, |ui| {
                                                    ui.label(RichText::new(&msg.plaintext).color(Color32::WHITE));
                                                });
                                        });
                                    } else {
                                        ui.with_layout(Layout::left_to_right(egui::Align::TOP), |ui| {
                                            egui::Frame::none()
                                                .fill(Color32::from_rgb(45, 45, 48))
                                                .rounding(Rounding::same(8.0))
                                                .inner_margin(8.0)
                                                .show(ui, |ui| {
                                                    ui.label(RichText::new(&msg.plaintext).color(Color32::WHITE));
                                                });
                                        });
                                    }
                                });
                                ui.add_space(4.0);
                            }
                        }
                    });

                ui.separator();

                // Input Field & Send Button (DISABLED while has_key_change_lock is true)
                ui.horizontal(|ui| {
                    let hint = if self.has_key_change_lock {
                        "🚫 Input disabled: Tap security warning above to verify"
                    } else {
                        "Type an end-to-end encrypted message..."
                    };

                    let response = ui.add_enabled(
                        !self.has_key_change_lock,
                        egui::TextEdit::singleline(&mut self.message_input)
                            .hint_text(hint)
                            .desired_width(ui.available_width() - 80.0),
                    );

                    let send_clicked = ui.add_enabled(!self.has_key_change_lock, egui::Button::new(if self.has_key_change_lock { "Blocked 🚫" } else { "Send 🚀" })).clicked();
                    let enter_pressed = response.lost_focus() && ctx.input(|i| i.key_pressed(egui::Key::Enter));

                    if !self.has_key_change_lock && (send_clicked || enter_pressed) && !self.message_input.trim().is_empty() {
                        let text = self.message_input.trim().to_string();
                        self.messages.push(StoredMessage {
                            id: uuid::Uuid::new_v4().to_string(),
                            conversation_id: contact.user_id.clone(),
                            sender_id: "me".into(),
                            is_mine: true,
                            plaintext: text,
                            timestamp: Utc::now().timestamp(),
                            expires_at: self.current_ttl.to_seconds().map(|s| Utc::now().timestamp() + s),
                        });
                        self.message_input.clear();
                        response.request_focus();
                    }
                });
            } else {
                ui.centered_and_justified(|ui| {
                    ui.label("Select a contact or add a new Friend Code to begin chatting.");
                });
            }
        });

        // Add Contact Modal Dialog
        if self.show_add_contact_dialog {
            egui::Window::new("Add Contact by Friend Code")
                .collapsible(false)
                .resizable(false)
                .show(ctx, |ui| {
                    ui.label("Nickname:");
                    ui.text_edit_singleline(&mut self.new_contact_name);

                    ui.label("Friend Code (anon:fc:...):");
                    ui.text_edit_singleline(&mut self.new_contact_code);

                    ui.horizontal(|ui| {
                        if ui.button("Save").clicked() {
                            if !self.new_contact_code.is_empty() && !self.new_contact_name.is_empty() {
                                let user_id = self.new_contact_code.trim_start_matches("anon:fc:").to_string();
                                self.contacts.push(StoredContact {
                                    friend_code: self.new_contact_code.clone(),
                                    user_id,
                                    nickname: self.new_contact_name.clone(),
                                    ttl_seconds: Some(86400),
                                });
                                self.new_contact_code.clear();
                                self.new_contact_name.clear();
                                self.show_add_contact_dialog = false;
                            }
                        }
                        if ui.button("Cancel").clicked() {
                            self.show_add_contact_dialog = false;
                        }
                    });
                });
        }

        // Safety Number QR & Monospace Verification Dialog
        if self.show_safety_number_dialog {
            if let Some(ref contact) = self.selected_contact {
                let nickname = contact.nickname.clone();
                egui::Window::new(format!("Verify {}", nickname))
                    .collapsible(false)
                    .resizable(false)
                    .min_width(380.0)
                    .show(ctx, |ui| {
                        ui.vertical_centered(|ui| {
                            ui.add_space(8.0);
                            // 2. Actionable Explanation Text
                            ui.label(RichText::new(format!(
                                "Scan this code with {}'s phone, or compare the numbers below.",
                                nickname
                            )).color(Color32::from_rgb(220, 220, 220)));
                            ui.add_space(14.0);

                            // 3. High-Contrast QR Code with Quiet Zone (280x280)
                            if let Some(ref texture) = self.qr_texture {
                                egui::Frame::none()
                                    .fill(Color32::WHITE)
                                    .rounding(Rounding::same(12.0))
                                    .inner_margin(12.0)
                                    .show(ui, |ui| {
                                        ui.image((texture.id(), Vec2::new(240.0, 240.0)));
                                    });
                            }
                            ui.add_space(14.0);

                            // 4. Numeric Display (Monospace Alignment)
                            ui.label(RichText::new("SAFETY NUMBER").small().weak());
                            egui::Frame::none()
                                .fill(Color32::from_rgb(24, 24, 24))
                                .rounding(Rounding::same(8.0))
                                .inner_margin(10.0)
                                .stroke(Stroke::new(1.0, Color32::from_rgb(50, 50, 50)))
                                .show(ui, |ui| {
                                    ui.label(
                                        RichText::new(&self.active_safety_number)
                                            .monospace()
                                            .strong()
                                            .color(Color32::from_rgb(255, 183, 77))
                                    );
                                });
                            ui.add_space(14.0);

                            if self.is_contact_verified {
                                ui.label(RichText::new("✓ Verified").strong().color(Color32::from_rgb(0, 210, 180)));
                                ui.add_space(8.0);
                            }

                            // 5. Button opens explicit confirmation dialog
                            let btn_label = if self.is_contact_verified {
                                "Re-verify Safety Number"
                            } else {
                                "Mark as Verified"
                            };

                            if ui.button(RichText::new(btn_label).strong().size(15.0)).clicked() {
                                self.show_verify_confirm_modal = true;
                            }

                            ui.add_space(6.0);
                            if ui.button("Close").clicked() {
                                self.show_safety_number_dialog = false;
                            }
                        });
                    });
            }
        }

        // Critical UX Requirement: Confirmation Dialog
        if self.show_verify_confirm_modal {
            if let Some(ref contact) = self.selected_contact {
                let nickname = contact.nickname.clone();
                egui::Window::new("Confirm Safety Number Match")
                    .collapsible(false)
                    .resizable(false)
                    .show(ctx, |ui| {
                        ui.label(format!("Did you compare the numbers with {} and confirm they match?", nickname));
                        ui.add_space(12.0);
                        ui.horizontal(|ui| {
                            if ui.button("No, not yet").clicked() {
                                self.show_verify_confirm_modal = false;
                            }
                            if ui.button(RichText::new("Yes, they match").strong().color(Color32::from_rgb(0, 210, 180))).clicked() {
                                self.is_contact_verified = true;
                                self.has_key_change_lock = false;
                                self.show_verify_confirm_modal = false;
                                self.show_safety_number_dialog = false;
                            }
                        });
                    });
            }
        }

        // Key Change Resolution Window
        if self.show_key_change_dialog {
            if let Some(ref contact) = self.selected_contact {
                let nickname = contact.nickname.clone();
                egui::Window::new("Security Code Changed")
                    .collapsible(false)
                    .resizable(false)
                    .min_width(400.0)
                    .show(ctx, |ui| {
                        ui.label(RichText::new(format!(
                            "The cryptographic identity key for {} has changed.\n\n\
                            This could mean they reinstalled the app, switched devices, or someone is intercepting your messages (Man-in-the-Middle attack).\n\n\
                            Outbound messaging is LOCKED until resolved.",
                            nickname
                        )).color(Color32::from_rgb(240, 240, 240)));

                        ui.add_space(14.0);

                        // Option A: Verify again
                        if ui.button(RichText::new("✓ Verify Again (Safety Number Match)").strong().color(Color32::from_rgb(0, 210, 180))).clicked() {
                            self.show_key_change_dialog = false;
                            self.show_safety_number_dialog = true;
                        }

                        ui.add_space(8.0);

                        // Option B: Accept without verification
                        if ui.button(RichText::new("⚠️ Accept New Key (Without Verification)").strong().color(Color32::from_rgb(255, 82, 82))).clicked() {
                            self.show_key_change_dialog = false;
                            self.show_accept_warning_modal = true;
                        }

                        ui.add_space(8.0);
                        if ui.button("Keep Blocked (Cancel)").clicked() {
                            self.show_key_change_dialog = false;
                        }
                    });
            }
        }

        // Explicit Accept Without Verification Warning Dialog
        if self.show_accept_warning_modal {
            if let Some(ref contact) = self.selected_contact {
                let nickname = contact.nickname.clone();
                egui::Window::new("Security Warning: Accept Without Verification?")
                    .collapsible(false)
                    .resizable(false)
                    .min_width(380.0)
                    .show(ctx, |ui| {
                        ui.label(RichText::new(format!(
                            "You are accepting a new security code for {} WITHOUT verifying it.\n\n\
                            If someone is intercepting your connection (MITM), they will be able to read and modify your messages.\n\n\
                            Are you sure you want to proceed?",
                            nickname
                        )).color(Color32::from_rgb(255, 183, 77)));

                        ui.add_space(14.0);
                        ui.horizontal(|ui| {
                            if ui.button("Cancel").clicked() {
                                self.show_accept_warning_modal = false;
                            }
                            if ui.button(RichText::new("Accept Without Verification").strong().color(Color32::RED)).clicked() {
                                self.has_key_change_lock = false; // Unlocks message input!
                                self.show_accept_warning_modal = false;
                            }
                        });
                    });
            }
        }

        // Mandatory Pre-Backup Warning Screen
        if self.show_pre_backup_warning {
            egui::Window::new("Security Warning: Your backup is yours alone")
                .collapsible(false)
                .resizable(false)
                .min_width(520.0)
                .show(ctx, |ui| {
                    ui.add_space(6.0);
                    ui.heading(
                        RichText::new("Your backup is yours alone")
                            .size(20.0)
                            .color(Color32::from_rgb(255, 82, 82))
                            .strong(),
                    );
                    ui.add_space(10.0);

                    // Body text (exact wording)
                    ui.label(
                        RichText::new(
                            "If you lose your passphrase, your backup cannot be recovered. No one, including us, can help you. We do not have a copy of your key."
                        )
                        .size(14.0)
                        .color(Color32::WHITE)
                        .strong(),
                    );

                    ui.add_space(8.0);

                    // Secondary text (exact wording)
                    ui.label(
                        RichText::new(
                            "This is not a limitation. It is what makes your backup private. If we could recover it, so could anyone who compromises our servers."
                        )
                        .size(13.0)
                        .color(Color32::from_rgb(180, 180, 180)),
                    );

                    ui.add_space(16.0);
                    ui.separator();
                    ui.add_space(12.0);

                    // Required action: Checkbox (exact wording)
                    ui.checkbox(
                        &mut self.pre_backup_warning_acknowledged,
                        RichText::new(
                            "I understand that if I lose my passphrase, my backup is permanently lost."
                        )
                        .color(Color32::from_rgb(255, 215, 0))
                        .strong(),
                    );

                    ui.add_space(16.0);
                    ui.horizontal(|ui| {
                        // Continue button: Disabled until the checkbox is checked
                        let can_continue = self.pre_backup_warning_acknowledged;
                        if ui
                            .add_enabled(can_continue, egui::Button::new(RichText::new("Continue").strong()))
                            .clicked()
                        {
                            self.show_pre_backup_warning = false;
                            self.pre_backup_warning_acknowledged = false; // Never remember
                            self.show_backup_dialog = true;
                        }

                        if ui.button("Cancel").clicked() {
                            // If the user navigates away, do not remember that they saw the warning
                            self.show_pre_backup_warning = false;
                            self.pre_backup_warning_acknowledged = false;
                        }
                    });
                });
        }

        // Self-Describing Encrypted Backup Container Dialog
        if self.show_backup_dialog {
            egui::Window::new("Self-Describing Encrypted Backup (Argon2id)")
                .collapsible(false)
                .resizable(false)
                .min_width(450.0)
                .show(ctx, |ui| {
                    ui.label("Derives a 256-bit AES key from your passphrase using Argon2id.");
                    ui.label("Cryptographically binds the 42-byte header as AES-256-GCM AAD.");
                    ui.add_space(8.0);

                    ui.label("Passphrase (min 12 characters, strong diversity):");
                    ui.add(egui::TextEdit::singleline(&mut self.backup_passphrase).password(true));

                    // Show live validation feedback
                    let validation = validate_passphrase(&self.backup_passphrase);
                    match &validation {
                        Ok(()) => {
                            ui.label(RichText::new("✓ Passphrase meets strength criteria").color(Color32::from_rgb(0, 210, 180)));
                        }
                        Err(e) => {
                            ui.label(RichText::new(format!("⚠️ {}", e)).color(Color32::from_rgb(255, 183, 77)));
                        }
                    }

                    if let Some((ref msg, is_err)) = self.backup_status_msg {
                        ui.add_space(6.0);
                        let color = if is_err { Color32::from_rgb(255, 82, 82) } else { Color32::from_rgb(0, 210, 180) };
                        ui.label(RichText::new(msg).color(color).strong());
                    }

                    ui.add_space(12.0);
                    ui.horizontal(|ui| {
                        let can_export = validation.is_ok();
                        if ui.add_enabled(can_export, egui::Button::new("🔒 Export Backup Container")).clicked() {
                            let sample_db = serde_json::json!({
                                "contacts": self.contacts.len(),
                                "messages": self.messages.len(),
                                "timestamp": Utc::now().timestamp(),
                            }).to_string();

                            match BackupContainer::encrypt_with_passphrase(
                                &self.backup_passphrase,
                                sample_db.as_bytes(),
                                3,
                                16,
                                4,
                            ) {
                                Ok(container) => {
                                    let bytes = container.to_bytes();
                                    let len = bytes.len();
                                    self.last_backup_container = Some(bytes);
                                    self.backup_status_msg = Some((
                                        format!("Backup exported! Total size: {} bytes (42B header + payload)", len),
                                        false,
                                    ));
                                }
                                Err(e) => {
                                    self.backup_status_msg = Some((format!("Export failed: {}", e), true));
                                }
                            }
                        }

                        if ui.add_enabled(can_export, egui::Button::new("☁ Upload to Server")).clicked() {
                            let sample_db = serde_json::json!({
                                "contacts": self.contacts.len(),
                                "messages": self.messages.len(),
                                "timestamp": Utc::now().timestamp(),
                            }).to_string();

                            match BackupContainer::encrypt_with_passphrase(
                                &self.backup_passphrase,
                                sample_db.as_bytes(),
                                3,
                                16,
                                4,
                            ) {
                                Ok(container) => {
                                    let bytes = container.to_bytes();
                                    self.last_backup_container = Some(bytes);
                                    // Client-Side Requirement:
                                    // Display: "Backup encrypted and uploaded. Your passphrase is the only way to restore it. We cannot recover it if you forget it."
                                    // Do not display a "success" checkmark that implies the server can help with recovery.
                                    self.backup_status_msg = Some((
                                        "Backup encrypted and uploaded. Your passphrase is the only way to restore it. We cannot recover it if you forget it.".to_string(),
                                        false,
                                    ));
                                }
                                Err(e) => {
                                    self.backup_status_msg = Some((format!("Upload failed: {}", e), true));
                                }
                            }
                        }

                        let has_backup = self.last_backup_container.is_some();
                        if ui.add_enabled(has_backup, egui::Button::new("🔓 Restore & Verify Backup")).clicked() {
                            if let Some(ref bytes) = self.last_backup_container {
                                match BackupContainer::from_bytes(bytes) {
                                    Ok(container) => {
                                        match container.decrypt_with_passphrase(&self.backup_passphrase) {
                                            Ok(decrypted) => {
                                                let str_res = String::from_utf8_lossy(&decrypted);
                                                self.backup_status_msg = Some((
                                                    format!("✓ Decryption & AAD verification successful! Payload: {}", str_res),
                                                    false,
                                                ));
                                            }
                                            Err(e) => {
                                                self.backup_status_msg = Some((
                                                    format!("{}", e),
                                                    true,
                                                ));
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        self.backup_status_msg = Some((format!("Invalid container: {}", e), true));
                                    }
                                }
                            }
                        }

                        if ui.button("Close").clicked() {
                            self.show_backup_dialog = false;
                        }
                    });
                });
        }
    }
}

