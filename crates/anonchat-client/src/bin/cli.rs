//! AnonChat Interactive Terminal Client (CLI)
//!
//! Demonstrates full cryptographic identity generation, Tor SOCKS5 transport,
//! sealed sender encryption, blind relay polling, and disappearing message cleanup.

use std::io::{self, Write};
use std::sync::Arc;
use secrecy::Secret;

use anonchat_client::storage::{ClientDatabase, StoredContact};
use anonchat_client::{AnonChatEngine, RelayApiClient, TorConfig, TorTransport};
use anonchat_crypto::identity::{ClientIdentity, SecretBytes32};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    println!("============================================================");
    println!("     AnonChat - Anonymous E2EE Messenger (CLI Mode)       ");
    println!("============================================================");

    // 1. Generate local cryptographic identity
    let identity = ClientIdentity::generate();
    let friend_code = identity.friend_code();
    let user_id = identity.user_id();

    println!("[+] Generated Cryptographic Identity:");
    println!("    Friend Code : {}", friend_code);
    println!("    User ID     : {}", user_id);

    // 2. Local encrypted database (SQLCipher)
    let master_key = Secret::new(SecretBytes32([0x55; 32]));
    let db = Arc::new(ClientDatabase::open_in_memory(&master_key)?);
    println!("[+] Initialized local SQLCipher database (256-bit AES encrypted).");

    // 3. Tor SOCKS5 Transport
    let relay_url = std::env::var("RELAY_URL").unwrap_or_else(|_| "http://127.0.0.1:8080".into());
    let tor_config = TorConfig::default();
    let transport = TorTransport::direct(tor_config)?;
    let api_client = RelayApiClient::new(relay_url.clone(), transport);
    println!("[+] Configured transport pointing to Blind Relay at: {}", relay_url);

    // 4. Initialize engine & publish PreKeyBundle
    let engine = AnonChatEngine::new(identity, db.clone(), api_client);
    println!("[+] Registering public PreKeyBundle on Blind Relay...");
    if let Err(e) = engine.register_on_relay().await {
        println!("    [!] Note: Relay registration skipped or failed ({})", e);
    } else {
        println!("    [✓] PreKeyBundle registered successfully.");
    }

    // 5. Spawn background Disappearing Messages cleaner
    db.clone().spawn_ttl_cleanup_worker(std::time::Duration::from_secs(10));
    println!("[+] Disappearing messages background worker active (purges expired TTLs).");

    println!("\nCommands:");
    println!("  code                 - Print your Friend Code");
    println!("  add <nickname> <code> - Save a contact by Friend Code");
    println!("  contacts             - List saved contacts");
    println!("  send <user_id> <msg> - Send an encrypted, 4KB-padded message");
    println!("  recv                 - Poll for pending incoming messages");
    println!("  exit                 - Quit");
    println!("------------------------------------------------------------\n");

    let stdin = io::stdin();
    loop {
        print!("anonchat> ");
        io::stdout().flush()?;
        let mut line = String::new();
        if stdin.read_line(&mut line)? == 0 {
            break;
        }
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        match parts[0] {
            "code" => {
                println!("Your Friend Code: {}", friend_code);
            }
            "contacts" => {
                let contacts = db.list_contacts().unwrap_or_default();
                if contacts.is_empty() {
                    println!("No contacts saved yet. Use 'add <name> <friend_code>'.");
                } else {
                    for c in contacts {
                        println!(" - {} ({}) [TTL: {:?}s]", c.nickname, c.friend_code, c.ttl_seconds);
                    }
                }
            }
            "add" => {
                if parts.len() < 3 {
                    println!("Usage: add <nickname> <friend_code>");
                    continue;
                }
                let nick = parts[1];
                let fcode = parts[2];
                let u_id = fcode.trim_start_matches("anon:fc:").to_string();
                db.save_contact(&StoredContact {
                    friend_code: fcode.to_string(),
                    user_id: u_id,
                    nickname: nick.to_string(),
                    ttl_seconds: Some(86400),
                })?;
                println!("Saved contact '{}'.", nick);
            }
            "send" => {
                if parts.len() < 3 {
                    println!("Usage: send <recipient_user_id> <message>");
                    continue;
                }
                let recipient = parts[1];
                let text = parts[2..].join(" ");
                println!("[*] Padded message to 4KB blocks and sealing sender envelope...");
                match engine.send_message(recipient, &text).await {
                    Ok(id) => println!("[✓] Message queued successfully (ID: {})", id),
                    Err(e) => println!("[!] Failed to send: {}", e),
                }
            }
            "recv" => {
                println!("[*] Polling relay server for queued blobs...");
                match engine.receive_messages().await {
                    Ok(msgs) => {
                        if msgs.is_empty() {
                            println!("No pending messages on relay.");
                        } else {
                            for m in msgs {
                                println!("[📬 From {}]: {}", m.sender_id, m.plaintext);
                            }
                        }
                    }
                    Err(e) => println!("[!] Error polling messages: {}", e),
                }
            }
            "exit" | "quit" => {
                println!("Exiting AnonChat. Ephemeral keys zeroized from memory.");
                break;
            }
            _ => {
                println!("Unknown command: {}", parts[0]);
            }
        }
    }

    Ok(())
}

