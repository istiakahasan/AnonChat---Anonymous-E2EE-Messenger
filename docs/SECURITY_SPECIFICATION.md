# AnonChat Cryptographic & Threat Model Specification

## 1. Cryptographic Primitives

| Purpose | Algorithm / Primitive | Security Parameter | Standard / RFC |
| :--- | :--- | :--- | :--- |
| **Long-Term Digital Signatures** | Ed25519 (Edwards25519) | 128-bit security level | RFC 8032 |
| **Key Agreement (Diffie-Hellman)** | X25519 (Montgomery Curve25519) | 128-bit security level | RFC 7748 |
| **Asynchronous Key Agreement** | Extended Triple Diffie-Hellman (X3DH) | Multi-DH composition | Signal X3DH Spec v1 |
| **Continuous Rekeying** | Double Ratchet (DH + Symmetric KDF) | Per-message unique keys | Signal Double Ratchet Spec v1 |
| **Symmetric Encryption (AEAD)** | AES-256-GCM | 256-bit key, 96-bit nonce, 128-bit tag | NIST SP 800-38D |
| **Key Derivation Function** | HKDF-SHA256 | HMAC-based extract & expand | RFC 5869 |
| **Chain Key KDF** | HMAC-SHA256 | Distinct 0x01 / 0x02 constants | RFC 2104 |
| **Local Disk Encryption** | SQLCipher (AES-256-CBC / AES-256-GCM) | PBKDF2 / Argon2id derived key | SQLCipher v4 Spec |
| **Transport Layer Anonymity** | Tor (The Onion Router) | 3-hop onion encrypted circuits | Tor Rendezvous Spec v3 |
| **Traffic Analysis Protection** | Uniform 4KB Constant Padding | Random byte stuffing | AnonChat Spec v1 |

---

## 2. Security Invariants

### 2.1 Forward Secrecy (FS)
- Compromise of long-term identity keys $(IK)$ does not reveal past communications.
- Every message key ($MK$) is derived from ephemeral chain keys ($CK$) and ephemeral Diffie-Hellman exchanges.
- Chain keys advance deterministically via a one-way function ($\text{HMAC-SHA256}$); once a message is decrypted, the message key is zeroized.

### 2.2 Post-Compromise Security (Break-in Recovery)
- If an active session state is temporarily compromised, the attacker loses decryption capability as soon as an uncompromised round-trip exchange occurs (the Diffie-Hellman ratchet injects fresh entropy into the root key $RK$).

### 2.3 Sender Anonymity (Sealed Sender)
- The Blind Relay Server never learns the identity of the message sender.
- The sender encrypts an inner envelope containing $(SenderID, Ciphertext)$ using an ephemeral X25519 keypair and the recipient's Identity DH public key.
- The outer envelope presented to the server contains only `recipientId` and the encrypted blob.

### 2.4 Traffic Analysis Resistance
- Plaintexts of varying sizes (e.g., "Hi" vs. a 3KB document) are padded with cryptographically secure random bytes to integer multiples of 4096 bytes (4KB).
- Passive network observers and relay operators observe only uniform 4KB+ block sizes.

---

## 3. Threat Model & Adversary Capabilities

| Adversary Type | Capabilities | Mitigation in AnonChat |
| :--- | :--- | :--- |
| **Global Passive Network Observer (ISP, Exit Node)** | Monitors network packet timing, IP headers, and packet sizes. | Traffic is tunneled through Tor (`socks5h://`); all packet sizes are padded to 4KB blocks; DNS requests resolved over Tor. |
| **Compromised / Malicious Blind Relay** | Inspects stored blobs, attempts social graph reconstruction, tampers with headers. | Sealed Sender hides sender identities; PreKey bundles contain no private keys; One-Time PreKeys are popped atomically; headers are AEAD-authenticated (tampering fails decryption); messages are deleted immediately upon retrieval. |
| **Active Network Man-in-the-Middle (MitM)** | Injects, replays, or modifies payloads in transit. | X3DH enforces signature verification on Signed PreKeys; Double Ratchet headers are authenticated via AES-256-GCM AAD; Tor circuits prevent in-transit tampering. |
| **Device Seizure / Forensic Analysis** | Physical access to client filesystem. | Local database is encrypted with SQLCipher (256-bit AES); private keys in RAM are wrapped in zeroizing secret wrappers; Disappearing Messages worker continuously wipes expired messages. |

---

## 4. Architectural Comparison

| Security Feature | AnonChat | Signal | Telegram | Session | SimpleX |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **No Phone Number / Email Required** | **Yes** | No | No | Yes | Yes |
| **End-to-End Encryption by Default** | **Yes** | Yes | No (Opt-in) | Yes | Yes |
| **X3DH + Double Ratchet** | **Yes** | Yes | No (MTProto) | Yes (Sesquratchet) | No (2-layer E2EE) |
| **Tor Transport Routing** | **Yes** | No | No | Lokinet (Oxen) | SOCKS5 optional |
| **Sealed Sender (Sender Blind)** | **Yes** | Yes | No | Yes | Yes |
| **Fixed 4KB Traffic Padding** | **Yes** | Variable | No | Fixed blocks | Fixed blocks |
| **Zero-Knowledge Ephemeral Queue** | **Yes** | Server holds queue | Cloud store | Onion routing | Ephemeral queues |
| **Disappearing Messages (Local TTL)** | **Yes** | Yes | Secret chats only | Yes | Yes |

