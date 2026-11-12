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

---

## 5. Self-Describing Backup Container Format

### 5.1 Rationale: Why a Self-Describing Header Is Mandatory
A naive format of `[salt][nonce][ciphertext]` fails silently when KDF (Argon2id) parameters are tuned or evolved in the future. The application of the future cannot decrypt the backup of the past because parameters were hardcoded in application logic, not preserved with the backup blob. Because the relay server acts as a blind store and cannot assist, the backup file must carry self-describing metadata needed for deterministic recovery.

### 5.2 Binary Layout (42-Byte Little-Endian Header + Authenticated Ciphertext)

| Offset | Size (Bytes) | Field | Value / Representation | Description |
| :---: | :---: | :--- | :--- | :--- |
| **0** | 4 | Magic Bytes | `"ANON"` (`0x41 0x4E 0x4F 0x4E`) | File type identification |
| **4** | 1 | Format Version | `0x01` (`uint8`) | Container structure version |
| **5** | 1 | KDF Identifier | `0x01` (`uint8`) | `0x01` = Argon2id |
| **6** | 1 | Argon2 Time Cost | `uint8` | Number of iterations (e.g., 3) |
| **7** | 1 | Argon2 Memory Exponent | `uint8` | $\text{Memory (KiB)} = 1 \ll \text{exponent}$ (e.g. 16 $\rightarrow$ 64 MiB) |
| **8** | 1 | Argon2 Parallelism | `uint8` | Number of execution lanes (e.g., 4) |
| **9** | 16 | Salt | 16 raw bytes | Random cryptographically secure salt |
| **25** | 1 | Cipher Identifier | `0x01` (`uint8`) | `0x01` = AES-256-GCM |
| **26** | 12 | Nonce / IV | 12 raw bytes | Random 96-bit AES-GCM IV |
| **38** | 4 | Ciphertext Length ($N$) | `uint32` (Little-Endian) | Length of ciphertext in bytes |
| **42** | $N$ | Ciphertext + Auth Tag | $N$ raw bytes | AES-256-GCM payload; final 16 bytes are the GCM authentication tag |

### 5.3 Cryptographic Integrity (AAD Binding)
The entire 42-byte header (offsets 0 through 41) is passed as **Additional Authenticated Data (AAD)** to AES-256-GCM during encryption and decryption. Any tampering with KDF parameters, format version, salt, nonce, or payload length causes tag verification to fail immediately with an integrity check error.

### 5.4 Sub-Step 3.2: Argon2id Key Derivation & Passphrase Policies

#### Passphrase Policy Requirements:
- **Minimum Length**: Enforced $\ge 12$ characters (recommended: 15+ characters).
- **Entropy & Diversity**: Requires at least 5 distinct characters across at least 2 character categories (lowercase, uppercase, digits, symbols).
- **Pattern Rejection**: Rejects trivial repeated strings (e.g., `aaaaaaaaaaaa`) and monotonic sequences (e.g., `abcdefghijkl`, `123456789012`) before invoking KDF calculations to conserve device resources and enforce password hygiene.

#### Key Derivation Inputs & Outputs:
- **Passphrase**: UTF-8 bytes of validated passphrase.
- **Salt**: 16 cryptographically secure random bytes generated afresh per backup. Salts are **never** reused across backups.
- **Memory Cost**: $\text{memory\_kib} = 1 \ll \text{memory\_exponent}$ (from header offset 7, default: $1 \ll 16 = 65,536\text{ KiB} = 64\text{ MiB}$).
- **Time Cost / Iterations**: $t = \text{time\_cost}$ (from header offset 6, default: 3).
- **Parallelism / Lanes**: $p = \text{parallelism}$ (from header offset 8, default: 4).
- **Algorithm**: Argon2id, Version `0x13`.
- **Output**: 32-byte (256-bit) symmetric key, protected by automatic zeroization (`Zeroizing` / secure memory scrubbing) immediately after use.

#### React Native / Expo Native Implementation:
```typescript
import { argon2id } from '@sonnetstationsolutions/expo-argon2';

const passwordBytes = new TextEncoder().encode(passphrase);
const salt = crypto.getRandomValues(new Uint8Array(16));
const key = await argon2id({
  password: passwordBytes,
  salt,
  memory: 65536,   // KiB (1 << 16)
  iterations: 3,
  parallelism: 1,
  hashLength: 32,
});
// key is a Uint8Array(32)
```

#### Flutter / Dart Native Implementation (`package:cryptography`):
```dart
import 'package:cryptography/cryptography.dart';

final algorithm = Argon2id(
  memory: 65536,
  iterations: 3,
  parallelism: 1,
  hashLength: 32,
);
final secretKey = await algorithm.deriveKey(
  secretKey: SecretKey(utf8.encode(passphrase)),
  nonce: salt, // 16 bytes
);
final keyBytes = await secretKey.extractBytes();
// keyBytes is Uint8List(32)
```


