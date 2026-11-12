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

---

### 5.5 Sub-Step 3.3: Encrypt the Payload with AES-256-GCM

#### Inputs:
- `plaintext`: Serialized backup payload bytes (containing client identity, ratchet sessions, contacts, and message history).
- `key`: 32-byte derived key (from Argon2id in Sub-Step 3.2).
- `nonce`: 12 random bytes, generated fresh for every encryption. **Never** reuse a nonce with the same key.
- `aad`: The header bytes from offset 0 to 37 (38 bytes total, encompassing magic bytes, version, KDF ID, time cost, memory exponent, parallelism, salt, cipher ID, and nonce). This binds the header parameters to the ciphertext and detects any parameter tampering.

#### Rust Implementation:
```rust
use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, KeyInit, Payload};

let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
let ciphertext = cipher.encrypt(
    Nonce::from_slice(&nonce),
    Payload { msg: &plaintext, aad: &header_bytes[0..38] }
)?;
// ciphertext includes the 16-byte GCM auth tag at the end
```

#### Verification & Tamper Resistance:
- **Header Tampering**: Flipping any bit in offsets 0..37 causes GCM tag verification to fail immediately.
- **Nonce Integrity**: The 12-byte nonce is embedded in both the header (offsets 26..38) and the GCM IV and authenticated through AAD.
- **Ciphertext Integrity**: Tampering with any byte of ciphertext or the final 16-byte GCM authentication tag causes decryption to abort with zero plaintext leakage.

---

### 5.6 Sub-Step 3.4: Decrypt the Backup (Restore Path) & Resource Exhaustion Defense

#### Decryption Path Workflow:
1. **Header Parsing**: Read the 42-byte binary header. Validate magic bytes equal `"ANON"` (`0x41 0x4E 0x4F 0x4E`) and format version equals `0x01`. Unknown versions or corrupted magic are rejected immediately.
2. **Resource Exhaustion Defense**:
   A malicious backup file could declare exorbitant parameters (e.g. `memory_exponent = 30` -> 1 GiB per Argon2 invocation) to execute a Denial-of-Service / Out-Of-Memory attack on the restoring device.
   **Hard ceilings enforced before derivation**:
   - `memory_exponent <= 20` (max 1 GiB: $1 \ll 20\text{ KiB} = 1,048,576\text{ KiB}$)
   - `time_cost <= 10` iterations
   - `parallelism <= 4` lanes
   Any container exceeding these ceilings is aborted *before* Argon2 initialization or memory allocation.
3. **Parameter Evolution**:
   Key derivation strictly uses the parameters embedded in the container header:
   $$\text{key} = \text{Argon2id}(\text{passphrase}, \text{salt}, 1 \ll \text{memory\_exponent}, \text{time\_cost}, \text{parallelism}, 32)$$
   Future app versions can increase Argon2 memory or iteration costs without breaking backward compatibility. The restore path reads whatever parameters the file specifies.
4. **Authenticated Decryption**:
   Decrypt ciphertext using AES-256-GCM with Additional Authenticated Data $\text{AAD} = \text{header}[0..38]$.
   - On authentication failure or wrong passphrase: uniform error reported as:
     `"Incorrect passphrase or corrupted backup file."`
   - Invariant: Does **not** distinguish between an incorrect passphrase and a tampered/corrupted container to prevent timing and side-channel leakage.
5. **State Restoration & Atomic DB Import**:
   The decrypted plaintext JSON is deserialized into `BackupData`, and imported within an atomic SQLite/SQLCipher transaction:
   - Client Ed25519 identity and X25519 DH keys are reconstructed and verified.
   - Contact records, nicknames, and TTL preferences are updated.
   - Contact Safety Number verification states are restored.
   - Active Double Ratchet sessions are restored into memory and persisted.
   - Non-expired chat messages are restored; expired messages are discarded.

---

### 5.7 Server-Side Opaque Backup Storage (`POST /v1/backup`)

#### Endpoint Specification:
- **Route**: `POST /v1/backup`
- **Body**: Complete raw backup file bytes (`[42-byte header || N-byte ciphertext]`).
- **Authentication**: Blinded token or SHA-256 hash of the client's identity public key passed in `X-User-Id` or `Authorization: Bearer <token>`. **Zero** personal metadata (no email, no phone number, no IP tracking).

#### Server-Side Invariants:
1. **Zero Knowledge / Opaque Blob**:
   - The server **MUST NOT** inspect, parse, or log the backup contents.
   - The server stores the raw bytes as an opaque binary blob in `backups(user_id, blob, created_at, size_bytes)`.
2. **Replacement Policy**:
   - Replaces previous backups for the same user, keeping strictly the latest backup unless versioning is explicitly opted into.
3. **Storage Abuse Protection**:
   - Enforces a maximum blob size ceiling of **100 MB** (`104,857,600` bytes). Requests exceeding 100 MB are rejected with `HTTP 413 Payload Too Large`.
   - Blobs shorter than 42 bytes (the minimum container header size) are rejected with `HTTP 400 Bad Request`.

#### Client-Side Confirmation Invariant:
After a successful upload, the client interface **MUST** display:
> *"Backup encrypted and uploaded. Your passphrase is the only way to restore it. We cannot recover it if you forget it."*

**Critical UX Rule**: The client must **not** render a success checkmark (e.g. `✓` or `✔`) that implies the server can assist with recovery or password reset. The user must understand that zero-knowledge backup recovery is solely dependent on their passphrase.

---

### 5.8 Double Ratchet State Initialization from X3DH Shared Secret

#### Sender State Initialization (Alice, Initiator):
- **Inputs**:
  - `shared_secret`: 32-byte shared secret output from X3DH protocol.
  - `bob_ratchet_public`: Bob's signed prekey public key (the DH ratchet key Bob published in his PreKeyBundle).
- **State Initialization**:
  - `DHs`: Fresh X25519 keypair generated by Alice for this ratchet session.
  - `DHr`: `bob_ratchet_public`.
  - `RK`: `HKDF(shared_secret, DH(DHs_private, DHr), info="root")`.
  - `CKs`: `HKDF(RK, info="chain-send")`.
  - `CKr`: `null` (no incoming messages yet).
  - `Ns`: `0` (messages sent in current chain).
  - `Nr`: `0` (messages received in current chain).
  - `PNs`: `0` (previous chain length).
  - `MKSKIPPED`: Empty map (no skipped message keys).
  - `BOB_FIRST_MESSAGE`: `false`.

#### Receiver State Initialization (Bob, Recipient):
- **Inputs**:
  - `shared_secret`: Identical 32-byte shared secret recovered from X3DH handshake.
  - `bob_ratchet_keypair`: Bob's signed prekey keypair (private + public).
- **State Initialization**:
  - `DHs`: `bob_ratchet_keypair`.
  - `DHr`: `null` (Bob has not yet received Alice's ratchet public key).
  - `RK`: `shared_secret` (before the first DH ratchet step).
  - `CKs`: `null`.
  - `CKr`: `null`.
  - `Ns`: `0`, `Nr`: `0`, `PNs`: `0`.
  - `MKSKIPPED`: Empty map.
  - `BOB_FIRST_MESSAGE`: `true` (flag indicating Bob is awaiting the initiator's first inbound message).

#### Initial Handshake Transition:
Upon receiving and authenticating Alice's first message envelope:
1. Bob reads Alice's ephemeral DH public key (`header.dh` / `header.dh_pub`).
2. Bob advances the DH ratchet using `DH(bob_ratchet_keypair.priv, alice_dh_pub)` and derives `CKr`.
3. Bob advances the receiving chain to decrypt the message payload.
4. Bob transitions `BOB_FIRST_MESSAGE` from `true` to `false`.
5. Bob generates a fresh DH keypair for subsequent replies.

### 5.9 Sub-Step 4.2: Encrypt a Message (Sender Path)

#### Per-Message Encryption Algorithm:
1. **Lazy Sending Chain Initialization**:
   - If sending chain key `CKs` is null:
     - Verify peer's current ratchet public key `DHr` is known. If `DHr` is null (e.g., receiver state prior to receiving any incoming packet), abort with `MissingSendingChain`.
     - Perform a Diffie-Hellman ratchet step (Sub-Step 4.4) to generate a fresh ephemeral keypair `DHs`, set `PNs = Ns`, reset `Ns = 0`, compute `DH(DHs_private, DHr)`, derive `RK_new` and `CKs` via `KDF_RK`.
2. **Symmetric Chain Key Derivation**:
   - Advance the symmetric sending chain using `KDF_CK(CKs)`:
     $$\text{MK} = \text{HMAC-SHA256}(\text{CKs}, \texttt{0x01})$$
     $$\text{CKs}_{\text{new}} = \text{HMAC-SHA256}(\text{CKs}, \texttt{0x02})$$
   - Replace active `CKs` with $\text{CKs}_{\text{new}}$.
3. **Random Nonce Generation**:
   - Generate a fresh cryptographically secure random 12-byte nonce (96 bits) for AES-256-GCM using system CSPRNG (`OsRng` / `Random.secure()` / `crypto.getRandomValues`).
   - *Security invariant*: Derivation of a unique, single-use `MK` per message eliminates collision vulnerabilities and counter-state tracking complexities.
4. **Header Construction**:
   - Construct the message header before incrementing $N_s$:
     ```json
     {
       "dh": "<base64(DHs_public)>",
       "pn": <PNs>,
       "n": <Ns>
     }
     ```
   - For backwards compatibility, parsers accept both `"dh"` and `"dh_pub"`.
5. **Chain Counter Increment**:
   - Increment sending counter: $N_s \leftarrow N_s + 1$.
6. **Padding & AEAD Binding**:
   - Plaintext payload is padded to fixed 4096-byte blocks with big-endian length prefix and random bytes.
   - Header JSON is serialized and bound as AES-256-GCM **Additional Authenticated Data (AAD)**.
   - Ciphertext output includes 16-byte GCM authentication tag appended at the end.

### 5.10 Sub-Step 4.3: Decrypt a Message (Receiver Path)

#### Per-Message Decryption Algorithm:
Inputs: `(header, nonce, ciphertext)`
1. **Check Skipped Keys First**:
   - Compute map lookup key: `key = header.dh + ":" + header.n`.
   - If `MKSKIPPED[key]` exists:
     - Retrieve single-use message key `MK`.
     - Delete entry from `MKSKIPPED` immediately (enforces forward secrecy against replay).
     - Decrypt ciphertext with `MK` using AES-256-GCM and header as AAD.
     - Zeroize `MK` and return plaintext (without advancing any ratchet state).
2. **Check for DH Ratchet Step**:
   - If `header.dh != state.DHr`:
     - Save skipped keys from current receiving chain up to $PN$: while $N_r < \text{header.pn}$, derive $(CK_{r\text{,new}}, MK_{\text{skipped}}) = \text{KDF\_CK}(CK_r)$, store in `MKSKIPPED[state.DHr + ":" + state.Nr]`, advance $CK_r$ and $N_r$.
     - Enforce `MAX_SKIP = 100` ceiling on skip gap ($until - N_r \le 100$) and cache capacity limit (`MAX_SKIPPED_KEYS = 1000`).
     - Perform Diffie-Hellman ratchet step (Sub-Step 4.4).
3. **Skip Messages in New Chain**:
   - While $N_r < \text{header.n}$:
     - Derive $(CK_{r\text{,new}}, MK_{\text{skipped}}) = \text{KDF\_CK}(CK_r)$.
     - Store `MKSKIPPED[header.dh + ":" + state.Nr] = MK_skipped`.
     - Advance $CK_r \leftarrow CK_{r\text{,new}}$ and $N_r \leftarrow N_r + 1$.
     - Enforce `MAX_SKIP = 100`.
4. **Derive Message Key**:
   - Derive $(CK_{r\text{,new}}, MK) = \text{KDF\_CK}(CK_r)$ via HMAC-SHA256 (`0x01` for $MK$, `0x02` for $CK_{r\text{,new}}$).
   - Advance receiving chain: $CK_r \leftarrow CK_{r\text{,new}}$ and $N_r \leftarrow N_r + 1$.
5. **Authenticated Decryption**:
   - Decrypt ciphertext with AES-256-GCM using `MK`, nonce, and serialized header as AAD.
   - If authentication tag check fails, throw an error immediately (prevents ciphertext forgery or tampering).
   - Strip 4096-byte constant block padding.
6. **Zeroize `MK`**:
   - Overwrite `MK` with zeros immediately after decryption.

#### Critical Defense: `MAX_SKIP = 100` DoS Mitigation:
An adversary could send an envelope with $N = 1,000,000$ to trigger a million costly KDF computations and allocate memory for a million message keys. AnonChat enforces `MAX_SKIP = 100` at the gate: if the gap between $N_r$ and the requested message number exceeds 100, the packet is rejected with a `GapTooLarge` error before entering the derivation loop.

### 5.11 Sub-Step 4.4: Diffie-Hellman Ratchet Step (Continuous Rekeying & Post-Compromise Security)

#### When It Runs:
- **Receiver Side**: Triggered inside `ratchet_decrypt` whenever `header.dh != state.DHr` (the peer has ratcheted their DH key).
- **Sender Side**: Triggered inside `ratchet_encrypt` when sending chain key `CKs` is null and peer's DH key `DHr` is known.

#### Algorithm (Receiver Side):
1. Save previous sending chain length: $\text{state.PNs} \leftarrow \text{state.Ns}$.
2. Reset message counter for new sending chain: $\text{state.Ns} \leftarrow 0$.
3. Reset message counter for new receiving chain: $\text{state.Nr} \leftarrow 0$.
4. Update peer's DH ratchet public key: $\text{state.DHr} \leftarrow \text{header.dh}$.
5. **Derive New Receiving Chain Key**:
   $$DH_{\text{rx}} = X25519(\text{state.DHs\_private}, \text{state.DHr})$$
   $$(\text{state.RK}, \text{state.CKr}) = \text{KDF\_RK}(\text{state.RK}, DH_{\text{rx}})$$
6. **Generate Fresh Ephemeral Keypair**:
   $$DH_{\text{s\_new}} = \text{generate\_X25519\_keypair}()$$
   $$\text{state.DHs} \leftarrow DH_{\text{s\_new}}$$
7. **Derive New Sending Chain Key**:
   $$DH_{\text{tx}} = X25519(\text{state.DHs\_new\_private}, \text{state.DHr})$$
   $$(\text{state.RK}, \text{state.CKs}) = \text{KDF\_RK}(\text{state.RK}, DH_{\text{tx}})$$

#### Algorithm (Sender Side, when initiating after receiving):
- Generate new X25519 keypair $DH_{\text{s\_new}}$.
- Compute $DH_{\text{tx}} = X25519(DH_{\text{s\_new\_private}}, \text{state.DHr})$.
- Derive $(\text{state.RK}, \text{state.CKs}) = \text{KDF\_RK}(\text{state.RK}, DH_{\text{tx}})$.
- Overwrite old private keys and zeroize intermediate buffers.

#### Post-Compromise Security (Break-in Recovery):
Even if an active attacker seizes physical device RAM and extracts current session keys $(RK, CK_s, CK_r)$, security self-heals after a single round-trip ratchet exchange. The newly generated Curve25519 private keys inject fresh entropy inaccessible to the adversary, re-establishing end-to-end forward secrecy and confidentiality.

#### KDF_RK Specification (Signal Protocol Standard):
$$\text{PRK} = \text{HMAC-SHA256}(\text{salt} = \text{RK}, \text{ikm} = DH_{\text{output}})$$
$$\text{Output}_{64} = \text{HKDF-Expand}(\text{PRK}, \text{info} = \texttt{"DoubleRatchet"}, \text{len} = 64)$$
$$\text{RootKey} = \text{Output}[0..32]$$
$$\text{ChainKey} = \text{Output}[32..64]$$

### 5.12 Sub-Step 4.5: Wire Format and State Persistence

#### Wire Packet (Relay Transmission Format):
Every Double Ratchet message transmitted across the blind relay server is serialized as a versioned `WirePacket` JSON envelope:
```json
{
  "v": 1,
  "header": {
    "dh": "base64_x25519_public_key",
    "pn": 0,
    "n": 42
  },
  "nonce": "base64_12_bytes",
  "ciphertext": "base64_aes_gcm_output_with_tag"
}
```

#### Wire Packet Validation Invariants:
1. `v == 1`: The wire packet version must strictly equal 1. Unsupported or unknown versions are rejected immediately before decryption attempts.
2. `header.dh`: Must decode to a valid 32-byte Curve25519 public key.
3. `nonce`: Must decode to exactly 12 bytes (`GCM_NONCE_SIZE`).
4. `ciphertext`: Must decode to at least 16 bytes (16-byte AES-GCM authentication tag).
5. The associated authenticated data (AAD) bound during AES-256-GCM encryption is the canonical JSON serialization of the header object (`{"dh": "...", "n": 42, "pn": 0}`).

#### State Persistence & Local Encrypted Storage:
Double Ratchet sessions maintain critical continuous cryptographic state across ephemeral app processes:
- `DHs_pub`, `DHs_priv`: Current sender Curve25519 keypair.
- `DHr`: Current peer Curve25519 public ratchet key (or null during initial handshake).
- `RK`: Current 32-byte Root Key.
- `CKs`: Sending chain key (or null pending ratchet turn).
- `CKr`: Receiving chain key (or null pending peer transmission).
- `Ns`: Sent message index in current sending chain.
- `Nr`: Received message index in current receiving chain.
- `PNs`: Length of previous sending chain.
- `MKSKIPPED`: Map of skipped message keys (`"dh:msgNum"` $\to$ 32-byte key) for delayed out-of-order delivery.
- `bob_first_message`: Handshake state flag.

#### Cold Restart & Persistence Guarantees:
- **Zero Plaintext on Disk**: Ratchet state JSON is never saved in plaintext. It is encrypted in SQLCipher tables (`ratchet_sessions(peer_user_id, session_json, updated_at)`) or serialized into the encrypted backup container using Argon2id-derived keys.
- **Immediate Resumption**: When an application restarts or awakes from background sleep, active ratchet states are reloaded from SQLCipher into memory. Outbound and inbound message counters ($N_s, N_r$) continue sequentially without key desynchronization.
- **Zeroization**: In-memory secrets (`Zeroize`, `ZeroizeOnDrop`) are wiped from memory buffers when sessions are closed or dropped.

### 5.13 Mandatory Pre-Backup Warning Screen & User Mental Model Framing

#### User Mental Model Framing:
End-to-end encrypted backup systems that promise recoverability while cryptographically guaranteeing zero-knowledge unrecoverability cause severe user frustration if the threat model is not made explicit *before* key generation. Reframing the limitation as a fundamental privacy feature aligns user expectations with technical realities.

#### UI & Textual Requirements:
Before the user can enter a passphrase or generate a recovery code, a full-screen warning is shown:

1. **Header**:
   `"Your backup is yours alone"`
2. **Body Text**:
   `"If you lose your passphrase, your backup cannot be recovered. No one, including us, can help you. We do not have a copy of your key."`
3. **Secondary Framing Text**:
   `"This is not a limitation. It is what makes your backup private. If we could recover it, so could anyone who compromises our servers."`
4. **Required Explicit Acknowledgment (Checkbox)**:
   `"I understand that if I lose my passphrase, my backup is permanently lost."`
5. **Continue Button**:
   Strictly disabled (`disabled = true`) until the user checks the acknowledgment checkbox.

#### Anti-Bypass Enforcements:
- **No Skip or Deferred Prompts**: The interface does not provide a `"Skip"`, `"Later"`, or `"Remind me later"` option.
- **Ephemeral State (No Memory on Navigation Away)**: If the user navigates away or cancels, the application does not record or persist that the warning was viewed. The screen is presented fresh every time backup generation is initiated.

---

### 5.14 High-Entropy Recovery Codes (BIP39 & Base32)

To eliminate the vulnerability of weak or reused user passphrases (e.g. `"password123"`), AnonChat supports randomly generated high-entropy recovery codes as a first-class alternative to user-chosen passphrases.

#### 1. Security & Cryptographic Invariants
- **True 256-Bit Entropy**: Generated via cryptographically secure pseudorandom number generators (`CSPRNG`: `ring::rand::SystemRandom`, `crypto.getRandomValues`, `SecureRandom`, `SecRandomCopyBytes`, or `secrets.token_bytes`).
- **Option B (Recommended): 24-Word BIP39 Mnemonic**:
  - Entropy length: 256 bits ($ENT = 256$).
  - Checksum: 8 bits ($CS = ENT / 32 = 8$ bits), derived from the first byte of `SHA-256(entropy)`.
  - Bit stream: $ENT + CS = 264$ bits.
  - Word encoding: 264 bits divided into 24 chunks of 11 bits each ($24 \times 11 = 264$), indexing into the standardized 2048-word BIP39 English dictionary.
  - Error detection: Any corruption, mistyped word, or single bit-flip is detected with 99.6% ($1 - 2^{-8}$) probability.
- **Option A: Crockford Base32 52-Character Code**:
  - Entropy length: 256 bits + 4 zero-padding bits = 260 bits.
  - Base32 encoding: 260 bits divided into 52 5-bit chunks using Crockford's Base32 alphabet (`0123456789ABCDEFGHJKMNPQRSTVWXYZ`).
  - Formatting: 13 groups of 4 characters separated by spaces (`K7QM 3XPR 9WTF 2BNH ...`).
  - Ambiguity tolerance & normalization: Strips spaces and hyphens; normalizes `O` $\rightarrow$ `0` and `I`/`L` $\rightarrow$ `1`.
- **Passphrase Compatibility**: Both formats yield strings substantially exceeding the 12-character minimum passphrase length (`MIN_PASSPHRASE_LEN`) for Argon2id key derivation, maintaining 100% backward and forward compatibility with the 42-byte binary container header without format changes.
- **Unified Validator**: Accepts either 24 BIP39 English words or a 52-character Crockford Base32 string, restoring the identical 32-byte (256-bit) entropy key.

#### 2. Key Derivation Formula
```text
key = Argon2id(recoveryCode, salt, memory, iterations, parallelism, 32)
```

- **Parameters**:
  - `recoveryCode`: String, UTF-8 encoded (e.g. 24 BIP39 words separated by spaces, or 52 Crockford Base32 characters).
  - `salt`: 16 cryptographically random bytes stored in the container header at offset `9..25`.
  - `memory`: Memory cost in KiB ($1 \ll \text{memory\_exponent}$, default $65,536\text{ KiB} = 64\text{ MiB}$).
  - `iterations`: Time cost (default 3 iterations).
  - `parallelism`: Parallel lanes (default 4 lanes on desktop/Android, 1 lane in single-threaded environments).
  - `32`: Desired derived key length in bytes (256-bit symmetric key for AES-256-GCM).

- **Architectural Rationale**:
  1. **Unified Pipeline**: A single, uniform decryption path handles both user-chosen passphrases and randomly generated recovery codes. No format flag or container modification is required.
  2. **Domain Separation & Salt Independence**: A fresh 16-byte random salt per backup guarantees that multiple backups generated with the same recovery code produce completely independent symmetric keys.
  3. **Defense-in-Depth**: Memory-hard Argon2id execution ensures maximum resistance against physical extraction and offline attacks.












