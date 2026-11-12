# Browser E2EE with `@getmaapp/signal-wasm` (Experimental)

> ### ⚠️ CRITICAL SECURITY WARNING
> **This library's WebAssembly bindings are NOT audited.**
> The author explicitly states:
> *"The bindings themselves have not been audited"* and the project was *"built with significant assistance from AI coding agents."*
>
> For an anonymity-focused messenger (AnonChat):
> **DO NOT USE THIS IN PRODUCTION WITHOUT AN INDEPENDENT THIRD-PARTY CRYPTOGRAPHIC AUDIT.**
> **USE STRICTLY FOR PROTOTYPING AND TESTING.**

---

## 1. Installation

```bash
npm install @getmaapp/signal-wasm idb
```

Bundler setup requires Vite with WASM support:
```bash
npm install -D vite vite-plugin-wasm vite-plugin-top-level-await
```

---

## 2. Browser Implementation Walkthrough

### Step 2: Initialize WebAssembly Module
WebAssembly cannot access `/dev/urandom` or OS-level entropy. Rust's standard `rand::rngs::OsRng` causes an immediate panic in the browser. `@getmaapp/signal-wasm` binds to the **Web Crypto API** (`window.crypto.getRandomValues`) to provide cryptographically secure entropy.

```javascript
import init, { SignalClient } from "@getmaapp/signal-wasm";

// Initialize the compiled WASM binary
await init();

// Instantiate the client for this device
const client = new SignalClient("your-uuid", 1);
```

### Step 3: Generate Keys for Registration
Generates standard PreKeys along with post-quantum Kyber PreKeys:

```javascript
// 100 One-Time PreKeys
const prekeys = client.generate_pre_keys(100);

// Signed PreKey (signed with Ed25519 identity key)
const signedPreKey = client.generate_signed_pre_key();

// Post-Quantum Kyber PreKey (ML-KEM / PQXDH)
const kyberPreKey = client.generate_kyber_pre_key();

// Ed25519 Identity Public Key
const identityKey = client.get_identity_public_key();
```

### Step 4: Session Establishment
Establishes an active Double Ratchet session from a peer's public `PreKeyBundle`:

```javascript
client.process_pre_key_bundle(recipientId, deviceId, preKeyBundle);
```

### Step 5: Encrypt / Decrypt
```javascript
// Encrypt outbound message
const ciphertext = client.encrypt_message(recipientId, deviceId, plaintext);

// Decrypt inbound message
const decryptedPlaintext = client.decrypt_message(senderId, deviceId, ciphertext);
```

### Step 6: Safety Numbers (Built-in Verification)
Computes a standard numerical fingerprint to verify the authenticity of the peer's identity key and detect Man-in-the-Middle (MitM) attacks:

```javascript
// Generate scannable safety number
const safetyNumber = client.generate_safety_number(recipientId, deviceId);

// Verify peer's scanned safety number
const isValid = client.verify_safety_number(recipientId, deviceId, scannedNumber);
if (!isValid) {
  throw new Error("Safety number mismatch! Possible Man-in-the-Middle attack.");
}
```

### Step 7: Persistence (Encrypted IndexedDB)
Security Requirement:
> *Store serialized records in IndexedDB with an additional layer of encryption if possible.*

In [encryptedIndexedDb.ts](file:///E:/Projects/Anon_Chat/web-client/src/storage/encryptedIndexedDb.ts), we use the **Web Crypto API (`window.crypto.subtle`)** to encrypt exported sessions with a non-extractable 256-bit AES-GCM master key before writing them to IndexedDB:

```javascript
// Export session from WASM state
const serializedSession = client.export_session(recipientId, deviceId);

// Encrypt and store in IndexedDB
await encryptedDb.saveEncryptedSession(recipientId, serializedSession);

// Restore session from IndexedDB
const restoredSession = await encryptedDb.loadDecryptedSession(recipientId);
if (restoredSession) {
  client.import_session(recipientId, deviceId, restoredSession);
}
```

---

## 3. Running the Web Prototype

Start the Vite development server:
```bash
cd web-client
npm install
npm run dev
```

Open your browser at `http://localhost:3000`.

---

## 4. File Index

- [package.json](file:///E:/Projects/Anon_Chat/web-client/package.json) — Dependencies (`@getmaapp/signal-wasm`, `idb`, `vite`)
- [vite.config.ts](file:///E:/Projects/Anon_Chat/web-client/vite.config.ts) — Vite WASM & top-level-await configuration
- [signalWasmService.ts](file:///E:/Projects/Anon_Chat/web-client/src/crypto/signalWasmService.ts) — Signal WASM service with critical security warning
- [encryptedIndexedDb.ts](file:///E:/Projects/Anon_Chat/web-client/src/storage/encryptedIndexedDb.ts) — Web Crypto AES-256-GCM encrypted IndexedDB storage
- [index.html](file:///E:/Projects/Anon_Chat/web-client/index.html) — Web interface with security banner and testing playground
- [main.ts](file:///E:/Projects/Anon_Chat/web-client/src/main.ts) — DOM event bindings
- [README.md](file:///E:/Projects/Anon_Chat/web-client/README.md) — Documentation and security warning

