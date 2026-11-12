# React Native / Expo Integration (@toled/signal-expo)

This module provides the complete, production-grade integration of the **Signal Protocol** in **React Native & Expo** using `@toled/signal-expo` and `expo-secure-store`.

---

## 1. Prerequisites & Installation

### Requirements
- **Expo SDK 50+** (or React Native 0.73+)
- **iOS 13.0+**
- **Android API 24+** (Android 7.0+)
- **Custom Development Build Required**: `@toled/signal-expo` contains native C/Rust bindings (`libsignal-client`). It cannot run inside standard Expo Go. You must use `expo-dev-client` or prebuild.

### Installation
```bash
npm install @toled/signal-expo expo-secure-store
```

### Config Plugin (`app.json`)
The config plugin must be declared in `app.json`:

```json
{
  "expo": {
    "name": "AnonChat",
    "slug": "anonchat",
    "plugins": [
      "@toled/signal-expo",
      "expo-secure-store"
    ],
    "ios": {
      "deploymentTarget": "13.0"
    },
    "android": {
      "minSdkVersion": 24
    }
  }
}
```

### Clean Prebuild
Generate native project files for iOS and Android:
```bash
npx expo prebuild --clean
```

---

## 2. Cryptographic Architecture

```
expo-client/
├── package.json
├── app.json
├── src/
│   ├── types/
│   │   └── signal.ts               # Address, Bundle, KeyChangeAlert types
│   ├── crypto/
│   │   ├── secureStorage.ts        # Hardware-backed SecureStore (Private key isolation)
│   │   ├── keyChangeDetector.ts    # Safety Number & Key-Change Detection Engine
│   │   └── signalService.ts        # Signal Protocol lifecycle implementation
│   ├── hooks/
│   │   └── useSignalChat.ts        # React hook for encryption/decryption & alerts
│   ├── components/
│   │   └── KeyChangeWarningModal.tsx # UI warning when contact's identity key changes
│   └── screens/
│       └── ChatScreen.tsx          # Complete chat UI screen
└── README.md
```

---

## 3. Protocol Implementation Walkthrough

### Step 1: Generate Identity (One-Time per Device)
Identity keys, registration ID, signed prekey, and one-time prekeys are generated on initial launch:

```typescript
import {
  generateIdentityKeyPair,
  generateRegistrationId,
  generatePreKeys,
  generateSignedPreKey,
  initialize,
} from '@toled/signal-expo';

const identityKeyPair = generateIdentityKeyPair();
const registrationId = generateRegistrationId();
const preKeys = generatePreKeys(1, 100);
const signedPreKey = generateSignedPreKey(identityKeyPair, 1);
```

### Step 2: Protocol Initialization
Before any encryption or decryption can occur:

```typescript
await initialize(identityKeyPair, registrationId, preKeys, signedPreKey);
```

### Step 3: Upload Public Keys to Server
**SECURITY**: Only upload public components. Private keys never leave the device.

```typescript
const publicBundle = {
  identityPublicKey: identityKeyPair.publicKey,
  registrationId: registrationId,
  preKeys: preKeys.map((k) => ({ id: k.id, publicKey: k.publicKey })),
  signedPreKey: {
    id: signedPreKey.id,
    publicKey: signedPreKey.publicKey,
    signature: signedPreKey.signature,
  },
};

// Send publicBundle to your relay server via POST /v1/keys
```

### Step 4: Establish Session with Recipient & Key-Change Check
Before establishing a session, the contact's identity key is evaluated against previously trusted keys:

```typescript
import { createSession } from '@toled/signal-expo';
import { KeyChangeDetector } from './crypto/keyChangeDetector';

const recipientAddress = { name: 'user123', deviceId: 1 };

// Check if identity key has changed (MitM defense)
const check = await KeyChangeDetector.checkContactKey(
  recipientAddress.name,
  recipientPreKeyBundle.identityKey
);

if (!check.verified) {
  // BLOCK SENDING: Prompt user with KeyChangeWarningModal!
  throw new Error('Contact safety code has changed!');
}

await createSession(recipientAddress, recipientPreKeyBundle);
```

### Step 5: Encrypt Message
```typescript
import { encrypt } from '@toled/signal-expo';

const plaintext = new TextEncoder().encode('Hello, world!');
const ciphertext = await encrypt(recipientAddress, plaintext);
```

### Step 6: Decrypt Received Message
```typescript
import { decrypt } from '@toled/signal-expo';

const decrypted = await decrypt(senderAddress, receivedCiphertext);
const message = new TextDecoder().decode(decrypted.plaintext);
```

---

## 4. Security Requirements Enforcement

### 1. Private Key Isolation (`expo-secure-store`)
- `identityKeyPair.privateKey` is stored exclusively in `expo-secure-store` using `WHEN_UNLOCKED_THIS_DEVICE_ONLY`.
- **`AsyncStorage` is NEVER used for private keys.**

### 2. Zero-Private-Key Uploads
- `exportPublicBundle()` filters out all private key fields.

### 3. Key-Change Detection & Safety Number Verification
- When communicating with a contact, their identity key fingerprint is cross-referenced with the locally trusted store.
- If the fingerprint does not match, all outbound messages are **BLOCKED**.
- The `KeyChangeWarningModal` alerts the user to potential Man-in-the-Middle attacks and displays the previous vs. new Safety Numbers, requiring explicit user approval to proceed.

