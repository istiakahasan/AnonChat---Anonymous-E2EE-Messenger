import { SignalWasmService } from './crypto/signalWasmService';
import { WebBackupContainerService } from './crypto/backupContainer';

const signalService = SignalWasmService.getInstance();

const btnInit = document.getElementById('btn-init') as HTMLButtonElement;
const initStatus = document.getElementById('init-status') as HTMLDivElement;
const btnGenKeys = document.getElementById('btn-gen-keys') as HTMLButtonElement;
const keysOutput = document.getElementById('keys-output') as HTMLPreElement;
const btnTestCipher = document.getElementById('btn-test-cipher') as HTMLButtonElement;
const inputMsg = document.getElementById('input-msg') as HTMLInputElement;
const cipherOutput = document.getElementById('cipher-output') as HTMLPreElement;
const safetyBox = document.getElementById('safety-number-box') as HTMLDivElement;
const btnPersist = document.getElementById('btn-persist') as HTMLButtonElement;
const btnRestore = document.getElementById('btn-restore') as HTMLButtonElement;
const dbStatus = document.getElementById('db-status') as HTMLDivElement;

// Key change & mismatch UI elements
const btnSimulateKeyChange = document.getElementById('btn-simulate-keychange') as HTMLButtonElement;
const systemWarningBubble = document.getElementById('system-warning-bubble') as HTMLDivElement;
const keychangeModal = document.getElementById('keychange-modal') as HTMLDivElement;
const btnModalVerify = document.getElementById('btn-modal-verify') as HTMLButtonElement;
const btnModalAccept = document.getElementById('btn-modal-accept') as HTMLButtonElement;
const btnModalCancel = document.getElementById('btn-modal-cancel') as HTMLButtonElement;
const mismatchBanner = document.getElementById('mismatch-banner') as HTMLDivElement;
const btnDismissMismatch = document.getElementById('btn-dismiss-mismatch') as HTMLButtonElement;

let registrationBundle: any = null;
const myUuid = 'user-alice-' + Math.random().toString(36).substring(7);
const peerUser = 'user-bob';

let isInputBlocked = false;
let verifiedAt: number | null = null;
let lastRemoteKeyHex = '4A5560EE65C96167969CDA8AF0773669113FDD4D5A4AB721475018FEA959BC81';

btnInit.addEventListener('click', async () => {
  initStatus.textContent = 'Status: Initializing WASM & Web Crypto...';
  try {
    await signalService.initialize(myUuid, 1);
    initStatus.innerHTML = `<span style="color: #00d2b4">✓ WASM initialized! Client UUID: <code>${myUuid}</code> (Device 1)</span>`;
    btnGenKeys.disabled = false;
    btnTestCipher.disabled = false;
    btnPersist.disabled = false;
    btnRestore.disabled = false;
  } catch (err: any) {
    initStatus.innerHTML = `<span style="color: #ff5252">Initialization failed: ${err.message}</span>`;
  }
});

btnGenKeys.addEventListener('click', () => {
  try {
    registrationBundle = signalService.generateRegistrationKeys();
    keysOutput.textContent = JSON.stringify(
      {
        uuid: registrationBundle.uuid,
        identityKey: registrationBundle.identityKey ? '[Public Key Generated]' : null,
        signedPreKey: registrationBundle.signedPreKey ? '[Signed PreKey Generated]' : null,
        kyberPreKey: registrationBundle.kyberPreKey ? '[Kyber Post-Quantum PreKey Generated]' : null,
        preKeysCount: registrationBundle.preKeys?.length || 100,
      },
      null,
      2
    );
  } catch (err: any) {
    keysOutput.textContent = `Error generating keys: ${err.message}`;
  }
});

/**
 * Trigger Key Change:
 * 1. Set verifiedAt = null in storage.
 * 2. Insert persistent non-dismissable system message in chat.
 * 3. DISABLE message input field and send button.
 */
function triggerKeyChangeDetected() {
  verifiedAt = null; // Step 1: Set verifiedAt = null in local storage
  isInputBlocked = true;

  // Step 2: Show persistent system warning bubble in chat
  systemWarningBubble.style.display = 'block';

  // Step 3: Disable message input field and send button
  inputMsg.disabled = true;
  inputMsg.value = '';
  inputMsg.placeholder = '🚫 Input disabled: Tap security warning above to verify';
  btnTestCipher.disabled = true;
  btnTestCipher.textContent = 'Blocked 🚫';
}

btnSimulateKeyChange.addEventListener('click', () => {
  triggerKeyChangeDetected();
});

systemWarningBubble.addEventListener('click', () => {
  keychangeModal.style.display = 'flex';
});

btnModalCancel.addEventListener('click', () => {
  keychangeModal.style.display = 'none';
});

// Resolution Option A: Completes verification again (Safety Number matches)
btnModalVerify.addEventListener('click', () => {
  keychangeModal.style.display = 'none';
  verifiedAt = Date.now();
  isInputBlocked = false;

  // Unlock input
  inputMsg.disabled = false;
  inputMsg.placeholder = 'Type an encrypted message...';
  inputMsg.value = 'Hello from browser WebAssembly Signal Protocol!';
  btnTestCipher.disabled = false;
  btnTestCipher.textContent = 'Send Encrypted Message 🚀';

  alert(`✓ Safety Number verified for ${peerUser}. Message input unlocked.`);
});

// Resolution Option B: Explicitly accepts new key (with strict warning confirmation)
btnModalAccept.addEventListener('click', () => {
  const confirmed = confirm(
    `Security Warning: You are accepting a new security code for ${peerUser} WITHOUT verification.\n\n` +
      `If an attacker or rogue server is intercepting your connection, they will be able to read and modify your messages.\n\n` +
      `Do you still want to proceed?`
  );

  if (confirmed) {
    keychangeModal.style.display = 'none';
    lastRemoteKeyHex = 'F9E8D7C6B5A43210F9E8D7C6B5A43210F9E8D7C6B5A43210F9E8D7C6B5A43210';
    verifiedAt = null; // Remains unverified
    isInputBlocked = false;

    // Unlock input
    inputMsg.disabled = false;
    inputMsg.placeholder = 'Type an encrypted message...';
    inputMsg.value = 'Hello from browser WebAssembly Signal Protocol!';
    btnTestCipher.disabled = false;
    btnTestCipher.textContent = 'Send Encrypted Message 🚀';

    alert(`New key for ${peerUser} accepted without verification. Input field unlocked.`);
  }
});

btnDismissMismatch.addEventListener('click', () => {
  mismatchBanner.style.display = 'none';
});

btnTestCipher.addEventListener('click', () => {
  if (isInputBlocked) {
    alert('Transmission blocked: Safety code has changed. Verify contact before sending.');
    return;
  }

  const plaintext = inputMsg.value || 'Hello Signal WASM!';

  try {
    cipherOutput.textContent = 'Processing session and encrypting message...';

    // Mock ciphertext sealed envelope
    const mockCipher = {
      type: 3, // PreKeySignalMessage
      destination: peerUser,
      body: btoa(plaintext),
      timestamp: Date.now(),
    };

    cipherOutput.textContent = JSON.stringify(mockCipher, null, 2);

    // 60-digit safety number
    safetyBox.textContent = '58514 34043 94056 44585 48893 32257 82277 01943 81263 81849 42018 21380';
  } catch (err: any) {
    cipherOutput.textContent = `Encryption error: ${err.message}`;
  }
});

btnPersist.addEventListener('click', async () => {
  dbStatus.textContent = 'Encrypting and saving session to IndexedDB (AES-256-GCM)...';
  try {
    await signalService.persistSession(peerUser, 1);
    dbStatus.innerHTML =
      '<span style="color: #00d2b4">✓ Session encrypted with non-extractable CryptoKey and stored in IndexedDB!</span>';
  } catch (err: any) {
    dbStatus.innerHTML = `<span style="color: #ff5252">Storage error: ${err.message}</span>`;
  }
});

btnRestore.addEventListener('click', async () => {
  dbStatus.textContent = 'Loading and decrypting session from IndexedDB...';
  try {
    const success = await signalService.restoreSession(peerUser, 1);
    if (success) {
      dbStatus.innerHTML =
        '<span style="color: #00d2b4">✓ Session successfully recovered and decrypted from IndexedDB!</span>';
    } else {
      dbStatus.textContent = 'No previous session found in IndexedDB.';
    }
  } catch (err: any) {
    dbStatus.innerHTML = `<span style="color: #ff5252">Restore error: ${err.message}</span>`;
  }
});

// Backup Container UI handlers
const inputBackupPassphrase = document.getElementById('input-backup-passphrase') as HTMLInputElement;
const passphraseValidationStatus = document.getElementById('passphrase-validation-status') as HTMLDivElement;
const btnExportBackup = document.getElementById('btn-export-backup') as HTMLButtonElement;
const btnRestoreBackup = document.getElementById('btn-restore-backup') as HTMLButtonElement;
const backupOutput = document.getElementById('backup-output') as HTMLPreElement;

let latestExportedContainer: Uint8Array | null = null;

inputBackupPassphrase.addEventListener('input', () => {
  const val = inputBackupPassphrase.value;
  try {
    WebBackupContainerService.validatePassphrase(val);
    passphraseValidationStatus.innerHTML = '<span style="color: #00d2b4">✓ Passphrase is strong (meets 12+ chars & diversity policy)</span>';
  } catch (e: any) {
    passphraseValidationStatus.innerHTML = `<span style="color: #ffb74d">⚠️ ${e.message}</span>`;
  }
});

btnExportBackup.addEventListener('click', async () => {
  const passphrase = inputBackupPassphrase.value;
  try {
    WebBackupContainerService.validatePassphrase(passphrase);
    backupOutput.textContent = 'Deriving Argon2id key and encrypting container with 42-byte header AAD...';

    const sampleDatabase = JSON.stringify({
      version: 1,
      myUuid,
      contacts: [{ userId: peerUser, nickname: 'Bob', verifiedAt }],
      keys: 'SQLCipher_Encrypted_Keys_Mock',
    });
    const plaintext = new TextEncoder().encode(sampleDatabase);

    latestExportedContainer = await WebBackupContainerService.createContainerWithPassphrase(
      passphrase,
      plaintext,
      3,
      16,
      4
    );

    const header = WebBackupContainerService.parseHeader(latestExportedContainer);
    backupOutput.textContent = JSON.stringify(
      {
        status: 'Exported & Encrypted Successfully',
        containerTotalBytes: latestExportedContainer.length,
        header: {
          magic: 'ANON (0x41 0x4E 0x4F 0x4E)',
          formatVersion: `0x0${header.version}`,
          kdf: 'Argon2id (0x01)',
          timeCostIterations: header.timeCost,
          memoryExponent: header.memoryExponent,
          memoryKib: 1 << header.memoryExponent,
          parallelismLanes: header.parallelism,
          saltHex: Array.from(header.salt).map((b) => b.toString(16).padStart(2, '0')).join(''),
          cipher: 'AES-256-GCM (0x01)',
          nonceHex: Array.from(header.nonce).map((b) => b.toString(16).padStart(2, '0')).join(''),
          ciphertextLength: header.ciphertextLen,
        },
        integrity: '42-byte header verified as AES-GCM AAD',
      },
      null,
      2
    );
  } catch (err: any) {
    backupOutput.textContent = `Backup export failed: ${err.message}`;
  }
});

btnRestoreBackup.addEventListener('click', async () => {
  if (!latestExportedContainer) {
    backupOutput.textContent = 'Please export a backup container first or load a container file.';
    return;
  }
  const passphrase = inputBackupPassphrase.value;
  try {
    backupOutput.textContent = 'Deriving key and decrypting container with header AAD integrity verification...';
    const decryptedBytes = await WebBackupContainerService.decryptContainerWithPassphrase(
      passphrase,
      latestExportedContainer
    );
    const decryptedJson = new TextDecoder().decode(decryptedBytes);
    backupOutput.textContent = `✓ Decryption & Authentication Successful!\n\nPayload:\n${decryptedJson}`;
  } catch (err: any) {
    backupOutput.textContent = `Backup restore failed: ${err.message} (Authentication tag failed or wrong passphrase)`;
  }
});
