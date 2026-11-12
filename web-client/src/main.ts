import { SignalWasmService } from './crypto/signalWasmService';

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

let registrationBundle: any = null;
const myUuid = 'user-alice-' + Math.random().toString(36).substring(7);

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

btnTestCipher.addEventListener('click', () => {
  const plaintext = inputMsg.value || 'Hello Signal WASM!';
  const targetUser = 'user-bob';

  try {
    // 1. In real app, recipient bundle is fetched from relay server
    // For local prototype simulation:
    cipherOutput.textContent = 'Processing session and encrypting message...';

    // Simulated ciphertext format
    const mockCipher = {
      type: 3, // PreKeySignalMessage
      destination: targetUser,
      body: btoa(plaintext),
      timestamp: Date.now(),
    };

    cipherOutput.textContent = JSON.stringify(mockCipher, null, 2);

    // Safety Number demo
    safetyBox.textContent = '34912 80419 28103 48190 28190 19284';
  } catch (err: any) {
    cipherOutput.textContent = `Encryption error: ${err.message}`;
  }
});

btnPersist.addEventListener('click', async () => {
  dbStatus.textContent = 'Encrypting and saving session to IndexedDB (AES-256-GCM)...';
  try {
    await signalService.persistSession('user-bob', 1);
    dbStatus.innerHTML = '<span style="color: #00d2b4">✓ Session encrypted with non-extractable CryptoKey and stored in IndexedDB!</span>';
  } catch (err: any) {
    dbStatus.innerHTML = `<span style="color: #ff5252">Storage error: ${err.message}</span>`;
  }
});

btnRestore.addEventListener('click', async () => {
  dbStatus.textContent = 'Loading and decrypting session from IndexedDB...';
  try {
    const success = await signalService.restoreSession('user-bob', 1);
    if (success) {
      dbStatus.innerHTML = '<span style="color: #00d2b4">✓ Session successfully recovered and decrypted from IndexedDB!</span>';
    } else {
      dbStatus.textContent = 'No previous session found in IndexedDB.';
    }
  } catch (err: any) {
    dbStatus.innerHTML = `<span style="color: #ff5252">Restore error: ${err.message}</span>`;
  }
});

