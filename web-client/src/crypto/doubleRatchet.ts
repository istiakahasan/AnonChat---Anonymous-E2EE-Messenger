/**
 * AnonChat Double Ratchet State Initialization (Web / WASM / TypeScript)
 *
 * Implements:
 * - Sender State (Alice, who initiated X3DH)
 * - Receiver State (Bob)
 * - RatchetState serializable interface
 *
 * Invariants:
 * - Sender generates fresh DHs, sets DHr to bob_ratchet_public, derives RK and CKs,
 *   initializes CKr=null, Ns=0, Nr=0, PNs=0, MKSKIPPED={}, bobFirstMessage=false.
 * - Receiver sets DHs to bob_ratchet_keypair, DHr=null, RK=shared_secret,
 *   CKs=null, CKr=null, Ns=0, Nr=0, PNs=0, MKSKIPPED={}, bobFirstMessage=true.
 */

export interface RatchetState {
  DHs_pub: string; DHs_priv: string;  // current sender DH keypair (base64)
  DHr: string | null;                  // peer's current DH public key
  RK: string;                          // root key (32 bytes base64)
  CKs: string | null;                  // sending chain key
  CKr: string | null;                  // receiving chain key
  Ns: number; Nr: number; PNs: number;
  MKSKIPPED: Record<string, string>;   // key: "dhPub:msgNum"
}

export interface DoubleRatchetSessionState {
  dhsPrivate?: Uint8Array;
  dhsPublic?: Uint8Array;
  dhrPublic?: Uint8Array;
  rootKey: Uint8Array;
  sendingChainKey?: Uint8Array;
  receivingChainKey?: Uint8Array;
  ns: number;
  nr: number;
  pns: number;
  mkSkipped: Map<string, Uint8Array>;
  bobFirstMessage: boolean;
}

export interface RatchetKeyPair {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
}

/**
 * Base64 encoding/decoding utilities compatible with Web Crypto and browser WASM
 */
export function uint8ArrayToBase64(bytes: Uint8Array): string {
  if (typeof Buffer !== 'undefined') {
    return Buffer.from(bytes).toString('base64');
  }
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

export function base64ToUint8Array(base64: string): Uint8Array {
  if (typeof Buffer !== 'undefined') {
    return new Uint8Array(Buffer.from(base64, 'base64'));
  }
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function normalizeBytes(input: Uint8Array | string): Uint8Array {
  if (typeof input === 'string') {
    return base64ToUint8Array(input);
  }
  return input;
}

/**
 * Initializes Double Ratchet Sender State (Alice, who initiated X3DH).
 */
export async function initSenderState(
  sharedSecret: Uint8Array,
  bobRatchetPublic: Uint8Array,
  generateDhs?: () => Promise<RatchetKeyPair>
): Promise<DoubleRatchetSessionState> {
  const dhs = generateDhs
    ? await generateDhs()
    : {
        privateKey: window.crypto.getRandomValues(new Uint8Array(32)),
        publicKey: window.crypto.getRandomValues(new Uint8Array(32)),
      };

  return {
    dhsPrivate: dhs.privateKey,
    dhsPublic: dhs.publicKey,
    dhrPublic: new Uint8Array(bobRatchetPublic),
    rootKey: new Uint8Array(sharedSecret),
    sendingChainKey: undefined,
    receivingChainKey: undefined,
    ns: 0,
    nr: 0,
    pns: 0,
    mkSkipped: new Map<string, Uint8Array>(),
    bobFirstMessage: false,
  };
}

/**
 * Initializes Double Ratchet Sender State returning a serializable RatchetState.
 */
export async function initSenderRatchetSession(
  sharedSecret: Uint8Array | string,
  bobRatchetPublic: Uint8Array | string,
  generateDhs?: () => Promise<RatchetKeyPair>
): Promise<RatchetState> {
  const secretBytes = normalizeBytes(sharedSecret);
  const bobPubBytes = normalizeBytes(bobRatchetPublic);

  const dhs = generateDhs
    ? await generateDhs()
    : {
        privateKey: window.crypto.getRandomValues(new Uint8Array(32)),
        publicKey: window.crypto.getRandomValues(new Uint8Array(32)),
      };

  return {
    DHs_pub: uint8ArrayToBase64(dhs.publicKey),
    DHs_priv: uint8ArrayToBase64(dhs.privateKey),
    DHr: uint8ArrayToBase64(bobPubBytes),
    RK: uint8ArrayToBase64(secretBytes),
    CKs: null,
    CKr: null,
    Ns: 0,
    Nr: 0,
    PNs: 0,
    MKSKIPPED: {},
  };
}

/**
 * Initializes Double Ratchet Receiver State (Bob).
 */
export function initReceiverState(
  sharedSecret: Uint8Array,
  bobRatchetKeypair: RatchetKeyPair
): DoubleRatchetSessionState {
  return {
    dhsPrivate: new Uint8Array(bobRatchetKeypair.privateKey),
    dhsPublic: new Uint8Array(bobRatchetKeypair.publicKey),
    dhrPublic: undefined,
    rootKey: new Uint8Array(sharedSecret),
    sendingChainKey: undefined,
    receivingChainKey: undefined,
    ns: 0,
    nr: 0,
    pns: 0,
    mkSkipped: new Map<string, Uint8Array>(),
    bobFirstMessage: true,
  };
}

/**
 * Initializes Double Ratchet Receiver State returning a serializable RatchetState.
 */
export function initReceiverRatchetSession(
  sharedSecret: Uint8Array | string,
  bobRatchetKeypair: RatchetKeyPair | { privateKey: string; publicKey: string }
): RatchetState {
  const secretBytes = normalizeBytes(sharedSecret);
  const privStr =
    typeof bobRatchetKeypair.privateKey === 'string'
      ? bobRatchetKeypair.privateKey
      : uint8ArrayToBase64(bobRatchetKeypair.privateKey);
  const pubStr =
    typeof bobRatchetKeypair.publicKey === 'string'
      ? bobRatchetKeypair.publicKey
      : uint8ArrayToBase64(bobRatchetKeypair.publicKey);

  return {
    DHs_pub: pubStr,
    DHs_priv: privStr,
    DHr: null,
    RK: uint8ArrayToBase64(secretBytes),
    CKs: null,
    CKr: null,
    Ns: 0,
    Nr: 0,
    PNs: 0,
    MKSKIPPED: {},
  };
}

/**
 * Converts DoubleRatchetSessionState to JSON-serializable RatchetState
 */
export function toRatchetState(session: DoubleRatchetSessionState): RatchetState {
  const mkSkippedRecord: Record<string, string> = {};
  session.mkSkipped.forEach((val, key) => {
    mkSkippedRecord[key] = uint8ArrayToBase64(val);
  });

  return {
    DHs_pub: session.dhsPublic ? uint8ArrayToBase64(session.dhsPublic) : '',
    DHs_priv: session.dhsPrivate ? uint8ArrayToBase64(session.dhsPrivate) : '',
    DHr: session.dhrPublic ? uint8ArrayToBase64(session.dhrPublic) : null,
    RK: uint8ArrayToBase64(session.rootKey),
    CKs: session.sendingChainKey ? uint8ArrayToBase64(session.sendingChainKey) : null,
    CKr: session.receivingChainKey ? uint8ArrayToBase64(session.receivingChainKey) : null,
    Ns: session.ns,
    Nr: session.nr,
    PNs: session.pns,
    MKSKIPPED: mkSkippedRecord,
  };
}

/**
 * Reconstructs DoubleRatchetSessionState from RatchetState
 */
export function fromRatchetState(state: RatchetState): DoubleRatchetSessionState {
  const mkSkipped = new Map<string, Uint8Array>();
  for (const [key, val] of Object.entries(state.MKSKIPPED)) {
    mkSkipped.set(key, base64ToUint8Array(val));
  }

  return {
    dhsPublic: state.DHs_pub ? base64ToUint8Array(state.DHs_pub) : undefined,
    dhsPrivate: state.DHs_priv ? base64ToUint8Array(state.DHs_priv) : undefined,
    dhrPublic: state.DHr ? base64ToUint8Array(state.DHr) : undefined,
    rootKey: base64ToUint8Array(state.RK),
    sendingChainKey: state.CKs ? base64ToUint8Array(state.CKs) : undefined,
    receivingChainKey: state.CKr ? base64ToUint8Array(state.CKr) : undefined,
    ns: state.Ns,
    nr: state.Nr,
    pns: state.PNs,
    mkSkipped,
    bobFirstMessage: state.DHr === null,
  };
}

export interface RatchetMessageHeader {
  dh: string;
  pn: number;
  n: number;
}

/**
 * Wire packet transmitted over the relay server (Sub-Step 4.5).
 *
 * Layout:
 * ```json
 * {
 *   "v": 1,
 *   "header": {
 *     "dh": "base64_x25519_public_key",
 *     "pn": 0,
 *     "n": 42
 *   },
 *   "nonce": "base64_12_bytes",
 *   "ciphertext": "base64_aes_gcm_output_with_tag"
 * }
 * ```
 */
export interface WirePacket {
  v: number;
  header: RatchetMessageHeader;
  nonce: string;
  ciphertext: string;
}

export interface RatchetEnvelope extends WirePacket {
  v: number;
  header: RatchetMessageHeader;
  ciphertext: string;
  nonce: string;
  mk?: string;
}

/**
 * Validates wire packet fields according to Sub-Step 4.5 specification.
 */
export function validateWirePacket(packet: WirePacket): void {
  if (packet.v !== 1) {
    throw new Error(`Unsupported wire packet version: ${packet.v}`);
  }
  if (!packet.header || typeof packet.header.dh !== 'string') {
    throw new Error('Invalid wire packet: missing header.dh');
  }
  const dhBytes = base64ToUint8Array(packet.header.dh);
  if (dhBytes.length !== 32) {
    throw new Error(`Invalid ratchet public key length: ${dhBytes.length}`);
  }
  const nonceBytes = base64ToUint8Array(packet.nonce);
  if (nonceBytes.length !== 12) {
    throw new Error(`Invalid nonce length: expected 12 bytes, got ${nonceBytes.length}`);
  }
  const ctBytes = base64ToUint8Array(packet.ciphertext);
  if (ctBytes.length < 16) {
    throw new Error(`Invalid ciphertext: length ${ctBytes.length} < 16 (missing tag)`);
  }
}

/**
 * Serializes a WirePacket to a JSON string with format validation.
 */
export function serializeWirePacket(packet: WirePacket): string {
  validateWirePacket(packet);
  return JSON.stringify(packet);
}

/**
 * Deserializes a WirePacket from a JSON string with format validation.
 */
export function deserializeWirePacket(jsonStr: string): WirePacket {
  const parsed = JSON.parse(jsonStr) as WirePacket;
  validateWirePacket(parsed);
  return parsed;
}

/**
 * Serializes RatchetState to a JSON string for persistent encrypted storage (Sub-Step 4.5).
 */
export function serializeRatchetState(state: RatchetState): string {
  return JSON.stringify(state);
}

/**
 * Deserializes RatchetState from a JSON string.
 */
export function deserializeRatchetState(jsonStr: string): RatchetState {
  const parsed = JSON.parse(jsonStr) as RatchetState;
  if (!parsed.RK || !parsed.DHs_priv || !parsed.DHs_pub) {
    throw new Error('Invalid RatchetState: missing required key material');
  }
  return parsed;
}

/**
 * Exports DoubleRatchetSessionState to a JSON string.
 */
export function exportSessionState(session: DoubleRatchetSessionState): string {
  const state = toRatchetState(session);
  return serializeRatchetState(state);
}

/**
 * Imports DoubleRatchetSessionState from a JSON string.
 */
export function importSessionState(jsonStr: string): DoubleRatchetSessionState {
  const state = deserializeRatchetState(jsonStr);
  return fromRatchetState(state);
}

export async function kdfCk(ck: Uint8Array): Promise<{ nextCk: Uint8Array; mk: Uint8Array }> {
  const hmacKey = await window.crypto.subtle.importKey(
    'raw',
    ck,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const mkBuffer = await window.crypto.subtle.sign('HMAC', hmacKey, new Uint8Array([0x01]));
  const nextCkBuffer = await window.crypto.subtle.sign('HMAC', hmacKey, new Uint8Array([0x02]));
  return {
    nextCk: new Uint8Array(nextCkBuffer),
    mk: new Uint8Array(mkBuffer),
  };
}

export async function kdfCK(cks: string | Uint8Array): Promise<[string, Uint8Array]> {
  const cksBytes = typeof cks === 'string' ? base64ToUint8Array(cks) : cks;
  const { nextCk, mk } = await kdfCk(cksBytes);
  return [uint8ArrayToBase64(nextCk), mk];
}

export function padTo4KB(payload: Uint8Array): Uint8Array {
  const blockSize = 4096;
  const minCapacity = 4 + payload.length;
  const targetSize = Math.ceil(minCapacity / blockSize) * blockSize;
  const padLen = targetSize - minCapacity;

  const result = new Uint8Array(targetSize);
  const view = new DataView(result.buffer);
  view.setUint32(0, payload.length, false);
  result.set(payload, 4);

  const randomPad = window.crypto.getRandomValues(new Uint8Array(padLen));
  result.set(randomPad, 4 + payload.length);
  return result;
}

export async function aesGcmEncrypt(
  mk: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array | string,
  additionalData?: Uint8Array
): Promise<Uint8Array> {
  const rawBytes = typeof plaintext === 'string' ? new TextEncoder().encode(plaintext) : plaintext;
  const padded = padTo4KB(rawBytes);

  const cryptoKey = await window.crypto.subtle.importKey(
    'raw',
    mk,
    { name: 'AES-GCM' },
    false,
    ['encrypt']
  );

  const ctBuffer = await window.crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: nonce,
      additionalData: additionalData || new Uint8Array(0),
      tagLength: 128,
    },
    cryptoKey,
    padded
  );

  return new Uint8Array(ctBuffer);
}

export async function ratchetEncrypt(
  state: RatchetState,
  plaintext: Uint8Array | string,
  performDhRatchet?: (state: RatchetState) => Promise<void>
): Promise<RatchetEnvelope> {
  if (!state.CKs) {
    if (performDhRatchet) {
      await performDhRatchet(state);
    } else {
      if (!state.DHr) {
        throw new Error('Cannot send message before receiving peer ratchet key');
      }
      throw new Error('Missing sending chain key');
    }
  }

  // 1. Derive message key
  const [newCKs, MK] = await kdfCK(state.CKs);

  // 2. Build header
  const header: RatchetMessageHeader = {
    dh: state.DHs_pub,
    pn: state.PNs,
    n: state.Ns,
  };
  const headerBytes = new TextEncoder().encode(JSON.stringify(header));

  // 3. Encrypt with AES-GCM
  const nonce = window.crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await aesGcmEncrypt(MK, nonce, plaintext, headerBytes);

  // 4. Update state
  state.CKs = newCKs;
  state.Ns += 1;

  return {
    v: 1,
    header,
    nonce: uint8ArrayToBase64(nonce),
    ciphertext: uint8ArrayToBase64(ciphertext),
    mk: uint8ArrayToBase64(MK),
  };
}

export const MAX_SKIP = 100;
export const MAX_SKIPPED_KEYS = 1000;

export function unpad4KB(padded: Uint8Array): Uint8Array {
  if (padded.length < 4) {
    throw new Error('Padded payload too short: minimum 4 bytes required');
  }
  const view = new DataView(padded.buffer, padded.byteOffset, padded.byteLength);
  const originalLen = view.getUint32(0, false);
  if (4 + originalLen > padded.length) {
    throw new Error('Padded payload corrupted: invalid length field');
  }
  return padded.slice(4, 4 + originalLen);
}

export async function skipMessageKeys(state: RatchetState, until: number): Promise<void> {
  if (until > state.Nr + MAX_SKIP) {
    throw new Error(`Skip gap too large: ${until - state.Nr} > ${MAX_SKIP} (MAX_SKIP DoS defense)`);
  }

  if (state.CKr) {
    let currentCkr = base64ToUint8Array(state.CKr);
    const dhrStr = state.DHr || '';

    while (state.Nr < until) {
      if (Object.keys(state.MKSKIPPED).length >= MAX_SKIPPED_KEYS) {
        throw new Error(`Skipped keys table reached maximum capacity (${MAX_SKIPPED_KEYS})`);
      }

      const { nextCk, mk } = await kdfCk(currentCkr);
      currentCkr = nextCk;
      state.MKSKIPPED[`${dhrStr}:${state.Nr}`] = uint8ArrayToBase64(mk);
      state.Nr += 1;
    }

    state.CKr = uint8ArrayToBase64(currentCkr);
  }
}

export async function ratchetDecrypt(
  state: RatchetState,
  header: RatchetMessageHeader,
  nonce: Uint8Array | string,
  ciphertext: Uint8Array | string,
  performDhRatchet?: (state: RatchetState, peerDhPub: string) => Promise<void>
): Promise<Uint8Array> {
  const nonceBytes = typeof nonce === 'string' ? base64ToUint8Array(nonce) : nonce;
  const ctBytes = typeof ciphertext === 'string' ? base64ToUint8Array(ciphertext) : ciphertext;

  const headerKey = `${header.dh}:${header.n}`;
  const headerBytes = new TextEncoder().encode(
    JSON.stringify({
      dh: header.dh,
      n: header.n,
      pn: header.pn,
    })
  );

  // 1. Check skipped keys first
  if (state.MKSKIPPED[headerKey]) {
    const mk = base64ToUint8Array(state.MKSKIPPED[headerKey]);
    delete state.MKSKIPPED[headerKey];

    const cryptoKey = await window.crypto.subtle.importKey(
      'raw',
      mk,
      { name: 'AES-GCM' },
      false,
      ['decrypt']
    );

    const ptBuffer = await window.crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: nonceBytes, additionalData: headerBytes, tagLength: 128 },
      cryptoKey,
      ctBytes
    );

    mk.fill(0);
    return unpad4KB(new Uint8Array(ptBuffer));
  }

  // 2. Check for DH ratchet step
  if (!state.DHr || state.DHr !== header.dh) {
    await skipMessageKeys(state, header.pn);
    if (performDhRatchet) {
      await performDhRatchet(state, header.dh);
    } else {
      state.DHr = header.dh;
      state.PNs = state.Ns;
      state.Ns = 0;
      state.Nr = 0;
    }
  } else if (header.n < state.Nr) {
    // Sub-Step SM.2: Enforce message key uniqueness
    throw new Error('Duplicate or already-consumed message: message key cannot be reused');
  }

  // 3. Skip messages in the new chain
  await skipMessageKeys(state, header.n);

  // 4. Derive message key
  if (!state.CKr) {
    throw new Error('Missing receiving chain key');
  }
  const ckrBytes = base64ToUint8Array(state.CKr);
  const { nextCk, mk } = await kdfCk(ckrBytes);
  state.CKr = uint8ArrayToBase64(nextCk);
  state.Nr += 1;

  // 5. Decrypt
  const cryptoKey = await window.crypto.subtle.importKey(
    'raw',
    mk,
    { name: 'AES-GCM' },
    false,
    ['decrypt']
  );

  const ptBuffer = await window.crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: nonceBytes, additionalData: headerBytes, tagLength: 128 },
    cryptoKey,
    ctBytes
  );

  mk.fill(0);
  return unpad4KB(new Uint8Array(ptBuffer));
}

export async function kdfRk(rk: Uint8Array, dhOut: Uint8Array): Promise<[Uint8Array, Uint8Array]> {
  const hmacKey = await window.crypto.subtle.importKey(
    'raw',
    rk,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const prkBuffer = await window.crypto.subtle.sign('HMAC', hmacKey, dhOut);
  const prkKey = await window.crypto.subtle.importKey(
    'raw',
    prkBuffer,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );

  const info = new TextEncoder().encode('DoubleRatchet');
  const t1Input = new Uint8Array(info.length + 1);
  t1Input.set(info, 0);
  t1Input[info.length] = 0x01;
  const t1 = new Uint8Array(await window.crypto.subtle.sign('HMAC', prkKey, t1Input));

  const t2Input = new Uint8Array(t1.length + info.length + 1);
  t2Input.set(t1, 0);
  t2Input.set(info, t1.length);
  t2Input[t1.length + info.length] = 0x02;
  const t2 = new Uint8Array(await window.crypto.subtle.sign('HMAC', prkKey, t2Input));

  return [t1, t2];
}

export async function dhRatchet(
  state: RatchetState,
  peerDhPub: string,
  computeDh?: (priv: Uint8Array, pub: Uint8Array) => Promise<Uint8Array>,
  generateKeyPair?: () => Promise<RatchetKeyPair>
): Promise<void> {
  state.PNs = state.Ns;
  state.Ns = 0;
  state.Nr = 0;
  state.DHr = peerDhPub;

  if (computeDh && generateKeyPair) {
    const peerDhBytes = base64ToUint8Array(peerDhPub);
    const rkBytes = base64ToUint8Array(state.RK);

    const dhOutRx = await computeDh(base64ToUint8Array(state.DHs_priv), peerDhBytes);
    const [newRkRx, ckr] = await kdfRk(rkBytes, dhOutRx);
    state.CKr = uint8ArrayToBase64(ckr);

    const newDhs = await generateKeyPair();
    state.DHs_priv = uint8ArrayToBase64(newDhs.privateKey);
    state.DHs_pub = uint8ArrayToBase64(newDhs.publicKey);

    const dhOutTx = await computeDh(newDhs.privateKey, peerDhBytes);
    const [newRkTx, cks] = await kdfRk(newRkRx, dhOutTx);
    state.RK = uint8ArrayToBase64(newRkTx);
    state.CKs = uint8ArrayToBase64(cks);
  }
}
