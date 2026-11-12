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
