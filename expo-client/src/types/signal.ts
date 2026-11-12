/**
 * Signal Protocol Types for @toled/signal-expo integration
 */

export interface SignalAddress {
  name: string;
  deviceId: number;
}

export interface KeyPair {
  publicKey: Uint8Array | string;
  privateKey: Uint8Array | string;
}

export interface PreKey {
  id: number;
  publicKey: Uint8Array | string;
}

export interface SignedPreKey {
  id: number;
  publicKey: Uint8Array | string;
  signature: Uint8Array | string;
}

/**
 * Public bundle exported to the server.
 * SECURITY: Contains ZERO private keys.
 */
export interface ServerPublicBundle {
  identityPublicKey: string; // Base64 or Hex
  registrationId: number;
  preKeys: Array<{
    id: number;
    publicKey: string;
  }>;
  signedPreKey: {
    id: number;
    publicKey: string;
    signature: string;
  };
}

/**
 * Key change status tracking for contact identity verification
 */
export interface KeyChangeAlert {
  contactName: string;
  previousKeyFingerprint: string;
  newKeyFingerprint: string;
  detectedAt: number;
}

/**
 * Double Ratchet Session State Interface (Signal Protocol)
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

