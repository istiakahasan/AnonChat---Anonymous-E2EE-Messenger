import {
  RatchetState,
  initSenderRatchetSession,
  initReceiverRatchetSession,
  toRatchetState,
  fromRatchetState,
  initSenderState,
  initReceiverState,
  uint8ArrayToBase64,
  base64ToUint8Array,
  ratchetEncrypt,
  ratchetDecrypt,
  MAX_SKIP,
} from '../src/crypto/doubleRatchet';

describe('RatchetState & DoubleRatchet State Machine', () => {
  const mockSharedSecret = new Uint8Array(32).fill(0x5a);
  const mockBobKeyPair = {
    privateKey: new Uint8Array(32).fill(0x11),
    publicKey: new Uint8Array(32).fill(0x22),
  };

  test('initializes sender and receiver RatchetState conforming to interface specification', async () => {
    // Alice (Sender):
    const aliceState: RatchetState = await initSenderRatchetSession(
      mockSharedSecret,
      mockBobKeyPair.publicKey
    );

    // Verify Alice RatchetState fields
    expect(typeof aliceState.DHs_pub).toBe('string');
    expect(typeof aliceState.DHs_priv).toBe('string');
    expect(aliceState.DHr).toBe(uint8ArrayToBase64(mockBobKeyPair.publicKey));
    expect(aliceState.RK).toBe(uint8ArrayToBase64(mockSharedSecret));
    expect(aliceState.CKs).toBeNull();
    expect(aliceState.CKr).toBeNull();
    expect(aliceState.Ns).toBe(0);
    expect(aliceState.Nr).toBe(0);
    expect(aliceState.PNs).toBe(0);
    expect(aliceState.MKSKIPPED).toEqual({});

    // Bob (Receiver):
    const bobState: RatchetState = initReceiverRatchetSession(
      mockSharedSecret,
      mockBobKeyPair
    );

    // Verify Bob RatchetState fields
    expect(bobState.DHs_pub).toBe(uint8ArrayToBase64(mockBobKeyPair.publicKey));
    expect(bobState.DHs_priv).toBe(uint8ArrayToBase64(mockBobKeyPair.privateKey));
    expect(bobState.DHr).toBeNull();
    expect(bobState.RK).toBe(uint8ArrayToBase64(mockSharedSecret));
    expect(bobState.CKs).toBeNull();
    expect(bobState.CKr).toBeNull();
    expect(bobState.Ns).toBe(0);
    expect(bobState.Nr).toBe(0);
    expect(bobState.PNs).toBe(0);
    expect(bobState.MKSKIPPED).toEqual({});
  });

  test('roundtrips between DoubleRatchetSessionState and RatchetState', async () => {
    const session = await initSenderState(mockSharedSecret, mockBobKeyPair.publicKey);
    session.mkSkipped.set('peerDhBase64:1', new Uint8Array(32).fill(0x99));

    const state = toRatchetState(session);
    expect(typeof state.DHs_pub).toBe('string');
    expect(typeof state.MKSKIPPED['peerDhBase64:1']).toBe('string');

    const recovered = fromRatchetState(state);
    expect(recovered.rootKey).toEqual(session.rootKey);
    expect(recovered.dhrPublic).toEqual(session.dhrPublic);
    expect(recovered.ns).toBe(session.ns);
    expect(recovered.nr).toBe(session.nr);
    expect(recovered.mkSkipped.get('peerDhBase64:1')).toEqual(new Uint8Array(32).fill(0x99));
  });

  test('Sub-Step 4.2: Encrypt message advances sending chain, generates nonce, and builds header', async () => {
    const state: RatchetState = {
      DHs_pub: uint8ArrayToBase64(new Uint8Array(32).fill(0x01)),
      DHs_priv: uint8ArrayToBase64(new Uint8Array(32).fill(0x02)),
      DHr: uint8ArrayToBase64(new Uint8Array(32).fill(0x03)),
      RK: uint8ArrayToBase64(new Uint8Array(32).fill(0x04)),
      CKs: uint8ArrayToBase64(new Uint8Array(32).fill(0x05)),
      CKr: null,
      Ns: 0,
      Nr: 0,
      PNs: 0,
      MKSKIPPED: {},
    };

    // Message 1
    const env1 = await ratchetEncrypt(state, 'Hello from TypeScript Double Ratchet');
    expect(state.Ns).toBe(1);
    expect(env1.header.dh).toBe(state.DHs_pub);
    expect(env1.header.n).toBe(0);
    expect(env1.header.pn).toBe(0);
    expect(env1.nonce).toBeDefined();

    // Message 2
    const env2 = await ratchetEncrypt(state, 'Second message');
    expect(state.Ns).toBe(2);
    expect(env2.header.n).toBe(1);
    expect(env2.header.pn).toBe(0);
    expect(env2.nonce).not.toBe(env1.nonce); // Fresh random nonce
  });

  test('Sub-Step 4.3: Decrypt a message (Receiver Path) & Out-of-Order handling', async () => {
    // Setup matching receiver state
    const sharedSecret = new Uint8Array(32).fill(0x33);
    const sharedCks = new Uint8Array(32).fill(0x77);

    const senderState: RatchetState = {
      DHs_pub: uint8ArrayToBase64(new Uint8Array(32).fill(0x10)),
      DHs_priv: uint8ArrayToBase64(new Uint8Array(32).fill(0x11)),
      DHr: uint8ArrayToBase64(new Uint8Array(32).fill(0x20)),
      RK: uint8ArrayToBase64(sharedSecret),
      CKs: uint8ArrayToBase64(sharedCks),
      CKr: null,
      Ns: 0,
      Nr: 0,
      PNs: 0,
      MKSKIPPED: {},
    };

    const receiverState: RatchetState = {
      DHs_pub: uint8ArrayToBase64(new Uint8Array(32).fill(0x20)),
      DHs_priv: uint8ArrayToBase64(new Uint8Array(32).fill(0x21)),
      DHr: uint8ArrayToBase64(new Uint8Array(32).fill(0x10)),
      RK: uint8ArrayToBase64(sharedSecret),
      CKs: null,
      CKr: uint8ArrayToBase64(sharedCks), // Synchronized receiving chain
      Ns: 0,
      Nr: 0,
      PNs: 0,
      MKSKIPPED: {},
    };

    // 1. In-order decryption
    const env0 = await ratchetEncrypt(senderState, 'Message zero');
    const pt0 = await ratchetDecrypt(receiverState, env0.header, env0.nonce, env0.ciphertext);
    expect(new TextDecoder().decode(pt0)).toBe('Message zero');
    expect(receiverState.Nr).toBe(1);

    // 2. Out-of-order delivery: Send messages 1, 2, 3; Receive 3 first
    const env1 = await ratchetEncrypt(senderState, 'Message one');
    const env2 = await ratchetEncrypt(senderState, 'Message two');
    const env3 = await ratchetEncrypt(senderState, 'Message three');

    // Deliver message 3 first (skipping 1 and 2)
    const pt3 = await ratchetDecrypt(receiverState, env3.header, env3.nonce, env3.ciphertext);
    expect(new TextDecoder().decode(pt3)).toBe('Message three');
    expect(receiverState.Nr).toBe(4);
    expect(receiverState.MKSKIPPED[`${env3.header.dh}:1`]).toBeDefined();
    expect(receiverState.MKSKIPPED[`${env3.header.dh}:2`]).toBeDefined();

    // Deliver delayed message 1
    const pt1 = await ratchetDecrypt(receiverState, env1.header, env1.nonce, env1.ciphertext);
    expect(new TextDecoder().decode(pt1)).toBe('Message one');
    // Once used, removed from MKSKIPPED
    expect(receiverState.MKSKIPPED[`${env1.header.dh}:1`]).toBeUndefined();

    // Deliver delayed message 2
    const pt2 = await ratchetDecrypt(receiverState, env2.header, env2.nonce, env2.ciphertext);
    expect(new TextDecoder().decode(pt2)).toBe('Message two');
    expect(receiverState.MKSKIPPED[`${env2.header.dh}:2`]).toBeUndefined();

    // 3. MAX_SKIP = 100 DoS defense: gap > 100 rejected
    const maliciousHeader = { dh: env3.header.dh, pn: 0, n: receiverState.Nr + MAX_SKIP + 1 };
    await expect(
      ratchetDecrypt(receiverState, maliciousHeader, env3.nonce, env3.ciphertext)
    ).rejects.toThrow(/MAX_SKIP DoS defense/);
  });
});

