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
});

