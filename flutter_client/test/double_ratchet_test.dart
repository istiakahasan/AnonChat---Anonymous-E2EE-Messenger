import 'dart:typed_data';
import 'package:flutter_test/flutter_test.dart';
import 'package:anonchat_flutter/src/crypto/double_ratchet.dart';

void main() {
  group('DoubleRatchet (Flutter / Dart)', () {
    test('initializes sender and receiver states correctly from X3DH shared secret', () {
      final sodium = null; // optional engine or null
      final ratchet = DoubleRatchet(sodium);

      final sharedSecret = Uint8List(32)..fillRange(0, 32, 0x42);
      final bobRatchetKeyPair = RatchetKeyPair.generate();
      final bobPublicKey = bobRatchetKeyPair.publicKey;

      // Alice:
      final aliceSession = ratchet.initSenderSession(sharedSecret, bobPublicKey);
      // Bob:
      final bobSession = ratchet.initReceiverSession(sharedSecret, bobRatchetKeyPair);

      // Verify Alice Sender State
      expect(aliceSession.dhs.publicKey.length, equals(32));
      expect(aliceSession.dhr, equals(bobPublicKey));
      expect(aliceSession.rootKey.length, equals(32));
      expect(aliceSession.rootKey, isNot(equals(sharedSecret)));
      expect(aliceSession.sendingChainKey, isNotNull);
      expect(aliceSession.sendingChainKey!.length, equals(32));
      expect(aliceSession.receivingChainKey, isNull);
      expect(aliceSession.ns, equals(0));
      expect(aliceSession.nr, equals(0));
      expect(aliceSession.pns, equals(0));
      expect(aliceSession.mkSkipped.isEmpty, isTrue);
      expect(aliceSession.bobFirstMessage, isFalse);

      // Verify Bob Receiver State
      expect(bobSession.dhs.publicKey, equals(bobPublicKey));
      expect(bobSession.dhr, isNull);
      expect(bobSession.rootKey, equals(sharedSecret));
      expect(bobSession.sendingChainKey, isNull);
      expect(bobSession.receivingChainKey, isNull);
      expect(bobSession.ns, equals(0));
      expect(bobSession.nr, equals(0));
      expect(bobSession.pns, equals(0));
      expect(bobSession.mkSkipped.isEmpty, isTrue);
      expect(bobSession.bobFirstMessage, isTrue);
    });

    test('performs initial handshake and transitions bobFirstMessage', () {
      final ratchet = DoubleRatchet();
      final sharedSecret = Uint8List(32)..fillRange(0, 32, 0x77);
      final bobRatchetKeyPair = RatchetKeyPair.generate();

      final aliceSession = ratchet.initSenderSession(sharedSecret, bobRatchetKeyPair.publicKey);
      final bobSession = ratchet.initReceiverSession(sharedSecret, bobRatchetKeyPair);

      // Alice sends message
      final envelope = aliceSession.ratchetEncrypt('Hello Bob!');
      expect(aliceSession.ns, equals(1));

      // Bob decrypts message through standard library ratchetDecrypt API
      final pt = bobSession.ratchetDecrypt(envelope);
      expect(utf8.decode(pt), equals('Hello Bob!'));
      expect(bobSession.bobFirstMessage, isFalse);
      expect(bobSession.nr, equals(1));
      expect(bobSession.dhr, equals(aliceSession.dhs.publicKey));
      expect(bobSession.sendingChainKey, isNotNull);
    });

    test('Sub-Step 4.2: Encrypt a message (Sender Path) requirements', () {
      final ratchet = DoubleRatchet();
      final sharedSecret = Uint8List(32)..fillRange(0, 32, 0x88);
      final bobRatchetKeyPair = RatchetKeyPair.generate();

      final aliceSession = ratchet.initSenderSession(sharedSecret, bobRatchetKeyPair.publicKey);
      final bobSession = ratchet.initReceiverSession(sharedSecret, bobRatchetKeyPair);

      // 1. Bob cannot send before receiving peer ratchet key
      expect(() => bobSession.ratchetEncrypt('Cannot send yet'), throwsA(isA<StateError>()));

      // 2. Alice sends message: header contains canonical dh, pn, n; ns increments
      final env1 = aliceSession.ratchetEncrypt('Alice message 1');
      expect(aliceSession.ns, equals(1));
      final header1 = env1['header'] as Map<String, dynamic>;
      expect(header1['dh'], isNotNull);
      expect(header1['n'], equals(0));
      expect(header1['pn'], equals(0));
      expect(env1['nonce'], isNotNull);

      // 3. Alice sends second message: ns increments to 2, fresh random nonce generated
      final env2 = aliceSession.ratchetEncrypt('Alice message 2');
      expect(aliceSession.ns, equals(2));
      final header2 = env2['header'] as Map<String, dynamic>;
      expect(header2['n'], equals(1));
      expect(header2['pn'], equals(0));
      expect(env2['nonce'], isNot(equals(env1['nonce']))); // Random nonce independence

      // 4. Bob receives Alice's message via standard ratchetDecrypt, then encrypts reply (CKs ratchet send step)
      bobSession.ratchetDecrypt(env1);
      final bobReply = bobSession.ratchetEncrypt('Bob reply 1');
      expect(bobSession.ns, equals(1));
      final bobHeader = bobReply['header'] as Map<String, dynamic>;
      expect(bobHeader['n'], equals(0));
      expect(bobHeader['dh'], isNotNull);
    });

    test('Sub-Step 4.3: Decrypt a message (Receiver Path) & Out-of-Order handling', () {
      final ratchet = DoubleRatchet();
      final sharedSecret = Uint8List(32)..fillRange(0, 32, 0x99);
      final bobRatchetKeyPair = RatchetKeyPair.generate();

      final aliceSession = ratchet.initSenderSession(sharedSecret, bobRatchetKeyPair.publicKey);
      final bobSession = ratchet.initReceiverSession(sharedSecret, bobRatchetKeyPair);

      // In-order decryption
      final pkt0 = ratchet.encrypt(aliceSession, 'Packet 0');
      final pt0 = ratchet.decrypt(bobSession, pkt0);
      expect(String.fromCharCodes(pt0), equals('Packet 0'));
      expect(bobSession.nr, equals(1));

      // Out-of-order delivery: Alice sends 1, 2, 3; Bob receives 3 first
      final pkt1 = ratchet.encrypt(aliceSession, 'Packet 1');
      final pkt2 = ratchet.encrypt(aliceSession, 'Packet 2');
      final pkt3 = ratchet.encrypt(aliceSession, 'Packet 3');

      // Packet 3 arrives first
      final pt3 = ratchet.decrypt(bobSession, pkt3);
      expect(String.fromCharCodes(pt3), equals('Packet 3'));
      expect(bobSession.nr, equals(4));
      expect(bobSession.mkSkipped.isNotEmpty, isTrue);

      // Packet 1 arrives later (from skipped keys)
      final pt1 = ratchet.decrypt(bobSession, pkt1);
      expect(String.fromCharCodes(pt1), equals('Packet 1'));

      // Packet 2 arrives later (from skipped keys)
      final pt2 = ratchet.decrypt(bobSession, pkt2);
      expect(String.fromCharCodes(pt2), equals('Packet 2'));

      // MAX_SKIP = 100 defense: attacker sending n = 500 is rejected
      final maliciousPkt = {
        'header': {'dh': pkt3['header']['dh'], 'pn': 0, 'n': 500},
        'ciphertext': pkt3['ciphertext'],
        'nonce': pkt3['nonce'],
      };
      expect(() => ratchet.decrypt(bobSession, maliciousPkt), throwsA(isA<StateError>()));
    });

    test('Sub-Step 4.4: DH Ratchet Step & Continuous Rekeying', () {
      final ratchet = DoubleRatchet();
      final sharedSecret = Uint8List(32)..fillRange(0, 32, 0x42);
      final bobRatchetKeyPair = RatchetKeyPair.generate();

      final aliceSession = ratchet.initSenderSession(sharedSecret, bobRatchetKeyPair.publicKey);
      final bobSession = ratchet.initReceiverSession(sharedSecret, bobRatchetKeyPair);

      // Alice sends message 0
      final msg0 = ratchet.encrypt(aliceSession, 'Round 1 Alice');
      final pt0 = ratchet.decrypt(bobSession, msg0);
      expect(String.fromCharCodes(pt0), equals('Round 1 Alice'));
      expect(bobSession.dhr, isNotNull);

      // Bob replies: triggers sender DH ratchet turn
      final reply0 = ratchet.encrypt(bobSession, 'Round 1 Bob reply');
      final replyPt0 = ratchet.decrypt(aliceSession, reply0);
      expect(String.fromCharCodes(replyPt0), equals('Round 1 Bob reply'));
    });

    test('Sub-Step 4.5: Wire Format & State Persistence', () {
      final ratchet = DoubleRatchet();
      final sharedSecret = Uint8List(32)..fillRange(0, 32, 0x77);
      final bobRatchetKeyPair = RatchetKeyPair.generate();

      final aliceSession = ratchet.initSenderSession(sharedSecret, bobRatchetKeyPair.publicKey);
      final bobSession = ratchet.initReceiverSession(sharedSecret, bobRatchetKeyPair);

      // 1. WirePacket validation and JSON serialization
      final wirePkt = aliceSession.encryptWire('Hello over the wire');
      expect(wirePkt.v, equals(1));
      expect(wirePkt.header['dh'], isNotNull);
      expect(wirePkt.header['n'], equals(0));
      expect(wirePkt.header['pn'], equals(0));
      expect(base64.decode(wirePkt.nonce).length, equals(12));

      final jsonStr = wirePkt.toJsonString();
      final parsedWire = WirePacket.fromJsonString(jsonStr);
      expect(parsedWire.v, equals(1));
      expect(parsedWire.nonce, equals(wirePkt.nonce));
      expect(parsedWire.ciphertext, equals(wirePkt.ciphertext));

      // Unsupported version rejection
      final badVersionJson = {'v': 2, 'header': wirePkt.header, 'nonce': wirePkt.nonce, 'ciphertext': wirePkt.ciphertext};
      expect(() => WirePacket.fromJson(badVersionJson), throwsA(isA<FormatException>()));

      // 2. State Persistence: serialize Alice and Bob state to JSON
      final aliceSavedJson = aliceSession.toJsonString();
      final bobSavedJson = bobSession.toJsonString();

      // Restore sessions from saved JSON (simulating app restart)
      final aliceRestored = DoubleRatchetSession.fromJsonString(aliceSavedJson);
      final bobRestored = DoubleRatchetSession.fromJsonString(bobSavedJson);

      expect(aliceRestored.ns, equals(aliceSession.ns));
      expect(bobRestored.bobFirstMessage, equals(bobSession.bobFirstMessage));

      // Decrypt wire packet using restored Bob session
      final pt = ratchet.decrypt(bobRestored, parsedWire.toJson());
      expect(String.fromCharCodes(pt), equals('Hello over the wire'));

      // Bob replies using restored session
      final replyWire = bobRestored.encryptWire('Restored Bob reply');
      final replyPt = ratchet.decrypt(aliceRestored, replyWire.toJson());
      expect(String.fromCharCodes(replyPt), equals('Restored Bob reply'));
    });
  });
}

