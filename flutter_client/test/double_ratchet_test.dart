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

      // Bob receives message and transitions
      bobSession.onMessageReceived(envelope['header'] as Map<String, dynamic>);
      expect(bobSession.bobFirstMessage, isFalse);
      expect(bobSession.nr, equals(1));
      expect(bobSession.dhr, equals(aliceSession.dhs.publicKey));
      expect(bobSession.sendingChainKey, isNotNull);
    });
  });
}
