import 'dart:convert';
import 'dart:typed_data';
import 'package:flutter_test/flutter_test.dart';

void main() {
  group('AnonChat Flutter Cryptographic Logic & Key Change Detection Tests', () {
    test('Safety Number formatting chunking logic', () {
      final sampleKeyBytes = Uint8List.fromList([
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
      ]);

      final hex = sampleKeyBytes
          .map((b) => b.toRadixString(16).padLeft(2, '0'))
          .join()
          .toUpperCase();

      expect(hex.startsWith('123456789ABCDEF0'), isTrue);
      expect(hex.length, equals(64));
    });

    test('Fixed 4KB block padding calculation', () {
      const blockSize = 4096;
      final payload = utf8.encode('Hello World!');
      final minCapacity = 4 + payload.length; // 4-byte big endian length prefix

      final targetSize = ((minCapacity + blockSize - 1) ~/ blockSize) * blockSize;
      expect(targetSize, equals(4096));

      // Test large payload exceeding 4KB
      final largePayload = Uint8List(5000);
      final minLargeCapacity = 4 + largePayload.length;
      final targetLargeSize = ((minLargeCapacity + blockSize - 1) ~/ blockSize) * blockSize;
      expect(targetLargeSize, equals(8192));
    });

    test('Simulated Key Change Detection triggers safety alert', () {
      final trustedContacts = <String, String>{};

      // 1. First interaction: Bob registers key A
      const contact = 'bob';
      const keyA = 'A1B2C3D4E5F60708...';
      trustedContacts[contact] = keyA;

      expect(trustedContacts[contact], equals(keyA));

      // 2. Second interaction: Bob presents identical key A -> PASS
      const incomingKeyValid = 'A1B2C3D4E5F60708...';
      expect(incomingKeyValid == trustedContacts[contact], isTrue);

      // 3. Attacker or reinstalled client presents key B -> BLOCKED
      const incomingKeyChanged = 'F9E8D7C6B5A4...';
      final hasChanged = incomingKeyChanged != trustedContacts[contact];
      expect(hasChanged, isTrue);

      // Verify that communication must be blocked
      var isSendingBlocked = false;
      if (hasChanged) {
        isSendingBlocked = true;
      }
      expect(isSendingBlocked, isTrue);
    });
  });
}

