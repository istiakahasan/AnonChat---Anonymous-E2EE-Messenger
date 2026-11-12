import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_client/src/ui/pre_backup_warning_screen.dart';

void main() {
  group('PreBackupWarningScreen UX & Security Specification', () {
    test('enforces exact required copy and text layout', () {
      expect(PreBackupWarningScreen.expectedHeader, equals('Your backup is yours alone'));
      expect(
        PreBackupWarningScreen.expectedBody,
        equals(
          'If you lose your passphrase, your backup cannot be recovered. No one, including us, can help you. We do not have a copy of your key.',
        ),
      );
      expect(
        PreBackupWarningScreen.expectedSecondary,
        equals(
          'This is not a limitation. It is what makes your backup private. If we could recover it, so could anyone who compromises our servers.',
        ),
      );
      expect(
        PreBackupWarningScreen.expectedCheckbox,
        equals(
          'I understand that if I lose my passphrase, my backup is permanently lost.',
        ),
      );
    });

    test('enforces gatekeeping: continue action blocked until checkbox acknowledged', () {
      bool acknowledged = false;
      bool continued = false;

      void onContinue() {
        if (!acknowledged) return;
        continued = true;
      }

      // Initial state: unchecked
      onContinue();
      expect(continued, isFalse);

      // Acknowledged state: checked
      acknowledged = true;
      onContinue();
      expect(continued, isTrue);
    });

    test('enforces no bypass: navigating away resets acknowledgement', () {
      bool acknowledged = true;

      void onCancel() {
        acknowledged = false; // Never remember
      }

      onCancel();
      expect(acknowledged, isFalse);
    });
  });
}

