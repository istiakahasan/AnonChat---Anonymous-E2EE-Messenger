import 'package:flutter/material.dart';

/// Mandatory Pre-Backup Warning Screen (Flutter / Dart)
///
/// Security & UI Requirements:
/// 1. Header: "Your backup is yours alone"
/// 2. Body text: "If you lose your passphrase, your backup cannot be recovered. No one, including us, can help you. We do not have a copy of your key."
/// 3. Secondary text: "This is not a limitation. It is what makes your backup private. If we could recover it, so could anyone who compromises our servers."
/// 4. Required action: Checkbox: "I understand that if I lose my passphrase, my backup is permanently lost."
/// 5. Continue button: Disabled until the checkbox is checked.
/// 6. Strictly NO bypass: No "Skip" or "Remind me later" buttons.
/// 7. Ephemeral state: If user navigates away, do not remember that they saw the warning.
class PreBackupWarningScreen extends StatefulWidget {
  final VoidCallback onContinue;
  final VoidCallback? onCancel;

  const PreBackupWarningScreen({
    Key? key,
    required this.onContinue,
    this.onCancel,
  }) : super(key: key);

  static const String expectedHeader = 'Your backup is yours alone';
  static const String expectedBody =
      'If you lose your passphrase, your backup cannot be recovered. No one, including us, can help you. We do not have a copy of your key.';
  static const String expectedSecondary =
      'This is not a limitation. It is what makes your backup private. If we could recover it, so could anyone who compromises our servers.';
  static const String expectedCheckbox =
      'I understand that if I lose my passphrase, my backup is permanently lost.';

  @override
  State<PreBackupWarningScreen> createState() => _PreBackupWarningScreenState();
}

class _PreBackupWarningScreenState extends State<PreBackupWarningScreen> {
  bool _acknowledged = false;

  void _handleCancel() {
    setState(() {
      _acknowledged = false; // Never remember
    });
    if (widget.onCancel != null) {
      widget.onCancel!();
    } else {
      Navigator.of(context).maybePop();
    }
  }

  void _handleContinue() {
    if (!_acknowledged) return;
    widget.onContinue();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: const Color(0xFF121212),
      appBar: AppBar(
        backgroundColor: Colors.transparent,
        elevation: 0,
        leading: IconButton(
          key: const Key('pre_backup_cancel_button'),
          icon: const Icon(Icons.close, color: Colors.white70),
          onPressed: _handleCancel,
        ),
      ),
      body: SafeArea(
        child: SingleChildScrollView(
          padding: const EdgeInsets.symmetric(horizontal: 24.0, vertical: 16.0),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.center,
            children: [
              // Shield warning icon
              Container(
                width: 72,
                height: 72,
                decoration: BoxDecoration(
                  shape: BoxShape.circle,
                  color: const Color(0xFFFF5252).withOpacity(0.12),
                  border: Border.Border.all(
                    color: const Color(0xFFFF5252).withOpacity(0.35),
                    width: 1.5,
                  ),
                ),
                child: const Icon(
                  Icons.shield_outlined,
                  size: 38,
                  color: Color(0xFFFF5252),
                ),
              ),
              const SizedBox(height: 24),

              // 1. Header
              const Text(
                PreBackupWarningScreen.expectedHeader,
                key: Key('pre_backup_header'),
                style: TextStyle(
                  color: Colors.white,
                  fontSize: 24,
                  fontWeight: FontWeight.bold,
                  letterSpacing: 0.3,
                ),
                textAlign: TextAlign.center,
              ),
              const SizedBox(height: 20),

              // 2. Body Text (exact wording)
              Container(
                width: double.infinity,
                padding: const EdgeInsets.all(16.0),
                decoration: BoxDecoration(
                  color: const Color(0xFF1E1E1E),
                  borderRadius: BorderRadius.circular(12),
                  border: const Border(
                    left: BorderSide(color: Color(0xFFFF5252), width: 4),
                  ),
                ),
                child: const Text(
                  PreBackupWarningScreen.expectedBody,
                  key: Key('pre_backup_body'),
                  style: TextStyle(
                    color: Color(0xFFF5F5F5),
                    fontSize: 15,
                    fontWeight: FontWeight.w600,
                    height: 1.45,
                  ),
                ),
              ),
              const SizedBox(height: 16),

              // 3. Secondary Text (exact wording)
              const Text(
                PreBackupWarningScreen.expectedSecondary,
                key: Key('pre_backup_secondary'),
                style: TextStyle(
                  color: Color(0xFFAAAAAA),
                  fontSize: 14,
                  height: 1.45,
                ),
              ),
              const SizedBox(height: 28),
              const Divider(color: Color(0xFF2A2A2A)),
              const SizedBox(height: 20),

              // 4. Required Action: Checkbox
              InkWell(
                key: const Key('pre_backup_checkbox_row'),
                onTap: () {
                  setState(() {
                    _acknowledged = !_acknowledged;
                  });
                },
                borderRadius: BorderRadius.circular(12),
                child: Container(
                  padding: const EdgeInsets.all(14.0),
                  decoration: BoxDecoration(
                    color: const Color(0xFF1A1A1A),
                    borderRadius: BorderRadius.circular(12),
                    border: Border.all(
                      color: _acknowledged
                          ? const Color(0xFF00D2B4)
                          : const Color(0xFF333333),
                      width: 1.2,
                    ),
                  ),
                  child: Row(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Checkbox(
                        key: const Key('pre_backup_checkbox'),
                        value: _acknowledged,
                        activeColor: const Color(0xFF00D2B4),
                        checkColor: Colors.black,
                        side: const BorderSide(color: Color(0xFF777777), width: 1.5),
                        shape: RoundedRectangleBorder(
                          borderRadius: BorderRadius.circular(4),
                        ),
                        onChanged: (val) {
                          setState(() {
                            _acknowledged = val ?? false;
                          });
                        },
                      ),
                      const SizedBox(width: 8),
                      const Expanded(
                        child: Text(
                          PreBackupWarningScreen.expectedCheckbox,
                          key: Key('pre_backup_checkbox_label'),
                          style: TextStyle(
                            color: Color(0xFFEEEEEE),
                            fontSize: 14,
                            fontWeight: FontWeight.w500,
                            height: 1.35,
                          ),
                        ),
                      ),
                    ],
                  ),
                ),
              ),
              const SizedBox(height: 32),

              // 5. Continue Button (disabled until checkbox checked)
              SizedBox(
                width: double.infinity,
                height: 52,
                child: ElevatedButton(
                  key: const Key('pre_backup_continue_button'),
                  style: ElevatedButton.styleFrom(
                    backgroundColor: const Color(0xFF00D2B4),
                    disabledBackgroundColor: const Color(0xFF262626),
                    foregroundColor: Colors.black,
                    disabledForegroundColor: const Color(0xFF555555),
                    shape: RoundedRectangleBorder(
                      borderRadius: BorderRadius.circular(12),
                    ),
                    elevation: _acknowledged ? 4 : 0,
                  ),
                  onPressed: _acknowledged ? _handleContinue : null,
                  child: const Text(
                    'Continue',
                    style: TextStyle(
                      fontSize: 16,
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

