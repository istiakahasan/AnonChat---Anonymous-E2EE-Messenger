import 'package:flutter/material.dart';
import 'package:qr_flutter/qr_flutter.dart';
import '../crypto/safety_number.dart';

class SafetyNumberVerifyScreen extends StatefulWidget {
  final String contactName;
  final String contactId;
  final String safetyNumberString; // 60-digit string (12 groups of 5 digits)
  final VoidCallback? onVerified;

  const SafetyNumberVerifyScreen({
    Key? key,
    required this.contactName,
    required this.contactId,
    required this.safetyNumberString,
    this.onVerified,
  }) : super(key: key);

  @override
  State<SafetyNumberVerifyScreen> createState() =>
      _SafetyNumberVerifyScreenState();
}

class _SafetyNumberVerifyScreenState extends State<SafetyNumberVerifyScreen> {
  bool _isVerified = false;
  String? _verifiedDate;

  @override
  void initState() {
    super.initState();
    _loadVerificationStatus();
  }

  Future<void> _loadVerificationStatus() async {
    final state =
        await SafetyNumberService.getVerificationState(widget.contactId);
    if (state != null && state.verifiedAt != null) {
      setState(() {
        _isVerified = true;
        _verifiedDate = DateTime.fromMillisecondsSinceEpoch(state.verifiedAt!)
            .toLocal()
            .toString()
            .split(' ')
            .first;
      });
    }
  }

  /// Critical UX Requirement:
  /// Research on Signal verification found that when "Mark as verified" was passively available,
  /// 12 out of 14 participants toggled it WITHOUT comparing numbers.
  /// Your button MUST require a confirmation dialog that explicitly asks whether the numbers matched.
  void _promptVerificationConfirmation() {
    showDialog(
      context: context,
      barrierDismissible: false,
      builder: (ctx) => AlertDialog(
        backgroundColor: const Color(0xFF1E1E1E),
        title: const Text(
          'Confirm Safety Number Match',
          style: TextStyle(color: Colors.white, fontWeight: FontWeight.bold),
        ),
        content: Text(
          'Did you compare the numbers with ${widget.contactName} and confirm they match?',
          style: const TextStyle(color: Colors.white70, fontSize: 15),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx),
            child: const Text('No, not yet',
                style: TextStyle(color: Colors.grey)),
          ),
          ElevatedButton(
            style: ElevatedButton.styleFrom(
              backgroundColor: const Color(0xFF00D2B4),
              foregroundColor: Colors.black,
            ),
            onPressed: () async {
              await SafetyNumberService.markVerified(widget.contactId);
              Navigator.pop(ctx);
              setState(() {
                _isVerified = true;
                _verifiedDate = DateTime.now().toLocal().toString().split(' ').first;
              });
              if (widget.onVerified != null) {
                widget.onVerified!();
              }
            },
            child: const Text('Yes, they match',
                style: TextStyle(fontWeight: FontWeight.bold)),
          ),
        ],
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final digitGroups = widget.safetyNumberString.split(' ');

    return Scaffold(
      backgroundColor: const Color(0xFF121212),
      appBar: AppBar(
        backgroundColor: const Color(0xFF1E1E1E),
        title: Text(
          'Verify ${widget.contactName}',
          style: const TextStyle(
            color: Color(0xFF00D2B4),
            fontWeight: FontWeight.bold,
          ),
        ),
        centerTitle: true,
      ),
      body: SingleChildScrollView(
        padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 20),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.center,
          children: [
            // 2. Actionable Explanation Text
            Text(
              'Scan this code with ${widget.contactName}\'s phone, or compare the numbers below.',
              textAlign: TextAlign.center,
              style: const TextStyle(
                color: Color(0xFFE0E0E0),
                fontSize: 15,
                height: 1.4,
              ),
            ),
            const SizedBox(height: 24),

            // 3. High-Contrast QR Code with Quiet Zone (Margin)
            Container(
              decoration: BoxDecoration(
                color: Colors.white,
                borderRadius: BorderRadius.circular(16),
                boxShadow: [
                  BoxShadow(
                    color: Colors.black.withOpacity(0.5),
                    blurRadius: 10,
                    offset: const Offset(0, 4),
                  ),
                ],
              ),
              padding: const EdgeInsets.all(12),
              child: QrImageView(
                data: widget.safetyNumberString,
                version: QrVersions.auto,
                size: 280.0,
                padding: const EdgeInsets.all(8.0),
                backgroundColor: Colors.white,
                eyeStyle: const QrEyeStyle(
                  eyeShape: QrEyeShape.square,
                  color: Colors.black,
                ),
                dataModuleStyle: const QrDataModuleStyle(
                  dataModuleShape: QrDataModuleShape.square,
                  color: Colors.black,
                ),
              ),
            ),
            const SizedBox(height: 24),

            // 4. Numeric Display (Monospace Alignment)
            Container(
              width: double.infinity,
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(
                color: const Color(0xFF1A1A1A),
                borderRadius: BorderRadius.circular(12),
                border: Border.all(color: const Color(0xFF2A2A2A)),
              ),
              child: Column(
                children: [
                  const Text(
                    'SAFETY NUMBER',
                    style: TextStyle(
                      color: Colors.grey,
                      fontSize: 11,
                      fontWeight: FontWeight.w600,
                      letterSpacing: 1.2,
                    ),
                  ),
                  const SizedBox(height: 12),
                  Wrap(
                    spacing: 8,
                    runSpacing: 8,
                    alignment: WrapAlignment.center,
                    children: digitGroups.map((group) {
                      return Container(
                        padding: const EdgeInsets.symmetric(
                            horizontal: 10, vertical: 6),
                        decoration: BoxDecoration(
                          color: const Color(0xFF262626),
                          borderRadius: BorderRadius.circular(6),
                          border: Border.all(color: const Color(0xFF333333)),
                        ),
                        child: Text(
                          group,
                          style: const TextStyle(
                            fontFamily: 'monospace',
                            fontSize: 15,
                            fontWeight: FontWeight.bold,
                            color: Color(0xFFFFB74D),
                            letterSpacing: 1.2,
                          ),
                        ),
                      );
                    }).toList(),
                  ),
                ],
              ),
            ),
            const SizedBox(height: 16),

            // Verified Badge
            if (_isVerified)
              Container(
                margin: const EdgeInsets.only(bottom: 16),
                padding: const EdgeInsets.symmetric(
                    horizontal: 16, vertical: 8),
                decoration: BoxDecoration(
                  color: const Color(0xFF00D2B4).withOpacity(0.15),
                  borderRadius: BorderRadius.circular(20),
                  border: Border.all(color: const Color(0xFF00D2B4)),
                ),
                child: Text(
                  '✓ Verified on $_verifiedDate',
                  style: const TextStyle(
                    color: Color(0xFF00D2B4),
                    fontWeight: FontWeight.bold,
                    fontSize: 13,
                  ),
                ),
              ),

            // 5. Button with Confirmation Dialog
            SizedBox(
              width: double.infinity,
              height: 52,
              child: ElevatedButton(
                style: ElevatedButton.styleFrom(
                  backgroundColor: _isVerified
                      ? const Color(0xFF37474F)
                      : const Color(0xFF00D2B4),
                  foregroundColor:
                      _isVerified ? Colors.white70 : Colors.black,
                  shape: RoundedCornerShape(12),
                ),
                onPressed: _promptVerificationConfirmation,
                child: Text(
                  _isVerified ? 'Re-verify Safety Number' : 'Mark as Verified',
                  style: const TextStyle(
                    fontSize: 16,
                    fontWeight: FontWeight.bold,
                  ),
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }
}

class RoundedCornerShape extends RoundedRectangleBorder {
  RoundedCornerShape(double radius)
      : super(borderRadius: BorderRadius.circular(radius));
}

