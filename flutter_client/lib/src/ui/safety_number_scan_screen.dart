import 'package:flutter/material.dart';
import 'package:mobile_scanner/mobile_scanner.dart';
import '../crypto/safety_number.dart';

class SafetyNumberScanScreen extends StatefulWidget {
  final String contactName;
  final String contactId;
  final String expectedSafetyNumber;
  final VoidCallback? onVerified;
  final VoidCallback? onSwitchToDisplay;
  final void Function(String scannedCode)? onMismatch;

  const SafetyNumberScanScreen({
    Key? key,
    required this.contactName,
    required this.contactId,
    required this.expectedSafetyNumber,
    this.onVerified,
    this.onSwitchToDisplay,
    this.onMismatch,
  }) : super(key: key);

  @override
  State<SafetyNumberScanScreen> createState() => _SafetyNumberScanScreenState();
}

class _SafetyNumberScanScreenState extends State<SafetyNumberScanScreen> {
  final MobileScannerController _scannerController = MobileScannerController();
  bool _isProcessing = false;

  void _onDetect(BarcodeCapture capture) async {
    if (_isProcessing) return;

    for (final barcode in capture.barcodes) {
      final rawValue = barcode.rawValue;
      if (rawValue != null && rawValue.isNotEmpty) {
        setState(() => _isProcessing = true);

        final cleanScanned = rawValue.replaceAll(RegExp(r'\s+'), '').trim();
        final cleanExpected =
            widget.expectedSafetyNumber.replaceAll(RegExp(r'\s+'), '').trim();

        if (cleanScanned == cleanExpected && cleanScanned.length == 60) {
          // 1. MATCH: Verified & Authenticated
          await SafetyNumberService.markVerified(widget.contactId);
          if (!mounted) return;

          showDialog(
            context: context,
            barrierDismissible: false,
            builder: (ctx) => AlertDialog(
              backgroundColor: const Color(0xFF1E1E1E),
              title: const Row(
                children: [
                  Icon(Icons.verified, color: Color(0xFF00D2B4)),
                  SizedBox(width: 8),
                  Text('Safety Number Verified',
                      style: TextStyle(color: Color(0xFF00D2B4))),
                ],
              ),
              content: Text(
                'The safety code matches ${widget.contactName}\'s cryptographic key. Communication is authenticated.',
                style: const TextStyle(color: Colors.white70),
              ),
              actions: [
                ElevatedButton(
                  style: ElevatedButton.styleFrom(
                    backgroundColor: const Color(0xFF00D2B4),
                    foregroundColor: Colors.black,
                  ),
                  onPressed: () {
                    Navigator.pop(ctx);
                    if (widget.onVerified != null) widget.onVerified!();
                    Navigator.pop(context);
                  },
                  child: const Text('OK',
                      style: TextStyle(fontWeight: FontWeight.bold)),
                ),
              ],
            ),
          );
        } else {
          // 2. MISMATCH: Security Warning Alert
          if (widget.onMismatch != null) {
            widget.onMismatch!(rawValue);
          }
          if (!mounted) return;

          showDialog(
            context: context,
            barrierDismissible: false,
            builder: (ctx) => AlertDialog(
              backgroundColor: const Color(0xFF1E1E1E),
              title: const Row(
                children: [
                  Icon(Icons.warning, color: Colors.redAccent),
                  SizedBox(width: 8),
                  Text('Safety Number Mismatch!',
                      style: TextStyle(color: Colors.redAccent)),
                ],
              ),
              content: Text(
                'The QR code scanned from ${widget.contactName}\'s phone does NOT match the safety number computed by your device.\n\n'
                'Expected: ${widget.expectedSafetyNumber}\n'
                'Scanned:  $rawValue\n\n'
                'Possible Man-in-the-Middle attack. Communication remains BLOCKED.',
                style: const TextStyle(color: Colors.white70),
              ),
              actions: [
                TextButton(
                  onPressed: () {
                    Navigator.pop(ctx);
                    Navigator.pop(context); // Return to chat with banner visible
                  },
                  child: const Text('View in Chat',
                      style: TextStyle(color: Colors.redAccent, fontWeight: FontWeight.bold)),
                ),
                TextButton(
                  onPressed: () {
                    Navigator.pop(ctx);
                    setState(() => _isProcessing = false);
                  },
                  child: const Text('Try Again',
                      style: TextStyle(color: Colors.grey)),
                ),
              ],
            ),
          );
        }
        break;
      }
    }
  }

  @override
  void dispose() {
    _scannerController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: Colors.black,
      appBar: AppBar(
        backgroundColor: Colors.black.withOpacity(0.8),
        title: Text('Scan ${widget.contactName}\'s Code'),
        actions: [
          if (widget.onSwitchToDisplay != null)
            TextButton(
              onPressed: widget.onSwitchToDisplay,
              child: const Text(
                'Show QR',
                style: TextStyle(
                    color: Color(0xFF00D2B4), fontWeight: FontWeight.bold),
              ),
            ),
        ],
      ),
      body: Stack(
        children: [
          MobileScanner(
            controller: _scannerController,
            onDetect: _onDetect,
          ),
          // Reticle Target Box
          Center(
            child: Container(
              width: 260,
              height: 260,
              decoration: BoxDecoration(
                border: Border.all(color: const Color(0xFF00D2B4), width: 3),
                borderRadius: BorderRadius.circular(16),
              ),
            ),
          ),
          Positioned(
            bottom: 40,
            left: 20,
            right: 20,
            child: Container(
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(
                color: Colors.black.withOpacity(0.8),
                borderRadius: BorderRadius.circular(12),
              ),
              child: Text(
                'Point camera at the QR code displayed on ${widget.contactName}\'s screen.',
                textAlign: TextAlign.center,
                style: const TextStyle(color: Colors.white70, fontSize: 14),
              ),
            ),
          ),
        ],
      ),
    );
  }
}
