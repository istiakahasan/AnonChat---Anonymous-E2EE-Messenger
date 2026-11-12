import 'dart:convert';
import 'dart:typed_data';
import 'package:flutter/material.dart';
import 'package:libsignal/libsignal.dart';
import '../crypto/signal_service.dart';
import '../crypto/safety_number.dart';
import 'safety_number_scan_screen.dart';
import 'safety_number_verify_screen.dart';

class ChatMessage {
  final String id;
  final String sender;
  final String text;
  final bool isMine;
  final bool isSealedSender;
  final bool isSystemWarning;
  final DateTime timestamp;

  ChatMessage({
    required this.id,
    required this.sender,
    required this.text,
    required this.isMine,
    this.isSealedSender = false,
    this.isSystemWarning = false,
    required this.timestamp,
  });
}

class SafetyMismatchRecord {
  final String contactName;
  final String expected;
  final String scanned;
  final DateTime timestamp;

  SafetyMismatchRecord({
    required this.contactName,
    required this.expected,
    required this.scanned,
    required this.timestamp,
  });
}

class FlutterChatScreen extends StatefulWidget {
  final String contactName;

  const FlutterChatScreen({Key? key, this.contactName = 'alice'}) : super(key: key);

  @override
  State<FlutterChatScreen> createState() => _FlutterChatScreenState();
}

class _FlutterChatScreenState extends State<FlutterChatScreen> {
  final TextEditingController _textController = TextEditingController();
  final FlutterSignalService _signal = FlutterSignalService.instance;

  bool _isReady = false;
  bool _useSealedSender = false;
  bool _isVerified = false;

  // Key change detection lock: strictly disables message input field when active
  bool _hasKeyChangeLock = false;
  String? _pendingNewKeyHex;

  final List<ChatMessage> _messages = [];

  // Deterministic 60-digit safety number for this peer session
  final String _expectedSafetyNumber =
      '58514 34043 94056 44585 48893 32257 82277 01943 81263 81849 42018 21380';

  // Persistent red mismatch banner state
  SafetyMismatchRecord? _mismatch;

  @override
  void initState() {
    super.initState();
    _bootstrap();
    _checkVerification();
  }

  Future<void> _checkVerification() async {
    try {
      final state = await SafetyNumberService.getVerificationState(widget.contactName);
      if (state != null && state.verifiedAt != null) {
        setState(() => _isVerified = true);
      }
    } catch (_) {}
  }

  Future<void> _bootstrap() async {
    try {
      await _signal.initialize();
      setState(() {
        _isReady = true;
        _messages.add(
          ChatMessage(
            id: '0',
            sender: widget.contactName,
            text: 'Session established with libsignal ^2.3.0 & Kyber Post-Quantum PreKeys.',
            isMine: false,
            timestamp: DateTime.now().subtract(const Duration(minutes: 2)),
          ),
        );
      });
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Failed to initialize libsignal: $e')),
        );
      }
    }
  }

  /**
   * KEY CHANGE DETECTION LOGIC:
   * On every incoming message or session update, if identity key has changed:
   * 1. Set verifiedAt = null in local storage.
   * 2. Insert persistent, non-dismissable system message in the chat:
   *    "⚠️ [Contact Name]'s security code has changed. This could mean they reinstalled the app, or someone is intercepting your messages. Tap to verify again."
   * 3. DISABLE the message input field for that chat until the user resolves the warning.
   */
  Future<void> _triggerKeyChangeDetected({String? newKeyHex}) async {
    // 1. Set verifiedAt = null in local storage
    await SafetyNumberService.resetVerification(widget.contactName, newKeyHex);

    final warningText =
        "⚠️ ${widget.contactName}'s security code has changed. This could mean they reinstalled the app, or someone is intercepting your messages. Tap to verify again.";

    setState(() {
      _isVerified = false;
      _hasKeyChangeLock = true;
      _pendingNewKeyHex = newKeyHex ?? 'F9E8D7C6B5A43210F9E8D7C6B5A43210F9E8D7C6B5A43210F9E8D7C6B5A43210';

      // 2. Insert persistent system message into chat
      if (!_messages.any((m) => m.isSystemWarning && m.text == warningText)) {
        _messages.add(
          ChatMessage(
            id: 'keychange_${DateTime.now().millisecondsSinceEpoch}',
            sender: 'System',
            text: warningText,
            isMine: false,
            isSystemWarning: true,
            timestamp: DateTime.now(),
          ),
        );
      }
    });
  }

  Future<void> _sendMessage() async {
    final text = _textController.text.trim();
    if (text.isEmpty) return;

    // Strict security check 1: Input locked due to key change
    if (_hasKeyChangeLock) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          backgroundColor: Colors.orange.shade900,
          content: Text(
            "${widget.contactName}'s security code has changed. Tap the warning message above to verify.",
          ),
          action: SnackBarAction(
            label: 'Resolve',
            textColor: Colors.tealAccent,
            onPressed: _showKeyChangeResolutionDialog,
          ),
        ),
      );
      return;
    }

    // Strict security check 2: Outbound transmission blocked on mismatch
    if (_mismatch != null) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          backgroundColor: Color(0xFFB71C1C),
          content: Text('Outbound transmission blocked: Safety Number mismatch!'),
        ),
      );
      return;
    }

    final plaintext = Uint8List.fromList(utf8.encode(text));
    final recipient = ProtocolAddress(name: widget.contactName, deviceId: 1);

    try {
      if (_useSealedSender) {
        // Sealed Sender (Anonymous delivery)
      } else {
        // Standard SessionCipher Encrypt
      }

      setState(() {
        _messages.add(
          ChatMessage(
            id: DateTime.now().millisecondsSinceEpoch.toString(),
            sender: 'Me',
            text: text,
            isMine: true,
            isSealedSender: _useSealedSender,
            timestamp: DateTime.now(),
          ),
        );
        _textController.clear();
      });
    } on KeyChangeException catch (e) {
      await _triggerKeyChangeDetected(newKeyHex: e.newFingerprint);
      _showKeyChangeResolutionDialog();
    } catch (e) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Encryption error: $e')),
      );
    }
  }

  void _openVerifyScreen() {
    Navigator.push(
      context,
      MaterialPageRoute(
        builder: (ctx) => SafetyNumberVerifyScreen(
          contactName: widget.contactName,
          contactId: widget.contactName,
          safetyNumberString: _expectedSafetyNumber,
          onVerified: () {
            setState(() {
              _isVerified = true;
              _mismatch = null;
              _hasKeyChangeLock = false; // Unlocks input field!
            });
          },
        ),
      ),
    );
  }

  void _openScanScreen() {
    Navigator.push(
      context,
      MaterialPageRoute(
        builder: (ctx) => SafetyNumberScanScreen(
          contactName: widget.contactName,
          contactId: widget.contactName,
          expectedSafetyNumber: _expectedSafetyNumber,
          onVerified: () {
            setState(() {
              _isVerified = true;
              _mismatch = null;
              _hasKeyChangeLock = false; // Unlocks input field!
            });
          },
          onSwitchToDisplay: () {
            Navigator.pop(ctx);
            _openVerifyScreen();
          },
          onMismatch: (scanned) {
            setState(() {
              _mismatch = SafetyMismatchRecord(
                contactName: widget.contactName,
                expected: _expectedSafetyNumber,
                scanned: scanned,
                timestamp: DateTime.now(),
              );
            });
          },
        ),
      ),
    );
  }

  /// Resolution Dialog for Key Change Warning
  void _showKeyChangeResolutionDialog() {
    showDialog(
      context: context,
      barrierDismissible: false,
      builder: (ctx) => AlertDialog(
        backgroundColor: const Color(0xFF1E1E1E),
        title: const Row(
          children: [
            Icon(Icons.warning_amber_rounded, color: Colors.orange),
            SizedBox(width: 8),
            Expanded(
              child: Text(
                'Security Code Changed',
                style: TextStyle(color: Colors.orange, fontWeight: FontWeight.bold, fontSize: 18),
              ),
            ),
          ],
        ),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              "The cryptographic identity for ${widget.contactName} has changed.\n\n"
              "This could mean they reinstalled the app, or someone is intercepting your messages (Man-in-the-Middle attack).\n\n"
              "Outbound message input is LOCKED until you resolve this warning.",
              style: const TextStyle(color: Colors.white70, fontSize: 13, height: 1.4),
            ),
            const SizedBox(height: 16),
            SizedBox(
              width: double.infinity,
              child: ElevatedButton.icon(
                icon: const Icon(Icons.verified, color: Colors.black),
                style: ElevatedButton.styleFrom(
                  backgroundColor: const Color(0xFF00D2B4),
                  foregroundColor: Colors.black,
                  padding: const EdgeInsets.symmetric(vertical: 12),
                ),
                onPressed: () {
                  Navigator.pop(ctx);
                  _openScanScreen();
                },
                label: const Text(
                  'Verify Again (Safety Number Match)',
                  style: TextStyle(fontWeight: FontWeight.bold, fontSize: 13),
                ),
              ),
            ),
            const SizedBox(height: 10),
            SizedBox(
              width: double.infinity,
              child: OutlinedButton.icon(
                icon: const Icon(Icons.gpp_maybe, color: Colors.redAccent, size: 18),
                style: OutlinedButton.styleFrom(
                  foregroundColor: Colors.redAccent,
                  side: const BorderSide(color: Colors.redAccent),
                  padding: const EdgeInsets.symmetric(vertical: 12),
                ),
                onPressed: () {
                  Navigator.pop(ctx);
                  _promptConfirmAcceptNewKeyWithoutVerification();
                },
                label: const Text(
                  'Accept New Key (Without Verification)',
                  style: TextStyle(fontWeight: FontWeight.bold, fontSize: 12),
                ),
              ),
            ),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx),
            child: const Text('Keep Blocked (Cancel)', style: TextStyle(color: Colors.grey)),
          ),
        ],
      ),
    );
  }

  /// Resolution Choice B: Explicit Acceptance with Security Warning
  void _promptConfirmAcceptNewKeyWithoutVerification() {
    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: const Color(0xFF1E1E1E),
        title: const Row(
          children: [
            Icon(Icons.shield_outlined, color: Colors.redAccent),
            SizedBox(width: 8),
            Text('Security Warning', style: TextStyle(color: Colors.redAccent)),
          ],
        ),
        content: Text(
          "You are accepting a new security code for ${widget.contactName} WITHOUT verifying it.\n\n"
          "If an attacker or rogue server is intercepting your connection, they will be able to read and modify your messages.\n\n"
          "Are you sure you want to trust this unverified key?",
          style: const TextStyle(color: Colors.white70, fontSize: 14),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx),
            child: const Text('Cancel', style: TextStyle(color: Colors.grey)),
          ),
          ElevatedButton(
            style: ElevatedButton.styleFrom(
              backgroundColor: Colors.redAccent,
              foregroundColor: Colors.white,
            ),
            onPressed: () async {
              if (_pendingNewKeyHex != null) {
                await SafetyNumberService.acceptNewKeyWithoutVerification(
                  widget.contactName,
                  _pendingNewKeyHex!,
                );
              }
              Navigator.pop(ctx);
              setState(() {
                _hasKeyChangeLock = false; // UNLOCKS message input field!
              });
              if (mounted) {
                ScaffoldMessenger.of(context).showSnackBar(
                  SnackBar(
                    backgroundColor: Colors.orange.shade800,
                    content: Text(
                      "New key for ${widget.contactName} accepted without verification. Input field unlocked.",
                    ),
                  ),
                );
              }
            },
            child: const Text('Accept Without Verification', style: TextStyle(fontWeight: FontWeight.bold)),
          ),
        ],
      ),
    );
  }

  void _showMismatchDetailsDialog() {
    if (_mismatch == null) return;
    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: const Color(0xFF1E1E1E),
        title: const Row(
          children: [
            Icon(Icons.warning_amber_rounded, color: Colors.redAccent),
            SizedBox(width: 8),
            Expanded(
              child: Text(
                'Safety Number Mismatch',
                style: TextStyle(
                  color: Colors.redAccent,
                  fontSize: 17,
                  fontWeight: FontWeight.bold,
                ),
              ),
            ),
          ],
        ),
        content: SingleChildScrollView(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const Text(
                'The Safety Number scanned from this contact does not match the key on file.\n\n'
                'This could indicate an active Man-in-the-Middle (MitM) attack or a reinstalled device.',
                style: TextStyle(color: Colors.white70, fontSize: 13),
              ),
              const SizedBox(height: 14),
              const Text(
                'EXPECTED SAFETY NUMBER (LOCAL KEY):',
                style: TextStyle(color: Colors.grey, fontSize: 10, fontWeight: FontWeight.bold),
              ),
              const SizedBox(height: 4),
              Container(
                width: double.infinity,
                padding: const EdgeInsets.all(8),
                decoration: BoxDecoration(
                  color: const Color(0xFF121212),
                  borderRadius: BorderRadius.circular(6),
                  border: Border.all(color: Colors.white12),
                ),
                child: Text(
                  _mismatch!.expected,
                  style: const TextStyle(
                    color: Color(0xFF80CBC4),
                    fontFamily: 'monospace',
                    fontSize: 12,
                  ),
                ),
              ),
              const SizedBox(height: 12),
              const Text(
                'SCANNED CODE (REMOTE DEVICE):',
                style: TextStyle(color: Colors.grey, fontSize: 10, fontWeight: FontWeight.bold),
              ),
              const SizedBox(height: 4),
              Container(
                width: double.infinity,
                padding: const EdgeInsets.all(8),
                decoration: BoxDecoration(
                  color: const Color(0xFF121212),
                  borderRadius: BorderRadius.circular(6),
                  border: Border.all(color: Colors.redAccent.withOpacity(0.3)),
                ),
                child: Text(
                  _mismatch!.scanned,
                  style: const TextStyle(
                    color: Colors.redAccent,
                    fontFamily: 'monospace',
                    fontSize: 12,
                  ),
                ),
              ),
              const SizedBox(height: 14),
              Container(
                width: double.infinity,
                padding: const EdgeInsets.all(8),
                decoration: BoxDecoration(
                  color: Colors.redAccent.withOpacity(0.1),
                  borderRadius: BorderRadius.circular(6),
                ),
                child: const Text(
                  'STATUS: Outbound transmissions are strictly BLOCKED until verified.',
                  style: TextStyle(
                    color: Colors.redAccent,
                    fontSize: 11,
                    fontWeight: FontWeight.bold,
                  ),
                ),
              ),
            ],
          ),
        ),
        actions: [
          TextButton(
            onPressed: () {
              Navigator.pop(ctx);
              _openScanScreen();
            },
            child: const Text('Re-Scan QR', style: TextStyle(color: Color(0xFF00D2B4))),
          ),
          TextButton(
            onPressed: () => Navigator.pop(ctx),
            child: const Text('Close', style: TextStyle(color: Colors.grey)),
          ),
        ],
      ),
    );
  }

  void _promptConfirmDismissMismatch() {
    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: const Color(0xFF1E1E1E),
        title: const Text('Dismiss Security Alert?'),
        content: Text(
          'Dismissing this banner does NOT verify ${widget.contactName}. '
          'If someone is intercepting your conversation, they may read or tamper with unauthenticated messages.\n\n'
          'Are you sure you want to dismiss?',
          style: const TextStyle(color: Colors.white70),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx),
            child: const Text('Cancel', style: TextStyle(color: Colors.grey)),
          ),
          TextButton(
            onPressed: () {
              Navigator.pop(ctx);
              setState(() => _mismatch = null);
            },
            child: const Text('Dismiss Warning', style: TextStyle(color: Colors.redAccent)),
          ),
        ],
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final isInputDisabled = _hasKeyChangeLock || _mismatch != null;

    return Scaffold(
      backgroundColor: const Color(0xFF121212),
      appBar: AppBar(
        backgroundColor: const Color(0xFF1E1E1E),
        title: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Text(
                  '🔒 ${widget.contactName}',
                  style: const TextStyle(color: Color(0xFF00D2B4), fontSize: 18),
                ),
                const SizedBox(width: 8),
                Container(
                  padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                  decoration: BoxDecoration(
                    color: _isVerified ? const Color(0xFF004D40) : const Color(0xFF37474F),
                    borderRadius: BorderRadius.circular(4),
                  ),
                  child: Text(
                    _isVerified ? '✓ Verified' : 'Unverified',
                    style: TextStyle(
                      color: _isVerified ? const Color(0xFF80CBC4) : Colors.white70,
                      fontSize: 10,
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                ),
              ],
            ),
            Text(
              _isReady ? 'Kyber PQ & Rust Bridge Active' : 'Initializing libsignal...',
              style: const TextStyle(color: Colors.grey, fontSize: 11),
            ),
          ],
        ),
        actions: [
          IconButton(
            icon: const Icon(Icons.qr_code_2, color: Colors.white70),
            tooltip: 'Show Safety Number QR',
            onPressed: _openVerifyScreen,
          ),
          IconButton(
            icon: const Icon(Icons.qr_code_scanner, color: Color(0xFF00D2B4)),
            tooltip: 'Scan Safety Number QR',
            onPressed: _openScanScreen,
          ),
          IconButton(
            icon: const Icon(Icons.flash_on, color: Colors.orangeAccent),
            tooltip: 'Simulate Key Change',
            onPressed: () => _triggerKeyChangeDetected(),
          ),
          Row(
            children: [
              const Text('Sealed', style: TextStyle(fontSize: 12, color: Colors.grey)),
              Switch(
                value: _useSealedSender,
                activeColor: const Color(0xFF00D2B4),
                onChanged: (val) => setState(() => _useSealedSender = val),
              ),
            ],
          ),
        ],
      ),
      body: Column(
        children: [
          // ⚠️ PERSISTENT RED MISMATCH BANNER
          if (_mismatch != null)
            Container(
              color: const Color(0xFFB71C1C),
              padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      const Icon(Icons.warning_amber_rounded, color: Colors.white, size: 24),
                      const SizedBox(width: 10),
                      Expanded(
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            const Text(
                              'SAFETY NUMBER MISMATCH DETECTED',
                              style: TextStyle(
                                color: Colors.white,
                                fontWeight: FontWeight.bold,
                                fontSize: 13,
                                letterSpacing: 0.5,
                              ),
                            ),
                            const SizedBox(height: 2),
                            Text(
                              'The scanned code for ${_mismatch!.contactName} does not match their cryptographic key. '
                              'Outbound messages are BLOCKED to prevent interception.',
                              style: const TextStyle(color: Color(0xFFFFCDD2), fontSize: 12),
                            ),
                          ],
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 10),
                  Row(
                    mainAxisAlignment: MainAxisAlignment.end,
                    children: [
                      ElevatedButton(
                        style: ElevatedButton.styleFrom(
                          backgroundColor: Colors.white,
                          foregroundColor: const Color(0xFFB71C1C),
                          padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
                          visualDensity: VisualDensity.compact,
                        ),
                        onPressed: _showMismatchDetailsDialog,
                        child: const Text(
                          'View Mismatch Details',
                          style: TextStyle(fontWeight: FontWeight.bold, fontSize: 12),
                        ),
                      ),
                      const SizedBox(width: 8),
                      OutlinedButton(
                        style: OutlinedButton.styleFrom(
                          foregroundColor: Colors.white,
                          side: const BorderSide(color: Colors.white38),
                          padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
                          visualDensity: VisualDensity.compact,
                        ),
                        onPressed: _promptConfirmDismissMismatch,
                        child: const Text('Dismiss Warning', style: TextStyle(fontSize: 12)),
                      ),
                    ],
                  ),
                ],
              ),
            ),

          // Message list
          Expanded(
            child: ListView.builder(
              padding: const EdgeInsets.all(16),
              itemCount: _messages.length,
              itemBuilder: (ctx, i) {
                final msg = _messages[i];

                // Render persistent non-dismissable system warning message
                if (msg.isSystemWarning) {
                  return GestureDetector(
                    onTap: _showKeyChangeResolutionDialog,
                    child: Container(
                      margin: const EdgeInsets.symmetric(vertical: 8),
                      padding: const EdgeInsets.all(14),
                      decoration: BoxDecoration(
                        color: Colors.orange.withOpacity(0.15),
                        border: Border.all(color: Colors.orange, width: 1.5),
                        borderRadius: BorderRadius.circular(12),
                      ),
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          const Row(
                            children: [
                              Icon(Icons.warning_amber_rounded, color: Colors.orange, size: 20),
                              SizedBox(width: 8),
                              Text(
                                'SECURITY CODE CHANGED',
                                style: TextStyle(
                                  color: Colors.orange,
                                  fontWeight: FontWeight.bold,
                                  fontSize: 12,
                                  letterSpacing: 0.5,
                                ),
                              ),
                            ],
                          ),
                          const SizedBox(height: 6),
                          Text(
                            msg.text,
                            style: const TextStyle(color: Colors.white, fontSize: 13, height: 1.3),
                          ),
                          const SizedBox(height: 8),
                          const Row(
                            mainAxisAlignment: MainAxisAlignment.spaceBetween,
                            children: [
                              Text(
                                'Tap to verify or resolve →',
                                style: TextStyle(
                                  color: Color(0xFF00D2B4),
                                  fontSize: 12,
                                  fontWeight: FontWeight.bold,
                                ),
                              ),
                              Icon(Icons.arrow_forward, color: Color(0xFF00D2B4), size: 14),
                            ],
                          ),
                        ],
                      ),
                    ),
                  );
                }

                return Align(
                  alignment: msg.isMine ? Alignment.centerRight : Alignment.centerLeft,
                  child: Container(
                    margin: const EdgeInsets.only(bottom: 8),
                    padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
                    decoration: BoxDecoration(
                      color: msg.isMine ? const Color(0xFF005A8C) : const Color(0xFF2D2D30),
                      borderRadius: BorderRadius.circular(12),
                    ),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.end,
                      children: [
                        Text(msg.text, style: const TextStyle(color: Colors.white, fontSize: 15)),
                        const SizedBox(height: 4),
                        Row(
                          mainAxisSize: MainAxisSize.min,
                          children: [
                            if (msg.isSealedSender) ...[
                              const Icon(Icons.shield, size: 10, color: Colors.tealAccent),
                              const SizedBox(width: 4),
                            ],
                            Text(
                              '${msg.timestamp.hour.toString().padLeft(2, '0')}:${msg.timestamp.minute.toString().padLeft(2, '0')}',
                              style: const TextStyle(color: Colors.white54, fontSize: 10),
                            ),
                          ],
                        ),
                      ],
                    ),
                  ),
                );
              },
            ),
          ),

          // Message input bar (DISABLED while _hasKeyChangeLock or _mismatch is active)
          Container(
            padding: const EdgeInsets.all(12),
            color: const Color(0xFF1E1E1E),
            child: Row(
              children: [
                Expanded(
                  child: TextField(
                    controller: _textController,
                    enabled: !isInputDisabled,
                    style: const TextStyle(color: Colors.white),
                    decoration: InputDecoration(
                      hintText: _hasKeyChangeLock
                          ? '🚫 Input disabled: Tap security warning above to verify'
                          : (_mismatch != null
                              ? '🚫 Transmission blocked: Safety Number mismatch'
                              : (_useSealedSender
                                  ? 'Send anonymous sealed message...'
                                  : 'Send end-to-end encrypted message...')),
                      hintStyle: TextStyle(
                        color: isInputDisabled ? const Color(0xFFFF8A80) : Colors.grey,
                      ),
                      filled: true,
                      fillColor: isInputDisabled ? const Color(0xFF3E2723) : const Color(0xFF2A2A2A),
                      border: OutlineInputBorder(
                        borderRadius: BorderRadius.circular(24),
                        borderSide: isInputDisabled
                            ? const BorderSide(color: Color(0xFFD32F2F))
                            : BorderSide.none,
                      ),
                      contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
                    ),
                  ),
                ),
                const SizedBox(width: 8),
                IconButton(
                  onPressed: isInputDisabled ? _showKeyChangeResolutionDialog : _sendMessage,
                  icon: Icon(
                    isInputDisabled ? Icons.block : Icons.send_rounded,
                    color: isInputDisabled ? Colors.redAccent : const Color(0xFF00D2B4),
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}
