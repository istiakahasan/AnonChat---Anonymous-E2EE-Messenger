import React, { useState, useEffect } from 'react';
import {
  View,
  Text,
  TextInput,
  TouchableOpacity,
  FlatList,
  StyleSheet,
  SafeAreaView,
  StatusBar,
  Alert,
  Modal,
  ScrollView,
} from 'react-native';
import { useSignalChat } from '../hooks/useSignalChat';
import { SafetyNumberScanScreen } from './SafetyNumberScanScreen';
import { SafetyNumberVerifyScreen } from './SafetyNumberVerifyScreen';
import { SafetyNumberService } from '../crypto/safetyNumber';

interface Message {
  id: string;
  sender: string;
  text: string;
  timestamp: string;
  isMine: boolean;
  isSystemWarning?: boolean;
}

export interface SafetyMismatchState {
  contactName: string;
  expected: string;
  scanned: string;
  timestamp: number;
}

export interface KeyChangeState {
  contactName: string;
  detectedAt: number;
  newKeyHex?: string;
  previousKeyHex?: string;
}

export const ChatScreen: React.FC = () => {
  const {
    isInitialized,
    publicBundle,
    keyChangeAlert,
    sendEncryptedMessage,
    decryptReceivedMessage,
    approveKeyChange,
    rejectKeyChange,
  } = useSignalChat();

  const [contactName, setContactName] = useState('user123');
  const [inputText, setInputText] = useState('');
  const [isVerified, setIsVerified] = useState(false);

  // Standard 60-digit safety number for this peer session
  const [expectedSafetyNumber, setExpectedSafetyNumber] = useState(
    '58514 34043 94056 44585 48893 32257 82277 01943 81263 81849 42018 21380'
  );

  // Key change detection lock: strictly disables message input field when active
  const [keyChangeLock, setKeyChangeLock] = useState<KeyChangeState | null>(null);
  const [showKeyChangeResolutionModal, setShowKeyChangeResolutionModal] = useState(false);

  // Persistent red mismatch banner state
  const [mismatchBanner, setMismatchBanner] = useState<SafetyMismatchState | null>(null);

  // Active modal screen ('scan' | 'verify' | 'mismatch_details' | null)
  const [activeModal, setActiveModal] = useState<'scan' | 'verify' | 'mismatch_details' | null>(null);

  const [messages, setMessages] = useState<Message[]>([
    {
      id: '1',
      sender: 'user123',
      text: 'Session established with Signal Protocol (@toled/signal-expo).',
      timestamp: '14:02',
      isMine: false,
    },
  ]);

  // Load verification state from local storage on mount
  useEffect(() => {
    async function checkVerification() {
      try {
        const record = await SafetyNumberService.getVerificationState(contactName);
        if (record && record.verifiedAt) {
          setIsVerified(true);
        }
      } catch (err) {
        console.warn('Could not read verification status:', err);
      }
    }
    checkVerification();
  }, [contactName]);

  /**
   * KEY CHANGE DETECTION LOGIC:
   * On every incoming message or session update, if the identity key has changed:
   * 1. Set verifiedAt = null in local storage.
   * 2. Insert persistent, non-dismissable system message in the chat:
   *    "⚠️ [Contact Name]'s security code has changed. This could mean they reinstalled the app, or someone is intercepting your messages. Tap to verify again."
   * 3. DISABLE the message input field for that chat until the user resolves the warning.
   */
  const handleKeyChangeDetected = async (cName: string, newKeyHex?: string, prevKeyHex?: string) => {
    // 1. Set verifiedAt = null in local storage
    await SafetyNumberService.resetVerification(cName, newKeyHex);
    setIsVerified(false);

    // 2. Insert persistent non-dismissable system message in chat
    const warningText = `⚠️ ${cName}'s security code has changed. This could mean they reinstalled the app, or someone is intercepting your messages. Tap to verify again.`;

    setMessages((prev) => {
      // Avoid duplicate consecutive system warning messages
      const last = prev[prev.length - 1];
      if (last && last.isSystemWarning && last.text === warningText) {
        return prev;
      }
      return [
        ...prev,
        {
          id: `keychange_${Date.now()}`,
          sender: 'System',
          text: warningText,
          timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
          isMine: false,
          isSystemWarning: true,
        },
      ];
    });

    // 3. DISABLE the message input field for that chat
    setKeyChangeLock({
      contactName: cName,
      detectedAt: Date.now(),
      newKeyHex: newKeyHex || '4A5560EE65C96167969CDA8AF0773669113FDD4D5A4AB721475018FEA959BC81',
      previousKeyHex: prevKeyHex,
    });
  };

  // Sync protocol key change events
  useEffect(() => {
    if (keyChangeAlert) {
      handleKeyChangeDetected(
        keyChangeAlert.contactName,
        keyChangeAlert.newKeyFingerprint,
        keyChangeAlert.previousKeyFingerprint
      );
    }
  }, [keyChangeAlert]);

  // Outbound send handler
  const handleSend = async () => {
    if (!inputText.trim()) return;

    // Strict security check 1: Input locked due to key change
    if (keyChangeLock) {
      Alert.alert(
        'Sending Blocked: Key Change Detected',
        `${contactName}'s security code has changed. Tap the warning message in the chat to verify or accept the new code before sending messages.`,
        [{ text: 'OK', onPress: () => setShowKeyChangeResolutionModal(true) }]
      );
      return;
    }

    // Strict security check 2: Outbound messages blocked on safety number mismatch
    if (mismatchBanner) {
      Alert.alert(
        'Outbound Transmission Blocked',
        `A Safety Number mismatch was detected with ${contactName}.\n\n` +
          'To protect against Man-in-the-Middle attacks, outbound messages are disabled until the identity is verified.',
        [{ text: 'OK' }]
      );
      return;
    }

    try {
      // Encrypt message via Signal Protocol Double Ratchet
      const ciphertext = await sendEncryptedMessage(contactName, inputText.trim());

      setMessages((prev) => [
        ...prev,
        {
          id: Date.now().toString(),
          sender: 'Me',
          text: inputText.trim(),
          timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
          isMine: true,
        },
      ]);
      setInputText('');
    } catch (err: any) {
      if (!keyChangeAlert) {
        Alert.alert('Encryption Error', err.message);
      }
    }
  };

  /**
   * Resolution Choice A: Completes verification again (Safety Number matches)
   */
  const handleResolutionVerifyAgain = () => {
    setShowKeyChangeResolutionModal(false);
    setActiveModal('scan');
  };

  /**
   * Resolution Choice B: Explicitly accepts the new key (with strict warning confirmation)
   */
  const handleResolutionExplicitAccept = () => {
    Alert.alert(
      'Security Warning: Accept Without Verification?',
      `You are accepting a new security code for ${contactName} WITHOUT comparing Safety Numbers.\n\n` +
        `If someone is intercepting your connection (Man-in-the-Middle attack), they will be able to decrypt, read, and modify your messages.\n\n` +
        `Are you sure you want to trust this unverified key?`,
      [
        { text: 'Cancel', style: 'cancel' },
        {
          text: 'Accept Without Verification',
          style: 'destructive',
          onPress: async () => {
            if (keyChangeLock?.newKeyHex) {
              await SafetyNumberService.acceptNewKeyWithoutVerification(
                contactName,
                keyChangeLock.newKeyHex
              );
            }
            if (approveKeyChange) {
              await approveKeyChange();
            }
            // Unlock message input field
            setKeyChangeLock(null);
            setShowKeyChangeResolutionModal(false);
            Alert.alert(
              'New Key Accepted',
              `The new security code for ${contactName} was accepted. Input field is now unlocked. Note that the contact remains unverified until verified.`,
              [{ text: 'OK' }]
            );
          },
        },
      ]
    );
  };

  const handleConfirmDismissMismatch = () => {
    Alert.alert(
      'Dismiss Security Alert?',
      `Dismissing this banner does NOT verify ${contactName}. If someone is intercepting your conversation, they may read or tamper with unauthenticated messages.\n\nAre you sure you want to dismiss?`,
      [
        { text: 'Cancel', style: 'cancel' },
        {
          text: 'Dismiss Warning',
          style: 'destructive',
          onPress: () => setMismatchBanner(null),
        },
      ]
    );
  };

  const handleMismatchDetected = (scannedCode: string) => {
    setMismatchBanner({
      contactName,
      expected: expectedSafetyNumber,
      scanned: scannedCode,
      timestamp: Date.now(),
    });
  };

  // Called when verification succeeds (Safety Number matches)
  const handleVerifiedSuccess = () => {
    setIsVerified(true);
    setMismatchBanner(null);
    setKeyChangeLock(null); // Unlocks message input field!
    setShowKeyChangeResolutionModal(false);
  };

  const isInputDisabled = Boolean(keyChangeLock || mismatchBanner);

  return (
    <SafeAreaView style={styles.container}>
      <StatusBar barStyle="light-content" />

      {/* Header */}
      <View style={styles.header}>
        <View style={styles.headerLeft}>
          <Text style={styles.headerTitle}>🔒 AnonChat</Text>
          <View style={styles.contactRow}>
            <Text style={styles.headerSubtitle}>
              Contact: <Text style={styles.bold}>{contactName}</Text>
            </Text>
            <View
              style={[
                styles.verificationBadge,
                isVerified ? styles.badgeVerified : styles.badgeUnverified,
              ]}
            >
              <Text style={styles.verificationBadgeText}>
                {isVerified ? '✓ Verified' : 'Unverified'}
              </Text>
            </View>
          </View>
        </View>

        {/* Header Action Buttons */}
        <View style={styles.headerActions}>
          <TouchableOpacity
            style={styles.actionButton}
            onPress={() => setActiveModal('verify')}
            accessibilityLabel="Show Safety Number QR"
          >
            <Text style={styles.actionButtonText}>Show QR</Text>
          </TouchableOpacity>
          <TouchableOpacity
            style={[styles.actionButton, styles.actionButtonScan]}
            onPress={() => setActiveModal('scan')}
            accessibilityLabel="Scan Contact Safety Number QR"
          >
            <Text style={styles.actionButtonScanText}>Scan QR</Text>
          </TouchableOpacity>
        </View>
      </View>

      {/* Safety Info Bar with Key Change Test Trigger */}
      <View style={styles.infoBar}>
        <Text style={styles.infoText}>
          RegID: {publicBundle?.registrationId || 'Active'} | Tor Circuits Active
        </Text>
        <TouchableOpacity
          onPress={() =>
            handleKeyChangeDetected(
              contactName,
              'F9E8D7C6B5A43210F9E8D7C6B5A43210F9E8D7C6B5A43210F9E8D7C6B5A43210',
              'A1B2C3D4E5F60708A1B2C3D4E5F60708A1B2C3D4E5F60708A1B2C3D4E5F60708'
            )
          }
        >
          <Text style={styles.testTriggerText}>[Simulate Key Change]</Text>
        </TouchableOpacity>
      </View>

      {/* ⚠️ PERSISTENT RED MISMATCH BANNER */}
      {mismatchBanner && (
        <View style={styles.mismatchBanner}>
          <View style={styles.mismatchContentRow}>
            <Text style={styles.mismatchIcon}>⚠️</Text>
            <View style={styles.mismatchTextCol}>
              <Text style={styles.mismatchHeader}>SAFETY NUMBER MISMATCH DETECTED</Text>
              <Text style={styles.mismatchDesc}>
                The scanned Safety Number for {mismatchBanner.contactName} does not match the key on file.
                Outbound messages are BLOCKED to prevent interception.
              </Text>
            </View>
          </View>

          <View style={styles.mismatchButtonsRow}>
            <TouchableOpacity
              style={styles.mismatchDetailsButton}
              onPress={() => setActiveModal('mismatch_details')}
            >
              <Text style={styles.mismatchDetailsButtonText}>View Mismatch Details</Text>
            </TouchableOpacity>
            <TouchableOpacity
              style={styles.mismatchDismissButton}
              onPress={handleConfirmDismissMismatch}
            >
              <Text style={styles.mismatchDismissButtonText}>Dismiss Warning</Text>
            </TouchableOpacity>
          </View>
        </View>
      )}

      {/* Messages List */}
      <FlatList
        data={messages}
        keyExtractor={(item) => item.id}
        contentContainerStyle={styles.messageList}
        renderItem={({ item }) => {
          // Render persistent, non-dismissable system message in chat
          if (item.isSystemWarning) {
            return (
              <TouchableOpacity
                style={styles.systemWarningBubble}
                activeOpacity={0.85}
                onPress={() => setShowKeyChangeResolutionModal(true)}
              >
                <View style={styles.systemWarningHeaderRow}>
                  <Text style={styles.systemWarningIcon}>⚠️</Text>
                  <Text style={styles.systemWarningTitle}>SECURITY CODE CHANGED</Text>
                </View>
                <Text style={styles.systemWarningText}>{item.text}</Text>
                <View style={styles.systemWarningFooter}>
                  <Text style={styles.systemWarningAction}>Tap to verify or resolve →</Text>
                  <Text style={styles.systemWarningTimestamp}>{item.timestamp}</Text>
                </View>
              </TouchableOpacity>
            );
          }

          return (
            <View
              style={[
                styles.messageBubble,
                item.isMine ? styles.myBubble : styles.peerBubble,
              ]}
            >
              <Text style={styles.messageText}>{item.text}</Text>
              <Text style={styles.timestamp}>{item.timestamp}</Text>
            </View>
          );
        }}
      />

      {/* Input Bar (DISABLED while keyChangeLock or mismatch is active) */}
      <View style={styles.inputContainer}>
        <TextInput
          style={[styles.input, isInputDisabled && styles.inputDisabled]}
          placeholder={
            keyChangeLock
              ? '🚫 Input disabled: Tap security warning above to verify'
              : mismatchBanner
              ? '🚫 Transmission blocked: Safety Number mismatch'
              : 'Type an encrypted message...'
          }
          placeholderTextColor={isInputDisabled ? '#FF8A80' : '#777777'}
          value={inputText}
          onChangeText={setInputText}
          editable={!isInputDisabled}
        />
        <TouchableOpacity
          style={[styles.sendButton, isInputDisabled && styles.sendButtonDisabled]}
          onPress={handleSend}
          disabled={isInputDisabled}
        >
          <Text style={[styles.sendButtonText, isInputDisabled && styles.sendButtonTextDisabled]}>
            {isInputDisabled ? 'Blocked 🚫' : 'Send 🚀'}
          </Text>
        </TouchableOpacity>
      </View>

      {/* Modal: Key-Change Resolution Options Modal */}
      <Modal
        visible={showKeyChangeResolutionModal}
        transparent={true}
        animationType="fade"
        onRequestClose={() => setShowKeyChangeResolutionModal(false)}
      >
        <View style={styles.modalOverlay}>
          <View style={styles.keyChangeCard}>
            <Text style={styles.keyChangeIcon}>⚠️</Text>
            <Text style={styles.keyChangeTitle}>Security Code Changed</Text>
            <Text style={styles.keyChangeDescription}>
              <Text style={styles.bold}>{contactName}</Text>&apos;s cryptographic identity key has changed.
              {'\n\n'}
              This could mean they reinstalled the app, switched devices, or someone may be intercepting
              your messages (Man-in-the-Middle attack).
              {'\n\n'}
              Outbound message sending is <Text style={styles.boldRed}>LOCKED</Text> until resolved.
            </Text>

            <View style={styles.keyChangeChoicesContainer}>
              {/* Option A: Complete verification again */}
              <TouchableOpacity
                style={styles.choiceButtonVerify}
                onPress={handleResolutionVerifyAgain}
              >
                <Text style={styles.choiceButtonVerifyText}>
                  ✓ Verify Again (Safety Number Match)
                </Text>
                <Text style={styles.choiceButtonSubtext}>
                  Recommended: Scan their QR code or compare numbers.
                </Text>
              </TouchableOpacity>

              {/* Option B: Explicitly accept new key */}
              <TouchableOpacity
                style={styles.choiceButtonAccept}
                onPress={handleResolutionExplicitAccept}
              >
                <Text style={styles.choiceButtonAcceptText}>
                  ⚠️ Accept New Key (Without Verification)
                </Text>
                <Text style={styles.choiceButtonAcceptSubtext}>
                  Security risk: Trusts the new key without proof.
                </Text>
              </TouchableOpacity>

              {/* Keep blocked */}
              <TouchableOpacity
                style={styles.choiceButtonCancel}
                onPress={() => setShowKeyChangeResolutionModal(false)}
              >
                <Text style={styles.choiceButtonCancelText}>Keep Blocked (Cancel)</Text>
              </TouchableOpacity>
            </View>
          </View>
        </View>
      </Modal>

      {/* Modal: QR Display Screen */}
      <Modal
        visible={activeModal === 'verify'}
        animationType="slide"
        presentationStyle="fullScreen"
        onRequestClose={() => setActiveModal(null)}
      >
        <SafetyNumberVerifyScreen
          contactName={contactName}
          contactId={contactName}
          safetyNumberString={expectedSafetyNumber}
          onVerified={handleVerifiedSuccess}
          onClose={() => setActiveModal(null)}
        />
      </Modal>

      {/* Modal: QR Scanner Screen */}
      <Modal
        visible={activeModal === 'scan'}
        animationType="slide"
        presentationStyle="fullScreen"
        onRequestClose={() => setActiveModal(null)}
      >
        <SafetyNumberScanScreen
          contactName={contactName}
          contactId={contactName}
          expectedSafetyNumber={expectedSafetyNumber}
          onVerified={handleVerifiedSuccess}
          onSwitchToDisplayQr={() => setActiveModal('verify')}
          onClose={() => setActiveModal(null)}
          onMismatch={handleMismatchDetected}
        />
      </Modal>

      {/* Modal: Mismatch Details Screen */}
      <Modal
        visible={activeModal === 'mismatch_details'}
        animationType="fade"
        transparent={true}
        onRequestClose={() => setActiveModal(null)}
      >
        <View style={styles.modalOverlay}>
          <View style={styles.detailsModalBox}>
            <View style={styles.detailsHeaderRow}>
              <Text style={styles.detailsIcon}>⚠️</Text>
              <Text style={styles.detailsTitle}>Safety Number Mismatch Details</Text>
            </View>

            <ScrollView style={styles.detailsScrollView}>
              <Text style={styles.detailsExplanation}>
                The Safety Number generated from {mismatchBanner?.contactName}&apos;s identity key on your device
                does not match the code you scanned.
              </Text>

              <Text style={styles.detailsSubExplanation}>
                Possible causes include:
                {'\n'}• An active Man-in-the-Middle (MitM) attack intercepting your connection
                {'\n'}• {mismatchBanner?.contactName} reinstalled their app or restored from an old backup
                {'\n'}• A malicious third party is attempting to impersonate your contact
              </Text>

              <View style={styles.codeComparisonBox}>
                <Text style={styles.codeLabel}>EXPECTED SAFETY NUMBER (LOCAL KEY):</Text>
                <Text style={styles.codeValueExpected}>
                  {mismatchBanner?.expected || expectedSafetyNumber}
                </Text>
              </View>

              <View style={styles.codeComparisonBox}>
                <Text style={styles.codeLabel}>SCANNED CODE (REMOTE DEVICE):</Text>
                <Text style={styles.codeValueScanned}>
                  {mismatchBanner?.scanned || 'Unknown / Unrecognized format'}
                </Text>
              </View>

              <View style={styles.diffWarningBox}>
                <Text style={styles.diffWarningText}>
                  STATUS: Outbound transmissions are strictly blocked. Do NOT share sensitive information
                  until you confirm the identity out-of-band.
                </Text>
              </View>
            </ScrollView>

            <View style={styles.detailsActionsRow}>
              <TouchableOpacity
                style={styles.detailsRescanButton}
                onPress={() => setActiveModal('scan')}
              >
                <Text style={styles.detailsRescanButtonText}>Re-Scan QR Code</Text>
              </TouchableOpacity>
              <TouchableOpacity
                style={styles.detailsCloseButton}
                onPress={() => setActiveModal(null)}
              >
                <Text style={styles.detailsCloseButtonText}>Close</Text>
              </TouchableOpacity>
            </View>
          </View>
        </View>
      </Modal>
    </SafeAreaView>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#121212',
  },
  header: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    paddingHorizontal: 16,
    paddingVertical: 12,
    backgroundColor: '#1E1E1E',
    borderBottomWidth: 1,
    borderBottomColor: '#2C2C2C',
  },
  headerLeft: {
    flex: 1,
  },
  headerTitle: {
    color: '#00D2B4',
    fontSize: 18,
    fontWeight: 'bold',
  },
  contactRow: {
    flexDirection: 'row',
    alignItems: 'center',
    marginTop: 4,
    gap: 8,
  },
  headerSubtitle: {
    color: '#888888',
    fontSize: 12,
  },
  bold: {
    color: '#FFFFFF',
    fontWeight: 'bold',
  },
  boldRed: {
    color: '#FF5252',
    fontWeight: 'bold',
  },
  verificationBadge: {
    paddingHorizontal: 6,
    paddingVertical: 2,
    borderRadius: 4,
  },
  badgeVerified: {
    backgroundColor: '#004D40',
  },
  badgeUnverified: {
    backgroundColor: '#37474F',
  },
  verificationBadgeText: {
    color: '#80CBC4',
    fontSize: 10,
    fontWeight: '600',
  },
  headerActions: {
    flexDirection: 'row',
    gap: 8,
    alignItems: 'center',
  },
  actionButton: {
    backgroundColor: '#2A2A2A',
    paddingHorizontal: 10,
    paddingVertical: 6,
    borderRadius: 6,
    borderWidth: 1,
    borderColor: '#3D3D3D',
  },
  actionButtonText: {
    color: '#CCCCCC',
    fontSize: 12,
    fontWeight: '600',
  },
  actionButtonScan: {
    backgroundColor: '#00D2B4',
    borderColor: '#00D2B4',
  },
  actionButtonScanText: {
    color: '#000000',
    fontSize: 12,
    fontWeight: 'bold',
  },
  infoBar: {
    backgroundColor: '#1A1A1A',
    paddingVertical: 6,
    paddingHorizontal: 16,
    borderBottomWidth: 1,
    borderBottomColor: '#252525',
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
  },
  infoText: {
    color: '#666666',
    fontSize: 10,
    fontFamily: 'monospace',
  },
  testTriggerText: {
    color: '#FFB74D',
    fontSize: 10,
    fontWeight: '600',
  },

  /* ⚠️ PERSISTENT RED BANNER STYLES */
  mismatchBanner: {
    backgroundColor: '#B71C1C',
    borderBottomWidth: 2,
    borderBottomColor: '#FF5252',
    padding: 12,
  },
  mismatchContentRow: {
    flexDirection: 'row',
    alignItems: 'flex-start',
    gap: 10,
  },
  mismatchIcon: {
    fontSize: 22,
  },
  mismatchTextCol: {
    flex: 1,
  },
  mismatchHeader: {
    color: '#FFFFFF',
    fontSize: 13,
    fontWeight: 'bold',
    letterSpacing: 0.5,
  },
  mismatchDesc: {
    color: '#FFCDD2',
    fontSize: 12,
    lineHeight: 16,
    marginTop: 2,
  },
  mismatchButtonsRow: {
    flexDirection: 'row',
    justifyContent: 'flex-end',
    gap: 10,
    marginTop: 10,
  },
  mismatchDetailsButton: {
    backgroundColor: '#FFFFFF',
    paddingHorizontal: 12,
    paddingVertical: 6,
    borderRadius: 4,
  },
  mismatchDetailsButtonText: {
    color: '#B71C1C',
    fontSize: 12,
    fontWeight: 'bold',
  },
  mismatchDismissButton: {
    backgroundColor: 'rgba(0, 0, 0, 0.3)',
    paddingHorizontal: 12,
    paddingVertical: 6,
    borderRadius: 4,
    borderWidth: 1,
    borderColor: 'rgba(255, 255, 255, 0.4)',
  },
  mismatchDismissButtonText: {
    color: '#FFFFFF',
    fontSize: 12,
  },

  /* Message List Styles */
  messageList: {
    padding: 16,
    gap: 10,
  },
  messageBubble: {
    maxWidth: '80%',
    padding: 12,
    borderRadius: 12,
  },
  myBubble: {
    alignSelf: 'flex-end',
    backgroundColor: '#005A8C',
  },
  peerBubble: {
    alignSelf: 'flex-start',
    backgroundColor: '#2D2D30',
  },
  messageText: {
    color: '#FFFFFF',
    fontSize: 15,
  },
  timestamp: {
    color: '#B0BEC5',
    fontSize: 10,
    alignSelf: 'flex-end',
    marginTop: 4,
  },

  /* Persistent Non-Dismissable System Warning Message */
  systemWarningBubble: {
    backgroundColor: 'rgba(230, 81, 0, 0.15)',
    borderWidth: 1.5,
    borderColor: '#FF9800',
    borderRadius: 12,
    padding: 14,
    marginVertical: 6,
    alignSelf: 'center',
    width: '95%',
  },
  systemWarningHeaderRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 6,
    marginBottom: 6,
  },
  systemWarningIcon: {
    fontSize: 16,
  },
  systemWarningTitle: {
    color: '#FFB74D',
    fontSize: 12,
    fontWeight: 'bold',
    letterSpacing: 0.6,
  },
  systemWarningText: {
    color: '#FFF3E0',
    fontSize: 13,
    lineHeight: 18,
    marginBottom: 8,
  },
  systemWarningFooter: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    borderTopWidth: 1,
    borderTopColor: 'rgba(255, 152, 0, 0.25)',
    paddingTop: 8,
  },
  systemWarningAction: {
    color: '#00D2B4',
    fontSize: 12,
    fontWeight: 'bold',
  },
  systemWarningTimestamp: {
    color: '#B0BEC5',
    fontSize: 10,
  },

  /* Input Bar Styles */
  inputContainer: {
    flexDirection: 'row',
    padding: 12,
    backgroundColor: '#1E1E1E',
    borderTopWidth: 1,
    borderTopColor: '#2C2C2C',
    alignItems: 'center',
    gap: 8,
  },
  input: {
    flex: 1,
    backgroundColor: '#2A2A2A',
    color: '#FFFFFF',
    paddingHorizontal: 16,
    paddingVertical: 10,
    borderRadius: 20,
    fontSize: 14,
  },
  inputDisabled: {
    backgroundColor: '#3E2723',
    color: '#FF8A80',
    borderColor: '#D32F2F',
    borderWidth: 1,
  },
  sendButton: {
    backgroundColor: '#00D2B4',
    paddingHorizontal: 16,
    paddingVertical: 10,
    borderRadius: 20,
  },
  sendButtonDisabled: {
    backgroundColor: '#37474F',
  },
  sendButtonText: {
    color: '#000000',
    fontWeight: 'bold',
    fontSize: 14,
  },
  sendButtonTextDisabled: {
    color: '#78909C',
  },

  /* Modals Overlay */
  modalOverlay: {
    flex: 1,
    backgroundColor: 'rgba(0, 0, 0, 0.85)',
    justifyContent: 'center',
    alignItems: 'center',
    padding: 20,
  },

  /* Key-Change Resolution Card */
  keyChangeCard: {
    backgroundColor: '#1E1E1E',
    borderRadius: 16,
    padding: 24,
    width: '100%',
    maxWidth: 440,
    borderWidth: 2,
    borderColor: '#FF9800',
  },
  keyChangeIcon: {
    fontSize: 36,
    textAlign: 'center',
    marginBottom: 8,
  },
  keyChangeTitle: {
    color: '#FF9800',
    fontSize: 19,
    fontWeight: 'bold',
    textAlign: 'center',
    marginBottom: 12,
  },
  keyChangeDescription: {
    color: '#E0E0E0',
    fontSize: 13,
    lineHeight: 19,
    textAlign: 'center',
    marginBottom: 20,
  },
  keyChangeChoicesContainer: {
    gap: 12,
  },
  choiceButtonVerify: {
    backgroundColor: '#00D2B4',
    borderRadius: 10,
    paddingVertical: 12,
    paddingHorizontal: 16,
    alignItems: 'center',
  },
  choiceButtonVerifyText: {
    color: '#000000',
    fontWeight: 'bold',
    fontSize: 14,
  },
  choiceButtonSubtext: {
    color: '#00332C',
    fontSize: 11,
    marginTop: 2,
  },
  choiceButtonAccept: {
    backgroundColor: 'rgba(255, 82, 82, 0.15)',
    borderRadius: 10,
    paddingVertical: 12,
    paddingHorizontal: 16,
    alignItems: 'center',
    borderWidth: 1,
    borderColor: '#FF5252',
  },
  choiceButtonAcceptText: {
    color: '#FF5252',
    fontWeight: 'bold',
    fontSize: 13,
  },
  choiceButtonAcceptSubtext: {
    color: '#FFCDD2',
    fontSize: 11,
    marginTop: 2,
  },
  choiceButtonCancel: {
    paddingVertical: 10,
    alignItems: 'center',
  },
  choiceButtonCancelText: {
    color: '#888888',
    fontSize: 13,
  },

  /* Mismatch Details Modal */
  detailsModalBox: {
    backgroundColor: '#1E1E1E',
    borderRadius: 16,
    padding: 20,
    width: '100%',
    maxHeight: '85%',
    borderWidth: 1,
    borderColor: '#FF5252',
  },
  detailsHeaderRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8,
    marginBottom: 12,
  },
  detailsIcon: {
    fontSize: 24,
  },
  detailsTitle: {
    color: '#FF5252',
    fontSize: 17,
    fontWeight: 'bold',
    flex: 1,
  },
  detailsScrollView: {
    marginBottom: 16,
  },
  detailsExplanation: {
    color: '#E0E0E0',
    fontSize: 13,
    lineHeight: 18,
    marginBottom: 8,
  },
  detailsSubExplanation: {
    color: '#AAAAAA',
    fontSize: 12,
    lineHeight: 18,
    marginBottom: 16,
  },
  codeComparisonBox: {
    backgroundColor: '#121212',
    borderRadius: 8,
    padding: 12,
    marginBottom: 12,
    borderWidth: 1,
    borderColor: '#333333',
  },
  codeLabel: {
    color: '#888888',
    fontSize: 10,
    fontWeight: 'bold',
    marginBottom: 6,
  },
  codeValueExpected: {
    color: '#80CBC4',
    fontFamily: 'monospace',
    fontSize: 13,
    letterSpacing: 0.8,
  },
  codeValueScanned: {
    color: '#FF8A80',
    fontFamily: 'monospace',
    fontSize: 13,
    letterSpacing: 0.8,
  },
  diffWarningBox: {
    backgroundColor: 'rgba(255, 82, 82, 0.1)',
    borderRadius: 8,
    padding: 10,
    borderWidth: 1,
    borderColor: 'rgba(255, 82, 82, 0.3)',
  },
  diffWarningText: {
    color: '#FF8A80',
    fontSize: 11,
    lineHeight: 16,
    fontWeight: '600',
  },
  detailsActionsRow: {
    flexDirection: 'row',
    justifyContent: 'flex-end',
    gap: 12,
  },
  detailsRescanButton: {
    backgroundColor: '#00D2B4',
    paddingHorizontal: 16,
    paddingVertical: 10,
    borderRadius: 8,
  },
  detailsRescanButtonText: {
    color: '#000000',
    fontWeight: 'bold',
    fontSize: 13,
  },
  detailsCloseButton: {
    backgroundColor: '#2A2A2A',
    paddingHorizontal: 16,
    paddingVertical: 10,
    borderRadius: 8,
  },
  detailsCloseButtonText: {
    color: '#CCCCCC',
    fontSize: 13,
  },
});
