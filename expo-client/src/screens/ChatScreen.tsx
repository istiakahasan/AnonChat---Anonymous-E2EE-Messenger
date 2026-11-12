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
import { KeyChangeWarningModal } from '../components/KeyChangeWarningModal';
import { SafetyNumberScanScreen } from './SafetyNumberScanScreen';
import { SafetyNumberVerifyScreen } from './SafetyNumberVerifyScreen';
import { SafetyNumberService } from '../crypto/safetyNumber';

interface Message {
  id: string;
  sender: string;
  text: string;
  timestamp: string;
  isMine: boolean;
}

export interface SafetyMismatchState {
  contactName: string;
  expected: string;
  scanned: string;
  timestamp: number;
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

  // Outbound send handler
  const handleSend = async () => {
    if (!inputText.trim()) return;

    // Strict security check: Outbound messages are strictly blocked on safety number mismatch
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

  const handleVerifiedSuccess = () => {
    setIsVerified(true);
    setMismatchBanner(null);
  };

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

        {/* Header Action Buttons for Verification */}
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

      {/* Safety Info Bar */}
      <View style={styles.infoBar}>
        <Text style={styles.infoText}>
          RegID: {publicBundle?.registrationId || 'Active'} | Tor Onion Routing | Isolated SecureStore
        </Text>
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
        renderItem={({ item }) => (
          <View
            style={[
              styles.messageBubble,
              item.isMine ? styles.myBubble : styles.peerBubble,
            ]}
          >
            <Text style={styles.messageText}>{item.text}</Text>
            <Text style={styles.timestamp}>{item.timestamp}</Text>
          </View>
        )}
      />

      {/* Input Bar */}
      <View style={styles.inputContainer}>
        <TextInput
          style={[styles.input, mismatchBanner && styles.inputDisabled]}
          placeholder={
            mismatchBanner
              ? '🚫 Transmission blocked: Safety Number mismatch'
              : 'Type an encrypted message...'
          }
          placeholderTextColor={mismatchBanner ? '#FF8A80' : '#777777'}
          value={inputText}
          onChangeText={setInputText}
          editable={!mismatchBanner}
        />
        <TouchableOpacity
          style={[styles.sendButton, mismatchBanner && styles.sendButtonDisabled]}
          onPress={handleSend}
          disabled={Boolean(mismatchBanner)}
        >
          <Text style={[styles.sendButtonText, mismatchBanner && styles.sendButtonTextDisabled]}>
            {mismatchBanner ? 'Blocked 🚫' : 'Send 🚀'}
          </Text>
        </TouchableOpacity>
      </View>

      {/* Key-Change Warning Modal from Protocol */}
      <KeyChangeWarningModal
        alert={keyChangeAlert}
        onApprove={approveKeyChange}
        onReject={rejectKeyChange}
      />

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

              {/* Expected Number */}
              <View style={styles.codeComparisonBox}>
                <Text style={styles.codeLabel}>EXPECTED SAFETY NUMBER (LOCAL KEY):</Text>
                <Text style={styles.codeValueExpected}>
                  {mismatchBanner?.expected || expectedSafetyNumber}
                </Text>
              </View>

              {/* Scanned Number */}
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
  },
  infoText: {
    color: '#666666',
    fontSize: 10,
    fontFamily: 'monospace',
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

  messageList: {
    padding: 16,
    gap: 8,
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

  /* Mismatch Details Modal */
  modalOverlay: {
    flex: 1,
    backgroundColor: 'rgba(0, 0, 0, 0.85)',
    justifyContent: 'center',
    alignItems: 'center',
    padding: 20,
  },
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
