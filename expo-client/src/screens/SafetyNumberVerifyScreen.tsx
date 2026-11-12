import React, { useState, useEffect } from 'react';
import {
  View,
  Text,
  StyleSheet,
  ScrollView,
  TouchableOpacity,
  Alert,
  SafeAreaView,
  StatusBar,
} from 'react-native';
import QRCode from 'react-native-qrcode-svg';
import { SafetyNumberService } from '../crypto/safetyNumber';

interface Props {
  contactName: string;
  contactId: string;
  safetyNumberString: string; // 60-digit string formatted as 12 groups of 5 digits
  onVerified?: () => void;
  onClose?: () => void;
}

export const SafetyNumberVerifyScreen: React.FC<Props> = ({
  contactName,
  contactId,
  safetyNumberString,
  onVerified,
  onClose,
}) => {
  const [isVerified, setIsVerified] = useState(false);
  const [verifiedDate, setVerifiedDate] = useState<string | null>(null);

  useEffect(() => {
    async function loadVerificationState() {
      const state = await SafetyNumberService.getVerificationState(contactId);
      if (state && state.verifiedAt) {
        setIsVerified(true);
        setVerifiedDate(new Date(state.verifiedAt).toLocaleDateString());
      }
    }
    loadVerificationState();
  }, [contactId]);

  /**
   * Critical UX Requirement:
   * Research on Signal verification found that when "Mark as verified" was a passive toggle,
   * 12 out of 14 participants toggled it WITHOUT comparing numbers.
   * This button MUST prompt with an explicit confirmation dialog asking whether the numbers matched.
   */
  const handleMarkAsVerifiedPress = () => {
    Alert.alert(
      'Confirm Safety Number Match',
      `Did you compare the numbers with ${contactName} and confirm they match?`,
      [
        {
          text: 'No, not yet',
          style: 'cancel',
        },
        {
          text: 'Yes, they match',
          style: 'default',
          onPress: async () => {
            await SafetyNumberService.markContactVerified(contactId);
            setIsVerified(true);
            setVerifiedDate(new Date().toLocaleDateString());
            if (onVerified) onVerified();
          },
        },
      ],
      { cancelable: true }
    );
  };

  // Split the 12 groups of 5 digits into chunks for clean monospace alignment
  const digitGroups = safetyNumberString.split(' ');

  return (
    <SafeAreaView style={styles.container}>
      <StatusBar barStyle="light-content" />

      {/* 1. Header */}
      <View style={styles.header}>
        {onClose && (
          <TouchableOpacity onPress={onClose} style={styles.closeButton}>
            <Text style={styles.closeText}>✕</Text>
          </TouchableOpacity>
        )}
        <Text style={styles.headerTitle}>Verify {contactName}</Text>
        <View style={styles.placeholder} />
      </View>

      <ScrollView contentContainerStyle={styles.scrollContent}>
        {/* 2. Actionable Explanation Text */}
        <Text style={styles.explanationText}>
          Scan this code with {contactName}&apos;s phone, or compare the numbers below.
        </Text>

        {/* 3. High-Contrast QR Code with Quiet Zone */}
        <View style={styles.qrWrapper}>
          <View style={styles.qrWhiteContainer}>
            <QRCode
              value={safetyNumberString}
              size={280}
              color="#000000"
              backgroundColor="#FFFFFF"
              quietZone={16}
            />
          </View>
        </View>

        {/* 4. Numeric Display (Monospace Alignment) */}
        <View style={styles.numericContainer}>
          <Text style={styles.numericLabel}>Safety Number</Text>
          <View style={styles.gridContainer}>
            {digitGroups.map((group, index) => (
              <View key={index} style={styles.digitGroupBadge}>
                <Text style={styles.digitGroupText}>{group}</Text>
              </View>
            ))}
          </View>
        </View>

        {/* Verification Status Indicator */}
        {isVerified && (
          <View style={styles.verifiedBadge}>
            <Text style={styles.verifiedBadgeText}>
              ✓ Verified on {verifiedDate}
            </Text>
          </View>
        )}

        {/* 5. Mark as Verified Button with Confirmation Dialog */}
        <TouchableOpacity
          style={[styles.verifyButton, isVerified && styles.verifyButtonDisabled]}
          onPress={handleMarkAsVerifiedPress}
          activeOpacity={0.8}
        >
          <Text style={styles.verifyButtonText}>
            {isVerified ? 'Re-verify Safety Number' : 'Mark as Verified'}
          </Text>
        </TouchableOpacity>
      </ScrollView>
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
    alignItems: 'center',
    justifyContent: 'space-between',
    paddingHorizontal: 16,
    paddingVertical: 14,
    backgroundColor: '#1E1E1E',
    borderBottomWidth: 1,
    borderBottomColor: '#2A2A2A',
  },
  closeButton: {
    padding: 8,
  },
  closeText: {
    color: '#FFFFFF',
    fontSize: 18,
    fontWeight: 'bold',
  },
  headerTitle: {
    color: '#00D2B4',
    fontSize: 18,
    fontWeight: 'bold',
    textAlign: 'center',
    flex: 1,
  },
  placeholder: {
    width: 32,
  },
  scrollContent: {
    padding: 24,
    alignItems: 'center',
  },
  explanationText: {
    color: '#E0E0E0',
    fontSize: 15,
    lineHeight: 22,
    textAlign: 'center',
    marginBottom: 20,
    paddingHorizontal: 12,
  },
  qrWrapper: {
    alignItems: 'center',
    justifyContent: 'center',
    marginBottom: 24,
  },
  qrWhiteContainer: {
    padding: 12,
    backgroundColor: '#FFFFFF',
    borderRadius: 16,
    shadowColor: '#000000',
    shadowOffset: { width: 0, height: 4 },
    shadowOpacity: 0.3,
    shadowRadius: 8,
    elevation: 6,
  },
  numericContainer: {
    width: '100%',
    backgroundColor: '#1A1A1A',
    borderRadius: 12,
    padding: 16,
    marginBottom: 20,
    borderWidth: 1,
    borderColor: '#2A2A2A',
  },
  numericLabel: {
    color: '#888888',
    fontSize: 12,
    textTransform: 'uppercase',
    textAlign: 'center',
    marginBottom: 12,
    fontWeight: '600',
  },
  gridContainer: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    justifyContent: 'space-between',
    gap: 8,
  },
  digitGroupBadge: {
    width: '30%',
    backgroundColor: '#262626',
    paddingVertical: 8,
    borderRadius: 6,
    alignItems: 'center',
    borderWidth: 1,
    borderColor: '#333333',
  },
  digitGroupText: {
    color: '#FFB74D',
    fontFamily: 'monospace',
    fontSize: 15,
    fontWeight: 'bold',
    letterSpacing: 1,
  },
  verifiedBadge: {
    backgroundColor: 'rgba(0, 210, 180, 0.15)',
    borderWidth: 1,
    borderColor: '#00D2B4',
    paddingVertical: 8,
    paddingHorizontal: 16,
    borderRadius: 20,
    marginBottom: 20,
  },
  verifiedBadgeText: {
    color: '#00D2B4',
    fontSize: 13,
    fontWeight: 'bold',
  },
  verifyButton: {
    width: '100%',
    backgroundColor: '#00D2B4',
    paddingVertical: 16,
    borderRadius: 12,
    alignItems: 'center',
  },
  verifyButtonDisabled: {
    backgroundColor: '#37474F',
  },
  verifyButtonText: {
    color: '#000000',
    fontSize: 16,
    fontWeight: 'bold',
  },
});

