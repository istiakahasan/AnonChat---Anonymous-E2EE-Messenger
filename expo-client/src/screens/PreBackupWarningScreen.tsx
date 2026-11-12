import React, { useState } from 'react';
import {
  View,
  Text,
  StyleSheet,
  TouchableOpacity,
  SafeAreaView,
  StatusBar,
  ScrollView,
} from 'react-native';

export interface PreBackupWarningScreenProps {
  onContinue: () => void;
  onCancel?: () => void;
}

/**
 * Mandatory Pre-Backup Warning Screen
 *
 * Security & UX Requirements:
 * 1. Header: "Your backup is yours alone"
 * 2. Body text: "If you lose your passphrase, your backup cannot be recovered. No one, including us, can help you. We do not have a copy of your key."
 * 3. Secondary text: "This is not a limitation. It is what makes your backup private. If we could recover it, so could anyone who compromises our servers."
 * 4. Required action: Checkbox: "I understand that if I lose my passphrase, my backup is permanently lost."
 * 5. Continue button: Disabled until the checkbox is checked.
 * 6. Strictly NO bypass: No "Skip" or "Remind me later" buttons.
 * 7. Ephemeral state: Navigating away does not persist acknowledgment; warning reappears next time.
 */
export const PreBackupWarningScreen: React.FC<PreBackupWarningScreenProps> = ({
  onContinue,
  onCancel,
}) => {
  const [acknowledged, setAcknowledged] = useState(false);

  const handleCancel = () => {
    // Reset state before navigating away
    setAcknowledged(false);
    if (onCancel) {
      onCancel();
    }
  };

  const handleContinue = () => {
    if (!acknowledged) return;
    onContinue();
  };

  return (
    <SafeAreaView style={styles.container}>
      <StatusBar barStyle="light-content" />

      {/* Top Bar with Cancel only (No Skip or Remind me later) */}
      <View style={styles.topBar}>
        {onCancel && (
          <TouchableOpacity
            testID="pre-backup-cancel-button"
            onPress={handleCancel}
            style={styles.cancelButton}
          >
            <Text style={styles.cancelButtonText}>Cancel</Text>
          </TouchableOpacity>
        )}
      </View>

      <ScrollView contentContainerStyle={styles.contentContainer}>
        {/* Warning Icon Shield */}
        <View style={styles.iconContainer}>
          <Text style={styles.iconText}>🛡️</Text>
        </View>

        {/* 1. Header */}
        <Text testID="pre-backup-header" style={styles.headerTitle}>
          Your backup is yours alone
        </Text>

        {/* 2. Body Text (exact wording) */}
        <View style={styles.bodyBox}>
          <Text testID="pre-backup-body" style={styles.bodyText}>
            If you lose your passphrase, your backup cannot be recovered. No one, including us, can help you. We do not have a copy of your key.
          </Text>
        </View>

        {/* 3. Secondary Text (exact wording) */}
        <Text testID="pre-backup-secondary" style={styles.secondaryText}>
          This is not a limitation. It is what makes your backup private. If we could recover it, so could anyone who compromises our servers.
        </Text>

        <View style={styles.divider} />

        {/* 4. Required Action: Checkbox */}
        <TouchableOpacity
          testID="pre-backup-checkbox"
          style={styles.checkboxContainer}
          onPress={() => setAcknowledged((prev) => !prev)}
          activeOpacity={0.8}
        >
          <View style={[styles.checkboxBox, acknowledged && styles.checkboxBoxChecked]}>
            {acknowledged && <Text style={styles.checkmarkText}>✓</Text>}
          </View>
          <Text testID="pre-backup-checkbox-label" style={styles.checkboxLabel}>
            I understand that if I lose my passphrase, my backup is permanently lost.
          </Text>
        </TouchableOpacity>

        {/* 5. Continue Button: Disabled until checkbox is checked */}
        <TouchableOpacity
          testID="pre-backup-continue-button"
          style={[styles.continueButton, !acknowledged && styles.continueButtonDisabled]}
          onPress={handleContinue}
          disabled={!acknowledged}
          activeOpacity={0.8}
        >
          <Text
            style={[
              styles.continueButtonText,
              !acknowledged && styles.continueButtonTextDisabled,
            ]}
          >
            Continue
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
  topBar: {
    flexDirection: 'row',
    justifyContent: 'flex-start',
    paddingHorizontal: 20,
    paddingTop: 10,
    minHeight: 44,
  },
  cancelButton: {
    paddingVertical: 8,
    paddingHorizontal: 12,
  },
  cancelButtonText: {
    color: '#888888',
    fontSize: 16,
  },
  contentContainer: {
    paddingHorizontal: 24,
    paddingBottom: 40,
    alignItems: 'center',
  },
  iconContainer: {
    width: 80,
    height: 80,
    borderRadius: 40,
    backgroundColor: 'rgba(255, 82, 82, 0.12)',
    alignItems: 'center',
    justifyContent: 'center',
    marginTop: 20,
    marginBottom: 24,
    borderWidth: 1,
    borderColor: 'rgba(255, 82, 82, 0.3)',
  },
  iconText: {
    fontSize: 40,
  },
  headerTitle: {
    fontSize: 26,
    fontWeight: 'bold',
    color: '#FFFFFF',
    textAlign: 'center',
    marginBottom: 20,
    letterSpacing: 0.3,
  },
  bodyBox: {
    width: '100%',
    backgroundColor: '#1E1E1E',
    borderRadius: 12,
    padding: 18,
    marginBottom: 16,
    borderLeftWidth: 4,
    borderLeftColor: '#FF5252',
  },
  bodyText: {
    fontSize: 16,
    lineHeight: 24,
    color: '#F5F5F5',
    fontWeight: '600',
  },
  secondaryText: {
    fontSize: 14,
    lineHeight: 22,
    color: '#AAAAAA',
    textAlign: 'left',
    marginBottom: 28,
  },
  divider: {
    width: '100%',
    height: 1,
    backgroundColor: '#2A2A2A',
    marginBottom: 24,
  },
  checkboxContainer: {
    width: '100%',
    flexDirection: 'row',
    alignItems: 'flex-start',
    backgroundColor: '#1A1A1A',
    padding: 16,
    borderRadius: 12,
    marginBottom: 32,
    borderWidth: 1,
    borderColor: '#333333',
  },
  checkboxBox: {
    width: 24,
    height: 24,
    borderRadius: 6,
    borderWidth: 2,
    borderColor: '#666666',
    alignItems: 'center',
    justifyContent: 'center',
    marginRight: 14,
    marginTop: 2,
    backgroundColor: '#121212',
  },
  checkboxBoxChecked: {
    backgroundColor: '#00D2B4',
    borderColor: '#00D2B4',
  },
  checkmarkText: {
    color: '#000000',
    fontSize: 15,
    fontWeight: 'bold',
  },
  checkboxLabel: {
    flex: 1,
    fontSize: 14,
    lineHeight: 20,
    color: '#EEEEEE',
    fontWeight: '500',
  },
  continueButton: {
    width: '100%',
    backgroundColor: '#00D2B4',
    paddingVertical: 16,
    borderRadius: 12,
    alignItems: 'center',
    shadowColor: '#00D2B4',
    shadowOffset: { width: 0, height: 4 },
    shadowOpacity: 0.25,
    shadowRadius: 8,
    elevation: 4,
  },
  continueButtonDisabled: {
    backgroundColor: '#262626',
    shadowOpacity: 0,
    elevation: 0,
  },
  continueButtonText: {
    color: '#000000',
    fontSize: 16,
    fontWeight: 'bold',
  },
  continueButtonTextDisabled: {
    color: '#555555',
  },
});
