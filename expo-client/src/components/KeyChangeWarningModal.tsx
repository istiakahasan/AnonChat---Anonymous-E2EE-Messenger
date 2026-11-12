import React from 'react';
import {
  Modal,
  View,
  Text,
  StyleSheet,
  TouchableOpacity,
  ScrollView,
} from 'react-native';
import { KeyChangeAlert } from '../types/signal';

interface Props {
  alert: KeyChangeAlert | null;
  onApprove: () => void;
  onReject: () => void;
}

export const KeyChangeWarningModal: React.FC<Props> = ({
  alert,
  onApprove,
  onReject,
}) => {
  if (!alert) return null;

  return (
    <Modal visible={true} transparent={true} animationType="fade">
      <View style={styles.overlay}>
        <View style={styles.card}>
          <Text style={styles.icon}>⚠️</Text>
          <Text style={styles.title}>Security Code Changed</Text>

          <Text style={styles.description}>
            The identity key for{' '}
            <Text style={styles.bold}>{alert.contactName}</Text> has changed.
            This could indicate that they reinstalled their app, switched devices,
            or an attacker may be attempting a Man-in-the-Middle (MitM) interception.
          </Text>

          <Text style={styles.warningNote}>
            All outbound messages to this contact are currently BLOCKED to protect your privacy.
          </Text>

          <View style={styles.fingerprintBox}>
            <Text style={styles.label}>Previous Trusted Safety Code:</Text>
            <Text style={styles.codeText}>{alert.previousKeyFingerprint}</Text>

            <View style={styles.divider} />

            <Text style={styles.label}>New Safety Code Received:</Text>
            <Text style={[styles.codeText, styles.highlightCode]}>
              {alert.newKeyFingerprint}
            </Text>
          </View>

          <View style={styles.actions}>
            <TouchableOpacity
              style={[styles.button, styles.rejectButton]}
              onPress={onReject}
            >
              <Text style={styles.rejectText}>Block & Abort</Text>
            </TouchableOpacity>

            <TouchableOpacity
              style={[styles.button, styles.approveButton]}
              onPress={onApprove}
            >
              <Text style={styles.approveText}>Trust New Key</Text>
            </TouchableOpacity>
          </View>
        </View>
      </View>
    </Modal>
  );
};

const styles = StyleSheet.create({
  overlay: {
    flex: 1,
    backgroundColor: 'rgba(0, 0, 0, 0.85)',
    justifyContent: 'center',
    alignItems: 'center',
    padding: 20,
  },
  card: {
    backgroundColor: '#1E1E1E',
    borderRadius: 16,
    padding: 24,
    width: '100%',
    maxWidth: 420,
    borderWidth: 1,
    borderColor: '#E65100',
  },
  icon: {
    fontSize: 40,
    textAlign: 'center',
    marginBottom: 8,
  },
  title: {
    color: '#FF9800',
    fontSize: 20,
    fontWeight: 'bold',
    textAlign: 'center',
    marginBottom: 12,
  },
  description: {
    color: '#CCCCCC',
    fontSize: 14,
    lineHeight: 20,
    textAlign: 'center',
    marginBottom: 12,
  },
  bold: {
    fontWeight: 'bold',
    color: '#FFFFFF',
  },
  warningNote: {
    color: '#FF5252',
    fontSize: 12,
    fontWeight: '600',
    textAlign: 'center',
    marginBottom: 16,
  },
  fingerprintBox: {
    backgroundColor: '#121212',
    padding: 12,
    borderRadius: 8,
    marginBottom: 20,
  },
  label: {
    color: '#888888',
    fontSize: 11,
    marginBottom: 4,
    textTransform: 'uppercase',
  },
  codeText: {
    color: '#AAAAAA',
    fontFamily: 'monospace',
    fontSize: 12,
  },
  highlightCode: {
    color: '#FFB74D',
    fontWeight: 'bold',
  },
  divider: {
    height: 1,
    backgroundColor: '#2A2A2A',
    marginVertical: 10,
  },
  actions: {
    flexDirection: 'row',
    gap: 12,
  },
  button: {
    flex: 1,
    paddingVertical: 12,
    borderRadius: 8,
    alignItems: 'center',
  },
  rejectButton: {
    backgroundColor: '#2C2C2C',
    borderWidth: 1,
    borderColor: '#444444',
  },
  rejectText: {
    color: '#FFFFFF',
    fontWeight: 'bold',
  },
  approveButton: {
    backgroundColor: '#E65100',
  },
  approveText: {
    color: '#FFFFFF',
    fontWeight: 'bold',
  },
});

