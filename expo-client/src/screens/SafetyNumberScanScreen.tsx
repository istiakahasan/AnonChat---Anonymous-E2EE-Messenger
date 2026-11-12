import React, { useState } from 'react';
import {
  View,
  Text,
  StyleSheet,
  TouchableOpacity,
  Alert,
  SafeAreaView,
  Dimensions,
} from 'react-native';
import { CameraView, useCameraPermissions } from 'expo-camera';
import { SafetyNumberService } from '../crypto/safetyNumber';

interface Props {
  contactName: string;
  contactId: string;
  expectedSafetyNumber: string; // 60-digit safety number
  onVerified: () => void;
  onSwitchToDisplayQr: () => void;
  onClose: () => void;
  onMismatch?: (scanned: string) => void;
}

const { width } = Dimensions.get('window');
const SCAN_TARGET_SIZE = width * 0.7;

export const SafetyNumberScanScreen: React.FC<Props> = ({
  contactName,
  contactId,
  expectedSafetyNumber,
  onVerified,
  onSwitchToDisplayQr,
  onClose,
  onMismatch,
}) => {
  const [permission, requestPermission] = useCameraPermissions();
  const [scanned, setScanned] = useState(false);
  const [verificationResult, setVerificationResult] = useState<'success' | 'mismatch' | null>(null);

  if (!permission) {
    return <View style={styles.container} />;
  }

  if (!permission.granted) {
    return (
      <SafeAreaView style={styles.container}>
        <View style={styles.permissionBox}>
          <Text style={styles.permissionTitle}>Camera Access Required</Text>
          <Text style={styles.permissionText}>
            AnonChat needs camera access to scan and verify {contactName}&apos;s Safety Number QR code.
          </Text>
          <TouchableOpacity style={styles.grantButton} onPress={requestPermission}>
            <Text style={styles.grantButtonText}>Grant Camera Permission</Text>
          </TouchableOpacity>
          <TouchableOpacity style={styles.cancelButton} onPress={onClose}>
            <Text style={styles.cancelButtonText}>Cancel</Text>
          </TouchableOpacity>
        </View>
      </SafeAreaView>
    );
  }

  const handleBarcodeScanned = async ({ data }: { data: string }) => {
    if (scanned) return;
    setScanned(true);

    // Normalize strings by removing all whitespace
    const cleanScanned = data.replace(/\s+/g, '').trim();
    const cleanExpected = expectedSafetyNumber.replace(/\s+/g, '').trim();

    if (cleanScanned === cleanExpected && cleanScanned.length === 60) {
      // 1. MATCH: Authenticated
      setVerificationResult('success');
      await SafetyNumberService.markContactVerified(contactId);

      Alert.alert(
        '✓ Safety Number Verified',
        `The safety code matches ${contactName}'s identity key. Communication is authenticated and trusted.`,
        [
          {
            text: 'OK',
            onPress: () => {
              onVerified();
              onClose();
            },
          },
        ]
      );
    } else {
      // 2. MISMATCH: Critical Security Alert
      setVerificationResult('mismatch');
      if (onMismatch) {
        onMismatch(data);
      }

      Alert.alert(
        '⚠️ Safety Number Mismatch!',
        `The QR code scanned from ${contactName}'s phone does NOT match the safety number computed by your device.\n\n` +
          `Expected: ${expectedSafetyNumber}\n` +
          `Scanned:  ${data}\n\n` +
          `This could indicate an active Man-in-the-Middle attack or a different contact. Transmission remains BLOCKED.`,
        [
          {
            text: 'View Mismatch in Chat',
            style: 'destructive',
            onPress: () => {
              onClose();
            },
          },
          {
            text: 'Scan Again',
            onPress: () => {
              setScanned(false);
              setVerificationResult(null);
            },
          },
        ]
      );
    }
  };

  return (
    <SafeAreaView style={styles.container}>
      {/* Header */}
      <View style={styles.header}>
        <TouchableOpacity onPress={onClose} style={styles.headerButton}>
          <Text style={styles.headerButtonText}>✕</Text>
        </TouchableOpacity>
        <Text style={styles.headerTitle}>Scan {contactName}&apos;s Code</Text>
        <TouchableOpacity onPress={onSwitchToDisplayQr} style={styles.headerButton}>
          <Text style={styles.headerButtonAction}>Show QR</Text>
        </TouchableOpacity>
      </View>

      {/* Camera Scanner View */}
      <View style={styles.cameraWrapper}>
        <CameraView
          style={StyleSheet.absoluteFillObject}
          facing="back"
          onBarcodeScanned={scanned ? undefined : handleBarcodeScanned}
          barcodeScannerSettings={{
            barcodeTypes: ['qr'],
          }}
        />

        {/* Reticle / Target Box */}
        <View style={styles.overlay}>
          <View
            style={[
              styles.targetBox,
              verificationResult === 'success' && styles.targetSuccess,
              verificationResult === 'mismatch' && styles.targetMismatch,
            ]}
          >
            <View style={[styles.corner, styles.cornerTL]} />
            <View style={[styles.corner, styles.cornerTR]} />
            <View style={[styles.corner, styles.cornerBL]} />
            <View style={[styles.corner, styles.cornerBR]} />
          </View>
        </View>
      </View>

      {/* Instructions Footer */}
      <View style={styles.footer}>
        <Text style={styles.instructionText}>
          Point your camera at the QR code displayed on {contactName}&apos;s device to verify safety codes.
        </Text>
        <TouchableOpacity style={styles.switchButton} onPress={onSwitchToDisplayQr}>
          <Text style={styles.switchButtonText}>Display My QR Code Instead</Text>
        </TouchableOpacity>
      </View>
    </SafeAreaView>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#000000',
  },
  header: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    paddingHorizontal: 16,
    paddingVertical: 12,
    backgroundColor: 'rgba(0, 0, 0, 0.7)',
    zIndex: 10,
  },
  headerButton: {
    padding: 8,
  },
  headerButtonText: {
    color: '#FFFFFF',
    fontSize: 20,
    fontWeight: 'bold',
  },
  headerButtonAction: {
    color: '#00D2B4',
    fontSize: 14,
    fontWeight: 'bold',
  },
  headerTitle: {
    color: '#FFFFFF',
    fontSize: 16,
    fontWeight: 'bold',
  },
  cameraWrapper: {
    flex: 1,
    position: 'relative',
    justifyContent: 'center',
    alignItems: 'center',
  },
  overlay: {
    ...StyleSheet.absoluteFillObject,
    justifyContent: 'center',
    alignItems: 'center',
  },
  targetBox: {
    width: SCAN_TARGET_SIZE,
    height: SCAN_TARGET_SIZE,
    borderWidth: 2,
    borderColor: 'rgba(255, 255, 255, 0.6)',
    borderRadius: 16,
    position: 'relative',
  },
  targetSuccess: {
    borderColor: '#00D2B4',
    backgroundColor: 'rgba(0, 210, 180, 0.1)',
  },
  targetMismatch: {
    borderColor: '#FF5252',
    backgroundColor: 'rgba(255, 82, 82, 0.15)',
  },
  corner: {
    position: 'absolute',
    width: 24,
    height: 24,
    borderColor: '#00D2B4',
  },
  cornerTL: { top: -2, left: -2, borderTopWidth: 4, borderLeftWidth: 4 },
  cornerTR: { top: -2, right: -2, borderTopWidth: 4, borderRightWidth: 4 },
  cornerBL: { bottom: -2, left: -2, borderBottomWidth: 4, borderLeftWidth: 4 },
  cornerBR: { bottom: -2, right: -2, borderBottomWidth: 4, borderRightWidth: 4 },
  footer: {
    padding: 24,
    backgroundColor: 'rgba(0, 0, 0, 0.85)',
    alignItems: 'center',
  },
  instructionText: {
    color: '#CCCCCC',
    fontSize: 14,
    textAlign: 'center',
    lineHeight: 20,
    marginBottom: 16,
  },
  switchButton: {
    backgroundColor: '#1E1E1E',
    borderWidth: 1,
    borderColor: '#00D2B4',
    paddingVertical: 12,
    paddingHorizontal: 20,
    borderRadius: 8,
  },
  switchButtonText: {
    color: '#00D2B4',
    fontWeight: 'bold',
    fontSize: 14,
  },
  permissionBox: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
    padding: 32,
  },
  permissionTitle: {
    color: '#FFFFFF',
    fontSize: 20,
    fontWeight: 'bold',
    marginBottom: 12,
  },
  permissionText: {
    color: '#AAAAAA',
    fontSize: 14,
    textAlign: 'center',
    marginBottom: 24,
    lineHeight: 20,
  },
  grantButton: {
    backgroundColor: '#00D2B4',
    paddingVertical: 14,
    paddingHorizontal: 24,
    borderRadius: 8,
    marginBottom: 12,
  },
  grantButtonText: {
    color: '#000000',
    fontWeight: 'bold',
    fontSize: 15,
  },
  cancelButton: {
    padding: 10,
  },
  cancelButtonText: {
    color: '#888888',
    fontSize: 14,
  },
});
