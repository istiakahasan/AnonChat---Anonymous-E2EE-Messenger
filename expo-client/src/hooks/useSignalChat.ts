/**
 * React Hook: useSignalChat
 * Provides stateful messaging, encryption/decryption, and Key-Change Alert UI bindings.
 */

import { useState, useEffect, useCallback } from 'react';
import { SignalService, KeyChangeException } from '../crypto/signalService';
import { ServerPublicBundle, KeyChangeAlert, SignalAddress } from '../types/signal';

export function useSignalChat() {
  const [isInitialized, setIsInitialized] = useState(false);
  const [publicBundle, setPublicBundle] = useState<ServerPublicBundle | null>(null);
  const [keyChangeAlert, setKeyChangeAlert] = useState<KeyChangeAlert | null>(null);
  const [pendingRecipientBundle, setPendingRecipientBundle] = useState<{
    address: SignalAddress;
    bundle: any;
  } | null>(null);

  const signalService = SignalService.getInstance();

  useEffect(() => {
    async function init() {
      try {
        const bundle = await signalService.ensureInitialized();
        setPublicBundle(bundle);
        setIsInitialized(true);
      } catch (err) {
        console.error('Failed to initialize Signal protocol:', err);
      }
    }
    init();
  }, []);

  /**
   * Establishes a session with a contact.
   * If a key change is detected, intercepts and sets keyChangeAlert, blocking sending.
   */
  const connectContact = useCallback(
    async (contactName: string, recipientBundle: any): Promise<boolean> => {
      const address: SignalAddress = { name: contactName, deviceId: 1 };
      try {
        await signalService.establishSession(address, recipientBundle);
        return true;
      } catch (err: any) {
        if (err instanceof KeyChangeException) {
          // Block session and trigger UI warning
          setKeyChangeAlert(err.alert);
          setPendingRecipientBundle({ address, bundle: recipientBundle });
          return false;
        }
        throw err;
      }
    },
    [signalService]
  );

  /**
   * Sends an end-to-end encrypted message.
   */
  const sendEncryptedMessage = useCallback(
    async (contactName: string, messageText: string, recipientBundle?: any): Promise<any> => {
      const address: SignalAddress = { name: contactName, deviceId: 1 };

      // Ensure session is established
      if (recipientBundle) {
        const connected = await connectContact(contactName, recipientBundle);
        if (!connected) {
          throw new Error('Message blocked due to security code / key change alert.');
        }
      }

      // Encrypt message
      const ciphertext = await signalService.encryptMessage(address, messageText);
      return ciphertext;
    },
    [signalService, connectContact]
  );

  /**
   * Decrypts an incoming message.
   */
  const decryptReceivedMessage = useCallback(
    async (senderName: string, ciphertext: any): Promise<string> => {
      const address: SignalAddress = { name: senderName, deviceId: 1 };
      return await signalService.decryptMessage(address, ciphertext);
    },
    [signalService]
  );

  /**
   * User explicitly approves a contact's changed identity key after reviewing Safety Number.
   */
  const approveKeyChange = useCallback(async () => {
    if (!keyChangeAlert || !pendingRecipientBundle) return;

    const newKey =
      pendingRecipientBundle.bundle.identityKey ||
      pendingRecipientBundle.bundle.identityPublicKey;

    await signalService.approveContactKeyChange(keyChangeAlert.contactName, newKey);
    // Re-establish session now that key is trusted
    await signalService.establishSession(
      pendingRecipientBundle.address,
      pendingRecipientBundle.bundle
    );

    setKeyChangeAlert(null);
    setPendingRecipientBundle(null);
  }, [keyChangeAlert, pendingRecipientBundle, signalService]);

  /**
   * User blocks or rejects a contact's key change (potential MitM attack).
   */
  const rejectKeyChange = useCallback(() => {
    setKeyChangeAlert(null);
    setPendingRecipientBundle(null);
  }, []);

  return {
    isInitialized,
    publicBundle,
    keyChangeAlert,
    connectContact,
    sendEncryptedMessage,
    decryptReceivedMessage,
    approveKeyChange,
    rejectKeyChange,
  };
}

