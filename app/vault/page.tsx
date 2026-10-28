'use client';

import React, { useState, useEffect, useRef, useCallback } from 'react';
import {
  Lock,
  ClipboardCheck,
  X,
  KeyRound,
  Copy,
  Check,
  ShieldCheck,
} from 'lucide-react';
import {
  type ActiveVaultKeyring,
  type DecryptedVaultItem,
  type DecryptedVaultItemPayload,
  type VaultRecordType,
  decryptVaultItem,
  deriveSyncAuthToken,
  encryptVaultItem,
  rotateRecoveryKey,
  unlockVaultWithMasterPassword,
  unlockVaultWithRecoveryKey,
  verifyRecoveryKeyCryptographically,
  zeroizeKeyring,
} from '@/lib/crypto/vault-crypto';
import {
  createEncryptedBackupContainer,
  verifyBackupContainerIntegrity,
} from '@/lib/crypto/backup-engine';
import {
  loadEncryptedVaultStore,
  provisionNewEncryptedVault,
  saveEncryptedVaultStore,
  type PersistedEncryptedVaultStore,
} from '@/lib/storage/vault-storage';
import LockScreen from '@/components/vault/LockScreen';
import VaultWorkspace from '@/components/vault/VaultWorkspace';
import GeneratorView from '@/components/vault/GeneratorView';
import SecurityCenterView from '@/components/vault/SecurityCenterView';
import SettingsRecoverySyncView from '@/components/vault/SettingsRecoverySyncView';
import CsvImportModal from '@/components/vault/CsvImportModal';
import PrivacyShieldView from '@/components/vault/PrivacyShieldView';
import {
  type CsvImportAnalysisSession,
  type CsvImportExecutionReport,
  type DuplicateHandlingPolicy,
  clearCsvImportSessionBuffer,
  encryptAndImportCsvBatch,
} from '@/lib/import/csv-migration';
import {
  type RedactedSecurityEvent,
  type ScreenExposureState,
  buildScreenExposureDiagnosticsSnapshot,
  canRenderSensitiveContent,
  detectBrowserDisplaySignals,
  executeEmergencyExposureMitigation,
  getRedactedSecurityEvents,
  recordRedactedSecurityEvent,
  verifyPreRenderSecretRevealGate,
} from '@/lib/security/screen-exposure-engine';
import { signInWithPopup, signOut } from 'firebase/auth';
import { auth, googleAuthProvider } from '../../src/lib/firebase';

type ActiveTab = 'vault' | 'generator' | 'security' | 'settings';

export default function BlacktowerVaultApp() {
  const [store, setStore] = useState<PersistedEncryptedVaultStore | null>(null);
  const [isLoaded, setIsLoaded] = useState(false);
  const [isUnlocked, setIsUnlocked] = useState(false);
  const [activeTab, setActiveTab] = useState<ActiveTab>('vault');
  const [decryptedItems, setDecryptedItems] = useState<DecryptedVaultItem[]>([]);
  const [lastLockedReason, setLastLockedReason] = useState<string | null>(null);
  const [isCsvImportOpen, setIsCsvImportOpen] = useState(false);

  // Screen Exposure Protection State Machine (Sections 1, 6, 7, 14, 15, 16)
  const [screenExposureState, setScreenExposureState] =
    useState<ScreenExposureState>('VAULT_LOCKED');
  const [redactedEvents, setRedactedEvents] = useState<RedactedSecurityEvent[]>([]);

  // Sensitive keyring held in volatile ref so it can be zeroized immediately on lock or exposure
  const keyringRef = useRef<ActiveVaultKeyring | null>(null);
  const syncTokenRef = useRef<string | null>(null);
  const firebaseIdTokenRef = useRef<string | null>(null);
  const [cloudAuthEmail, setCloudAuthEmail] = useState<string | null>(null);
  const activeCsvSessionRef = useRef<CsvImportAnalysisSession | null>(null);

  // Explicit Recovery Key Creation / Replacement Flow Modal (Phase 6)
  const [explicitRecoveryKeyModal, setExplicitRecoveryKeyModal] = useState<string | null>(null);
  const [copiedRecoveryModal, setCopiedRecoveryModal] = useState(false);

  // Timed Clipboard Protection State (Phase 1 & Rule 6)
  const [clipboardGuard, setClipboardGuard] = useState<{
    label: string;
    secondsRemaining: number;
  } | null>(null);

  // Decrypt all stored envelopes using active keyring
  const decryptAllStoreItems = useCallback(
    async (keyring: ActiveVaultKeyring, targetStore: PersistedEncryptedVaultStore) => {
      const out: DecryptedVaultItem[] = [];
      for (const env of targetStore.items) {
        const dec = await decryptVaultItem(keyring, env);
        out.push(dec);
      }
      setDecryptedItems(out);
    },
    []
  );

  // Lock Vault & Zeroize Memory (Phase 4 & Rule 18)
  const lockVault = useCallback((reason: string = 'Manual lock') => {
    if (keyringRef.current) {
      zeroizeKeyring(keyringRef.current);
      keyringRef.current = null;
    }
    if (activeCsvSessionRef.current) {
      clearCsvImportSessionBuffer(activeCsvSessionRef.current);
      activeCsvSessionRef.current = null;
    }
    syncTokenRef.current = null;
    setDecryptedItems([]);
    setIsUnlocked(false);
    setScreenExposureState('VAULT_LOCKED');
    setIsCsvImportOpen(false);
    setClipboardGuard(null);
    setExplicitRecoveryKeyModal(null);
    setLastLockedReason(reason);
  }, []);

  // Emergency Exposure Mitigation Handler (Sections 6, 7, 11, 14)
  const triggerExposureProtection = useCallback(
    (detectedRiskState: Exclude<ScreenExposureState, 'PRIVATE_SAFE'>) => {
      const extremeEnabled = store?.settings.extremeScreenProtection ?? true;
      executeEmergencyExposureMitigation({
        detectedRiskState,
        extremeModeEnabled: extremeEnabled,
        activeKeyring: keyringRef.current,
        activeCsvSession: activeCsvSessionRef.current,
      });
      if (extremeEnabled && keyringRef.current) {
        keyringRef.current = null;
        syncTokenRef.current = null;
        setDecryptedItems([]);
      }
      activeCsvSessionRef.current = null;
      setIsCsvImportOpen(false);
      setClipboardGuard(null);
      setExplicitRecoveryKeyModal(null);
      setScreenExposureState(detectedRiskState);
      setRedactedEvents(getRedactedSecurityEvents());
    },
    [store]
  );

  // Pre-Render Secret Reveal Gate (Sections 8, 9, 15)
  const handleVerifySafeBeforeSecretReveal = useCallback((): boolean => {
    const signals = detectBrowserDisplaySignals();
    const check = verifyPreRenderSecretRevealGate({
      extremeModeEnabled: store?.settings.extremeScreenProtection ?? true,
      lockOnBackgroundEnabled: store?.settings.lockOnBackgroundHide ?? true,
      isVaultUnlocked: isUnlocked,
      documentVisibility: signals.documentVisibility,
      windowFocused: signals.windowFocused,
      screenIsExtended: signals.screenIsExtended,
      simulatedExposureState:
        screenExposureState !== 'PRIVATE_SAFE' ? screenExposureState : null,
    });
    if (!check.allowed) {
      setRedactedEvents(getRedactedSecurityEvents());
      if (check.state !== 'PRIVATE_SAFE') {
        triggerExposureProtection(check.state);
      }
      return false;
    }
    return true;
  }, [isUnlocked, screenExposureState, store, triggerExposureProtection]);

  // Initial load + ?autostart=1 support
  useEffect(() => {
    let active = true;
    (async () => {
      const existing = loadEncryptedVaultStore();
      if (!active) return;
      if (existing) {
        setStore(existing);
      }
      setIsLoaded(true);

      if (typeof window !== 'undefined') {
        const params = new URLSearchParams(window.location.search);
        const tabParam = params.get('tab');
        if (
          tabParam === 'vault' ||
          tabParam === 'generator' ||
          tabParam === 'security' ||
          tabParam === 'settings'
        ) {
          setActiveTab(tabParam);
        }
        if (params.get('autostart') === '1') {
          const defaultPass = 'Blacktower!Master#2026';
          if (existing) {
            try {
              const kr = await unlockVaultWithMasterPassword(defaultPass, existing.hierarchy);
              if (!active) return;
              keyringRef.current = kr;
              syncTokenRef.current = deriveSyncAuthToken(
                defaultPass,
                existing.hierarchy.accountId,
                existing.hierarchy.kdfSaltHex
              );
              await decryptAllStoreItems(kr, existing);
              setScreenExposureState('PRIVATE_SAFE');
              setIsUnlocked(true);
              return;
            } catch {
              // If existing vault had a different password, provision fresh for autostart
            }
          }
          const created = await provisionNewEncryptedVault({
            masterPassword: defaultPass,
            includeSampleItems: true,
          });
          if (!active) return;
          created.store.settings.recoveryKeyVerifiedAt = new Date().toISOString();
          saveEncryptedVaultStore(created.store);
          keyringRef.current = created.keyring;
          syncTokenRef.current = deriveSyncAuthToken(
            defaultPass,
            created.store.hierarchy.accountId,
            created.store.hierarchy.kdfSaltHex
          );
          setStore(created.store);
          await decryptAllStoreItems(created.keyring, created.store);
          setScreenExposureState('PRIVATE_SAFE');
          setIsUnlocked(true);
        }
      }
    })();
    return () => {
      active = false;
    };
  }, [decryptAllStoreItems]);

  // Inactivity Auto-Lock, Background Lock & Display Exposure Observer (Phase 4 & Sections 3-6, 10)
  useEffect(() => {
    if (!isUnlocked || !store) return;

    const timeoutMs = (store.settings.autoLockTimeoutSeconds || 300) * 1000;
    let timerId = window.setTimeout(() => {
      lockVault('Inactivity timeout');
    }, timeoutMs);

    const resetTimer = () => {
      window.clearTimeout(timerId);
      timerId = window.setTimeout(() => {
        lockVault('Inactivity timeout');
      }, timeoutMs);
    };

    const handleVisibilityChange = () => {
      if (document.visibilityState === 'hidden') {
        if (store.settings.extremeScreenProtection || store.settings.lockOnBackgroundHide) {
          recordRedactedSecurityEvent({
            eventCode: 'VAULT_AUTO_LOCKED',
            resultingState: 'VAULT_LOCKED',
            extremeModeActive: store.settings.extremeScreenProtection ?? true,
          });
          setRedactedEvents(getRedactedSecurityEvents());
          lockVault('Background visibility lock (Recents & Background Protection)');
        } else {
          triggerExposureProtection('PROTECTED_HIDDEN');
        }
      }
    };

    const handleScreenChange = () => {
      const signals = detectBrowserDisplaySignals();
      if (signals.screenIsExtended === true) {
        triggerExposureProtection('EXTERNAL_DISPLAY_DETECTED');
      }
    };

    window.addEventListener('pointerdown', resetTimer);
    window.addEventListener('keydown', resetTimer);
    document.addEventListener('visibilitychange', handleVisibilityChange);
    const screenObj = window.screen as Screen & {
      addEventListener?: (type: string, listener: () => void) => void;
      removeEventListener?: (type: string, listener: () => void) => void;
    };
    screenObj.addEventListener?.('change', handleScreenChange);

    return () => {
      window.clearTimeout(timerId);
      window.removeEventListener('pointerdown', resetTimer);
      window.removeEventListener('keydown', resetTimer);
      document.removeEventListener('visibilitychange', handleVisibilityChange);
      screenObj.removeEventListener?.('change', handleScreenChange);
    };
  }, [isUnlocked, store, lockVault, triggerExposureProtection]);

  // Clipboard Countdown Timer (Rule 6)
  useEffect(() => {
    if (!clipboardGuard) return;
    const timer = window.setTimeout(() => {
      setClipboardGuard((prev) => {
        if (!prev) return null;
        if (prev.secondsRemaining <= 1) {
          if (typeof navigator !== 'undefined' && navigator.clipboard?.writeText) {
            navigator.clipboard.writeText('').catch(() => {});
          }
          return null;
        }
        return { ...prev, secondsRemaining: prev.secondsRemaining - 1 };
      });
    }, 1000);
    return () => window.clearTimeout(timer);
  }, [clipboardGuard]);

  const handleCopySecretWithGuard = useCallback(
    (label: string, secretValue: string) => {
      if (typeof navigator !== 'undefined' && navigator.clipboard?.writeText) {
        navigator.clipboard.writeText(secretValue).catch(() => {});
      }
      const timeoutSec = store?.settings.clipboardClearSeconds || 20;
      setClipboardGuard({
        label,
        secondsRemaining: timeoutSec,
      });
    },
    [store]
  );

  const handleClearClipboardNow = () => {
    if (typeof navigator !== 'undefined' && navigator.clipboard?.writeText) {
      navigator.clipboard.writeText('').catch(() => {});
    }
    setClipboardGuard(null);
  };

  // Unlock Handlers
  const handleCreateNewVault = async (masterPassword: string, includeSampleItems: boolean) => {
    const created = await provisionNewEncryptedVault({
      masterPassword,
      includeSampleItems,
    });
    keyringRef.current = created.keyring;
    syncTokenRef.current = deriveSyncAuthToken(
      masterPassword,
      created.store.hierarchy.accountId,
      created.store.hierarchy.kdfSaltHex
    );
    setStore(created.store);
    await decryptAllStoreItems(created.keyring, created.store);
    setScreenExposureState('PRIVATE_SAFE');
    setIsUnlocked(true);
    setLastLockedReason(null);
    setExplicitRecoveryKeyModal(created.formattedRecoveryKey);
  };

  const handleUnlockWithPassword = async (masterPassword: string) => {
    if (!store) throw new Error('No encrypted vault found.');
    const kr = await unlockVaultWithMasterPassword(masterPassword, store.hierarchy);
    keyringRef.current = kr;
    syncTokenRef.current = deriveSyncAuthToken(
      masterPassword,
      store.hierarchy.accountId,
      store.hierarchy.kdfSaltHex
    );
    await decryptAllStoreItems(kr, store);
    setScreenExposureState('PRIVATE_SAFE');
    setIsUnlocked(true);
    setLastLockedReason(null);
  };

  const handleUnlockWithRecoveryKey = async (recoveryKey: string) => {
    if (!store) throw new Error('No encrypted vault found.');
    const kr = await unlockVaultWithRecoveryKey(recoveryKey, store.hierarchy);
    keyringRef.current = kr;
    syncTokenRef.current = deriveSyncAuthToken(
      recoveryKey,
      store.hierarchy.accountId,
      store.hierarchy.kdfSaltHex
    );
    const updatedStore: PersistedEncryptedVaultStore = {
      ...store,
      settings: {
        ...store.settings,
        recoveryKeyVerifiedAt: new Date().toISOString(),
      },
    };
    saveEncryptedVaultStore(updatedStore);
    setStore(updatedStore);
    await decryptAllStoreItems(kr, updatedStore);
    setScreenExposureState('PRIVATE_SAFE');
    setIsUnlocked(true);
    setLastLockedReason(null);
  };

  // Vault Item CRUD Operations
  const handleAddOrUpdateItem = async (params: {
    itemId?: string;
    recordType: VaultRecordType;
    favorite: boolean;
    payload: DecryptedVaultItemPayload;
  }) => {
    if (!keyringRef.current || !store) throw new Error('Vault is locked');
    const existingEnvelope = params.itemId
      ? store.items.find((i) => i.itemId === params.itemId)
      : undefined;
    const nextRevision = existingEnvelope ? existingEnvelope.revision + 1 : 1;

    const newEnvelope = await encryptVaultItem({
      keyring: keyringRef.current,
      itemId: params.itemId,
      revision: nextRevision,
      recordType: params.recordType,
      favorite: params.favorite,
      createdAt: existingEnvelope?.createdAt,
      payload: params.payload,
    });

    const nextItems = existingEnvelope
      ? store.items.map((i) => (i.itemId === params.itemId ? newEnvelope : i))
      : [newEnvelope, ...store.items];

    const updatedStore: PersistedEncryptedVaultStore = {
      ...store,
      items: nextItems,
    };
    saveEncryptedVaultStore(updatedStore);
    setStore(updatedStore);
    await decryptAllStoreItems(keyringRef.current, updatedStore);
  };

  const handleDeleteItem = async (itemId: string) => {
    if (!keyringRef.current || !store) return;
    const nextItems = store.items.filter((i) => i.itemId !== itemId);
    const updatedStore: PersistedEncryptedVaultStore = {
      ...store,
      items: nextItems,
    };
    saveEncryptedVaultStore(updatedStore);
    setStore(updatedStore);
    await decryptAllStoreItems(keyringRef.current, updatedStore);
  };

  const handleToggleFavorite = async (item: DecryptedVaultItem) => {
    await handleAddOrUpdateItem({
      itemId: item.itemId,
      recordType: item.recordType,
      favorite: !item.favorite,
      payload: item.data,
    });
  };

  const handleSaveGeneratedPasswordAsItem = async (generatedPassword: string) => {
    await handleAddOrUpdateItem({
      recordType: 'password',
      favorite: false,
      payload: {
        title: `Generated Credential (${new Date().toLocaleTimeString()})`,
        subtitle: 'Created via CSPRNG Generator',
        folder: 'Generated',
        username: 'user@blacktower.vault',
        password: generatedPassword,
      },
    });
    setActiveTab('vault');
  };

  // CSV Migration / Import Handler
  const handleExecuteCsvImport = async (
    session: CsvImportAnalysisSession,
    duplicatePolicy: DuplicateHandlingPolicy
  ): Promise<CsvImportExecutionReport> => {
    if (!keyringRef.current || !store) {
      throw new Error('Vault is locked.');
    }
    const report = await encryptAndImportCsvBatch({
      keyring: keyringRef.current,
      session,
      duplicatePolicy,
    });
    if (report.encryptedEnvelopes.length > 0) {
      const updatedStore: PersistedEncryptedVaultStore = {
        ...store,
        items: [...report.encryptedEnvelopes, ...store.items],
      };
      saveEncryptedVaultStore(updatedStore);
      setStore(updatedStore);
      await decryptAllStoreItems(keyringRef.current, updatedStore);
    }
    return report;
  };

  // Settings, Recovery, Backup & Sync Handlers
  const handleUpdateSettings = (partial: Partial<PersistedEncryptedVaultStore['settings']>) => {
    if (!store) return;
    const updatedStore: PersistedEncryptedVaultStore = {
      ...store,
      settings: {
        ...store.settings,
        ...partial,
      },
    };
    saveEncryptedVaultStore(updatedStore);
    setStore(updatedStore);
  };

  const handleVerifyRecoveryKey = async (inputKey: string): Promise<boolean> => {
    if (!store) return false;
    const valid = await verifyRecoveryKeyCryptographically(inputKey, store.hierarchy);
    if (valid) {
      handleUpdateSettings({ recoveryKeyVerifiedAt: new Date().toISOString() });
    }
    return valid;
  };

  const handleRotateRecoveryKey = async () => {
    if (!keyringRef.current || !store) return;
    const { updatedHierarchy, newFormattedRecoveryKey } = await rotateRecoveryKey(
      keyringRef.current,
      store.hierarchy
    );
    const updatedStore: PersistedEncryptedVaultStore = {
      ...store,
      hierarchy: updatedHierarchy,
      settings: {
        ...store.settings,
        recoveryKeyVerifiedAt: new Date().toISOString(),
      },
    };
    saveEncryptedVaultStore(updatedStore);
    setStore(updatedStore);
    setExplicitRecoveryKeyModal(newFormattedRecoveryKey);
  };

  const handleExportBackup = (): string => {
    if (!keyringRef.current || !store) throw new Error('Vault is locked');
    const container = createEncryptedBackupContainer({
      keyring: keyringRef.current,
      hierarchy: store.hierarchy,
      items: store.items,
    });
    handleUpdateSettings({ lastBackupExportedAt: container.exportedAt });
    return JSON.stringify(container, null, 2);
  };

  const handleRestoreBackup = async (rawJson: string) => {
    if (!keyringRef.current || !store) throw new Error('Vault is locked');
    const { container } = verifyBackupContainerIntegrity(rawJson, keyringRef.current);
    const updatedStore: PersistedEncryptedVaultStore = {
      ...store,
      hierarchy: container.hierarchy,
      items: container.items,
    };
    saveEncryptedVaultStore(updatedStore);
    setStore(updatedStore);
    await decryptAllStoreItems(keyringRef.current, updatedStore);
  };

  const handleSignInWithGoogle = async () => {
    const cred = await signInWithPopup(auth, googleAuthProvider);
    const idToken = await cred.user.getIdToken();
    firebaseIdTokenRef.current = idToken;
    setCloudAuthEmail(cred.user.email || cred.user.uid);
  };

  const handleSignOutCloudSync = async () => {
    await signOut(auth);
    firebaseIdTokenRef.current = null;
    setCloudAuthEmail(null);
  };

  const getSyncHeaders = (): Record<string, string> => {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (firebaseIdTokenRef.current) {
      headers.Authorization = `Bearer ${firebaseIdTokenRef.current}`;
    }
    return headers;
  };

  const handleSyncPush = async () => {
    if (!store || !syncTokenRef.current) throw new Error('Sync session not initialized');
    const res = await fetch('/api/sync', {
      method: 'POST',
      headers: getSyncHeaders(),
      body: JSON.stringify({
        action: 'push',
        accountId: store.hierarchy.accountId,
        vaultId: store.hierarchy.vaultId,
        deviceId: store.syncState.activeDeviceId,
        syncAuthToken: syncTokenRef.current,
        expectedRevision: store.syncState.lastSyncedRevision,
        forceOverwrite: true,
        hierarchy: store.hierarchy,
        items: store.items,
      }),
    });
    const data = await res.json();
    if (!res.ok) {
      throw new Error(data.message || data.error || 'Sync push failed');
    }
    const updatedStore: PersistedEncryptedVaultStore = {
      ...store,
      syncState: {
        ...store.syncState,
        lastSyncedRevision: data.revision,
        lastSyncTimestamp: data.syncedAt,
        remoteSyncStatus: 'synced',
      },
    };
    saveEncryptedVaultStore(updatedStore);
    setStore(updatedStore);
    return { status: data.status, revision: data.revision, syncedAt: data.syncedAt };
  };

  const handleSyncPull = async () => {
    if (!store || !syncTokenRef.current || !keyringRef.current) {
      throw new Error('Sync session not initialized');
    }
    const res = await fetch('/api/sync', {
      method: 'POST',
      headers: getSyncHeaders(),
      body: JSON.stringify({
        action: 'pull',
        accountId: store.hierarchy.accountId,
        vaultId: store.hierarchy.vaultId,
        deviceId: store.syncState.activeDeviceId,
        syncAuthToken: syncTokenRef.current,
      }),
    });
    const data = await res.json();
    if (!res.ok) {
      throw new Error(data.message || data.error || 'Sync pull failed');
    }
    if (data.status === 'NO_REMOTE_VAULT') {
      return { status: data.status, revision: 0, message: data.message };
    }
    const updatedStore: PersistedEncryptedVaultStore = {
      ...store,
      hierarchy: data.hierarchy,
      items: data.items,
      syncState: {
        ...store.syncState,
        lastSyncedRevision: data.revision,
        lastSyncTimestamp: data.updatedAt,
        remoteSyncStatus: 'synced',
      },
    };
    saveEncryptedVaultStore(updatedStore);
    setStore(updatedStore);
    await decryptAllStoreItems(keyringRef.current, updatedStore);
    return { status: data.status, revision: data.revision };
  };

  const handleRevokeDevice = async (deviceId: string) => {
    if (!store || !syncTokenRef.current) return;
    await fetch('/api/sync', {
      method: 'POST',
      headers: getSyncHeaders(),
      body: JSON.stringify({
        action: 'revoke_device',
        accountId: store.hierarchy.accountId,
        vaultId: store.hierarchy.vaultId,
        deviceId: store.syncState.activeDeviceId,
        targetRevokeDeviceId: deviceId,
        syncAuthToken: syncTokenRef.current,
      }),
    });
    const updatedStore: PersistedEncryptedVaultStore = {
      ...store,
      syncState: {
        ...store.syncState,
        devices: store.syncState.devices.map((d) =>
          d.deviceId === deviceId ? { ...d, revoked: true } : d
        ),
      },
    };
    saveEncryptedVaultStore(updatedStore);
    setStore(updatedStore);
  };

  const handleTestServerPlaintextRejection = async () => {
    const res = await fetch('/api/sync', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        action: 'push',
        accountId: store?.hierarchy.accountId || 'test_acct',
        vaultId: store?.hierarchy.vaultId || 'test_vault',
        deviceId: 'probe_device',
        syncAuthToken: 'probe_token',
        items: [
          {
            itemId: 'bad_item',
            password: 'PlaintextSecretShouldBeRejectedImmediately',
          },
        ],
      }),
    });
    const data = await res.json();
    return {
      httpStatus: res.status,
      errorCode: data.error || 'UNKNOWN',
      rejectedField: data.rejectedField || 'password',
      message: data.message || '',
    };
  };

  if (!isLoaded) {
    return (
      <div className="min-h-screen bg-[#0B0F17] text-slate-400 flex items-center justify-center text-sm font-mono">
        Initializing BLACKTOWER VAULT™ Cryptographic Engine...
      </div>
    );
  }

  if (!isUnlocked || !store) {
    return (
      <LockScreen
        hasExistingVault={Boolean(store)}
        vaultId={store?.hierarchy.vaultId}
        lastLockedReason={lastLockedReason}
        onUnlockWithPassword={handleUnlockWithPassword}
        onUnlockWithRecoveryKey={handleUnlockWithRecoveryKey}
        onCreateNewVault={handleCreateNewVault}
      />
    );
  }

  // Section 7 & 16: If state !== PRIVATE_SAFE, DO NOT render sensitive UI — replace with Privacy Shield UI
  if (!canRenderSensitiveContent(screenExposureState)) {
    const extremeEnabled = store.settings.extremeScreenProtection ?? true;
    return (
      <PrivacyShieldView
        exposureState={screenExposureState}
        extremeModeEnabled={extremeEnabled}
        onReturnToSafety={() => {
          if (extremeEnabled || !keyringRef.current) {
            // Section 6.7 & 14: Require re-authentication when returning to a trusted/private display
            lockVault(
              'Extreme Screen Protection: Re-authentication required after screen exposure'
            );
          } else {
            recordRedactedSecurityEvent({
              eventCode: 'PRIVATE_SAFE_RESTORED',
              resultingState: 'PRIVATE_SAFE',
              extremeModeActive: false,
            });
            setRedactedEvents(getRedactedSecurityEvents());
            setScreenExposureState('PRIVATE_SAFE');
          }
        }}
        onLockVault={() => lockVault('Locked from Privacy Shield')}
      />
    );
  }

  const runtimeSignals = detectBrowserDisplaySignals();
  const exposureDiagnostics = buildScreenExposureDiagnosticsSnapshot({
    currentState: screenExposureState,
    extremeModeEnabled: store.settings.extremeScreenProtection ?? true,
    lockOnBackgroundEnabled: store.settings.lockOnBackgroundHide ?? true,
    screenIsExtended: runtimeSignals.screenIsExtended,
  });

  return (
    <div className="min-h-screen bg-[#050505] text-[#F4F7F5] flex flex-col">
      {/* Mandatory 3-Zone Top Bar Contract */}
      <header className="flex items-center justify-between gap-1.5 sm:gap-6 md:gap-8 px-2.5 sm:px-6 py-3 sm:py-3.5 border-b border-[#161B20] bg-[#050505] sticky top-0 z-30">
        {/* Zone 1: Single text element Brand wordmark */}
        <a
          href="#top"
          onClick={(e) => {
            e.preventDefault();
            setActiveTab('vault');
          }}
          className="text-[11px] sm:text-base font-bold tracking-tight text-white whitespace-nowrap shrink-0 max-w-[92px] sm:max-w-none truncate font-[family-name:var(--font-display)] flex items-center gap-2"
        >
          <span
            className="w-2 h-2 rounded-full bg-[#00FF66] shadow-[0_0_8px_rgba(0,255,102,0.8)] shrink-0"
            aria-hidden="true"
          />
          <span>BLACKTOWER VAULT™</span>
        </a>

        {/* Zone 2: 5 concise single-line text navigation links */}
        <nav
          aria-label="Primary Vault Navigation"
          className="flex items-center gap-2 sm:gap-6 text-[11px] sm:text-sm font-medium"
        >
          {(
            [
              { id: 'vault', label: 'Vault' },
              { id: 'generator', label: 'Generator' },
              { id: 'security', label: 'Security' },
              { id: 'settings', label: 'Settings' },
            ] as const
          ).map((nav) => (
            <button
              key={nav.id}
              type="button"
              onClick={() => setActiveTab(nav.id)}
              className={`py-1 transition-colors whitespace-nowrap shrink-0 border-b-2 ${
                activeTab === nav.id
                  ? 'border-[#00FF66] text-white font-semibold'
                  : 'border-transparent text-zinc-400 hover:text-zinc-100'
              }`}
            >
              {nav.label}
            </button>
          ))}
          <a
            href="/command"
            className="py-1 transition-colors whitespace-nowrap shrink-0 border-b-2 border-transparent text-zinc-400 hover:text-[#00FF66]"
          >
            BLACKTOWER OS™
          </a>
        </nav>

        {/* Zone 3: 1 primary action */}
        <div className="flex items-center shrink-0">
          <button
            type="button"
            onClick={() => lockVault('Manual lock')}
            className="px-2 sm:px-4 py-1 sm:py-2 text-[11px] sm:text-xs font-semibold text-[#050505] bg-[#00FF66] hover:bg-[#22FF7A] rounded-lg transition-colors flex items-center gap-1 sm:gap-1.5 whitespace-nowrap shrink-0 shadow-[0_0_20px_rgba(0,255,102,0.16)]"
          >
            <Lock className="w-3 h-3 sm:w-3.5 sm:h-3.5" />
            <span>Lock</span>
          </button>
        </div>
      </header>

      {/* Active Clipboard Auto-Clear Countdown Banner */}
      {clipboardGuard && (
        <div className="bg-[#0B0E11] border-b border-[#161B20] px-6 py-2.5 flex items-center justify-between gap-4 text-xs">
          <div className="flex items-center gap-2 text-zinc-200">
            <ClipboardCheck className="w-4 h-4 text-[#00FF66] shrink-0" />
            <span>
              <strong>{clipboardGuard.label}</strong> copied to clipboard · Auto-clearing in{' '}
              <span className="font-mono tabular-nums font-bold text-[#00FF66]">
                {clipboardGuard.secondsRemaining}s
              </span>
            </span>
          </div>
          <button
            type="button"
            onClick={handleClearClipboardNow}
            className="text-xs font-medium text-zinc-300 hover:text-white underline whitespace-nowrap"
          >
            Clear Clipboard Now
          </button>
        </div>
      )}

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-6 py-8">
        {activeTab === 'vault' && (
          <VaultWorkspace
            items={decryptedItems}
            rawEnvelopes={store.items}
            developerMode={store.settings.developerDiagnosticsMode}
            screenExposureState={screenExposureState}
            onVerifySafeBeforeSecretReveal={handleVerifySafeBeforeSecretReveal}
            onAddOrUpdateItem={handleAddOrUpdateItem}
            onDeleteItem={handleDeleteItem}
            onToggleFavorite={handleToggleFavorite}
            onCopySecretWithGuard={handleCopySecretWithGuard}
            onOpenCsvImport={() => setIsCsvImportOpen(true)}
          />
        )}

        {activeTab === 'generator' && (
          <GeneratorView
            onCopySecretWithGuard={handleCopySecretWithGuard}
            onSaveGeneratedAsVaultItem={handleSaveGeneratedPasswordAsItem}
          />
        )}

        {activeTab === 'security' && (
          <SecurityCenterView
            store={store}
            exposureDiagnostics={exposureDiagnostics}
            redactedEvents={redactedEvents}
            onTriggerExposureDrill={triggerExposureProtection}
            onNavigateToSettings={() => setActiveTab('settings')}
          />
        )}

        {activeTab === 'settings' && (
          <SettingsRecoverySyncView
            store={store}
            cloudAuthEmail={cloudAuthEmail}
            onSignInWithGoogle={handleSignInWithGoogle}
            onSignOutCloudSync={handleSignOutCloudSync}
            onUpdateSettings={handleUpdateSettings}
            onVerifyRecoveryKey={handleVerifyRecoveryKey}
            onRotateRecoveryKey={handleRotateRecoveryKey}
            onExportBackup={handleExportBackup}
            onRestoreBackup={handleRestoreBackup}
            onSyncPush={handleSyncPush}
            onSyncPull={handleSyncPull}
            onRevokeDevice={handleRevokeDevice}
            onTestServerPlaintextRejection={handleTestServerPlaintextRejection}
            onOpenCsvImport={() => setIsCsvImportOpen(true)}
          />
        )}
      </main>

      {/* Local-Only Zero-Knowledge CSV Import / Migration Modal */}
      <CsvImportModal
        isOpen={isCsvImportOpen}
        existingItems={decryptedItems}
        screenExposureState={screenExposureState}
        onActiveSessionChange={(s) => {
          activeCsvSessionRef.current = s;
        }}
        onClose={() => {
          activeCsvSessionRef.current = null;
          setIsCsvImportOpen(false);
        }}
        onExecuteImport={handleExecuteCsvImport}
        onViewImportedItems={() => {
          activeCsvSessionRef.current = null;
          setIsCsvImportOpen(false);
          setActiveTab('vault');
        }}
      />

      {/* Explicit Creation / Replacement Flow Modal for 256-Bit Recovery Key (Phase 6 & Rule 13) */}
      {explicitRecoveryKeyModal && (
        <div
          role="dialog"
          aria-modal="true"
          aria-labelledby="recovery-modal-title"
          className="fixed inset-0 z-50 bg-black/80 flex items-center justify-center p-4"
        >
          <div className="bg-[#0B0E11] border border-[#161B20] rounded-xl max-w-lg w-full p-6 space-y-5">
            <div className="flex items-start justify-between gap-4 border-b border-[#161B20] pb-4">
              <div className="flex items-center gap-2.5">
                <KeyRound className="w-5 h-5 text-[#00FF66] shrink-0" />
                <h3
                  id="recovery-modal-title"
                  className="text-lg font-bold text-white"
                  style={{ fontFamily: 'var(--font-display)' }}
                >
                  Save Your 256-Bit Recovery Key
                </h3>
              </div>
              <button
                type="button"
                aria-label="Close Recovery Key Modal"
                onClick={() => setExplicitRecoveryKeyModal(null)}
                className="p-1 text-zinc-400 hover:text-white"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <p className="text-xs text-zinc-300 leading-relaxed">
              This 256-bit cryptographically random Recovery Key independently wraps your Account Root Key. Per the BLACKTOWER VAULT™ Security Constitution, it is never logged, never stored in plaintext, and never shown outside this explicit creation flow.
            </p>

            <div className="p-4 rounded-lg bg-[#07090B] border border-[#161B20] font-mono text-xs text-[#00FF66] break-all select-all leading-relaxed">
              {explicitRecoveryKeyModal}
            </div>

            <div className="flex flex-wrap items-center justify-between gap-3 pt-2">
              <button
                type="button"
                onClick={() => {
                  handleCopySecretWithGuard('Recovery Key', explicitRecoveryKeyModal);
                  setCopiedRecoveryModal(true);
                  setTimeout(() => setCopiedRecoveryModal(false), 2000);
                }}
                className="px-4 py-2 text-xs font-medium text-zinc-200 bg-[#10151A] hover:bg-[#161D24] border border-[#161B20] rounded-lg transition-colors flex items-center gap-1.5"
              >
                {copiedRecoveryModal ? (
                  <>
                    <Check className="w-4 h-4 text-[#00FF66]" />
                    <span>Copied (20s Guard Active)</span>
                  </>
                ) : (
                  <>
                    <Copy className="w-4 h-4" />
                    <span>Copy Recovery Key</span>
                  </>
                )}
              </button>

              <button
                type="button"
                onClick={async () => {
                  await handleVerifyRecoveryKey(explicitRecoveryKeyModal);
                  setExplicitRecoveryKeyModal(null);
                }}
                className="px-4 py-2 text-xs font-semibold text-[#050505] bg-[#00FF66] hover:bg-[#22FF7A] rounded-lg transition-colors flex items-center gap-1.5"
              >
                <ShieldCheck className="w-4 h-4" />
                <span>I Have Saved My Recovery Key</span>
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Quiet Footer */}
      <footer className="px-6 py-4 border-t border-[#161B20] text-xs text-zinc-500 flex flex-wrap items-center justify-between gap-4">
        <span>
          BLACKTOWER VAULT™ · Vault {store.hierarchy.vaultId} · {decryptedItems.length} Encrypted Records
        </span>
        <span>Neon PostgreSQL Ciphertext Storage · AES-256-GCM + Argon2id v1.3</span>
      </footer>
    </div>
  );
}
