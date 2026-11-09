import {
  type ActiveVaultKeyring,
  type DecryptedVaultItemPayload,
  type EncryptedVaultItemEnvelope,
  type VaultKeyHierarchyMetadata,
  type VaultRecordType,
  SecurityAbortError,
  encryptVaultItem,
  initializeVaultHierarchy,
} from '../crypto/vault-crypto.ts';
import {
  inspectPayloadForPlaintextSecrets,
  inspectStorageForPlaintextLeakage,
} from '../sync/sync-validator.ts';

const STORAGE_KEY_V1 = 'BLACKTOWER_VAULT_ENCRYPTED_STORE_V1';

export interface SyncDeviceMetadata {
  deviceId: string;
  deviceName: string;
  platform: 'Browser Preview (WebCrypto)' | 'Android Native (Keystore)';
  registeredAt: string;
  lastSyncAt: string | null;
  revoked: boolean;
}

export interface PersistedEncryptedVaultStore {
  storeVersion: 1;
  hierarchy: VaultKeyHierarchyMetadata;
  items: EncryptedVaultItemEnvelope[];
  syncState: {
    lastSyncedRevision: number;
    lastSyncTimestamp: string | null;
    remoteSyncStatus: 'local_only' | 'synced' | 'conflict_detected' | 'error';
    activeDeviceId: string;
    devices: SyncDeviceMetadata[];
  };
  settings: {
    autoLockTimeoutSeconds: number;
    clipboardClearSeconds: 20 | 30 | 60;
    lockOnBackgroundHide: boolean;
    extremeScreenProtection: boolean;
    developerDiagnosticsMode: boolean;
    recoveryKeyVerifiedAt: string | null;
    lastBackupExportedAt: string | null;
  };
}

export function assertStoreZeroPlaintext(store: PersistedEncryptedVaultStore): void {
  const check = inspectPayloadForPlaintextSecrets({
    hierarchy: store.hierarchy,
    items: store.items,
  });
  if (!check.valid) {
    throw new SecurityAbortError(
      'STORAGE_PLAINTEXT_VIOLATION',
      check.reason || 'Attempted to persist plaintext secret field to local storage'
    );
  }
}

export function loadEncryptedVaultStore(): PersistedEncryptedVaultStore | null {
  if (typeof window === 'undefined' || !window.localStorage) return null;
  const raw = window.localStorage.getItem(STORAGE_KEY_V1);
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw) as PersistedEncryptedVaultStore;
    assertStoreZeroPlaintext(parsed);
    return {
      ...parsed,
      settings: {
        ...parsed.settings,
        extremeScreenProtection: parsed.settings?.extremeScreenProtection ?? true,
        lockOnBackgroundHide: parsed.settings?.lockOnBackgroundHide ?? true,
      },
    };
  } catch {
    return null;
  }
}

export function saveEncryptedVaultStore(store: PersistedEncryptedVaultStore): void {
  assertStoreZeroPlaintext(store);
  if (typeof window === 'undefined' || !window.localStorage) return;
  window.localStorage.setItem(STORAGE_KEY_V1, JSON.stringify(store));
}

export function getRawEncryptedStorageSnapshot(): {
  rawBytesLength: number;
  rawJson: string;
  leakageCheck: {
    passed: boolean;
    leakedFieldOrCanary: string | null;
    details: string;
  };
} {
  if (typeof window === 'undefined' || !window.localStorage) {
    return {
      rawBytesLength: 0,
      rawJson: '{}',
      leakageCheck: {
        passed: true,
        leakedFieldOrCanary: null,
        details: 'No browser storage initialized',
      },
    };
  }
  const rawJson = window.localStorage.getItem(STORAGE_KEY_V1) || '{}';
  const leakageCheck = inspectStorageForPlaintextLeakage(rawJson);
  return {
    rawBytesLength: new TextEncoder().encode(rawJson).length,
    rawJson,
    leakageCheck,
  };
}

export function wipeEncryptedVaultStore(): void {
  if (typeof window === 'undefined' || !window.localStorage) return;
  window.localStorage.removeItem(STORAGE_KEY_V1);
}

/**
 * Synthetic development-only records. They contain no real credentials,
 * identities, payment data, or infrastructure secrets.
 */
const SYNTHETIC_DEMO_ITEMS: Array<{
  recordType: VaultRecordType;
  favorite: boolean;
  payload: DecryptedVaultItemPayload;
}> = [
  {
    recordType: 'password',
    favorite: true,
    payload: {
      title: 'DEMO — Example Service',
      subtitle: 'demo@example.invalid',
      folder: 'DEMO ONLY',
      username: 'demo@example.invalid',
      password: 'DEMO_NOT_A_REAL_PASSWORD_2026',
      url: 'https://example.invalid',
      totpSecret: 'DEMO_NOT_A_REAL_TOTP_SECRET',
      noteContent: 'Synthetic development fixture. Never use for real authentication.',
    },
  },
  {
    recordType: 'note',
    favorite: false,
    payload: {
      title: 'DEMO — Security Procedure',
      subtitle: 'Synthetic test note',
      folder: 'DEMO ONLY',
      noteContent: 'Synthetic development fixture. Contains no operational security material.',
    },
  },
  {
    recordType: 'identity',
    favorite: false,
    payload: {
      title: 'DEMO — Synthetic Identity',
      subtitle: 'Example Person · ID-DEMO-0000',
      folder: 'DEMO ONLY',
      fullName: 'Example Person',
      email: 'demo@example.invalid',
      phone: '+60 00-000 0000',
      passportOrIdNumber: 'DEMO-ID-0000',
      address: 'DEMO ADDRESS — NOT REAL',
      noteContent: 'Synthetic development fixture. Not a real identity.',
    },
  },
  {
    recordType: 'card',
    favorite: false,
    payload: {
      title: 'DEMO — Synthetic Payment Card',
      subtitle: '•••• 0000 · Exp 01/30',
      folder: 'DEMO ONLY',
      cardholderName: 'EXAMPLE PERSON',
      cardNumber: '0000 0000 0000 0000',
      cardExpiry: '01/30',
      cardCvv: '000',
      cardPin: '0000',
      noteContent: 'Synthetic development fixture. Never use for payments.',
    },
  },
  {
    recordType: 'custom',
    favorite: false,
    payload: {
      title: 'DEMO — Synthetic Private Key',
      subtitle: 'demo.example.invalid',
      folder: 'DEMO ONLY',
      customFields: [
        { label: 'Interface Address', value: '192.0.2.1/32', sensitive: false },
        { label: 'Endpoint', value: '198.51.100.1:51820', sensitive: false },
        {
          label: 'Synthetic Private Key',
          value: 'DEMO_NOT_A_REAL_PRIVATE_KEY',
          sensitive: true,
        },
      ],
      noteContent: 'Synthetic development fixture. Not usable cryptographic material.',
    },
  },
];

export async function provisionNewEncryptedVault(params: {
  masterPassword: string;
  includeSampleItems?: boolean;
}): Promise<{
  store: PersistedEncryptedVaultStore;
  keyring: ActiveVaultKeyring;
  formattedRecoveryKey: string;
}> {
  const { hierarchy, keyring, formattedRecoveryKey } = await initializeVaultHierarchy({
    masterPassword: params.masterPassword,
    kdfProfile: 'argon2id-v1.3-standard',
  });

  const encryptedItems: EncryptedVaultItemEnvelope[] = [];
  // Demo fixtures are opt-in. Production provisioning is empty by default.
  if (params.includeSampleItems === true) {
    for (const sample of SYNTHETIC_DEMO_ITEMS) {
      const env = await encryptVaultItem({
        keyring,
        recordType: sample.recordType,
        favorite: sample.favorite,
        payload: sample.payload,
      });
      encryptedItems.push(env);
    }
  }

  const deviceId = `dev_web_${hierarchy.vaultId.slice(-6)}`;
  const now = new Date().toISOString();

  const store: PersistedEncryptedVaultStore = {
    storeVersion: 1,
    hierarchy,
    items: encryptedItems,
    syncState: {
      lastSyncedRevision: 0,
      lastSyncTimestamp: null,
      remoteSyncStatus: 'local_only',
      activeDeviceId: deviceId,
      devices: [
        {
          deviceId,
          deviceName: 'Current Browser Preview Session',
          platform: 'Browser Preview (WebCrypto)',
          registeredAt: now,
          lastSyncAt: null,
          revoked: false,
        },
      ],
    },
    settings: {
      autoLockTimeoutSeconds: 300,
      clipboardClearSeconds: 20,
      lockOnBackgroundHide: true,
      extremeScreenProtection: true,
      developerDiagnosticsMode: false,
      recoveryKeyVerifiedAt: null,
      lastBackupExportedAt: null,
    },
  };

  saveEncryptedVaultStore(store);

  return {
    store,
    keyring,
    formattedRecoveryKey,
  };
}
