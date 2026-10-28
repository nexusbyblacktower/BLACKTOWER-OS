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
    autoLockTimeoutSeconds: number; // e.g., 60, 300, 900
    clipboardClearSeconds: 20 | 30 | 60;
    lockOnBackgroundHide: boolean;
    extremeScreenProtection: boolean; // ON by default per Section 6 & 19
    developerDiagnosticsMode: boolean;
    recoveryKeyVerifiedAt: string | null;
    lastBackupExportedAt: string | null;
  };
}

/**
 * Validates that a store object contains zero forbidden plaintext fields before persisting.
 */
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

const INITIAL_SAMPLE_ITEMS: Array<{
  recordType: VaultRecordType;
  favorite: boolean;
  payload: DecryptedVaultItemPayload;
}> = [
  {
    recordType: 'password',
    favorite: true,
    payload: {
      title: 'Cloudflare Zero Trust Root Console',
      subtitle: 'secops-admin@blacktower.internal',
      folder: 'Infrastructure',
      username: 'secops-admin@blacktower.internal',
      password: 'Bt9#vK2!mQ8$pL5@xR4&zN7*wC1',
      url: 'https://one.dash.cloudflare.com',
      totpSecret: 'JBSWY3DPEHPK3PXP',
      noteContent: 'Primary infrastructure DNS & hardware-key enforced root console.',
    },
  },
  {
    recordType: 'password',
    favorite: true,
    payload: {
      title: 'GitHub Enterprise Signing Org',
      subtitle: 'k.vance@blacktower.io',
      folder: 'Engineering',
      username: 'k.vance@blacktower.io',
      password: 'Gh7$wP9#nL3@qX5!vB8&mK2*rT6',
      url: 'https://github.com/enterprises/blacktower',
      totpSecret: 'KRSXG5CTMVRXEZLU',
      noteContent: 'Commit signing authority and release verification account.',
    },
  },
  {
    recordType: 'note',
    favorite: true,
    payload: {
      title: 'Cold Storage HSM Quorum Protocol',
      subtitle: 'Offline air-gapped key ceremony procedure',
      folder: 'Security Protocols',
      noteContent:
        'Quorum requires 3-of-5 physical YubiKey HSM shards located in Zurich, Singapore, and Reykjavik vaults. Never initialize reconstruction on network-attached hardware.',
    },
  },
  {
    recordType: 'identity',
    favorite: false,
    payload: {
      title: 'Diplomatic & Sovereign Travel Identity',
      subtitle: 'Kieran Vance · Passport #CH-9948102',
      folder: 'Personal Identity',
      fullName: 'Kieran Vance',
      email: 'kieran.vance@proton.me',
      phone: '+41 44 580 29 10',
      passportOrIdNumber: 'CH-9948102-Z',
      address: 'Bahnhofstrasse 42, 8001 Zürich, Switzerland',
      noteContent: 'Primary biometric passport and tax residency registration.',
    },
  },
  {
    recordType: 'card',
    favorite: false,
    payload: {
      title: 'Swiss Corporate Treasury Visa Infinite',
      subtitle: '•••• 8842 · Exp 09/29',
      folder: 'Financial',
      cardholderName: 'KIERAN VANCE',
      cardNumber: '4532 8910 4421 8842',
      cardExpiry: '09/29',
      cardCvv: '739',
      cardPin: '8492',
      noteContent: 'Dedicated hardware procurement and cloud infrastructure settlement card.',
    },
  },
  {
    recordType: 'custom',
    favorite: false,
    payload: {
      title: 'WireGuard Core Mesh Private Key',
      subtitle: 'wg0-zurich-core01.blacktower.net',
      folder: 'Cryptography',
      customFields: [
        { label: 'Interface Address', value: '10.99.0.1/24', sensitive: false },
        { label: 'Endpoint', value: '185.220.101.4:51820', sensitive: false },
        {
          label: 'Curve25519 Private Key',
          value: 'cG9sYXJpc19zero_knowledge_wireguard_key_9981234==',
          sensitive: true,
        },
        {
          label: 'Preshared Key (PSK)',
          value: 'psk_88492019482716253490128374651928==',
          sensitive: true,
        },
      ],
      noteContent: 'Rotated every 30 days via automated ephemeral tunnel daemon.',
    },
  },
];

/**
 * Provisions a new encrypted vault with the 4-tier hierarchy and encrypts starter records
 * so every record persisted on disk is genuine AES-256-GCM ciphertext.
 */
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
  if (params.includeSampleItems !== false) {
    for (const sample of INITIAL_SAMPLE_ITEMS) {
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
      autoLockTimeoutSeconds: 300, // 5 minutes default
      clipboardClearSeconds: 20, // 20 seconds default per constitution
      lockOnBackgroundHide: true, // Preferred extreme mode: LOCK VAULT WHEN BACKGROUNDED
      extremeScreenProtection: true, // EXTREME SCREEN PROTECTION ON by default
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
