import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';
import {
  type ActiveVaultKeyring,
  type EncryptedVaultItemEnvelope,
  type VaultKeyHierarchyMetadata,
  SecurityAbortError,
  bytesToHex,
} from './vault-crypto.ts';
import { inspectPayloadForPlaintextSecrets } from '../sync/sync-validator.ts';

export interface BtVaultBackupContainer {
  magic: 'BLACKTOWER_VAULT_CONTAINER_V1';
  containerVersion: 1;
  exportedAt: string;
  accountId: string;
  vaultId: string;
  itemCount: number;
  hierarchy: VaultKeyHierarchyMetadata;
  items: EncryptedVaultItemEnvelope[];
  integritySealHex: string; // Authenticated HMAC-SHA256 over canonical container body using Vault Key
}

function buildCanonicalBackupDigestInput(
  container: Omit<BtVaultBackupContainer, 'integritySealHex'>
): Uint8Array {
  const canonicalPayload = JSON.stringify({
    magic: container.magic,
    containerVersion: container.containerVersion,
    exportedAt: container.exportedAt,
    accountId: container.accountId,
    vaultId: container.vaultId,
    itemCount: container.itemCount,
    hierarchy: container.hierarchy,
    items: container.items,
  });
  return new TextEncoder().encode(canonicalPayload);
}

/**
 * Creates an authenticated, encrypted .btvault backup container.
 * Verifies zero plaintext secrets exist before sealing with HMAC-SHA256 under a domain-separated key derived from Vault Key.
 */
export function createEncryptedBackupContainer(params: {
  keyring: ActiveVaultKeyring;
  hierarchy: VaultKeyHierarchyMetadata;
  items: EncryptedVaultItemEnvelope[];
}): BtVaultBackupContainer {
  // Verify no plaintext fields leaked into items or hierarchy
  const check = inspectPayloadForPlaintextSecrets({
    hierarchy: params.hierarchy,
    items: params.items,
  });
  if (!check.valid) {
    throw new SecurityAbortError(
      'BACKUP_PLAINTEXT_REJECTED',
      check.reason || 'Backup rejected due to plaintext field presence'
    );
  }

  const unsignedContainer: Omit<BtVaultBackupContainer, 'integritySealHex'> = {
    magic: 'BLACKTOWER_VAULT_CONTAINER_V1',
    containerVersion: 1,
    exportedAt: new Date().toISOString(),
    accountId: params.hierarchy.accountId,
    vaultId: params.hierarchy.vaultId,
    itemCount: params.items.length,
    hierarchy: params.hierarchy,
    items: params.items,
  };

  const backupMacKey = hmac(
    sha256,
    params.keyring.vaultKeyBytes,
    new TextEncoder().encode(`BTVAULT_BACKUP_SEAL_KEY_V1|${params.hierarchy.vaultId}`)
  );
  const digestInput = buildCanonicalBackupDigestInput(unsignedContainer);
  const sealBytes = hmac(sha256, backupMacKey, digestInput);

  return {
    ...unsignedContainer,
    integritySealHex: bytesToHex(sealBytes),
  };
}

/**
 * Verifies the structure, zero-plaintext rule, and cryptographic HMAC-SHA256 integrity seal
 * of a .btvault backup container before allowing restoration.
 */
export function verifyBackupContainerIntegrity(
  rawJson: string,
  keyring?: ActiveVaultKeyring
): {
  container: BtVaultBackupContainer;
  cryptographicallyAuthenticated: boolean;
} {
  let parsed: unknown;
  try {
    parsed = JSON.parse(rawJson);
  } catch {
    throw new SecurityAbortError('BACKUP_CORRUPTED_JSON', 'Backup file is not valid JSON');
  }

  const plaintextCheck = inspectPayloadForPlaintextSecrets(parsed);
  if (!plaintextCheck.valid) {
    throw new SecurityAbortError(
      'BACKUP_PLAINTEXT_REJECTED',
      plaintextCheck.reason || 'Backup container rejected: contains forbidden plaintext secret fields'
    );
  }

  const candidate = parsed as Partial<BtVaultBackupContainer>;
  if (
    candidate.magic !== 'BLACKTOWER_VAULT_CONTAINER_V1' ||
    candidate.containerVersion !== 1 ||
    !candidate.hierarchy ||
    !Array.isArray(candidate.items) ||
    typeof candidate.integritySealHex !== 'string' ||
    candidate.integritySealHex.length !== 64
  ) {
    throw new SecurityAbortError('BACKUP_INVALID_SCHEMA', 'Invalid or unsupported .btvault backup container header');
  }

  if (candidate.items.length !== candidate.itemCount) {
    throw new SecurityAbortError(
      'BACKUP_ITEM_COUNT_MISMATCH',
      'Backup container itemCount does not match encrypted record array length'
    );
  }

  const fullContainer = candidate as BtVaultBackupContainer;

  if (keyring) {
    const backupMacKey = hmac(
      sha256,
      keyring.vaultKeyBytes,
      new TextEncoder().encode(`BTVAULT_BACKUP_SEAL_KEY_V1|${fullContainer.vaultId}`)
    );
    const digestInput = buildCanonicalBackupDigestInput(fullContainer);
    const expectedSealHex = bytesToHex(hmac(sha256, backupMacKey, digestInput));
    if (expectedSealHex !== fullContainer.integritySealHex) {
      throw new SecurityAbortError(
        'BACKUP_INTEGRITY_SEAL_FAILED',
        'Backup container integrity seal verification failed: container has been tampered with'
      );
    }
    return { container: fullContainer, cryptographicallyAuthenticated: true };
  }

  return { container: fullContainer, cryptographicallyAuthenticated: false };
}
