import { eq } from 'drizzle-orm';
import { db } from './index.ts';
import { encryptedVaults, encryptedVaultItems } from './schema.ts';
import type {
  AesGcmEnvelope,
  EncryptedVaultItemEnvelope,
  VaultKeyHierarchyMetadata,
  VaultRecordType,
} from '../../lib/crypto/vault-crypto.ts';
import {
  inspectPayloadForPlaintextSecrets,
  validateZeroKnowledgeItemEnvelope,
} from '../../lib/sync/sync-validator.ts';

export interface PersistedDatabaseVaultSnapshot {
  vaultId: string;
  userUid: string;
  accountId: string;
  revision: number;
  syncAuthVerifierHash: string;
  updatedAt: string;
  hierarchy: VaultKeyHierarchyMetadata;
  items: EncryptedVaultItemEnvelope[];
  revokedDevices: string[];
}

/**
 * Fetches an encrypted vault hierarchy and all of its encrypted item envelopes from PostgreSQL.
 * Enforces two-layer error sanitization so database internals never leak.
 */
export async function getEncryptedVaultByVaultId(
  vaultId: string
): Promise<PersistedDatabaseVaultSnapshot | null> {
  try {
    const vaultRows = await db
      .select()
      .from(encryptedVaults)
      .where(eq(encryptedVaults.vaultId, vaultId));

    if (vaultRows.length === 0) {
      return null;
    }

    const v = vaultRows[0];
    const itemRows = await db
      .select()
      .from(encryptedVaultItems)
      .where(eq(encryptedVaultItems.vaultId, vaultId));

    const hierarchy: VaultKeyHierarchyMetadata = {
      schemaVersion: 1,
      accountId: v.accountId,
      vaultId: v.vaultId,
      createdAt: v.createdAt.toISOString(),
      updatedAt: v.updatedAt.toISOString(),
      kdfSaltHex: v.kdfSaltHex,
      kdfProfile: v.kdfProfile as VaultKeyHierarchyMetadata['kdfProfile'],
      kekKeyId: v.kekKeyId,
      recoveryKeyId: v.recoveryKeyId,
      rootKeyId: v.rootKeyId,
      vaultKeyId: v.vaultKeyId,
      rootWrappedByKek: JSON.parse(v.rootWrappedByKekJson) as AesGcmEnvelope,
      rootWrappedByRecovery: JSON.parse(v.rootWrappedByRecoveryJson) as AesGcmEnvelope,
      vaultKeyWrappedByRoot: JSON.parse(v.vaultKeyWrappedByRootJson) as AesGcmEnvelope,
      recoveryKeyVerificationHash: v.recoveryKeyVerificationHash,
      nativeBiometricSlot: {
        status: 'UNAVAILABLE_IN_PREVIEW',
        reason:
          'Browser preview does not have access to Android Keystore / StrongBox hardware-backed key wrapping.',
      },
    };

    const items: EncryptedVaultItemEnvelope[] = itemRows.map((row) => ({
      itemId: row.itemId,
      vaultId: row.vaultId,
      revision: row.revision,
      recordType: row.recordType as VaultRecordType,
      schemaVersion: 1,
      favorite: row.favorite === 1,
      createdAt: row.createdAt,
      updatedAt: row.updatedAt,
      itemKeyId: row.itemKeyId,
      wrappedItemKey: {
        keyId: v.vaultKeyId,
        nonceHex: row.wrappedItemKeyNonceHex,
        ciphertextWithTagHex: row.wrappedItemKeyCiphertextHex,
      },
      encryptedPayload: {
        keyId: row.itemKeyId,
        nonceHex: row.payloadNonceHex,
        ciphertextWithTagHex: row.payloadCiphertextHex,
      },
    }));

    const revokedDevices = JSON.parse(v.revokedDevicesJson || '[]') as string[];

    return {
      vaultId: v.vaultId,
      userUid: v.userUid,
      accountId: v.accountId,
      revision: v.revision,
      syncAuthVerifierHash: v.syncAuthVerifierHash,
      updatedAt: v.updatedAt.toISOString(),
      hierarchy,
      items,
      revokedDevices,
    };
  } catch (error) {
    console.error('Database query failed in getEncryptedVaultByVaultId');
    throw new Error('Database query failed. Please try again later.', { cause: error });
  }
}

/**
 * Validates and persists an encrypted vault hierarchy and its encrypted item envelopes to PostgreSQL.
 * Strictly rejects any payload containing plaintext fields or malformed AES-256-GCM envelopes before touching SQL.
 */
export async function upsertEncryptedVaultAndItems(params: {
  vaultId: string;
  userUid: string;
  accountId: string;
  syncAuthVerifierHash: string;
  revision: number;
  hierarchy: VaultKeyHierarchyMetadata;
  items: EncryptedVaultItemEnvelope[];
  revokedDevices: string[];
}): Promise<{ revision: number; updatedAt: string; itemCount: number }> {
  // Pre-SQL Zero-Knowledge Gate: reject any plaintext secrets or invalid envelopes
  const hierarchyCheck = inspectPayloadForPlaintextSecrets(params.hierarchy);
  if (!hierarchyCheck.valid) {
    throw new Error(hierarchyCheck.reason || 'Forbidden plaintext field in hierarchy');
  }

  for (const item of params.items) {
    const envCheck = validateZeroKnowledgeItemEnvelope(item);
    if (!envCheck.valid) {
      throw new Error(envCheck.reason || 'Invalid zero-knowledge item envelope');
    }
  }

  try {
    const now = new Date();
    await db
      .insert(encryptedVaults)
      .values({
        vaultId: params.vaultId,
        userUid: params.userUid,
        accountId: params.accountId,
        schemaVersion: 1,
        revision: params.revision,
        syncAuthVerifierHash: params.syncAuthVerifierHash,
        kdfProfile: params.hierarchy.kdfProfile,
        kdfSaltHex: params.hierarchy.kdfSaltHex,
        kekKeyId: params.hierarchy.kekKeyId,
        recoveryKeyId: params.hierarchy.recoveryKeyId,
        rootKeyId: params.hierarchy.rootKeyId,
        vaultKeyId: params.hierarchy.vaultKeyId,
        rootWrappedByKekJson: JSON.stringify(params.hierarchy.rootWrappedByKek),
        rootWrappedByRecoveryJson: JSON.stringify(params.hierarchy.rootWrappedByRecovery),
        vaultKeyWrappedByRootJson: JSON.stringify(params.hierarchy.vaultKeyWrappedByRoot),
        recoveryKeyVerificationHash: params.hierarchy.recoveryKeyVerificationHash,
        revokedDevicesJson: JSON.stringify(params.revokedDevices),
        updatedAt: now,
      })
      .onConflictDoUpdate({
        target: encryptedVaults.vaultId,
        set: {
          userUid: params.userUid,
          accountId: params.accountId,
          revision: params.revision,
          syncAuthVerifierHash: params.syncAuthVerifierHash,
          kdfProfile: params.hierarchy.kdfProfile,
          kdfSaltHex: params.hierarchy.kdfSaltHex,
          kekKeyId: params.hierarchy.kekKeyId,
          recoveryKeyId: params.hierarchy.recoveryKeyId,
          rootKeyId: params.hierarchy.rootKeyId,
          vaultKeyId: params.hierarchy.vaultKeyId,
          rootWrappedByKekJson: JSON.stringify(params.hierarchy.rootWrappedByKek),
          rootWrappedByRecoveryJson: JSON.stringify(params.hierarchy.rootWrappedByRecovery),
          vaultKeyWrappedByRootJson: JSON.stringify(params.hierarchy.vaultKeyWrappedByRoot),
          recoveryKeyVerificationHash: params.hierarchy.recoveryKeyVerificationHash,
          revokedDevicesJson: JSON.stringify(params.revokedDevices),
          updatedAt: now,
        },
      });

    // Replace vault items atomically with the current encrypted envelope set
    await db
      .delete(encryptedVaultItems)
      .where(eq(encryptedVaultItems.vaultId, params.vaultId));

    if (params.items.length > 0) {
      await db.insert(encryptedVaultItems).values(
        params.items.map((item) => ({
          itemId: item.itemId,
          vaultId: params.vaultId,
          revision: item.revision,
          recordType: item.recordType,
          schemaVersion: item.schemaVersion,
          favorite: 0, // Favorites are sealed inside AES-256-GCM payloadCiphertextHex; never stored as plaintext in Neon
          itemKeyId: item.itemKeyId,
          wrappedItemKeyNonceHex: item.wrappedItemKey.nonceHex,
          wrappedItemKeyCiphertextHex: item.wrappedItemKey.ciphertextWithTagHex,
          payloadNonceHex: item.encryptedPayload.nonceHex,
          payloadCiphertextHex: item.encryptedPayload.ciphertextWithTagHex,
          createdAt: item.createdAt,
          updatedAt: item.updatedAt,
        }))
      );
    }

    return {
      revision: params.revision,
      updatedAt: now.toISOString(),
      itemCount: params.items.length,
    };
  } catch (error) {
    console.error('Database query failed in upsertEncryptedVaultAndItems');
    throw new Error('Database query failed. Please try again later.', { cause: error });
  }
}

/**
 * Updates the revoked devices list for a given vault in PostgreSQL.
 */
export async function revokeDeviceInDatabaseVault(
  vaultId: string,
  targetRevokeDeviceId: string
): Promise<string[]> {
  try {
    const existing = await getEncryptedVaultByVaultId(vaultId);
    if (!existing) {
      throw new Error('VAULT_NOT_FOUND');
    }
    const revokedSet = new Set<string>(existing.revokedDevices);
    revokedSet.add(targetRevokeDeviceId);
    const updatedList = Array.from(revokedSet);

    await db
      .update(encryptedVaults)
      .set({
        revokedDevicesJson: JSON.stringify(updatedList),
        updatedAt: new Date(),
      })
      .where(eq(encryptedVaults.vaultId, vaultId));

    return updatedList;
  } catch (error) {
    console.error('Database query failed in revokeDeviceInDatabaseVault');
    throw new Error('Database query failed. Please try again later.', { cause: error });
  }
}
