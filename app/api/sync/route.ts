import { NextRequest, NextResponse } from 'next/server';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex } from '@/lib/crypto/vault-crypto';
import {
  inspectPayloadForPlaintextSecrets,
  validateZeroKnowledgeItemEnvelope,
} from '@/lib/sync/sync-validator';
import type {
  EncryptedVaultItemEnvelope,
  VaultKeyHierarchyMetadata,
} from '@/lib/crypto/vault-crypto';
import { adminAuth } from '../../../src/lib/firebase-admin.ts';
import { getOrCreateUser } from '../../../src/db/users.ts';
import {
  getEncryptedVaultByVaultId,
  upsertEncryptedVaultAndItems,
  revokeDeviceInDatabaseVault,
} from '../../../src/db/vault-repository.ts';

const rateLimitWindowMap = new Map<string, { count: number; windowStartMs: number }>();

const RATE_LIMIT_MAX_REQ = 30;
const RATE_LIMIT_WINDOW_MS = 60_000;

function checkRateLimit(clientKey: string): boolean {
  const now = Date.now();
  const entry = rateLimitWindowMap.get(clientKey);
  if (!entry || now - entry.windowStartMs > RATE_LIMIT_WINDOW_MS) {
    rateLimitWindowMap.set(clientKey, { count: 1, windowStartMs: now });
    return true;
  }
  entry.count += 1;
  return entry.count <= RATE_LIMIT_MAX_REQ;
}

function hashSyncToken(token: string): string {
  return bytesToHex(sha256(new TextEncoder().encode(`BTVAULT_SERVER_VERIFIER_V1|${token}`)));
}

export async function POST(req: NextRequest) {
  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json(
      { error: 'INVALID_JSON_PAYLOAD', message: 'Request body must be valid JSON' },
      { status: 400 }
    );
  }

  // PHASE 11 & CONSTITUTION RULE 17 & ZERO-KNOWLEDGE MANDATE:
  // Mandatory Server Plaintext & Metadata Rejection BEFORE any database or auth action.
  const plaintextInspection = inspectPayloadForPlaintextSecrets(body);
  if (!plaintextInspection.valid) {
    return NextResponse.json(
      {
        error: 'SECURITY_POLICY_REJECTED_PLAINTEXT_FIELD',
        rejectedField: plaintextInspection.rejectedField,
        rejectedPath: plaintextInspection.rejectedPath,
        message:
          plaintextInspection.reason ||
          'Zero-Knowledge Policy Violation: Server rejected payload containing forbidden plaintext field.',
      },
      { status: 400 }
    );
  }

  // Verify Firebase ID token if provided in Authorization Bearer header
  let authenticatedUid: string | null = null;
  const authHeader = req.headers.get('authorization');
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const idToken = authHeader.slice('Bearer '.length).trim();
    if (idToken) {
      try {
        const decodedToken = await adminAuth.verifyIdToken(idToken);
        authenticatedUid = decodedToken.uid;
        await getOrCreateUser(
          decodedToken.uid,
          decodedToken.email || `${decodedToken.uid}@blacktower.vault`
        );
      } catch {
        return NextResponse.json(
          { error: 'UNAUTHORIZED_FIREBASE_TOKEN', message: 'Invalid Firebase authentication token' },
          { status: 401 }
        );
      }
    }
  }

  const payload = body as {
    action?: 'push' | 'pull' | 'revoke_device' | 'status';
    accountId?: string;
    vaultId?: string;
    deviceId?: string;
    targetRevokeDeviceId?: string;
    syncAuthToken?: string;
    expectedRevision?: number;
    forceOverwrite?: boolean;
    hierarchy?: VaultKeyHierarchyMetadata;
    items?: EncryptedVaultItemEnvelope[];
  };

  const clientKey = `${payload.accountId || 'anon'}:${payload.deviceId || 'unknown'}`;
  if (!checkRateLimit(clientKey)) {
    return NextResponse.json(
      {
        error: 'RATE_LIMIT_EXCEEDED',
        message: 'Too many synchronization requests. Please wait before retrying.',
      },
      { status: 429 }
    );
  }

  if (!payload.accountId || !payload.vaultId || !payload.syncAuthToken || !payload.deviceId) {
    return NextResponse.json(
      {
        error: 'MISSING_AUTH_PARAMETERS',
        message: 'accountId, vaultId, deviceId, and syncAuthToken are required',
      },
      { status: 400 }
    );
  }

  const incomingVerifierHash = hashSyncToken(payload.syncAuthToken);
  const effectiveUserUid = authenticatedUid || `zk_${payload.accountId}`;

  try {
    // Ensure a user record exists for referential tracking without storing any vault secrets
    if (!authenticatedUid) {
      await getOrCreateUser(effectiveUserUid, `${payload.accountId}@zk.blacktower.vault`);
    }

    const existingRecord = await getEncryptedVaultByVaultId(payload.vaultId);

    // Verify zero-knowledge authentication verifier hash and device revocation if vault exists in PostgreSQL
    if (existingRecord) {
      if (existingRecord.syncAuthVerifierHash !== incomingVerifierHash) {
        return NextResponse.json(
          {
            error: 'SYNC_AUTH_VERIFIER_MISMATCH',
            message: 'Zero-knowledge sync authentication verifier rejected',
          },
          { status: 401 }
        );
      }
      if (existingRecord.revokedDevices.includes(payload.deviceId)) {
        return NextResponse.json(
          {
            error: 'DEVICE_REVOKED',
            message: `Device ${payload.deviceId} has been revoked from synchronizing with this vault`,
          },
          { status: 403 }
        );
      }
    }

    const action = payload.action || 'status';

    if (action === 'revoke_device') {
      if (!existingRecord) {
        return NextResponse.json({ error: 'VAULT_NOT_FOUND' }, { status: 404 });
      }
      if (!payload.targetRevokeDeviceId) {
        return NextResponse.json({ error: 'MISSING_TARGET_DEVICE' }, { status: 400 });
      }
      const updatedRevoked = await revokeDeviceInDatabaseVault(
        payload.vaultId,
        payload.targetRevokeDeviceId
      );
      return NextResponse.json({
        status: 'DEVICE_REVOKED_SUCCESS',
        revokedDeviceId: payload.targetRevokeDeviceId,
        revokedDevices: updatedRevoked,
      });
    }

    if (action === 'push') {
      if (!payload.hierarchy || !Array.isArray(payload.items)) {
        return NextResponse.json(
          {
            error: 'INVALID_ENCRYPTED_ENVELOPE',
            message: 'hierarchy and encrypted items array required',
          },
          { status: 400 }
        );
      }

      for (const item of payload.items) {
        const check = validateZeroKnowledgeItemEnvelope(item);
        if (!check.valid) {
          return NextResponse.json(
            {
              error: 'INVALID_ZERO_KNOWLEDGE_ENVELOPE',
              message: check.reason || 'Item envelope failed zero-knowledge cryptographic validation',
            },
            { status: 400 }
          );
        }
      }

      const currentRev = existingRecord ? existingRecord.revision : 0;
      const expectedRev = payload.expectedRevision ?? currentRev;

      if (existingRecord && expectedRev !== currentRev && !payload.forceOverwrite) {
        return NextResponse.json(
          {
            error: 'REVISION_CONFLICT',
            serverRevision: currentRev,
            clientExpectedRevision: expectedRev,
            message: `Database vault is at revision ${currentRev}, but client expected ${expectedRev}.`,
          },
          { status: 409 }
        );
      }

      const nextRevision = currentRev + 1;
      const persisted = await upsertEncryptedVaultAndItems({
        vaultId: payload.vaultId,
        userUid: effectiveUserUid,
        accountId: payload.accountId,
        syncAuthVerifierHash: incomingVerifierHash,
        revision: nextRevision,
        hierarchy: payload.hierarchy,
        items: payload.items,
        revokedDevices: existingRecord ? existingRecord.revokedDevices : [],
      });

      return NextResponse.json({
        status: 'SYNC_PUSH_OK',
        vaultId: payload.vaultId,
        revision: persisted.revision,
        syncedAt: persisted.updatedAt,
        itemCount: persisted.itemCount,
        zeroKnowledgeVerified: true,
      });
    }

    if (action === 'pull') {
      if (!existingRecord) {
        return NextResponse.json(
          {
            status: 'NO_REMOTE_VAULT',
            revision: 0,
            message: 'No encrypted vault snapshot pushed to remote database yet.',
          },
          { status: 200 }
        );
      }

      return NextResponse.json({
        status: 'SYNC_PULL_OK',
        vaultId: existingRecord.vaultId,
        revision: existingRecord.revision,
        updatedAt: existingRecord.updatedAt,
        hierarchy: existingRecord.hierarchy,
        items: existingRecord.items,
        revokedDevices: existingRecord.revokedDevices,
      });
    }

    return NextResponse.json({
      status: 'SYNC_STATUS_OK',
      vaultExists: Boolean(existingRecord),
      revision: existingRecord ? existingRecord.revision : 0,
      updatedAt: existingRecord ? existingRecord.updatedAt : null,
      itemCount: existingRecord ? existingRecord.items.length : 0,
    });
  } catch (error) {
    console.error('Encrypted sync route failed');
    return NextResponse.json(
      {
        error: 'SYNC_STORAGE_ERROR',
        message: error instanceof Error ? error.message : 'Unable to process encrypted sync request',
      },
      { status: 500 }
    );
  }
}
