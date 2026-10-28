/**
 * Server, Database & Client Plaintext Rejection and Secret Leakage Guard
 * Enforces Constitution Rules 1, 5, 8, 9, 10, 11, 17 and Neon/PostgreSQL Zero-Knowledge Mandate.
 */

export const FORBIDDEN_PLAINTEXT_FIELDS = new Set<string>([
  'password',
  'masterPassword',
  'username',
  'totpSecret',
  'cardNumber',
  'cardCvv',
  'cardPin',
  'cardExpiry',
  'cardholderName',
  'privateKey',
  'seedPhrase',
  'plaintext',
  'kekBytes',
  'rootKeyBytes',
  'vaultKeyBytes',
  'itemKeyBytes',
  'recoveryKey',
  'noteContent',
  'passportOrIdNumber',
  'title',
  'subtitle',
  'folder',
  'url',
  'website',
  'notes',
  'fullName',
  'phone',
  'address',
  'customFields',
  'rawKey',
  'kek',
  'rootKey',
  'vaultKey',
  'itemKey',
]);

export interface PlaintextInspectionResult {
  valid: boolean;
  rejectedField: string | null;
  rejectedPath: string | null;
  reason: string | null;
}

/**
 * Recursively inspects any payload (Sync request, PostgreSQL row parameters, Backup JSON, LocalStorage record)
 * to ensure no forbidden plaintext secret or unencrypted metadata fields are present.
 */
export function inspectPayloadForPlaintextSecrets(
  payload: unknown,
  currentPath = 'root'
): PlaintextInspectionResult {
  if (payload === null || payload === undefined) {
    return { valid: true, rejectedField: null, rejectedPath: null, reason: null };
  }

  if (Array.isArray(payload)) {
    for (let i = 0; i < payload.length; i++) {
      const res = inspectPayloadForPlaintextSecrets(payload[i], `${currentPath}[${i}]`);
      if (!res.valid) return res;
    }
    return { valid: true, rejectedField: null, rejectedPath: null, reason: null };
  }

  if (typeof payload === 'object') {
    for (const [key, value] of Object.entries(payload as Record<string, unknown>)) {
      const path = `${currentPath}.${key}`;
      if (FORBIDDEN_PLAINTEXT_FIELDS.has(key)) {
        return {
          valid: false,
          rejectedField: key,
          rejectedPath: path,
          reason: `SECURITY_POLICY_REJECTED_PLAINTEXT_FIELD: Forbidden field "${key}" detected at ${path}`,
        };
      }
      const nested = inspectPayloadForPlaintextSecrets(value, path);
      if (!nested.valid) return nested;
    }
  }

  return { valid: true, rejectedField: null, rejectedPath: null, reason: null };
}

/**
 * Validates that an EncryptedVaultItemEnvelope satisfies strict PostgreSQL Zero-Knowledge invariants:
 * - No plaintext fields anywhere on the envelope
 * - 96-bit (24 hex chars) CSPRNG nonces for both wrappedItemKey and encryptedPayload
 * - At least 128-bit (32 hex chars) AES-256-GCM authentication tag in ciphertextWithTagHex
 */
export function validateZeroKnowledgeItemEnvelope(envelope: unknown): {
  valid: boolean;
  reason: string | null;
} {
  const plaintextCheck = inspectPayloadForPlaintextSecrets(envelope);
  if (!plaintextCheck.valid) {
    return { valid: false, reason: plaintextCheck.reason };
  }
  if (!envelope || typeof envelope !== 'object') {
    return { valid: false, reason: 'Envelope must be a non-null object' };
  }
  const env = envelope as Record<string, unknown>;
  const wrappedKey = env.wrappedItemKey as Record<string, unknown> | undefined;
  const encPayload = env.encryptedPayload as Record<string, unknown> | undefined;

  if (!wrappedKey || !encPayload) {
    return { valid: false, reason: 'Missing wrappedItemKey or encryptedPayload envelope' };
  }

  const hex96Regex = /^[0-9a-fA-F]{24}$/;
  const hexCipherRegex = /^[0-9a-fA-F]{32,}$/;

  if (
    typeof wrappedKey.nonceHex !== 'string' ||
    !hex96Regex.test(wrappedKey.nonceHex) ||
    typeof encPayload.nonceHex !== 'string' ||
    !hex96Regex.test(encPayload.nonceHex)
  ) {
    return {
      valid: false,
      reason: 'INVALID_GCM_NONCE: Every envelope must carry a 96-bit (24-hex) CSPRNG nonce',
    };
  }

  if (
    typeof wrappedKey.ciphertextWithTagHex !== 'string' ||
    !hexCipherRegex.test(wrappedKey.ciphertextWithTagHex) ||
    typeof encPayload.ciphertextWithTagHex !== 'string' ||
    !hexCipherRegex.test(encPayload.ciphertextWithTagHex)
  ) {
    return {
      valid: false,
      reason: 'INVALID_GCM_CIPHERTEXT: Every envelope must include AES-256-GCM ciphertext and 128-bit tag',
    };
  }

  if (wrappedKey.nonceHex === encPayload.nonceHex && wrappedKey.keyId === encPayload.keyId) {
    return {
      valid: false,
      reason: 'CRYPTO_NONCE_COLLISION: Wrapped key and payload cannot share (keyId, nonceHex)',
    };
  }

  return { valid: true, reason: null };
}

/**
 * Inspects serialized storage strings against forbidden fields and known canary secrets.
 */
export function inspectStorageForPlaintextLeakage(
  serializedStorage: string,
  knownSensitiveCanaries: string[] = []
): {
  passed: boolean;
  leakedFieldOrCanary: string | null;
  details: string;
} {
  try {
    const parsed = JSON.parse(serializedStorage);
    const fieldCheck = inspectPayloadForPlaintextSecrets(parsed);
    if (!fieldCheck.valid) {
      return {
        passed: false,
        leakedFieldOrCanary: fieldCheck.rejectedField,
        details: fieldCheck.reason || 'Forbidden plaintext field in storage',
      };
    }
  } catch {
    // If not valid JSON, still scan raw text below
  }

  for (const canary of knownSensitiveCanaries) {
    if (canary && canary.trim().length >= 4 && serializedStorage.includes(canary)) {
      return {
        passed: false,
        leakedFieldOrCanary: '[CANARY_SECRET_MATCH]',
        details: 'Raw storage string contains unencrypted secret canary value',
      };
    }
  }

  return {
    passed: true,
    leakedFieldOrCanary: null,
    details: 'Zero plaintext secret fields or canary values detected in storage',
  };
}

/**
 * Redacts any diagnostic or error object so sensitive keys or raw key material
 * can never leak into logs or developer diagnostics (TEST-09).
 */
export function redactDiagnosticObject<T>(input: T): T {
  if (input === null || input === undefined) return input;
  if (typeof input === 'string') {
    return input.replace(/BTVK(?:-[0-9A-F]{8}){8}/gi, '[REDACTED_RECOVERY_KEY]') as unknown as T;
  }
  if (input instanceof Uint8Array) {
    return '[REDACTED_KEY_BUFFER]' as unknown as T;
  }
  if (Array.isArray(input)) {
    return input.map((item) => redactDiagnosticObject(item)) as unknown as T;
  }
  if (typeof input === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(input as Record<string, unknown>)) {
      if (
        FORBIDDEN_PLAINTEXT_FIELDS.has(k) ||
        /password|secret|private|cvv|recovery|kek|rootkey|vaultkey|itemkey|seedphrase/i.test(k)
      ) {
        out[k] = '[REDACTED]';
      } else {
        out[k] = redactDiagnosticObject(v);
      }
    }
    return out as T;
  }
  return input;
}
