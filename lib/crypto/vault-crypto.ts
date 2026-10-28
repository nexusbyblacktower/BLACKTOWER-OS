import { argon2id } from '@noble/hashes/argon2.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { hmac } from '@noble/hashes/hmac.js';

export type VaultRecordType = 'password' | 'note' | 'identity' | 'card' | 'custom';

export interface Argon2ParamsVersion {
  versionId: 'argon2id-v1.3-standard' | 'argon2id-v1.3-fast';
  algorithm: 'Argon2id';
  rfcVersion: 0x13;
  memoryKiB: number;
  iterations: number;
  parallelism: number;
  tagLengthBytes: 32;
}

export const ARGON2_PROFILES: Record<Argon2ParamsVersion['versionId'], Argon2ParamsVersion> = {
  'argon2id-v1.3-standard': {
    versionId: 'argon2id-v1.3-standard',
    algorithm: 'Argon2id',
    rfcVersion: 0x13,
    memoryKiB: 8192, // 8 MiB in browser main-thread for responsive real RFC 9106 Argon2id v1.3
    iterations: 2,
    parallelism: 1,
    tagLengthBytes: 32,
  },
  'argon2id-v1.3-fast': {
    versionId: 'argon2id-v1.3-fast',
    algorithm: 'Argon2id',
    rfcVersion: 0x13,
    memoryKiB: 2048,
    iterations: 2,
    parallelism: 1,
    tagLengthBytes: 32,
  },
};

export class SecurityAbortError extends Error {
  public readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = 'SecurityAbortError';
    this.code = code;
  }
}

/**
 * Runtime Nonce Reuse Detection Registry
 * Tracks (keyId, nonceHex) across the active runtime.
 * If a duplicate (keyId, nonceHex) is ever detected, ABORTS immediately.
 */
class NonceReuseGuard {
  private seenNonces = new Map<string, Set<string>>();
  private totalChecked = 0;
  private duplicateAborts = 0;

  public assertFreshNonce(keyId: string, nonceHex: string): void {
    this.totalChecked += 1;
    let keySet = this.seenNonces.get(keyId);
    if (!keySet) {
      keySet = new Set<string>();
      this.seenNonces.set(keyId, keySet);
    }
    if (keySet.has(nonceHex)) {
      this.duplicateAborts += 1;
      throw new SecurityAbortError(
        'CRYPTO_NONCE_REUSE_ABORT',
        `Critical Security Abort: Duplicate 96-bit nonce detected for keyId=${keyId}`
      );
    }
    keySet.add(nonceHex);
  }

  public getStats() {
    let uniquePairs = 0;
    for (const set of this.seenNonces.values()) {
      uniquePairs += set.size;
    }
    return {
      trackedKeys: this.seenNonces.size,
      uniqueNoncePairs: uniquePairs,
      totalChecked: this.totalChecked,
      duplicateAborts: this.duplicateAborts,
    };
  }
}

export const runtimeNonceGuard = new NonceReuseGuard();

export function bytesToHex(bytes: Uint8Array): string {
  let hex = '';
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, '0');
  }
  return hex;
}

export function hexToBytes(hex: string): Uint8Array {
  const clean = hex.trim().replace(/[^0-9a-fA-F]/g, '');
  if (clean.length % 2 !== 0) {
    throw new SecurityAbortError('CRYPTO_INVALID_HEX', 'Invalid hex encoding length');
  }
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export function randomBytes(length: number): Uint8Array {
  const buf = new Uint8Array(length);
  globalThis.crypto.getRandomValues(buf);
  return buf;
}

export function generateKeyId(prefix: string): string {
  return `${prefix}_${bytesToHex(randomBytes(8))}`;
}

/**
 * Zeroizes a sensitive Uint8Array buffer in memory.
 */
export function zeroizeBuffer(buffer: Uint8Array | null | undefined): boolean {
  if (!buffer) return true;
  buffer.fill(0);
  for (let i = 0; i < buffer.length; i++) {
    if (buffer[i] !== 0) return false;
  }
  return true;
}

/**
 * Canonical length-prefixed AAD encoder to prevent delimiter ambiguity or injection.
 */
export function encodeCanonicalAad(fields: Record<string, string | number>): Uint8Array {
  const orderedKeys = Object.keys(fields).sort();
  const parts: string[] = ['BTVAULT_AAD_V1'];
  for (const k of orderedKeys) {
    const val = String(fields[k]);
    parts.push(`${k.length}:${k}=${val.length}:${val}`);
  }
  return new TextEncoder().encode(parts.join('|'));
}

export function buildRootKeyWrapAad(params: {
  accountId: string;
  rootKeyId: string;
  wrapChannel: 'master_kek' | 'recovery_key';
  kdfVersion: string;
}): Uint8Array {
  return encodeCanonicalAad({
    purpose: 'TIER2_ROOT_KEY_WRAP',
    accountId: params.accountId,
    rootKeyId: params.rootKeyId,
    wrapChannel: params.wrapChannel,
    kdfVersion: params.kdfVersion,
  });
}

export function buildVaultKeyWrapAad(params: {
  accountId: string;
  vaultId: string;
  rootKeyId: string;
  vaultKeyId: string;
}): Uint8Array {
  return encodeCanonicalAad({
    purpose: 'TIER3_VAULT_KEY_WRAP',
    accountId: params.accountId,
    vaultId: params.vaultId,
    rootKeyId: params.rootKeyId,
    vaultKeyId: params.vaultKeyId,
  });
}

export function buildItemKeyWrapAad(params: {
  vaultId: string;
  itemId: string;
  revision: number;
  vaultKeyId: string;
  itemKeyId: string;
}): Uint8Array {
  return encodeCanonicalAad({
    purpose: 'TIER4_ITEM_KEY_WRAP',
    vaultId: params.vaultId,
    itemId: params.itemId,
    revision: params.revision,
    vaultKeyId: params.vaultKeyId,
    itemKeyId: params.itemKeyId,
  });
}

export function buildItemPayloadAad(params: {
  vaultId: string;
  itemId: string;
  revision: number;
  recordType: VaultRecordType;
  schemaVersion: number;
  keyId: string;
}): Uint8Array {
  return encodeCanonicalAad({
    purpose: 'TIER4_ITEM_PAYLOAD',
    vaultId: params.vaultId,
    itemId: params.itemId,
    revision: params.revision,
    recordType: params.recordType,
    schemaVersion: params.schemaVersion,
    keyId: params.keyId,
  });
}

/**
 * TIER 1: Master Password -> Argon2id v1.3 -> 256-bit KEK
 */
export function deriveKekFromMasterPassword(
  masterPassword: string,
  saltBytes: Uint8Array,
  profileId: Argon2ParamsVersion['versionId'] = 'argon2id-v1.3-standard'
): Uint8Array {
  if (!masterPassword || masterPassword.length < 1) {
    throw new SecurityAbortError('CRYPTO_EMPTY_PASSWORD', 'Master password cannot be empty');
  }
  if (saltBytes.length !== 16) {
    throw new SecurityAbortError('CRYPTO_INVALID_SALT', 'Argon2id salt must be exactly 16 bytes (128 bits)');
  }
  const profile = ARGON2_PROFILES[profileId];
  const passwordBytes = new TextEncoder().encode(masterPassword);
  try {
    const kek = argon2id(passwordBytes, saltBytes, {
      t: profile.iterations,
      m: profile.memoryKiB,
      p: profile.parallelism,
      dkLen: profile.tagLengthBytes,
      version: profile.rfcVersion,
    });
    return new Uint8Array(kek);
  } finally {
    zeroizeBuffer(passwordBytes);
  }
}

/**
 * Derives a domain-separated Zero-Knowledge Sync Authentication Verifier.
 * Never exposes Master Password or KEK to the sync server.
 */
export function deriveSyncAuthToken(masterPassword: string, accountId: string, saltHex: string): string {
  const domainSalt = sha256(new TextEncoder().encode(`BTVAULT_ZK_SYNC_AUTH_V1|${accountId}|${saltHex}`)).slice(0, 16);
  const authKey = deriveKekFromMasterPassword(masterPassword, domainSalt, 'argon2id-v1.3-fast');
  try {
    const verifier = hmac(sha256, authKey, new TextEncoder().encode(`SYNC_CLIENT_TOKEN|${accountId}`));
    return bytesToHex(verifier);
  } finally {
    zeroizeBuffer(authKey);
  }
}

export interface AesGcmEnvelope {
  keyId: string;
  nonceHex: string; // 96-bit (12 bytes)
  ciphertextWithTagHex: string; // Ciphertext + 128-bit (16 bytes) GCM authentication tag
}

/**
 * Authenticated AES-256-GCM Encryption with 96-bit CSPRNG nonce, 128-bit auth tag,
 * canonical AAD, and strict runtime nonce reuse detection.
 */
export async function aes256GcmEncrypt(params: {
  keyBytes: Uint8Array;
  keyId: string;
  plaintextBytes: Uint8Array;
  aadBytes: Uint8Array;
  explicitNonceBytes?: Uint8Array; // Only used to test nonce reuse detection in TEST-04
}): Promise<AesGcmEnvelope> {
  if (params.keyBytes.length !== 32) {
    throw new SecurityAbortError('CRYPTO_INVALID_KEY_LENGTH', 'AES-256-GCM requires a 256-bit (32-byte) key');
  }
  const nonceBytes = params.explicitNonceBytes ? new Uint8Array(params.explicitNonceBytes) : randomBytes(12);
  if (nonceBytes.length !== 12) {
    throw new SecurityAbortError('CRYPTO_INVALID_NONCE_LENGTH', 'AES-256-GCM requires a 96-bit (12-byte) nonce');
  }
  const nonceHex = bytesToHex(nonceBytes);

  // Runtime Nonce Reuse Detection — ABORTS on duplicate (keyId, nonceHex)
  runtimeNonceGuard.assertFreshNonce(params.keyId, nonceHex);

  const cryptoKey = await globalThis.crypto.subtle.importKey(
    'raw',
    params.keyBytes as BufferSource,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt']
  );

  const encryptedBuffer = await globalThis.crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: nonceBytes as BufferSource,
      additionalData: params.aadBytes as BufferSource,
      tagLength: 128,
    },
    cryptoKey,
    params.plaintextBytes as BufferSource
  );

  return {
    keyId: params.keyId,
    nonceHex,
    ciphertextWithTagHex: bytesToHex(new Uint8Array(encryptedBuffer)),
  };
}

/**
 * Authenticated AES-256-GCM Decryption.
 * Fails closed if ciphertext, 128-bit tag, or AAD is tampered.
 */
export async function aes256GcmDecrypt(params: {
  keyBytes: Uint8Array;
  envelope: AesGcmEnvelope;
  aadBytes: Uint8Array;
}): Promise<Uint8Array> {
  if (params.keyBytes.length !== 32) {
    throw new SecurityAbortError('CRYPTO_INVALID_KEY_LENGTH', 'AES-256-GCM requires a 256-bit (32-byte) key');
  }
  const nonceBytes = hexToBytes(params.envelope.nonceHex);
  const ciphertextBytes = hexToBytes(params.envelope.ciphertextWithTagHex);

  if (nonceBytes.length !== 12) {
    throw new SecurityAbortError('CRYPTO_INVALID_NONCE_LENGTH', 'AES-256-GCM nonce must be 12 bytes');
  }
  if (ciphertextBytes.length < 16) {
    throw new SecurityAbortError('CRYPTO_TRUNCATED_CIPHERTEXT', 'Ciphertext shorter than 128-bit authentication tag');
  }

  const cryptoKey = await globalThis.crypto.subtle.importKey(
    'raw',
    params.keyBytes as BufferSource,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  );

  try {
    const decryptedBuffer = await globalThis.crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: nonceBytes as BufferSource,
        additionalData: params.aadBytes as BufferSource,
        tagLength: 128,
      },
      cryptoKey,
      ciphertextBytes as BufferSource
    );
    return new Uint8Array(decryptedBuffer);
  } catch {
    throw new SecurityAbortError(
      'CRYPTO_AUTH_TAG_VERIFICATION_FAILED',
      'AES-256-GCM authentication failed: invalid key, tampered ciphertext, or mismatched AAD'
    );
  }
}

/**
 * Formats a 256-bit Recovery Key into 8 groups of 8 uppercase hex characters:
 * e.g. BTVK-A1B2C3D4-E5F60718-...
 */
export function formatRecoveryKey(rawKeyBytes: Uint8Array): string {
  if (rawKeyBytes.length !== 32) {
    throw new SecurityAbortError('CRYPTO_INVALID_RECOVERY_KEY', 'Recovery key must be 256 bits (32 bytes)');
  }
  const hex = bytesToHex(rawKeyBytes).toUpperCase();
  const groups: string[] = ['BTVK'];
  for (let i = 0; i < 64; i += 8) {
    groups.push(hex.slice(i, i + 8));
  }
  return groups.join('-');
}

export function parseRecoveryKeyString(formatted: string): Uint8Array {
  const cleaned = formatted.trim().toUpperCase().replace(/^BTVK-?/, '').replace(/-/g, '');
  if (cleaned.length !== 64 || !/^[0-9A-F]{64}$/.test(cleaned)) {
    throw new SecurityAbortError(
      'CRYPTO_INVALID_RECOVERY_FORMAT',
      'Recovery Key must be a valid 256-bit (64-hex character) BLACKTOWER key'
    );
  }
  return hexToBytes(cleaned);
}

export interface VaultKeyHierarchyMetadata {
  schemaVersion: 1;
  accountId: string;
  vaultId: string;
  createdAt: string;
  updatedAt: string;
  kdfSaltHex: string; // 16-byte CSPRNG salt
  kdfProfile: Argon2ParamsVersion['versionId'];
  kekKeyId: string;
  recoveryKeyId: string;
  rootKeyId: string;
  vaultKeyId: string;
  rootWrappedByKek: AesGcmEnvelope;
  rootWrappedByRecovery: AesGcmEnvelope;
  vaultKeyWrappedByRoot: AesGcmEnvelope;
  recoveryKeyVerificationHash: string; // HMAC-SHA256 verifier
  nativeBiometricSlot: {
    status: 'UNAVAILABLE_IN_PREVIEW';
    reason: 'Browser preview does not have access to Android Keystore / StrongBox hardware-backed key wrapping.';
  };
}

export interface EncryptedVaultItemEnvelope {
  itemId: string;
  vaultId: string;
  revision: number;
  recordType: VaultRecordType;
  schemaVersion: 1;
  favorite: boolean;
  createdAt: string;
  updatedAt: string;
  itemKeyId: string;
  wrappedItemKey: AesGcmEnvelope; // Item Key wrapped under Vault Key
  encryptedPayload: AesGcmEnvelope; // Item JSON encrypted under Item Key
}

export interface DecryptedVaultItemPayload {
  title: string;
  subtitle?: string;
  folder?: string;
  favorite?: boolean;
  // Type-specific fields (never persisted in plaintext outside encryptedPayload!)
  username?: string;
  password?: string;
  url?: string;
  totpSecret?: string;
  noteContent?: string;
  // Identity fields
  fullName?: string;
  email?: string;
  phone?: string;
  passportOrIdNumber?: string;
  address?: string;
  // Credit card fields
  cardholderName?: string;
  cardNumber?: string;
  cardExpiry?: string;
  cardCvv?: string;
  cardPin?: string;
  // Custom fields
  customFields?: Array<{ label: string; value: string; sensitive: boolean }>;
}

export interface DecryptedVaultItem {
  itemId: string;
  vaultId: string;
  revision: number;
  recordType: VaultRecordType;
  schemaVersion: 1;
  favorite: boolean;
  createdAt: string;
  updatedAt: string;
  itemKeyId: string;
  data: DecryptedVaultItemPayload;
}

export interface ActiveVaultKeyring {
  accountId: string;
  vaultId: string;
  rootKeyId: string;
  vaultKeyId: string;
  rootKeyBytes: Uint8Array;
  vaultKeyBytes: Uint8Array;
}

/**
 * Initializes a brand-new Four-Tier Cryptographic Hierarchy:
 * Master Password -> Argon2id KEK -> wraps Account Root Key
 * Recovery Key -> wraps Account Root Key
 * Account Root Key -> wraps Vault Key
 */
export async function initializeVaultHierarchy(params: {
  masterPassword: string;
  accountId?: string;
  vaultId?: string;
  kdfProfile?: Argon2ParamsVersion['versionId'];
}): Promise<{
  hierarchy: VaultKeyHierarchyMetadata;
  keyring: ActiveVaultKeyring;
  formattedRecoveryKey: string;
}> {
  const accountId = params.accountId || generateKeyId('acct');
  const vaultId = params.vaultId || generateKeyId('vault');
  const kdfProfile = params.kdfProfile || 'argon2id-v1.3-standard';
  const kdfSaltBytes = randomBytes(16);
  const kdfSaltHex = bytesToHex(kdfSaltBytes);

  const kekKeyId = generateKeyId('kek');
  const recoveryKeyId = generateKeyId('rk');
  const rootKeyId = generateKeyId('root');
  const vaultKeyId = generateKeyId('vk');

  // Tier 1: Derive KEK from Master Password
  const kekBytes = deriveKekFromMasterPassword(params.masterPassword, kdfSaltBytes, kdfProfile);

  // Tier 2: Generate 256-bit CSPRNG Account Root Key & 256-bit Recovery Key
  const rootKeyBytes = randomBytes(32);
  const recoveryKeyBytes = randomBytes(32);
  const formattedRecoveryKey = formatRecoveryKey(recoveryKeyBytes);

  // Tier 3: Generate 256-bit CSPRNG Vault Key
  const vaultKeyBytes = randomBytes(32);

  try {
    const rootKekAad = buildRootKeyWrapAad({
      accountId,
      rootKeyId,
      wrapChannel: 'master_kek',
      kdfVersion: kdfProfile,
    });
    const rootWrappedByKek = await aes256GcmEncrypt({
      keyBytes: kekBytes,
      keyId: kekKeyId,
      plaintextBytes: rootKeyBytes,
      aadBytes: rootKekAad,
    });

    const rootRecoveryAad = buildRootKeyWrapAad({
      accountId,
      rootKeyId,
      wrapChannel: 'recovery_key',
      kdfVersion: kdfProfile,
    });
    const rootWrappedByRecovery = await aes256GcmEncrypt({
      keyBytes: recoveryKeyBytes,
      keyId: recoveryKeyId,
      plaintextBytes: rootKeyBytes,
      aadBytes: rootRecoveryAad,
    });

    const vaultWrapAad = buildVaultKeyWrapAad({
      accountId,
      vaultId,
      rootKeyId,
      vaultKeyId,
    });
    const vaultKeyWrappedByRoot = await aes256GcmEncrypt({
      keyBytes: rootKeyBytes,
      keyId: rootKeyId,
      plaintextBytes: vaultKeyBytes,
      aadBytes: vaultWrapAad,
    });

    const recoveryVerifier = hmac(
      sha256,
      recoveryKeyBytes,
      new TextEncoder().encode(`BTVAULT_RECOVERY_VERIFY|${accountId}|${rootKeyId}`)
    );

    const now = new Date().toISOString();
    const hierarchy: VaultKeyHierarchyMetadata = {
      schemaVersion: 1,
      accountId,
      vaultId,
      createdAt: now,
      updatedAt: now,
      kdfSaltHex,
      kdfProfile,
      kekKeyId,
      recoveryKeyId,
      rootKeyId,
      vaultKeyId,
      rootWrappedByKek,
      rootWrappedByRecovery,
      vaultKeyWrappedByRoot,
      recoveryKeyVerificationHash: bytesToHex(recoveryVerifier),
      nativeBiometricSlot: {
        status: 'UNAVAILABLE_IN_PREVIEW',
        reason: 'Browser preview does not have access to Android Keystore / StrongBox hardware-backed key wrapping.',
      },
    };

    return {
      hierarchy,
      keyring: {
        accountId,
        vaultId,
        rootKeyId,
        vaultKeyId,
        rootKeyBytes,
        vaultKeyBytes,
      },
      formattedRecoveryKey,
    };
  } finally {
    // Always zeroize KEK and raw Recovery Key bytes immediately after wrapping
    zeroizeBuffer(kekBytes);
    zeroizeBuffer(recoveryKeyBytes);
  }
}

/**
 * Unlocks the Vault Hierarchy using the Master Password.
 */
export async function unlockVaultWithMasterPassword(
  masterPassword: string,
  hierarchy: VaultKeyHierarchyMetadata
): Promise<ActiveVaultKeyring> {
  const saltBytes = hexToBytes(hierarchy.kdfSaltHex);
  const kekBytes = deriveKekFromMasterPassword(masterPassword, saltBytes, hierarchy.kdfProfile);

  try {
    const rootKekAad = buildRootKeyWrapAad({
      accountId: hierarchy.accountId,
      rootKeyId: hierarchy.rootKeyId,
      wrapChannel: 'master_kek',
      kdfVersion: hierarchy.kdfProfile,
    });

    const rootKeyBytes = await aes256GcmDecrypt({
      keyBytes: kekBytes,
      envelope: hierarchy.rootWrappedByKek,
      aadBytes: rootKekAad,
    });

    const vaultWrapAad = buildVaultKeyWrapAad({
      accountId: hierarchy.accountId,
      vaultId: hierarchy.vaultId,
      rootKeyId: hierarchy.rootKeyId,
      vaultKeyId: hierarchy.vaultKeyId,
    });

    const vaultKeyBytes = await aes256GcmDecrypt({
      keyBytes: rootKeyBytes,
      envelope: hierarchy.vaultKeyWrappedByRoot,
      aadBytes: vaultWrapAad,
    });

    return {
      accountId: hierarchy.accountId,
      vaultId: hierarchy.vaultId,
      rootKeyId: hierarchy.rootKeyId,
      vaultKeyId: hierarchy.vaultKeyId,
      rootKeyBytes,
      vaultKeyBytes,
    };
  } finally {
    zeroizeBuffer(kekBytes);
  }
}

/**
 * Unlocks the Vault Hierarchy using the 256-bit Recovery Key.
 */
export async function unlockVaultWithRecoveryKey(
  formattedRecoveryKey: string,
  hierarchy: VaultKeyHierarchyMetadata
): Promise<ActiveVaultKeyring> {
  const recoveryKeyBytes = parseRecoveryKeyString(formattedRecoveryKey);

  try {
    const rootRecoveryAad = buildRootKeyWrapAad({
      accountId: hierarchy.accountId,
      rootKeyId: hierarchy.rootKeyId,
      wrapChannel: 'recovery_key',
      kdfVersion: hierarchy.kdfProfile,
    });

    const rootKeyBytes = await aes256GcmDecrypt({
      keyBytes: recoveryKeyBytes,
      envelope: hierarchy.rootWrappedByRecovery,
      aadBytes: rootRecoveryAad,
    });

    const vaultWrapAad = buildVaultKeyWrapAad({
      accountId: hierarchy.accountId,
      vaultId: hierarchy.vaultId,
      rootKeyId: hierarchy.rootKeyId,
      vaultKeyId: hierarchy.vaultKeyId,
    });

    const vaultKeyBytes = await aes256GcmDecrypt({
      keyBytes: rootKeyBytes,
      envelope: hierarchy.vaultKeyWrappedByRoot,
      aadBytes: vaultWrapAad,
    });

    return {
      accountId: hierarchy.accountId,
      vaultId: hierarchy.vaultId,
      rootKeyId: hierarchy.rootKeyId,
      vaultKeyId: hierarchy.vaultKeyId,
      rootKeyBytes,
      vaultKeyBytes,
    };
  } finally {
    zeroizeBuffer(recoveryKeyBytes);
  }
}

/**
 * Cryptographically verifies a Recovery Key by unwrapping the Account Root Key
 * and checking the verification tag, then immediately zeroizing both buffers.
 */
export async function verifyRecoveryKeyCryptographically(
  formattedRecoveryKey: string,
  hierarchy: VaultKeyHierarchyMetadata
): Promise<boolean> {
  let keyring: ActiveVaultKeyring | null = null;
  try {
    keyring = await unlockVaultWithRecoveryKey(formattedRecoveryKey, hierarchy);
    return keyring.rootKeyBytes.length === 32 && keyring.vaultKeyBytes.length === 32;
  } catch {
    return false;
  } finally {
    if (keyring) {
      zeroizeKeyring(keyring);
    }
  }
}

/**
 * Rotates / Replaces the Recovery Key while keeping the Account Root Key intact.
 */
export async function rotateRecoveryKey(
  keyring: ActiveVaultKeyring,
  hierarchy: VaultKeyHierarchyMetadata
): Promise<{
  updatedHierarchy: VaultKeyHierarchyMetadata;
  newFormattedRecoveryKey: string;
}> {
  const newRecoveryKeyBytes = randomBytes(32);
  const newRecoveryKeyId = generateKeyId('rk');
  const newFormattedRecoveryKey = formatRecoveryKey(newRecoveryKeyBytes);

  try {
    const rootRecoveryAad = buildRootKeyWrapAad({
      accountId: hierarchy.accountId,
      rootKeyId: hierarchy.rootKeyId,
      wrapChannel: 'recovery_key',
      kdfVersion: hierarchy.kdfProfile,
    });

    const rootWrappedByRecovery = await aes256GcmEncrypt({
      keyBytes: newRecoveryKeyBytes,
      keyId: newRecoveryKeyId,
      plaintextBytes: keyring.rootKeyBytes,
      aadBytes: rootRecoveryAad,
    });

    const recoveryVerifier = hmac(
      sha256,
      newRecoveryKeyBytes,
      new TextEncoder().encode(`BTVAULT_RECOVERY_VERIFY|${hierarchy.accountId}|${hierarchy.rootKeyId}`)
    );

    const updatedHierarchy: VaultKeyHierarchyMetadata = {
      ...hierarchy,
      updatedAt: new Date().toISOString(),
      recoveryKeyId: newRecoveryKeyId,
      rootWrappedByRecovery,
      recoveryKeyVerificationHash: bytesToHex(recoveryVerifier),
    };

    return {
      updatedHierarchy,
      newFormattedRecoveryKey,
    };
  } finally {
    zeroizeBuffer(newRecoveryKeyBytes);
  }
}

/**
 * TIER 4: Encrypts an individual Vault Item with its own fresh 256-bit Item Encryption Key,
 * wrapped under the Vault Key, with canonical AAD binding vaultId, itemId, revision, recordType, schemaVersion, keyId.
 */
export async function encryptVaultItem(params: {
  keyring: ActiveVaultKeyring;
  itemId?: string;
  revision?: number;
  recordType: VaultRecordType;
  favorite?: boolean;
  createdAt?: string;
  payload: DecryptedVaultItemPayload;
}): Promise<EncryptedVaultItemEnvelope> {
  const itemId = params.itemId || generateKeyId('item');
  const revision = params.revision ?? 1;
  const schemaVersion = 1 as const;
  const itemKeyId = generateKeyId('ik');
  const itemKeyBytes = randomBytes(32);

  try {
    const itemKeyWrapAad = buildItemKeyWrapAad({
      vaultId: params.keyring.vaultId,
      itemId,
      revision,
      vaultKeyId: params.keyring.vaultKeyId,
      itemKeyId,
    });

    const wrappedItemKey = await aes256GcmEncrypt({
      keyBytes: params.keyring.vaultKeyBytes,
      keyId: params.keyring.vaultKeyId,
      plaintextBytes: itemKeyBytes,
      aadBytes: itemKeyWrapAad,
    });

    const payloadAad = buildItemPayloadAad({
      vaultId: params.keyring.vaultId,
      itemId,
      revision,
      recordType: params.recordType,
      schemaVersion,
      keyId: itemKeyId,
    });

    const isFavorite = Boolean(params.favorite ?? params.payload.favorite);
    const sealedPayload: DecryptedVaultItemPayload = {
      ...params.payload,
      favorite: isFavorite,
    };
    const plaintextBytes = new TextEncoder().encode(JSON.stringify(sealedPayload));
    try {
      const encryptedPayload = await aes256GcmEncrypt({
        keyBytes: itemKeyBytes,
        keyId: itemKeyId,
        plaintextBytes,
        aadBytes: payloadAad,
      });

      const now = new Date().toISOString();
      return {
        itemId,
        vaultId: params.keyring.vaultId,
        revision,
        recordType: params.recordType,
        schemaVersion,
        favorite: false,
        createdAt: params.createdAt || now,
        updatedAt: now,
        itemKeyId,
        wrappedItemKey,
        encryptedPayload,
      };
    } finally {
      zeroizeBuffer(plaintextBytes);
    }
  } finally {
    zeroizeBuffer(itemKeyBytes);
  }
}

/**
 * TIER 4: Decrypts an individual EncryptedVaultItemEnvelope using the active Vault Keyring.
 * Verifies both the Item Key wrap AAD+tag and the Item Payload AAD+tag before returning plaintext.
 */
export async function decryptVaultItem(
  keyring: ActiveVaultKeyring,
  envelope: EncryptedVaultItemEnvelope
): Promise<DecryptedVaultItem> {
  if (envelope.vaultId !== keyring.vaultId) {
    throw new SecurityAbortError('CRYPTO_VAULT_ID_MISMATCH', 'Item vaultId does not match active Vault Keyring');
  }

  const itemKeyWrapAad = buildItemKeyWrapAad({
    vaultId: envelope.vaultId,
    itemId: envelope.itemId,
    revision: envelope.revision,
    vaultKeyId: keyring.vaultKeyId,
    itemKeyId: envelope.itemKeyId,
  });

  const itemKeyBytes = await aes256GcmDecrypt({
    keyBytes: keyring.vaultKeyBytes,
    envelope: envelope.wrappedItemKey,
    aadBytes: itemKeyWrapAad,
  });

  try {
    const payloadAad = buildItemPayloadAad({
      vaultId: envelope.vaultId,
      itemId: envelope.itemId,
      revision: envelope.revision,
      recordType: envelope.recordType,
      schemaVersion: envelope.schemaVersion,
      keyId: envelope.itemKeyId,
    });

    const decryptedBytes = await aes256GcmDecrypt({
      keyBytes: itemKeyBytes,
      envelope: envelope.encryptedPayload,
      aadBytes: payloadAad,
    });

    try {
      const data = JSON.parse(new TextDecoder().decode(decryptedBytes)) as DecryptedVaultItemPayload;
      const favorite =
        typeof data.favorite === 'boolean' ? data.favorite : Boolean(envelope.favorite);
      return {
        itemId: envelope.itemId,
        vaultId: envelope.vaultId,
        revision: envelope.revision,
        recordType: envelope.recordType,
        schemaVersion: envelope.schemaVersion,
        favorite,
        createdAt: envelope.createdAt,
        updatedAt: envelope.updatedAt,
        itemKeyId: envelope.itemKeyId,
        data,
      };
    } finally {
      zeroizeBuffer(decryptedBytes);
    }
  } finally {
    zeroizeBuffer(itemKeyBytes);
  }
}

/**
 * Zeroizes an ActiveVaultKeyring on manual lock or auto-lock.
 */
export function zeroizeKeyring(keyring: ActiveVaultKeyring | null | undefined): {
  rootZeroized: boolean;
  vaultZeroized: boolean;
} {
  if (!keyring) {
    return { rootZeroized: true, vaultZeroized: true };
  }
  const rootZeroized = zeroizeBuffer(keyring.rootKeyBytes);
  const vaultZeroized = zeroizeBuffer(keyring.vaultKeyBytes);
  return { rootZeroized, vaultZeroized };
}
