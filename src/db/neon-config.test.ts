import test from 'node:test';
import assert from 'node:assert/strict';
import {
  createPool,
  isDatabaseConfigured,
  resolveNeonPoolConfig,
} from './index.ts';
import {
  issueSignedPortalSessionToken,
  resolvePortalSigningSecret,
  verifySignedPortalSessionToken,
} from '../../lib/portal/portal-server-session.ts';
import {
  decryptVaultItem,
  encryptVaultItem,
  initializeVaultHierarchy,
  zeroizeKeyring,
} from '../../lib/crypto/vault-crypto.ts';

const SYNTHETIC_NEON_URL =
  'postgresql://synthetic_role:synthetic_secret@ep-synthetic-pooler.us-east-2.aws.neon.tech/blacktower_vault?sslmode=require';
const SYNTHETIC_PORTAL_SECRET =
  'bt_portal_signing_secret_synthetic_test_key_2026_v1';

test('DATABASE_URL configured -> Neon pool initializes with enforced TLS verification', async () => {
  const syntheticEnv: Record<string, string | undefined> = {
    DATABASE_URL: SYNTHETIC_NEON_URL,
  };

  assert.equal(isDatabaseConfigured(syntheticEnv), true);

  const config = resolveNeonPoolConfig(syntheticEnv);
  assert.equal(config.connectionString, SYNTHETIC_NEON_URL);
  assert.deepEqual(config.ssl, { rejectUnauthorized: true });

  const pool = createPool(syntheticEnv);
  assert.ok(pool);
  await pool.end();
});

test('DATABASE_URL missing -> application fails closed immediately', () => {
  const emptyEnv: Record<string, string | undefined> = {};

  assert.equal(isDatabaseConfigured(emptyEnv), false);

  assert.throws(
    () => resolveNeonPoolConfig(emptyEnv),
    /FATAL_DATABASE_CONFIG_MISSING/
  );
  assert.throws(() => createPool(emptyEnv), /FATAL_DATABASE_CONFIG_MISSING/);
});

test('Cloud SQL variables present without DATABASE_URL -> application STILL fails closed (zero Cloud SQL fallback)', () => {
  const legacyCloudSqlEnv: Record<string, string | undefined> = {
    ['SQL_' + 'HOST']: '10.0.0.1',
    ['SQL_' + 'USER']: 'legacy_user',
    ['SQL_' + 'PASSWORD']: 'legacy_pass',
    ['SQL_' + 'DB_NAME']: 'legacy_db',
    ['SQL_' + 'ADMIN_USER']: 'legacy_admin',
    ['SQL_' + 'ADMIN_PASSWORD']: 'legacy_admin_pass',
  };

  assert.equal(isDatabaseConfigured(legacyCloudSqlEnv), false);

  assert.throws(
    () => resolveNeonPoolConfig(legacyCloudSqlEnv),
    /FATAL_DATABASE_CONFIG_MISSING/
  );
  assert.throws(
    () => createPool(legacyCloudSqlEnv),
    /FATAL_DATABASE_CONFIG_MISSING/
  );
});

test('Duplicate non-canonical Neon variable cannot override DATABASE_URL or satisfy configuration when DATABASE_URL is missing', () => {
  const competingNeonVarKey = ['NEON', 'DATABASE', 'URL'].join('_');
  const competingUrl =
    'postgresql://other:other@ep-competing.us-east-2.aws.neon.tech/otherdb?sslmode=require';

  // 1. Without DATABASE_URL, competing variable still fails closed
  const onlyCompetingEnv: Record<string, string | undefined> = {
    [competingNeonVarKey]: competingUrl,
  };
  assert.equal(isDatabaseConfigured(onlyCompetingEnv), false);
  assert.throws(
    () => resolveNeonPoolConfig(onlyCompetingEnv),
    /FATAL_DATABASE_CONFIG_MISSING/
  );

  // 2. With DATABASE_URL present, competing variable cannot override canonical DATABASE_URL
  const bothEnv: Record<string, string | undefined> = {
    DATABASE_URL: SYNTHETIC_NEON_URL,
    [competingNeonVarKey]: competingUrl,
  };
  const resolved = resolveNeonPoolConfig(bothEnv);
  assert.equal(resolved.connectionString, SYNTHETIC_NEON_URL);
  assert.notEqual(resolved.connectionString, competingUrl);
});

test('Portal authentication fails closed when PORTAL_SIGNING_SECRET is missing', () => {
  const envWithoutPortalSecret: Record<string, string | undefined> = {
    DATABASE_URL: SYNTHETIC_NEON_URL,
  };

  assert.throws(
    () => resolvePortalSigningSecret(envWithoutPortalSecret),
    /FATAL_AUTH_CONFIG_MISSING/
  );
  assert.throws(
    () =>
      issueSignedPortalSessionToken(
        { uid: 'bt_op_1', email: 'operator@blacktower.internal' },
        ''
      ),
    /FATAL_AUTH_CONFIG_MISSING/
  );
  const verifyEmpty = verifySignedPortalSessionToken('fake.token', '');
  assert.equal(verifyEmpty.valid, false);
});

test('Portal authentication strictly rejects DATABASE_URL or PostgreSQL URIs as a signing key', () => {
  // 1. Passing DATABASE_URL as PORTAL_SIGNING_SECRET fails closed with SECURITY_DOMAIN_VIOLATION
  const domainViolationEnv: Record<string, string | undefined> = {
    DATABASE_URL: SYNTHETIC_NEON_URL,
    PORTAL_SIGNING_SECRET: SYNTHETIC_NEON_URL,
  };
  assert.throws(
    () => resolvePortalSigningSecret(domainViolationEnv),
    /SECURITY_DOMAIN_VIOLATION/
  );

  // 2. Direct token issuance with a PostgreSQL connection string fails closed
  assert.throws(
    () =>
      issueSignedPortalSessionToken(
        { uid: 'bt_op_1', email: 'operator@blacktower.internal' },
        SYNTHETIC_NEON_URL
      ),
    /SECURITY_DOMAIN_VIOLATION/
  );

  // 3. Direct token verification with a PostgreSQL connection string fails closed
  const verifyResult = verifySignedPortalSessionToken(
    'eyJ1aWQiOiJidF9vcF8xIn0.0000000000000000000000000000000000000000000000000000000000000000',
    SYNTHETIC_NEON_URL
  );
  assert.equal(verifyResult.valid, false);
  assert.ok(verifyResult.reason.includes('SECURITY_DOMAIN_VIOLATION'));

  // 4. Independent PORTAL_SIGNING_SECRET succeeds
  const validEnv: Record<string, string | undefined> = {
    DATABASE_URL: SYNTHETIC_NEON_URL,
    PORTAL_SIGNING_SECRET: SYNTHETIC_PORTAL_SECRET,
  };
  const resolvedSecret = resolvePortalSigningSecret(validEnv);
  assert.equal(resolvedSecret, SYNTHETIC_PORTAL_SECRET);
  const token = issueSignedPortalSessionToken(
    { uid: 'bt_op_1', email: 'operator@blacktower.internal' },
    resolvedSecret
  );
  const verified = verifySignedPortalSessionToken(token, resolvedSecret);
  assert.equal(verified.valid, true);
});

test('Zero-knowledge boundary: favorite status is encrypted inside AES-256-GCM payload and never exposed on envelope', async () => {
  const { keyring } = await initializeVaultHierarchy({
    masterPassword: 'SyntheticTestMasterPassword!2026',
    kdfProfile: 'argon2id-v1.3-fast',
  });

  try {
    const envelope = await encryptVaultItem({
      keyring,
      recordType: 'password',
      favorite: true,
      payload: {
        title: 'Synthetic Vault Item',
        username: 'user@blacktower.internal',
        password: 'SyntheticItemPassword!99',
        folder: 'Infrastructure',
      },
    });

    // Outer envelope sent to server/Neon never exposes favorite=true in plaintext
    assert.equal(envelope.favorite, false);

    // Decrypting with the Vault Keyring restores favorite=true from the authenticated payload ciphertext
    const decrypted = await decryptVaultItem(keyring, envelope);
    assert.equal(decrypted.favorite, true);
    assert.equal(decrypted.data.folder, 'Infrastructure');
  } finally {
    zeroizeKeyring(keyring);
  }
});
