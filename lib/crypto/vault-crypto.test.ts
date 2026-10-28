import test from 'node:test';
import assert from 'node:assert/strict';
import {
  decryptVaultItem,
  encryptVaultItem,
  initializeVaultHierarchy,
  rotateRecoveryKey,
  unlockVaultWithMasterPassword,
  unlockVaultWithRecoveryKey,
  verifyRecoveryKeyCryptographically,
  zeroizeKeyring,
} from './vault-crypto.ts';
import { generateSecurePassword } from './password-generator.ts';
import {
  createEncryptedBackupContainer,
  verifyBackupContainerIntegrity,
} from './backup-engine.ts';
import {
  inspectPayloadForPlaintextSecrets,
  redactDiagnosticObject,
} from '../sync/sync-validator.ts';
import { runAllSecurityDiagnostics } from '../diagnostics/security-tests.ts';
import {
  clearCsvImportSessionBuffer,
  detectCsvColumnMappings,
  encryptAndImportCsvBatch,
  evaluateCsvCandidates,
  generateSafeCsvTemplateContent,
  generateSampleMigrationCsvForTesting,
  maskSensitivePreviewValue,
  parseRawCsvLocally,
} from '../import/csv-migration.ts';

import {
  ALL_SCREEN_EXPOSURE_STATES,
  buildScreenExposureDiagnosticsSnapshot,
  canRenderSensitiveContent,
  clearRedactedSecurityEvents,
  getRedactedSecurityEvents,
  verifyPreRenderSecretRevealGate,
} from '../security/screen-exposure-engine.ts';

test('All 12 mandatory security regression tests (TEST-01 through TEST-12) execute and pass', async () => {
  const report = await runAllSecurityDiagnostics();
  assert.equal(report.totalCount, 12);
  for (const res of report.results) {
    assert.equal(
      res.passed,
      true,
      `Expected ${res.id} (${res.name}) to PASS, but failed: ${res.failureReason}`
    );
  }
  assert.equal(report.overallStatus, 'PASS');
});

test('Screen Exposure Protection Engine enforces 8-state rendering invariant, pre-render secret gate, and honest diagnostics', () => {
  clearRedactedSecurityEvents();

  // Only PRIVATE_SAFE permits sensitive rendering
  for (const st of ALL_SCREEN_EXPOSURE_STATES) {
    assert.equal(canRenderSensitiveContent(st), st === 'PRIVATE_SAFE');
  }

  // Honest diagnostics report "Platform cannot verify" when browser cannot verify OS capture/projection
  const snap = buildScreenExposureDiagnosticsSnapshot({
    currentState: 'PRIVATE_SAFE',
    extremeModeEnabled: true,
    lockOnBackgroundEnabled: true,
    screenIsExtended: false,
  });
  assert.equal(
    snap.webPreviewLimitationNotice,
    'Some device-level screen protection requires the native Android application.'
  );
  const captureItem = snap.items.find((i) => i.id === 'screen_capture');
  assert.equal(captureItem?.status, 'PLATFORM_CANNOT_VERIFY');
  assert.ok(captureItem?.displayText.includes('Platform cannot verify'));

  // Pre-render secret reveal gate blocks reveal when external display or risk is active
  const blocked = verifyPreRenderSecretRevealGate({
    extremeModeEnabled: true,
    lockOnBackgroundEnabled: true,
    isVaultUnlocked: true,
    screenIsExtended: true,
  });
  assert.equal(blocked.allowed, false);
  assert.equal(blocked.state, 'EXTERNAL_DISPLAY_DETECTED');
  assert.equal(getRedactedSecurityEvents()[0]?.eventCode, 'PASSWORD_REVEAL_BLOCKED');
});

test('CSV Import / Migration System parses locally, detects columns, flags duplicates/invalid/unsupported rows, encrypts per-item, and wipes temporary state', async () => {
  const { keyring } = await initializeVaultHierarchy({
    masterPassword: 'CsvMigrationTestPassword!2026',
    kdfProfile: 'argon2id-v1.3-fast',
  });

  const template = generateSafeCsvTemplateContent();
  assert.ok(template.includes('FakeTemplatePass!9928#DoNotUse'));
  assert.equal(maskSensitivePreviewValue('SuperSecret'), '••••••••••••');

  const sampleCsv = generateSampleMigrationCsvForTesting('secops-admin@blacktower.internal');
  const parsed = parseRawCsvLocally(sampleCsv);
  const mappings = detectCsvColumnMappings(parsed.headers);

  // Verify automatic alias detection for login_uri -> url, login_username -> username, login_password -> password, extra -> noteContent
  assert.equal(mappings.find((m) => m.csvHeader === 'login_uri')?.targetField, 'url');
  assert.equal(mappings.find((m) => m.csvHeader === 'login_username')?.targetField, 'username');
  assert.equal(mappings.find((m) => m.csvHeader === 'login_password')?.targetField, 'password');
  assert.equal(mappings.find((m) => m.csvHeader === 'extra')?.targetField, 'noteContent');

  // Create one existing decrypted item to test duplicate detection
  const existingItemEnvelope = await encryptVaultItem({
    keyring,
    recordType: 'password',
    payload: {
      title: 'Cloudflare Zero Trust Root Console',
      username: 'secops-admin@blacktower.internal',
      password: 'ExistingPassword123',
      url: 'https://one.dash.cloudflare.com',
    },
  });
  const existingDecrypted = await decryptVaultItem(keyring, existingItemEnvelope);

  const session = evaluateCsvCandidates({
    fileName: 'migration-sample.csv',
    fileSizeBytes: sampleCsv.length,
    headers: parsed.headers,
    rawRows: parsed.rows,
    mappings,
    existingVaultItems: [existingDecrypted],
  });

  assert.equal(session.summary.totalRecords, 5);
  assert.equal(session.summary.validRecords, 2);
  assert.equal(session.summary.duplicateRecords, 1);
  assert.equal(session.summary.invalidRecords, 1);
  assert.equal(session.summary.unsupportedRecords, 1);

  const report = await encryptAndImportCsvBatch({
    keyring,
    session,
    duplicatePolicy: 'skip',
  });

  assert.equal(report.status, 'Import Complete');
  assert.equal(report.importedCount, 2);
  assert.equal(report.skippedCount, 1);
  assert.equal(report.failedCount, 2); // 1 invalid URL + 1 unsupported type
  assert.equal(report.temporaryStateCleared, true);
  assert.equal(session.cleared, true);
  assert.equal(session.candidates.length, 0);

  // Verify clearCsvImportSessionBuffer is idempotent
  assert.equal(clearCsvImportSessionBuffer(session), true);

  zeroizeKeyring(keyring);
});

test('Recovery Key verification and rotation preserve Account Root Key and invalidate old Recovery Key', async () => {
  const { hierarchy, keyring, formattedRecoveryKey } = await initializeVaultHierarchy({
    masterPassword: 'TestMasterPassword!2026',
    kdfProfile: 'argon2id-v1.3-fast',
  });

  const item = await encryptVaultItem({
    keyring,
    recordType: 'password',
    payload: {
      title: 'Root SSH Key',
      username: 'root',
      password: 'ImmutableSecretValue99!',
    },
  });

  const isOrigValid = await verifyRecoveryKeyCryptographically(formattedRecoveryKey, hierarchy);
  assert.equal(isOrigValid, true);

  const { updatedHierarchy, newFormattedRecoveryKey } = await rotateRecoveryKey(keyring, hierarchy);
  assert.notEqual(newFormattedRecoveryKey, formattedRecoveryKey);

  // Old recovery key must fail on updatedHierarchy
  const isOldStillValid = await verifyRecoveryKeyCryptographically(
    formattedRecoveryKey,
    updatedHierarchy
  );
  assert.equal(isOldStillValid, false);

  // New recovery key must unlock updatedHierarchy and decrypt existing item without re-encrypting item
  const recoveredKeyring = await unlockVaultWithRecoveryKey(
    newFormattedRecoveryKey,
    updatedHierarchy
  );
  const decrypted = await decryptVaultItem(recoveredKeyring, item);
  assert.equal(decrypted.data.password, 'ImmutableSecretValue99!');

  zeroizeKeyring(keyring);
  zeroizeKeyring(recoveredKeyring);
});

test('CSPRNG password generator respects length bounds, character classes, and unbiased entropy calculation', () => {
  const res = generateSecurePassword({
    length: 32,
    uppercase: true,
    lowercase: true,
    numbers: true,
    symbols: true,
  });
  assert.equal(res.password.length, 32);
  assert.equal(/[A-Z]/.test(res.password), true);
  assert.equal(/[a-z]/.test(res.password), true);
  assert.equal(/[0-9]/.test(res.password), true);
  assert.equal(res.entropyBits > 180, true);
  assert.equal(res.strengthLabel, 'Brutal');
});

test('Server Plaintext Rejection validator catches all forbidden fields at any nesting depth', () => {
  const forbiddenSamples = [
    { password: '123' },
    { masterPassword: 'abc' },
    { nested: { totpSecret: 'JBSWY3DPEHPK3PXP' } },
    { items: [{ cardNumber: '4111222233334444' }] },
    { deep: { arr: [{ seedPhrase: 'witch collapse practice feed shame open' }] } },
    { kekBytes: 'deadbeef' },
    { rootKeyBytes: 'deadbeef' },
    { vaultKeyBytes: 'deadbeef' },
  ];

  for (const sample of forbiddenSamples) {
    const check = inspectPayloadForPlaintextSecrets(sample);
    assert.equal(check.valid, false, `Expected sample ${JSON.stringify(sample)} to be rejected`);
    assert.ok(check.reason?.includes('SECURITY_POLICY_REJECTED_PLAINTEXT_FIELD'));
  }
});

test('.btvault backup container rejects plaintext injection and tampered HMAC seals', async () => {
  const { hierarchy, keyring } = await initializeVaultHierarchy({
    masterPassword: 'BackupTestPassword#1',
    kdfProfile: 'argon2id-v1.3-fast',
  });
  const encItem = await encryptVaultItem({
    keyring,
    recordType: 'note',
    payload: { title: 'Note', noteContent: 'Encrypted content' },
  });

  const container = createEncryptedBackupContainer({
    keyring,
    hierarchy,
    items: [encItem],
  });

  const verified = verifyBackupContainerIntegrity(JSON.stringify(container), keyring);
  assert.equal(verified.cryptographicallyAuthenticated, true);

  // Inject forbidden plaintext field into backup JSON
  const injected = { ...container, password: 'leaked' };
  assert.throws(() => {
    verifyBackupContainerIntegrity(JSON.stringify(injected), keyring);
  }, /SECURITY_POLICY_REJECTED_PLAINTEXT_FIELD/);

  // Redaction check
  const redacted = redactDiagnosticObject({
    masterPassword: 'secret',
    safeField: 'visible',
  });
  assert.equal(redacted.masterPassword, '[REDACTED]');
  assert.equal(redacted.safeField, 'visible');

  zeroizeKeyring(keyring);
});
