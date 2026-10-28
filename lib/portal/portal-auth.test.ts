import test from 'node:test';
import assert from 'node:assert/strict';
import {
  BLACKTOWER_VAULT_INTERNAL_CAPABILITIES,
  COMMAND_CENTRE_NOTION_URL,
  PORTAL_WORKSPACES,
  filterWorkspaces,
  getApprovedShowcaseProducts,
  getPendingOwnerReviewProjects,
  getPreservedInternalWorkspaces,
  getVaultSubsystemRecords,
  sanitizeExternalHttpsUrl,
  setProjectVisibilityInList,
  validatePortalEmail,
  validatePortalPassword,
  validateRecoveryPassword,
  verifyAuthorizedPortalCredentials,
} from './portal-auth.ts';
import {
  issueSignedPortalSessionToken,
  verifySignedPortalSessionToken,
} from './portal-server-session.ts';

test('validatePortalEmail trims, lowercases, and rejects malformed addresses', () => {
  const valid = validatePortalEmail('  Operator@Blacktower.io  ');
  assert.equal(valid.valid, true);
  assert.equal(valid.normalizedEmail, 'operator@blacktower.io');

  const empty = validatePortalEmail('   ');
  assert.equal(empty.valid, false);

  const malformed = validatePortalEmail('not-an-email');
  assert.equal(malformed.valid, false);
});

test('validatePortalPassword enforces non-empty bounds', () => {
  assert.equal(validatePortalPassword('').valid, false);
  assert.equal(validatePortalPassword('StrongVaultSecret!2026').valid, true);
  assert.equal(validatePortalPassword('a'.repeat(129)).valid, false);
});

test('validateRecoveryPassword enforces minimum 12 chars and matching confirmation', () => {
  assert.equal(validateRecoveryPassword('short', 'short').valid, false);
  assert.equal(
    validateRecoveryPassword('ValidLongPass123!', 'DifferentPass123!').valid,
    false
  );
  assert.equal(
    validateRecoveryPassword('ValidLongPass123!', 'ValidLongPass123!').valid,
    true
  );
});

test('verifyAuthorizedPortalCredentials rejects invalid/short passwords and accepts valid operator credentials', () => {
  const rejected = verifyAuthorizedPortalCredentials('ops@blacktower.io', '123');
  assert.equal(rejected.ok, false);

  const accepted = verifyAuthorizedPortalCredentials(
    'ops@blacktower.io',
    'BlacktowerCommand2026!'
  );
  assert.equal(accepted.ok, true);
  if (accepted.ok) {
    assert.equal(accepted.user.email, 'ops@blacktower.io');
    assert.ok(accepted.user.uid.startsWith('bt_op_'));
  }
});

test('sanitizeExternalHttpsUrl allows clean https URLs and blocks unsafe protocols or embedded credentials', () => {
  assert.equal(
    sanitizeExternalHttpsUrl(COMMAND_CENTRE_NOTION_URL),
    COMMAND_CENTRE_NOTION_URL
  );
  assert.equal(sanitizeExternalHttpsUrl('javascript:alert(1)'), null);
  assert.equal(sanitizeExternalHttpsUrl('http://insecure.example.com'), null);
  assert.equal(
    sanitizeExternalHttpsUrl('https://user:pass@example.com/secret'),
    null
  );
});

test('Showcase architecture: BLACKTOWER VAULT is the sole approved showcase product; subsystems, pending projects, and Notion workspaces are separated', () => {
  assert.equal(PORTAL_WORKSPACES.length, 11);

  const showcase = getApprovedShowcaseProducts(PORTAL_WORKSPACES);
  const pendingReview = getPendingOwnerReviewProjects(PORTAL_WORKSPACES);
  const internalOnly = getPreservedInternalWorkspaces(PORTAL_WORKSPACES);
  const subsystems = getVaultSubsystemRecords(PORTAL_WORKSPACES);

  // 1. BLACKTOWER VAULT™ is the ONLY approved public showcase project
  assert.equal(showcase.length, 1);
  assert.equal(showcase[0].id, 'blacktower-vault');
  assert.equal(showcase[0].name, 'BLACKTOWER VAULT™');
  assert.equal(showcase[0].category, 'SECURITY & PRIVACY');
  assert.equal(showcase[0].description, 'Secure Password & Digital Identity Vault.');
  assert.equal(showcase[0].completionStatus, 'COMPLETED');
  assert.equal(showcase[0].authorizationStatus, 'APPROVED_FOR_DISPLAY');
  assert.equal(showcase[0].concept, 'PUBLIC SHOWCASE PROJECT');
  assert.equal(showcase[0].internalRoute, '/vault');
  assert.equal(showcase[0].url, '');

  // 2. Subsystems of BLACKTOWER VAULT™ are NOT promoted as independent showcase products
  assert.equal(subsystems.length, 3);
  assert.ok(
    subsystems.every(
      (s) =>
        s.visibility === 'vault_subsystem' &&
        (s.concept === 'SECURITY SUBSYSTEM' || s.concept === 'ENGINEERING TEST')
    )
  );

  // 3. Future projects are preserved under pending_owner_review (not marked completed or public)
  assert.equal(pendingReview.length, 2);
  assert.ok(
    pendingReview.every(
      (p) =>
        p.visibility === 'pending_owner_review' &&
        p.completionStatus === 'PENDING_OWNER_REVIEW' &&
        p.concept === 'PENDING OWNER REVIEW'
    )
  );

  // 4. Internal Notion workspaces are preserved under internal_only
  assert.equal(internalOnly.length, 5);
  assert.ok(
    internalOnly.every(
      (w) =>
        w.visibility === 'internal_only' &&
        w.completionStatus === 'INTERNAL_ONLY' &&
        w.concept === 'INTERNAL WORKSPACE'
    )
  );

  // 5. Internal Vault capability descriptors clearly distinguish PRODUCT FEATURE, SECURITY SUBSYSTEM, and ENGINEERING TEST
  assert.equal(BLACKTOWER_VAULT_INTERNAL_CAPABILITIES.length, 5);
});

test('setProjectVisibilityInList safely and reversibly updates visibility status without deleting records', () => {
  const promoted = setProjectVisibilityInList(
    PORTAL_WORKSPACES,
    'nexus-tracker',
    'approved_showcase'
  );
  assert.equal(getApprovedShowcaseProducts(promoted).length, 2);
  assert.equal(getPendingOwnerReviewProjects(promoted).length, 1);

  const restored = setProjectVisibilityInList(
    promoted,
    'nexus-tracker',
    'pending_owner_review'
  );
  assert.equal(getApprovedShowcaseProducts(restored).length, 1);
  assert.equal(getPendingOwnerReviewProjects(restored).length, 2);
});

test('Server-side HMAC-SHA256 session token signing and verification reject tampering and expiration', () => {
  const secret = 'test-server-hmac-secret-key-2026';
  const token = issueSignedPortalSessionToken(
    { uid: 'bt_op_12345678', email: 'blackmaster.blacktower@blacktowermail.com' },
    secret,
    3600
  );

  const verified = verifySignedPortalSessionToken(token, secret);
  assert.equal(verified.valid, true);
  if (verified.valid) {
    assert.equal(verified.uid, 'bt_op_12345678');
    assert.equal(verified.email, 'blackmaster.blacktower@blacktowermail.com');
  }

  // Reject wrong secret
  const wrongSecret = verifySignedPortalSessionToken(token, 'wrong-secret');
  assert.equal(wrongSecret.valid, false);

  // Reject tampered token payload
  const [payloadB64, sigHex] = token.split('.');
  const tamperedToken = `${payloadB64}a.${sigHex}`;
  assert.equal(verifySignedPortalSessionToken(tamperedToken, secret).valid, false);

  // Reject expired token
  const expiredToken = issueSignedPortalSessionToken(
    { uid: 'bt_op_12345678', email: 'blackmaster.blacktower@blacktowermail.com' },
    secret,
    -10
  );
  const expiredCheck = verifySignedPortalSessionToken(expiredToken, secret);
  assert.equal(expiredCheck.valid, false);
});

test('filterWorkspaces filters by name, tagline, description, and category case-insensitively', () => {
  const vaultMatches = filterWorkspaces(PORTAL_WORKSPACES, 'digital identity');
  assert.equal(vaultMatches.length, 1);
  assert.equal(vaultMatches[0].id, 'blacktower-vault');
});
