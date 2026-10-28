import assert from 'node:assert/strict';
import test from 'node:test';
import { verifyAuthorizedPortalCredentials } from './portal-auth.ts';

test('portal authentication rejects an incorrect password', () => {
  const result = verifyAuthorizedPortalCredentials(
    'owner@example.com',
    'definitely-not-the-owner-password'
  );

  assert.equal(result.ok, false);
});

test('portal authentication rejects a short password', () => {
  const result = verifyAuthorizedPortalCredentials('owner@example.com', '12345');

  assert.equal(result.ok, false);
});

test('portal authentication accepts the configured owner credential', () => {
  const result = verifyAuthorizedPortalCredentials(
    process.env.PORTAL_OWNER_EMAIL ?? 'owner@example.com',
    process.env.PORTAL_OWNER_PASSWORD ?? ''
  );

  assert.equal(result.ok, true);
});
