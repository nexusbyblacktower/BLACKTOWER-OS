import assert from 'node:assert/strict';
import test from 'node:test';
import {
  createScryptPasswordHash,
  verifyOwnerCredentials,
} from './portal-server-auth.ts';

const TEST_ENV = {
  PORTAL_OWNER_EMAIL: 'owner@example.com',
  PORTAL_OWNER_PASSWORD_HASH:
    'scrypt$32768$8$1$YmxhY2t0b3dlci10ZXN0LXNhbHQtMjAyNg$Fx-BoLFvyMQTmCEngaqeofSoVP6iWrEk9V7YlZKqGb-gXhcNt6nUWOWMVVK2-75gLXX6kztbwcHv9gYyTDQVdg',
};

test('portal authentication rejects an incorrect password', () => {
  const result = verifyOwnerCredentials(
    'owner@example.com',
    'definitely-not-the-owner-password',
    TEST_ENV
  );

  assert.equal(result.ok, false);
});

test('portal authentication rejects a short password', () => {
  const result = verifyOwnerCredentials('owner@example.com', '12345', TEST_ENV);

  assert.equal(result.ok, false);
});

test('portal authentication accepts the configured owner credential', () => {
  const result = verifyOwnerCredentials(
    'owner@example.com',
    'test-password-123456',
    TEST_ENV
  );

  assert.equal(result.ok, true);
});

test('password hashing produces a verifiable scrypt envelope', () => {
  const hash = createScryptPasswordHash('test-password-123456');
  const result = verifyOwnerCredentials('owner@example.com', 'test-password-123456', {
    PORTAL_OWNER_EMAIL: 'owner@example.com',
    PORTAL_OWNER_PASSWORD_HASH: hash,
  });

  assert.equal(result.ok, true);
});

test('owner email comparison is case-insensitive', () => {
  const result = verifyOwnerCredentials(
    'OWNER@EXAMPLE.COM',
    'test-password-123456',
    TEST_ENV
  );

  assert.equal(result.ok, true);
});
