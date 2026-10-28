import assert from 'node:assert/strict';
import test from 'node:test';
import { createPortalRateLimiter } from './portal-rate-limit.ts';

test('portal rate limiter allows five attempts and blocks the sixth within the window', () => {
  const limiter = createPortalRateLimiter({ maxAttempts: 5, windowMs: 60_000 });
  const key = 'owner@example.com:203.0.113.10';

  for (let i = 0; i < 5; i += 1) {
    assert.equal(limiter.check(key).allowed, true);
  }

  const blocked = limiter.check(key);
  assert.equal(blocked.allowed, false);
  assert.equal(blocked.retryAfterSeconds > 0, true);
});

test('portal rate limiter uses separate buckets for different keys', () => {
  const limiter = createPortalRateLimiter({ maxAttempts: 1, windowMs: 60_000 });

  assert.equal(limiter.check('owner@example.com:203.0.113.10').allowed, true);
  assert.equal(limiter.check('owner@example.com:203.0.113.11').allowed, true);
});
