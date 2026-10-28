import {
  createHash,
  randomBytes,
  scryptSync,
  timingSafeEqual,
} from 'node:crypto';
import type { PortalSessionUser } from './portal-auth.ts';

const SCRYPT_N = 32_768;
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const SCRYPT_KEY_LENGTH = 64;
const SCRYPT_MAXMEM = 64 * 1024 * 1024;
const HASH_PREFIX = 'scrypt';

interface PortalAuthEnvironment {
  PORTAL_OWNER_EMAIL?: string;
  PORTAL_OWNER_PASSWORD_HASH?: string;
}

function normalizeEmail(rawEmail: unknown): string | null {
  if (typeof rawEmail !== 'string') return null;
  const email = rawEmail.trim().toLowerCase();
  if (!email || email.length > 255 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return null;
  }
  return email;
}

function validatePassword(rawPassword: unknown): rawPassword is string {
  return (
    typeof rawPassword === 'string' &&
    rawPassword.length >= 12 &&
    rawPassword.length <= 128
  );
}

function parseScryptHash(encoded: string): {
  n: number;
  r: number;
  p: number;
  salt: Buffer;
  digest: Buffer;
} | null {
  const parts = encoded.split('$');
  if (parts.length !== 6 || parts[0] !== HASH_PREFIX) return null;

  const n = Number(parts[1]);
  const r = Number(parts[2]);
  const p = Number(parts[3]);
  if (!Number.isSafeInteger(n) || !Number.isSafeInteger(r) || !Number.isSafeInteger(p)) {
    return null;
  }
  if (n < 16_384 || n > 262_144 || r < 1 || r > 32 || p < 1 || p > 8) {
    return null;
  }

  try {
    const salt = Buffer.from(parts[4], 'base64url');
    const digest = Buffer.from(parts[5], 'base64url');
    if (salt.length < 16 || salt.length > 64 || digest.length !== SCRYPT_KEY_LENGTH) {
      return null;
    }
    return { n, r, p, salt, digest };
  } catch {
    return null;
  }
}

export function createScryptPasswordHash(password: string): string {
  if (!validatePassword(password)) {
    throw new Error('Password must be between 12 and 128 characters.');
  }

  const salt = randomBytes(24);
  const digest = scryptSync(password, salt, SCRYPT_KEY_LENGTH, {
    N: SCRYPT_N,
    r: SCRYPT_R,
    p: SCRYPT_P,
    maxmem: SCRYPT_MAXMEM,
  });

  return [
    HASH_PREFIX,
    SCRYPT_N,
    SCRYPT_R,
    SCRYPT_P,
    salt.toString('base64url'),
    digest.toString('base64url'),
  ].join('$');
}

export function verifyOwnerCredentials(
  rawEmail: unknown,
  rawPassword: unknown,
  env: PortalAuthEnvironment = process.env
): { ok: true; user: PortalSessionUser } | { ok: false; error: string } {
  const email = normalizeEmail(rawEmail);
  if (!email || !validatePassword(rawPassword)) {
    return { ok: false, error: 'Invalid email or password.' };
  }

  const configuredEmail = normalizeEmail(env.PORTAL_OWNER_EMAIL);
  const encodedHash = env.PORTAL_OWNER_PASSWORD_HASH?.trim();
  if (!configuredEmail || !encodedHash) {
    return { ok: false, error: 'Portal authentication is not configured.' };
  }

  const parsed = parseScryptHash(encodedHash);
  if (!parsed) {
    return { ok: false, error: 'Portal authentication is not configured.' };
  }

  let passwordDigest: Buffer;
  try {
    passwordDigest = scryptSync(rawPassword, parsed.salt, parsed.digest.length, {
      N: parsed.n,
      r: parsed.r,
      p: parsed.p,
      maxmem: SCRYPT_MAXMEM,
    });
  } catch {
    return { ok: false, error: 'Invalid email or password.' };
  }

  const emailDigest = createHash('sha256').update(email).digest();
  const configuredEmailDigest = createHash('sha256')
    .update(configuredEmail)
    .digest();
  const emailMatches = timingSafeEqual(emailDigest, configuredEmailDigest);
  const passwordMatches = timingSafeEqual(passwordDigest, parsed.digest);

  if (!emailMatches || !passwordMatches) {
    return { ok: false, error: 'Invalid email or password.' };
  }

  const uidDigest = createHash('sha256').update(configuredEmail).digest('hex');

  return {
    ok: true,
    user: {
      uid: `bt_op_${uidDigest}`,
      email: configuredEmail,
      verifiedAt: new Date().toISOString(),
    },
  };
}
