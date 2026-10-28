import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';

/**
 * Resolves and validates the dedicated server-only PORTAL_SIGNING_SECRET used
 * exclusively for BLACKTOWER OS™ HMAC-SHA256 operator session tokens.
 *
 * Fails closed if PORTAL_SIGNING_SECRET is missing or too short.
 * Explicitly prohibits reusing DATABASE_URL or any PostgreSQL connection URI
 * across security domains.
 */
export function resolvePortalSigningSecret(
  env: Record<string, string | undefined> = process.env
): string {
  const rawSecret = env.PORTAL_SIGNING_SECRET?.trim();
  if (!rawSecret) {
    throw new Error(
      'FATAL_AUTH_CONFIG_MISSING: PORTAL_SIGNING_SECRET is required for BLACKTOWER OS session signing. Fail-closed policy active.'
    );
  }
  if (rawSecret.length < 16) {
    throw new Error(
      'FATAL_AUTH_CONFIG_INVALID: PORTAL_SIGNING_SECRET must be at least 16 characters.'
    );
  }
  if (
    /^postgres(ql)?:\/\//i.test(rawSecret) ||
    (env.DATABASE_URL && rawSecret === env.DATABASE_URL.trim())
  ) {
    throw new Error(
      'SECURITY_DOMAIN_VIOLATION: PORTAL_SIGNING_SECRET must be an independent secret and must never reuse DATABASE_URL or database credentials.'
    );
  }
  return rawSecret;
}

function assertValidSigningKeyMaterial(secretKey: string): string {
  if (!secretKey || typeof secretKey !== 'string') {
    throw new Error(
      'FATAL_AUTH_CONFIG_MISSING: PORTAL_SIGNING_SECRET is required.'
    );
  }
  const trimmed = secretKey.trim();
  if (trimmed.length < 16) {
    throw new Error(
      'FATAL_AUTH_CONFIG_INVALID: PORTAL_SIGNING_SECRET must be at least 16 characters.'
    );
  }
  if (/^postgres(ql)?:\/\//i.test(trimmed)) {
    throw new Error(
      'SECURITY_DOMAIN_VIOLATION: Database connection strings cannot be used as portal session signing keys.'
    );
  }
  return trimmed;
}

/**
 * Pure HMAC-SHA256 server session token signing & verification.
 * Used exclusively by server routes (/api/portal/auth and /api/portal/projects)
 * to enforce mandatory server-side authorization before releasing internal workspace records.
 */
export function issueSignedPortalSessionToken(
  user: { uid: string; email: string },
  secretKey: string,
  ttlSeconds = 60 * 60 * 12
): string {
  const validatedSecret = assertValidSigningKeyMaterial(secretKey);
  const nowSec = Math.floor(Date.now() / 1000);
  const payloadObj = {
    uid: user.uid,
    email: user.email,
    role: 'owner_operator',
    iat: nowSec,
    exp: nowSec + ttlSeconds,
  };
  const payloadBase64 = Buffer.from(JSON.stringify(payloadObj), 'utf8').toString(
    'base64url'
  );
  const macBytes = hmac(
    sha256,
    new TextEncoder().encode(validatedSecret),
    new TextEncoder().encode(`BT_OS_SESSION_V1.${payloadBase64}`)
  );
  const macHex = Array.from(macBytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
  return `${payloadBase64}.${macHex}`;
}

export function verifySignedPortalSessionToken(
  token: string | null | undefined,
  secretKey: string
): { valid: true; uid: string; email: string } | { valid: false; reason: string } {
  let validatedSecret: string;
  try {
    validatedSecret = assertValidSigningKeyMaterial(secretKey);
  } catch (err) {
    return {
      valid: false,
      reason: err instanceof Error ? err.message : 'INVALID_SIGNING_SECRET',
    };
  }

  if (!token || typeof token !== 'string') {
    return { valid: false, reason: 'MISSING_SESSION_TOKEN' };
  }
  const parts = token.trim().split('.');
  if (parts.length !== 2) {
    return { valid: false, reason: 'MALFORMED_SESSION_TOKEN' };
  }
  const [payloadBase64, providedMacHex] = parts;
  if (!payloadBase64 || !providedMacHex || providedMacHex.length !== 64) {
    return { valid: false, reason: 'INVALID_TOKEN_FORMAT' };
  }

  const expectedMacBytes = hmac(
    sha256,
    new TextEncoder().encode(validatedSecret),
    new TextEncoder().encode(`BT_OS_SESSION_V1.${payloadBase64}`)
  );
  const expectedMacHex = Array.from(expectedMacBytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');

  // Constant-time comparison
  let diff = 0;
  for (let i = 0; i < expectedMacHex.length; i++) {
    diff |= expectedMacHex.charCodeAt(i) ^ providedMacHex.charCodeAt(i);
  }
  if (diff !== 0) {
    return { valid: false, reason: 'SIGNATURE_MISMATCH' };
  }

  try {
    const decoded = JSON.parse(
      Buffer.from(payloadBase64, 'base64url').toString('utf8')
    ) as {
      uid?: string;
      email?: string;
      exp?: number;
    };
    const nowSec = Math.floor(Date.now() / 1000);
    if (!decoded.exp || decoded.exp < nowSec) {
      return { valid: false, reason: 'SESSION_EXPIRED' };
    }
    if (!decoded.uid || !decoded.email) {
      return { valid: false, reason: 'INVALID_SESSION_CLAIMS' };
    }
    return { valid: true, uid: decoded.uid, email: decoded.email };
  } catch {
    return { valid: false, reason: 'CORRUPTED_SESSION_PAYLOAD' };
  }
}
