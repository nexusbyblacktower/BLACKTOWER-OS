import { NextRequest, NextResponse } from 'next/server';
import {
  validatePortalEmail,
  verifyAuthorizedPortalCredentials,
} from '@/lib/portal/portal-auth';
import {
  issueSignedPortalSessionToken,
  resolvePortalSigningSecret,
} from '@/lib/portal/portal-server-session';
import { isDatabaseConfigured } from '../../../../src/db/index';
import { getOrCreateUser } from '../../../../src/db/users';

export async function POST(req: NextRequest) {
  let body: Record<string, unknown>;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json(
      { error: 'Access service is unavailable. Please try again later.' },
      { status: 400 }
    );
  }

  const mode = typeof body.mode === 'string' ? body.mode : 'signin';

  if (mode === 'signout') {
    const res = NextResponse.json({ status: 'SIGNED_OUT' }, { status: 200 });
    res.cookies.set('bt_os_session', '', {
      httpOnly: true,
      secure: true,
      sameSite: 'none',
      path: '/',
      maxAge: 0,
    });
    return res;
  }

  if (mode === 'recover') {
    const emailCheck = validatePortalEmail(body.email);
    if (!emailCheck.valid) {
      return NextResponse.json({ error: emailCheck.error }, { status: 400 });
    }
    return NextResponse.json(
      {
        status: 'RECOVERY_SENT',
        message:
          'If this email belongs to an authorized account, a recovery link will arrive shortly.',
      },
      { status: 200 }
    );
  }

  // Fail closed if PORTAL_SIGNING_SECRET is missing or invalid
  let signingSecret: string;
  try {
    signingSecret = resolvePortalSigningSecret(process.env);
  } catch {
    return NextResponse.json(
      {
        error: 'PORTAL_AUTH_CONFIG_MISSING',
        message:
          'Portal authentication is unavailable because PORTAL_SIGNING_SECRET is not configured on the server.',
      },
      { status: 503 }
    );
  }

  const verified = verifyAuthorizedPortalCredentials(body.email, body.password);
  if (!verified.ok) {
    return NextResponse.json({ error: verified.error }, { status: 401 });
  }

  // Upsert operator identity into Neon PostgreSQL users table (zero password material stored)
  if (isDatabaseConfigured()) {
    try {
      await getOrCreateUser(verified.user.uid, verified.user.email);
    } catch {
      // Fail gracefully if DB connection is warming up; never leak SQL internals
    }
  }

  const sessionToken = issueSignedPortalSessionToken(
    { uid: verified.user.uid, email: verified.user.email },
    signingSecret
  );

  const response = NextResponse.json(
    {
      status: 'VERIFIED',
      user: {
        ...verified.user,
        sessionToken,
      },
    },
    { status: 200 }
  );

  response.cookies.set('bt_os_session', sessionToken, {
    httpOnly: true,
    secure: true,
    sameSite: 'none',
    path: '/',
    maxAge: 60 * 60 * 12,
  });

  return response;
}
