import { NextRequest, NextResponse } from 'next/server';
import { verifyOwnerCredentials } from '@/lib/portal/portal-server-auth';
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
  const secureCookie = process.env.NODE_ENV === 'production';

  if (mode === 'signout') {
    const res = NextResponse.json({ status: 'SIGNED_OUT' }, { status: 200 });
    res.cookies.set('bt_os_session', '', {
      httpOnly: true,
      secure: secureCookie,
      sameSite: 'lax',
      path: '/',
      maxAge: 0,
    });
    return res;
  }

  if (mode === 'recover') {
    return NextResponse.json(
      {
        error: 'PASSWORD_RECOVERY_NOT_CONFIGURED',
        message:
          'Password recovery is disabled until a verified recovery provider is configured. No recovery message was sent.',
      },
      { status: 501 }
    );
  }

  let signingSecret: string;
  try {
    signingSecret = resolvePortalSigningSecret(process.env);
  } catch {
    return NextResponse.json(
      {
        error: 'PORTAL_AUTH_CONFIG_MISSING',
        message:
          'Portal authentication is unavailable because the required server authentication configuration is missing.',
      },
      { status: 503 }
    );
  }

  const verified = verifyOwnerCredentials(body.email, body.password, process.env);
  if (!verified.ok) {
    return NextResponse.json({ error: verified.error }, { status: 401 });
  }

  if (isDatabaseConfigured()) {
    try {
      await getOrCreateUser(verified.user.uid, verified.user.email);
    } catch {
      // Authentication remains valid; database internals are never disclosed.
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
    secure: secureCookie,
    sameSite: 'lax',
    path: '/',
    maxAge: 60 * 60 * 12,
  });

  return response;
}
