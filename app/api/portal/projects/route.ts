import { NextRequest, NextResponse } from 'next/server';
import {
  setPortalProjectVisibility,
  syncAndListPortalProjects,
} from '../../../../src/db/portal-projects-repository';
import {
  COMMAND_CENTRE_NOTION_URL,
  getApprovedShowcaseProducts,
  type PortalProjectVisibility,
} from '@/lib/portal/portal-auth';
import {
  resolvePortalSigningSecret,
  verifySignedPortalSessionToken,
} from '@/lib/portal/portal-server-session';

function authenticatePortalOperatorRequest(req: NextRequest): {
  authorized: boolean;
  uid?: string;
  email?: string;
} {
  let signingSecret: string;
  try {
    signingSecret = resolvePortalSigningSecret(process.env);
  } catch {
    // Fail closed when PORTAL_SIGNING_SECRET is not configured
    return { authorized: false };
  }

  const authHeader = req.headers.get('authorization');
  const bearerToken =
    authHeader && authHeader.startsWith('Bearer ')
      ? authHeader.slice('Bearer '.length).trim()
      : null;
  const cookieToken = req.cookies.get('bt_os_session')?.value || null;
  const token = bearerToken || cookieToken;

  const verified = verifySignedPortalSessionToken(token, signingSecret);
  if (!verified.valid) {
    return { authorized: false };
  }
  return {
    authorized: true,
    uid: verified.uid,
    email: verified.email,
  };
}

/**
 * GET /api/portal/projects
 *
 * Enforces mandatory server-side authorization:
 * - Default / public showcase (`?scope=showcase` or unauthenticated):
 *   Returns ONLY `approved_showcase` projects (BLACKTOWER VAULT™) and strips all internal Notion links.
 * - Authenticated internal scope (`?scope=internal`):
 *   Verifies the HMAC-SHA256 server session token signed with PORTAL_SIGNING_SECRET before returning
 *   `pending_owner_review`, `internal_only` Notion workspaces, and `vault_subsystem` engineering records.
 */
export async function GET(req: NextRequest) {
  const scope = req.nextUrl.searchParams.get('scope') || 'showcase';
  const allItems = await syncAndListPortalProjects();

  if (scope === 'internal') {
    const auth = authenticatePortalOperatorRequest(req);
    if (!auth.authorized) {
      return NextResponse.json(
        {
          error: 'UNAUTHORIZED_INTERNAL_WORKSPACE_ACCESS',
          message:
            'Server-side authorization required to access internal workspaces and pending owner review records.',
        },
        { status: 401 }
      );
    }

    return NextResponse.json({
      status: 'OK',
      scope: 'internal',
      operatorEmail: auth.email,
      commandCentreNotionUrl: COMMAND_CENTRE_NOTION_URL,
      items: allItems,
    });
  }

  // Public / primary showcase response: strictly filter on server and never leak Notion URLs
  const approvedShowcaseOnly = getApprovedShowcaseProducts(allItems);
  return NextResponse.json({
    status: 'OK',
    scope: 'showcase',
    items: approvedShowcaseOnly,
  });
}

/**
 * PATCH /api/portal/projects
 *
 * Enforces server-side operator authorization via PORTAL_SIGNING_SECRET before updating
 * a project's visibility status ('approved_showcase' | 'pending_owner_review' | 'internal_only' | 'vault_subsystem').
 */
export async function PATCH(req: NextRequest) {
  const auth = authenticatePortalOperatorRequest(req);
  if (!auth.authorized) {
    return NextResponse.json(
      {
        error: 'UNAUTHORIZED_PROJECT_MUTATION',
        message:
          'Server-side operator authentication required to modify project visibility.',
      },
      { status: 401 }
    );
  }

  let body: Record<string, unknown>;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: 'Invalid request body.' }, { status: 400 });
  }

  const slug = typeof body.slug === 'string' ? body.slug.trim() : '';
  const allowedVisibilities: PortalProjectVisibility[] = [
    'approved_showcase',
    'pending_owner_review',
    'internal_only',
    'vault_subsystem',
  ];
  const visibility = allowedVisibilities.includes(
    body.visibility as PortalProjectVisibility
  )
    ? (body.visibility as PortalProjectVisibility)
    : null;

  if (!slug || !visibility) {
    return NextResponse.json(
      { error: 'Valid slug and visibility status are required.' },
      { status: 400 }
    );
  }

  const items = await setPortalProjectVisibility(slug, visibility);
  return NextResponse.json({
    status: 'UPDATED',
    items,
  });
}
