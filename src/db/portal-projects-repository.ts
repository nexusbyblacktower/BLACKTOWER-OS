import { eq } from 'drizzle-orm';
import { db, isDatabaseConfigured } from './index.ts';
import { portalProjects } from './schema.ts';
import {
  PORTAL_WORKSPACES,
  type PortalAuthorizationStatus,
  type PortalCompletionStatus,
  type PortalProjectVisibility,
  type PortalWorkspaceItem,
} from '../../lib/portal/portal-auth.ts';

const VALID_VISIBILITIES = new Set<PortalProjectVisibility>([
  'approved_showcase',
  'pending_owner_review',
  'internal_only',
  'vault_subsystem',
]);

function normalizeVisibility(
  rawVisibility: string,
  fallback: PortalProjectVisibility
): PortalProjectVisibility {
  if (rawVisibility === 'primary_showcase') {
    return fallback;
  }
  if (rawVisibility === 'internal_archive') {
    return fallback;
  }
  if (VALID_VISIBILITIES.has(rawVisibility as PortalProjectVisibility)) {
    return rawVisibility as PortalProjectVisibility;
  }
  return fallback;
}

/**
 * Synchronizes and retrieves the BLACKTOWER OS™ catalog from Neon PostgreSQL
 * (`portal_projects` table) without deleting any database rows.
 */
export async function syncAndListPortalProjects(): Promise<PortalWorkspaceItem[]> {
  if (!isDatabaseConfigured()) {
    return PORTAL_WORKSPACES;
  }

  try {
    const existingRows = await db.select().from(portalProjects);
    const existingBySlug = new Map(existingRows.map((row) => [row.slug, row]));

    for (const item of PORTAL_WORKSPACES) {
      if (!existingBySlug.has(item.id)) {
        await db.insert(portalProjects).values({
          slug: item.id,
          indexLabel: item.indexLabel,
          name: item.name,
          tagline: item.tagline,
          description: item.description,
          category: item.category,
          visibility: item.visibility,
          completionStatus: item.completionStatus,
          authorizationStatus: item.authorizationStatus,
          externalUrl: item.url,
          internalRoute: item.internalRoute ?? '',
          actionLabel: item.actionLabel ?? 'Open',
          iconKey: item.iconKey,
          displayOrder: item.displayOrder,
        });
      }
    }

    const updatedRows = await db.select().from(portalProjects);
    const rowBySlug = new Map(updatedRows.map((r) => [r.slug, r]));

    return PORTAL_WORKSPACES.map((item) => {
      const dbRow = rowBySlug.get(item.id);
      if (!dbRow) return item;
      return {
        ...item,
        visibility: normalizeVisibility(dbRow.visibility, item.visibility),
        completionStatus: (dbRow.completionStatus ||
          item.completionStatus) as PortalCompletionStatus,
        authorizationStatus: (dbRow.authorizationStatus ||
          item.authorizationStatus) as PortalAuthorizationStatus,
      };
    });
  } catch {
    return PORTAL_WORKSPACES;
  }
}

/**
 * Safely and reversibly updates a project's visibility status in Neon PostgreSQL
 * without deleting any database rows.
 */
export async function setPortalProjectVisibility(
  slug: string,
  visibility: PortalProjectVisibility
): Promise<PortalWorkspaceItem[]> {
  if (isDatabaseConfigured()) {
    try {
      await syncAndListPortalProjects();
      await db
        .update(portalProjects)
        .set({
          visibility,
          updatedAt: new Date(),
        })
        .where(eq(portalProjects.slug, slug));
    } catch {
      // Fall through to return current state
    }
  }
  return syncAndListPortalProjects();
}
