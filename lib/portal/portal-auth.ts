export interface PortalSessionUser {
  uid: string;
  email: string;
  verifiedAt: string;
  sessionToken?: string;
}

/**
 * Architectural visibility states defined by the BLACKTOWER OS™ specification.
 */
export type PortalProjectVisibility =
  | 'approved_showcase'
  | 'pending_owner_review'
  | 'internal_only'
  | 'vault_subsystem';

export type PortalCompletionStatus =
  | 'COMPLETED'
  | 'SECURITY_SUBSYSTEM'
  | 'ENGINEERING_TEST'
  | 'PENDING_OWNER_REVIEW'
  | 'INTERNAL_ONLY';

export type PortalAuthorizationStatus =
  | 'APPROVED_FOR_DISPLAY'
  | 'AUTHORIZED'
  | 'RESTRICTED';

export type PortalEntityConcept =
  | 'PUBLIC SHOWCASE PROJECT'
  | 'PRODUCT FEATURE'
  | 'SECURITY SUBSYSTEM'
  | 'ENGINEERING TEST'
  | 'PENDING OWNER REVIEW'
  | 'INTERNAL WORKSPACE';

export interface VaultInternalCapability {
  id: string;
  concept: 'PRODUCT FEATURE' | 'SECURITY SUBSYSTEM' | 'ENGINEERING TEST';
  title: string;
  summary: string;
  verificationNote: string;
  route: string;
}

export interface PortalWorkspaceItem {
  id: string;
  indexLabel: string;
  name: string;
  tagline: string;
  description: string;
  category: string;
  concept: PortalEntityConcept;
  visibility: PortalProjectVisibility;
  completionStatus: PortalCompletionStatus;
  authorizationStatus: PortalAuthorizationStatus;
  url: string;
  internalRoute?: string;
  actionLabel?: string;
  capabilities?: string[];
  architectureSummary?: string;
  iconKey:
    | 'calendar'
    | 'kanban'
    | 'cpu'
    | 'briefcase'
    | 'database'
    | 'shield'
    | 'book'
    | 'lock';
  displayOrder: number;
}

export const COMMAND_CENTRE_NOTION_URL =
  'https://www.notion.so/3f79e06eef388184a546d2db5a108857';

export const BLACKTOWER_VAULT_INTERNAL_CAPABILITIES: VaultInternalCapability[] = [
  {
    id: 'cap-vault-records',
    concept: 'PRODUCT FEATURE',
    title: 'Client-Side Encrypted Vault Records & CSPRNG Generator',
    summary:
      'Manages logins, TOTP authenticators, payment cards, digital identities, secure notes, local CSV migration, and authenticated .btvault backup containers.',
    verificationNote:
      'Payloads are encrypted locally in browser memory prior to persistence.',
    route: '/vault',
  },
  {
    id: 'cap-key-hierarchy',
    concept: 'SECURITY SUBSYSTEM',
    title: 'Four-Tier Cryptographic Key Hierarchy (Argon2id v1.3 + AES-256-GCM)',
    summary:
      'Master Password → Argon2id v1.3 → KEK → Account Root Key → Vault Key → Per-Item 256-bit Key with canonical v1 AAD and 96-bit nonce duplicate detection.',
    verificationNote:
      'Subsystem of BLACKTOWER VAULT™. Enforces fail-closed unwrapping and memory buffer zeroization on lock.',
    route: '/vault?tab=security',
  },
  {
    id: 'cap-screen-exposure',
    concept: 'SECURITY SUBSYSTEM',
    title: 'Screen Exposure Protection Subsystem',
    summary:
      'Runtime display-capture, visibility, and focus-loss defense that masks secrets by default, enforces a pre-render secret gate, and clears clipboard secrets on a timer.',
    verificationNote:
      'Subsystem of BLACKTOWER VAULT™. Browser preview enforces DOM/DisplayMedia capture guards; native Android FLAG_SECURE is unavailable in browser preview.',
    route: '/vault?tab=privacy',
  },
  {
    id: 'cap-neon-sync',
    concept: 'SECURITY SUBSYSTEM',
    title: 'Neon PostgreSQL Ciphertext Sync & Recovery Subsystem',
    summary:
      'Synchronizes wrapped key hierarchies and AES-256-GCM item envelopes through the backend API to Neon PostgreSQL while rejecting forbidden plaintext fields.',
    verificationNote:
      'Subsystem of BLACKTOWER VAULT™. Independently supports 256-bit Recovery Key unwrapping.',
    route: '/vault?tab=settings',
  },
  {
    id: 'cap-engineering-tests',
    concept: 'ENGINEERING TEST',
    title: 'Runtime Cryptographic Self-Test Suite (TEST-01 through TEST-09)',
    summary:
      'Executes real browser cryptographic assertions covering round-trip encryption, wrong password rejection, ciphertext tampering, nonce reuse abort, and AAD substitution.',
    verificationNote:
      'Engineering verification suite inside BLACKTOWER VAULT™. Automated self-tests verify runtime invariants and do not by themselves certify production environment security.',
    route: '/vault?tab=security',
  },
];

export const PORTAL_WORKSPACES: PortalWorkspaceItem[] = [
  {
    id: 'blacktower-vault',
    indexLabel: '01',
    name: 'BLACKTOWER VAULT™',
    tagline: 'Secure Password & Digital Identity Vault.',
    description: 'Secure Password & Digital Identity Vault.',
    category: 'SECURITY & PRIVACY',
    concept: 'PUBLIC SHOWCASE PROJECT',
    visibility: 'approved_showcase',
    completionStatus: 'COMPLETED',
    authorizationStatus: 'APPROVED_FOR_DISPLAY',
    url: '',
    internalRoute: '/vault',
    actionLabel: 'EXPLORE BLACKTOWER VAULT™',
    capabilities: [
      'Argon2id v1.3 KDF + 4-Tier AES-256-GCM Key Hierarchy',
      'Neon PostgreSQL Ciphertext Envelope Persistence',
      'Screen Exposure Defense & 256-Bit Emergency Recovery Key',
    ],
    architectureSummary:
      'Client-Side AES-256-GCM · Argon2id v1.3 · Neon PostgreSQL Backend',
    iconKey: 'lock',
    displayOrder: 1,
  },
  {
    id: 'screen-exposure-engine',
    indexLabel: 'S1',
    name: 'Screen Exposure Protection Engine',
    tagline: 'BLACKTOWER VAULT™ Runtime Privacy Subsystem',
    description:
      'Internal security subsystem of BLACKTOWER VAULT™ providing fail-closed Privacy Shield overlays, pre-render secret gating, and timed clipboard auto-clear.',
    category: 'BLACKTOWER VAULT™ Security Subsystem',
    concept: 'SECURITY SUBSYSTEM',
    visibility: 'vault_subsystem',
    completionStatus: 'SECURITY_SUBSYSTEM',
    authorizationStatus: 'AUTHORIZED',
    url: '',
    internalRoute: '/vault?tab=privacy',
    actionLabel: 'Inspect Subsystem in Vault',
    iconKey: 'shield',
    displayOrder: 2,
  },
  {
    id: 'zk-cloud-sync',
    indexLabel: 'S2',
    name: 'Neon PostgreSQL Ciphertext Sync & Recovery Subsystem',
    tagline: 'BLACKTOWER VAULT™ Encrypted Persistence Subsystem',
    description:
      'Internal security subsystem of BLACKTOWER VAULT™ synchronizing wrapped key hierarchies and AES-256-GCM item envelopes to Neon PostgreSQL with server-side plaintext rejection.',
    category: 'BLACKTOWER VAULT™ Security Subsystem',
    concept: 'SECURITY SUBSYSTEM',
    visibility: 'vault_subsystem',
    completionStatus: 'SECURITY_SUBSYSTEM',
    authorizationStatus: 'AUTHORIZED',
    url: '',
    internalRoute: '/vault?tab=settings',
    actionLabel: 'Inspect Subsystem in Vault',
    iconKey: 'database',
    displayOrder: 3,
  },
  {
    id: 'crypto-diagnostics-suite',
    indexLabel: 'S3',
    name: 'Cryptographic Verification & Audit Suite',
    tagline: 'BLACKTOWER VAULT™ Engineering Test Suite',
    description:
      'Internal engineering self-test suite of BLACKTOWER VAULT™ executing runtime cryptographic assertions (TEST-01 through TEST-09).',
    category: 'BLACKTOWER VAULT™ Engineering Test Suite',
    concept: 'ENGINEERING TEST',
    visibility: 'vault_subsystem',
    completionStatus: 'ENGINEERING_TEST',
    authorizationStatus: 'AUTHORIZED',
    url: '',
    internalRoute: '/vault?tab=security',
    actionLabel: 'Run Engineering Tests in Vault',
    iconKey: 'cpu',
    displayOrder: 4,
  },
  {
    id: 'nexus-tracker',
    indexLabel: 'P1',
    name: 'NEXUS V4 Tracker',
    tagline: 'System Architecture, Milestones & Engineering Registry',
    description:
      'Existing ecosystem record preserved under pending_owner_review until publication status is finalized by the owner.',
    category: 'Ecosystem Project Record',
    concept: 'PENDING OWNER REVIEW',
    visibility: 'pending_owner_review',
    completionStatus: 'PENDING_OWNER_REVIEW',
    authorizationStatus: 'AUTHORIZED',
    url: 'https://app.notion.com/p/3979e06eef3880718b06f5d70bbe69db',
    actionLabel: 'Open Internal Record',
    iconKey: 'cpu',
    displayOrder: 7,
  },
  {
    id: 'amway-business',
    indexLabel: 'P2',
    name: 'Amway Business OS',
    tagline: 'Commercial Operations, Volume Tracking & Partner Pipeline',
    description:
      'Existing project record preserved under pending_owner_review until publication status is finalized by the owner.',
    category: 'Ecosystem Project Record',
    concept: 'PENDING OWNER REVIEW',
    visibility: 'pending_owner_review',
    completionStatus: 'PENDING_OWNER_REVIEW',
    authorizationStatus: 'AUTHORIZED',
    url: '',
    actionLabel: 'Pending Owner Review',
    iconKey: 'briefcase',
    displayOrder: 8,
  },
  {
    id: 'daily-tasks',
    indexLabel: '01',
    name: 'Daily Tasks',
    tagline: 'Operational Execution & Daily Priority Queue',
    description:
      'Preserved internal Notion workspace for daily task execution and tactical check-ins.',
    category: 'Internal Planning (Notion)',
    concept: 'INTERNAL WORKSPACE',
    visibility: 'internal_only',
    completionStatus: 'INTERNAL_ONLY',
    authorizationStatus: 'AUTHORIZED',
    url: 'https://app.notion.com/p/20b9e06eef38806093aee1507e116e8f',
    actionLabel: 'Open Notion Workspace',
    iconKey: 'calendar',
    displayOrder: 5,
  },
  {
    id: 'project-planner',
    indexLabel: '02',
    name: 'Project Planner',
    tagline: 'Master Roadmap, Sprints & Deliverable Sequencing',
    description:
      'Preserved internal Notion workspace for multi-project timelines and architectural milestones.',
    category: 'Internal Planning (Notion)',
    concept: 'INTERNAL WORKSPACE',
    visibility: 'internal_only',
    completionStatus: 'INTERNAL_ONLY',
    authorizationStatus: 'AUTHORIZED',
    url: 'https://app.notion.com/p/20b9e06eef3880c5a68ec7a7e30b9c17',
    actionLabel: 'Open Notion Workspace',
    iconKey: 'kanban',
    displayOrder: 6,
  },
  {
    id: 'mirror-backup',
    indexLabel: '05',
    name: 'Supabase Mirror & Backup',
    tagline: 'Database Replication, Snapshot Verification & Failover',
    description:
      'Preserved internal Notion workspace for database backup runbooks and disaster recovery.',
    category: 'Internal Infrastructure (Notion)',
    concept: 'INTERNAL WORKSPACE',
    visibility: 'internal_only',
    completionStatus: 'INTERNAL_ONLY',
    authorizationStatus: 'AUTHORIZED',
    url: 'https://app.notion.com/p/3f79e06eef388137af36efe6dfde1e',
    actionLabel: 'Open Notion Workspace',
    iconKey: 'database',
    displayOrder: 9,
  },
  {
    id: 'workspace-audit',
    indexLabel: '06',
    name: 'Workspace Audit',
    tagline: 'Access Control Logs, Integrity Reviews & Compliance',
    description:
      'Preserved internal Notion workspace for security posture reviews and permission audits.',
    category: 'Internal Security Audit (Notion)',
    concept: 'INTERNAL WORKSPACE',
    visibility: 'internal_only',
    completionStatus: 'INTERNAL_ONLY',
    authorizationStatus: 'AUTHORIZED',
    url: 'https://app.notion.com/p/3f59e06eef3881038811dad8aa7c69fa',
    actionLabel: 'Open Notion Workspace',
    iconKey: 'shield',
    displayOrder: 10,
  },
  {
    id: 'knowledge-architecture',
    indexLabel: '07',
    name: 'Knowledge / Architecture',
    tagline: 'Technical Specifications, Protocols & Reference Library',
    description:
      'Preserved internal Notion knowledge base for system blueprints and cryptographic specifications.',
    category: 'Internal Documentation (Notion)',
    concept: 'INTERNAL WORKSPACE',
    visibility: 'internal_only',
    completionStatus: 'INTERNAL_ONLY',
    authorizationStatus: 'AUTHORIZED',
    url: 'https://app.notion.com/p/3ac9e06eef388002a4acdc0c237538c1',
    actionLabel: 'Open Notion Workspace',
    iconKey: 'book',
    displayOrder: 11,
  },
];

export const PORTAL_SESSION_STORAGE_KEY = 'blacktower_os_portal_session_v1';

const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export function validatePortalEmail(rawEmail: unknown): {
  valid: boolean;
  normalizedEmail: string;
  error?: string;
} {
  if (typeof rawEmail !== 'string') {
    return { valid: false, normalizedEmail: '', error: 'Enter a valid email address.' };
  }
  const trimmed = rawEmail.trim().toLowerCase();
  if (!trimmed || trimmed.length > 255 || !EMAIL_PATTERN.test(trimmed)) {
    return {
      valid: false,
      normalizedEmail: trimmed,
      error: 'Enter a valid email address.',
    };
  }
  return { valid: true, normalizedEmail: trimmed };
}

export function validatePortalPassword(rawPassword: unknown): {
  valid: boolean;
  error?: string;
} {
  if (typeof rawPassword !== 'string' || rawPassword.length < 1) {
    return { valid: false, error: 'Password is required.' };
  }
  if (rawPassword.length > 128) {
    return { valid: false, error: 'Password must be 128 characters or fewer.' };
  }
  return { valid: true };
}

export function validateRecoveryPassword(
  newPassword: unknown,
  confirmPassword: unknown
): { valid: boolean; error?: string } {
  if (typeof newPassword !== 'string' || newPassword.length < 12) {
    return { valid: false, error: 'New password must be at least 12 characters.' };
  }
  if (newPassword.length > 128) {
    return { valid: false, error: 'Password must be 128 characters or fewer.' };
  }
  if (newPassword !== confirmPassword) {
    return { valid: false, error: 'Passwords do not match.' };
  }
  return { valid: true };
}

/**
 * Intentionally disabled. Authentication is server-only and must use
 * verifyOwnerCredentials from portal-server-auth.ts. Keeping an insecure
 * client-importable verifier would create an authentication bypass risk.
 */
export function verifyAuthorizedPortalCredentials():
  | { ok: false; error: string } {
  return {
    ok: false,
    error: 'Portal credential verification is server-only.',
  };
}

export function sanitizeExternalHttpsUrl(rawUrl: string): string | null {
  if (!rawUrl || typeof rawUrl !== 'string') return null;
  try {
    const parsed = new URL(rawUrl);
    if (parsed.protocol !== 'https:' || parsed.username || parsed.password) {
      return null;
    }
    return parsed.toString();
  } catch {
    return null;
  }
}

export function getApprovedShowcaseProducts(
  items: PortalWorkspaceItem[]
): PortalWorkspaceItem[] {
  return items
    .filter((item) => item.visibility === 'approved_showcase')
    .map((item) => ({ ...item, url: '' }))
    .sort((a, b) => a.displayOrder - b.displayOrder);
}

export function getPendingOwnerReviewProjects(
  items: PortalWorkspaceItem[]
): PortalWorkspaceItem[] {
  return items
    .filter((item) => item.visibility === 'pending_owner_review')
    .sort((a, b) => a.displayOrder - b.displayOrder);
}

export function getPreservedInternalWorkspaces(
  items: PortalWorkspaceItem[]
): PortalWorkspaceItem[] {
  return items
    .filter((item) => item.visibility === 'internal_only')
    .sort((a, b) => a.displayOrder - b.displayOrder);
}

export function getVaultSubsystemRecords(
  items: PortalWorkspaceItem[]
): PortalWorkspaceItem[] {
  return items
    .filter((item) => item.visibility === 'vault_subsystem')
    .sort((a, b) => a.displayOrder - b.displayOrder);
}

export function setProjectVisibilityInList(
  items: PortalWorkspaceItem[],
  projectId: string,
  targetVisibility: PortalProjectVisibility
): PortalWorkspaceItem[] {
  return items.map((item) =>
    item.id === projectId ? { ...item, visibility: targetVisibility } : item
  );
}

export function filterWorkspaces(
  items: PortalWorkspaceItem[],
  query: string
): PortalWorkspaceItem[] {
  const q = query.trim().toLowerCase();
  if (!q) return items;
  return items.filter(
    (item) =>
      item.name.toLowerCase().includes(q) ||
      item.tagline.toLowerCase().includes(q) ||
      item.description.toLowerCase().includes(q) ||
      item.category.toLowerCase().includes(q)
  );
}

export function savePortalSession(user: PortalSessionUser): void {
  if (typeof window === 'undefined') return;
  try {
    window.sessionStorage.setItem(PORTAL_SESSION_STORAGE_KEY, JSON.stringify(user));
  } catch {
    // Ignore storage quota errors.
  }
}

export function loadPortalSession(): PortalSessionUser | null {
  if (typeof window === 'undefined') return null;
  try {
    const raw = window.sessionStorage.getItem(PORTAL_SESSION_STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as Partial<PortalSessionUser>;
    if (
      typeof parsed.uid === 'string' &&
      typeof parsed.email === 'string' &&
      typeof parsed.verifiedAt === 'string'
    ) {
      return {
        uid: parsed.uid,
        email: parsed.email,
        verifiedAt: parsed.verifiedAt,
        sessionToken:
          typeof parsed.sessionToken === 'string' ? parsed.sessionToken : undefined,
      };
    }
    return null;
  } catch {
    return null;
  }
}

export function clearPortalSession(): void {
  if (typeof window === 'undefined') return;
  try {
    window.sessionStorage.removeItem(PORTAL_SESSION_STORAGE_KEY);
  } catch {
    // Ignore storage errors.
  }
}
