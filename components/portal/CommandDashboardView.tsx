'use client';

import React, { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import {
  Archive,
  ArrowRight,
  ArrowUpRight,
  BookOpen,
  BriefcaseBusiness,
  CalendarCheck,
  ChevronDown,
  ChevronUp,
  Cpu,
  Database,
  Kanban,
  Layers,
  Lock,
  LogOut,
  Search,
  Shield,
} from 'lucide-react';
import {
  BLACKTOWER_VAULT_INTERNAL_CAPABILITIES,
  PORTAL_WORKSPACES,
  type PortalProjectVisibility,
  type PortalSessionUser,
  type PortalWorkspaceItem,
  clearPortalSession,
  filterWorkspaces,
  getApprovedShowcaseProducts,
  getPendingOwnerReviewProjects,
  getPreservedInternalWorkspaces,
  getVaultSubsystemRecords,
  sanitizeExternalHttpsUrl,
  setProjectVisibilityInList,
} from '@/lib/portal/portal-auth';
import { BlacktowerBrand, BlacktowerFooter } from './PortalChrome';
import VaultEcosystemTransition from './VaultEcosystemTransition';

interface CommandDashboardViewProps {
  sessionUser: PortalSessionUser;
}

type PortalSectionTab = 'showcase' | 'internal';

function renderWorkspaceIcon(iconKey: PortalWorkspaceItem['iconKey']) {
  const iconClass = 'w-5 h-5 text-[#00FF66]';
  switch (iconKey) {
    case 'lock':
      return <Lock className={iconClass} />;
    case 'calendar':
      return <CalendarCheck className={iconClass} />;
    case 'kanban':
      return <Kanban className={iconClass} />;
    case 'cpu':
      return <Cpu className={iconClass} />;
    case 'briefcase':
      return <BriefcaseBusiness className={iconClass} />;
    case 'database':
      return <Database className={iconClass} />;
    case 'shield':
      return <Shield className={iconClass} />;
    case 'book':
      return <BookOpen className={iconClass} />;
  }
}

export default function CommandDashboardView({
  sessionUser,
}: CommandDashboardViewProps) {
  const router = useRouter();
  const [activeTab, setActiveTab] = useState<PortalSectionTab>('showcase');
  const [showcaseCatalog, setShowcaseCatalog] = useState<PortalWorkspaceItem[]>(
    () => getApprovedShowcaseProducts(PORTAL_WORKSPACES)
  );
  const [internalCatalog, setInternalCatalog] = useState<PortalWorkspaceItem[]>(
    []
  );
  const [commandCentreUrl, setCommandCentreUrl] = useState<string | null>(null);
  const [internalAuthVerified, setInternalAuthVerified] =
    useState<boolean>(false);
  const [internalAuthError, setInternalAuthError] = useState<string | null>(
    null
  );
  const [searchQuery, setSearchQuery] = useState('');
  const [isUpdatingVisibility, setIsUpdatingVisibility] = useState<
    string | null
  >(null);
  const [showVaultCapabilities, setShowVaultCapabilities] =
    useState<boolean>(false);
  const [transitionTarget, setTransitionTarget] = useState<{
    active: boolean;
    route: string;
    label: string;
  }>({
    active: false,
    route: '/vault',
    label: 'BLACKTOWER VAULT™',
  });

  // 1. Fetch public/approved showcase items from server
  useEffect(() => {
    let active = true;
    fetch('/api/portal/projects?scope=showcase')
      .then((res) => res.json())
      .then((data: { items?: PortalWorkspaceItem[] }) => {
        if (active && Array.isArray(data.items) && data.items.length > 0) {
          setShowcaseCatalog(data.items);
        }
      })
      .catch(() => {
        // Fallback to local approved showcase catalog
      });
    return () => {
      active = false;
    };
  }, []);

  // 2. Fetch internal workspaces & pending_owner_review records via server-authorized endpoint
  useEffect(() => {
    if (!sessionUser.sessionToken) {
      return;
    }
    let active = true;
    const headers: Record<string, string> = {
      Authorization: `Bearer ${sessionUser.sessionToken}`,
    };

    fetch('/api/portal/projects?scope=internal', {
      headers,
      credentials: 'include',
    })
      .then(async (res) => {
        if (!res.ok) {
          if (active) {
            setInternalAuthVerified(false);
            setInternalAuthError(
              'Server-side operator session verification required to view internal workspaces.'
            );
          }
          return null;
        }
        return res.json() as Promise<{
          items?: PortalWorkspaceItem[];
          commandCentreNotionUrl?: string;
        }>;
      })
      .then((data) => {
        if (!active || !data) return;
        if (Array.isArray(data.items)) {
          setInternalCatalog(data.items);
          setShowcaseCatalog(getApprovedShowcaseProducts(data.items));
          setInternalAuthVerified(true);
          setInternalAuthError(null);
        }
        if (data.commandCentreNotionUrl) {
          setCommandCentreUrl(
            sanitizeExternalHttpsUrl(data.commandCentreNotionUrl)
          );
        }
      })
      .catch(() => {
        if (active) {
          setInternalAuthVerified(false);
        }
      });

    return () => {
      active = false;
    };
  }, [sessionUser.sessionToken]);

  const handleLaunchVaultWithTransition = (
    route = '/vault',
    label = 'BLACKTOWER VAULT™'
  ) => {
    setTransitionTarget({ active: true, route, label });
    const delayMs =
      typeof navigator !== 'undefined' &&
      (navigator.webdriver || /HeadlessChrome/i.test(navigator.userAgent))
        ? 180
        : 520;
    window.setTimeout(() => {
      router.push(route);
    }, delayMs);
  };

  const handleSignOut = async () => {
    clearPortalSession();
    try {
      await fetch('/api/portal/auth', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mode: 'signout' }),
      });
    } catch {
      // Ignore network errors on signout
    }
    router.replace('/');
  };

  const handleChangeVisibility = async (
    projectId: string,
    targetVisibility: PortalProjectVisibility
  ) => {
    setIsUpdatingVisibility(projectId);
    const updatedLocal = setProjectVisibilityInList(
      internalCatalog,
      projectId,
      targetVisibility
    );
    setInternalCatalog(updatedLocal);
    setShowcaseCatalog(getApprovedShowcaseProducts(updatedLocal));

    try {
      const headers: Record<string, string> = {
        'Content-Type': 'application/json',
      };
      if (sessionUser.sessionToken) {
        headers.Authorization = `Bearer ${sessionUser.sessionToken}`;
      }
      const res = await fetch('/api/portal/projects', {
        method: 'PATCH',
        headers,
        credentials: 'include',
        body: JSON.stringify({
          slug: projectId,
          visibility: targetVisibility,
        }),
      });
      const data = (await res.json()) as { items?: PortalWorkspaceItem[] };
      if (res.ok && Array.isArray(data.items)) {
        setInternalCatalog(data.items);
        setShowcaseCatalog(getApprovedShowcaseProducts(data.items));
      }
    } catch {
      // Retain local update
    } finally {
      setIsUpdatingVisibility(null);
    }
  };

  const approvedProducts = getApprovedShowcaseProducts(
    internalCatalog.length > 0 ? internalCatalog : showcaseCatalog
  );
  const pendingReviewProjects = filterWorkspaces(
    getPendingOwnerReviewProjects(internalCatalog),
    searchQuery
  );
  const internalWorkspaces = filterWorkspaces(
    getPreservedInternalWorkspaces(internalCatalog),
    searchQuery
  );
  const vaultSubsystems = filterWorkspaces(
    getVaultSubsystemRecords(internalCatalog),
    searchQuery
  );

  const primaryVaultProduct =
    approvedProducts.find((item) => item.id === 'blacktower-vault') ||
    approvedProducts[0];
  const additionalApprovedProducts = approvedProducts.filter(
    (item) => item.id !== 'blacktower-vault'
  );

  return (
    <div className="min-h-screen bg-[#050505] text-[#F4F7F5] flex flex-col justify-between">
      <VaultEcosystemTransition
        active={transitionTarget.active}
        targetLabel={transitionTarget.label}
      />

      {/* Minimalist Top Bar matching BLACKTOWER VAULT™ Design Authority */}
      <header className="border-b border-[#161B20] bg-[#050505]/95 backdrop-blur-md sticky top-0 z-30">
        <div className="max-w-6xl mx-auto flex items-center justify-between gap-3 px-4 sm:px-8 py-4">
          <BlacktowerBrand subtitle="BLACKTOWER OS™" />

          {/* Desktop Navigation */}
          <nav
            aria-label="BLACKTOWER OS navigation"
            className="hidden md:flex items-center gap-6 text-xs font-[family-name:var(--font-mono)] tracking-[0.16em] uppercase"
          >
            <button
              type="button"
              onClick={() => setActiveTab('showcase')}
              className={`py-1.5 border-b-2 transition-colors whitespace-nowrap ${
                activeTab === 'showcase'
                  ? 'border-[#00FF66] text-white font-semibold'
                  : 'border-transparent text-zinc-400 hover:text-zinc-200'
              }`}
            >
              Product Showcase
            </button>
            <button
              type="button"
              onClick={() => setActiveTab('internal')}
              className={`py-1.5 border-b-2 transition-colors whitespace-nowrap flex items-center gap-1.5 ${
                activeTab === 'internal'
                  ? 'border-[#00FF66] text-white font-semibold'
                  : 'border-transparent text-zinc-400 hover:text-zinc-200'
              }`}
            >
              <Archive className="w-3.5 h-3.5 text-[#00FF66]" />
              <span>Internal Workspaces</span>
            </button>
          </nav>

          {/* Right Operator Controls */}
          <div className="flex items-center gap-2.5 shrink-0">
            <span className="hidden lg:inline-block font-[family-name:var(--font-mono)] text-[11px] text-zinc-400 max-w-[200px] truncate">
              {sessionUser.email}
            </span>

            <button
              type="button"
              onClick={() =>
                handleLaunchVaultWithTransition('/vault', 'BLACKTOWER VAULT™')
              }
              className="px-3.5 py-2 rounded-lg bg-[#00FF66] hover:bg-[#22FF7A] text-[#050505] font-semibold text-xs inline-flex items-center gap-1.5 transition-colors whitespace-nowrap shadow-[0_0_20px_rgba(0,255,102,0.16)]"
            >
              <Lock className="w-3.5 h-3.5" />
              <span>Explore Vault</span>
            </button>

            <button
              type="button"
              onClick={handleSignOut}
              aria-label="Sign out"
              className="px-3 py-2 rounded-lg border border-[#161B20] bg-[#0B0E11] hover:bg-[#11161B] text-xs font-medium text-zinc-300 hover:text-white inline-flex items-center gap-1.5 transition-colors whitespace-nowrap"
            >
              <LogOut className="w-3.5 h-3.5" />
              <span className="hidden sm:inline">Sign out</span>
            </button>
          </div>
        </div>

        {/* Mobile Sub-Navigation Bar */}
        <nav
          aria-label="Mobile BLACKTOWER OS navigation"
          className="flex md:hidden items-center gap-2 px-4 py-2 border-t border-[#161B20] bg-[#07090B]"
        >
          <button
            type="button"
            onClick={() => setActiveTab('showcase')}
            className={`flex-1 py-1.5 px-2.5 rounded-md text-xs font-medium transition-colors text-center whitespace-nowrap ${
              activeTab === 'showcase'
                ? 'bg-[#0B0E11] text-[#00FF66] border border-[#00FF66]/40'
                : 'text-zinc-400 hover:text-zinc-200'
            }`}
          >
            Product Showcase
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('internal')}
            className={`flex-1 py-1.5 px-2.5 rounded-md text-xs font-medium transition-colors text-center whitespace-nowrap ${
              activeTab === 'internal'
                ? 'bg-[#0B0E11] text-[#00FF66] border border-[#00FF66]/40'
                : 'text-zinc-400 hover:text-zinc-200'
            }`}
          >
            Internal Workspaces
          </button>
        </nav>
      </header>

      {/* Main Content Area */}
      <main className="flex-1 max-w-6xl w-full mx-auto px-4 sm:px-8 py-12 sm:py-16 space-y-12">
        {/* ================================================================= */}
        {/* TAB 1: PRIVATE PRODUCT SHOWCASE (DEFAULT)                         */}
        {/* ================================================================= */}
        {activeTab === 'showcase' && (
          <div className="space-y-12">
            {/* Showcase Hero Header following exact Section 7 hierarchy */}
            <section className="space-y-4 max-w-3xl">
              <div className="inline-flex items-center gap-2.5 px-3 py-1 rounded-md bg-[#0B0E11] border border-[#00FF66]/30 text-[11px] font-[family-name:var(--font-mono)] tracking-[0.22em] uppercase text-[#00FF66]">
                <span
                  className="w-1.5 h-1.5 rounded-full bg-[#00FF66] shadow-[0_0_8px_rgba(0,255,102,0.8)]"
                  aria-hidden="true"
                />
                <span>BLACKTOWER OS™</span>
              </div>

              <div className="font-[family-name:var(--font-mono)] text-xs tracking-[0.24em] uppercase text-zinc-400">
                THE BLACKTOWER ECOSYSTEM
              </div>

              <h1 className="font-[family-name:var(--font-display)] text-4xl sm:text-5xl lg:text-6xl font-bold tracking-tight text-white leading-[1.08]">
                Built by BLACKTOWER.
              </h1>
            </section>

            {/* Released Projects Section */}
            <section className="space-y-6">
              <div className="flex items-center justify-between border-b border-[#161B20] pb-4">
                <div className="flex items-center gap-3">
                  <span
                    className="w-2 h-2 rounded-full bg-[#00FF66] shadow-[0_0_8px_rgba(0,255,102,0.8)]"
                    aria-hidden="true"
                  />
                  <h2 className="font-[family-name:var(--font-mono)] text-xs tracking-[0.24em] uppercase text-zinc-200 font-semibold">
                    RELEASED PROJECTS
                  </h2>
                </div>
                <span className="font-[family-name:var(--font-mono)] text-[11px] tracking-[0.18em] uppercase text-zinc-500">
                  {approvedProducts.length === 1
                    ? '1 APPROVED PRODUCT'
                    : `${approvedProducts.length} APPROVED PRODUCTS`}
                </span>
              </div>

              {/* Primary Approved Showcase Product Card: BLACKTOWER VAULT™ */}
              {primaryVaultProduct && (
                <div className="bg-[#0B0E11] border border-[#161B20] hover:border-[#00FF66]/35 rounded-2xl p-6 sm:p-10 transition-colors shadow-[0_24px_64px_-16px_rgba(0,0,0,0.85)] space-y-8">
                  {/* Top Metadata Bar */}
                  <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[#161B20] pb-5">
                    <div className="flex flex-wrap items-center gap-2.5">
                      <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-md bg-[#00FF66]/10 border border-[#00FF66]/35 text-[11px] font-[family-name:var(--font-mono)] uppercase tracking-[0.16em] text-[#00FF66] font-semibold">
                        <span
                          className="w-1.5 h-1.5 rounded-full bg-[#00FF66]"
                          aria-hidden="true"
                        />
                        <span>COMPLETED</span>
                      </span>
                      <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-md bg-[#07090B] border border-[#161B20] text-[11px] font-[family-name:var(--font-mono)] uppercase tracking-[0.16em] text-zinc-300">
                        APPROVED FOR DISPLAY
                      </span>
                      <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-md bg-[#07090B] border border-[#161B20] text-[11px] font-[family-name:var(--font-mono)] uppercase tracking-[0.16em] text-zinc-400">
                        CATEGORY: {primaryVaultProduct.category}
                      </span>
                    </div>

                    <span className="font-[family-name:var(--font-mono)] text-[11px] tracking-[0.18em] uppercase text-zinc-500">
                      PUBLIC SHOWCASE PROJECT
                    </span>
                  </div>

                  {/* Main Product Presentation */}
                  <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-center">
                    <div className="lg:col-span-8 space-y-4">
                      <div className="flex items-center gap-3.5">
                        <div className="w-12 h-12 rounded-xl bg-[#07090B] border border-[#00FF66]/35 flex items-center justify-center shrink-0 shadow-[0_0_20px_rgba(0,255,102,0.12)]">
                          <Lock className="w-6 h-6 text-[#00FF66]" />
                        </div>
                        <div>
                          <h3 className="font-[family-name:var(--font-display)] text-2xl sm:text-4xl font-bold text-white tracking-tight">
                            {primaryVaultProduct.name}
                          </h3>
                          <p className="font-[family-name:var(--font-mono)] text-[11px] tracking-[0.2em] uppercase text-[#00FF66] mt-1">
                            {primaryVaultProduct.category}
                          </p>
                        </div>
                      </div>

                      <p className="text-lg sm:text-xl text-zinc-200 font-medium leading-relaxed pt-1">
                        {primaryVaultProduct.description}
                      </p>

                      <p className="text-sm text-zinc-400 leading-relaxed max-w-2xl">
                        Personal password and digital identity vault engineered around client-side key derivation, per-item AES-256-GCM encryption envelopes, and Neon PostgreSQL ciphertext storage.
                      </p>
                    </div>

                    {/* Primary Action Column */}
                    <div className="lg:col-span-4 flex flex-col sm:flex-row lg:flex-col gap-3 justify-end">
                      <button
                        type="button"
                        onClick={() =>
                          handleLaunchVaultWithTransition(
                            '/vault',
                            'BLACKTOWER VAULT™'
                          )
                        }
                        className="w-full py-3.5 px-6 rounded-xl bg-[#00FF66] hover:bg-[#22FF7A] text-[#050505] font-semibold text-sm flex items-center justify-between transition-colors shadow-[0_0_28px_rgba(0,255,102,0.2)]"
                      >
                        <span>EXPLORE BLACKTOWER VAULT™</span>
                        <ArrowRight className="w-4 h-4" />
                      </button>

                      <button
                        type="button"
                        onClick={() =>
                          setShowVaultCapabilities((prev) => !prev)
                        }
                        aria-expanded={showVaultCapabilities}
                        className="w-full py-2.5 px-4 rounded-xl bg-[#07090B] hover:bg-[#10151A] border border-[#161B20] hover:border-[#00FF66]/35 text-xs font-medium text-zinc-300 hover:text-white flex items-center justify-between transition-colors"
                      >
                        <span>
                          {showVaultCapabilities
                            ? 'Hide Internal Capabilities & Subsystems'
                            : 'View Internal Capabilities & Subsystems'}
                        </span>
                        {showVaultCapabilities ? (
                          <ChevronUp className="w-4 h-4 text-[#00FF66]" />
                        ) : (
                          <ChevronDown className="w-4 h-4 text-[#00FF66]" />
                        )}
                      </button>
                    </div>
                  </div>

                  {/* Inside-Product Capability Drawer (Distinguishing PRODUCT FEATURE, SECURITY SUBSYSTEM, ENGINEERING TEST) */}
                  {showVaultCapabilities && (
                    <div className="pt-6 border-t border-[#161B20] space-y-4">
                      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                        <div className="font-[family-name:var(--font-mono)] text-[11px] tracking-[0.18em] uppercase text-zinc-400">
                          BLACKTOWER VAULT™ INTERNAL ARCHITECTURE &amp; CAPABILITIES
                        </div>
                        <span className="text-xs text-zinc-500">
                          Subsystems and self-tests belong to BLACKTOWER VAULT™ and are not standalone products.
                        </span>
                      </div>

                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        {BLACKTOWER_VAULT_INTERNAL_CAPABILITIES.map((cap) => (
                          <div
                            key={cap.id}
                            className="p-4 rounded-xl bg-[#07090B] border border-[#161B20] flex flex-col justify-between gap-3"
                          >
                            <div className="space-y-2">
                              <div className="flex items-center justify-between gap-2">
                                <span className="px-2 py-0.5 rounded bg-[#00FF66]/10 border border-[#00FF66]/30 text-[10px] font-[family-name:var(--font-mono)] uppercase tracking-wider text-[#00FF66]">
                                  {cap.concept}
                                </span>
                              </div>
                              <h4 className="text-sm font-semibold text-white font-[family-name:var(--font-display)]">
                                {cap.title}
                              </h4>
                              <p className="text-xs text-zinc-400 leading-relaxed">
                                {cap.summary}
                              </p>
                              <p className="text-[11px] text-zinc-500 font-[family-name:var(--font-mono)]">
                                {cap.verificationNote}
                              </p>
                            </div>

                            <div className="pt-2 border-t border-[#161B20]/80 flex justify-end">
                              <button
                                type="button"
                                onClick={() =>
                                  handleLaunchVaultWithTransition(
                                    cap.route,
                                    cap.title
                                  )
                                }
                                className="text-xs font-medium text-[#00FF66] hover:underline inline-flex items-center gap-1"
                              >
                                <span>Open inside BLACKTOWER VAULT™</span>
                                <ArrowUpRight className="w-3.5 h-3.5" />
                              </button>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* Additional Owner-Approved Showcase Projects (only appears if explicitly approved by owner) */}
              {additionalApprovedProducts.length > 0 && (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6 pt-2">
                  {additionalApprovedProducts.map((project) => (
                    <div
                      key={project.id}
                      className="bg-[#0B0E11] border border-[#161B20] hover:border-[#00FF66]/35 rounded-xl p-6 flex flex-col justify-between gap-5"
                    >
                      <div className="space-y-3">
                        <div className="flex items-center justify-between gap-2">
                          <span className="px-2.5 py-0.5 rounded bg-[#00FF66]/10 border border-[#00FF66]/30 text-[10px] font-[family-name:var(--font-mono)] uppercase tracking-wider text-[#00FF66]">
                            APPROVED FOR DISPLAY
                          </span>
                          <span className="text-[10px] font-[family-name:var(--font-mono)] uppercase tracking-wider text-zinc-500">
                            {project.category}
                          </span>
                        </div>
                        <div className="flex items-center gap-3">
                          <div className="w-10 h-10 rounded-lg bg-[#07090B] border border-[#161B20] flex items-center justify-center shrink-0">
                            {renderWorkspaceIcon(project.iconKey)}
                          </div>
                          <div>
                            <h3 className="text-lg font-bold text-white font-[family-name:var(--font-display)]">
                              {project.name}
                            </h3>
                            <p className="text-xs text-[#00FF66]">
                              {project.tagline}
                            </p>
                          </div>
                        </div>
                        <p className="text-xs text-zinc-400 leading-relaxed">
                          {project.description}
                        </p>
                      </div>

                      {project.internalRoute && (
                        <button
                          type="button"
                          onClick={() =>
                            handleLaunchVaultWithTransition(
                              project.internalRoute!,
                              project.name
                            )
                          }
                          className="w-full py-2.5 px-4 rounded-lg bg-[#07090B] hover:bg-[#10151A] border border-[#00FF66]/35 text-xs font-semibold text-[#00FF66] flex items-center justify-between transition-colors"
                        >
                          <span>{project.actionLabel || 'Explore Project'}</span>
                          <ArrowRight className="w-3.5 h-3.5" />
                        </button>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </section>
          </div>
        )}

        {/* ================================================================= */}
        {/* TAB 2: AUTHENTICATED INTERNAL WORKSPACES & OWNER REVIEW           */}
        {/* ================================================================= */}
        {activeTab === 'internal' && (
          <div className="space-y-10">
            <div className="flex flex-col lg:flex-row lg:items-end justify-between gap-6 border-b border-[#161B20] pb-6">
              <div className="space-y-2 max-w-2xl">
                <div className="inline-flex items-center gap-2 text-xs font-medium text-[#00FF66] tracking-wide">
                  <Archive className="w-3.5 h-3.5" />
                  <span>
                    SERVER-AUTHORIZED INTERNAL AREA · HIDDEN FROM PRIMARY SHOWCASE
                  </span>
                </div>
                <h1 className="font-[family-name:var(--font-display)] text-2xl sm:text-3xl font-bold text-white tracking-tight">
                  Internal Workspaces &amp; Owner Review Queue
                </h1>
                <p className="text-sm text-zinc-400 leading-relaxed">
                  Internal planning systems, Notion workspaces, and unfinalized projects remain preserved in Neon PostgreSQL behind server-side session verification without cluttering the primary BLACKTOWER OS™ showcase.
                </p>
              </div>

              <div className="flex flex-wrap items-center gap-3">
                <div className="relative w-full sm:w-64">
                  <Search className="w-4 h-4 text-zinc-500 absolute left-3.5 top-1/2 -translate-y-1/2 pointer-events-none" />
                  <input
                    type="search"
                    aria-label="Search internal records"
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    placeholder="Filter internal records..."
                    className="w-full h-10 pl-10 pr-3.5 rounded-lg bg-[#0B0E11] border border-[#161B20] text-xs text-white placeholder:text-zinc-500 focus:outline-none focus:border-[#00FF66] transition-colors"
                  />
                </div>

                {commandCentreUrl && (
                  <a
                    href={commandCentreUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="h-10 px-4 rounded-lg bg-[#0B0E11] hover:bg-[#11161B] border border-[#161B20] hover:border-[#00FF66]/40 text-xs font-medium text-zinc-200 hover:text-[#00FF66] inline-flex items-center gap-2 transition-colors whitespace-nowrap"
                  >
                    <span>Notion Command Centre</span>
                    <ArrowUpRight className="w-3.5 h-3.5 text-[#00FF66]" />
                  </a>
                )}
              </div>
            </div>

            {!internalAuthVerified && internalAuthError ? (
              <div className="p-6 rounded-xl bg-[#0B0E11] border border-rose-800/70 text-sm text-rose-200">
                {internalAuthError}
              </div>
            ) : (
              <>
                {/* 1. Future Projects Pending Owner Review */}
                <section className="space-y-4">
                  <div className="flex items-center justify-between">
                    <h2 className="font-[family-name:var(--font-mono)] text-xs tracking-[0.2em] uppercase text-zinc-300 font-semibold">
                      PROJECTS PENDING OWNER REVIEW (VISIBILITY: PENDING_OWNER_REVIEW)
                    </h2>
                    <span className="font-[family-name:var(--font-mono)] text-[11px] text-zinc-500">
                      {pendingReviewProjects.length} records
                    </span>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {pendingReviewProjects.map((project) => {
                      const safeUrl = sanitizeExternalHttpsUrl(project.url);
                      return (
                        <div
                          key={project.id}
                          className="bg-[#0B0E11] border border-[#161B20] rounded-xl p-5 flex flex-col justify-between gap-4"
                        >
                          <div className="space-y-2.5">
                            <div className="flex items-center justify-between gap-2">
                              <span className="px-2 py-0.5 rounded bg-amber-950/50 border border-amber-700/50 text-[10px] font-[family-name:var(--font-mono)] uppercase tracking-wider text-amber-300">
                                visibility_status: pending_owner_review
                              </span>
                              <span className="text-[10px] font-[family-name:var(--font-mono)] text-zinc-500">
                                {project.category}
                              </span>
                            </div>

                            <div className="flex items-center gap-3">
                              <div className="w-9 h-9 rounded-lg bg-[#07090B] border border-[#161B20] flex items-center justify-center shrink-0">
                                {renderWorkspaceIcon(project.iconKey)}
                              </div>
                              <div>
                                <h3 className="text-base font-bold text-white font-[family-name:var(--font-display)]">
                                  {project.name}
                                </h3>
                                <p className="text-xs text-zinc-400">
                                  {project.tagline}
                                </p>
                              </div>
                            </div>

                            <p className="text-xs text-zinc-500 leading-relaxed">
                              {project.description}
                            </p>
                          </div>

                          <div className="pt-3 border-t border-[#161B20] flex flex-wrap items-center justify-between gap-2">
                            {safeUrl ? (
                              <a
                                href={safeUrl}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="px-3 py-1.5 rounded-lg bg-[#07090B] hover:bg-[#10151A] border border-[#161B20] text-xs text-zinc-200 hover:text-[#00FF66] inline-flex items-center gap-1.5 transition-colors"
                              >
                                <span>Open Internal Record</span>
                                <ArrowUpRight className="w-3.5 h-3.5 text-[#00FF66]" />
                              </a>
                            ) : (
                              <span className="text-[11px] font-[family-name:var(--font-mono)] text-zinc-500">
                                Publication status not finalized
                              </span>
                            )}

                            <button
                              type="button"
                              disabled={isUpdatingVisibility === project.id}
                              onClick={() =>
                                handleChangeVisibility(
                                  project.id,
                                  'approved_showcase'
                                )
                              }
                              className="px-3 py-1.5 rounded-lg bg-[#07090B] hover:bg-[#10151A] border border-[#00FF66]/35 text-xs font-medium text-[#00FF66] transition-colors"
                            >
                              Approve for Showcase
                            </button>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </section>

                {/* 2. Internal Workspaces & Preserved Notion Links */}
                <section className="space-y-4">
                  <div className="flex items-center justify-between">
                    <h2 className="font-[family-name:var(--font-mono)] text-xs tracking-[0.2em] uppercase text-zinc-300 font-semibold">
                      INTERNAL WORKSPACES &amp; NOTION REFERENCES (VISIBILITY: INTERNAL_ONLY)
                    </h2>
                    <span className="font-[family-name:var(--font-mono)] text-[11px] text-zinc-500">
                      {internalWorkspaces.length} records
                    </span>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                    {internalWorkspaces.map((item) => {
                      const safeUrl = sanitizeExternalHttpsUrl(item.url);
                      return (
                        <div
                          key={item.id}
                          className="bg-[#0B0E11] border border-[#161B20] rounded-xl p-5 flex flex-col justify-between gap-4"
                        >
                          <div className="space-y-2.5">
                            <div className="flex items-center justify-between gap-2">
                              <span className="px-2 py-0.5 rounded bg-[#07090B] border border-[#161B20] text-[10px] font-[family-name:var(--font-mono)] uppercase tracking-wider text-zinc-400">
                                visibility_status: internal_only
                              </span>
                            </div>

                            <div className="flex items-center gap-3">
                              <div className="w-9 h-9 rounded-lg bg-[#07090B] border border-[#161B20] flex items-center justify-center shrink-0">
                                {renderWorkspaceIcon(item.iconKey)}
                              </div>
                              <div>
                                <h3 className="text-sm font-bold text-white font-[family-name:var(--font-display)]">
                                  {item.name}
                                </h3>
                                <p className="text-[11px] text-zinc-400">
                                  {item.category}
                                </p>
                              </div>
                            </div>

                            <p className="text-xs text-zinc-500 leading-relaxed">
                              {item.description}
                            </p>
                          </div>

                          <div className="pt-3 border-t border-[#161B20] flex items-center justify-between gap-2">
                            {safeUrl ? (
                              <a
                                href={safeUrl}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="px-3 py-1.5 rounded-lg bg-[#07090B] hover:bg-[#10151A] border border-[#161B20] hover:border-[#00FF66]/40 text-xs font-medium text-zinc-200 hover:text-[#00FF66] inline-flex items-center gap-1.5 transition-colors"
                              >
                                <span>Open Notion Workspace</span>
                                <ArrowUpRight className="w-3.5 h-3.5 text-[#00FF66]" />
                              </a>
                            ) : (
                              <span className="text-xs text-zinc-500">
                                Internal Record
                              </span>
                            )}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </section>

                {/* 3. BLACKTOWER VAULT™ Subsystems & Engineering Self-Tests */}
                <section className="space-y-4">
                  <div className="flex items-center justify-between">
                    <h2 className="font-[family-name:var(--font-mono)] text-xs tracking-[0.2em] uppercase text-zinc-300 font-semibold">
                      BLACKTOWER VAULT™ INTERNAL SUBSYSTEMS &amp; ENGINEERING TESTS
                    </h2>
                    <span className="font-[family-name:var(--font-mono)] text-[11px] text-zinc-500">
                      Part of BLACKTOWER VAULT™ · Not Standalone Products
                    </span>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    {vaultSubsystems.map((sub) => (
                      <div
                        key={sub.id}
                        className="bg-[#0B0E11] border border-[#161B20] rounded-xl p-5 flex flex-col justify-between gap-4"
                      >
                        <div className="space-y-2">
                          <span className="inline-block px-2 py-0.5 rounded bg-[#00FF66]/10 border border-[#00FF66]/30 text-[10px] font-[family-name:var(--font-mono)] uppercase tracking-wider text-[#00FF66]">
                            {sub.concept}
                          </span>
                          <h3 className="text-sm font-bold text-white font-[family-name:var(--font-display)]">
                            {sub.name}
                          </h3>
                          <p className="text-xs text-zinc-400 leading-relaxed">
                            {sub.description}
                          </p>
                        </div>

                        {sub.internalRoute && (
                          <button
                            type="button"
                            onClick={() =>
                              handleLaunchVaultWithTransition(
                                sub.internalRoute!,
                                sub.name
                              )
                            }
                            className="px-3 py-1.5 rounded-lg bg-[#07090B] hover:bg-[#10151A] border border-[#161B20] text-xs font-medium text-[#00FF66] inline-flex items-center justify-between transition-colors"
                          >
                            <span>{sub.actionLabel || 'Inspect in Vault'}</span>
                            <ArrowUpRight className="w-3.5 h-3.5" />
                          </button>
                        )}
                      </div>
                    ))}
                  </div>
                </section>
              </>
            )}
          </div>
        )}
      </main>

      <BlacktowerFooter />
    </div>
  );
}
