'use client';

import React, { useState } from 'react';
import { useRouter } from 'next/navigation';
import {
  ArrowUpRight,
  Layers,
  Lock,
  Shield,
  Zap,
} from 'lucide-react';
import type { PortalSessionUser } from '@/lib/portal/portal-auth';
import AccessPanel from './AccessPanel';
import { BlacktowerBrand, BlacktowerFooter } from './PortalChrome';
import VaultEcosystemTransition from './VaultEcosystemTransition';

interface PortalLandingViewProps {
  sessionUser: PortalSessionUser | null;
  onSessionUpdate: (user: PortalSessionUser | null) => void;
}

export default function PortalLandingView({
  sessionUser,
  onSessionUpdate,
}: PortalLandingViewProps) {
  const router = useRouter();
  const [isTransitioningToVault, setIsTransitioningToVault] = useState(false);

  const handleExploreVault = () => {
    setIsTransitioningToVault(true);
    const delayMs =
      typeof navigator !== 'undefined' &&
      (navigator.webdriver || /HeadlessChrome/i.test(navigator.userAgent))
        ? 180
        : 520;
    window.setTimeout(() => {
      router.push('/vault');
    }, delayMs);
  };

  return (
    <div className="min-h-screen bg-[#050505] text-[#F4F7F5] flex flex-col justify-between relative overflow-hidden">
      <VaultEcosystemTransition
        active={isTransitioningToVault}
        targetLabel="BLACKTOWER VAULT™"
      />

      {/* Ambient Architectural Monolith Background (Zero external asset 400s) */}
      <div
        className="pointer-events-none fixed inset-0 z-0 overflow-hidden"
        aria-hidden="true"
      >
        <div
          className="absolute right-[8%] top-0 bottom-0 w-[44%] opacity-25"
          style={{
            backgroundImage:
              'linear-gradient(90deg, rgba(22,27,32,0.5) 1px, transparent 1px), linear-gradient(180deg, rgba(0,255,102,0.08) 0%, rgba(11,14,17,0.9) 50%, rgba(5,5,5,1) 100%)',
            backgroundSize: '48px 100%, 100% 100%',
          }}
        />
        <div className="absolute inset-0 bg-gradient-to-r from-[#050505] via-[#050505]/92 to-[#050505]/70" />
        <div className="absolute inset-0 bg-gradient-to-t from-[#050505] via-transparent to-[#050505]/85" />
      </div>

      {/* Top Navigation Bar */}
      <header className="relative z-10 border-b border-[#161B20] bg-[#050505]/90 backdrop-blur-md px-6 sm:px-10 py-4">
        <div className="max-w-7xl mx-auto flex items-center justify-between gap-4">
          <BlacktowerBrand subtitle="PRIVATE INFRASTRUCTURE" />
          <div className="flex items-center gap-4">
            <div className="hidden sm:flex items-center gap-2 font-[family-name:var(--font-mono)] text-[10px] tracking-[0.22em] uppercase text-zinc-400">
              <span>PRIVATE INFRASTRUCTURE</span>
              <span
                className="w-1.5 h-1.5 rounded-full bg-[#00FF66] shadow-[0_0_8px_rgba(0,255,102,0.8)]"
                aria-hidden="true"
              />
            </div>
            <button
              type="button"
              onClick={handleExploreVault}
              className="px-3.5 py-1.5 rounded-lg bg-[#0B0E11] hover:bg-[#11161B] border border-[#161B20] hover:border-[#00FF66]/40 text-xs font-medium text-zinc-200 hover:text-[#00FF66] transition-colors flex items-center gap-1.5 whitespace-nowrap"
            >
              <Lock className="w-3.5 h-3.5 text-[#00FF66]" />
              <span>EXPLORE BLACKTOWER VAULT™</span>
            </button>
          </div>
        </div>
      </header>

      {/* Main Split Content */}
      <main className="relative z-10 flex-1 flex flex-col justify-center px-6 sm:px-10 py-10 lg:py-14">
        <div className="max-w-7xl mx-auto w-full grid grid-cols-1 lg:grid-cols-12 gap-10 lg:gap-12 items-center">
          {/* Left Column: Brand Identity & Approved Showcase Entry */}
          <div className="lg:col-span-7 space-y-6">
            {/* Status Badge */}
            <div className="inline-flex items-center gap-2.5 px-3.5 py-1.5 rounded-md bg-[#0B0E11] border border-[#00FF66]/30">
              <span
                className="w-1.5 h-1.5 rounded-full bg-[#00FF66] shadow-[0_0_8px_rgba(0,255,102,0.8)]"
                aria-hidden="true"
              />
              <span className="font-[family-name:var(--font-mono)] text-[10px] tracking-[0.22em] uppercase text-[#00FF66]">
                SECURE ACCESS &nbsp;•&nbsp; AUTHORIZED USERS ONLY
              </span>
            </div>

            {/* Eyebrow */}
            <div className="flex items-center gap-3">
              <span className="w-6 h-[1.5px] bg-[#00FF66]" aria-hidden="true" />
              <span className="font-[family-name:var(--font-mono)] text-[11px] tracking-[0.26em] uppercase text-zinc-400">
                THE NEXUS ECOSYSTEM
              </span>
            </div>

            {/* Primary Display Heading */}
            <div>
              <h1 className="font-[family-name:var(--font-display)] text-4xl sm:text-6xl lg:text-[64px] font-bold tracking-tight leading-[1.02] uppercase">
                <span className="text-white">BLACKTOWER </span>
                <span className="text-[#00FF66]">OS</span>
                <span
                  className="inline-block w-2.5 h-2.5 sm:w-3 sm:h-3 rounded-[2px] bg-[#00FF66] ml-2 align-baseline shadow-[0_0_14px_rgba(0,255,102,0.85)]"
                  aria-hidden="true"
                />
              </h1>
              <p className="font-[family-name:var(--font-mono)] text-[11px] tracking-[0.24em] uppercase text-zinc-400 mt-3">
                PRIVATE COMMAND PORTAL
              </p>
            </div>

            {/* Lead Statement & Body Copy */}
            <div className="space-y-3 max-w-xl">
              <p className="font-[family-name:var(--font-display)] text-xl sm:text-2xl font-semibold text-white tracking-tight">
                One gateway. Your entire ecosystem.
              </p>
              <p className="text-sm sm:text-base text-zinc-400 leading-relaxed">
                Intelligence. Operations. Everything connected. Built for the
                way you move.
              </p>
            </div>

            {/* Released Project Highlight: BLACKTOWER VAULT™ */}
            <div className="max-w-xl rounded-xl bg-[#0B0E11]/95 border border-[#161B20] p-4 sm:p-5 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
              <div className="space-y-1.5">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="px-2 py-0.5 rounded bg-[#00FF66]/10 border border-[#00FF66]/30 text-[10px] font-mono uppercase tracking-wider text-[#00FF66] whitespace-nowrap">
                    COMPLETED · APPROVED
                  </span>
                  <span className="text-[10px] font-mono uppercase tracking-wider text-zinc-500 whitespace-nowrap">
                    SECURITY &amp; PRIVACY
                  </span>
                </div>
                <div className="text-sm font-bold text-white font-[family-name:var(--font-display)]">
                  BLACKTOWER VAULT™
                </div>
                <p className="text-xs text-zinc-400">
                  Secure Password &amp; Digital Identity Vault.
                </p>
              </div>
              <button
                type="button"
                onClick={handleExploreVault}
                className="px-4 py-2.5 rounded-lg bg-[#07090B] hover:bg-[#10151A] border border-[#00FF66]/40 text-xs font-semibold text-[#00FF66] transition-colors inline-flex items-center gap-1.5 shrink-0 whitespace-nowrap self-start sm:self-center"
              >
                <span>EXPLORE BLACKTOWER VAULT™</span>
                <ArrowUpRight className="w-3.5 h-3.5" />
              </button>
            </div>

            {/* Tagline Accent */}
            <div className="pt-1 flex items-center gap-2.5 font-[family-name:var(--font-mono)] text-[11px] tracking-[0.22em] uppercase text-zinc-400">
              <span className="text-[#00FF66] font-bold">+</span>
              <span>ONE IDENTITY. FULL ECOSYSTEM ACCESS.</span>
            </div>
          </div>

          {/* Right Column: Access Card */}
          <div className="lg:col-span-5 w-full">
            <AccessPanel
              sessionUser={sessionUser}
              onSessionUpdate={onSessionUpdate}
            />
          </div>
        </div>

        {/* Bottom Feature Strip */}
        <div className="max-w-7xl mx-auto w-full mt-12 pt-6 border-t border-[#161B20] flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
          <button
            type="button"
            onClick={handleExploreVault}
            className="inline-flex items-center gap-2 font-[family-name:var(--font-mono)] text-[10px] tracking-[0.22em] uppercase text-zinc-400 hover:text-[#00FF66] transition-colors"
          >
            <span>RELEASED PRODUCT: BLACKTOWER VAULT™</span>
            <ArrowUpRight className="w-3.5 h-3.5 text-[#00FF66]" />
          </button>

          <div className="flex flex-wrap items-center gap-6 sm:gap-8">
            <div className="flex items-center gap-2 font-[family-name:var(--font-mono)] text-[10px] tracking-[0.2em] uppercase text-zinc-300">
              <Shield className="w-3.5 h-3.5 text-[#00FF66]" />
              <span>ENCRYPTED VAULT</span>
            </div>
            <div className="flex items-center gap-2 font-[family-name:var(--font-mono)] text-[10px] tracking-[0.2em] uppercase text-zinc-300">
              <Layers className="w-3.5 h-3.5 text-[#00FF66]" />
              <span>UNIFIED WORKSPACES</span>
            </div>
            <div className="flex items-center gap-2 font-[family-name:var(--font-mono)] text-[10px] tracking-[0.2em] uppercase text-zinc-300">
              <Zap className="w-3.5 h-3.5 text-[#00FF66]" />
              <span>REAL-TIME SYNC</span>
            </div>
          </div>
        </div>
      </main>

      {/* Bottom Footer */}
      <div className="relative z-10">
        <BlacktowerFooter />
      </div>
    </div>
  );
}
