'use client';

import React from 'react';
import Link from 'next/link';

export function BlacktowerBrand({ subtitle }: { subtitle?: string }) {
  return (
    <Link
      href="/"
      aria-label="BLACKTOWER home"
      className="font-[family-name:var(--font-display)] flex items-center gap-3 group focus:outline-none focus-visible:ring-2 focus-visible:ring-[#00FF66]/50 rounded-md"
    >
      <span className="flex items-end gap-[3px] h-5" aria-hidden="true">
        <span className="w-[3px] h-4 bg-white rounded-[1px]" />
        <span className="w-[3px] h-5 bg-[#00FF66] rounded-[1px] shadow-[0_0_8px_rgba(0,255,102,0.5)]" />
        <span className="w-[3px] h-3.5 bg-white/85 rounded-[1px]" />
      </span>
      <span className="text-sm sm:text-base font-bold tracking-[0.12em] uppercase text-white">
        BLACKTOWER<sup className="text-[10px] text-[#00FF66] ml-0.5">™</sup>
      </span>
      {subtitle && (
        <span className="hidden sm:inline-block font-[family-name:var(--font-mono)] text-[10px] tracking-[0.22em] uppercase text-zinc-400 border-l border-[#161B20] pl-3 whitespace-nowrap shrink-0">
          {subtitle}
        </span>
      )}
    </Link>
  );
}

export function BlacktowerFooter() {
  return (
    <footer className="border-t border-[#161B20] px-6 sm:px-10 py-4 bg-[#050505]">
      <div className="max-w-7xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-3">
        <p className="font-[family-name:var(--font-mono)] text-[10px] tracking-[0.18em] uppercase text-zinc-500">
          © 2026 BLACKTOWER™ &nbsp;/&nbsp; ALL RIGHTS RESERVED
        </p>
        <div className="flex items-center gap-2 font-[family-name:var(--font-mono)] text-[10px] tracking-[0.18em] uppercase text-zinc-400">
          <span className="text-zinc-500">
            SIMPLE OUTSIDE. BRUTAL SECURITY INSIDE.
          </span>
          <span className="text-zinc-700">·</span>
          <span className="font-semibold text-white">BLACKTOWER OS™</span>
          <span
            className="inline-block w-1.5 h-1.5 rounded-full bg-[#00FF66] shadow-[0_0_8px_rgba(0,255,102,0.7)]"
            aria-hidden="true"
          />
        </div>
      </div>
    </footer>
  );
}
