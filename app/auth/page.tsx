'use client';

import React, { useEffect, useState } from 'react';
import AccessPanel from '@/components/portal/AccessPanel';
import {
  BlacktowerBrand,
  BlacktowerFooter,
} from '@/components/portal/PortalChrome';
import {
  type PortalSessionUser,
  loadPortalSession,
} from '@/lib/portal/portal-auth';

export default function AuthPage() {
  const [sessionUser, setSessionUser] = useState<PortalSessionUser | null>(
    null
  );

  useEffect(() => {
    const existing = loadPortalSession();
    if (existing) {
      setSessionUser(existing);
    }
  }, []);

  return (
    <div className="min-h-screen bg-[#050505] text-[#F4F7F5] flex flex-col justify-between">
      <header className="border-b border-[#161B20] bg-[#050505]/95 px-6 sm:px-10 py-4">
        <div className="max-w-7xl mx-auto flex items-center justify-between">
          <BlacktowerBrand subtitle="PRIVATE INFRASTRUCTURE" />
          <div className="flex items-center gap-2 font-[family-name:var(--font-mono)] text-[10px] tracking-[0.22em] uppercase text-zinc-400">
            <span>ACCESS VERIFICATION</span>
            <span className="w-1.5 h-1.5 rounded-full bg-[#00FF66]" />
          </div>
        </div>
      </header>

      <main className="flex-1 flex items-center justify-center px-6 py-12">
        <AccessPanel
          sessionUser={sessionUser}
          onSessionUpdate={setSessionUser}
        />
      </main>

      <BlacktowerFooter />
    </div>
  );
}
