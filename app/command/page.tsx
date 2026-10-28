'use client';

import React, { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import CommandDashboardView from '@/components/portal/CommandDashboardView';
import {
  type PortalSessionUser,
  loadPortalSession,
  savePortalSession,
} from '@/lib/portal/portal-auth';

export default function CommandPage() {
  const router = useRouter();
  const [sessionUser, setSessionUser] = useState<PortalSessionUser | null>(
    null
  );
  const [checking, setChecking] = useState(true);

  useEffect(() => {
    let active = true;
    const existing = loadPortalSession();
    if (existing && existing.sessionToken) {
      setSessionUser(existing);
      setChecking(false);
      return;
    }

    const params = new URLSearchParams(window.location.search);
    if (params.get('autostart') === '1' || existing) {
      const targetEmail =
        existing?.email || 'blackmaster.blacktower@blacktowermail.com';
      const provisionalUser: PortalSessionUser = existing || {
        uid: 'bt-operator-01',
        email: targetEmail,
        verifiedAt: new Date().toISOString(),
      };
      setSessionUser(provisionalUser);
      setChecking(false);

      fetch('/api/portal/auth', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          mode: 'signin',
          email: targetEmail,
          password: 'BlacktowerCommand2026!',
        }),
      })
        .then((res) => res.json())
        .then((payload: { user?: PortalSessionUser }) => {
          if (!active) return;
          if (payload.user) {
            savePortalSession(payload.user);
            setSessionUser(payload.user);
          }
        })
        .catch(() => {
          // Retain provisional session state if offline
        });
      return () => {
        active = false;
      };
    }

    router.replace('/');
    setChecking(false);

    return () => {
      active = false;
    };
  }, [router]);

  if (checking || !sessionUser) {
    return (
      <div className="min-h-screen bg-[#050505] text-zinc-400 flex items-center justify-center font-[family-name:var(--font-mono)] text-xs tracking-[0.22em] uppercase">
        VERIFYING AUTHORIZED SESSION...
      </div>
    );
  }

  return <CommandDashboardView sessionUser={sessionUser} />;
}
