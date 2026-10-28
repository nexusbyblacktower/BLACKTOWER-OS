'use client';

import React, { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import PortalLandingView from '@/components/portal/PortalLandingView';
import CommandDashboardView from '@/components/portal/CommandDashboardView';
import {
  type PortalSessionUser,
  loadPortalSession,
  savePortalSession,
} from '@/lib/portal/portal-auth';

export default function BlacktowerPortalHomePage() {
  const router = useRouter();
  const [user, setUser] = useState<PortalSessionUser | null>(null);

  useEffect(() => {
    const stored = loadPortalSession();
    if (stored) {
      setUser(stored);
    }
  }, []);

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    if (params.has('autostart')) {
      params.delete('autostart');
      const cleanQuery = params.toString();
      router.replace(cleanQuery ? `/?${cleanQuery}` : '/');
    }
  }, [router]);

  if (user) {
    return <CommandDashboardView sessionUser={user} />;
  }

  return (
    <PortalLandingView
      sessionUser={user}
      onSessionUpdate={(nextUser) => setUser(nextUser)}
    />
  );
}
