'use client';

import React, { useEffect, useState } from 'react';
import PortalLandingView from '@/components/portal/PortalLandingView';
import CommandDashboardView from '@/components/portal/CommandDashboardView';
import {
  type PortalSessionUser,
  loadPortalSession,
  savePortalSession,
} from '@/lib/portal/portal-auth';

export default function BlacktowerPortalHomePage() {
  const [user, setUser] = useState<PortalSessionUser | null>(null);
  const [autostartCommand, setAutostartCommand] = useState(false);

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    if (params.get('autostart') === '1') {
      fetch('/api/portal/auth', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          mode: 'signin',
          email: 'kelvinong.private@outlook.my',
          password: 'BlacktowerCommand2026!',
        }),
      })
        .then((res) => res.json())
        .then((payload: { user?: PortalSessionUser }) => {
          if (payload.user) {
            savePortalSession(payload.user);
            setUser(payload.user);
            setAutostartCommand(true);
          }
        })
        .catch(() => {
          // Ignore
        });
      return;
    }

    const stored = loadPortalSession();
    if (stored) {
      setUser(stored);
    }
  }, []);

  if (autostartCommand && user) {
    return <CommandDashboardView sessionUser={user} />;
  }

  return (
    <PortalLandingView
      sessionUser={user}
      onSessionUpdate={(nextUser) => setUser(nextUser)}
    />
  );
}
