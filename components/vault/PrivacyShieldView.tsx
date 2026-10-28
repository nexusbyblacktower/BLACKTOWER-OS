'use client';

import React from 'react';
import { ShieldAlert, Lock, ShieldCheck } from 'lucide-react';
import type { ScreenExposureState } from '@/lib/security/screen-exposure-engine';

interface PrivacyShieldViewProps {
  exposureState: ScreenExposureState;
  extremeModeEnabled: boolean;
  onReturnToSafety: () => void;
  onLockVault: () => void;
}

export default function PrivacyShieldView({
  exposureState,
  extremeModeEnabled,
  onReturnToSafety,
  onLockVault,
}: PrivacyShieldViewProps) {
  return (
    <div
      role="region"
      aria-labelledby="privacy-shield-heading"
      className="min-h-screen bg-[#050505] text-slate-100 flex flex-col items-center justify-center p-6 select-none"
    >
      <div className="max-w-lg w-full bg-[#0B0E11] border border-slate-800 rounded-xl p-8 space-y-6 text-center">
        <div className="w-14 h-14 rounded-xl bg-amber-950/70 border border-amber-800/80 flex items-center justify-center mx-auto">
          <ShieldAlert className="w-7 h-7 text-amber-400" />
        </div>

        <div className="space-y-3">
          <div className="text-xs font-mono uppercase tracking-wider text-amber-400">
            Screen Exposure Protection Engine · {exposureState}
          </div>

          <h1
            id="privacy-shield-heading"
            className="text-2xl font-bold text-white tracking-tight"
            style={{ fontFamily: 'var(--font-display)' }}
          >
            Vault Protected
          </h1>

          <p className="text-sm text-slate-200 leading-relaxed">
            Sensitive content is temporarily hidden because this device appears to be sharing or displaying its screen externally.
          </p>

          <p className="text-xs text-slate-400 leading-relaxed">
            Disconnect screen sharing or external display to continue.
          </p>
        </div>

        {extremeModeEnabled && (
          <div className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-300 leading-relaxed">
            <strong>Extreme Screen Protection Active:</strong> Decrypted vault buffers, revealed secrets, and temporary previews were immediately cleared. Re-authentication is required upon returning to a private display.
          </div>
        )}

        <div className="flex flex-col sm:flex-row items-center justify-center gap-3 pt-2">
          <button
            type="button"
            onClick={onReturnToSafety}
            className="w-full sm:w-auto px-5 py-2.5 text-xs font-semibold text-slate-950 bg-[#00FF66] hover:bg-[#22FF7A] rounded-lg transition-colors inline-flex items-center justify-center gap-2 whitespace-nowrap"
          >
            <ShieldCheck className="w-4 h-4" />
            <span>Return to Safety</span>
          </button>

          <button
            type="button"
            onClick={onLockVault}
            className="w-full sm:w-auto px-5 py-2.5 text-xs font-medium text-slate-200 bg-slate-900 hover:bg-slate-800 border border-slate-700 rounded-lg transition-colors inline-flex items-center justify-center gap-2 whitespace-nowrap"
          >
            <Lock className="w-4 h-4 text-slate-400" />
            <span>Lock Vault</span>
          </button>
        </div>
      </div>
    </div>
  );
}
