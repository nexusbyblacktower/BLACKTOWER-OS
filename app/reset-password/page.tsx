'use client';

import React, { useEffect, useState } from 'react';
import Link from 'next/link';
import { LockKeyhole } from 'lucide-react';
import {
  BlacktowerBrand,
  BlacktowerFooter,
} from '@/components/portal/PortalChrome';
import { validateRecoveryPassword } from '@/lib/portal/portal-auth';

export default function ResetPasswordPage() {
  const [hasValidToken, setHasValidToken] = useState(false);
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [completed, setCompleted] = useState(false);

  useEffect(() => {
    if (typeof window === 'undefined') return;
    const hash = window.location.hash || '';
    const search = window.location.search || '';
    if (
      hash.includes('type=recovery') ||
      search.includes('type=recovery') ||
      search.includes('token=')
    ) {
      setHasValidToken(true);
    }
  }, []);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMessage(null);
    const check = validateRecoveryPassword(newPassword, confirmPassword);
    if (!check.valid) {
      setErrorMessage(check.error || 'Invalid password.');
      return;
    }
    setCompleted(true);
    setNewPassword('');
    setConfirmPassword('');
  };

  return (
    <div className="min-h-screen bg-[#050505] text-[#F4F7F5] flex flex-col justify-between">
      <header className="border-b border-[#161B20] bg-[#050505]/95 px-6 sm:px-10 py-4">
        <div className="max-w-7xl mx-auto flex items-center justify-between">
          <BlacktowerBrand subtitle="PRIVATE INFRASTRUCTURE" />
          <div className="flex items-center gap-2 font-[family-name:var(--font-mono)] text-[10px] tracking-[0.22em] uppercase text-zinc-400">
            <span>RECOVERY VERIFICATION</span>
            <span className="w-1.5 h-1.5 rounded-full bg-[#00FF66]" />
          </div>
        </div>
      </header>

      <main className="flex-1 flex items-center justify-center px-6 py-12">
        <div className="bg-[#0B0E11] border border-[#161B20] rounded-2xl p-6 sm:p-8 w-full max-w-md mx-auto shadow-[0_24px_64px_-16px_rgba(0,0,0,0.85)]">
          <div className="flex items-center justify-between mb-6">
            <div className="w-11 h-11 rounded-xl bg-[#07090B] border border-[#161B20] flex items-center justify-center">
              <LockKeyhole className="w-5 h-5 text-[#00FF66]" />
            </div>
            <span className="font-[family-name:var(--font-mono)] text-[10px] tracking-[0.22em] uppercase text-zinc-400">
              ACCESS POINT / RECOVERY
            </span>
          </div>

          {!hasValidToken ? (
            <div className="space-y-5">
              <div>
                <h1 className="font-[family-name:var(--font-display)] text-2xl font-bold text-white tracking-tight">
                  Invalid or expired link.
                </h1>
                <p className="text-xs sm:text-sm text-zinc-400 mt-1.5 leading-relaxed">
                  Please request a new password reset from the login screen.
                </p>
              </div>

              <div className="pt-1 flex flex-col gap-2.5">
                <Link
                  href="/"
                  className="h-11 px-5 rounded-lg bg-[#00FF66] hover:bg-[#22FF7A] text-[#050505] font-semibold text-sm flex items-center justify-center w-full transition-colors"
                >
                  Return to sign in
                </Link>
                <button
                  type="button"
                  onClick={() => setHasValidToken(true)}
                  className="text-[11px] font-[family-name:var(--font-mono)] text-zinc-500 hover:text-zinc-300 underline pt-1"
                >
                  Have a manual recovery token? Verify session
                </button>
              </div>
            </div>
          ) : completed ? (
            <div className="space-y-5">
              <div>
                <h1 className="font-[family-name:var(--font-display)] text-2xl font-bold text-white tracking-tight">
                  Password updated.
                </h1>
                <p className="text-xs sm:text-sm text-zinc-400 mt-1.5">
                  Your BLACKTOWER OS™ credentials have been updated.
                </p>
              </div>
              <Link
                href="/"
                className="h-11 px-5 rounded-lg bg-[#00FF66] hover:bg-[#22FF7A] text-[#050505] font-semibold text-sm flex items-center justify-center w-full transition-colors"
              >
                Continue to sign in
              </Link>
            </div>
          ) : (
            <form onSubmit={handleSubmit} className="space-y-4" noValidate>
              <div>
                <h1 className="font-[family-name:var(--font-display)] text-2xl font-bold text-white tracking-tight">
                  Set new password.
                </h1>
                <p className="text-xs sm:text-sm text-zinc-400 mt-1">
                  Enter a new password for your authorized account.
                </p>
              </div>

              <div>
                <label
                  htmlFor="new-password"
                  className="block font-[family-name:var(--font-mono)] text-[10px] tracking-[0.2em] uppercase text-zinc-300 mb-2"
                >
                  New password
                </label>
                <input
                  id="new-password"
                  type="password"
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  placeholder="Minimum 12 characters"
                  className="w-full h-11 px-3.5 rounded-lg bg-[#07090B] border border-[#161B20] text-sm text-white placeholder:text-zinc-600 focus:outline-none focus:border-[#00FF66]"
                />
              </div>

              <div>
                <label
                  htmlFor="confirm-password"
                  className="block font-[family-name:var(--font-mono)] text-[10px] tracking-[0.2em] uppercase text-zinc-300 mb-2"
                >
                  Confirm password
                </label>
                <input
                  id="confirm-password"
                  type="password"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  placeholder="Re-enter new password"
                  className="w-full h-11 px-3.5 rounded-lg bg-[#07090B] border border-[#161B20] text-sm text-white placeholder:text-zinc-600 focus:outline-none focus:border-[#00FF66]"
                />
              </div>

              {errorMessage && (
                <div
                  role="alert"
                  className="p-3 rounded-lg bg-rose-950/60 border border-rose-800/80 text-xs text-rose-200"
                >
                  {errorMessage}
                </div>
              )}

              <button
                type="submit"
                className="h-11 px-5 rounded-lg bg-[#00FF66] hover:bg-[#22FF7A] text-[#050505] font-semibold text-sm flex items-center justify-center w-full transition-colors"
              >
                Update password
              </button>
            </form>
          )}
        </div>
      </main>

      <BlacktowerFooter />
    </div>
  );
}
