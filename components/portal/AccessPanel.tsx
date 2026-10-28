'use client';

import React, { useState } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import {
  ArrowLeft,
  ArrowRight,
  Eye,
  EyeOff,
  Fingerprint,
  LoaderCircle,
  LockKeyhole,
  LogOut,
  Mail,
  Shield,
} from 'lucide-react';
import {
  type PortalSessionUser,
  clearPortalSession,
  savePortalSession,
  validatePortalEmail,
  validatePortalPassword,
} from '@/lib/portal/portal-auth';

interface AccessPanelProps {
  sessionUser: PortalSessionUser | null;
  onSessionUpdate: (user: PortalSessionUser | null) => void;
  defaultEmail?: string;
  defaultPassword?: string;
}

export default function AccessPanel({
  sessionUser,
  onSessionUpdate,
  defaultEmail = '',
  defaultPassword = '',
}: AccessPanelProps) {
  const router = useRouter();
  const [mode, setMode] = useState<'signin' | 'forgot'>('signin');
  const [email, setEmail] = useState(defaultEmail);
  const [password, setPassword] = useState(defaultPassword);
  const [showPassword, setShowPassword] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [recoverySuccessMessage, setRecoverySuccessMessage] = useState<
    string | null
  >(null);

  const handleSignInSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMessage(null);

    const emailCheck = validatePortalEmail(email);
    if (!emailCheck.valid) {
      setErrorMessage(emailCheck.error || 'Enter a valid email address.');
      return;
    }

    const passwordCheck = validatePortalPassword(password);
    if (!passwordCheck.valid) {
      setErrorMessage(passwordCheck.error || 'Password is required.');
      return;
    }

    setIsSubmitting(true);
    try {
      const response = await fetch('/api/portal/auth', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          mode: 'signin',
          email: emailCheck.normalizedEmail,
          password,
        }),
      });

      const payload = (await response.json()) as {
        status?: string;
        user?: PortalSessionUser;
        error?: string;
      };

      if (!response.ok || !payload.user) {
        setErrorMessage(payload.error || 'Invalid email or password.');
        return;
      }

      savePortalSession(payload.user);
      onSessionUpdate(payload.user);
      setPassword('');
      router.push('/command');
    } catch {
      setErrorMessage(
        'Access service is unavailable. Please try again later.'
      );
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleRecoverySubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMessage(null);
    setRecoverySuccessMessage(null);

    const emailCheck = validatePortalEmail(email);
    if (!emailCheck.valid) {
      setErrorMessage(emailCheck.error || 'Enter a valid email address.');
      return;
    }

    setIsSubmitting(true);
    try {
      const response = await fetch('/api/portal/auth', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          mode: 'recover',
          email: emailCheck.normalizedEmail,
        }),
      });

      const payload = (await response.json()) as {
        status?: string;
        message?: string;
        error?: string;
      };

      if (!response.ok) {
        setErrorMessage(
          payload.error ||
            'Access service is unavailable. Please try again later.'
        );
        return;
      }

      setRecoverySuccessMessage(
        payload.message ||
          'If this email belongs to an authorized account, a recovery link will arrive shortly.'
      );
    } catch {
      setErrorMessage(
        'Access service is unavailable. Please try again later.'
      );
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleSignOut = async () => {
    clearPortalSession();
    onSessionUpdate(null);
    setPassword('');
    setErrorMessage(null);
    try {
      await fetch('/api/portal/auth', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mode: 'signout' }),
      });
    } catch {
      // Ignore network error on local signout
    }
  };

  return (
    <div className="bg-[#0B0E11] border border-[#161B20] rounded-2xl p-6 sm:p-8 w-full max-w-md mx-auto shadow-[0_24px_64px_-16px_rgba(0,0,0,0.85)]">
      {/* Top Row: Fingerprint Icon Box + ACCESS POINT / 01 */}
      <div className="flex items-center justify-between mb-6">
        <div className="w-11 h-11 rounded-xl bg-[#07090B] border border-[#161B20] flex items-center justify-center">
          <Fingerprint className="w-5 h-5 text-[#00FF66]" />
        </div>
        <span className="font-[family-name:var(--font-mono)] text-[10px] tracking-[0.22em] uppercase text-zinc-400">
          ACCESS POINT / 01
        </span>
      </div>

      {/* Authenticated Session View */}
      {sessionUser ? (
        <div className="space-y-6">
          <div>
            <h2 className="font-[family-name:var(--font-display)] text-2xl font-bold text-white tracking-tight">
              Session verified.
            </h2>
            <p className="text-sm text-zinc-400 mt-1">
              Authorized access to BLACKTOWER OS™ is active.
            </p>
          </div>

          <div className="rounded-xl bg-[#07090B] border border-[#161B20] p-4 space-y-2">
            <div className="flex items-center justify-between">
              <span className="font-[family-name:var(--font-mono)] text-[10px] tracking-[0.2em] uppercase text-[#00FF66]">
                ACTIVE OPERATOR
              </span>
              <span className="inline-flex items-center gap-1.5 font-[family-name:var(--font-mono)] text-[10px] uppercase tracking-wider text-[#00FF66]">
                <span className="w-1.5 h-1.5 rounded-full bg-[#00FF66] animate-pulse" />
                ONLINE
              </span>
            </div>
            <p className="text-sm font-medium text-white truncate">
              {sessionUser.email}
            </p>
          </div>

          <div className="space-y-2.5">
            <Link
              href="/command"
              className="h-11 px-5 rounded-lg bg-[#00FF66] hover:bg-[#22FF7A] text-[#050505] font-semibold text-sm flex items-center justify-between w-full transition-colors shadow-[0_0_24px_rgba(0,255,102,0.16)]"
            >
              <span>Open BLACKTOWER OS™</span>
              <ArrowRight className="w-4 h-4" />
            </Link>

            <button
              type="button"
              onClick={handleSignOut}
              className="h-10 px-4 rounded-lg border border-[#161B20] bg-[#07090B] hover:bg-[#10151A] text-xs font-medium text-zinc-300 hover:text-white flex items-center justify-center gap-2 w-full transition-colors"
            >
              <LogOut className="w-3.5 h-3.5" />
              <span>Sign out of portal</span>
            </button>
          </div>
        </div>
      ) : mode === 'signin' ? (
        /* Sign-In Mode */
        <div>
          <h2 className="font-[family-name:var(--font-display)] text-2xl font-bold text-white tracking-tight">
            Welcome back.
          </h2>
          <p className="text-xs sm:text-sm text-zinc-400 mt-1 mb-6">
            Sign in to access your private infrastructure.
          </p>

          <form onSubmit={handleSignInSubmit} className="space-y-4" noValidate>
            <div>
              <label
                htmlFor="portal-email"
                className="block font-[family-name:var(--font-mono)] text-[10px] tracking-[0.2em] uppercase text-zinc-300 mb-2"
              >
                Email address
              </label>
              <div className="relative">
                <Mail className="w-4 h-4 text-zinc-500 absolute left-3.5 top-1/2 -translate-y-1/2 pointer-events-none" />
                <input
                  id="portal-email"
                  name="email"
                  type="email"
                  autoComplete="email"
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="you@company.com"
                  className="w-full h-11 pl-10 pr-3.5 rounded-lg bg-[#07090B] border border-[#161B20] text-sm text-white placeholder:text-zinc-600 focus:outline-none focus:border-[#00FF66] focus:ring-1 focus:ring-[#00FF66]/20 transition-colors"
                />
              </div>
            </div>

            <div>
              <div className="flex items-center justify-between mb-2">
                <label
                  htmlFor="portal-password"
                  className="font-[family-name:var(--font-mono)] text-[10px] tracking-[0.2em] uppercase text-zinc-300"
                >
                  Password
                </label>
                <button
                  type="button"
                  onClick={() => {
                    setErrorMessage(null);
                    setRecoverySuccessMessage(null);
                    setMode('forgot');
                  }}
                  className="text-xs text-zinc-400 hover:text-[#00FF66] transition-colors"
                >
                  Forgot password?
                </button>
              </div>
              <div className="relative">
                <LockKeyhole className="w-4 h-4 text-zinc-500 absolute left-3.5 top-1/2 -translate-y-1/2 pointer-events-none" />
                <input
                  id="portal-password"
                  name="password"
                  type={showPassword ? 'text' : 'password'}
                  autoComplete="current-password"
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Enter your password"
                  className="w-full h-11 pl-10 pr-10 rounded-lg bg-[#07090B] border border-[#161B20] text-sm text-white placeholder:text-zinc-600 focus:outline-none focus:border-[#00FF66] focus:ring-1 focus:ring-[#00FF66]/20 transition-colors"
                />
                <button
                  type="button"
                  aria-label={showPassword ? 'Hide password' : 'Show password'}
                  onClick={() => setShowPassword((prev) => !prev)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-zinc-500 hover:text-zinc-300 transition-colors"
                >
                  {showPassword ? (
                    <EyeOff className="w-4 h-4" />
                  ) : (
                    <Eye className="w-4 h-4" />
                  )}
                </button>
              </div>
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
              disabled={isSubmitting}
              className="h-11 px-5 rounded-lg bg-[#00FF66] hover:bg-[#22FF7A] disabled:opacity-50 text-[#050505] font-semibold text-sm flex items-center justify-between w-full transition-colors mt-2 shadow-[0_0_24px_rgba(0,255,102,0.16)]"
            >
              <span>
                {isSubmitting
                  ? 'Verifying credentials...'
                  : 'Enter command portal'}
              </span>
              {isSubmitting ? (
                <LoaderCircle className="w-4 h-4 animate-spin" />
              ) : (
                <ArrowRight className="w-4 h-4" />
              )}
            </button>
          </form>

          <p className="text-[11px] text-zinc-500 mt-4">
            Authorized accounts only. No public registration.
          </p>
        </div>
      ) : (
        /* Forgot Password / Recovery Mode */
        <div>
          <h2 className="font-[family-name:var(--font-display)] text-2xl font-bold text-white tracking-tight">
            Password recovery.
          </h2>
          <p className="text-xs sm:text-sm text-zinc-400 mt-1 mb-6">
            Enter your authorized email to receive a secure reset link.
          </p>

          <form onSubmit={handleRecoverySubmit} className="space-y-4" noValidate>
            <div>
              <label
                htmlFor="recovery-email"
                className="block font-[family-name:var(--font-mono)] text-[10px] tracking-[0.2em] uppercase text-zinc-300 mb-2"
              >
                Email address
              </label>
              <div className="relative">
                <Mail className="w-4 h-4 text-zinc-500 absolute left-3.5 top-1/2 -translate-y-1/2 pointer-events-none" />
                <input
                  id="recovery-email"
                  name="email"
                  type="email"
                  autoComplete="email"
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="you@company.com"
                  className="w-full h-11 pl-10 pr-3.5 rounded-lg bg-[#07090B] border border-[#161B20] text-sm text-white placeholder:text-zinc-600 focus:outline-none focus:border-[#00FF66] focus:ring-1 focus:ring-[#00FF66]/20 transition-colors"
                />
              </div>
            </div>

            {errorMessage && (
              <div
                role="alert"
                className="p-3 rounded-lg bg-rose-950/60 border border-rose-800/80 text-xs text-rose-200"
              >
                {errorMessage}
              </div>
            )}

            {recoverySuccessMessage && (
              <div
                role="status"
                className="p-3.5 rounded-lg bg-[#00FF66]/10 border border-[#00FF66]/30 text-xs text-zinc-200 space-y-2"
              >
                <p>{recoverySuccessMessage}</p>
                <Link
                  href="/reset-password"
                  className="inline-flex items-center gap-1.5 text-[#00FF66] hover:underline font-medium"
                >
                  <span>Proceed to password reset verification</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </Link>
              </div>
            )}

            <button
              type="submit"
              disabled={isSubmitting}
              className="h-11 px-5 rounded-lg bg-[#00FF66] hover:bg-[#22FF7A] disabled:opacity-50 text-[#050505] font-semibold text-sm flex items-center justify-between w-full transition-colors shadow-[0_0_24px_rgba(0,255,102,0.16)]"
            >
              <span>
                {isSubmitting ? 'Dispatching link...' : 'Send recovery link'}
              </span>
              {isSubmitting ? (
                <LoaderCircle className="w-4 h-4 animate-spin" />
              ) : (
                <ArrowRight className="w-4 h-4" />
              )}
            </button>

            <button
              type="button"
              onClick={() => {
                setErrorMessage(null);
                setRecoverySuccessMessage(null);
                setMode('signin');
              }}
              className="w-full pt-1 text-xs text-zinc-400 hover:text-white inline-flex items-center justify-center gap-1.5 transition-colors"
            >
              <ArrowLeft className="w-3.5 h-3.5" />
              <span>Back to sign in</span>
            </button>
          </form>
        </div>
      )}

      {/* Card Footer */}
      <div className="mt-6 pt-5 border-t border-[#161B20] flex items-center justify-center gap-2 text-zinc-500">
        <Shield className="w-3.5 h-3.5 text-[#00FF66]" />
        <span className="font-[family-name:var(--font-mono)] text-[10px] tracking-[0.2em] uppercase">
          PRIVATE ACCESS. BY INVITATION ONLY.
        </span>
      </div>
    </div>
  );
}
