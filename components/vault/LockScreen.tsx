'use client';

import React, { useState } from 'react';
import Link from 'next/link';
import { motion } from 'motion/react';
import {
  Lock,
  KeyRound,
  Fingerprint,
  Eye,
  EyeOff,
  AlertCircle,
  CheckCircle2,
  ArrowLeft,
  ArrowRight,
  RefreshCw,
} from 'lucide-react';

interface LockScreenProps {
  hasExistingVault: boolean;
  vaultId?: string;
  lastLockedReason: string | null;
  onUnlockWithPassword: (password: string) => Promise<void>;
  onUnlockWithRecoveryKey: (recoveryKey: string) => Promise<void>;
  onCreateNewVault: (password: string, includeSampleItems: boolean) => Promise<void>;
}

export default function LockScreen({
  hasExistingVault,
  vaultId,
  lastLockedReason,
  onUnlockWithPassword,
  onUnlockWithRecoveryKey,
  onCreateNewVault,
}: LockScreenProps) {
  const [mode, setMode] = useState<'unlock' | 'recovery' | 'setup'>(
    hasExistingVault ? 'unlock' : 'setup'
  );
  const [password, setPassword] = useState(
    hasExistingVault ? '' : 'Blacktower!Master#2026'
  );
  const [confirmPassword, setConfirmPassword] = useState(
    hasExistingVault ? '' : 'Blacktower!Master#2026'
  );
  const [recoveryInput, setRecoveryInput] = useState('');
  const [includeSampleItems, setIncludeSampleItems] = useState(true);
  const [showPassword, setShowPassword] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [showBiometricNotice, setShowBiometricNotice] = useState(false);

  const handlePasswordUnlock = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg(null);
    if (!password.trim()) {
      setErrorMsg('Enter your Master Password to derive the unlocking key.');
      return;
    }
    setIsSubmitting(true);
    try {
      await onUnlockWithPassword(password);
      setPassword('');
    } catch {
      setErrorMsg(
        'Authentication failed. The derived key could not verify the Account Root Key authentication tag.'
      );
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleRecoveryUnlock = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg(null);
    if (!recoveryInput.trim()) {
      setErrorMsg('Enter your 256-bit Recovery Key (BTVK-...).');
      return;
    }
    setIsSubmitting(true);
    try {
      await onUnlockWithRecoveryKey(recoveryInput);
      setRecoveryInput('');
    } catch {
      setErrorMsg(
        'Recovery verification failed. Ensure the 256-bit Recovery Key matches this vault.'
      );
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleSetupVault = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg(null);
    if (password.length < 10) {
      setErrorMsg('Master Password must be at least 10 characters long.');
      return;
    }
    if (password !== confirmPassword) {
      setErrorMsg('Master Password confirmation does not match.');
      return;
    }
    setIsSubmitting(true);
    try {
      await onCreateNewVault(password, includeSampleItems);
      setPassword('');
      setConfirmPassword('');
    } catch (err) {
      setErrorMsg(
        err instanceof Error ? err.message : 'Failed to initialize vault hierarchy.'
      );
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#050505] text-[#F4F7F5] flex flex-col justify-between">
      {/* Top Bar Contract: 3 zones */}
      <header className="flex items-center justify-between gap-4 md:gap-8 px-4 sm:px-6 py-4 border-b border-[#161B20] bg-[#050505]">
        <div className="flex items-center gap-3">
          <Link
            href="/command"
            className="px-2.5 py-1 rounded-md bg-[#0B0E11] hover:bg-[#11161B] border border-[#161B20] hover:border-[#00FF66]/40 text-[11px] font-[family-name:var(--font-mono)] tracking-[0.14em] uppercase text-zinc-300 hover:text-[#00FF66] transition-colors inline-flex items-center gap-1.5"
          >
            <ArrowLeft className="w-3 h-3 text-[#00FF66]" />
            <span>BLACKTOWER OS™</span>
          </Link>
          <span aria-hidden="true" className="text-zinc-700">
            /
          </span>
          <a
            href="#top"
            className="text-sm sm:text-base font-bold tracking-tight text-white whitespace-nowrap shrink-0 flex items-center gap-2"
            style={{ fontFamily: 'var(--font-display)' }}
          >
            <span
              className="w-2 h-2 rounded-full bg-[#00FF66] shadow-[0_0_8px_rgba(0,255,102,0.8)]"
              aria-hidden="true"
            />
            <span>BLACKTOWER VAULT™</span>
          </a>
        </div>

        <nav className="hidden md:flex items-center gap-6 text-xs font-[family-name:var(--font-mono)] tracking-[0.14em] uppercase text-zinc-400">
          <span className="whitespace-nowrap">Client-Side Key Hierarchy</span>
          <span aria-hidden="true" className="text-zinc-700">
            ·
          </span>
          <span className="whitespace-nowrap">Neon PostgreSQL Ciphertext Sync</span>
          <span aria-hidden="true" className="text-zinc-700">
            ·
          </span>
          <span className="whitespace-nowrap">Fail-Closed Storage</span>
        </nav>

        <div className="flex items-center gap-3 shrink-0">
          {hasExistingVault ? (
            <button
              type="button"
              onClick={() => {
                setErrorMsg(null);
                setMode(mode === 'recovery' ? 'unlock' : 'recovery');
              }}
              className="px-3.5 py-1.5 text-xs font-medium text-zinc-300 hover:text-[#00FF66] border border-[#161B20] hover:border-[#00FF66]/40 bg-[#0B0E11] rounded-lg transition-colors whitespace-nowrap shrink-0"
            >
              {mode === 'recovery' ? 'Use Master Password' : 'Recovery Key Unlock'}
            </button>
          ) : (
            <span className="text-xs text-[#00FF66] font-mono tabular-nums whitespace-nowrap">
              STATE: UNINITIALIZED
            </span>
          )}
        </div>
      </header>

      {/* Main Content Split */}
      <motion.main
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.25, ease: 'easeOut' }}
        className="flex-1 max-w-6xl w-full mx-auto px-6 py-12 grid grid-cols-1 lg:grid-cols-12 gap-12 items-center"
      >
        {/* Left Column: Value Proposition & Honest Platform Posture */}
        <div className="lg:col-span-7 space-y-6">
          <div className="text-xs font-mono uppercase tracking-[0.2em] text-[#00FF66]">
            Secure Password &amp; Digital Identity Vault · Independent Auth Boundary
          </div>
          <h1
            className="text-3xl sm:text-4xl lg:text-5xl font-bold tracking-tight text-white leading-[1.12]"
            style={{ fontFamily: 'var(--font-display)', textWrap: 'balance' }}
          >
            Simple outside. Brutal security inside.
          </h1>
          <p className="text-base text-zinc-300 leading-relaxed max-w-xl">
            Every password, note, identity, and payment card is sealed locally using an independent 256-bit item key before touching storage. Your Master Password never leaves memory and is never transmitted.
          </p>

          <div className="pt-4 border-t border-[#161B20] grid grid-cols-1 sm:grid-cols-3 gap-6">
            <div>
              <div className="text-sm font-semibold text-white">
                Four-Tier Key Separation
              </div>
              <p className="text-xs text-zinc-400 mt-1 leading-relaxed">
                Master Password derives KEK via Argon2id v1.3 to unwrap Root, Vault, and Per-Item AES-256-GCM keys.
              </p>
            </div>
            <div>
              <div className="text-sm font-semibold text-white">
                Neon Ciphertext Storage
              </div>
              <p className="text-xs text-zinc-400 mt-1 leading-relaxed">
                Local storage and Neon PostgreSQL hold authenticated ciphertext envelopes only. Memory zeroized on lock.
              </p>
            </div>
            <div>
              <div className="text-sm font-semibold text-white">
                Runtime Diagnostics
              </div>
              <p className="text-xs text-zinc-400 mt-1 leading-relaxed">
                Nine live cryptographic self-tests execute directly in your browser runtime—never simulated.
              </p>
            </div>
          </div>

          {lastLockedReason && (
            <div className="p-4 rounded-lg bg-[#0B0E11] border border-[#161B20] flex items-center gap-3 text-xs text-zinc-300">
              <Lock className="w-4 h-4 text-[#00FF66] shrink-0" />
              <span>
                Session locked ({lastLockedReason}). Sensitive key buffers and decrypted records were cleared from memory.
              </span>
            </div>
          )}
        </div>

        {/* Right Column: Authentication / Provisioning Card */}
        <div className="lg:col-span-5">
          <div className="bg-[#0B0E11] border border-[#161B20] rounded-2xl p-6 sm:p-8 space-y-6 shadow-[0_24px_64px_-16px_rgba(0,0,0,0.85)]">
            {/* Mode Switch Tabs when vault exists */}
            {hasExistingVault && (
              <div className="flex items-center gap-1 p-1 bg-[#07090B] rounded-lg border border-[#161B20]">
                <button
                  type="button"
                  onClick={() => {
                    setErrorMsg(null);
                    setMode('unlock');
                  }}
                  className={`flex-1 py-2 px-3 text-xs font-medium rounded-md transition-colors whitespace-nowrap ${
                    mode === 'unlock'
                      ? 'bg-[#10151A] text-[#00FF66] border border-[#00FF66]/35'
                      : 'text-zinc-400 hover:text-zinc-200'
                  }`}
                >
                  Master Password
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setErrorMsg(null);
                    setMode('recovery');
                  }}
                  className={`flex-1 py-2 px-3 text-xs font-medium rounded-md transition-colors whitespace-nowrap ${
                    mode === 'recovery'
                      ? 'bg-[#10151A] text-[#00FF66] border border-[#00FF66]/35'
                      : 'text-zinc-400 hover:text-zinc-200'
                  }`}
                >
                  Recovery Key
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setErrorMsg(null);
                    setMode('setup');
                  }}
                  className={`flex-1 py-2 px-3 text-xs font-medium rounded-md transition-colors whitespace-nowrap ${
                    mode === 'setup'
                      ? 'bg-[#10151A] text-[#00FF66] border border-[#00FF66]/35'
                      : 'text-zinc-400 hover:text-zinc-200'
                  }`}
                >
                  Reset / New
                </button>
              </div>
            )}

            {mode === 'unlock' && (
              <form onSubmit={handlePasswordUnlock} className="space-y-5">
                <div>
                  <h2
                    className="text-xl font-semibold text-white"
                    style={{ fontFamily: 'var(--font-display)' }}
                  >
                    Unlock Vault
                  </h2>
                  <p className="text-xs text-zinc-400 mt-1">
                    {vaultId
                      ? `Encrypted Container · ${vaultId}`
                      : 'Local Encrypted Vault'}
                  </p>
                </div>

                <div className="space-y-2">
                  <label
                    htmlFor="unlock-master-password"
                    className="block text-xs font-medium text-zinc-300"
                  >
                    Master Password
                  </label>
                  <div className="relative">
                    <input
                      id="unlock-master-password"
                      type={showPassword ? 'text' : 'password'}
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      placeholder="Enter Master Password"
                      autoComplete="current-password"
                      className="w-full px-3.5 py-2.5 pr-10 text-sm bg-[#07090B] border border-[#161B20] rounded-lg text-white placeholder:text-zinc-600 focus:outline-none focus:border-[#00FF66]"
                    />
                    <button
                      type="button"
                      aria-label={
                        showPassword
                          ? 'Hide Master Password'
                          : 'Show Master Password'
                      }
                      onClick={() => setShowPassword(!showPassword)}
                      className="absolute right-3 top-1/2 -translate-y-1/2 text-zinc-400 hover:text-zinc-200"
                    >
                      {showPassword ? (
                        <EyeOff className="w-4 h-4" />
                      ) : (
                        <Eye className="w-4 h-4" />
                      )}
                    </button>
                  </div>
                </div>

                {errorMsg && (
                  <div
                    role="alert"
                    className="p-3 rounded-lg bg-rose-950/60 border border-rose-800/80 text-xs text-rose-200 flex items-start gap-2.5"
                  >
                    <AlertCircle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
                    <span>{errorMsg}</span>
                  </div>
                )}

                <button
                  type="submit"
                  disabled={isSubmitting}
                  className="w-full py-2.5 px-4 bg-[#00FF66] hover:bg-[#22FF7A] disabled:opacity-50 text-[#050505] font-semibold text-sm rounded-lg transition-colors flex items-center justify-center gap-2 whitespace-nowrap shadow-[0_0_24px_rgba(0,255,102,0.16)]"
                >
                  {isSubmitting ? (
                    <>
                      <RefreshCw className="w-4 h-4 animate-spin" />
                      <span>Deriving Key &amp; Unwrapping...</span>
                    </>
                  ) : (
                    <>
                      <Lock className="w-4 h-4" />
                      <span>Unlock Vault</span>
                    </>
                  )}
                </button>

                {/* Honest Biometric Entry Point */}
                <div className="pt-3 border-t border-[#161B20] space-y-2">
                  <button
                    type="button"
                    onClick={() => setShowBiometricNotice(!showBiometricNotice)}
                    className="w-full py-2 px-3 bg-[#07090B] hover:bg-[#10151A] border border-[#161B20] rounded-lg text-xs text-zinc-400 flex items-center justify-between transition-colors"
                  >
                    <span className="flex items-center gap-2">
                      <Fingerprint className="w-4 h-4 text-zinc-500" />
                      <span>
                        Biometric authentication — Unavailable in Preview
                      </span>
                    </span>
                    <span className="text-zinc-500 underline">Why?</span>
                  </button>

                  {showBiometricNotice && (
                    <div className="p-3 rounded-lg bg-[#07090B] border border-[#161B20] text-xs text-zinc-400 leading-relaxed">
                      Platform Honesty Policy: Browser preview does not have access to native Android Keystore or StrongBox hardware-backed biometric key wrapping (`BiometricPrompt.CryptoObject`). BLACKTOWER VAULT™ never simulates hardware biometric unlock in a browser.
                    </div>
                  )}
                </div>
              </form>
            )}

            {mode === 'recovery' && (
              <form onSubmit={handleRecoveryUnlock} className="space-y-5">
                <div>
                  <h2
                    className="text-xl font-semibold text-white"
                    style={{ fontFamily: 'var(--font-display)' }}
                  >
                    Recovery Key Restore
                  </h2>
                  <p className="text-xs text-zinc-400 mt-1">
                    Unwraps the Account Root Key using your 256-bit emergency Recovery Key.
                  </p>
                </div>

                <div className="space-y-2">
                  <label
                    htmlFor="recovery-key-input"
                    className="block text-xs font-medium text-zinc-300"
                  >
                    256-Bit Recovery Key
                  </label>
                  <textarea
                    id="recovery-key-input"
                    rows={3}
                    value={recoveryInput}
                    onChange={(e) => setRecoveryInput(e.target.value)}
                    placeholder="BTVK-XXXXXXXX-XXXXXXXX-XXXXXXXX-XXXXXXXX-XXXXXXXX-XXXXXXXX-XXXXXXXX-XXXXXXXX"
                    className="w-full px-3.5 py-2.5 text-xs font-mono bg-[#07090B] border border-[#161B20] rounded-lg text-white placeholder:text-zinc-600 focus:outline-none focus:border-[#00FF66]"
                  />
                </div>

                {errorMsg && (
                  <div
                    role="alert"
                    className="p-3 rounded-lg bg-rose-950/60 border border-rose-800/80 text-xs text-rose-200 flex items-start gap-2.5"
                  >
                    <AlertCircle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
                    <span>{errorMsg}</span>
                  </div>
                )}

                <button
                  type="submit"
                  disabled={isSubmitting}
                  className="w-full py-2.5 px-4 bg-[#00FF66] hover:bg-[#22FF7A] disabled:opacity-50 text-[#050505] font-semibold text-sm rounded-lg transition-colors flex items-center justify-center gap-2 whitespace-nowrap shadow-[0_0_24px_rgba(0,255,102,0.16)]"
                >
                  <KeyRound className="w-4 h-4" />
                  <span>
                    {isSubmitting
                      ? 'Verifying Recovery Key...'
                      : 'Verify & Unlock Vault'}
                  </span>
                </button>
              </form>
            )}

            {mode === 'setup' && (
              <form onSubmit={handleSetupVault} className="space-y-4">
                <div>
                  <h2
                    className="text-xl font-semibold text-white"
                    style={{ fontFamily: 'var(--font-display)' }}
                  >
                    {hasExistingVault
                      ? 'Provision Fresh Vault'
                      : 'Initialize Encrypted Vault'}
                  </h2>
                  <p className="text-xs text-zinc-400 mt-1">
                    Generates a fresh 16-byte salt, derives an Argon2id v1.3 KEK, and wraps a new 256-bit Root Key and Vault Key.
                  </p>
                </div>

                <div className="space-y-1.5">
                  <label
                    htmlFor="setup-master-password"
                    className="block text-xs font-medium text-zinc-300"
                  >
                    Master Password
                  </label>
                  <div className="relative">
                    <input
                      id="setup-master-password"
                      type={showPassword ? 'text' : 'password'}
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      placeholder="Minimum 10 characters"
                      className="w-full px-3.5 py-2 pr-10 text-sm bg-[#07090B] border border-[#161B20] rounded-lg text-white placeholder:text-zinc-600 focus:outline-none focus:border-[#00FF66]"
                    />
                    <button
                      type="button"
                      aria-label={
                        showPassword
                          ? 'Hide Master Password'
                          : 'Show Master Password'
                      }
                      onClick={() => setShowPassword(!showPassword)}
                      className="absolute right-3 top-1/2 -translate-y-1/2 text-zinc-400 hover:text-zinc-200"
                    >
                      {showPassword ? (
                        <EyeOff className="w-4 h-4" />
                      ) : (
                        <Eye className="w-4 h-4" />
                      )}
                    </button>
                  </div>
                </div>

                <div className="space-y-1.5">
                  <label
                    htmlFor="setup-confirm-password"
                    className="block text-xs font-medium text-zinc-300"
                  >
                    Confirm Master Password
                  </label>
                  <input
                    id="setup-confirm-password"
                    type={showPassword ? 'text' : 'password'}
                    value={confirmPassword}
                    onChange={(e) => setConfirmPassword(e.target.value)}
                    placeholder="Confirm Master Password"
                    className="w-full px-3.5 py-2 text-sm bg-[#07090B] border border-[#161B20] rounded-lg text-white placeholder:text-zinc-600 focus:outline-none focus:border-[#00FF66]"
                  />
                </div>

                <label className="flex items-start gap-2.5 pt-1 cursor-pointer select-none">
                  <input
                    type="checkbox"
                    checked={includeSampleItems}
                    onChange={(e) => setIncludeSampleItems(e.target.checked)}
                    className="mt-0.5 rounded border-[#161B20] bg-[#07090B] accent-[#00FF66]"
                  />
                  <span className="text-xs text-zinc-300 leading-snug">
                    Encrypt sample records (Passwords, Secure Note, Identity, Credit Card, WireGuard Key) using per-item AES-256-GCM keys
                  </span>
                </label>

                {errorMsg && (
                  <div
                    role="alert"
                    className="p-3 rounded-lg bg-rose-950/60 border border-rose-800/80 text-xs text-rose-200 flex items-start gap-2.5"
                  >
                    <AlertCircle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
                    <span>{errorMsg}</span>
                  </div>
                )}

                <button
                  type="submit"
                  disabled={isSubmitting}
                  className="w-full py-2.5 px-4 bg-[#00FF66] hover:bg-[#22FF7A] disabled:opacity-50 text-[#050505] font-semibold text-sm rounded-lg transition-colors flex items-center justify-center gap-2 whitespace-nowrap shadow-[0_0_24px_rgba(0,255,102,0.16)]"
                >
                  {isSubmitting ? (
                    <>
                      <RefreshCw className="w-4 h-4 animate-spin" />
                      <span>Generating Four-Tier Key Hierarchy...</span>
                    </>
                  ) : (
                    <>
                      <CheckCircle2 className="w-4 h-4" />
                      <span>Initialize Vault &amp; Unlock</span>
                      <ArrowRight className="w-4 h-4" />
                    </>
                  )}
                </button>
              </form>
            )}
          </div>
        </div>
      </motion.main>

      {/* Quiet Footer */}
      <footer className="px-6 py-4 border-t border-[#161B20] text-xs text-zinc-500 flex flex-wrap items-center justify-between gap-4">
        <span>BLACKTOWER VAULT™ · Personal Password &amp; Digital Identity Vault</span>
        <span>
          Browser Preview Environment · Native Android Keystore Unavailable in Preview
        </span>
      </footer>
    </div>
  );
}
