'use client';

import React, { useState } from 'react';
import {
  KeyRound,
  Download,
  Upload,
  Cloud,
  ShieldAlert,
  CheckCircle2,
  RefreshCw,
  Clock,
  Clipboard,
  Terminal,
  Trash2,
  FileSpreadsheet,
} from 'lucide-react';
import type { PersistedEncryptedVaultStore } from '@/lib/storage/vault-storage';

interface SettingsRecoverySyncViewProps {
  store: PersistedEncryptedVaultStore;
  cloudAuthEmail?: string | null;
  onSignInWithGoogle?: () => Promise<void>;
  onSignOutCloudSync?: () => Promise<void>;
  onUpdateSettings: (partial: Partial<PersistedEncryptedVaultStore['settings']>) => void;
  onVerifyRecoveryKey: (inputKey: string) => Promise<boolean>;
  onRotateRecoveryKey: () => Promise<void>;
  onExportBackup: () => string;
  onRestoreBackup: (rawJson: string) => Promise<void>;
  onSyncPush: () => Promise<{ status: string; revision: number; syncedAt: string }>;
  onSyncPull: () => Promise<{ status: string; revision: number; message?: string }>;
  onRevokeDevice: (deviceId: string) => Promise<void>;
  onTestServerPlaintextRejection: () => Promise<{
    httpStatus: number;
    errorCode: string;
    rejectedField: string;
    message: string;
  }>;
  onOpenCsvImport: () => void;
}

export default function SettingsRecoverySyncView({
  store,
  cloudAuthEmail,
  onSignInWithGoogle,
  onSignOutCloudSync,
  onUpdateSettings,
  onVerifyRecoveryKey,
  onRotateRecoveryKey,
  onExportBackup,
  onRestoreBackup,
  onSyncPush,
  onSyncPull,
  onRevokeDevice,
  onTestServerPlaintextRejection,
  onOpenCsvImport,
}: SettingsRecoverySyncViewProps) {
  // Recovery Key Verification State
  const [recoveryVerifyInput, setRecoveryVerifyInput] = useState('');
  const [recoveryVerifyMessage, setRecoveryVerifyMessage] = useState<{
    type: 'success' | 'error';
    text: string;
  } | null>(null);
  const [isRotatingRecovery, setIsRotatingRecovery] = useState(false);

  // Backup State
  const [exportedBackupJson, setExportedBackupJson] = useState<string>('');
  const [importBackupJson, setImportBackupJson] = useState<string>('');
  const [backupFeedback, setBackupFeedback] = useState<{
    type: 'success' | 'error';
    text: string;
  } | null>(null);

  // Sync & Server Plaintext Rejection State
  const [isSyncing, setIsSyncing] = useState(false);
  const [syncFeedback, setSyncFeedback] = useState<{
    type: 'success' | 'error';
    text: string;
  } | null>(null);
  const [plaintextRejectionResult, setPlaintextRejectionResult] = useState<{
    httpStatus: number;
    errorCode: string;
    rejectedField: string;
    message: string;
  } | null>(null);

  const handleVerifyRecovery = async (e: React.FormEvent) => {
    e.preventDefault();
    setRecoveryVerifyMessage(null);
    if (!recoveryVerifyInput.trim()) {
      setRecoveryVerifyMessage({
        type: 'error',
        text: 'Enter your 256-bit Recovery Key (BTVK-...) to verify.',
      });
      return;
    }
    const valid = await onVerifyRecoveryKey(recoveryVerifyInput);
    if (valid) {
      setRecoveryVerifyMessage({
        type: 'success',
        text: 'Cryptographic unwrap succeeded. Recovery Key verified against Account Root Key.',
      });
      setRecoveryVerifyInput('');
    } else {
      setRecoveryVerifyMessage({
        type: 'error',
        text: 'Verification failed: Recovery Key did not authenticate the Account Root Key tag.',
      });
    }
  };

  const handleRotateRecovery = async () => {
    setIsRotatingRecovery(true);
    try {
      await onRotateRecoveryKey();
    } finally {
      setIsRotatingRecovery(false);
    }
  };

  const handleGenerateBackup = () => {
    setBackupFeedback(null);
    try {
      const json = onExportBackup();
      setExportedBackupJson(json);
      setBackupFeedback({
        type: 'success',
        text: 'Authenticated .btvault container sealed with HMAC-SHA256 and verified free of plaintext.',
      });
    } catch (err) {
      setBackupFeedback({
        type: 'error',
        text: err instanceof Error ? err.message : 'Failed to generate backup.',
      });
    }
  };

  const handleDownloadBackupFile = () => {
    const json = exportedBackupJson || onExportBackup();
    setExportedBackupJson(json);
    const blob = new Blob([json], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `blacktower-${store.hierarchy.vaultId}.btvault`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleRestoreBackupSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBackupFeedback(null);
    if (!importBackupJson.trim()) {
      setBackupFeedback({
        type: 'error',
        text: 'Paste a .btvault container JSON payload to verify and restore.',
      });
      return;
    }
    try {
      await onRestoreBackup(importBackupJson);
      setBackupFeedback({
        type: 'success',
        text: 'Backup integrity seal verified and encrypted records restored into vault.',
      });
      setImportBackupJson('');
    } catch (err) {
      setBackupFeedback({
        type: 'error',
        text: err instanceof Error ? err.message : 'Backup restoration rejected.',
      });
    }
  };

  const handlePush = async () => {
    setIsSyncing(true);
    setSyncFeedback(null);
    try {
      const res = await onSyncPush();
      setSyncFeedback({
        type: 'success',
        text: `Zero-knowledge push complete · Server revision v${res.revision} (${new Date(
          res.syncedAt
        ).toLocaleTimeString()})`,
      });
    } catch (err) {
      setSyncFeedback({
        type: 'error',
        text: err instanceof Error ? err.message : 'Sync push failed',
      });
    } finally {
      setIsSyncing(false);
    }
  };

  const handlePull = async () => {
    setIsSyncing(true);
    setSyncFeedback(null);
    try {
      const res = await onSyncPull();
      setSyncFeedback({
        type: 'success',
        text:
          res.message ||
          `Pulled encrypted vault revision v${res.revision} and verified authentication tags.`,
      });
    } catch (err) {
      setSyncFeedback({
        type: 'error',
        text: err instanceof Error ? err.message : 'Sync pull failed',
      });
    } finally {
      setIsSyncing(false);
    }
  };

  const handleRunPlaintextRejectionProbe = async () => {
    const res = await onTestServerPlaintextRejection();
    setPlaintextRejectionResult(res);
  };

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="pb-4 border-b border-slate-800/80">
        <h2
          className="text-xl font-bold text-white"
          style={{ fontFamily: 'var(--font-display)' }}
        >
          Vault Settings, Recovery, Backup & Zero-Knowledge Sync
        </h2>
        <p className="text-xs text-slate-400 mt-1">
          Configure auto-lock policies, manage your 256-bit Recovery Key, export authenticated .btvault backups, and synchronize ciphertext envelopes.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Section 1: Auto-Lock, Clipboard & Developer Mode */}
        <div className="bg-[#0B0E11] border border-slate-800 rounded-xl p-6 space-y-5">
          <div className="border-b border-slate-800 pb-3">
            <h3
              className="text-base font-bold text-white flex items-center gap-2"
              style={{ fontFamily: 'var(--font-display)' }}
            >
              <Clock className="w-4 h-4 text-[#00FF66]" />
              <span>Session Locking & Clipboard Protection</span>
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Locking immediately wipes decrypted records and zeroes in-memory Uint8Array key buffers.
            </p>
          </div>

          <div className="space-y-4">
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-2">
                Inactivity Auto-Lock Timeout
              </label>
              <div className="grid grid-cols-3 gap-2">
                {(
                  [
                    { sec: 60, label: '1 Minute' },
                    { sec: 300, label: '5 Minutes' },
                    { sec: 900, label: '15 Minutes' },
                  ] as const
                ).map((opt) => (
                  <button
                    key={opt.sec}
                    type="button"
                    onClick={() => onUpdateSettings({ autoLockTimeoutSeconds: opt.sec })}
                    className={`py-2 px-3 text-xs font-medium rounded-lg border transition-colors ${
                      store.settings.autoLockTimeoutSeconds === opt.sec
                        ? 'bg-slate-800 border-[#00FF66] text-white'
                        : 'bg-slate-950 border-slate-800 text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    {opt.label}
                  </button>
                ))}
              </div>
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-300 mb-2 flex items-center gap-1.5">
                <Clipboard className="w-3.5 h-3.5 text-[#00FF66]" />
                <span>Sensitive Clipboard Auto-Clear Lifetime</span>
              </label>
              <div className="grid grid-cols-3 gap-2">
                {([20, 30, 60] as const).map((sec) => (
                  <button
                    key={sec}
                    type="button"
                    onClick={() => onUpdateSettings({ clipboardClearSeconds: sec })}
                    className={`py-2 px-3 text-xs font-mono tabular-nums font-medium rounded-lg border transition-colors ${
                      store.settings.clipboardClearSeconds === sec
                        ? 'bg-slate-800 border-[#00FF66] text-white'
                        : 'bg-slate-950 border-slate-800 text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    {sec} seconds {sec === 20 ? '(Default)' : ''}
                  </button>
                ))}
              </div>
            </div>

            <div className="pt-2 border-t border-slate-800/80 space-y-3">
              <label className="flex items-center justify-between gap-4 cursor-pointer select-none">
                <div>
                  <div className="text-xs font-medium text-slate-200 flex items-center gap-1.5">
                    <ShieldAlert className="w-3.5 h-3.5 text-[#00FF66]" />
                    <span>Extreme Screen Protection (Default: ON)</span>
                  </div>
                  <div className="text-xs text-slate-500">
                    Immediately hides decrypted UI, wipes revealed secrets &amp; CSV buffers, and locks vault requiring re-authentication on any external display, projection, or capture risk
                  </div>
                </div>
                <input
                  type="checkbox"
                  checked={store.settings.extremeScreenProtection ?? true}
                  onChange={(e) =>
                    onUpdateSettings({ extremeScreenProtection: e.target.checked })
                  }
                  className="rounded border-slate-700 bg-slate-950 text-[#00FF66]"
                />
              </label>

              <label className="flex items-center justify-between gap-4 cursor-pointer select-none">
                <div>
                  <div className="text-xs font-medium text-slate-200">
                    Lock Immediately When Application is Backgrounded (Default: ON)
                  </div>
                  <div className="text-xs text-slate-500">
                    Zeroizes active keys and prevents Recents screen exposure on visibilitychange hidden event
                  </div>
                </div>
                <input
                  type="checkbox"
                  checked={store.settings.lockOnBackgroundHide}
                  onChange={(e) => onUpdateSettings({ lockOnBackgroundHide: e.target.checked })}
                  className="rounded border-slate-700 bg-slate-950 text-[#00FF66]"
                />
              </label>

              <label className="flex items-center justify-between gap-4 cursor-pointer select-none">
                <div>
                  <div className="text-xs font-medium text-slate-200 flex items-center gap-1.5">
                    <Terminal className="w-3.5 h-3.5 text-[#00FF66]" />
                    <span>Developer / Engineering Diagnostics Mode</span>
                  </div>
                  <div className="text-xs text-slate-500">
                    Exposes Argon2id, KEK, AAD, nonces, and key IDs in the item inspector
                  </div>
                </div>
                <input
                  type="checkbox"
                  checked={store.settings.developerDiagnosticsMode}
                  onChange={(e) =>
                    onUpdateSettings({ developerDiagnosticsMode: e.target.checked })
                  }
                  className="rounded border-slate-700 bg-slate-950 text-[#00FF66]"
                />
              </label>
            </div>
          </div>
        </div>

        {/* Section 2: Phase 6 Recovery Key System */}
        <div className="bg-[#0B0E11] border border-slate-800 rounded-xl p-6 space-y-5">
          <div className="flex items-start justify-between gap-4 border-b border-slate-800 pb-3">
            <div>
              <h3
                className="text-base font-bold text-white flex items-center gap-2"
                style={{ fontFamily: 'var(--font-display)' }}
              >
                <KeyRound className="w-4 h-4 text-[#00FF66]" />
                <span>256-Bit Emergency Recovery Key</span>
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Independently wraps your Account Root Key with AES-256-GCM. Never stored or transmitted in plaintext.
              </p>
            </div>
            <span className="text-xs font-mono text-slate-400 shrink-0">
              ID: {store.hierarchy.recoveryKeyId}
            </span>
          </div>

          <form onSubmit={handleVerifyRecovery} className="space-y-3">
            <label
              htmlFor="verify-recovery-input"
              className="block text-xs font-medium text-slate-300"
            >
              Verify Existing Recovery Key (Cryptographic Unwrap Check)
            </label>
            <div className="flex gap-2">
              <input
                id="verify-recovery-input"
                type="text"
                value={recoveryVerifyInput}
                onChange={(e) => setRecoveryVerifyInput(e.target.value)}
                placeholder="BTVK-XXXXXXXX-XXXXXXXX-..."
                className="flex-1 px-3 py-2 text-xs font-mono bg-slate-950 border border-slate-800 rounded-lg text-white"
              />
              <button
                type="submit"
                className="px-4 py-2 text-xs font-semibold text-slate-950 bg-[#00FF66] hover:bg-[#22FF7A] rounded-lg whitespace-nowrap"
              >
                Verify Key
              </button>
            </div>
          </form>

          {recoveryVerifyMessage && (
            <div
              className={`p-3 rounded-lg text-xs border ${
                recoveryVerifyMessage.type === 'success'
                  ? 'bg-[#00FF66]/10 border-[#00FF66]/35 text-[#00FF66]'
                  : 'bg-rose-950/40 border-rose-800 text-rose-300'
              }`}
            >
              {recoveryVerifyMessage.text}
            </div>
          )}

          <div className="pt-3 border-t border-slate-800/80 flex items-center justify-between gap-4">
            <div className="text-xs text-slate-400">
              {store.settings.recoveryKeyVerifiedAt
                ? `Last verified: ${new Date(
                    store.settings.recoveryKeyVerifiedAt
                  ).toLocaleTimeString()}`
                : 'Not verified in current vault lifecycle'}
            </div>
            <button
              type="button"
              disabled={isRotatingRecovery}
              onClick={handleRotateRecovery}
              className="px-3.5 py-2 text-xs font-medium text-slate-200 bg-slate-900 hover:bg-slate-800 border border-slate-700 rounded-lg transition-colors flex items-center gap-1.5 whitespace-nowrap"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isRotatingRecovery ? 'animate-spin' : ''}`} />
              <span>Replace / Rotate Recovery Key</span>
            </button>
          </div>
        </div>
      </div>

      {/* Section 3 & 4: Encrypted .btvault Backups + Zero-Knowledge Sync */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Phase 9: .btvault Encrypted Backup Container */}
        <div className="bg-[#0B0E11] border border-slate-800 rounded-xl p-6 space-y-5">
          <div className="border-b border-slate-800 pb-3">
            <h3
              className="text-base font-bold text-white flex items-center gap-2"
              style={{ fontFamily: 'var(--font-display)' }}
            >
              <Download className="w-4 h-4 text-[#00FF66]" />
              <span>Import &amp; Export · .btvault Backup &amp; CSV Migration</span>
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Export authenticated .btvault containers sealed with HMAC-SHA256 or migrate external credentials locally via CSV Import.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2.5">
            <button
              type="button"
              onClick={onOpenCsvImport}
              className="px-3.5 py-2 text-xs font-medium text-slate-200 bg-slate-900 hover:bg-slate-800 border border-slate-700 rounded-lg transition-colors flex items-center gap-1.5"
            >
              <FileSpreadsheet className="w-3.5 h-3.5 text-[#00FF66]" />
              <span>Import CSV</span>
            </button>
            <button
              type="button"
              onClick={handleGenerateBackup}
              className="px-3.5 py-2 text-xs font-semibold text-slate-950 bg-[#00FF66] hover:bg-[#22FF7A] rounded-lg transition-colors flex items-center gap-1.5"
            >
              <CheckCircle2 className="w-3.5 h-3.5" />
              <span>Generate .btvault Snapshot</span>
            </button>
            <button
              type="button"
              onClick={handleDownloadBackupFile}
              className="px-3.5 py-2 text-xs font-medium text-slate-200 bg-slate-900 hover:bg-slate-800 border border-slate-800 rounded-lg transition-colors flex items-center gap-1.5"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Download .btvault File</span>
            </button>
            {exportedBackupJson && (
              <button
                type="button"
                onClick={() => setImportBackupJson(exportedBackupJson)}
                className="px-3 py-2 text-xs text-[#00FF66] hover:underline"
              >
                Copy to Restore Inspector ↓
              </button>
            )}
          </div>

          {exportedBackupJson && (
            <div className="space-y-1">
              <div className="text-xs text-slate-400 font-mono">
                Generated .btvault Container Preview (Ciphertext + HMAC-SHA256 Seal):
              </div>
              <textarea
                readOnly
                rows={3}
                value={exportedBackupJson}
                className="w-full p-2.5 text-xs font-mono bg-slate-950 border border-slate-800 rounded-lg text-slate-300"
              />
            </div>
          )}

          <form onSubmit={handleRestoreBackupSubmit} className="space-y-3 pt-2 border-t border-slate-800/80">
            <label
              htmlFor="restore-backup-textarea"
              className="block text-xs font-medium text-slate-300"
            >
              Verify & Restore .btvault Container JSON
            </label>
            <textarea
              id="restore-backup-textarea"
              rows={3}
              value={importBackupJson}
              onChange={(e) => setImportBackupJson(e.target.value)}
              placeholder='{"magic":"BLACKTOWER_VAULT_CONTAINER_V1", ...}'
              className="w-full p-2.5 text-xs font-mono bg-slate-950 border border-slate-800 rounded-lg text-white"
            />
            <button
              type="submit"
              className="px-4 py-2 text-xs font-medium text-slate-200 bg-slate-800 hover:bg-slate-700 rounded-lg transition-colors flex items-center gap-1.5"
            >
              <Upload className="w-3.5 h-3.5" />
              <span>Verify HMAC Seal & Restore</span>
            </button>
          </form>

          {backupFeedback && (
            <div
              className={`p-3 rounded-lg text-xs border ${
                backupFeedback.type === 'success'
                  ? 'bg-[#00FF66]/10 border-[#00FF66]/35 text-[#00FF66]'
                  : 'bg-rose-950/40 border-rose-800 text-rose-300'
              }`}
            >
              {backupFeedback.text}
            </div>
          )}
        </div>

        {/* Phase 10 & 11: Zero-Knowledge Cloud Sync & Server Plaintext Rejection */}
        <div className="bg-[#0B0E11] border border-slate-800 rounded-xl p-6 space-y-5">
          <div className="flex items-start justify-between gap-4 border-b border-slate-800 pb-3">
            <div>
              <h3
                className="text-base font-bold text-white flex items-center gap-2"
                style={{ fontFamily: 'var(--font-display)' }}
              >
                <Cloud className="w-4 h-4 text-[#00FF66]" />
                <span>Zero-Knowledge Sync & Server Plaintext Guard</span>
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Server receives only a domain-separated SHA-256 auth verifier and AES-256-GCM envelopes.
              </p>
            </div>
            <span className="text-xs font-mono tabular-nums text-slate-400 shrink-0">
              Rev: v{store.syncState.lastSyncedRevision}
            </span>
          </div>

          <div className="flex flex-wrap items-center justify-between gap-2.5 p-3 rounded-lg bg-slate-950 border border-slate-800 text-xs">
            <div className="text-slate-300">
              {cloudAuthEmail ? (
                <span>
                  Cloud Identity: <strong className="text-[#00FF66]">{cloudAuthEmail}</strong> (In-Memory Token Only)
                </span>
              ) : (
                <span>Cloud Sync Identity: Zero-Knowledge Cryptographic Verifier</span>
              )}
            </div>
            {cloudAuthEmail ? (
              <button
                type="button"
                onClick={() => onSignOutCloudSync?.()}
                className="px-3 py-1 text-xs font-medium text-slate-300 bg-slate-900 hover:bg-slate-800 border border-slate-700 rounded-md transition-colors"
              >
                Sign Out Cloud Account
              </button>
            ) : (
              onSignInWithGoogle && (
                <button
                  type="button"
                  onClick={() => onSignInWithGoogle()}
                  className="px-3 py-1 text-xs font-medium text-[#00FF66] bg-[#00FF66]/10 hover:bg-[#00FF66]/20 border border-[#00FF66]/35 rounded-md transition-colors"
                >
                  Link Google Account for Cloud Sync
                </button>
              )
            )}
          </div>

          <div className="flex flex-wrap items-center gap-2.5">
            <button
              type="button"
              disabled={isSyncing}
              onClick={handlePush}
              className="px-4 py-2 text-xs font-semibold text-slate-950 bg-[#00FF66] hover:bg-[#22FF7A] disabled:opacity-50 rounded-lg transition-colors flex items-center gap-1.5"
            >
              <Upload className="w-3.5 h-3.5" />
              <span>Push Encrypted Vault</span>
            </button>
            <button
              type="button"
              disabled={isSyncing}
              onClick={handlePull}
              className="px-4 py-2 text-xs font-medium text-slate-200 bg-slate-900 hover:bg-slate-800 border border-slate-800 rounded-lg transition-colors flex items-center gap-1.5"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Pull Encrypted Vault</span>
            </button>
          </div>

          {syncFeedback && (
            <div
              className={`p-3 rounded-lg text-xs border ${
                syncFeedback.type === 'success'
                  ? 'bg-[#00FF66]/10 border-[#00FF66]/35 text-[#00FF66]'
                  : 'bg-rose-950/40 border-rose-800 text-rose-300'
              }`}
            >
              {syncFeedback.text}
            </div>
          )}

          {/* Authorized Sync Devices & Revocation */}
          <div className="space-y-2 pt-2 border-t border-slate-800/80">
            <div className="text-xs font-medium text-slate-300">Authorized Sync Devices</div>
            <div className="divide-y divide-slate-800 border border-slate-800 rounded-lg bg-slate-950">
              {store.syncState.devices.map((dev) => (
                <div
                  key={dev.deviceId}
                  className="px-3.5 py-2.5 flex items-center justify-between gap-3 text-xs"
                >
                  <div>
                    <div className="text-slate-200 font-medium">
                      {dev.deviceName} ({dev.deviceId})
                    </div>
                    <div className="text-slate-500">
                      {dev.platform} · {dev.revoked ? 'REVOKED' : 'Active'}
                    </div>
                  </div>
                  {!dev.revoked && dev.deviceId !== store.syncState.activeDeviceId && (
                    <button
                      type="button"
                      onClick={() => onRevokeDevice(dev.deviceId)}
                      className="px-2.5 py-1 text-xs text-rose-300 bg-rose-950/60 border border-rose-800 rounded hover:bg-rose-900"
                    >
                      <Trash2 className="w-3 h-3 inline mr-1" />
                      Revoke
                    </button>
                  )}
                </div>
              ))}
            </div>
          </div>

          {/* Phase 11 Live Server Plaintext Rejection Test */}
          <div className="pt-3 border-t border-slate-800/80 space-y-3">
            <div className="flex items-center justify-between gap-4">
              <div>
                <div className="text-xs font-semibold text-slate-200 flex items-center gap-1.5">
                  <ShieldAlert className="w-3.5 h-3.5 text-amber-400" />
                  <span>Server Plaintext Rejection Policy Enforcement</span>
                </div>
                <p className="text-xs text-slate-400">
                  Test sending a forbidden plaintext field (&quot;password&quot;) to POST /api/sync to verify HTTP 400 rejection.
                </p>
              </div>
              <button
                type="button"
                onClick={handleRunPlaintextRejectionProbe}
                className="px-3 py-1.5 text-xs font-medium text-amber-300 bg-amber-950/50 hover:bg-amber-900/60 border border-amber-800/80 rounded-lg transition-colors whitespace-nowrap shrink-0"
              >
                Test Server Rejection
              </button>
            </div>

            {plaintextRejectionResult && (
              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono space-y-1">
                <div className="text-[#00FF66] font-semibold">
                  Verified: Server Rejected Unencrypted Field (HTTP {plaintextRejectionResult.httpStatus})
                </div>
                <div className="text-slate-300">Error Code: {plaintextRejectionResult.errorCode}</div>
                <div className="text-slate-400">
                  Rejected Field: &quot;{plaintextRejectionResult.rejectedField}&quot;
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
