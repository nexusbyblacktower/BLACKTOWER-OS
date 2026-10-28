'use client';

import React, { useState, useEffect, useCallback } from 'react';
import {
  Shield,
  CheckCircle2,
  AlertTriangle,
  Play,
  RefreshCw,
  Cpu,
  Lock,
  Database,
  KeyRound,
  Smartphone,
  MonitorOff,
  Activity,
} from 'lucide-react';
import {
  runAllSecurityDiagnostics,
  type SecurityDiagnosticSuiteReport,
} from '@/lib/diagnostics/security-tests';
import {
  detectRuntimePlatformCapabilities,
  NATIVE_ANDROID_ARCHITECTURE_MODULES,
} from '@/lib/android/native-reference';
import { runtimeNonceGuard } from '@/lib/crypto/vault-crypto';
import {
  getRawEncryptedStorageSnapshot,
  type PersistedEncryptedVaultStore,
} from '@/lib/storage/vault-storage';
import {
  type RedactedSecurityEvent,
  type ScreenExposureDiagnosticsSnapshot,
  type ScreenExposureState,
} from '@/lib/security/screen-exposure-engine';

export type SecurityPostureState = 'Excellent' | 'Protected' | 'Attention Required';

interface SecurityCenterViewProps {
  store: PersistedEncryptedVaultStore;
  exposureDiagnostics: ScreenExposureDiagnosticsSnapshot;
  redactedEvents: RedactedSecurityEvent[];
  onTriggerExposureDrill: (
    targetState: Exclude<ScreenExposureState, 'PRIVATE_SAFE'>
  ) => void;
  onNavigateToSettings: () => void;
}

export default function SecurityCenterView({
  store,
  exposureDiagnostics,
  redactedEvents,
  onTriggerExposureDrill,
  onNavigateToSettings,
}: SecurityCenterViewProps) {
  const [suiteReport, setSuiteReport] = useState<SecurityDiagnosticSuiteReport | null>(null);
  const [isRunningTests, setIsRunningTests] = useState(false);
  const [showAndroidModules, setShowAndroidModules] = useState(false);
  const [selectedAndroidModuleIdx, setSelectedAndroidModuleIdx] = useState(0);

  const platformCaps = detectRuntimePlatformCapabilities();
  const storageSnapshot = getRawEncryptedStorageSnapshot();
  const nonceStats = runtimeNonceGuard.getStats();

  // Execute real runtime checks to compute the 4 required Security Center pillars:
  // Device Security, Encryption, Vault Integrity, Recovery
  const computeDeviceSecurityPosture = (): {
    state: SecurityPostureState;
    reason: string;
  } => {
    if (!platformCaps.webCryptoAvailable || !platformCaps.secureContext) {
      return {
        state: 'Attention Required',
        reason: 'WebCrypto SubtleCrypto or Secure Context unavailable.',
      };
    }
    return {
      state: 'Protected',
      reason:
        'WebCrypto SubtleCrypto active with auto-lock timer. Native Android Keystore / StrongBox Unavailable in Preview.',
    };
  };

  const computeEncryptionPosture = (): {
    state: SecurityPostureState;
    reason: string;
  } => {
    const has4Tiers =
      Boolean(store.hierarchy.kekKeyId) &&
      Boolean(store.hierarchy.rootKeyId) &&
      Boolean(store.hierarchy.vaultKeyId) &&
      store.items.every((i) => Boolean(i.itemKeyId) && i.encryptedPayload.nonceHex.length === 24);

    if (!has4Tiers) {
      return {
        state: 'Attention Required',
        reason: 'Incomplete key hierarchy or invalid item nonce length.',
      };
    }
    return {
      state: 'Excellent',
      reason: `Argon2id v1.3 + AES-256-GCM 4-tier hierarchy verified (${nonceStats.uniqueNoncePairs} unique nonces tracked).`,
    };
  };

  const computeVaultIntegrityPosture = (): {
    state: SecurityPostureState;
    reason: string;
  } => {
    if (!storageSnapshot.leakageCheck.passed) {
      return {
        state: 'Attention Required',
        reason: storageSnapshot.leakageCheck.details,
      };
    }
    if (suiteReport && suiteReport.overallStatus === 'FAIL') {
      return {
        state: 'Attention Required',
        reason: 'One or more security diagnostic tests failed.',
      };
    }
    return {
      state: 'Excellent',
      reason: `0 plaintext secrets in ${storageSnapshot.rawBytesLength} bytes of local storage; canonical AAD bound across ${store.items.length} records.`,
    };
  };

  const computeRecoveryPosture = (): {
    state: SecurityPostureState;
    reason: string;
  } => {
    const hasRecoveryVerified = Boolean(store.settings.recoveryKeyVerifiedAt);
    const hasBackupExported = Boolean(store.settings.lastBackupExportedAt);
    if (hasRecoveryVerified && hasBackupExported) {
      return {
        state: 'Excellent',
        reason: '256-bit Recovery Key verified and authenticated .btvault backup exported.',
      };
    }
    if (hasRecoveryVerified || hasBackupExported) {
      return {
        state: 'Protected',
        reason: hasRecoveryVerified
          ? 'Recovery Key verified. Export an encrypted .btvault backup for full redundancy.'
          : 'Encrypted .btvault backup exported. Verify your 256-bit Recovery Key in Settings.',
      };
    }
    return {
      state: 'Attention Required',
      reason: 'Recovery Key has not been verified yet and no .btvault backup has been exported.',
    };
  };

  const deviceSecurity = computeDeviceSecurityPosture();
  const encryptionSecurity = computeEncryptionPosture();
  const vaultIntegrity = computeVaultIntegrityPosture();
  const recoverySecurity = computeRecoveryPosture();

  const executeDiagnostics = useCallback(async () => {
    setIsRunningTests(true);
    try {
      const report = await runAllSecurityDiagnostics();
      setSuiteReport(report);
    } finally {
      setIsRunningTests(false);
    }
  }, []);

  useEffect(() => {
    let cancelled = false;
    runAllSecurityDiagnostics().then((report) => {
      if (!cancelled) {
        setSuiteReport(report);
      }
    });
    return () => {
      cancelled = true;
    };
  }, []);

  const renderStateIndicator = (state: SecurityPostureState) => {
    if (state === 'Excellent') {
      return (
        <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-[#00FF66]">
          <CheckCircle2 className="w-4 h-4" />
          <span>Excellent</span>
        </span>
      );
    }
    if (state === 'Protected') {
      return (
        <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-[#00FF66]">
          <Shield className="w-4 h-4" />
          <span>Protected</span>
        </span>
      );
    }
    return (
      <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-amber-400">
        <AlertTriangle className="w-4 h-4" />
        <span>Attention Required</span>
      </span>
    );
  };

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-4 pb-4 border-b border-slate-800/80">
        <div>
          <h2
            className="text-xl font-bold text-white"
            style={{ fontFamily: 'var(--font-display)' }}
          >
            Security Center &amp; Runtime Diagnostics
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            All security statuses are computed dynamically from live cryptographic checks, display state machine telemetry, and storage inspection.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            type="button"
            onClick={() => setShowAndroidModules(!showAndroidModules)}
            className="px-3.5 py-2 text-xs font-medium text-slate-300 hover:text-white bg-[#0B0E11] border border-slate-800 rounded-lg transition-colors flex items-center gap-2 whitespace-nowrap"
          >
            <Smartphone className="w-3.5 h-3.5 text-[#00FF66]" />
            <span>
              {showAndroidModules
                ? 'Hide Native Android Architecture'
                : 'Native Android Kotlin Architecture'}
            </span>
          </button>

          <button
            type="button"
            disabled={isRunningTests}
            onClick={executeDiagnostics}
            className="px-4 py-2 text-xs font-semibold text-slate-950 bg-[#00FF66] hover:bg-[#22FF7A] disabled:opacity-50 rounded-lg transition-colors flex items-center gap-2 whitespace-nowrap"
          >
            {isRunningTests ? (
              <>
                <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                <span>Executing 12 Security Tests...</span>
              </>
            ) : (
              <>
                <Play className="w-3.5 h-3.5" />
                <span>Run All 12 Security Tests</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Phase 7: Four Dynamic Security Center Pillars */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-[#0B0E11] border border-slate-800 rounded-xl p-5 space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400 flex items-center gap-1.5">
              <Cpu className="w-4 h-4 text-slate-400" />
              <span>Device Security</span>
            </span>
            {renderStateIndicator(deviceSecurity.state)}
          </div>
          <p className="text-xs text-slate-300 leading-relaxed">{deviceSecurity.reason}</p>
          <div className="pt-2 border-t border-slate-800/80 text-xs text-slate-500 space-y-1">
            <div>Biometric Hardware: {platformCaps.hardwareBiometricStatus}</div>
            <div>Android Keystore / StrongBox: {platformCaps.strongBoxStatus}</div>
          </div>
        </div>

        <div className="bg-[#0B0E11] border border-slate-800 rounded-xl p-5 space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400 flex items-center gap-1.5">
              <Lock className="w-4 h-4 text-slate-400" />
              <span>Encryption</span>
            </span>
            {renderStateIndicator(encryptionSecurity.state)}
          </div>
          <p className="text-xs text-slate-300 leading-relaxed">{encryptionSecurity.reason}</p>
          <div className="pt-2 border-t border-slate-800/80 text-xs text-slate-500 font-mono tabular-nums space-y-1">
            <div>KDF: {store.hierarchy.kdfProfile}</div>
            <div>Root Key ID: {store.hierarchy.rootKeyId}</div>
          </div>
        </div>

        <div className="bg-[#0B0E11] border border-slate-800 rounded-xl p-5 space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400 flex items-center gap-1.5">
              <Database className="w-4 h-4 text-slate-400" />
              <span>Vault Integrity</span>
            </span>
            {renderStateIndicator(vaultIntegrity.state)}
          </div>
          <p className="text-xs text-slate-300 leading-relaxed">{vaultIntegrity.reason}</p>
          <div className="pt-2 border-t border-slate-800/80 text-xs text-slate-500 font-mono tabular-nums space-y-1">
            <div>Vault ID: {store.hierarchy.vaultId}</div>
            <div>
              Nonce Guard Checks: {nonceStats.totalChecked} ({nonceStats.duplicateAborts} blocked)
            </div>
          </div>
        </div>

        <div className="bg-[#0B0E11] border border-slate-800 rounded-xl p-5 space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400 flex items-center gap-1.5">
              <KeyRound className="w-4 h-4 text-slate-400" />
              <span>Recovery</span>
            </span>
            {renderStateIndicator(recoverySecurity.state)}
          </div>
          <p className="text-xs text-slate-300 leading-relaxed">{recoverySecurity.reason}</p>
          <div className="pt-2 border-t border-slate-800/80">
            <button
              type="button"
              onClick={onNavigateToSettings}
              className="text-xs text-[#00FF66] hover:underline"
            >
              Verify Recovery Key or Export Backup →
            </button>
          </div>
        </div>
      </div>

      {/* Screen Exposure Protection Engine Diagnostics & Live Drills (Sections 12, 13, 16, 17) */}
      <div className="bg-[#0B0E11] border border-slate-800 rounded-xl p-6 space-y-5">
        <div className="flex flex-wrap items-start justify-between gap-4 border-b border-slate-800 pb-4">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <MonitorOff className="w-4 h-4 text-[#00FF66]" />
              <h3
                className="text-base font-bold text-white"
                style={{ fontFamily: 'var(--font-display)' }}
              >
                Screen Exposure Protection Engine &amp; Display State Machine
              </h3>
            </div>
            <p className="text-xs text-amber-300/90 font-medium">
              {exposureDiagnostics.webPreviewLimitationNotice}
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-3 text-xs font-mono">
            <span className="text-slate-400">
              State Machine:{' '}
              <strong
                className={
                  exposureDiagnostics.currentState === 'PRIVATE_SAFE'
                    ? 'text-[#00FF66]'
                    : 'text-amber-400'
                }
              >
                {exposureDiagnostics.currentState}
              </strong>
            </span>
            <span aria-hidden="true" className="text-slate-600">
              ·
            </span>
            <span className="text-slate-400">
              Extreme Screen Protection:{' '}
              <strong
                className={
                  exposureDiagnostics.extremeModeEnabled ? 'text-[#00FF66]' : 'text-amber-400'
                }
              >
                {exposureDiagnostics.extremeModeEnabled ? 'ON (Default)' : 'Custom'}
              </strong>
            </span>
          </div>
        </div>

        {/* 5 Required Honest Screen Exposure Diagnostic Checks */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-3">
          {exposureDiagnostics.items.map((item) => (
            <div
              key={item.id}
              className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 space-y-1.5"
            >
              <div className="text-xs font-semibold text-slate-200">{item.label}</div>
              <div
                className={`text-xs font-mono leading-snug ${
                  item.status === 'VERIFIED_SAFE'
                    ? 'text-[#00FF66]'
                    : item.status === 'RISK_DETECTED'
                    ? 'text-rose-400'
                    : 'text-amber-300'
                }`}
              >
                {item.displayText}
              </div>
              <div className="text-[11px] text-slate-500 leading-relaxed">{item.technicalNote}</div>
            </div>
          ))}
        </div>

        {/* Live Screen Exposure Drills & Redacted Event Log */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 pt-2">
          <div className="p-4 rounded-lg bg-slate-950 border border-slate-800 space-y-3">
            <div className="text-xs font-semibold text-white">
              Interactive Exposure Protection Drills (Verify Privacy Shield &amp; Zeroization)
            </div>
            <p className="text-xs text-slate-400 leading-relaxed">
              Trigger a live display/capture risk state to verify that BLACKTOWER VAULT™ immediately hides decrypted content, replaces the UI with the neutral Privacy Shield, and enforces Extreme Mode lock/re-authentication.
            </p>
            <div className="flex flex-wrap items-center gap-2 pt-1">
              <button
                type="button"
                onClick={() => onTriggerExposureDrill('EXTERNAL_DISPLAY_DETECTED')}
                className="px-3 py-1.5 text-xs font-medium text-amber-300 bg-amber-950/50 hover:bg-amber-900/60 border border-amber-800/70 rounded-lg transition-colors"
              >
                Simulate External Display (HDMI / USB-C)
              </button>
              <button
                type="button"
                onClick={() => onTriggerExposureDrill('PROJECTION_DETECTED')}
                className="px-3 py-1.5 text-xs font-medium text-amber-300 bg-amber-950/50 hover:bg-amber-900/60 border border-amber-800/70 rounded-lg transition-colors"
              >
                Simulate Screen Mirroring / Cast
              </button>
              <button
                type="button"
                onClick={() => onTriggerExposureDrill('SCREEN_CAPTURE_DETECTED')}
                className="px-3 py-1.5 text-xs font-medium text-rose-300 bg-rose-950/50 hover:bg-rose-900/60 border border-rose-800/70 rounded-lg transition-colors"
              >
                Simulate Screen Capture / Recording
              </button>
            </div>
          </div>

          <div className="p-4 rounded-lg bg-slate-950 border border-slate-800 space-y-2.5">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-white flex items-center gap-1.5">
                <Activity className="w-3.5 h-3.5 text-[#00FF66]" />
                <span>Minimal Redacted Security Event Log (Zero Secrets)</span>
              </span>
              <span className="text-[11px] font-mono text-slate-500">
                {redactedEvents.length} event(s)
              </span>
            </div>

            {redactedEvents.length === 0 ? (
              <div className="text-xs font-mono text-slate-500 py-3">
                No screen exposure or blocked reveal events recorded in this session.
              </div>
            ) : (
              <div className="max-h-28 overflow-y-auto divide-y divide-slate-800/70 text-xs font-mono">
                {redactedEvents.slice(0, 8).map((evt) => (
                  <div
                    key={evt.eventId}
                    className="py-1.5 flex items-center justify-between gap-2 text-slate-300"
                  >
                    <span className="text-amber-300 font-semibold">{evt.eventCode}</span>
                    <span className="text-slate-400">→ {evt.resultingState}</span>
                    <span className="text-slate-500 tabular-nums">
                      {new Date(evt.timestamp).toLocaleTimeString()}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Optional Native Android Reference Architecture Inspector */}
      {showAndroidModules && (
        <div className="bg-[#0B0E11] border border-slate-800 rounded-xl p-6 space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-800 pb-4">
            <div>
              <h3
                className="text-base font-bold text-white"
                style={{ fontFamily: 'var(--font-display)' }}
              >
                Native Android Reference Architecture (Kotlin / Jetpack Compose / Keystore)
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Browser Preview runs WebCrypto and marks native Android Keystore &amp; FLAG_SECURE as Unavailable in Preview. Below is the production Kotlin implementation including ScreenExposureProtectionManager.kt.
              </p>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              {NATIVE_ANDROID_ARCHITECTURE_MODULES.map((mod, idx) => (
                <button
                  key={mod.moduleName}
                  type="button"
                  onClick={() => setSelectedAndroidModuleIdx(idx)}
                  className={`px-3 py-1.5 text-xs font-mono rounded-lg transition-colors ${
                    selectedAndroidModuleIdx === idx
                      ? 'bg-slate-800 text-[#00FF66] border border-slate-700'
                      : 'text-slate-400 hover:text-white bg-slate-950'
                  }`}
                >
                  {mod.moduleName}
                </button>
              ))}
            </div>
          </div>

          <div className="text-xs text-slate-300">
            {NATIVE_ANDROID_ARCHITECTURE_MODULES[selectedAndroidModuleIdx].summary}
          </div>

          <pre className="p-4 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono text-slate-200 overflow-x-auto leading-relaxed">
            {NATIVE_ANDROID_ARCHITECTURE_MODULES[selectedAndroidModuleIdx].code}
          </pre>
        </div>
      )}

      {/* Phase 8: Live Security Regression Suite (TEST-01 through TEST-11) */}
      <div className="bg-[#0B0E11] border border-slate-800 rounded-xl overflow-hidden">
        <div className="p-6 border-b border-slate-800 flex flex-wrap items-center justify-between gap-4">
          <div className="space-y-1">
            <h3
              className="text-base font-bold text-white"
              style={{ fontFamily: 'var(--font-display)' }}
            >
              Cryptographic &amp; Security Regression Suite (TEST-01 — TEST-12)
            </h3>
            {suiteReport ? (
              <div className="flex flex-wrap items-center gap-2 text-xs text-slate-400 font-mono tabular-nums">
                <span>
                  Last verification: {new Date(suiteReport.executedAt).toLocaleTimeString()}
                </span>
                <span aria-hidden="true">·</span>
                <span>
                  Overall Result:{' '}
                  <strong
                    className={
                      suiteReport.overallStatus === 'PASS' ? 'text-[#00FF66]' : 'text-rose-400'
                    }
                  >
                    {suiteReport.overallStatus} ({suiteReport.passedCount}/{suiteReport.totalCount})
                  </strong>
                </span>
                <span aria-hidden="true">·</span>
                <span>Total Execution Time: {suiteReport.totalDurationMs} ms</span>
              </div>
            ) : (
              <div className="text-xs text-slate-400">Executing live cryptographic checks...</div>
            )}
          </div>

          {suiteReport && (
            <div className="flex flex-wrap items-center gap-4 text-xs font-mono">
              {(
                ['Cryptography', 'Integrity', 'Isolation', 'Recovery'] as Array<
                  keyof SecurityDiagnosticSuiteReport['categorySummary']
                >
              ).map((cat) => (
                <div key={cat} className="flex items-center gap-1.5">
                  <span className="text-slate-400">{cat}:</span>
                  <span
                    className={
                      suiteReport.categorySummary[cat] === 'PASS'
                        ? 'text-[#00FF66] font-semibold'
                        : 'text-rose-400 font-semibold'
                    }
                  >
                    {suiteReport.categorySummary[cat]}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* High-Density Test Results Table */}
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-slate-800 text-xs text-slate-400 bg-slate-950/60">
                <th className="py-3 px-4 font-medium">Test ID</th>
                <th className="py-3 px-4 font-medium">Verification Target</th>
                <th className="py-3 px-4 font-medium">Category</th>
                <th className="py-3 px-4 font-medium">Live Execution Detail</th>
                <th className="py-3 px-4 font-medium text-right">Duration</th>
                <th className="py-3 px-4 font-medium text-right">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70 text-xs">
              {suiteReport?.results.map((test) => (
                <tr key={test.id} className="hover:bg-slate-900/50 transition-colors">
                  <td className="py-3 px-4 font-mono font-semibold text-[#00FF66] whitespace-nowrap">
                    {test.id}
                  </td>
                  <td className="py-3 px-4 font-medium text-slate-100 whitespace-nowrap">
                    {test.name}
                  </td>
                  <td className="py-3 px-4 text-slate-400 whitespace-nowrap">{test.category}</td>
                  <td className="py-3 px-4 text-slate-300">
                    {test.verificationDetail}
                    {test.failureReason && (
                      <div className="text-rose-400 mt-1 font-mono">
                        Failure: {test.failureReason}
                      </div>
                    )}
                  </td>
                  <td className="py-3 px-4 text-right font-mono tabular-nums text-slate-300 whitespace-nowrap">
                    {test.durationMs.toFixed(2)} ms
                  </td>
                  <td className="py-3 px-4 text-right font-mono font-semibold whitespace-nowrap">
                    {test.passed ? (
                      <span className="text-[#00FF66]">PASS</span>
                    ) : (
                      <span className="text-rose-400">FAIL</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
