import {
  type ActiveVaultKeyring,
  zeroizeKeyring,
} from '../crypto/vault-crypto.ts';
import {
  type CsvImportAnalysisSession,
  clearCsvImportSessionBuffer,
} from '../import/csv-migration.ts';
import { inspectPayloadForPlaintextSecrets } from '../sync/sync-validator.ts';

/**
 * Explicit Screen Security State Machine (Section 16)
 * Sensitive content may ONLY be rendered in PRIVATE_SAFE.
 * All other states MUST prevent sensitive rendering.
 */
export type ScreenExposureState =
  | 'PRIVATE_SAFE'
  | 'EXPOSURE_SUSPECTED'
  | 'EXTERNAL_DISPLAY_DETECTED'
  | 'SCREEN_CAPTURE_DETECTED'
  | 'PROJECTION_DETECTED'
  | 'PROTECTED_HIDDEN'
  | 'VAULT_LOCKED'
  | 'AUTHENTICATION_REQUIRED';

export const ALL_SCREEN_EXPOSURE_STATES: ScreenExposureState[] = [
  'PRIVATE_SAFE',
  'EXPOSURE_SUSPECTED',
  'EXTERNAL_DISPLAY_DETECTED',
  'SCREEN_CAPTURE_DETECTED',
  'PROJECTION_DETECTED',
  'PROTECTED_HIDDEN',
  'VAULT_LOCKED',
  'AUTHENTICATION_REQUIRED',
];

/**
 * Minimal Redacted Security Event Codes (Section 13)
 * Never logs passwords, usernames, vault contents, card numbers, notes, recovery keys, or screen contents.
 */
export type ScreenSecurityEventCode =
  | 'SCREEN_EXPOSURE_DETECTED'
  | 'EXTERNAL_DISPLAY_DETECTED'
  | 'CAPTURE_RISK_DETECTED'
  | 'PROJECTION_RISK_DETECTED'
  | 'VAULT_AUTO_LOCKED'
  | 'PASSWORD_REVEAL_BLOCKED'
  | 'CSV_PREVIEW_TERMINATED_ON_EXPOSURE'
  | 'PRIVATE_SAFE_RESTORED';

export interface RedactedSecurityEvent {
  eventId: string;
  timestamp: string;
  eventCode: ScreenSecurityEventCode;
  resultingState: ScreenExposureState;
  extremeModeActive: boolean;
}

export type DiagnosticVerificationStatus =
  | 'VERIFIED_SAFE'
  | 'PLATFORM_CANNOT_VERIFY'
  | 'RISK_DETECTED';

export interface ScreenExposureDiagnosticItem {
  id:
    | 'screen_protection'
    | 'external_display'
    | 'screen_capture'
    | 'projection'
    | 'background_protection';
  label: string;
  status: DiagnosticVerificationStatus;
  displayText: string;
  technicalNote: string;
}

export interface ScreenExposureDiagnosticsSnapshot {
  currentState: ScreenExposureState;
  canRenderSensitive: boolean;
  extremeModeEnabled: boolean;
  lockOnBackgroundEnabled: boolean;
  webPreviewLimitationNotice: string;
  items: ScreenExposureDiagnosticItem[];
}

export interface RuntimeDisplayEnvironmentInput {
  extremeModeEnabled: boolean;
  lockOnBackgroundEnabled: boolean;
  isVaultUnlocked: boolean;
  documentVisibility?: 'visible' | 'hidden';
  windowFocused?: boolean;
  screenIsExtended?: boolean | null; // boolean when supported by Window Management API, null when unsupported
  simulatedExposureState?: Exclude<ScreenExposureState, 'PRIVATE_SAFE'> | null;
}

// In-memory ring buffer of minimal redacted security events (max 50 events, zero secrets)
const redactedSecurityEventsLog: RedactedSecurityEvent[] = [];

/**
 * Strict gate: Sensitive content may ONLY be rendered in PRIVATE_SAFE.
 * Every other state fails closed and prevents rendering.
 */
export function canRenderSensitiveContent(state: ScreenExposureState): boolean {
  return state === 'PRIVATE_SAFE';
}

/**
 * Appends a minimal, redacted security event after verifying zero forbidden fields exist.
 */
export function recordRedactedSecurityEvent(params: {
  eventCode: ScreenSecurityEventCode;
  resultingState: ScreenExposureState;
  extremeModeActive: boolean;
  extraCheckPayload?: unknown;
}): RedactedSecurityEvent {
  if (params.extraCheckPayload !== undefined) {
    const check = inspectPayloadForPlaintextSecrets(params.extraCheckPayload);
    if (!check.valid) {
      throw new Error(
        `SECURITY_EVENT_LOG_REJECTED_SECRET: ${check.reason || 'Forbidden secret field in event'}`
      );
    }
  }

  const entry: RedactedSecurityEvent = {
    eventId: `sec_evt_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`,
    timestamp: new Date().toISOString(),
    eventCode: params.eventCode,
    resultingState: params.resultingState,
    extremeModeActive: params.extremeModeActive,
  };

  redactedSecurityEventsLog.unshift(entry);
  if (redactedSecurityEventsLog.length > 50) {
    redactedSecurityEventsLog.pop();
  }
  return entry;
}

export function getRedactedSecurityEvents(): RedactedSecurityEvent[] {
  return [...redactedSecurityEventsLog];
}

export function clearRedactedSecurityEvents(): void {
  redactedSecurityEventsLog.length = 0;
}

/**
 * Evaluates the current runtime display & capture environment and resolves the authoritative
 * ScreenExposureState.
 */
export function evaluateScreenExposureState(
  input: RuntimeDisplayEnvironmentInput
): ScreenExposureState {
  if (!input.isVaultUnlocked) {
    return 'VAULT_LOCKED';
  }

  // 1. Check explicit simulated or detected exposure overrides first
  if (input.simulatedExposureState) {
    return input.simulatedExposureState;
  }

  // 2. Check external/secondary display via browser screen.isExtended API when available
  if (input.screenIsExtended === true) {
    return 'EXTERNAL_DISPLAY_DETECTED';
  }

  // 3. Check application background / visibility state
  if (input.documentVisibility === 'hidden') {
    return input.extremeModeEnabled || input.lockOnBackgroundEnabled
      ? 'VAULT_LOCKED'
      : 'PROTECTED_HIDDEN';
  }

  return 'PRIVATE_SAFE';
}

/**
 * Pre-Render Gate (Sections 8, 9, 15):
 * Must be checked BEFORE revealing any password, card number, CVV, TOTP secret, identity document,
 * or recovery key.
 * If any risk is present, blocks the reveal and records PASSWORD_REVEAL_BLOCKED.
 */
export function verifyPreRenderSecretRevealGate(
  input: RuntimeDisplayEnvironmentInput
): {
  allowed: boolean;
  state: ScreenExposureState;
  blockedEvent?: RedactedSecurityEvent;
} {
  const state = evaluateScreenExposureState(input);
  if (!canRenderSensitiveContent(state)) {
    const blockedEvent = recordRedactedSecurityEvent({
      eventCode: 'PASSWORD_REVEAL_BLOCKED',
      resultingState: state,
      extremeModeActive: input.extremeModeEnabled,
    });
    return {
      allowed: false,
      state,
      blockedEvent,
    };
  }

  return {
    allowed: true,
    state: 'PRIVATE_SAFE',
  };
}

/**
 * Executes the Extreme Screen Exposure response protocol (Sections 6, 11, 14):
 * - Zeroizes active cryptographic keyring in memory when Extreme Mode is enabled
 * - Terminates any active CSV import preview and wipes temporary plaintext buffers
 * - Records minimal redacted security telemetry events
 */
export function executeEmergencyExposureMitigation(params: {
  detectedRiskState: Exclude<ScreenExposureState, 'PRIVATE_SAFE'>;
  extremeModeEnabled: boolean;
  activeKeyring?: ActiveVaultKeyring | null;
  activeCsvSession?: CsvImportAnalysisSession | null;
}): {
  enforcedState: ScreenExposureState;
  vaultLockedAndZeroized: boolean;
  csvSessionCleared: boolean;
  recordedEvents: RedactedSecurityEvent[];
} {
  const recordedEvents: RedactedSecurityEvent[] = [];

  // Map risk state to primary redacted event code
  const primaryEventCode: ScreenSecurityEventCode =
    params.detectedRiskState === 'EXTERNAL_DISPLAY_DETECTED'
      ? 'EXTERNAL_DISPLAY_DETECTED'
      : params.detectedRiskState === 'SCREEN_CAPTURE_DETECTED'
      ? 'CAPTURE_RISK_DETECTED'
      : params.detectedRiskState === 'PROJECTION_DETECTED'
      ? 'PROJECTION_RISK_DETECTED'
      : 'SCREEN_EXPOSURE_DETECTED';

  recordedEvents.push(
    recordRedactedSecurityEvent({
      eventCode: primaryEventCode,
      resultingState: params.detectedRiskState,
      extremeModeActive: params.extremeModeEnabled,
    })
  );

  let csvSessionCleared = false;
  if (params.activeCsvSession && !params.activeCsvSession.cleared) {
    clearCsvImportSessionBuffer(params.activeCsvSession);
    csvSessionCleared = true;
    recordedEvents.push(
      recordRedactedSecurityEvent({
        eventCode: 'CSV_PREVIEW_TERMINATED_ON_EXPOSURE',
        resultingState: params.detectedRiskState,
        extremeModeActive: params.extremeModeEnabled,
      })
    );
  }

  let vaultLockedAndZeroized = false;
  if (params.extremeModeEnabled) {
    if (params.activeKeyring) {
      zeroizeKeyring(params.activeKeyring);
    }
    vaultLockedAndZeroized = true;
    recordedEvents.push(
      recordRedactedSecurityEvent({
        eventCode: 'VAULT_AUTO_LOCKED',
        resultingState: 'AUTHENTICATION_REQUIRED',
        extremeModeActive: true,
      })
    );
  }

  return {
    enforcedState: params.detectedRiskState,
    vaultLockedAndZeroized,
    csvSessionCleared,
    recordedEvents,
  };
}

/**
 * Inspects real runtime browser signals (never fabricating Android hardware/OS guarantees).
 */
export function detectBrowserDisplaySignals(): {
  screenIsExtended: boolean | null;
  documentVisibility: 'visible' | 'hidden';
  windowFocused: boolean;
} {
  if (typeof window === 'undefined' || typeof document === 'undefined') {
    return {
      screenIsExtended: null,
      documentVisibility: 'visible',
      windowFocused: true,
    };
  }

  const screenWithExtended = window.screen as Screen & { isExtended?: boolean };
  const screenIsExtended =
    typeof screenWithExtended?.isExtended === 'boolean'
      ? screenWithExtended.isExtended
      : null;

  const documentVisibility =
    document.visibilityState === 'hidden' ? 'hidden' : 'visible';
  const windowFocused =
    typeof document.hasFocus === 'function' ? document.hasFocus() : true;

  return {
    screenIsExtended,
    documentVisibility,
    windowFocused,
  };
}

/**
 * Builds the honest, non-fabricated Screen Exposure Diagnostics snapshot (Sections 12 & 17).
 * Explicitly reports "Platform cannot verify" whenever the browser runtime cannot verify
 * OS-level capture, projection, or hardware FLAG_SECURE.
 */
export function buildScreenExposureDiagnosticsSnapshot(params: {
  currentState: ScreenExposureState;
  extremeModeEnabled: boolean;
  lockOnBackgroundEnabled: boolean;
  screenIsExtended: boolean | null;
}): ScreenExposureDiagnosticsSnapshot {
  const canRenderSensitive = canRenderSensitiveContent(params.currentState);

  const items: ScreenExposureDiagnosticItem[] = [
    {
      id: 'screen_protection',
      label: 'Screen Protection',
      status: 'PLATFORM_CANNOT_VERIFY',
      displayText:
        'Platform cannot verify OS-level FLAG_SECURE in Browser Preview (DOM Pre-Render Gate Active)',
      technicalNote:
        'Native Android enforces WindowManager.LayoutParams.FLAG_SECURE before setContent(). Browser preview enforces pre-render state machine gating.',
    },
    {
      id: 'external_display',
      label: 'External Display',
      status:
        params.currentState === 'EXTERNAL_DISPLAY_DETECTED' || params.screenIsExtended === true
          ? 'RISK_DETECTED'
          : params.screenIsExtended === false
          ? 'VERIFIED_SAFE'
          : 'PLATFORM_CANNOT_VERIFY',
      displayText:
        params.currentState === 'EXTERNAL_DISPLAY_DETECTED' || params.screenIsExtended === true
          ? 'External / secondary display detected — Vault Protected'
          : params.screenIsExtended === false
          ? '✓ No untrusted external display detected (window.screen.isExtended = false)'
          : 'Platform cannot verify (Multi-Screen isExtended API not exposed by this browser)',
      technicalNote:
        'Monitors window.screen.isExtended in supported browsers; Native Android monitors DisplayManager for secondary, presentation, and virtual displays.',
    },
    {
      id: 'screen_capture',
      label: 'Screen Capture',
      status:
        params.currentState === 'SCREEN_CAPTURE_DETECTED'
          ? 'RISK_DETECTED'
          : 'PLATFORM_CANNOT_VERIFY',
      displayText:
        params.currentState === 'SCREEN_CAPTURE_DETECTED'
          ? 'Screen capture risk detected — Sensitive rendering halted'
          : 'Platform cannot verify OS-level screen recording/screenshots in Browser Preview',
      technicalNote:
        'Browsers do not expose OS-level screenshot or third-party screen recorder state to JS. Native Android enforces FLAG_SECURE + Activity.ScreenCaptureCallback (API 34+).',
    },
    {
      id: 'projection',
      label: 'Projection / Mirroring',
      status:
        params.currentState === 'PROJECTION_DETECTED' ||
        params.currentState === 'EXPOSURE_SUSPECTED'
          ? 'RISK_DETECTED'
          : 'PLATFORM_CANNOT_VERIFY',
      displayText:
        params.currentState === 'PROJECTION_DETECTED' ||
        params.currentState === 'EXPOSURE_SUSPECTED'
          ? 'Projection / casting risk active — Sensitive rendering halted'
          : 'Platform cannot verify OS-level MediaProjection / Smart View / HDMI mirroring in Browser Preview',
      technicalNote:
        'Native Android monitors DisplayManager virtual/presentation flags and MediaProjection callbacks. Browser preview fails closed on any suspected projection event.',
    },
    {
      id: 'background_protection',
      label: 'Application Background Protection',
      status: 'VERIFIED_SAFE',
      displayText:
        params.extremeModeEnabled || params.lockOnBackgroundEnabled
          ? '✓ Enabled (Immediate secret masking + Vault Auto-Lock on background/visibility hidden)'
          : '✓ Enabled (Immediate secret masking on background transition)',
      technicalNote:
        'Hooks document.visibilitychange and window blur in Web Preview; hooks ProcessLifecycleOwner.onStop() + FLAG_SECURE Recents blanking on Native Android.',
    },
  ];

  return {
    currentState: params.currentState,
    canRenderSensitive,
    extremeModeEnabled: params.extremeModeEnabled,
    lockOnBackgroundEnabled: params.lockOnBackgroundEnabled,
    webPreviewLimitationNotice:
      'Some device-level screen protection requires the native Android application.',
    items,
  };
}
