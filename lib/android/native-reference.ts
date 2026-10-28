/**
 * Platform Honesty & Native Android Security Architecture Reference
 * Enforces Phase 12 & Phase 13, Screen Exposure Protection Engine (Section 18),
 * and Constitution Rule 7 & Platform Honesty Rule.
 */

export interface RuntimePlatformSecurityStatus {
  environment: 'BROWSER_PREVIEW';
  webCryptoAvailable: boolean;
  secureContext: boolean;
  androidKeystoreStatus: 'Unavailable in Preview';
  strongBoxStatus: 'Unavailable in Preview';
  hardwareBiometricStatus: 'Unavailable in Preview';
  flagSecureScreenProtection: 'Unavailable in Preview (Requires Native Android WindowManager.LayoutParams.FLAG_SECURE)';
  sensitiveClipboardFlag: 'Unavailable in Preview (Timer-Based Auto-Clear Active)';
  webPreviewScreenNotice: 'Some device-level screen protection requires the native Android application.';
}

export function detectRuntimePlatformCapabilities(): RuntimePlatformSecurityStatus {
  const hasCrypto = typeof globalThis !== 'undefined' && Boolean(globalThis.crypto?.subtle);
  const isSecure =
    typeof window !== 'undefined' ? Boolean(window.isSecureContext) : true;

  return {
    environment: 'BROWSER_PREVIEW',
    webCryptoAvailable: hasCrypto,
    secureContext: isSecure,
    androidKeystoreStatus: 'Unavailable in Preview',
    strongBoxStatus: 'Unavailable in Preview',
    hardwareBiometricStatus: 'Unavailable in Preview',
    flagSecureScreenProtection:
      'Unavailable in Preview (Requires Native Android WindowManager.LayoutParams.FLAG_SECURE)',
    sensitiveClipboardFlag: 'Unavailable in Preview (Timer-Based Auto-Clear Active)',
    webPreviewScreenNotice:
      'Some device-level screen protection requires the native Android application.',
  };
}

export const NATIVE_ANDROID_ARCHITECTURE_MODULES = [
  {
    moduleName: 'ScreenExposureProtectionManager.kt',
    layer: 'Extreme Screen Exposure Protection Engine (DisplayManager + FLAG_SECURE + Lifecycle + Compose Gate)',
    summary:
      'Enforces WindowManager.LayoutParams.FLAG_SECURE BEFORE setContent(), monitors DisplayManager for secondary/presentation/virtual displays, registers Android 14+ ScreenCaptureCallback, hooks ProcessLifecycleOwner for Recents blanking and Extreme Mode auto-lock, and drives the 8-state ScreenExposureState machine.',
    code: `package com.blacktower.vault.security.exposure

import android.app.Activity
import android.content.Context
import android.hardware.display.DisplayManager
import android.os.Build
import android.view.Display
import android.view.WindowManager
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.ProcessLifecycleOwner
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

enum class ScreenExposureState {
    PRIVATE_SAFE,
    EXPOSURE_SUSPECTED,
    EXTERNAL_DISPLAY_DETECTED,
    SCREEN_CAPTURE_DETECTED,
    PROJECTION_DETECTED,
    PROTECTED_HIDDEN,
    VAULT_LOCKED,
    AUTHENTICATION_REQUIRED
}

enum class RedactedSecurityEventCode {
    SCREEN_EXPOSURE_DETECTED,
    EXTERNAL_DISPLAY_DETECTED,
    CAPTURE_RISK_DETECTED,
    PROJECTION_RISK_DETECTED,
    VAULT_AUTO_LOCKED,
    PASSWORD_REVEAL_BLOCKED
}

class ScreenExposureProtectionManager(
    context: Context,
    private val extremeModeEnabled: () -> Boolean = { true },
    private val onEmergencyLockVaultAndZeroize: (RedactedSecurityEventCode) -> Unit,
    private val onRecordRedactedEvent: (RedactedSecurityEventCode) -> Unit
) : DefaultLifecycleObserver, DisplayManager.DisplayListener {

    private val displayManager =
        context.applicationContext.getSystemService(Context.DISPLAY_SERVICE) as DisplayManager

    private val _exposureState = MutableStateFlow(ScreenExposureState.PRIVATE_SAFE)
    val exposureState: StateFlow<ScreenExposureState> = _exposureState.asStateFlow()

    /**
     * Sensitive content may ONLY be rendered when state == PRIVATE_SAFE.
     */
    val canRenderSensitiveContent: Boolean
        get() = _exposureState.value == ScreenExposureState.PRIVATE_SAFE

    fun register() {
        ProcessLifecycleOwner.get().lifecycle.addObserver(this)
        displayManager.registerDisplayListener(this, null)
        evaluateAllConnectedDisplays()
    }

    fun unregister() {
        ProcessLifecycleOwner.get().lifecycle.removeObserver(this)
        displayManager.unregisterDisplayListener(this)
    }

    /**
     * Must be invoked in ComponentActivity.onCreate() BEFORE setContent { ... }
     * so sensitive screens (Vault Home, Password Reveal, Notes, Cards, CSV Preview,
     * Recovery Key, Diagnostics) are never rendered into an unprotected window buffer.
     */
    fun enforceFlagSecureBeforeRender(activity: Activity) {
        activity.window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        )

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            activity.registerScreenCaptureCallback(
                activity.mainExecutor,
                Activity.ScreenCaptureCallback {
                    handleExposureDetected(
                        newState = ScreenExposureState.SCREEN_CAPTURE_DETECTED,
                        eventCode = RedactedSecurityEventCode.CAPTURE_RISK_DETECTED
                    )
                }
            )
        }
        evaluateAllConnectedDisplays()
    }

    /**
     * Pre-render race-condition gate checked BEFORE revealing any password, PAN, CVV,
     * TOTP secret, identity field, or recovery key.
     */
    fun verifySafeBeforeSecretReveal(): Boolean {
        evaluateAllConnectedDisplays()
        if (_exposureState.value != ScreenExposureState.PRIVATE_SAFE) {
            onRecordRedactedEvent(RedactedSecurityEventCode.PASSWORD_REVEAL_BLOCKED)
            return false
        }
        return true
    }

    private fun evaluateAllConnectedDisplays() {
        val displays = displayManager.displays
        for (display in displays) {
            if (display.displayId != Display.DEFAULT_DISPLAY) {
                val flags = display.flags
                val isPresentation = (flags and Display.FLAG_PRESENTATION) != 0
                val isPrivate = (flags and Display.FLAG_PRIVATE) != 0
                val isSecure = (flags and Display.FLAG_SECURE) != 0

                // Virtual / mirroring / MediaProjection / Cast / Smart View / HDMI detection
                if (isPresentation || !isPrivate || !isSecure) {
                    val detectedState = if (isPresentation) {
                        ScreenExposureState.EXTERNAL_DISPLAY_DETECTED
                    } else {
                        ScreenExposureState.PROJECTION_DETECTED
                    }
                    val code = if (isPresentation) {
                        RedactedSecurityEventCode.EXTERNAL_DISPLAY_DETECTED
                    } else {
                        RedactedSecurityEventCode.PROJECTION_RISK_DETECTED
                    }
                    handleExposureDetected(detectedState, code)
                    return
                } else {
                    // Fail closed even for secondary displays unless explicitly trusted
                    handleExposureDetected(
                        ScreenExposureState.EXTERNAL_DISPLAY_DETECTED,
                        RedactedSecurityEventCode.EXTERNAL_DISPLAY_DETECTED
                    )
                    return
                }
            }
        }
    }

    private fun handleExposureDetected(
        newState: ScreenExposureState,
        eventCode: RedactedSecurityEventCode
    ) {
        _exposureState.value = newState
        onRecordRedactedEvent(eventCode)

        if (extremeModeEnabled()) {
            onRecordRedactedEvent(RedactedSecurityEventCode.VAULT_AUTO_LOCKED)
            onEmergencyLockVaultAndZeroize(eventCode)
        }
    }

    override fun onDisplayAdded(displayId: Int) = evaluateAllConnectedDisplays()
    override fun onDisplayChanged(displayId: Int) = evaluateAllConnectedDisplays()
    override fun onDisplayRemoved(displayId: Int) = evaluateAllConnectedDisplays()

    override fun onPause(owner: LifecycleOwner) {
        // Immediately obscure sensitive content for Android Recents / app switcher preview
        if (_exposureState.value == ScreenExposureState.PRIVATE_SAFE) {
            _exposureState.value = ScreenExposureState.PROTECTED_HIDDEN
        }
    }

    override fun onStop(owner: LifecycleOwner) {
        // Preferred Extreme Mode behavior: lock vault and zeroize keys when backgrounded
        if (extremeModeEnabled()) {
            _exposureState.value = ScreenExposureState.VAULT_LOCKED
            onRecordRedactedEvent(RedactedSecurityEventCode.VAULT_AUTO_LOCKED)
            onEmergencyLockVaultAndZeroize(RedactedSecurityEventCode.VAULT_AUTO_LOCKED)
        }
    }
}

@Composable
fun ScreenExposureGate(
    exposureManager: ScreenExposureProtectionManager,
    onReturnToSafety: () -> Unit,
    onLockVault: () -> Unit,
    sensitiveContent: @Composable () -> Unit,
    privacyShieldContent: @Composable (
        onReturnToSafety: () -> Unit,
        onLockVault: () -> Unit
    ) -> Unit
) {
    val state by exposureManager.exposureState.collectAsState()
    if (state == ScreenExposureState.PRIVATE_SAFE) {
        sensitiveContent()
    } else {
        // Never render sensitive composable tree when state != PRIVATE_SAFE
        privacyShieldContent(onReturnToSafety, onLockVault)
    }
}`,
  },
  {
    moduleName: 'AndroidKeystoreWrappingEngine.kt',
    layer: 'Android Keystore / StrongBox Hardware Layer',
    summary:
      'Hardware-backed AES-256-GCM wrapping key generation inside StrongBox Keymaster with automatic TEE fallback, biometric user authentication requirement, and setInvalidatedByBiometricEnrollment(true).',
    code: `package com.blacktower.vault.crypto.android

import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

class AndroidKeystoreWrappingEngine(private val packageManager: PackageManager) {
    companion object {
        private const val KEYSTORE_PROVIDER = "AndroidKeyStore"
        private const val BIOMETRIC_WRAP_ALIAS = "com.blacktower.vault.ROOT_KEY_BIOMETRIC_WRAP_V1"
        private const val GCM_TAG_BITS = 128
    }

    fun getOrCreateHardwareWrappingKey(): SecretKey {
        val ks = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
        (ks.getKey(BIOMETRIC_WRAP_ALIAS, null) as? SecretKey)?.let { return it }

        val hasStrongBox = Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
            packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)

        return try {
            generateBiometricKey(useStrongBox = hasStrongBox)
        } catch (e: StrongBoxUnavailableException) {
            // Explicit fail-safe fallback to Trusted Execution Environment (TEE)
            generateBiometricKey(useStrongBox = false)
        }
    }

    private fun generateBiometricKey(useStrongBox: Boolean): SecretKey {
        val keyGenerator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES,
            KEYSTORE_PROVIDER
        )
        val builder = KeyGenParameterSpec.Builder(
            BIOMETRIC_WRAP_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setUserAuthenticationRequired(true)
            .setInvalidatedByBiometricEnrollment(true)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            builder.setUserAuthenticationParameters(
                0, // Require authentication on every cryptographic operation
                KeyProperties.AUTH_BIOMETRIC_STRONG
            )
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && useStrongBox) {
            builder.setIsStrongBoxBacked(true)
        }

        keyGenerator.init(builder.build())
        return keyGenerator.generateKey()
    }

    fun initWrapCipher(aadBytes: ByteArray): Cipher {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, getOrCreateHardwareWrappingKey())
        cipher.updateAAD(aadBytes)
        return cipher
    }

    fun initUnwrapCipher(ivBytes: ByteArray, aadBytes: ByteArray): Cipher {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val spec = GCMParameterSpec(GCM_TAG_BITS, ivBytes)
        cipher.init(Cipher.DECRYPT_MODE, getOrCreateHardwareWrappingKey(), spec)
        cipher.updateAAD(aadBytes)
        return cipher
    }
}`,
  },
  {
    moduleName: 'VaultSecurityLifecycleObserver.kt',
    layer: 'FLAG_SECURE & Sensitive Clipboard Protection',
    summary:
      'Marks copied secrets with ClipDescription.EXTRA_IS_SENSITIVE on Android 13+ and schedules deterministic clipboard clearing.',
    code: `package com.blacktower.vault.security

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.os.Build
import android.os.PersistableBundle
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

object SensitiveClipboardGuard {
    fun copySensitiveSecret(
        clipboardManager: ClipboardManager,
        label: String,
        secretValue: String,
        timeoutSeconds: Long,
        scope: CoroutineScope
    ): Job {
        val clip = ClipData.newPlainText(label, secretValue)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            clip.description.extras = PersistableBundle().apply {
                putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true)
            }
        }
        clipboardManager.setPrimaryClip(clip)

        return scope.launch {
            delay(timeoutSeconds * 1000L)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                clipboardManager.clearPrimaryClip()
            } else {
                clipboardManager.setPrimaryClip(ClipData.newPlainText("", ""))
            }
        }
    }
}`,
  },
];
