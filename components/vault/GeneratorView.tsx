'use client';

import React, { useState, useCallback, useEffect } from 'react';
import {
  RefreshCw,
  Copy,
  Check,
  Sliders,
  ShieldCheck,
  PlusCircle,
} from 'lucide-react';
import {
  generateSecurePassword,
  type GeneratedPasswordResult,
  type PasswordGeneratorConfig,
} from '@/lib/crypto/password-generator';

interface GeneratorViewProps {
  onCopySecretWithGuard: (label: string, value: string) => void;
  onSaveGeneratedAsVaultItem: (password: string) => void;
}

export default function GeneratorView({
  onCopySecretWithGuard,
  onSaveGeneratedAsVaultItem,
}: GeneratorViewProps) {
  const [config, setConfig] = useState<PasswordGeneratorConfig>({
    length: 24,
    uppercase: true,
    lowercase: true,
    numbers: true,
    symbols: true,
    excludeAmbiguous: false,
  });

  const [result, setResult] = useState<GeneratedPasswordResult | null>(null);
  const [copied, setCopied] = useState(false);
  const [advancedMode, setAdvancedMode] = useState(false);
  const [sessionHistory, setSessionHistory] = useState<
    Array<{ password: string; entropyBits: number; generatedAt: string }>
  >([]);

  const applyConfigAndGenerate = useCallback((nextConfig: PasswordGeneratorConfig) => {
    setConfig(nextConfig);
    try {
      const generated = generateSecurePassword(nextConfig);
      setResult(generated);
      setSessionHistory((prev) => [
        {
          password: generated.password,
          entropyBits: generated.entropyBits,
          generatedAt: new Date().toLocaleTimeString(),
        },
        ...prev.slice(0, 4),
      ]);
    } catch {
      // Fallback if user unchecks last charset
    }
  }, []);

  useEffect(() => {
    const id = window.setTimeout(() => {
      applyConfigAndGenerate({
        length: 24,
        uppercase: true,
        lowercase: true,
        numbers: true,
        symbols: true,
        excludeAmbiguous: false,
      });
    }, 0);
    return () => window.clearTimeout(id);
  }, [applyConfigAndGenerate]);

  const updateCharToggle = (
    field: 'uppercase' | 'lowercase' | 'numbers' | 'symbols',
    checked: boolean
  ) => {
    const next = { ...config, [field]: checked };
    // Ensure at least one character set remains enabled
    if (!next.uppercase && !next.lowercase && !next.numbers && !next.symbols) {
      return;
    }
    applyConfigAndGenerate(next);
  };

  const handleCopy = () => {
    if (!result) return;
    onCopySecretWithGuard('Generated Password', result.password);
    setCopied(true);
    setTimeout(() => setCopied(false), 1800);
  };

  const getStrengthColor = (label?: GeneratedPasswordResult['strengthLabel']) => {
    switch (label) {
      case 'Brutal':
        return 'text-[#00FF66]';
      case 'Strong':
        return 'text-[#00FF66]';
      case 'Moderate':
        return 'text-amber-400';
      default:
        return 'text-rose-400';
    }
  };

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-4 pb-4 border-b border-slate-800/80">
        <div>
          <h2
            className="text-xl font-bold text-white"
            style={{ fontFamily: 'var(--font-display)' }}
          >
            Cryptographic Password Generator
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Generates high-entropy credentials using rejection-sampled CSPRNG bytes with zero modulo bias.
          </p>
        </div>

        <button
          type="button"
          onClick={() => setAdvancedMode(!advancedMode)}
          className="px-3.5 py-2 text-xs font-medium text-slate-300 hover:text-white bg-[#0B0E11] border border-slate-800 rounded-lg transition-colors flex items-center gap-2 whitespace-nowrap"
        >
          <Sliders className="w-3.5 h-3.5 text-[#00FF66]" />
          <span>{advancedMode ? 'Hide Entropy Telemetry' : 'Advanced Entropy Mode'}</span>
        </button>
      </div>

      {/* Main Generator Output Surface */}
      <div className="bg-[#0B0E11] border border-slate-800 rounded-xl p-6 space-y-6">
        <div className="p-5 rounded-lg bg-slate-950 border border-slate-800/90 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="min-w-0 flex-1">
            <div
              data-testid="generated-password-output"
              className="text-lg sm:text-xl font-mono text-white break-all tracking-wide select-all"
            >
              {result?.password || 'Generating...'}
            </div>
            <div className="flex flex-wrap items-center gap-2 text-xs text-slate-400 mt-2">
              <span className={`font-semibold ${getStrengthColor(result?.strengthLabel)}`}>
                Strength: {result?.strengthLabel || 'Brutal'}
              </span>
              <span aria-hidden="true">·</span>
              <span className="font-mono tabular-nums">{config.length} characters</span>
              <span aria-hidden="true">·</span>
              <span>Offline crack resistance: {result?.estimatedOfflineCrackTime}</span>
            </div>
          </div>

          <div className="flex items-center gap-2.5 shrink-0">
            <button
              type="button"
              aria-label="Regenerate password"
              onClick={() => applyConfigAndGenerate(config)}
              className="px-3.5 py-2.5 text-xs font-medium text-slate-200 bg-slate-900 hover:bg-slate-800 border border-slate-800 rounded-lg transition-colors flex items-center gap-1.5 whitespace-nowrap"
            >
              <RefreshCw className="w-4 h-4" />
              <span>Regenerate</span>
            </button>
            <button
              type="button"
              onClick={handleCopy}
              className="px-4 py-2.5 text-xs font-semibold text-slate-950 bg-[#00FF66] hover:bg-[#22FF7A] rounded-lg transition-colors flex items-center gap-1.5 whitespace-nowrap"
            >
              {copied ? (
                <>
                  <Check className="w-4 h-4" />
                  <span>Copied</span>
                </>
              ) : (
                <>
                  <Copy className="w-4 h-4" />
                  <span>Copy Password</span>
                </>
              )}
            </button>
          </div>
        </div>

        {/* Length Slider (`8-64` characters) */}
        <div className="space-y-2">
          <div className="flex items-center justify-between text-xs">
            <label htmlFor="pw-length-slider" className="font-medium text-slate-300">
              Password Length (8–64 characters)
            </label>
            <span className="font-mono tabular-nums text-sm font-semibold text-[#00FF66]">
              {config.length} chars
            </span>
          </div>
          <input
            id="pw-length-slider"
            type="range"
            min={8}
            max={64}
            value={config.length}
            onChange={(e) =>
              applyConfigAndGenerate({ ...config, length: Number(e.target.value) })
            }
            className="w-full accent-[#00FF66] cursor-pointer"
          />
          <div className="flex justify-between text-xs text-slate-500 font-mono tabular-nums">
            <span>8</span>
            <span>16</span>
            <span>24</span>
            <span>32</span>
            <span>48</span>
            <span>64</span>
          </div>
        </div>

        {/* Character Set Controls */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3 pt-2 border-t border-slate-800/80">
          <label className="flex items-center gap-2.5 p-3 rounded-lg bg-slate-950 border border-slate-800/80 cursor-pointer select-none">
            <input
              type="checkbox"
              checked={config.uppercase}
              onChange={(e) => updateCharToggle('uppercase', e.target.checked)}
              className="rounded border-slate-700 bg-slate-900 text-[#00FF66]"
            />
            <span className="text-xs font-medium text-slate-200">Uppercase (A–Z)</span>
          </label>

          <label className="flex items-center gap-2.5 p-3 rounded-lg bg-slate-950 border border-slate-800/80 cursor-pointer select-none">
            <input
              type="checkbox"
              checked={config.lowercase}
              onChange={(e) => updateCharToggle('lowercase', e.target.checked)}
              className="rounded border-slate-700 bg-slate-900 text-[#00FF66]"
            />
            <span className="text-xs font-medium text-slate-200">Lowercase (a–z)</span>
          </label>

          <label className="flex items-center gap-2.5 p-3 rounded-lg bg-slate-950 border border-slate-800/80 cursor-pointer select-none">
            <input
              type="checkbox"
              checked={config.numbers}
              onChange={(e) => updateCharToggle('numbers', e.target.checked)}
              className="rounded border-slate-700 bg-slate-900 text-[#00FF66]"
            />
            <span className="text-xs font-medium text-slate-200">Numbers (0–9)</span>
          </label>

          <label className="flex items-center gap-2.5 p-3 rounded-lg bg-slate-950 border border-slate-800/80 cursor-pointer select-none">
            <input
              type="checkbox"
              checked={config.symbols}
              onChange={(e) => updateCharToggle('symbols', e.target.checked)}
              className="rounded border-slate-700 bg-slate-900 text-[#00FF66]"
            />
            <span className="text-xs font-medium text-slate-200">Symbols (!@#$)</span>
          </label>

          <label className="flex items-center gap-2.5 p-3 rounded-lg bg-slate-950 border border-slate-800/80 cursor-pointer select-none">
            <input
              type="checkbox"
              checked={Boolean(config.excludeAmbiguous)}
              onChange={(e) =>
                applyConfigAndGenerate({ ...config, excludeAmbiguous: e.target.checked })
              }
              className="rounded border-slate-700 bg-slate-900 text-[#00FF66]"
            />
            <span className="text-xs font-medium text-slate-200">No Ambiguous (0O1lI)</span>
          </label>
        </div>

        {/* Save Directly to Vault Action */}
        <div className="pt-2 border-t border-slate-800/80 flex items-center justify-between gap-4">
          <div className="text-xs text-slate-400 flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-[#00FF66] shrink-0" />
            <span>Generated entirely in local volatile memory. Cleared when vault locks.</span>
          </div>
          {result && (
            <button
              type="button"
              onClick={() => onSaveGeneratedAsVaultItem(result.password)}
              className="px-3.5 py-2 text-xs font-medium text-[#00FF66] hover:text-[#00FF66] border border-slate-800 hover:border-slate-700 rounded-lg transition-colors flex items-center gap-1.5 whitespace-nowrap"
            >
              <PlusCircle className="w-3.5 h-3.5" />
              <span>Encrypt as New Vault Item</span>
            </button>
          )}
        </div>
      </div>

      {/* Advanced Mode: Entropy, CSPRNG Source & Methodology */}
      {advancedMode && result && (
        <div className="bg-[#0B0E11] border border-slate-800 rounded-xl p-6 space-y-5">
          <div className="border-b border-slate-800 pb-3">
            <h3
              className="text-sm font-semibold text-white"
              style={{ fontFamily: 'var(--font-display)' }}
            >
              Advanced Cryptographic Entropy & CSPRNG Methodology
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Real-time parameters from the latest unbiased rejection-sampling pass.
            </p>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
            <div className="p-3.5 rounded-lg bg-slate-950 border border-slate-800">
              <div className="text-xs text-slate-400">Shannon / Pool Entropy</div>
              <div className="text-lg font-mono tabular-nums font-bold text-[#00FF66] mt-1">
                {result.entropyBits} bits
              </div>
            </div>
            <div className="p-3.5 rounded-lg bg-slate-950 border border-slate-800">
              <div className="text-xs text-slate-400">Active Symbol Pool</div>
              <div className="text-lg font-mono tabular-nums font-bold text-white mt-1">
                {result.charsetSize} symbols
              </div>
            </div>
            <div className="p-3.5 rounded-lg bg-slate-950 border border-slate-800">
              <div className="text-xs text-slate-400">CSPRNG Byte Draws</div>
              <div className="text-lg font-mono tabular-nums font-bold text-[#00FF66] mt-1">
                {result.telemetry.totalDraws} ({result.telemetry.rejectionDraws} rejected)
              </div>
            </div>
            <div className="p-3.5 rounded-lg bg-slate-950 border border-slate-800">
              <div className="text-xs text-slate-400">Modulo Bias</div>
              <div className="text-lg font-mono tabular-nums font-bold text-[#00FF66] mt-1">
                0.000% (Eliminated)
              </div>
            </div>
          </div>

          <div className="text-xs font-mono text-slate-400 space-y-1 bg-slate-950 p-3.5 rounded-lg border border-slate-800">
            <div>Entropy Source: {result.telemetry.csprngSource}</div>
            <div>Selection Algorithm: {result.telemetry.methodology}</div>
            <div>
              Acceptance Bound Formula: limit = 256 - (256 mod N); bytes &gt;= limit are discarded
              and redrawn.
            </div>
          </div>

          {sessionHistory.length > 1 && (
            <div className="space-y-2 pt-2">
              <div className="text-xs font-medium text-slate-400">
                Ephemeral In-Memory Generation Log (Wiped on Vault Lock)
              </div>
              <div className="divide-y divide-slate-800/80 border border-slate-800 rounded-lg bg-slate-950">
                {sessionHistory.map((h, i) => (
                  <div
                    key={i}
                    className="px-3.5 py-2 flex items-center justify-between gap-4 text-xs font-mono"
                  >
                    <span className="text-slate-300 truncate">{h.password}</span>
                    <span className="text-slate-500 tabular-nums shrink-0">
                      {h.entropyBits} bits · {h.generatedAt}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
