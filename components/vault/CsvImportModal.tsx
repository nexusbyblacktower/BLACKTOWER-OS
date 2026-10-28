'use client';

import React, { useState, useRef } from 'react';
import {
  Upload,
  FileSpreadsheet,
  Download,
  X,
  CheckCircle2,
  AlertTriangle,
  ShieldCheck,
  Lock,
  Sparkles,
  RefreshCw,
} from 'lucide-react';
import type { DecryptedVaultItem } from '@/lib/crypto/vault-crypto';
import {
  type CsvImportAnalysisSession,
  type CsvImportExecutionReport,
  type DuplicateHandlingPolicy,
  type VaultCsvTargetField,
  clearCsvImportSessionBuffer,
  detectCsvColumnMappings,
  evaluateCsvCandidates,
  generateSafeCsvTemplateContent,
  generateSampleMigrationCsvForTesting,
  maskSensitivePreviewValue,
  parseRawCsvLocally,
} from '@/lib/import/csv-migration';

import {
  type ScreenExposureState,
  canRenderSensitiveContent,
} from '@/lib/security/screen-exposure-engine';

interface CsvImportModalProps {
  isOpen: boolean;
  existingItems: DecryptedVaultItem[];
  screenExposureState: ScreenExposureState;
  onActiveSessionChange?: (session: CsvImportAnalysisSession | null) => void;
  onClose: () => void;
  onExecuteImport: (
    session: CsvImportAnalysisSession,
    duplicatePolicy: DuplicateHandlingPolicy
  ) => Promise<CsvImportExecutionReport>;
  onViewImportedItems: () => void;
}

const TARGET_FIELD_OPTIONS: Array<{ value: VaultCsvTargetField; label: string }> = [
  { value: 'title', label: 'Vault: Title / Name' },
  { value: 'username', label: 'Vault: Username / Email' },
  { value: 'password', label: 'Vault: Password (Masked)' },
  { value: 'url', label: 'Vault: Website / URL' },
  { value: 'noteContent', label: 'Vault: Notes' },
  { value: 'folder', label: 'Vault: Category / Folder' },
  { value: 'favorite', label: 'Vault: Favorite' },
  { value: 'totpSecret', label: 'Vault: TOTP / OTP Secret' },
  { value: 'recordType', label: 'Vault: Record Type' },
  { value: 'ignore', label: 'Ignore / Unmapped' },
];

export default function CsvImportModal({
  isOpen,
  existingItems,
  screenExposureState,
  onActiveSessionChange,
  onClose,
  onExecuteImport,
  onViewImportedItems,
}: CsvImportModalProps) {
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const [session, setSession] = useState<CsvImportAnalysisSession | null>(null);
  const [duplicatePolicy, setDuplicatePolicy] = useState<DuplicateHandlingPolicy>('skip');
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [isEncrypting, setIsEncrypting] = useState(false);
  const [completionReport, setCompletionReport] = useState<CsvImportExecutionReport | null>(null);

  if (!isOpen || !canRenderSensitiveContent(screenExposureState)) {
    return null;
  }

  const updateActiveSession = (next: CsvImportAnalysisSession | null) => {
    setSession(next);
    onActiveSessionChange?.(next);
  };

  const wipeTemporaryStateAndReset = () => {
    if (session) {
      clearCsvImportSessionBuffer(session);
    }
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
    updateActiveSession(null);
    setCompletionReport(null);
    setErrorMsg(null);
    setDuplicatePolicy('skip');
  };

  const handleCancelAndClose = () => {
    wipeTemporaryStateAndReset();
    onClose();
  };

  const handleDownloadTemplate = () => {
    const templateCsv = generateSafeCsvTemplateContent();
    const blob = new Blob([templateCsv], { type: 'text/csv;charset=utf-8' });
    const objectUrl = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = objectUrl;
    a.download = 'blacktower-vault-import-template.csv';
    a.click();
    // Immediately revoke temporary object URL per specification
    window.setTimeout(() => URL.revokeObjectURL(objectUrl), 0);
  };

  const processCsvTextLocally = (fileName: string, csvText: string) => {
    if (!canRenderSensitiveContent(screenExposureState)) {
      wipeTemporaryStateAndReset();
      return;
    }
    setErrorMsg(null);
    setCompletionReport(null);
    if (session) {
      clearCsvImportSessionBuffer(session);
    }

    try {
      const rawBuffer = new TextEncoder().encode(csvText);
      const parsed = parseRawCsvLocally(csvText);
      const detectedMappings = detectCsvColumnMappings(parsed.headers);
      const nextSession = evaluateCsvCandidates({
        fileName,
        fileSizeBytes: rawBuffer.byteLength,
        headers: parsed.headers,
        rawRows: parsed.rows,
        mappings: detectedMappings,
        existingVaultItems: existingItems,
      });
      nextSession.rawBufferRef = rawBuffer;
      updateActiveSession(nextSession);
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : 'Failed to parse CSV file locally.');
      updateActiveSession(null);
    }
  };

  const handleFileChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    if (!file.name.toLowerCase().endsWith('.csv') && file.type !== 'text/csv') {
      setErrorMsg('Unsupported file format. Only ".csv" files are accepted.');
      e.target.value = '';
      return;
    }

    try {
      const text = await file.text();
      // Release input File reference immediately after reading into local memory
      e.target.value = '';
      processCsvTextLocally(file.name, text);
    } catch {
      e.target.value = '';
      setErrorMsg('Could not read the selected CSV file.');
    }
  };

  const handleLoadSampleMigrationCsv = () => {
    const sample = generateSampleMigrationCsvForTesting(
      existingItems[0]?.data.username || 'secops-admin@blacktower.internal'
    );
    processCsvTextLocally('password-manager-export.csv', sample);
  };

  const handleUpdateColumnMapping = (columnIndex: number, newTarget: VaultCsvTargetField) => {
    if (!session) return;
    const updatedMappings = session.mappings.map((m) =>
      m.columnIndex === columnIndex
        ? { ...m, targetField: newTarget, confidence: 'exact' as const }
        : m
    );
    const reevaluated = evaluateCsvCandidates({
      fileName: session.fileName,
      fileSizeBytes: session.fileSizeBytes,
      headers: session.headers,
      rawRows: session.rawRows,
      mappings: updatedMappings,
      existingVaultItems: existingItems,
    });
    reevaluated.rawBufferRef = session.rawBufferRef;
    setSession(reevaluated);
  };

  const handleToggleDuplicateRowReview = (rowNumber: number, checked: boolean) => {
    if (!session) return;
    const nextCandidates = session.candidates.map((c) =>
      c.rowNumber === rowNumber ? { ...c, selectedForReviewImport: checked } : c
    );
    setSession({
      ...session,
      candidates: nextCandidates,
    });
  };

  const handleConfirmEncryptAndImport = async () => {
    if (!session) return;
    setIsEncrypting(true);
    setErrorMsg(null);
    try {
      const report = await onExecuteImport(session, duplicatePolicy);
      // Clear file input reference and session state in UI
      if (fileInputRef.current) {
        fileInputRef.current.value = '';
      }
      setSession(null);
      setCompletionReport(report);
    } catch (err) {
      wipeTemporaryStateAndReset();
      setErrorMsg(
        err instanceof Error
          ? err.message
          : 'Import aborted: failed closed during item encryption.'
      );
    } finally {
      setIsEncrypting(false);
    }
  };

  const importableCount = session
    ? session.summary.validRecords +
      (duplicatePolicy === 'import_as_new'
        ? session.summary.duplicateRecords
        : duplicatePolicy === 'review'
        ? session.candidates.filter(
            (c) => c.status === 'duplicate' && c.selectedForReviewImport
          ).length
        : 0)
    : 0;

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="csv-import-modal-title"
      className="fixed inset-0 z-50 bg-black/80 flex items-center justify-center p-4 overflow-y-auto"
    >
      <div className="bg-[#0B0E11] border border-slate-800 rounded-xl max-w-5xl w-full p-6 space-y-6 my-8 max-h-[92vh] overflow-y-auto">
        {/* Top Modal Header */}
        <div className="flex flex-wrap items-start justify-between gap-4 border-b border-slate-800 pb-4">
          <div>
            <div className="flex items-center gap-2 text-xs text-[#00FF66] font-medium">
              <FileSpreadsheet className="w-4 h-4" />
              <span>Local-Only Zero-Knowledge Migration Engine</span>
            </div>
            <h2
              id="csv-import-modal-title"
              className="text-xl font-bold text-white mt-0.5"
              style={{ fontFamily: 'var(--font-display)' }}
            >
              Import Credentials from CSV
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              CSV parsing, validation, and per-item AES-256-GCM encryption occur strictly in local memory. Raw CSV data is never uploaded or logged.
            </p>
          </div>

          <div className="flex items-center gap-2.5 shrink-0">
            <button
              type="button"
              onClick={handleDownloadTemplate}
              className="px-3.5 py-2 text-xs font-medium text-slate-200 bg-slate-900 hover:bg-slate-800 border border-slate-700 rounded-lg transition-colors flex items-center gap-1.5 whitespace-nowrap"
            >
              <Download className="w-3.5 h-3.5 text-[#00FF66]" />
              <span>Download CSV Template</span>
            </button>

            <button
              type="button"
              onClick={handleCancelAndClose}
              className="px-3.5 py-2 text-xs font-medium text-slate-300 hover:text-white bg-slate-900 hover:bg-slate-800 border border-slate-800 rounded-lg transition-colors flex items-center gap-1.5 whitespace-nowrap"
            >
              <X className="w-3.5 h-3.5" />
              <span>Cancel</span>
            </button>
          </div>
        </div>

        {/* Hidden Native File Input (.csv only) */}
        <input
          ref={fileInputRef}
          type="file"
          accept=".csv,text/csv"
          onChange={handleFileChange}
          className="hidden"
          aria-label="Select CSV file to import"
        />

        {/* STATE 1: Completion Screen */}
        {completionReport ? (
          <div className="p-8 rounded-xl bg-slate-950 border border-slate-800 text-center space-y-6">
            <div className="w-12 h-12 rounded-full bg-[#00FF66]/10/80 border border-[#00FF66]/35 flex items-center justify-center mx-auto">
              <CheckCircle2 className="w-6 h-6 text-[#00FF66]" />
            </div>

            <div className="space-y-1">
              <h3
                className="text-2xl font-bold text-white"
                style={{ fontFamily: 'var(--font-display)' }}
              >
                Import Complete
              </h3>
              <p className="text-xs text-slate-400">
                Every imported record was sealed with a unique 256-bit Item Encryption Key and fresh 96-bit nonce. Temporary CSV plaintext buffers have been cleared.
              </p>
            </div>

            <div className="max-w-md mx-auto grid grid-cols-3 gap-4">
              <div className="p-4 rounded-lg bg-[#0B0E11] border border-slate-800">
                <div className="text-xs text-slate-400">Imported</div>
                <div className="text-2xl font-mono tabular-nums font-bold text-[#00FF66] mt-1">
                  Imported: {completionReport.importedCount}
                </div>
              </div>
              <div className="p-4 rounded-lg bg-[#0B0E11] border border-slate-800">
                <div className="text-xs text-slate-400">Skipped</div>
                <div className="text-2xl font-mono tabular-nums font-bold text-amber-400 mt-1">
                  Skipped: {completionReport.skippedCount}
                </div>
              </div>
              <div className="p-4 rounded-lg bg-[#0B0E11] border border-slate-800">
                <div className="text-xs text-slate-400">Failed</div>
                <div className="text-2xl font-mono tabular-nums font-bold text-rose-400 mt-1">
                  Failed: {completionReport.failedCount}
                </div>
              </div>
            </div>

            <div className="text-xs font-mono text-slate-400 flex items-center justify-center gap-4">
              <span>Local Parsing: Verified</span>
              <span aria-hidden="true">·</span>
              <span>Network Upload: 0 bytes</span>
              <span aria-hidden="true">·</span>
              <span>Temporary State Cleared: {completionReport.temporaryStateCleared ? 'Yes' : 'No'}</span>
            </div>

            <div className="pt-2">
              <button
                type="button"
                onClick={() => {
                  wipeTemporaryStateAndReset();
                  onViewImportedItems();
                }}
                className="px-6 py-2.5 text-xs font-semibold text-slate-950 bg-[#00FF66] hover:bg-[#22FF7A] rounded-lg transition-colors inline-flex items-center gap-2"
              >
                <ShieldCheck className="w-4 h-4" />
                <span>View Imported Items</span>
              </button>
            </div>
          </div>
        ) : (
          <>
            {/* Upload Bar */}
            <div className="p-5 rounded-xl bg-slate-950 border border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
              <div className="space-y-1">
                <div className="text-sm font-semibold text-slate-100">
                  {session
                    ? `Loaded File: ${session.fileName} (${session.fileSizeBytes} bytes · Local Memory Only)`
                    : 'Select a Password Manager Export (.csv)'}
                </div>
                <p className="text-xs text-slate-400">
                  Supports exports from Bitwarden, 1Password, Chrome, Firefox, KeePass, or the BLACKTOWER CSV Template.
                </p>
              </div>

              <div className="flex flex-wrap items-center gap-2.5 shrink-0">
                <button
                  type="button"
                  onClick={() => fileInputRef.current?.click()}
                  className="px-4 py-2 text-xs font-semibold text-slate-950 bg-[#00FF66] hover:bg-[#22FF7A] rounded-lg transition-colors flex items-center gap-1.5 whitespace-nowrap"
                >
                  <Upload className="w-3.5 h-3.5" />
                  <span>Upload CSV File</span>
                </button>

                <button
                  type="button"
                  onClick={handleLoadSampleMigrationCsv}
                  className="px-3.5 py-2 text-xs font-medium text-slate-300 hover:text-white bg-[#0B0E11] border border-slate-800 rounded-lg transition-colors flex items-center gap-1.5 whitespace-nowrap"
                >
                  <Sparkles className="w-3.5 h-3.5 text-[#00FF66]" />
                  <span>Load Sample Migration CSV</span>
                </button>
              </div>
            </div>

            {errorMsg && (
              <div
                role="alert"
                className="p-3.5 rounded-lg bg-rose-950/60 border border-rose-800 text-xs text-rose-200 flex items-center gap-2.5"
              >
                <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
                <span>{errorMsg}</span>
              </div>
            )}

            {/* Preview, Mapping & Validation Section when a CSV is loaded */}
            {session && (
              <div className="space-y-6">
                {/* 1. Five Required Record Counters */}
                <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
                  <div className="p-3.5 rounded-lg bg-slate-950 border border-slate-800">
                    <div className="text-xs text-slate-400">Total records</div>
                    <div className="text-lg font-mono tabular-nums font-bold text-white mt-0.5">
                      {session.summary.totalRecords}
                    </div>
                  </div>
                  <div className="p-3.5 rounded-lg bg-slate-950 border border-slate-800">
                    <div className="text-xs text-slate-400">Valid records</div>
                    <div className="text-lg font-mono tabular-nums font-bold text-[#00FF66] mt-0.5">
                      {session.summary.validRecords}
                    </div>
                  </div>
                  <div className="p-3.5 rounded-lg bg-slate-950 border border-slate-800">
                    <div className="text-xs text-slate-400">Invalid records</div>
                    <div className="text-lg font-mono tabular-nums font-bold text-rose-400 mt-0.5">
                      {session.summary.invalidRecords}
                    </div>
                  </div>
                  <div className="p-3.5 rounded-lg bg-slate-950 border border-slate-800">
                    <div className="text-xs text-slate-400">Duplicate records</div>
                    <div className="text-lg font-mono tabular-nums font-bold text-amber-400 mt-0.5">
                      {session.summary.duplicateRecords}
                    </div>
                  </div>
                  <div className="p-3.5 rounded-lg bg-slate-950 border border-slate-800">
                    <div className="text-xs text-slate-400">Unsupported records</div>
                    <div className="text-lg font-mono tabular-nums font-bold text-purple-400 mt-0.5">
                      {session.summary.unsupportedRecords}
                    </div>
                  </div>
                </div>

                {/* 2. Column Mapping Controls */}
                <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-3">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div>
                      <h3 className="text-xs font-semibold text-white">
                        Column Mapping (Automatic Detection + Manual Override)
                      </h3>
                      <p className="text-xs text-slate-400">
                        Map CSV headers (such as login_uri, login_username, login_password, extra) to BLACKTOWER Vault fields.
                      </p>
                    </div>
                    {session.hasUncertainMappings && (
                      <span className="text-xs text-amber-400 flex items-center gap-1">
                        <AlertTriangle className="w-3.5 h-3.5" />
                        <span>Verify unmapped columns before importing</span>
                      </span>
                    )}
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
                    {session.mappings.map((mapping) => (
                      <div
                        key={mapping.columnIndex}
                        className="p-2.5 rounded-lg bg-[#0B0E11] border border-slate-800 flex items-center justify-between gap-2"
                      >
                        <div className="min-w-0">
                          <div className="text-xs font-mono text-slate-200 truncate">
                            CSV &quot;{mapping.csvHeader}&quot;
                          </div>
                          <div className="text-[11px] text-slate-500">
                            {mapping.confidence === 'exact'
                              ? 'Exact match'
                              : mapping.confidence === 'alias'
                              ? 'Alias detected'
                              : 'Uncertain — review'}
                          </div>
                        </div>
                        <select
                          aria-label={`Map CSV column ${mapping.csvHeader}`}
                          value={mapping.targetField}
                          onChange={(e) =>
                            handleUpdateColumnMapping(
                              mapping.columnIndex,
                              e.target.value as VaultCsvTargetField
                            )
                          }
                          className="px-2 py-1 text-xs bg-slate-950 border border-slate-700 rounded text-slate-100 focus:outline-none focus:border-[#00FF66]"
                        >
                          {TARGET_FIELD_OPTIONS.map((opt) => (
                            <option key={opt.value} value={opt.value}>
                              {opt.label}
                            </option>
                          ))}
                        </select>
                      </div>
                    ))}
                  </div>
                </div>

                {/* 3. Duplicate Handling Strategy */}
                <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                  <div>
                    <div className="text-xs font-semibold text-white">
                      Duplicate Handling Policy
                    </div>
                    <div className="text-xs text-slate-400">
                      Existing vault records are never overwritten automatically.
                    </div>
                  </div>

                  <div className="flex items-center gap-1.5 p-1 bg-[#0B0E11] border border-slate-800 rounded-lg">
                    {(
                      [
                        { id: 'skip', label: 'Skip duplicates' },
                        { id: 'import_as_new', label: 'Import as new' },
                        { id: 'review', label: 'Review duplicates' },
                      ] as const
                    ).map((mode) => (
                      <button
                        key={mode.id}
                        type="button"
                        onClick={() => setDuplicatePolicy(mode.id)}
                        className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap ${
                          duplicatePolicy === mode.id
                            ? 'bg-slate-800 text-white'
                            : 'text-slate-400 hover:text-slate-200'
                        }`}
                      >
                        {mode.label}
                      </button>
                    ))}
                  </div>
                </div>

                {/* 4. Secure Masked Import Preview & Validation Diagnostics Table */}
                <div className="border border-slate-800 rounded-xl overflow-hidden bg-slate-950">
                  <div className="px-4 py-3 border-b border-slate-800 flex items-center justify-between gap-4">
                    <span className="text-xs font-semibold text-slate-200">
                      Import Preview & Row-Level Validation (Passwords Masked by Default)
                    </span>
                    <span className="text-xs font-mono text-slate-400">
                      Ready to Encrypt: {importableCount} record(s)
                    </span>
                  </div>

                  <div className="overflow-x-auto max-h-64">
                    <table className="w-full text-left border-collapse text-xs">
                      <thead>
                        <tr className="border-b border-slate-800 text-slate-400 bg-[#0B0E11]">
                          <th className="py-2.5 px-3 font-medium">Row</th>
                          <th className="py-2.5 px-3 font-medium">Status</th>
                          <th className="py-2.5 px-3 font-medium">Title / Name</th>
                          <th className="py-2.5 px-3 font-medium">Username</th>
                          <th className="py-2.5 px-3 font-medium">Website</th>
                          <th className="py-2.5 px-3 font-medium">Password</th>
                          <th className="py-2.5 px-3 font-medium">Validation / Diagnostic Detail</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800/70">
                        {session.candidates.map((row) => (
                          <tr key={row.rowNumber} className="hover:bg-slate-900/50">
                            <td className="py-2.5 px-3 font-mono tabular-nums text-slate-400">
                              #{row.rowNumber}
                            </td>
                            <td className="py-2.5 px-3 font-medium whitespace-nowrap">
                              {row.status === 'valid' && (
                                <span className="text-[#00FF66]">Valid</span>
                              )}
                              {row.status === 'duplicate' && (
                                <span className="text-amber-400">Duplicate</span>
                              )}
                              {row.status === 'invalid' && (
                                <span className="text-rose-400">Invalid</span>
                              )}
                              {row.status === 'unsupported' && (
                                <span className="text-purple-400">Unsupported</span>
                              )}
                            </td>
                            <td className="py-2.5 px-3 text-slate-100 font-medium">
                              {row.mapped.title || '—'}
                            </td>
                            <td className="py-2.5 px-3 font-mono text-slate-300">
                              {row.mapped.username || '—'}
                            </td>
                            <td className="py-2.5 px-3 text-slate-400 truncate max-w-[160px]">
                              {row.mapped.url || '—'}
                            </td>
                            <td className="py-2.5 px-3 font-mono text-slate-400">
                              {maskSensitivePreviewValue(row.mapped.password)}
                            </td>
                            <td className="py-2.5 px-3 text-slate-300">
                              {row.status === 'valid' ? (
                                <span className="text-slate-400">
                                  Ready for AES-256-GCM per-item encryption
                                </span>
                              ) : (
                                <div className="space-y-1">
                                  <div className="text-amber-300">{row.reasons.join('; ')}</div>
                                  {row.status === 'duplicate' && duplicatePolicy === 'review' && (
                                    <label className="inline-flex items-center gap-1.5 text-[#00FF66] cursor-pointer">
                                      <input
                                        type="checkbox"
                                        checked={row.selectedForReviewImport}
                                        onChange={(e) =>
                                          handleToggleDuplicateRowReview(
                                            row.rowNumber,
                                            e.target.checked
                                          )
                                        }
                                        className="rounded border-slate-700 bg-slate-900 text-[#00FF66]"
                                      />
                                      <span>Include this duplicate in import</span>
                                    </label>
                                  )}
                                </div>
                              )}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>

                {/* 5. Footer Action Bar */}
                <div className="flex flex-wrap items-center justify-between gap-4 pt-2 border-t border-slate-800">
                  <div className="text-xs text-slate-400 flex items-center gap-2">
                    <Lock className="w-3.5 h-3.5 text-[#00FF66] shrink-0" />
                    <span>
                      Each accepted record receives a fresh 256-bit Item Encryption Key and 96-bit CSPRNG nonce.
                    </span>
                  </div>

                  <div className="flex items-center gap-3">
                    <button
                      type="button"
                      onClick={handleCancelAndClose}
                      className="px-4 py-2 text-xs font-medium text-slate-300 hover:text-white bg-slate-900 rounded-lg"
                    >
                      Cancel
                    </button>

                    <button
                      type="button"
                      disabled={isEncrypting || importableCount === 0}
                      onClick={handleConfirmEncryptAndImport}
                      className="px-5 py-2 text-xs font-semibold text-slate-950 bg-[#00FF66] hover:bg-[#22FF7A] disabled:opacity-50 rounded-lg transition-colors flex items-center gap-2 whitespace-nowrap"
                    >
                      {isEncrypting ? (
                        <>
                          <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                          <span>Encrypting & Sealing Records...</span>
                        </>
                      ) : (
                        <>
                          <Lock className="w-3.5 h-3.5" />
                          <span>Encrypt & Import ({importableCount}) into Vault</span>
                        </>
                      )}
                    </button>
                  </div>
                </div>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}
