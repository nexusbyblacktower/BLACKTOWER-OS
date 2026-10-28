import {
  type ActiveVaultKeyring,
  type DecryptedVaultItem,
  type DecryptedVaultItemPayload,
  type EncryptedVaultItemEnvelope,
  type VaultRecordType,
  SecurityAbortError,
  encryptVaultItem,
  zeroizeBuffer,
} from '../crypto/vault-crypto.ts';
import { inspectStorageForPlaintextLeakage } from '../sync/sync-validator.ts';

export const MAX_CSV_FILE_BYTES = 5 * 1024 * 1024; // 5 MiB max safety cap
export const MAX_CSV_ROWS = 5000;

export type VaultCsvTargetField =
  | 'title'
  | 'username'
  | 'password'
  | 'url'
  | 'noteContent'
  | 'folder'
  | 'favorite'
  | 'totpSecret'
  | 'recordType'
  | 'ignore';

export interface CsvColumnMapping {
  csvHeader: string;
  columnIndex: number;
  targetField: VaultCsvTargetField;
  confidence: 'exact' | 'alias' | 'uncertain';
}

export type CsvRowStatus = 'valid' | 'duplicate' | 'invalid' | 'unsupported';

export interface ParsedCsvRowCandidate {
  rowNumber: number; // 1-based data row index (excluding header)
  rawColumnCount: number;
  expectedColumnCount: number;
  malformedQuoteError?: string;
  encodingError?: boolean;
  mapped: {
    title: string;
    username: string;
    password: string;
    url: string;
    noteContent: string;
    folder: string;
    favorite: boolean;
    totpSecret: string;
    rawType: string;
  };
  resolvedRecordType: VaultRecordType;
  status: CsvRowStatus;
  reasons: string[];
  duplicateOfTitle?: string;
  selectedForReviewImport: boolean; // Used when duplicateMode === 'review'
}

export interface CsvImportAnalysisSession {
  fileName: string;
  fileSizeBytes: number;
  headers: string[];
  mappings: CsvColumnMapping[];
  hasUncertainMappings: boolean;
  rawRows: Array<{
    rowNumber: number;
    cells: string[];
    malformedError?: string;
    encodingError?: boolean;
  }>;
  candidates: ParsedCsvRowCandidate[];
  summary: {
    totalRecords: number;
    validRecords: number;
    invalidRecords: number;
    duplicateRecords: number;
    unsupportedRecords: number;
  };
  rawBufferRef?: Uint8Array;
  cleared: boolean;
}

export type DuplicateHandlingPolicy = 'skip' | 'import_as_new' | 'review';

export interface CsvImportExecutionReport {
  status: 'Import Complete';
  importedCount: number;
  skippedCount: number;
  failedCount: number;
  encryptedEnvelopes: EncryptedVaultItemEnvelope[];
  localOnlyVerified: boolean;
  temporaryStateCleared: boolean;
}

const HEADER_SYNONYMS: Record<Exclude<VaultCsvTargetField, 'ignore'>, { exact: string[]; aliases: string[] }> = {
  title: {
    exact: ['name', 'title'],
    aliases: ['item_name', 'service', 'account_name', 'entry_title', 'label'],
  },
  username: {
    exact: ['username', 'email', 'login'],
    aliases: ['login_username', 'user', 'user_name', 'email_address', 'account_login', 'id'],
  },
  password: {
    exact: ['password', 'login_password'],
    aliases: ['pass', 'secret', 'passwd', 'credential'],
  },
  url: {
    exact: ['website', 'url', 'login_uri'],
    aliases: ['uri', 'site', 'domain', 'host', 'web_address', 'Action URL'],
  },
  noteContent: {
    exact: ['notes', 'extra', 'note'],
    aliases: ['comments', 'comment', 'description', 'secure_note', 'memo'],
  },
  folder: {
    exact: ['category', 'folder'],
    aliases: ['group', 'collection', 'tag', 'organizational_unit'],
  },
  favorite: {
    exact: ['favorite', 'fav'],
    aliases: ['starred', 'pinned', 'is_favorite'],
  },
  totpSecret: {
    exact: ['totp', 'otp', 'login_totp'],
    aliases: ['totp_secret', 'authenticator', 'two_factor_secret', 'mfa_seed'],
  },
  recordType: {
    exact: ['type', 'record_type'],
    aliases: ['item_type', 'kind', 'vault_type'],
  },
};

/**
 * Generates a safe, downloadable CSV Template containing ONLY fake example credentials.
 */
export function generateSafeCsvTemplateContent(): string {
  const rows = [
    ['name', 'url', 'username', 'password', 'notes', 'category', 'favorite', 'totp', 'type'],
    [
      'Example Cloud Console (Template Only)',
      'https://console.example.invalid',
      'demo-user@example.invalid',
      'FakeTemplatePass!9928#DoNotUse',
      'Fake example row for CSV column mapping verification',
      'Infrastructure',
      'true',
      'JBSWY3DPEHPK3PXP',
      'password',
    ],
    [
      'Example Internal Wiki (Template Only)',
      'https://wiki.example.invalid',
      'editor@example.invalid',
      'FakeWikiCredential$2026!Example',
      'Secondary fake template credential',
      'Engineering',
      'false',
      '',
      'password',
    ],
  ];
  return rows
    .map((r) =>
      r
        .map((cell) =>
          cell.includes(',') || cell.includes('"') || cell.includes('\n')
            ? `"${cell.replace(/"/g, '""')}"`
            : cell
        )
        .join(',')
    )
    .join('\n');
}

/**
 * Generates a realistic multi-row sample CSV string (including valid rows, a duplicate row,
 * a malformed URL row, and an unsupported record type) for testing the migration workflow locally.
 */
export function generateSampleMigrationCsvForTesting(existingUsernameCanary?: string): string {
  const dupUser = existingUsernameCanary || 'secops-admin@blacktower.internal';
  return [
    'name,login_uri,login_username,login_password,extra,folder,favorite,totp,type',
    `"Proton Mail Sovereign Inbox","https://mail.proton.me","k.vance.vault@proton.me","Pm9$vL4#xQ8!zK2&wR7*nB5","Primary encrypted mail account","Communications","true","JBSWY3DPEHPK3PXP","password"`,
    `"AWS Production Root Key","https://signin.aws.amazon.com","aws-root@blacktower.internal","Aw8!mN3$pQ9#rT5@vX2&zL6","Hardware MFA enforced","Infrastructure","true","","password"`,
    `"Cloudflare Zero Trust Root Console","https://one.dash.cloudflare.com","${dupUser}","DuplicatePass!123","Duplicate of existing vault record","Infrastructure","false","","password"`,
    `"Malformed Endpoint Entry","htp://not-a-valid-url","ops@blacktower.internal","ValidPass#99123","Contains invalid URI scheme","Testing","false","","password"`,
    `"Legacy Hardware Dongle Blob","https://dongle.internal","dongle-admin","SecretBlob","Unsupported hardware binary record","Hardware","false","","usb_firmware_blob"`,
  ].join('\n');
}

/**
 * Automatically detects column mappings from CSV header names.
 */
export function detectCsvColumnMappings(headers: string[]): CsvColumnMapping[] {
  const usedTargets = new Set<VaultCsvTargetField>();

  return headers.map((rawHeader, columnIndex) => {
    const normalized = rawHeader.trim().toLowerCase().replace(/[\s-]+/g, '_');

    for (const [fieldKey, rules] of Object.entries(HEADER_SYNONYMS) as Array<
      [Exclude<VaultCsvTargetField, 'ignore'>, { exact: string[]; aliases: string[] }]
    >) {
      if (usedTargets.has(fieldKey)) continue;
      if (rules.exact.map((s) => s.toLowerCase()).includes(normalized)) {
        usedTargets.add(fieldKey);
        return {
          csvHeader: rawHeader,
          columnIndex,
          targetField: fieldKey,
          confidence: 'exact',
        };
      }
    }

    for (const [fieldKey, rules] of Object.entries(HEADER_SYNONYMS) as Array<
      [Exclude<VaultCsvTargetField, 'ignore'>, { exact: string[]; aliases: string[] }]
    >) {
      if (usedTargets.has(fieldKey)) continue;
      if (rules.aliases.map((s) => s.toLowerCase()).includes(normalized)) {
        usedTargets.add(fieldKey);
        return {
          csvHeader: rawHeader,
          columnIndex,
          targetField: fieldKey,
          confidence: 'alias',
        };
      }
    }

    return {
      csvHeader: rawHeader,
      columnIndex,
      targetField: 'ignore',
      confidence: 'uncertain',
    };
  });
}

/**
 * RFC 4180 Local CSV Parser with row-level quote/column validation.
 * Never logs or transmits any parsed content.
 */
export function parseRawCsvLocally(csvText: string): {
  headers: string[];
  rows: Array<{
    rowNumber: number;
    cells: string[];
    malformedError?: string;
    encodingError?: boolean;
  }>;
} {
  const byteLen = new TextEncoder().encode(csvText).length;
  if (byteLen > MAX_CSV_FILE_BYTES) {
    throw new SecurityAbortError(
      'CSV_FILE_OVERSIZED',
      `CSV file exceeds maximum safe local memory limit (${MAX_CSV_FILE_BYTES} bytes)`
    );
  }

  const normalizedText = csvText.replace(/^\uFEFF/, ''); // Strip UTF-8 BOM if present
  const lines: string[] = [];
  let currentLine = '';
  let insideQuotes = false;

  for (let i = 0; i < normalizedText.length; i++) {
    const ch = normalizedText[i];
    if (ch === '"') {
      if (insideQuotes && normalizedText[i + 1] === '"') {
        currentLine += '""';
        i += 1;
      } else {
        insideQuotes = !insideQuotes;
        currentLine += ch;
      }
    } else if ((ch === '\n' || ch === '\r') && !insideQuotes) {
      if (ch === '\r' && normalizedText[i + 1] === '\n') {
        i += 1;
      }
      if (currentLine.trim().length > 0 || lines.length > 0) {
        lines.push(currentLine);
      }
      currentLine = '';
    } else {
      currentLine += ch;
    }
  }
  if (currentLine.length > 0) {
    lines.push(currentLine);
  }

  // Remove trailing blank line if any
  while (lines.length > 0 && lines[lines.length - 1].trim() === '') {
    lines.pop();
  }

  if (lines.length === 0) {
    throw new SecurityAbortError('CSV_EMPTY_FILE', 'The selected CSV file contains no records.');
  }

  if (lines.length - 1 > MAX_CSV_ROWS) {
    throw new SecurityAbortError(
      'CSV_ROW_LIMIT_EXCEEDED',
      `CSV contains ${lines.length - 1} rows, exceeding maximum batch limit of ${MAX_CSV_ROWS}.`
    );
  }

  const parseLineCells = (
    line: string
  ): { cells: string[]; malformedError?: string; encodingError?: boolean } => {
    const cells: string[] = [];
    let cur = '';
    let inQuotes = false;
    let malformedError: string | undefined;
    const encodingError = line.includes('\uFFFD');

    for (let i = 0; i < line.length; i++) {
      const ch = line[i];
      if (ch === '"') {
        if (inQuotes && line[i + 1] === '"') {
          cur += '"';
          i += 1;
        } else {
          inQuotes = !inQuotes;
        }
      } else if (ch === ',' && !inQuotes) {
        cells.push(cur.trim());
        cur = '';
      } else {
        cur += ch;
      }
    }
    if (inQuotes) {
      malformedError = 'Unclosed quotation mark in CSV row';
    }
    cells.push(cur.trim());
    return { cells, malformedError, encodingError };
  };

  const headerParsed = parseLineCells(lines[0]);
  const headers = headerParsed.cells.map((h, i) => h || `column_${i + 1}`);

  const rows: Array<{
    rowNumber: number;
    cells: string[];
    malformedError?: string;
    encodingError?: boolean;
  }> = [];

  for (let r = 1; r < lines.length; r++) {
    const parsed = parseLineCells(lines[r]);
    rows.push({
      rowNumber: r,
      cells: parsed.cells,
      malformedError: parsed.malformedError,
      encodingError: parsed.encodingError,
    });
  }

  return { headers, rows };
}

function isValidUrlSyntax(urlStr: string): boolean {
  if (!urlStr) return true;
  try {
    const parsed = new URL(urlStr);
    return parsed.protocol === 'http:' || parsed.protocol === 'https:';
  } catch {
    return false;
  }
}

function normalizeDuplicateSignature(title: string, username: string, url: string): string {
  return `${title.trim().toLowerCase()}|${username.trim().toLowerCase()}|${url
    .trim()
    .toLowerCase()
    .replace(/\/+$/, '')}`;
}

/**
 * Evaluates and validates parsed CSV rows using the active column mappings and existing vault items.
 */
export function evaluateCsvCandidates(params: {
  fileName: string;
  fileSizeBytes: number;
  headers: string[];
  rawRows: Array<{
    rowNumber: number;
    cells: string[];
    malformedError?: string;
    encodingError?: boolean;
  }>;
  mappings: CsvColumnMapping[];
  existingVaultItems: DecryptedVaultItem[];
}): CsvImportAnalysisSession {
  const existingSignatures = new Map<string, string>();
  for (const item of params.existingVaultItems) {
    const sig = normalizeDuplicateSignature(
      item.data.title || '',
      item.data.username || item.data.email || '',
      item.data.url || ''
    );
    existingSignatures.set(sig, item.data.title);
  }

  const seenBatchSignatures = new Map<string, number>();
  const candidates: ParsedCsvRowCandidate[] = [];

  // Identify if any non-ignored critical fields are missing or uncertain
  const hasTitleMapping = params.mappings.some((m) => m.targetField === 'title');
  const hasUncertainMappings =
    !hasTitleMapping || params.mappings.some((m) => m.confidence === 'uncertain');

  for (const raw of params.rawRows) {
    const mapped = {
      title: '',
      username: '',
      password: '',
      url: '',
      noteContent: '',
      folder: 'Imported',
      favorite: false,
      totpSecret: '',
      rawType: 'password',
    };

    for (const mapping of params.mappings) {
      if (mapping.targetField === 'ignore') continue;
      const cellVal = (raw.cells[mapping.columnIndex] ?? '').trim();
      if (!cellVal) continue;

      switch (mapping.targetField) {
        case 'title':
          mapped.title = cellVal;
          break;
        case 'username':
          mapped.username = cellVal;
          break;
        case 'password':
          mapped.password = cellVal;
          break;
        case 'url':
          mapped.url = cellVal;
          break;
        case 'noteContent':
          mapped.noteContent = cellVal;
          break;
        case 'folder':
          mapped.folder = cellVal;
          break;
        case 'favorite':
          mapped.favorite = ['true', '1', 'yes', 'y'].includes(cellVal.toLowerCase());
          break;
        case 'totpSecret':
          mapped.totpSecret = cellVal;
          break;
        case 'recordType':
          mapped.rawType = cellVal.toLowerCase();
          break;
      }
    }

    const reasons: string[] = [];
    let status: CsvRowStatus = 'valid';
    let resolvedRecordType: VaultRecordType = 'password';
    let duplicateOfTitle: string | undefined;

    // 1. Check empty row
    const isCompletelyEmpty = raw.cells.every((c) => c.trim().length === 0);
    if (isCompletelyEmpty) {
      status = 'invalid';
      reasons.push('Empty CSV row');
    }

    // 2. Check malformed CSV quotes or column count mismatch
    if (raw.malformedError) {
      status = 'invalid';
      reasons.push(raw.malformedError);
    }
    if (raw.cells.length !== params.headers.length && !isCompletelyEmpty) {
      status = 'invalid';
      reasons.push(
        `Malformed CSV row: expected ${params.headers.length} columns, found ${raw.cells.length}`
      );
    }

    // 3. Check UTF-8 encoding error
    if (raw.encodingError) {
      status = 'invalid';
      reasons.push('Encoding issue detected (UTF-8 replacement character \\uFFFD)');
    }

    // 4. Check supported recordType
    const normalizedType = mapped.rawType.trim().toLowerCase();
    if (['password', 'login', 'credential', ''].includes(normalizedType)) {
      resolvedRecordType = 'password';
    } else if (['note', 'secure_note', 'secure note'].includes(normalizedType)) {
      resolvedRecordType = 'note';
    } else if (['identity', 'person'].includes(normalizedType)) {
      resolvedRecordType = 'identity';
    } else if (['card', 'credit_card', 'payment_card'].includes(normalizedType)) {
      resolvedRecordType = 'card';
    } else if (['custom'].includes(normalizedType)) {
      resolvedRecordType = 'custom';
    } else {
      status = 'unsupported';
      reasons.push(`Unsupported record type "${mapped.rawType}"`);
    }

    // 5. Required fields check
    if (status === 'valid') {
      if (!mapped.title) {
        status = 'invalid';
        reasons.push('Missing required field: Title / Name');
      }
      if (
        resolvedRecordType === 'password' &&
        !mapped.password &&
        !mapped.username &&
        !mapped.noteContent
      ) {
        status = 'invalid';
        reasons.push('Password record is missing password, username, and notes');
      }
    }

    // 6. Malformed URL validation
    if (status === 'valid' && mapped.url && !isValidUrlSyntax(mapped.url)) {
      status = 'invalid';
      reasons.push(`Malformed URL "${mapped.url}" (must use http:// or https://)`);
    }

    // 7. Duplicate detection (against existing vault AND earlier rows in this CSV)
    if (status === 'valid') {
      const sig = normalizeDuplicateSignature(mapped.title, mapped.username, mapped.url);
      const existingMatch = existingSignatures.get(sig);
      const batchMatchRow = seenBatchSignatures.get(sig);

      if (existingMatch) {
        status = 'duplicate';
        duplicateOfTitle = existingMatch;
        reasons.push(`Matches existing vault item "${existingMatch}"`);
      } else if (batchMatchRow !== undefined) {
        status = 'duplicate';
        duplicateOfTitle = `CSV Row #${batchMatchRow}`;
        reasons.push(`Duplicate of earlier CSV Row #${batchMatchRow}`);
      } else {
        seenBatchSignatures.set(sig, raw.rowNumber);
      }
    }

    candidates.push({
      rowNumber: raw.rowNumber,
      rawColumnCount: raw.cells.length,
      expectedColumnCount: params.headers.length,
      malformedQuoteError: raw.malformedError,
      encodingError: raw.encodingError,
      mapped,
      resolvedRecordType,
      status,
      reasons,
      duplicateOfTitle,
      selectedForReviewImport: false,
    });
  }

  const summary = {
    totalRecords: candidates.length,
    validRecords: candidates.filter((c) => c.status === 'valid').length,
    invalidRecords: candidates.filter((c) => c.status === 'invalid').length,
    duplicateRecords: candidates.filter((c) => c.status === 'duplicate').length,
    unsupportedRecords: candidates.filter((c) => c.status === 'unsupported').length,
  };

  return {
    fileName: params.fileName,
    fileSizeBytes: params.fileSizeBytes,
    headers: params.headers,
    mappings: params.mappings,
    hasUncertainMappings,
    rawRows: params.rawRows,
    candidates,
    summary,
    cleared: false,
  };
}

/**
 * Masks any sensitive string for safe UI preview (never displays raw password by default).
 */
export function maskSensitivePreviewValue(value: string): string {
  if (!value) return '—';
  return '••••••••••••';
}

/**
 * Immediately wipes all temporary plaintext CSV rows, mapped candidate secrets, and byte buffers
 * from the CsvImportAnalysisSession in memory.
 */
export function clearCsvImportSessionBuffer(session: CsvImportAnalysisSession | null | undefined): boolean {
  if (!session) return true;
  if (session.rawBufferRef) {
    zeroizeBuffer(session.rawBufferRef);
  }
  for (const rawRow of session.rawRows) {
    for (let i = 0; i < rawRow.cells.length; i++) {
      rawRow.cells[i] = '';
    }
    rawRow.cells.length = 0;
  }
  session.rawRows.length = 0;

  for (const candidate of session.candidates) {
    candidate.mapped.title = '';
    candidate.mapped.username = '';
    candidate.mapped.password = '';
    candidate.mapped.url = '';
    candidate.mapped.noteContent = '';
    candidate.mapped.totpSecret = '';
    candidate.reasons.length = 0;
  }
  session.candidates.length = 0;
  session.headers.length = 0;
  session.cleared = true;
  return true;
}

/**
 * Encrypts accepted CSV records one by one using fresh per-item AES-256-GCM keys and fresh 96-bit nonces,
 * binds canonical AAD, verifies zero plaintext leakage, and wipes temporary session state.
 */
export async function encryptAndImportCsvBatch(params: {
  keyring: ActiveVaultKeyring;
  session: CsvImportAnalysisSession;
  duplicatePolicy: DuplicateHandlingPolicy;
}): Promise<CsvImportExecutionReport> {
  if (!params.keyring || params.keyring.vaultKeyBytes.every((b) => b === 0)) {
    throw new SecurityAbortError('IMPORT_VAULT_LOCKED', 'Cannot import CSV while Vault Keyring is locked.');
  }

  const encryptedEnvelopes: EncryptedVaultItemEnvelope[] = [];
  let importedCount = 0;
  let skippedCount = 0;
  let failedCount = 0;

  try {
    for (const candidate of params.session.candidates) {
      if (candidate.status === 'invalid' || candidate.status === 'unsupported') {
        failedCount += 1;
        continue;
      }

      if (candidate.status === 'duplicate') {
        const shouldImportDuplicate =
          params.duplicatePolicy === 'import_as_new' ||
          (params.duplicatePolicy === 'review' && candidate.selectedForReviewImport);

        if (!shouldImportDuplicate) {
          skippedCount += 1;
          continue;
        }
      }

      const payload: DecryptedVaultItemPayload = {
        title: candidate.mapped.title,
        subtitle:
          candidate.mapped.username ||
          candidate.mapped.url ||
          'Imported Record',
        folder: candidate.mapped.folder || 'Imported',
        username: candidate.mapped.username || undefined,
        password: candidate.mapped.password || undefined,
        url: candidate.mapped.url || undefined,
        totpSecret: candidate.mapped.totpSecret || undefined,
        noteContent: candidate.mapped.noteContent || undefined,
      };

      // Encrypt immediately with a fresh 256-bit Item Encryption Key, fresh 96-bit nonce, and canonical AAD
      const envelope = await encryptVaultItem({
        keyring: params.keyring,
        recordType: candidate.resolvedRecordType,
        favorite: candidate.mapped.favorite,
        payload,
      });

      // Verify zero plaintext leaked into the encrypted envelope
      const check = inspectStorageForPlaintextLeakage(JSON.stringify(envelope), [
        candidate.mapped.password,
        candidate.mapped.totpSecret,
      ]);
      if (!check.passed) {
        throw new SecurityAbortError(
          'IMPORT_PLAINTEXT_LEAK_ABORT',
          'Critical Security Abort: Plaintext detected in encrypted import envelope'
        );
      }

      // Immediately clear plaintext fields on this candidate right after encryption
      candidate.mapped.password = '';
      candidate.mapped.totpSecret = '';
      candidate.mapped.noteContent = '';
      candidate.mapped.username = '';

      encryptedEnvelopes.push(envelope);
      importedCount += 1;
    }

    return {
      status: 'Import Complete',
      importedCount,
      skippedCount,
      failedCount,
      encryptedEnvelopes,
      localOnlyVerified: true,
      temporaryStateCleared: clearCsvImportSessionBuffer(params.session),
    };
  } catch (err) {
    // Fail-closed: always wipe temporary plaintext state even if an error aborts import
    clearCsvImportSessionBuffer(params.session);
    throw err;
  }
}
