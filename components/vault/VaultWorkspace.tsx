'use client';

import React, { useState, useMemo, useEffect, useRef } from 'react';
import {
  Search,
  Plus,
  Star,
  Key,
  FileText,
  UserCheck,
  CreditCard,
  Sliders,
  Copy,
  Check,
  Eye,
  EyeOff,
  Trash2,
  Edit3,
  ExternalLink,
  Code2,
  X,
  Sparkles,
  FileSpreadsheet,
  ShieldAlert,
} from 'lucide-react';
import type {
  DecryptedVaultItem,
  DecryptedVaultItemPayload,
  EncryptedVaultItemEnvelope,
  VaultRecordType,
} from '@/lib/crypto/vault-crypto';
import { generateSecurePassword } from '@/lib/crypto/password-generator';
import {
  type ScreenExposureState,
  canRenderSensitiveContent,
} from '@/lib/security/screen-exposure-engine';

interface VaultWorkspaceProps {
  items: DecryptedVaultItem[];
  rawEnvelopes: EncryptedVaultItemEnvelope[];
  developerMode: boolean;
  screenExposureState: ScreenExposureState;
  onVerifySafeBeforeSecretReveal: () => boolean;
  onAddOrUpdateItem: (params: {
    itemId?: string;
    recordType: VaultRecordType;
    favorite: boolean;
    payload: DecryptedVaultItemPayload;
  }) => Promise<void>;
  onDeleteItem: (itemId: string) => Promise<void>;
  onToggleFavorite: (item: DecryptedVaultItem) => Promise<void>;
  onCopySecretWithGuard: (label: string, value: string) => void;
  onOpenCsvImport: () => void;
}

const RECORD_TYPE_LABELS: Record<VaultRecordType, string> = {
  password: 'Password',
  note: 'Secure Note',
  identity: 'Identity',
  card: 'Credit Card',
  custom: 'Custom Item',
};

export default function VaultWorkspace({
  items,
  rawEnvelopes,
  developerMode,
  screenExposureState,
  onVerifySafeBeforeSecretReveal,
  onAddOrUpdateItem,
  onDeleteItem,
  onToggleFavorite,
  onCopySecretWithGuard,
  onOpenCsvImport,
}: VaultWorkspaceProps) {
  const [searchQuery, setSearchQuery] = useState('');
  const [categoryFilter, setCategoryFilter] = useState<'all' | 'favorites' | VaultRecordType>('all');
  const [selectedItemId, setSelectedItemId] = useState<string | null>(
    items.length > 0 ? items[0].itemId : null
  );
  const [revealedFields, setRevealedFields] = useState<Record<string, boolean>>({});
  const [revealBlockedNotice, setRevealBlockedNotice] = useState<string | null>(null);
  const [copiedFieldKey, setCopiedFieldKey] = useState<string | null>(null);
  const [showEnvelopeDetails, setShowEnvelopeDetails] = useState(false);
  const revealTimersRef = useRef<Record<string, number>>({});

  // Modal state for Add / Edit
  const [isEditorOpen, setIsEditorOpen] = useState(false);
  const [editingItemId, setEditingItemId] = useState<string | undefined>(undefined);
  const [formType, setFormType] = useState<VaultRecordType>('password');
  const [formFavorite, setFormFavorite] = useState(false);
  const [formTitle, setFormTitle] = useState('');
  const [formFolder, setFormFolder] = useState('General');
  const [formUsername, setFormUsername] = useState('');
  const [formPassword, setFormPassword] = useState('');
  const [formUrl, setFormUrl] = useState('');
  const [formTotp, setFormTotp] = useState('');
  const [formNote, setFormNote] = useState('');
  const [formFullName, setFormFullName] = useState('');
  const [formEmail, setFormEmail] = useState('');
  const [formPhone, setFormPhone] = useState('');
  const [formPassport, setFormPassport] = useState('');
  const [formAddress, setFormAddress] = useState('');
  const [formCardholder, setFormCardholder] = useState('');
  const [formCardNumber, setFormCardNumber] = useState('');
  const [formCardExpiry, setFormCardExpiry] = useState('');
  const [formCardCvv, setFormCardCvv] = useState('');
  const [formCardPin, setFormCardPin] = useState('');
  const [formCustomFields, setFormCustomFields] = useState<
    Array<{ label: string; value: string; sensitive: boolean }>
  >([
    { label: 'Key Identifier', value: '', sensitive: false },
    { label: 'Private Secret', value: '', sensitive: true },
  ]);
  const [formError, setFormError] = useState<string | null>(null);
  const [isSaving, setIsSaving] = useState(false);

  const filteredItems = useMemo(() => {
    return items.filter((item) => {
      if (categoryFilter === 'favorites' && !item.favorite) return false;
      if (
        categoryFilter !== 'all' &&
        categoryFilter !== 'favorites' &&
        item.recordType !== categoryFilter
      ) {
        return false;
      }
      if (!searchQuery.trim()) return true;
      const q = searchQuery.toLowerCase();
      const titleMatch = item.data.title.toLowerCase().includes(q);
      const folderMatch = (item.data.folder || '').toLowerCase().includes(q);
      const subMatch = (item.data.subtitle || item.data.username || item.data.email || '')
        .toLowerCase()
        .includes(q);
      return titleMatch || folderMatch || subMatch;
    });
  }, [items, categoryFilter, searchQuery]);

  const selectedItem = useMemo(() => {
    return (
      filteredItems.find((i) => i.itemId === selectedItemId) ||
      items.find((i) => i.itemId === selectedItemId) ||
      filteredItems[0] ||
      null
    );
  }, [filteredItems, items, selectedItemId]);

  const selectedRawEnvelope = useMemo(() => {
    if (!selectedItem) return null;
    return rawEnvelopes.find((e) => e.itemId === selectedItem.itemId) || null;
  }, [rawEnvelopes, selectedItem]);

  // Immediately re-mask all revealed fields on window blur or visibility hidden (Section 8 & 9)
  useEffect(() => {
    const clearAllRevealed = () => {
      Object.values(revealTimersRef.current).forEach((tId) => window.clearTimeout(tId));
      revealTimersRef.current = {};
      setRevealedFields({});
    };

    const onVisibility = () => {
      if (document.visibilityState === 'hidden') {
        clearAllRevealed();
      }
    };

    window.addEventListener('blur', clearAllRevealed);
    document.addEventListener('visibilitychange', onVisibility);
    return () => {
      window.removeEventListener('blur', clearAllRevealed);
      document.removeEventListener('visibilitychange', onVisibility);
      Object.values(revealTimersRef.current).forEach((tId) => window.clearTimeout(tId));
    };
  }, []);

  const isPrivateSafe = canRenderSensitiveContent(screenExposureState);

  const toggleReveal = (key: string) => {
    setRevealBlockedNotice(null);
    if (revealedFields[key]) {
      if (revealTimersRef.current[key]) {
        window.clearTimeout(revealTimersRef.current[key]);
        delete revealTimersRef.current[key];
      }
      setRevealedFields((prev) => ({ ...prev, [key]: false }));
      return;
    }

    // Pre-Render Race-Condition Protection (Sections 8, 9, 15):
    // Check security state BEFORE rendering sensitive content.
    const safe = onVerifySafeBeforeSecretReveal();
    if (!safe || !isPrivateSafe) {
      setRevealedFields({});
      setRevealBlockedNotice(
        'Secret reveal blocked by Screen Exposure Protection Engine: untrusted display or capture risk detected.'
      );
      return;
    }

    setRevealedFields((prev) => ({ ...prev, [key]: true }));
    if (revealTimersRef.current[key]) {
      window.clearTimeout(revealTimersRef.current[key]);
    }
    // 15-second auto-hide timer per Section 8
    revealTimersRef.current[key] = window.setTimeout(() => {
      setRevealedFields((prev) => ({ ...prev, [key]: false }));
      delete revealTimersRef.current[key];
    }, 15000);
  };

  const handleCopy = (fieldKey: string, label: string, value: string) => {
    if (!onVerifySafeBeforeSecretReveal() || !isPrivateSafe) {
      setRevealBlockedNotice(
        'Clipboard copy blocked by Screen Exposure Protection Engine.'
      );
      return;
    }
    onCopySecretWithGuard(label, value);
    setCopiedFieldKey(fieldKey);
    setTimeout(() => {
      setCopiedFieldKey((prev) => (prev === fieldKey ? null : prev));
    }, 1800);
  };

  const openNewItemModal = (defaultType: VaultRecordType = 'password') => {
    setEditingItemId(undefined);
    setFormType(defaultType);
    setFormFavorite(false);
    setFormTitle('');
    setFormFolder('General');
    setFormUsername('');
    setFormPassword('');
    setFormUrl('');
    setFormTotp('');
    setFormNote('');
    setFormFullName('');
    setFormEmail('');
    setFormPhone('');
    setFormPassport('');
    setFormAddress('');
    setFormCardholder('');
    setFormCardNumber('');
    setFormCardExpiry('');
    setFormCardCvv('');
    setFormCardPin('');
    setFormCustomFields([
      { label: 'Endpoint / Host', value: '', sensitive: false },
      { label: 'Secret Key', value: '', sensitive: true },
    ]);
    setFormError(null);
    setIsEditorOpen(true);
  };

  const openEditItemModal = (item: DecryptedVaultItem) => {
    setEditingItemId(item.itemId);
    setFormType(item.recordType);
    setFormFavorite(item.favorite);
    setFormTitle(item.data.title || '');
    setFormFolder(item.data.folder || 'General');
    setFormUsername(item.data.username || '');
    setFormPassword(item.data.password || '');
    setFormUrl(item.data.url || '');
    setFormTotp(item.data.totpSecret || '');
    setFormNote(item.data.noteContent || '');
    setFormFullName(item.data.fullName || '');
    setFormEmail(item.data.email || '');
    setFormPhone(item.data.phone || '');
    setFormPassport(item.data.passportOrIdNumber || '');
    setFormAddress(item.data.address || '');
    setFormCardholder(item.data.cardholderName || '');
    setFormCardNumber(item.data.cardNumber || '');
    setFormCardExpiry(item.data.cardExpiry || '');
    setFormCardCvv(item.data.cardCvv || '');
    setFormCardPin(item.data.cardPin || '');
    setFormCustomFields(
      item.data.customFields && item.data.customFields.length > 0
        ? item.data.customFields
        : [{ label: 'Field 1', value: '', sensitive: true }]
    );
    setFormError(null);
    setIsEditorOpen(true);
  };

  const handleSaveItem = async (e: React.FormEvent) => {
    e.preventDefault();
    setFormError(null);
    if (!formTitle.trim()) {
      setFormError('Item title is required.');
      return;
    }

    const subtitle =
      formType === 'password'
        ? formUsername || formUrl || 'Login Credential'
        : formType === 'identity'
        ? formFullName || formEmail || 'Personal Identity'
        : formType === 'card'
        ? `•••• ${formCardNumber.replace(/\s+/g, '').slice(-4) || 'XXXX'}`
        : formFolder;

    const payload: DecryptedVaultItemPayload = {
      title: formTitle.trim(),
      subtitle,
      folder: formFolder.trim() || 'General',
      username: formUsername.trim() || undefined,
      password: formPassword || undefined,
      url: formUrl.trim() || undefined,
      totpSecret: formTotp.trim() || undefined,
      noteContent: formNote.trim() || undefined,
      fullName: formFullName.trim() || undefined,
      email: formEmail.trim() || undefined,
      phone: formPhone.trim() || undefined,
      passportOrIdNumber: formPassport.trim() || undefined,
      address: formAddress.trim() || undefined,
      cardholderName: formCardholder.trim() || undefined,
      cardNumber: formCardNumber.trim() || undefined,
      cardExpiry: formCardExpiry.trim() || undefined,
      cardCvv: formCardCvv.trim() || undefined,
      cardPin: formCardPin.trim() || undefined,
      customFields:
        formType === 'custom'
          ? formCustomFields.filter((f) => f.label.trim().length > 0)
          : undefined,
    };

    setIsSaving(true);
    try {
      await onAddOrUpdateItem({
        itemId: editingItemId,
        recordType: formType,
        favorite: formFavorite,
        payload,
      });
      setIsEditorOpen(false);
    } catch (err) {
      setFormError(err instanceof Error ? err.message : 'Encryption failed');
    } finally {
      setIsSaving(false);
    }
  };

  const getRecordIcon = (type: VaultRecordType) => {
    switch (type) {
      case 'password':
        return <Key className="w-4 h-4 text-[#00FF66] shrink-0" />;
      case 'note':
        return <FileText className="w-4 h-4 text-[#00FF66] shrink-0" />;
      case 'identity':
        return <UserCheck className="w-4 h-4 text-amber-400 shrink-0" />;
      case 'card':
        return <CreditCard className="w-4 h-4 text-purple-400 shrink-0" />;
      case 'custom':
        return <Sliders className="w-4 h-4 text-rose-400 shrink-0" />;
    }
  };

  return (
    <div className="space-y-6">
      {/* Workspace Toolbar: Search, Category Filters, New Item Button */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-4 border-b border-slate-800/80">
        {/* Search Input */}
        <div className="relative flex-1 max-w-md">
          <Search className="w-4 h-4 text-slate-500 absolute left-3.5 top-1/2 -translate-y-1/2" />
          <input
            type="search"
            aria-label="Search decrypted vault items"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search titles, usernames, folders..."
            className="w-full pl-10 pr-4 py-2 text-sm bg-[#0B0E11] border border-slate-800 rounded-lg text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-[#00FF66]"
          />
        </div>

        {/* Interactive Category Segmented Filter Bar */}
        <div className="flex items-center gap-1 p-1 bg-[#0B0E11] border border-slate-800 rounded-lg overflow-x-auto">
          {(
            [
              { id: 'all', label: `All (${items.length})` },
              { id: 'favorites', label: 'Favorites' },
              { id: 'password', label: 'Passwords' },
              { id: 'note', label: 'Notes' },
              { id: 'identity', label: 'Identities' },
              { id: 'card', label: 'Cards' },
              { id: 'custom', label: 'Custom' },
            ] as const
          ).map((tab) => (
            <button
              key={tab.id}
              type="button"
              onClick={() => setCategoryFilter(tab.id)}
              className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 ${
                categoryFilter === tab.id
                  ? 'bg-slate-800 text-white'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>

        <div className="flex items-center gap-2 shrink-0 self-start lg:self-auto">
          <button
            type="button"
            onClick={onOpenCsvImport}
            className="px-3.5 py-2 bg-[#0B0E11] hover:bg-slate-800 text-slate-200 border border-slate-800 font-medium text-xs rounded-lg transition-colors flex items-center gap-1.5 whitespace-nowrap shrink-0"
          >
            <FileSpreadsheet className="w-4 h-4 text-[#00FF66]" />
            <span>Import CSV</span>
          </button>

          <button
            type="button"
            onClick={() => openNewItemModal('password')}
            className="px-4 py-2 bg-[#00FF66] hover:bg-[#22FF7A] text-slate-950 font-semibold text-xs rounded-lg transition-colors flex items-center gap-2 whitespace-nowrap shrink-0"
          >
            <Plus className="w-4 h-4" />
            <span>New Vault Item</span>
          </button>
        </div>
      </div>

      {/* Two-Column Vault Master-Detail Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Left List Column (5 cols) */}
        <div className="lg:col-span-5 bg-[#0B0E11] border border-slate-800 rounded-xl divide-y divide-slate-800/80 overflow-hidden">
          {filteredItems.length === 0 ? (
            <div className="p-8 text-center space-y-3">
              <p className="text-sm font-medium text-slate-300">No matching vault items</p>
              <p className="text-xs text-slate-500">
                Try clearing your search filter or encrypt a new record into your vault.
              </p>
              <button
                type="button"
                onClick={() => openNewItemModal('password')}
                className="px-3.5 py-2 bg-slate-800 hover:bg-slate-700 text-xs font-medium text-white rounded-lg transition-colors inline-flex items-center gap-1.5"
              >
                <Plus className="w-3.5 h-3.5" />
                <span>Add First Item</span>
              </button>
            </div>
          ) : (
            filteredItems.map((item) => {
              const isSelected = selectedItem?.itemId === item.itemId;
              return (
                <div
                  key={item.itemId}
                  className={`flex items-center justify-between gap-3 px-4 py-3.5 transition-colors ${
                    isSelected ? 'bg-slate-800/70' : 'hover:bg-slate-900/60'
                  }`}
                >
                  <button
                    type="button"
                    onClick={() => setSelectedItemId(item.itemId)}
                    className="flex items-start gap-3 text-left flex-1 min-w-0"
                  >
                    <div className="mt-0.5">{getRecordIcon(item.recordType)}</div>
                    <div className="min-w-0 flex-1">
                      <div className="text-sm font-medium text-slate-100 truncate">
                        {item.data.title}
                      </div>
                      {/* Zero-Pill Metadata Discipline: Clean unboxed text with · separators */}
                      <div className="flex items-center gap-1.5 text-xs text-slate-400 truncate mt-0.5">
                        <span className="truncate">
                          {item.data.subtitle || RECORD_TYPE_LABELS[item.recordType]}
                        </span>
                        <span aria-hidden="true">·</span>
                        <span className="shrink-0">{item.data.folder || 'General'}</span>
                        <span aria-hidden="true">·</span>
                        <span className="font-mono tabular-nums shrink-0">v{item.revision}</span>
                      </div>
                    </div>
                  </button>

                  <button
                    type="button"
                    aria-label={
                      item.favorite
                        ? `Remove ${item.data.title} from favorites`
                        : `Favorite ${item.data.title}`
                    }
                    onClick={() => onToggleFavorite(item)}
                    className="p-1.5 text-slate-500 hover:text-amber-400 transition-colors shrink-0"
                  >
                    <Star
                      className={`w-4 h-4 ${
                        item.favorite ? 'fill-amber-400 text-amber-400' : ''
                      }`}
                    />
                  </button>
                </div>
              );
            })
          )}
        </div>

        {/* Right Detail Inspector Column (7 cols) */}
        <div className="lg:col-span-7 bg-[#0B0E11] border border-slate-800 rounded-xl p-6 space-y-6">
          {!selectedItem ? (
            <div className="py-16 text-center text-sm text-slate-500">
              Select an item from your vault to decrypt and inspect its fields.
            </div>
          ) : (
            <>
              {/* Item Header */}
              <div className="flex flex-wrap items-start justify-between gap-4 pb-5 border-b border-slate-800">
                <div className="space-y-1">
                  <div className="flex items-center gap-2 text-xs text-slate-400">
                    {getRecordIcon(selectedItem.recordType)}
                    <span>{RECORD_TYPE_LABELS[selectedItem.recordType]}</span>
                    <span aria-hidden="true">·</span>
                    <span>{selectedItem.data.folder || 'General'}</span>
                    <span aria-hidden="true">·</span>
                    <span className="font-mono tabular-nums">Revision {selectedItem.revision}</span>
                  </div>
                  <h2
                    className="text-xl font-bold text-white"
                    style={{ fontFamily: 'var(--font-display)' }}
                  >
                    {selectedItem.data.title}
                  </h2>
                </div>

                <div className="flex items-center gap-2 shrink-0">
                  <button
                    type="button"
                    onClick={() => openEditItemModal(selectedItem)}
                    className="px-3 py-1.5 text-xs font-medium text-slate-200 bg-slate-800 hover:bg-slate-700 rounded-lg transition-colors flex items-center gap-1.5 whitespace-nowrap"
                  >
                    <Edit3 className="w-3.5 h-3.5" />
                    <span>Edit</span>
                  </button>
                  <button
                    type="button"
                    aria-label={`Delete ${selectedItem.data.title}`}
                    onClick={() => onDeleteItem(selectedItem.itemId)}
                    className="px-3 py-1.5 text-xs font-medium text-rose-300 bg-rose-950/50 hover:bg-rose-900/60 border border-rose-800/60 rounded-lg transition-colors flex items-center gap-1.5 whitespace-nowrap"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                    <span>Delete</span>
                  </button>
                </div>
              </div>

              {/* Type-Specific Decrypted Fields */}
              <div className="space-y-4">
                {selectedItem.data.username && (
                  <div className="flex items-center justify-between gap-4 py-2.5 border-b border-slate-800/60">
                    <div className="min-w-0">
                      <div className="text-xs text-slate-400">Username / Identifier</div>
                      <div className="text-sm font-mono text-slate-100 mt-0.5 break-all">
                        {selectedItem.data.username}
                      </div>
                    </div>
                    <button
                      type="button"
                      onClick={() =>
                        handleCopy(
                          `${selectedItem.itemId}-user`,
                          'Username',
                          selectedItem.data.username!
                        )
                      }
                      className="px-3 py-1.5 text-xs font-medium text-slate-300 hover:text-white bg-slate-900 hover:bg-slate-800 border border-slate-800 rounded-lg transition-colors flex items-center gap-1.5 shrink-0"
                    >
                      {copiedFieldKey === `${selectedItem.itemId}-user` ? (
                        <>
                          <Check className="w-3.5 h-3.5 text-[#00FF66]" />
                          <span>Copied</span>
                        </>
                      ) : (
                        <>
                          <Copy className="w-3.5 h-3.5" />
                          <span>Copy</span>
                        </>
                      )}
                    </button>
                  </div>
                )}

                {selectedItem.data.password && (
                  <div className="flex items-center justify-between gap-4 py-2.5 border-b border-slate-800/60">
                    <div className="min-w-0">
                      <div className="text-xs text-slate-400">Password</div>
                      <div className="text-sm font-mono text-slate-100 mt-0.5 break-all">
                        {revealedFields[`${selectedItem.itemId}-pass`]
                          ? selectedItem.data.password
                          : '••••••••••••••••••••••••'}
                      </div>
                    </div>
                    <div className="flex items-center gap-2 shrink-0">
                      <button
                        type="button"
                        aria-label={
                          revealedFields[`${selectedItem.itemId}-pass`]
                            ? 'Hide password'
                            : 'Reveal password'
                        }
                        onClick={() => toggleReveal(`${selectedItem.itemId}-pass`)}
                        className="p-1.5 text-slate-400 hover:text-white bg-slate-900 border border-slate-800 rounded-lg"
                      >
                        {revealedFields[`${selectedItem.itemId}-pass`] ? (
                          <EyeOff className="w-4 h-4" />
                        ) : (
                          <Eye className="w-4 h-4" />
                        )}
                      </button>
                      <button
                        type="button"
                        onClick={() =>
                          handleCopy(
                            `${selectedItem.itemId}-pass`,
                            'Password',
                            selectedItem.data.password!
                          )
                        }
                        className="px-3 py-1.5 text-xs font-medium text-slate-950 bg-[#00FF66] hover:bg-[#22FF7A] rounded-lg transition-colors flex items-center gap-1.5 whitespace-nowrap"
                      >
                        {copiedFieldKey === `${selectedItem.itemId}-pass` ? (
                          <>
                            <Check className="w-3.5 h-3.5" />
                            <span>Copied</span>
                          </>
                        ) : (
                          <>
                            <Copy className="w-3.5 h-3.5" />
                            <span>Copy Password</span>
                          </>
                        )}
                      </button>
                    </div>
                  </div>
                )}

                {selectedItem.data.totpSecret && (
                  <div className="flex items-center justify-between gap-4 py-2.5 border-b border-slate-800/60">
                    <div className="min-w-0">
                      <div className="text-xs text-slate-400">Authenticator Seed (TOTP)</div>
                      <div className="text-sm font-mono text-slate-100 mt-0.5">
                        {revealedFields[`${selectedItem.itemId}-totp`]
                          ? selectedItem.data.totpSecret
                          : '•••• •••• •••• ••••'}
                      </div>
                    </div>
                    <div className="flex items-center gap-2 shrink-0">
                      <button
                        type="button"
                        aria-label="Toggle TOTP Seed visibility"
                        onClick={() => toggleReveal(`${selectedItem.itemId}-totp`)}
                        className="p-1.5 text-slate-400 hover:text-white bg-slate-900 border border-slate-800 rounded-lg"
                      >
                        {revealedFields[`${selectedItem.itemId}-totp`] ? (
                          <EyeOff className="w-4 h-4" />
                        ) : (
                          <Eye className="w-4 h-4" />
                        )}
                      </button>
                      <button
                        type="button"
                        onClick={() =>
                          handleCopy(
                            `${selectedItem.itemId}-totp`,
                            'TOTP Secret',
                            selectedItem.data.totpSecret!
                          )
                        }
                        className="px-3 py-1.5 text-xs font-medium text-slate-300 hover:text-white bg-slate-900 border border-slate-800 rounded-lg flex items-center gap-1.5"
                      >
                        <Copy className="w-3.5 h-3.5" />
                        <span>Copy Seed</span>
                      </button>
                    </div>
                  </div>
                )}

                {selectedItem.data.url && (
                  <div className="flex items-center justify-between gap-4 py-2.5 border-b border-slate-800/60">
                    <div className="min-w-0">
                      <div className="text-xs text-slate-400">Service URI</div>
                      <div className="text-sm text-[#00FF66] truncate mt-0.5">
                        {selectedItem.data.url}
                      </div>
                    </div>
                    <a
                      href={selectedItem.data.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="px-3 py-1.5 text-xs font-medium text-slate-300 hover:text-white bg-slate-900 border border-slate-800 rounded-lg flex items-center gap-1.5 shrink-0"
                    >
                      <span>Open</span>
                      <ExternalLink className="w-3.5 h-3.5" />
                    </a>
                  </div>
                )}

                {/* Identity Fields with Screen Exposure Reveal Protection (Section 9) */}
                {selectedItem.recordType === 'identity' && (
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 py-2 border-b border-slate-800/60">
                    {selectedItem.data.fullName && (
                      <div>
                        <div className="text-xs text-slate-400">Full Legal Name</div>
                        <div className="text-sm text-slate-100 mt-0.5">
                          {selectedItem.data.fullName}
                        </div>
                      </div>
                    )}
                    {selectedItem.data.passportOrIdNumber && (
                      <div className="flex items-center justify-between gap-2">
                        <div>
                          <div className="text-xs text-slate-400">Passport / National ID</div>
                          <div className="text-sm font-mono text-slate-100 mt-0.5">
                            {isPrivateSafe && revealedFields[`${selectedItem.itemId}-idnum`]
                              ? selectedItem.data.passportOrIdNumber
                              : '••••••••••••'}
                          </div>
                        </div>
                        <button
                          type="button"
                          aria-label="Toggle Passport or ID visibility"
                          onClick={() => toggleReveal(`${selectedItem.itemId}-idnum`)}
                          className="p-1.5 text-slate-400 hover:text-white bg-slate-900 border border-slate-800 rounded-lg"
                        >
                          {isPrivateSafe && revealedFields[`${selectedItem.itemId}-idnum`] ? (
                            <EyeOff className="w-4 h-4" />
                          ) : (
                            <Eye className="w-4 h-4" />
                          )}
                        </button>
                      </div>
                    )}
                    {selectedItem.data.email && (
                      <div className="flex items-center justify-between gap-2">
                        <div className="min-w-0">
                          <div className="text-xs text-slate-400">Email</div>
                          <div className="text-sm text-slate-100 mt-0.5 truncate">
                            {isPrivateSafe && revealedFields[`${selectedItem.itemId}-email`]
                              ? selectedItem.data.email
                              : '••••••@••••••••'}
                          </div>
                        </div>
                        <button
                          type="button"
                          aria-label="Toggle Email visibility"
                          onClick={() => toggleReveal(`${selectedItem.itemId}-email`)}
                          className="p-1.5 text-slate-400 hover:text-white bg-slate-900 border border-slate-800 rounded-lg shrink-0"
                        >
                          {isPrivateSafe && revealedFields[`${selectedItem.itemId}-email`] ? (
                            <EyeOff className="w-4 h-4" />
                          ) : (
                            <Eye className="w-4 h-4" />
                          )}
                        </button>
                      </div>
                    )}
                    {selectedItem.data.phone && (
                      <div className="flex items-center justify-between gap-2">
                        <div>
                          <div className="text-xs text-slate-400">Phone</div>
                          <div className="text-sm font-mono text-slate-100 mt-0.5">
                            {isPrivateSafe && revealedFields[`${selectedItem.itemId}-phone`]
                              ? selectedItem.data.phone
                              : '•••• ••• ••••'}
                          </div>
                        </div>
                        <button
                          type="button"
                          aria-label="Toggle Phone visibility"
                          onClick={() => toggleReveal(`${selectedItem.itemId}-phone`)}
                          className="p-1.5 text-slate-400 hover:text-white bg-slate-900 border border-slate-800 rounded-lg shrink-0"
                        >
                          {isPrivateSafe && revealedFields[`${selectedItem.itemId}-phone`] ? (
                            <EyeOff className="w-4 h-4" />
                          ) : (
                            <Eye className="w-4 h-4" />
                          )}
                        </button>
                      </div>
                    )}
                    {selectedItem.data.address && (
                      <div className="sm:col-span-2 flex items-center justify-between gap-2">
                        <div>
                          <div className="text-xs text-slate-400">Registered Address</div>
                          <div className="text-sm text-slate-100 mt-0.5">
                            {isPrivateSafe && revealedFields[`${selectedItem.itemId}-addr`]
                              ? selectedItem.data.address
                              : '••••••••••••••••••••••••••••••••'}
                          </div>
                        </div>
                        <button
                          type="button"
                          aria-label="Toggle Address visibility"
                          onClick={() => toggleReveal(`${selectedItem.itemId}-addr`)}
                          className="p-1.5 text-slate-400 hover:text-white bg-slate-900 border border-slate-800 rounded-lg shrink-0"
                        >
                          {isPrivateSafe && revealedFields[`${selectedItem.itemId}-addr`] ? (
                            <EyeOff className="w-4 h-4" />
                          ) : (
                            <Eye className="w-4 h-4" />
                          )}
                        </button>
                      </div>
                    )}
                  </div>
                )}

                {/* Credit Card Fields */}
                {selectedItem.recordType === 'card' && (
                  <div className="space-y-3 py-2 border-b border-slate-800/60">
                    <div className="flex items-center justify-between gap-4">
                      <div>
                        <div className="text-xs text-slate-400">Card Number (PAN)</div>
                        <div className="text-sm font-mono tabular-nums text-slate-100 mt-0.5">
                          {revealedFields[`${selectedItem.itemId}-pan`]
                            ? selectedItem.data.cardNumber
                            : `•••• •••• •••• ${(selectedItem.data.cardNumber || '').slice(-4)}`}
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        <button
                          type="button"
                          aria-label="Toggle Card Number visibility"
                          onClick={() => toggleReveal(`${selectedItem.itemId}-pan`)}
                          className="p-1.5 text-slate-400 hover:text-white bg-slate-900 border border-slate-800 rounded-lg"
                        >
                          {revealedFields[`${selectedItem.itemId}-pan`] ? (
                            <EyeOff className="w-4 h-4" />
                          ) : (
                            <Eye className="w-4 h-4" />
                          )}
                        </button>
                        {selectedItem.data.cardNumber && (
                          <button
                            type="button"
                            onClick={() =>
                              handleCopy(
                                `${selectedItem.itemId}-pan`,
                                'Card Number',
                                selectedItem.data.cardNumber!
                              )
                            }
                            className="px-3 py-1.5 text-xs font-medium text-slate-950 bg-[#00FF66] hover:bg-[#22FF7A] rounded-lg flex items-center gap-1.5"
                          >
                            <Copy className="w-3.5 h-3.5" />
                            <span>Copy Card</span>
                          </button>
                        )}
                      </div>
                    </div>

                    <div className="grid grid-cols-3 gap-4 pt-2">
                      <div>
                        <div className="text-xs text-slate-400">Cardholder</div>
                        <div className="text-sm text-slate-100 mt-0.5">
                          {selectedItem.data.cardholderName || '—'}
                        </div>
                      </div>
                      <div>
                        <div className="text-xs text-slate-400">Expiry</div>
                        <div className="text-sm font-mono tabular-nums text-slate-100 mt-0.5">
                          {selectedItem.data.cardExpiry || '—'}
                        </div>
                      </div>
                      <div>
                        <div className="text-xs text-slate-400">CVV / PIN</div>
                        <div className="flex items-center gap-2 mt-0.5">
                          <span className="text-sm font-mono tabular-nums text-slate-100">
                            {revealedFields[`${selectedItem.itemId}-cvv`]
                              ? `${selectedItem.data.cardCvv || '—'} / ${
                                  selectedItem.data.cardPin || '—'
                                }`
                              : '••• / ••••'}
                          </span>
                          <button
                            type="button"
                            aria-label="Toggle CVV visibility"
                            onClick={() => toggleReveal(`${selectedItem.itemId}-cvv`)}
                            className="text-xs text-[#00FF66] hover:underline"
                          >
                            {revealedFields[`${selectedItem.itemId}-cvv`] ? 'Hide' : 'Show'}
                          </button>
                        </div>
                      </div>
                    </div>
                  </div>
                )}

                {/* Custom Fields */}
                {selectedItem.data.customFields && selectedItem.data.customFields.length > 0 && (
                  <div className="space-y-3 py-2 border-b border-slate-800/60">
                    {selectedItem.data.customFields.map((cf, idx) => {
                      const fKey = `${selectedItem.itemId}-cf-${idx}`;
                      return (
                        <div key={fKey} className="flex items-center justify-between gap-4">
                          <div className="min-w-0">
                            <div className="text-xs text-slate-400">{cf.label}</div>
                            <div className="text-sm font-mono text-slate-100 mt-0.5 break-all">
                              {cf.sensitive && !revealedFields[fKey]
                                ? '••••••••••••••••••••••••'
                                : cf.value}
                            </div>
                          </div>
                          <div className="flex items-center gap-2 shrink-0">
                            {cf.sensitive && (
                              <button
                                type="button"
                                aria-label={`Toggle ${cf.label} visibility`}
                                onClick={() => toggleReveal(fKey)}
                                className="p-1.5 text-slate-400 hover:text-white bg-slate-900 border border-slate-800 rounded-lg"
                              >
                                {revealedFields[fKey] ? (
                                  <EyeOff className="w-4 h-4" />
                                ) : (
                                  <Eye className="w-4 h-4" />
                                )}
                              </button>
                            )}
                            <button
                              type="button"
                              onClick={() => handleCopy(fKey, cf.label, cf.value)}
                              className="px-3 py-1.5 text-xs font-medium text-slate-300 hover:text-white bg-slate-900 border border-slate-800 rounded-lg flex items-center gap-1.5"
                            >
                              <Copy className="w-3.5 h-3.5" />
                              <span>Copy</span>
                            </button>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}

                {/* Secure Note Content with Screen Exposure Protection (Section 9) */}
                {selectedItem.data.noteContent && (
                  <div className="space-y-1.5 pt-1">
                    <div className="flex items-center justify-between gap-2">
                      <div className="text-xs text-slate-400">
                        Encrypted Note (15s Auto-Mask Active)
                      </div>
                      <button
                        type="button"
                        aria-label="Toggle Private Note visibility"
                        onClick={() => toggleReveal(`${selectedItem.itemId}-note`)}
                        className="text-xs text-[#00FF66] hover:underline flex items-center gap-1"
                      >
                        {isPrivateSafe && revealedFields[`${selectedItem.itemId}-note`] ? (
                          <>
                            <EyeOff className="w-3.5 h-3.5" />
                            <span>Mask Note</span>
                          </>
                        ) : (
                          <>
                            <Eye className="w-3.5 h-3.5" />
                            <span>Reveal Note</span>
                          </>
                        )}
                      </button>
                    </div>
                    <div className="p-3.5 rounded-lg bg-slate-950 border border-slate-800/80 text-sm text-slate-200 whitespace-pre-wrap leading-relaxed font-mono">
                      {isPrivateSafe && revealedFields[`${selectedItem.itemId}-note`]
                        ? selectedItem.data.noteContent
                        : '••••••••••••••••••••••••••••••••••••••••••••••••••••••••••••'}
                    </div>
                  </div>
                )}

                {revealBlockedNotice && (
                  <div
                    role="alert"
                    className="p-3 rounded-lg bg-rose-950/60 border border-rose-800 text-xs text-rose-200 flex items-center gap-2"
                  >
                    <ShieldAlert className="w-4 h-4 text-rose-400 shrink-0" />
                    <span>{revealBlockedNotice}</span>
                  </div>
                )}
              </div>

              {/* Metadata Footer & Optional Developer Mode Envelope View */}
              <div className="pt-4 border-t border-slate-800/80 flex flex-wrap items-center justify-between gap-4 text-xs text-slate-500">
                <div className="flex items-center gap-2 font-mono tabular-nums">
                  <span>Updated {new Date(selectedItem.updatedAt).toLocaleString()}</span>
                  <span aria-hidden="true">·</span>
                  <span>AES-256-GCM Authenticated</span>
                </div>

                {developerMode && (
                  <button
                    type="button"
                    onClick={() => setShowEnvelopeDetails(!showEnvelopeDetails)}
                    className="text-xs text-[#00FF66] hover:underline flex items-center gap-1.5"
                  >
                    <Code2 className="w-3.5 h-3.5" />
                    <span>
                      {showEnvelopeDetails
                        ? 'Hide Cryptographic Envelope'
                        : 'Inspect Tier-4 Cryptographic Envelope'}
                    </span>
                  </button>
                )}
              </div>

              {developerMode && showEnvelopeDetails && selectedRawEnvelope && (
                <div className="p-4 rounded-lg bg-slate-950 border border-slate-800 space-y-2 text-xs font-mono text-slate-300">
                  <div className="text-[#00FF66] font-semibold">
                    Developer Diagnostics · Tier-4 Per-Item Cryptographic Envelope
                  </div>
                  <div>itemId: {selectedRawEnvelope.itemId}</div>
                  <div>itemKeyId: {selectedRawEnvelope.itemKeyId}</div>
                  <div>
                    wrappedItemKey.nonceHex (96-bit): {selectedRawEnvelope.wrappedItemKey.nonceHex}
                  </div>
                  <div>
                    encryptedPayload.nonceHex (96-bit):{' '}
                    {selectedRawEnvelope.encryptedPayload.nonceHex}
                  </div>
                  <div className="truncate">
                    ciphertextWithTagHex:{' '}
                    {selectedRawEnvelope.encryptedPayload.ciphertextWithTagHex.slice(0, 64)}...
                  </div>
                  <div className="text-slate-500">
                    Canonical AAD Bound: vaultId | itemId | revision={selectedRawEnvelope.revision}{' '}
                    | recordType={selectedRawEnvelope.recordType} | schemaVersion=1 | keyId=
                    {selectedRawEnvelope.itemKeyId}
                  </div>
                </div>
              )}
            </>
          )}
        </div>
      </div>

      {/* Add / Edit Item Dialog Modal */}
      {isEditorOpen && (
        <div
          role="dialog"
          aria-modal="true"
          aria-labelledby="item-modal-title"
          className="fixed inset-0 z-50 bg-black/75 flex items-center justify-center p-4 overflow-y-auto"
        >
          <div className="bg-[#0B0E11] border border-slate-800 rounded-xl max-w-lg w-full p-6 space-y-5 my-8">
            <div className="flex items-center justify-between gap-3 border-b border-slate-800 pb-4">
              <h3
                id="item-modal-title"
                className="text-lg font-bold text-white"
                style={{ fontFamily: 'var(--font-display)' }}
              >
                {editingItemId ? 'Edit Encrypted Vault Record' : 'New Encrypted Vault Record'}
              </h3>
              <div className="flex items-center gap-2">
                {!editingItemId && (
                  <button
                    type="button"
                    onClick={() => {
                      setIsEditorOpen(false);
                      onOpenCsvImport();
                    }}
                    className="px-3 py-1.5 text-xs font-medium text-[#00FF66] hover:text-[#00FF66] bg-slate-950 border border-slate-800 rounded-lg flex items-center gap-1.5"
                  >
                    <FileSpreadsheet className="w-3.5 h-3.5" />
                    <span>Import CSV</span>
                  </button>
                )}
                <button
                  type="button"
                  aria-label="Close modal"
                  onClick={() => setIsEditorOpen(false)}
                  className="p-1 text-slate-400 hover:text-white"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>
            </div>

            <form onSubmit={handleSaveItem} className="space-y-4">
              {/* Record Type Selector */}
              <div className="grid grid-cols-5 gap-1.5 p-1 bg-slate-950 border border-slate-800 rounded-lg">
                {(['password', 'note', 'identity', 'card', 'custom'] as const).map((t) => (
                  <button
                    key={t}
                    type="button"
                    onClick={() => setFormType(t)}
                    className={`py-1.5 px-2 text-xs font-medium rounded-md transition-colors capitalize whitespace-nowrap ${
                      formType === t
                        ? 'bg-slate-800 text-white'
                        : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    {t}
                  </button>
                ))}
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                <div className="sm:col-span-2 space-y-1">
                  <label htmlFor="item-title" className="block text-xs font-medium text-slate-300">
                    Record Title
                  </label>
                  <input
                    id="item-title"
                    type="text"
                    value={formTitle}
                    onChange={(e) => setFormTitle(e.target.value)}
                    placeholder="e.g. Production AWS Root"
                    className="w-full px-3 py-2 text-sm bg-slate-950 border border-slate-800 rounded-lg text-white"
                  />
                </div>
                <div className="space-y-1">
                  <label htmlFor="item-folder" className="block text-xs font-medium text-slate-300">
                    Category / Folder
                  </label>
                  <input
                    id="item-folder"
                    type="text"
                    value={formFolder}
                    onChange={(e) => setFormFolder(e.target.value)}
                    placeholder="Infrastructure"
                    className="w-full px-3 py-2 text-sm bg-slate-950 border border-slate-800 rounded-lg text-white"
                  />
                </div>
              </div>

              {formType === 'password' && (
                <div className="space-y-3">
                  <div className="space-y-1">
                    <label
                      htmlFor="item-username"
                      className="block text-xs font-medium text-slate-300"
                    >
                      Username or Email
                    </label>
                    <input
                      id="item-username"
                      type="text"
                      value={formUsername}
                      onChange={(e) => setFormUsername(e.target.value)}
                      placeholder="admin@domain.com"
                      className="w-full px-3 py-2 text-sm bg-slate-950 border border-slate-800 rounded-lg text-white font-mono"
                    />
                  </div>
                  <div className="space-y-1">
                    <div className="flex items-center justify-between">
                      <label
                        htmlFor="item-password"
                        className="block text-xs font-medium text-slate-300"
                      >
                        Password
                      </label>
                      <button
                        type="button"
                        onClick={() => {
                          const generated = generateSecurePassword({
                            length: 24,
                            uppercase: true,
                            lowercase: true,
                            numbers: true,
                            symbols: true,
                          });
                          setFormPassword(generated.password);
                        }}
                        className="text-xs text-[#00FF66] hover:underline flex items-center gap-1"
                      >
                        <Sparkles className="w-3 h-3" />
                        <span>Generate 24-Char CSPRNG Password</span>
                      </button>
                    </div>
                    <input
                      id="item-password"
                      type="text"
                      value={formPassword}
                      onChange={(e) => setFormPassword(e.target.value)}
                      placeholder="Enter or generate strong password"
                      className="w-full px-3 py-2 text-sm bg-slate-950 border border-slate-800 rounded-lg text-white font-mono"
                    />
                  </div>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    <div className="space-y-1">
                      <label
                        htmlFor="item-url"
                        className="block text-xs font-medium text-slate-300"
                      >
                        Service URL
                      </label>
                      <input
                        id="item-url"
                        type="text"
                        value={formUrl}
                        onChange={(e) => setFormUrl(e.target.value)}
                        placeholder="https://..."
                        className="w-full px-3 py-2 text-sm bg-slate-950 border border-slate-800 rounded-lg text-white"
                      />
                    </div>
                    <div className="space-y-1">
                      <label
                        htmlFor="item-totp"
                        className="block text-xs font-medium text-slate-300"
                      >
                        TOTP Secret (Optional)
                      </label>
                      <input
                        id="item-totp"
                        type="text"
                        value={formTotp}
                        onChange={(e) => setFormTotp(e.target.value)}
                        placeholder="JBSWY3DPEHPK3PXP"
                        className="w-full px-3 py-2 text-sm bg-slate-950 border border-slate-800 rounded-lg text-white font-mono"
                      />
                    </div>
                  </div>
                </div>
              )}

              {formType === 'identity' && (
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div className="space-y-1">
                    <label
                      htmlFor="item-fullname"
                      className="block text-xs font-medium text-slate-300"
                    >
                      Full Legal Name
                    </label>
                    <input
                      id="item-fullname"
                      type="text"
                      value={formFullName}
                      onChange={(e) => setFormFullName(e.target.value)}
                      className="w-full px-3 py-2 text-sm bg-slate-950 border border-slate-800 rounded-lg text-white"
                    />
                  </div>
                  <div className="space-y-1">
                    <label
                      htmlFor="item-passport"
                      className="block text-xs font-medium text-slate-300"
                    >
                      Passport / National ID
                    </label>
                    <input
                      id="item-passport"
                      type="text"
                      value={formPassport}
                      onChange={(e) => setFormPassport(e.target.value)}
                      className="w-full px-3 py-2 text-sm bg-slate-950 border border-slate-800 rounded-lg text-white font-mono"
                    />
                  </div>
                  <div className="space-y-1">
                    <label
                      htmlFor="item-email"
                      className="block text-xs font-medium text-slate-300"
                    >
                      Email
                    </label>
                    <input
                      id="item-email"
                      type="email"
                      value={formEmail}
                      onChange={(e) => setFormEmail(e.target.value)}
                      className="w-full px-3 py-2 text-sm bg-slate-950 border border-slate-800 rounded-lg text-white"
                    />
                  </div>
                  <div className="space-y-1">
                    <label
                      htmlFor="item-phone"
                      className="block text-xs font-medium text-slate-300"
                    >
                      Phone Number
                    </label>
                    <input
                      id="item-phone"
                      type="text"
                      value={formPhone}
                      onChange={(e) => setFormPhone(e.target.value)}
                      className="w-full px-3 py-2 text-sm bg-slate-950 border border-slate-800 rounded-lg text-white font-mono"
                    />
                  </div>
                  <div className="sm:col-span-2 space-y-1">
                    <label
                      htmlFor="item-address"
                      className="block text-xs font-medium text-slate-300"
                    >
                      Address
                    </label>
                    <input
                      id="item-address"
                      type="text"
                      value={formAddress}
                      onChange={(e) => setFormAddress(e.target.value)}
                      className="w-full px-3 py-2 text-sm bg-slate-950 border border-slate-800 rounded-lg text-white"
                    />
                  </div>
                </div>
              )}

              {formType === 'card' && (
                <div className="space-y-3">
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    <div className="space-y-1">
                      <label
                        htmlFor="item-cardholder"
                        className="block text-xs font-medium text-slate-300"
                      >
                        Cardholder Name
                      </label>
                      <input
                        id="item-cardholder"
                        type="text"
                        value={formCardholder}
                        onChange={(e) => setFormCardholder(e.target.value)}
                        className="w-full px-3 py-2 text-sm bg-slate-950 border border-slate-800 rounded-lg text-white"
                      />
                    </div>
                    <div className="space-y-1">
                      <label
                        htmlFor="item-cardnumber"
                        className="block text-xs font-medium text-slate-300"
                      >
                        Card Number
                      </label>
                      <input
                        id="item-cardnumber"
                        type="text"
                        value={formCardNumber}
                        onChange={(e) => setFormCardNumber(e.target.value)}
                        placeholder="4532 •••• •••• ••••"
                        className="w-full px-3 py-2 text-sm bg-slate-950 border border-slate-800 rounded-lg text-white font-mono"
                      />
                    </div>
                  </div>
                  <div className="grid grid-cols-3 gap-3">
                    <div className="space-y-1">
                      <label
                        htmlFor="item-expiry"
                        className="block text-xs font-medium text-slate-300"
                      >
                        Expiry (MM/YY)
                      </label>
                      <input
                        id="item-expiry"
                        type="text"
                        value={formCardExpiry}
                        onChange={(e) => setFormCardExpiry(e.target.value)}
                        placeholder="09/29"
                        className="w-full px-3 py-2 text-sm bg-slate-950 border border-slate-800 rounded-lg text-white font-mono"
                      />
                    </div>
                    <div className="space-y-1">
                      <label
                        htmlFor="item-cvv"
                        className="block text-xs font-medium text-slate-300"
                      >
                        CVV
                      </label>
                      <input
                        id="item-cvv"
                        type="text"
                        value={formCardCvv}
                        onChange={(e) => setFormCardCvv(e.target.value)}
                        placeholder="739"
                        className="w-full px-3 py-2 text-sm bg-slate-950 border border-slate-800 rounded-lg text-white font-mono"
                      />
                    </div>
                    <div className="space-y-1">
                      <label
                        htmlFor="item-pin"
                        className="block text-xs font-medium text-slate-300"
                      >
                        PIN
                      </label>
                      <input
                        id="item-pin"
                        type="text"
                        value={formCardPin}
                        onChange={(e) => setFormCardPin(e.target.value)}
                        placeholder="8492"
                        className="w-full px-3 py-2 text-sm bg-slate-950 border border-slate-800 rounded-lg text-white font-mono"
                      />
                    </div>
                  </div>
                </div>
              )}

              {formType === 'custom' && (
                <div className="space-y-2">
                  <div className="text-xs font-medium text-slate-300">Custom Key-Value Fields</div>
                  {formCustomFields.map((field, idx) => (
                    <div key={idx} className="flex items-center gap-2">
                      <input
                        type="text"
                        value={field.label}
                        onChange={(e) => {
                          const next = [...formCustomFields];
                          next[idx] = { ...next[idx], label: e.target.value };
                          setFormCustomFields(next);
                        }}
                        placeholder="Field Label"
                        className="w-1/3 px-2.5 py-1.5 text-xs bg-slate-950 border border-slate-800 rounded-lg text-white"
                      />
                      <input
                        type="text"
                        value={field.value}
                        onChange={(e) => {
                          const next = [...formCustomFields];
                          next[idx] = { ...next[idx], value: e.target.value };
                          setFormCustomFields(next);
                        }}
                        placeholder="Secret Value"
                        className="flex-1 px-2.5 py-1.5 text-xs font-mono bg-slate-950 border border-slate-800 rounded-lg text-white"
                      />
                    </div>
                  ))}
                  <button
                    type="button"
                    onClick={() =>
                      setFormCustomFields([
                        ...formCustomFields,
                        { label: '', value: '', sensitive: true },
                      ])
                    }
                    className="text-xs text-[#00FF66] hover:underline"
                  >
                    + Add Custom Field
                  </button>
                </div>
              )}

              <div className="space-y-1">
                <label htmlFor="item-note" className="block text-xs font-medium text-slate-300">
                  Encrypted Notes
                </label>
                <textarea
                  id="item-note"
                  rows={3}
                  value={formNote}
                  onChange={(e) => setFormNote(e.target.value)}
                  placeholder="Additional sensitive notes (sealed inside AES-256-GCM payload)..."
                  className="w-full px-3 py-2 text-sm bg-slate-950 border border-slate-800 rounded-lg text-white"
                />
              </div>

              <label className="flex items-center gap-2 cursor-pointer select-none">
                <input
                  type="checkbox"
                  checked={formFavorite}
                  onChange={(e) => setFormFavorite(e.target.checked)}
                  className="rounded border-slate-700 bg-slate-950 text-[#00FF66]"
                />
                <span className="text-xs text-slate-300">Pin to Favorites</span>
              </label>

              {formError && <div className="text-xs text-rose-400">{formError}</div>}

              <div className="flex items-center justify-end gap-3 pt-3 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setIsEditorOpen(false)}
                  className="px-4 py-2 text-xs font-medium text-slate-300 hover:text-white bg-slate-900 rounded-lg"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isSaving}
                  className="px-4 py-2 text-xs font-semibold text-slate-950 bg-[#00FF66] hover:bg-[#22FF7A] rounded-lg"
                >
                  {isSaving ? 'Encrypting...' : 'Encrypt & Save Item'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
