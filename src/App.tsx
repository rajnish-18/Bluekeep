import React, { useState, useEffect, useMemo } from 'react';
import {
  Shield,
  Lock,
  Unlock,
  Plus,
  Search,
  Key,
  FileText,
  Terminal,
  Globe,
  Copy,
  Check,
  Eye,
  EyeOff,
  Trash2,
  Download,
  Upload,
  RefreshCw,
  Pin,
  Code2,
  AlertCircle,
  Sparkles,
  Edit3,
  Save,
  X,
} from 'lucide-react';
import {
  EncryptedEnvelope,
  VaultSecret,
  encryptPayload,
  decryptPayload,
  generateHighEntropySecret,
  calculateEntropyBits,
} from './crypto';

const STORAGE_KEY = 'bluekeep_encrypted_vault_v1';

const SAMPLE_SECRETS: VaultSecret[] = [
  {
    id: 'sec-1',
    title: 'Production PostgreSQL Cluster',
    category: 'credential',
    username: 'admin_ro_vault',
    secretValue: 'k9#mP2$vL8@nQ5!xR4&zW7*j',
    url: 'postgres://db-primary.internal:5432/bluekeep_prod',
    content:
      'Primary read/write replica credentials. Rotate every 90 days via HashiCorp Vault or manual key ceremony. Never expose outside VPN.',
    tags: ['database', 'production', 'infra'],
    pinned: true,
    createdAt: new Date(Date.now() - 86400000 * 5).toISOString(),
    updatedAt: new Date(Date.now() - 86400000 * 1).toISOString(),
  },
  {
    id: 'sec-2',
    title: 'Cloudflare DNS Zone API Token',
    category: 'api-key',
    username: 'zone-dns-automation',
    secretValue: 'cf_live_98a7f6d5e4c3b2a10987654321fedcba',
    url: 'https://dash.cloudflare.com',
    content:
      'Scoped strictly to Zone.DNS Edit for ACME wildcard TLS certificate renewal hooks.',
    tags: ['cloudflare', 'dns', 'tls'],
    pinned: true,
    createdAt: new Date(Date.now() - 86400000 * 3).toISOString(),
    updatedAt: new Date(Date.now() - 86400000 * 2).toISOString(),
  },
  {
    id: 'sec-3',
    title: 'Zero-Knowledge Recovery Protocol Notes',
    category: 'note',
    content:
      '1. Master passphrase is never stored or transmitted.\n2. PBKDF2-HMAC-SHA256 derives a 256-bit key using 250,000 iterations and a 128-bit random salt.\n3. AES-256-GCM encrypts the serialized vault with a fresh 96-bit IV on every save operation and appends a 128-bit authentication tag.',
    tags: ['security', 'architecture', 'recovery'],
    pinned: false,
    createdAt: new Date(Date.now() - 86400000 * 7).toISOString(),
    updatedAt: new Date(Date.now() - 86400000 * 7).toISOString(),
  },
];

export default function App() {
  const [envelope, setEnvelope] = useState<EncryptedEnvelope | null>(() => {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      return raw ? (JSON.parse(raw) as EncryptedEnvelope) : null;
    } catch {
      return null;
    }
  });

  const [isUnlocked, setIsUnlocked] = useState(false);
  const [masterPassphrase, setMasterPassphrase] = useState('');
  const [passphraseInput, setPassphraseInput] = useState('');
  const [confirmPassphraseInput, setConfirmPassphraseInput] = useState('');
  const [showPassphrase, setShowPassphrase] = useState(false);
  const [authError, setAuthError] = useState<string | null>(null);
  const [isBusy, setIsBusy] = useState(false);

  const [secrets, setSecrets] = useState<VaultSecret[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [categoryFilter, setCategoryFilter] = useState<string>('all');
  const [showSecretValue, setShowSecretValue] = useState(false);
  const [copiedField, setCopiedField] = useState<string | null>(null);
  const [showCryptoInspector, setShowCryptoInspector] = useState(false);

  // Editor state
  const [isEditing, setIsEditing] = useState(false);
  const [draftTitle, setDraftTitle] = useState('');
  const [draftCategory, setDraftCategory] = useState<VaultSecret['category']>('note');
  const [draftUsername, setDraftUsername] = useState('');
  const [draftSecretValue, setDraftSecretValue] = useState('');
  const [draftUrl, setDraftUrl] = useState('');
  const [draftContent, setDraftContent] = useState('');
  const [draftTags, setDraftTags] = useState('');

  // Password generator modal state
  const [genLength, setGenLength] = useState(24);
  const [genSymbols, setGenSymbols] = useState(true);

  const selectedSecret = useMemo(
    () => secrets.find((s) => s.id === selectedId) || null,
    [secrets, selectedId]
  );

  const filteredSecrets = useMemo(() => {
    return secrets
      .filter((item) => {
        if (categoryFilter !== 'all' && item.category !== categoryFilter) {
          return false;
        }
        if (!searchQuery.trim()) return true;
        const q = searchQuery.toLowerCase();
        return (
          item.title.toLowerCase().includes(q) ||
          item.content.toLowerCase().includes(q) ||
          (item.username && item.username.toLowerCase().includes(q)) ||
          item.tags.some((t) => t.toLowerCase().includes(q))
        );
      })
      .sort((a, b) => {
        if (a.pinned !== b.pinned) return a.pinned ? -1 : 1;
        return new Date(b.updatedAt).getTime() - new Date(a.updatedAt).getTime();
      });
  }, [secrets, categoryFilter, searchQuery]);

  async function persistVault(nextSecrets: VaultSecret[], activePassphrase = masterPassphrase) {
    if (!activePassphrase) return;
    const encrypted = await encryptPayload(JSON.stringify(nextSecrets), activePassphrase);
    localStorage.setItem(STORAGE_KEY, JSON.stringify(encrypted));
    setEnvelope(encrypted);
    setSecrets(nextSecrets);
  }

  async function handleInitializeVault(e: React.FormEvent) {
    e.preventDefault();
    setAuthError(null);
    if (passphraseInput.length < 8) {
      setAuthError('Master passphrase must be at least 8 characters.');
      return;
    }
    if (passphraseInput !== confirmPassphraseInput) {
      setAuthError('Passphrases do not match.');
      return;
    }

    setIsBusy(true);
    try {
      const initialItems = SAMPLE_SECRETS;
      const encrypted = await encryptPayload(JSON.stringify(initialItems), passphraseInput);
      localStorage.setItem(STORAGE_KEY, JSON.stringify(encrypted));
      setEnvelope(encrypted);
      setMasterPassphrase(passphraseInput);
      setSecrets(initialItems);
      setSelectedId(initialItems[0]?.id || null);
      setIsUnlocked(true);
      setPassphraseInput('');
      setConfirmPassphraseInput('');
    } catch (err) {
      setAuthError('Failed to initialize AES-256-GCM vault.');
    } finally {
      setIsBusy(false);
    }
  }

  async function handleUnlockVault(e: React.FormEvent) {
    e.preventDefault();
    if (!envelope) return;
    setAuthError(null);
    setIsBusy(true);
    try {
      const plaintext = await decryptPayload(envelope, passphraseInput);
      const parsed = JSON.parse(plaintext) as VaultSecret[];
      setSecrets(parsed);
      setMasterPassphrase(passphraseInput);
      setSelectedId(parsed[0]?.id || null);
      setIsUnlocked(true);
      setPassphraseInput('');
    } catch {
      setAuthError('Authentication tag verification failed: invalid passphrase or tampered ciphertext.');
    } finally {
      setIsBusy(false);
    }
  }

  function handleLockVault() {
    setIsUnlocked(false);
    setMasterPassphrase('');
    setSecrets([]);
    setSelectedId(null);
    setIsEditing(false);
    setShowSecretValue(false);
  }

  function handleResetVault() {
    localStorage.removeItem(STORAGE_KEY);
    setEnvelope(null);
    handleLockVault();
    setAuthError(null);
  }

  function startNewSecret() {
    const newId = `sec-${Date.now()}`;
    const newSecret: VaultSecret = {
      id: newId,
      title: 'Untitled Encrypted Entry',
      category: 'credential',
      username: '',
      secretValue: generateHighEntropySecret(24, {
        uppercase: true,
        lowercase: true,
        digits: true,
        symbols: true,
      }),
      url: '',
      content: '',
      tags: ['vault'],
      pinned: false,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };
    const next = [newSecret, ...secrets];
    persistVault(next);
    setSelectedId(newId);
    openEditor(newSecret);
  }

  function openEditor(secret: VaultSecret) {
    setDraftTitle(secret.title);
    setDraftCategory(secret.category);
    setDraftUsername(secret.username || '');
    setDraftSecretValue(secret.secretValue || '');
    setDraftUrl(secret.url || '');
    setDraftContent(secret.content);
    setDraftTags(secret.tags.join(', '));
    setIsEditing(true);
  }

  async function saveEditor() {
    if (!selectedSecret) return;
    const updated: VaultSecret = {
      ...selectedSecret,
      title: draftTitle.trim() || 'Untitled Secret',
      category: draftCategory,
      username: draftUsername.trim() || undefined,
      secretValue: draftSecretValue || undefined,
      url: draftUrl.trim() || undefined,
      content: draftContent,
      tags: draftTags
        .split(',')
        .map((t) => t.trim())
        .filter(Boolean),
      updatedAt: new Date().toISOString(),
    };
    const next = secrets.map((s) => (s.id === selectedSecret.id ? updated : s));
    await persistVault(next);
    setIsEditing(false);
  }

  async function deleteSecret(id: string) {
    const next = secrets.filter((s) => s.id !== id);
    await persistVault(next);
    if (selectedId === id) {
      setSelectedId(next[0]?.id || null);
      setIsEditing(false);
    }
  }

  async function togglePin(secret: VaultSecret) {
    const next = secrets.map((s) =>
      s.id === secret.id ? { ...s, pinned: !s.pinned, updatedAt: new Date().toISOString() } : s
    );
    await persistVault(next);
  }

  function copyToClipboard(text: string, label: string) {
    navigator.clipboard.writeText(text);
    setCopiedField(label);
    setTimeout(() => setCopiedField(null), 1800);
  }

  function exportEncryptedVault() {
    if (!envelope) return;
    const blob = new Blob([JSON.stringify(envelope, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `bluekeep-vault-${new Date().toISOString().slice(0, 10)}.bluekeep.json`;
    a.click();
    URL.revokeObjectURL(url);
  }

  function handleImportVault(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      try {
        const parsed = JSON.parse(String(reader.result)) as EncryptedEnvelope;
        if (parsed.alg === 'AES-256-GCM' && parsed.ciphertext && parsed.iv && parsed.salt) {
          localStorage.setItem(STORAGE_KEY, JSON.stringify(parsed));
          setEnvelope(parsed);
          handleLockVault();
          setAuthError(null);
        } else {
          setAuthError('Invalid Bluekeep encrypted vault envelope.');
        }
      } catch {
        setAuthError('Could not parse vault JSON file.');
      }
    };
    reader.readAsText(file);
  }

  // Render Lock / Initialization Screen when locked
  if (!isUnlocked) {
    const isInitializing = !envelope;
    const entropyBits = calculateEntropyBits(passphraseInput);

    return (
      <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col justify-between p-6">
        <header className="max-w-6xl w-full mx-auto flex items-center justify-between py-2">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-blue-600/20 border border-blue-500/40 flex items-center justify-center text-blue-400 shadow-lg shadow-blue-950/50">
              <Shield className="w-5 h-5" />
            </div>
            <div>
              <span className="font-semibold tracking-tight text-lg text-white">Bluekeep</span>
              <span className="ml-2 text-xs font-mono uppercase px-2 py-0.5 rounded bg-blue-500/10 text-blue-400 border border-blue-500/20">
                AES-256-GCM
              </span>
            </div>
          </div>

          <div className="flex items-center gap-3 text-xs text-slate-400 font-mono">
            <span className="hidden sm:inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-slate-900 border border-slate-800">
              <span className="w-2 h-2 rounded-full bg-emerald-400" />
              Web Crypto API Ready
            </span>
            <label className="cursor-pointer inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-800 transition">
              <Upload className="w-3.5 h-3.5" />
              <span>Import Vault</span>
              <input type="file" accept=".json" onChange={handleImportVault} className="hidden" />
            </label>
          </div>
        </header>

        <main className="my-auto max-w-md w-full mx-auto">
          <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-8 shadow-2xl shadow-black/60 backdrop-blur">
            <div className="w-12 h-12 rounded-2xl bg-blue-500/10 border border-blue-500/30 flex items-center justify-center text-blue-400 mb-6">
              <Lock className="w-6 h-6" />
            </div>

            <h1 className="text-2xl font-bold text-white tracking-tight">
              {isInitializing ? 'Initialize Zero-Knowledge Vault' : 'Unlock Encrypted Vault'}
            </h1>
            <p className="text-sm text-slate-400 mt-2 leading-relaxed">
              {isInitializing
                ? 'Derive your local encryption key via PBKDF2-SHA256 (250,000 iterations). Your master passphrase never leaves your browser.'
                : 'Enter your master passphrase to derive the 256-bit key and verify the AES-GCM authentication tag.'}
            </p>

            {authError && (
              <div className="mt-4 p-3.5 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs flex items-start gap-2.5">
                <AlertCircle className="w-4 h-4 shrink-0 mt-0.5 text-rose-400" />
                <span>{authError}</span>
              </div>
            )}

            <form
              onSubmit={isInitializing ? handleInitializeVault : handleUnlockVault}
              className="mt-6 space-y-4"
            >
              <div>
                <label className="block text-xs font-medium uppercase tracking-wider text-slate-400 mb-2">
                  Master Passphrase
                </label>
                <div className="relative">
                  <input
                    type={showPassphrase ? 'text' : 'password'}
                    value={passphraseInput}
                    onChange={(e) => setPassphraseInput(e.target.value)}
                    placeholder={
                      isInitializing ? 'Enter a strong master passphrase...' : 'Enter master passphrase...'
                    }
                    className="w-full bg-slate-950 border border-slate-800 focus:border-blue-500 focus:outline-none rounded-xl px-4 py-3 pr-11 text-sm text-white placeholder-slate-600 font-mono"
                    autoFocus
                    required
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassphrase(!showPassphrase)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300"
                  >
                    {showPassphrase ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>

                {isInitializing && passphraseInput.length > 0 && (
                  <div className="mt-2 flex items-center justify-between text-xs font-mono">
                    <span className="text-slate-400">Estimated Entropy:</span>
                    <span
                      className={
                        entropyBits >= 80
                          ? 'text-emerald-400'
                          : entropyBits >= 50
                          ? 'text-amber-400'
                          : 'text-rose-400'
                      }
                    >
                      {entropyBits} bits ({entropyBits >= 80 ? 'Strong' : entropyBits >= 50 ? 'Moderate' : 'Weak'})
                    </span>
                  </div>
                )}
              </div>

              {isInitializing && (
                <div>
                  <label className="block text-xs font-medium uppercase tracking-wider text-slate-400 mb-2">
                    Confirm Master Passphrase
                  </label>
                  <input
                    type={showPassphrase ? 'text' : 'password'}
                    value={confirmPassphraseInput}
                    onChange={(e) => setConfirmPassphraseInput(e.target.value)}
                    placeholder="Re-enter master passphrase..."
                    className="w-full bg-slate-950 border border-slate-800 focus:border-blue-500 focus:outline-none rounded-xl px-4 py-3 text-sm text-white placeholder-slate-600 font-mono"
                    required
                  />
                </div>
              )}

              <button
                type="submit"
                disabled={isBusy}
                className="w-full py-3 px-4 rounded-xl bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white font-medium text-sm transition flex items-center justify-center gap-2 shadow-lg shadow-blue-600/25 cursor-pointer"
              >
                <Unlock className="w-4 h-4" />
                <span>
                  {isBusy
                    ? 'Running PBKDF2 (250,000 rounds)...'
                    : isInitializing
                    ? 'Create & Encrypt Vault'
                    : 'Decrypt & Unlock Vault'}
                </span>
              </button>
            </form>

            {!isInitializing && envelope && (
              <div className="mt-6 pt-5 border-t border-slate-800/80 space-y-3">
                <div className="flex items-center justify-between text-xs text-slate-400 font-mono">
                  <span>Ciphertext Envelope</span>
                  <span>{envelope.ciphertext.length} B64 chars</span>
                </div>
                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800/80 font-mono text-[11px] text-slate-400 break-all max-h-24 overflow-y-auto">
                  <div>
                    <span className="text-blue-400">salt:</span> {envelope.salt}
                  </div>
                  <div>
                    <span className="text-blue-400">iv:</span> {envelope.iv}
                  </div>
                  <div>
                    <span className="text-blue-400">gcm:</span> {envelope.ciphertext.slice(0, 72)}...
                  </div>
                </div>
                <div className="flex items-center justify-between pt-1">
                  <button
                    type="button"
                    onClick={exportEncryptedVault}
                    className="text-xs text-slate-400 hover:text-slate-200 inline-flex items-center gap-1.5 cursor-pointer"
                  >
                    <Download className="w-3.5 h-3.5" />
                    Backup Ciphertext
                  </button>
                  <button
                    type="button"
                    onClick={handleResetVault}
                    className="text-xs text-rose-400/80 hover:text-rose-300 inline-flex items-center gap-1 cursor-pointer"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                    Wipe Local Vault
                  </button>
                </div>
              </div>
            )}
          </div>
        </main>

        <footer className="max-w-6xl w-full mx-auto text-center text-xs text-slate-500 py-2 font-mono">
          Zero-Knowledge Client Architecture • AES-256-GCM • PBKDF2-HMAC-SHA256 (250k iterations)
        </footer>
      </div>
    );
  }

  // Unlocked Main Vault Interface
  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col">
      {/* Top Bar */}
      <header className="h-16 border-b border-slate-800/80 bg-slate-900/60 px-6 flex items-center justify-between shrink-0">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-xl bg-blue-600/20 border border-blue-500/40 flex items-center justify-center text-blue-400">
            <Shield className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-semibold text-white tracking-tight">Bluekeep</span>
              <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                UNLOCKED • AES-256-GCM
              </span>
            </div>
            <p className="text-xs text-slate-400 hidden sm:block">
              Client-side zero-knowledge vault ({secrets.length} encrypted records)
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2.5">
          <button
            onClick={() => setShowCryptoInspector(!showCryptoInspector)}
            className={`px-3 py-1.5 rounded-lg text-xs font-mono border transition inline-flex items-center gap-1.5 cursor-pointer ${
              showCryptoInspector
                ? 'bg-blue-600/20 border-blue-500/40 text-blue-300'
                : 'bg-slate-900 border-slate-800 text-slate-300 hover:bg-slate-800'
            }`}
          >
            <Code2 className="w-3.5 h-3.5" />
            <span>Crypto Inspector</span>
          </button>

          <button
            onClick={exportEncryptedVault}
            className="px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-900 hover:bg-slate-800 text-slate-200 border border-slate-800 transition inline-flex items-center gap-1.5 cursor-pointer"
          >
            <Download className="w-3.5 h-3.5" />
            <span className="hidden sm:inline">Export Encrypted JSON</span>
          </button>

          <button
            onClick={handleLockVault}
            className="px-3.5 py-1.5 rounded-lg text-xs font-medium bg-rose-500/10 hover:bg-rose-500/20 text-rose-300 border border-rose-500/30 transition inline-flex items-center gap-1.5 cursor-pointer"
          >
            <Lock className="w-3.5 h-3.5" />
            <span>Lock Vault</span>
          </button>
        </div>
      </header>

      {/* Optional Live AES-256-GCM Ciphertext Inspector Bar */}
      {showCryptoInspector && envelope && (
        <div className="bg-slate-900/95 border-b border-blue-500/30 px-6 py-4 text-xs font-mono">
          <div className="max-w-7xl mx-auto space-y-2">
            <div className="flex flex-wrap items-center justify-between gap-2 text-blue-300">
              <span>LIVE LOCALSTORAGE CIPHERTEXT ENVELOPE (ZERO-KNOWLEDGE PROOF)</span>
              <span>
                KDF: {envelope.kdf} ({envelope.iter.toLocaleString()} iterations) • Cipher: {envelope.alg}
              </span>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3 pt-1">
              <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800">
                <span className="text-slate-500 block text-[10px]">128-BIT SALT (BASE64)</span>
                <span className="text-slate-200 break-all">{envelope.salt}</span>
              </div>
              <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800">
                <span className="text-slate-500 block text-[10px]">96-BIT IV / NONCE (BASE64)</span>
                <span className="text-slate-200 break-all">{envelope.iv}</span>
              </div>
              <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800">
                <span className="text-slate-500 block text-[10px]">
                  AES-GCM CIPHERTEXT + 128-BIT AUTH TAG
                </span>
                <span className="text-emerald-400 break-all">
                  {envelope.ciphertext.slice(0, 96)}...
                </span>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Main 3-Column Vault Workspace */}
      <div className="flex-1 grid grid-cols-1 lg:grid-cols-12 overflow-hidden">
        {/* Column 1: Categories & Entropy Generator */}
        <aside className="lg:col-span-3 xl:col-span-2 border-r border-slate-800/80 bg-slate-900/30 p-4 flex flex-col justify-between gap-6">
          <div className="space-y-6">
            <button
              onClick={startNewSecret}
              className="w-full py-2.5 px-4 rounded-xl bg-blue-600 hover:bg-blue-500 text-white font-medium text-sm transition flex items-center justify-center gap-2 shadow-lg shadow-blue-600/20 cursor-pointer"
            >
              <Plus className="w-4 h-4" />
              <span>New Encrypted Secret</span>
            </button>

            <nav className="space-y-1">
              <p className="px-3 text-[11px] font-mono uppercase tracking-wider text-slate-500 mb-2">
                Vault Partitions
              </p>
              {[
                { id: 'all', label: 'All Secrets', icon: Shield },
                { id: 'credential', label: 'Credentials', icon: Key },
                { id: 'note', label: 'Encrypted Notes', icon: FileText },
                { id: 'api-key', label: 'API Tokens', icon: Sparkles },
                { id: 'ssh-key', label: 'SSH / Infra Keys', icon: Terminal },
              ].map((cat) => {
                const Icon = cat.icon;
                const count =
                  cat.id === 'all'
                    ? secrets.length
                    : secrets.filter((s) => s.category === cat.id).length;
                return (
                  <button
                    key={cat.id}
                    onClick={() => setCategoryFilter(cat.id)}
                    className={`w-full flex items-center justify-between px-3 py-2 rounded-lg text-xs font-medium transition cursor-pointer ${
                      categoryFilter === cat.id
                        ? 'bg-blue-600/15 text-blue-300 border border-blue-500/30'
                        : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
                    }`}
                  >
                    <span className="flex items-center gap-2.5">
                      <Icon className="w-4 h-4" />
                      {cat.label}
                    </span>
                    <span className="font-mono text-[11px] text-slate-500">{count}</span>
                  </button>
                );
              })}
            </nav>
          </div>

          {/* Built-in CSPRNG Key Generator Widget */}
          <div className="p-3.5 rounded-xl bg-slate-900/90 border border-slate-800 space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-slate-200 flex items-center gap-1.5">
                <RefreshCw className="w-3.5 h-3.5 text-blue-400" />
                CSPRNG Generator
              </span>
              <span className="text-[11px] font-mono text-slate-400">{genLength} chars</span>
            </div>
            <input
              type="range"
              min={12}
              max={64}
              value={genLength}
              onChange={(e) => setGenLength(Number(e.target.value))}
              className="w-full accent-blue-500"
            />
            <div className="flex items-center justify-between text-xs text-slate-400">
              <label className="flex items-center gap-1.5 cursor-pointer">
                <input
                  type="checkbox"
                  checked={genSymbols}
                  onChange={(e) => setGenSymbols(e.target.checked)}
                  className="accent-blue-500"
                />
                <span>Include Symbols</span>
              </label>
              <button
                type="button"
                onClick={() => {
                  const generated = generateHighEntropySecret(genLength, {
                    uppercase: true,
                    lowercase: true,
                    digits: true,
                    symbols: genSymbols,
                  });
                  copyToClipboard(generated, 'csprng');
                }}
                className="text-blue-400 hover:text-blue-300 font-mono text-xs cursor-pointer"
              >
                {copiedField === 'csprng' ? 'Copied!' : 'Generate & Copy'}
              </button>
            </div>
          </div>
        </aside>

        {/* Column 2: Search & Secret List */}
        <section className="lg:col-span-4 xl:col-span-4 border-r border-slate-800/80 flex flex-col bg-slate-950/60">
          <div className="p-4 border-b border-slate-800/80">
            <div className="relative">
              <Search className="w-4 h-4 text-slate-500 absolute left-3.5 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search decrypted titles, tags, usernames..."
                className="w-full bg-slate-900 border border-slate-800 focus:border-blue-500 focus:outline-none rounded-xl pl-10 pr-4 py-2 text-xs text-slate-100 placeholder-slate-500"
              />
            </div>
          </div>

          <div className="flex-1 overflow-y-auto divide-y divide-slate-800/60">
            {filteredSecrets.length === 0 ? (
              <div className="p-10 text-center text-slate-500 text-xs space-y-2">
                <p>No matching encrypted records in this partition.</p>
              </div>
            ) : (
              filteredSecrets.map((item) => {
                const isSelected = item.id === selectedId;
                return (
                  <button
                    key={item.id}
                    onClick={() => {
                      setSelectedId(item.id);
                      setIsEditing(false);
                      setShowSecretValue(false);
                    }}
                    className={`w-full text-left p-4 transition flex items-start justify-between gap-3 cursor-pointer ${
                      isSelected ? 'bg-blue-600/10 border-l-2 border-l-blue-500' : 'hover:bg-slate-900/60'
                    }`}
                  >
                    <div className="min-w-0 space-y-1">
                      <div className="flex items-center gap-2">
                        {item.pinned && <Pin className="w-3 h-3 text-blue-400 shrink-0" />}
                        <h3 className="font-medium text-sm text-slate-100 truncate">{item.title}</h3>
                      </div>
                      {item.username && (
                        <p className="text-xs font-mono text-slate-400 truncate">{item.username}</p>
                      )}
                      <p className="text-xs text-slate-500 line-clamp-1">{item.content}</p>
                      <div className="flex flex-wrap gap-1 pt-1">
                        <span className="text-[10px] font-mono uppercase px-1.5 py-0.5 rounded bg-slate-900 text-blue-400 border border-slate-800">
                          {item.category}
                        </span>
                        {item.tags.map((tag) => (
                          <span
                            key={tag}
                            className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-900 text-slate-400"
                          >
                            #{tag}
                          </span>
                        ))}
                      </div>
                    </div>
                  </button>
                );
              })
            )}
          </div>
        </section>

        {/* Column 3: Decrypted Record Inspector / Editor */}
        <main className="lg:col-span-5 xl:col-span-6 p-6 overflow-y-auto bg-slate-950">
          {!selectedSecret ? (
            <div className="h-full flex flex-col items-center justify-center text-center text-slate-500 py-16">
              <Shield className="w-10 h-10 text-slate-700 mb-3" />
              <p className="text-sm font-medium text-slate-400">Select a secret to decrypt in memory</p>
              <p className="text-xs text-slate-600 mt-1">
                All records are encrypted at rest with AES-256-GCM.
              </p>
            </div>
          ) : isEditing ? (
            <div className="max-w-2xl mx-auto space-y-5 bg-slate-900/60 border border-slate-800 rounded-2xl p-6">
              <div className="flex items-center justify-between border-b border-slate-800 pb-4">
                <h2 className="text-base font-semibold text-white">Edit Vault Record</h2>
                <button
                  onClick={() => setIsEditing(false)}
                  className="text-slate-400 hover:text-slate-200 cursor-pointer"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                <div className="sm:col-span-2">
                  <label className="block text-xs font-mono uppercase text-slate-400 mb-1.5">
                    Title
                  </label>
                  <input
                    type="text"
                    value={draftTitle}
                    onChange={(e) => setDraftTitle(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3.5 py-2 text-sm text-white"
                  />
                </div>
                <div>
                  <label className="block text-xs font-mono uppercase text-slate-400 mb-1.5">
                    Category
                  </label>
                  <select
                    value={draftCategory}
                    onChange={(e) => setDraftCategory(e.target.value as VaultSecret['category'])}
                    className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3.5 py-2 text-sm text-white"
                  >
                    <option value="credential">Credential</option>
                    <option value="note">Encrypted Note</option>
                    <option value="api-key">API Token</option>
                    <option value="ssh-key">SSH / Infra Key</option>
                  </select>
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-mono uppercase text-slate-400 mb-1.5">
                    Identity / Username
                  </label>
                  <input
                    type="text"
                    value={draftUsername}
                    onChange={(e) => setDraftUsername(e.target.value)}
                    placeholder="e.g. root@cluster-01"
                    className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3.5 py-2 text-sm text-white font-mono"
                  />
                </div>
                <div>
                  <label className="block text-xs font-mono uppercase text-slate-400 mb-1.5">
                    Service URI / Endpoint
                  </label>
                  <input
                    type="text"
                    value={draftUrl}
                    onChange={(e) => setDraftUrl(e.target.value)}
                    placeholder="https://..."
                    className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3.5 py-2 text-sm text-white font-mono"
                  />
                </div>
              </div>

              <div>
                <div className="flex items-center justify-between mb-1.5">
                  <label className="text-xs font-mono uppercase text-slate-400">
                    Secret / Password / Token
                  </label>
                  <button
                    type="button"
                    onClick={() =>
                      setDraftSecretValue(
                        generateHighEntropySecret(24, {
                          uppercase: true,
                          lowercase: true,
                          digits: true,
                          symbols: true,
                        })
                      )
                    }
                    className="text-xs font-mono text-blue-400 hover:text-blue-300 cursor-pointer"
                  >
                    + Roll 256-Bit Secret
                  </button>
                </div>
                <input
                  type="text"
                  value={draftSecretValue}
                  onChange={(e) => setDraftSecretValue(e.target.value)}
                  placeholder="Optional sensitive secret value..."
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3.5 py-2 text-sm text-emerald-300 font-mono"
                />
              </div>

              <div>
                <label className="block text-xs font-mono uppercase text-slate-400 mb-1.5">
                  Encrypted Notes & Recovery Instructions
                </label>
                <textarea
                  rows={5}
                  value={draftContent}
                  onChange={(e) => setDraftContent(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl p-3.5 text-sm text-slate-200 font-mono"
                />
              </div>

              <div>
                <label className="block text-xs font-mono uppercase text-slate-400 mb-1.5">
                  Tags (comma-separated)
                </label>
                <input
                  type="text"
                  value={draftTags}
                  onChange={(e) => setDraftTags(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3.5 py-2 text-sm text-slate-200 font-mono"
                />
              </div>

              <div className="flex items-center justify-end gap-3 pt-2">
                <button
                  type="button"
                  onClick={() => setIsEditing(false)}
                  className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-xs font-medium text-slate-300 cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="button"
                  onClick={saveEditor}
                  className="px-4 py-2 rounded-xl bg-blue-600 hover:bg-blue-500 text-xs font-medium text-white inline-flex items-center gap-1.5 cursor-pointer"
                >
                  <Save className="w-3.5 h-3.5" />
                  <span>Re-Encrypt & Save</span>
                </button>
              </div>
            </div>
          ) : (
            <div className="max-w-2xl mx-auto space-y-6">
              <div className="flex items-start justify-between gap-4 border-b border-slate-800/80 pb-5">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-mono uppercase px-2 py-0.5 rounded bg-blue-500/10 text-blue-400 border border-blue-500/20">
                      {selectedSecret.category}
                    </span>
                    <span className="text-xs font-mono text-slate-500">
                      Updated {new Date(selectedSecret.updatedAt).toLocaleDateString()}
                    </span>
                  </div>
                  <h2 className="text-2xl font-bold text-white mt-2">{selectedSecret.title}</h2>
                </div>

                <div className="flex items-center gap-2">
                  <button
                    onClick={() => togglePin(selectedSecret)}
                    className={`p-2 rounded-lg border transition cursor-pointer ${
                      selectedSecret.pinned
                        ? 'bg-blue-600/20 border-blue-500/40 text-blue-400'
                        : 'bg-slate-900 border-slate-800 text-slate-400 hover:text-slate-200'
                    }`}
                    title="Pin Secret"
                  >
                    <Pin className="w-4 h-4" />
                  </button>
                  <button
                    onClick={() => openEditor(selectedSecret)}
                    className="px-3 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 text-xs font-medium text-slate-200 inline-flex items-center gap-1.5 cursor-pointer"
                  >
                    <Edit3 className="w-3.5 h-3.5" />
                    <span>Edit</span>
                  </button>
                  <button
                    onClick={() => deleteSecret(selectedSecret.id)}
                    className="p-2 rounded-lg bg-slate-900 hover:bg-rose-500/15 border border-slate-800 hover:border-rose-500/30 text-slate-400 hover:text-rose-400 transition cursor-pointer"
                    title="Delete Secret"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>
              </div>

              {/* Structured Credentials Fields */}
              {(selectedSecret.username || selectedSecret.secretValue || selectedSecret.url) && (
                <div className="bg-slate-900/70 border border-slate-800 rounded-2xl divide-y divide-slate-800">
                  {selectedSecret.username && (
                    <div className="p-4 flex items-center justify-between gap-4">
                      <div>
                        <span className="text-[11px] font-mono uppercase text-slate-500 block">
                          Username / Identifier
                        </span>
                        <span className="text-sm font-mono text-slate-100">
                          {selectedSecret.username}
                        </span>
                      </div>
                      <button
                        onClick={() => copyToClipboard(selectedSecret.username!, 'username')}
                        className="px-2.5 py-1.5 rounded-lg bg-slate-950 hover:bg-slate-800 border border-slate-800 text-xs text-slate-300 inline-flex items-center gap-1.5 cursor-pointer"
                      >
                        {copiedField === 'username' ? (
                          <Check className="w-3.5 h-3.5 text-emerald-400" />
                        ) : (
                          <Copy className="w-3.5 h-3.5" />
                        )}
                        <span>{copiedField === 'username' ? 'Copied' : 'Copy'}</span>
                      </button>
                    </div>
                  )}

                  {selectedSecret.secretValue && (
                    <div className="p-4 flex items-center justify-between gap-4">
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center gap-2">
                          <span className="text-[11px] font-mono uppercase text-slate-500">
                            Encrypted Secret Payload
                          </span>
                          <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-emerald-500/10 text-emerald-400">
                            {calculateEntropyBits(selectedSecret.secretValue)} bits entropy
                          </span>
                        </div>
                        <p className="text-sm font-mono text-emerald-300 truncate mt-0.5">
                          {showSecretValue
                            ? selectedSecret.secretValue
                            : '••••••••••••••••••••••••••••'}
                        </p>
                      </div>
                      <div className="flex items-center gap-2">
                        <button
                          onClick={() => setShowSecretValue(!showSecretValue)}
                          className="p-2 rounded-lg bg-slate-950 hover:bg-slate-800 border border-slate-800 text-slate-300 cursor-pointer"
                        >
                          {showSecretValue ? (
                            <EyeOff className="w-3.5 h-3.5" />
                          ) : (
                            <Eye className="w-3.5 h-3.5" />
                          )}
                        </button>
                        <button
                          onClick={() => copyToClipboard(selectedSecret.secretValue!, 'secret')}
                          className="px-2.5 py-1.5 rounded-lg bg-slate-950 hover:bg-slate-800 border border-slate-800 text-xs text-slate-300 inline-flex items-center gap-1.5 cursor-pointer"
                        >
                          {copiedField === 'secret' ? (
                            <Check className="w-3.5 h-3.5 text-emerald-400" />
                          ) : (
                            <Copy className="w-3.5 h-3.5" />
                          )}
                          <span>{copiedField === 'secret' ? 'Copied' : 'Copy'}</span>
                        </button>
                      </div>
                    </div>
                  )}

                  {selectedSecret.url && (
                    <div className="p-4 flex items-center justify-between gap-4">
                      <div className="min-w-0">
                        <span className="text-[11px] font-mono uppercase text-slate-500 block">
                          Endpoint / URI
                        </span>
                        <span className="text-xs font-mono text-blue-400 break-all">
                          {selectedSecret.url}
                        </span>
                      </div>
                      <button
                        onClick={() => copyToClipboard(selectedSecret.url!, 'url')}
                        className="px-2.5 py-1.5 rounded-lg bg-slate-950 hover:bg-slate-800 border border-slate-800 text-xs text-slate-300 inline-flex items-center gap-1.5 shrink-0 cursor-pointer"
                      >
                        <Globe className="w-3.5 h-3.5" />
                        <span>{copiedField === 'url' ? 'Copied' : 'Copy URI'}</span>
                      </button>
                    </div>
                  )}
                </div>
              )}

              {/* Decrypted Note Body */}
              <div className="bg-slate-900/50 border border-slate-800 rounded-2xl p-5 space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono uppercase text-slate-400">
                    Decrypted Note Payload
                  </span>
                  <button
                    onClick={() => copyToClipboard(selectedSecret.content, 'content')}
                    className="text-xs font-mono text-slate-400 hover:text-slate-200 inline-flex items-center gap-1 cursor-pointer"
                  >
                    <Copy className="w-3 h-3" />
                    <span>{copiedField === 'content' ? 'Copied' : 'Copy Note'}</span>
                  </button>
                </div>
                <pre className="text-sm font-mono text-slate-200 whitespace-pre-wrap leading-relaxed">
                  {selectedSecret.content || 'No additional notes attached to this record.'}
                </pre>
              </div>

              {/* Tags & Cryptographic Metadata */}
              <div className="flex flex-wrap items-center justify-between gap-4 pt-2 text-xs text-slate-500 font-mono">
                <div className="flex flex-wrap gap-1.5">
                  {selectedSecret.tags.map((t) => (
                    <span
                      key={t}
                      className="px-2.5 py-1 rounded-md bg-slate-900 border border-slate-800 text-slate-400"
                    >
                      #{t}
                    </span>
                  ))}
                </div>
                <span>Record ID: {selectedSecret.id}</span>
              </div>
            </div>
          )}
        </main>
      </div>
    </div>
  );
}
