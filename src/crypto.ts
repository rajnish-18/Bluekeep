export interface EncryptedEnvelope {
  v: 1;
  alg: 'AES-256-GCM';
  kdf: 'PBKDF2-SHA256';
  iter: number;
  salt: string; // base64
  iv: string; // base64
  ciphertext: string; // base64 (includes 128-bit GCM auth tag)
}

export interface VaultSecret {
  id: string;
  title: string;
  category: 'note' | 'credential' | 'api-key' | 'ssh-key';
  username?: string;
  secretValue?: string;
  url?: string;
  content: string;
  tags: string[];
  pinned: boolean;
  createdAt: string;
  updatedAt: string;
}

const PBKDF2_ITERATIONS = 250_000;

function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function base64ToBytes(base64: string): Uint8Array {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

export async function deriveKey(
  passphrase: string,
  salt: Uint8Array,
  iterations = PBKDF2_ITERATIONS
): Promise<CryptoKey> {
  const enc = new TextEncoder();
  const keyMaterial = await window.crypto.subtle.importKey(
    'raw',
    enc.encode(passphrase),
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );

  return window.crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt as BufferSource,
      iterations,
      hash: 'SHA-256',
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

export async function encryptPayload(
  plaintext: string,
  passphrase: string
): Promise<EncryptedEnvelope> {
  const salt = window.crypto.getRandomValues(new Uint8Array(16));
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(passphrase, salt, PBKDF2_ITERATIONS);

  const enc = new TextEncoder();
  const encoded = enc.encode(plaintext);

  const encryptedBuffer = await window.crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: iv as BufferSource,
      tagLength: 128,
    },
    key,
    encoded
  );

  return {
    v: 1,
    alg: 'AES-256-GCM',
    kdf: 'PBKDF2-SHA256',
    iter: PBKDF2_ITERATIONS,
    salt: bytesToBase64(salt),
    iv: bytesToBase64(iv),
    ciphertext: bytesToBase64(new Uint8Array(encryptedBuffer)),
  };
}

export async function decryptPayload(
  envelope: EncryptedEnvelope,
  passphrase: string
): Promise<string> {
  const salt = base64ToBytes(envelope.salt);
  const iv = base64ToBytes(envelope.iv);
  const ciphertext = base64ToBytes(envelope.ciphertext);
  const key = await deriveKey(passphrase, salt, envelope.iter || PBKDF2_ITERATIONS);

  const decryptedBuffer = await window.crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: iv as BufferSource,
      tagLength: 128,
    },
    key,
    ciphertext as BufferSource
  );

  const dec = new TextDecoder();
  return dec.decode(decryptedBuffer);
}

export function generateHighEntropySecret(
  length = 24,
  options = { uppercase: true, lowercase: true, digits: true, symbols: true }
): string {
  let charset = '';
  if (options.lowercase) charset += 'abcdefghijkmnopqrstuvwxyz';
  if (options.uppercase) charset += 'ABCDEFGHJKLMNPQRSTUVWXYZ';
  if (options.digits) charset += '23456789';
  if (options.symbols) charset += '!@#$%^&*()-_=+[]{}|;:,.<>?';
  if (!charset) charset = 'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789';

  const randomValues = new Uint32Array(length);
  window.crypto.getRandomValues(randomValues);
  let result = '';
  for (let i = 0; i < length; i++) {
    result += charset[randomValues[i] % charset.length];
  }
  return result;
}

export function calculateEntropyBits(secret: string): number {
  if (!secret) return 0;
  let pool = 0;
  if (/[a-z]/.test(secret)) pool += 26;
  if (/[A-Z]/.test(secret)) pool += 26;
  if (/[0-9]/.test(secret)) pool += 10;
  if (/[^a-zA-Z0-9]/.test(secret)) pool += 32;
  if (pool === 0) return 0;
  return Math.round(secret.length * Math.log2(pool));
}
