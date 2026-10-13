/**
 * Bitwarden-compatible cryptography implementation using Web Crypto API.
 * Adapted from NodeWarden's webapp crypto module for server-side use in Workers.
 */

export function bytesToBase64(bytes: Uint8Array): string {
  let s = '';
  for (let i = 0; i < bytes.length; i += 1) s += String.fromCharCode(bytes[i]);
  return btoa(s);
}

export function base64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) out[i] = bin.charCodeAt(i);
  return out;
}

export function concatBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

function toBuffer(bytes: Uint8Array): ArrayBuffer {
  return new Uint8Array(bytes).buffer;
}

// --- PBKDF2 ---
export async function pbkdf2(
  password: string | Uint8Array,
  salt: string | Uint8Array,
  iterations: number,
  keyLen: number,
): Promise<Uint8Array> {
  const pwdBytes = typeof password === 'string' ? new TextEncoder().encode(password) : password;
  const saltBytes = typeof salt === 'string' ? new TextEncoder().encode(salt) : salt;
  const subtle = crypto.subtle;
  const key = await subtle.importKey('raw', toBuffer(pwdBytes), 'PBKDF2', false, ['deriveBits']);
  const bits = await subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt: toBuffer(saltBytes), iterations },
    key,
    keyLen * 8,
  );
  return new Uint8Array(bits);
}

// --- HKDF-Expand (no extract step, used for key stretching) ---
export async function hkdfExpand(prk: Uint8Array, info: string, length: number): Promise<Uint8Array> {
  const infoBytes = new TextEncoder().encode(info);
  const subtle = crypto.subtle;
  const key = await subtle.importKey('raw', toBuffer(prk), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const result = new Uint8Array(length);
  let previous = new Uint8Array(0);
  let offset = 0;
  let counter = 1;

  while (offset < length) {
    const input = new Uint8Array(previous.length + infoBytes.length + 1);
    input.set(previous, 0);
    input.set(infoBytes, previous.length);
    input[input.length - 1] = counter & 0xff;
    previous = new Uint8Array(await subtle.sign('HMAC', key, toBuffer(input)));
    const copyLen = Math.min(previous.length, length - offset);
    result.set(previous.slice(0, copyLen), offset);
    offset += copyLen;
    counter += 1;
  }

  return result;
}

// --- HMAC-SHA256 ---
async function hmacSha256(keyBytes: Uint8Array, dataBytes: Uint8Array): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey('raw', toBuffer(keyBytes), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', key, toBuffer(dataBytes)));
}

// --- AES-CBC ---
async function encryptAesCbc(data: Uint8Array, key: Uint8Array, iv: Uint8Array): Promise<Uint8Array> {
  const cryptoKey = await crypto.subtle.importKey('raw', toBuffer(key), { name: 'AES-CBC' }, false, ['encrypt']);
  return new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-CBC', iv: toBuffer(iv) }, cryptoKey, toBuffer(data)));
}

async function decryptAesCbc(data: Uint8Array, key: Uint8Array, iv: Uint8Array): Promise<Uint8Array> {
  const cryptoKey = await crypto.subtle.importKey('raw', toBuffer(key), { name: 'AES-CBC' }, false, ['decrypt']);
  return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-CBC', iv: toBuffer(iv) }, cryptoKey, toBuffer(data)));
}

export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= a[i] ^ b[i];
  return diff === 0;
}

// --- Bitwarden encrypt/decrypt (type 2: AesCbc256_HmacSha256_B64) ---
// Format: "2.<base64(iv)>|<base64(ciphertext)>|<base64(mac)>"

export async function encryptBw(data: Uint8Array, encKey: Uint8Array, macKey: Uint8Array): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(16));
  const cipher = await encryptAesCbc(data, encKey, iv);
  const mac = await hmacSha256(macKey, concatBytes(iv, cipher));
  return `2.${bytesToBase64(iv)}|${bytesToBase64(cipher)}|${bytesToBase64(mac)}`;
}

interface ParsedCipherString {
  type: number;
  iv: Uint8Array;
  ct: Uint8Array;
  mac: Uint8Array | null;
}

function parseCipherString(s: string): ParsedCipherString {
  if (!s || typeof s !== 'string') throw new Error('invalid encrypted string');
  const p = s.indexOf('.');
  if (p <= 0) throw new Error('invalid encrypted string');
  const type = Number(s.slice(0, p));
  const body = s.slice(p + 1);
  const parts = body.split('|');
  if (type === 2 && parts.length === 3) {
    return { type: 2, iv: base64ToBytes(parts[0]), ct: base64ToBytes(parts[1]), mac: base64ToBytes(parts[2]) };
  }
  if ((type === 0 || type === 1 || type === 4) && parts.length >= 2) {
    return { type, iv: base64ToBytes(parts[0]), ct: base64ToBytes(parts[1]), mac: null };
  }
  throw new Error('unsupported enc type');
}

export async function decryptBw(cipherString: string, encKey: Uint8Array, macKey?: Uint8Array): Promise<Uint8Array> {
  const parsed = parseCipherString(cipherString);
  if (parsed.type === 2 && macKey && parsed.mac) {
    const expected = await hmacSha256(macKey, concatBytes(parsed.iv, parsed.ct));
    if (!constantTimeEqual(expected, parsed.mac)) throw new Error('MAC mismatch');
  }
  return decryptAesCbc(parsed.ct, encKey, parsed.iv);
}

export async function decryptStr(cipherString: string | null | undefined, encKey: Uint8Array, macKey?: Uint8Array): Promise<string> {
  if (!cipherString || typeof cipherString !== 'string') return '';
  const plain = await decryptBw(cipherString, encKey, macKey);
  return new TextDecoder().decode(plain);
}

// --- Vault key unlocking ---
// masterKey = PBKDF2(masterPassword, email, iterations, 32)
// loginHash = PBKDF2(masterKey, masterPassword, 1, 32) → base64 (sent as "password" to login)
// encKey = HKDF-Expand(masterKey, "enc", 32)
// macKey = HKDF-Expand(masterKey, "mac", 32)
// symKey = decryptBw(protectedKey, encKey, macKey) → 64 bytes
// symEncKey = symKey[0:32], symMacKey = symKey[32:64]

export async function deriveMasterKey(email: string, password: string, iterations: number): Promise<Uint8Array> {
  return pbkdf2(password, email.toLowerCase(), iterations, 32);
}

export async function deriveLoginHash(masterKey: Uint8Array, password: string): Promise<string> {
  const hash = await pbkdf2(masterKey, password, 1, 32);
  return bytesToBase64(hash);
}

export interface VaultKeys {
  symEncKey: Uint8Array;
  symMacKey: Uint8Array;
  symEncKeyB64: string;
  symMacKeyB64: string;
}

export async function unlockVaultKey(protectedKey: string, masterKey: Uint8Array): Promise<VaultKeys> {
  const encKey = await hkdfExpand(masterKey, 'enc', 32);
  const macKey = await hkdfExpand(masterKey, 'mac', 32);
  const keyBytes = await decryptBw(protectedKey, encKey, macKey);
  if (!keyBytes || keyBytes.length < 64) throw new Error('Invalid profile key');
  const symEncKey = keyBytes.slice(0, 32);
  const symMacKey = keyBytes.slice(32, 64);
  return {
    symEncKey,
    symMacKey,
    symEncKeyB64: bytesToBase64(symEncKey),
    symMacKeyB64: bytesToBase64(symMacKey),
  };
}

// --- TOTP ---
function base32ToBytes(input: string): Uint8Array {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const clean = input.toUpperCase().replace(/[^A-Z2-7]/g, '');
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (let i = 0; i < clean.length; i += 1) {
    const idx = alphabet.indexOf(clean.charAt(i));
    if (idx < 0) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return new Uint8Array(out);
}

export async function calcTotp(rawSecret: string, nowMs: number = Date.now()): Promise<{ code: string; remain: number; period: number } | null> {
  const secret = rawSecret.trim().toUpperCase().replace(/[\s-]/g, '').replace(/=+$/g, '');
  if (!secret) return null;

  // Parse otpauth URI if present
  let totpSecret = secret;
  let algorithm: 'SHA-1' | 'SHA-256' | 'SHA-512' = 'SHA-1';
  let digits = 6;
  let period = 30;

  if (rawSecret.trim().toLowerCase().startsWith('otpauth://')) {
    try {
      const u = new URL(rawSecret.trim());
      totpSecret = (u.searchParams.get('secret') || '').toUpperCase().replace(/[\s-]/g, '').replace(/=+$/g, '');
      const alg = (u.searchParams.get('algorithm') || 'SHA1').toUpperCase().replace('-', '');
      if (alg === 'SHA256') algorithm = 'SHA-256';
      else if (alg === 'SHA512') algorithm = 'SHA-512';
      digits = Number(u.searchParams.get('digits') || 6);
      period = Number(u.searchParams.get('period') || 30);
    } catch {
      // fall through with defaults
    }
  }

  if (!totpSecret) return null;
  const keyBytes = base32ToBytes(totpSecret);
  if (!keyBytes.length) return null;

  const epoch = Math.floor(nowMs / 1000);
  const counter = Math.floor(epoch / period);
  const remain = period - (epoch % period);

  const message = new Uint8Array(8);
  let c = counter;
  for (let i = 7; i >= 0; i -= 1) {
    message[i] = c & 0xff;
    c = Math.floor(c / 256);
  }

  const key = await crypto.subtle.importKey('raw', toBuffer(keyBytes), { name: 'HMAC', hash: algorithm }, false, ['sign']);
  const hs = new Uint8Array(await crypto.subtle.sign('HMAC', key, toBuffer(message)));
  const offset = hs[hs.length - 1] & 0x0f;
  const bin = ((hs[offset] & 0x7f) << 24) | ((hs[offset + 1] & 0xff) << 16) | ((hs[offset + 2] & 0xff) << 8) | (hs[offset + 3] & 0xff);
  const code = (bin % 10 ** digits).toString().padStart(digits, '0');
  return { code, remain, period };
}

// --- Password generator ---
export function generatePassword(options: {
  length?: number;
  uppercase?: boolean;
  lowercase?: boolean;
  numbers?: boolean;
  special?: boolean;
  avoidAmbiguous?: boolean;
}): string {
  const length = Math.max(4, Math.min(128, options.length ?? 16));
  let charset = '';
  const upper = 'ABCDEFGHJKLMNPQRSTUVWXYZ';
  const lower = 'abcdefghijkmnpqrstuvwxyz';
  const nums = '23456789';
  const special = '!@#$%^&*';
  const ambiguous = 'ILl1O0';

  if (options.uppercase !== false) charset += options.avoidAmbiguous ? upper : 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  if (options.lowercase !== false) charset += options.avoidAmbiguous ? lower : 'abcdefghijklmnopqrstuvwxyz';
  if (options.numbers !== false) charset += options.avoidAmbiguous ? nums : '0123456789';
  if (options.special) charset += special;
  if (!charset) charset = lower + nums;

  // Rejection sampling to eliminate modulo bias
  const limit = 256 - (256 % charset.length);
  const randomBytes = crypto.getRandomValues(new Uint8Array(length * 2));
  let result = '';
  let i = 0;
  while (result.length < length && i < randomBytes.length) {
    const val = randomBytes[i++];
    if (val >= limit) continue;
    result += charset[val % charset.length];
  }
  // Fallback: if we ran out of bytes (extremely unlikely), fill with biased sampling
  while (result.length < length) {
    const val = crypto.getRandomValues(new Uint8Array(1))[0];
    if (val < limit) result += charset[val % charset.length];
  }
  return result;
}
