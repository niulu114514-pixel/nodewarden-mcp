/** NodeWarden API client — handles authentication and vault operations.
 *
 * Security features:
 * - Session cached in-memory only (never persisted to KV)
 * - Sync response cached in KV (encrypted data, 2-min TTL) + in-memory (30s)
 * - All fetch calls have 15s timeout to prevent hanging
 * - Write operations invalidate the sync cache
 * - Individual field decryption failures are caught (returns "[decryption failed]")
 */

import {
  base64ToBytes,
  deriveLoginHash,
  deriveMasterKey,
  decryptBw,
  decryptStr,
  encryptBw,
  unlockVaultKey,
  type VaultKeys,
} from './crypto';
import { getCachedSync, setCachedSync, invalidateCachedSync } from './sync-cache';
import type {
  Cipher,
  DecryptedCipher,
  Folder,
  PreloginResponse,
  SessionState,
  SyncResponse,
  TokenResponse,
} from './types';

const FETCH_TIMEOUT_MS = 15_000;
const SYNC_MEM_CACHE_TTL = 30_000; // 30 seconds in-memory
const CLIENT_REFRESH_MS = 50 * 60 * 1000; // refresh client every 50 minutes

export class NodeWardenClient {
  private baseUrl: string;
  private email: string;
  private masterPassword: string;
  private kv: KVNamespace;
  private session: SessionState | null = null;
  private syncCache: SyncResponse | null = null;
  private syncCacheTime = 0;
  // Decrypted cipher cache — keyed by cipher ID + revisionDate for staleness detection
  private decryptedCache: Map<string, DecryptedCipher> = new Map();
  private decryptedFoldersCache: Map<string, string> = new Map();
  readonly expiresAt: number;

  constructor(baseUrl: string, email: string, masterPassword: string, kv: KVNamespace) {
    this.baseUrl = baseUrl.replace(/\/+$/, '');
    this.email = email.trim().toLowerCase();
    this.masterPassword = masterPassword;
    this.kv = kv;
    this.expiresAt = Date.now() + CLIENT_REFRESH_MS;
  }

  private async fetchApi(path: string, options: RequestInit = {}): Promise<Response> {
    const url = `${this.baseUrl}${path}`;
    const headers = new Headers(options.headers);
    if (this.session?.accessToken) {
      headers.set('Authorization', `Bearer ${this.session.accessToken}`);
    }
    if (!headers.has('Content-Type') && options.body) {
      headers.set('Content-Type', 'application/json');
    }
    return fetch(url, {
      ...options,
      headers,
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    });
  }

  async authenticate(): Promise<void> {
    if (this.session && Date.now() < this.session.expiresAt) {
      return;
    }

    // Step 1: Prelogin to get KDF parameters
    const preloginResp = await fetch(`${this.baseUrl}/identity/accounts/prelogin`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: this.email }),
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    });
    if (!preloginResp.ok) {
      throw new Error(`Authentication failed (${preloginResp.status})`);
    }
    const prelogin = (await preloginResp.json()) as PreloginResponse;
    const iterations = prelogin.kdfIterations || 600000;

    // Step 2: Derive master key and login hash
    const masterKey = await deriveMasterKey(this.email, this.masterPassword, iterations);
    const loginHash = await deriveLoginHash(masterKey, this.masterPassword);

    // Step 3: Login to get access token
    const body = new URLSearchParams();
    body.set('grant_type', 'password');
    body.set('username', this.email);
    body.set('password', loginHash);
    body.set('scope', 'api offline_access');
    body.set('deviceIdentifier', 'nodewarden-mcp-server');
    body.set('deviceName', 'NodeWarden MCP Server');
    body.set('deviceType', '14');

    const tokenResp = await fetch(`${this.baseUrl}/identity/connect/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString(),
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    });
    if (!tokenResp.ok) {
      throw new Error(`Authentication failed (${tokenResp.status})`);
    }
    const token = (await tokenResp.json()) as TokenResponse;

    // Step 4: Unlock vault key
    const vaultKeys = await unlockVaultKey(token.Key, masterKey);

    this.session = {
      accessToken: token.access_token,
      refreshToken: token.refresh_token || null,
      protectedKey: token.Key,
      vaultKeys: {
        symEncKeyB64: vaultKeys.symEncKeyB64,
        symMacKeyB64: vaultKeys.symMacKeyB64,
      },
      expiresAt: Date.now() + (token.expires_in - 60) * 1000,
    };
  }

  private getEncKey(): Uint8Array {
    if (!this.session) throw new Error('Not authenticated');
    return base64ToBytes(this.session.vaultKeys.symEncKeyB64);
  }

  private getMacKey(): Uint8Array {
    if (!this.session) throw new Error('Not authenticated');
    return base64ToBytes(this.session.vaultKeys.symMacKeyB64);
  }

  async getVaultKeys(): Promise<VaultKeys> {
    await this.authenticate();
    return {
      symEncKey: this.getEncKey(),
      symMacKey: this.getMacKey(),
      symEncKeyB64: this.session!.vaultKeys.symEncKeyB64,
      symMacKeyB64: this.session!.vaultKeys.symMacKeyB64,
    };
  }

  // --- Sync (get all vault data) with two-layer caching ---
  async sync(): Promise<SyncResponse> {
    await this.authenticate();

    // Layer 1: in-memory cache (30s)
    const now = Date.now();
    if (this.syncCache && now - this.syncCacheTime < SYNC_MEM_CACHE_TTL) {
      return this.syncCache;
    }

    // Layer 2: KV cache (2 min TTL)
    const kvCached = await getCachedSync(this.kv, this.email);
    if (kvCached) {
      this.syncCache = kvCached;
      this.syncCacheTime = now;
      return kvCached;
    }

    // Layer 3: fetch from NodeWarden API
    const resp = await this.fetchApi('/api/sync');
    if (!resp.ok) throw new Error(`Sync failed (${resp.status})`);
    const data = (await resp.json()) as SyncResponse;

    // Update both caches
    this.syncCache = data;
    this.syncCacheTime = now;
    await setCachedSync(this.kv, this.email, data);

    return data;
  }

  /** Invalidate all caches (call after write operations). */
  async invalidateCache(): Promise<void> {
    this.syncCache = null;
    this.syncCacheTime = 0;
    this.decryptedCache.clear();
    this.decryptedFoldersCache.clear();
    await invalidateCachedSync(this.kv, this.email);
  }

  // --- Cipher operations ---
  async listCiphers(): Promise<Cipher[]> {
    const syncData = await this.sync();
    return (syncData.ciphers || []).filter((c) => !c.deletedDate);
  }

  /** Batch-decrypt all ciphers with caching. Uses revisionDate for staleness detection.
   * This is the primary method tools should call — far faster than decrypting one-by-one. */
  async listDecryptedCiphers(): Promise<DecryptedCipher[]> {
    const [ciphers, folders] = await Promise.all([
      this.listCiphers(),
      this.listFolders(),
    ]);
    return Promise.all(ciphers.map((c) => this.decryptCipher(c, folders)));
  }

  /** Batch-decrypt trashed ciphers with caching. */
  async listDecryptedTrashed(): Promise<DecryptedCipher[]> {
    const [trash, folders] = await Promise.all([
      this.listTrashedCiphers(),
      this.listFolders(),
    ]);
    return Promise.all(trash.map((c) => this.decryptCipher(c, folders)));
  }

  async getCipher(id: string): Promise<Cipher> {
    await this.authenticate();
    const resp = await this.fetchApi(`/api/ciphers/${id}`);
    if (!resp.ok) throw new Error(`Get cipher failed (${resp.status})`);
    return resp.json() as Promise<Cipher>;
  }

  async createCipher(cipher: Partial<Cipher>): Promise<Cipher> {
    await this.authenticate();
    const resp = await this.fetchApi('/api/ciphers', {
      method: 'POST',
      body: JSON.stringify(cipher),
    });
    if (!resp.ok) throw new Error(`Create cipher failed (${resp.status})`);
    const result = await resp.json() as Cipher;
    await this.invalidateCache();
    return result;
  }

  async updateCipher(id: string, cipher: Partial<Cipher>): Promise<Cipher> {
    await this.authenticate();
    const resp = await this.fetchApi(`/api/ciphers/${id}`, {
      method: 'PUT',
      body: JSON.stringify(cipher),
    });
    if (!resp.ok) throw new Error(`Update cipher failed (${resp.status})`);
    const result = await resp.json() as Cipher;
    await this.invalidateCache();
    return result;
  }

  // Soft delete: move cipher to recycle bin (Bitwarden API: PUT /api/ciphers/{id}/delete)
  async softDeleteCipher(id: string): Promise<void> {
    await this.authenticate();
    const resp = await this.fetchApi(`/api/ciphers/${id}/delete`, {
      method: 'PUT',
    });
    if (!resp.ok) throw new Error(`Soft delete cipher failed (${resp.status})`);
    await this.invalidateCache();
  }

  // Permanent delete: remove cipher completely (Bitwarden API: DELETE /api/ciphers/{id})
  async permanentDeleteCipher(id: string): Promise<void> {
    await this.authenticate();
    const resp = await this.fetchApi(`/api/ciphers/${id}`, {
      method: 'DELETE',
    });
    if (!resp.ok) throw new Error(`Permanent delete cipher failed (${resp.status})`);
    await this.invalidateCache();
  }

  // Restore cipher from recycle bin (Bitwarden API: PUT /api/ciphers/{id}/restore)
  async restoreCipher(id: string): Promise<Cipher> {
    await this.authenticate();
    const resp = await this.fetchApi(`/api/ciphers/${id}/restore`, {
      method: 'PUT',
    });
    if (!resp.ok) throw new Error(`Restore cipher failed (${resp.status})`);
    const result = await resp.json() as Cipher;
    await this.invalidateCache();
    return result;
  }

  // List items in the recycle bin (deleted items from sync)
  async listTrashedCiphers(): Promise<Cipher[]> {
    const syncData = await this.sync();
    return (syncData.ciphers || []).filter((c) => c.deletedDate);
  }

  // Purge all items from recycle bin (Bitwarden API: POST /api/ciphers/purge)
  async purgeRecycleBin(): Promise<void> {
    await this.authenticate();
    const resp = await this.fetchApi('/api/ciphers/purge', {
      method: 'POST',
    });
    if (!resp.ok) throw new Error(`Purge recycle bin failed (${resp.status})`);
    await this.invalidateCache();
  }

  // Unified delete: soft delete (recycle bin) or permanent delete based on flag
  async deleteCipher(id: string, permanent: boolean = false): Promise<void> {
    if (permanent) {
      await this.permanentDeleteCipher(id);
    } else {
      await this.softDeleteCipher(id);
    }
  }

  // --- Folder operations ---
  async listFolders(): Promise<Folder[]> {
    const syncData = await this.sync();
    return syncData.folders || [];
  }

  /** Decrypt a folder name using vault keys (with caching). */
  async decryptFolderName(folder: Folder): Promise<string> {
    const cached = this.decryptedFoldersCache.get(folder.id);
    if (cached !== undefined) return cached;
    const encKey = this.getEncKey();
    const macKey = this.getMacKey();
    const name = await decryptStr(folder.name, encKey, macKey).catch(() => '');
    this.decryptedFoldersCache.set(folder.id, name);
    return name;
  }

  async createFolder(name: string): Promise<Folder> {
    await this.authenticate();
    const encKey = this.getEncKey();
    const macKey = this.getMacKey();
    const encryptedName = await encryptBw(new TextEncoder().encode(name), encKey, macKey);
    const resp = await this.fetchApi('/api/folders', {
      method: 'POST',
      body: JSON.stringify({ name: encryptedName }),
    });
    if (!resp.ok) throw new Error(`Create folder failed (${resp.status})`);
    const result = await resp.json() as Folder;
    await this.invalidateCache();
    return result;
  }

  // --- Encryption helpers for creating/updating ciphers ---
  async encryptField(value: string): Promise<string> {
    const encKey = this.getEncKey();
    const macKey = this.getMacKey();
    return encryptBw(new TextEncoder().encode(value), encKey, macKey);
  }

  // --- Decrypt a cipher's fields with fault tolerance + caching ---
  async decryptCipher(cipher: Cipher, folders: Folder[] = []): Promise<DecryptedCipher> {
    // Cache check: use id + revisionDate as composite key for staleness detection
    const cacheKey = `${cipher.id}:${cipher.revisionDate || ''}`;
    const cached = this.decryptedCache.get(cacheKey);
    if (cached) return cached;

    const encKey = this.getEncKey();
    const macKey = this.getMacKey();

    // Check for item-level key
    let itemEnc = encKey;
    let itemMac = macKey;
    if (cipher.key) {
      try {
        const itemKey = await decryptBw(cipher.key, encKey, macKey);
        if (itemKey.length >= 64) {
          itemEnc = itemKey.slice(0, 32);
          itemMac = itemKey.slice(32, 64);
        }
      } catch {
        // Keep user key
      }
    }

    // Safe decrypt helper — returns "[decryption failed]" on error
    const safeDec = (s: string | null | undefined): Promise<string> =>
      decryptStr(s, itemEnc, itemMac).catch(() => '[decryption failed]');

    const decName = await safeDec(cipher.name);
    const decNotes = await safeDec(cipher.notes);

    const folder = folders.find((f) => f.id === cipher.folderId);
    const folderName = folder ? await decryptStr(folder.name, encKey, macKey).catch(() => '') : '';

    const result: DecryptedCipher = {
      id: cipher.id,
      type: cipher.type,
      name: decName,
      notes: decNotes,
      favorite: cipher.favorite,
      folderId: cipher.folderId,
      folderName: folderName || undefined,
      revisionDate: cipher.revisionDate,
    };

    if (cipher.login) {
      result.login = {
        username: await safeDec(cipher.login.username),
        password: await safeDec(cipher.login.password),
        totp: await safeDec(cipher.login.totp),
        uris: await Promise.all(
          (cipher.login.uris || []).map((u) => safeDec(u.uri)),
        ),
      };
    }

    if (cipher.card) {
      result.card = {
        cardholderName: await safeDec(cipher.card.cardholderName),
        number: await safeDec(cipher.card.number),
        brand: await safeDec(cipher.card.brand),
        expMonth: await safeDec(cipher.card.expMonth),
        expYear: await safeDec(cipher.card.expYear),
        code: await safeDec(cipher.card.code),
      };
    }

    if (cipher.identity) {
      result.identity = {
        title: await safeDec(cipher.identity.title),
        firstName: await safeDec(cipher.identity.firstName),
        middleName: await safeDec(cipher.identity.middleName),
        lastName: await safeDec(cipher.identity.lastName),
        username: await safeDec(cipher.identity.username),
        company: await safeDec(cipher.identity.company),
        ssn: await safeDec(cipher.identity.ssn),
        passportNumber: await safeDec(cipher.identity.passportNumber),
        licenseNumber: await safeDec(cipher.identity.licenseNumber),
        email: await safeDec(cipher.identity.email),
        phone: await safeDec(cipher.identity.phone),
        address1: await safeDec(cipher.identity.address1),
        address2: await safeDec(cipher.identity.address2),
        address3: await safeDec(cipher.identity.address3),
        city: await safeDec(cipher.identity.city),
        state: await safeDec(cipher.identity.state),
        postalCode: await safeDec(cipher.identity.postalCode),
        country: await safeDec(cipher.identity.country),
      };
    }

    if (cipher.fields && cipher.fields.length > 0) {
      result.fields = await Promise.all(
        cipher.fields.map(async (field) => ({
          name: await safeDec(field.name),
          value: await safeDec(field.value),
          type: field.type,
        })),
      );
    }

    // Store in cache for future calls
    this.decryptedCache.set(cacheKey, result);
    return result;
  }

  // Toggle favorite status on a cipher (Bitwarden API: PUT /api/ciphers/{id})
  async toggleFavorite(id: string): Promise<boolean> {
    await this.authenticate();
    const cipher = await this.getCipher(id);
    const newFavorite = !cipher.favorite;

    const payload: Record<string, unknown> = {
      type: cipher.type,
      name: cipher.name,
      notes: cipher.notes,
      folderId: cipher.folderId,
      favorite: newFavorite,
      fields: cipher.fields || [],
    };
    if (cipher.login) payload.login = cipher.login;
    if (cipher.card) payload.card = cipher.card;
    if (cipher.identity) payload.identity = cipher.identity;

    const resp = await this.fetchApi(`/api/ciphers/${id}`, {
      method: 'PUT',
      body: JSON.stringify(payload),
    });
    if (!resp.ok) throw new Error(`Toggle favorite failed (${resp.status})`);
    await this.invalidateCache();
    return newFavorite;
  }

  // --- Build encrypted card cipher for creation (type 3) ---
  async buildCreateCardPayload(params: {
    name: string;
    cardholderName?: string;
    number?: string;
    brand?: string;
    expMonth?: string;
    expYear?: string;
    code?: string;
    notes?: string;
    folderId?: string;
  }): Promise<Partial<Cipher>> {
    const encKey = this.getEncKey();
    const macKey = this.getMacKey();

    const encName = await encryptBw(new TextEncoder().encode(params.name), encKey, macKey);
    const encNotes = params.notes ? await encryptBw(new TextEncoder().encode(params.notes), encKey, macKey) : null;

    return {
      type: 3,
      name: encName,
      notes: encNotes,
      folderId: params.folderId || null,
      favorite: false,
      card: {
        cardholderName: params.cardholderName ? await encryptBw(new TextEncoder().encode(params.cardholderName), encKey, macKey) : null,
        number: params.number ? await encryptBw(new TextEncoder().encode(params.number), encKey, macKey) : null,
        brand: params.brand ? await encryptBw(new TextEncoder().encode(params.brand), encKey, macKey) : null,
        expMonth: params.expMonth ? await encryptBw(new TextEncoder().encode(params.expMonth), encKey, macKey) : null,
        expYear: params.expYear ? await encryptBw(new TextEncoder().encode(params.expYear), encKey, macKey) : null,
        code: params.code ? await encryptBw(new TextEncoder().encode(params.code), encKey, macKey) : null,
      },
    };
  }

  // --- Build encrypted secure note cipher for creation (type 2) ---
  async buildCreateSecureNotePayload(params: {
    name: string;
    notes?: string;
    folderId?: string;
  }): Promise<Partial<Cipher>> {
    const encKey = this.getEncKey();
    const macKey = this.getMacKey();

    const encName = await encryptBw(new TextEncoder().encode(params.name), encKey, macKey);
    const encNotes = params.notes ? await encryptBw(new TextEncoder().encode(params.notes), encKey, macKey) : null;

    return {
      type: 2,
      name: encName,
      notes: encNotes,
      folderId: params.folderId || null,
      favorite: false,
      secureNote: { type: 0 },
    };
  }

  // --- Build encrypted cipher for creation ---
  async buildCreateCipherPayload(params: {
    name: string;
    username?: string;
    password?: string;
    uri?: string;
    notes?: string;
    folderId?: string;
    type?: number;
    totp?: string;
  }): Promise<Partial<Cipher>> {
    const encKey = this.getEncKey();
    const macKey = this.getMacKey();

    const encName = await encryptBw(new TextEncoder().encode(params.name), encKey, macKey);
    const encNotes = params.notes ? await encryptBw(new TextEncoder().encode(params.notes), encKey, macKey) : null;

    const cipherType = params.type ?? 1;

    const payload: Partial<Cipher> = {
      type: cipherType,
      name: encName,
      notes: encNotes,
      folderId: params.folderId || null,
      favorite: false,
    };

    if (cipherType === 1) {
      const encUsername = params.username ? await encryptBw(new TextEncoder().encode(params.username), encKey, macKey) : null;
      const encPassword = params.password ? await encryptBw(new TextEncoder().encode(params.password), encKey, macKey) : null;
      const encTotp = params.totp ? await encryptBw(new TextEncoder().encode(params.totp), encKey, macKey) : null;
      const uris = params.uri ? [{ uri: await encryptBw(new TextEncoder().encode(params.uri), encKey, macKey), match: null }] : null;

      payload.login = {
        username: encUsername,
        password: encPassword,
        totp: encTotp,
        uris,
        fido2Credentials: [],
      };
    }

    return payload;
  }

  // --- Build encrypted cipher for updating ---
  async buildUpdateCipherPayload(cipher: Cipher, params: {
    name?: string;
    username?: string;
    password?: string;
    uri?: string;
    notes?: string;
    folderId?: string;
    // Card fields (type 3)
    cardholderName?: string;
    cardNumber?: string;
    cardBrand?: string;
    cardExpMonth?: string;
    cardExpYear?: string;
    cardCode?: string;
    // Identity fields (type 4)
    identityTitle?: string;
    identityFirstName?: string;
    identityLastName?: string;
    identityEmail?: string;
    identityPhone?: string;
    identityAddress1?: string;
    identityCity?: string;
    identityState?: string;
    identityPostalCode?: string;
    identityCountry?: string;
  }): Promise<Partial<Cipher>> {
    const encKey = this.getEncKey();
    const macKey = this.getMacKey();

    const enc = async (val: string | undefined, existing: string | null): Promise<string | null> =>
      val !== undefined ? (val ? encryptBw(new TextEncoder().encode(val), encKey, macKey) : null) : existing;

    const encName = params.name !== undefined
      ? await encryptBw(new TextEncoder().encode(params.name), encKey, macKey)
      : cipher.name;

    const encNotes = params.notes !== undefined
      ? (params.notes ? await encryptBw(new TextEncoder().encode(params.notes), encKey, macKey) : null)
      : cipher.notes;

    const payload: Partial<Cipher> = {
      type: cipher.type,
      name: encName,
      notes: encNotes,
      folderId: params.folderId !== undefined ? params.folderId : cipher.folderId,
      favorite: cipher.favorite,
    };

    if (cipher.type === 1) {
      const existingLogin = cipher.login || { username: null, password: null, totp: null, uris: null, fido2Credentials: [] };

      const encUsername = await enc(params.username, existingLogin.username);
      const encPassword = await enc(params.password, existingLogin.password);

      let uris = existingLogin.uris;
      if (params.uri !== undefined) {
        uris = params.uri ? [{ uri: await encryptBw(new TextEncoder().encode(params.uri), encKey, macKey), match: null }] : null;
      }

      payload.login = {
        username: encUsername,
        password: encPassword,
        totp: existingLogin.totp,
        uris,
        fido2Credentials: existingLogin.fido2Credentials || [],
      };
    }

    if (cipher.type === 3) {
      const existing = cipher.card || { cardholderName: null, number: null, brand: null, expMonth: null, expYear: null, code: null };
      payload.card = {
        cardholderName: await enc(params.cardholderName, existing.cardholderName),
        number: await enc(params.cardNumber, existing.number),
        brand: await enc(params.cardBrand, existing.brand),
        expMonth: await enc(params.cardExpMonth, existing.expMonth),
        expYear: await enc(params.cardExpYear, existing.expYear),
        code: await enc(params.cardCode, existing.code),
      };
    }

    if (cipher.type === 4) {
      const existing = cipher.identity || {
        title: null, firstName: null, middleName: null, lastName: null,
        username: null, company: null, ssn: null, passportNumber: null,
        licenseNumber: null, email: null, phone: null,
        address1: null, address2: null, address3: null,
        city: null, state: null, postalCode: null, country: null,
      };
      payload.identity = {
        title: await enc(params.identityTitle, existing.title),
        firstName: await enc(params.identityFirstName, existing.firstName),
        middleName: existing.middleName,
        lastName: await enc(params.identityLastName, existing.lastName),
        username: existing.username,
        company: existing.company,
        ssn: existing.ssn,
        passportNumber: existing.passportNumber,
        licenseNumber: existing.licenseNumber,
        email: await enc(params.identityEmail, existing.email),
        phone: await enc(params.identityPhone, existing.phone),
        address1: await enc(params.identityAddress1, existing.address1),
        address2: existing.address2,
        address3: existing.address3,
        city: await enc(params.identityCity, existing.city),
        state: await enc(params.identityState, existing.state),
        postalCode: await enc(params.identityPostalCode, existing.postalCode),
        country: await enc(params.identityCountry, existing.country),
      };
    }

    return payload;
  }
}
