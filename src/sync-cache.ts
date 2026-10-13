/** KV cache utility — stores encrypted sync responses to reduce API load.
 *
 * The sync response from NodeWarden contains encrypted cipher data (still
 * encrypted with the user's vault key). Caching it in KV is safe because
 * the data remains encrypted — decryption only happens in-memory after
 * retrieval, using vault keys that are never persisted to KV.
 *
 * TTL: 2 minutes — balances freshness with performance.
 */

import type { SyncResponse } from './types';

const CACHE_TTL = 120; // seconds
const CACHE_PREFIX = 'sync_cache:';

/** Build a cache key from the user's email (lowercased, trimmed). */
function cacheKey(email: string): string {
  return `${CACHE_PREFIX}${email.trim().toLowerCase()}`;
}

/** Retrieve a cached sync response from KV. Returns null on miss/expiry. */
export async function getCachedSync(kv: KVNamespace, email: string): Promise<SyncResponse | null> {
  try {
    const raw = await kv.get(cacheKey(email));
    if (!raw) return null;
    return JSON.parse(raw) as SyncResponse;
  } catch {
    return null;
  }
}

/** Store a sync response in KV with a short TTL. */
export async function setCachedSync(kv: KVNamespace, email: string, data: SyncResponse): Promise<void> {
  try {
    await kv.put(cacheKey(email), JSON.stringify(data), { expirationTtl: CACHE_TTL });
  } catch {
    // KV write failure is non-fatal — we just skip caching
  }
}

/** Invalidate the cached sync response (call after write operations). */
export async function invalidateCachedSync(kv: KVNamespace, email: string): Promise<void> {
  try {
    await kv.delete(cacheKey(email));
  } catch {
    // Non-fatal
  }
}
