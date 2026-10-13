/** NodeWarden MCP Server — MCP only. No web UI, no navigation.
 *
 * Security design:
 * - Unauthenticated requests get 404 (reveals nothing about the service)
 * - Token comparison uses constant-time equality to prevent timing attacks
 * - Client instance cached globally to avoid re-authentication on every request
 * - Error messages are desensitized — internal details never leak to clients
 * - Only /mcp route exists; everything else returns 404
 * - CORS restricted to configured origins (falls back to * if not set)
 * - Rate limiting: 30 requests/minute per IP via KV (prevents token brute force)
 */

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { WebStandardStreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js';
import { registerTools } from './tools';
import { NodeWardenClient } from './nodewarden-client';
import { constantTimeEqual } from './crypto';
import type { Env } from './types';

// ─── 404 (plain text, reveals nothing) ─────────────────

function notFound(): Response {
  return new Response('Not Found', { status: 404, headers: securityHeaders({ 'Content-Type': 'text/plain' }) });
}

function securityHeaders(initial?: HeadersInit): Headers {
  const headers = new Headers(initial);
  headers.set('Cache-Control', 'no-store');
  headers.set('X-Content-Type-Options', 'nosniff');
  headers.set('Referrer-Policy', 'no-referrer');
  headers.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  return headers;
}

// ─── CORS helpers ──────────────────────────────────────

const CORS_HEADERS: Record<string, string> = {
  'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Authorization, Content-Type, Mcp-Session-Id, Mcp-Protocol-Version, Last-Event-ID, Accept',
  'Access-Control-Expose-Headers': 'Mcp-Session-Id',
};

/** Return the allowed origin for this request, or null if blocked. */
function getAllowedOrigin(request: Request, env: Env): string {
  if (env.ALLOWED_ORIGINS) {
    const allowed = env.ALLOWED_ORIGINS.split(',').map((s) => s.trim());
    const origin = request.headers.get('Origin') || '';
    return allowed.includes(origin) ? origin : '';
  }
  // Fallback: allow all (less secure, but backwards-compatible)
  return '*';
}

// ─── Rate limiting (KV-based, 30 req/min per IP) ───────

const RATE_LIMIT_WINDOW = 60; // seconds
const RATE_LIMIT_MAX = 30; // requests per window

async function checkRateLimit(kv: KVNamespace, ip: string): Promise<boolean> {
  const key = `rl:${ip}`;
  try {
    const raw = await kv.get(key);
    const count = raw ? parseInt(raw, 10) : 0;
    if (count >= RATE_LIMIT_MAX) return false;
    // Increment counter (non-blocking via ctx.waitUntil in caller, but we await here for simplicity)
    await kv.put(key, String(count + 1), { expirationTtl: RATE_LIMIT_WINDOW });
    return true;
  } catch {
    // KV failure — allow request through (fail open, not fail closed)
    return true;
  }
}

// ─── Global client cache ───────────────────────────────

let globalClient: NodeWardenClient | null = null;

async function getClient(env: Env): Promise<NodeWardenClient> {
  if (!env.NODEWARDEN_URL) throw new Error('Configuration missing');
  if (!env.USER_EMAIL) throw new Error('Configuration missing');
  if (!env.MASTER_PASSWORD) throw new Error('Configuration missing');

  // Reuse cached client if still valid
  if (globalClient && Date.now() < globalClient.expiresAt) {
    return globalClient;
  }

  const client = new NodeWardenClient(
    env.NODEWARDEN_URL,
    env.USER_EMAIL,
    env.MASTER_PASSWORD,
    env.KV,
  );
  await client.getVaultKeys();
  globalClient = client;
  return client;
}

// ─── MCP server factory ────────────────────────────────

function createMcpServer(env: Env): McpServer {
  const server = new McpServer({ name: 'nodewarden-mcp', version: '1.0.0' });
  const softDelete = env.SOFT_DELETE !== 'false';
  const getClientFn = () => getClient(env);
  registerTools(server, getClientFn, () => softDelete);
  return server;
}

// ─── Entry point ───────────────────────────────────────

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;
    const origin = getAllowedOrigin(request, env);

    // CORS preflight (needed for MCP clients)
    if (request.method === 'OPTIONS') {
      if (!origin) return notFound();
      return new Response(null, {
        status: 204,
        headers: securityHeaders({ ...CORS_HEADERS, 'Access-Control-Allow-Origin': origin, Vary: 'Origin' }),
      });
    }

    // MCP endpoint — the only route that exists
    if (path === '/mcp' || path.startsWith('/mcp/')) {
      // Rate limiting — check before auth to prevent token brute force
      const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
      const allowed = await checkRateLimit(env.KV, ip);
      if (!allowed) {
        return new Response('Too Many Requests', {
          status: 429,
          headers: securityHeaders({ 'Retry-After': String(RATE_LIMIT_WINDOW) }),
        });
      }

      // Extract bearer token
      const authHeader = request.headers.get('Authorization') || '';
      const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : '';

      // No token configured or token mismatch → 404 (not 401, to hide the endpoint)
      if (!env.MCP_AUTH_TOKEN) {
        return notFound();
      }

      // Constant-time comparison to prevent timing attacks
      const tokenBytes = new TextEncoder().encode(token);
      const expectedBytes = new TextEncoder().encode(env.MCP_AUTH_TOKEN);
      if (!constantTimeEqual(tokenBytes, expectedBytes)) {
        return notFound();
      }

      try {
        const transport = new WebStandardStreamableHTTPServerTransport({ sessionIdGenerator: undefined });
        const server = createMcpServer(env);
        await server.connect(transport);
        const response = await transport.handleRequest(request);
        // Add CORS headers to the MCP response
        if (origin) {
          const headers = new Headers(response.headers);
          headers.set('Access-Control-Allow-Origin', origin);
          headers.set('Vary', 'Origin');
          for (const [name, value] of securityHeaders()) headers.set(name, value);
          return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
        }
        return response;
      } catch (e: unknown) {
        // Log full error server-side; return generic message to client
        console.error('MCP error:', e);
        return new Response(
          JSON.stringify({ jsonrpc: '2.0', error: { code: -32603, message: 'Internal error' }, id: null }),
          { status: 500, headers: securityHeaders({ 'Content-Type': 'application/json' }) },
        );
      }
    }

    // Everything else → 404
    return notFound();
  },
};
