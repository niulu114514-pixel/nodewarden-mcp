/** MCP tool definitions for NodeWarden password management. */

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { NodeWardenClient } from './nodewarden-client';
import { calcTotp, generatePassword } from './crypto';
import type { DecryptedCipher } from './types';

function formatCipherSummary(c: DecryptedCipher): string {
  const typeNames: Record<number, string> = { 1: 'Login', 2: 'SecureNote', 3: 'Card', 4: 'Identity' };
  let line = `[${typeNames[c.type] || 'Unknown'}] ${c.name}`;
  if (c.login?.username) line += ` | user: ${c.login.username}`;
  if (c.login?.uris?.length) line += ` | url: ${c.login.uris.join(', ')}`;
  if (c.folderName) line += ` | folder: ${c.folderName}`;
  if (c.favorite) line += ' | ★';
  return line;
}

function formatCipherDetail(c: DecryptedCipher): string {
  const typeNames: Record<number, string> = { 1: 'Login', 2: 'SecureNote', 3: 'Card', 4: 'Identity' };
  const lines: string[] = [
    `=== ${c.name} ===`,
    `ID: ${c.id}`,
    `Type: ${typeNames[c.type] || 'Unknown'}`,
    `Folder: ${c.folderName || '(none)'}`,
    `Favorite: ${c.favorite ? 'Yes' : 'No'}`,
  ];

  if (c.notes) lines.push(`Notes: ${c.notes}`);

  if (c.login) {
    lines.push('', '--- Login ---');
    if (c.login.username) lines.push(`Username: ${c.login.username}`);
    if (c.login.password) lines.push(`Password: ${c.login.password}`);
    if (c.login.totp) lines.push(`TOTP: ${c.login.totp}`);
    if (c.login.uris?.length) lines.push(`URLs: ${c.login.uris.join(', ')}`);
  }

  if (c.card) {
    lines.push('', '--- Card ---');
    if (c.card.cardholderName) lines.push(`Cardholder: ${c.card.cardholderName}`);
    if (c.card.number) lines.push(`Number: ${c.card.number}`);
    if (c.card.brand) lines.push(`Brand: ${c.card.brand}`);
    if (c.card.expMonth) lines.push(`Exp Month: ${c.card.expMonth}`);
    if (c.card.expYear) lines.push(`Exp Year: ${c.card.expYear}`);
    if (c.card.code) lines.push(`CVV: ${c.card.code}`);
  }

  if (c.identity) {
    lines.push('', '--- Identity ---');
    if (c.identity.title) lines.push(`Title: ${c.identity.title}`);
    if (c.identity.firstName) lines.push(`First Name: ${c.identity.firstName}`);
    if (c.identity.middleName) lines.push(`Middle Name: ${c.identity.middleName}`);
    if (c.identity.lastName) lines.push(`Last Name: ${c.identity.lastName}`);
    if (c.identity.username) lines.push(`Username: ${c.identity.username}`);
    if (c.identity.company) lines.push(`Company: ${c.identity.company}`);
    if (c.identity.ssn) lines.push(`SSN: ${c.identity.ssn}`);
    if (c.identity.passportNumber) lines.push(`Passport: ${c.identity.passportNumber}`);
    if (c.identity.licenseNumber) lines.push(`License: ${c.identity.licenseNumber}`);
    if (c.identity.email) lines.push(`Email: ${c.identity.email}`);
    if (c.identity.phone) lines.push(`Phone: ${c.identity.phone}`);
    if (c.identity.address1) lines.push(`Address1: ${c.identity.address1}`);
    if (c.identity.address2) lines.push(`Address2: ${c.identity.address2}`);
    if (c.identity.address3) lines.push(`Address3: ${c.identity.address3}`);
    if (c.identity.city) lines.push(`City: ${c.identity.city}`);
    if (c.identity.state) lines.push(`State: ${c.identity.state}`);
    if (c.identity.postalCode) lines.push(`Postal: ${c.identity.postalCode}`);
    if (c.identity.country) lines.push(`Country: ${c.identity.country}`);
  }

  if (c.fields && c.fields.length > 0) {
    lines.push('', '--- Custom Fields ---');
    for (const f of c.fields) {
      lines.push(`${f.name}: ${f.value}`);
    }
  }

  if (c.revisionDate) lines.push(`\nLast Modified: ${c.revisionDate}`);

  return lines.join('\n');
}

/** Mask sensitive fields in cipher detail text. */
function maskSensitiveFields(detail: string): string {
  return detail
    .replace(/Password: .*/g, 'Password: [hidden - set include_passwords=true to show]')
    .replace(/TOTP: .*/g, 'TOTP: [hidden - use get_totp tool to retrieve]')
    .replace(/Number: .*/g, 'Number: [hidden]')
    .replace(/CVV: .*/g, 'CVV: [hidden]')
    .replace(/SSN: .*/g, 'SSN: [hidden]')
    .replace(/Passport: .*/g, 'Passport: [hidden]')
    .replace(/License: .*/g, 'License: [hidden]');
}

export function registerTools(
  server: McpServer,
  getClient: () => Promise<NodeWardenClient>,
  getSoftDelete: () => boolean,
): void {
  // --- list_items ---
  server.tool(
    'list_items',
    'List all vault items with decrypted names, usernames, and URLs',
    {},
    async () => {
      const client = await getClient();
      const decrypted = await client.listDecryptedCiphers();

      if (decrypted.length === 0) {
        return { content: [{ type: 'text', text: 'Vault is empty. No items found.' }] };
      }

      const lines = decrypted.map((c, i) => `${i + 1}. ${formatCipherSummary(c)}`);
      return {
        content: [{ type: 'text', text: `Found ${decrypted.length} items:\n\n${lines.join('\n')}` }],
      };
    },
  );

  // --- search_items ---
  server.tool(
    'search_items',
    'Search vault items by name, username, or URL (case-insensitive)',
    {
      query: z.string().min(1).describe('Search query - matches against item name, username, or URL'),
    },
    async ({ query }) => {
      const client = await getClient();
      const decrypted = await client.listDecryptedCiphers();

      const q = query.toLowerCase();
      const matched = decrypted.filter((c) => {
        const name = c.name.toLowerCase();
        const username = c.login?.username?.toLowerCase() || '';
        const uris = c.login?.uris?.join(' ').toLowerCase() || '';
        const notes = c.notes.toLowerCase();
        return name.includes(q) || username.includes(q) || uris.includes(q) || notes.includes(q);
      });

      if (matched.length === 0) {
        return { content: [{ type: 'text', text: `No items found matching "${query}".` }] };
      }

      const lines = matched.map((c, i) => `${i + 1}. ${formatCipherSummary(c)}`);
      return {
        content: [{ type: 'text', text: `Found ${matched.length} items matching "${query}":\n\n${lines.join('\n')}` }],
      };
    },
  );

  // --- get_item ---
  server.tool(
    'get_item',
    'Get full decrypted details of a vault item by ID or name (includes password)',
    {
      id: z.string().optional().describe('Item ID (exact match)'),
      name: z.string().optional().describe('Item name (fuzzy match, returns first match)'),
    },
    async ({ id, name }) => {
      if (!id && !name) {
        return { content: [{ type: 'text', text: 'Error: Either id or name must be provided.' }] };
      }

      const client = await getClient();
      const decrypted = await client.listDecryptedCiphers();

      let target = decrypted.find((c) => c.id === id);
      if (!target && name) {
        target = decrypted.find((c) => c.name.toLowerCase().includes(name!.toLowerCase()));
      }

      if (!target) {
        return { content: [{ type: 'text', text: `Item not found.${id ? ` ID: ${id}` : ''}${name ? ` Name: ${name}` : ''}` }] };
      }

      return { content: [{ type: 'text', text: formatCipherDetail(target) }] };
    },
  );

  // --- create_item ---
  server.tool(
    'create_item',
    'Create a new login item in the vault',
    {
      name: z.string().min(1).describe('Item name (e.g., website name)'),
      username: z.string().optional().describe('Login username'),
      password: z.string().optional().describe('Login password (if omitted, use generate_password first)'),
      uri: z.string().optional().describe('Website URL'),
      notes: z.string().optional().describe('Additional notes'),
      folder_id: z.string().optional().describe('Folder ID (use list_folders to find)'),
      totp: z.string().optional().describe('TOTP secret or otpauth:// URI'),
    },
    async (params) => {
      const client = await getClient();
      const payload = await client.buildCreateCipherPayload({
        name: params.name,
        username: params.username,
        password: params.password,
        uri: params.uri,
        notes: params.notes,
        folderId: params.folder_id,
        totp: params.totp,
      });
      const created = await client.createCipher(payload);
      return {
        content: [{ type: 'text', text: `Created item "${params.name}" with ID: ${created.id}` }],
      };
    },
  );

  // --- update_item ---
  server.tool(
    'update_item',
    'Update an existing vault item (only specified fields are changed)',
    {
      id: z.string().describe('Item ID to update'),
      name: z.string().optional().describe('New item name'),
      username: z.string().optional().describe('New username'),
      password: z.string().optional().describe('New password'),
      uri: z.string().optional().describe('New website URL'),
      notes: z.string().optional().describe('New notes (set to empty string to clear)'),
      folder_id: z.string().optional().describe('New folder ID'),
    },
    async (params) => {
      const client = await getClient();
      const cipher = await client.getCipher(params.id);
      const payload = await client.buildUpdateCipherPayload(cipher, {
        name: params.name,
        username: params.username,
        password: params.password,
        uri: params.uri,
        notes: params.notes,
        folderId: params.folder_id,
      });
      await client.updateCipher(params.id, payload);
      return {
        content: [{ type: 'text', text: `Updated item ${params.id} successfully.` }],
      };
    },
  );

  // --- delete_item (with confirmation gating) ---
  server.tool(
    'delete_item',
    'Delete a vault item. Requires confirm="YES" to proceed. By default, moves to recycle bin (soft delete). Set permanent=true to permanently delete.',
    {
      id: z.string().describe('Item ID to delete'),
      permanent: z.boolean().optional().describe('If true, permanently delete (cannot be undone). If false/omitted, moves to recycle bin.'),
      confirm: z.literal('YES').describe('Must be exactly "YES" to confirm deletion'),
    },
    async ({ id, permanent, confirm }) => {
      if (confirm !== 'YES') {
        return { content: [{ type: 'text', text: 'Deletion cancelled. To confirm, set confirm="YES".' }] };
      }
      const client = await getClient();
      const usePermanent = permanent ?? !getSoftDelete();
      if (usePermanent) {
        await client.deleteCipher(id, true);
        return {
          content: [{ type: 'text', text: `Item ${id} permanently deleted. This cannot be undone.` }],
        };
      } else {
        await client.deleteCipher(id, false);
        return {
          content: [{ type: 'text', text: `Item ${id} moved to recycle bin. Use restore_item to recover, or purge_recycle_bin to permanently remove.` }],
        };
      }
    },
  );

  // --- list_trash ---
  server.tool(
    'list_trash',
    'List all items in the recycle bin (soft-deleted items that can be restored)',
    {},
    async () => {
      const client = await getClient();
      const decrypted = await client.listDecryptedTrashed();
      if (decrypted.length === 0) {
        return { content: [{ type: 'text', text: 'Recycle bin is empty.' }] };
      }
      const lines = decrypted.map((c, i) => `${i + 1}. ${formatCipherSummary(c)}`);
      return {
        content: [{ type: 'text', text: `Recycle bin (${decrypted.length} items):\n\n${lines.join('\n')}` }],
      };
    },
  );

  // --- restore_item ---
  server.tool(
    'restore_item',
    'Restore an item from the recycle bin back to the vault',
    {
      id: z.string().describe('Item ID to restore from recycle bin'),
    },
    async ({ id }) => {
      const client = await getClient();
      await client.restoreCipher(id);
      return {
        content: [{ type: 'text', text: `Item ${id} restored from recycle bin.` }],
      };
    },
  );

  // --- purge_recycle_bin (with confirmation gating) ---
  server.tool(
    'purge_recycle_bin',
    'Permanently delete ALL items in the recycle bin. Requires confirm="YES". This action cannot be undone.',
    {
      confirm: z.literal('YES').describe('Must be exactly "YES" to confirm purge'),
    },
    async ({ confirm }) => {
      if (confirm !== 'YES') {
        return { content: [{ type: 'text', text: 'Purge cancelled. To confirm, set confirm="YES".' }] };
      }
      const client = await getClient();
      await client.purgeRecycleBin();
      return {
        content: [{ type: 'text', text: 'Recycle bin purged. All trashed items have been permanently deleted.' }],
      };
    },
  );

  // --- list_folders ---
  server.tool(
    'list_folders',
    'List all folders in the vault with decrypted names',
    {},
    async () => {
      const client = await getClient();
      const folders = await client.listFolders();
      if (folders.length === 0) {
        return { content: [{ type: 'text', text: 'No folders found.' }] };
      }
      const decFolders = await Promise.all(
        folders.map(async (f) => ({
          id: f.id,
          name: await client.decryptFolderName(f),
        })),
      );
      const lines = decFolders.map((f, i) => `${i + 1}. ${f.name} | ID: ${f.id}`);
      return {
        content: [{ type: 'text', text: `Folders (${decFolders.length}):\n${lines.join('\n')}` }],
      };
    },
  );

  // --- create_folder ---
  server.tool(
    'create_folder',
    'Create a new folder in the vault',
    {
      name: z.string().min(1).describe('Folder name'),
    },
    async ({ name }) => {
      const client = await getClient();
      const folder = await client.createFolder(name);
      return {
        content: [{ type: 'text', text: `Created folder "${name}" with ID: ${folder.id}` }],
      };
    },
  );

  // --- generate_password ---
  server.tool(
    'generate_password',
    'Generate a random secure password',
    {
      length: z.number().int().min(4).max(128).optional().describe('Password length (default: 16)'),
      uppercase: z.boolean().optional().describe('Include uppercase letters (default: true)'),
      lowercase: z.boolean().optional().describe('Include lowercase letters (default: true)'),
      numbers: z.boolean().optional().describe('Include numbers (default: true)'),
      special: z.boolean().optional().describe('Include special characters (default: false)'),
      avoid_ambiguous: z.boolean().optional().describe('Avoid ambiguous characters like 0/O, 1/l (default: true)'),
    },
    async (params) => {
      const password = generatePassword({
        length: params.length,
        uppercase: params.uppercase,
        lowercase: params.lowercase,
        numbers: params.numbers,
        special: params.special,
        avoidAmbiguous: params.avoid_ambiguous ?? true,
      });
      return {
        content: [{ type: 'text', text: `Generated password (${password.length} chars): ${password}` }],
      };
    },
  );

  // --- get_totp ---
  server.tool(
    'get_totp',
    'Get current TOTP verification code for a vault item',
    {
      id: z.string().describe('Item ID with TOTP configured'),
    },
    async ({ id }) => {
      const client = await getClient();
      const decrypted = await client.listDecryptedCiphers();
      const target = decrypted.find((c) => c.id === id);
      if (!target) {
        return { content: [{ type: 'text', text: `Item ${id} not found.` }] };
      }
      if (!target.login?.totp) {
        return { content: [{ type: 'text', text: `Item "${target.name}" has no TOTP configured.` }] };
      }
      const totpResult = await calcTotp(target.login.totp);
      if (!totpResult) {
        return { content: [{ type: 'text', text: 'Invalid TOTP secret.' }] };
      }
      return {
        content: [{
          type: 'text',
          text: `TOTP for "${target.name}": ${totpResult.code}\nValid for ${totpResult.remain}s (period: ${totpResult.period}s)`,
        }],
      };
    },
  );

  // ========================================
  // ONE-SHOT / SMART TOOLS
  // ========================================

  // --- help ---
  server.tool(
    'help',
    'Get a complete guide to all available tools, common workflows, and usage tips. CALL THIS FIRST if you are unsure which tool to use.',
    {},
    async () => {
      const guide = `=== NodeWarden Password Manager - Tool Guide ===

--- BROWSING & SEARCHING ---

1. get_vault_summary
   Returns: total item count, breakdown by type, folder list, favorites count, recycle bin count, and recent items.

2. list_items
   Returns: all vault items with name, username, URL, folder, and favorite status.

3. search_items (query)
   Returns: items matching the query (searches name, username, URL, notes).

4. quick_find (query, include_passwords)
   Returns: FULL decrypted details of ALL matching items in one call.

5. get_password (name)
   Returns: JUST the username, password, and URL for the first matching item.

6. get_item (id OR name)
   Returns: full decrypted details of a single item.

7. list_favorites
   Returns: all items marked as favorite.

--- CREATING ITEMS ---

8. create_item (name, username, password, uri, notes, folder_id, totp)
   Creates a login item. Use generate_password first if you need a password.

9. create_secure_note (name, notes, folder_id)
   Creates a secure note (type 2).

10. create_card (name, cardholderName, number, brand, expMonth, expYear, code, notes, folder_id)
    Creates a card item (type 3).

11. create_folder (name)
    Creates a new folder.

12. generate_password (length, uppercase, lowercase, numbers, special, avoid_ambiguous)
    Generates a random secure password.

--- MODIFYING ITEMS ---

13. update_item (id, name?, username?, password?, uri?, notes?, folder_id?)
    Updates specified fields of an existing item (supports Login, Card, and Identity types).

14. toggle_favorite (id)
    Toggles the favorite/star status of an item.

15. move_to_folder (id, folder_name)
    Moves an item to a folder by folder name (creates folder if it does not exist).

--- DELETING & RECYCLE BIN ---

16. delete_item (id, permanent?, confirm="YES")
    Requires confirm="YES". By default moves to recycle bin. Set permanent=true to permanently delete.

17. list_trash
    Returns: all items in the recycle bin.

18. restore_item (id)
    Restores an item from the recycle bin.

19. purge_recycle_bin (confirm="YES")
    Requires confirm="YES". Permanently deletes ALL items in the recycle bin.

--- UTILITIES ---

20. get_totp (id)
    Returns: current TOTP verification code for an item with 2FA configured.

21. list_folders
    Returns: all folders with their IDs and decrypted names.

22. check_duplicate (check_type)
    Returns: items that share the same password or username.

--- COMMON WORKFLOWS ---

Workflow 1: "Get my password for Gmail"
  -> get_password(name="Gmail")

Workflow 2: "Find everything related to bank"
  -> quick_find(query="bank")

Workflow 3: "Create a new login for example.com"
  -> generate_password(length=20, special=true)
  -> create_item(name="Example", username="me@example.com", password="<generated>", uri="https://example.com")

Workflow 4: "Show me my vault overview"
  -> get_vault_summary()

Workflow 5: "Move GitHub to Work folder"
  -> move_to_folder(id="<item-id>", folder_name="Work")

Workflow 6: "Check for duplicate passwords"
  -> check_duplicate(check_type="password")

Workflow 7: "Delete item abc123"
  -> delete_item(id="abc123", confirm="YES")

--- TIPS ---
- Always call help first if unsure.
- Use quick_find or get_password to minimize calls.
- Item IDs are returned by list_items, search_items, get_vault_summary, quick_find.
- All search/matching is case-insensitive.`;
      return { content: [{ type: 'text', text: guide }] };
    },
  );

  // --- get_vault_summary ---
  server.tool(
    'get_vault_summary',
    'Get a comprehensive overview of the entire vault: total items, breakdown by type, folder list with counts, favorites count, recycle bin count, and 5 most recently modified items.',
    {},
    async () => {
      const client = await getClient();
      const syncData = await client.sync();
      const allCiphers = syncData.ciphers || [];
      const folders = syncData.folders || [];

      const decFolders = await Promise.all(
        folders.map(async (f) => ({
          id: f.id,
          name: await client.decryptFolderName(f),
        })),
      );

      const active = allCiphers.filter((c) => !c.deletedDate);
      const trashed = allCiphers.filter((c) => c.deletedDate);

      const byType: Record<number, number> = {};
      for (const c of active) {
        byType[c.type] = (byType[c.type] || 0) + 1;
      }
      const typeNames: Record<number, string> = { 1: 'Login', 2: 'SecureNote', 3: 'Card', 4: 'Identity' };

      const favorites = active.filter((c) => c.favorite);

      // Decrypt all active ciphers at once (cached) and sort by revisionDate
      const decrypted = await client.listDecryptedCiphers();
      const decRecent = decrypted
        .sort((a, b) => new Date(b.revisionDate || 0).getTime() - new Date(a.revisionDate || 0).getTime())
        .slice(0, 5);

      const folderCounts: Record<string, number> = {};
      for (const c of active) {
        if (c.folderId) folderCounts[c.folderId] = (folderCounts[c.folderId] || 0) + 1;
      }

      const lines: string[] = [
        '=== Vault Summary ===',
        '',
        `Total items: ${active.length}`,
        `By type: ${Object.entries(byType).map(([t, n]) => `${typeNames[Number(t)] || 'Unknown'}: ${n}`).join(', ')}`,
        `Favorites: ${favorites.length}`,
        `Recycle bin: ${trashed.length} items`,
        `Folders: ${decFolders.length}`,
        '',
        '--- Folders ---',
      ];
      for (const f of decFolders) {
        lines.push(`  ${f.name} (${folderCounts[f.id] || 0} items) | ID: ${f.id}`);
      }
      if (decFolders.length === 0) lines.push('  (no folders)');

      lines.push('', '--- Recently Modified ---');
      for (const c of decRecent) {
        lines.push(`  ${formatCipherSummary(c)} | modified: ${c.revisionDate || 'unknown'}`);
      }

      return { content: [{ type: 'text', text: lines.join('\n') }] };
    },
  );

  // --- get_password ---
  server.tool(
    'get_password',
    'Quickly get the username and password for a vault item by name. Returns just the credentials for the first matching item.',
    {
      name: z.string().min(1).describe('Item name or partial name to search for'),
    },
    async ({ name }) => {
      const client = await getClient();
      const decrypted = await client.listDecryptedCiphers();

      const q = name.toLowerCase();
      const match = decrypted.find((c) =>
        c.type === 1 && c.name.toLowerCase().includes(q),
      );

      if (!match) {
        return { content: [{ type: 'text', text: `No login item found matching "${name}".` }] };
      }

      const c = match;
      const lines: string[] = [
        `=== ${c.name} ===`,
        `ID: ${c.id}`,
      ];
      if (c.login?.username) lines.push(`Username: ${c.login.username}`);
      if (c.login?.password) lines.push(`Password: ${c.login.password}`);
      if (c.login?.uris?.length) lines.push(`URL: ${c.login.uris.join(', ')}`);
      if (c.login?.totp) lines.push(`TOTP: configured (use get_totp tool with this ID to get current code)`);
      if (c.folderName) lines.push(`Folder: ${c.folderName}`);

      return { content: [{ type: 'text', text: lines.join('\n') }] };
    },
  );

  // --- quick_find ---
  server.tool(
    'quick_find',
    'Search vault items AND return their full decrypted details in one call. Combines search_items + get_item into a single step.',
    {
      query: z.string().min(1).describe('Search query - matches name, username, URL, or notes'),
      include_passwords: z.boolean().optional().describe('Whether to include passwords and sensitive fields in the output (default: true)'),
    },
    async ({ query, include_passwords }) => {
      const showPasswords = include_passwords ?? true;
      const client = await getClient();
      const decrypted = await client.listDecryptedCiphers();

      const q = query.toLowerCase();
      const matched = decrypted.filter((c) => {
        const name = c.name.toLowerCase();
        const username = c.login?.username?.toLowerCase() || '';
        const uris = c.login?.uris?.join(' ').toLowerCase() || '';
        const notes = c.notes.toLowerCase();
        return name.includes(q) || username.includes(q) || uris.includes(q) || notes.includes(q);
      });

      if (matched.length === 0) {
        return { content: [{ type: 'text', text: `No items found matching "${query}".` }] };
      }

      const results = matched.map((c, i) => {
        const detail = formatCipherDetail(c);
        if (!showPasswords) {
          return `${i + 1}. ${maskSensitiveFields(detail)}`;
        }
        return `${i + 1}. ${detail}`;
      });

      return {
        content: [{ type: 'text', text: `Found ${matched.length} items matching "${query}":\n\n${results.join('\n\n---\n\n')}` }],
      };
    },
  );

  // --- toggle_favorite ---
  server.tool(
    'toggle_favorite',
    'Toggle the favorite (star) status of a vault item',
    {
      id: z.string().describe('Item ID to toggle favorite status'),
    },
    async ({ id }) => {
      const client = await getClient();
      const newStatus = await client.toggleFavorite(id);
      return {
        content: [{ type: 'text', text: `Item ${id} ${newStatus ? 'added to' : 'removed from'} favorites.` }],
      };
    },
  );

  // --- list_favorites ---
  server.tool(
    'list_favorites',
    'List all vault items marked as favorite (starred)',
    {},
    async () => {
      const client = await getClient();
      const decrypted = await client.listDecryptedCiphers();
      const favorites = decrypted.filter((c) => c.favorite);
      if (favorites.length === 0) {
        return { content: [{ type: 'text', text: 'No favorite items found.' }] };
      }
      const lines = favorites.map((c, i) => `${i + 1}. ${formatCipherSummary(c)}`);
      return {
        content: [{ type: 'text', text: `Favorite items (${favorites.length}):\n\n${lines.join('\n')}` }],
      };
    },
  );

  // --- create_secure_note ---
  server.tool(
    'create_secure_note',
    'Create a new secure note in the vault (for storing secrets, codes, or text that is not a login)',
    {
      name: z.string().min(1).describe('Note title/name'),
      notes: z.string().optional().describe('Note content/body'),
      folder_id: z.string().optional().describe('Folder ID (use list_folders to find)'),
    },
    async (params) => {
      const client = await getClient();
      const payload = await client.buildCreateSecureNotePayload({
        name: params.name,
        notes: params.notes,
        folderId: params.folder_id,
      });
      const created = await client.createCipher(payload);
      return {
        content: [{ type: 'text', text: `Created secure note "${params.name}" with ID: ${created.id}` }],
      };
    },
  );

  // --- create_card ---
  server.tool(
    'create_card',
    'Create a new card item in the vault (for storing credit/debit card information)',
    {
      name: z.string().min(1).describe('Card item name (e.g., "Visa Credit")'),
      cardholder_name: z.string().optional().describe('Name on the card'),
      number: z.string().optional().describe('Card number'),
      brand: z.string().optional().describe('Card brand (e.g., Visa, Mastercard)'),
      exp_month: z.string().optional().describe('Expiration month (e.g., "01")'),
      exp_year: z.string().optional().describe('Expiration year (e.g., "2027")'),
      code: z.string().optional().describe('CVV/security code'),
      notes: z.string().optional().describe('Additional notes'),
      folder_id: z.string().optional().describe('Folder ID'),
    },
    async (params) => {
      const client = await getClient();
      const payload = await client.buildCreateCardPayload({
        name: params.name,
        cardholderName: params.cardholder_name,
        number: params.number,
        brand: params.brand,
        expMonth: params.exp_month,
        expYear: params.exp_year,
        code: params.code,
        notes: params.notes,
        folderId: params.folder_id,
      });
      const created = await client.createCipher(payload);
      return {
        content: [{ type: 'text', text: `Created card "${params.name}" with ID: ${created.id}` }],
      };
    },
  );

  // --- move_to_folder ---
  server.tool(
    'move_to_folder',
    'Move a vault item to a folder by folder name. If the folder does not exist, it will be created automatically.',
    {
      id: z.string().describe('Item ID to move'),
      folder_name: z.string().min(1).describe('Target folder name (created if it does not exist)'),
    },
    async ({ id, folder_name }) => {
      const client = await getClient();
      const folders = await client.listFolders();

      // Parallel-decrypt all folder names for faster lookup
      const decFolders = await Promise.all(
        folders.map(async (f) => ({ f, name: await client.decryptFolderName(f) })),
      );
      const targetFolder = decFolders.find(
        ({ name }) => name.toLowerCase() === folder_name.toLowerCase(),
      )?.f;

      let folderId: string;
      if (targetFolder) {
        folderId = targetFolder.id;
      } else {
        const created = await client.createFolder(folder_name);
        folderId = created.id;
      }

      const cipher = await client.getCipher(id);
      const payload = await client.buildUpdateCipherPayload(cipher, { folderId });
      await client.updateCipher(id, payload);

      return {
        content: [{ type: 'text', text: `Moved item ${id} to folder "${folder_name}" (ID: ${folderId}).` }],
      };
    },
  );

  // --- check_duplicate ---
  server.tool(
    'check_duplicate',
    'Check the vault for security issues: find items with duplicate passwords or duplicate usernames.',
    {
      check_type: z.enum(['password', 'username']).describe('What to check for duplicates: "password" or "username"'),
    },
    async ({ check_type }) => {
      const client = await getClient();
      const decrypted = await client.listDecryptedCiphers();

      const logins = decrypted.filter((c) => c.type === 1 && c.login);

      const groups: Record<string, typeof logins> = {};
      for (const c of logins) {
        let val: string | undefined;
        if (check_type === 'password') {
          val = c.login!.password;
        } else {
          val = c.login!.username;
        }
        if (!val) continue;
        const key = val;
        if (!groups[key]) groups[key] = [];
        groups[key].push(c);
      }

      const duplicates = Object.entries(groups).filter(([, items]) => items.length > 1);

      if (duplicates.length === 0) {
        return {
          content: [{ type: 'text', text: `No duplicate ${check_type}s found. All ${check_type}s are unique.` }],
        };
      }

      const lines: string[] = [`Found ${duplicates.length} duplicate ${check_type} group(s):\n`];
      for (const [val, items] of duplicates) {
        const masked = check_type === 'password' ? `${val.slice(0, 2)}***${val.slice(-2)}` : val;
        lines.push(`Duplicate ${check_type}: "${masked}" (${items.length} items)`);
        for (const c of items) {
          lines.push(`  - ${c.name} (ID: ${c.id})${c.folderName ? ` [${c.folderName}]` : ''}`);
        }
        lines.push('');
      }
      return { content: [{ type: 'text', text: lines.join('\n') }] };
    },
  );
}
