/** Type definitions for NodeWarden API responses and MCP server. */

export interface Env {
  // KV namespace — used for sync response caching (encrypted data only)
  KV: KVNamespace;
  // All config fields are optional — validated at runtime
  NODEWARDEN_URL?: string;
  USER_EMAIL?: string;
  MASTER_PASSWORD?: string;
  MCP_AUTH_TOKEN?: string;
  // Comma-separated list of allowed CORS origins (e.g., "https://app.example.com,https://chat.example.com")
  // If unset, defaults to "*" (less secure — any site can send requests)
  ALLOWED_ORIGINS?: string;
  // Whether delete_item moves to recycle bin ("true") or permanently deletes ("false").
  // Default: "true" (soft delete / recycle bin)
  SOFT_DELETE?: string;
}

export interface PreloginResponse {
  kdf: number;
  kdfIterations: number;
  kdfMemory: number | null;
  kdfParallelism: number | null;
}

export interface TokenResponse {
  access_token: string;
  expires_in: number;
  token_type: string;
  refresh_token?: string;
  Key: string;
  PrivateKey?: string;
  Kdf: number;
  KdfIterations: number;
  KdfMemory?: number | null;
  KdfParallelism?: number | null;
}

export interface CipherUri {
  uri: string | null;
  match: number | null;
}

export interface CipherLogin {
  username: string | null;
  password: string | null;
  totp: string | null;
  uris: CipherUri[] | null;
  fido2Credentials?: unknown[];
}

export interface CipherField {
  name: string | null;
  value: string | null;
  type: number;
  linkedId?: number | null;
}

export interface CipherCard {
  cardholderName: string | null;
  number: string | null;
  brand: string | null;
  expMonth: string | null;
  expYear: string | null;
  code: string | null;
}

export interface CipherIdentity {
  title: string | null;
  firstName: string | null;
  middleName: string | null;
  lastName: string | null;
  username: string | null;
  company: string | null;
  ssn: string | null;
  passportNumber: string | null;
  licenseNumber: string | null;
  email: string | null;
  phone: string | null;
  address1: string | null;
  address2: string | null;
  address3: string | null;
  city: string | null;
  state: string | null;
  postalCode: string | null;
  country: string | null;
}

export interface Cipher {
  id: string;
  userId?: string;
  organizationId?: string | null;
  type: number; // 1=Login, 2=SecureNote, 3=Card, 4=Identity
  folderId: string | null;
  favorite: boolean;
  reprompt?: number;
  name: string;
  notes: string | null;
  key?: string | null;
  login?: CipherLogin | null;
  card?: CipherCard | null;
  identity?: CipherIdentity | null;
  fields?: CipherField[];
  attachments?: unknown[];
  passwordHistory?: Array<{ password: string; lastUsedDate: string }>;
  secureNote?: { type: number } | null;
  collectionIds?: string[];
  revisionDate?: string;
  creationDate?: string;
  deletedDate?: string | null;
  archivedDate?: string | null;
}

export interface Folder {
  id: string;
  name: string;
  revisionDate?: string;
}

export interface SyncResponse {
  profile?: {
    id: string;
    email: string;
    name: string;
    key: string;
  };
  ciphers?: Cipher[];
  folders?: Folder[];
  domains?: unknown;
  policies?: unknown[];
  sends?: unknown[];
}

export interface DecryptedCipher {
  id: string;
  type: number;
  name: string;
  notes: string;
  favorite: boolean;
  folderId: string | null;
  folderName?: string;
  login?: {
    username: string;
    password: string;
    totp: string;
    uris: string[];
  };
  card?: {
    cardholderName: string;
    number: string;
    brand: string;
    expMonth: string;
    expYear: string;
    code: string;
  };
  identity?: {
    title: string;
    firstName: string;
    middleName: string;
    lastName: string;
    username: string;
    company: string;
    ssn: string;
    passportNumber: string;
    licenseNumber: string;
    email: string;
    phone: string;
    address1: string;
    address2: string;
    address3: string;
    city: string;
    state: string;
    postalCode: string;
    country: string;
  };
  fields?: Array<{ name: string; value: string; type: number }>;
  revisionDate?: string;
}

export interface SessionState {
  accessToken: string;
  refreshToken: string | null;
  protectedKey: string;
  vaultKeys: {
    symEncKeyB64: string;
    symMacKeyB64: string;
  };
  expiresAt: number;
}
