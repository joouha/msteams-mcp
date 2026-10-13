/**
 * Secure session state storage.
 *
 * Handles reading and writing session state with:
 * - Encryption at rest
 * - Restricted file permissions
 * - Automatic migration from plaintext
 * - Multi-account support via account-scoped directories
 *
 * Session files are stored in a user-specific config directory (~/.teams-mcp-server/)
 * to ensure consistency regardless of how the server is invoked (npx, global install, etc.).
 *
 * For multi-account use, each account gets its own subdirectory:
 *   ~/.teams-mcp-server/               ← "default" account (backward compatible)
 *   ~/.teams-mcp-server/accounts/work/  ← "work" account
 *   ~/.teams-mcp-server/accounts/personal/ ← "personal" account
 */

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { AsyncLocalStorage } from 'async_hooks';
import { encrypt, decrypt } from './crypto.js';
import { SESSION_EXPIRY_HOURS } from '../constants.js';
import * as log from '../utils/logger.js';

/**
 * Base config directory, overridable via TEAMS_MCP_CONFIG_DIR env var.
 * - Windows: %APPDATA%\teams-mcp-server\
 * - macOS/Linux: ~/.teams-mcp-server/
 */
const BASE_CONFIG_DIR = process.env.TEAMS_MCP_CONFIG_DIR
  ?? (process.platform === 'win32'
    ? path.join(process.env.APPDATA || path.join(os.homedir(), 'AppData', 'Roaming'), 'teams-mcp-server')
    : path.join(os.homedir(), '.teams-mcp-server'));

// ─────────────────────────────────────────────────────────────────────────────
// Multi-Account Support
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Currently active account name. Defaults to "default" or TEAMS_MCP_ACCOUNT.
 * One MCP server process should use one account.
 */
const accountContext = new AsyncLocalStorage<string>();
let activeAccount: string = process.env.TEAMS_MCP_ACCOUNT || 'default';

/**
 * Sets the active account for the current tool invocation.
 * Must be called before any session/token access.
 */
export function setActiveAccount(account: string): void {
  const resolvedAccount = account || 'default';
  // Validate the account name before changing process-level state.
  accountConfigDir(resolvedAccount);
  activeAccount = resolvedAccount;
  fs.mkdirSync(accountConfigDir(resolvedAccount), { recursive: true, mode: 0o700 });
}

/**
 * Returns the currently active account name.
 */
export function getActiveAccount(): string {
  return accountContext.getStore() ?? activeAccount;
}

/**
 * Runs an operation within an account context. AsyncLocalStorage prevents
 * concurrent MCP calls for different accounts from changing each other's
 * session/token paths.
 */
export function runWithAccount<T>(account: string, operation: () => T): T {
  const resolvedAccount = account || 'default';
  accountConfigDir(resolvedAccount);
  fs.mkdirSync(accountConfigDir(resolvedAccount), { recursive: true, mode: 0o700 });
  return accountContext.run(resolvedAccount, operation);
}

/**
 * Resolves the config directory for a given account.
 * - "default" → BASE_CONFIG_DIR (backward compatible)
 * - "work"    → BASE_CONFIG_DIR/accounts/work/
 */
function accountConfigDir(account: string): string {
  // Account names are directory components; reject traversal and separators.
  if (!/^[A-Za-z0-9._-]+$/.test(account)) {
    throw new Error(`Invalid account name: ${account}`);
  }
  if (account === 'default') return BASE_CONFIG_DIR;
  return path.join(BASE_CONFIG_DIR, 'accounts', account);
}

/**
 * Returns the active account's config directory.
 */
export function getConfigDir(): string {
  return accountConfigDir(getActiveAccount());
}

/**
 * Returns the active account's session state path.
 */
export function getSessionStatePath(): string {
  return path.join(getConfigDir(), 'session-state.json');
}

/**
 * Returns the active account's token cache path.
 */
export function getTokenCachePath(): string {
  return path.join(getConfigDir(), 'token-cache.json');
}

/**
 * Returns the active account's browser profile directory path.
 */
export function getBrowserProfileDir(): string {
  return path.join(getConfigDir(), 'browser-profile');
}

// ─────────────────────────────────────────────────────────────────────────────
// Legacy exports (for backward compat — still use "default" account paths)
// ─────────────────────────────────────────────────────────────────────────────

/** @deprecated Use getConfigDir() instead. */
export const CONFIG_DIR = BASE_CONFIG_DIR;

/** @deprecated Use getSessionStatePath() instead. */
export const SESSION_STATE_PATH = path.join(BASE_CONFIG_DIR, 'session-state.json');

/** @deprecated Use getTokenCachePath() instead. */
export const TOKEN_CACHE_PATH = path.join(BASE_CONFIG_DIR, 'token-cache.json');

/** File permission mode: owner read/write only. */
const SECURE_FILE_MODE = 0o600;

/**
 * Ensures the active account's config directory exists with secure permissions.
 */
export function ensureConfigDir(): void {
  fs.mkdirSync(getConfigDir(), { recursive: true, mode: 0o700 });
}

/** Session state as stored by Playwright. */
export interface SessionState {
  cookies: Array<{
    name: string;
    value: string;
    domain?: string;
    path?: string;
    expires?: number;
    httpOnly?: boolean;
    secure?: boolean;
    sameSite?: 'Strict' | 'Lax' | 'None';
  }>;
  origins: Array<{
    origin: string;
    localStorage: Array<{ name: string; value: string }>;
  }>;
}

/** Token cache structure. */
export interface TokenCache {
  substrateToken: string;
  substrateTokenExpiry: number;
  extractedAt: number;
}

/**
 * Writes data securely with encryption and file permissions.
 */
function writeSecure(filePath: string, data: unknown): void {
  const json = JSON.stringify(data, null, 2);
  const encrypted = encrypt(json);

  fs.writeFileSync(filePath, JSON.stringify(encrypted, null, 2), {
    mode: SECURE_FILE_MODE,
    encoding: 'utf8',
  });
}

/**
 * Reads and decrypts data. Returns null if missing or undecryptable
 * (different machine, corrupted).
 */
function readSecure<T>(filePath: string): T | null {
  if (!fs.existsSync(filePath)) return null;
  try {
    return JSON.parse(decrypt(JSON.parse(fs.readFileSync(filePath, 'utf8')))) as T;
  } catch (error) {
    log.error('session-store', `Failed to read ${filePath}: ${error instanceof Error ? error.message : error}`);
    return null;
  }
}

/**
 * Checks if session state file exists for the active account.
 */
export function hasSessionState(): boolean {
  return fs.existsSync(getSessionStatePath());
}

/**
 * Reads the session state for the active account.
 */
export function readSessionState(): SessionState | null {
  return readSecure<SessionState>(getSessionStatePath());
}

/**
 * Writes the session state securely for the active account.
 */
export function writeSessionState(state: SessionState): void {
  ensureConfigDir();
  writeSecure(getSessionStatePath(), state);
}

/**
 * Deletes the session state file for the active account.
 */
export function clearSessionState(): void {
  if (fs.existsSync(getSessionStatePath())) {
    fs.unlinkSync(getSessionStatePath());
  }
}

/**
 * Gets the age of the session state in hours for the active account.
 */
export function getSessionAge(): number | null {
  if (!hasSessionState()) {
    return null;
  }

  const stats = fs.statSync(getSessionStatePath());
  const ageMs = Date.now() - stats.mtimeMs;
  return ageMs / (1000 * 60 * 60);
}

/**
 * Checks if session is likely expired (>12 hours old) for the active account.
 */
export function isSessionLikelyExpired(): boolean {
  const age = getSessionAge();
  if (age === null) return true;
  return age > SESSION_EXPIRY_HOURS;
}

/**
 * Reads the token cache for the active account.
 */
export function readTokenCache(): TokenCache | null {
  return readSecure<TokenCache>(getTokenCachePath());
}

/**
 * Writes the token cache securely for the active account.
 */
export function writeTokenCache(cache: TokenCache): void {
  ensureConfigDir();
  writeSecure(getTokenCachePath(), cache);
}

/**
 * Clears the token cache for the active account.
 */
export function clearTokenCache(): void {
  if (fs.existsSync(getTokenCachePath())) {
    fs.unlinkSync(getTokenCachePath());
  }
}

/**
 * Known Teams origins (commercial and government clouds).
 * Used to find the correct origin in session state.
 */
const TEAMS_ORIGINS = [
  'https://teams.cloud.microsoft', // New Teams URL (often holds SubstrateSearch tokens)
  'https://teams.microsoft.com',   // Commercial legacy
  'https://teams.microsoft.us',    // GCC-High
  'https://dod.teams.microsoft.us', // DoD
];

/**
 * Returns true if localStorage has a SubstrateSearch MSAL token entry.
 */
function hasSubstrateSearchToken(
  localStorage: SessionState['origins'][number]['localStorage'] | undefined
): boolean {
  for (const item of localStorage ?? []) {
    try {
      const entry = JSON.parse(item.value) as { target?: string; secret?: string };
      if (
        entry.target?.includes('SubstrateSearch') &&
        typeof entry.secret === 'string' &&
        entry.secret.startsWith('ey')
      ) {
        return true;
      }
    } catch {
      // ignore non-JSON localStorage values
    }
  }
  return false;
}

/**
 * Gets the Teams origin from session state.
 * Checks multiple known Teams domains to support government clouds.
 *
 * Prefers an origin that has a SubstrateSearch token so Outlook/email and
 * Substrate search keep working when both teams.cloud.microsoft and
 * teams.microsoft.com are present in the saved session (common after the
 * New Teams host migration).
 */
export function getTeamsOrigin(state: SessionState): SessionState['origins'][number] | null {
  if (!state.origins) return null;

  const withSubstrate = state.origins.find(o => hasSubstrateSearchToken(o.localStorage));
  if (withSubstrate) return withSubstrate;

  // Try known Teams origins in priority order
  for (const knownOrigin of TEAMS_ORIGINS) {
    const origin = state.origins.find(o => o.origin === knownOrigin);
    if (origin) return origin;
  }

  // Fallback: find any origin containing 'teams.microsoft'
  return state.origins.find(o =>
    o.origin.includes('teams.microsoft') || o.origin.includes('teams.cloud')
  ) ?? null;
}
