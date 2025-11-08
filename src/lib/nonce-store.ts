// src/lib/nonce-store.ts
import crypto from 'crypto';
import { getSupabaseAdmin } from './supabase';
import { env } from './env';

type NonceRow = {
  id: string;
  nonce: string;
  created_at: string; // ISO from Supabase
  expires_at: string;
  domain?: string | null;
};

const TTL_MS = (() => {
  const n = Number(env.SIWS_NONCE_TTL_SECONDS || '600') * 1000;
  if (!Number.isFinite(n) || n <= 0) return 10 * 60 * 1000;
  return Math.min(n, 10 * 60 * 1000);
})();

function nowISO() {
  return new Date().toISOString();
}

function addMsISO(baseISO: string, deltaMs: number) {
  return new Date(new Date(baseISO).getTime() + deltaMs).toISOString();
}

function genNonce(): string {
  // 24 bytes → 32-char base64url-ish token; good entropy; short enough for UX
  return crypto.randomBytes(24).toString('base64url');
}

/**
 * issueNonce — inserts a unique nonce row; retries on rare collision.
 * Optionally persist domain if you want to bind nonce→expectedDomain.
 */
export async function issueNonce(opts?: { domain?: string }) {
  const db = getSupabaseAdmin();
  const createdAt = nowISO();
  const expiresAt = addMsISO(createdAt, TTL_MS);

  for (let i = 0; i < 3; i++) {
    const nonce = genNonce();
    const insert = {
      nonce,
      created_at: createdAt,
      expires_at: expiresAt,
      ...(opts?.domain ? { domain: opts.domain } : {}),
    };
    const { data, error } = await db.from('siws_nonce').insert(insert).select('*').single<NonceRow>();
    if (!error && data) {
      return { id: data.id, nonce: data.nonce, createdAt: data.created_at, expiresAt: data.expires_at, domain: data.domain ?? undefined };
    }
    // 23505 is unique_violation in Postgres; Supabase surfaces it in error.code
    if (error && error.code === '23505') continue; // rare collision: retry
    // Other errors bubble; route will catch and return {hint:'issueNonce_failed'}
    throw error;
  }
  // If we somehow collided 3x
  throw new Error('nonce_collision');
}

/**
 * getNonce — returns a non-expired nonce row by value.
 * If your DB already cleans expired rows, we still check in code for safety.
 */
export async function getNonce(nonce: string): Promise<NonceRow | null> {
  const db = getSupabaseAdmin();
  const { data, error } = await db.from('siws_nonce').select('*').eq('nonce', nonce).limit(1).maybeSingle<NonceRow>();
  if (error) throw error;
  if (!data) return null;
  // Enforce expiry in code too
  if (Date.now() > Date.parse(data.expires_at)) return null;
  return data;
}

/**
 * consumeNonce — deletes the row by id, returning true if exactly one row was removed.
 */
export async function consumeNonce(id: string): Promise<boolean> {
  const db = getSupabaseAdmin();
  const { count, error } = await db.from('siws_nonce').delete({ count: 'exact' }).eq('id', id);
  if (error) throw error;
  return !!count && count > 0;
}
