// src/lib/nonce-store.ts
import { randomBytes } from 'crypto';
import { createClient } from '@supabase/supabase-js';

const NONCE_TTL_SECONDS = Math.max(
  10,
  Math.min(600, Number((process.env.SIWS_NONCE_TTL_SECONDS || '600').trim()) || 600)
);

const TABLE = (process.env.NONCE_TABLE || 'siws_nonce').trim();

function supabase() {
  const url = process.env.SUPABASE_URL!;
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY!;
  if (!url || !key) throw new Error('Supabase credentials missing');
  return createClient(url, key, { auth: { persistSession: false } });
}

function genNonce() {
  // 24 bytes -> 32-char base64urlish when b58'd; short and unique.
  return Buffer.from(randomBytes(24)).toString('base64url');
}

export async function issueNonce(input: { domain: string }) {
  const sb = supabase();
  const nonce = genNonce();
  const issuedAt = new Date().toISOString();
  const expiresAt = new Date(Date.now() + NONCE_TTL_SECONDS * 1000).toISOString();

  const { error, data } = await sb
    .from(TABLE)
    .insert({
      nonce,
      issued_at_text: issuedAt,
      expires_at: expiresAt,
      domain: input.domain,
      consumed: false,
    })
    .select('id, nonce, issued_at_text, expires_at')
    .single();

  if (error) {
    (error as any).code = error.code || 'db_insert_error';
    throw error;
  }

  return {
    id: data.id as string,
    nonce: data.nonce as string,
    createdAt: data.issued_at_text as string,
    expiresAt: data.expires_at as string,
  };
}

export async function getNonce(nonce: string) {
  const sb = supabase();
  const { data, error } = await sb
    .from(TABLE)
    .select('id, nonce, issued_at_text, expires_at, domain, consumed')
    .eq('nonce', nonce)
    .single();

  if (error) {
    if (error.code === 'PGRST116') return null; // no rows
    return null;
  }
  if (!data || data.consumed) return null;
  return data;
}

export async function consumeNonce(id: string): Promise<boolean> {
  const sb = supabase();
  const { error } = await sb.from(TABLE).update({ consumed: true }).eq('id', id);
  return !error;
}
