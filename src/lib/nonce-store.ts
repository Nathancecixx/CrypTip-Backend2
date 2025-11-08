import { randomBytes } from 'crypto';
import { supa } from './db';
import { env } from './env';

const NONCE_TTL_SECONDS = Math.min(Math.max(env.SIWS_NONCE_TTL_SECONDS, 1), 600);

export type SiwsNonceRow = {
  id: string;
  nonce: string;
  address: string | null;
  created_at: string;
  expires_at: string;
};

function generateNonce(bytes = 16): string {
  return randomBytes(bytes)
    .toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

export async function issueNonce(): Promise<{ nonce: string; createdAt: string; expiresAt: string }> {
  const expiresAt = new Date(Date.now() + NONCE_TTL_SECONDS * 1000).toISOString();
  const nonce = generateNonce();

  const { data, error } = await supa
    .from('siws_nonce')
    .insert({ nonce, expires_at: expiresAt })
    .select('*')
    .single();

  if (error) {
    throw error;
  }

  return {
    nonce: data.nonce as string,
    createdAt: data.created_at as string,
    expiresAt: data.expires_at as string,
  };
}

export async function getNonce(nonce: string): Promise<SiwsNonceRow | null> {
  const normalizedNonce = nonce.trim();
  if (!normalizedNonce) {
    return null;
  }

  const nowIso = new Date().toISOString();

  const { data, error } = await supa
    .from('siws_nonce')
    .select('*')
    .eq('nonce', normalizedNonce)
    .gt('expires_at', nowIso)
    .maybeSingle();

  if (error) {
    throw error;
  }

  if (!data) {
    return null;
  }

  return data as SiwsNonceRow;
}

export async function consumeNonce(id: string): Promise<boolean> {
  const normalizedId = id.trim();
  if (!normalizedId) {
    return false;
  }

  const { data, error } = await supa
    .from('siws_nonce')
    .delete()
    .eq('id', normalizedId)
    .select('id')
    .maybeSingle();

  if (error) {
    throw error;
  }

  return Boolean(data);
}
