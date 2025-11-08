import { randomBytes } from 'crypto';
import { supa } from './db';
import { env } from './env';

const NONCE_TTL_SECONDS = Math.min(Math.max(env.SIWS_NONCE_TTL_SECONDS, 1), 600);

type IssueNonceParams = {
  address: string;
  domain: string;
  ip?: string;
  userAgent?: string;
};

type ConsumeNonceParams = {
  address: string;
  nonce: string;
  domain: string;
};

export type SiwsNonceRow = {
  address: string;
  nonce: string;
  domain: string;
  issued_at: string;
  expires_at: string;
  used: boolean;
  used_at: string | null;
  ip: string | null;
  user_agent: string | null;
};

function generateNonce(bytes = 16): string {
  return randomBytes(bytes)
    .toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

function sanitizeInput(value?: string | null, maxLength = 512): string | undefined {
  if (!value) return undefined;
  const trimmed = value.trim();
  if (!trimmed) return undefined;
  return trimmed.slice(0, maxLength);
}

export function extractNonceFromMessage(message: string): string | null {
  const match = message.match(/(?:^|\n)Nonce: ([^\n]+)/);
  return match ? match[1].trim() : null;
}

export async function issueNonce({
  address,
  domain,
  ip,
  userAgent,
}: IssueNonceParams): Promise<{ nonce: string; issuedAt: string; expiresAt: string }> {
  const normalizedAddress = address.trim();
  const normalizedDomain = domain.trim();
  if (!normalizedAddress) {
    throw new Error('address_required');
  }
  if (!normalizedDomain) {
    throw new Error('domain_required');
  }

  const issuedAt = new Date();
  const expiresAt = new Date(issuedAt.getTime() + NONCE_TTL_SECONDS * 1000);
  const nonce = generateNonce();

  const payload = {
    address: normalizedAddress,
    nonce,
    domain: normalizedDomain,
    issued_at: issuedAt.toISOString(),
    expires_at: expiresAt.toISOString(),
    used: false,
    used_at: null as string | null,
    ip: sanitizeInput(ip, 255) ?? null,
    user_agent: sanitizeInput(userAgent, 1024) ?? null,
  };

  const { data, error } = await supa
    .from('siws_nonces')
    .insert(payload)
    .select('*')
    .single();

  if (error) {
    throw error;
  }

  return {
    nonce: data.nonce as string,
    issuedAt: data.issued_at as string,
    expiresAt: data.expires_at as string,
  };
}

export async function consumeIfValid({ address, nonce, domain }: ConsumeNonceParams): Promise<SiwsNonceRow | null> {
  const normalizedAddress = address.trim();
  const normalizedDomain = domain.trim();
  if (!normalizedAddress || !normalizedDomain) {
    return null;
  }

  const nowIso = new Date().toISOString();

  const { data, error } = await supa
    .from('siws_nonces')
    .update({ used: true, used_at: nowIso })
    .eq('address', normalizedAddress)
    .eq('nonce', nonce)
    .eq('domain', normalizedDomain)
    .eq('used', false)
    .gte('expires_at', nowIso)
    .select('*')
    .maybeSingle();

  if (error) {
    throw error;
  }

  if (!data) {
    return null;
  }

  return data as SiwsNonceRow;
}
