import nacl from 'tweetnacl';
import bs58 from 'bs58';
import jwt, { type JwtPayload } from 'jsonwebtoken';
import { cookies } from 'next/headers';
import { env } from './env';
import { randomId } from './crypto';

export type SiwsMessageFields = {
  domain: string;
  address: string;
  statement: string;
  nonce: string;
  issuedAt: string;
  chainId: string;
  resources: string[];
};

export function makeNonce() {
  return randomId(16);
}

type BuildSiwsMessageOptions = {
  domain: string;
  statement?: string;
  resources?: string[];
};

export function buildSiwsMessage(address: string, nonce: string, options: BuildSiwsMessageOptions): {
  message: string;
  fields: SiwsMessageFields;
} {
  const issuedAt = new Date().toISOString();
  const statement = options.statement ?? 'Sign in to Crypto Tip Jar';
  const resources = options.resources?.filter(Boolean) ?? [env.FRONTEND_ORIGIN].filter(Boolean);
  const fields: SiwsMessageFields = {
    domain: options.domain,
    address,
    statement,
    nonce,
    issuedAt,
    chainId: env.NEXT_PUBLIC_SOLANA_CLUSTER,
    resources,
  };

  const header = `${fields.domain} wants you to sign in with your Solana account:`;
  const statementBlock = `${fields.statement}`;
  const details = `Chain ID: ${fields.chainId}\nNonce: ${fields.nonce}\nIssued At: ${fields.issuedAt}`;
  const resourcesBlock =
    fields.resources.length > 0
      ? `\nResources:\n${fields.resources.map((resource) => `- ${resource}`).join('\n')}`
      : '';

  const message = `${header}\n${fields.address}\n\n${statementBlock}\n\n${details}${resourcesBlock}`;

  return { message, fields };
}

export function verifySignature(message: string, signatureBase58: string, walletBase58: string) {
  const msgBytes = new TextEncoder().encode(message);
  const sig = bs58.decode(signatureBase58);
  const pub = bs58.decode(walletBase58);
  return nacl.sign.detached.verify(msgBytes, sig, pub);
}

export function setSessionCookie(_req: Request, userId: string) {
  const token = jwt.sign({ sub: userId, aud: env.SIWS_DOMAIN }, env.SESSION_SECRET, { expiresIn: '30d' });
  cookies().set(env.SESSION_COOKIE_NAME, token, {
    httpOnly: true,
    sameSite: 'none',
    secure: true,
    path: '/',
    maxAge: 60 * 60 * 24 * 30,
  });
}

export function requireSession(): { userId: string } {
  const token = cookies().get(env.SESSION_COOKIE_NAME)?.value;
  if (!token) throw new UnauthorizedError('missing_session');

  try {
    const payload = jwt.verify(token, env.SESSION_SECRET) as JwtPayload;
    if (!payload.sub) {
      throw new UnauthorizedError('invalid_session');
    }
    return { userId: payload.sub as string };
  } catch (error) {
    if (error instanceof UnauthorizedError) {
      throw error;
    }
    throw new UnauthorizedError('invalid_session');
  }
}

export class UnauthorizedError extends Error {
  constructor(message = 'unauthorized') {
    super(message);
    this.name = 'UnauthorizedError';
  }
}

export function cookiePolicyForRequest(req: Request) {
  const requestUrl = new URL(req.url);
  const crossSite = isCrossSiteRequest(req, requestUrl);

  return {
    sameSite: crossSite ? ('none' as const) : ('lax' as const),
    secure: crossSite ? true : requestUrl.protocol === 'https:',
  };
}

function isCrossSiteRequest(req: Request, requestUrl: URL) {
  const origin = req.headers.get('origin');
  if (!origin) return false;

  try {
    const originUrl = new URL(origin);
    return !urlsShareSite(originUrl, requestUrl);
  } catch {
    return false;
  }
}

function urlsShareSite(a: URL, b: URL) {
  return a.protocol === b.protocol && a.hostname === b.hostname && getPort(a) === getPort(b);
}

function getPort(url: URL) {
  if (url.port) return url.port;
  if (url.protocol === 'https:') return '443';
  if (url.protocol === 'http:') return '80';
  return '';
}
