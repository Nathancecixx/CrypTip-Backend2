import nacl from 'tweetnacl';
import bs58 from 'bs58';
import jwt from 'jsonwebtoken';
import { cookies } from 'next/headers';
import { env } from './env';
import { randomId } from './crypto';

export function makeNonce() {
  return randomId(16);
}

export function buildSiwsMessage(wallet: string, nonce: string) {
  return `Sign in with Solana to ${env.SIWS_DOMAIN}\n\nWallet: ${wallet}\nNonce: ${nonce}\nIssued At: ${new Date().toISOString()}`;
}

export function verifySignature(message: string, signatureBase58: string, walletBase58: string) {
  const msgBytes = new TextEncoder().encode(message);
  const sig = bs58.decode(signatureBase58);
  const pub = bs58.decode(walletBase58);
  return nacl.sign.detached.verify(msgBytes, sig, pub);
}

export function setSessionCookie(req: Request, userId: string) {
  const token = jwt.sign({ sub: userId, aud: env.SIWS_DOMAIN }, env.JWT_SECRET, { expiresIn: '15m' });
  const policy = cookiePolicyForRequest(req);
  cookies().set(env.SESSION_COOKIE_NAME, token, {
    httpOnly: true,
    sameSite: policy.sameSite,
    secure: policy.secure,
    path: '/',
    maxAge: 15 * 60,
  });
}

export function requireSession(): { userId: string } {
  const token = cookies().get(env.SESSION_COOKIE_NAME)?.value;
  if (!token) throw new Error('unauthorized');
  const payload = jwt.verify(token, env.JWT_SECRET) as any;
  return { userId: payload.sub as string };
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
