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

export function setSessionCookie(userId: string) {
  const token = jwt.sign({ sub: userId, aud: env.SIWS_DOMAIN }, env.JWT_SECRET, { expiresIn: '15m' });
  cookies().set(env.SESSION_COOKIE_NAME, token, { httpOnly: true, sameSite: 'lax', secure: true, path: '/' });
}

export function requireSession(): { userId: string } {
  const token = cookies().get(env.SESSION_COOKIE_NAME)?.value;
  if (!token) throw new Error('unauthorized');
  const payload = jwt.verify(token, env.JWT_SECRET) as any;
  return { userId: payload.sub as string };
}
