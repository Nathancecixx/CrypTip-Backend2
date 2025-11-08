// src/lib/auth.ts
import { NextResponse } from 'next/server';
import jwt from 'jsonwebtoken';
import { env } from './env';

export function buildSiwsMessage(domain: string, address: string, nonce: string, createdAtISO: string) {
  return [
    `Sign-In With Solana`,
    `Domain: ${domain}`,
    `Address: ${address}`,
    `Nonce: ${nonce}`,
    `Issued At: ${createdAtISO}`,
  ].join('\n');
}

export function issueSessionJWT(userId: string) {
  if (!env.SESSION_SECRET) throw new Error('missing_session_secret');
  return jwt.sign({ sub: userId }, env.SESSION_SECRET, { expiresIn: '7d', audience: 'cryptip', issuer: 'cryptip' });
}

export function setSessionCookie(res: NextResponse, token: string) {
  res.cookies.set('ctj_sess', token, {
    httpOnly: true,
    secure: true,
    sameSite: 'none', // cross-site cookie for different domains
    path: '/',
    maxAge: 60 * 60 * 24 * 7, // 7 days
  });
}
