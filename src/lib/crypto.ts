import crypto from 'crypto';

export function randomId(len = 16) {
  return crypto.randomBytes(len).toString('hex');
}

export function hmacSha256Base64(secret: string, raw: string) {
  return crypto.createHmac('sha256', secret).update(raw).digest('base64');
}

export function timingSafeEqual(a: string, b: string) {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ab.length !== bb.length) return false;
  return crypto.timingSafeEqual(ab, bb);
}
