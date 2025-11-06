import { z } from 'zod';
import { env } from './env';
import { hmacSha256Base64, timingSafeEqual } from './crypto';

export const WebhookHeadersSchema = z.object({
  signature: z.string(),
  idem: z.string().optional(),
});

export function verifyX402Webhook(rawBody: string, signatureB64: string) {
  const expected = hmacSha256Base64(env.X402_WEBHOOK_SECRET, rawBody);
  return timingSafeEqual(expected, signatureB64);
}

// Placeholder: adapt to x402 provider's exact payload schema
export function buildX402Payload(orderId: string, sku: string, amountAtomic: number) {
  return {
    order_id: orderId,
    transaction: {
      memo: `ctj:${orderId}:${sku}`,
    },
    amount_atomic: amountAtomic,
    expires_at: Math.floor(Date.now() / 1000) + 600,
  };
}
