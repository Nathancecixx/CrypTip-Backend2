import { z } from 'zod';
import { requireSession } from '@/src/lib/auth';
import { insertPurchase } from '@/src/lib/db';
import { SKU, SKU_ALLOWLIST } from '@/src/constants';
import { buildX402Payload } from '@/src/lib/x402';
import { randomId } from '@/src/lib/crypto';
import { handleCorsOptions, withCors } from '@/src/middleware/cors';
export const runtime = 'nodejs';

const AllowedSkus = z.enum([
  SKU.VANITY_MONTHLY,
  SKU.TEMPLATES_PACK_A,
  SKU.ADDON_HALO_V1,
]);

const Body = z.object({ sku: AllowedSkus });

const SKU_PRICE_ATOMIC: Record<(typeof SKU)[keyof typeof SKU], number> = {
  'vanity.monthly': 1000000,
  'templates.packA': 3000000,
  'addon.halo.v1': 5000000
};

export const OPTIONS = handleCorsOptions;

export const POST = withCors(async (req: Request) => {
  let userId: string;
  try {
    ({ userId } = requireSession());
  } catch {
    return Response.json({ error: 'Unauthorized' }, { status: 401 });
  }

  let body;
  try {
    body = Body.parse(await req.json());
  } catch {
    return Response.json({ error: 'Invalid payload' }, { status: 400 });
  }

  const { sku } = body;
  if (!SKU_ALLOWLIST.has(sku)) {
    return Response.json({ error: 'Invalid SKU' }, { status: 400 });
  }

  const idempotency_key = randomId();
  const amount = SKU_PRICE_ATOMIC[sku];

  try {
    const purchase = await insertPurchase({
      user_id: userId,
      sku,
      amount_atomic: amount,
      status: 'pending',
      idempotency_key,
    });

    const checkout = buildX402Payload(purchase.id, sku, amount);
    return Response.json({ order_id: purchase.id, x402: checkout });
  } catch {
    return Response.json({ error: 'Failed to create purchase' }, { status: 500 });
  }
});
