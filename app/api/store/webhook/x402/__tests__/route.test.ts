import test, { mock } from 'node:test';
import assert from 'node:assert/strict';
import { SKU } from '@/src/constants';

process.env.RPC_PRIMARY_URL ??= 'https://rpc.localhost';
process.env.NEXT_PUBLIC_SUPABASE_URL ??= 'https://supabase.localhost';
process.env.SUPABASE_SERVICE_ROLE_KEY ??= 'service-role-key-example';
process.env.JWT_SECRET ??= 'jwt-secret-placeholder-value-123456';
process.env.SIWS_DOMAIN ??= 'example.com';
process.env.X402_WEBHOOK_SECRET ??= 'webhook-secret-12345';
process.env.MINT_COLLECTION_ADDRESS ??= 'collection-address-placeholder';
process.env.MINT_SIGNER_SECRET ??= 'mint-signer-secret-placeholder';

const { handleX402Webhook } = await import('../route.ts');

test('fails the purchase when amount mismatch occurs', async () => {
  const insertMock = mock.fn(async () => ({}));
  const fromMock = mock.fn(() => ({ insert: insertMock }));

  const deps = {
    verifyX402Webhook: mock.fn(() => true),
    supa: { from: fromMock },
    waitForFinalized: mock.fn(async () => true),
    getPurchaseById: mock.fn(async () => ({
      id: 'order-1',
      user_id: 'user-1',
      sku: SKU.TEMPLATES_PACK_A,
      amount_atomic: 100,
    })),
    markPurchaseStatus: mock.fn(async (id: string, status: 'paid' | 'paid-pending-mint' | 'failed') => ({
      id,
      user_id: 'user-1',
      sku: SKU.TEMPLATES_PACK_A,
      amount_atomic: 100,
      status,
    })),
    addEntitlement: mock.fn(async () => ({})),
    log: mock.fn(() => undefined),
    mintLicense: mock.fn(async () => ({ mint: 'mint' })),
    mintAddon: mock.fn(async () => ({ mint: 'mint' })),
  } as any;

  const request = new Request('https://example.com/api/store/webhook/x402', {
    method: 'POST',
    headers: {
      'x-402-signature': 'sig',
      'x-idempotency-key': 'idem',
    },
    body: JSON.stringify({
      order_id: 'order-1',
      sku: SKU.TEMPLATES_PACK_A,
      tx_sig: 'tx123',
      amount_atomic: 200,
      user_wallet: 'wallet',
    }),
  });

  const response = await handleX402Webhook(request, deps);

  assert.equal(response.status, 422);
  assert.equal(deps.markPurchaseStatus.mock.calls.length, 1);
  assert.deepEqual(deps.markPurchaseStatus.mock.calls[0].arguments, ['order-1', 'failed']);
  assert.equal(deps.addEntitlement.mock.calls.length, 0);
  assert.equal(deps.log.mock.calls[0].arguments[0], 'purchase.amount_mismatch');
  assert.deepEqual(deps.log.mock.calls[0].arguments[1], {
    purchase_id: 'order-1',
    expected_atomic: 100,
    received_atomic: 200,
    tx: 'tx123',
  });
});
