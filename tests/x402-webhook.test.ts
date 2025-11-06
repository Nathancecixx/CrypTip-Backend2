import { test } from 'node:test';
import assert from 'node:assert/strict';
import { SKU } from '@/src/constants';
import type { PurchaseStatusResult, PurchaseRow } from '@/src/lib/db';
import type { X402WebhookDeps } from '@/app/api/store/webhook/x402/route';

const envDefaults = {
  RPC_PRIMARY_URL: 'http://localhost:8899',
  NEXT_PUBLIC_SUPABASE_URL: 'http://localhost:54321',
  SUPABASE_SERVICE_ROLE_KEY: 'service-role-key',
  JWT_SECRET: 'jwt-secret-value-that-is-32-chars',
  SIWS_DOMAIN: 'localhost',
  X402_WEBHOOK_SECRET: 'webhook-secret',
  MINT_COLLECTION_ADDRESS: 'collection-address-12345',
  MINT_SIGNER_SECRET: 'signer-secret-value-6789',
};

for (const [key, value] of Object.entries(envDefaults)) {
  if (!process.env[key]) {
    process.env[key] = value;
  }
}

test('duplicate webhooks do not trigger additional mints', async () => {
  const minted: Array<{ wallet: string; sku: string }> = [];
  const addedEntitlements: any[] = [];
  const subscriptionInserts: any[] = [];
  const logs: Array<{ event: string; payload: any }> = [];
  const webhookEvents: any[] = [];

  const purchaseRow: PurchaseRow = {
    id: 'order-1',
    sku: SKU.TEMPLATES_PACK_A,
    user_id: 'user-1',
    status: 'paid',
    tx_sig: 'tx-1',
  };

  let markCalls = 0;
  const markPurchaseStatus = async (): Promise<PurchaseStatusResult> => {
    markCalls += 1;
    return markCalls === 1
      ? { row: purchaseRow, previous_status: 'pending', updated: true }
      : { row: purchaseRow, previous_status: 'paid', updated: false };
  };

  const deps: X402WebhookDeps = {
    verifyX402Webhook: () => true,
    supa: {
      from(table: string) {
        if (table === 'webhook_events') {
          return {
            insert: async (payload: any) => {
              webhookEvents.push(payload);
              return { data: payload, error: null };
            },
          };
        }
        if (table === 'entitlements') {
          return {
            insert: async (payload: any) => {
              subscriptionInserts.push(payload);
              return { data: payload, error: null };
            },
          };
        }
        throw new Error(`Unexpected table ${table}`);
      },
    } as unknown as X402WebhookDeps['supa'],
    waitForFinalized: async () => true,
    markPurchaseStatus,
    log(event: string, payload: any) {
      logs.push({ event, payload });
    },
    mintAddon: async () => {
      throw new Error('mintAddon should not be called');
    },
    mintLicense: async (wallet: string, sku: string) => {
      minted.push({ wallet, sku });
      return { mint: `mint-${minted.length}` };
    },
    addEntitlement: async (payload: any) => {
      addedEntitlements.push(payload);
      return payload;
    },
  };

  const payload = {
    order_id: purchaseRow.id,
    sku: purchaseRow.sku,
    tx_sig: purchaseRow.tx_sig!,
    amount_atomic: 100,
    user_wallet: 'wallet-1',
  };

  const headers = new Headers({
    'x-402-signature': 'sig-1',
    'x-idempotency-key': 'idem-1',
  });

  const { handleX402Webhook } = await import('@/app/api/store/webhook/x402/route');

  const firstResponse = await handleX402Webhook(
    new Request('http://localhost/api/store/webhook/x402', {
      method: 'POST',
      headers,
      body: JSON.stringify(payload),
    }),
    deps,
  );

  assert.equal(firstResponse.status, 200);
  await firstResponse.json();

  const secondResponse = await handleX402Webhook(
    new Request('http://localhost/api/store/webhook/x402', {
      method: 'POST',
      headers: new Headers({
        'x-402-signature': 'sig-1',
        'x-idempotency-key': 'idem-1',
      }),
      body: JSON.stringify(payload),
    }),
    deps,
  );

  assert.equal(secondResponse.status, 200);
  await secondResponse.json();

  assert.equal(markCalls, 2);
  assert.equal(minted.length, 1);
  assert.equal(addedEntitlements.length, 1);
  assert.equal(subscriptionInserts.length, 0);
  const duplicateLog = logs.find((entry) => entry.event === 'purchase.duplicate');
  assert.ok(duplicateLog, 'expected duplicate log entry');
  assert.equal(webhookEvents.length, 2);
});
