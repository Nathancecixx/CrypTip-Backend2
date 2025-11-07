import { test } from 'node:test';
import assert from 'node:assert/strict';
import { NextResponse } from 'next/server';

const envDefaults: Record<string, string> = {
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

test('setSessionCookie issues cross-site session cookie without Domain', async () => {
  const { setSessionCookie } = await import('@/src/lib/auth');
  const response = NextResponse.json({ ok: true });

  setSessionCookie(response, 'token-value');

  const header = response.headers.get('set-cookie');
  assert.ok(header, 'expected Set-Cookie header to be set');
  assert.ok(header.startsWith('ctj_sess=token-value'), 'unexpected cookie payload');
  assert.ok(header.includes('; HttpOnly'));
  assert.ok(header.includes('; Secure'));
  assert.ok(header.includes('; SameSite=None'));
  assert.ok(header.includes('; Path=/'));
  assert.ok(!header.includes('Domain='));
  assert.ok(!header.includes('Partitioned'));
});

test('setSessionCookie adds Partitioned attribute when enabled', async () => {
  const { setSessionCookie } = await import('@/src/lib/auth');
  const previous = process.env.EXPERIMENTAL_PARTITIONED_COOKIES;
  process.env.EXPERIMENTAL_PARTITIONED_COOKIES = '1';

  try {
    const response = NextResponse.json({ ok: true });
    setSessionCookie(response, 'token-value');
    const header = response.headers.get('set-cookie') ?? '';
    assert.ok(header.includes('; Partitioned'));
  } finally {
    if (previous === undefined) {
      delete process.env.EXPERIMENTAL_PARTITIONED_COOKIES;
    } else {
      process.env.EXPERIMENTAL_PARTITIONED_COOKIES = previous;
    }
  }
});
