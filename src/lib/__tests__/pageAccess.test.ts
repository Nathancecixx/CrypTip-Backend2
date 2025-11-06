import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { authorizePageUpdate, ForbiddenError, type ActiveEntitlement } from '../pageAccess';

const wallet = 'WalletPubKey123';

function makeEntitlement(sku: string): ActiveEntitlement {
  return { sku, status: 'active', type: 'subscription' };
}

describe('authorizePageUpdate', () => {
  it('allows slug equal to wallet without vanity entitlement', () => {
    const payload = authorizePageUpdate({ slug: wallet }, { wallet, entitlements: [] });
    assert.equal(payload.slug, wallet);
  });

  it('rejects non-wallet slug without vanity entitlement', () => {
    assert.throws(
      () => authorizePageUpdate({ slug: 'custom-slug' }, { wallet, entitlements: [] }),
      ForbiddenError,
    );
  });

  it('allows non-wallet slug with vanity entitlement', () => {
    const entitlements = [makeEntitlement('vanity')];
    const payload = authorizePageUpdate({ slug: 'custom-slug' }, { wallet, entitlements });
    assert.equal(payload.slug, 'custom-slug');
  });

  it('rejects custom domain without entitlement', () => {
    assert.throws(
      () => authorizePageUpdate({ custom_domain: 'example.com' }, { wallet, entitlements: [] }),
      ForbiddenError,
    );
  });

  it('allows custom domain with entitlement and trims value', () => {
    const entitlements = [makeEntitlement('custom_domain')];
    const payload = authorizePageUpdate({ custom_domain: '  example.com  ' }, { wallet, entitlements });
    assert.equal(payload.custom_domain, 'example.com');
  });

  it('accepts empty custom domain without entitlement and normalizes to null', () => {
    const payload = authorizePageUpdate({ custom_domain: '   ' }, { wallet, entitlements: [] });
    assert.equal(payload.custom_domain, null);
  });

  it('allows prefixed custom domain entitlement SKUs', () => {
    const entitlements = [makeEntitlement('custom_domain.plus')];
    const payload = authorizePageUpdate({ custom_domain: 'plus.example' }, { wallet, entitlements });
    assert.equal(payload.custom_domain, 'plus.example');
  });
});
