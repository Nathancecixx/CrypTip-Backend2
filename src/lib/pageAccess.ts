export type ActiveEntitlement = {
  sku: string;
  type?: string;
  status?: string;
};

export type PageUpdatePayload = {
  slug?: string;
  custom_domain?: string | null;
  [key: string]: unknown;
};

export type PageUpdateContext = {
  wallet: string;
  entitlements: ActiveEntitlement[];
};

export class ForbiddenError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ForbiddenError';
  }
}

const VANITY_SKU = 'vanity';
const CUSTOM_DOMAIN_SKU = 'custom_domain';

function hasEntitlement(entitlements: ActiveEntitlement[], sku: string) {
  const normalized = sku.toLowerCase();
  return entitlements.some((ent) => {
    if (!ent) return false;
    if (ent.status && ent.status !== 'active') return false;
    const entSku = typeof ent.sku === 'string' ? ent.sku.toLowerCase() : '';
    if (!entSku) return false;
    return entSku === normalized || entSku.startsWith(`${normalized}.`);
  });
}

export function authorizePageUpdate(payload: PageUpdatePayload, context: PageUpdateContext) {
  const sanitized: PageUpdatePayload = { ...payload };
  const { wallet, entitlements } = context;

  if (typeof sanitized.slug !== 'undefined' && sanitized.slug !== wallet) {
    if (!hasEntitlement(entitlements, VANITY_SKU)) {
      throw new ForbiddenError('Vanity subscription required to set custom slug.');
    }
  }

  if (typeof sanitized.custom_domain !== 'undefined') {
    const value = sanitized.custom_domain;
    const trimmed = typeof value === 'string' ? value.trim() : value ?? '';
    const normalized = typeof trimmed === 'string' ? trimmed : '';

    if (normalized.length > 0 && !hasEntitlement(entitlements, CUSTOM_DOMAIN_SKU)) {
      throw new ForbiddenError('Custom domain entitlement required.');
    }

    sanitized.custom_domain = normalized.length > 0 ? normalized : null;
  }

  return sanitized;
}

export function hasVanityEntitlement(entitlements: ActiveEntitlement[]) {
  return hasEntitlement(entitlements, VANITY_SKU);
}

export function hasCustomDomainEntitlement(entitlements: ActiveEntitlement[]) {
  return hasEntitlement(entitlements, CUSTOM_DOMAIN_SKU);
}
