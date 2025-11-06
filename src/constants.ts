export const SKU = {
  VANITY_MONTHLY: 'vanity.monthly',
  TEMPLATES_PACK_A: 'templates.packA',
  ADDON_HALO_V1: 'addon.halo.v1',
} as const;

export const SKU_ALLOWLIST = new Set(Object.values(SKU));

export const COLLECTION = {
  MAIN: process.env.MINT_COLLECTION_ADDRESS || '',
};
