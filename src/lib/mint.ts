import { env } from './env';
import { log } from './logger';

export type MintResult = { mint: string; metadataUri?: string; collectionVerified?: boolean };

export async function mintLicense(userWallet: string, sku: string): Promise<MintResult> {
  if (env.ENABLE_FAKE_MINT === '1') {
    const fake = `FakeMint${Math.random().toString(36).slice(2,10)}`;
    log('mint.fake.license', { userWallet, sku, mint: fake });
    return { mint: fake, collectionVerified: true };
  }
  // TODO: Implement Token‑2022 NonTransferable mint flow (server‑signer)
  throw new Error('Mint not implemented');
}

export async function mintAddon(userWallet: string, sku: string): Promise<MintResult> {
  if (env.ENABLE_FAKE_MINT === '1') {
    const fake = `FakeMint${Math.random().toString(36).slice(2,10)}`;
    log('mint.fake.addon', { userWallet, sku, mint: fake });
    return { mint: fake, collectionVerified: true };
  }
  // TODO: Implement Metaplex NFT mint, collection‑verified
  throw new Error('Mint not implemented');
}
