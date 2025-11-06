import { z } from 'zod';

const EnvSchema = z.object({
  NEXT_PUBLIC_SOLANA_CLUSTER: z.enum(['mainnet-beta','devnet','testnet']).default('mainnet-beta'),
  RPC_PRIMARY_URL: z.string().url(),
  RPC_FALLBACK_URL: z.string().url().optional(),

  NEXT_PUBLIC_SUPABASE_URL: z.string().url(),
  SUPABASE_SERVICE_ROLE_KEY: z.string().min(10),

  JWT_SECRET: z.string().min(32),
  SIWS_DOMAIN: z.string().min(3),
  SESSION_COOKIE_NAME: z.string().default('ctj_sess'),

  X402_WEBHOOK_SECRET: z.string().min(10),

  MINT_COLLECTION_ADDRESS: z.string().min(20),
  MINT_SIGNER_SECRET: z.string().min(20),
  ENABLE_FAKE_MINT: z.string().optional(),

  UPSTASH_REDIS_REST_URL: z.string().url().optional(),
  UPSTASH_REDIS_REST_TOKEN: z.string().optional(),
});

export const env = EnvSchema.parse({
  NEXT_PUBLIC_SOLANA_CLUSTER: process.env.NEXT_PUBLIC_SOLANA_CLUSTER,
  RPC_PRIMARY_URL: process.env.RPC_PRIMARY_URL,
  RPC_FALLBACK_URL: process.env.RPC_FALLBACK_URL,

  NEXT_PUBLIC_SUPABASE_URL: process.env.NEXT_PUBLIC_SUPABASE_URL,
  SUPABASE_SERVICE_ROLE_KEY: process.env.SUPABASE_SERVICE_ROLE_KEY,

  JWT_SECRET: process.env.JWT_SECRET,
  SIWS_DOMAIN: process.env.SIWS_DOMAIN,
  SESSION_COOKIE_NAME: process.env.SESSION_COOKIE_NAME,

  X402_WEBHOOK_SECRET: process.env.X402_WEBHOOK_SECRET,

  MINT_COLLECTION_ADDRESS: process.env.MINT_COLLECTION_ADDRESS,
  MINT_SIGNER_SECRET: process.env.MINT_SIGNER_SECRET,
  ENABLE_FAKE_MINT: process.env.ENABLE_FAKE_MINT,

  UPSTASH_REDIS_REST_URL: process.env.UPSTASH_REDIS_REST_URL,
  UPSTASH_REDIS_REST_TOKEN: process.env.UPSTASH_REDIS_REST_TOKEN,
});
