import { Connection, clusterApiUrl } from '@solana/web3.js';
import { env } from './env';

export function rpc() {
  const url = env.RPC_PRIMARY_URL || clusterApiUrl(env.NEXT_PUBLIC_SOLANA_CLUSTER as any);
  return new Connection(url, { commitment: 'finalized' });
}

export async function waitForFinalized(signature: string, timeoutMs = 15000) {
  const conn = rpc();
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    const st = await conn.getSignatureStatus(signature, { searchTransactionHistory: true });
    const s = st?.value;
    if (s && s.confirmationStatus === 'finalized') return true;
    await new Promise(r => setTimeout(r, 1200));
  }
  return false;
}

export async function getParsedTransaction(signature: string) {
  const conn = rpc();
  return conn.getParsedTransaction(signature, { maxSupportedTransactionVersion: 0 });
}
