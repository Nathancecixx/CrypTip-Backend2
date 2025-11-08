import type { NextRequest } from 'next/server';
import { requireSession, UnauthorizedError } from './auth';
import { getUserById } from './db';

export type SessionInfo = {
  sub: string;
  wallet: string;
  handle: string | null;
};

export async function getSessionFromRequest(req: NextRequest): Promise<SessionInfo | null> {
  try {
    const { userId } = requireSession(req);
    const user = await getUserById(userId);
    if (!user) return null;

    return {
      sub: user.id,
      wallet: user.wallet_pubkey,
      handle: user.handle,
    };
  } catch (error) {
    if (error instanceof UnauthorizedError) {
      return null;
    }
    throw error;
  }
}
