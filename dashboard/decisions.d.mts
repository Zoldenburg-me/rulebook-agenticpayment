export function verifyHeldDecision(args: {
  config: unknown;
  contractId: string;
  id: string;
  status: 'approved' | 'rejected';
  assertion: unknown;
  minNonce: number;
  nowSecs: number;
  port?: number;
}): Promise<void>;
