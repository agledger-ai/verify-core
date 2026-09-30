import { describe, expect, it } from 'vitest';
import { suggestion, type FailureCode } from '../failures.js';

describe('failure taxonomy', () => {
  it('carries a next step for the envelope claim checks the dump verifier runs', () => {
    const claimCodes: FailureCode[] = ['CHECKPOINT_CLAIM_MISMATCH', 'TENANT_READ_CLAIM_MISMATCH', 'TENANT_CHECKPOINT_CLAIM_MISMATCH'];
    for (const code of claimCodes) expect(suggestion(code)).toMatch(/signed inside .* envelope .* rewritten beside an intact envelope/);
  });
});
