import { describe, it, expect } from 'vitest';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { orgReadLeafHash, orgReadMerkleRoot, verifyOrgReadInclusion } from '../primitives.js';

/**
 * The org_admin_reads tree is RFC 9162 §2.1 over the bytes each hex hash
 * denotes. The reference below is written from the RFC and the route's
 * published rule, with no reference to primitives.ts, so a shared mistake
 * cannot pass both halves. The corpus section checks the primitives against
 * leaves and signed tree heads the engine wrote.
 */

const sha256 = (...parts: Buffer[]): Buffer => createHash('sha256').update(Buffer.concat(parts)).digest();
const LEAF = (data: Buffer): string => sha256(Buffer.from([0x00]), data).toString('hex');
const NODE = (l: string, r: string): string =>
  sha256(Buffer.from([0x01]), Buffer.from(l, 'hex'), Buffer.from(r, 'hex')).toString('hex');

function mth(leaves: readonly string[]): string {
  if (leaves.length === 0) return createHash('sha256').update('').digest('hex');
  if (leaves.length === 1) return leaves[0]!;
  let k = 1;
  while (k * 2 < leaves.length) k *= 2;
  return NODE(mth(leaves.slice(0, k)), mth(leaves.slice(k)));
}

/** RFC 9162 §2.1.3.1 PATH(m, D[n]), leaf to root. */
function path(m: number, leaves: readonly string[]): string[] {
  if (leaves.length <= 1) return [];
  let k = 1;
  while (k * 2 < leaves.length) k *= 2;
  return m < k
    ? [...path(m, leaves.slice(0, k)), mth(leaves.slice(k))]
    : [...path(m - k, leaves.slice(k)), mth(leaves.slice(0, k))];
}

const leafData = (i: number): Buffer => Buffer.from(`cose-sign1-${i}`);
const SIZES = [1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 33, 100];

describe('org-read Merkle primitives (RFC 9162 §2.1, hex)', () => {
  it('the leaf hash is sha256(0x00 || cose_sign1)', () => {
    expect(orgReadLeafHash(leafData(0))).toBe(LEAF(leafData(0)));
  });

  it('the empty tree is sha256("")', () => {
    expect(orgReadMerkleRoot([])).toBe(createHash('sha256').update('').digest('hex'));
  });

  it.each(SIZES)('a %i-leaf root and every inclusion path agree with the RFC', (n) => {
    const leaves = Array.from({ length: n }, (_, i) => orgReadLeafHash(leafData(i)));
    const root = mth(leaves);
    expect(orgReadMerkleRoot(leaves)).toBe(root);
    for (let i = 0; i < n; i++) {
      expect(verifyOrgReadInclusion(leaves[i]!, i, n, path(i, leaves), root), `leaf ${i} of ${n}`).toBe(true);
    }
  });

  it('a one-leaf tree has an empty path and its root is the leaf', () => {
    const leaf = orgReadLeafHash(leafData(0));
    expect(orgReadMerkleRoot([leaf])).toBe(leaf);
    expect(verifyOrgReadInclusion(leaf, 0, 1, [], leaf)).toBe(true);
    expect(verifyOrgReadInclusion(leaf, 0, 1, [leaf], leaf)).toBe(false);
  });

  it('an altered path entry, a wrong leaf, a surplus entry or an out-of-range index breaks the walk', () => {
    const leaves = Array.from({ length: 100 }, (_, i) => orgReadLeafHash(leafData(i)));
    const root = mth(leaves);
    const proof = path(42, leaves);
    const mauled = [...proof];
    mauled[1] = `${mauled[1]!.slice(0, 63)}${mauled[1]!.endsWith('0') ? '1' : '0'}`;
    expect(verifyOrgReadInclusion(leaves[42]!, 42, 100, mauled, root)).toBe(false);
    expect(verifyOrgReadInclusion(leaves[43]!, 42, 100, proof, root)).toBe(false);
    expect(verifyOrgReadInclusion(leaves[42]!, 42, 100, [...proof, proof[0]!], root)).toBe(false);
    expect(verifyOrgReadInclusion(leaves[42]!, 100, 100, proof, root)).toBe(false);
  });

  it('hashing the hex text instead of the bytes it denotes does not reproduce the root', () => {
    const leaves = Array.from({ length: 5 }, (_, i) => orgReadLeafHash(leafData(i)));
    const overText = createHash('sha256')
      .update(Buffer.from([0x01]))
      .update(leaves[0]! + leaves[1]!, 'utf8')
      .digest('hex');
    expect(overText).not.toBe(NODE(leaves[0]!, leaves[1]!));
    expect(orgReadMerkleRoot(leaves.slice(0, 2))).toBe(NODE(leaves[0]!, leaves[1]!));
  });

  it('refuses a value that is not 64 lowercase hex characters', () => {
    const leaf = orgReadLeafHash(leafData(0));
    expect(orgReadMerkleRoot([leaf, leaf.toUpperCase()])).toBeNull();
    expect(orgReadMerkleRoot([leaf, 'zz'])).toBeNull();
    expect(verifyOrgReadInclusion(leaf.slice(2), 0, 1, [], leaf)).toBe(false);
  });
});

const DUMP_DIR = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'testdata', 'conformance', 'dump');

function ndjson<T>(vector: string, file: string): T[] {
  return readFileSync(join(DUMP_DIR, vector, file), 'utf8')
    .split('\n')
    .filter((l) => l.trim() !== '')
    .map((l) => JSON.parse(l) as T);
}

interface Leaf { org_id: string; leaf_index: number; leaf_hash: string; cose_sign1: string }
interface TreeHead { org_id: string; tree_size: number; root_hash: string }

describe('org-read Merkle primitives against the engine corpus', () => {
  // Every pass vector that carries read-log leaves under a signed tree head.
  const vectors = ['valid', 'valid-unsigned-history-then-signed', 'valid-key-succession', 'valid-es256'];

  it.each(vectors)('dump/%s: every stored leaf_hash and every signed root recompute', (vector) => {
    const leaves = ndjson<Leaf>(vector, 'org_admin_reads.ndjson');
    const heads = ndjson<TreeHead>(vector, 'org_admin_reads_checkpoints.ndjson');
    expect(leaves.length).toBeGreaterThan(0);
    expect(heads.length).toBeGreaterThan(0);
    for (const leaf of leaves) {
      expect(orgReadLeafHash(Buffer.from(leaf.cose_sign1, 'base64'))).toBe(leaf.leaf_hash);
    }
    for (const head of heads) {
      const ordered = leaves
        .filter((l) => l.org_id === head.org_id)
        .sort((a, b) => a.leaf_index - b.leaf_index)
        .map((l) => l.leaf_hash);
      expect(orgReadMerkleRoot(ordered.slice(0, head.tree_size))).toBe(head.root_hash);
      for (let i = 0; i < head.tree_size; i++) {
        expect(verifyOrgReadInclusion(ordered[i]!, i, head.tree_size, path(i, ordered.slice(0, head.tree_size)), head.root_hash)).toBe(true);
      }
    }
  });

  it('dump/tenant-checkpoint-root-mismatch: the tampered root does not recompute', () => {
    const leaves = ndjson<Leaf>('tenant-checkpoint-root-mismatch', 'org_admin_reads.ndjson');
    const heads = ndjson<TreeHead>('tenant-checkpoint-root-mismatch', 'org_admin_reads_checkpoints.ndjson');
    const mismatched = heads.filter((head) => {
      const ordered = leaves.filter((l) => l.org_id === head.org_id).sort((a, b) => a.leaf_index - b.leaf_index);
      return orgReadMerkleRoot(ordered.slice(0, head.tree_size).map((l) => l.leaf_hash)) !== head.root_hash;
    });
    expect(mismatched.length).toBeGreaterThan(0);
  });
});
