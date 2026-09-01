import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { ToolDefinition, type JsonObject } from '../src/index.js';

/**
 * The cross-language digest corpus from `prism-parity`.
 *
 * This is the suite that could not be written inside one language. Every
 * per-language test of `digest()` passes trivially — the implementation and the
 * expectation come from the same encoder — and three implementations were
 * perfectly happy producing three different hashes for the same tool.
 *
 * A digest is the material of a `TrustPolicy` pin. An operator computes one
 * against a running server and pastes it into a config, and nothing in either
 * language tells them the two disagree. It fails CLOSED, which is the safe
 * direction, but the failure looks like a rug pull that did not happen — and
 * the usual response to a pin that refuses a tool you trust is to delete the
 * pin.
 *
 * Rows this language does not match the reference on are asserted as
 * DIVERGENCES rather than skipped. A skip removes the row from the report; this
 * keeps it visible and goes red the moment either side changes, which is what
 * makes the eventual fix detectable. See G-20.
 */
interface DigestCase {
  id: string;
  title: string;
  payload: JsonObject;
  digest: { php: string; ts: string; py: string };
  agrees: boolean;
  divergence?: string;
  notes: string;
}

const corpus = JSON.parse(
  readFileSync(new URL('./fixtures/mcp-tool-digest.json', import.meta.url), 'utf8'),
) as { cases: DigestCase[] };

const agreeing = corpus.cases.filter((entry) => entry.agrees);
const diverging = corpus.cases.filter((entry) => !entry.agrees);

describe('the cross-language tool-digest corpus', () => {
  it('is the whole suite, not a subset someone trimmed to green', () => {
    expect(corpus.cases).toHaveLength(10);
  });

  it.each(corpus.cases)('$id produces this language’s recorded digest ($title)', ({ payload, digest }) => {
    expect(ToolDefinition.fromPayload(payload).digest()).toBe(digest.ts);
  });

  it.each(agreeing)('$id agrees with the PHP reference, so a pin transfers ($title)', ({ payload, digest }) => {
    expect(ToolDefinition.fromPayload(payload).digest()).toBe(digest.php);
  });

  it.each(diverging)('$id STILL diverges from the reference ($divergence)', ({ payload, digest }) => {
    // Asserted in the negative on purpose. When someone fixes G-20 this test
    // fails, which forces the corpus and the manifest's gap statement to be
    // updated in the same change rather than left claiming a divergence that
    // no longer exists.
    expect(ToolDefinition.fromPayload(payload).digest()).not.toBe(digest.php);
  });

  it('diverges on exactly the three rows the manifest names', () => {
    expect(diverging.map((entry) => entry.id)).toEqual(['dig-0002', 'dig-0003', 'dig-0007']);
  });

  it('agrees with Python on EVERY row, including the divergent ones', () => {
    // The useful signal. Two ports disagreeing with the reference in the same
    // place is one reference-side artefact plus one coercion choice; two ports
    // disagreeing with the reference in DIFFERENT places would be two
    // independent bugs, and a much worse position.
    for (const entry of corpus.cases) expect(entry.digest.ts).toBe(entry.digest.py);
  });
});
