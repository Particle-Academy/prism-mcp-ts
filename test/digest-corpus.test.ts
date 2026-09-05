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
 * **All thirteen rows agree as of 2026-09-04.** Three did not: dig-0002 and
 * dig-0003 were closed in the REFERENCE, which stopped rendering an empty
 * map-typed field as `[]`, and dig-0007 was closed HERE, by coercing an absent
 * description to `''` as the reference always has. Opposite directions, each
 * judged on its own merits. G-20.
 *
 * Every digest in the corpus changed as a result. A pin recorded before that
 * date matches none of the three implementations and has to be recomputed.
 */
interface DigestCase {
  id: string;
  title: string;
  payload: JsonObject;
  digest: { php: string; ts: string; py: string };
  agrees: boolean;
  notes: string;
}

const corpus = JSON.parse(
  readFileSync(new URL('./fixtures/mcp-tool-digest.json', import.meta.url), 'utf8'),
) as { cases: DigestCase[] };

const byId = new Map(corpus.cases.map((entry) => [entry.id, entry]));

function payload(id: string): JsonObject {
  const entry = byId.get(id);

  if (entry === undefined) throw new Error(`The corpus has no row ${id}.`);

  return entry.payload;
}

describe('the cross-language tool-digest corpus', () => {
  it('is the whole suite, not a subset someone trimmed to green', () => {
    expect(corpus.cases).toHaveLength(13);
  });

  it.each(corpus.cases)('$id produces this language’s recorded digest ($title)', ({ payload, digest }) => {
    expect(ToolDefinition.fromPayload(payload).digest()).toBe(digest.ts);
  });

  it.each(corpus.cases)('$id agrees with the PHP reference, so a pin transfers ($title)', ({ payload, digest }) => {
    expect(ToolDefinition.fromPayload(payload).digest()).toBe(digest.php);
  });

  it('records no divergence, because there is none left to record', () => {
    // The three rows that used to be asserted in the NEGATIVE are gone, which
    // is what closing G-20 looks like from here. Kept as a positive assertion
    // rather than deleted: a suite that simply stopped mentioning divergence
    // could not tell "fixed" from "no longer checked".
    expect(corpus.cases.filter((entry) => !entry.agrees)).toEqual([]);
  });

  it('agrees with Python on EVERY row', () => {
    // Two ports disagreeing with the reference in the same place was the useful
    // signal while G-20 was open — one reference-side artefact plus one coercion
    // choice, rather than two independent port bugs. Kept now because it is the
    // cheapest way to notice one port being fixed without the other.
    for (const entry of corpus.cases) expect(entry.digest.ts).toBe(entry.digest.py);
  });

  it('reads an ABSENT schema and an explicitly empty one as the same tool', () => {
    // dig-0002 omits `inputSchema`; dig-0011 sends `{}`. A server that starts
    // emitting a field it used to leave out has not rewritten its tool, and a
    // pin that broke on that would be deleted by the first operator it hit.
    expect(ToolDefinition.fromPayload(payload('dig-0002')).digest()).toBe(
      ToolDefinition.fromPayload(payload('dig-0011')).digest(),
    );
  });

  it('digests an empty LIST as a list, so the reference fix did not over-reach', () => {
    // The guard on the FIX rather than on the defect. `required` is a list and
    // `properties` is a map; a rule that promoted every empty array to an object
    // would have rendered `"required": []` as `{}` — green on the rows the fix
    // was for, and broken on a far more ordinary one. This language never had
    // the ambiguity, so this row is what makes it the reference's check too.
    const asList = ToolDefinition.fromPayload(payload('dig-0012'));
    const asMap = ToolDefinition.fromPayload({
      name: 'search',
      description: 'd',
      inputSchema: { type: 'object', properties: {}, required: {} },
    });

    expect(asList.digest()).not.toBe(asMap.digest());
    expect(asList.digest()).toBe(byId.get('dig-0012')?.digest.php);
  });
});
