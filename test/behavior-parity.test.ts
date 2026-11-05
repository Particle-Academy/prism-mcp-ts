import { describe, expect, it, vi } from 'vitest';
import { Client, ResultGuard, ToolDefinition, TrustPolicy, type JsonObject, type JsonValue } from '../src/index.js';

const payload = { name: 'owned', description: 'Owned fixture', inputSchema: { type: 'object', properties: {} } };
const tool = ToolDefinition.fromPayload(payload);
function clientFor(reply: JsonValue, trust = TrustPolicy.allowingEveryTool()) {
  const transport = vi.fn(async () => reply);
  return { client: new Client({ server: 'configured', transport, trust, guard: new ResultGuard({ frameProvenance: false }) }), transport };
}

describe('G230 native behavior boundaries', () => {
  it.each([['missing', TrustPolicy.undeclared()], ['empty', TrustPolicy.allowing([])]] as const)('refuses %s trust before transport', async (_name, policy) => {
    const { client, transport } = clientFor({ tools: [] }, policy);
    await expect(client.listTools()).rejects.toMatchObject({ code: 'server_not_trusted' });
    expect(transport).not.toHaveBeenCalled();
  });

  it('preserves wildcard discovery of an empty server', async () => {
    const { client, transport } = clientFor({ tools: [] });
    await expect(client.listTools()).resolves.toEqual([]);
    expect(transport).toHaveBeenCalledTimes(1);
  });

  it.each([null, true, 0, 1, '', 'false', 'true', [], {}].map((value) => ({ value })))('treats present non-false isError $value as failure', async ({ value }) => {
    const { client } = clientFor({ content: [{ type: 'text', text: 'owned' }], isError: value });
    expect((await client.callTool(tool)).isError).toBe(true);
  });

  it.each([{}, { isError: false }])('keeps absent or literal false successful', async (flags) => {
    const { client } = clientFor({ content: [{ type: 'text', text: 'owned' }], ...flags });
    expect((await client.callTool(tool)).isError).toBe(false);
  });

  it('uses the 262144-byte default and counts UTF-8 bytes', () => {
    const guard = new ResultGuard({ frameProvenance: false });
    expect(guard.guard('configured', 'owned', 'é'.repeat(131072))).toHaveLength(131072);
    expect(() => guard.guard('configured', 'owned', 'é'.repeat(131073))).toThrowError(/cap/);
  });

  it('does not let an error bypass the cap', async () => {
    const { client } = clientFor({ content: [{ type: 'text', text: 'a'.repeat(262145) }], isError: true });
    await expect(client.callTool(tool)).rejects.toMatchObject({ code: 'result_too_large' });
  });

  it('marks omitted content in order and never forwards its text or data', async () => {
    const { client } = clientFor({ content: [{ type: 'text', text: 'alpha' }, { type: 'image', text: 'SYNTHETIC_SECRET', data: 'SYNTHETIC_SECRET' }, { text: 'SYNTHETIC_SECRET' }, { type: 'text', text: 'omega' }] });
    expect((await client.callTool(tool)).text).toBe('alpha\n[image content omitted: this release passes text through only]\n[unknown content omitted: this release passes text through only]\nomega');
  });

  it('raises when an explicitly named tool has invalid annotations', async () => {
    const bad: JsonObject = { ...payload, inputSchema: { type: 'object', properties: { tenant: { type: 'object', 'x-mcp-header': 'Tenant' } } } };
    const { client } = clientFor({ tools: [bad] }, TrustPolicy.allowing(['owned']));
    await expect(client.listTools()).rejects.toMatchObject({ code: 'mirrored_parameter_refused' });
  });

  it('warns by default when configured names are not offered', async () => {
    const warning = vi.spyOn(process, 'emitWarning').mockImplementation(() => {});
    try {
      const { client } = clientFor({ tools: [payload] }, TrustPolicy.allowing(['owned', 'configured_missing']));
      expect((await client.listTools()).map((entry) => entry.name)).toEqual(['owned']);
      expect(warning).toHaveBeenCalledTimes(1);
      expect(warning.mock.calls[0]?.[0]).toContain('configured_missing');
    } finally { warning.mockRestore(); }
  });

  it('reports immutable configured names and replaces the native warning', async () => {
    const warning = vi.spyOn(process, 'emitWarning').mockImplementation(() => {});
    const diagnostic = vi.fn();
    try {
      const client = new Client({ server: 'configured', trust: TrustPolicy.allowing(['owned', 'configured_missing']), onDiagnostic: diagnostic, transport: async () => ({ tools: [payload, { ...payload, name: 'REMOTE_SENTINEL', description: 'REMOTE_SECRET' }] }) });
      expect((await client.listTools()).map((entry) => entry.name)).toEqual(['owned']);
      expect(diagnostic).toHaveBeenCalledTimes(1);
      expect(diagnostic.mock.calls[0]?.[0]).toEqual({ code: 'trusted_tools_not_offered', server: 'configured', toolNames: ['configured_missing'] });
      const value = diagnostic.mock.calls[0]?.[0];
      expect(Object.isFrozen(value)).toBe(true);
      expect(Object.isFrozen(value.toolNames)).toBe(true);
      expect(JSON.stringify(value)).not.toContain('REMOTE_');
      expect(warning).not.toHaveBeenCalled();
    } finally { warning.mockRestore(); }
  });

  it.each(['sync', 'async'] as const)('propagates a %s diagnostic failure without offering tools', async (kind) => {
    const failure = new Error('owned diagnostic failure');
    const onDiagnostic = kind === 'sync' ? () => { throw failure; } : async () => { throw failure; };
    const client = new Client({ server: 'configured', trust: TrustPolicy.allowing(['configured_missing']), transport: async () => ({ tools: [] }), onDiagnostic });
    await expect(client.listTools()).rejects.toBe(failure);
  });

  it('does not report remote-only names for wildcard trust', async () => {
    const diagnostic = vi.fn();
    const client = new Client({ server: 'configured', trust: TrustPolicy.allowingEveryTool(), transport: async () => ({ tools: [payload] }), onDiagnostic: diagnostic });
    expect(await client.listTools()).toHaveLength(1);
    expect(diagnostic).not.toHaveBeenCalled();
  });

  it('keeps detached wildcard exclusions and clears them on a fresh discovery', async () => {
    const bad: JsonObject = { ...payload, inputSchema: { properties: { tenant: { type: 'object', 'x-mcp-header': 'Tenant' } } } };
    const transport = vi.fn().mockResolvedValueOnce({ tools: [bad] }).mockResolvedValueOnce({ tools: [payload] });
    const client = new Client({ server: 'configured', trust: TrustPolicy.allowingEveryTool(), transport });
    expect(await client.listTools()).toEqual([]);
    const excluded = client.excluded();
    expect(excluded).toHaveProperty('owned');
    expect(Reflect.deleteProperty(excluded, 'owned')).toBe(false);
    expect(client.excluded()).toHaveProperty('owned');
    expect(await client.listTools()).toHaveLength(1);
    expect(client.excluded()).toEqual({});
  });
});
