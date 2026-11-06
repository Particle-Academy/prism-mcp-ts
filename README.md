# Prism MCP for TypeScript

Consuming MCP servers as Prism tools, across an explicit trust boundary. The
TypeScript port of
[`particle-academy/prism-mcp`](https://github.com/Particle-Academy/prism-mcp).

Zero runtime dependencies. Node 22+.

```
npm install @particle-academy/prism-mcp
```

## Usage

You supply the transport — a function from a request to a JSON result — and the
package supplies the trust boundary around it:

```ts
import { Client, TrustPolicy } from '@particle-academy/prism-mcp';

const client = new Client({
  server: 'tickets',
  transport: myTransport,
  trust: TrustPolicy.allowing(['search_tickets', 'read_ticket']),
});

const tools = await client.listTools();

const result = await client.callTool(tools[0], { query: 'open bugs' });

result.text;
result.isError;
```

A refusal throws `McpError`, whose `code` names which rule stopped it.

## An MCP server is not trusted input

A server describes its own tools, and those descriptions reach your model. That
makes a server a party that can rewrite what your agent believes it is calling,
so nothing here trusts it by default:

| | |
|---|---|
| **Undeclared is not permissive.** | `TrustPolicy.undeclared()` and `allowing([])` both raise `server_not_trusted` before discovery sends a request, with distinct missing and empty allowlist messages. Use `allowingEveryTool()` explicitly to accept every tool, including an empty server. |
| **A tool can be pinned to its definition.** | `allowing(tools, pins)` takes a digest per tool. `ToolDefinition.digest()` covers everything the model will see — name, title, description, input schema — with keys sorted recursively so a server reordering its JSON does not read as a rewritten tool. A server that swaps a description after you approved it fails the pin instead of quietly changing what the model was told. Annotations are deliberately **not** pinned: the spec already tells clients to distrust them, and a server claiming `readOnlyHint: true` can delete your files anyway. |
| **An oversized result is refused, not truncated.** | `ResultGuard` throws `result_too_large` past its cap (262,144 UTF-8 bytes by default). Truncating would hand the model a partial result it reasons about as though it were complete. Set `maxBytes` explicitly for a smaller bound; `0` disables it. The cap is also the only bound on how many tokens a remote party can spend on your behalf. |
| **A result is framed as untrusted data.** | On by default. The result is wrapped in a tag naming the server and tool, carrying **a random id per result** — a fixed marker is forgeable, since a server that knows the closing tag can emit one and have the rest of its output read as though it came from outside the wrapper (G-60). The server-chosen tool name is attribute-escaped, which the reference does not do. |
| **A gate can refuse a specific call.** | `gate` sees the server, the tool and the actual arguments, and may refuse per call — which is where authorization belongs, since only the host knows who is asking. |

Trusting every tool a server offers is possible and is spelled out as such.
It is not reachable by leaving a field unset.

## Discovery diagnostics

An explicit allowlist naming tools the server did not offer produces a native
Node warning with code `MCP_TRUSTED_TOOLS_NOT_OFFERED`. To route the diagnostic
through your application, pass `onDiagnostic` in `ClientOptions`:

```ts
const client = new Client({
  server: 'tickets', transport: myTransport,
  trust: TrustPolicy.allowing(['search_tickets']),
  onDiagnostic: async (event) => {
    // event.code === 'trusted_tools_not_offered'
    // event.server and event.toolNames contain only application-configured names.
    await reportMissingTools(event);
  },
});
```

The event and its `toolNames` list are frozen. Supplying a callback replaces
the native warning. Its completion is awaited; a throw or rejected promise
propagates from `listTools()` and no tools are returned. Wildcard trust has
no configured tool names to report.

A tool with invalid `x-mcp-header` annotations raises
`mirrored_parameter_refused` when your allowlist explicitly names it. Under
wildcard trust it is excluded; `client.excluded()` returns a frozen, detached
snapshot of tool names and reasons, cleared on each discovery. Treat exclusion
reasons as untrusted server data. Mirrored header value encoding is unchanged.

## Results

Text parts are joined in order. Nontext or malformed object parts have an
explicit marker such as `[image content omitted: this release passes text
through only]`; their data or stray `text` fields are not forwarded. Missing
or nonstring type labels are labelled `unknown`. Bounding, filtering and framing also apply to
error results.

Only an absent `isError` or literal `false` reports success. Every other present
value, including `null`, `0`, an empty string or a container, reports failure
through `result.isError`. A reported tool failure remains a guarded result;
transport failures raise separately.

## Protocol versions

`LATEST_PROTOCOL_VERSION` is `2026-07-28`. `KNOWN_PROTOCOL_VERSIONS` lists what
this port recognises, and `isStatelessProtocol()` answers whether a given
version requires session state — asked as a function because the answer is a
property of the protocol, not of your configuration.

## Parity

The refusal codes, the digest the pins compare, and the undeclared-vs-empty
distinction are pinned against the PHP reference and the Python port by
prism-parity's mcp corpus — all thirteen rows agree. Getting there moved the
reference, which had treated an empty tool map and an absent tool description as
the same thing; every pin minted before that agreement is invalidated by it.
