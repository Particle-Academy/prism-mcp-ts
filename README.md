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
| **Undeclared is not permissive.** | `TrustPolicy.undeclared()` — the state when nobody said anything — allows nothing. `allowing([])` is declared-empty, which is a *different* state from undeclared, and the two are kept distinct rather than collapsed to one falsy check. |
| **A tool can be pinned to its definition.** | `allowing(tools, pins)` takes a digest per tool. `ToolDefinition.digest()` covers everything the model will see — name, title, description, input schema — with keys sorted recursively so a server reordering its JSON does not read as a rewritten tool. A server that swaps a description after you approved it fails the pin instead of quietly changing what the model was told. Annotations are deliberately **not** pinned: the spec already tells clients to distrust them, and a server claiming `readOnlyHint: true` can delete your files anyway. |
| **An oversized result is refused, not truncated.** | `ResultGuard` throws `result_too_large` past its cap (64 KiB default). Truncating would hand the model a partial result it reasons about as though it were complete. The cap is also the only bound on how many tokens a remote party can spend on your behalf. |
| **A result is framed as untrusted data.** | On by default. The result is wrapped in a tag naming the server and tool, carrying **a random id per result** — a fixed marker is forgeable, since a server that knows the closing tag can emit one and have the rest of its output read as though it came from outside the wrapper (G-60). The server-chosen tool name is attribute-escaped, which the reference does not do. |
| **A gate can refuse a specific call.** | `gate` sees the server, the tool and the actual arguments, and may refuse per call — which is where authorization belongs, since only the host knows who is asking. |

Trusting every tool a server offers is possible and is spelled out as such.
It is not reachable by leaving a field unset.

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
