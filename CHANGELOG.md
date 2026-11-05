# Changelog

## Unreleased

- **Breaking:** an explicit empty trust allowlist now raises before discovery,
  with a message distinct from missing trust. Wildcard empty-server discovery
  remains valid.
- Report missing explicitly configured tools through optional async
  `onDiagnostic`, or a native Node warning by default. Diagnostics contain only
  configured names; callback failures propagate without offering tools.
- **Behavior change:** increase the default result limit from 65,536 to 262,144
  UTF-8 bytes, matching PHP. Explicit limits and disabled limits retain their
  meaning; oversized success and error results are refused.
- **Breaking:** replace silently dropped nontext content with ordered omission
  markers. Forward text only from parts labelled `type: 'text'`.
- **Breaking:** invalid mirrored annotations on explicitly trusted tools raise;
  wildcard exclusions remain inspectable through `excluded()`.
- **Breaking:** only absent or literal `false` `isError` values report success.
  All other present values, including `null`, report guarded tool failure.
- No HTTP transport, cache or mirrored header value encoding change.
