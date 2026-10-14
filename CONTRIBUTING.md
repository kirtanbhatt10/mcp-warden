# Contributing to mcp-warden

Thanks for helping make AI agents safer! Contributions of every size are welcome — a new token pattern or a malicious package name is a great first PR.

## Setup

```bash
git clone https://github.com/kirtanbhatt10/mcp-warden && cd mcp-warden
npm test            # node --test, no install step needed
npm run demo        # scan the bundled vulnerable examples
```

There are **no dependencies** and we'd like to keep it that way.

## Project layout

| Path | What lives there |
|---|---|
| `src/rules.js` | Config rules (`MW…`). Each rule has `id`, `name`, `severity`, `title`, `description`, `fix` and a `check(server)` function |
| `src/tools.js` | Tool-poisoning rules (`TP…`) |
| `src/secrets.js` | Token patterns, placeholder detection, entropy |
| `src/packages.js` | npx / uvx / docker launch parsing and pin detection |
| `src/data.js` | Popular, archived and known-vulnerable package lists |
| `src/discover.js` | Client config locations per OS |
| `src/report.js` | text / JSON / SARIF / Markdown output |
| `src/inspect.js` | Live MCP client (stdio + Streamable HTTP) used by `inspect` |
| `src/lock.js` | Tool-definition hashing and rug-pull lock files |
| `src/baseline.js` | Baselines and `.mcp-warden.json` settings |
| `examples/servers/demo-server.js` | Harmless MCP server with benign / poisoned / rug-pull modes for tests |

## Adding a rule

1. Add it to `SERVER_RULES` in `src/rules.js` (or `TOOL_RULES` in `src/tools.js`) with the next free ID.
2. Add positive **and** negative tests in `test/`. False positives matter as much as detections.
3. Run `node scripts/gen-rules-doc.js` to refresh `docs/rules.md`, and add a row to the README table.
4. Never commit real-looking secrets — build test tokens at runtime (see `fake()` in `test/rules.test.js`).

## Adding a client

Add its config paths to `knownLocations()` in `src/discover.js`. If it uses a new schema, teach `extractServers()` / `normalizeServer()` in `src/config.js` and add a test.

## Commit style

Small, focused PRs with a clear description. Conventional-commit prefixes (`feat:`, `fix:`, `docs:`) are appreciated but not required.
