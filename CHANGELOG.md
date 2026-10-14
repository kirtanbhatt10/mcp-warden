# Changelog

## 1.1.0 — 2026-10-14

### Added
- **`mcp-warden inspect`** — connect to a live MCP server (stdio command, `--url` Streamable HTTP/SSE, or `--server`/`--all` from your configs), fetch `tools/list` and run every tool-poisoning rule on what the model actually sees.
- **Rug-pull detection** — `--lock <file>` pins a SHA-256 of every tool definition; later runs flag changed (TP011), removed (TP012) and new (TP013) tools. `--update-lock` accepts reviewed changes.
- **Baselines** — `--write-baseline` / `--baseline` so teams can adopt mcp-warden in CI and only fail on *new* findings.
- **Project settings** — `.mcp-warden.json` (`paths`, `ignore`, `failOn`, `minSeverity`, `baseline`, `format`), searched upwards from the working directory.
- **pre-commit hook** (`.pre-commit-hooks.yaml`).
- `baseline` input for the GitHub Action.
- `examples/servers/demo-server.js` — a harmless MCP server with benign, poisoned and rug-pull modes for demos and tests.
- Demo recordings in `docs/`.

## 1.0.0 — 2026-10-14

First public release.

- 19 config rules (MW001–MW019): hard-coded secrets (25+ token formats), unpinned packages, typosquats, archived servers, insecure transport, shell/remote-code launchers, dangerous containers, broad filesystem access, secrets in URLs, auto-approve, privilege escalation, inline code, disabled TLS, untrusted registries, file permissions, known-vulnerable/malicious packages.
- 10 tool-poisoning rules (TP001–TP010) including Unicode tag-character decoding and cross-server tool-name collisions.
- Auto-discovery for Claude Desktop, Claude Code, Cursor, VS Code (+Insiders/VSCodium), Windsurf, Gemini CLI, Codex CLI, Zed, Cline, Roo Code, Amazon Q and LM Studio on macOS, Linux and Windows.
- Text, JSON, SARIF 2.1.0 and Markdown reports; security score and grade.
- Composite GitHub Action with SARIF upload.
- Zero runtime dependencies; built-in JSONC and TOML parsers.
