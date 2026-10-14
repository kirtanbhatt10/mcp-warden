# Changelog

## 1.0.0 — 2026-10-14

First public release.

- 19 config rules (MW001–MW019): hard-coded secrets (25+ token formats), unpinned packages, typosquats, archived servers, insecure transport, shell/remote-code launchers, dangerous containers, broad filesystem access, secrets in URLs, auto-approve, privilege escalation, inline code, disabled TLS, untrusted registries, file permissions, known-vulnerable/malicious packages.
- 10 tool-poisoning rules (TP001–TP010) including Unicode tag-character decoding and cross-server tool-name collisions.
- Auto-discovery for Claude Desktop, Claude Code, Cursor, VS Code (+Insiders/VSCodium), Windsurf, Gemini CLI, Codex CLI, Zed, Cline, Roo Code, Amazon Q and LM Studio on macOS, Linux and Windows.
- Text, JSON, SARIF 2.1.0 and Markdown reports; security score and grade.
- Composite GitHub Action with SARIF upload.
- Zero runtime dependencies; built-in JSONC and TOML parsers.
