# Security policy

## Reporting a vulnerability in mcp-warden

Please **do not** open a public issue. Use GitHub's [private vulnerability reporting](https://github.com/kirtanbhatt10/mcp-warden/security/advisories/new) or email **kirtan11bhatt@gmail.com**. You'll get a response within 72 hours.

## Reporting a malicious or vulnerable MCP package

Found an MCP server that should be flagged by `MW019 known-vulnerable-package`? Open an issue with the "New rule / detection" template and a link to the advisory or write-up, or send a PR adding it to `src/data.js`.

## Scope

mcp-warden is a static, read-only analyzer. It never executes the servers it inspects and makes no network requests. A clean report does not guarantee a server is safe — it means none of the known risky patterns were found.
