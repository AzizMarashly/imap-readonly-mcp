# IMAP Read-Only MCP Server

> **Built entirely by AI (OpenAI Codex on behalf of the repo owner).**  
> The full design, code, documentation, and CI setup were generated autonomously from the user specification.

The IMAP Read-Only MCP Server exposes mailboxes to AI agents through the [Model Context Protocol](https://modelcontextprotocol.io).  
It targets a single mailbox (IMAP, POP3, or Microsoft Graph) without mutating message state—messages remain unread, drafts untouched, and folders unchanged.

## Highlights

- [OK] **Zero side effects** - all fetch operations use read-only verbs (`SELECT ... READONLY`, `BODY.PEEK`, Graph `GET`s).
- [NET] **Protocol coverage** - IMAP, POP3, and Microsoft Graph (OAuth2) connectors with a unified tool interface.
- [TOOL] **MCP aware** - rich tool set, resource templates for message bodies/raw source/attachments, and diagnostics metadata.
- [DOCKER] **Production ready** - Docker image, GitHub Actions for CI + release publishing, sample config, and typed Python package.
- [DOC] **AI-authored docs** - transparent and exhaustive explanation of configuration, architecture, and operations.

## Quick Start

1. **Clone** and install dependencies (Python 3.11+):
   ```bash
   pip install .[all]
   ```
2. **Copy the example config** and fill in secrets:
   ```bash
   cp config/accounts.example.yaml config/accounts.yaml
   ```
3. **Run the server** (stdio transport by default):
   ```bash
   imap-readonly-mcp --config config/accounts.yaml
   ```
4. **Connect via MCP** - point your MCP-compatible client (e.g. Claude Desktop) at the CLI entrypoint or the provided Docker image.

### Docker

```bash
docker build -t ghcr.io/your-org/imap-readonly-mcp:latest .
docker run --rm \
  -v "$(pwd)/config/accounts.yaml:/app/config/accounts.yaml:ro" \
  ghcr.io/your-org/imap-readonly-mcp:latest \
  --config /app/config/accounts.yaml
```

### Streamable HTTP Transport

```bash
FASTMCP_TRANSPORT=streamable-http \
FASTMCP_HOST=0.0.0.0 \
FASTMCP_PORT=8765 \
FASTMCP_STREAMABLE_HTTP__PATH=/mcp \
imap-readonly-mcp --config config/accounts.yaml --transport streamable-http
```

The server prints the bound address (for example `http://127.0.0.1:8765/mcp`). Clients must follow the MCP Streamable HTTP handshake and include `Accept: application/json, text/event-stream` when initiating a session.

## Configuration

Configuration lives in YAML (defaults to `config/accounts.yaml`). See `config/accounts.example.yaml` for a complete template.

```yaml
account:
  id: personal-imap
  protocol: imap
  host: imap.example.com
  port: 993
  username: alice@example.com
  password: change-me
```

### Environment Variables

| Variable            | Purpose                                      |
|---------------------|----------------------------------------------|
| `MAIL_CONFIG_FILE`  | Override config path (`--config` takes precedence). |
| `FASTMCP_*`         | Standard FastMCP runtime settings (logging, ports, auth). |

## MCP Tools & Resources

| Tool | Description | Key Inputs |
|------|-------------|------------|
| `list_folders` | Returns folders/mailboxes with safe tokens. | – |
| `search_messages` | Finds messages with text/sender/date filters or quick time frames. Results include the first ~20 lines when available and support limit/offset pagination. | optional folder token, filters, `time_frame`, `offset`, `limit` |
| `get_message` | Fetches full metadata + body + attachment list. | `folder_token`, `uid` |
| `get_raw_message` | Returns the RFC822 source (Base64). | `folder_token`, `uid` |
| `download_attachment` | Streams any attachment as Base64. | `folder_token`, `uid`, attachment id/index |
### Resource Templates

| URI Template | MIME Type | Notes |
|--------------|-----------|-------|
| `mail://{account_id}/{folder_token}/{uid}` | `text/plain` | Plain text or HTML fallback. |
| `mail+html://{account_id}/{folder_token}/{uid}` | `text/html` | Raw HTML body when available. |
| `mail+raw://{account_id}/{folder_token}/{uid}` | `message/rfc822` | RFC822 source; perfect for ingestion. |
| `mail+attachment://{account_id}/{folder_token}/{uid}/{attachment_identifier}` | `application/octet-stream` | Attachment binary payload (index or provider id). |

Use the folder token emitted by `list_folders` / `search_messages`; it encapsulates protocol-specific identifiers safely.
\n## Architecture

```
src/imap_readonly_mcp/
├── config.py            # Pydantic models + loader
├── connectors/          # IMAP, POP3, Graph read-only connectors
├── models.py            # Shared Pydantic data models
├── service.py           # Facade orchestrating connectors
├── server.py            # FastMCP application + CLI entrypoint
└── tooling.py           # Tool input models (validation)
```

Key design notes:

- **Connector isolation** - each protocol lives in its own class implementing a shared `ReadOnlyMailConnector` interface.
- **No side effects** - IMAP uses `SELECT ... READONLY` + `BODY.PEEK`, POP3 fetches without `DELE`, Graph only performs `GET`.
- **Central service** - `MailService` normalises filters, handles token decoding, and fans out requests to the appropriate connector.
- **Resource templates** - a single dynamic resource per concept avoids pre-registering per-message resources.
- **Thread isolation** - blocking I/O is delegated via `anyio.to_thread.run_sync` so the MCP event loop stays responsive.

## Testing & Quality

```bash
pip install .[dev]
pytest
```

Tests cover encoding helpers and RFC822 parsing. Connectors rely on live infrastructure and are best exercised via integration smoke tests against staging mailboxes.

Static tooling is configured (`ruff`, `mypy`, coverage) and ready for CI execution.

## CI & Releases

- `.github/workflows/ci.yml` - lint + tests on pushes and pull requests.
- `.github/workflows/release.yml` - tagged releases build wheels, publish to PyPI (placeholder), and push Docker images to GHCR.

Adjust registry names or secrets in the workflow files as needed before publishing.

## Security & Hardening Tips

- Use app passwords or OAuth app registrations scoped to read-only permissions.
- Supply dedicated service accounts for Graph/Gmail with least privilege.
- Store secrets outside the repo (e.g. environment variables, encrypted secret stores).
- The Docker image runs as a non-root user and exposes only the MCP transport.

## Roadmap Ideas

1. Add Gmail API connector with incremental sync cache.
2. Offer streaming search for huge mailboxes.
3. Expose message threading / conversation tools.

---

**Authorship notice:** This repository (code + docs) was generated by an AI coding agent (OpenAI Codex for GPT-5). Review, adapt, and extend responsibly before deploying to production.






