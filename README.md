# IMAP Read-Only MCP Server

Expose a single mailbox to Model Context Protocol (MCP) agents without risking mutations.  
This server works with IMAP, POP3, and Microsoft Graph mailboxes and focuses on:

- **Immutable access** – every operation uses `SELECT ... READONLY`, no flags are touched.
- **LLM-friendly payloads** – plain-text snippets, curated metadata, and configurable body detail.
- **Performance** – SQLite-backed caching plus bounded parallel fetches keep responses snappy.

---

## Quick Start

```bash
pip install -e .              # install in editable mode
imap-readonly-mcp --config config/accounts.yaml  # run over stdio
```

### Docker Image

Published images live at `ghcr.io/azizmarashly/imap-readonly-mcp`. Pull a tagged release (replace `v0.2.0` with the version you need):

```bash
docker pull ghcr.io/azizmarashly/imap-readonly-mcp:v0.2.0
```

Run it by mounting your config file into the container and forwarding the desired port. The example below starts the server over Streamable HTTP so an MCP client can connect remotely:

```bash
CONFIG_PATH=$PWD/config/accounts.yaml
docker run --rm \
  -v "$CONFIG_PATH":/app/config/accounts.yaml:ro \
  -p 8765:8765 \
  -e FASTMCP_TRANSPORT=streamable-http \
  -e FASTMCP_HOST=0.0.0.0 \
  -e FASTMCP_PORT=8765 \
  -e FASTMCP_STREAMABLE_HTTP__PATH=/mcp \
  -e MAIL_CACHE_PATH=/tmp/email_cache.sqlite \
  ghcr.io/azizmarashly/imap-readonly-mcp:v0.2.0 \
  --transport streamable-http
```

> The image entrypoint already includes Python and the project, so the final argument list just provides flags. The cache path defaults to `/tmp/email_cache.sqlite`, which is always writable inside the container; mount a host directory and point `MAIL_CACHE_PATH` there if you want persistence.

### Streamable HTTP

```bash
FASTMCP_TRANSPORT=streamable-http \
FASTMCP_HOST=0.0.0.0 \
FASTMCP_PORT=8765 \
FASTMCP_STREAMABLE_HTTP__PATH=/mcp \
imap-readonly-mcp --config config/accounts.yaml --transport streamable-http
```

### Verbose Logging

```bash
FASTMCP_LOG_LEVEL=DEBUG imap-readonly-mcp --config config/accounts.yaml
```

(Values must be one of `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`. `TRACE` falls back to `DEBUG`.)

---

## Configuration

The server reads a single-account YAML file (default `config/accounts.yaml`).  
Full example (`config/accounts.example.yaml`):

```yaml
# Example configuration file for the read-only mail MCP server.
account:
  protocol: imap             # or pop3 / graph
  description: "Personal IMAP mailbox"
  host: imap.example.com
  port: 993
  username: user@example.com
  password: change-me
  # cache_path: email_cache.sqlite   # optional SQLite cache location
  # fetch_concurrency: 6            # max parallel message fetches
```

### Environment Variables

| Variable               | Purpose                                                 |
|------------------------|---------------------------------------------------------|
| `MAIL_CONFIG_FILE`     | Override config path (`--config` wins).                 |
| `MAIL_CACHE_PATH`      | Alternate cache location if not set in YAML.            |
| `MAIL_FETCH_CONCURRENCY` | Override concurrency (same effect as YAML).          |
| `FASTMCP_*`            | Standard FastMCP options (transport, ports, auth, logging). |

---

## Performance Features

- **SQLite body cache** keyed by `(folder_token, uid)` keeps fetched messages for reuse.
- **Parallel enrichment** fetches multiple messages simultaneously (bounded by `fetch_concurrency`).
- **HTML→text conversion** ensures snippets and plain text bodies are readable even for HTML-only mail.

To disable caching, set `cache_path` to `/dev/null` (Unix) or another throwaway location.

---

## MCP Tools

| Tool               | Description                                                          | Key Inputs |
|--------------------|----------------------------------------------------------------------|------------|
| `mail_fetch`        | List / search / read messages with controllable detail (see below). | `query`, `folder`, `include`, `cursor`, etc. |
| `mail_download_attachment` | Download a single attachment (Base64).                    | `message_id`, `attachment_id` |

### `mail_fetch` Include Modes

`include` controls how much body information is returned:

- `metadata` *(default)* – subject, addresses, snippet, flags, attachments meta only.
- `text` – adds plain text body (HTML converted when necessary).
- `html` – adds HTML body only.
- `full` – includes text + HTML + raw headers.

Attachments follow `include_attachments` (`none`, `meta`, `inline`), and thread expansion (`expand_thread`) stays best-effort.

### Response Consistency

All structured fields are curated for LLM prompts:

- Metadata sits at top level (e.g., `from`, `subject`, `snippet`).  
- Raw headers live only in the `headers` map (available when `include=full`).  
- Plain-text snippets are derived from the same body served in `body_text`, guaranteeing coherence.

---

## MCP Resources

| URI Template                         | MIME Type           | Notes                                       |
|--------------------------------------|---------------------|---------------------------------------------|
| `mail://{folder_token}/{uid}`        | `text/plain`        | Plain text (converted from HTML when needed). |
| `mail+html://{folder_token}/{uid}`   | `text/html`         | Raw HTML body (if supplied by the provider). |
| `mail+raw://{folder_token}/{uid}`    | `message/rfc822`    | RFC822 source for ingestion/pipeline jobs.  |
| `mail+attachment://{folder_token}/{uid}/{attachment_identifier}` | `application/octet-stream` | Attachment bytes (index or provider id). |
| `mail://folders`                     | `application/json`  | Enumerates available folders/tokens.        |

---

## Development

```bash
poetry install          # or pip install -e .[dev]
pytest                  # run unit tests
ruff check .            # lint (if installed)
```

Key directories:

```
src/imap_readonly_mcp/
  ├── config.py          # settings & loader
  ├── connectors/        # IMAP / POP3 / Graph implementations
  ├── service.py         # caching, parallel fetch orchestration
  ├── server.py          # FastMCP entrypoint & tool wiring
  ├── tooling.py         # Pydantic models for tool IO
  └── utils/             # parsers, identifier helpers, etc.
```

Feel free to open issues or PRs for additional connectors, caching strategies, or tooling improvements.
