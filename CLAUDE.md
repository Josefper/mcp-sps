# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

MCP (Model Context Protocol) server for **One Identity Safeguard for Privileged Sessions (SPS)**. Provides AI assistants with tools to interact with the SPS REST API for session auditing, connection policy management, and appliance configuration.

## Architecture

Single-file Python MCP server (`safeguard_sps_mcp_server.py`, ~1,280 lines) built on **FastMCP** with **httpx** for HTTP. No separate modules — all tools, auth, and helpers live in one file.

**Key architectural patterns:**
- In-memory session cookie cache (`_session_cache` dict) keyed by appliance URL
- HTTP Basic authentication against `/api/authentication`, session maintained via `session_id` cookie
- httpx synchronous client with context manager for connection lifecycle
- All API calls go through `/api/` endpoints (configuration, audit, health, cluster)
- Transaction-based configuration changes: open → modify → commit

**Tool groups in order:**
1. **Authentication** (~L86-161): `authenticate`, `logout`
2. **Health & Status** (~L163-186): `check_appliance_health`
3. **Configuration** (~L188-218): Generic configuration tree access
4. **Transactions** (~L220-311): `open_transaction`, `get_transaction_status`, `commit_transaction`, `cancel_transaction`
5. **Session Audit** (~L313-493): Search, retrieve, and inspect recorded sessions
6. **Connection Policies** (~L495-675): CRUD for SSH, RDP, Telnet, VNC, HTTP, ICA connection policies
7. **Policy Management** (~L677-817): Settings, channel, audit, archive, content, time policies
8. **User Management** (~L819-882): Local users and user groups
9. **AAA/Auth Settings** (~L884-923): Login methods, LDAP servers
10. **Network & Credentials** (~L925-1033): Network config, passwords, keys, certificates, trusted CAs
11. **Plugins & Reporting** (~L1035-1076): Installed plugins, configured reports
12. **Cluster** (~L1078-1117): Cluster status and node listing
13. **Appliance Settings** (~L1119-1200): Basic settings, firmware, syslog, SNMP
14. **Indexer & Credential Stores** (~L1202-1248): Indexer status, credential store configs
15. **Support** (~L1250-1273): Support bundle generation

## Running the Server

```bash
python3 safeguard_sps_mcp_server.py
```

Configured via `.mcp.json` for Claude Code integration. Key environment variables:
- `SPS_APPLIANCE_URL` (required): SPS appliance URL
- `SPS_VERIFY_SSL` (default: `false`): SSL cert validation
- `SPS_USERNAME`, `SPS_PASSWORD`: Optional default credentials

## Dependencies

- `mcp` (FastMCP framework)
- `httpx` (HTTP client)

No requirements.txt — install manually: `pip install mcp httpx`

## Testing

No automated test suite exists. Testing is manual against a live SPS appliance.
