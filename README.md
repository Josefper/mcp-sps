# MCP Server for One Identity Safeguard for Privileged Sessions (SPS)

A [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) server that enables AI assistants to interact with **One Identity Safeguard for Privileged Sessions (SPS)** through its REST API.

## Features

- **Authentication** — HTTP Basic auth with session cookie management
- **Session Audit** — Search, retrieve, and inspect recorded privileged sessions with full-text content search
- **Connection Policies** — Full CRUD for SSH, RDP, Telnet, VNC, HTTP, and ICA connection policies
- **Configuration Management** — Transaction-based configuration changes (open → modify → commit)
- **Policy Management** — Audit, archive, content, time, channel, and settings policies
- **User Management** — Local users and user groups
- **Health & Monitoring** — Appliance health, cluster status, indexer status, syslog, SNMP
- **Credentials** — Stored passwords, private keys, certificates, trusted CAs, credential stores
- **Reporting & Plugins** — List reports and installed plugins
- **Support** — Generate support bundles for troubleshooting

## Prerequisites

- Python 3.10+
- Access to a One Identity Safeguard for Privileged Sessions appliance

## Installation

```bash
pip install mcp httpx
```

Clone this repository:

```bash
git clone https://github.com/Josefper/mcp-sps.git
cd mcp-sps
```

## Configuration

### Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `SPS_APPLIANCE_URL` | Yes | — | SPS appliance URL (e.g. `https://sps.example.com`) |
| `SPS_VERIFY_SSL` | No | `false` | Enable SSL certificate validation |
| `SPS_USERNAME` | No | — | Default username for authentication |
| `SPS_PASSWORD` | No | — | Default password for authentication |

### Claude Code Integration

Add this to your `.mcp.json`:

```json
{
  "mcpServers": {
    "safeguard-sps": {
      "command": "python3",
      "args": ["path/to/safeguard_sps_mcp_server.py"],
      "env": {
        "SPS_APPLIANCE_URL": "https://your-sps-appliance.example.com",
        "SPS_VERIFY_SSL": "false"
      }
    }
  }
}
```

## Usage

### Running Standalone

```bash
python3 safeguard_sps_mcp_server.py
```

### Example Workflow

1. **Authenticate** to the SPS appliance
2. **Search sessions** to find recorded privileged sessions
3. **Inspect session content** to review commands executed during a session
4. **Manage connection policies** to control how connections are proxied and recorded
5. **Check appliance health** to monitor the SPS deployment

### Configuration Changes

SPS uses a transaction model for configuration changes:

1. **Open a transaction** — locks configuration for editing
2. **Make changes** — create/update/delete connection policies, settings, etc.
3. **Commit the transaction** — applies all changes atomically
4. **Or cancel** — discards all uncommitted changes

## Available Tools

| Tool | Description |
|---|---|
| `authenticate` | Authenticate to SPS with username/password |
| `logout` | Discard the cached session |
| `check_appliance_health` | Check SPS appliance health status |
| `get_configuration` | Retrieve configuration at a given path |
| `open_transaction` | Open a configuration transaction |
| `commit_transaction` | Commit pending configuration changes |
| `cancel_transaction` | Discard pending configuration changes |
| `get_transaction_status` | Check current transaction state |
| `search_sessions` | Search the session audit database |
| `search_sessions_advanced` | Advanced session search (POST, >10k results) |
| `get_session` | Retrieve details of a specific session |
| `get_session_statistics` | Get aggregated session statistics |
| `search_session_content` | Search within a session's recorded content |
| `list_connection_policies` | List connection policies by protocol |
| `get_connection_policy` | Get a specific connection policy |
| `create_connection_policy` | Create a new connection policy |
| `update_connection_policy` | Update an existing connection policy |
| `delete_connection_policy` | Delete a connection policy |
| `list_settings_policies` | List settings policies by protocol |
| `list_channel_policies` | List channel policies by protocol |
| `list_audit_policies` | List audit recording policies |
| `list_archive_policies` | List archive/cleanup policies |
| `list_content_policies` | List content monitoring policies |
| `list_time_policies` | List time-based access policies |
| `list_users` | List local SPS users |
| `get_user` | Get details of a specific user |
| `list_user_groups` | List user groups |
| `list_login_methods` | List available login methods |
| `list_ldap_servers` | List LDAP server configurations |
| `get_network_configuration` | Retrieve network settings |
| `list_stored_passwords` | List stored passwords |
| `list_private_keys` | List private keys |
| `list_certificates` | List certificates |
| `list_trusted_cas` | List trusted CA certificates |
| `list_plugins` | List installed plugins |
| `list_reports` | List configured reports |
| `get_cluster_status` | Get cluster status |
| `list_cluster_nodes` | List cluster nodes |
| `get_basic_settings` | Get basic appliance settings |
| `get_firmware_info` | Get firmware information |
| `get_syslog_configuration` | Get syslog configuration |
| `get_snmp_configuration` | Get SNMP configuration |
| `get_indexer_status` | Check session indexer status |
| `list_credential_stores` | List credential store configurations |
| `generate_support_bundle` | Generate a support bundle |

## Related

- [MCP Server for Safeguard SPP](https://github.com/Josefper/mpc-spp) — MCP server for One Identity Safeguard for Privileged Passwords

## License

MIT
