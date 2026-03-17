#!/usr/bin/env python3
"""
MCP Server for One Identity Safeguard for Privileged Sessions (SPS).

Exposes Safeguard SPS operations as MCP tools for AI assistants:
  - Authentication (Basic HTTP auth + session cookie)
  - Session audit search and retrieval
  - Connection policy management (SSH, RDP, Telnet, VNC, HTTP, ICA)
  - Configuration management with transaction support
  - User and user group management
  - Health and status monitoring
"""

import json
import logging
import os
from typing import Any

import httpx
from mcp.server.fastmcp import FastMCP

# ---------------------------------------------------------------------------
# Configuration – reads from environment variables
# ---------------------------------------------------------------------------
SPS_APPLIANCE_URL = os.environ.get("SPS_APPLIANCE_URL", "")  # e.g. https://10.0.0.1
SPS_VERIFY_SSL = os.environ.get("SPS_VERIFY_SSL", "false").lower() == "true"

# Optional default credentials (can be overridden per-call)
SPS_USERNAME = os.environ.get("SPS_USERNAME", "")
SPS_PASSWORD = os.environ.get("SPS_PASSWORD", "")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("safeguard-sps-mcp")

# ---------------------------------------------------------------------------
# MCP Server
# ---------------------------------------------------------------------------
mcp = FastMCP(
    "safeguard-sps",
    instructions="One Identity Safeguard for Privileged Sessions – MCP Server",
)

# In-memory session cookie cache (per appliance URL)
_session_cache: dict[str, str] = {}


def _http_client(appliance_url: str | None = None) -> httpx.Client:
    """Create an httpx client with appropriate SSL settings."""
    base = (appliance_url or SPS_APPLIANCE_URL).rstrip("/")
    return httpx.Client(
        base_url=base,
        verify=SPS_VERIFY_SSL,
        timeout=30.0,
    )


def _ensure_appliance(appliance_url: str | None) -> str:
    url = (appliance_url or SPS_APPLIANCE_URL).rstrip("/")
    if not url:
        raise ValueError(
            "No appliance URL configured. Set SPS_APPLIANCE_URL or pass appliance_url."
        )
    return url


def _get_session_cookie(appliance_url: str) -> str:
    token = _session_cache.get(appliance_url)
    if not token:
        raise ValueError(
            "Not authenticated. Call authenticate() first to obtain a session."
        )
    return token


def _cookies(session_id: str) -> dict[str, str]:
    return {"session_id": session_id}


def _json_headers() -> dict[str, str]:
    return {
        "Content-Type": "application/json",
        "Accept": "application/json",
    }


# ===================================================================
# TOOL: authenticate
# ===================================================================
@mcp.tool()
def authenticate(
    username: str = "",
    password: str = "",
    appliance_url: str = "",
) -> str:
    """
    Authenticate to One Identity Safeguard SPS and obtain a session cookie.

    Uses HTTP Basic authentication against /api/authentication.
    On success, stores the session_id cookie for subsequent API calls.

    Parameters:
      username     – SPS admin username (falls back to SPS_USERNAME env var)
      password     – SPS admin password (falls back to SPS_PASSWORD env var)
      appliance_url – Override the default SPS appliance URL
    """
    url = _ensure_appliance(appliance_url)
    user = username or SPS_USERNAME
    pwd = password or SPS_PASSWORD
    if not user or not pwd:
        return json.dumps({"error": "Username and password are required."})

    with _http_client(url) as client:
        resp = client.get(
            "/api/authentication",
            auth=(user, pwd),
            follow_redirects=False,
        )
        if resp.status_code in (200, 302):
            session_id = resp.cookies.get("session_id", "")
            if session_id:
                _session_cache[url] = session_id
                logger.info("Authenticated to SPS at %s", url)
                try:
                    body = resp.json()
                except Exception:
                    body = resp.text
                return json.dumps({
                    "status": "authenticated",
                    "appliance": url,
                    "response": body,
                })
            else:
                return json.dumps({
                    "error": "Authentication succeeded but no session_id cookie received.",
                    "status_code": resp.status_code,
                    "body": resp.text,
                })
        else:
            return json.dumps({
                "error": "Authentication failed",
                "status_code": resp.status_code,
                "body": resp.text,
            })


# ===================================================================
# TOOL: logout
# ===================================================================
@mcp.tool()
def logout(appliance_url: str = "") -> str:
    """
    Log out from SPS by discarding the cached session cookie.

    Parameters:
      appliance_url – Override the default SPS appliance URL
    """
    url = _ensure_appliance(appliance_url)
    removed = _session_cache.pop(url, None)
    if removed:
        return json.dumps({"status": "logged_out", "appliance": url})
    return json.dumps({"status": "no_session_found", "appliance": url})


# ===================================================================
# TOOL: check_appliance_health
# ===================================================================
@mcp.tool()
def check_appliance_health(appliance_url: str = "") -> str:
    """
    Check the health status of the SPS appliance.

    Queries /api/health/appliance for system health information.
    Requires authentication.

    Parameters:
      appliance_url – Override the default SPS appliance URL
    """
    url = _ensure_appliance(appliance_url)
    session_id = _get_session_cookie(url)
    with _http_client(url) as client:
        resp = client.get(
            "/api/health/appliance",
            cookies=_cookies(session_id),
            headers=_json_headers(),
        )
        return resp.text


# ===================================================================
# TOOL: get_configuration
# ===================================================================
@mcp.tool()
def get_configuration(
    path: str = "",
    appliance_url: str = "",
) -> str:
    """
    Retrieve SPS configuration at the given path.

    The SPS REST API exposes configuration as a tree under /api/configuration/.
    Pass a sub-path to drill down, e.g. "network/naming" or "aaa/users".

    Parameters:
      path          – Configuration sub-path (empty = root configuration tree)
      appliance_url – Override the default SPS appliance URL
    """
    url = _ensure_appliance(appliance_url)
    session_id = _get_session_cookie(url)
    endpoint = "/api/configuration"
    if path:
        endpoint = f"/api/configuration/{path.strip('/')}"
    with _http_client(url) as client:
        resp = client.get(
            endpoint,
            cookies=_cookies(session_id),
            headers=_json_headers(),
        )
        return resp.text


# ===================================================================
# TRANSACTION HELPERS
# ===================================================================
@mcp.tool()
def open_transaction(appliance_url: str = "") -> str:
    """
    Open a configuration transaction on SPS.

    Configuration changes in SPS require a transaction: open → modify → commit.
    Only one transaction can be open at a time (similar to the web UI lock).

    Parameters:
      appliance_url – Override the default SPS appliance URL
    """
    url = _ensure_appliance(appliance_url)
    session_id = _get_session_cookie(url)
    with _http_client(url) as client:
        resp = client.post(
            "/api/transaction",
            content=b"",
            cookies=_cookies(session_id),
            headers=_json_headers(),
        )
        return resp.text


@mcp.tool()
def get_transaction_status(appliance_url: str = "") -> str:
    """
    Get the current transaction status (open or closed).

    Parameters:
      appliance_url – Override the default SPS appliance URL
    """
    url = _ensure_appliance(appliance_url)
    session_id = _get_session_cookie(url)
    with _http_client(url) as client:
        resp = client.get(
            "/api/transaction",
            cookies=_cookies(session_id),
            headers=_json_headers(),
        )
        return resp.text


@mcp.tool()
def commit_transaction(
    message: str = "",
    appliance_url: str = "",
) -> str:
    """
    Commit the open transaction, applying configuration changes to SPS.

    Parameters:
      message       – Optional commit message (may be required by SPS accounting settings)
      appliance_url – Override the default SPS appliance URL
    """
    url = _ensure_appliance(appliance_url)
    session_id = _get_session_cookie(url)
    body: dict[str, str] = {"status": "commit"}
    if message:
        body["message"] = message
    with _http_client(url) as client:
        resp = client.put(
            "/api/transaction",
            json=body,
            cookies=_cookies(session_id),
            headers=_json_headers(),
        )
        return resp.text


@mcp.tool()
def cancel_transaction(appliance_url: str = "") -> str:
    """
    Cancel (delete) the open transaction, discarding uncommitted changes.

    Parameters:
      appliance_url – Override the default SPS appliance URL
    """
    url = _ensure_appliance(appliance_url)
    session_id = _get_session_cookie(url)
    with _http_client(url) as client:
        resp = client.delete(
            "/api/transaction",
            cookies=_cookies(session_id),
            headers=_json_headers(),
        )
        if resp.status_code == 200:
            return json.dumps({"status": "transaction_cancelled"})
        return resp.text


# ===================================================================
# TOOL: search_sessions
# ===================================================================
@mcp.tool()
def search_sessions(
    query: str = "",
    fields: str = "",
    limit: int = 50,
    offset: int = 0,
    sort: str = "",
    format: str = "json",
    appliance_url: str = "",
) -> str:
    """
    Search the SPS session audit database using the basic search method.

    Queries /api/audit/sessions with filtering, field selection, and pagination.
    Max 10000 results via basic search; use search_sessions_advanced for more.

    Parameters:
      query         – Filter expression, e.g. "protocol:ssh", "active:true",
                      "name:admin". Multiple filters separated by space.
      fields        – Comma-separated fields to return, e.g.
                      "start_time,name,duration,psm.target.address"
      limit         – Number of results per page (default 50)
      offset        – Starting offset for pagination (max 10000)
      sort          – Field to sort by, e.g. "start_time" or "-start_time" for descending
      format        – Response format: "json" (default) or "csv"
      appliance_url – Override the default SPS appliance URL
    """
    url = _ensure_appliance(appliance_url)
    session_id = _get_session_cookie(url)
    params: dict[str, Any] = {}
    if query:
        params["q"] = query
    if fields:
        params["fields"] = fields
    if limit:
        params["limit"] = limit
    if offset:
        params["offset"] = offset
    if sort:
        params["sort"] = sort
    if format and format != "json":
        params["format"] = format
    with _http_client(url) as client:
        resp = client.get(
            "/api/audit/sessions",
            params=params,
            cookies=_cookies(session_id),
            headers=_json_headers(),
        )
        return resp.text


# ===================================================================
# TOOL: search_sessions_advanced
# ===================================================================
@mcp.tool()
def search_sessions_advanced(
    query_body: str = "{}",
    appliance_url: str = "",
) -> str:
    """
    Search the SPS session database using the advanced search method (POST).

    Use this when the basic search would exceed 10000 results.
    Sends a POST request to /api/audit/sessions/query with a JSON query body.

    Parameters:
      query_body    – JSON string with the advanced search query
      appliance_url – Override the default SPS appliance URL
    """
    url = _ensure_appliance(appliance_url)
    session_id = _get_session_cookie(url)
    try:
        body = json.loads(query_body)
    except json.JSONDecodeError as e:
        return json.dumps({"error": f"Invalid JSON in query_body: {e}"})
    with _http_client(url) as client:
        resp = client.post(
            "/api/audit/sessions/query",
            json=body,
            cookies=_cookies(session_id),
            headers=_json_headers(),
        )
        return resp.text


# ===================================================================
# TOOL: get_session
# ===================================================================
@mcp.tool()
def get_session(
    session_id_param: str = "",
    appliance_url: str = "",
) -> str:
    """
    Retrieve details of a specific audited session.

    Parameters:
      session_id_param – The session ID (key) to retrieve
      appliance_url    – Override the default SPS appliance URL
    """
    url = _ensure_appliance(appliance_url)
    session_id = _get_session_cookie(url)
    if not session_id_param:
        return json.dumps({"error": "session_id_param is required."})
    with _http_client(url) as client:
        resp = client.get(
            f"/api/audit/sessions/{session_id_param}",
            cookies=_cookies(session_id),
            headers=_json_headers(),
        )
        return resp.text


# ===================================================================
# TOOL: get_session_statistics
# ===================================================================
@mcp.tool()
def get_session_statistics(
    query: str = "",
    appliance_url: str = "",
) -> str:
    """
    Retrieve session statistics from the SPS audit database.

    Returns aggregated statistics about sessions (e.g. by protocol, user, etc.).

    Parameters:
      query         – Optional filter expression (same syntax as search_sessions)
      appliance_url – Override the default SPS appliance URL
    """
    url = _ensure_appliance(appliance_url)
    session_id = _get_session_cookie(url)
    params: dict[str, str] = {}
    if query:
        params["q"] = query
    with _http_client(url) as client:
        resp = client.get(
            "/api/audit/sessions/statistics",
            params=params,
            cookies=_cookies(session_id),
            headers=_json_headers(),
        )
        return resp.text


# ===================================================================
# TOOL: search_session_content
# ===================================================================
@mcp.tool()
def search_session_content(
    session_id_param: str = "",
    content_query: str = "",
    appliance_url: str = "",
) -> str:
    """
    Search within the content of a specific audited session (e.g. commands typed).

    Parameters:
      session_id_param – The session ID (key) to search in
      content_query    – Text to search for in the session content
      appliance_url    – Override the default SPS appliance URL
    """
    url = _ensure_appliance(appliance_url)
    session_id = _get_session_cookie(url)
    if not session_id_param:
        return json.dumps({"error": "session_id_param is required."})
    if not content_query:
        return json.dumps({"error": "content_query is required."})
    with _http_client(url) as client:
        resp = client.get(
            f"/api/audit/sessions/{session_id_param}/content",
            params={"q": content_query},
            cookies=_cookies(session_id),
            headers=_json_headers(),
        )
        return resp.text


# ===================================================================
# CONNECTION POLICY TOOLS
# ===================================================================
SUPPORTED_PROTOCOLS = ("ssh", "rdp", "telnet", "vnc", "http", "ica")


@mcp.tool()
def list_connection_policies(
    protocol: str = "ssh",
    appliance_url: str = "",
) -> str:
    """
    List connection policies for a given protocol.

    Parameters:
      protocol      – Protocol type: ssh, rdp, telnet, vnc, http, ica (default: ssh)
      appliance_url – Override the default SPS appliance URL
    """
    url = _ensure_appliance(appliance_url)
    session_id = _get_session_cookie(url)
    proto = protocol.lower()
    if proto not in SUPPORTED_PROTOCOLS:
        return json.dumps({
            "error": f"Unsupported protocol '{proto}'. Must be one of: {', '.join(SUPPORTED_PROTOCOLS)}"
        })
    with _http_client(url) as client:
        resp = client.get(
            f"/api/configuration/{proto}/connections",
            cookies=_cookies(session_id),
            headers=_json_headers(),
        )
        return resp.text


@mcp.tool()
def get_connection_policy(
    protocol: str = "ssh",
    policy_key: str = "",
    appliance_url: str = "",
) -> str:
    """
    Retrieve a specific connection policy by its key.

    Parameters:
      protocol      – Protocol type: ssh, rdp, telnet, vnc, http, ica
      policy_key    – The key (UUID) of the connection policy
      appliance_url – Override the default SPS appliance URL
    """
    url = _ensure_appliance(appliance_url)
    session_id = _get_session_cookie(url)
    proto = protocol.lower()
    if proto not in SUPPORTED_PROTOCOLS:
        return json.dumps({
            "error": f"Unsupported protocol '{proto}'. Must be one of: {', '.join(SUPPORTED_PROTOCOLS)}"
        })
    if not policy_key:
        return json.dumps({"error": "policy_key is required."})
    with _http_client(url) as client:
        resp = client.get(
            f"/api/configuration/{proto}/connections/{policy_key}",
            cookies=_cookies(session_id),
            headers=_json_headers(),
        )
        return resp.text


@mcp.tool()
def create_connection_policy(
    protocol: str = "ssh",
    policy_json: str = "{}",
    appliance_url: str = "",
) -> str:
    """
    Create a new connection policy for the specified protocol.

    Requires an open transaction. After creation, commit the transaction to apply.

    Parameters:
      protocol      – Protocol type: ssh, rdp, telnet, vnc, http, ica
      policy_json   – JSON string with the connection policy body. Key fields include:
                      name, active, network (clients, ports, targets),
                      server_address, policies (audit_policy, channel_policy, settings, etc.)
      appliance_url – Override the default SPS appliance URL
    """
    url = _ensure_appliance(appliance_url)
    session_id = _get_session_cookie(url)
    proto = protocol.lower()
    if proto not in SUPPORTED_PROTOCOLS:
        return json.dumps({
            "error": f"Unsupported protocol '{proto}'. Must be one of: {', '.join(SUPPORTED_PROTOCOLS)}"
        })
    try:
        body = json.loads(policy_json)
    except json.JSONDecodeError as e:
        return json.dumps({"error": f"Invalid JSON in policy_json: {e}"})
    with _http_client(url) as client:
        resp = client.post(
            f"/api/configuration/{proto}/connections",
            json=body,
            cookies=_cookies(session_id),
            headers=_json_headers(),
        )
        return resp.text


@mcp.tool()
def update_connection_policy(
    protocol: str = "ssh",
    policy_key: str = "",
    policy_json: str = "{}",
    appliance_url: str = "",
) -> str:
    """
    Update an existing connection policy.

    Requires an open transaction. After modification, commit the transaction to apply.

    Parameters:
      protocol      – Protocol type: ssh, rdp, telnet, vnc, http, ica
      policy_key    – The key (UUID) of the connection policy to update
      policy_json   – JSON string with the full updated policy body
      appliance_url – Override the default SPS appliance URL
    """
    url = _ensure_appliance(appliance_url)
    session_id = _get_session_cookie(url)
    proto = protocol.lower()
    if proto not in SUPPORTED_PROTOCOLS:
        return json.dumps({
            "error": f"Unsupported protocol '{proto}'. Must be one of: {', '.join(SUPPORTED_PROTOCOLS)}"
        })
    if not policy_key:
        return json.dumps({"error": "policy_key is required."})
    try:
        body = json.loads(policy_json)
    except json.JSONDecodeError as e:
        return json.dumps({"error": f"Invalid JSON in policy_json: {e}"})
    with _http_client(url) as client:
        resp = client.put(
            f"/api/configuration/{proto}/connections/{policy_key}",
            json=body,
            cookies=_cookies(session_id),
            headers=_json_headers(),
        )
        return resp.text


@mcp.tool()
def delete_connection_policy(
    protocol: str = "ssh",
    policy_key: str = "",
    appliance_url: str = "",
) -> str:
    """
    Delete a connection policy.

    Requires an open transaction. After deletion, commit the transaction to apply.

    Parameters:
      protocol      – Protocol type: ssh, rdp, telnet, vnc, http, ica
      policy_key    – The key (UUID) of the connection policy to delete
      appliance_url – Override the default SPS appliance URL
    """
    url = _ensure_appliance(appliance_url)
    session_id = _get_session_cookie(url)
    proto = protocol.lower()
    if proto not in SUPPORTED_PROTOCOLS:
        return json.dumps({
            "error": f"Unsupported protocol '{proto}'. Must be one of: {', '.join(SUPPORTED_PROTOCOLS)}"
        })
    if not policy_key:
        return json.dumps({"error": "policy_key is required."})
    with _http_client(url) as client:
        resp = client.delete(
            f"/api/configuration/{proto}/connections/{policy_key}",
            cookies=_cookies(session_id),
            headers=_json_headers(),
        )
        if resp.status_code in (200, 204):
            return json.dumps({"status": "deleted", "protocol": proto, "key": policy_key})
        return resp.text


# ===================================================================
# SETTINGS/CHANNEL POLICY TOOLS
# ===================================================================
@mcp.tool()
def list_settings_policies(
    protocol: str = "ssh",
    appliance_url: str = "",
) -> str:
    """
    List settings policies for a given protocol.

    Parameters:
      protocol      – Protocol type: ssh, rdp, telnet, vnc, http, ica
      appliance_url – Override the default SPS appliance URL
    """
    url = _ensure_appliance(appliance_url)
    session_id = _get_session_cookie(url)
    proto = protocol.lower()
    if proto not in SUPPORTED_PROTOCOLS:
        return json.dumps({
            "error": f"Unsupported protocol '{proto}'. Must be one of: {', '.join(SUPPORTED_PROTOCOLS)}"
        })
    with _http_client(url) as client:
        resp = client.get(
            f"/api/configuration/{proto}/settings_policies",
            cookies=_cookies(session_id),
            headers=_json_headers(),
        )
        return resp.text


@mcp.tool()
def list_channel_policies(
    protocol: str = "ssh",
    appliance_url: str = "",
) -> str:
    """
    List channel policies for a given protocol.

    Channel policies define which channels (e.g. terminal, SCP, SFTP for SSH;
    drawing, clipboard for RDP) are permitted or audited.

    Parameters:
      protocol      – Protocol type: ssh, rdp, telnet, vnc, http, ica
      appliance_url – Override the default SPS appliance URL
    """
    url = _ensure_appliance(appliance_url)
    session_id = _get_session_cookie(url)
    proto = protocol.lower()
    if proto not in SUPPORTED_PROTOCOLS:
        return json.dumps({
            "error": f"Unsupported protocol '{proto}'. Must be one of: {', '.join(SUPPORTED_PROTOCOLS)}"
        })
    with _http_client(url) as client:
        resp = client.get(
            f"/api/configuration/{proto}/channel_policies",
            cookies=_cookies(session_id),
            headers=_json_headers(),
        )
        return resp.text


# ===================================================================
# GLOBAL POLICY TOOLS
# ===================================================================
@mcp.tool()
def list_audit_policies(appliance_url: str = "") -> str:
    """
    List audit policies that control session recording behavior.

    Parameters:
      appliance_url – Override the default SPS appliance URL
    """
    url = _ensure_appliance(appliance_url)
    session_id = _get_session_cookie(url)
    with _http_client(url) as client:
        resp = client.get(
            "/api/configuration/policies/audit",
            cookies=_cookies(session_id),
            headers=_json_headers(),
        )
        return resp.text


@mcp.tool()
def list_archive_policies(appliance_url: str = "") -> str:
    """
    List archive/cleanup policies for session data.

    Parameters:
      appliance_url – Override the default SPS appliance URL
    """
    url = _ensure_appliance(appliance_url)
    session_id = _get_session_cookie(url)
    with _http_client(url) as client:
        resp = client.get(
            "/api/configuration/policies/archive",
            cookies=_cookies(session_id),
            headers=_json_headers(),
        )
        return resp.text


@mcp.tool()
def list_content_policies(appliance_url: str = "") -> str:
    """
    List content monitoring policies that define patterns to detect in sessions.

    Parameters:
      appliance_url – Override the default SPS appliance URL
    """
    url = _ensure_appliance(appliance_url)
    session_id = _get_session_cookie(url)
    with _http_client(url) as client:
        resp = client.get(
            "/api/configuration/policies/content",
            cookies=_cookies(session_id),
            headers=_json_headers(),
        )
        return resp.text


@mcp.tool()
def list_time_policies(appliance_url: str = "") -> str:
    """
    List time policies that restrict when connections are allowed.

    Parameters:
      appliance_url – Override the default SPS appliance URL
    """
    url = _ensure_appliance(appliance_url)
    session_id = _get_session_cookie(url)
    with _http_client(url) as client:
        resp = client.get(
            "/api/configuration/policies/time",
            cookies=_cookies(session_id),
            headers=_json_headers(),
        )
        return resp.text


# ===================================================================
# USER MANAGEMENT
# ===================================================================
@mcp.tool()
def list_users(appliance_url: str = "") -> str:
    """
    List local users configured on the SPS appliance.

    Parameters:
      appliance_url – Override the default SPS appliance URL
    """
    url = _ensure_appliance(appliance_url)
    session_id = _get_session_cookie(url)
    with _http_client(url) as client:
        resp = client.get(
            "/api/configuration/aaa/users",
            cookies=_cookies(session_id),
            headers=_json_headers(),
        )
        return resp.text


@mcp.tool()
def get_user(
    user_key: str = "",
    appliance_url: str = "",
) -> str:
    """
    Retrieve details of a specific local user.

    Parameters:
      user_key      – The key of the user to retrieve
      appliance_url – Override the default SPS appliance URL
    """
    url = _ensure_appliance(appliance_url)
    session_id = _get_session_cookie(url)
    if not user_key:
        return json.dumps({"error": "user_key is required."})
    with _http_client(url) as client:
        resp = client.get(
            f"/api/configuration/aaa/users/{user_key}",
            cookies=_cookies(session_id),
            headers=_json_headers(),
        )
        return resp.text


@mcp.tool()
def list_user_groups(appliance_url: str = "") -> str:
    """
    List user groups configured on the SPS appliance.

    Parameters:
      appliance_url – Override the default SPS appliance URL
    """
    url = _ensure_appliance(appliance_url)
    session_id = _get_session_cookie(url)
    with _http_client(url) as client:
        resp = client.get(
            "/api/configuration/aaa/usergroups",
            cookies=_cookies(session_id),
            headers=_json_headers(),
        )
        return resp.text


# ===================================================================
# AAA / AUTHENTICATION SETTINGS
# ===================================================================
@mcp.tool()
def list_login_methods(appliance_url: str = "") -> str:
    """
    List available login methods on the SPS appliance (local, LDAP, RADIUS, X.509).

    This endpoint does not require authentication.

    Parameters:
      appliance_url – Override the default SPS appliance URL
    """
    url = _ensure_appliance(appliance_url)
    with _http_client(url) as client:
        resp = client.get(
            "/api/authentication/login_methods",
            headers=_json_headers(),
        )
        return resp.text


@mcp.tool()
def list_ldap_servers(appliance_url: str = "") -> str:
    """
    List LDAP server configurations used for authentication on SPS.

    Parameters:
      appliance_url – Override the default SPS appliance URL
    """
    url = _ensure_appliance(appliance_url)
    session_id = _get_session_cookie(url)
    with _http_client(url) as client:
        resp = client.get(
            "/api/configuration/aaa/ldap_servers",
            cookies=_cookies(session_id),
            headers=_json_headers(),
        )
        return resp.text


# ===================================================================
# NETWORK CONFIGURATION
# ===================================================================
@mcp.tool()
def get_network_configuration(
    section: str = "",
    appliance_url: str = "",
) -> str:
    """
    Retrieve network configuration settings from SPS.

    Parameters:
      section       – Optional sub-section: "addresses", "dns", "routing",
                      "naming", "services", "settings" (empty = full network config)
      appliance_url – Override the default SPS appliance URL
    """
    url = _ensure_appliance(appliance_url)
    session_id = _get_session_cookie(url)
    endpoint = "/api/configuration/network"
    if section:
        endpoint = f"/api/configuration/network/{section.strip('/')}"
    with _http_client(url) as client:
        resp = client.get(
            endpoint,
            cookies=_cookies(session_id),
            headers=_json_headers(),
        )
        return resp.text


# ===================================================================
# CREDENTIAL MANAGEMENT
# ===================================================================
@mcp.tool()
def list_stored_passwords(appliance_url: str = "") -> str:
    """
    List passwords stored on the SPS appliance (used for server-side authentication).

    Parameters:
      appliance_url – Override the default SPS appliance URL
    """
    url = _ensure_appliance(appliance_url)
    session_id = _get_session_cookie(url)
    with _http_client(url) as client:
        resp = client.get(
            "/api/configuration/credentials/passwords",
            cookies=_cookies(session_id),
            headers=_json_headers(),
        )
        return resp.text


@mcp.tool()
def list_private_keys(appliance_url: str = "") -> str:
    """
    List private keys stored on the SPS appliance.

    Parameters:
      appliance_url – Override the default SPS appliance URL
    """
    url = _ensure_appliance(appliance_url)
    session_id = _get_session_cookie(url)
    with _http_client(url) as client:
        resp = client.get(
            "/api/configuration/credentials/private_keys",
            cookies=_cookies(session_id),
            headers=_json_headers(),
        )
        return resp.text


@mcp.tool()
def list_certificates(appliance_url: str = "") -> str:
    """
    List certificates stored on the SPS appliance.

    Parameters:
      appliance_url – Override the default SPS appliance URL
    """
    url = _ensure_appliance(appliance_url)
    session_id = _get_session_cookie(url)
    with _http_client(url) as client:
        resp = client.get(
            "/api/configuration/credentials/certificates",
            cookies=_cookies(session_id),
            headers=_json_headers(),
        )
        return resp.text


@mcp.tool()
def list_trusted_cas(appliance_url: str = "") -> str:
    """
    List trusted CA certificates on the SPS appliance.

    Parameters:
      appliance_url – Override the default SPS appliance URL
    """
    url = _ensure_appliance(appliance_url)
    session_id = _get_session_cookie(url)
    with _http_client(url) as client:
        resp = client.get(
            "/api/configuration/trust/ca_certificates",
            cookies=_cookies(session_id),
            headers=_json_headers(),
        )
        return resp.text


# ===================================================================
# PLUGINS
# ===================================================================
@mcp.tool()
def list_plugins(appliance_url: str = "") -> str:
    """
    List plugins installed on the SPS appliance (AA, credential store, etc.).

    Parameters:
      appliance_url – Override the default SPS appliance URL
    """
    url = _ensure_appliance(appliance_url)
    session_id = _get_session_cookie(url)
    with _http_client(url) as client:
        resp = client.get(
            "/api/configuration/plugins",
            cookies=_cookies(session_id),
            headers=_json_headers(),
        )
        return resp.text


# ===================================================================
# REPORTING
# ===================================================================
@mcp.tool()
def list_reports(appliance_url: str = "") -> str:
    """
    List configured reports on the SPS appliance.

    Parameters:
      appliance_url – Override the default SPS appliance URL
    """
    url = _ensure_appliance(appliance_url)
    session_id = _get_session_cookie(url)
    with _http_client(url) as client:
        resp = client.get(
            "/api/reporting/reports",
            cookies=_cookies(session_id),
            headers=_json_headers(),
        )
        return resp.text


# ===================================================================
# CLUSTER MANAGEMENT
# ===================================================================
@mcp.tool()
def get_cluster_status(appliance_url: str = "") -> str:
    """
    Get the cluster status of the SPS appliance.

    Parameters:
      appliance_url – Override the default SPS appliance URL
    """
    url = _ensure_appliance(appliance_url)
    session_id = _get_session_cookie(url)
    with _http_client(url) as client:
        resp = client.get(
            "/api/cluster/status",
            cookies=_cookies(session_id),
            headers=_json_headers(),
        )
        return resp.text


@mcp.tool()
def list_cluster_nodes(appliance_url: str = "") -> str:
    """
    List nodes in the SPS cluster.

    Parameters:
      appliance_url – Override the default SPS appliance URL
    """
    url = _ensure_appliance(appliance_url)
    session_id = _get_session_cookie(url)
    with _http_client(url) as client:
        resp = client.get(
            "/api/cluster/nodes",
            cookies=_cookies(session_id),
            headers=_json_headers(),
        )
        return resp.text


# ===================================================================
# BASIC SETTINGS & FIRMWARE
# ===================================================================
@mcp.tool()
def get_basic_settings(appliance_url: str = "") -> str:
    """
    Retrieve basic appliance settings (hostname, firmware info, etc.).

    Parameters:
      appliance_url – Override the default SPS appliance URL
    """
    url = _ensure_appliance(appliance_url)
    session_id = _get_session_cookie(url)
    with _http_client(url) as client:
        resp = client.get(
            "/api/configuration/basicSettings",
            cookies=_cookies(session_id),
            headers=_json_headers(),
        )
        return resp.text


@mcp.tool()
def get_firmware_info(appliance_url: str = "") -> str:
    """
    Retrieve firmware information from the SPS appliance.

    Parameters:
      appliance_url – Override the default SPS appliance URL
    """
    url = _ensure_appliance(appliance_url)
    session_id = _get_session_cookie(url)
    with _http_client(url) as client:
        resp = client.get(
            "/api/configuration/firmware",
            cookies=_cookies(session_id),
            headers=_json_headers(),
        )
        return resp.text


# ===================================================================
# LOGGING & MONITORING CONFIG
# ===================================================================
@mcp.tool()
def get_syslog_configuration(appliance_url: str = "") -> str:
    """
    Retrieve syslog server configuration.

    Parameters:
      appliance_url – Override the default SPS appliance URL
    """
    url = _ensure_appliance(appliance_url)
    session_id = _get_session_cookie(url)
    with _http_client(url) as client:
        resp = client.get(
            "/api/configuration/logging/syslog",
            cookies=_cookies(session_id),
            headers=_json_headers(),
        )
        return resp.text


@mcp.tool()
def get_snmp_configuration(appliance_url: str = "") -> str:
    """
    Retrieve SNMP monitoring configuration.

    Parameters:
      appliance_url – Override the default SPS appliance URL
    """
    url = _ensure_appliance(appliance_url)
    session_id = _get_session_cookie(url)
    with _http_client(url) as client:
        resp = client.get(
            "/api/configuration/logging/snmp",
            cookies=_cookies(session_id),
            headers=_json_headers(),
        )
        return resp.text


# ===================================================================
# INDEXER STATUS
# ===================================================================
@mcp.tool()
def get_indexer_status(appliance_url: str = "") -> str:
    """
    Check the status of the session indexer service.

    The indexer processes recorded sessions to enable full-text content search.

    Parameters:
      appliance_url – Override the default SPS appliance URL
    """
    url = _ensure_appliance(appliance_url)
    session_id = _get_session_cookie(url)
    with _http_client(url) as client:
        resp = client.get(
            "/api/health/indexer",
            cookies=_cookies(session_id),
            headers=_json_headers(),
        )
        return resp.text


# ===================================================================
# CREDENTIAL STORES
# ===================================================================
@mcp.tool()
def list_credential_stores(appliance_url: str = "") -> str:
    """
    List credential store configurations on SPS.

    Credential stores allow SPS to retrieve passwords from external vaults
    (e.g. Safeguard SPP, CyberArk, HashiCorp Vault) for server-side login.

    Parameters:
      appliance_url – Override the default SPS appliance URL
    """
    url = _ensure_appliance(appliance_url)
    session_id = _get_session_cookie(url)
    with _http_client(url) as client:
        resp = client.get(
            "/api/configuration/credential_stores",
            cookies=_cookies(session_id),
            headers=_json_headers(),
        )
        return resp.text


# ===================================================================
# SUPPORT BUNDLE
# ===================================================================
@mcp.tool()
def generate_support_bundle(appliance_url: str = "") -> str:
    """
    Generate a support bundle for troubleshooting.

    Returns status and download information for the support bundle.

    Parameters:
      appliance_url – Override the default SPS appliance URL
    """
    url = _ensure_appliance(appliance_url)
    session_id = _get_session_cookie(url)
    with _http_client(url) as client:
        resp = client.post(
            "/api/support/bundle",
            content=b"",
            cookies=_cookies(session_id),
            headers=_json_headers(),
        )
        return resp.text


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    mcp.run()
