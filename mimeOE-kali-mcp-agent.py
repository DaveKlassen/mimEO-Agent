#!/usr/bin/env python3
"""
fetch_response.py — LangGraph + triple-transport MCP pre-processing

Environment variables (required):
    HOST_PORT           e.g. "10.0.0.149:8083"       (LLM endpoint)
    BEARER_TOKEN        e.g. "ABCD"                   (LLM auth token)

Choose ONE MCP transport — or use the built-in Kali client (default):
    (none set)          → Kali stdio transport via client.py  ← DEFAULT
    MCP_URL             e.g. "http://localhost:3000"  → generic HTTP/SSE
    MCP_COMMAND         e.g. "npx -y @my/mcp-server" → generic stdio subprocess

    MCP_TOOL_NAME       required for HTTP/SSE and generic stdio transports
                        (Kali transport selects its tool automatically)

Optional:
    MODEL                    defaults to "smollm-360m"
    MCP_BEARER_TOKEN         auth header for HTTP/SSE transport
    MCP_SUBPROCESS_TIMEOUT   seconds to wait for stdio response (default 300)
    KALI_SERVER              Kali API URL (default: http://192.168.64.2:5000/)
    KALI_CLIENT_PATH         path to client.py (default: ./client.py)
    KALI_TIMEOUT             Kali API request timeout seconds (default: 300)

Graph flow (Kali transport):
    validate_env
        └─(ok)──► route_mcp_transport
                    ├─(http)───► call_mcp_http
                    ├─(stdio)──► call_mcp_stdio
                    └─(kali)───► select_kali_tool ──► call_mcp_kali   ← NEW
                                   (all converge)──► stream_completion
                                                       └──► assemble_response
                                                               └──► print_response ──► END
        (any error) └──► error_node ──► END

Usage:
    # Kali transport (default — no MCP_URL or MCP_COMMAND needed)
    python fetch_response.py "Run an nmap scan on 10.0.0.1"
    python fetch_response.py "Check if 10.0.0.5 has any web vulnerabilities"
    python fetch_response.py "Crack the hashes in /tmp/hashes.txt"

    # Override Kali server address
    export KALI_SERVER="http://192.168.64.2:5000/"
    python fetch_response.py "Enumerate SMB shares on 10.0.0.20"

    # Generic HTTP/SSE transport
    export MCP_URL="http://localhost:3000"
    export MCP_TOOL_NAME="lookup_context"
    python fetch_response.py "Who am I?"

    # Generic stdio transport
    export MCP_COMMAND="npx -y @modelcontextprotocol/server-filesystem /tmp"
    export MCP_TOOL_NAME="read_file"
    python fetch_response.py "List the files in /tmp"
"""

import os
import re
import sys
import json
import subprocess
import threading
import time
import httpx
from typing import TypedDict
from langgraph.graph import StateGraph, END


# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------

class ChatState(TypedDict):
    """Shared state passed between LangGraph nodes."""
    # LLM config
    host_port: str
    bearer_token: str
    model: str
    # MCP shared config
    mcp_tool_name: str
    mcp_tool_args: dict         # resolved tool arguments (Kali transport)
    mcp_transport: str          # "http" | "stdio" | "kali"
    # MCP HTTP/SSE config
    mcp_url: str
    mcp_bearer_token: str
    # MCP stdio / Kali config
    mcp_command: str
    mcp_subprocess_timeout: int
    # Kali-specific config
    kali_server: str
    kali_client_path: str
    kali_timeout: int
    # Results
    user_message: str
    mcp_result: dict            # raw JSON-RPC response
    mcp_context: str            # extracted text prepended to LLM prompt
    raw_chunks: list[dict]      # SSE delta objects from the LLM
    response_text: str          # final assembled LLM answer
    error: str                  # non-empty → something went wrong


# ---------------------------------------------------------------------------
# Shared MCP helpers
# ---------------------------------------------------------------------------

def _extract_mcp_context(mcp_result: dict, tool_name: str) -> str:
    """
    Pull plain text out of a JSON-RPC 2.0 tools/call response.

    Standard shape:
        { "jsonrpc": "2.0", "id": 1,
          "result": { "content": [{"type": "text", "text": "..."}] } }
    """
    rpc_result = mcp_result.get("result", mcp_result)
    if not isinstance(rpc_result, dict):
        return json.dumps(mcp_result, indent=2)

    blocks = rpc_result.get("content", [])
    text_parts = [
        b["text"]
        for b in blocks
        if isinstance(b, dict) and b.get("type") == "text" and b.get("text")
    ]
    if text_parts:
        return "\n".join(text_parts)
    if "text" in rpc_result:
        return str(rpc_result["text"])
    return json.dumps(rpc_result, indent=2)


# ---------------------------------------------------------------------------
# _StdioMCPClient — shared by both generic stdio and Kali transport
# ---------------------------------------------------------------------------

class _StdioMCPClient:
    """
    Minimal MCP stdio client.

    Launches an MCP server as a subprocess and communicates via
    newline-delimited JSON-RPC 2.0 on stdin/stdout.

    Lifecycle:
        __enter__  → spawn process + MCP initialize handshake
        call_tool  → send tools/call, read matching response
        __exit__   → send shutdown, terminate process
    """

    def __init__(self, command: str, timeout: int = 300):
        self.command = command
        self.timeout = timeout
        self._proc: subprocess.Popen | None = None
        self._lock = threading.Lock()
        self._next_id = 1

    def _send(self, obj: dict) -> None:
        line = json.dumps(obj) + "\n"
        self._proc.stdin.write(line.encode())
        self._proc.stdin.flush()

    def _recv(self) -> dict:
        result_box: list[dict] = []
        error_box:  list[Exception] = []

        def _read():
            try:
                raw = self._proc.stdout.readline()
                if raw:
                    result_box.append(json.loads(raw.decode()))
            except Exception as exc:
                error_box.append(exc)

        t = threading.Thread(target=_read, daemon=True)
        t.start()
        t.join(self.timeout)

        if error_box:
            raise error_box[0]
        if not result_box:
            stderr_out = self._drain_stderr()
            raise TimeoutError(
                f"MCP stdio server did not respond within {self.timeout}s.\n"
                f"Stderr: {stderr_out}"
            )
        return result_box[0]

    def _drain_stderr(self) -> str:
        try:
            self._proc.stderr.read1 and None  # flush buffer hint
            import select
            ready, _, _ = select.select([self._proc.stderr], [], [], 0.5)
            if ready:
                return self._proc.stderr.read(4096).decode(errors="replace")
        except Exception:
            pass
        return ""

    def _next_rpc_id(self) -> int:
        with self._lock:
            rpc_id = self._next_id
            self._next_id += 1
        return rpc_id

    def __enter__(self) -> "_StdioMCPClient":
        self._proc = subprocess.Popen(
            self.command,
            shell=True,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        # MCP initialize handshake
        init_id = self._next_rpc_id()
        self._send({
            "jsonrpc": "2.0",
            "id": init_id,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "fetch_response", "version": "1.0"},
            },
        })
        init_resp = self._recv()
        if "error" in init_resp:
            raise RuntimeError(f"MCP initialize failed: {init_resp['error']}")

        # Required notification after successful initialize
        self._send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        return self

    def __exit__(self, *_) -> None:
        if self._proc and self._proc.poll() is None:
            try:
                self._send({"jsonrpc": "2.0", "id": self._next_rpc_id(), "method": "shutdown"})
            except Exception:
                pass
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()

    def call_tool(self, tool_name: str, arguments: dict) -> dict:
        """Send tools/call and return the matching JSON-RPC response."""
        rpc_id = self._next_rpc_id()
        self._send({
            "jsonrpc": "2.0",
            "id": rpc_id,
            "method": "tools/call",
            "params": {"name": tool_name, "arguments": arguments},
        })

        deadline = time.monotonic() + self.timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(
                    f"MCP stdio server did not return tool result within {self.timeout}s"
                )
            resp = self._recv()
            if resp.get("id") == rpc_id:
                return resp
            # Otherwise it's a notification — keep reading


# ---------------------------------------------------------------------------
# Node 1 — validate_env
# ---------------------------------------------------------------------------

def validate_env(state: ChatState) -> ChatState:
    """Read environment variables and determine MCP transport."""
    host_port    = os.environ.get("HOST_PORT", "").strip()
    bearer_token = os.environ.get("BEARER_TOKEN", "").strip()
    model        = os.environ.get("MODEL", "smollm-360m").strip()
    tool_name    = os.environ.get("MCP_TOOL_NAME", "").strip()
    mcp_url      = os.environ.get("MCP_URL", "").strip()
    mcp_bearer   = os.environ.get("MCP_BEARER_TOKEN", "").strip()
    mcp_command  = os.environ.get("MCP_COMMAND", "").strip()
    mcp_timeout  = int(os.environ.get("MCP_SUBPROCESS_TIMEOUT", "300"))
    kali_server  = os.environ.get("KALI_SERVER", "http://192.168.64.2:5000/").strip()
    kali_path    = os.environ.get("KALI_CLIENT_PATH", "client.py").strip()
    kali_timeout = int(os.environ.get("KALI_TIMEOUT", "300"))

    if not host_port:
        return {**state, "error": 'Please set HOST_PORT, e.g. export HOST_PORT="10.0.0.149:8083"'}
    if not bearer_token:
        return {**state, "error": 'Please set BEARER_TOKEN, e.g. export BEARER_TOKEN="ABCD"'}

    # Determine transport — Kali is the default when nothing else is set
    if mcp_url:
        if not tool_name:
            return {**state, "error": 'Please set MCP_TOOL_NAME when using MCP_URL'}
        transport = "http"
    elif mcp_command:
        if not tool_name:
            return {**state, "error": 'Please set MCP_TOOL_NAME when using MCP_COMMAND'}
        transport = "stdio"
    else:
        transport = "kali"

    return {
        **state,
        "host_port":              host_port,
        "bearer_token":           bearer_token,
        "model":                  model,
        "mcp_tool_name":          tool_name,
        "mcp_transport":          transport,
        "mcp_url":                mcp_url,
        "mcp_bearer_token":       mcp_bearer,
        "mcp_command":            mcp_command,
        "mcp_subprocess_timeout": mcp_timeout,
        "kali_server":            kali_server,
        "kali_client_path":       kali_path,
        "kali_timeout":           kali_timeout,
    }


# ---------------------------------------------------------------------------
# Node 2 — select_kali_tool  (Kali transport only)
# ---------------------------------------------------------------------------

# Available tools in client.py and their required argument keys
KALI_TOOLS = {
    "nmap_scan":       ["target", "scan_type", "ports", "additional_args"],
    "gobuster_scan":   ["url", "mode", "wordlist", "additional_args"],
    "dirb_scan":       ["url", "wordlist", "additional_args"],
    "nikto_scan":      ["target", "additional_args"],
    "sqlmap_scan":     ["url", "data", "additional_args"],
    "metasploit_run":  ["module", "options"],
    "hydra_attack":    ["target", "service", "username", "username_file",
                        "password", "password_file", "additional_args"],
    "john_crack":      ["hash_file", "wordlist", "format_type", "additional_args"],
    "wpscan_analyze":  ["url", "additional_args"],
    "enum4linux_scan": ["target", "additional_args"],
    "server_health":   [],
    "execute_command": ["command"],
}

# Keyword patterns for heuristic tool selection
_KALI_TOOL_PATTERNS = [
    (r"\bnmap\b|port scan|service detect|version scan|os detect",        "nmap_scan"),
    (r"\bgobuster\b|directory brust|dir brust|subdomain enum|vhost",     "gobuster_scan"),
    (r"\bdirb\b|web content scan|directory scan",                        "dirb_scan"),
    (r"\bnikto\b|web server vuln|web vuln scan",                         "nikto_scan"),
    (r"\bsqlmap\b|sql inject|sqli",                                      "sqlmap_scan"),
    (r"\bmetasploit\b|msf|exploit module",                               "metasploit_run"),
    (r"\bhydra\b|password crack|brute.?force|login attack",              "hydra_attack"),
    (r"\bjohn\b|john the ripper|hash crack|crack hash",                  "john_crack"),
    (r"\bwpscan\b|wordpress scan|wp vuln",                               "wpscan_analyze"),
    (r"\benum4linux\b|smb enum|samba enum|windows enum",                 "enum4linux_scan"),
    (r"\bhealth\b|server status|api status",                             "server_health"),
]

def _select_tool_and_args(user_message: str) -> tuple[str, dict]:
    """
    Heuristically pick the best Kali tool and build its argument dict
    from the user's natural-language message.

    Returns (tool_name, arguments_dict).
    Falls back to execute_command if no pattern matches.
    """
    msg = user_message.lower()

    # Match tool by keyword
    tool_name = "execute_command"
    for pattern, name in _KALI_TOOL_PATTERNS:
        if re.search(pattern, msg, re.IGNORECASE):
            tool_name = name
            break

    # Extract common values from the message
    # IP / hostname — grab first thing that looks like one
    ip_match = re.search(
        r'\b(?:\d{1,3}\.){3}\d{1,3}\b'          # IPv4
        r'|(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}',   # hostname / domain
        user_message
    )
    target = ip_match.group(0) if ip_match else ""

    # URL — grab first http(s) URL
    url_match = re.search(r'https?://[^\s\'"]+', user_message, re.IGNORECASE)
    url = url_match.group(0) if url_match else (f"http://{target}" if target else "")

    # File path
    path_match = re.search(r'(/[\w./-]+)', user_message)
    file_path = path_match.group(1) if path_match else ""

    # Build arguments per tool
    args: dict = {}

    if tool_name == "nmap_scan":
        args = {
            "target":          target,
            "scan_type":       "-sV",
            "ports":           "",
            "additional_args": "",
        }

    elif tool_name == "gobuster_scan":
        args = {
            "url":             url,
            "mode":            "dir",
            "wordlist":        "/usr/share/wordlists/dirb/common.txt",
            "additional_args": "",
        }

    elif tool_name == "dirb_scan":
        args = {
            "url":             url,
            "wordlist":        "/usr/share/wordlists/dirb/common.txt",
            "additional_args": "",
        }

    elif tool_name == "nikto_scan":
        args = {
            "target":          url or target,
            "additional_args": "",
        }

    elif tool_name == "sqlmap_scan":
        args = {
            "url":             url,
            "data":            "",
            "additional_args": "--batch",
        }

    elif tool_name == "metasploit_run":
        # User must supply the module name — use execute_command as fallback
        module_match = re.search(r'(?:module|use)\s+([\w/]+)', user_message, re.IGNORECASE)
        if module_match:
            args = {"module": module_match.group(1), "options": {}}
        else:
            tool_name = "execute_command"
            args = {"command": user_message}

    elif tool_name == "hydra_attack":
        svc_match = re.search(
            r'\b(ssh|ftp|http|https|smb|rdp|telnet|smtp|pop3|imap)\b',
            user_message, re.IGNORECASE
        )
        args = {
            "target":        target,
            "service":       svc_match.group(1).lower() if svc_match else "ssh",
            "username":      "",
            "username_file": "/usr/share/wordlists/metasploit/unix_users.txt",
            "password":      "",
            "password_file": "/usr/share/wordlists/rockyou.txt",
            "additional_args": "",
        }

    elif tool_name == "john_crack":
        args = {
            "hash_file":      file_path or "/tmp/hashes.txt",
            "wordlist":       "/usr/share/wordlists/rockyou.txt",
            "format_type":    "",
            "additional_args": "",
        }

    elif tool_name == "wpscan_analyze":
        args = {
            "url":             url,
            "additional_args": "",
        }

    elif tool_name == "enum4linux_scan":
        args = {
            "target":          target,
            "additional_args": "-a",
        }

    elif tool_name == "server_health":
        args = {}

    else:  # execute_command
        args = {"command": user_message}

    return tool_name, args


def select_kali_tool(state: ChatState) -> ChatState:
    """
    Inspect the user message and pick the appropriate Kali tool + arguments.
    Stores the result in state so call_mcp_kali can use it directly.
    """
    tool_name, tool_args = _select_tool_and_args(state["user_message"])
    print(f"[Kali] Selected tool: {tool_name}")
    print(f"[Kali] Arguments:     {json.dumps(tool_args, indent=2)}")
    return {**state, "mcp_tool_name": tool_name, "mcp_tool_args": tool_args}


# ---------------------------------------------------------------------------
# Node 3a — call_mcp_kali  (Kali stdio subprocess transport)
# ---------------------------------------------------------------------------

def call_mcp_kali(state: ChatState) -> ChatState:
    """
    Launch client.py as a stdio MCP subprocess and call the selected Kali tool.

    The subprocess command is:
        python <kali_client_path> --server <kali_server> --timeout <kali_timeout>

    The MCP initialize handshake is performed automatically by _StdioMCPClient.
    Tool arguments were resolved by select_kali_tool.
    """
    cmd = (
        f'python {state["kali_client_path"]} '
        f'--server "{state["kali_server"]}" '
        f'--timeout {state["kali_timeout"]}'
    )
    tool     = state["mcp_tool_name"]
    args     = state["mcp_tool_args"]
    timeout  = state["mcp_subprocess_timeout"]

    print(f"[Kali] Launching: {cmd}")
    print(f"[Kali] Calling tool '{tool}' ...")

    try:
        with _StdioMCPClient(cmd, timeout=timeout) as client:
            mcp_result = client.call_tool(tool, args)
    except TimeoutError as exc:
        return {**state, "error": f"Kali MCP timeout: {exc}"}
    except RuntimeError as exc:
        return {**state, "error": f"Kali MCP error: {exc}"}
    except Exception as exc:
        return {**state, "error": f"Kali MCP unexpected error: {exc}"}

    if "error" in mcp_result:
        return {**state, "error": f"Kali tool error: {mcp_result['error']}"}

    mcp_context = _extract_mcp_context(mcp_result, tool)
    print(f"[Kali] Received output ({len(mcp_context)} chars)")
    return {**state, "mcp_result": mcp_result, "mcp_context": mcp_context}


# ---------------------------------------------------------------------------
# Node 3b — call_mcp_http  (generic HTTP/SSE transport)
# ---------------------------------------------------------------------------

def _parse_mcp_sse_lines(lines: list[str]) -> dict:
    for line in lines:
        line = line.strip()
        if not line:
            continue
        if line.startswith("data:"):
            payload = line[len("data:"):].strip()
            if payload in ("[DONE]", ""):
                continue
            try:
                return json.loads(payload)
            except json.JSONDecodeError:
                continue
        else:
            try:
                return json.loads(line)
            except json.JSONDecodeError:
                continue
    raise ValueError("No valid JSON found in MCP HTTP/SSE response")


def call_mcp_http(state: ChatState) -> ChatState:
    """Call a generic MCP server via HTTP/SSE (JSON-RPC 2.0 POST /messages)."""
    url = f"{state['mcp_url'].rstrip('/')}/messages"
    headers: dict[str, str] = {"Content-Type": "application/json"}
    if state["mcp_bearer_token"]:
        headers["Authorization"] = f"Bearer {state['mcp_bearer_token']}"

    rpc_payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": state["mcp_tool_name"],
            "arguments": {"query": state["user_message"]},
        },
    }

    print(f"[MCP/HTTP] Calling tool '{state['mcp_tool_name']}' at {url} ...")

    try:
        with httpx.Client(timeout=30) as client:
            resp = client.post(url, headers=headers, json=rpc_payload)
            resp.raise_for_status()
            content_type = resp.headers.get("content-type", "")
            lines = resp.text.splitlines() if "text/event-stream" in content_type else [resp.text]
            mcp_result = _parse_mcp_sse_lines(lines)

    except httpx.HTTPStatusError as exc:
        return {**state, "error": f"MCP HTTP error {exc.response.status_code}: {exc.response.text}"}
    except httpx.RequestError as exc:
        return {**state, "error": f"MCP request failed: {exc}"}
    except ValueError as exc:
        return {**state, "error": f"MCP response parse error: {exc}"}

    mcp_context = _extract_mcp_context(mcp_result, state["mcp_tool_name"])
    print(f"[MCP/HTTP] Retrieved context ({len(mcp_context)} chars)")
    return {**state, "mcp_result": mcp_result, "mcp_context": mcp_context}


# ---------------------------------------------------------------------------
# Node 3c — call_mcp_stdio  (generic stdio subprocess transport)
# ---------------------------------------------------------------------------

def call_mcp_stdio(state: ChatState) -> ChatState:
    """Call a generic MCP server via stdio subprocess."""
    command  = state["mcp_command"]
    tool     = state["mcp_tool_name"]
    timeout  = state.get("mcp_subprocess_timeout", 300)

    print(f"[MCP/stdio] Launching subprocess: {command}")
    print(f"[MCP/stdio] Calling tool '{tool}' ...")

    try:
        with _StdioMCPClient(command, timeout=timeout) as client:
            mcp_result = client.call_tool(tool, {"query": state["user_message"]})
    except TimeoutError as exc:
        return {**state, "error": f"MCP stdio timeout: {exc}"}
    except RuntimeError as exc:
        return {**state, "error": f"MCP stdio error: {exc}"}
    except Exception as exc:
        return {**state, "error": f"MCP stdio unexpected error: {exc}"}

    if "error" in mcp_result:
        return {**state, "error": f"MCP tool error: {mcp_result['error']}"}

    mcp_context = _extract_mcp_context(mcp_result, tool)
    print(f"[MCP/stdio] Retrieved context ({len(mcp_context)} chars)")
    return {**state, "mcp_result": mcp_result, "mcp_context": mcp_context}


# ---------------------------------------------------------------------------
# Node 4 — stream_completion
# ---------------------------------------------------------------------------

def stream_completion(state: ChatState) -> ChatState:
    """Call the OpenAI-compatible streaming LLM endpoint with MCP context injected."""
    url = f"http://{state['host_port']}/mimik-ai/openai/v1/chat/completions"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {state['bearer_token']}",
    }

    if state.get("mcp_context"):
        prompt = (
            f"Use the following output from the security tool '{state['mcp_tool_name']}' "
            f"to answer the question.\n\n"
            f"--- Tool output ---\n"
            f"{state['mcp_context']}\n"
            f"--- End of tool output ---\n\n"
            f"{state['user_message']}"
        )
    else:
        prompt = state["user_message"]

    payload = {
        "model": state["model"],
        "messages": [{"role": "user", "content": prompt}],
        "stream": True,
    }

    print(f"\nYou are asking the model: {state['model']}")
    print(f"\t\t\t {state['user_message']}")
    print("Thinking on this...")

    chunks: list[dict] = []
    try:
        with httpx.Client(timeout=60) as client:
            with client.stream("POST", url, headers=headers, json=payload) as resp:
                resp.raise_for_status()
                for line in resp.iter_lines():
                    line = line.strip()
                    if not line or line == "data: [DONE]":
                        continue
                    if line.startswith("data: "):
                        line = line[len("data: "):]
                    try:
                        chunks.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass

    except httpx.HTTPStatusError as exc:
        return {**state, "error": f"HTTP error {exc.response.status_code}: {exc.response.text}"}
    except httpx.RequestError as exc:
        return {**state, "error": f"Request failed: {exc}"}

    return {**state, "raw_chunks": chunks}


# ---------------------------------------------------------------------------
# Node 5 — assemble_response
# ---------------------------------------------------------------------------

def assemble_response(state: ChatState) -> ChatState:
    parts: list[str] = []
    for chunk in state["raw_chunks"]:
        for choice in chunk.get("choices", []):
            content = choice.get("delta", {}).get("content")
            if content and content != "null":
                parts.append(content)
    return {**state, "response_text": "".join(parts)}


# ---------------------------------------------------------------------------
# Node 6 — print_response
# ---------------------------------------------------------------------------

def print_response(state: ChatState) -> ChatState:
    print(f"\n\t\t\t... The answer from {state['model']} is:")
    print(state["response_text"])
    return state


# ---------------------------------------------------------------------------
# Routing helpers
# ---------------------------------------------------------------------------

def has_error(state: ChatState) -> str:
    return "error" if state.get("error") else "ok"


def route_mcp_transport(state: ChatState) -> str:
    return state.get("mcp_transport", "kali")   # "http" | "stdio" | "kali"


def error_node(state: ChatState) -> ChatState:
    print(f"Error: {state['error']}", file=sys.stderr)
    return state


# ---------------------------------------------------------------------------
# Graph construction
# ---------------------------------------------------------------------------

def build_graph():
    graph = StateGraph(ChatState)

    graph.add_node("validate_env",      validate_env)
    graph.add_node("route_mcp",         lambda s: s)        # pass-through branch node
    graph.add_node("select_kali_tool",  select_kali_tool)   # NEW
    graph.add_node("call_mcp_kali",     call_mcp_kali)      # NEW
    graph.add_node("call_mcp_http",     call_mcp_http)
    graph.add_node("call_mcp_stdio",    call_mcp_stdio)
    graph.add_node("stream_completion", stream_completion)
    graph.add_node("assemble_response", assemble_response)
    graph.add_node("print_response",    print_response)
    graph.add_node("error_node",        error_node)

    graph.set_entry_point("validate_env")

    graph.add_conditional_edges(
        "validate_env",
        has_error,
        {"error": "error_node", "ok": "route_mcp"},
    )
    graph.add_conditional_edges(
        "route_mcp",
        route_mcp_transport,
        {"http": "call_mcp_http", "stdio": "call_mcp_stdio", "kali": "select_kali_tool"},
    )

    # Kali: tool selection → tool call
    graph.add_conditional_edges(
        "select_kali_tool",
        has_error,
        {"error": "error_node", "ok": "call_mcp_kali"},
    )

    # All three MCP nodes converge on stream_completion
    for mcp_node in ("call_mcp_kali", "call_mcp_http", "call_mcp_stdio"):
        graph.add_conditional_edges(
            mcp_node,
            has_error,
            {"error": "error_node", "ok": "stream_completion"},
        )

    graph.add_conditional_edges(
        "stream_completion",
        has_error,
        {"error": "error_node", "ok": "assemble_response"},
    )
    graph.add_edge("assemble_response", "print_response")
    graph.add_edge("print_response",    END)
    graph.add_edge("error_node",        END)

    return graph.compile()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    if len(sys.argv) < 2:
        print('Please enter some input in quotes to query the AI')
        print('  Ex. python fetch_response.py "Run an nmap scan on 10.0.0.1"')
        sys.exit(1)

    initial_state: ChatState = {
        "host_port":              "",
        "bearer_token":           "",
        "model":                  "",
        "mcp_tool_name":          "",
        "mcp_tool_args":          {},
        "mcp_transport":          "",
        "mcp_url":                "",
        "mcp_bearer_token":       "",
        "mcp_command":            "",
        "mcp_subprocess_timeout": 300,
        "kali_server":            "http://192.168.64.2:5000/",
        "kali_client_path":       "client.py",
        "kali_timeout":           300,
        "user_message":           sys.argv[1],
        "mcp_result":             {},
        "mcp_context":            "",
        "raw_chunks":             [],
        "response_text":          "",
        "error":                  "",
    }

    build_graph().invoke(initial_state)


if __name__ == "__main__":
    main()
