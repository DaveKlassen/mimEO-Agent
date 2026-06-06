#!/usr/bin/env python3
"""
fetch_response.py — LangGraph conversion of fetch-response.sh

Environment variables (required):
    HOST_PORT     e.g. "10.0.0.149:8083"
    BEARER_TOKEN  e.g. "ABCD"

Optional:
    MODEL         defaults to "smollm-360m"

Usage:
    python fetch_response.py "Who am I and what am I doing?"
"""

import os
import sys
import json
import httpx
from typing import TypedDict, Annotated
from langgraph.graph import StateGraph, END


# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------

class ChatState(TypedDict):
    """Shared state passed between LangGraph nodes."""
    host_port: str
    bearer_token: str
    model: str
    user_message: str
    raw_chunks: list[dict]       # parsed SSE delta objects
    response_text: str           # final assembled answer
    error: str                   # non-empty means something went wrong


# ---------------------------------------------------------------------------
# Nodes
# ---------------------------------------------------------------------------

def validate_env(state: ChatState) -> ChatState:
    """Check that required environment variables are present."""
    host_port = os.environ.get("HOST_PORT", "").strip()
    bearer_token = os.environ.get("BEARER_TOKEN", "").strip()
    model = os.environ.get("MODEL", "smollm-360m").strip()

    if not host_port:
        return {**state, "error": (
            "Please set the HOST_PORT environment variable.\n"
            '  export HOST_PORT="10.0.0.149:8083"'
        )}
    if not bearer_token:
        return {**state, "error": (
            "Please set the BEARER_TOKEN environment variable.\n"
            '  export BEARER_TOKEN="ABCD"'
        )}

    return {**state, "host_port": host_port, "bearer_token": bearer_token, "model": model}


def stream_completion(state: ChatState) -> ChatState:
    """
    Call the OpenAI-compatible /chat/completions endpoint with stream=True
    and collect all SSE delta chunks.
    """
    url = f"http://{state['host_port']}/mimik-ai/openai/v1/chat/completions"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {state['bearer_token']}",
    }
    payload = {
        "model": state["model"],
        "messages": [{"role": "user", "content": state["user_message"]}],
        "stream": True,
    }

    print(f"You are asking the model: {state['model']}")
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
                        chunk = json.loads(line)
                        chunks.append(chunk)
                    except json.JSONDecodeError:
                        pass  # skip malformed lines

    except httpx.HTTPStatusError as exc:
        return {**state, "error": f"HTTP error {exc.response.status_code}: {exc.response.text}"}
    except httpx.RequestError as exc:
        return {**state, "error": f"Request failed: {exc}"}

    return {**state, "raw_chunks": chunks}


def assemble_response(state: ChatState) -> ChatState:
    """Concatenate delta content from all chunks into the final answer."""
    parts: list[str] = []
    for chunk in state["raw_chunks"]:
        for choice in chunk.get("choices", []):
            content = choice.get("delta", {}).get("content")
            if content and content != "null":
                parts.append(content)

    return {**state, "response_text": "".join(parts)}


def print_response(state: ChatState) -> ChatState:
    """Print the assembled answer."""
    print(f"\n\t\t\t... The answer from {state['model']} is:")
    print(state["response_text"])
    return state


# ---------------------------------------------------------------------------
# Routing helpers
# ---------------------------------------------------------------------------

def has_error(state: ChatState) -> str:
    if state.get("error"):
        return "error"
    return "ok"


def error_node(state: ChatState) -> ChatState:
    print(f"Error: {state['error']}", file=sys.stderr)
    return state


# ---------------------------------------------------------------------------
# Graph construction
# ---------------------------------------------------------------------------

def build_graph() -> StateGraph:
    graph = StateGraph(ChatState)

    graph.add_node("validate_env", validate_env)
    graph.add_node("stream_completion", stream_completion)
    graph.add_node("assemble_response", assemble_response)
    graph.add_node("print_response", print_response)
    graph.add_node("error_node", error_node)

    graph.set_entry_point("validate_env")

    graph.add_conditional_edges(
        "validate_env",
        has_error,
        {"error": "error_node", "ok": "stream_completion"},
    )
    graph.add_conditional_edges(
        "stream_completion",
        has_error,
        {"error": "error_node", "ok": "assemble_response"},
    )
    graph.add_edge("assemble_response", "print_response")
    graph.add_edge("print_response", END)
    graph.add_edge("error_node", END)

    return graph.compile()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    if len(sys.argv) < 2:
        print('Please enter some input in quotes to query the AI')
        print('  Ex. python fetch_response.py "Who am I and what am I doing?"')
        sys.exit(1)

    user_message = sys.argv[1]

    initial_state: ChatState = {
        "host_port": "",
        "bearer_token": "",
        "model": "",
        "user_message": user_message,
        "raw_chunks": [],
        "response_text": "",
        "error": "",
    }

    app = build_graph()
    app.invoke(initial_state)


if __name__ == "__main__":
    main()
