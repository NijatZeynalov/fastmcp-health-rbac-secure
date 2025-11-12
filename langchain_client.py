from __future__ import annotations

import argparse
import asyncio
import json
import os
from typing import Any

from dotenv import load_dotenv
from langchain_core.messages import AIMessage, ToolMessage
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_google_genai import ChatGoogleGenerativeAI

try:  # langchain_mcp_adapters exposes the client differently per release
    from langchain_mcp_adapters import MCPAdapter  # type: ignore
except ImportError:  # pragma: no cover - backwards compatibility path
    from langchain_mcp_adapters.client import MultiServerMCPClient as MCPAdapter  # type: ignore

load_dotenv()

ROLE_TOKEN_ENV = {
    "doctor": "JWT_DOCTOR_TOKEN",
    "nurse": "JWT_NURSE_TOKEN",
    "labtechnician": "JWT_LABTECH_TOKEN",
    "adminstaff": "JWT_ADMIN_TOKEN",
}


def build_prompt() -> ChatPromptTemplate:
    return ChatPromptTemplate.from_messages(
        [
            (
                "system",
                (
                    "You are Gemini 2.0 Flash orchestrating clinical workflows. "
                    "When a user request maps to an MCP tool, call it with precise arguments. "
                    "Only answer from tool outputs or clearly state when information is unavailable."
                ),
            ),
            ("user", "{input}"),
            MessagesPlaceholder(variable_name="agent_scratchpad"),
        ]
    )


async def run_agent(role: str, query: str, server_url: str) -> dict[str, Any]:
    token_env = ROLE_TOKEN_ENV.get(role.lower())
    if not token_env:
        valid_roles = ", ".join(ROLE_TOKEN_ENV.keys())
        raise ValueError(f"Unsupported role '{role}'. Choose one of: {valid_roles}")

    token = os.getenv(token_env)
    if not token:
        raise RuntimeError(f"{token_env} is not defined in your environment.")

    headers = {"Authorization": f"Bearer {token}"}
    connections = {
        "patient_rbac": {
            "transport": "sse",
            "url": server_url,
            "headers": headers,
        }
    }

    async with MCPAdapter(connections) as client:
        tools = client.get_tools()
        if not tools:
            raise RuntimeError("No MCP tools loaded from the server.")

        tool_lookup = {tool.name: tool for tool in tools}
        model = ChatGoogleGenerativeAI(
            model="gemini-2.0-flash",
            temperature=0.2,
            max_output_tokens=1024,
        ).bind_tools(tools)

        prompt = build_prompt()
        chain = prompt | model
        scratchpad: list[Any] = []

        for _ in range(5):
            ai_message = await chain.ainvoke({"input": query, "agent_scratchpad": scratchpad})
            if isinstance(ai_message, AIMessage) and ai_message.tool_calls:
                scratchpad.append(ai_message)
                for tool_call in ai_message.tool_calls:
                    tool = tool_lookup.get(tool_call["name"])
                    if tool is None:
                        observation = f"Tool {tool_call['name']} is not available."
                    else:
                        args = tool_call.get("args") or {}
                        observation = await tool.ainvoke(args)
                    scratchpad.append(
                        ToolMessage(
                            content=_stringify_observation(observation),
                            tool_call_id=tool_call["id"],
                        )
                    )
                continue

            output = ai_message.content if isinstance(ai_message, AIMessage) else ai_message
            return {"output": output}

        raise RuntimeError("Reached maximum number of tool iterations without a final answer.")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Gemini 2.0 Flash + MCP RBAC client")
    parser.add_argument(
        "--role",
        required=True,
        choices=["doctor", "nurse", "labtechnician", "adminstaff"],
        help="Which JWT/token to use for testing.",
    )
    parser.add_argument(
        "--query",
        required=True,
        help="Natural language instruction for Gemini (e.g. 'Order a lab test for patient 2').",
    )
    parser.add_argument(
        "--server-url",
        default=os.getenv("MCP_SERVER_SSE_URL", "http://127.0.0.1:8000/sse"),
        help="SSE endpoint exposed by FastMCP (default: %(default)s).",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    result = asyncio.run(run_agent(args.role, args.query, args.server_url))
    output = result.get("output") or result
    print(output)


def _stringify_observation(value: Any) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, default=str)
    except TypeError:
        return str(value)


if __name__ == "__main__":
    main()
