"""API client dispatch for Spof (Anthropic SDK, OpenRouter, and AgentRouter)."""

import copy
import json
import urllib.request
import urllib.error
from anthropic import Anthropic
from src.utils import intercept_warnings
from src import config
from src.tools import TOOLS


def _get_tools(description_less: bool = False, no_tools: bool = False) -> list:
    """Return the tools list, optionally stripped of descriptions or empty for no-tools mode."""
    if no_tools:
        return []
    if not description_less:
        return TOOLS
    result = copy.deepcopy(TOOLS)
    for tool in result:
        if tool.get("type") == "function":
            tool["function"].pop("description", None)
            params = tool["function"].get("parameters", {})
            for prop in params.get("properties", {}).values():
                prop.pop("description", None)
    return result


@intercept_warnings
def call_openrouter_or_agentrouter(messages: list, url: str, api_key: str, model: str, is_agentrouter: bool = False, description_less: bool = False, no_tools: bool = False, temperature: float = None) -> dict:
    """Send a chat completion request to the OpenRouter or AgentRouter API using urllib."""
    if not api_key:
        return {
            "error": True,
            "detail": f"API Key is not set for {url}. Please check configuration."
        }

    formatted_messages = []
    for msg in messages:
        role = msg.get("role")
        content = msg.get("content")
        
        if role == "tool":
            formatted_messages.append({
                "role": "tool",
                "tool_call_id": msg.get("tool_call_id"),
                "content": content
            })
        elif role == "assistant":
            formatted_msg = {
                "role": "assistant",
                "content": content
            }
            if msg.get("tool_calls"):
                formatted_msg["tool_calls"] = msg["tool_calls"]
            formatted_messages.append(formatted_msg)
        else:
            formatted_messages.append(msg)

    tools = _get_tools(description_less, no_tools)
    payload = {
        "model": model,
        "messages": formatted_messages,
        "tools": tools,
    }
    if tools:
        payload["tool_choice"] = "auto"
    if temperature is not None:
        payload["temperature"] = temperature

    body = json.dumps(payload).encode("utf-8")
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://github.com/spof",
        "X-Title": "Spof",
    }
    
    if is_agentrouter:
        headers.update({
            "Originator": "codex_cli_rs",
            "Version": "0.101.0",
            "User-Agent": "codex_cli_rs/0.101.0 (Mac OS 26.0.1; arm64) Apple_Terminal/464",
        })

    req = urllib.request.Request(
        url, data=body, headers=headers, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", errors="replace")
        return {"error": True, "status": e.code, "detail": detail}
    except Exception as e:
        return {"error": True, "detail": str(e)}


@intercept_warnings
def call_anthropic(messages: list, model: str, description_less: bool = False, no_tools: bool = False, temperature: float = None) -> dict:
    """Send a chat completion request to the Anthropic API using their SDK."""
    if not config.ANTHROPIC_API_KEY:
        return {
            "error": True,
            "detail": "ANTHROPIC_API_KEY is not set. Please set it in your environment or env/.env file."
        }

    try:
        client = Anthropic(api_key=config.ANTHROPIC_API_KEY)
        
        system_prompt = ""
        api_messages = []
        
        for msg in messages:
            if msg.get("role") == "system":
                system_prompt = msg.get("content", "")
            else:
                api_messages.append(msg)

        anthropic_tools = []
        for tool in _get_tools(description_less, no_tools):
            if tool.get("type") == "function":
                func = tool["function"]
                anthropic_tools.append({
                    "name": func["name"],
                    "description": func.get("description", ""),
                    "input_schema": func["parameters"]
                })

        anthropic_messages = []
        for msg in api_messages:
            role = msg.get("role")
            content = msg.get("content")
            
            if role == "tool":
                anthropic_messages.append({
                    "role": "user",
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": msg.get("tool_call_id"),
                            "content": content
                        }
                    ]
                })
            elif role == "assistant":
                blocks = []
                if content:
                    blocks.append({"type": "text", "text": content})
                if msg.get("tool_calls"):
                    for tc in msg["tool_calls"]:
                        if tc.get("type") == "function":
                            func = tc["function"]
                            blocks.append({
                                "type": "tool_use",
                                "id": tc.get("id"),
                                "name": func.get("name"),
                                "input": json.loads(func.get("arguments", "{}"))
                            })
                anthropic_messages.append({
                    "role": "assistant",
                    "content": blocks
                })
            else:
                anthropic_messages.append({
                    "role": "user",
                    "content": content
                })

        create_kwargs = {
            "model": model,
            "max_tokens": 4096,
            "system": system_prompt,
            "messages": anthropic_messages,
            "tools": anthropic_tools,
        }
        if temperature is not None:
            create_kwargs["temperature"] = temperature

        response = client.messages.create(**create_kwargs)


        choices = []
        message_content = ""
        tool_calls = []
        
        for block in response.content:
            if block.type == "text":
                message_content += block.text
            elif block.type == "tool_use":
                tool_calls.append({
                    "id": block.id,
                    "type": "function",
                    "function": {
                        "name": block.name,
                        "arguments": json.dumps(block.input)
                    }
                })
        
        message_dict = {
            "role": "assistant",
            "content": message_content if message_content else None
        }
        if tool_calls:
            message_dict["tool_calls"] = tool_calls

        choices.append({
            "message": message_dict
        })
        
        return {
            "choices": choices
        }

    except Exception as e:
        return {"error": True, "detail": str(e)}


def call_api(messages: list, provider: str = None, model: str = None, description_less: bool = False, no_tools: bool = False, temperature: float = None) -> dict:
    """Dispatches call to the configured or requested provider with the requested model."""
    prov = provider or config.DEFAULT_PROVIDER
    
    # --- AGENTROUTER (EASY TO REMOVE SECTION) ---
    if prov == "agentrouter":
        target_model = model or config.DEFAULT_AGENTROUTER_MODEL
        return call_openrouter_or_agentrouter(
            messages,
            url=config.AGENTROUTER_URL,
            api_key=config.AGENTROUTER_KEY,
            model=target_model,
            is_agentrouter=True,
            description_less=description_less,
            no_tools=no_tools,
            temperature=temperature,
        )
    # ---------------------------------------------

    if prov == "hackclub":
        target_model = model or "claude-3-5-sonnet-20241022"
        return call_openrouter_or_agentrouter(
            messages,
            url=config.HACKCLUB_URL,
            api_key=config.HACKCLUB_API_KEY,
            model=target_model,
            is_agentrouter=False,
            description_less=description_less,
            no_tools=no_tools,
            temperature=temperature,
        )

    if prov == "openrouter":
        target_model = model or config.DEFAULT_OPENROUTER_MODEL
        return call_openrouter_or_agentrouter(
            messages,
            url=config.OPENROUTER_URL,
            api_key=config.OPENROUTER_KEY,
            model=target_model,
            is_agentrouter=False,
            description_less=description_less,
            no_tools=no_tools,
            temperature=temperature,
        )
    else:
        target_model = model or config.DEFAULT_ANTHROPIC_MODEL
        return call_anthropic(messages, model=target_model, description_less=description_less, no_tools=no_tools, temperature=temperature)

