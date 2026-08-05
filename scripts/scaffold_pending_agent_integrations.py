"""Scaffold pending high-value Bastion integrations: langgraph, pydantic-ai, openai-agents."""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent / "integrations"
LICENSE = "See LICENSE and COMMERCIAL_LICENSE.md in the MCP-Bastion repository."
LICENSE_BLURB = """## License

Same terms as the [MCP-Bastion](https://github.com/vaquarkhan/MCP-Bastion) project: see [LICENSE](https://github.com/vaquarkhan/MCP-Bastion/blob/main/LICENSE). Non-commercial use is free with required **citation/attribution**; **copyright** terms apply. **Commercial** use as defined in the License may need a **separate agreement** ([COMMERCIAL_LICENSE.md](https://github.com/vaquarkhan/MCP-Bastion/blob/main/COMMERCIAL_LICENSE.md)).
"""

PACKAGES = [
    {
        "name": "mcp-bastion-langgraph",
        "mod": "mcp_bastion_langgraph",
        "cls": "secure_node",
        "exports": '["secure_node", "BastionGraphGuard"]',
        "title": "LangGraph",
        "desc": "MCP-Bastion security helpers for LangGraph nodes and tool calls.",
        "keywords": '["mcp", "bastion", "langgraph", "langchain", "security", "agents"]',
        "deps": ['"mcp-bastion-python>=4.0.0,<5"'],
        "usage": (
            "from mcp_bastion_langgraph import secure_node, BastionGraphGuard\n\n"
            "@secure_node\n"
            "def my_tool_node(state):\n"
            '    return {"out": state["query"]}\n\n'
            "guard = BastionGraphGuard()\n"
            'guard.check_text(state.get("query", ""))'
        ),
        "init_extra": "from mcp_bastion_langgraph.middleware import BastionGraphGuard, secure_node\n",
        "middleware": '''"""LangGraph node / message guard with MCP-Bastion security."""
from __future__ import annotations
from typing import Any, Callable

from mcp_bastion.errors import PromptInjectionError, RateLimitExceededError
from mcp_bastion.pillars.content_filter import ContentFilter
from mcp_bastion.pillars.prompt_guard import PromptGuardEngine
from mcp_bastion.pillars.rate_limit import TokenBucketRateLimiter


class BastionGraphGuard:
    """Scan text flowing through LangGraph nodes before tools / LLM hops."""

    def __init__(self, max_requests: int = 120, window_seconds: int = 60) -> None:
        self._filter = ContentFilter()
        self._prompt_guard = PromptGuardEngine(fail_open=True, heuristic_fallback=True)
        self._limiter = TokenBucketRateLimiter(
            max_iterations=max_requests, timeout_seconds=float(window_seconds)
        )
        self._session = "langgraph-default"

    def check_text(self, text: str) -> None:
        if not text or not str(text).strip():
            return
        check = self._limiter.check_iteration(session_id=self._session)
        if not check.allowed:
            raise RateLimitExceededError(check.message or "Rate limit exceeded")
        self._filter.check(text)
        if self._prompt_guard.is_malicious(text):
            raise PromptInjectionError("Request blocked: suspected prompt injection")
        self._limiter.consume_iteration(session_id=self._session)

    def check_state(self, state: Any, keys: tuple[str, ...] = ("query", "input", "messages")) -> None:
        if not isinstance(state, dict):
            return
        for key in keys:
            val = state.get(key)
            if isinstance(val, str):
                self.check_text(val)
            elif isinstance(val, list):
                for item in val[-3:]:
                    content = getattr(item, "content", None)
                    if isinstance(content, str):
                        self.check_text(content)
                    elif isinstance(item, dict) and isinstance(item.get("content"), str):
                        self.check_text(item["content"])


_default_guard = BastionGraphGuard()


def secure_node(fn: Callable[..., Any]) -> Callable[..., Any]:
    """Decorator: scan string args / common state keys, then call the node."""

    def wrapper(*args: Any, **kwargs: Any) -> Any:
        for a in args:
            if isinstance(a, str):
                _default_guard.check_text(a)
            elif isinstance(a, dict):
                _default_guard.check_state(a)
        for v in kwargs.values():
            if isinstance(v, str):
                _default_guard.check_text(v)
            elif isinstance(v, dict):
                _default_guard.check_state(v)
        return fn(*args, **kwargs)

    wrapper.__name__ = getattr(fn, "__name__", "secure_node")
    wrapper.__doc__ = fn.__doc__
    return wrapper
''',
    },
    {
        "name": "mcp-bastion-pydantic-ai",
        "mod": "mcp_bastion_pydantic_ai",
        "cls": "SecurePydanticAI",
        "exports": '["SecurePydanticAI"]',
        "title": "Pydantic AI",
        "desc": "MCP-Bastion security helpers for Pydantic AI agent prompts and tool args.",
        "keywords": '["mcp", "bastion", "pydantic-ai", "pydantic", "security", "agents"]',
        "deps": ['"mcp-bastion-python>=4.0.0,<5"'],
        "usage": (
            "from mcp_bastion_pydantic_ai import SecurePydanticAI\n\n"
            "guard = SecurePydanticAI()\n"
            'guard.check_prompt("Summarize this ticket")\n'
            'guard.check_tool_args({"path": "README.md"})'
        ),
        "init_extra": "from mcp_bastion_pydantic_ai.middleware import SecurePydanticAI\n",
        "middleware": '''"""Pydantic AI prompt / tool-arg guard with MCP-Bastion security."""
from __future__ import annotations
import json
from typing import Any

from mcp_bastion.errors import PromptInjectionError, RateLimitExceededError
from mcp_bastion.pillars.content_filter import ContentFilter
from mcp_bastion.pillars.prompt_guard import PromptGuardEngine
from mcp_bastion.pillars.rate_limit import TokenBucketRateLimiter


class SecurePydanticAI:
    """Scan prompts and tool arguments before Pydantic AI agents act."""

    def __init__(self, max_requests: int = 60, window_seconds: int = 60) -> None:
        self._filter = ContentFilter()
        self._prompt_guard = PromptGuardEngine(fail_open=True, heuristic_fallback=True)
        self._limiter = TokenBucketRateLimiter(
            max_iterations=max_requests, timeout_seconds=float(window_seconds)
        )
        self._session = "pydantic-ai-default"

    def _gate(self, text: str) -> None:
        check = self._limiter.check_iteration(session_id=self._session)
        if not check.allowed:
            raise RateLimitExceededError(check.message or "Rate limit exceeded")
        self._filter.check(text)
        if self._prompt_guard.is_malicious(text):
            raise PromptInjectionError("Request blocked: suspected prompt injection")
        self._limiter.consume_iteration(session_id=self._session)

    def check_prompt(self, text: str) -> None:
        if text and str(text).strip():
            self._gate(str(text))

    def check_tool_args(self, arguments: Any) -> None:
        if arguments is None:
            return
        if isinstance(arguments, str):
            self._gate(arguments)
            return
        try:
            blob = json.dumps(arguments, default=str)
        except (TypeError, ValueError):
            blob = str(arguments)
        self._gate(blob)
''',
    },
    {
        "name": "mcp-bastion-openai-agents",
        "mod": "mcp_bastion_openai_agents",
        "cls": "SecureOpenAIAgents",
        "exports": '["SecureOpenAIAgents", "secure_tool"]',
        "title": "OpenAI Agents SDK",
        "desc": "MCP-Bastion security helpers for OpenAI Agents SDK tools and messages.",
        "keywords": '["mcp", "bastion", "openai-agents", "openai", "security", "agents", "mcp"]',
        "deps": ['"mcp-bastion-python>=4.0.0,<5"'],
        "usage": (
            "from mcp_bastion_openai_agents import SecureOpenAIAgents, secure_tool\n\n"
            "guard = SecureOpenAIAgents()\n"
            'guard.check_message("user or tool text")\n\n'
            "@secure_tool\n"
            "def lookup(query: str) -> str:\n"
            "    return query"
        ),
        "init_extra": (
            "from mcp_bastion_openai_agents.middleware import SecureOpenAIAgents, secure_tool\n"
        ),
        "middleware": '''"""OpenAI Agents SDK message / tool guard with MCP-Bastion security."""
from __future__ import annotations
from typing import Any, Callable

from mcp_bastion.errors import PromptInjectionError, RateLimitExceededError
from mcp_bastion.pillars.content_filter import ContentFilter
from mcp_bastion.pillars.prompt_guard import PromptGuardEngine
from mcp_bastion.pillars.rate_limit import TokenBucketRateLimiter


class SecureOpenAIAgents:
    """Scan agent / tool messages for the OpenAI Agents SDK."""

    def __init__(self, max_requests: int = 60, window_seconds: int = 60) -> None:
        self._filter = ContentFilter()
        self._prompt_guard = PromptGuardEngine(fail_open=True, heuristic_fallback=True)
        self._limiter = TokenBucketRateLimiter(
            max_iterations=max_requests, timeout_seconds=float(window_seconds)
        )
        self._session = "openai-agents-default"

    def check_message(self, text: str) -> None:
        if not text or not str(text).strip():
            return
        check = self._limiter.check_iteration(session_id=self._session)
        if not check.allowed:
            raise RateLimitExceededError(check.message or "Rate limit exceeded")
        self._filter.check(text)
        if self._prompt_guard.is_malicious(text):
            raise PromptInjectionError("Request blocked: suspected prompt injection")
        self._limiter.consume_iteration(session_id=self._session)


_default = SecureOpenAIAgents()


def secure_tool(fn: Callable[..., Any]) -> Callable[..., Any]:
    """Decorator: scan string tool args, then call the tool function."""

    def wrapper(*args: Any, **kwargs: Any) -> Any:
        for a in args:
            if isinstance(a, str):
                _default.check_message(a)
        for v in kwargs.values():
            if isinstance(v, str):
                _default.check_message(v)
        return fn(*args, **kwargs)

    wrapper.__name__ = getattr(fn, "__name__", "secure_tool")
    wrapper.__doc__ = fn.__doc__
    return wrapper
''',
    },
]


def main() -> None:
    for p in PACKAGES:
        base = ROOT / p["name"]
        src = base / "src" / p["mod"]
        src.mkdir(parents=True, exist_ok=True)
        deps = ",\n    ".join(p["deps"])
        exports = p["exports"]
        (base / "pyproject.toml").write_text(
            f"""[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "{p["name"]}"
version = "4.0.0"
description = "{p["desc"]}"
readme = "README.md"
license = {{ text = "{LICENSE}" }}
requires-python = ">=3.10"
authors = [{{ name = "Vaquar Khan" }}]
keywords = {p["keywords"]}
classifiers = [
    "Development Status :: 4 - Beta",
    "Intended Audience :: Developers",
    "License :: Other/Proprietary License",
    "Programming Language :: Python :: 3",
    "Topic :: Security",
]
dependencies = [
    {deps},
]

[project.urls]
Homepage = "https://github.com/vaquarkhan/MCP-Bastion"
Repository = "https://github.com/vaquarkhan/MCP-Bastion"
Documentation = "https://github.com/vaquarkhan/MCP-Bastion/tree/main/integrations/{p["name"]}"

[tool.hatch.build.targets.wheel]
packages = ["src/{p["mod"]}"]
""",
            encoding="utf-8",
        )
        (src / "__init__.py").write_text(
            f'''"""MCP-Bastion security integration for {p["title"]}."""
__version__ = "4.0.0"
{p["init_extra"]}__all__ = {exports}
''',
            encoding="utf-8",
        )
        (src / "middleware.py").write_text(p["middleware"], encoding="utf-8")
        (base / "README.md").write_text(
            f"""# {p["name"]}

Security helpers for **{p["title"]}** powered by [MCP-Bastion](https://pypi.org/project/mcp-bastion-python/).

{p["desc"]}

## Install

```bash
pip install {p["name"]}
```

## Usage

```python
{p["usage"]}
```

## Features

- In-process content filter + injection heuristics
- Rate limiting per caller
- Thin adapter only — does not change MCP-Bastion's zero-infra nature
- Pulls in `mcp-bastion-python` automatically

{LICENSE_BLURB}
""",
            encoding="utf-8",
        )
        print("created", p["name"])
    print("done", len(PACKAGES))


if __name__ == "__main__":
    main()
