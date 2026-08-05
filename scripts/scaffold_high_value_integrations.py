"""Scaffold high-value Bastion integration packages (one-shot)."""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent / "integrations"
LICENSE = "See LICENSE and COMMERCIAL_LICENSE.md in the MCP-Bastion repository."
LICENSE_BLURB = """## License

Same terms as the [MCP-Bastion](https://github.com/vaquarkhan/MCP-Bastion) project: see [LICENSE](https://github.com/vaquarkhan/MCP-Bastion/blob/main/LICENSE). Non-commercial use is free with required **citation/attribution**; **copyright** terms apply. **Commercial** use as defined in the License may need a **separate agreement** ([COMMERCIAL_LICENSE.md](https://github.com/vaquarkhan/MCP-Bastion/blob/main/COMMERCIAL_LICENSE.md)).
"""

PACKAGES: list[dict] = [
    {
        "name": "mcp-bastion-litellm",
        "mod": "mcp_bastion_litellm",
        "cls": "SecureLiteLLM",
        "title": "LiteLLM",
        "desc": "MCP-Bastion security middleware for LiteLLM (100+ LLM providers via one OpenAI-compatible API).",
        "keywords": '["mcp", "bastion", "litellm", "security", "llm", "prompt-injection", "proxy"]',
        "deps": ['"mcp-bastion-python>=4.0.0,<5"', '"litellm>=1.40.0"'],
        "usage": (
            "from mcp_bastion_litellm import SecureLiteLLM\n\n"
            "client = SecureLiteLLM()\n"
            'print(client.chat("What is MCP?", model="gpt-4o-mini"))'
        ),
        "middleware": '''"""LiteLLM wrapper with MCP-Bastion security."""
from __future__ import annotations
from typing import Any

import litellm

from mcp_bastion.errors import RateLimitExceededError
from mcp_bastion.pillars.content_filter import ContentFilter
from mcp_bastion.pillars.rate_limit import TokenBucketRateLimiter


class SecureLiteLLM:
    """Drop-in LiteLLM completion wrapper with MCP-Bastion security.

    Usage::

        from mcp_bastion_litellm import SecureLiteLLM
        client = SecureLiteLLM()
        print(client.chat("What is MCP?", model="gpt-4o-mini"))
    """

    def __init__(self, max_requests: int = 60, window_seconds: int = 60) -> None:
        self._filter = ContentFilter()
        self._limiter = TokenBucketRateLimiter(
            max_iterations=max_requests, timeout_seconds=float(window_seconds)
        )
        self._session = "litellm-default"

    def chat(self, prompt: str, model: str = "gpt-4o-mini", **kwargs: Any) -> str:
        check = self._limiter.check_iteration(session_id=self._session)
        if not check.allowed:
            raise RateLimitExceededError(check.message or "Rate limit exceeded")
        self._filter.check(prompt)
        response = litellm.completion(
            model=model,
            messages=[{"role": "user", "content": prompt}],
            **kwargs,
        )
        self._limiter.consume_iteration(session_id=self._session)
        choice = response.choices[0]
        msg = getattr(choice, "message", None) or choice.get("message", {})
        content = (
            getattr(msg, "content", None)
            if not isinstance(msg, dict)
            else msg.get("content")
        )
        return content or ""
''',
    },
    {
        "name": "mcp-bastion-ollama",
        "mod": "mcp_bastion_ollama",
        "cls": "SecureOllama",
        "title": "Ollama",
        "desc": "MCP-Bastion security middleware for Ollama local models (OpenAI-compatible API).",
        "keywords": '["mcp", "bastion", "ollama", "local", "security", "llm", "prompt-injection"]',
        "deps": ['"mcp-bastion-python>=4.0.0,<5"', '"openai>=1.0.0"'],
        "usage": (
            "from mcp_bastion_ollama import SecureOllama\n\n"
            "client = SecureOllama()  # default http://localhost:11434/v1\n"
            'print(client.chat("What is MCP?", model="llama3.2"))'
        ),
        "middleware": '''"""Ollama client wrapper with MCP-Bastion security (OpenAI-compatible local API)."""
from __future__ import annotations
from typing import Any

from openai import OpenAI

from mcp_bastion.errors import RateLimitExceededError
from mcp_bastion.pillars.content_filter import ContentFilter
from mcp_bastion.pillars.rate_limit import TokenBucketRateLimiter


class SecureOllama:
    """Drop-in wrapper around Ollama with MCP-Bastion security.

    Usage::

        from mcp_bastion_ollama import SecureOllama
        client = SecureOllama()
        print(client.chat("What is MCP?", model="llama3.2"))
    """

    def __init__(
        self,
        base_url: str = "http://localhost:11434/v1",
        api_key: str = "ollama",
        max_requests: int = 60,
        window_seconds: int = 60,
    ) -> None:
        self._client = OpenAI(api_key=api_key, base_url=base_url)
        self._filter = ContentFilter()
        self._limiter = TokenBucketRateLimiter(
            max_iterations=max_requests, timeout_seconds=float(window_seconds)
        )
        self._session = "ollama-default"

    def chat(self, prompt: str, model: str = "llama3.2", **kwargs: Any) -> str:
        check = self._limiter.check_iteration(session_id=self._session)
        if not check.allowed:
            raise RateLimitExceededError(check.message or "Rate limit exceeded")
        self._filter.check(prompt)
        response = self._client.chat.completions.create(
            model=model, messages=[{"role": "user", "content": prompt}], **kwargs
        )
        self._limiter.consume_iteration(session_id=self._session)
        return response.choices[0].message.content or ""
''',
    },
    {
        "name": "mcp-bastion-openrouter",
        "mod": "mcp_bastion_openrouter",
        "cls": "SecureOpenRouter",
        "title": "OpenRouter",
        "desc": "MCP-Bastion security middleware for OpenRouter (multi-model gateway).",
        "keywords": '["mcp", "bastion", "openrouter", "security", "llm", "prompt-injection"]',
        "deps": ['"mcp-bastion-python>=4.0.0,<5"', '"openai>=1.0.0"'],
        "usage": (
            "from mcp_bastion_openrouter import SecureOpenRouter\n\n"
            "client = SecureOpenRouter()  # uses OPENROUTER_API_KEY\n"
            'print(client.chat("What is MCP?"))'
        ),
        "middleware": '''"""OpenRouter client wrapper with MCP-Bastion security."""
from __future__ import annotations
import os
from typing import Any

from openai import OpenAI

from mcp_bastion.errors import RateLimitExceededError
from mcp_bastion.pillars.content_filter import ContentFilter
from mcp_bastion.pillars.rate_limit import TokenBucketRateLimiter


class SecureOpenRouter:
    """Drop-in wrapper around OpenRouter with MCP-Bastion security.

    Usage::

        from mcp_bastion_openrouter import SecureOpenRouter
        client = SecureOpenRouter()
        print(client.chat("What is MCP?"))
    """

    def __init__(
        self,
        api_key: str | None = None,
        max_requests: int = 60,
        window_seconds: int = 60,
    ) -> None:
        key = api_key or os.environ.get("OPENROUTER_API_KEY")
        self._client = OpenAI(api_key=key, base_url="https://openrouter.ai/api/v1")
        self._filter = ContentFilter()
        self._limiter = TokenBucketRateLimiter(
            max_iterations=max_requests, timeout_seconds=float(window_seconds)
        )
        self._session = "openrouter-default"

    def chat(self, prompt: str, model: str = "openai/gpt-4o-mini", **kwargs: Any) -> str:
        check = self._limiter.check_iteration(session_id=self._session)
        if not check.allowed:
            raise RateLimitExceededError(check.message or "Rate limit exceeded")
        self._filter.check(prompt)
        response = self._client.chat.completions.create(
            model=model, messages=[{"role": "user", "content": prompt}], **kwargs
        )
        self._limiter.consume_iteration(session_id=self._session)
        return response.choices[0].message.content or ""
''',
    },
    {
        "name": "mcp-bastion-xai",
        "mod": "mcp_bastion_xai",
        "cls": "SecureXAI",
        "title": "xAI Grok",
        "desc": "MCP-Bastion security middleware for xAI Grok (OpenAI-compatible API).",
        "keywords": '["mcp", "bastion", "xai", "grok", "security", "llm", "prompt-injection"]',
        "deps": ['"mcp-bastion-python>=4.0.0,<5"', '"openai>=1.0.0"'],
        "usage": (
            "from mcp_bastion_xai import SecureXAI\n\n"
            "client = SecureXAI()  # uses XAI_API_KEY\n"
            'print(client.chat("What is MCP?"))'
        ),
        "middleware": '''"""xAI Grok client wrapper with MCP-Bastion security."""
from __future__ import annotations
import os
from typing import Any

from openai import OpenAI

from mcp_bastion.errors import RateLimitExceededError
from mcp_bastion.pillars.content_filter import ContentFilter
from mcp_bastion.pillars.rate_limit import TokenBucketRateLimiter


class SecureXAI:
    """Drop-in wrapper around xAI Grok with MCP-Bastion security.

    Usage::

        from mcp_bastion_xai import SecureXAI
        client = SecureXAI()
        print(client.chat("What is MCP?"))
    """

    def __init__(
        self,
        api_key: str | None = None,
        max_requests: int = 60,
        window_seconds: int = 60,
    ) -> None:
        key = api_key or os.environ.get("XAI_API_KEY")
        self._client = OpenAI(api_key=key, base_url="https://api.x.ai/v1")
        self._filter = ContentFilter()
        self._limiter = TokenBucketRateLimiter(
            max_iterations=max_requests, timeout_seconds=float(window_seconds)
        )
        self._session = "xai-default"

    def chat(self, prompt: str, model: str = "grok-2-latest", **kwargs: Any) -> str:
        check = self._limiter.check_iteration(session_id=self._session)
        if not check.allowed:
            raise RateLimitExceededError(check.message or "Rate limit exceeded")
        self._filter.check(prompt)
        response = self._client.chat.completions.create(
            model=model, messages=[{"role": "user", "content": prompt}], **kwargs
        )
        self._limiter.consume_iteration(session_id=self._session)
        return response.choices[0].message.content or ""
''',
    },
    {
        "name": "mcp-bastion-autogen",
        "mod": "mcp_bastion_autogen",
        "cls": "SecureAutoGen",
        "title": "Microsoft AutoGen",
        "desc": "MCP-Bastion security helpers for Microsoft AutoGen / Agent Framework tool messages.",
        "keywords": '["mcp", "bastion", "autogen", "microsoft", "security", "llm", "agents"]',
        "deps": ['"mcp-bastion-python>=4.0.0,<5"'],
        "usage": (
            "from mcp_bastion_autogen import SecureAutoGen\n\n"
            "guard = SecureAutoGen()\n"
            'guard.check_message("Summarize this ticket")  # raises on injection / rate limit'
        ),
        "middleware": '''"""AutoGen / agent-message guard with MCP-Bastion security."""
from __future__ import annotations
from typing import Any

from mcp_bastion.errors import PromptInjectionError, RateLimitExceededError
from mcp_bastion.pillars.content_filter import ContentFilter
from mcp_bastion.pillars.prompt_guard import PromptGuardEngine
from mcp_bastion.pillars.rate_limit import TokenBucketRateLimiter


class SecureAutoGen:
    """Scan agent / tool messages before they reach AutoGen handlers.

    Usage::

        from mcp_bastion_autogen import SecureAutoGen
        guard = SecureAutoGen()
        guard.check_message("user text or tool output")
    """

    def __init__(self, max_requests: int = 60, window_seconds: int = 60) -> None:
        self._filter = ContentFilter()
        self._prompt_guard = PromptGuardEngine(fail_open=True, heuristic_fallback=True)
        self._limiter = TokenBucketRateLimiter(
            max_iterations=max_requests, timeout_seconds=float(window_seconds)
        )
        self._session = "autogen-default"

    def check_message(self, text: str) -> None:
        """Raise if rate-limited, content-filtered, or injection heuristics match."""
        check = self._limiter.check_iteration(session_id=self._session)
        if not check.allowed:
            raise RateLimitExceededError(check.message or "Rate limit exceeded")
        self._filter.check(text)
        if self._prompt_guard.is_malicious(text):
            raise PromptInjectionError("Request blocked: suspected prompt injection")
        self._limiter.consume_iteration(session_id=self._session)

    def wrap_callable(self, fn: Any) -> Any:
        """Return a wrapper that scans the first string arg then calls ``fn``."""

        def _wrapped(*args: Any, **kwargs: Any) -> Any:
            for a in args:
                if isinstance(a, str) and a.strip():
                    self.check_message(a)
                    break
            return fn(*args, **kwargs)

        return _wrapped
''',
    },
]


def main() -> None:
    for p in PACKAGES:
        base = ROOT / p["name"]
        src = base / "src" / p["mod"]
        src.mkdir(parents=True, exist_ok=True)
        deps = ",\n    ".join(p["deps"])
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
from {p["mod"]}.middleware import {p["cls"]}
__all__ = ["{p["cls"]}"]
''',
            encoding="utf-8",
        )
        (src / "middleware.py").write_text(p["middleware"], encoding="utf-8")
        (base / "README.md").write_text(
            f"""# {p["name"]}

Security middleware for **{p["title"]}** powered by [MCP-Bastion](https://pypi.org/project/mcp-bastion-python/).

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

- Content filtering on prompts / messages
- Rate limiting per caller
- Prompt injection heuristics (via MCP-Bastion core)
- Pulls in `mcp-bastion-python` automatically

{LICENSE_BLURB}
""",
            encoding="utf-8",
        )
        print("created", p["name"])
    print("done", len(PACKAGES))


if __name__ == "__main__":
    main()
