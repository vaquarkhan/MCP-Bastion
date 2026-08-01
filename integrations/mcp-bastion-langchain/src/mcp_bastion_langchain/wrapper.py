"""Wrap any LangChain tool with MCP-Bastion security."""

from __future__ import annotations

from typing import Any, Callable

from mcp_bastion.pillars.content_filter import ContentFilter


_filter = ContentFilter()


def secure_tool(func: Callable[..., Any]) -> Callable[..., Any]:
    """Decorator that scans tool input through MCP-Bastion before execution.

    Usage::

        from mcp_bastion_langchain import secure_tool

        @secure_tool
        def my_tool(query: str) -> str:
            return do_something(query)
    """

    def wrapper(*args: Any, **kwargs: Any) -> Any:
        for arg in args:
            if isinstance(arg, str):
                _filter.check(arg)
        for val in kwargs.values():
            if isinstance(val, str):
                _filter.check(val)
        return func(*args, **kwargs)

    wrapper.__name__ = getattr(func, "__name__", "secure_tool")
    wrapper.__doc__ = func.__doc__
    return wrapper
