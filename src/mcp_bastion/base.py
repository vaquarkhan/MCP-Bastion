"""
Base middleware abstractions for MCP-Bastion.

Middleware base class, MiddlewareContext dataclass, compose_middleware.
"""

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any, Generic, TypeVar

T = TypeVar("T")


@dataclass
class MiddlewareContext(Generic[T]):
    """Context for middleware chain: message, metadata, request_id, session_id."""

    message: T
    metadata: dict[str, Any] = field(default_factory=dict)
    request_id: str | None = None
    session_id: str | None = None

    def copy(self, **kwargs: Any) -> "MiddlewareContext[T]":
        """Create a copy with updated fields."""
        data = {
            "message": self.message,
            "metadata": dict(self.metadata),
            "request_id": self.request_id,
            "session_id": self.session_id,
        }
        data.update(kwargs)
        return MiddlewareContext(**data)


CallNext = Callable[[MiddlewareContext[T]], Awaitable[Any]]


class Middleware(Generic[T]):
    """Base class for MCP middleware. Override on_message, on_call_tool, on_read_resource."""

    async def __call__(
        self,
        context: MiddlewareContext[T],
        call_next: CallNext[T],
    ) -> Any:
        return await self.on_message(context, call_next)

    async def on_message(
        self,
        context: MiddlewareContext[T],
        call_next: CallNext[T],
    ) -> Any:
        """Handle any message. Override for generic processing."""
        return await call_next(context)

    async def on_call_tool(
        self,
        context: MiddlewareContext[T],
        call_next: CallNext[T],
    ) -> Any:
        """Handle tool calls. Override for tool-specific processing."""
        return await self.on_message(context, call_next)

    async def on_read_resource(
        self,
        context: MiddlewareContext[T],
        call_next: CallNext[T],
    ) -> Any:
        """Handle resource reads. Override for resource-specific processing."""
        return await self.on_message(context, call_next)


def compose_middleware(
    *middleware: Middleware[Any],
) -> Callable[[MiddlewareContext[Any], CallNext[Any]], Awaitable[Any]]:
    """Compose middleware. First in list = outermost."""
    if not middleware:
        async def passthrough(ctx: MiddlewareContext[Any], call_next: CallNext[Any]) -> Any:
            return await call_next(ctx)
        return passthrough

    async def composed(
        context: MiddlewareContext[Any],
        call_next: CallNext[Any],
    ) -> Any:
        index = 0

        async def next_handler(ctx: MiddlewareContext[Any]) -> Any:
            nonlocal index
            if index >= len(middleware):
                return await call_next(ctx)
            mw = middleware[index]
            index += 1
            return await mw(ctx, next_handler)

        return await next_handler(context)

    return composed
