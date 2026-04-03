"""Agent authentication — pluggable auth provider for agent identity.

Community defines the interface. Pro registers implementations:
- BearerTokenAuthProvider (self-hosted)
- OIDCAuthProvider (enterprise)
- MTLSAuthProvider (enterprise with PKI)
- SaaSAuthProvider (cloud multi-tenant)

The auth layer extracts AgentIdentity from request headers.
All downstream data access is scoped by namespace_id from the identity.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod

from lumen_argus.models import AgentIdentity

log = logging.getLogger("argus.auth")


class AuthenticationError(Exception):
    """Raised when authentication explicitly fails (bad token, expired, revoked).

    Distinct from returning None (which means "this provider doesn't handle
    this request, try next"). Raising AuthenticationError stops the chain
    and returns 401.
    """


class AgentAuthProvider(ABC):
    """Pluggable agent authentication provider.

    Pro registers an implementation via extensions.set_agent_auth_provider().
    The dashboard server calls authenticate() on agent-facing API requests.

    Contract:
    - Return AgentIdentity on successful authentication
    - Return None if this provider doesn't handle the request (fall through)
    - Raise AuthenticationError on explicit auth failure (invalid/expired token)
    """

    @abstractmethod
    async def authenticate(self, headers: dict[str, str]) -> AgentIdentity | None:
        """Extract and verify agent identity from request headers.

        Args:
            headers: HTTP request headers as a plain dict.

        Returns:
            AgentIdentity on success, None if not handled by this provider.

        Raises:
            AuthenticationError: On explicit auth failure (invalid token,
                expired, revoked). The caller returns 401.
        """

    async def on_token_issued(self, agent_id: str, token_hash: str) -> None:
        """Called after a new agent token is issued. Override for audit/metrics."""

    async def on_token_revoked(self, agent_id: str) -> None:
        """Called after an agent token is revoked. Override for cleanup."""
