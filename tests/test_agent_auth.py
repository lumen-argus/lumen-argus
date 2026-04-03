"""Tests for AgentIdentity, AgentAuthProvider, and auth extension hook."""

import asyncio
import unittest

from lumen_argus.auth import AgentAuthProvider, AuthenticationError
from lumen_argus.extensions import ExtensionRegistry
from lumen_argus.models import AgentIdentity


class TestAgentIdentity(unittest.TestCase):
    """Test AgentIdentity dataclass."""

    def test_frozen(self):
        identity = AgentIdentity(agent_id="agent_abc", namespace_id=1)
        with self.assertRaises(AttributeError):
            identity.agent_id = "changed"  # type: ignore[misc]

    def test_defaults(self):
        identity = AgentIdentity(agent_id="agent_abc", namespace_id=1)
        self.assertEqual(identity.agent_id, "agent_abc")
        self.assertEqual(identity.namespace_id, 1)
        self.assertEqual(identity.scopes, frozenset())
        self.assertEqual(identity.device_id, "")
        self.assertEqual(identity.machine_id, "")
        self.assertEqual(identity.namespace_slug, "")

    def test_with_scopes(self):
        identity = AgentIdentity(
            agent_id="agent_abc",
            namespace_id=1,
            scopes=frozenset({"stats:read", "findings:read"}),
        )
        self.assertIn("stats:read", identity.scopes)
        self.assertEqual(len(identity.scopes), 2)

    def test_equality(self):
        a = AgentIdentity(agent_id="agent_abc", namespace_id=1)
        b = AgentIdentity(agent_id="agent_abc", namespace_id=1)
        self.assertEqual(a, b)

    def test_inequality_different_namespace(self):
        a = AgentIdentity(agent_id="agent_abc", namespace_id=1)
        b = AgentIdentity(agent_id="agent_abc", namespace_id=2)
        self.assertNotEqual(a, b)

    def test_hashable(self):
        """AgentIdentity should be usable as a dict key / set member."""
        identity = AgentIdentity(agent_id="agent_abc", namespace_id=1)
        s = {identity}
        self.assertIn(identity, s)


class TestAgentAuthProviderABC(unittest.TestCase):
    """Test AgentAuthProvider abstract class."""

    def test_cannot_instantiate(self):
        with self.assertRaises(TypeError):
            AgentAuthProvider()  # type: ignore[abstract]

    def test_concrete_implementation(self):
        class MockProvider(AgentAuthProvider):
            async def authenticate(self, headers):
                if headers.get("authorization", "").startswith("Bearer la_agent_"):
                    return AgentIdentity(agent_id="agent_test", namespace_id=1)
                return None

        provider = MockProvider()
        self.assertIsInstance(provider, AgentAuthProvider)

    def test_authenticate_returns_identity(self):
        class MockProvider(AgentAuthProvider):
            async def authenticate(self, headers):
                return AgentIdentity(agent_id="agent_test", namespace_id=1)

        provider = MockProvider()
        result = asyncio.run(provider.authenticate({"authorization": "Bearer la_agent_xxx"}))
        self.assertIsInstance(result, AgentIdentity)
        self.assertEqual(result.agent_id, "agent_test")

    def test_authenticate_returns_none(self):
        class MockProvider(AgentAuthProvider):
            async def authenticate(self, headers):
                return None

        provider = MockProvider()
        result = asyncio.run(provider.authenticate({}))
        self.assertIsNone(result)

    def test_authenticate_raises_auth_error(self):
        class MockProvider(AgentAuthProvider):
            async def authenticate(self, headers):
                raise AuthenticationError("token expired")

        provider = MockProvider()
        with self.assertRaises(AuthenticationError):
            asyncio.run(provider.authenticate({"authorization": "Bearer la_agent_expired"}))

    def test_optional_hooks_are_noop(self):
        """on_token_issued and on_token_revoked have default no-op implementations."""

        class MockProvider(AgentAuthProvider):
            async def authenticate(self, headers):
                return None

        provider = MockProvider()
        # These should not raise
        asyncio.run(provider.on_token_issued("agent_x", "hash_y"))
        asyncio.run(provider.on_token_revoked("agent_x"))


class TestAgentAuthExtensionHook(unittest.TestCase):
    """Test the extension registry hook for agent auth."""

    def test_default_is_none(self):
        registry = ExtensionRegistry()
        self.assertIsNone(registry.get_agent_auth_provider())

    def test_set_and_get(self):
        class MockProvider(AgentAuthProvider):
            async def authenticate(self, headers):
                return None

        registry = ExtensionRegistry()
        provider = MockProvider()
        registry.set_agent_auth_provider(provider)
        self.assertIs(registry.get_agent_auth_provider(), provider)

    def test_last_wins(self):
        class ProviderA(AgentAuthProvider):
            async def authenticate(self, headers):
                return None

        class ProviderB(AgentAuthProvider):
            async def authenticate(self, headers):
                return None

        registry = ExtensionRegistry()
        a = ProviderA()
        b = ProviderB()
        registry.set_agent_auth_provider(a)
        registry.set_agent_auth_provider(b)
        self.assertIs(registry.get_agent_auth_provider(), b)
