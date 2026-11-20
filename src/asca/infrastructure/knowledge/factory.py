"""Build the knowledge federation from validated settings.

Enabled providers are instantiated; disabled ones are passed to the federation as
descriptors, so they are still reported. Constructing a provider never touches the
network or the filesystem: every outbound call happens inside an operation, and the
federation only calls network providers when ``live`` is true.
"""

import os
from collections.abc import Mapping

from asca.application.knowledge.federation import FederationPolicy, FederationService
from asca.application.knowledge.models import ProviderDescriptor
from asca.application.ports import Clock, KnowledgeProvider
from asca.infrastructure.knowledge.arxiv import ArxivProvider
from asca.infrastructure.knowledge.config import effective_precedence
from asca.infrastructure.knowledge.hepdata import HepdataProvider
from asca.infrastructure.knowledge.http import ClientFactory, default_client_factory
from asca.infrastructure.knowledge.inspire import InspireProvider
from asca.infrastructure.knowledge.local import LocalLibraryProvider
from asca.infrastructure.knowledge.mcp_client import McpConnector, McpKnowledgeProvider
from asca.infrastructure.knowledge.settings import KnowledgeSettings


def build_providers(
    settings: KnowledgeSettings,
    *,
    clock: Clock,
    client_factory: ClientFactory = default_client_factory,
    mcp_connectors: Mapping[str, McpConnector] | None = None,
    environ: Mapping[str, str] = os.environ,
) -> tuple[tuple[KnowledgeProvider, ...], tuple[ProviderDescriptor, ...]]:
    """Return ``(enabled providers, disabled descriptors)`` in configuration order.

    ``mcp_connectors`` maps a provider id (``mcp:<server_id>``) to an injected connector;
    it is a test seam for in-process servers and is never read from configuration.
    """
    network = settings.network
    connectors = mcp_connectors or {}
    entries: list[tuple[bool, KnowledgeProvider]] = [
        (
            settings.inspire.enabled,
            InspireProvider(
                settings.inspire, network=network, clock=clock, client_factory=client_factory
            ),
        ),
        (
            settings.arxiv.enabled,
            ArxivProvider(
                settings.arxiv, network=network, clock=clock, client_factory=client_factory
            ),
        ),
        (
            settings.hepdata.enabled,
            HepdataProvider(
                settings.hepdata, network=network, clock=clock, client_factory=client_factory
            ),
        ),
    ]
    if settings.local is not None:
        entries.append((settings.local.enabled, LocalLibraryProvider(settings.local, clock=clock)))
    for server in settings.mcp:
        provider = McpKnowledgeProvider(
            server,
            network=network,
            clock=clock,
            connector=connectors.get(server.provider_id),
            environ=environ,
            client_factory=client_factory,
        )
        entries.append((server.enabled, provider))
    enabled = tuple(provider for active, provider in entries if active)
    disabled = tuple(provider.descriptor for active, provider in entries if not active)
    return enabled, disabled


def build_federation(
    settings: KnowledgeSettings,
    *,
    live: bool,
    clock: Clock,
    client_factory: ClientFactory = default_client_factory,
    mcp_connectors: Mapping[str, McpConnector] | None = None,
    environ: Mapping[str, str] = os.environ,
) -> FederationService:
    """The federation over every configured provider.

    Precedence: ``settings.precedence`` first, then inspire, arxiv, hepdata, local, then
    MCP servers in configuration order. Network providers run only when ``live`` is true.
    """
    enabled, disabled = build_providers(
        settings,
        clock=clock,
        client_factory=client_factory,
        mcp_connectors=mcp_connectors,
        environ=environ,
    )
    policy = FederationPolicy(live=live, precedence=effective_precedence(settings))
    return FederationService(enabled, policy, disabled=disabled)
