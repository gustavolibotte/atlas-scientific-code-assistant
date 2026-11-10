#!/usr/bin/env python3
"""Check public CERN OIDC discovery metadata; never attempt authentication.

By default no network request is made. Use --live explicitly to perform one
public metadata GET from the known CERN SSO issuer. No credentials are needed.
"""

from __future__ import annotations

import argparse

from asca.application.oidc_discovery import OidcDiscoveryPolicy, OidcDiscoveryService
from asca.domain.oidc_discovery import OidcDiscoveryError
from asca.infrastructure.oidc_http import HttpsOidcMetadataFetcher


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--live", action="store_true", help="Fetch public metadata via HTTPS")
    args = parser.parse_args(argv)
    policy = OidcDiscoveryPolicy()
    print("Provider: CERN SSO")
    print(f"Expected issuer: {policy.expected_issuer}")
    print(f"Discovery URL: {policy.discovery_url}")
    if not args.live:
        print("Result: OFFLINE_ONLY (no network request; live provider not verified)")
        return 0
    try:
        provider = OidcDiscoveryService(policy, HttpsOidcMetadataFetcher(policy)).discover()
    except OidcDiscoveryError as error:
        print(f"Result: NOT_VERIFIED ({error})")
        return 1
    print("Result: VALIDATED_PUBLIC_METADATA")
    print("Authorization Code: supported")
    print("PKCE S256: supported")
    print("Approved ID-token algorithms: " + ", ".join(provider.approved_id_token_algorithms))
    print("Authentication enabled: NO (no client registration, token exchange, or login)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
