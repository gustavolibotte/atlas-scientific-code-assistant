#!/usr/bin/env python3
"""Opt-in, non-authenticating live CERN OIDC native code-exchange diagnostic.

This script performs a real browser-mediated authorization, code exchange and
ID-token signature/claims check ONLY with --live. A successful result never
creates a user identity, authenticated ASCA session, or chATLAS permission.
No authorization URL, callback request, code, token, nonce or user identifier is
printed or persisted. Never use this script to authenticate API requests.
"""

from __future__ import annotations

import argparse
import webbrowser
from contextlib import suppress
from typing import Final

from asca.application.identity import AuthorizationStart
from asca.application.oidc_discovery import CERN_OIDC_ISSUER
from asca.domain.oidc_native_exchange import ExchangedUntrustedCernOidcToken
from asca.domain.oidc_native_lifecycle import NativeCallbackDenied
from asca.infrastructure.oidc_native_bootstrap import CernOidcNativeUntrustedBootstrap
from asca.infrastructure.oidc_native_lifecycle import CernNativeCallbackLifecycle
from asca.infrastructure.oidc_native_listener import CernNativeLoopbackListener

CLIENT_ID: Final = "asca-glibotte-dev"
CALLBACK_PATH: Final = "/oidc/callback"
EXPECTED_REGISTERED_URI: Final = "http://127.0.0.1/oidc/callback"


def _run_live(*, timeout_seconds: int) -> str:
    """Perform one bound native transaction and return a secret-free status only.

    All network-capable collaborators are existing ASCA default adapters.
    There are no parameters for injecting tokens, JWKS, transports or claims.
    """
    with CernNativeLoopbackListener(
        host="127.0.0.1",
        client_id=CLIENT_ID,
        callback_path=CALLBACK_PATH,
        scopes=("openid",),
        timeout_seconds=float(timeout_seconds),
        max_connections=8,
        max_request_bytes=8192,
    ) as listener:
        print("STEP=LOCAL_LISTENER_BOUND", flush=True)
        exchange = None
        try:
            if (
                listener.registration.client_id != CLIENT_ID
                or listener.registration.redirect_uri
                != f"http://127.0.0.1:{listener.binding.port}{CALLBACK_PATH}"
            ):
                return "LOCAL_BINDING_REJECTED"

            # Trusted public discovery and default HTTPS/JWKS adapters; no
            # caller-provided verifier or token transport is accepted here.
            exchange = CernOidcNativeUntrustedBootstrap(listener.registration).build()
            if exchange.callback_registration != listener.registration:
                return "LOCAL_BINDING_REJECTED"
            print("STEP=CERN_METADATA_CHECKED", flush=True)
            lifecycle = CernNativeCallbackLifecycle(exchange)
            start = lifecycle.begin()
            if type(start) is not AuthorizationStart or not start.browser_binding:
                return "START_REJECTED"

            print("BROWSER_OPEN=STARTING", flush=True)
            # The browser receives the authorization URL; stdout never does.
            # False means no browser was opened, not an authorization failure.
            if not webbrowser.open(start.authorization_url, new=1, autoraise=True):
                return "BROWSER_NOT_OPENED"
            print("BROWSER_OPEN=OK", flush=True)
            callback = listener.receive()
            print("STEP=CALLBACK_RECEIVED", flush=True)
            # This is the same private binding issued before opening the
            # browser. Never derive a binding from callback query parameters.
            result = lifecycle.complete(
                request=callback,
                protected_binding=start.browser_binding,
            )
            if type(result) is NativeCallbackDenied:
                return "PROVIDER_DENIED"
            if (
                type(result) is not ExchangedUntrustedCernOidcToken
                or result.issuer != CERN_OIDC_ISSUER
                or CLIENT_ID not in result.audiences
                or not result.subject
            ):
                return "CHECK_REJECTED"
            return "ID_TOKEN_CHECK_PASSED_NO_SESSION"
        finally:
            # The listener is closed by its context manager. Independently
            # revoke any remaining opaque authorization capabilities.
            if exchange is not None:
                with suppress(Exception):
                    exchange.cancel_pending()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--live",
        action="store_true",
        help="Perform ONE real CERN browser authorization and HTTPS code exchange",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=120,
        help="Callback listener timeout in seconds (30-120; default 120)",
    )
    args = parser.parse_args(argv)
    if not 30 <= args.timeout <= 120:
        parser.error("--timeout must be from 30 through 120 seconds")
    print(f"CLIENT_ID={CLIENT_ID}")
    print(f"REGISTERED_CALLBACK={EXPECTED_REGISTERED_URI}")
    print("MODE=EXPLICIT_OPT_IN")
    print("ASCA_SESSION=DISABLED")
    print("ROLE_AUTHORIZATION=NOT_CHECKED")
    print("CHATLAS_ACCESS=DISABLED")
    print("SECRETS_IN_DIAGNOSTICS=NONE")
    if not args.live:
        print("RESULT=OFFLINE_ONLY")
        return 0
    try:
        outcome = _run_live(timeout_seconds=args.timeout)
    except KeyboardInterrupt:
        print("RESULT=INTERRUPTED")
        return 130
    except Exception:
        # Provider, HTTP and callback failures may contain tokens in the
        # underlying exception text. Never print exception repr/traceback.
        print("RESULT=REJECTED_OR_TIMEOUT")
        return 1
    print(f"RESULT={outcome}")
    return 0 if outcome == "ID_TOKEN_CHECK_PASSED_NO_SESSION" else 1


if __name__ == "__main__":
    raise SystemExit(main())
