#!/usr/bin/env python3
"""Opt-in CERN native OIDC role observation; no login, sessions or permissions.

A live invocation performs one real browser authorization and token verification
against pinned CERN endpoints. It displays only fixed status labels. Neither
an observed role nor this diagnostic is an ASCA authorization capability.
"""

from __future__ import annotations

import argparse
import webbrowser
from contextlib import suppress
from typing import Final

from asca.application.identity import AuthorizationStart
from asca.domain.oidc_native_lifecycle import NativeCallbackDenied
from asca.domain.oidc_role_claims import UntrustedCernRoleObservation
from asca.infrastructure.oidc_native_bootstrap import CernOidcNativeUntrustedBootstrap
from asca.infrastructure.oidc_native_lifecycle import CernNativeCallbackLifecycle
from asca.infrastructure.oidc_native_listener import CernNativeLoopbackListener

CLIENT_ID: Final = "asca-glibotte-dev"
ROLE: Final = "asca-developer"
CALLBACK_PATH: Final = "/oidc/callback"
EXPECTED_REGISTERED_URI: Final = "http://127.0.0.1/oidc/callback"
_STATUSES: Final = frozenset(
    {"claimed", "absent", "mfa_required", "loa_required", "mfa_and_loa_required"}
)


def _run_live(*, timeout_seconds: int) -> tuple[str, str | None]:
    """Return a fixed result and optional role-status label; never token data."""
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
                return "LOCAL_BINDING_REJECTED", None
            exchange = CernOidcNativeUntrustedBootstrap(listener.registration).build()
            if exchange.callback_registration != listener.registration:
                return "LOCAL_BINDING_REJECTED", None
            print("STEP=CERN_METADATA_CHECKED", flush=True)
            lifecycle = CernNativeCallbackLifecycle(exchange)
            start = lifecycle.begin()
            if type(start) is not AuthorizationStart or not start.browser_binding:
                return "START_REJECTED", None
            print("BROWSER_OPEN=STARTING", flush=True)
            if not webbrowser.open(start.authorization_url, new=1, autoraise=True):
                return "BROWSER_NOT_OPENED", None
            print("BROWSER_OPEN=OK", flush=True)
            callback = listener.receive()
            print("STEP=CALLBACK_RECEIVED", flush=True)
            result = lifecycle.complete_role_observation(
                request=callback,
                protected_binding=start.browser_binding,
            )
            if type(result) is NativeCallbackDenied:
                return "PROVIDER_DENIED", None
            if (
                type(result) is not UntrustedCernRoleObservation
                or result.status not in _STATUSES
                or result.authorization != "not_implemented"
                or result.login != "not_implemented"
            ):
                return "ROLE_CHECK_REJECTED", None
            return "ROLE_OBSERVATION_COMPLETE_NO_SESSION", result.status
        finally:
            if exchange is not None:
                with suppress(Exception):
                    exchange.cancel_pending()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--live", action="store_true", help="Perform one real CERN role-claim observation"
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
    print("ROLE_AUTHORIZATION=DISABLED")
    print("CHATLAS_ACCESS=DISABLED")
    print("SECRETS_IN_DIAGNOSTICS=NONE")
    if not args.live:
        print("RESULT=OFFLINE_ONLY")
        return 0
    try:
        outcome, role_status = _run_live(timeout_seconds=args.timeout)
    except KeyboardInterrupt:
        print("RESULT=INTERRUPTED")
        return 130
    except Exception:
        # Never display an exception: its message could include credential data.
        print("RESULT=REJECTED_OR_TIMEOUT")
        return 1
    if outcome == "ROLE_OBSERVATION_COMPLETE_NO_SESSION" and role_status in _STATUSES:
        print(f"ROLE_STATUS={role_status.upper()}")
        print(f"RESULT={outcome}")
        return 0
    print(f"RESULT={outcome}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
