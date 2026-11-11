"""Unmounted native-loopback callback dispatch with single-use denial handling.

The HTTP envelope is still forgeable. The future OS listener must populate
socket metadata, keep the browser binding in protected local host state, limit
requests and close on completion. This class neither installs a listener nor
creates an authenticated identity, and it may use lower-level test adapters.
"""

from __future__ import annotations

import re

from asca.application.identity import AuthorizationStart
from asca.domain.oidc_native_callback import NativeLoopbackHttpRequest, OidcNativeCallbackError
from asca.domain.oidc_native_exchange import (
    ExchangedUntrustedCernOidcToken,
    OidcNativeExchangeError,
)
from asca.domain.oidc_native_lifecycle import NativeCallbackDenied, OidcNativeLifecycleError
from asca.domain.oidc_registration import OidcClientMode, OidcClientRegistration
from asca.domain.oidc_role_claims import UntrustedCernRoleObservation
from asca.infrastructure.oidc_native_callback import CernNativeLoopbackCallbackPolicy
from asca.infrastructure.oidc_native_exchange import CernOidcNativeCodeExchange

_BINDING = re.compile(r"[A-Za-z0-9_-]{43,128}\Z", re.ASCII)


class CernNativeCallbackLifecycle:
    """Dispatch one parsed callback to the SAME native attempt store as begin().

    The only callback-specific arguments are the raw untrusted HTTP envelope
    and the protected host binding. No caller-supplied code verifier, token,
    metadata, identity, HTTP transport or attempt store is accepted here.
    Atomic single-use protection is provided by the lower-level store within
    one process, not by this dispatcher or the HTTP parser.
    """

    def __init__(self, exchange: CernOidcNativeCodeExchange) -> None:
        if type(exchange) is not CernOidcNativeCodeExchange:
            raise OidcNativeLifecycleError("Invalid native callback lifecycle configuration")
        try:
            registration = exchange.callback_registration
            self._policy = CernNativeLoopbackCallbackPolicy(registration)
            self._registration_snapshot = (
                registration.client_id,
                registration.redirect_uri,
                registration.mode,
                registration.scopes,
            )
        except (OidcNativeCallbackError, TypeError, ValueError, AttributeError):
            raise OidcNativeLifecycleError(
                "Invalid native callback lifecycle configuration"
            ) from None
        self._exchange = exchange

    def begin(self) -> AuthorizationStart:
        """Create a pending attempt in this dispatcher's underlying exchange."""
        try:
            return self._exchange.begin()
        except (OidcNativeExchangeError, ValueError, TypeError):
            raise OidcNativeLifecycleError("Native authorization start was rejected") from None

    def complete(
        self,
        *,
        request: NativeLoopbackHttpRequest,
        protected_binding: str,
    ) -> ExchangedUntrustedCernOidcToken | NativeCallbackDenied:
        """Parse, correlate and consume a callback, including OAuth denials.

        protected_binding MUST come from the initiating native host's private
        state; it MUST NOT come from the request target, header, cookie or body.
        This method cannot attest the socket data or close an actual listener.
        """
        if not isinstance(protected_binding, str) or _BINDING.fullmatch(protected_binding) is None:
            raise OidcNativeLifecycleError("Native callback lifecycle was rejected")
        try:
            registration = self._exchange.callback_registration
            if (
                type(registration) is not OidcClientRegistration
                or type(registration.mode) is not OidcClientMode
                or (
                    registration.client_id,
                    registration.redirect_uri,
                    registration.mode,
                    registration.scopes,
                )
                != self._registration_snapshot
            ):
                raise OidcNativeLifecycleError("Native callback lifecycle was rejected")
            parsed = self._policy.parse(request)
            if parsed.error is not None:
                self._exchange.reject_callback(
                    browser_binding=protected_binding,
                    state=parsed.state,
                    error=parsed.error,
                    response_issuer=parsed.response_issuer,
                )
                return NativeCallbackDenied()
            if parsed.code is None:
                raise OidcNativeLifecycleError("Native callback lifecycle was rejected")
            return self._exchange.exchange_callback(
                browser_binding=protected_binding,
                state=parsed.state,
                code=parsed.code,
                response_issuer=parsed.response_issuer,
            )
        except (
            OidcNativeCallbackError,
            OidcNativeExchangeError,
            OidcNativeLifecycleError,
            ValueError,
            TypeError,
            AttributeError,
        ):
            raise OidcNativeLifecycleError("Native callback lifecycle was rejected") from None

    def complete_role_observation(
        self,
        *,
        request: NativeLoopbackHttpRequest,
        protected_binding: str,
    ) -> UntrustedCernRoleObservation | NativeCallbackDenied:
        """Inspect one role after the same strict, single-use native callback.

        The binding MUST remain private to the host and cannot come from
        callback parameters. Denials consume their associated pending attempt.
        This separate path does not change the existing complete() behavior.
        """
        if not isinstance(protected_binding, str) or _BINDING.fullmatch(protected_binding) is None:
            raise OidcNativeLifecycleError("Native role callback lifecycle was rejected")
        try:
            registration = self._exchange.callback_registration
            if (
                type(registration) is not OidcClientRegistration
                or type(registration.mode) is not OidcClientMode
                or (
                    registration.client_id,
                    registration.redirect_uri,
                    registration.mode,
                    registration.scopes,
                )
                != self._registration_snapshot
            ):
                raise OidcNativeLifecycleError("Native role callback lifecycle was rejected")
            parsed = self._policy.parse(request)
            if parsed.error is not None:
                self._exchange.reject_callback(
                    browser_binding=protected_binding,
                    state=parsed.state,
                    error=parsed.error,
                    response_issuer=parsed.response_issuer,
                )
                return NativeCallbackDenied()
            if parsed.code is None:
                raise OidcNativeLifecycleError("Native role callback lifecycle was rejected")
            return self._exchange.exchange_callback_observe_role(
                browser_binding=protected_binding,
                state=parsed.state,
                code=parsed.code,
                response_issuer=parsed.response_issuer,
            )
        except (
            OidcNativeCallbackError,
            OidcNativeExchangeError,
            OidcNativeLifecycleError,
            ValueError,
            TypeError,
            AttributeError,
        ):
            raise OidcNativeLifecycleError("Native role callback lifecycle was rejected") from None
