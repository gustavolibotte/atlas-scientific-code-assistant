"""Isolated one-shot native OIDC host orchestration; never a login route.

Create an ephemeral loopback listener BEFORE configuring the native exchange,
keep the browser binding strictly inside this host, and complete only from an
OS-received HTTP envelope. Both success and denial remain non-authenticating.

This deliberately injectable *offline prototype* requires explicit transport,
verifier, and provider metadata. The caller is responsible for ensuring its
adapters are synthetic; this is not a production-default trust boundary.
Nothing is mounted in FastAPI and no browser or CERN endpoint is opened here.
"""

from __future__ import annotations

import re
import threading
import time
from collections.abc import Callable
from contextlib import suppress
from typing import Self
from urllib.parse import parse_qs, urlsplit

from asca.application.identity import AuthorizationStart
from asca.application.oidc_discovery import CERN_OIDC_ISSUER
from asca.domain.oidc_discovery import OidcProviderMetadata
from asca.domain.oidc_native_exchange import (
    ExchangedUntrustedCernOidcToken,
    OidcNativeExchangeError,
)
from asca.domain.oidc_native_host import NativeOidcHostStart, OidcNativeHostError
from asca.domain.oidc_native_lifecycle import NativeCallbackDenied
from asca.domain.oidc_native_listener import NativeLoopbackListenerBinding
from asca.domain.oidc_registration import OidcClientRegistration
from asca.infrastructure.oidc_native_exchange import CernOidcNativeCodeExchange
from asca.infrastructure.oidc_native_lifecycle import CernNativeCallbackLifecycle
from asca.infrastructure.oidc_native_listener import CernNativeLoopbackListener
from asca.infrastructure.oidc_token_http import HttpsOidcTokenTransport
from asca.infrastructure.oidc_verification import CernOidcVerificationPipeline

_STATE = re.compile(r"[A-Za-z0-9_-]{43,128}\Z", re.ASCII)
_BINDING = re.compile(r"[A-Za-z0-9_-]{43,128}\Z", re.ASCII)
_CHALLENGE = re.compile(r"[A-Za-z0-9_-]{43}\Z", re.ASCII)


class CernNativeOidcHostTransaction:
    """Own exactly one loopback listener and one private authorization attempt.

    begin() exposes only the public authorization URL; the initiating caller
    must not reconstruct or transmit the private binding. complete() accepts
    NO request, state, verifier, binding, or token arguments: it receives from
    the actual owned socket, validates correlation, and consumes once.

    close() cancels a pending attempt using the existing atomic denial path.
    All methods are non-authenticating. An explicit test transport/verifier is
    mandatory to avoid accidentally selecting the real HTTPS defaults here.
    """

    def __init__(
        self,
        *,
        host: str,
        client_id: str,
        metadata: OidcProviderMetadata,
        transport: HttpsOidcTokenTransport,
        verifier: CernOidcVerificationPipeline,
        callback_path: str = "/oidc/callback",
        scopes: tuple[str, ...] = ("openid",),
        timeout_seconds: float = 30.0,
        per_connection_seconds: float = 2.0,
        max_connections: int = 8,
        max_request_bytes: int = 8192,
        clock: Callable[[], float] = time.time,
        ttl_seconds: int = 300,
    ) -> None:
        # Explicit adapters, no default CERN token or signing-key network path.
        # Injection is for isolated tests, NOT production registration attestation.
        if (
            type(metadata) is not OidcProviderMetadata
            or not isinstance(transport, HttpsOidcTokenTransport)
            or not isinstance(verifier, CernOidcVerificationPipeline)
            or type(transport) is HttpsOidcTokenTransport
            or type(verifier) is CernOidcVerificationPipeline
        ):
            raise OidcNativeHostError("Invalid native host configuration")
        listener: CernNativeLoopbackListener | None = None
        try:
            listener = CernNativeLoopbackListener(
                host=host,
                client_id=client_id,
                callback_path=callback_path,
                scopes=scopes,
                timeout_seconds=timeout_seconds,
                per_connection_seconds=per_connection_seconds,
                max_connections=max_connections,
                max_request_bytes=max_request_bytes,
            )
            exchange = CernOidcNativeCodeExchange(
                listener.registration,
                metadata,
                transport=transport,
                verifier=verifier,
                clock=clock,
                ttl_seconds=ttl_seconds,
                max_pending=1,
            )
            lifecycle = CernNativeCallbackLifecycle(exchange)
            if exchange.callback_registration != listener.registration:
                raise OidcNativeHostError("Invalid native host configuration")
        except Exception:
            if listener is not None:
                with suppress(OSError):
                    listener.close()
            raise OidcNativeHostError("Invalid native host configuration") from None

        self._listener = listener
        self._exchange = exchange
        self._lifecycle = lifecycle
        self._registration_snapshot = listener.registration
        self._lock = threading.RLock()
        self._started = False
        self._receiving = False
        self._closed = False
        self._browser_binding: str | None = None
        self._state: str | None = None

    @property
    def binding(self) -> NativeLoopbackListenerBinding:
        """OS-selected endpoint descriptor, never an authenticated identity."""
        return self._listener.binding

    @property
    def closed(self) -> bool:
        with self._lock:
            return self._closed

    def _check_registration(self) -> None:
        current = self._exchange.callback_registration
        if (
            type(current) is not OidcClientRegistration
            or current != self._registration_snapshot
            or self._listener.registration != self._registration_snapshot
            or self._listener.binding.redirect_uri != self._registration_snapshot.redirect_uri
            or self._listener.closed
        ):
            raise OidcNativeHostError("Native host transaction was rejected")

    def begin(self) -> NativeOidcHostStart:
        """Start once and retain the binding; return only a browser-safe URL."""
        try:
            with self._lock:
                if self._closed or self._started:
                    raise OidcNativeHostError("Native host transaction was rejected")
                self._check_registration()
                attempt = self._lifecycle.begin()
                if type(attempt) is not AuthorizationStart:
                    raise OidcNativeHostError("Native host transaction was rejected")
                # Store the private binding *before* validating the returned URL.
                # A failed validation may leave an attempt in the memory store,
                # but does not make the binding available to any caller.
                binding = attempt.browser_binding
                if type(binding) is not str or _BINDING.fullmatch(binding) is None:
                    raise OidcNativeHostError("Native host transaction was rejected")
                self._browser_binding = binding
                url = attempt.authorization_url
                if type(url) is not str:
                    raise OidcNativeHostError("Native host transaction was rejected")
                if len(url) > 8192 or any(ord(ch) <= 32 or ord(ch) == 127 for ch in url):
                    raise OidcNativeHostError("Native host transaction was rejected")
                parsed = urlsplit(url)
                query = parse_qs(
                    parsed.query, keep_blank_values=True, strict_parsing=True, max_num_fields=16
                )
                expected = urlsplit(CERN_OIDC_ISSUER + "/protocol/openid-connect/auth")
                required = {
                    "state",
                    "nonce",
                    "response_type",
                    "client_id",
                    "redirect_uri",
                    "scope",
                    "code_challenge",
                    "code_challenge_method",
                }
                state = query.get("state", [])
                if len(state) == 1 and _STATE.fullmatch(state[0]) is not None:
                    # Retain the original state for atomic cancellation even if
                    # a later authorization URL policy check rejects the URL.
                    self._state = state[0]
                if (
                    parsed.scheme != expected.scheme
                    or parsed.netloc != expected.netloc
                    or parsed.path != expected.path
                    or parsed.fragment
                    or set(query) != required
                    or len(state) != 1
                    or _STATE.fullmatch(state[0]) is None
                    or query.get("client_id") != [self._registration_snapshot.client_id]
                    or query.get("redirect_uri") != [self._registration_snapshot.redirect_uri]
                    or query.get("response_type") != ["code"]
                    or query.get("scope") != [" ".join(self._registration_snapshot.scopes)]
                    or query.get("code_challenge_method") != ["S256"]
                    or len(query.get("code_challenge", [])) != 1
                    or _CHALLENGE.fullmatch(query["code_challenge"][0]) is None
                    or len(query.get("nonce", [])) != 1
                    or _STATE.fullmatch(query["nonce"][0]) is None
                    or "code_verifier" in query
                    or "browser_binding" in query
                ):
                    raise OidcNativeHostError("Native host transaction was rejected")
                self._state = state[0]
                self._check_registration()
                self._started = True
                return NativeOidcHostStart(
                    authorization_url=url,
                    redirect_uri=self._registration_snapshot.redirect_uri,
                )
        except Exception:
            self.close()
            raise OidcNativeHostError("Native host transaction was rejected") from None

    def complete(self) -> ExchangedUntrustedCernOidcToken | NativeCallbackDenied:
        """Receive one OS callback and correlate against private host state.

        A local process can deny service by supplying the first valid HTTP
        envelope, but cannot supply the protected binding to this method.
        """
        try:
            with self._lock:
                if self._closed or not self._started or self._receiving:
                    raise OidcNativeHostError("Native host transaction was rejected")
                self._check_registration()
                self._receiving = True
            request = self._listener.receive()
            with self._lock:
                # Hold the lock through token processing so that close() cannot
                # return successfully while a token exchange remains in flight.
                if self._closed or not self._started:
                    raise OidcNativeHostError("Native host transaction was rejected")
                if self._browser_binding is None or self._state is None:
                    raise OidcNativeHostError("Native host transaction was rejected")
                if self._exchange.callback_registration != self._registration_snapshot:
                    raise OidcNativeHostError("Native host transaction was rejected")
                return self._lifecycle.complete(
                    request=request,
                    protected_binding=self._browser_binding,
                )
        except Exception:
            raise OidcNativeHostError("Native host transaction was rejected") from None
        finally:
            self.close()

    def close(self) -> None:
        """Close socket, clear host secrets and revoke any still-pending attempt.

        Revocation competes atomically with success/denial consumption; an
        already consumed attempt cannot be restored by cancellation. The
        listener can be interrupted from another thread during receive().
        """
        with self._lock:
            self._browser_binding = None
            self._state = None
            self._closed = True
        try:
            # Best-effort socket shutdown must not prevent attempt revocation.
            with suppress(OSError):
                self._listener.close()
        finally:
            # Independent cancellation capability was recorded inside exchange
            # before the authorization URL was inspected. Neither state nor
            # browser_binding from an untrusted URL is required for revocation.
            with suppress(OidcNativeExchangeError, ValueError, TypeError):
                self._exchange.cancel_pending()

    def __enter__(self) -> Self:
        if self.closed:
            raise OidcNativeHostError("Native host transaction was rejected")
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()
