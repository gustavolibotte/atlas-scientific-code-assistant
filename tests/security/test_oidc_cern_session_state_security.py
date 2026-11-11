"""Adversarial validation of the optional, non-authoritative Keycloak session_state."""

from __future__ import annotations

import pytest

from asca.domain.oidc_native_callback import NativeLoopbackHttpRequest, OidcNativeCallbackError
from asca.domain.oidc_registration import OidcClientMode, OidcClientRegistration
from asca.infrastructure.oidc_native_callback import CernNativeLoopbackCallbackPolicy

STATE = "S" * 43
CODE = "synthetic-code"


def _check(query: str) -> None:
    policy = CernNativeLoopbackCallbackPolicy(
        OidcClientRegistration(
            client_id="synthetic-client",
            redirect_uri="http://127.0.0.1:59044/oidc/callback",
            mode=OidcClientMode.NATIVE_LOOPBACK,
        )
    )
    with pytest.raises(OidcNativeCallbackError):
        policy.parse(
            NativeLoopbackHttpRequest(
                method="GET",
                request_target=f"/oidc/callback?{query}",
                http_version="HTTP/1.1",
                headers=(("Host", "127.0.0.1:59044"),),
                peer_ip="127.0.0.1",
                local_ip="127.0.0.1",
                local_port=59044,
            )
        )


@pytest.mark.parametrize(
    "value",
    [
        "",
        "a" * 129,
        "%00",
        "%0A",
        "%20",
        "bad%2Fvalue",
        "bad%3Dvalue",
        "bad%3Fvalue",
        "bad%26value",
        "bad%5Cvalue",
        "%FF",
        "%ZZ",
        "bad+value",
        "bad%40value",
        "bad%3Avalue",
    ],
)
def test_reject_unsupported_or_malformed_session_state(value: str) -> None:
    _check(f"state={STATE}&code={CODE}&session_state={value}")


@pytest.mark.parametrize(
    "query",
    [
        f"state={STATE}&code={CODE}&session_state=first&session_state=second",
        f"state={STATE}&code={CODE}&session_state=first&session_state=first",
        f"state={STATE}&code={CODE}&session_state=okay&unknown=value",
        f"state={STATE}&code={CODE}&session_state=okay&extra=1&extra2=2",
        f"state={STATE}&code={CODE}&session_state=okay&error=access_denied",
        f"state={STATE}&code={CODE}&session_state=okay&iss=evil",
        f"state={STATE}&code={CODE}&session_state=okay&iss=%FF",
        f"state={STATE}&code={CODE}&session_state=okay&iss=https://evil.invalid",
        f"state={STATE}&code={CODE}&session_state=okay&code=another",
        f"state={STATE}&code={CODE}&session_state=okay&state={STATE}",
        f"state={STATE}&code={CODE}&session_state=okay&SESSION_STATE=uppercase",
        f"state={STATE}&code={CODE}&session-state=wrong-key",
        f"state={STATE}&code={CODE}&session_state=okay&access_token=not-allowed",
    ],
)
def test_reject_unknown_duplicate_or_inconsistent_query_fields(query: str) -> None:
    _check(query)
