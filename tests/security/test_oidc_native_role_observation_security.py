"""Adversarial replay and privacy tests for the native CERN role observation path."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

import pytest

from asca.domain.oidc_native_exchange import OidcNativeExchangeError
from asca.domain.oidc_native_lifecycle import OidcNativeLifecycleError
from asca.domain.oidc_role_claims import UntrustedCernRoleObservation
from asca.infrastructure.oidc_native_exchange import CernOidcNativeCodeExchange

_UNIT_FILE = Path(__file__).resolve().parents[1] / "unit" / "test_oidc_native_role_observation.py"
_SPEC = spec_from_file_location("asca_native_role_test_helpers", _UNIT_FILE)
if _SPEC is None or _SPEC.loader is None:
    raise ImportError("Offline native role test helpers are unavailable")
_helpers = module_from_spec(_SPEC)
_SPEC.loader.exec_module(_helpers)
callback = _helpers.callback
make = _helpers.make
start = _helpers.start


@pytest.mark.parametrize(
    "change",
    [
        {"browser_binding": "invalid-binding"},
        {"browser_binding": None},
        {"state": "z" * 43},
        {"state": None},
        {"code": ""},
        {"code": "bad code"},
        {"code": None},
        {"response_issuer": "https://untrusted.invalid"},
        {"response_issuer": 123},
    ],
)
def test_invalid_callback_does_not_consume_role_attempt(change: dict[str, object]) -> None:
    life, exchange, transport, verifier = make()
    binding, state, _ = start(life)
    data: dict[str, object] = {
        "browser_binding": binding,
        "state": state,
        "code": "synthetic-code",
    }
    data.update(change)
    with pytest.raises(OidcNativeExchangeError):
        exchange.exchange_callback_observe_role(**data)  # type: ignore[arg-type]
    assert not transport.requests and not verifier.observed
    assert (
        exchange.exchange_callback_observe_role(
            browser_binding=binding, state=state, code="synthetic-code"
        ).status
        == "claimed"
    )
    assert len(transport.requests) == 1


def test_forged_result_is_rejected_and_cannot_be_replayed() -> None:
    life, exchange, transport, verifier = make()
    verifier.invalid = True
    binding, state, _ = start(life)
    with pytest.raises(OidcNativeExchangeError):
        exchange.exchange_callback_observe_role(
            browser_binding=binding, state=state, code="synthetic-code"
        )
    assert len(transport.requests) == 1
    with pytest.raises(OidcNativeExchangeError):
        exchange.exchange_callback_observe_role(
            browser_binding=binding, state=state, code="synthetic-code"
        )
    assert len(transport.requests) == 1


def test_verifier_failure_sanitizes_secret_and_rejects_replay() -> None:
    life, _, transport, verifier = make()
    verifier.fail = True
    binding, state, _ = start(life)
    with pytest.raises(OidcNativeLifecycleError) as failure:
        life.complete_role_observation(request=callback(state), protected_binding=binding)
    assert "synthetic-private-secret" not in str(failure.value)
    assert len(transport.requests) == 1
    with pytest.raises(OidcNativeLifecycleError):
        life.complete_role_observation(request=callback(state), protected_binding=binding)
    assert len(transport.requests) == 1


def test_wrong_local_binding_and_injected_callback_cannot_consume() -> None:
    life, _, transport, _ = make()
    binding, state, _ = start(life)
    with pytest.raises(OidcNativeLifecycleError):
        life.complete_role_observation(request=callback(state), protected_binding="Y" * 43)
    with pytest.raises(OidcNativeLifecycleError):
        life.complete_role_observation(request=callback("Z" * 43), protected_binding=binding)
    assert not transport.requests
    assert (
        life.complete_role_observation(request=callback(state), protected_binding=binding).status
        == "claimed"
    )
    assert len(transport.requests) == 1


def test_racing_callbacks_produce_one_token_post() -> None:
    life, exchange, transport, _ = make()
    binding, state, _ = start(life)

    def finish(_: int) -> bool:
        try:
            result = exchange.exchange_callback_observe_role(
                browser_binding=binding, state=state, code="synthetic-code"
            )
            return type(result) is UntrustedCernRoleObservation
        except OidcNativeExchangeError:
            return False

    with ThreadPoolExecutor(max_workers=8) as pool:
        assert sum(pool.map(finish, range(32))) == 1
    assert len(transport.requests) == 1


def test_neither_flow_accepts_caller_supplied_tokens_or_role_identifiers() -> None:
    _, exchange, _, _ = make()
    for extra in ("tokens", "expected_role", "jwks", "verifier", "role_claims"):
        with pytest.raises(TypeError):
            exchange.exchange_callback_observe_role(
                browser_binding="Y" * 43,
                state="Z" * 43,
                code="synthetic-code",
                **{extra: "synthetic-token"},
            )


def test_new_path_never_creates_identity_or_permission() -> None:
    life, _, _, _ = make()
    binding, state, _ = start(life)
    outcome = life.complete_role_observation(request=callback(state), protected_binding=binding)
    assert type(outcome) is UntrustedCernRoleObservation
    for forbidden in ("subject", "session", "permissions", "principal", "access_token"):
        assert not hasattr(outcome, forbidden)
    assert outcome.authorization == "not_implemented"
    assert not hasattr(CernOidcNativeCodeExchange, "create_session")
