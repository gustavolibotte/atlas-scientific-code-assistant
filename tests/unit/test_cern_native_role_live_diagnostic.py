"""Offline tests of the separately opt-in, privacy-preserving role diagnostic."""

from __future__ import annotations

from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
from types import SimpleNamespace

import pytest

from asca.application.identity import AuthorizationStart
from asca.domain.oidc_native_lifecycle import NativeCallbackDenied
from asca.domain.oidc_role_claims import UntrustedCernRoleObservation

_SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "check_cern_oidc_native_role_live.py"
_SPEC = spec_from_file_location("asca_native_live_role_diagnostic", _SCRIPT)
if _SPEC is None or _SPEC.loader is None:
    raise ImportError("CERN role diagnostic source is unavailable")
diagnostic = module_from_spec(_SPEC)
_SPEC.loader.exec_module(diagnostic)


class Harness:
    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.events: list[str] = []
        self.status: object = UntrustedCernRoleObservation(status="claimed")
        self.fail: str | None = None
        self.registration = SimpleNamespace(
            client_id=diagnostic.CLIENT_ID,
            redirect_uri="http://127.0.0.1:43210/oidc/callback",
        )
        harness = self

        class Listener:
            def __init__(self, **kwargs: object) -> None:
                assert kwargs["host"] == "127.0.0.1"
                assert kwargs["client_id"] == diagnostic.CLIENT_ID
                assert kwargs["scopes"] == ("openid",)
                self.registration = harness.registration
                self.binding = SimpleNamespace(port=43210)
                harness.events.append("listener-created")

            def __enter__(self) -> Listener:
                harness.events.append("listener-bound")
                return self

            def __exit__(self, *_args: object) -> None:
                harness.events.append("listener-closed")

            def receive(self) -> object:
                harness.events.append("callback-received")
                if harness.fail == "receive":
                    raise ValueError("synthetic-private-token-secret")
                return object()

        class Exchange:
            callback_registration = harness.registration

            def cancel_pending(self) -> None:
                harness.events.append("attempts-revoked")

        class Bootstrap:
            def __init__(self, registration: object) -> None:
                assert registration is harness.registration

            def build(self) -> Exchange:
                harness.events.append("bootstrap-default")
                if harness.fail == "bootstrap":
                    raise ValueError("synthetic-private-token-secret")
                return Exchange()

        class Lifecycle:
            def __init__(self, exchange: Exchange) -> None:
                assert exchange.callback_registration is harness.registration

            def begin(self) -> AuthorizationStart:
                harness.events.append("authorization-started")
                return AuthorizationStart(
                    authorization_url=(
                        "https://auth.cern.ch/auth/realms/cern/authorize?state=private"
                    ),
                    browser_binding="private-binding",
                )

            def complete_role_observation(self, *, request: object, protected_binding: str):
                assert request is not None and protected_binding == "private-binding"
                harness.events.append("role-observed")
                if harness.fail == "verification":
                    raise ValueError("synthetic-private-token-secret")
                return harness.status

        def browser_open(url: str, **_kwargs: object) -> bool:
            assert url.startswith("https://auth.cern.ch/")
            harness.events.append("browser-opened")
            return harness.fail != "browser"

        monkeypatch.setattr(diagnostic, "CernNativeLoopbackListener", Listener)
        monkeypatch.setattr(diagnostic, "CernOidcNativeUntrustedBootstrap", Bootstrap)
        monkeypatch.setattr(diagnostic, "CernNativeCallbackLifecycle", Lifecycle)
        monkeypatch.setattr(diagnostic.webbrowser, "open", browser_open)


def test_default_execution_cannot_start_browser_or_network(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(diagnostic, "_run_live", lambda **_kwargs: pytest.fail("Unexpected live"))
    assert diagnostic.main([]) == 0
    out = capsys.readouterr().out
    assert "RESULT=OFFLINE_ONLY" in out
    assert "ROLE_AUTHORIZATION=DISABLED" in out
    assert "ASCA_SESSION=DISABLED" in out


@pytest.mark.parametrize(
    "role_status",
    ["claimed", "absent", "mfa_required", "loa_required", "mfa_and_loa_required"],
)
def test_live_result_shows_only_fixed_labels(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    role_status: str,
) -> None:
    harness = Harness(monkeypatch)
    harness.status = UntrustedCernRoleObservation(status=role_status)  # type: ignore[arg-type]
    assert diagnostic.main(["--live", "--timeout", "45"]) == 0
    output = capsys.readouterr().out
    assert f"ROLE_STATUS={role_status.upper()}" in output
    assert "RESULT=ROLE_OBSERVATION_COMPLETE_NO_SESSION" in output
    assert "private-binding" not in output
    assert "private-token" not in output
    assert "state=" not in output
    assert harness.events.count("role-observed") == 1
    assert harness.events[-2:] == ["attempts-revoked", "listener-closed"]


@pytest.mark.parametrize("failure", ["bootstrap", "receive", "verification", "browser"])
def test_error_paths_never_echo_secrets_and_close_listener(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    failure: str,
) -> None:
    harness = Harness(monkeypatch)
    harness.fail = failure
    assert diagnostic.main(["--live", "--timeout", "45"]) == 1
    output = capsys.readouterr().out
    assert "synthetic-private-token-secret" not in output
    assert "ROLE_STATUS=" not in output
    assert "RESULT=" in output
    assert harness.events[-1] == "listener-closed"
    if failure != "bootstrap":
        assert "attempts-revoked" in harness.events


def test_denial_and_invalid_role_result_are_not_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = Harness(monkeypatch)
    harness.status = NativeCallbackDenied()
    assert diagnostic._run_live(timeout_seconds=45) == ("PROVIDER_DENIED", None)
    harness.status = object()
    assert diagnostic._run_live(timeout_seconds=45) == ("ROLE_CHECK_REJECTED", None)


def test_cli_refuses_token_and_network_override_flags() -> None:
    for option in ("--issuer", "--token", "--jwks", "--transport", "--redirect-uri"):
        with pytest.raises(SystemExit):
            diagnostic.main([option, "https://untrusted.invalid"])


def test_timeout_is_checked_before_any_execution(capsys: pytest.CaptureFixture[str]) -> None:
    for timeout in ("29", "121", "-1"):
        with pytest.raises(SystemExit):
            diagnostic.main(["--live", "--timeout", timeout])
        assert "CLIENT_ID=" not in capsys.readouterr().out
