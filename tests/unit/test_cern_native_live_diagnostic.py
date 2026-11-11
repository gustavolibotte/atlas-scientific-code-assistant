"""Offline orchestration tests for the opt-in CERN native OIDC diagnostic."""

from __future__ import annotations

from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
from types import SimpleNamespace

import pytest

from asca.application.identity import AuthorizationStart
from asca.application.oidc_discovery import CERN_OIDC_ISSUER
from asca.domain.oidc_native_exchange import ExchangedUntrustedCernOidcToken
from asca.domain.oidc_native_lifecycle import NativeCallbackDenied

_SCRIPT_PATH = Path(__file__).resolve().parents[2] / "scripts" / "check_cern_oidc_native_live.py"
_SPEC = spec_from_file_location("asca_native_live_diagnostic", _SCRIPT_PATH)
if _SPEC is None or _SPEC.loader is None:
    raise ImportError("Native diagnostic script is unavailable")
diagnostic = module_from_spec(_SPEC)
_SPEC.loader.exec_module(diagnostic)


class Harness:
    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.events: list[str] = []
        self.outcome: object = self.good_result()
        self.opened = True
        self.registration = SimpleNamespace(
            client_id=diagnostic.CLIENT_ID,
            redirect_uri="http://127.0.0.1:43210/oidc/callback",
        )
        self.callback = object()
        self.fail_stage: str | None = None
        self.last_binding: str | None = None

        harness = self

        class Listener:
            def __init__(self, **kwargs: object) -> None:
                assert kwargs["host"] == "127.0.0.1"
                assert kwargs["client_id"] == diagnostic.CLIENT_ID
                assert kwargs["callback_path"] == diagnostic.CALLBACK_PATH
                assert kwargs["scopes"] == ("openid",)
                assert kwargs["timeout_seconds"] == 45.0
                self.registration = harness.registration
                self.binding = SimpleNamespace(port=43210)
                harness.events.append("listener-created")

            def __enter__(self) -> Listener:
                harness.events.append("listener-entered")
                return self

            def __exit__(self, *_args: object) -> None:
                harness.events.append("listener-closed")

            def receive(self) -> object:
                harness.events.append("callback-received")
                if harness.fail_stage == "receive":
                    raise RuntimeError("secret-code-must-not-be-logged")
                return harness.callback

        class Exchange:
            def __init__(self) -> None:
                self.callback_registration = harness.registration

            def cancel_pending(self) -> None:
                harness.events.append("attempts-revoked")

        class Bootstrap:
            def __init__(self, registration: object) -> None:
                assert registration is harness.registration
                harness.events.append("bootstrap-created")

            def build(self) -> Exchange:
                harness.events.append("bootstrap-checked")
                if harness.fail_stage == "bootstrap":
                    raise RuntimeError("private-token-or-secret")
                return Exchange()

        class Lifecycle:
            def __init__(self, exchange: Exchange) -> None:
                assert exchange.callback_registration is harness.registration
                harness.events.append("lifecycle-created")

            def begin(self) -> AuthorizationStart:
                harness.events.append("authorization-started")
                return AuthorizationStart(
                    authorization_url=(
                        "https://auth.cern.ch/auth/realms/cern/protocol/"
                        "openid-connect/auth?state=private-state"
                    ),
                    browser_binding="private-binding",
                )

            def complete(self, *, request: object, protected_binding: str) -> object:
                assert request is harness.callback
                harness.last_binding = protected_binding
                harness.events.append("callback-checked")
                if harness.fail_stage == "complete":
                    raise RuntimeError("secret-token-must-not-be-logged")
                return harness.outcome

        def open_browser(url: str, **_kwargs: object) -> bool:
            assert url.startswith("https://auth.cern.ch/")
            harness.events.append("browser-open-attempt")
            return harness.opened

        monkeypatch.setattr(diagnostic, "CernNativeLoopbackListener", Listener)
        monkeypatch.setattr(diagnostic, "CernOidcNativeUntrustedBootstrap", Bootstrap)
        monkeypatch.setattr(diagnostic, "CernNativeCallbackLifecycle", Lifecycle)
        monkeypatch.setattr(diagnostic.webbrowser, "open", open_browser)

    @staticmethod
    def good_result() -> ExchangedUntrustedCernOidcToken:
        return ExchangedUntrustedCernOidcToken(
            issuer=CERN_OIDC_ISSUER,
            subject="private-user-identifier",
            audiences=(diagnostic.CLIENT_ID,),
            expires_at=1_800_000_300,
            algorithm="RS256",
            kid="private-key-id",
        )


def test_offline_default_has_no_network_or_browser(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("Offline mode must not start live diagnostic")

    monkeypatch.setattr(diagnostic, "_run_live", forbidden)
    assert diagnostic.main([]) == 0
    out = capsys.readouterr().out
    assert "RESULT=OFFLINE_ONLY" in out
    assert "ASCA_SESSION=DISABLED" in out
    assert "ROLE_AUTHORIZATION=NOT_CHECKED" in out


def test_successful_isolated_full_orchestration(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    harness = Harness(monkeypatch)
    assert diagnostic._run_live(timeout_seconds=45) == "ID_TOKEN_CHECK_PASSED_NO_SESSION"
    out = capsys.readouterr().out
    assert "BROWSER_OPEN=OK" in out
    assert harness.last_binding == "private-binding"
    assert harness.events == [
        "listener-created",
        "listener-entered",
        "bootstrap-created",
        "bootstrap-checked",
        "lifecycle-created",
        "authorization-started",
        "browser-open-attempt",
        "callback-received",
        "callback-checked",
        "attempts-revoked",
        "listener-closed",
    ]
    assert "private-state" not in out
    assert "private-binding" not in out
    assert "private-user-identifier" not in out


def test_provider_denial_never_becomes_login(monkeypatch: pytest.MonkeyPatch) -> None:
    harness = Harness(monkeypatch)
    harness.outcome = NativeCallbackDenied()
    assert diagnostic._run_live(timeout_seconds=45) == "PROVIDER_DENIED"
    assert harness.events[-2:] == ["attempts-revoked", "listener-closed"]


def test_browser_failure_always_revokes(monkeypatch: pytest.MonkeyPatch) -> None:
    harness = Harness(monkeypatch)
    harness.opened = False
    assert diagnostic._run_live(timeout_seconds=45) == "BROWSER_NOT_OPENED"
    assert "callback-received" not in harness.events
    assert harness.events[-2:] == ["attempts-revoked", "listener-closed"]


def test_bad_registration_never_opens_browser(monkeypatch: pytest.MonkeyPatch) -> None:
    harness = Harness(monkeypatch)
    harness.registration.redirect_uri = "http://127.0.0.1:44444/oidc/callback"
    assert diagnostic._run_live(timeout_seconds=45) == "LOCAL_BINDING_REJECTED"
    assert "browser-open-attempt" not in harness.events


@pytest.mark.parametrize("stage", ["bootstrap", "receive", "complete"])
def test_failures_are_sanitized_and_revoke_when_possible(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    stage: str,
) -> None:
    harness = Harness(monkeypatch)
    harness.fail_stage = stage
    assert diagnostic.main(["--live", "--timeout", "45"]) == 1
    out = capsys.readouterr().out
    assert "RESULT=REJECTED_OR_TIMEOUT" in out
    assert "private-token" not in out
    assert "secret-" not in out
    assert "attempts-revoked" in harness.events or stage == "bootstrap"
    assert harness.events[-1] == "listener-closed"


@pytest.mark.parametrize("bad", ["29", "121", "-1", "99999"])
def test_invalid_timeout_is_rejected_before_network(
    capsys: pytest.CaptureFixture[str], bad: str
) -> None:
    with pytest.raises(SystemExit) as exc:
        diagnostic.main(["--live", "--timeout", bad])
    assert exc.value.code == 2
    assert "CLIENT_ID=" not in capsys.readouterr().out


def test_live_flag_is_required(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[int] = []

    def fake_run(*, timeout_seconds: int) -> str:
        calls.append(timeout_seconds)
        return "ID_TOKEN_CHECK_PASSED_NO_SESSION"

    monkeypatch.setattr(diagnostic, "_run_live", fake_run)
    assert diagnostic.main([]) == 0
    assert calls == []
    assert diagnostic.main(["--live"]) == 0
    assert calls == [120]
