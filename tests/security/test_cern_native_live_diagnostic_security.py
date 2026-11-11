"""Fail-closed diagnostic output tests; synthetic outcomes never confer identity."""

from __future__ import annotations

from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
from types import SimpleNamespace

import pytest

from asca.application.identity import AuthorizationStart
from asca.application.oidc_discovery import CERN_OIDC_ISSUER
from asca.domain.oidc_native_exchange import ExchangedUntrustedCernOidcToken

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
        harness = self

        class Listener:
            def __init__(self, **_kwargs: object) -> None:
                self.registration = SimpleNamespace(
                    client_id=diagnostic.CLIENT_ID,
                    redirect_uri="http://127.0.0.1:43210/oidc/callback",
                )
                self.binding = SimpleNamespace(port=43210)
                harness.registration = self.registration

            def __enter__(self):
                return self

            def __exit__(self, *_args: object) -> None:
                harness.events.append("listener-closed")

            def receive(self) -> object:
                return object()

        class Exchange:
            @property
            def callback_registration(self):
                return harness.registration

            def cancel_pending(self) -> None:
                harness.events.append("attempts-revoked")

        class Bootstrap:
            def __init__(self, _registration: object) -> None:
                pass

            def build(self) -> Exchange:
                return Exchange()

        class Lifecycle:
            def __init__(self, _exchange: Exchange) -> None:
                pass

            def begin(self) -> AuthorizationStart:
                return AuthorizationStart(
                    authorization_url=(
                        "https://auth.cern.ch/auth/realms/cern/protocol/"
                        "openid-connect/auth?state=private-state"
                    ),
                    browser_binding="private-binding",
                )

            def complete(self, *, request: object, protected_binding: str) -> object:
                assert protected_binding == "private-binding"
                return harness.outcome

        monkeypatch.setattr(diagnostic, "CernNativeLoopbackListener", Listener)
        monkeypatch.setattr(diagnostic, "CernOidcNativeUntrustedBootstrap", Bootstrap)
        monkeypatch.setattr(diagnostic, "CernNativeCallbackLifecycle", Lifecycle)
        monkeypatch.setattr(diagnostic.webbrowser, "open", lambda *_args, **_kwargs: True)

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


@pytest.mark.parametrize(
    "issuer,audiences,subject",
    [
        ("https://evil.example.invalid", (diagnostic.CLIENT_ID,), "subject"),
        (CERN_OIDC_ISSUER, ("wrong-client",), "subject"),
        (CERN_OIDC_ISSUER, (), "subject"),
        (CERN_OIDC_ISSUER, (diagnostic.CLIENT_ID,), ""),
    ],
)
def test_invalid_descriptor_never_passes_even_after_callback(
    monkeypatch: pytest.MonkeyPatch, issuer: str, audiences: tuple[str, ...], subject: str
) -> None:
    harness = Harness(monkeypatch)
    harness.outcome = ExchangedUntrustedCernOidcToken(
        issuer=issuer,
        audiences=audiences,
        subject=subject,
        expires_at=1_800_000_300,
        algorithm="RS256",
        kid="key",
    )
    assert diagnostic._run_live(timeout_seconds=45) == "CHECK_REJECTED"
    assert harness.events[-2:] == ["attempts-revoked", "listener-closed"]


def test_forged_result_object_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    harness = Harness(monkeypatch)
    harness.outcome = object()
    assert diagnostic._run_live(timeout_seconds=45) == "CHECK_REJECTED"


def test_no_identity_authority_or_token_fields_in_cli_output(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    Harness(monkeypatch)
    assert diagnostic.main(["--live", "--timeout", "45"]) == 0
    out = capsys.readouterr().out
    assert "RESULT=ID_TOKEN_CHECK_PASSED_NO_SESSION" in out
    assert "ROLE_AUTHORIZATION=NOT_CHECKED" in out
    assert "ASCA_SESSION=DISABLED" in out
    assert "CHATLAS_ACCESS=DISABLED" in out
    for forbidden in (
        "private-binding",
        "private-state",
        "private-user-identifier",
        "access_token=",
        "id_token=",
        "refresh_token=",
        "nonce=",
        "code_verifier=",
    ):
        assert forbidden not in out


def test_no_runtime_inputs_for_malicious_urls_or_tokens() -> None:
    assert diagnostic.CLIENT_ID == "asca-glibotte-dev"
    assert diagnostic.CALLBACK_PATH == "/oidc/callback"
    assert diagnostic.EXPECTED_REGISTERED_URI == "http://127.0.0.1/oidc/callback"
    for option in ("--issuer", "--jwks", "--token", "--transport", "--redirect-uri"):
        with pytest.raises(SystemExit):
            diagnostic.main([option, "https://evil.example.invalid"])
