from contextlib import nullcontext
from types import SimpleNamespace

from django.conf import settings

from x402f.chain_handlers.base import VerificationResult
from x402f.views_multichain import X402SettleView, X402VerifyView


def test_verify_fails_closed_when_nonce_reservation_cannot_be_saved(monkeypatch):
    payload = {
        "scheme": "exact",
        "network": "base",
        "payload": {"authorization": {"nonce": "0x01"}, "signature": "0xabc"},
    }
    requirements = {
        "scheme": "exact",
        "network": "base",
        "amount": "1",
        "payTo": "0x0000000000000000000000000000000000000001",
        "asset": "0x0000000000000000000000000000000000000002",
    }

    class Handler:
        def verify_signature(self, _payload, _requirements):
            return VerificationResult(
                is_valid=True,
                payer="0x0000000000000000000000000000000000000003",
                details={"amount": 1, "nonce": "0x01"},
            )

    class BrokenAuthorization:
        def __init__(self, **_kwargs):
            pass

        def save(self, **_kwargs):
            raise RuntimeError("database unavailable")

    monkeypatch.setattr("x402f.views_multichain._parse_payload", lambda _data: (payload, requirements))
    monkeypatch.setattr("x402f.views_multichain._get_chain_config", lambda _network: {})
    monkeypatch.setattr("x402f.views_multichain.ChainHandlerFactory.create", lambda *_args, **_kwargs: Handler())
    monkeypatch.setattr("x402f.views_multichain.X402Authorization", BrokenAuthorization)
    monkeypatch.setattr("x402f.views_multichain.transaction.atomic", nullcontext)

    response = X402VerifyView().post(SimpleNamespace(data={}, headers={}))

    assert response.status_code == 503
    assert response.data == {
        "isValid": False,
        "invalidReason": "Unable to reserve payment authorization.",
        "payer": None,
    }


def test_upto_settle_rejects_unauthenticated_caller(monkeypatch):
    monkeypatch.setattr(settings, "X402_SETTLE_TOKEN", "internal-secret")
    monkeypatch.setattr(
        "x402f.views_multichain._parse_payload",
        lambda _data: ({"scheme": "upto", "payload": {}}, {"scheme": "upto", "network": "base"}),
    )

    response = X402SettleView().post(SimpleNamespace(data={}, headers={"X-Settlement-Token": "wrong"}))

    assert response.status_code == 403
    assert response.data == {
        "success": False,
        "errorReason": "Unauthorized settlement caller.",
        "transaction": None,
    }
