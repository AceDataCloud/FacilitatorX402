"""Standard endpoint contracts with real SDK signatures and a synthetic chain."""

import copy
import hashlib
import json
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from importlib.metadata import version
from threading import Barrier
from types import SimpleNamespace
from unittest import skipUnless
from unittest.mock import patch

from django.db import close_old_connections, connection, connections
from django.test import TestCase, TransactionTestCase, override_settings
from django.urls import reverse
from eth_account import Account
from eth_account.messages import encode_typed_data
from x402.mechanisms.evm.types import AUTHORIZATION_TYPES

from x402f import envar_policy
from x402f.management.commands.reconcile_x402 import reconcile_record
from x402f.models import X402Authorization
from x402f.official import build_facilitator
from x402f.tests.test_official_facilitator import FakeEvmSigner

TX = "0x" + "ab" * 32


def signed_payment(intent, *, payer=None, recipient=None, amount="10000"):
    payer = payer or Account.create()
    recipient = recipient or Account.create().address
    auth = {
        "from": payer.address,
        "to": recipient,
        "value": amount,
        "validAfter": "0",
        "validBefore": str(int(time.time()) + 600),
        "nonce": "0x" + hashlib.sha256(b"envar-delegation-payment-v1:" + intent.bytes).hexdigest(),
    }
    message = {
        **auth,
        "value": int(amount),
        "validAfter": 0,
        "validBefore": int(auth["validBefore"]),
        "nonce": bytes.fromhex(auth["nonce"][2:]),
    }
    signature = payer.sign_message(
        encode_typed_data(
            domain_data={
                "name": "USD Coin",
                "version": "2",
                "chainId": 8453,
                "verifyingContract": envar_policy.BASE_USDC,
            },
            message_types=AUTHORIZATION_TYPES,
            message_data=message,
        )
    ).signature.to_0x_hex()
    terms = {
        "scheme": "exact",
        "network": envar_policy.BASE_NETWORK,
        "asset": envar_policy.BASE_USDC,
        "amount": amount,
        "payTo": recipient,
        "maxTimeoutSeconds": 600,
        "extra": {"name": "USD Coin", "version": "2", "paymentFlow": "upfront"},
    }
    return {
        "x402Version": 2,
        "paymentRequirements": terms,
        "paymentPayload": {
            "x402Version": 2,
            "accepted": copy.deepcopy(terms),
            "payload": {"authorization": auth, "signature": signature},
        },
    }


class SyntheticChain(FakeEvmSigner):
    def __init__(self):
        super().__init__()
        self.events = []
        self.proven = True
        self.tx_status = "confirmed"
        self.lose_receipt = False
        self.on_prepared = None

    def read_contract(self, address, abi, function_name, *args):
        self.events.append("simulation")
        return super().read_contract(address, abi, function_name, *args)

    def write_contract(self, address, abi, function_name, *args, data_suffix=None):
        assert function_name == "transferWithAuthorization"
        record = X402Authorization.objects.get()
        assert record.verification_id.startswith("envar:")
        assert record.status == X402Authorization.Status.SETTLING
        assert record.payment_payload and self.simulated_transfer
        self.on_prepared(TX, "synthetic-raw", 7)
        record.refresh_from_db()
        assert record.transaction_hash == TX and record.prepared_transaction == "synthetic-raw"
        self.events.append("broadcast")
        return TX

    def wait_for_transaction_receipt(self, tx_hash):
        if self.lose_receipt:
            raise TimeoutError("synthetic receipt timeout")
        return super().wait_for_transaction_receipt(tx_hash)

    def get_transaction_status(self, tx_hash):
        assert tx_hash == TX
        return self.tx_status

    def has_exact_usdc_transfer(self, tx_hash, asset, payer, recipient, amount):
        record = X402Authorization.objects.get()
        assert (tx_hash, asset.lower(), payer.lower(), recipient.lower(), amount) == (
            TX,
            envar_policy.BASE_USDC.lower(),
            record.payer.lower(),
            record.pay_to.lower(),
            int(record.value),
        )
        self.events.append("proof")
        return self.proven

    def broadcast_prepared(self, raw):
        assert raw == "synthetic-raw"
        self.events.append("rebroadcast")
        return TX


ENVAR_SETTINGS = dict(
    X402_ENVAR_DELEGATION_ENABLED=True,
    X402_ENVAR_DELEGATION_TOKEN="envar-secret",
    X402_SETTLE_TOKEN="ordinary-secret",
    X402_BASE_NETWORK="eip155:8453",
    X402_BASE_CHAIN_ID=8453,
    X402_BASE_EXACT_ENABLED=True,
    X402_BASE_ASSET=envar_policy.BASE_USDC,
    X402_BASE_PAY_TO="0x" + "1" * 40,
)


@override_settings(**ENVAR_SETTINGS)
class StandardEnvarTests(TestCase):
    def setUp(self):
        assert version("x402") == "2.24.0"
        self.intent = uuid.uuid4()
        self.body = signed_payment(self.intent)
        self.chain = SyntheticChain()
        self.config = patch("x402f.views_official._configured", side_effect=self.configured).start()
        self.addCleanup(patch.stopall)

    def configured(self, network, on_transaction_prepared=None, on_transaction_broadcast=None):
        assert network == envar_policy.BASE_NETWORK
        if on_transaction_prepared is not None:
            self.chain.on_prepared = on_transaction_prepared
        return SimpleNamespace(facilitator=build_facilitator(self.chain), signer_for=lambda _: self.chain)

    def settle(self, body=None, headers=None):
        headers = (
            headers
            if headers is not None
            else {"HTTP_X_ENVAR_DELEGATION_TOKEN": "envar-secret", "HTTP_X_ENVAR_INTENT_ID": str(self.intent)}
        )
        return self.client.post(
            reverse("x402:settle"), json.dumps(body or self.body), content_type="application/json", **headers
        )

    def test_direct_settle_verifies_and_persists_before_broadcast_then_replays_same_tx(self):
        first = self.settle()
        assert first.json()["success"] is True, first.content
        assert first.json()["amount"] == "10000"
        assert self.chain.events[:2] == ["simulation", "broadcast"]
        second = self.settle()
        assert second.json() == first.json()
        assert self.chain.events.count("broadcast") == 1
        assert self.chain.events.count("simulation") == 1
        assert X402Authorization.objects.count() == 1
        assert X402Authorization.objects.get().verification_id == f"envar:{self.intent}"

    def test_authentication_and_disabled_or_reused_key_fail_before_sdk(self):
        for headers in [
            {},
            {"HTTP_X_ENVAR_INTENT_ID": str(self.intent)},
            {"HTTP_X_ENVAR_DELEGATION_TOKEN": "envar-secret"},
            {"HTTP_X_ENVAR_DELEGATION_TOKEN": "ordinary-secret", "HTTP_X_ENVAR_INTENT_ID": str(self.intent)},
            {"HTTP_X_ENVAR_DELEGATION_TOKEN": "envar-secret", "HTTP_X_ENVAR_INTENT_ID": "invalid"},
            {
                "HTTP_X_ENVAR_DELEGATION_TOKEN": "envar-secret",
                "HTTP_X_ENVAR_INTENT_ID": str(self.intent),
                "HTTP_X_SETTLEMENT_TOKEN": "ordinary-secret",
            },
            {"HTTP_X_SETTLEMENT_TOKEN": "envar-secret"},
        ]:
            assert self.settle(headers=headers).status_code == 403
        for override in [
            dict(X402_ENVAR_DELEGATION_ENABLED=False),
            dict(X402_ENVAR_DELEGATION_TOKEN="ordinary-secret"),
            dict(X402_BASE_CHAIN_ID=84532),
            dict(X402_BASE_EXACT_ENABLED=False),
        ]:
            with override_settings(**override):
                assert self.settle().status_code == 403
        self.config.assert_not_called()
        assert not X402Authorization.objects.exists()

    def test_bounded_terms_and_authorization_tampering_fail_before_sdk(self):
        mutations = [
            ("scheme", "upto"),
            ("network", "eip155:84532"),
            ("asset", "0x" + "2" * 40),
            ("amount", "0"),
            ("amount", "10001"),
            ("amount", "01000"),
            ("payTo", "0x" + "0" * 40),
            ("maxTimeoutSeconds", 601),
            ("extra", {"name": "USD Coin", "version": "2"}),
        ]
        for key, value in mutations:
            body = copy.deepcopy(self.body)
            body["paymentRequirements"][key] = value
            body["paymentPayload"]["accepted"][key] = value
            assert self.settle(body).status_code == 400
        for key, value in [
            ("nonce", "0x" + "0" * 64),
            ("to", "0x" + "3" * 40),
            ("from", self.body["paymentRequirements"]["payTo"]),
            ("value", "9999"),
        ]:
            body = copy.deepcopy(self.body)
            body["paymentPayload"]["payload"]["authorization"][key] = value
            assert self.settle(body).status_code == 400
        body = copy.deepcopy(self.body)
        body["intent_id"] = str(self.intent)
        assert self.settle(body).status_code == 400
        self.config.assert_not_called()

    def test_sdk_rejects_bad_signature_without_reservation_or_broadcast(self):
        self.body["paymentPayload"]["payload"]["signature"] = "0x" + "1" * 130
        assert self.settle().status_code == 400
        assert not X402Authorization.objects.exists() and self.chain.events == []

    def test_expired_future_and_overlong_authorizations_never_broadcast(self):
        for key, value in [
            ("validBefore", str(int(time.time()) - 10)),
            ("validBefore", str(int(time.time()) + 3600)),
            ("validAfter", str(int(time.time()) + 60)),
        ]:
            body = copy.deepcopy(self.body)
            body["paymentPayload"]["payload"]["authorization"][key] = value
            assert self.settle(body).status_code == 400
        assert not X402Authorization.objects.exists() and "broadcast" not in self.chain.events

    def test_accepted_terms_and_intent_must_match_exactly(self):
        body = copy.deepcopy(self.body)
        body["paymentPayload"]["accepted"]["amount"] = "9999"
        assert self.settle(body).status_code == 400
        headers = {"HTTP_X_ENVAR_DELEGATION_TOKEN": "envar-secret", "HTTP_X_ENVAR_INTENT_ID": str(uuid.uuid4())}
        assert self.settle(headers=headers).status_code == 400
        self.config.assert_not_called()

    def test_verifier_unavailable_never_reserves_or_broadcasts(self):
        self.config.side_effect = TimeoutError("synthetic RPC unavailable")
        assert self.settle().json()["success"] is False
        assert not X402Authorization.objects.exists() and self.chain.events == []

    def test_pending_prepared_transaction_rebroadcasts_only_the_original_bytes(self):
        self.chain.lose_receipt = True
        assert self.settle().json()["success"] is False
        self.chain.tx_status = "pending"
        assert self.settle().json()["success"] is False
        assert self.chain.events.count("broadcast") == 1 and self.chain.events.count("rebroadcast") == 1
        record = X402Authorization.objects.get()
        assert record.transaction_hash == TX and record.prepared_transaction == "synthetic-raw"

    def test_reconciler_retains_a_reverted_transaction_for_manual_review(self):
        self.chain.lose_receipt = True
        self.settle()
        self.chain.tx_status = "failed"
        record = X402Authorization.objects.get()
        with patch("x402f.management.commands.reconcile_x402._configured", side_effect=self.configured):
            assert reconcile_record(record) == "failed"
        record.refresh_from_db()
        assert record.status == X402Authorization.Status.FAILED and record.transaction_hash == TX
        assert self.settle().json()["success"] is False
        assert self.chain.events.count("broadcast") == 1

    def test_same_intent_cannot_bind_a_second_payer_or_changed_signature(self):
        assert self.settle().json()["success"]
        assert self.settle(signed_payment(self.intent)).status_code == 409
        body = copy.deepcopy(self.body)
        body["paymentPayload"]["payload"]["signature"] = "0x" + "1" * 130
        assert self.settle(body).status_code == 409
        assert self.chain.events.count("broadcast") == 1

    def test_no_exact_receipt_never_settles_even_in_reconciler(self):
        self.chain.proven = False
        assert self.settle().json()["success"] is False
        record = X402Authorization.objects.get()
        assert record.status == X402Authorization.Status.SETTLING
        assert self.settle().json()["success"] is False
        with patch("x402f.management.commands.reconcile_x402._configured", side_effect=self.configured):
            assert reconcile_record(record) == "pending_proof"
        assert self.chain.events.count("broadcast") == 1 and "rebroadcast" not in self.chain.events
        self.chain.proven = True
        assert self.settle().json()["success"] is True
        self.chain.proven = False
        assert self.settle().json()["success"] is False

    def test_lost_reply_and_expired_authorization_only_reconcile_original_transaction(self):
        self.chain.lose_receipt = True
        first = self.settle()
        assert first.json()["success"] is False
        record = X402Authorization.objects.get()
        assert record.transaction_hash == TX
        with patch("time.time", return_value=time.time() + 1000):
            assert self.settle().json()["success"] is True
        assert self.chain.events.count("broadcast") == 1

    def test_failed_envar_transaction_retains_hash_and_never_reauthorizes(self):
        self.chain.lose_receipt = True
        self.settle()
        self.chain.tx_status = "failed"
        assert self.settle().json()["success"] is False
        record = X402Authorization.objects.get()
        assert record.status == X402Authorization.Status.FAILED and record.transaction_hash == TX
        assert self.settle().json()["success"] is False
        assert self.chain.events.count("broadcast") == 1

    def test_ordinary_rail_cannot_claim_reserved_intent_or_spend_envar_record(self):
        with override_settings(X402_BASE_PAY_TO=self.body["paymentRequirements"]["payTo"]):
            response = self.client.post(
                reverse("x402:verify"),
                json.dumps(self.body),
                content_type="application/json",
                HTTP_X_IDEMPOTENCY_KEY=f"envar:{self.intent}",
            )
            assert response.json()["isValid"] is False
            assert self.settle().json()["success"] is True
            assert self.settle(headers={"HTTP_X_SETTLEMENT_TOKEN": "ordinary-secret"}).json()["success"] is False
        assert self.chain.events.count("broadcast") == 1

    def test_ordinary_nonce_reservation_cannot_be_adopted_by_envar(self):
        with override_settings(X402_BASE_PAY_TO=self.body["paymentRequirements"]["payTo"]):
            response = self.client.post(
                reverse("x402:verify"),
                json.dumps(self.body),
                content_type="application/json",
                HTTP_X_IDEMPOTENCY_KEY="ordinary",
            )
            assert response.json()["isValid"] is True
        assert self.settle().status_code == 409
        assert "broadcast" not in self.chain.events

    def test_old_private_routes_are_removed(self):
        for operation in ["register", "verify", "settle"]:
            assert self.client.post(f"/envar/delegations/{operation}", {}).status_code == 404


@skipUnless(connection.vendor == "postgresql", "Requires PostgreSQL unique-key concurrency")
@override_settings(**ENVAR_SETTINGS)
class ConcurrentEnvarTests(TransactionTestCase):
    setUp = StandardEnvarTests.setUp
    settle = StandardEnvarTests.settle

    def configured(self, network, on_transaction_prepared=None, on_transaction_broadcast=None):
        configured = StandardEnvarTests.configured(self, network, on_transaction_prepared, on_transaction_broadcast)
        original = configured.facilitator.verify

        def verify(*args):
            result = original(*args)
            self.barrier.wait(timeout=10)
            return result

        configured.facilitator.verify = verify
        return configured

    def race(self, bodies):
        self.barrier = Barrier(2)

        def send(body):
            close_old_connections()
            try:
                response = self.settle(body)
                return response.status_code, response.json()
            finally:
                connections.close_all()

        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(send, body) for body in bodies]
            return [future.result(timeout=15) for future in futures]

    def test_same_nonce_concurrent_settle_broadcasts_only_one_transaction(self):
        results = self.race([self.body, self.body])
        assert all(code == 200 for code, _ in results)
        assert any(body["success"] for _, body in results)
        assert self.chain.events.count("broadcast") == 1
        assert X402Authorization.objects.count() == 1

    def test_concurrent_distinct_payers_cannot_reserve_one_intent_twice(self):
        results = self.race([self.body, signed_payment(self.intent)])
        assert sorted(code for code, _ in results) == [200, 409]
        assert self.chain.events.count("broadcast") == 1
        assert X402Authorization.objects.count() == 1
