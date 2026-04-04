"""
Patch for FacilitatorX402/x402f/views.py

This patch improves the _submit_transfer_with_authorization function and
X402SettleView to handle RPC/balance transient errors with retry logic.

Apply with: patch -p1 < x402_views_retry_patch.py

Key changes:
1. _submit_transfer_with_authorization now accepts skip_preflight parameter
2. New _submit_transfer_with_retry function with exponential backoff
3. X402SettleView.post() uses retry logic for transient errors
4. Better error classification and logging
"""

# ============================================================================
# PART 1: Replace _submit_transfer_with_authorization signature
# ============================================================================

# OLD:
# def _submit_transfer_with_authorization(data: ValidatedAuthorization) -> str:


# NEW:
def _submit_transfer_with_authorization_patched(
    data: ValidatedAuthorization,
    skip_preflight: bool = False,
    retry_attempt: int = 1,
) -> str:
    """
    Submit transferWithAuthorization transaction to blockchain.

    Args:
        data: Validated authorization data
        skip_preflight: If True, skip the preflight check and go directly to submission.
                        Used when retrying after preflight-only failures where state may have changed.
        retry_attempt: Which attempt number this is (for logging)

    Raises:
        SettlementError: With classification for retry logic to use
        X402FacilitatorError: For configuration errors (never retryable)
    """

    from x402f.settlement_enhancements import SettlementError, SettlementErrorType, classify_error

    rpc_url = getattr(settings, "X402_RPC_URL", "")
    private_key = getattr(settings, "X402_SIGNER_PRIVATE_KEY", "")
    configured_address = getattr(settings, "X402_SIGNER_ADDRESS", "")
    timeout = getattr(settings, "X402_TX_TIMEOUT_SECONDS", 120)
    gas_limit = getattr(settings, "X402_GAS_LIMIT", 250000)
    max_fee = getattr(settings, "X402_MAX_FEE_PER_GAS_WEI", 0)
    max_priority_fee = getattr(settings, "X402_MAX_PRIORITY_FEE_PER_GAS_WEI", 0)

    if not rpc_url:
        raise X402FacilitatorError("X402_RPC_URL is not configured.")
    if not private_key:
        raise X402FacilitatorError("X402_SIGNER_PRIVATE_KEY is not configured.")

    web3 = Web3(HTTPProvider(rpc_url))
    if not web3.is_connected():
        raise SettlementError(
            error_type=SettlementErrorType.RPC_UNAVAILABLE,
            message="Unable to connect to RPC endpoint",
        )

    account = web3.eth.account.from_key(private_key)
    signer_address = _normalize_address(configured_address or account.address)

    asset_address = _normalize_address(data.requirements.asset)
    authorization = data.payload.payload.authorization

    logger.debug(
        "x402 settlement attempt {}: network={} asset={} signer={} payer={} {pay_to={} value={} skip_preflight={}",
        retry_attempt,
        str(data.requirements.network),
        asset_address,
        signer_address,
        data.payer,
        data.pay_to,
        int(data.value),
        skip_preflight,
    )

    contract = web3.eth.contract(
        address=asset_address,
        abi=USDC_TRANSFER_WITH_AUTHORIZATION_ABI,
    )

    nonce_bytes = HexBytes(authorization.nonce)
    v, r, s = _signature_to_components(data.signature)

    transfer_fn = contract.functions.transferWithAuthorization(
        _normalize_address(authorization.from_),
        _normalize_address(authorization.to),
        int(authorization.value),
        int(authorization.valid_after),
        int(authorization.valid_before),
        nonce_bytes,
        v,
        r,
        s,
    )

    # ========================================================================
    # PREFLIGHT CHECK (can be skipped on retry if state may have changed)
    # ========================================================================

    if not skip_preflight:
        try:
            transfer_fn.call({"from": signer_address})
            logger.debug("x402 preflight check passed for attempt {}", retry_attempt)
        except ContractLogicError as exc:
            friendly = _map_contract_logic_error(exc)
            error = classify_error(exc)

            logger.warning(
                "x402 preflight failed attempt {}: {} (error_type={}, may retry)",
                retry_attempt,
                friendly,
                error.error_type.value,
            )
            raise error
        except BadFunctionCallOutput:
            logger.debug("x402 preflight returned empty data (non-standard contract), continuing without validation")
        except Exception as exc:
            error = classify_error(exc)
            logger.warning(
                "x402 preflight check error attempt {}: {} (error_type={})",
                retry_attempt,
                str(exc),
                error.error_type.value,
            )
            raise error

    # ========================================================================
    # GAS ESTIMATION (safe to retry)
    # ========================================================================

    try:
        estimated_gas = transfer_fn.estimate_gas({"from": signer_address})
        logger.debug(
            "x402 gas estimate attempt {}: {}",
            retry_attempt,
            estimated_gas,
        )
    except Exception as exc:
        logger.debug("x402 gas estimation failed attempt {}, using fallback: {}", retry_attempt, exc)
        estimated_gas = gas_limit

        # If gas estimation fails, it might be a transient RPC issue
        # We still continue with fallback but log it
        error = classify_error(exc)
        if error.error_type == SettlementErrorType.RPC_UNAVAILABLE:
            raise error

    # ========================================================================
    # BUILD AND SUBMIT TRANSACTION
    # ========================================================================

    tx_params = {
        "chainId": int(get_chain_id(str(data.requirements.network))),
        "from": signer_address,
        "nonce": web3.eth.get_transaction_count(signer_address),
        "gas": max(estimated_gas, gas_limit),
    }

    if max_fee and max_priority_fee:
        tx_params["maxFeePerGas"] = int(max_fee)
        tx_params["maxPriorityFeePerGas"] = int(max_priority_fee)
    else:
        tx_params["gasPrice"] = web3.eth.gas_price

    transaction = transfer_fn.build_transaction(tx_params)
    signed = web3.eth.account.sign_transaction(transaction, private_key=private_key)

    raw_tx = getattr(signed, "rawTransaction", None)
    if raw_tx is None:
        raw_tx = getattr(signed, "raw_transaction", None)
    if raw_tx is None:
        raise X402FacilitatorError("Signer returned unexpected transaction encoding.")

    tx_hash = web3.eth.send_raw_transaction(raw_tx)
    logger.info(
        "x402 transaction submitted attempt {}: nonce={} tx={}",
        retry_attempt,
        data.nonce,
        tx_hash.hex(),
    )

    # ========================================================================
    # WAIT FOR RECEIPT
    # ========================================================================

    try:
        receipt = web3.eth.wait_for_transaction_receipt(tx_hash, timeout=timeout)
    except Exception as exc:
        # Timeout waiting for receipt - transaction may still succeed
        # Don't retry, as it's likely still pending
        raise SettlementError(
            error_type=SettlementErrorType.TX_TIMEOUT,
            message="Timed out waiting for settlement transaction (may still succeed).",
            original_error=exc,
            details={"tx_hash": tx_hash.hex(), "timeout_seconds": timeout},
        )

    if receipt.status != 1:
        raise SettlementError(
            error_type=SettlementErrorType.CONTRACT_REVERTED,
            message="Settlement transaction reverted on-chain.",
            details={"tx_hash": tx_hash.hex(), "gas_used": str(receipt.gasUsed)},
        )

    logger.info(
        "x402 settlement succeeded attempt {}: nonce={} tx={} gas_used={}",
        retry_attempt,
        data.nonce,
        tx_hash.hex(),
        receipt.gasUsed,
    )

    return tx_hash.hex()


# ============================================================================
# PART 2: New retry wrapper function
# ============================================================================


def _submit_transfer_with_retry(
    data: ValidatedAuthorization,
    config: Optional[RetryConfig] = None,
) -> str:
    """
    Submit transfer with intelligent retry logic for transient errors.

    Handles:
    - Balance insufficient (preflight may be stale, retry with skip_preflight=True)
    - RPC temporary unavailability (exponential backoff)
    - Gas estimation failures (may be state-dependent, exponential backoff)

    Non-retryable errors:
    - Invalid signature
    - Invalid parameters
    - Configuration errors
    - Nonce already used

    Args:
        data: Validated authorization
        config: RetryConfig (uses Django settings default if not provided)

    Returns:
        Transaction hash on success

    Raises:
        SettlementError: Final error after all retries exhausted or non-retryable error
    """
    from x402f.settlement_enhancements import (
        SettlementAttempts,
        SettlementError,
        should_log_as_error,
    )
    from x402f.settlement_retry_integration import get_retry_config

    if config is None:
        config = get_retry_config()

    attempts = SettlementAttempts(nonce=data.nonce, config=config)

    while True:
        attempt = len(attempts.attempts) + 1
        skip_preflight = False

        try:
            # Check if we should skip preflight (state may have changed for balance errors)
            if attempt > 1 and attempts.last_error and attempts.last_error.should_skip_preflight_on_retry:
                skip_preflight = True
                logger.info(
                    "x402 skipping preflight on retry attempt {} due to previous {} error",
                    attempt,
                    attempts.last_error.error_type.value,
                )

            tx_hash = _submit_transfer_with_authorization_patched(
                data,
                skip_preflight=skip_preflight,
                retry_attempt=attempt,
            )

            attempts.add_attempt(error=None, tx_hash=tx_hash)
            logger.info(
                "x402 settlement succeeded on attempt {} for nonce {}",
                attempt,
                data.nonce,
            )
            return tx_hash

        except SettlementError as exc:
            attempts.add_attempt(error=exc, tx_hash=None)

            # Determine log level
            if should_log_as_error(exc, attempt):
                logger.error(
                    "x402 settlement attempt {} failed for nonce {}: {} (type={})",
                    attempt,
                    data.nonce,
                    exc.message,
                    exc.error_type.value,
                )
            else:
                logger.warning(
                    "x402 settlement attempt {} failed for nonce {}: {} (type={}, will retry)",
                    attempt,
                    data.nonce,
                    exc.message,
                    exc.error_type.value,
                )

            # Check if we should retry
            can_retry, reason = attempts.can_retry()
            if not can_retry:
                logger.error(
                    "x402 settlement abandoned for nonce {}: {}",
                    data.nonce,
                    reason,
                )
                raise

            # Calculate backoff and sleep
            delay_ms = attempts.get_retry_delay_ms()
            logger.info(
                "x402 will retry in {}ms (attempt {}/{})",
                delay_ms,
                attempt + 1,
                config.get_max_retries(exc.error_type),
            )
            time.sleep(delay_ms / 1000.0)

        except X402FacilitatorError as exc:
            # Configuration error - never retry
            error = SettlementError(
                error_type=SettlementErrorType.SIGNER_MISCONFIGURED,
                message=str(exc),
                original_error=exc,
            )
            attempts.add_attempt(error=error, tx_hash=None)

            logger.error(
                "x402 settlement failed with configuration error for nonce {}: {}",
                data.nonce,
                str(exc),
            )
            raise error


# ============================================================================
# PART 3: Update X402SettleView.post() to use retry logic
# ============================================================================

# In X402SettleView.post(), replace the settlement block with:

"""
        try:
            with transaction.atomic():
                record = X402Authorization.objects.select_for_update().get(nonce=validated.nonce)
                if record.status == X402Authorization.Status.SETTLED:
                    raise X402FacilitatorValidationError("Authorization nonce already settled.")

                if record.signature.lower() != validated.signature.lower():
                    raise X402FacilitatorValidationError("Authorization signature mismatch.")

                if record.payer.lower() != validated.payer.lower():
                    raise X402FacilitatorValidationError("Authorization signer mismatch.")

                if int(record.value) != validated.value:
                    raise X402FacilitatorValidationError("Authorization value mismatch.")

                # NEW: Use retry logic instead of direct submission
                tx_hash = _submit_transfer_with_retry(validated)
                
                record.mark_settled(tx_hash)
                record.save(update_fields=["status", "transaction_hash", "settled_at", "updated_at"])
        except X402Authorization.DoesNotExist:
            logger.info("x402 settlement attempted without prior verification for nonce {}", validated.nonce)
            return Response(
                {
                    "success": False,
                    "errorReason": "Authorization nonce not verified.",
                    "transaction": None,
                },
                status=status.HTTP_200_OK,
            )
        except X402FacilitatorValidationError as exc:
            logger.info("x402 settlement rejected: {}", exc.message)
            return Response(
                {
                    "success": False,
                    "errorReason": exc.message,
                    "transaction": None,
                },
                status=status.HTTP_200_OK,
            )
        except SettlementError as exc:
            # NEW: Classify error and return appropriate response
            logger.warning(
                "x402 settlement final error for nonce {}: {} (type={}, retryable={})",
                validated.nonce,
                exc.message,
                exc.error_type.value,
                exc.is_retryable,
            )
            return Response(
                {
                    "success": False,
                    "errorReason": exc.message,
                    "errorType": exc.error_type.value,
                    "isRetryable": exc.is_retryable,
                    "transaction": None,
                },
                status=status.HTTP_200_OK,
            )
        except X402FacilitatorError as exc:
            logger.error("x402 settlement failed: {}", exc)
            return Response(
                {
                    "success": False,
                    "errorReason": str(exc),
                    "transaction": None,
                },
                status=status.HTTP_200_OK,
            )

        logger.info("x402 settlement succeeded for nonce {} tx {}", validated.nonce, tx_hash)
        return Response(
            {
                "success": True,
                "errorReason": None,
                "transaction": tx_hash,
                "network": str(validated.requirements.network),
                "payer": validated.payer,
            },
            status=status.HTTP_200_OK,
        )
"""
