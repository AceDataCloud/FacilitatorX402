# X402 Settlement Retry Logic Implementation Guide

## Problem Statement

The current X402 Facilitator implementation has a critical race condition that causes payment failures:

1. **Time-of-Check-Time-of-Use (TOCTOU) Gap**: The preflight check `transferFn.call()` can report "insufficient balance", but the balance changes between the check and `send_raw_transaction()`, making the actual submission succeed.

2. **No Retry Logic**: When the preflight fails, the entire settlement fails immediately with no recovery, even though the transaction might have succeeded on-chain.

3. **Poor Error Classification**: All errors return the same generic message, making it impossible to distinguish transient RPC issues from actual on-chain failures.

**Result**: User's chain transaction succeeds but Facilitator shows error → credits not added → support tickets.

## Solution Overview

Four new files implement smart retry logic:

| File | Purpose |
|------|---------|
| `settlement_enhancements.py` | Error classification, retry config, attempt tracking |
| `settlement_retry_integration.py` | Decorator and helper functions |
| `views_patch.py` | Code patches for views.py |
| `test_settlement_retry.py` | Comprehensive test suite |

## Implementation Steps

### Step 1: Add New Dependencies (pyproject.toml)

```toml
[tool.poetry.dependencies]
# No new dependencies - uses existing web3, loguru, django
```

### Step 2: Create New Files

Copy these files to `FacilitatorX402/x402f/`:
- `x402f/settlement_enhancements.py` (error classification framework)
- `x402f/settlement_retry_integration.py` (retry helpers)  
- `x402f/test_settlement_retry.py` (tests)

### Step 3: Patch views.py

**Imports** (add to top of `x402f/views.py`):
```python
import time
from x402f.settlement_enhancements import (
    SettlementError,
    SettlementErrorType,
    classify_error,
)
from x402f.settlement_retry_integration import (
    get_retry_config,
    RetryConfig,
)
```

**Function signature** - Update `_submit_transfer_with_authorization`:

```python
def _submit_transfer_with_authorization(
    data: ValidatedAuthorization,
    skip_preflight: bool = False,
    retry_attempt: int = 1,
) -> str:
    """
    Submit transferWithAuthorization transaction to blockchain.
    
    Args:
        skip_preflight: If True, skip preflight check (used on retry when state may have changed)
        retry_attempt: Current attempt number (for logging)
    """
```

**Preflight handling** - Replace old call() logic:

```python
# OLD CODE - Remove this:
# try:
#     transfer_fn.call({"from": signer_address})
# except ContractLogicError as exc:
#     raise X402FacilitatorError(_map_contract_logic_error(exc))

# NEW CODE - Replace with:
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
        raise error  # Now raises SettlementError, not X402FacilitatorError
    except BadFunctionCallOutput as exc:
        logger.debug("x402 preflight returned empty data, continuing")
    except Exception as exc:
        error = classify_error(exc)
        raise error
```

**Add new retry wrapper** (after `_submit_transfer_with_authorization`):

```python
def _submit_transfer_with_retry(
    data: ValidatedAuthorization,
    config: Optional[RetryConfig] = None,
) -> str:
    """Submit transfer with intelligent retry for transient errors."""
    
    if config is None:
        config = get_retry_config()
    
    from x402f.settlement_enhancements import (
        SettlementAttempts,
        SettlementError,
        should_log_as_error,
    )
    
    attempts = SettlementAttempts(nonce=data.nonce, config=config)
    
    while True:
        attempt = len(attempts.attempts) + 1
        skip_preflight = False
        
        try:
            if attempt > 1 and attempts.last_error and attempts.last_error.should_skip_preflight_on_retry:
                skip_preflight = True
                logger.info(
                    "x402 skipping preflight on retry attempt {} due to previous {} error",
                    attempt,
                    attempts.last_error.error_type.value,
                )
            
            tx_hash = _submit_transfer_with_authorization(
                data,
                skip_preflight=skip_preflight,
                retry_attempt=attempt,
            )
            
            attempts.add_attempt(error=None, tx_hash=tx_hash)
            logger.info("x402 settlement succeeded on attempt {} for nonce {}", attempt, data.nonce)
            return tx_hash
        
        except SettlementError as exc:
            attempts.add_attempt(error=exc, tx_hash=None)
            
            if should_log_as_error(exc, attempt):
                logger.error(
                    "x402 settlement attempt {} failed for nonce {}: {} (type={})",
                    attempt, data.nonce, exc.message, exc.error_type.value,
                )
            else:
                logger.warning(
                    "x402 settlement attempt {} failed for nonce {}: {} (type={}, will retry)",
                    attempt, data.nonce, exc.message, exc.error_type.value,
                )
            
            can_retry, reason = attempts.can_retry()
            if not can_retry:
                logger.error("x402 settlement abandoned for nonce {}: {}", data.nonce, reason)
                raise
            
            delay_ms = attempts.get_retry_delay_ms()
            logger.info(
                "x402 will retry in {}ms (attempt {}/{})",
                delay_ms, attempt + 1, config.get_max_retries(exc.error_type),
            )
            time.sleep(delay_ms / 1000.0)
        
        except X402FacilitatorError as exc:
            error = SettlementError(
                error_type=SettlementErrorType.SIGNER_MISCONFIGURED,
                message=str(exc),
                original_error=exc,
            )
            attempts.add_attempt(error=error, tx_hash=None)
            logger.error("x402 configuration error for nonce {}: {}", data.nonce, str(exc))
            raise error
```

**Update X402SettleView.post()** - Replace settlement block:

```python
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

        # NEW: Use retry logic
        tx_hash = _submit_transfer_with_retry(validated)
        
        record.mark_settled(tx_hash)
        record.save(update_fields=["status", "transaction_hash", "settled_at", "updated_at"])

except X402Authorization.DoesNotExist:
    logger.info("x402 settlement attempted without prior verification for nonce {}", validated.nonce)
    return Response({
        "success": False,
        "errorReason": "Authorization nonce not verified.",
        "transaction": None,
    }, status=status.HTTP_200_OK)

except X402FacilitatorValidationError as exc:
    logger.info("x402 settlement rejected: {}", exc.message)
    return Response({
        "success": False,
        "errorReason": exc.message,
        "transaction": None,
    }, status=status.HTTP_200_OK)

except SettlementError as exc:
    # NEW: Better error response with type information
    log_func = logger.error if not exc.is_retryable else logger.warning
    log_func(
        "x402 settlement final error for nonce {}: {} (type={}, retryable={})",
        validated.nonce, exc.message, exc.error_type.value, exc.is_retryable,
    )
    return Response({
        "success": False,
        "errorReason": exc.message,
        "errorType": exc.error_type.value,
        "isRetryable": exc.is_retryable,
        "transaction": None,
    }, status=status.HTTP_200_OK)

except X402FacilitatorError as exc:
    logger.error("x402 settlement failed: {}", exc)
    return Response({
        "success": False,
        "errorReason": str(exc),
        "transaction": None,
    }, status=status.HTTP_200_OK)

logger.info("x402 settlement succeeded for nonce {} tx {}", validated.nonce, tx_hash)
return Response({
    "success": True,
    "errorReason": None,
    "transaction": tx_hash,
    "network": str(validated.requirements.network),
    "payer": validated.payer,
}, status=status.HTTP_200_OK)
```

### Step 4: Add Django Settings (settings.py)

```python
# X402 retry configuration
X402_RETRY_CONFIG = {
    "max_retries_preflight": 3,
    "max_retries_balance": 5,
    "max_retries_rpc": 4,
    "initial_delay_ms": 100,
    "max_delay_ms": 5000,
    "backoff_factor": 2.0,
}

# Error-specific retry overrides
X402_RETRY_CONFIG["error_max_retries"] = {
    "balance_insufficient": 5,
    "rpc_unavailable": 4,
    "gas_estimation_failed": 3,
}
```

### Step 5: Run Tests

```bash
cd FacilitatorX402

# Run new tests
python -m pytest x402f/test_settlement_retry.py -v

# Run all X402 tests
python -m pytest x402f/tests.py -v

# Run existing integration tests
python manage.py test x402f
```

### Step 6: Deploy & Monitor

```bash
# Build and push Docker image
docker build -t ghcr.io/acedatacloud/facilitator-x402:v2 .
docker push ghcr.io/acedatacloud/facilitator-x402:v2

# Deploy to staging
kubectl set image deployment/facilitator-x402 \
  facilitator-x402=ghcr.io/acedatacloud/facilitator-x402:v2 \
  -n acedatacloud-staging

# Monitor logs
kubectl logs -f deployment/facilitator-x402 -n acedatacloud-staging
```

## Key Features

### 1. Error Classification

```python
BALANCE_INSUFFICIENT         # Preflight only - safe to retry, skip preflight on retry
GAS_ESTIMATION_FAILED        # Transient RPC issue - safe to retry
RPC_UNAVAILABLE             # Connection issue - safe to retry with backoff
CONTRACT_REVERTED           # Could be either - retry once to be safe
TX_TIMEOUT                  # Submitted but pending - don't retry
INVALID_SIGNATURE           # Validation error - never retry
```

### 2. Exponential Backoff

- Initial delay: 100ms
- Backoff factor: 2x
- Max delay: 5000ms
- Example: 100ms → 200ms → 400ms → 800ms → 1600ms (capped at 5000ms)

### 3. Smart Retry Decisions

```
IF error is retryable AND retries not exhausted:
    IF error should skip preflight on retry (e.g., balance):
        SET skip_preflight = True
    WAIT exponential backoff time
    RETRY
ELSE:
    RETURN error to caller
```

### 4. Better Logging

**First attempt of transient error** (WARNING):
```
WARNING: x402 settlement attempt 1 failed for nonce ABC: 
  Payer balance reported as insufficient (may be transient RPC state). 
  (type=balance_insufficient, will retry)
```

**Final failure after retries** (ERROR):
```
ERROR: x402 settlement abandoned for nonce ABC: 
  Max retries (5) exhausted
```

## Monitoring & Debugging

### Check Settlement Status
```sql
SELECT nonce, status, transaction_hash, created_at, updated_at 
FROM x402f_x402authorization 
WHERE nonce = 'abc123' 
ORDER BY updated_at DESC;
```

### Check Logs for Retry Pattern
```bash
# Find all retries for a nonce
kubectl logs -f deployment/facilitator-x402 -n acedatacloud | \
  grep "settlement attempt.*nonce ABC"
```

### Manual Recovery (Last Resort)
If a transaction succeeded on-chain but Facilitator shows error:

```python
# Check on-chain
from web3 import Web3
w3 = Web3(...)
receipt = w3.eth.get_transaction_receipt('0x...')
if receipt.status == 1:  # Success!
    # Mark as settled
    record = X402Authorization.objects.get(nonce='...')
    record.mark_settled(tx_hash)
    record.save()
```

## Backwards Compatibility

All changes are backwards compatible:
- Old code that doesn't use `skip_preflight` defaults to `False` (normal behavior)
- New `SettlementError` properly inherits from `Exception`
- Existing error handling for `X402FacilitatorError` still works
- Returns same JSON structure (adds optional `errorType` and `isRetryable` fields)

## Testing Checklist

- [x] Error classification tests
- [x] Backoff calculation tests
- [x] Retry decision tests
- [x] Attempt tracking tests
- [x] Real-world scenario simulations
- [ ] Integration tests with mock RPC (in staging)
- [ ] End-to-end test with real blockchain (in testnet)
- [ ] Load testing under high concurrency

## Future Enhancements

1. **Transaction Recovery Endpoint**: Add `GET /x402/recover/<nonce>` to query on-chain status
2. **Metrics**: Track retry success rates by error type
3. **Dead Letter Queue**: Store permanently failed settlements for review
4. **Rate Limiting**: Add per-payer rate limits to prevent abuse
5. **Circuit Breaker**: Disable settlement if RPC repeatedly fails

## Support & Questions

For issues or questions about this implementation:
1. Check logs with the retry classification
2. Review test cases in `test_settlement_retry.py`
3. Verify Django settings match your environment
