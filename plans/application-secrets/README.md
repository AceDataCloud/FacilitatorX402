# Application secret naming and configuration cleanup

Status: prepared for review. No cluster changes or production key rotation are performed by this PR.

All services use `APPLICATION_SECRET_KEY` for their own application signatures. The identical field name does not mean identical values: each service has a separate Kubernetes Secret and receives only its own value. Keep JWT signing separate from application signing.

| Service | Kubernetes Secret | Environment variable / Secret field |
|---|---|---|
| AuthBackend | `auth-backend-application` | `APPLICATION_SECRET_KEY` |
| PlatformBackend and its jobs | `platform-backend-application` | `APPLICATION_SECRET_KEY` |
| GitHubCenter | `github-center-application` | `APPLICATION_SECRET_KEY` |
| FacilitatorX402 | `facilitator-application` | `APPLICATION_SECRET_KEY` |

The existing JWT contract stays `AUTH_JWT_SIGNING_PRIVATE_KEY`/`AUTH_JWT_ACTIVE_KID` in Secret `auth-jwt-signing`, and `AUTH_JWT_PUBLIC_KEYS_JSON`/`AUTH_JWT_ISSUER`/`AUTH_JWT_AUDIENCE` in ConfigMap `auth-jwt-public`. Only Auth web receives the private key. Resource services remain RS256-only and cannot sign. Missing application/public configuration fails closed in production. Removed names are not read as aliases.

## Deployment prerequisites

1. Before merging an auto-deploying repository, securely create the new Auth/Platform/GitHub Secret objects by copying each existing independent application key byte-for-byte into `APPLICATION_SECRET_KEY`. Auth's `scripts/prepare_application_secrets.py` prepares owner-only JSON files from an exported SecretList; it applies nothing and prints no values. Keep the established email identity HMAC unchanged. This is a naming migration, so login JWTs and existing application signatures remain valid.
2. The paused SV Facilitator still used the retired shared value. Give `facilitator-application` a fresh independent random key; never copy the old SV `app/SECRET_KEY`. Keep Deployment replicas0 and reconciliation suspended throughout this configuration change. No settlement, funding or signer change is authorized here.
3. Deploy matching code, web/init/worker/CronJob references in the owning cluster+namespace. Preserve live images' other changes, replicas, suspension and all payment/buyback pauses. Verify the same application value on senders/readers (especially internal mail) and RSA-only login/refresh/SSO/WS and revocation. Before rollout, maintain both old and new Secret objects; the new code accepts only the new variable. A safe rollback retains RSA-only code and its matching application-key reference.
4. After all old processes and Jobs exit, remove the old application Secret objects and any zero-replica templates that reference them. Preserve encrypted metadata for incident evidence. Remove dormant HK zhishuyun and SV app/SECRET_KEY fields only after verifying no remaining workload references; preserve unrelated fields. Do not reactivate dormant/test services.

## Historical risk material

`auth-risk-signals` remains a separate purpose-specific Secret: historical `RISK_SIGNAL_KEYS.v1` is required for old IP/device digest matching; future writes usev2. Do not erase these one-way evidence records or confuse the retained value with an accepted JWT key. It is never injected into resource services. Retirement requires retention expiry or a separately reviewed migration.

Tests generating HS256 tokens prove refusal and remain. SSM/subprocess filters mentioning obsolete fields block injection rather than providing compatibility. Historical plans stay archived; current README/env examples describe RSA public verification only. API credentials and platform-* credentials remain independent of JWT signature keys.
