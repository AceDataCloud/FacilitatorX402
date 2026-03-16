"""
Tencent Cloud SSM (Secrets Manager) loader.

Fetches a single JSON secret by name and injects every key/value pair
into os.environ before the app reads settings.

If TENCENT_SSM_SECRET_NAME is not set the loader is skipped silently,
so local development with a plain .env file continues to work unchanged.

Values already present in os.environ take precedence — they will NOT be
overwritten by SSM. This lets K8s env vars serve as fallback.
"""

import json
import os

from loguru import logger


def load_ssm_secrets() -> None:
    """Fetch secrets from Tencent Cloud SSM and inject into os.environ."""
    secret_name = os.environ.get("TENCENT_SSM_SECRET_NAME", "").strip()
    if not secret_name:
        return

    secret_id = os.environ.get("TENCENT_CLOUD_SECRET_ID", "").strip()
    secret_key = os.environ.get("TENCENT_CLOUD_SECRET_KEY", "").strip()
    region = os.environ.get("TENCENT_SSM_REGION", "ap-hongkong").strip()

    if not secret_id or not secret_key:
        logger.warning(
            "TENCENT_SSM_SECRET_NAME is set but TENCENT_CLOUD_SECRET_ID / "
            "TENCENT_CLOUD_SECRET_KEY are missing — skipping SSM load."
        )
        return

    try:
        from tencentcloud.common import credential
        from tencentcloud.ssm.v20190923 import models, ssm_client
    except ImportError:
        logger.warning(
            "tencentcloud-sdk-python is not installed; "
            "skipping SSM, falling back to env/K8s secrets."
        )
        return

    try:
        cred = credential.Credential(secret_id, secret_key)
        client = ssm_client.SsmClient(cred, region)

        req = models.GetSecretValueRequest()
        req.SecretName = secret_name
        req.VersionId = "LATEST"

        resp = client.GetSecretValue(req)
        raw = resp.SecretString
    except Exception as exc:
        logger.warning(
            f"Failed to fetch SSM secret '{secret_name}' from "
            f"region '{region}': {exc}. Falling back to env/K8s secrets."
        )
        return

    try:
        secrets: dict[str, str] = json.loads(raw)
    except json.JSONDecodeError as exc:
        logger.warning(
            f"SSM secret '{secret_name}' is not valid JSON: "
            f"{exc}. Falling back to env/K8s secrets."
        )
        return

    injected = 0
    skipped = 0
    for key, value in secrets.items():
        if key in os.environ:
            skipped += 1
        else:
            os.environ[key] = str(value)
            injected += 1

    logger.info(
        f"SSM '{secret_name}' loaded: {injected} injected, {skipped} skipped (already set)."
    )
