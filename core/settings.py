from pathlib import Path

from environs import Env

from core.ssm import load_ssm_secrets

load_ssm_secrets()

BASE_DIR = Path(__file__).resolve().parent.parent

env = Env()
env.read_env(BASE_DIR / ".env")

APP_ENV = env.str("APP_ENV", "local")

SECRET_KEY = env.str("APP_SECRET_KEY", "change-me")

DEBUG = env.bool("DEBUG", APP_ENV != "production")

ALLOWED_HOSTS = env.list("ALLOWED_HOSTS", default=["*"])
APPEND_SLASH = False
USE_X_FORWARDED_HOST = True
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "rest_framework",
    "x402f",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "core.middleware.WellKnownX402Middleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "core.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "core.wsgi.application"


DATABASES = {
    "default": {
        "ENGINE": env.str("DATABASE_ENGINE", "django.db.backends.postgresql_psycopg2"),
        "NAME": env.str(
            "PGSQL_DATABASE_FACILITATOR",
            env.str("PGSQL_DATABASE", "acedatacloud_facilitator"),
        ),
        "USER": env.str("PGSQL_USER", "postgres"),
        "PASSWORD": env.str("PGSQL_PASSWORD", "mysecretpassword"),
        "HOST": env.str("PGSQL_HOST", "localhost"),
        "PORT": env.int("PGSQL_PORT", 5432),
    }
}


AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
    },
]


LANGUAGE_CODE = "en-us"

TIME_ZONE = "UTC"

USE_I18N = True

USE_L10N = True

USE_TZ = True


STATIC_URL = "/static/"
STATIC_ROOT = BASE_DIR / "static"

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

REST_FRAMEWORK = {
    "DEFAULT_RENDERER_CLASSES": [
        "rest_framework.renderers.JSONRenderer",
    ],
}

X402_GAS_LIMIT = env.int("X402_GAS_LIMIT", 250000)
X402_SETTLEMENT_LEASE_SECONDS = env.int("X402_SETTLEMENT_LEASE_SECONDS", 300)
X402_PREPARED_MAX_AGE_SECONDS = env.int("X402_PREPARED_MAX_AGE_SECONDS", 1800)
X402_TX_TIMEOUT_SECONDS = env.int("X402_TX_TIMEOUT_SECONDS", 120)
X402_SETTLE_TOKEN = env.str("X402_SETTLE_TOKEN", "")
X402_DISCOVERY_URL = env.str("X402_DISCOVERY_URL", "")
X402_DISCOVERY_ALLOWED_HOSTS = tuple(
    host.strip().lower() for host in env.list("X402_DISCOVERY_ALLOWED_HOSTS", []) if host.strip()
)
X402_DISCOVERY_RESOURCE_HOSTS = tuple(
    host.strip().lower() for host in env.list("X402_DISCOVERY_RESOURCE_HOSTS", ["x402.acedata.cloud"]) if host.strip()
)
X402_FACILITATOR_PUBLIC_URL = env.str("X402_FACILITATOR_PUBLIC_URL", "")

X402_BASE_RPC_URL = env.str("X402_BASE_RPC_URL", "")
X402_BASE_NETWORK = env.str("X402_BASE_NETWORK", "eip155:8453")
X402_BASE_CHAIN_ID = env.int("X402_BASE_CHAIN_ID", 8453)
X402_BASE_SIGNER_PRIVATE_KEY = env.str("X402_BASE_SIGNER_PRIVATE_KEY", "")
X402_BASE_SIGNER_ADDRESS = env.str("X402_BASE_SIGNER_ADDRESS", "")
X402_BASE_ASSET = env.str("X402_BASE_ASSET", "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913")
X402_BASE_PAY_TO = env.str("X402_BASE_PAY_TO", "")
X402_BASE_EXACT_ENABLED = env.bool("X402_BASE_EXACT_ENABLED", True)
X402_BASE_UPTO_ENABLED = env.bool("X402_BASE_UPTO_ENABLED", False)

X402_SOLANA_RPC_URL = env.str("X402_SOLANA_RPC_URL", "")
X402_SOLANA_SIGNER_PRIVATE_KEY = env.str("X402_SOLANA_SIGNER_PRIVATE_KEY", "")
X402_SOLANA_SIGNER_ADDRESS = env.str("X402_SOLANA_SIGNER_ADDRESS", "")
X402_SOLANA_ASSET = env.str("X402_SOLANA_ASSET", "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v")
X402_SOLANA_PAY_TO = env.str("X402_SOLANA_PAY_TO", "")
X402_SOLANA_MAINNET_ENABLED = env.bool("X402_SOLANA_MAINNET_ENABLED", False)
X402_SOLANA_DEVNET_ENABLED = env.bool("X402_SOLANA_DEVNET_ENABLED", False)
X402_SOLANA_DEVNET_RPC_URL = env.str("X402_SOLANA_DEVNET_RPC_URL", "https://api.devnet.solana.com")
X402_SOLANA_DEVNET_SIGNER_PRIVATE_KEY = env.str("X402_SOLANA_DEVNET_SIGNER_PRIVATE_KEY", X402_SOLANA_SIGNER_PRIVATE_KEY)
X402_SOLANA_DEVNET_SIGNER_ADDRESS = env.str("X402_SOLANA_DEVNET_SIGNER_ADDRESS", X402_SOLANA_SIGNER_ADDRESS)
X402_SOLANA_DEVNET_ASSET = env.str("X402_SOLANA_DEVNET_ASSET", "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU")
X402_SOLANA_DEVNET_PAY_TO = env.str("X402_SOLANA_DEVNET_PAY_TO", X402_SOLANA_PAY_TO)

# SKALE Base chain (zero gas fees, EVM-compatible)
X402_SKALE_RPC_URL = env.str("X402_SKALE_RPC_URL", "https://skale-base.skalenodes.com/v1/base")
X402_SKALE_SIGNER_PRIVATE_KEY = env.str("X402_SKALE_SIGNER_PRIVATE_KEY", "")
X402_SKALE_SIGNER_ADDRESS = env.str("X402_SKALE_SIGNER_ADDRESS", "")
X402_SKALE_CHAIN_ID = env.int("X402_SKALE_CHAIN_ID", 1187947933)
X402_SKALE_GAS_LIMIT = env.int("X402_SKALE_GAS_LIMIT", 50000000)
# Bridged USDC (SKALE Bridge) - adheres to Circle's Bridged USDC standard
X402_SKALE_ASSET = env.str("X402_SKALE_ASSET", "0x85889c8c714505E0c94b30fcfcF64fE3Ac8FCb20")
X402_SKALE_PAY_TO = env.str("X402_SKALE_PAY_TO", "")
X402_SKALE_EXACT_ENABLED = env.bool("X402_SKALE_EXACT_ENABLED", False)

# Robinhood Chain (Arbitrum Orbit L2, chainId 4663, ETH gas). Settles in USDG,
# the chain's native stablecoin — there is no canonical USDC. USDG is an EIP-2535
# Diamond that supports EIP-3009 transferWithAuthorization but does not expose
# version(), so token name/version are supplied via the payment requirement extra.
X402_ROBINHOOD_RPC_URL = env.str("X402_ROBINHOOD_RPC_URL", "")
X402_ROBINHOOD_SIGNER_PRIVATE_KEY = env.str("X402_ROBINHOOD_SIGNER_PRIVATE_KEY", "")
X402_ROBINHOOD_SIGNER_ADDRESS = env.str("X402_ROBINHOOD_SIGNER_ADDRESS", "")
X402_ROBINHOOD_CHAIN_ID = env.int("X402_ROBINHOOD_CHAIN_ID", 4663)
X402_ROBINHOOD_GAS_LIMIT = env.int("X402_ROBINHOOD_GAS_LIMIT", 500000)
# USDG (Global Dollar)
X402_ROBINHOOD_ASSET = env.str("X402_ROBINHOOD_ASSET", "0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168")
X402_ROBINHOOD_PAY_TO = env.str("X402_ROBINHOOD_PAY_TO", "")
X402_ROBINHOOD_EXACT_ENABLED = env.bool("X402_ROBINHOOD_EXACT_ENABLED", False)
