from environs import Env
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

env = Env()
env.read_env(BASE_DIR / '.env')

APP_ENV = env.str('APP_ENV', 'local')

SECRET_KEY = env.str('APP_SECRET_KEY', 'change-me')

DEBUG = APP_ENV != 'production'

ALLOWED_HOSTS = env.list('ALLOWED_HOSTS', default=['*'])

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'rest_framework',
    'x402f',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'core.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'core.wsgi.application'


DATABASES = {
    'default': {
        'ENGINE': env.str('DATABASE_ENGINE', 'django.db.backends.postgresql_psycopg2'),
        'NAME': env.str(
            'PGSQL_DATABASE_FACILITATOR',
            env.str('PGSQL_DATABASE', 'acedatacloud_facilitator'),
        ),
        'USER': env.str('PGSQL_USER', 'postgres'),
        'PASSWORD': env.str('PGSQL_PASSWORD', 'mysecretpassword'),
        'HOST': env.str('PGSQL_HOST', 'localhost'),
        'PORT': env.int('PGSQL_PORT', 5432),
    }
}


AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_L10N = True

USE_TZ = True


STATIC_URL = '/static/'
STATIC_ROOT = BASE_DIR / 'static'

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

REST_FRAMEWORK = {
    'DEFAULT_RENDERER_CLASSES': [
        'rest_framework.renderers.JSONRenderer',
    ],
}

X402_RPC_URL = env.str('X402_RPC_URL', '')
X402_SIGNER_PRIVATE_KEY = env.str('X402_SIGNER_PRIVATE_KEY', '')
X402_SIGNER_ADDRESS = env.str('X402_SIGNER_ADDRESS', '')
X402_GAS_LIMIT = env.int('X402_GAS_LIMIT', 250000)
X402_TX_TIMEOUT_SECONDS = env.int('X402_TX_TIMEOUT_SECONDS', 120)
X402_MAX_FEE_PER_GAS_WEI = env.int('X402_MAX_FEE_PER_GAS_WEI', 0)
X402_MAX_PRIORITY_FEE_PER_GAS_WEI = env.int(
    'X402_MAX_PRIORITY_FEE_PER_GAS_WEI', 0)
