FROM python:3.10 as requirements-stage
WORKDIR /tmp
RUN pip install poetry==1.8.5
COPY ./pyproject.toml ./poetry.lock* /tmp/
RUN poetry export -f requirements.txt --output requirements.txt --without-hashes

FROM python:3.10-alpine
ENV PYTHONUNBUFFERED 1
RUN apk update && apk add \
  libuuid \
  gcc \
  g++ \
  git \
  libc-dev \
  libffi-dev \
  linux-headers \
  postgresql-libs \
  postgresql-dev
WORKDIR /code
COPY --from=requirements-stage /tmp/requirements.txt /code/requirements.txt
RUN pip install --no-cache-dir --upgrade -r /code/requirements.txt
COPY . /code/
RUN python manage.py collectstatic --noinput
CMD ["uvicorn", "core.asgi:application", "--host", "0.0.0.0", "--port", "8000"]
