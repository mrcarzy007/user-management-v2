FROM python:3.14-slim AS base
WORKDIR /app
COPY --from=ghcr.io/astral-sh/uv:latest /uv /bin/
COPY pyproject.toml uv.lock README.md .
COPY src/app/__init__.py src/app/
RUN ["uv", "sync"] 

FROM base AS development
RUN apt update && apt install -y  --no-install-recommends git openssh-client curl
RUN curl -fsSL -o /usr/local/bin/dbmate https://github.com/amacneil/dbmate/releases/latest/download/dbmate-linux-amd64
RUN chmod +x /usr/local/bin/dbmate
COPY . .
EXPOSE 8000
CMD [ "uv", "run", "fastapi", "dev", "--host", "0.0.0.0"]

FROM base AS production
COPY . .
EXPOSE 8000
CMD [ "uv", "run", "fastapi", "run"]